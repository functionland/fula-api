//! Application state

use crate::config::GatewayConfig;
use crate::multipart::MultipartManager;
use blake3::Hasher;
use fula_blockstore::{
    FlexibleBlockStore, IpfsPinningBlockStore, IpfsPinningConfig, MemoryBlockStore,
};
use fula_core::BucketManager;
use std::sync::Arc;
use tracing::{info, warn};

/// Hash a user ID for privacy (Security audit fix A3)
/// This prevents exposing raw user IDs (e.g., email addresses) in stored metadata
pub fn hash_user_id(user_id: &str) -> String {
    let mut hasher = Hasher::new();
    hasher.update(b"fula:user_id:");  // Domain separation
    hasher.update(user_id.as_bytes());
    let hash = hasher.finalize();
    // Use first 16 bytes (128 bits) encoded as hex for reasonable uniqueness
    hex::encode(&hash.as_bytes()[..16])
}

/// Application state shared across handlers
pub struct AppState {
    /// Gateway configuration
    pub config: GatewayConfig,
    /// Block store (IPFS with pinning or memory fallback)
    pub block_store: Arc<FlexibleBlockStore>,
    /// Bucket manager
    pub bucket_manager: Arc<BucketManager<FlexibleBlockStore>>,
    /// Multipart upload manager
    pub multipart_manager: Arc<MultipartManager>,
    /// In-memory advisory lock store used to serialize v1 -> v7 forest
    /// migrations across devices. TTL-bounded; process-local only.
    pub lock_store: crate::handlers::locks::LockStore,
}

impl AppState {
    /// Create a new application state
    pub async fn new(config: GatewayConfig) -> anyhow::Result<Self> {
        // Initialize block store based on configuration
        let inner = if config.use_memory_store {
            info!("Using in-memory block store (data will not persist)");
            FlexibleBlockStore::Memory(MemoryBlockStore::new())
        } else {
            // Try to connect to IPFS with optional pinning service
            match Self::create_ipfs_store(&config).await {
                Ok(store) => {
                    info!("Connected to IPFS at {}", config.ipfs_url);
                    if config.pinning_service_endpoint.is_some() {
                        info!("Pinning service configured");
                    }
                    FlexibleBlockStore::IpfsPinning(store)
                }
                Err(e) => {
                    warn!(
                        "Failed to connect to IPFS ({}), falling back to in-memory storage",
                        e
                    );
                    FlexibleBlockStore::Memory(MemoryBlockStore::new())
                }
            }
        };

        // Optionally wrap in an LRU block cache
        let block_store = if config.block_cache_mb > 0 {
            info!("LRU block cache enabled ({} MB)", config.block_cache_mb);
            Arc::new(inner.with_cache_mb(config.block_cache_mb))
        } else {
            Arc::new(inner)
        };

        // Log storage mode
        if block_store.is_persistent() {
            info!("✓ Storage mode: IPFS (persistent)");
        } else {
            warn!("⚠ Storage mode: In-memory (NOT persistent - for development only)");
        }

        // Initialize bucket manager with persistence if configured
        let bucket_manager = if let Some(ref registry_path) = config.registry_cid_path {
            info!("Bucket registry persistence enabled at: {}", registry_path);
            Arc::new(BucketManager::with_persistence(
                Arc::clone(&block_store),
                registry_path,
            ))
        } else {
            info!("Bucket registry persistence disabled (no registry_cid_path configured)");
            Arc::new(BucketManager::new(Arc::clone(&block_store)))
        };

        // Load existing bucket registry from IPFS if available
        match bucket_manager.load_registry().await {
            Ok(count) if count > 0 => {
                info!("✓ Loaded {} bucket(s) from persistent registry", count);
            }
            Ok(_) => {
                info!("Starting with empty bucket registry");
            }
            Err(e) => {
                // CRITICAL: Don't continue with empty registry if load failed!
                // This prevents overwriting the CID file with an empty registry.
                return Err(anyhow::anyhow!(
                    "Failed to load bucket registry: {}. \
                     Refusing to start to prevent data loss. \
                     Ensure IPFS is running and the registry block is available, \
                     then restart the gateway.",
                    e
                ));
            }
        }

        // Initialize multipart manager
        let multipart_manager = Arc::new(MultipartManager::new(config.multipart_expiry_secs));

        // Initialize empty lock store. The sweeper is spawned by `server::run_server`
        // after AppState is wrapped in an Arc.
        let lock_store = crate::handlers::locks::LockStore::new();

        Ok(Self {
            config,
            block_store,
            bucket_manager,
            multipart_manager,
            lock_store,
        })
    }

    /// Create IPFS block store with optional pinning service endpoint
    /// Note: The pinning service token is provided per-request (from user's JWT),
    /// not at startup. Only the endpoint is configured at the server level.
    async fn create_ipfs_store(config: &GatewayConfig) -> anyhow::Result<IpfsPinningBlockStore> {
        let mut ipfs_config = IpfsPinningConfig::with_ipfs(&config.ipfs_url);

        // Store the pinning service endpoint if configured
        // The token will be provided per-request from the user's JWT
        if let Some(endpoint) = &config.pinning_service_endpoint {
            ipfs_config = ipfs_config.with_pinning_endpoint(endpoint);
        }

        let store = IpfsPinningBlockStore::new(ipfs_config).await?;
        Ok(store)
    }
}

/// User session information
#[derive(Clone, Debug)]
pub struct UserSession {
    /// User ID (from JWT sub claim)
    pub user_id: String,
    /// Hashed user ID for storage (Security audit fix A3)
    pub hashed_user_id: String,
    /// Display name
    pub display_name: Option<String>,
    /// Scopes
    pub scopes: Vec<String>,
    /// Expiration time
    pub expires_at: chrono::DateTime<chrono::Utc>,
    /// Raw JWT token for forwarding to pinning service
    pub jwt_token: String,
}

impl UserSession {
    /// Create a new user session with automatic ID hashing
    pub fn new(user_id: String, display_name: Option<String>, scopes: Vec<String>, expires_at: chrono::DateTime<chrono::Utc>, jwt_token: String) -> Self {
        let hashed_user_id = hash_user_id(&user_id);
        Self {
            user_id,
            hashed_user_id,
            display_name,
            scopes,
            expires_at,
            jwt_token,
        }
    }

    /// Check if the session has expired
    pub fn is_expired(&self) -> bool {
        chrono::Utc::now() > self.expires_at
    }

    /// Check if user has a scope
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.iter().any(|s| s == scope || s == "*")
    }

    /// Check if user can read
    pub fn can_read(&self) -> bool {
        self.has_scope("storage:read") || self.has_scope("storage:*")
    }

    /// Check if user can write
    pub fn can_write(&self) -> bool {
        self.has_scope("storage:write") || self.has_scope("storage:*")
    }

    /// Check if user is admin
    pub fn is_admin(&self) -> bool {
        self.has_scope("admin") || self.has_scope("*")
    }

    /// Check if user can access a bucket (owner or admin)
    /// Security audit fix A3: Uses hashed user ID for comparison
    pub fn can_access_bucket(&self, bucket_owner_id: &str) -> bool {
        self.hashed_user_id == bucket_owner_id || self.is_admin()
    }
}

/// Admin session information
#[derive(Clone, Debug)]
pub struct AdminSession {
    /// Admin ID (from JWT sub claim)
    pub admin_id: String,
    /// Expiration time
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

impl AdminSession {
    /// Create a new admin session
    pub fn new(admin_id: String, expires_at: chrono::DateTime<chrono::Utc>) -> Self {
        Self {
            admin_id,
            expires_at,
        }
    }

    /// Check if the session has expired
    pub fn is_expired(&self) -> bool {
        chrono::Utc::now() > self.expires_at
    }
}
