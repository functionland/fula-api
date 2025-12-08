//! Application state

use crate::config::GatewayConfig;
use crate::multipart::MultipartManager;
use blake3::Hasher;
use dashmap::DashMap;
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
    /// User session cache
    pub sessions: Arc<DashMap<String, UserSession>>,
}

impl AppState {
    /// Create a new application state
    pub async fn new(config: GatewayConfig) -> anyhow::Result<Self> {
        // Initialize block store based on configuration
        let block_store = if config.use_memory_store {
            info!("Using in-memory block store (data will not persist)");
            Arc::new(FlexibleBlockStore::Memory(MemoryBlockStore::new()))
        } else {
            // Try to connect to IPFS with optional pinning service
            match Self::create_ipfs_store(&config).await {
                Ok(store) => {
                    info!("Connected to IPFS at {}", config.ipfs_url);
                    if config.pinning_service_endpoint.is_some() {
                        info!("Pinning service configured");
                    }
                    Arc::new(FlexibleBlockStore::IpfsPinning(store))
                }
                Err(e) => {
                    warn!(
                        "Failed to connect to IPFS ({}), falling back to in-memory storage",
                        e
                    );
                    Arc::new(FlexibleBlockStore::Memory(MemoryBlockStore::new()))
                }
            }
        };

        // Log storage mode
        if block_store.is_persistent() {
            info!("✓ Storage mode: IPFS (persistent)");
        } else {
            warn!("⚠ Storage mode: In-memory (NOT persistent - for development only)");
        }

        // Initialize bucket manager
        let bucket_manager = Arc::new(BucketManager::new(Arc::clone(&block_store)));

        // Initialize multipart manager
        let multipart_manager = Arc::new(MultipartManager::new(config.multipart_expiry_secs));

        Ok(Self {
            config,
            block_store,
            bucket_manager,
            multipart_manager,
            sessions: Arc::new(DashMap::new()),
        })
    }

    /// Create IPFS block store with optional pinning service
    async fn create_ipfs_store(config: &GatewayConfig) -> anyhow::Result<IpfsPinningBlockStore> {
        let mut ipfs_config = IpfsPinningConfig::with_ipfs(&config.ipfs_url);

        // Add pinning service if configured
        if let (Some(endpoint), Some(token)) = (
            &config.pinning_service_endpoint,
            &config.pinning_service_token,
        ) {
            ipfs_config = ipfs_config.with_pinning_service(endpoint, token);
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
}

impl UserSession {
    /// Create a new user session with automatic ID hashing
    pub fn new(user_id: String, display_name: Option<String>, scopes: Vec<String>, expires_at: chrono::DateTime<chrono::Utc>) -> Self {
        let hashed_user_id = hash_user_id(&user_id);
        Self {
            user_id,
            hashed_user_id,
            display_name,
            scopes,
            expires_at,
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
