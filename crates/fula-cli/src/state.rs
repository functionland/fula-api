//! Application state

use crate::config::GatewayConfig;
use crate::multipart::MultipartManager;
use dashmap::DashMap;
use fula_blockstore::MemoryBlockStore;
use fula_core::BucketManager;
use std::sync::Arc;

/// Application state shared across handlers
pub struct AppState {
    /// Gateway configuration
    pub config: GatewayConfig,
    /// Block store (IPFS)
    pub block_store: Arc<MemoryBlockStore>, // Use MemoryBlockStore for now, can swap to IpfsBlockStore
    /// Bucket manager
    pub bucket_manager: Arc<BucketManager<MemoryBlockStore>>,
    /// Multipart upload manager
    pub multipart_manager: Arc<MultipartManager>,
    /// User session cache
    pub sessions: Arc<DashMap<String, UserSession>>,
}

impl AppState {
    /// Create a new application state
    pub async fn new(config: GatewayConfig) -> anyhow::Result<Self> {
        // Initialize block store
        // In production, use IpfsBlockStore::from_url(&config.ipfs_url).await?
        let block_store = Arc::new(MemoryBlockStore::new());
        
        // Initialize bucket manager
        let bucket_manager = Arc::new(BucketManager::new(Arc::clone(&block_store)));
        
        // Initialize multipart manager
        let multipart_manager = Arc::new(MultipartManager::new(
            config.multipart_expiry_secs,
        ));

        Ok(Self {
            config,
            block_store,
            bucket_manager,
            multipart_manager,
            sessions: Arc::new(DashMap::new()),
        })
    }
}

/// User session information
#[derive(Clone, Debug)]
pub struct UserSession {
    /// User ID (from JWT sub claim)
    pub user_id: String,
    /// Display name
    pub display_name: Option<String>,
    /// Scopes
    pub scopes: Vec<String>,
    /// Expiration time
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

impl UserSession {
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
}
