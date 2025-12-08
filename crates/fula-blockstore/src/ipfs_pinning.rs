//! Combined IPFS + Pinning Service block store
//!
//! This module provides a block store that:
//! - Uses IPFS HTTP API for reading/writing blocks
//! - Uses IPFS Pinning Service API for persistence
//!
//! This allows the gateway to work with any IPFS gateway for data operations
//! and any pinning service (Pinata, Web3.Storage, etc.) for persistence.

use crate::{
    ipfs::{IpfsBlockStore, IpfsConfig},
    memory::MemoryBlockStore,
    pinning_service::{Pin, PinningServiceClient, PinningServiceConfig, PinningStatus},
    BlockStore, BlockStoreError, PinStore, Result,
};
use async_trait::async_trait;
use bytes::Bytes;
use cid::Cid;
use dashmap::DashMap;
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, instrument, warn};

/// Configuration for the combined IPFS + Pinning store
#[derive(Clone)]
pub struct IpfsPinningConfig {
    /// IPFS configuration
    pub ipfs: IpfsConfig,
    /// Pinning service configuration (optional - if None, uses local IPFS pinning)
    pub pinning_service: Option<PinningServiceConfig>,
    /// Whether to wait for pinning to complete before returning
    pub wait_for_pin: bool,
    /// Timeout for waiting for pin completion
    pub pin_timeout: Duration,
    /// Poll interval when waiting for pin
    pub pin_poll_interval: Duration,
    /// Use local cache for reads
    pub enable_cache: bool,
    /// Cache capacity
    pub cache_capacity: usize,
}

impl Default for IpfsPinningConfig {
    fn default() -> Self {
        Self {
            ipfs: IpfsConfig::default(),
            pinning_service: None,
            wait_for_pin: false,
            pin_timeout: Duration::from_secs(300), // 5 minutes
            pin_poll_interval: Duration::from_secs(5),
            enable_cache: true,
            cache_capacity: 10_000,
        }
    }
}

impl IpfsPinningConfig {
    /// Create with IPFS URL only (no remote pinning service)
    pub fn with_ipfs(ipfs_url: impl Into<String>) -> Self {
        Self {
            ipfs: IpfsConfig::with_url(ipfs_url),
            ..Default::default()
        }
    }

    /// Add pinning service
    pub fn with_pinning_service(
        mut self,
        endpoint: impl Into<String>,
        access_token: impl Into<String>,
    ) -> Self {
        self.pinning_service = Some(PinningServiceConfig::new(endpoint, access_token));
        self
    }

    /// Set whether to wait for pin completion
    pub fn with_wait_for_pin(mut self, wait: bool) -> Self {
        self.wait_for_pin = wait;
        self
    }
}

/// Combined IPFS + Pinning Service block store
pub struct IpfsPinningBlockStore {
    /// IPFS block store for data operations
    ipfs: IpfsBlockStore,
    /// Pinning service client (optional)
    pinning_client: Option<PinningServiceClient>,
    /// Configuration
    config: IpfsPinningConfig,
    /// Local cache for frequently accessed blocks
    cache: Arc<DashMap<Cid, Bytes>>,
    /// Map of CID -> request_id for pin tracking
    pin_requests: Arc<DashMap<String, String>>,
}

impl IpfsPinningBlockStore {
    /// Create a new combined block store
    pub async fn new(config: IpfsPinningConfig) -> Result<Self> {
        // Initialize IPFS client
        let ipfs = IpfsBlockStore::new(config.ipfs.clone()).await?;

        // Initialize pinning service client if configured
        let pinning_client = if let Some(ref ps_config) = config.pinning_service {
            Some(PinningServiceClient::new(ps_config.clone())?)
        } else {
            None
        };

        let cache_capacity = if config.enable_cache {
            config.cache_capacity
        } else {
            0
        };

        Ok(Self {
            ipfs,
            pinning_client,
            config,
            cache: Arc::new(DashMap::with_capacity(cache_capacity)),
            pin_requests: Arc::new(DashMap::new()),
        })
    }

    /// Create with default local IPFS
    pub async fn default_local() -> Result<Self> {
        Self::new(IpfsPinningConfig::default()).await
    }

    /// Create from environment variables
    pub async fn from_env() -> Result<Self> {
        let ipfs_url = std::env::var("IPFS_API_URL")
            .unwrap_or_else(|_| "http://localhost:5001".to_string());

        let mut config = IpfsPinningConfig::with_ipfs(ipfs_url);

        // Check for pinning service configuration
        if let (Ok(endpoint), Ok(token)) = (
            std::env::var("PINNING_SERVICE_ENDPOINT"),
            std::env::var("PINNING_SERVICE_TOKEN"),
        ) {
            config = config.with_pinning_service(endpoint, token);
            info!("Pinning service configured");
        }

        Self::new(config).await
    }

    /// Pin a CID with the pinning service
    #[instrument(skip(self))]
    async fn pin_cid(&self, cid: &Cid, name: Option<&str>) -> Result<()> {
        let cid_str = cid.to_string();

        if let Some(ref client) = self.pinning_client {
            // Use remote pinning service
            let pin = if let Some(n) = name {
                Pin::new(&cid_str).with_name(n)
            } else {
                Pin::new(&cid_str)
            };

            let response = client.add_pin(pin).await?;
            
            // Store the request ID for tracking
            self.pin_requests
                .insert(cid_str.clone(), response.request_id.clone());

            // Optionally wait for pin to complete
            if self.config.wait_for_pin {
                client
                    .wait_for_pin(
                        &response.request_id,
                        self.config.pin_timeout,
                        self.config.pin_poll_interval,
                    )
                    .await?;
            }

            info!(cid = %cid, request_id = %response.request_id, "CID pinned to remote service");
        } else {
            // Fall back to local IPFS pinning
            let url = format!("{}/api/v0/pin/add?arg={}", self.config.ipfs.api_url, cid);
            let client = reqwest::Client::new();
            let response = client.post(&url).send().await?;

            if !response.status().is_success() {
                let error = response.text().await.unwrap_or_default();
                return Err(BlockStoreError::PinFailed(format!(
                    "Local IPFS pin failed: {}",
                    error
                )));
            }

            info!(cid = %cid, "CID pinned to local IPFS");
        }

        Ok(())
    }

    /// Unpin a CID
    #[instrument(skip(self))]
    async fn unpin_cid(&self, cid: &Cid) -> Result<()> {
        let cid_str = cid.to_string();

        if let Some(ref client) = self.pinning_client {
            // Find the pin request ID
            if let Some(request_id) = self.pin_requests.get(&cid_str) {
                client.delete_pin(request_id.value()).await?;
                drop(request_id); // Release the ref before removal
                self.pin_requests.remove(&cid_str);
            } else {
                // Try to find the pin by CID
                if let Some(status) = client.get_pin_by_cid(&cid_str).await? {
                    client.delete_pin(&status.request_id).await?;
                }
            }
        } else {
            // Fall back to local IPFS unpinning
            let url = format!("{}/api/v0/pin/rm?arg={}", self.config.ipfs.api_url, cid);
            let client = reqwest::Client::new();
            let response = client.post(&url).send().await?;

            if !response.status().is_success() {
                let error = response.text().await.unwrap_or_default();
                warn!(cid = %cid, error = %error, "Failed to unpin from local IPFS");
            }
        }

        Ok(())
    }
}

#[async_trait]
impl BlockStore for IpfsPinningBlockStore {
    #[instrument(skip(self, data), fields(size = data.len()))]
    async fn put_block(&self, data: &[u8]) -> Result<Cid> {
        // Put to IPFS
        let cid = self.ipfs.put_block(data).await?;

        // Cache the data
        if self.config.enable_cache {
            self.cache.insert(cid, Bytes::copy_from_slice(data));
        }

        // Pin for persistence
        if let Err(e) = self.pin_cid(&cid, None).await {
            warn!(cid = %cid, error = %e, "Failed to pin CID, data may not be persistent");
        }

        Ok(cid)
    }

    #[instrument(skip(self))]
    async fn get_block(&self, cid: &Cid) -> Result<Bytes> {
        // Check cache first
        if let Some(data) = self.cache.get(cid) {
            return Ok(data.value().clone());
        }

        // Fetch from IPFS
        let data = self.ipfs.get_block(cid).await?;

        // Cache for future reads
        if self.config.enable_cache {
            self.cache.insert(*cid, data.clone());
        }

        Ok(data)
    }

    async fn has_block(&self, cid: &Cid) -> Result<bool> {
        // Check cache first
        if self.cache.contains_key(cid) {
            return Ok(true);
        }

        // Check IPFS
        self.ipfs.has_block(cid).await
    }

    #[instrument(skip(self))]
    async fn delete_block(&self, cid: &Cid) -> Result<()> {
        // Remove from cache
        self.cache.remove(cid);

        // Unpin first
        let _ = self.unpin_cid(cid).await;

        // Then remove from IPFS
        self.ipfs.delete_block(cid).await
    }

    async fn block_size(&self, cid: &Cid) -> Result<u64> {
        // Check cache first
        if let Some(data) = self.cache.get(cid) {
            return Ok(data.value().len() as u64);
        }

        self.ipfs.block_size(cid).await
    }

    async fn put_ipld<T: serde::Serialize + Send + Sync>(&self, data: &T) -> Result<Cid> {
        let cid = self.ipfs.put_ipld(data).await?;

        // Pin for persistence
        if let Err(e) = self.pin_cid(&cid, None).await {
            warn!(cid = %cid, error = %e, "Failed to pin IPLD, data may not be persistent");
        }

        Ok(cid)
    }

    async fn get_ipld<T: serde::de::DeserializeOwned>(&self, cid: &Cid) -> Result<T> {
        self.ipfs.get_ipld(cid).await
    }
}

#[async_trait]
impl PinStore for IpfsPinningBlockStore {
    async fn pin(&self, cid: &Cid, name: Option<&str>) -> Result<()> {
        self.pin_cid(cid, name).await
    }

    async fn unpin(&self, cid: &Cid) -> Result<()> {
        self.unpin_cid(cid).await
    }

    async fn is_pinned(&self, cid: &Cid) -> Result<bool> {
        let cid_str = cid.to_string();

        if let Some(ref client) = self.pinning_client {
            client.is_pinned(&cid_str).await
        } else {
            // Check local IPFS
            let url = format!(
                "{}/api/v0/pin/ls?arg={}&type=recursive",
                self.config.ipfs.api_url, cid
            );
            let client = reqwest::Client::new();
            let response = client.post(&url).send().await?;

            Ok(response.status().is_success())
        }
    }

    async fn list_pins(&self) -> Result<Vec<Cid>> {
        if let Some(ref client) = self.pinning_client {
            let results = client.list_pins(None).await?;
            results
                .results
                .into_iter()
                .filter(|p| p.status == PinningStatus::Pinned)
                .map(|p| {
                    p.pin.cid.parse().map_err(|e: cid::Error| {
                        BlockStoreError::InvalidCid(e.to_string())
                    })
                })
                .collect()
        } else {
            // List from local IPFS
            let url = format!("{}/api/v0/pin/ls?type=recursive", self.config.ipfs.api_url);
            let client = reqwest::Client::new();
            let response = client.post(&url).send().await?;

            if !response.status().is_success() {
                return Ok(Vec::new());
            }

            #[derive(serde::Deserialize)]
            struct PinLsResponse {
                #[serde(rename = "Keys")]
                keys: std::collections::HashMap<String, serde_json::Value>,
            }

            let result: PinLsResponse = response.json().await?;
            result
                .keys
                .keys()
                .map(|k| {
                    k.parse().map_err(|e: cid::Error| {
                        BlockStoreError::InvalidCid(e.to_string())
                    })
                })
                .collect()
        }
    }

    async fn pin_status(&self, cid: &Cid) -> Result<crate::PinStatus> {
        let cid_str = cid.to_string();

        if let Some(ref client) = self.pinning_client {
            if let Some(status) = client.get_pin_by_cid(&cid_str).await? {
                return Ok(match status.status {
                    PinningStatus::Queued => crate::PinStatus::Queued,
                    PinningStatus::Pinning => crate::PinStatus::Pinning,
                    PinningStatus::Pinned => crate::PinStatus::Pinned,
                    PinningStatus::Failed => crate::PinStatus::Error,
                });
            }
            Ok(crate::PinStatus::Unpinned)
        } else {
            // Check local IPFS
            if self.is_pinned(cid).await? {
                Ok(crate::PinStatus::Pinned)
            } else {
                Ok(crate::PinStatus::Unpinned)
            }
        }
    }
}

/// Fallback-capable block store that uses IPFS with pinning when available,
/// or falls back to memory storage
pub enum FlexibleBlockStore {
    /// IPFS with pinning service
    IpfsPinning(IpfsPinningBlockStore),
    /// In-memory storage (fallback)
    Memory(MemoryBlockStore),
}

impl FlexibleBlockStore {
    /// Create from environment, falling back to memory if IPFS unavailable
    pub async fn from_env_or_memory() -> Self {
        match IpfsPinningBlockStore::from_env().await {
            Ok(store) => {
                info!("Using IPFS block store with pinning");
                Self::IpfsPinning(store)
            }
            Err(e) => {
                warn!(error = %e, "Failed to connect to IPFS, using in-memory storage");
                Self::Memory(MemoryBlockStore::new())
            }
        }
    }

    /// Check if using real IPFS or memory fallback
    pub fn is_persistent(&self) -> bool {
        matches!(self, Self::IpfsPinning(_))
    }
}

#[async_trait]
impl BlockStore for FlexibleBlockStore {
    async fn put_block(&self, data: &[u8]) -> Result<Cid> {
        match self {
            Self::IpfsPinning(store) => store.put_block(data).await,
            Self::Memory(store) => store.put_block(data).await,
        }
    }

    async fn get_block(&self, cid: &Cid) -> Result<Bytes> {
        match self {
            Self::IpfsPinning(store) => store.get_block(cid).await,
            Self::Memory(store) => store.get_block(cid).await,
        }
    }

    async fn has_block(&self, cid: &Cid) -> Result<bool> {
        match self {
            Self::IpfsPinning(store) => store.has_block(cid).await,
            Self::Memory(store) => store.has_block(cid).await,
        }
    }

    async fn delete_block(&self, cid: &Cid) -> Result<()> {
        match self {
            Self::IpfsPinning(store) => store.delete_block(cid).await,
            Self::Memory(store) => store.delete_block(cid).await,
        }
    }

    async fn block_size(&self, cid: &Cid) -> Result<u64> {
        match self {
            Self::IpfsPinning(store) => store.block_size(cid).await,
            Self::Memory(store) => store.block_size(cid).await,
        }
    }

    async fn put_ipld<T: serde::Serialize + Send + Sync>(&self, data: &T) -> Result<Cid> {
        match self {
            Self::IpfsPinning(store) => store.put_ipld(data).await,
            Self::Memory(store) => store.put_ipld(data).await,
        }
    }

    async fn get_ipld<T: serde::de::DeserializeOwned>(&self, cid: &Cid) -> Result<T> {
        match self {
            Self::IpfsPinning(store) => store.get_ipld(cid).await,
            Self::Memory(store) => store.get_ipld(cid).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = IpfsPinningConfig::default();
        assert_eq!(config.ipfs.api_url, "http://localhost:5001");
        assert!(config.pinning_service.is_none());
    }

    #[test]
    fn test_config_with_pinning() {
        let config = IpfsPinningConfig::with_ipfs("http://ipfs:5001")
            .with_pinning_service("https://api.pinata.cloud/psa", "my-token");

        assert_eq!(config.ipfs.api_url, "http://ipfs:5001");
        assert!(config.pinning_service.is_some());
        let ps = config.pinning_service.unwrap();
        assert_eq!(ps.endpoint, "https://api.pinata.cloud/psa");
        assert_eq!(ps.access_token, "my-token");
    }
}
