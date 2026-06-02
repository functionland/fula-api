//! Combined IPFS + Pinning Service block store
//!
//! This module provides a block store that:
//! - Uses IPFS HTTP API for reading/writing blocks
//! - Uses IPFS Pinning Service API for persistence
//!
//! This allows the gateway to work with any IPFS gateway for data operations
//! and any pinning service (Pinata, Web3.Storage, etc.) for persistence.

use crate::{
    cluster::ClusterClient,
    cluster_fallback::{ClusterFallbackBlockStore, ClusterFallbackConfig},
    ipfs::{IpfsBlockStore, IpfsConfig},
    memory::{CachedBlockStore, MemoryBlockStore},
    pinning_service::{Pin, PinningServiceClient, PinningServiceConfig, PinningStatus},
    BlockStore, BlockStoreError, PinStore, Result,
};
use async_trait::async_trait;
use bytes::Bytes;
use cid::Cid;
use dashmap::DashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;
use tracing::{info, instrument, warn};

/// Default cap on concurrent `POST /pins` requests issued from this blockstore.
///
/// Eight permits keep a multipart upload with many chunks from saturating the
/// pinning service (which often answers 429/503 under burst) while still
/// letting small numbers of parallel pins proceed without queuing. Tune via
/// `IpfsPinningConfig::with_max_concurrent_pins`.
const DEFAULT_MAX_CONCURRENT_PINS: u32 = 8;

/// Configuration for the combined IPFS + Pinning store
#[derive(Clone)]
pub struct IpfsPinningConfig {
    /// IPFS configuration
    pub ipfs: IpfsConfig,
    /// Pinning service configuration (optional - if None, uses local IPFS pinning)
    /// Note: This is for server-configured pinning. For per-request pinning with user JWT,
    /// use pin_with_token() instead.
    pub pinning_service: Option<PinningServiceConfig>,
    /// Pinning service endpoint URL (for per-request token-based pinning)
    /// When set, pin_with_token() will use this endpoint with the provided token
    pub pinning_endpoint: Option<String>,
    /// Whether to wait for pinning to complete before returning
    pub wait_for_pin: bool,
    /// Timeout for waiting for pin completion
    pub pin_timeout: Duration,
    /// Poll interval when waiting for pin
    pub pin_poll_interval: Duration,
    /// Cap on concurrent `POST /pins` requests from this blockstore. (R3.)
    pub max_concurrent_pins: u32,
}

impl Default for IpfsPinningConfig {
    fn default() -> Self {
        Self {
            ipfs: IpfsConfig::default(),
            pinning_service: None,
            pinning_endpoint: None,
            wait_for_pin: false,
            pin_timeout: Duration::from_secs(300), // 5 minutes
            pin_poll_interval: Duration::from_secs(5),
            max_concurrent_pins: DEFAULT_MAX_CONCURRENT_PINS,
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

    /// Add pinning service with static credentials (server-level configuration)
    /// Note: For per-request authentication, use with_pinning_endpoint() instead
    /// and call pin_with_token() with the user's JWT
    pub fn with_pinning_service(
        mut self,
        endpoint: impl Into<String>,
        access_token: impl Into<String>,
    ) -> Self {
        self.pinning_service = Some(PinningServiceConfig::new(endpoint, access_token));
        self
    }

    /// Set pinning service endpoint only (for per-request token-based auth)
    /// The token will be provided per-request via pin_with_token()
    pub fn with_pinning_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.pinning_endpoint = Some(endpoint.into());
        self
    }

    /// Set whether to wait for pin completion
    pub fn with_wait_for_pin(mut self, wait: bool) -> Self {
        self.wait_for_pin = wait;
        self
    }

    /// Override the concurrent-pins cap. Values of 0 coerce to 1. (R3.)
    pub fn with_max_concurrent_pins(mut self, max: u32) -> Self {
        self.max_concurrent_pins = max.max(1);
        self
    }

    /// Get the pinning endpoint (from either pinning_service or pinning_endpoint)
    pub fn get_pinning_endpoint(&self) -> Option<&str> {
        self.pinning_endpoint.as_deref()
            .or(self.pinning_service.as_ref().map(|s| s.endpoint.as_str()))
    }
}

/// Combined IPFS + Pinning Service block store.
///
/// Block-level caching lives in `CachedBlockStore` at the outer
/// `FlexibleBlockStore::Cached` layer; this struct no longer caches blocks
/// itself. It only owns the IPFS data client, the pinning service client,
/// and the pin-request tracking map.
pub struct IpfsPinningBlockStore {
    /// IPFS block store for data operations
    ipfs: IpfsBlockStore,
    /// Pinning service client (optional)
    pinning_client: Option<PinningServiceClient>,
    /// Configuration
    config: IpfsPinningConfig,
    /// Map of CID -> request_id for pin tracking
    pin_requests: Arc<DashMap<String, String>>,
    /// Caps concurrent `POST /pins` requests — shared across both the
    /// long-lived `pinning_client` path and the per-request token path so
    /// burst pins from a chunked multipart upload can't stampede the
    /// pinning service. (R3.)
    pin_semaphore: Arc<Semaphore>,
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

        let pin_semaphore = Arc::new(Semaphore::new(
            config.max_concurrent_pins.max(1) as usize,
        ));

        Ok(Self {
            ipfs,
            pinning_client,
            config,
            pin_requests: Arc::new(DashMap::new()),
            pin_semaphore,
        })
    }

    /// Create with default local IPFS
    pub async fn default_local() -> Result<Self> {
        Self::new(IpfsPinningConfig::default()).await
    }

    /// Create from environment variables
    /// Note: Only reads PINNING_SERVICE_ENDPOINT, not TOKEN.
    /// Authentication is provided per-request via pin_with_token() using the user's JWT.
    pub async fn from_env() -> Result<Self> {
        let ipfs_url = std::env::var("IPFS_API_URL")
            .unwrap_or_else(|_| "http://localhost:5001".to_string());

        let mut config = IpfsPinningConfig::with_ipfs(ipfs_url);

        // Check for pinning service endpoint (token is provided per-request)
        if let Ok(endpoint) = std::env::var("PINNING_SERVICE_ENDPOINT") {
            config = config.with_pinning_endpoint(endpoint);
            info!("Pinning service endpoint configured (auth via per-request JWT)");
        }

        Self::new(config).await
    }

    /// Pin a CID with the pinning service
    #[instrument(skip(self))]
    async fn pin_cid(&self, cid: &Cid, name: Option<&str>) -> Result<()> {
        let cid_str = cid.to_string();

        if let Some(ref client) = self.pinning_client {
            // Use remote pinning service. Attach the local IPFS node's
            // multiaddrs as origins so the pinning service can fetch the
            // CID directly from us instead of DHT-walking for the first
            // provider. (R3.)
            let origins = self.ipfs.origins().await;
            let mut pin = Pin::new(&cid_str);
            if let Some(n) = name {
                pin = pin.with_name(n);
            }
            if !origins.is_empty() {
                pin = pin.with_origins(origins);
            }

            // Cap concurrent /pins POSTs to prevent burst-storm 429/503s
            // when a chunked multipart upload fans out. (R3.)
            let _permit = self
                .pin_semaphore
                .acquire()
                .await
                .map_err(|e| BlockStoreError::PinFailed(format!("pin semaphore closed: {e}")))?;

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

    /// Pin a CID with a user-provided authentication token
    /// Creates a temporary pinning client using the configured endpoint and provided token
    #[instrument(skip(self, token))]
    async fn pin_cid_with_token(&self, cid: &Cid, name: Option<&str>, token: &str) -> Result<()> {
        let cid_str = cid.to_string();

        // Get the pinning endpoint
        let endpoint = self.config.get_pinning_endpoint()
            .ok_or_else(|| BlockStoreError::PinFailed(
                "No pinning service endpoint configured".to_string()
            ))?;

        // Skip if token is empty (e.g., dev mode)
        if token.is_empty() {
            warn!(cid = %cid, "Empty token provided, falling back to local IPFS pinning");
            return self.pin_cid(cid, name).await;
        }

        // Create a temporary pinning client with the user's token
        let config = PinningServiceConfig::new(endpoint, token);
        let client = PinningServiceClient::new(config)?;

        // Create pin request with origins hint pointing to the local IPFS
        // node so the pinning service can fetch us directly. (R3.)
        let origins = self.ipfs.origins().await;
        let mut pin = Pin::new(&cid_str);
        if let Some(n) = name {
            pin = pin.with_name(n);
        }
        if !origins.is_empty() {
            pin = pin.with_origins(origins);
        }

        // Share the blockstore-wide semaphore so token and non-token pins
        // count against the same concurrency budget. (R3.)
        let _permit = self
            .pin_semaphore
            .acquire()
            .await
            .map_err(|e| BlockStoreError::PinFailed(format!("pin semaphore closed: {e}")))?;

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

        info!(cid = %cid, request_id = %response.request_id, endpoint = %endpoint, "CID pinned with user token");

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
        //
        // NOTE: We deliberately DO NOT pin individual blocks here.
        // Instead, the root CID should be pinned at upload completion.
        // IPFS recursive pinning will automatically pin all referenced blocks.
        // This optimization reduces N pin requests to 1 for chunked uploads.
        //
        // Pinning should happen at:
        // - put_object() completion for single objects
        // - complete_multipart_upload() for multipart uploads
        self.ipfs.put_block(data).await
    }

    #[instrument(skip(self))]
    async fn get_block(&self, cid: &Cid) -> Result<Bytes> {
        self.ipfs.get_block(cid).await
    }

    async fn has_block(&self, cid: &Cid) -> Result<bool> {
        self.ipfs.has_block(cid).await
    }

    #[instrument(skip(self))]
    async fn delete_block(&self, cid: &Cid) -> Result<()> {
        // Unpin first
        let _ = self.unpin_cid(cid).await;

        // Then remove from IPFS
        self.ipfs.delete_block(cid).await
    }

    async fn block_size(&self, cid: &Cid) -> Result<u64> {
        self.ipfs.block_size(cid).await
    }

    async fn put_ipld<T: serde::Serialize + Send + Sync>(&self, data: &T) -> Result<Cid> {
        // NOTE: We deliberately DO NOT pin IPLD nodes inline.
        // Pin the root CID at upload completion for recursive pinning.
        self.ipfs.put_ipld(data).await
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

    async fn pin_with_token(&self, cid: &Cid, name: Option<&str>, token: &str) -> Result<()> {
        self.pin_cid_with_token(cid, name, token).await
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
/// or falls back to memory storage. Can optionally be wrapped in an LRU
/// cache via the `Cached` variant.
pub enum FlexibleBlockStore {
    /// IPFS with pinning service
    IpfsPinning(IpfsPinningBlockStore),
    /// In-memory storage (fallback)
    Memory(MemoryBlockStore),
    /// LRU-cached wrapper around any of the above (or further nesting)
    Cached(CachedBlockStore<Box<FlexibleBlockStore>>),
    /// Cluster-aware read fallback wrapping the IPFS store (see
    /// [`crate::cluster_fallback`]). Reads use the bounded/peered/locate path;
    /// every other operation delegates to the wrapped store unchanged.
    ClusterFallback(ClusterFallbackBlockStore),
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

    /// Wrap this block store in an LRU cache sized by megabytes.
    pub fn with_cache_mb(self, mb: usize) -> Self {
        Self::Cached(CachedBlockStore::with_mb(Box::new(self), mb))
    }

    /// Wrap this store with the cluster-aware read fallback. The wrapper holds
    /// its own bounded kubo handle (`ipfs`) plus the cluster client used to
    /// locate holders; reads take the bounded/peered/locate path while
    /// writes/pins/deletes delegate unchanged.
    pub fn with_cluster_fallback(
        self,
        ipfs: IpfsBlockStore,
        cluster: ClusterClient,
        cfg: ClusterFallbackConfig,
    ) -> Self {
        Self::ClusterFallback(ClusterFallbackBlockStore::new(
            Box::new(self),
            ipfs,
            cluster,
            cfg,
        ))
    }

    /// Check if using real IPFS or memory fallback (recursing through caches)
    pub fn is_persistent(&self) -> bool {
        match self {
            Self::IpfsPinning(_) => true,
            Self::Memory(_) => false,
            Self::Cached(cached) => {
                // Recurse through the wrapped box to find the underlying variant
                // via its BlockStore impl (safe — no behavioral coupling).
                // We can't borrow the Box'd FlexibleBlockStore through
                // CachedBlockStore directly, so expose a helper below.
                cached.inner_is_persistent()
            }
            Self::ClusterFallback(store) => store.inner_is_persistent(),
        }
    }
}

impl CachedBlockStore<Box<FlexibleBlockStore>> {
    /// Check whether the wrapped store is persistent (recurses).
    pub fn inner_is_persistent(&self) -> bool {
        self.inner_ref().is_persistent()
    }
}

#[async_trait]
impl BlockStore for FlexibleBlockStore {
    async fn put_block(&self, data: &[u8]) -> Result<Cid> {
        match self {
            Self::IpfsPinning(store) => store.put_block(data).await,
            Self::Memory(store) => store.put_block(data).await,
            Self::Cached(store) => store.put_block(data).await,
            Self::ClusterFallback(store) => store.put_block(data).await,
        }
    }

    async fn get_block(&self, cid: &Cid) -> Result<Bytes> {
        match self {
            Self::IpfsPinning(store) => store.get_block(cid).await,
            Self::Memory(store) => store.get_block(cid).await,
            Self::Cached(store) => store.get_block(cid).await,
            Self::ClusterFallback(store) => store.get_block(cid).await,
        }
    }

    async fn has_block(&self, cid: &Cid) -> Result<bool> {
        match self {
            Self::IpfsPinning(store) => store.has_block(cid).await,
            Self::Memory(store) => store.has_block(cid).await,
            Self::Cached(store) => store.has_block(cid).await,
            Self::ClusterFallback(store) => store.has_block(cid).await,
        }
    }

    async fn delete_block(&self, cid: &Cid) -> Result<()> {
        match self {
            Self::IpfsPinning(store) => store.delete_block(cid).await,
            Self::Memory(store) => store.delete_block(cid).await,
            Self::Cached(store) => store.delete_block(cid).await,
            Self::ClusterFallback(store) => store.delete_block(cid).await,
        }
    }

    async fn block_size(&self, cid: &Cid) -> Result<u64> {
        match self {
            Self::IpfsPinning(store) => store.block_size(cid).await,
            Self::Memory(store) => store.block_size(cid).await,
            Self::Cached(store) => store.block_size(cid).await,
            Self::ClusterFallback(store) => store.block_size(cid).await,
        }
    }

    async fn put_ipld<T: serde::Serialize + Send + Sync>(&self, data: &T) -> Result<Cid> {
        match self {
            Self::IpfsPinning(store) => store.put_ipld(data).await,
            Self::Memory(store) => store.put_ipld(data).await,
            Self::Cached(store) => store.put_ipld(data).await,
            Self::ClusterFallback(store) => store.put_ipld(data).await,
        }
    }

    async fn get_ipld<T: serde::de::DeserializeOwned>(&self, cid: &Cid) -> Result<T> {
        match self {
            Self::IpfsPinning(store) => store.get_ipld(cid).await,
            Self::Memory(store) => store.get_ipld(cid).await,
            Self::Cached(store) => store.get_ipld(cid).await,
            Self::ClusterFallback(store) => store.get_ipld(cid).await,
        }
    }
}

#[async_trait]
impl PinStore for FlexibleBlockStore {
    async fn pin(&self, cid: &Cid, name: Option<&str>) -> Result<()> {
        match self {
            Self::IpfsPinning(store) => store.pin(cid, name).await,
            Self::Memory(_) => {
                // Memory store doesn't need pinning, just succeed silently
                Ok(())
            }
            Self::Cached(store) => store.inner_ref().pin(cid, name).await,
            Self::ClusterFallback(store) => store.pin(cid, name).await,
        }
    }

    async fn pin_with_token(&self, cid: &Cid, name: Option<&str>, token: &str) -> Result<()> {
        match self {
            Self::IpfsPinning(store) => store.pin_with_token(cid, name, token).await,
            Self::Memory(_) => {
                // Memory store doesn't need pinning, just succeed silently
                Ok(())
            }
            Self::Cached(store) => store.inner_ref().pin_with_token(cid, name, token).await,
            Self::ClusterFallback(store) => store.pin_with_token(cid, name, token).await,
        }
    }

    async fn unpin(&self, cid: &Cid) -> Result<()> {
        match self {
            Self::IpfsPinning(store) => store.unpin(cid).await,
            Self::Memory(_) => Ok(()),
            Self::Cached(store) => store.inner_ref().unpin(cid).await,
            Self::ClusterFallback(store) => store.unpin(cid).await,
        }
    }

    async fn is_pinned(&self, cid: &Cid) -> Result<bool> {
        match self {
            Self::IpfsPinning(store) => store.is_pinned(cid).await,
            Self::Memory(_) => Ok(true), // Memory store "pins" everything
            Self::Cached(store) => store.inner_ref().is_pinned(cid).await,
            Self::ClusterFallback(store) => store.is_pinned(cid).await,
        }
    }

    async fn list_pins(&self) -> Result<Vec<Cid>> {
        match self {
            Self::IpfsPinning(store) => store.list_pins().await,
            Self::Memory(_) => Ok(Vec::new()),
            Self::Cached(store) => store.inner_ref().list_pins().await,
            Self::ClusterFallback(store) => store.list_pins().await,
        }
    }

    async fn pin_status(&self, cid: &Cid) -> Result<crate::PinStatus> {
        match self {
            Self::IpfsPinning(store) => store.pin_status(cid).await,
            Self::Memory(_) => Ok(crate::PinStatus::Pinned), // Memory store "pins" everything
            Self::Cached(store) => store.inner_ref().pin_status(cid).await,
            Self::ClusterFallback(store) => store.pin_status(cid).await,
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
        assert_eq!(config.max_concurrent_pins, DEFAULT_MAX_CONCURRENT_PINS);
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

    #[test]
    fn max_concurrent_pins_coerces_zero_to_one() {
        let config = IpfsPinningConfig::default().with_max_concurrent_pins(0);
        assert_eq!(config.max_concurrent_pins, 1);
    }

    // R3 regression: pin_cid must cap concurrent /pins POSTs at
    // `max_concurrent_pins`. With cap=2 and a 300ms-per-response mock, 4
    // concurrent pins should take ~600ms (two batches), not ~300ms.
    #[tokio::test]
    async fn pin_semaphore_caps_concurrent_pin_posts() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        // Mock both IPFS (for verify_connection + node_info) and the pinning
        // service on a single MockServer since wiremock routes by path.
        let server = MockServer::start().await;

        // /api/v0/id — verify_connection and origins fetch both hit this.
        Mock::given(method("POST"))
            .and(path("/api/v0/id"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ID": "QmPeerTest",
                "PublicKey": "pk",
                "Addresses": ["/ip4/127.0.0.1/tcp/4001/p2p/QmPeerTest"],
                "AgentVersion": "test/0.1",
                "ProtocolVersion": "ipfs/0.1.0"
            })))
            .mount(&server)
            .await;

        // /pins — 300ms delay per response so we can observe serialization.
        Mock::given(method("POST"))
            .and(path("/pins"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(Duration::from_millis(300))
                    .set_body_json(serde_json::json!({
                        "requestid": "req-test",
                        "status": "queued",
                        "created": "2026-04-20T00:00:00Z",
                        "pin": { "cid": "bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku" },
                        "delegates": []
                    })),
            )
            .mount(&server)
            .await;

        // Build the blockstore pointed at the mock server, with cap=2.
        let ipfs = IpfsConfig::with_url(server.uri());
        let ps = PinningServiceConfig::new(server.uri(), "token");
        let config = IpfsPinningConfig {
            ipfs,
            pinning_service: Some(ps),
            pinning_endpoint: None,
            wait_for_pin: false,
            pin_timeout: Duration::from_secs(30),
            pin_poll_interval: Duration::from_secs(1),
            max_concurrent_pins: 2,
        };
        let store = Arc::new(IpfsPinningBlockStore::new(config).await.unwrap());

        // Parse a valid CIDv1 for the pin request.
        let cid: Cid = "bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku"
            .parse()
            .unwrap();

        // Fire four concurrent pin_cid calls.
        let start = std::time::Instant::now();
        let completed = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();
        for _ in 0..4 {
            let store = Arc::clone(&store);
            let completed = Arc::clone(&completed);
            handles.push(tokio::spawn(async move {
                store.pin_cid(&cid, None).await.unwrap();
                completed.fetch_add(1, Ordering::SeqCst);
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
        let elapsed = start.elapsed();

        assert_eq!(completed.load(Ordering::SeqCst), 4);
        // With a cap of 2 and 300ms per response, 4 pins = 2 batches = >= ~600ms.
        // We pad the lower bound to 500ms to tolerate scheduling jitter on CI.
        assert!(
            elapsed >= Duration::from_millis(500),
            "4 pins with cap=2 finished in {:?} — semaphore did not serialize",
            elapsed
        );
        // Upper bound: nowhere near the fully-serial time of 4*300ms=1200ms.
        assert!(
            elapsed < Duration::from_millis(1100),
            "4 pins with cap=2 took {:?} — slower than expected",
            elapsed
        );
    }

    // R3 regression: pin_cid forwards local-node multiaddrs as the `origins`
    // field so the pinning service can skip DHT discovery.
    #[tokio::test]
    async fn pin_cid_attaches_origins_hint_from_local_node() {
        use std::sync::{Arc as StdArc, Mutex};
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

        struct CapturingResponder(StdArc<Mutex<Option<serde_json::Value>>>);
        impl Respond for CapturingResponder {
            fn respond(&self, req: &Request) -> ResponseTemplate {
                let body: serde_json::Value =
                    serde_json::from_slice(&req.body).unwrap_or(serde_json::Value::Null);
                *self.0.lock().unwrap() = Some(body);
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "requestid": "req-test",
                    "status": "queued",
                    "created": "2026-04-20T00:00:00Z",
                    "pin": { "cid": "bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku" },
                    "delegates": []
                }))
            }
        }

        let server = MockServer::start().await;
        let captured: StdArc<Mutex<Option<serde_json::Value>>> =
            StdArc::new(Mutex::new(None));

        Mock::given(method("POST"))
            .and(path("/api/v0/id"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ID": "QmPeerTest",
                "PublicKey": "pk",
                "Addresses": [
                    "/ip4/127.0.0.1/tcp/4001/p2p/QmPeerTest",
                    "/ip4/10.0.0.5/tcp/4001/p2p/QmPeerTest"
                ],
                "AgentVersion": "test/0.1",
                "ProtocolVersion": "ipfs/0.1.0"
            })))
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/pins"))
            .respond_with(CapturingResponder(StdArc::clone(&captured)))
            .mount(&server)
            .await;

        let ipfs = IpfsConfig::with_url(server.uri());
        let ps = PinningServiceConfig::new(server.uri(), "token");
        let config = IpfsPinningConfig {
            ipfs,
            pinning_service: Some(ps),
            pinning_endpoint: None,
            wait_for_pin: false,
            pin_timeout: Duration::from_secs(30),
            pin_poll_interval: Duration::from_secs(1),
            max_concurrent_pins: 4,
        };
        let store = IpfsPinningBlockStore::new(config).await.unwrap();

        let cid: Cid = "bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku"
            .parse()
            .unwrap();
        store.pin_cid(&cid, Some("hello")).await.unwrap();

        let body = captured.lock().unwrap().clone().expect("/pins never received a body");
        let origins = body
            .get("origins")
            .and_then(|v| v.as_array())
            .cloned()
            .expect("origins field should be set");
        assert_eq!(origins.len(), 2, "expected 2 origins from mocked node info");
        let first = origins[0].as_str().unwrap();
        assert!(first.contains("/p2p/QmPeerTest"), "origin string malformed: {first}");
    }
}
