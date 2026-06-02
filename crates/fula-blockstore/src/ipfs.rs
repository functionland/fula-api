//! IPFS HTTP API client for block operations

use crate::{BlockStore, BlockStoreError, Result};
use async_trait::async_trait;
use bytes::Bytes;
use cid::Cid;
use reqwest::{Client, multipart};
use serde::Deserialize;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;
use tracing::{debug, instrument};

/// Maximum size for a single IPFS block (slightly under 1MB to be safe)
/// Data larger than this MUST use UnixFS chunking via /api/v0/add
const MAX_BLOCK_SIZE: usize = 1024 * 1024 - 256; // ~1MB minus safety margin

/// Configuration for IPFS connection
#[derive(Clone)]
pub struct IpfsConfig {
    /// IPFS API URL (e.g., "http://localhost:5001")
    pub api_url: String,
    /// Request timeout
    pub timeout: Duration,
    /// Maximum retries
    pub max_retries: u32,
}

impl Default for IpfsConfig {
    fn default() -> Self {
        Self {
            api_url: "http://localhost:5001".to_string(),
            timeout: Duration::from_secs(30),
            max_retries: 3,
        }
    }
}

impl IpfsConfig {
    /// Create with a custom API URL
    pub fn with_url(api_url: impl Into<String>) -> Self {
        Self {
            api_url: api_url.into(),
            ..Default::default()
        }
    }
}

/// IPFS block store client
#[derive(Clone)]
pub struct IpfsBlockStore {
    client: Client,
    config: IpfsConfig,
    /// Cached local-node multiaddrs used as `origins` hints in
    /// pinning-service requests. Populated lazily on first successful call to
    /// [`IpfsBlockStore::origins`]; failed lookups are not cached so a later
    /// call after the IPFS daemon comes up will still populate the hint. (R3.)
    origins_cache: Arc<StdMutex<Option<Vec<String>>>>,
}

impl IpfsBlockStore {
    /// Create a new IPFS block store
    pub async fn new(config: IpfsConfig) -> Result<Self> {
        let client = Client::builder()
            .timeout(config.timeout)
            .build()
            .map_err(|e| BlockStoreError::Connection(e.to_string()))?;

        let store = Self {
            client,
            config,
            origins_cache: Arc::new(StdMutex::new(None)),
        };

        // Verify connection
        store.verify_connection().await?;

        Ok(store)
    }

    /// Create with default config
    pub async fn default_local() -> Result<Self> {
        Self::new(IpfsConfig::default()).await
    }

    /// Create from URL string
    pub async fn from_url(url: &str) -> Result<Self> {
        Self::new(IpfsConfig::with_url(url)).await
    }

    /// Verify connection to IPFS
    pub async fn verify_connection(&self) -> Result<()> {
        let url = format!("{}/api/v0/id", self.config.api_url);
        self.client
            .post(&url)
            .send()
            .await
            .map_err(|e| BlockStoreError::Connection(format!("Failed to connect to IPFS: {}", e)))?;
        Ok(())
    }

    /// Get IPFS node info
    pub async fn node_info(&self) -> Result<NodeInfo> {
        let url = format!("{}/api/v0/id", self.config.api_url);
        let response = self.client.post(&url).send().await?;

        if !response.status().is_success() {
            return Err(BlockStoreError::IpfsApi(format!(
                "Failed to get node info: {}",
                response.status()
            )));
        }

        response
            .json()
            .await
            .map_err(|e| BlockStoreError::IpfsApi(e.to_string()))
    }

    /// Return cached local-node multiaddrs for use as pinning-service `origins`
    /// hints. The first call fetches `/api/v0/id` and caches the result; later
    /// calls are O(1). If the lookup fails, returns an empty vec so callers
    /// can skip the `origins` field without propagating the error. (R3.)
    pub async fn origins(&self) -> Vec<String> {
        // Fast path: already cached from a prior successful lookup.
        if let Some(cached) = self.origins_cache.lock().ok().and_then(|g| g.clone()) {
            return cached;
        }

        // Cold path: fetch node_info. Only cache on success so a cold-start
        // race (IPFS daemon still warming up) doesn't permanently disable the
        // origins hint for this process.
        match self.node_info().await {
            Ok(info) => {
                if let Ok(mut guard) = self.origins_cache.lock() {
                    *guard = Some(info.addresses.clone());
                }
                info.addresses
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "Failed to fetch local IPFS node multiaddrs; pinning requests will omit origins hint this call"
                );
                Vec::new()
            }
        }
    }

    /// Add raw data to IPFS
    #[instrument(skip(self, data), fields(size = data.len()))]
    pub async fn add_raw(&self, data: &[u8]) -> Result<AddResponse> {
        let url = format!(
            "{}/api/v0/add?raw-leaves=true&cid-version=1",
            self.config.api_url
        );

        let part = multipart::Part::bytes(data.to_vec())
            .file_name("data")
            .mime_str("application/octet-stream")
            .map_err(|e| BlockStoreError::IpfsApi(e.to_string()))?;

        let form = multipart::Form::new().part("file", part);

        let response = self.client.post(&url).multipart(form).send().await?;

        if !response.status().is_success() {
            let error = response.text().await.unwrap_or_default();
            return Err(BlockStoreError::IpfsApi(format!(
                "Failed to add data: {}",
                error
            )));
        }

        response
            .json()
            .await
            .map_err(|e| BlockStoreError::IpfsApi(e.to_string()))
    }

    /// Get block by CID
    ///
    /// For raw blocks (codec 0x55), uses /api/v0/block/get directly.
    /// For UnixFS/dag-pb blocks (codec 0x70), uses /api/v0/cat to traverse
    /// the DAG and return the complete file content.
    #[instrument(skip(self))]
    pub async fn get_block_raw(&self, cid: &Cid) -> Result<Bytes> {
        // DAG-PB codec (0x70) indicates a UnixFS file that may have been chunked.
        // We must use /api/v0/cat to traverse the DAG and get the full content.
        // Using block/get on a dag-pb CID returns only the protobuf metadata, not the file.
        const DAG_PB_CODEC: u64 = 0x70;

        if cid.codec() == DAG_PB_CODEC {
            return self.cat_unixfs(cid).await;
        }

        let url = format!("{}/api/v0/block/get?arg={}", self.config.api_url, cid);

        let response = self.client.post(&url).send().await?;

        if !response.status().is_success() {
            if response.status().as_u16() == 404 {
                return Err(BlockStoreError::NotFound(*cid));
            }
            let error = response.text().await.unwrap_or_default();
            return Err(BlockStoreError::IpfsApi(format!(
                "Failed to get block: {}",
                error
            )));
        }

        response
            .bytes()
            .await
            .map_err(|e| BlockStoreError::IpfsApi(e.to_string()))
    }

    /// Retrieve UnixFS content by traversing the DAG
    ///
    /// Uses /api/v0/cat which automatically handles chunked files by
    /// following links in the DAG structure and reassembling the content.
    #[instrument(skip(self))]
    async fn cat_unixfs(&self, cid: &Cid) -> Result<Bytes> {
        let url = format!("{}/api/v0/cat?arg={}", self.config.api_url, cid);

        let response = self.client.post(&url).send().await?;

        if !response.status().is_success() {
            if response.status().as_u16() == 404 {
                return Err(BlockStoreError::NotFound(*cid));
            }
            let error = response.text().await.unwrap_or_default();
            return Err(BlockStoreError::IpfsApi(format!(
                "Failed to cat UnixFS content: {}",
                error
            )));
        }

        response
            .bytes()
            .await
            .map_err(|e| BlockStoreError::IpfsApi(e.to_string()))
    }

    /// Put a raw block
    /// Note: Raw blocks (file chunks) are NOT pinned inline to avoid timeouts.
    /// They are protected by the bucket root's recursive pin after flush_forest.
    /// 
    /// IMPORTANT: IPFS has a 1MB block limit. Data larger than ~1MB is automatically
    /// stored using UnixFS chunking via /api/v0/add instead of /api/v0/block/put.
    #[instrument(skip(self, data), fields(size = data.len()))]
    pub async fn put_block_raw(&self, data: &[u8]) -> Result<Cid> {
        // IPFS block/put has a 1MB limit. Use UnixFS add for larger data.
        // This is handled gracefully - retrieval uses /api/v0/cat for dag-pb CIDs.
        if data.len() > MAX_BLOCK_SIZE {
            debug!(
                size = data.len(),
                max = MAX_BLOCK_SIZE,
                "Data exceeds IPFS block limit, using UnixFS chunking"
            );
            return self.add_with_unixfs(data).await;
        }

        // Don't pin raw blocks inline - even small blocks can cause timeouts under load.
        // All blocks are protected by recursive pinning of the bucket root CID at flush time.
        let url = format!(
            "{}/api/v0/block/put?cid-codec=raw&mhtype=blake3",
            self.config.api_url,
        );

        let part = multipart::Part::bytes(data.to_vec())
            .file_name("data")
            .mime_str("application/octet-stream")
            .map_err(|e| BlockStoreError::IpfsApi(e.to_string()))?;

        let form = multipart::Form::new().part("data", part);

        let response = self.client.post(&url).multipart(form).send().await?;

        if !response.status().is_success() {
            let error = response.text().await.unwrap_or_default();
            return Err(BlockStoreError::IpfsApi(format!(
                "Failed to put block: {}",
                error
            )));
        }

        let result: BlockPutResponse = response
            .json()
            .await
            .map_err(|e| BlockStoreError::IpfsApi(e.to_string()))?;

        result.key.parse().map_err(|e: cid::Error| {
            BlockStoreError::InvalidCid(e.to_string())
        })
    }

    /// Add data using UnixFS (automatic chunking for large files)
    /// This uses /api/v0/add which handles files of any size by splitting
    /// them into chunks and creating a DAG structure.
    #[instrument(skip(self, data), fields(size = data.len()))]
    async fn add_with_unixfs(&self, data: &[u8]) -> Result<Cid> {
        // Use raw-leaves and CIDv1 for consistency with block/put
        // chunker=size-262144 creates 256KB chunks (well under 1MB limit)
        let url = format!(
            "{}/api/v0/add?raw-leaves=true&cid-version=1&chunker=size-262144&pin=false",
            self.config.api_url
        );

        let part = multipart::Part::bytes(data.to_vec())
            .file_name("data")
            .mime_str("application/octet-stream")
            .map_err(|e| BlockStoreError::IpfsApi(e.to_string()))?;

        let form = multipart::Form::new().part("file", part);

        let response = self.client.post(&url).multipart(form).send().await?;

        if !response.status().is_success() {
            let error = response.text().await.unwrap_or_default();
            return Err(BlockStoreError::IpfsApi(format!(
                "Failed to add data with UnixFS: {}",
                error
            )));
        }

        let result: AddResponse = response
            .json()
            .await
            .map_err(|e| BlockStoreError::IpfsApi(e.to_string()))?;

        result.hash.parse().map_err(|e: cid::Error| {
            BlockStoreError::InvalidCid(e.to_string())
        })
    }

    /// Get block stat (size)
    pub async fn block_stat(&self, cid: &Cid) -> Result<BlockStat> {
        let url = format!("{}/api/v0/block/stat?arg={}", self.config.api_url, cid);
        
        let response = self.client.post(&url).send().await?;

        if !response.status().is_success() {
            if response.status().as_u16() == 404 {
                return Err(BlockStoreError::NotFound(*cid));
            }
            let error = response.text().await.unwrap_or_default();
            return Err(BlockStoreError::IpfsApi(format!(
                "Failed to get block stat: {}",
                error
            )));
        }

        response
            .json()
            .await
            .map_err(|e| BlockStoreError::IpfsApi(e.to_string()))
    }

    /// Remove a block
    pub async fn remove_block(&self, cid: &Cid) -> Result<()> {
        let url = format!("{}/api/v0/block/rm?arg={}", self.config.api_url, cid);

        let response = self.client.post(&url).send().await?;

        if !response.status().is_success() {
            let error = response.text().await.unwrap_or_default();
            return Err(BlockStoreError::IpfsApi(format!(
                "Failed to remove block: {}",
                error
            )));
        }

        Ok(())
    }

    // ========================================================================
    // Cluster-aware read fallback primitives
    //
    // These power `cluster_fallback::ClusterFallbackBlockStore`. They give the
    // fallback layer (a) instant local-miss detection without paying the shared
    // 30s bitswap timeout (`offline=true`), (b) per-request-bounded online
    // fetches (explicit `.timeout(..)` overriding the client's 30s), and
    // (c) the swarm primitives to connect/keep-connected the gateway kubo to
    // the cluster nodes that actually hold a CID.
    // ========================================================================

    /// Construct without the startup `verify_connection` probe — for internal
    /// reuse (e.g. the cluster-fallback layer) where the caller already holds a
    /// verified handle to the same daemon.
    pub fn new_unverified(config: IpfsConfig) -> Result<Self> {
        let client = Client::builder()
            .timeout(config.timeout)
            .build()
            .map_err(|e| BlockStoreError::Connection(e.to_string()))?;
        Ok(Self {
            client,
            config,
            origins_cache: Arc::new(StdMutex::new(None)),
        })
    }

    /// Shared bytes fetch with an explicit per-request `timeout`. When
    /// `offline`, any non-success status OR transport failure maps to
    /// `NotFound` — a local miss is the expected, non-exceptional outcome of an
    /// `offline=true` probe, not an error to surface.
    async fn fetch_bytes_bounded(
        &self,
        url: &str,
        timeout: Duration,
        cid: &Cid,
        offline: bool,
    ) -> Result<Bytes> {
        let response = match self.client.post(url).timeout(timeout).send().await {
            Ok(r) => r,
            Err(e) => {
                if offline {
                    return Err(BlockStoreError::NotFound(*cid));
                }
                return Err(e.into());
            }
        };

        if !response.status().is_success() {
            if offline || response.status().as_u16() == 404 {
                return Err(BlockStoreError::NotFound(*cid));
            }
            let error = response.text().await.unwrap_or_default();
            return Err(BlockStoreError::IpfsApi(format!("Failed to get block: {}", error)));
        }

        response
            .bytes()
            .await
            .map_err(|e| BlockStoreError::IpfsApi(e.to_string()))
    }

    /// Codec-aware fetch reading the LOCAL datastore only (`offline=true`):
    /// instant hit, or instant `NotFound` on a miss — never bitswaps. Mirrors
    /// `get_block_raw`'s codec branch (cat for dag-pb, block/get otherwise).
    pub async fn get_block_offline(&self, cid: &Cid, timeout: Duration) -> Result<Bytes> {
        const DAG_PB_CODEC: u64 = 0x70;
        let url = if cid.codec() == DAG_PB_CODEC {
            format!("{}/api/v0/cat?arg={}&offline=true", self.config.api_url, cid)
        } else {
            format!("{}/api/v0/block/get?arg={}&offline=true", self.config.api_url, cid)
        };
        self.fetch_bytes_bounded(&url, timeout, cid, true).await
    }

    /// Codec-aware online fetch (bitswap allowed) bounded by `timeout` instead
    /// of the shared 30s client timeout.
    pub async fn get_block_online_bounded(&self, cid: &Cid, timeout: Duration) -> Result<Bytes> {
        const DAG_PB_CODEC: u64 = 0x70;
        let url = if cid.codec() == DAG_PB_CODEC {
            format!("{}/api/v0/cat?arg={}", self.config.api_url, cid)
        } else {
            format!("{}/api/v0/block/get?arg={}", self.config.api_url, cid)
        };
        self.fetch_bytes_bounded(&url, timeout, cid, false).await
    }

    /// Raw `block/get` of a single block, LOCAL only (`offline=true`), bounded.
    /// IPLD nodes (dag-cbor) are always single blocks, so no cat traversal.
    pub async fn get_raw_block_offline(&self, cid: &Cid, timeout: Duration) -> Result<Bytes> {
        let url = format!("{}/api/v0/block/get?arg={}&offline=true", self.config.api_url, cid);
        self.fetch_bytes_bounded(&url, timeout, cid, true).await
    }

    /// Raw `block/get` of a single block, online (bitswap), bounded.
    pub async fn get_raw_block_online_bounded(&self, cid: &Cid, timeout: Duration) -> Result<Bytes> {
        let url = format!("{}/api/v0/block/get?arg={}", self.config.api_url, cid);
        self.fetch_bytes_bounded(&url, timeout, cid, false).await
    }

    /// Best-effort `swarm/connect` to a peer multiaddr. Never errors — returns
    /// `true` on a 2xx, `false` on timeout / undialable / API error.
    pub async fn swarm_connect(&self, multiaddr: &str, timeout: Duration) -> bool {
        let url = format!(
            "{}/api/v0/swarm/connect?arg={}",
            self.config.api_url,
            urlencoding::encode(multiaddr)
        );
        match self.client.post(&url).timeout(timeout).send().await {
            Ok(r) => r.status().is_success(),
            Err(_) => false,
        }
    }

    /// Best-effort `swarm/peering/add` — registers a peer so kubo *maintains*
    /// and auto-reconnects the connection. Returns `true` on a 2xx.
    pub async fn swarm_peering_add(&self, multiaddr: &str, timeout: Duration) -> bool {
        let url = format!(
            "{}/api/v0/swarm/peering/add?arg={}",
            self.config.api_url,
            urlencoding::encode(multiaddr)
        );
        match self.client.post(&url).timeout(timeout).send().await {
            Ok(r) => r.status().is_success(),
            Err(_) => false,
        }
    }
}

#[async_trait]
impl BlockStore for IpfsBlockStore {
    async fn put_block(&self, data: &[u8]) -> Result<Cid> {
        self.put_block_raw(data).await
    }

    async fn get_block(&self, cid: &Cid) -> Result<Bytes> {
        self.get_block_raw(cid).await
    }

    async fn has_block(&self, cid: &Cid) -> Result<bool> {
        match self.block_stat(cid).await {
            Ok(_) => Ok(true),
            Err(BlockStoreError::NotFound(_)) => Ok(false),
            Err(e) => Err(e),
        }
    }

    async fn delete_block(&self, cid: &Cid) -> Result<()> {
        self.remove_block(cid).await
    }

    async fn block_size(&self, cid: &Cid) -> Result<u64> {
        let stat = self.block_stat(cid).await?;
        Ok(stat.size)
    }

    #[instrument(skip(self, data))]
    async fn put_ipld<T: serde::Serialize + Send + Sync>(&self, data: &T) -> Result<Cid> {
        let bytes = serde_ipld_dagcbor::to_vec(data)
            .map_err(|e| BlockStoreError::Serialization(e.to_string()))?;
        
        tracing::debug!(bytes_len = bytes.len(), "Serialized IPLD data to CBOR");
        
        // Don't pin inline - it delays the response body and causes timeouts.
        // All data is protected by bucket root recursive pin at flush_forest time.
        let url = format!(
            "{}/api/v0/dag/put?store-codec=dag-cbor&input-codec=dag-cbor",
            self.config.api_url
        );

        let part = multipart::Part::bytes(bytes)
            .file_name("data")
            .mime_str("application/octet-stream")
            .map_err(|e| BlockStoreError::IpfsApi(e.to_string()))?;

        let form = multipart::Form::new().part("file", part);

        tracing::debug!(url = %url, "Sending dag/put request to IPFS");
        
        let response = self.client.post(&url).multipart(form).send().await?;
        
        tracing::debug!(status = %response.status(), "Received response from IPFS");

        if !response.status().is_success() {
            let error = response.text().await.unwrap_or_default();
            tracing::error!(error = %error, "IPFS dag/put failed");
            return Err(BlockStoreError::IpfsApi(format!(
                "Failed to put DAG: {}",
                error
            )));
        }

        // Read response body as text first for debugging
        let body_text = response.text().await
            .map_err(|e| BlockStoreError::IpfsApi(format!("Failed to read response body: {}", e)))?;
        
        tracing::debug!(body = %body_text, "IPFS dag/put response body");
        
        let result: DagPutResponse = serde_json::from_str(&body_text)
            .map_err(|e| BlockStoreError::IpfsApi(format!("Failed to parse response: {} - body: {}", e, body_text)))?;

        tracing::debug!(cid = %result.cid.root_cid, "DAG stored successfully");
        
        result.cid.root_cid.parse().map_err(|e: cid::Error| {
            BlockStoreError::InvalidCid(e.to_string())
        })
    }

    #[instrument(skip(self))]
    async fn get_ipld<T: serde::de::DeserializeOwned>(&self, cid: &Cid) -> Result<T> {
        // Request CBOR output to match what we stored
        let url = format!(
            "{}/api/v0/block/get?arg={}",
            self.config.api_url, cid
        );
        
        tracing::debug!(url = %url, cid = %cid, "Fetching IPLD block");
        
        let response = self.client.post(&url).send().await?;

        if !response.status().is_success() {
            if response.status().as_u16() == 404 {
                return Err(BlockStoreError::NotFound(*cid));
            }
            let error = response.text().await.unwrap_or_default();
            tracing::error!(error = %error, "Failed to get IPLD block");
            return Err(BlockStoreError::IpfsApi(format!(
                "Failed to get DAG: {}",
                error
            )));
        }

        let bytes = response.bytes().await
            .map_err(|e| BlockStoreError::IpfsApi(e.to_string()))?;
        
        tracing::debug!(bytes_len = bytes.len(), "Retrieved IPLD block, deserializing from CBOR");
        
        // Deserialize from DAG-CBOR (matches what we stored)
        serde_ipld_dagcbor::from_slice(&bytes)
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to deserialize CBOR");
                BlockStoreError::Deserialization(e.to_string())
            })
    }
}

/// IPFS node information
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct NodeInfo {
    #[serde(rename = "ID")]
    pub id: String,
    pub public_key: String,
    pub addresses: Vec<String>,
    pub agent_version: String,
    pub protocol_version: String,
}

/// Response from /api/v0/add
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct AddResponse {
    pub name: String,
    pub hash: String,
    pub size: String,
}

/// Response from /api/v0/block/put
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct BlockPutResponse {
    pub key: String,
    pub size: u64,
}

/// Block statistics
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct BlockStat {
    pub key: String,
    pub size: u64,
}

/// Response from /api/v0/dag/put
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct DagPutResponse {
    pub cid: DagCid,
}

#[derive(Debug, Deserialize)]
pub struct DagCid {
    #[serde(rename = "/")]
    pub root_cid: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use httpmock::prelude::*;
    use serde_json::json;

    #[test]
    fn test_config_default() {
        let config = IpfsConfig::default();
        assert_eq!(config.api_url, "http://localhost:5001");
        assert_eq!(config.timeout, Duration::from_secs(30));
    }

    #[test]
    fn test_config_with_url() {
        let config = IpfsConfig::with_url("http://custom:5001");
        assert_eq!(config.api_url, "http://custom:5001");
    }

    #[tokio::test]
    async fn put_block_uses_block_put_for_small_data() {
        let server = MockServer::start_async().await;

        // Mock /api/v0/id probe
        let _id_mock = server
            .mock_async(|when, then| {
                when.method(POST).path("/api/v0/id");
                then.status(200).body("{}");
            })
            .await;

        // Expect block/put to be called for small payloads
        let block_put = server
            .mock_async(|when, then| {
                when.method(POST)
                    .path("/api/v0/block/put")
                    .query_param("cid-codec", "raw")
                    .query_param("mhtype", "blake3");
                then.status(200).json_body(json!({
                    "Key": "bafkreigh2akiscaildc6v5q2xg34x5sqo5djznnha64x4jn3fjvu3j6jci",
                    "Size": 5,
                }));
            })
            .await;

        let store = IpfsBlockStore::new(IpfsConfig::with_url(server.base_url()))
            .await
            .expect("ipfs store init");

        let _ = store.put_block(b"hello").await.expect("block put");

        block_put.assert_hits_async(1).await;
    }

    #[tokio::test]
    async fn put_block_uses_unixfs_add_for_large_data() {
        let server = MockServer::start_async().await;

        // Mock /api/v0/id probe
        let _id_mock = server
            .mock_async(|when, then| {
                when.method(POST).path("/api/v0/id");
                then.status(200).body("{}");
            })
            .await;

        // Expect /api/v0/add when payload exceeds MAX_BLOCK_SIZE
        let add_mock = server
            .mock_async(|when, then| {
                when.method(POST)
                    .path("/api/v0/add")
                    .query_param("raw-leaves", "true")
                    .query_param("cid-version", "1")
                    .query_param("chunker", "size-262144")
                    .query_param("pin", "false");
                then.status(200).json_body(json!({
                    "Name": "data",
                    "Hash": "bafkreigh2akiscaildc6v5q2xg34x5sqo5djznnha64x4jn3fjvu3j6jci",
                    "Size": "1049000",
                }));
            })
            .await;

        let store = IpfsBlockStore::new(IpfsConfig::with_url(server.base_url()))
            .await
            .expect("ipfs store init");

        let large = vec![0u8; MAX_BLOCK_SIZE + 10];
        let _ = store.put_block(&large).await.expect("unixfs add");

        add_mock.assert_hits_async(1).await;
    }

    #[tokio::test]
    async fn get_block_uses_block_get_for_raw_cid() {
        let server = MockServer::start_async().await;

        // Mock /api/v0/id probe
        let _id_mock = server
            .mock_async(|when, then| {
                when.method(POST).path("/api/v0/id");
                then.status(200).body("{}");
            })
            .await;

        // Create a raw CID (codec 0x55)
        let raw_cid = "bafkreigh2akiscaildc6v5q2xg34x5sqo5djznnha64x4jn3fjvu3j6jci";

        // Expect block/get to be called for raw CIDs
        let block_get = server
            .mock_async(|when, then| {
                when.method(POST)
                    .path("/api/v0/block/get")
                    .query_param("arg", raw_cid);
                then.status(200).body("hello world");
            })
            .await;

        let store = IpfsBlockStore::new(IpfsConfig::with_url(server.base_url()))
            .await
            .expect("ipfs store init");

        let cid: Cid = raw_cid.parse().expect("parse cid");
        let data = store.get_block(&cid).await.expect("get block");

        assert_eq!(&data[..], b"hello world");
        block_get.assert_hits_async(1).await;
    }

    #[tokio::test]
    async fn get_block_uses_cat_for_dagpb_cid() {
        let server = MockServer::start_async().await;

        // Mock /api/v0/id probe
        let _id_mock = server
            .mock_async(|when, then| {
                when.method(POST).path("/api/v0/id");
                then.status(200).body("{}");
            })
            .await;

        // Create a dag-pb CID (codec 0x70)
        // This is a CIDv1 with dag-pb codec - represents UnixFS chunked file
        let dagpb_cid = "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi";

        // Expect /api/v0/cat to be called for dag-pb CIDs (not block/get)
        let cat_mock = server
            .mock_async(|when, then| {
                when.method(POST)
                    .path("/api/v0/cat")
                    .query_param("arg", dagpb_cid);
                then.status(200).body("large file content reassembled from chunks");
            })
            .await;

        let store = IpfsBlockStore::new(IpfsConfig::with_url(server.base_url()))
            .await
            .expect("ipfs store init");

        let cid: Cid = dagpb_cid.parse().expect("parse cid");
        // Verify this is indeed a dag-pb CID
        assert_eq!(cid.codec(), 0x70, "CID should have dag-pb codec");

        let data = store.get_block(&cid).await.expect("get block via cat");

        assert_eq!(&data[..], b"large file content reassembled from chunks");
        cat_mock.assert_hits_async(1).await;
    }
}
