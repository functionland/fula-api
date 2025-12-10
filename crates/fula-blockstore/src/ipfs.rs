//! IPFS HTTP API client for block operations

use crate::{BlockStore, BlockStoreError, Result};
use async_trait::async_trait;
use bytes::Bytes;
use cid::Cid;
use reqwest::{Client, multipart};
use serde::Deserialize;
use std::time::Duration;
use tracing::instrument;

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
}

impl IpfsBlockStore {
    /// Create a new IPFS block store
    pub async fn new(config: IpfsConfig) -> Result<Self> {
        let client = Client::builder()
            .timeout(config.timeout)
            .build()
            .map_err(|e| BlockStoreError::Connection(e.to_string()))?;

        let store = Self { client, config };
        
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
    #[instrument(skip(self))]
    pub async fn get_block_raw(&self, cid: &Cid) -> Result<Bytes> {
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

    /// Put a raw block
    /// Note: Raw blocks (file chunks) are NOT pinned inline to avoid timeouts.
    /// They are protected by the bucket root's recursive pin after flush_forest.
    #[instrument(skip(self, data), fields(size = data.len()))]
    pub async fn put_block_raw(&self, data: &[u8]) -> Result<Cid> {
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
}
