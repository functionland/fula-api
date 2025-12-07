//! IPFS Cluster client for pinning and replication management

use crate::{BlockStoreError, Result};
use cid::Cid;
use reqwest::{Client, multipart};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::instrument;

/// Configuration for IPFS Cluster connection
#[derive(Clone, Debug)]
pub struct ClusterConfig {
    /// Cluster API URL (e.g., "http://localhost:9094")
    pub api_url: String,
    /// Request timeout
    pub timeout: Duration,
    /// Basic auth credentials (optional)
    pub basic_auth: Option<(String, String)>,
    /// Replication settings
    pub replication: ReplicationFactor,
}

impl Default for ClusterConfig {
    fn default() -> Self {
        Self {
            api_url: "http://localhost:9094".to_string(),
            timeout: Duration::from_secs(60),
            basic_auth: None,
            replication: ReplicationFactor::default(),
        }
    }
}

impl ClusterConfig {
    /// Create with a custom API URL
    pub fn with_url(api_url: impl Into<String>) -> Self {
        Self {
            api_url: api_url.into(),
            ..Default::default()
        }
    }

    /// Set basic auth credentials
    pub fn with_auth(mut self, username: impl Into<String>, password: impl Into<String>) -> Self {
        self.basic_auth = Some((username.into(), password.into()));
        self
    }
}

/// Replication factor settings
#[derive(Clone, Copy, Debug)]
pub struct ReplicationFactor {
    /// Minimum number of replicas
    pub min: i32,
    /// Maximum number of replicas (-1 for all peers)
    pub max: i32,
}

impl Default for ReplicationFactor {
    fn default() -> Self {
        Self { min: 2, max: 3 }
    }
}

impl ReplicationFactor {
    /// Create with specific min/max
    pub fn new(min: i32, max: i32) -> Self {
        Self { min, max }
    }

    /// Replicate to all peers
    pub fn all() -> Self {
        Self { min: -1, max: -1 }
    }
}

/// Pin status in the cluster
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PinStatus {
    /// Pin is being processed
    Pinning,
    /// Pin is complete
    Pinned,
    /// Pin failed
    Error,
    /// Pin is queued
    Queued,
    /// Unpin in progress
    Unpinning,
    /// Not pinned
    Unpinned,
    /// Status unknown
    Unknown,
}

impl Default for PinStatus {
    fn default() -> Self {
        Self::Unknown
    }
}

/// IPFS Cluster client
#[derive(Clone)]
pub struct ClusterClient {
    client: Client,
    config: ClusterConfig,
}

impl ClusterClient {
    /// Create a new cluster client
    pub async fn new(config: ClusterConfig) -> Result<Self> {
        let builder = Client::builder().timeout(config.timeout);

        let client = builder
            .build()
            .map_err(|e| BlockStoreError::Connection(e.to_string()))?;

        let cluster = Self { client, config };
        cluster.verify_connection().await?;
        Ok(cluster)
    }

    /// Create with default config
    pub async fn default_local() -> Result<Self> {
        Self::new(ClusterConfig::default()).await
    }

    /// Verify connection to cluster
    pub async fn verify_connection(&self) -> Result<()> {
        let url = format!("{}/id", self.config.api_url);
        let mut req = self.client.get(&url);
        
        if let Some((user, pass)) = &self.config.basic_auth {
            req = req.basic_auth(user, Some(pass));
        }

        req.send()
            .await
            .map_err(|e| BlockStoreError::Connection(format!("Failed to connect to cluster: {}", e)))?;
        Ok(())
    }

    /// Get cluster peer info
    pub async fn peer_info(&self) -> Result<ClusterPeerInfo> {
        let url = format!("{}/id", self.config.api_url);
        let mut req = self.client.get(&url);
        
        if let Some((user, pass)) = &self.config.basic_auth {
            req = req.basic_auth(user, Some(pass));
        }

        let response = req.send().await?;
        
        if !response.status().is_success() {
            return Err(BlockStoreError::ClusterApi(format!(
                "Failed to get peer info: {}",
                response.status()
            )));
        }

        response
            .json()
            .await
            .map_err(|e| BlockStoreError::ClusterApi(e.to_string()))
    }

    /// List all peers in the cluster
    pub async fn list_peers(&self) -> Result<Vec<ClusterPeerInfo>> {
        let url = format!("{}/peers", self.config.api_url);
        let mut req = self.client.get(&url);
        
        if let Some((user, pass)) = &self.config.basic_auth {
            req = req.basic_auth(user, Some(pass));
        }

        let response = req.send().await?;
        
        if !response.status().is_success() {
            return Err(BlockStoreError::ClusterApi(format!(
                "Failed to list peers: {}",
                response.status()
            )));
        }

        response
            .json()
            .await
            .map_err(|e| BlockStoreError::ClusterApi(e.to_string()))
    }

    /// Pin a CID in the cluster
    #[instrument(skip(self))]
    pub async fn pin_cid(&self, cid: &Cid, name: Option<&str>) -> Result<PinInfo> {
        let mut url = format!(
            "{}/pins/{}?replication-min={}&replication-max={}",
            self.config.api_url,
            cid,
            self.config.replication.min,
            self.config.replication.max
        );

        if let Some(n) = name {
            url.push_str(&format!("&name={}", urlencoding::encode(n)));
        }

        let mut req = self.client.post(&url);
        
        if let Some((user, pass)) = &self.config.basic_auth {
            req = req.basic_auth(user, Some(pass));
        }

        let response = req.send().await?;
        
        if !response.status().is_success() {
            let error = response.text().await.unwrap_or_default();
            return Err(BlockStoreError::PinFailed(format!(
                "Failed to pin {}: {}",
                cid, error
            )));
        }

        response
            .json()
            .await
            .map_err(|e| BlockStoreError::ClusterApi(e.to_string()))
    }

    /// Unpin a CID from the cluster
    #[instrument(skip(self))]
    pub async fn unpin_cid(&self, cid: &Cid) -> Result<PinInfo> {
        let url = format!("{}/pins/{}", self.config.api_url, cid);
        let mut req = self.client.delete(&url);
        
        if let Some((user, pass)) = &self.config.basic_auth {
            req = req.basic_auth(user, Some(pass));
        }

        let response = req.send().await?;
        
        if !response.status().is_success() {
            let error = response.text().await.unwrap_or_default();
            return Err(BlockStoreError::UnpinFailed(format!(
                "Failed to unpin {}: {}",
                cid, error
            )));
        }

        response
            .json()
            .await
            .map_err(|e| BlockStoreError::ClusterApi(e.to_string()))
    }

    /// Get pin status for a CID
    pub async fn get_pin_status(&self, cid: &Cid) -> Result<PinInfo> {
        let url = format!("{}/pins/{}", self.config.api_url, cid);
        let mut req = self.client.get(&url);
        
        if let Some((user, pass)) = &self.config.basic_auth {
            req = req.basic_auth(user, Some(pass));
        }

        let response = req.send().await?;
        
        if !response.status().is_success() {
            if response.status().as_u16() == 404 {
                return Err(BlockStoreError::NotFound(*cid));
            }
            let error = response.text().await.unwrap_or_default();
            return Err(BlockStoreError::ClusterApi(format!(
                "Failed to get pin status: {}",
                error
            )));
        }

        response
            .json()
            .await
            .map_err(|e| BlockStoreError::ClusterApi(e.to_string()))
    }

    /// List all pins
    pub async fn list_pins(&self) -> Result<Vec<PinInfo>> {
        let url = format!("{}/pins", self.config.api_url);
        let mut req = self.client.get(&url);
        
        if let Some((user, pass)) = &self.config.basic_auth {
            req = req.basic_auth(user, Some(pass));
        }

        let response = req.send().await?;
        
        if !response.status().is_success() {
            let error = response.text().await.unwrap_or_default();
            return Err(BlockStoreError::ClusterApi(format!(
                "Failed to list pins: {}",
                error
            )));
        }

        // The response is newline-delimited JSON
        let text = response.text().await?;
        let mut pins = Vec::new();
        
        for line in text.lines() {
            if !line.is_empty() {
                let pin: PinInfo = serde_json::from_str(line)
                    .map_err(|e| BlockStoreError::ClusterApi(e.to_string()))?;
                pins.push(pin);
            }
        }

        Ok(pins)
    }

    /// Add and pin data in one operation
    #[instrument(skip(self, data), fields(size = data.len()))]
    pub async fn add_and_pin(&self, data: &[u8], name: Option<&str>) -> Result<AddPinResponse> {
        let mut url = format!(
            "{}/add?replication-min={}&replication-max={}&cid-version=1",
            self.config.api_url,
            self.config.replication.min,
            self.config.replication.max
        );

        if let Some(n) = name {
            url.push_str(&format!("&name={}", urlencoding::encode(n)));
        }

        let part = multipart::Part::bytes(data.to_vec())
            .file_name("data")
            .mime_str("application/octet-stream")
            .map_err(|e| BlockStoreError::ClusterApi(e.to_string()))?;

        let form = multipart::Form::new().part("file", part);

        let mut req = self.client.post(&url).multipart(form);
        
        if let Some((user, pass)) = &self.config.basic_auth {
            req = req.basic_auth(user, Some(pass));
        }

        let response = req.send().await?;
        
        if !response.status().is_success() {
            let error = response.text().await.unwrap_or_default();
            return Err(BlockStoreError::ClusterApi(format!(
                "Failed to add and pin: {}",
                error
            )));
        }

        response
            .json()
            .await
            .map_err(|e| BlockStoreError::ClusterApi(e.to_string()))
    }

    /// Recover a pin (re-trigger pinning on failed peers)
    pub async fn recover_pin(&self, cid: &Cid) -> Result<PinInfo> {
        let url = format!("{}/pins/{}/recover", self.config.api_url, cid);
        let mut req = self.client.post(&url);
        
        if let Some((user, pass)) = &self.config.basic_auth {
            req = req.basic_auth(user, Some(pass));
        }

        let response = req.send().await?;
        
        if !response.status().is_success() {
            let error = response.text().await.unwrap_or_default();
            return Err(BlockStoreError::ClusterApi(format!(
                "Failed to recover pin: {}",
                error
            )));
        }

        response
            .json()
            .await
            .map_err(|e| BlockStoreError::ClusterApi(e.to_string()))
    }
}

/// Cluster peer information
#[derive(Clone, Debug, Deserialize)]
pub struct ClusterPeerInfo {
    pub id: String,
    pub addresses: Vec<String>,
    pub cluster_peers: Option<Vec<String>>,
    pub cluster_peers_addresses: Option<Vec<String>>,
    pub version: Option<String>,
    pub commit: Option<String>,
    pub peername: Option<String>,
    #[serde(default)]
    pub ipfs: Option<IpfsPeerInfo>,
}

/// IPFS peer info within cluster
#[derive(Clone, Debug, Deserialize)]
pub struct IpfsPeerInfo {
    pub id: Option<String>,
    pub addresses: Option<Vec<String>>,
}

/// Pin information
#[derive(Clone, Debug, Deserialize)]
pub struct PinInfo {
    pub cid: String,
    pub name: Option<String>,
    pub allocations: Option<Vec<String>>,
    pub origins: Option<Vec<String>>,
    pub created: Option<String>,
    pub metadata: Option<serde_json::Value>,
    pub peer_map: Option<std::collections::HashMap<String, PeerPinStatus>>,
}

/// Per-peer pin status
#[derive(Clone, Debug, Deserialize)]
pub struct PeerPinStatus {
    pub peername: Option<String>,
    pub status: String,
    pub timestamp: Option<String>,
    pub error: Option<String>,
}

/// Response from add and pin
#[derive(Clone, Debug, Deserialize)]
pub struct AddPinResponse {
    pub name: String,
    pub cid: String,
    pub size: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = ClusterConfig::default();
        assert_eq!(config.api_url, "http://localhost:9094");
        assert!(config.basic_auth.is_none());
    }

    #[test]
    fn test_config_with_auth() {
        let config = ClusterConfig::with_url("http://cluster:9094")
            .with_auth("user", "pass");
        assert_eq!(config.basic_auth, Some(("user".to_string(), "pass".to_string())));
    }

    #[test]
    fn test_replication_factor() {
        let default = ReplicationFactor::default();
        assert_eq!(default.min, 2);
        assert_eq!(default.max, 3);

        let all = ReplicationFactor::all();
        assert_eq!(all.min, -1);
        assert_eq!(all.max, -1);
    }

    #[test]
    fn test_pin_status_default() {
        let status = PinStatus::default();
        assert_eq!(status, PinStatus::Unknown);
    }
}
