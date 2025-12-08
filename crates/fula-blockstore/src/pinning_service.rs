//! IPFS Pinning Service API client (standard spec)
//!
//! Implements the standard IPFS Pinning Service API:
//! https://ipfs.github.io/pinning-services-api-spec/
//!
//! This allows the gateway to work with any pinning service that implements
//! the standard API (Pinata, Web3.Storage, Infura, etc.)

use crate::{BlockStoreError, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use tracing::instrument;

/// Configuration for IPFS Pinning Service
#[derive(Clone, Debug)]
pub struct PinningServiceConfig {
    /// Pinning service API endpoint (e.g., "https://api.pinata.cloud/psa")
    pub endpoint: String,
    /// Bearer token for authentication
    pub access_token: String,
    /// Request timeout
    pub timeout: Duration,
    /// Maximum retries for failed requests
    pub max_retries: u32,
}

impl PinningServiceConfig {
    /// Create a new pinning service config
    pub fn new(endpoint: impl Into<String>, access_token: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            access_token: access_token.into(),
            timeout: Duration::from_secs(60),
            max_retries: 3,
        }
    }

    /// Set timeout
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

/// Pin status values as per the spec
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PinningStatus {
    /// Pin is in the queue waiting to be processed
    Queued,
    /// Pin is actively being retrieved from the network
    Pinning,
    /// Pin is complete and data is stored
    Pinned,
    /// Pin operation failed
    Failed,
}

impl Default for PinningStatus {
    fn default() -> Self {
        Self::Queued
    }
}

/// Pin object - represents a pin request
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Pin {
    /// CID to be pinned
    pub cid: String,
    /// Optional name for the pin
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Optional list of multiaddrs known to provide the data
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origins: Option<Vec<String>>,
    /// Optional metadata
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<HashMap<String, String>>,
}

impl Pin {
    /// Create a new pin request
    pub fn new(cid: impl Into<String>) -> Self {
        Self {
            cid: cid.into(),
            name: None,
            origins: None,
            meta: None,
        }
    }

    /// Set the pin name
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Add origin addresses
    pub fn with_origins(mut self, origins: Vec<String>) -> Self {
        self.origins = Some(origins);
        self
    }

    /// Add metadata
    pub fn with_meta(mut self, meta: HashMap<String, String>) -> Self {
        self.meta = Some(meta);
        self
    }
}

/// Pin status response - represents the current state of a pin
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PinStatusResponse {
    /// Globally unique identifier of the pin request
    #[serde(rename = "requestid")]
    pub request_id: String,
    /// Current status of the pin
    pub status: PinningStatus,
    /// Timestamp when the pin was created
    pub created: String,
    /// The original pin request
    pub pin: Pin,
    /// List of delegate peers for receiving data via bitswap
    #[serde(default)]
    pub delegates: Vec<String>,
    /// Optional additional info
    #[serde(skip_serializing_if = "Option::is_none")]
    pub info: Option<HashMap<String, String>>,
}

/// Response for listing pins
#[derive(Clone, Debug, Deserialize)]
pub struct PinResults {
    /// Total count of pins matching the query
    pub count: u32,
    /// List of pin status objects
    pub results: Vec<PinStatusResponse>,
}

/// Query parameters for listing pins
#[derive(Clone, Debug, Default, Serialize)]
pub struct ListPinsQuery {
    /// Filter by CID(s)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cid: Option<Vec<String>>,
    /// Filter by name (exact match)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Match mode for name
    #[serde(skip_serializing_if = "Option::is_none", rename = "match")]
    pub name_match: Option<TextMatchingStrategy>,
    /// Filter by status
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<Vec<PinningStatus>>,
    /// Return pins created before this timestamp
    #[serde(skip_serializing_if = "Option::is_none")]
    pub before: Option<String>,
    /// Return pins created after this timestamp
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after: Option<String>,
    /// Maximum number of results
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    /// Metadata filter
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<HashMap<String, String>>,
}

/// Text matching strategy for name filter
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TextMatchingStrategy {
    /// Exact match
    Exact,
    /// Case-insensitive exact match
    Iexact,
    /// Partial match (contains)
    Partial,
    /// Case-insensitive partial match
    Ipartial,
}

/// IPFS Pinning Service client
#[derive(Clone)]
pub struct PinningServiceClient {
    client: Client,
    config: PinningServiceConfig,
}

impl PinningServiceClient {
    /// Create a new pinning service client
    pub fn new(config: PinningServiceConfig) -> Result<Self> {
        let client = Client::builder()
            .timeout(config.timeout)
            .build()
            .map_err(|e| BlockStoreError::Connection(e.to_string()))?;

        Ok(Self { client, config })
    }

    /// Get the authorization header value
    fn auth_header(&self) -> String {
        format!("Bearer {}", self.config.access_token)
    }

    /// Add a new pin
    #[instrument(skip(self, pin), fields(cid = %pin.cid))]
    pub async fn add_pin(&self, pin: Pin) -> Result<PinStatusResponse> {
        let url = format!("{}/pins", self.config.endpoint);

        let response = self
            .client
            .post(&url)
            .header("Authorization", self.auth_header())
            .header("Content-Type", "application/json")
            .json(&pin)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let error = response.text().await.unwrap_or_default();
            return Err(BlockStoreError::PinFailed(format!(
                "Failed to add pin ({}): {}",
                status, error
            )));
        }

        response
            .json()
            .await
            .map_err(|e| BlockStoreError::Deserialization(e.to_string()))
    }

    /// Get pin status by request ID
    #[instrument(skip(self))]
    pub async fn get_pin(&self, request_id: &str) -> Result<PinStatusResponse> {
        let url = format!("{}/pins/{}", self.config.endpoint, request_id);

        let response = self
            .client
            .get(&url)
            .header("Authorization", self.auth_header())
            .send()
            .await?;

        if response.status().as_u16() == 404 {
            return Err(BlockStoreError::PinFailed(format!(
                "Pin not found: {}",
                request_id
            )));
        }

        if !response.status().is_success() {
            let status = response.status();
            let error = response.text().await.unwrap_or_default();
            return Err(BlockStoreError::PinFailed(format!(
                "Failed to get pin ({}): {}",
                status, error
            )));
        }

        response
            .json()
            .await
            .map_err(|e| BlockStoreError::Deserialization(e.to_string()))
    }

    /// List pins with optional filters
    #[instrument(skip(self))]
    pub async fn list_pins(&self, query: Option<ListPinsQuery>) -> Result<PinResults> {
        let url = format!("{}/pins", self.config.endpoint);

        let mut req = self
            .client
            .get(&url)
            .header("Authorization", self.auth_header());

        if let Some(q) = query {
            // Build query string manually for complex types
            let mut params = Vec::new();
            
            if let Some(cids) = q.cid {
                for cid in cids {
                    params.push(("cid".to_string(), cid));
                }
            }
            if let Some(name) = q.name {
                params.push(("name".to_string(), name));
            }
            if let Some(limit) = q.limit {
                params.push(("limit".to_string(), limit.to_string()));
            }
            if let Some(statuses) = q.status {
                for status in statuses {
                    let status_str = match status {
                        PinningStatus::Queued => "queued",
                        PinningStatus::Pinning => "pinning",
                        PinningStatus::Pinned => "pinned",
                        PinningStatus::Failed => "failed",
                    };
                    params.push(("status".to_string(), status_str.to_string()));
                }
            }
            if let Some(before) = q.before {
                params.push(("before".to_string(), before));
            }
            if let Some(after) = q.after {
                params.push(("after".to_string(), after));
            }

            req = req.query(&params);
        }

        let response = req.send().await?;

        if !response.status().is_success() {
            let status = response.status();
            let error = response.text().await.unwrap_or_default();
            return Err(BlockStoreError::PinFailed(format!(
                "Failed to list pins ({}): {}",
                status, error
            )));
        }

        response
            .json()
            .await
            .map_err(|e| BlockStoreError::Deserialization(e.to_string()))
    }

    /// Replace an existing pin
    #[instrument(skip(self, pin), fields(cid = %pin.cid))]
    pub async fn replace_pin(&self, request_id: &str, pin: Pin) -> Result<PinStatusResponse> {
        let url = format!("{}/pins/{}", self.config.endpoint, request_id);

        let response = self
            .client
            .post(&url)
            .header("Authorization", self.auth_header())
            .header("Content-Type", "application/json")
            .json(&pin)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let error = response.text().await.unwrap_or_default();
            return Err(BlockStoreError::PinFailed(format!(
                "Failed to replace pin ({}): {}",
                status, error
            )));
        }

        response
            .json()
            .await
            .map_err(|e| BlockStoreError::Deserialization(e.to_string()))
    }

    /// Delete a pin
    #[instrument(skip(self))]
    pub async fn delete_pin(&self, request_id: &str) -> Result<()> {
        let url = format!("{}/pins/{}", self.config.endpoint, request_id);

        let response = self
            .client
            .delete(&url)
            .header("Authorization", self.auth_header())
            .send()
            .await?;

        // 202 Accepted or 200 OK are both valid
        if !response.status().is_success() && response.status().as_u16() != 202 {
            let status = response.status();
            let error = response.text().await.unwrap_or_default();
            return Err(BlockStoreError::UnpinFailed(format!(
                "Failed to delete pin ({}): {}",
                status, error
            )));
        }

        Ok(())
    }

    /// Check if a CID is pinned
    pub async fn is_pinned(&self, cid: &str) -> Result<bool> {
        let query = ListPinsQuery {
            cid: Some(vec![cid.to_string()]),
            status: Some(vec![PinningStatus::Pinned]),
            limit: Some(1),
            ..Default::default()
        };

        let results = self.list_pins(Some(query)).await?;
        Ok(results.count > 0)
    }

    /// Get pin status for a CID (finds the latest pin request for this CID)
    pub async fn get_pin_by_cid(&self, cid: &str) -> Result<Option<PinStatusResponse>> {
        let query = ListPinsQuery {
            cid: Some(vec![cid.to_string()]),
            limit: Some(1),
            ..Default::default()
        };

        let results = self.list_pins(Some(query)).await?;
        Ok(results.results.into_iter().next())
    }

    /// Wait for a pin to complete (polling)
    #[instrument(skip(self))]
    pub async fn wait_for_pin(
        &self,
        request_id: &str,
        timeout: Duration,
        poll_interval: Duration,
    ) -> Result<PinStatusResponse> {
        let start = std::time::Instant::now();

        loop {
            let status = self.get_pin(request_id).await?;

            match status.status {
                PinningStatus::Pinned => return Ok(status),
                PinningStatus::Failed => {
                    return Err(BlockStoreError::PinFailed(format!(
                        "Pin {} failed: {:?}",
                        request_id, status.info
                    )));
                }
                PinningStatus::Queued | PinningStatus::Pinning => {
                    if start.elapsed() > timeout {
                        return Err(BlockStoreError::Timeout {
                            seconds: timeout.as_secs(),
                        });
                    }
                    tokio::time::sleep(poll_interval).await;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pin_creation() {
        let pin = Pin::new("QmTest123")
            .with_name("test-pin")
            .with_origins(vec!["/ip4/1.2.3.4/tcp/4001".to_string()]);

        assert_eq!(pin.cid, "QmTest123");
        assert_eq!(pin.name, Some("test-pin".to_string()));
        assert!(pin.origins.is_some());
    }

    #[test]
    fn test_config_creation() {
        let config = PinningServiceConfig::new(
            "https://api.pinata.cloud/psa",
            "test-token",
        );

        assert_eq!(config.endpoint, "https://api.pinata.cloud/psa");
        assert_eq!(config.access_token, "test-token");
    }

    #[test]
    fn test_pinning_status_serialization() {
        let status = PinningStatus::Pinned;
        let json = serde_json::to_string(&status).unwrap();
        assert_eq!(json, "\"pinned\"");

        let deserialized: PinningStatus = serde_json::from_str("\"queued\"").unwrap();
        assert_eq!(deserialized, PinningStatus::Queued);
    }
}
