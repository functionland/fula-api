//! Per-user pinning service support
//!
//! Users provide their own pinning service credentials via request headers:
//! - `X-Pinning-Service`: Pinning service endpoint URL
//! - `X-Pinning-Token`: Bearer token for authentication
//!
//! This allows each user to pin data to their own preferred pinning service
//! (Pinata, Web3.Storage, etc.) without the gateway storing credentials.

use axum::http::HeaderMap;
use cid::Cid;
use fula_blockstore::{Pin, PinningServiceClient, PinningServiceConfig};
use tracing::{info, warn};

/// Header name for pinning service endpoint
pub const HEADER_PINNING_SERVICE: &str = "x-pinning-service";

/// Header name for pinning service token
pub const HEADER_PINNING_TOKEN: &str = "x-pinning-token";

/// Extracted pinning credentials from request headers
#[derive(Debug, Clone)]
pub struct PinningCredentials {
    /// Pinning service endpoint URL
    pub endpoint: String,
    /// Bearer token for authentication
    pub token: String,
    /// Optional name for the pin
    pub name: Option<String>,
}

impl PinningCredentials {
    /// Extract pinning credentials from request headers
    ///
    /// Returns None if headers are not present (pinning not requested)
    pub fn from_headers(headers: &HeaderMap) -> Option<Self> {
        let endpoint = headers
            .get(HEADER_PINNING_SERVICE)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())?;

        let token = headers
            .get(HEADER_PINNING_TOKEN)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())?;

        // Optional: pin name from x-pinning-name header
        let name = headers
            .get("x-pinning-name")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        Some(Self {
            endpoint,
            token,
            name,
        })
    }

    /// Create a pinning service client from these credentials
    pub fn create_client(&self) -> Result<PinningServiceClient, fula_blockstore::BlockStoreError> {
        let config = PinningServiceConfig::new(&self.endpoint, &self.token);
        PinningServiceClient::new(config)
    }
}

/// Pin a CID to the user's pinning service (if credentials provided)
///
/// This is a fire-and-forget operation - pinning happens asynchronously
/// and errors are logged but don't fail the main request.
pub async fn pin_for_user(headers: &HeaderMap, cid: &Cid, object_key: Option<&str>) {
    // Debug: log all headers to see what we received
    tracing::debug!("pin_for_user called with {} headers", headers.len());
    for (name, value) in headers.iter() {
        if name.as_str().starts_with("x-pinning") {
            tracing::debug!(header_name = %name, header_value = ?value, "Found pinning header");
        }
    }
    
    if let Some(creds) = PinningCredentials::from_headers(headers) {
        tracing::info!(
            endpoint = %creds.endpoint,
            "Remote pinning credentials found, will pin to user's service"
        );
        // Spawn a task to pin asynchronously (don't block the response)
        let cid = *cid;
        let name = object_key.map(|s| s.to_string()).or(creds.name.clone());
        let endpoint = creds.endpoint.clone();
        
        tokio::spawn(async move {
            match creds.create_client() {
                Ok(client) => {
                    let pin = if let Some(n) = name {
                        Pin::new(cid.to_string()).with_name(n)
                    } else {
                        Pin::new(cid.to_string())
                    };

                    match client.add_pin(pin).await {
                        Ok(status) => {
                            info!(
                                cid = %cid,
                                request_id = %status.request_id,
                                service = %endpoint,
                                "CID pinned to user's pinning service"
                            );
                        }
                        Err(e) => {
                            warn!(
                                cid = %cid,
                                service = %endpoint,
                                error = %e,
                                "Failed to pin to user's pinning service"
                            );
                        }
                    }
                }
                Err(e) => {
                    warn!(
                        service = %endpoint,
                        error = %e,
                        "Failed to create pinning client"
                    );
                }
            }
        });
    } else {
        tracing::debug!("No pinning credentials in headers, skipping remote pinning");
    }
}

/// Unpin a CID from the user's pinning service (if credentials provided)
pub async fn unpin_for_user(headers: &HeaderMap, cid: &Cid) {
    if let Some(creds) = PinningCredentials::from_headers(headers) {
        let cid = *cid;

        tokio::spawn(async move {
            match creds.create_client() {
                Ok(client) => {
                    // Find the pin by CID and delete it
                    match client.get_pin_by_cid(&cid.to_string()).await {
                        Ok(Some(status)) => {
                            if let Err(e) = client.delete_pin(&status.request_id).await {
                                warn!(
                                    cid = %cid,
                                    error = %e,
                                    "Failed to unpin from user's pinning service"
                                );
                            } else {
                                info!(cid = %cid, "CID unpinned from user's pinning service");
                            }
                        }
                        Ok(None) => {
                            // Not pinned, nothing to do
                        }
                        Err(e) => {
                            warn!(
                                cid = %cid,
                                error = %e,
                                "Failed to find pin in user's pinning service"
                            );
                        }
                    }
                }
                Err(e) => {
                    warn!(error = %e, "Failed to create pinning client for unpin");
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn test_extract_credentials() {
        let mut headers = HeaderMap::new();
        headers.insert(
            HEADER_PINNING_SERVICE,
            HeaderValue::from_static("https://api.pinata.cloud/psa"),
        );
        headers.insert(
            HEADER_PINNING_TOKEN,
            HeaderValue::from_static("test-token-123"),
        );

        let creds = PinningCredentials::from_headers(&headers).unwrap();
        assert_eq!(creds.endpoint, "https://api.pinata.cloud/psa");
        assert_eq!(creds.token, "test-token-123");
    }

    #[test]
    fn test_missing_credentials() {
        let headers = HeaderMap::new();
        assert!(PinningCredentials::from_headers(&headers).is_none());
    }

    #[test]
    fn test_partial_credentials() {
        let mut headers = HeaderMap::new();
        headers.insert(
            HEADER_PINNING_SERVICE,
            HeaderValue::from_static("https://api.pinata.cloud/psa"),
        );
        // Missing token
        assert!(PinningCredentials::from_headers(&headers).is_none());
    }
}
