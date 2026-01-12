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
use serde::Deserialize;
use std::time::Duration;
use tracing::{debug, info, warn};

use crate::ApiError;

/// Header name for pinning service endpoint
pub const HEADER_PINNING_SERVICE: &str = "x-pinning-service";
/// S3-compatible metadata header for pinning service endpoint
pub const HEADER_AMZ_PINNING_SERVICE: &str = "x-amz-meta-x-pinning-service";

/// Header name for pinning service token
pub const HEADER_PINNING_TOKEN: &str = "x-pinning-token";
/// S3-compatible metadata header for pinning service token
pub const HEADER_AMZ_PINNING_TOKEN: &str = "x-amz-meta-x-pinning-token";

/// Header name for pinning name
pub const HEADER_PINNING_NAME: &str = "x-pinning-name";
/// S3-compatible metadata header for pinning name
pub const HEADER_AMZ_PINNING_NAME: &str = "x-amz-meta-x-pinning-name";

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
    /// Checks both direct headers (x-pinning-*) and S3-compatible metadata headers
    /// (x-amz-meta-x-pinning-*) for compatibility with S3 client libraries like MinIO.
    ///
    /// Returns None if headers are not present (pinning not requested)
    /// Security audit fix #3: Validates endpoint to prevent SSRF
    pub fn from_headers(headers: &HeaderMap) -> Option<Self> {
        Self::from_headers_with_default(headers, None)
    }
    
    /// Extract pinning credentials with optional server-configured default endpoint
    ///
    /// If user provides only X-Pinning-Token (no X-Pinning-Service), uses the
    /// server's default endpoint. This allows local pinning services where the
    /// endpoint is controlled by the server admin (no SSRF risk).
    ///
    /// - If user provides both endpoint + token: validates endpoint for SSRF
    /// - If user provides only token + server has default: uses server's endpoint (no validation needed)
    /// - If user provides only token + no server default: returns None
    pub fn from_headers_with_default(headers: &HeaderMap, default_endpoint: Option<&str>) -> Option<Self> {
        let token = Self::get_header_value(headers, HEADER_PINNING_TOKEN, HEADER_AMZ_PINNING_TOKEN)?;
        
        // Check if user provided their own endpoint
        let user_endpoint = Self::get_header_value(headers, HEADER_PINNING_SERVICE, HEADER_AMZ_PINNING_SERVICE);
        
        let endpoint = if let Some(ep) = user_endpoint {
            // User provided endpoint - must validate for SSRF protection
            if !Self::is_valid_pinning_endpoint(&ep) {
                warn!(
                    "Rejected invalid pinning endpoint (must be https, no private IPs)"
                );
                return None;
            }
            ep
        } else if let Some(default) = default_endpoint {
            // No user endpoint, but server has a default - use it (no validation needed,
            // server admin controls this so no SSRF risk)
            info!("Using server's default pinning endpoint");
            default.to_string()
        } else {
            // No endpoint from user or server
            return None;
        };

        // Optional: pin name from x-pinning-name header (or x-amz-meta-x-pinning-name)
        let name = Self::get_header_value(headers, HEADER_PINNING_NAME, HEADER_AMZ_PINNING_NAME);

        Some(Self {
            endpoint,
            token,
            name,
        })
    }
    
    /// Get a header value, checking the direct header first, then the x-amz-meta-* prefixed version
    fn get_header_value(headers: &HeaderMap, direct: &str, amz_meta: &str) -> Option<String> {
        headers
            .get(direct)
            .or_else(|| headers.get(amz_meta))
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
    }
    
    /// Security audit fix #3: Validate pinning endpoint to prevent SSRF
    /// - Must use https scheme
    /// - Must not be a private/localhost address
    fn is_valid_pinning_endpoint(endpoint: &str) -> bool {
        // Must start with https://
        if !endpoint.starts_with("https://") {
            return false;
        }
        
        // Parse the URL to check the host
        let url = match url::Url::parse(endpoint) {
            Ok(u) => u,
            Err(_) => return false,
        };
        
        let host = match url.host_str() {
            Some(h) => h.to_lowercase(),
            None => return false,
        };
        
        // Block localhost and loopback
        if host == "localhost" || host == "127.0.0.1" || host == "::1" || host == "[::1]" {
            return false;
        }
        
        // Block private IP ranges (basic check)
        if host.starts_with("10.") 
            || host.starts_with("192.168.")
            || host.starts_with("172.16.")
            || host.starts_with("172.17.")
            || host.starts_with("172.18.")
            || host.starts_with("172.19.")
            || host.starts_with("172.2")  // 172.20-29
            || host.starts_with("172.30.")
            || host.starts_with("172.31.")
            || host.starts_with("169.254.")  // Link-local
            || host.starts_with("0.")
        {
            return false;
        }
        
        true
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
///
/// If `default_endpoint` is provided, users can send only X-Pinning-Token
/// and the server's endpoint will be used. This enables local pinning services.
///
/// If `default_token` is provided (typically the user's JWT from S3 auth), it will be used
/// as the authentication token when no X-Pinning-Token header is present.
pub async fn pin_for_user(
    headers: &HeaderMap,
    cid: &Cid,
    object_key: Option<&str>,
    default_endpoint: Option<&str>,
    default_token: Option<&str>,
) {
    // Security audit fix #2: Don't log header VALUES (contains tokens)
    // Only log presence of headers, never their values
    // Check both direct and x-amz-meta-* prefixed headers
    let has_service = headers.get(HEADER_PINNING_SERVICE).is_some()
        || headers.get(HEADER_AMZ_PINNING_SERVICE).is_some();
    let has_token = headers.get(HEADER_PINNING_TOKEN).is_some()
        || headers.get(HEADER_AMZ_PINNING_TOKEN).is_some();
    let has_default_token = default_token.map(|t| !t.is_empty()).unwrap_or(false);
    tracing::debug!(
        has_pinning_service = has_service,
        has_pinning_token = has_token,
        has_default_endpoint = default_endpoint.is_some(),
        has_default_token = has_default_token,
        "Checking for pinning credentials (direct or x-amz-meta-* headers)"
    );

    // Try to get credentials from headers first, then fall back to defaults
    let creds = PinningCredentials::from_headers_with_default(headers, default_endpoint)
        .or_else(|| {
            // If no header credentials, try using default endpoint + default token
            if let (Some(endpoint), Some(token)) = (default_endpoint, default_token) {
                if !token.is_empty() {
                    tracing::debug!("Using default endpoint and session JWT for pinning");
                    Some(PinningCredentials {
                        endpoint: endpoint.to_string(),
                        token: token.to_string(),
                        name: None,
                    })
                } else {
                    None
                }
            } else {
                None
            }
        });

    if let Some(creds) = creds {
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
        tracing::debug!("No pinning credentials available, skipping remote pinning");
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

/// Get a header value, checking the direct header first, then the x-amz-meta-* prefixed version
fn get_pinning_header(headers: &HeaderMap, direct: &str, amz_meta: &str) -> Option<String> {
    headers
        .get(direct)
        .or_else(|| headers.get(amz_meta))
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

/// Response from storage API balance check
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StorageStatus {
    can_upload: bool,
    // Other fields are ignored
}

/// Check if user can upload (has sufficient balance/quota)
///
/// This function checks the user's storage quota/balance by calling the storage API.
/// It should be called BEFORE storing data to avoid storing data that can't be pinned.
///
/// Returns:
/// - `Ok(true)` if upload is allowed
/// - `Ok(false)` if upload is not allowed (insufficient credits)
/// - `Err(...)` if there was an API error (caller should decide how to handle)
///
/// If no storage_api_url is configured or no pinning token is provided, returns `Ok(true)`
/// to allow local-only uploads without balance checking.
pub async fn check_can_upload(
    headers: &HeaderMap,
    storage_api_url: Option<&str>,
) -> Result<bool, ApiError> {
    // If no storage API configured, skip check (allow upload)
    let api_url = match storage_api_url {
        Some(url) => url,
        None => return Ok(true),
    };

    // Get token from headers (same headers as pinning)
    let token = match get_pinning_header(headers, HEADER_PINNING_TOKEN, HEADER_AMZ_PINNING_TOKEN) {
        Some(t) => t,
        None => {
            debug!("No pinning token provided, skipping balance check");
            return Ok(true); // No token = no remote pinning = skip check
        }
    };

    // Build the storage API URL
    let url = format!("{}/api/v1/storage", api_url.trim_end_matches('/'));
    debug!(url = %url, "Checking storage balance");

    // Call storage API
    let client = reqwest::Client::new();
    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", token))
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .map_err(|e| {
            warn!(error = %e, "Failed to check storage balance");
            // Fail open: allow upload if we can't reach the balance service
            // Return Ok(true) instead of error to avoid blocking users
        });

    let response = match response {
        Ok(r) => r,
        Err(_) => {
            warn!("Balance check failed, allowing upload (fail-open)");
            return Ok(true);
        }
    };

    if !response.status().is_success() {
        warn!(status = %response.status(), "Storage API returned error, allowing upload (fail-open)");
        return Ok(true);
    }

    let status: StorageStatus = match response.json().await {
        Ok(s) => s,
        Err(e) => {
            warn!(error = %e, "Failed to parse storage status, allowing upload (fail-open)");
            return Ok(true);
        }
    };

    if !status.can_upload {
        info!("User cannot upload: insufficient credits or quota exceeded");
    }

    Ok(status.can_upload)
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

    #[test]
    fn test_s3_compatible_amz_meta_headers() {
        // Test that x-amz-meta-x-pinning-* headers work (S3 client compatibility)
        let mut headers = HeaderMap::new();
        headers.insert(
            HEADER_AMZ_PINNING_SERVICE,
            HeaderValue::from_static("https://api.pinata.cloud/psa"),
        );
        headers.insert(
            HEADER_AMZ_PINNING_TOKEN,
            HeaderValue::from_static("test-token-456"),
        );
        headers.insert(
            HEADER_AMZ_PINNING_NAME,
            HeaderValue::from_static("my-pin-name"),
        );

        let creds = PinningCredentials::from_headers(&headers).unwrap();
        assert_eq!(creds.endpoint, "https://api.pinata.cloud/psa");
        assert_eq!(creds.token, "test-token-456");
        assert_eq!(creds.name, Some("my-pin-name".to_string()));
    }

    #[test]
    fn test_direct_headers_take_precedence() {
        // Direct headers should take precedence over x-amz-meta-* headers
        let mut headers = HeaderMap::new();
        // Direct headers
        headers.insert(
            HEADER_PINNING_SERVICE,
            HeaderValue::from_static("https://direct.example.com/psa"),
        );
        headers.insert(
            HEADER_PINNING_TOKEN,
            HeaderValue::from_static("direct-token"),
        );
        // Also add x-amz-meta-* headers (should be ignored)
        headers.insert(
            HEADER_AMZ_PINNING_SERVICE,
            HeaderValue::from_static("https://amz.example.com/psa"),
        );
        headers.insert(
            HEADER_AMZ_PINNING_TOKEN,
            HeaderValue::from_static("amz-token"),
        );

        let creds = PinningCredentials::from_headers(&headers).unwrap();
        assert_eq!(creds.endpoint, "https://direct.example.com/psa");
        assert_eq!(creds.token, "direct-token");
    }

    #[test]
    fn test_token_only_with_default_endpoint() {
        // User provides only token, server has default endpoint
        let mut headers = HeaderMap::new();
        headers.insert(
            HEADER_PINNING_TOKEN,
            HeaderValue::from_static("user-token-123"),
        );

        // Without default endpoint - should fail
        assert!(PinningCredentials::from_headers(&headers).is_none());

        // With default endpoint - should use server's endpoint
        let creds = PinningCredentials::from_headers_with_default(
            &headers,
            Some("http://localhost:6000/api/v1"),
        ).unwrap();
        assert_eq!(creds.endpoint, "http://localhost:6000/api/v1");
        assert_eq!(creds.token, "user-token-123");
    }

    #[test]
    fn test_user_endpoint_overrides_default() {
        // User provides both endpoint and token - should use user's (with validation)
        let mut headers = HeaderMap::new();
        headers.insert(
            HEADER_PINNING_SERVICE,
            HeaderValue::from_static("https://user.pinata.cloud/psa"),
        );
        headers.insert(
            HEADER_PINNING_TOKEN,
            HeaderValue::from_static("user-token"),
        );

        let creds = PinningCredentials::from_headers_with_default(
            &headers,
            Some("http://localhost:6000/api/v1"),
        ).unwrap();
        // User's endpoint should be used, not the default
        assert_eq!(creds.endpoint, "https://user.pinata.cloud/psa");
        assert_eq!(creds.token, "user-token");
    }
}
