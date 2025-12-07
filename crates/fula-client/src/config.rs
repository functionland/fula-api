//! Client configuration

use std::time::Duration;

/// Client configuration
#[derive(Clone, Debug)]
pub struct Config {
    /// Gateway endpoint URL
    pub endpoint: String,
    /// Access token (JWT)
    pub access_token: Option<String>,
    /// Request timeout
    pub timeout: Duration,
    /// Enable client-side encryption
    pub encryption_enabled: bool,
    /// User agent string
    pub user_agent: String,
    /// Maximum retry attempts
    pub max_retries: u32,
    /// Multipart upload threshold (bytes)
    pub multipart_threshold: u64,
    /// Multipart chunk size (bytes)
    pub multipart_chunk_size: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            endpoint: "http://localhost:9000".to_string(),
            access_token: None,
            timeout: Duration::from_secs(30),
            encryption_enabled: false,
            user_agent: format!("fula-client/{}", env!("CARGO_PKG_VERSION")),
            max_retries: 3,
            multipart_threshold: 100 * 1024 * 1024, // 100 MB
            multipart_chunk_size: 8 * 1024 * 1024,  // 8 MB
        }
    }
}

impl Config {
    /// Create a new config with the given endpoint
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            ..Default::default()
        }
    }

    /// Set the access token
    pub fn with_token(mut self, token: impl Into<String>) -> Self {
        self.access_token = Some(token.into());
        self
    }

    /// Enable encryption
    pub fn with_encryption(mut self) -> Self {
        self.encryption_enabled = true;
        self
    }

    /// Set timeout
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Build the base URL for API requests
    pub fn base_url(&self) -> &str {
        &self.endpoint
    }
}
