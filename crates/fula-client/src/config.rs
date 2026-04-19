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
    /// Per-chunk download timeout (F10).
    ///
    /// Applied to every individual chunk fetched by the windowed chunked-download
    /// engine. Guards against a slow server that trickles bytes below the global
    /// reqwest dead-connection threshold and stalls a download for minutes. Only
    /// active on native targets; wasm inherits the fetch default.
    pub per_chunk_download_timeout: Duration,
    /// Maximum plaintext size a buffered download will accept (F8).
    ///
    /// Applied *before* any network I/O by the buffered chunked-download engine.
    /// If the chunked metadata declares a `total_size` larger than this ceiling,
    /// the buffered path returns an error instead of allocating the buffer. This
    /// exists because the buffered engine holds the entire decrypted file in RAM
    /// until `finalize_and_verify` passes, then emits to the caller's writer —
    /// a disaster-recovery tradeoff that prefers a loud error over an unbounded
    /// allocation. The streaming variant (`..._to_writer`) has no such ceiling.
    ///
    /// Note: the ceiling bounds allocation under an honest manifest. A forged
    /// `total_size` that lies about the real payload is caught by the
    /// mid-stream per-chunk AEAD + size check in the engine itself, so the
    /// ceiling is an allocation guard, not a security boundary.
    pub buffered_download_max_bytes: u64,
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
            multipart_chunk_size: 256 * 1024,       // 256 KB (must be < 1MB for IPFS)
            per_chunk_download_timeout: Duration::from_secs(300), // 5 min
            buffered_download_max_bytes: 256 * 1024 * 1024,       // 256 MB
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
