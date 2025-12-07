//! Gateway configuration

use serde::{Deserialize, Serialize};

/// Gateway server configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GatewayConfig {
    /// Host to bind to
    pub host: String,
    /// Port to listen on
    pub port: u16,
    /// IPFS API URL
    pub ipfs_url: String,
    /// IPFS Cluster API URL
    pub cluster_url: String,
    /// JWT secret for authentication
    pub jwt_secret: Option<String>,
    /// Enable authentication
    pub auth_enabled: bool,
    /// Rate limit (requests per second per user)
    pub rate_limit_rps: u32,
    /// Maximum request body size (bytes)
    pub max_body_size: usize,
    /// Maximum multipart upload size (bytes)
    pub max_upload_size: u64,
    /// Multipart upload expiry (seconds)
    pub multipart_expiry_secs: u64,
    /// Enable CORS
    pub cors_enabled: bool,
    /// CORS allowed origins
    pub cors_origins: Vec<String>,
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            host: "0.0.0.0".to_string(),
            port: 9000,
            ipfs_url: "http://localhost:5001".to_string(),
            cluster_url: "http://localhost:9094".to_string(),
            jwt_secret: None,
            auth_enabled: true,
            rate_limit_rps: 100,
            max_body_size: 5 * 1024 * 1024 * 1024, // 5 GB
            max_upload_size: 5 * 1024 * 1024 * 1024 * 1024, // 5 TB
            multipart_expiry_secs: 24 * 60 * 60, // 24 hours
            cors_enabled: true,
            cors_origins: vec!["*".to_string()],
        }
    }
}

impl GatewayConfig {
    /// Get the bind address
    pub fn bind_addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}
