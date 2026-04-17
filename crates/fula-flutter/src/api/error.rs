//! Error types for Flutter bindings
//!
//! Provides a unified error type that maps from various internal error types
//! and is suitable for FFI/flutter_rust_bridge serialization.

use thiserror::Error;

/// Unified error type for Fula Flutter operations
///
/// This enum covers all possible errors from the underlying libraries
/// in a format that's easy to handle in Dart code.
///
/// Note: FulaResult uses anyhow::Result for FRB compatibility.
/// Errors are converted to strings on the Dart side.
#[derive(Debug, Clone, Error)]
pub enum FulaError {
    /// Network/HTTP error
    #[error("Network error: {0}")]
    Network(String),

    /// Object not found
    #[error("Not found: bucket={bucket}, key={key}")]
    NotFound {
        bucket: String,
        key: String,
    },

    /// Bucket not found
    #[error("Bucket not found: {0}")]
    BucketNotFound(String),

    /// Access denied
    #[error("Access denied: {0}")]
    AccessDenied(String),

    /// Encryption/decryption error
    #[error("Encryption error: {0}")]
    Encryption(String),

    /// Invalid configuration
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    /// Upload failed
    #[error("Upload failed: {0}")]
    UploadFailed(String),

    /// Download failed
    #[error("Download failed: {0}")]
    DownloadFailed(String),

    /// XML parsing error
    #[error("XML parse error: {0}")]
    XmlParse(String),

    /// Invalid response from server
    #[error("Invalid response: {0}")]
    InvalidResponse(String),

    /// Share token error
    #[error("Share error: {0}")]
    ShareError(String),

    /// Key rotation error
    #[error("Rotation error: {0}")]
    RotationError(String),

    /// Forest/index error
    #[error("Forest error: {0}")]
    ForestError(String),

    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),
}

/// Result type alias for Fula operations
/// Uses anyhow::Result for flutter_rust_bridge compatibility
pub type FulaResult<T> = anyhow::Result<T>;

// ============================================================================
// Conversions from internal error types
// ============================================================================

impl From<fula_client::ClientError> for FulaError {
    fn from(err: fula_client::ClientError) -> Self {
        use fula_client::ClientError;
        match err {
            ClientError::Http(e) => FulaError::Network(e.to_string()),
            ClientError::S3Error { code, message, .. } => {
                match code.as_str() {
                    "NoSuchKey" => FulaError::NotFound {
                        bucket: String::new(),
                        key: message,
                    },
                    "NoSuchBucket" => FulaError::BucketNotFound(message),
                    "AccessDenied" | "SignatureDoesNotMatch" => FulaError::AccessDenied(message),
                    _ => FulaError::InvalidResponse(format!("{}: {}", code, message)),
                }
            }
            ClientError::Config(msg) => FulaError::InvalidConfig(msg),
            ClientError::Encryption(e) => FulaError::Encryption(e.to_string()),
            ClientError::Io(e) => FulaError::Network(e.to_string()),
            ClientError::XmlParse(msg) => FulaError::XmlParse(msg),
            ClientError::InvalidResponse(msg) => FulaError::InvalidResponse(msg),
            ClientError::NotFound { bucket, key } => FulaError::NotFound { bucket, key },
            ClientError::BucketNotFound(name) => FulaError::BucketNotFound(name),
            ClientError::AccessDenied(msg) => FulaError::AccessDenied(msg),
            ClientError::UploadFailed(msg) => FulaError::UploadFailed(msg),
            ClientError::DownloadFailed(msg) => FulaError::DownloadFailed(msg),
            ClientError::ConcurrentModification(msg) => FulaError::InvalidResponse(
                format!("concurrent modification: {}", msg),
            ),
            ClientError::ConcurrentModificationExhausted { bucket, retries, unresolved_ops, wal_path } => {
                FulaError::InvalidResponse(format!(
                    "concurrent modification unresolved after {} retries: bucket={}, pending ops={}, wal={}",
                    retries, bucket, unresolved_ops, wal_path
                ))
            }
            ClientError::RotationInProgress { bucket } => FulaError::InvalidResponse(
                format!("rotation already in progress for bucket: {}", bucket),
            ),
        }
    }
}

impl From<fula_crypto::CryptoError> for FulaError {
    fn from(err: fula_crypto::CryptoError) -> Self {
        FulaError::Encryption(err.to_string())
    }
}

impl From<anyhow::Error> for FulaError {
    fn from(err: anyhow::Error) -> Self {
        FulaError::Internal(err.to_string())
    }
}

impl From<std::io::Error> for FulaError {
    fn from(err: std::io::Error) -> Self {
        FulaError::Network(err.to_string())
    }
}

// ============================================================================
// Helper methods
// ============================================================================

impl FulaError {
    /// Check if this is a "not found" error
    pub fn is_not_found(&self) -> bool {
        matches!(self, FulaError::NotFound { .. } | FulaError::BucketNotFound(_))
    }

    /// Check if this is an access denied error
    pub fn is_access_denied(&self) -> bool {
        matches!(self, FulaError::AccessDenied(_))
    }

    /// Check if this is a network error
    pub fn is_network_error(&self) -> bool {
        matches!(self, FulaError::Network(_))
    }

    /// Check if this is an encryption error
    pub fn is_encryption_error(&self) -> bool {
        matches!(self, FulaError::Encryption(_))
    }

    /// Get error code for categorization
    pub fn error_code(&self) -> &'static str {
        match self {
            FulaError::Network(_) => "NETWORK",
            FulaError::NotFound { .. } => "NOT_FOUND",
            FulaError::BucketNotFound(_) => "BUCKET_NOT_FOUND",
            FulaError::AccessDenied(_) => "ACCESS_DENIED",
            FulaError::Encryption(_) => "ENCRYPTION",
            FulaError::InvalidConfig(_) => "INVALID_CONFIG",
            FulaError::UploadFailed(_) => "UPLOAD_FAILED",
            FulaError::DownloadFailed(_) => "DOWNLOAD_FAILED",
            FulaError::XmlParse(_) => "XML_PARSE",
            FulaError::InvalidResponse(_) => "INVALID_RESPONSE",
            FulaError::ShareError(_) => "SHARE_ERROR",
            FulaError::RotationError(_) => "ROTATION_ERROR",
            FulaError::ForestError(_) => "FOREST_ERROR",
            FulaError::Internal(_) => "INTERNAL",
        }
    }
}
