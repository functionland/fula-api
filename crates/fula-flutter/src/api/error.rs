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

    /// Phase 2.2 of master-independent reads: a single block exceeds
    /// the configured `block_cache_max_bytes` budget. Surface to the
    /// user with guidance to raise the cache size or skip the cache.
    /// Native-only signal in practice (BlockCache is compiled out on
    /// wasm32) but defined unconditionally so the Dart binding always
    /// has the same enum shape across Android, iOS, Ubuntu, Windows,
    /// and web (flutter-js + wasm).
    #[error("Cache budget exceeded: size={size}, budget={budget}")]
    CacheBudgetExceeded { size: u64, budget: u64 },

    /// Phase 2.2 of master-independent reads: catch-all for the
    /// persistent block cache's I/O / storage / commit errors.
    /// Stringified at the FFI boundary; Dart code doesn't depend on
    /// any Rust storage-engine specifics. Native-only in practice.
    #[error("Cache error: {0}")]
    CacheError(String),

    /// Phase 3.3 — cold-start hybrid resolver could not resolve the
    /// master-published global users-index CID via IPNS or chain.
    /// Surface to Dart apps as "offline mode unavailable for this
    /// device until master is reachable again" — distinct from
    /// `Network` (which is a transient master-side glitch).
    #[error("Users-index resolution failed: {0}")]
    UsersIndexResolutionFailed(String),

    /// Phase 3.3 — replay defense: a payload's embedded sequence
    /// regressed below what the SDK has seen before. Dart apps
    /// should NOT silently retry; surface as a clear "stale-state"
    /// signal (possibly with a retry-after-N-minutes hint).
    #[error("Sequence regression in {channel}: observed={observed}, highest seen={highest_seen}")]
    SequenceRegression {
        observed: u64,
        highest_seen: u64,
        channel: String,
    },

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
            ClientError::MigrationLockHeld { bucket, expires_at } => FulaError::InvalidResponse(
                format!("migration lock held for bucket {} (expires at {} ms)", bucket, expires_at),
            ),
            // Phase 2.1 of master-independent reads: surface as a Network
            // error to existing Flutter callers — the closest existing
            // category, since the master is effectively unreachable.
            // Phase 2.4 catches this variant earlier and falls back to the
            // gateway race before reaching this conversion.
            ClientError::MasterUnreachable { down_for_secs } => FulaError::Network(
                format!("master unreachable (health gate; down for ~{}s)", down_for_secs),
            ),
            // Phase 2.2 — block cache surface. Map to first-class
            // FulaError variants so Dart code can pattern-match without
            // string parsing. Identical shape on every target (native +
            // wasm) so flutter-js / web builds compile against the same
            // enum.
            ClientError::BlockTooLarge { size, budget } => {
                FulaError::CacheBudgetExceeded { size, budget }
            }
            ClientError::BlockCache(msg) => FulaError::CacheError(msg),
            // Phase 3.3 cold-start hybrid resolver.
            ClientError::UsersIndexResolutionFailed { reason } => {
                FulaError::UsersIndexResolutionFailed(reason)
            }
            ClientError::SequenceRegression { observed, highest_seen, channel } => {
                FulaError::SequenceRegression { observed, highest_seen, channel }
            }
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
            FulaError::CacheBudgetExceeded { .. } => "CACHE_BUDGET_EXCEEDED",
            FulaError::CacheError(_) => "CACHE_ERROR",
            FulaError::UsersIndexResolutionFailed(_) => "USERS_INDEX_RESOLUTION_FAILED",
            FulaError::SequenceRegression { .. } => "SEQUENCE_REGRESSION",
            FulaError::Internal(_) => "INTERNAL",
        }
    }

    /// Phase 2.2 helper: detect block-cache-related errors so app code
    /// can offer a "retry without cache" or "raise budget" prompt
    /// without string-parsing the underlying message.
    pub fn is_cache_error(&self) -> bool {
        matches!(self, FulaError::CacheBudgetExceeded { .. } | FulaError::CacheError(_))
    }

    /// Phase 3.3 helper: detect cold-start resolution errors. Apps
    /// should surface this as "offline mode unavailable" instead of
    /// a generic "download failed" — the file is fine; we just can't
    /// learn its CID without master.
    pub fn is_users_index_error(&self) -> bool {
        matches!(
            self,
            FulaError::UsersIndexResolutionFailed(_) | FulaError::SequenceRegression { .. }
        )
    }
}
