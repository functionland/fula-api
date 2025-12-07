//! Error types for the fula-core crate

use thiserror::Error;

/// Result type alias using `CoreError`
pub type Result<T> = std::result::Result<T, CoreError>;

/// Errors that can occur in core storage operations
#[derive(Error, Debug)]
pub enum CoreError {
    /// Bucket not found
    #[error("bucket not found: {0}")]
    BucketNotFound(String),

    /// Bucket already exists
    #[error("bucket already exists: {0}")]
    BucketAlreadyExists(String),

    /// Object not found
    #[error("object not found: {bucket}/{key}")]
    ObjectNotFound { bucket: String, key: String },

    /// Invalid bucket name
    #[error("invalid bucket name: {0}")]
    InvalidBucketName(String),

    /// Invalid object key
    #[error("invalid object key: {0}")]
    InvalidObjectKey(String),

    /// Key conflict during merge
    #[error("key conflict: {key} modified by multiple writers")]
    KeyConflict { key: String },

    /// Tree corruption detected
    #[error("tree corruption: {0}")]
    TreeCorruption(String),

    /// Serialization error
    #[error("serialization error: {0}")]
    Serialization(String),

    /// Deserialization error
    #[error("deserialization error: {0}")]
    Deserialization(String),

    /// Block store error
    #[error("block store error: {0}")]
    BlockStore(#[from] fula_blockstore::BlockStoreError),

    /// Crypto error
    #[error("crypto error: {0}")]
    Crypto(#[from] fula_crypto::CryptoError),

    /// Version mismatch
    #[error("version mismatch: expected {expected}, got {actual}")]
    VersionMismatch { expected: String, actual: String },

    /// Operation not supported
    #[error("operation not supported: {0}")]
    NotSupported(String),

    /// Access denied
    #[error("access denied: {0}")]
    AccessDenied(String),

    /// Precondition failed
    #[error("precondition failed: {0}")]
    PreconditionFailed(String),
}
