//! Error types for the fula-blockstore crate

use thiserror::Error;
use cid::Cid;

/// Result type alias using `BlockStoreError`
pub type Result<T> = std::result::Result<T, BlockStoreError>;

/// Errors that can occur during block storage operations
#[derive(Error, Debug)]
pub enum BlockStoreError {
    /// Block not found
    #[error("block not found: {0}")]
    NotFound(Cid),

    /// Block already exists
    #[error("block already exists: {0}")]
    AlreadyExists(Cid),

    /// Invalid CID
    #[error("invalid CID: {0}")]
    InvalidCid(String),

    /// Block too large
    #[error("block too large: {size} bytes exceeds maximum {max} bytes")]
    BlockTooLarge { size: usize, max: usize },

    /// Serialization error
    #[error("serialization error: {0}")]
    Serialization(String),

    /// Deserialization error
    #[error("deserialization error: {0}")]
    Deserialization(String),

    /// IPFS API error
    #[error("IPFS API error: {0}")]
    IpfsApi(String),

    /// IPFS Cluster API error
    #[error("IPFS Cluster API error: {0}")]
    ClusterApi(String),

    /// Connection error
    #[error("connection error: {0}")]
    Connection(String),

    /// Pin operation failed
    #[error("pin operation failed: {0}")]
    PinFailed(String),

    /// Unpin operation failed
    #[error("unpin operation failed: {0}")]
    UnpinFailed(String),

    /// Timeout error
    #[error("operation timed out after {seconds}s")]
    Timeout { seconds: u64 },

    /// Hash mismatch
    #[error("hash mismatch: expected {expected}, got {actual}")]
    HashMismatch { expected: String, actual: String },

    /// IO error
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// HTTP error
    #[error("http error: {0}")]
    Http(String),

    /// Crypto error
    #[error("crypto error: {0}")]
    Crypto(#[from] fula_crypto::CryptoError),

    /// Configuration error
    #[error("configuration error: {0}")]
    Configuration(String),
}

impl From<reqwest::Error> for BlockStoreError {
    fn from(err: reqwest::Error) -> Self {
        if err.is_timeout() {
            BlockStoreError::Timeout { seconds: 30 }
        } else if err.is_connect() {
            BlockStoreError::Connection(err.to_string())
        } else {
            BlockStoreError::Http(err.to_string())
        }
    }
}

impl From<serde_json::Error> for BlockStoreError {
    fn from(err: serde_json::Error) -> Self {
        BlockStoreError::Serialization(err.to_string())
    }
}

impl From<serde_ipld_dagcbor::DecodeError<std::convert::Infallible>> for BlockStoreError {
    fn from(err: serde_ipld_dagcbor::DecodeError<std::convert::Infallible>) -> Self {
        BlockStoreError::Deserialization(err.to_string())
    }
}
