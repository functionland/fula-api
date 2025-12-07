//! Error types for the fula-crypto crate

use thiserror::Error;

/// Result type alias using `CryptoError`
pub type Result<T> = std::result::Result<T, CryptoError>;

/// Errors that can occur during cryptographic operations
#[derive(Error, Debug)]
pub enum CryptoError {
    /// Key generation failed
    #[error("key generation failed: {0}")]
    KeyGeneration(String),

    /// Encryption failed
    #[error("encryption failed: {0}")]
    Encryption(String),

    /// Decryption failed
    #[error("decryption failed: {0}")]
    Decryption(String),

    /// Invalid key format or length
    #[error("invalid key: {0}")]
    InvalidKey(String),

    /// Invalid ciphertext format
    #[error("invalid ciphertext: {0}")]
    InvalidCiphertext(String),

    /// Signature verification failed
    #[error("signature verification failed")]
    SignatureVerification,

    /// Hash verification failed
    #[error("hash verification failed: expected {expected}, got {actual}")]
    HashMismatch { expected: String, actual: String },

    /// Bao verification failed
    #[error("bao verification failed: {0}")]
    BaoVerification(String),

    /// Invalid nonce
    #[error("invalid nonce: {0}")]
    InvalidNonce(String),

    /// Data too large for operation
    #[error("data too large: {size} bytes exceeds maximum {max} bytes")]
    DataTooLarge { size: u64, max: u64 },

    /// Invalid chunk size
    #[error("invalid chunk size: {0}")]
    InvalidChunkSize(usize),

    /// IO error
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// Serialization error
    #[error("serialization error: {0}")]
    Serialization(String),

    /// Base64 decode error
    #[error("base64 decode error: {0}")]
    Base64Decode(#[from] base64::DecodeError),

    /// Hex decode error
    #[error("hex decode error: {0}")]
    HexDecode(#[from] hex::FromHexError),
}
