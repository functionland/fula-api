//! # Fula Crypto
//!
//! Cryptographic primitives for the Fula decentralized storage system.
//!
//! This crate provides:
//! - **HPKE (Hybrid Public Key Encryption)**: For secure file encryption and key exchange
//! - **BLAKE3**: Fast cryptographic hashing
//! - **Bao**: Verified streaming for integrity verification
//! - **Key Management**: DEK/KEK architecture for efficient key rotation
//! - **Sharing**: Secure file/folder sharing without exposing master keys
//! - **Key Rotation**: Full filesystem key rotation with DEK re-wrapping
//!
//! ## Security Model
//!
//! This crate implements a "Trust-No-One" security model where:
//! - All encryption happens client-side
//! - Private keys never leave the client device
//! - Storage nodes only see encrypted data
//!
//! ## Example
//!
//! ```rust,ignore
//! use fula_crypto::{KeyPair, Encryptor, Decryptor};
//!
//! // Generate a new key pair
//! let keypair = KeyPair::generate();
//!
//! // Encrypt data for a recipient
//! let encrypted = Encryptor::new(&recipient_public_key)
//!     .encrypt(b"Hello, World!")?;
//!
//! // Decrypt data
//! let decrypted = Decryptor::new(&recipient_keypair)
//!     .decrypt(&encrypted)?;
//! ```

pub mod chunked;
pub mod error;
pub mod hamt_index;
pub mod hashing;
pub mod hpke;
pub mod keys;
pub mod private_forest;
pub mod private_metadata;
pub mod rotation;
pub mod sharing;
pub mod streaming;
pub mod symmetric;

pub use chunked::{ChunkedEncoder, ChunkedDecoder, ChunkedFileMetadata, EncryptedChunk, should_use_chunked, CHUNKED_THRESHOLD, AsyncStreamingEncoder, VerifiedStreamingDecoder};
pub use chunked::DEFAULT_CHUNK_SIZE as CHUNKED_DEFAULT_SIZE;
pub use error::{CryptoError, Result};
pub use hamt_index::{HamtIndex, HamtNode, ShardedIndex};
pub use hashing::{Blake3Hash, Hasher, HashOutput};
pub use hpke::{Decryptor, EncapsulatedKey, EncryptedData, Encryptor, HpkeConfig, SharePermissions};
pub use keys::{DekKey, KekKeyPair, KeyManager, PublicKey, SecretKey};
pub use private_forest::{PrivateForest, EncryptedForest, ForestFileEntry, ForestDirectoryEntry, ForestFormat, derive_index_key, generate_flat_key};
pub use private_metadata::{PrivateMetadata, EncryptedPrivateMetadata, PublicMetadata, KeyObfuscation, obfuscate_key};
pub use rotation::{KeyRotationManager, FileSystemRotation, WrappedKeyInfo, RotationResult};
pub use sharing::{ShareToken, ShareBuilder, ShareRecipient, AcceptedShare, FolderShareManager, AccessValidation};
pub use streaming::{BaoEncoder, BaoDecoder, BaoOutboard, VerifiedStream};
pub use symmetric::{Aead, AeadCipher, Nonce};

/// The version of the cryptographic format
/// Version 1: Custom HPKE (X25519 + BLAKE3 + AEAD)
/// Version 2: RFC 9180 HPKE (X25519HkdfSha256 + HkdfSha256 + ChaCha20Poly1305)
pub const CRYPTO_VERSION: u8 = 2;

/// Default chunk size for streaming encryption (256 KB)
pub const DEFAULT_CHUNK_SIZE: usize = 256 * 1024;

/// Maximum file size for single-part encryption (5 GB)
pub const MAX_SINGLE_PART_SIZE: u64 = 5 * 1024 * 1024 * 1024;
