//! # Fula Crypto
//!
//! Cryptographic primitives for the Fula decentralized storage system.
//!
//! This crate provides:
//! - **HPKE (Hybrid Public Key Encryption)**: For secure file encryption and key exchange
//! - **BLAKE3**: Fast cryptographic hashing
//! - **Bao**: Verified streaming for integrity verification
//! - **Key Management**: DEK/KEK architecture for efficient key rotation
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

pub mod error;
pub mod hashing;
pub mod hpke;
pub mod keys;
pub mod streaming;
pub mod symmetric;

pub use error::{CryptoError, Result};
pub use hashing::{Blake3Hash, Hasher, HashOutput};
pub use hpke::{Decryptor, EncapsulatedKey, EncryptedData, Encryptor, HpkeConfig};
pub use keys::{DekKey, KekKeyPair, KeyManager, PublicKey, SecretKey};
pub use streaming::{BaoEncoder, BaoDecoder, BaoOutboard, VerifiedStream};
pub use symmetric::{Aead, AeadCipher, Nonce};

/// The version of the cryptographic format
pub const CRYPTO_VERSION: u8 = 1;

/// Default chunk size for streaming encryption (256 KB)
pub const DEFAULT_CHUNK_SIZE: usize = 256 * 1024;

/// Maximum file size for single-part encryption (5 GB)
pub const MAX_SINGLE_PART_SIZE: u64 = 5 * 1024 * 1024 * 1024;
