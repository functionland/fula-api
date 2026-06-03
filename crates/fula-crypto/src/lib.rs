//! # Fula Crypto
//!
//! Cryptographic primitives for the Fula decentralized storage system.
//!
//! ## 🔐 Quantum-Safe Encryption
//!
//! This crate provides **post-quantum cryptographic protection** via a hybrid approach:
//!
//! - **Hybrid KEM**: X25519 (classical) + ML-KEM-768 (NIST FIPS 203 post-quantum)
//! - **HPKE (RFC 9180)**: For backward-compatible classical encryption
//! - **AES-256-GCM / ChaCha20-Poly1305**: Symmetric encryption (quantum-resistant)
//! - **BLAKE3**: Fast cryptographic hashing (quantum-resistant)
//! - **Bao**: Verified streaming for integrity verification
//!
//! ### Post-Quantum Security
//!
//! The hybrid KEM combines:
//! - **X25519**: 128-bit classical security, fast, well-audited
//! - **ML-KEM-768 (Kyber768)**: NIST Security Level 3, resistant to Shor's algorithm
//!
//! If quantum computers break X25519, ML-KEM still protects your data.
//! If ML-KEM has unforeseen weaknesses, X25519 still provides security.
//!
//! ## Features
//!
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
//! ## Example (Quantum-Safe)
//!
//! ```rust,ignore
//! use fula_crypto::hybrid_kem::{HybridKeyPair, encapsulate, decapsulate};
//!
//! // Generate quantum-safe keypair
//! let keypair = HybridKeyPair::generate();
//!
//! // Encapsulate a shared secret (sender)
//! let (encapsulated_key, shared_secret) = encapsulate(keypair.public_key())?;
//!
//! // Decapsulate (recipient)
//! let recovered_secret = decapsulate(&encapsulated_key, keypair.secret_key())?;
//! assert_eq!(shared_secret, recovered_secret);
//! ```
//!
//! ## Example (Classical HPKE)
//!
//! ```rust,ignore
//! use fula_crypto::{KekKeyPair, Encryptor, Decryptor};
//!
//! // Generate a classical key pair
//! let keypair = KekKeyPair::generate();
//!
//! // Encrypt data for a recipient
//! let encrypted = Encryptor::new(keypair.public_key())
//!     .encrypt(b"Hello, World!")?;
//!
//! // Decrypt data
//! let decrypted = Decryptor::new(&keypair)
//!     .decrypt(&encrypted)?;
//! ```

pub mod chunked;
pub mod effective_user_id;
pub mod error;
pub mod hamt_index;
pub mod hashing;
pub mod hpke;
pub mod hybrid_kem;
pub mod inbox;
pub mod keys;
pub mod private_forest;
pub mod private_metadata;
pub mod rotation;
pub mod secret_link;
pub mod sharded_hamt_forest;
pub mod sharing;
pub mod streaming;
pub mod subtree_keys;
pub mod symmetric;
pub mod time;
pub mod user_buckets_index_aad;
pub mod user_entry;
pub mod wnfs_hamt;

pub use chunked::{ChunkedEncoder, ChunkedDecoder, ChunkedFileMetadata, EncryptedChunk, should_use_chunked, CHUNKED_THRESHOLD, VerifiedStreamingDecoder};
#[cfg(feature = "tokio-runtime")]
pub use chunked::AsyncStreamingEncoder;
pub use chunked::DEFAULT_CHUNK_SIZE as CHUNKED_DEFAULT_SIZE;
pub use error::{CryptoError, Result};
pub use hamt_index::{HamtIndex, HamtNode, ShardedIndex};
pub use hashing::{Blake3Hash, Hasher, HashOutput};
pub use hpke::{Decryptor, EncapsulatedKey, EncryptedData, Encryptor, HpkeConfig, SharePermissions};
pub use hybrid_kem::{
    HybridKeyPair, HybridPublicKey, HybridSecretKey, HybridEncapsulatedKey,
    encapsulate as hybrid_encapsulate, decapsulate as hybrid_decapsulate,
    try_encapsulate as hybrid_try_encapsulate,
    HYBRID_PUBLIC_KEY_SIZE, HYBRID_SECRET_KEY_SIZE, HYBRID_ENCAPSULATED_KEY_SIZE,
};
pub use inbox::{ShareEnvelope, ShareEnvelopeBuilder, InboxEntry, InboxEntryStatus, ShareInbox, INBOX_PREFIX, DEFAULT_INBOX_TTL_SECONDS};
pub use keys::{DekKey, KekKeyPair, KeyManager, PublicKey, SecretKey};
pub use private_forest::{
    PrivateForest, EncryptedForest, ForestFileEntry, ForestDirectoryEntry, ForestFormat,
    derive_index_key, generate_flat_key,
    ForestEvent, ForestOrManifest,
    detect_forest_format, derive_shard_key, compute_initial_shard_count,
    MAX_SHARDS,
    // Sharded-HAMT forest (v7)
    ShardV7, ShardManifestV7, EncryptedShardManifestV7,
    V7StorageKey, V7_STORAGE_KEY_LEN,
    manifest_v7_aad, hamt_node_v7_aad, compute_v7_node_key,
    // Meta-HAMT manifest (S-1.2)
    ManifestRoot, ManifestPage, EncryptedManifestPage, PageRef, PageId,
    PAGE_SIZE, MAX_PAGES, derive_manifest_page_key, manifest_page_aad,
    page_id_for_shard, shard_slot_in_page,
    // Directory index (F-1.3)
    DirectoryIndex, DirEntry, EncryptedDirectoryIndex,
    derive_dir_index_key, dir_index_aad,
};
pub use wnfs_hamt::{BlobBackend, BlobPutResult, V7NodeStore, V7_NODE_PREFIX};
pub use private_metadata::{PrivateMetadata, EncryptedPrivateMetadata, PublicMetadata, KeyObfuscation, obfuscate_key};
pub use rotation::{KeyRotationManager, FileSystemRotation, WrappedKeyInfo, RotationResult};
pub use sharded_hamt_forest::{HamtEntry, ShardedHamtPrivateForest};
pub use secret_link::{SecretLink, SecretLinkBuilder, SecretLinkPayload, is_valid_secret_link_url, extract_opaque_id, SHARE_PATH_PREFIX};
pub use sharing::{ShareToken, ShareBuilder, ShareRecipient, AcceptedShare, FolderShareManager, AccessValidation, ShareMode, SnapshotBinding, SnapshotVerification};
pub use streaming::{BaoEncoder, BaoDecoder, BaoOutboard, VerifiedStream};
pub use subtree_keys::{SubtreeKeyManager, EncryptedSubtreeDek, SubtreeKeyInfo, SubtreeRotationResult, SubtreeShareToken, SubtreeShareBuilder, SubtreeShareRecipient, AcceptedSubtreeShare};
pub use symmetric::{Aead, AeadCipher, Nonce};
pub use user_buckets_index_aad::{
    build_aad as build_user_buckets_index_aad,
    derive_index_key as derive_user_buckets_index_key,
    AAD_TAG as USER_BUCKETS_INDEX_AAD_TAG,
    ENVELOPE_VERSION as USER_BUCKETS_INDEX_ENVELOPE_VERSION,
    INDEX_KEY_LEN as USER_BUCKETS_INDEX_KEY_LEN,
    NONCE_LEN as USER_BUCKETS_INDEX_NONCE_LEN,
    PAYLOAD_VERSION as USER_BUCKETS_INDEX_PAYLOAD_VERSION,
    USER_KEY_HEX_LEN as USER_BUCKETS_INDEX_USER_KEY_HEX_LEN,
};
pub use user_entry::{
    derive_entry_signing_seed, entry_pubkey_from_kek, entry_signature_payload,
    sign_entry, verify_entry_signature, ENTRY_PUBKEY_LEN, ENTRY_SIGNATURE_LEN,
    ENTRY_SIGNATURE_TAG, ENTRY_SIGNING_SEED_LEN,
};

/// The version of the cryptographic format
/// - Version 1: Custom HPKE (X25519 + BLAKE3 + AEAD) [deprecated]
/// - Version 2: RFC 9180 HPKE (X25519HkdfSha256 + HkdfSha256 + ChaCha20Poly1305)
/// - Version 3: Quantum-Safe Hybrid (X25519 + ML-KEM-768 + ChaCha20Poly1305)
pub const CRYPTO_VERSION: u8 = 2;

/// Quantum-safe crypto version (X25519 + ML-KEM-768 hybrid)
pub const CRYPTO_VERSION_QUANTUM_SAFE: u8 = 3;

/// Content encryption version with AAD binding (storage_key bound to ciphertext)
pub const CRYPTO_VERSION_CONTENT_AAD: u8 = 4;

/// Default chunk size for streaming encryption (256 KB)
pub const DEFAULT_CHUNK_SIZE: usize = 256 * 1024;

/// Maximum file size for single-part encryption (5 GB)
pub const MAX_SINGLE_PART_SIZE: u64 = 5 * 1024 * 1024 * 1024;

/// Whether quantum-safe cryptography is available
pub const QUANTUM_SAFE_AVAILABLE: bool = true;
