//! Hashing utilities using BLAKE3
//!
//! This module provides fast cryptographic hashing with BLAKE3 for:
//! - Content addressing (CID generation)
//! - ETag calculation
//! - Data integrity verification
//! - Merkle tree construction

use crate::{CryptoError, Result};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Size of a BLAKE3 hash output in bytes (256 bits)
pub const HASH_BYTE_SIZE: usize = 32;

/// Type alias for hash output bytes
pub type HashOutput = [u8; HASH_BYTE_SIZE];

/// A BLAKE3 hash wrapper with convenience methods
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Blake3Hash(HashOutput);

impl Blake3Hash {
    /// Create a new hash from bytes
    pub fn new(bytes: HashOutput) -> Self {
        Self(bytes)
    }

    /// Create a hash from a hex string
    pub fn from_hex(s: &str) -> Result<Self> {
        let bytes = hex::decode(s)?;
        if bytes.len() != HASH_BYTE_SIZE {
            return Err(CryptoError::InvalidKey(format!(
                "hash must be {} bytes, got {}",
                HASH_BYTE_SIZE,
                bytes.len()
            )));
        }
        let mut arr = [0u8; HASH_BYTE_SIZE];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }

    /// Get the hash as bytes
    pub fn as_bytes(&self) -> &HashOutput {
        &self.0
    }

    /// Convert to a hex string
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Get the first N bytes for use as a prefix
    pub fn prefix(&self, n: usize) -> &[u8] {
        &self.0[..n.min(HASH_BYTE_SIZE)]
    }

    /// Check if this hash is all zeros
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|&b| b == 0)
    }
}

impl Default for Blake3Hash {
    fn default() -> Self {
        Self([0u8; HASH_BYTE_SIZE])
    }
}

impl fmt::Debug for Blake3Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Blake3Hash({})", self.to_hex())
    }
}

impl fmt::Display for Blake3Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl AsRef<[u8]> for Blake3Hash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<HashOutput> for Blake3Hash {
    fn from(bytes: HashOutput) -> Self {
        Self(bytes)
    }
}

impl From<Blake3Hash> for HashOutput {
    fn from(hash: Blake3Hash) -> Self {
        hash.0
    }
}

impl From<blake3::Hash> for Blake3Hash {
    fn from(hash: blake3::Hash) -> Self {
        Self(*hash.as_bytes())
    }
}

/// A trait for types that can generate hashes
pub trait Hasher {
    /// Generate a hash of the given data
    fn hash<D: AsRef<[u8]>>(data: &D) -> HashOutput;
}

/// BLAKE3 hasher implementation
pub struct Blake3Hasher;

impl Hasher for Blake3Hasher {
    fn hash<D: AsRef<[u8]>>(data: &D) -> HashOutput {
        *blake3::hash(data.as_ref()).as_bytes()
    }
}

/// An incremental hasher for streaming data
pub struct IncrementalHasher {
    hasher: blake3::Hasher,
    bytes_processed: u64,
}

impl IncrementalHasher {
    /// Create a new incremental hasher
    pub fn new() -> Self {
        Self {
            hasher: blake3::Hasher::new(),
            bytes_processed: 0,
        }
    }

    /// Create a keyed hasher for MAC generation
    pub fn new_keyed(key: &[u8; 32]) -> Self {
        Self {
            hasher: blake3::Hasher::new_keyed(key),
            bytes_processed: 0,
        }
    }

    /// Create a derive_key hasher for key derivation
    pub fn new_derive_key(context: &str) -> Self {
        Self {
            hasher: blake3::Hasher::new_derive_key(context),
            bytes_processed: 0,
        }
    }

    /// Update the hasher with more data
    pub fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
        self.bytes_processed += data.len() as u64;
    }

    /// Finalize and return the hash
    pub fn finalize(self) -> Blake3Hash {
        self.hasher.finalize().into()
    }

    /// Get the number of bytes processed
    pub fn bytes_processed(&self) -> u64 {
        self.bytes_processed
    }

    /// Reset the hasher to initial state
    pub fn reset(&mut self) {
        self.hasher.reset();
        self.bytes_processed = 0;
    }
}

impl Default for IncrementalHasher {
    fn default() -> Self {
        Self::new()
    }
}

/// Hash the given data using BLAKE3
pub fn hash(data: &[u8]) -> Blake3Hash {
    blake3::hash(data).into()
}

/// Hash multiple chunks of data
pub fn hash_chunks<I, D>(chunks: I) -> Blake3Hash
where
    I: IntoIterator<Item = D>,
    D: AsRef<[u8]>,
{
    let mut hasher = IncrementalHasher::new();
    for chunk in chunks {
        hasher.update(chunk.as_ref());
    }
    hasher.finalize()
}

/// Derive a key from the given input and context using BLAKE3 KDF
///
/// Note: For password-based or credential-based key derivation where brute-force
/// resistance is needed, use `derive_key_argon2id` instead.
pub fn derive_key(context: &str, input: &[u8]) -> Blake3Hash {
    let mut hasher = IncrementalHasher::new_derive_key(context);
    hasher.update(input);
    hasher.finalize()
}

/// Compute the **v2 client-derived user-lookup key** for the
/// global users-index (audit F-A3 / issue #15).
///
/// `userKey_v2 = BLAKE3("fula:user-lookup-v2:" || user_id || master_KEK_public)[..16]`
///
/// The key purpose is **lookup uniqueness** (mapping a user to their
/// bucketsIndex CID in the publicly-resolvable IPNS-published global
/// CBOR) without exposing the mapping to enumeration by anyone who
/// only knows `user_id` (typically email or Google `sub`).
///
/// Unlike the legacy `hash_user_id(user_id) = BLAKE3("fula:user_id:" || user_id)[..16]`,
/// which is server-derivable from a public attribute alone, this v2
/// derivation requires `master_KEK_public` — a client-derived value
/// that the server never sees. An attacker who can resolve the
/// global CBOR can no longer hash a target email and check membership.
///
/// **Effectiveness is gated by audit F-A1 (Mode B sign-up)**: if the
/// master KEK is still identity-derived (Mode A, no user-secret
/// entropy), `master_KEK_public` is also identity-derivable, so an
/// attacker who can compute master KEK can also compute `userKey_v2`.
/// The privacy improvement materialises only when paired with Mode B.
///
/// Domain separation: distinct from `hash_user_id` (`"fula:user_id:"`)
/// to prevent any cross-namespace collision.
///
/// # Arguments
/// * `user_id` — raw user identifier (email / Google `sub` bytes)
/// * `kek_pub` — 32-byte X25519 public component of the master KEK
///
/// # Returns
/// * 16-byte (128-bit) lookup key
pub fn compute_user_lookup_key_v2(user_id: &[u8], kek_pub: &[u8; 32]) -> [u8; 16] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"fula:user-lookup-v2:");
    hasher.update(user_id);
    hasher.update(kek_pub);
    let h = hasher.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&h.as_bytes()[..16]);
    out
}

/// Derive a key from the given input and context using Argon2id
///
/// This provides brute-force resistance for credential-based key derivation.
/// Uses memory-hard Argon2id algorithm with secure parameters:
/// - Memory: 64 MiB
/// - Iterations: 3
/// - Parallelism: 1 (for cross-platform consistency)
/// - Output: 32 bytes
///
/// The context string is used as the salt to provide domain separation.
///
/// # Example
/// ```
/// use fula_crypto::hashing::derive_key_argon2id;
///
/// let key = derive_key_argon2id("fula-files-v1", b"google:123456:user@example.com");
/// assert_eq!(key.len(), 32);
/// ```
pub fn derive_key_argon2id(context: &str, input: &[u8]) -> [u8; 32] {
    use argon2::{Argon2, Algorithm, Version, Params};

    // Secure parameters for credential-based key derivation
    // Memory: 64 MiB (65536 KiB) - provides memory-hardness
    // Iterations: 3 - time cost
    // Parallelism: 1 - for consistent cross-platform results
    let params = Params::new(65536, 3, 1, Some(32))
        .expect("Invalid Argon2 parameters");

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut output = [0u8; 32];

    // Use context as salt for domain separation
    // Pad or hash the context to ensure minimum 8-byte salt requirement
    let salt = if context.len() >= 8 {
        context.as_bytes().to_vec()
    } else {
        // Pad short contexts with zeros
        let mut padded = vec![0u8; 8];
        padded[..context.len()].copy_from_slice(context.as_bytes());
        padded
    };

    argon2
        .hash_password_into(input, &salt, &mut output)
        .expect("Argon2 hashing failed");

    output
}

/// Derive a key from the given input, context, and an EXPLICIT salt
/// using Argon2id.
///
/// Compared to [`derive_key_argon2id`], which uses the `context` bytes
/// as the salt, this variant takes the salt as a separate parameter so
/// callers can supply a per-user random salt. This is the load-bearing
/// piece of the audit F-A1 fix (Mode B sign-up): a per-user random
/// salt ensures that the master key is not derivable from public
/// identity attributes alone, even when an attacker knows the input.
///
/// Salt requirements (validated):
/// - Minimum 8 bytes (Argon2 spec)
/// - Recommended 16+ bytes; 32 bytes is what Mode B uses
///
/// # Panics
///
/// Panics if `salt.len() < 8` (caller error — surface this in tests).
/// Use [`derive_key_argon2id_with_salt_checked`] for a non-panicking
/// variant.
///
/// # Example
/// ```
/// use fula_crypto::hashing::derive_key_argon2id_with_salt;
///
/// let salt = [0u8; 32]; // Production: 32 random bytes per user.
/// let key = derive_key_argon2id_with_salt(
///     "fula-files-v1-google-pw",
///     b"google:123456:user@example.com:passphrase",
///     &salt,
/// );
/// assert_eq!(key.len(), 32);
/// ```
pub fn derive_key_argon2id_with_salt(context: &str, input: &[u8], salt: &[u8]) -> [u8; 32] {
    derive_key_argon2id_with_salt_checked(context, input, salt)
        .expect("derive_key_argon2id_with_salt: salt must be >= 8 bytes")
}

/// Non-panicking variant of [`derive_key_argon2id_with_salt`].
/// Returns `Err` if the salt is shorter than 8 bytes.
///
/// `context` is incorporated into the salt as a domain-separation
/// prefix: `actual_salt = blake3_keyed("fula-argon2id-v2:"||context)(salt)[..16]`
/// — concretely, we hash `(context || 0x00 || salt)` with BLAKE3 and
/// take the first 16 bytes as the Argon2 salt. This way:
///   1. Distinct contexts derive distinct keys even from the same
///      (input, salt) pair — preserves the domain-separation property
///      of the original `derive_key_argon2id`.
///   2. The caller-supplied salt is consumed.
///   3. The Argon2 salt is always exactly 16 bytes regardless of the
///      caller's salt length, so cross-platform consistency is
///      preserved (FxFiles is on native, WebUI on WASM).
pub fn derive_key_argon2id_with_salt_checked(
    context: &str,
    input: &[u8],
    salt: &[u8],
) -> std::result::Result<[u8; 32], &'static str> {
    use argon2::{Algorithm, Argon2, Params, Version};

    if salt.len() < 8 {
        return Err("salt must be at least 8 bytes");
    }

    let params = Params::new(65536, 3, 1, Some(32)).expect("Invalid Argon2 parameters");
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    // Build a deterministic 16-byte effective salt that incorporates
    // BOTH the context (domain separation) and the caller's salt. See
    // doc comment above for the rationale.
    let mut effective_salt = [0u8; 16];
    let combined = {
        let mut buf = Vec::with_capacity(context.len() + 1 + salt.len());
        buf.extend_from_slice(context.as_bytes());
        buf.push(0u8);
        buf.extend_from_slice(salt);
        buf
    };
    let h = blake3::hash(&combined);
    effective_salt.copy_from_slice(&h.as_bytes()[..16]);

    let mut output = [0u8; 32];
    argon2
        .hash_password_into(input, &effective_salt, &mut output)
        .expect("Argon2 hashing failed");

    Ok(output)
}

/// Calculate an MD5 hash for S3 ETag compatibility
pub fn md5_hash(data: &[u8]) -> String {
    use md5::{Md5, Digest};
    let mut hasher = Md5::new();
    hasher.update(data);
    let result = hasher.finalize();
    format!("{:x}", result)
}

/// Calculate an MD5 hash incrementally
pub struct Md5Hasher {
    hasher: md5::Md5,
    bytes_processed: u64,
}

impl Md5Hasher {
    pub fn new() -> Self {
        use md5::Digest;
        Self {
            hasher: md5::Md5::new(),
            bytes_processed: 0,
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        use md5::Digest;
        self.hasher.update(data);
        self.bytes_processed += data.len() as u64;
    }

    pub fn finalize(self) -> String {
        use md5::Digest;
        format!("{:x}", self.hasher.finalize())
    }

    pub fn bytes_processed(&self) -> u64 {
        self.bytes_processed
    }
}

impl Default for Md5Hasher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blake3_hash() {
        let data = b"Hello, World!";
        let hash = hash(data);
        assert!(!hash.is_zero());
        assert_eq!(hash.as_bytes().len(), HASH_BYTE_SIZE);
    }

    #[test]
    fn test_hash_consistency() {
        let data = b"test data";
        let hash1 = hash(data);
        let hash2 = hash(data);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_incremental_hasher() {
        let data = b"Hello, World!";
        
        // Full hash
        let full_hash = hash(data);
        
        // Incremental hash
        let mut hasher = IncrementalHasher::new();
        hasher.update(b"Hello, ");
        hasher.update(b"World!");
        let incremental_hash = hasher.finalize();
        
        assert_eq!(full_hash, incremental_hash);
    }

    #[test]
    fn test_hash_hex_roundtrip() {
        let data = b"test";
        let hash = hash(data);
        let hex_str = hash.to_hex();
        let parsed = Blake3Hash::from_hex(&hex_str).unwrap();
        assert_eq!(hash, parsed);
    }

    #[test]
    fn test_md5_hash() {
        let data = b"test";
        let hash = md5_hash(data);
        assert_eq!(hash.len(), 32); // MD5 produces 128 bits = 32 hex chars
    }

    #[test]
    fn test_derive_key() {
        let key1 = derive_key("context1", b"input");
        let key2 = derive_key("context2", b"input");
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_derive_key_argon2id() {
        // Test basic functionality
        let key1 = derive_key_argon2id("fula-files-v1", b"google:123456:user@example.com");
        assert_eq!(key1.len(), 32);

        // Test consistency - same input produces same output
        let key2 = derive_key_argon2id("fula-files-v1", b"google:123456:user@example.com");
        assert_eq!(key1, key2);

        // Test different context produces different key
        let key3 = derive_key_argon2id("fula-files-v2", b"google:123456:user@example.com");
        assert_ne!(key1, key3);

        // Test different input produces different key
        let key4 = derive_key_argon2id("fula-files-v1", b"google:789012:other@example.com");
        assert_ne!(key1, key4);
    }

    #[test]
    fn test_derive_key_argon2id_short_context() {
        // Test with short context (< 8 bytes) - should still work
        let key = derive_key_argon2id("short", b"input");
        assert_eq!(key.len(), 32);
    }

    // ---------------------------------------------------------------
    // Tests for `derive_key_argon2id_with_salt` (audit F-A1 / issue #14).
    //
    // The Mode B fix relies on this function consuming a per-user
    // random salt so the master key is not derivable from public
    // identity attributes alone.
    // ---------------------------------------------------------------

    #[test]
    fn argon2id_with_salt_basic_shape() {
        let salt = [0u8; 32];
        let key = derive_key_argon2id_with_salt(
            "fula-files-v1-google-pw",
            b"google:123:user@example.com:passphrase",
            &salt,
        );
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn argon2id_with_salt_distinct_salts_produce_distinct_keys() {
        let input = b"google:123:user@example.com:passphrase";
        let salt_a = [0xAAu8; 32];
        let salt_b = [0xBBu8; 32];
        let key_a = derive_key_argon2id_with_salt("ctx", input, &salt_a);
        let key_b = derive_key_argon2id_with_salt("ctx", input, &salt_b);
        assert_ne!(
            key_a, key_b,
            "salt is the load-bearing parameter for the F-A1 fix"
        );
    }

    #[test]
    fn argon2id_with_salt_distinct_contexts_produce_distinct_keys() {
        // Same input + same salt, different context → different key.
        // Preserves domain separation from the legacy function.
        let input = b"google:123:user@example.com:passphrase";
        let salt = [0x11u8; 32];
        let key_a = derive_key_argon2id_with_salt("ctx-a", input, &salt);
        let key_b = derive_key_argon2id_with_salt("ctx-b", input, &salt);
        assert_ne!(key_a, key_b);
    }

    #[test]
    fn argon2id_with_salt_deterministic() {
        let input = b"google:123:user@example.com:passphrase";
        let salt = [0x55u8; 32];
        let key_a = derive_key_argon2id_with_salt("ctx", input, &salt);
        let key_b = derive_key_argon2id_with_salt("ctx", input, &salt);
        assert_eq!(key_a, key_b);
    }

    #[test]
    fn argon2id_with_salt_rejects_short_salt() {
        let res = derive_key_argon2id_with_salt_checked("ctx", b"input", &[0u8; 7]);
        assert!(res.is_err());
    }

    #[test]
    #[should_panic(expected = "salt must be >= 8 bytes")]
    fn argon2id_with_salt_panics_on_short_salt() {
        let _ = derive_key_argon2id_with_salt("ctx", b"input", &[0u8; 7]);
    }

    #[test]
    fn argon2id_with_salt_does_not_match_legacy_even_with_context_as_salt() {
        // The new function applies a BLAKE3 domain-separation step to
        // the (context, salt) pair before passing to Argon2, so it is
        // intentionally NOT byte-equivalent to the legacy function. The
        // legacy function is kept in place for Mode A users (unchanged).
        let input = b"google:123:user@example.com";
        let legacy = derive_key_argon2id("fula-files-v1", input);
        let with_salt = derive_key_argon2id_with_salt(
            "fula-files-v1",
            input,
            b"fula-files-v1\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
        );
        assert_ne!(
            legacy, with_salt,
            "Mode A and Mode B derive distinct keys even given byte-equivalent inputs — Mode B users go through the rotation"
        );
    }
}
