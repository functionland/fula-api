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

/// Derive a key from the given input and context
pub fn derive_key(context: &str, input: &[u8]) -> Blake3Hash {
    let mut hasher = IncrementalHasher::new_derive_key(context);
    hasher.update(input);
    hasher.finalize()
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
}
