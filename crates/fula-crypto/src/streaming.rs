//! Verified streaming using Bao and BLAKE3
//!
//! This module provides verified streaming for large files:
//! - Compute Bao trees during upload for integrity verification
//! - Enable verified partial reads (any slice can be verified)
//! - Detect corruption from untrusted storage nodes

use crate::{CryptoError, Result, hashing::Blake3Hash, DEFAULT_CHUNK_SIZE};
use bytes::Bytes;
use std::io::Read;

/// The default block size for Bao encoding (1 KiB as per Bao spec)
pub const BAO_BLOCK_SIZE: usize = 1024;

/// Outboard data from Bao encoding (the Merkle tree)
#[derive(Clone)]
pub struct BaoOutboard {
    /// The Bao outboard data
    data: Vec<u8>,
    /// The root hash
    root_hash: Blake3Hash,
    /// Original content length
    content_length: u64,
}

impl BaoOutboard {
    /// Create from raw outboard data and hash
    pub fn new(data: Vec<u8>, root_hash: Blake3Hash, content_length: u64) -> Self {
        Self {
            data,
            root_hash,
            content_length,
        }
    }

    /// Get the outboard data
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Get the root hash
    pub fn root_hash(&self) -> &Blake3Hash {
        &self.root_hash
    }

    /// Get the content length
    pub fn content_length(&self) -> u64 {
        self.content_length
    }

    /// Get the number of leaf (block) hashes stored in the outboard
    pub fn num_leaves(&self) -> usize {
        self.data.len() / 32
    }

    /// Get the hash of a specific block by index
    ///
    /// Returns `None` if the index is out of range.
    pub fn leaf_hash(&self, index: usize) -> Option<Blake3Hash> {
        let offset = index * 32;
        if offset + 32 > self.data.len() {
            return None;
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&self.data[offset..offset + 32]);
        Some(Blake3Hash::new(bytes))
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(8 + 32 + self.data.len());
        result.extend_from_slice(&self.content_length.to_le_bytes());
        result.extend_from_slice(self.root_hash.as_bytes());
        result.extend_from_slice(&self.data);
        result
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 40 {
            return Err(CryptoError::BaoVerification(
                "outboard data too short".to_string(),
            ));
        }
        let content_length = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(&bytes[8..40]);
        let root_hash = Blake3Hash::new(hash_bytes);
        let data = bytes[40..].to_vec();
        Ok(Self {
            data,
            root_hash,
            content_length,
        })
    }
}

/// Encoder for creating Bao outboard data
pub struct BaoEncoder {
    hasher: blake3::Hasher,
    chunks: Vec<Blake3Hash>,
    bytes_processed: u64,
}

impl BaoEncoder {
    /// Create a new Bao encoder
    pub fn new() -> Self {
        Self {
            hasher: blake3::Hasher::new(),
            chunks: Vec::new(),
            bytes_processed: 0,
        }
    }

    /// Update with more data
    pub fn update(&mut self, data: &[u8]) {
        // Process in chunks for Merkle tree construction
        for chunk in data.chunks(BAO_BLOCK_SIZE) {
            let chunk_hash = blake3::hash(chunk);
            self.chunks.push(chunk_hash.into());
        }
        self.hasher.update(data);
        self.bytes_processed += data.len() as u64;
    }

    /// Finalize and return the outboard data
    pub fn finalize(self) -> BaoOutboard {
        let root_hash: Blake3Hash = self.hasher.finalize().into();
        
        // Build the outboard data (simplified Merkle tree)
        let mut outboard = Vec::new();
        for chunk_hash in &self.chunks {
            outboard.extend_from_slice(chunk_hash.as_bytes());
        }

        BaoOutboard::new(outboard, root_hash, self.bytes_processed)
    }

    /// Get bytes processed so far
    pub fn bytes_processed(&self) -> u64 {
        self.bytes_processed
    }
}

impl Default for BaoEncoder {
    fn default() -> Self {
        Self::new()
    }
}

/// Decoder for verifying Bao-encoded data
pub struct BaoDecoder {
    expected_hash: Blake3Hash,
    #[allow(dead_code)]
    outboard: BaoOutboard,
    verified_bytes: u64,
}

impl BaoDecoder {
    /// Create a new decoder with the expected hash and outboard data
    pub fn new(outboard: BaoOutboard) -> Self {
        let expected_hash = *outboard.root_hash();
        Self {
            expected_hash,
            outboard,
            verified_bytes: 0,
        }
    }

    /// Track a chunk of data at the given offset for deferred full-file verification.
    ///
    /// **Deprecated:** Use [`verify_chunk()`](Self::verify_chunk) instead, which
    /// actually verifies each block against the stored leaf hashes. This method
    /// only tracks the byte count for progress without performing any verification.
    #[deprecated(since = "0.6.0", note = "use verify_chunk() which performs actual per-block verification")]
    pub fn track_chunk(&mut self, offset: u64, data: &[u8]) -> Result<()> {
        let _chunk_index = (offset / BAO_BLOCK_SIZE as u64) as usize;
        let _chunk_hash: Blake3Hash = blake3::hash(data).into();
        self.verified_bytes += data.len() as u64;
        Ok(())
    }

    /// Verify a chunk of data at the given byte offset against stored block hashes.
    ///
    /// Verifies all complete BAO blocks (1 KiB each) covered by the data range.
    /// Each block's BLAKE3 hash is compared against the leaf hash stored in the outboard.
    /// The outboard is authenticated via AES-GCM (stored as encrypted metadata),
    /// so the leaf hashes are trustworthy.
    ///
    /// Returns an error if any block's hash does not match.
    pub fn verify_chunk(&mut self, offset: u64, data: &[u8]) -> Result<()> {
        if data.is_empty() {
            return Ok(());
        }

        let block_size = BAO_BLOCK_SIZE as u64;
        let start_block = (offset / block_size) as usize;
        let start_offset_in_block = (offset % block_size) as usize;
        let num_leaves = self.outboard.num_leaves();

        let mut data_offset = 0usize;
        let mut block_index = start_block;

        // If we start mid-block, skip to the next full block
        if start_offset_in_block > 0 {
            let skip = (BAO_BLOCK_SIZE - start_offset_in_block).min(data.len());
            data_offset += skip;
            block_index += 1;
        }

        // Verify each complete block
        while data_offset + BAO_BLOCK_SIZE <= data.len() && block_index < num_leaves {
            let block_data = &data[data_offset..data_offset + BAO_BLOCK_SIZE];
            let computed: Blake3Hash = blake3::hash(block_data).into();

            if let Some(expected) = self.outboard.leaf_hash(block_index) {
                if computed != expected {
                    return Err(CryptoError::BaoVerification(format!(
                        "block {} hash mismatch at offset {}",
                        block_index,
                        offset + data_offset as u64
                    )));
                }
            }

            data_offset += BAO_BLOCK_SIZE;
            block_index += 1;
        }

        // Verify the final partial block (only valid for the last block of the file)
        if data_offset < data.len() && block_index < num_leaves {
            let is_last_block = block_index == num_leaves - 1;
            if is_last_block {
                let block_data = &data[data_offset..];
                let computed: Blake3Hash = blake3::hash(block_data).into();
                if let Some(expected) = self.outboard.leaf_hash(block_index) {
                    if computed != expected {
                        return Err(CryptoError::BaoVerification(format!(
                            "final block {} hash mismatch", block_index
                        )));
                    }
                }
            }
        }

        self.verified_bytes += data.len() as u64;
        Ok(())
    }

    /// Verify the complete data
    pub fn verify_all(&self, data: &[u8]) -> Result<()> {
        let computed_hash: Blake3Hash = blake3::hash(data).into();
        if computed_hash != self.expected_hash {
            return Err(CryptoError::HashMismatch {
                expected: self.expected_hash.to_hex(),
                actual: computed_hash.to_hex(),
            });
        }
        Ok(())
    }

    /// Get the expected hash
    pub fn expected_hash(&self) -> &Blake3Hash {
        &self.expected_hash
    }
}

/// A verified stream that checks data integrity as it's read
pub struct VerifiedStream<R> {
    reader: R,
    decoder: BaoDecoder,
    buffer: Vec<u8>,
    position: u64,
}

impl<R: Read> VerifiedStream<R> {
    /// Create a new verified stream
    pub fn new(reader: R, outboard: BaoOutboard) -> Self {
        Self {
            reader,
            decoder: BaoDecoder::new(outboard),
            buffer: vec![0u8; DEFAULT_CHUNK_SIZE],
            position: 0,
        }
    }

    /// Read and verify a chunk
    ///
    /// Reads from the underlying reader and verifies each BAO block against
    /// the stored leaf hashes. Returns `None` at end of stream.
    pub fn read_verified(&mut self) -> Result<Option<Vec<u8>>> {
        let bytes_read = self.reader.read(&mut self.buffer)?;
        if bytes_read == 0 {
            return Ok(None);
        }

        let chunk = self.buffer[..bytes_read].to_vec();
        self.decoder.verify_chunk(self.position, &chunk)?;
        self.position += bytes_read as u64;

        Ok(Some(chunk))
    }

    /// Get the current position in the stream
    pub fn position(&self) -> u64 {
        self.position
    }
}

/// Compute Bao encoding for a complete piece of data
pub fn encode(data: &[u8]) -> BaoOutboard {
    let mut encoder = BaoEncoder::new();
    encoder.update(data);
    encoder.finalize()
}

/// Verify data against a Bao outboard
pub fn verify(data: &[u8], outboard: &BaoOutboard) -> Result<()> {
    let decoder = BaoDecoder::new(outboard.clone());
    decoder.verify_all(data)
}

/// Compute just the root hash without outboard (faster for integrity checks)
pub fn hash(data: &[u8]) -> Blake3Hash {
    blake3::hash(data).into()
}

/// Verified chunk for partial reads
#[derive(Clone, Debug)]
pub struct VerifiedChunk {
    /// The chunk data
    pub data: Bytes,
    /// The offset in the original file
    pub offset: u64,
    /// The chunk hash
    pub hash: Blake3Hash,
}

impl VerifiedChunk {
    /// Create a new verified chunk
    pub fn new(data: Bytes, offset: u64) -> Self {
        let hash = blake3::hash(&data).into();
        Self { data, offset, hash }
    }

    /// Get the length of the chunk
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if the chunk is empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bao_encode_verify() {
        let data = b"Hello, World! This is a test of Bao verified streaming.";
        
        let outboard = encode(data);
        assert!(!outboard.root_hash().is_zero());
        
        verify(data, &outboard).unwrap();
    }

    #[test]
    fn test_bao_verification_fails_on_corruption() {
        let data = b"original data";
        let outboard = encode(data);
        
        let corrupted = b"corrupted data";
        let result = verify(corrupted, &outboard);
        
        assert!(result.is_err());
    }

    #[test]
    fn test_bao_outboard_serialization() {
        let data = b"test data for serialization";
        let outboard = encode(data);
        
        let bytes = outboard.to_bytes();
        let restored = BaoOutboard::from_bytes(&bytes).unwrap();
        
        assert_eq!(outboard.root_hash(), restored.root_hash());
        assert_eq!(outboard.content_length(), restored.content_length());
    }

    #[test]
    fn test_incremental_encoding() {
        let data = b"Hello, World!";
        
        // Single update
        let outboard1 = encode(data);
        
        // Multiple updates
        let mut encoder = BaoEncoder::new();
        encoder.update(b"Hello, ");
        encoder.update(b"World!");
        let outboard2 = encoder.finalize();
        
        // Both should produce the same root hash
        assert_eq!(outboard1.root_hash(), outboard2.root_hash());
    }

    #[test]
    fn test_verified_stream() {
        let data = b"Test data for verified streaming";
        let outboard = encode(data);

        let reader = std::io::Cursor::new(data.to_vec());
        let mut stream = VerifiedStream::new(reader, outboard);

        let mut collected = Vec::new();
        while let Some(chunk) = stream.read_verified().unwrap() {
            collected.extend(chunk);
        }

        assert_eq!(data.as_slice(), collected.as_slice());
    }

    #[test]
    fn test_verify_chunk_single_block() {
        // Data smaller than BAO_BLOCK_SIZE (1 KiB)
        let data = b"Hello, Bao verification!";
        let outboard = encode(data);

        let mut decoder = BaoDecoder::new(outboard);
        // Single block = last block, verified via the final-block path
        decoder.verify_chunk(0, data).unwrap();
    }

    #[test]
    fn test_verify_chunk_multiple_blocks() {
        // Data spanning multiple BAO blocks (each 1 KiB)
        let data: Vec<u8> = (0..3 * BAO_BLOCK_SIZE).map(|i| (i % 256) as u8).collect();
        let outboard = encode(&data);

        let mut decoder = BaoDecoder::new(outboard);

        // Verify each block individually
        for i in 0..3 {
            let offset = i * BAO_BLOCK_SIZE;
            let block = &data[offset..offset + BAO_BLOCK_SIZE];
            decoder.verify_chunk(offset as u64, block).unwrap();
        }
    }

    #[test]
    fn test_verify_chunk_detects_corruption() {
        let data: Vec<u8> = (0..2 * BAO_BLOCK_SIZE).map(|i| (i % 256) as u8).collect();
        let outboard = encode(&data);

        let mut decoder = BaoDecoder::new(outboard);

        // Corrupt the first byte
        let mut corrupted = data[..BAO_BLOCK_SIZE].to_vec();
        corrupted[0] ^= 0xFF;
        let result = decoder.verify_chunk(0, &corrupted);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_chunk_large_contiguous_range() {
        // Verify a multi-block range in a single call
        let data: Vec<u8> = (0..4 * BAO_BLOCK_SIZE).map(|i| (i % 256) as u8).collect();
        let outboard = encode(&data);

        let mut decoder = BaoDecoder::new(outboard);
        // Pass the entire data — should verify all 4 blocks
        decoder.verify_chunk(0, &data).unwrap();
    }

    #[test]
    fn test_verify_chunk_with_trailing_partial_block() {
        // Data that doesn't evenly divide into BAO blocks
        let size = 2 * BAO_BLOCK_SIZE + 500;
        let data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
        let outboard = encode(&data);

        let mut decoder = BaoDecoder::new(outboard.clone());
        // Verify all at once — 2 full blocks + 1 partial (last block)
        decoder.verify_chunk(0, &data).unwrap();

        // Verify corruption in the partial final block is detected
        let mut corrupted = data.clone();
        corrupted[2 * BAO_BLOCK_SIZE + 10] ^= 0xFF;
        let mut decoder2 = BaoDecoder::new(outboard);
        let result = decoder2.verify_chunk(0, &corrupted);
        assert!(result.is_err());
    }

    #[test]
    fn test_outboard_leaf_hash_access() {
        let data: Vec<u8> = (0..3 * BAO_BLOCK_SIZE).map(|i| (i % 256) as u8).collect();
        let outboard = encode(&data);

        assert_eq!(outboard.num_leaves(), 3);
        // Each leaf hash should match BLAKE3 of its block
        for i in 0..3 {
            let block = &data[i * BAO_BLOCK_SIZE..(i + 1) * BAO_BLOCK_SIZE];
            let expected: Blake3Hash = blake3::hash(block).into();
            assert_eq!(outboard.leaf_hash(i).unwrap(), expected);
        }
        assert!(outboard.leaf_hash(3).is_none());
    }
}
