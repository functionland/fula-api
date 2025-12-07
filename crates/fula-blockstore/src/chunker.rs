//! File chunking for IPFS storage
//!
//! Splits large files into blocks for efficient storage and retrieval

use crate::{Block, BlockStoreError, Result, DEFAULT_CHUNK_SIZE, MAX_BLOCK_SIZE};
use bytes::Bytes;
use fula_crypto::hashing::{IncrementalHasher, Blake3Hash};
use std::io::Read;

/// Configuration for the chunker
#[derive(Clone, Debug)]
pub struct ChunkerConfig {
    /// Size of each chunk in bytes
    pub chunk_size: usize,
    /// Whether to compute hashes during chunking
    pub compute_hash: bool,
    /// Whether to encrypt chunks
    pub encrypt: bool,
}

impl Default for ChunkerConfig {
    fn default() -> Self {
        Self {
            chunk_size: DEFAULT_CHUNK_SIZE,
            compute_hash: true,
            encrypt: false,
        }
    }
}

impl ChunkerConfig {
    /// Create with a custom chunk size
    pub fn with_chunk_size(chunk_size: usize) -> Result<Self> {
        if chunk_size == 0 || chunk_size > MAX_BLOCK_SIZE {
            return Err(BlockStoreError::Configuration(format!(
                "chunk size must be between 1 and {} bytes",
                MAX_BLOCK_SIZE
            )));
        }
        Ok(Self {
            chunk_size,
            ..Default::default()
        })
    }
}

/// Result of chunking a file
#[derive(Clone, Debug)]
pub struct ChunkResult {
    /// The chunks produced
    pub chunks: Vec<Block>,
    /// Total size of the original data
    pub total_size: u64,
    /// Hash of the complete file
    pub file_hash: Blake3Hash,
    /// Number of chunks
    pub chunk_count: usize,
}

impl ChunkResult {
    /// Get all CIDs in order
    pub fn cids(&self) -> Vec<cid::Cid> {
        self.chunks.iter().map(|c| c.cid).collect()
    }

    /// Get total chunked size (may differ due to padding)
    pub fn chunked_size(&self) -> u64 {
        self.chunks.iter().map(|c| c.size() as u64).sum()
    }
}

/// Chunker for splitting data into blocks
pub struct Chunker {
    config: ChunkerConfig,
}

impl Chunker {
    /// Create a new chunker with default configuration
    pub fn new() -> Self {
        Self {
            config: ChunkerConfig::default(),
        }
    }

    /// Create with custom configuration
    pub fn with_config(config: ChunkerConfig) -> Self {
        Self { config }
    }

    /// Chunk data from a byte slice
    pub fn chunk_bytes(&self, data: &[u8]) -> ChunkResult {
        let mut chunks = Vec::new();
        let mut hasher = IncrementalHasher::new();
        
        for chunk_data in data.chunks(self.config.chunk_size) {
            hasher.update(chunk_data);
            let block = Block::from_data(Bytes::copy_from_slice(chunk_data));
            chunks.push(block);
        }

        ChunkResult {
            chunk_count: chunks.len(),
            total_size: data.len() as u64,
            file_hash: hasher.finalize(),
            chunks,
        }
    }

    /// Chunk data from a reader
    pub fn chunk_reader<R: Read>(&self, mut reader: R) -> Result<ChunkResult> {
        let mut chunks = Vec::new();
        let mut hasher = IncrementalHasher::new();
        let mut buffer = vec![0u8; self.config.chunk_size];
        let mut total_size = 0u64;

        loop {
            let bytes_read = reader.read(&mut buffer)?;
            if bytes_read == 0 {
                break;
            }

            let chunk_data = &buffer[..bytes_read];
            hasher.update(chunk_data);
            let block = Block::from_data(Bytes::copy_from_slice(chunk_data));
            chunks.push(block);
            total_size += bytes_read as u64;
        }

        Ok(ChunkResult {
            chunk_count: chunks.len(),
            total_size,
            file_hash: hasher.finalize(),
            chunks,
        })
    }

    /// Chunk with progress callback
    pub fn chunk_with_progress<R: Read, F: FnMut(u64, u64)>(
        &self,
        mut reader: R,
        total_hint: Option<u64>,
        mut progress: F,
    ) -> Result<ChunkResult> {
        let mut chunks = Vec::new();
        let mut hasher = IncrementalHasher::new();
        let mut buffer = vec![0u8; self.config.chunk_size];
        let mut bytes_processed = 0u64;

        loop {
            let bytes_read = reader.read(&mut buffer)?;
            if bytes_read == 0 {
                break;
            }

            let chunk_data = &buffer[..bytes_read];
            hasher.update(chunk_data);
            let block = Block::from_data(Bytes::copy_from_slice(chunk_data));
            chunks.push(block);
            bytes_processed += bytes_read as u64;

            // Report progress
            progress(bytes_processed, total_hint.unwrap_or(bytes_processed));
        }

        Ok(ChunkResult {
            chunk_count: chunks.len(),
            total_size: bytes_processed,
            file_hash: hasher.finalize(),
            chunks,
        })
    }

    /// Reassemble chunks back into data
    pub fn reassemble(&self, chunks: &[Block]) -> Bytes {
        let total_size: usize = chunks.iter().map(|c| c.size()).sum();
        let mut result = Vec::with_capacity(total_size);
        
        for chunk in chunks {
            result.extend_from_slice(&chunk.data);
        }
        
        Bytes::from(result)
    }

    /// Get the chunk size
    pub fn chunk_size(&self) -> usize {
        self.config.chunk_size
    }
}

impl Default for Chunker {
    fn default() -> Self {
        Self::new()
    }
}

/// Calculate how many chunks will be needed for a given size
pub fn calculate_chunk_count(size: u64, chunk_size: usize) -> usize {
    if size == 0 {
        return 0;
    }
    (size as usize + chunk_size - 1) / chunk_size
}

/// Calculate the size of the last chunk
pub fn last_chunk_size(total_size: u64, chunk_size: usize) -> usize {
    if total_size == 0 {
        return 0;
    }
    let remainder = (total_size as usize) % chunk_size;
    if remainder == 0 {
        chunk_size
    } else {
        remainder
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chunk_bytes() {
        let data = vec![0u8; 1024 * 1024]; // 1 MB
        let chunker = Chunker::new();
        let result = chunker.chunk_bytes(&data);

        assert_eq!(result.total_size, 1024 * 1024);
        assert_eq!(result.chunk_count, 4); // 1MB / 256KB = 4
        assert!(!result.file_hash.is_zero());
    }

    #[test]
    fn test_chunk_small_data() {
        let data = b"Hello, World!";
        let chunker = Chunker::new();
        let result = chunker.chunk_bytes(data);

        assert_eq!(result.chunk_count, 1);
        assert_eq!(result.total_size, 13);
    }

    #[test]
    fn test_chunk_empty() {
        let data: &[u8] = &[];
        let chunker = Chunker::new();
        let result = chunker.chunk_bytes(data);

        assert_eq!(result.chunk_count, 0);
        assert_eq!(result.total_size, 0);
    }

    #[test]
    fn test_reassemble() {
        let original = vec![1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let config = ChunkerConfig::with_chunk_size(3).unwrap();
        let chunker = Chunker::with_config(config);
        
        let result = chunker.chunk_bytes(&original);
        let reassembled = chunker.reassemble(&result.chunks);
        
        assert_eq!(original.as_slice(), reassembled.as_ref());
    }

    #[test]
    fn test_chunk_reader() {
        let data = vec![0u8; 1000];
        let reader = std::io::Cursor::new(data.clone());
        let chunker = Chunker::new();
        
        let result = chunker.chunk_reader(reader).unwrap();
        let reassembled = chunker.reassemble(&result.chunks);
        
        assert_eq!(data.as_slice(), reassembled.as_ref());
    }

    #[test]
    fn test_calculate_chunk_count() {
        assert_eq!(calculate_chunk_count(0, 256), 0);
        assert_eq!(calculate_chunk_count(100, 256), 1);
        assert_eq!(calculate_chunk_count(256, 256), 1);
        assert_eq!(calculate_chunk_count(257, 256), 2);
        assert_eq!(calculate_chunk_count(1024, 256), 4);
    }

    #[test]
    fn test_last_chunk_size() {
        assert_eq!(last_chunk_size(0, 256), 0);
        assert_eq!(last_chunk_size(100, 256), 100);
        assert_eq!(last_chunk_size(256, 256), 256);
        assert_eq!(last_chunk_size(300, 256), 44);
    }

    #[test]
    fn test_hash_consistency() {
        let data = b"consistent data";
        let chunker = Chunker::new();
        
        let result1 = chunker.chunk_bytes(data);
        let result2 = chunker.chunk_bytes(data);
        
        assert_eq!(result1.file_hash, result2.file_hash);
    }
}
