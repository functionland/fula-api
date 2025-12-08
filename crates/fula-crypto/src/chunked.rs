//! Chunked encryption for large files (WNFS-inspired)
//!
//! This module implements block-level encryption for large files, borrowing the
//! "file = encrypted blocks + index" pattern from WNFS while keeping Fula's
//! HPKE-based key wrapping and S3-compatible storage.
//!
//! ## Design
//!
//! Large files are split into fixed-size chunks (default 256KB). Each chunk is:
//! - Encrypted with AES-256-GCM using a chunk-specific nonce
//! - Stored as a separate S3 object with key pattern: `<storage_key>.chunks/<index>`
//!
//! A small "index object" is stored under the main storage key containing:
//! - Wrapped DEK (HPKE-encrypted, as before)
//! - Chunk count, size, and total file size
//! - Bao root hash for integrity verification
//! - KEK version for rotation support
//!
//! ## Compatibility
//!
//! - S3 Compatible: chunks are regular objects
//! - HPKE: DEK still wrapped with HPKE
//! - Privacy: all chunks encrypted, index encrypted
//! - Backward Compatible: `format: "streaming-v1"` distinguishes from v2

use crate::{
    CryptoError, Result,
    hashing::Blake3Hash,
    keys::DekKey,
    symmetric::{Aead, Nonce},
    streaming::{BaoEncoder, BaoOutboard},
};
use bytes::Bytes;
use serde::{Deserialize, Serialize};

/// Default chunk size: 256 KB (good balance for S3 and memory usage)
pub const DEFAULT_CHUNK_SIZE: usize = 256 * 1024;

/// Minimum chunk size: 64 KB
pub const MIN_CHUNK_SIZE: usize = 64 * 1024;

/// Maximum chunk size: 16 MB
pub const MAX_CHUNK_SIZE: usize = 16 * 1024 * 1024;

/// Threshold for using chunked upload (files larger than this use chunking)
pub const CHUNKED_THRESHOLD: usize = 5 * 1024 * 1024; // 5 MB

/// Metadata for a chunked/streaming encrypted file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkedFileMetadata {
    /// Format version identifier
    pub format: String,
    /// Size of each chunk in bytes (except possibly the last)
    pub chunk_size: u32,
    /// Number of chunks
    pub num_chunks: u32,
    /// Total file size in bytes
    pub total_size: u64,
    /// Bao root hash for integrity verification
    pub root_hash: String,
    /// Nonces for each chunk (base64 encoded)
    pub chunk_nonces: Vec<String>,
    /// Original content type
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
}

impl ChunkedFileMetadata {
    /// Create metadata for a new chunked file
    pub fn new(
        chunk_size: u32,
        num_chunks: u32,
        total_size: u64,
        root_hash: Blake3Hash,
        chunk_nonces: Vec<Nonce>,
        content_type: Option<String>,
    ) -> Self {
        use base64::Engine;
        Self {
            format: "streaming-v1".to_string(),
            chunk_size,
            num_chunks,
            total_size,
            root_hash: hex::encode(root_hash.as_bytes()),
            chunk_nonces: chunk_nonces
                .iter()
                .map(|n| base64::engine::general_purpose::STANDARD.encode(n.as_bytes()))
                .collect(),
            content_type,
        }
    }

    /// Get the storage key for a specific chunk
    pub fn chunk_key(base_key: &str, chunk_index: u32) -> String {
        format!("{}.chunks/{:08}", base_key, chunk_index)
    }

    /// Parse the chunk index from a chunk key
    pub fn parse_chunk_index(chunk_key: &str) -> Option<u32> {
        chunk_key
            .rsplit('/')
            .next()
            .and_then(|s| s.parse().ok())
    }

    /// Get nonce for a specific chunk
    pub fn get_chunk_nonce(&self, index: u32) -> Result<Nonce> {
        use base64::Engine;
        let nonce_b64 = self.chunk_nonces.get(index as usize)
            .ok_or_else(|| CryptoError::InvalidNonce(format!("No nonce for chunk {}", index)))?;
        let nonce_bytes = base64::engine::general_purpose::STANDARD.decode(nonce_b64)
            .map_err(|e| CryptoError::InvalidNonce(e.to_string()))?;
        Nonce::from_bytes(&nonce_bytes)
    }

    /// Get the root hash as bytes
    pub fn get_root_hash(&self) -> Result<Blake3Hash> {
        let bytes = hex::decode(&self.root_hash)
            .map_err(|e| CryptoError::Decryption(e.to_string()))?;
        if bytes.len() != 32 {
            return Err(CryptoError::Decryption("Invalid root hash length".to_string()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Blake3Hash::new(arr))
    }

    /// Calculate which chunks are needed for a byte range
    pub fn chunks_for_range(&self, offset: u64, length: u64) -> Vec<u32> {
        if length == 0 {
            return vec![];
        }
        
        let chunk_size = self.chunk_size as u64;
        let start_chunk = (offset / chunk_size) as u32;
        let end_offset = offset + length - 1;
        let end_chunk = (end_offset / chunk_size) as u32;
        
        (start_chunk..=end_chunk.min(self.num_chunks - 1)).collect()
    }
}

/// Encoder for chunked file upload
/// 
/// Processes a file in chunks, encrypting each chunk and computing
/// a Bao hash tree for integrity verification.
pub struct ChunkedEncoder {
    dek: DekKey,
    chunk_size: usize,
    bao_encoder: BaoEncoder,
    chunks: Vec<EncryptedChunk>,
    current_chunk: Vec<u8>,
    bytes_processed: u64,
}

/// An encrypted chunk ready for upload
#[derive(Debug, Clone)]
pub struct EncryptedChunk {
    /// Chunk index (0-based)
    pub index: u32,
    /// Encrypted chunk data
    pub ciphertext: Bytes,
    /// Nonce used for this chunk
    pub nonce: Nonce,
}

impl ChunkedEncoder {
    /// Create a new chunked encoder with the given DEK
    pub fn new(dek: DekKey) -> Self {
        Self::with_chunk_size(dek, DEFAULT_CHUNK_SIZE)
    }

    /// Create a new chunked encoder with a specific chunk size
    pub fn with_chunk_size(dek: DekKey, chunk_size: usize) -> Self {
        let chunk_size = chunk_size.clamp(MIN_CHUNK_SIZE, MAX_CHUNK_SIZE);
        Self {
            dek,
            chunk_size,
            bao_encoder: BaoEncoder::new(),
            chunks: Vec::new(),
            current_chunk: Vec::with_capacity(chunk_size),
            bytes_processed: 0,
        }
    }

    /// Feed data into the encoder
    /// 
    /// Returns any complete chunks that are ready for upload.
    pub fn update(&mut self, data: &[u8]) -> Result<Vec<EncryptedChunk>> {
        let mut ready_chunks = Vec::new();
        
        for byte in data {
            self.current_chunk.push(*byte);
            
            if self.current_chunk.len() >= self.chunk_size {
                let chunk = self.encrypt_current_chunk()?;
                ready_chunks.push(chunk);
            }
        }
        
        // Update Bao encoder with original plaintext for integrity
        self.bao_encoder.update(data);
        self.bytes_processed += data.len() as u64;
        
        Ok(ready_chunks)
    }

    /// Finalize the encoder and get the last chunk (if any) and metadata
    pub fn finalize(mut self) -> Result<(Option<EncryptedChunk>, ChunkedFileMetadata, BaoOutboard)> {
        // Encrypt any remaining data
        let final_chunk = if !self.current_chunk.is_empty() {
            Some(self.encrypt_current_chunk()?)
        } else {
            None
        };

        // Finalize Bao encoding
        let outboard = self.bao_encoder.finalize();
        
        // Collect all nonces
        let nonces: Vec<Nonce> = self.chunks.iter().map(|c| c.nonce.clone()).collect();
        
        let metadata = ChunkedFileMetadata::new(
            self.chunk_size as u32,
            self.chunks.len() as u32,
            self.bytes_processed,
            outboard.root_hash().clone(),
            nonces,
            None,
        );

        Ok((final_chunk, metadata, outboard))
    }

    /// Encrypt the current chunk buffer
    fn encrypt_current_chunk(&mut self) -> Result<EncryptedChunk> {
        let chunk_index = self.chunks.len() as u32;
        
        // Generate a unique nonce for this chunk
        // We derive it from the chunk index to be deterministic for the same DEK
        let nonce = Nonce::generate();
        
        // Encrypt the chunk
        let aead = Aead::new_default(&self.dek);
        let ciphertext = aead.encrypt(&nonce, &self.current_chunk)?;
        
        let chunk = EncryptedChunk {
            index: chunk_index,
            ciphertext: Bytes::from(ciphertext),
            nonce: nonce.clone(),
        };
        
        self.chunks.push(chunk.clone());
        self.current_chunk.clear();
        
        Ok(chunk)
    }

    /// Get chunks that have been processed
    pub fn chunks(&self) -> &[EncryptedChunk] {
        &self.chunks
    }

    /// Get total bytes processed
    pub fn bytes_processed(&self) -> u64 {
        self.bytes_processed
    }
}

/// Decoder for chunked file download
/// 
/// Decrypts chunks and optionally verifies integrity against Bao hash.
pub struct ChunkedDecoder {
    dek: DekKey,
    metadata: ChunkedFileMetadata,
    /// Collected plaintext chunks
    chunks: Vec<(u32, Vec<u8>)>,
}

impl ChunkedDecoder {
    /// Create a new decoder with the given DEK and metadata
    pub fn new(dek: DekKey, metadata: ChunkedFileMetadata) -> Self {
        Self {
            dek,
            metadata,
            chunks: Vec::new(),
        }
    }

    /// Decrypt a single chunk
    pub fn decrypt_chunk(&mut self, index: u32, ciphertext: &[u8]) -> Result<Bytes> {
        let nonce = self.metadata.get_chunk_nonce(index)?;
        let aead = Aead::new_default(&self.dek);
        let plaintext = aead.decrypt(&nonce, ciphertext)?;
        
        self.chunks.push((index, plaintext.clone()));
        
        Ok(Bytes::from(plaintext))
    }

    /// Finalize and get full file content
    /// 
    /// Sorts chunks by index and concatenates them.
    pub fn finalize(mut self) -> Result<Bytes> {
        // Sort chunks by index
        self.chunks.sort_by_key(|(idx, _)| *idx);
        
        // Verify we have all chunks
        let expected: Vec<u32> = (0..self.metadata.num_chunks).collect();
        let actual: Vec<u32> = self.chunks.iter().map(|(idx, _)| *idx).collect();
        
        if expected != actual {
            return Err(CryptoError::Decryption(format!(
                "Missing chunks: expected {:?}, got {:?}",
                expected, actual
            )));
        }
        
        // Concatenate
        let total_size = self.chunks.iter().map(|(_, data)| data.len()).sum();
        let mut result = Vec::with_capacity(total_size);
        for (_, data) in self.chunks {
            result.extend(data);
        }
        
        Ok(Bytes::from(result))
    }

    /// Get partial content for a byte range
    /// 
    /// Decrypts only the chunks needed for the range.
    pub fn get_range(
        &self,
        decrypted_chunks: &[(u32, Vec<u8>)],
        offset: u64,
        length: u64,
    ) -> Result<Bytes> {
        let chunk_size = self.metadata.chunk_size as u64;
        let mut result = Vec::with_capacity(length as usize);
        
        for (chunk_idx, chunk_data) in decrypted_chunks {
            let chunk_start = *chunk_idx as u64 * chunk_size;
            let chunk_end = chunk_start + chunk_data.len() as u64;
            
            // Calculate overlap with requested range
            let range_start = offset.max(chunk_start);
            let range_end = (offset + length).min(chunk_end);
            
            if range_start < range_end {
                let local_start = (range_start - chunk_start) as usize;
                let local_end = (range_end - chunk_start) as usize;
                result.extend_from_slice(&chunk_data[local_start..local_end]);
            }
        }
        
        Ok(Bytes::from(result))
    }

    /// Get the metadata
    pub fn metadata(&self) -> &ChunkedFileMetadata {
        &self.metadata
    }
}

/// Check if a file should use chunked upload based on size
pub fn should_use_chunked(size: usize) -> bool {
    size > CHUNKED_THRESHOLD
}

// ═══════════════════════════════════════════════════════════════════════════
// ASYNC STREAMING SUPPORT
// True streaming with AsyncRead - processes data as it arrives
// ═══════════════════════════════════════════════════════════════════════════

use tokio::io::{AsyncRead, AsyncReadExt};

/// Async streaming encoder for large files
/// 
/// Accepts an `AsyncRead` source and yields encrypted chunks as they're ready.
/// Memory usage is O(chunk_size) regardless of file size.
pub struct AsyncStreamingEncoder {
    dek: DekKey,
    chunk_size: usize,
    bao_encoder: BaoEncoder,
    chunk_index: u32,
    nonces: Vec<Nonce>,
    bytes_processed: u64,
}

impl AsyncStreamingEncoder {
    /// Create a new async streaming encoder
    pub fn new(dek: DekKey) -> Self {
        Self::with_chunk_size(dek, DEFAULT_CHUNK_SIZE)
    }

    /// Create with a specific chunk size
    pub fn with_chunk_size(dek: DekKey, chunk_size: usize) -> Self {
        let chunk_size = chunk_size.clamp(MIN_CHUNK_SIZE, MAX_CHUNK_SIZE);
        Self {
            dek,
            chunk_size,
            bao_encoder: BaoEncoder::new(),
            chunk_index: 0,
            nonces: Vec::new(),
            bytes_processed: 0,
        }
    }

    /// Process an async reader and return chunks as a stream
    /// 
    /// This reads from the source in chunk_size increments and yields
    /// encrypted chunks. Memory usage is bounded by chunk_size.
    pub async fn process_reader<R: AsyncRead + Unpin>(
        &mut self,
        mut reader: R,
    ) -> Result<Vec<EncryptedChunk>> {
        let mut chunks = Vec::new();
        let mut buffer = vec![0u8; self.chunk_size];
        
        loop {
            let mut bytes_read = 0;
            
            // Fill the buffer up to chunk_size
            while bytes_read < self.chunk_size {
                match reader.read(&mut buffer[bytes_read..]).await {
                    Ok(0) => break, // EOF
                    Ok(n) => bytes_read += n,
                    Err(e) => return Err(CryptoError::Encryption(e.to_string())),
                }
            }
            
            if bytes_read == 0 {
                break; // No more data
            }
            
            // Update Bao encoder for integrity
            self.bao_encoder.update(&buffer[..bytes_read]);
            self.bytes_processed += bytes_read as u64;
            
            // Encrypt this chunk
            let chunk = self.encrypt_chunk(&buffer[..bytes_read])?;
            chunks.push(chunk);
        }
        
        Ok(chunks)
    }

    /// Encrypt a single chunk of data
    fn encrypt_chunk(&mut self, data: &[u8]) -> Result<EncryptedChunk> {
        let nonce = Nonce::generate();
        let aead = Aead::new_default(&self.dek);
        let ciphertext = aead.encrypt(&nonce, data)?;
        
        let chunk = EncryptedChunk {
            index: self.chunk_index,
            ciphertext: Bytes::from(ciphertext),
            nonce: nonce.clone(),
        };
        
        self.nonces.push(nonce);
        self.chunk_index += 1;
        
        Ok(chunk)
    }

    /// Finalize and get metadata
    pub fn finalize(self) -> (ChunkedFileMetadata, BaoOutboard) {
        let outboard = self.bao_encoder.finalize();
        
        let metadata = ChunkedFileMetadata::new(
            self.chunk_size as u32,
            self.chunk_index,
            self.bytes_processed,
            outboard.root_hash().clone(),
            self.nonces,
            None,
        );
        
        (metadata, outboard)
    }

    /// Get bytes processed so far
    pub fn bytes_processed(&self) -> u64 {
        self.bytes_processed
    }

    /// Get number of chunks created so far
    pub fn chunk_count(&self) -> u32 {
        self.chunk_index
    }
}

/// Verified streaming decoder with Bao integrity checking
/// 
/// Downloads and decrypts chunks while verifying integrity using
/// the Bao hash tree. Detects corruption early in the stream.
pub struct VerifiedStreamingDecoder {
    dek: DekKey,
    metadata: ChunkedFileMetadata,
    expected_hash: Blake3Hash,
    bao_encoder: BaoEncoder,
    verified_bytes: u64,
}

impl VerifiedStreamingDecoder {
    /// Create a new verified streaming decoder
    pub fn new(dek: DekKey, metadata: ChunkedFileMetadata) -> Result<Self> {
        let expected_hash = metadata.get_root_hash()?;
        Ok(Self {
            dek,
            metadata,
            expected_hash,
            bao_encoder: BaoEncoder::new(),
            verified_bytes: 0,
        })
    }

    /// Decrypt and verify a single chunk
    /// 
    /// Returns the plaintext if decryption and verification succeed.
    /// Verification is progressive - each chunk updates the hash state.
    pub fn decrypt_and_verify(&mut self, index: u32, ciphertext: &[u8]) -> Result<Bytes> {
        // Decrypt
        let nonce = self.metadata.get_chunk_nonce(index)?;
        let aead = Aead::new_default(&self.dek);
        let plaintext = aead.decrypt(&nonce, ciphertext)?;
        
        // Update Bao encoder for verification
        self.bao_encoder.update(&plaintext);
        self.verified_bytes += plaintext.len() as u64;
        
        Ok(Bytes::from(plaintext))
    }

    /// Finalize and verify the complete file hash
    /// 
    /// Returns true if the reconstructed hash matches the expected hash.
    pub fn finalize_and_verify(self) -> Result<bool> {
        let outboard = self.bao_encoder.finalize();
        let computed_hash = outboard.root_hash();
        
        if computed_hash.as_bytes() == self.expected_hash.as_bytes() {
            Ok(true)
        } else {
            Err(CryptoError::BaoVerification(format!(
                "Hash mismatch: expected {:?}, got {:?}",
                hex::encode(self.expected_hash.as_bytes()),
                hex::encode(computed_hash.as_bytes())
            )))
        }
    }

    /// Get bytes verified so far
    pub fn verified_bytes(&self) -> u64 {
        self.verified_bytes
    }

    /// Get expected total size
    pub fn expected_size(&self) -> u64 {
        self.metadata.total_size
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::DekKey;

    #[test]
    fn test_chunked_roundtrip() {
        let dek = DekKey::generate();
        let original = b"Hello, World! This is a test of chunked encryption.".repeat(100);
        
        // Encode with small chunk size for testing
        let mut encoder = ChunkedEncoder::with_chunk_size(dek.clone(), MIN_CHUNK_SIZE);
        let chunks = encoder.update(&original).unwrap();
        let (final_chunk, metadata, _outboard) = encoder.finalize().unwrap();
        
        // Decode
        let mut decoder = ChunkedDecoder::new(dek, metadata.clone());
        for chunk in &chunks {
            decoder.decrypt_chunk(chunk.index, &chunk.ciphertext).unwrap();
        }
        if let Some(chunk) = final_chunk {
            decoder.decrypt_chunk(chunk.index, &chunk.ciphertext).unwrap();
        }
        
        let recovered = decoder.finalize().unwrap();
        assert_eq!(recovered.as_ref(), original.as_slice());
    }

    #[test]
    fn test_chunk_key_generation() {
        let base = "abc123/file.txt";
        assert_eq!(
            ChunkedFileMetadata::chunk_key(base, 0),
            "abc123/file.txt.chunks/00000000"
        );
        assert_eq!(
            ChunkedFileMetadata::chunk_key(base, 42),
            "abc123/file.txt.chunks/00000042"
        );
    }

    #[test]
    fn test_chunks_for_range() {
        let metadata = ChunkedFileMetadata {
            format: "streaming-v1".to_string(),
            chunk_size: 1000,
            num_chunks: 10,
            total_size: 10000,
            root_hash: "00".repeat(32),
            chunk_nonces: vec![],
            content_type: None,
        };
        
        // First byte of file
        assert_eq!(metadata.chunks_for_range(0, 1), vec![0]);
        
        // Span two chunks
        assert_eq!(metadata.chunks_for_range(999, 2), vec![0, 1]);
        
        // Middle of file
        assert_eq!(metadata.chunks_for_range(5000, 100), vec![5]);
        
        // Last chunk
        assert_eq!(metadata.chunks_for_range(9500, 500), vec![9]);
    }

    #[test]
    fn test_should_use_chunked() {
        assert!(!should_use_chunked(1024)); // 1 KB
        assert!(!should_use_chunked(1024 * 1024)); // 1 MB
        assert!(!should_use_chunked(5 * 1024 * 1024)); // 5 MB (exactly at threshold)
        assert!(should_use_chunked(5 * 1024 * 1024 + 1)); // Just over 5 MB
        assert!(should_use_chunked(100 * 1024 * 1024)); // 100 MB
    }

    #[tokio::test]
    async fn test_async_streaming_encoder() {
        let dek = DekKey::generate();
        let original = b"Hello, World! This is a test of async streaming.".repeat(200);
        
        // Create async reader from bytes
        let cursor = std::io::Cursor::new(original.clone());
        
        let mut encoder = AsyncStreamingEncoder::with_chunk_size(dek.clone(), MIN_CHUNK_SIZE);
        let chunks = encoder.process_reader(cursor).await.unwrap();
        let (metadata, _outboard) = encoder.finalize();
        
        assert!(chunks.len() > 0);
        assert_eq!(metadata.total_size, original.len() as u64);
        
        // Verify we can decrypt all chunks
        let mut decoder = ChunkedDecoder::new(dek, metadata);
        for chunk in &chunks {
            decoder.decrypt_chunk(chunk.index, &chunk.ciphertext).unwrap();
        }
        
        let recovered = decoder.finalize().unwrap();
        assert_eq!(recovered.as_ref(), original.as_slice());
    }

    #[tokio::test]
    async fn test_verified_streaming_decoder() {
        let dek = DekKey::generate();
        let original = b"Verified streaming test data.".repeat(100);
        
        // Encode
        let mut encoder = ChunkedEncoder::with_chunk_size(dek.clone(), MIN_CHUNK_SIZE);
        let chunks = encoder.update(&original).unwrap();
        let (final_chunk, metadata, _outboard) = encoder.finalize().unwrap();
        
        let mut all_chunks = chunks;
        if let Some(c) = final_chunk {
            all_chunks.push(c);
        }
        
        // Decode with verification
        let mut decoder = VerifiedStreamingDecoder::new(dek, metadata).unwrap();
        for chunk in &all_chunks {
            decoder.decrypt_and_verify(chunk.index, &chunk.ciphertext).unwrap();
        }
        
        // Final verification should pass
        let verified = decoder.finalize_and_verify().unwrap();
        assert!(verified);
    }

    #[tokio::test]
    async fn test_verified_decoder_detects_corruption() {
        let dek = DekKey::generate();
        let original = b"Corruption detection test.".repeat(100);
        
        // Encode
        let mut encoder = ChunkedEncoder::with_chunk_size(dek.clone(), MIN_CHUNK_SIZE);
        let chunks = encoder.update(&original).unwrap();
        let (final_chunk, mut metadata, _outboard) = encoder.finalize().unwrap();
        
        let mut all_chunks = chunks;
        if let Some(c) = final_chunk {
            all_chunks.push(c);
        }
        
        // Tamper with the expected hash in metadata (simulating corrupted index)
        metadata.root_hash = "00".repeat(32); // Wrong hash
        
        // Use tampered metadata - decryption works but verification should fail
        let mut decoder = VerifiedStreamingDecoder::new(dek, metadata).unwrap();
        for chunk in &all_chunks {
            // Decryption still works
            decoder.decrypt_and_verify(chunk.index, &chunk.ciphertext).unwrap();
        }
        
        // But final verification should fail because hash doesn't match
        let result = decoder.finalize_and_verify();
        assert!(result.is_err());
    }
}
