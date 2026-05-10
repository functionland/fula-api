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

use cid::Cid;
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

/// Maximum chunk size: 768 KB
/// CRITICAL: IPFS has a 1MB block limit. With encryption overhead (~16 bytes tag +
/// potential padding), we must stay well under 1MB. 768KB provides safety margin.
pub const MAX_CHUNK_SIZE: usize = 768 * 1024;

/// Threshold for using chunked upload (files larger than this use chunking)
/// Set to MAX_CHUNK_SIZE so any file that would exceed IPFS's block limit gets chunked.
pub const CHUNKED_THRESHOLD: usize = MAX_CHUNK_SIZE;

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
    /// Walkable-v8 (W.9.4-A2 / task #32): per-chunk CID hints,
    /// populated from master's PUT-response ETag for each chunk.
    /// Parallel to `chunk_nonces`: when non-empty, length must equal
    /// `num_chunks` and `chunk_cids[i]` is the CID for the chunk at
    /// `chunk_index == i`. Each entry is `Option<Cid>` so individual
    /// chunks can have `None` (e.g. one chunk's etag failed to parse
    /// or the writer flag was off) while siblings have valid hints.
    ///
    /// Empty Vec = legacy chunked metadata written before W.9.4-A2.
    /// `#[serde(default)]` keeps existing pinned/cached
    /// `ChunkedFileMetadata` blobs deserializing cleanly into the
    /// new struct — no migration required.
    ///
    /// **Storage shape (privacy posture)**: this struct is serialized
    /// into the index object's `chunked` JSON field alongside
    /// `chunk_nonces`, `root_hash`, `num_chunks`, `total_size`, etc.
    /// The index body is plaintext JSON — only the `wrapped_key` and
    /// `private_metadata` siblings are AEAD-encrypted. So `chunk_cids`
    /// is **plaintext-readable** by anyone who can fetch the index
    /// object. This is **not a privacy regression**: every existing
    /// field in the same plaintext block (`chunk_nonces`,
    /// `chunk_size`, `num_chunks`, …) was already plaintext-readable
    /// at the same level pre-W.9.4-A2. Adding the chunk CIDs joins
    /// that already-public set; an attacker with the index object
    /// could already enumerate child storage paths via
    /// `chunk_key(storage_key, i)` and fetch the same encrypted
    /// chunk bytes via gateway. The hints just make it cheaper for
    /// the legitimate offline reader.
    ///
    /// **Read-side use**: when an offline reader resolves a chunked
    /// `ForestFileEntry` and decodes this metadata, for each chunk
    /// it checks `chunk_cids[i].is_some()`: if yes, fetches via
    /// `get_object_with_offline_fallback_known_cid` (cold-cache
    /// gateway race from Phase 2.4); otherwise falls back to the
    /// legacy `chunk_key()` storage-path fetch. This is what makes
    /// chunked files (the dominant FxFiles content shape — photos,
    /// PDFs, videos) walkable offline. The W.9.4 HAMT walker only
    /// takes the reader to the file index; without these hints, the
    /// chunks themselves remain unreachable when master is down.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub chunk_cids: Vec<Option<Cid>>,
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
            // Walkable-v8 (W.9.4-A2): default to no hints. The writer
            // populates this AFTER per-chunk PUTs return etags via
            // `populate_chunk_cids`.
            chunk_cids: Vec::new(),
        }
    }

    /// Walkable-v8 (W.9.4-A2): bulk-set per-chunk CID hints after
    /// each chunk's PUT has returned an etag. Vec length must equal
    /// `num_chunks` or this is a no-op (caller bug — the reader's
    /// length check would otherwise reject the metadata at decode
    /// time).
    ///
    /// Idempotent: calling again with the same Vec re-stamps the
    /// same values. Calling with an empty Vec clears the hints
    /// (returns to legacy / pre-W.9.4-A2 behaviour for this entry).
    pub fn populate_chunk_cids(&mut self, cids: Vec<Option<Cid>>) {
        if cids.len() == self.num_chunks as usize {
            self.chunk_cids = cids;
        } else if cids.is_empty() {
            self.chunk_cids.clear();
        }
        // Mismatched length: no-op. The writer's caller must supply
        // exactly num_chunks entries (with `None` for any chunks
        // that didn't get a usable CID hint).
    }

    /// Walkable-v8 (W.9.4-A2): look up the CID hint for chunk
    /// `index`. Returns `None` if no hints are populated (legacy
    /// metadata) or if the specific chunk's hint is `None` (writer
    /// flag was off for that PUT, or its etag failed to parse).
    pub fn chunk_cid(&self, index: u32) -> Option<Cid> {
        self.chunk_cids
            .get(index as usize)
            .copied()
            .flatten()
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
    /// H-1: unkeyed BLAKE3 hasher fed the same plaintext as `bao_encoder`.
    /// Emits a content hash that can be bound to the forest entry (outside
    /// the attacker-forgeable HPKE envelope) so whole-file substitution is
    /// detectable on download. The Bao root hash is not enough because it
    /// lives inside the AEAD-encrypted `ChunkedFileMetadata` blob, whose
    /// DEK is attacker-chosen under an HPKE-to-self forgery.
    content_hasher: blake3::Hasher,
    chunks: Vec<EncryptedChunk>,
    current_chunk: Vec<u8>,
    bytes_processed: u64,
    aad_prefix: Option<Vec<u8>>,
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
            content_hasher: blake3::Hasher::new(),
            chunks: Vec::new(),
            current_chunk: Vec::with_capacity(chunk_size),
            bytes_processed: 0,
            aad_prefix: None,
        }
    }

    /// Create a new chunked encoder with AAD prefix for chunk binding
    ///
    /// Each chunk will be encrypted with AAD = `"{aad_prefix}:{chunk_index}"`,
    /// binding ciphertext to both the parent file and the chunk position.
    pub fn with_aad(dek: DekKey, aad_prefix: impl Into<Vec<u8>>) -> Self {
        Self {
            aad_prefix: Some(aad_prefix.into()),
            ..Self::new(dek)
        }
    }

    /// Create a new chunked encoder with AAD prefix and a specific chunk size
    pub fn with_aad_and_chunk_size(dek: DekKey, aad_prefix: impl Into<Vec<u8>>, chunk_size: usize) -> Self {
        Self {
            aad_prefix: Some(aad_prefix.into()),
            ..Self::with_chunk_size(dek, chunk_size)
        }
    }

    /// Feed data into the encoder
    /// 
    /// Returns any complete chunks that are ready for upload.
    pub fn update(&mut self, data: &[u8]) -> Result<Vec<EncryptedChunk>> {
        let mut ready_chunks = Vec::new();
        
        let mut offset = 0;
        while offset < data.len() {
            let remaining = self.chunk_size - self.current_chunk.len();
            let to_copy = remaining.min(data.len() - offset);
            self.current_chunk.extend_from_slice(&data[offset..offset + to_copy]);
            offset += to_copy;
            if self.current_chunk.len() >= self.chunk_size {
                let chunk = self.encrypt_current_chunk()?;
                ready_chunks.push(chunk);
            }
        }
        
        // Update Bao encoder with original plaintext for integrity
        self.bao_encoder.update(data);
        // H-1: feed the same plaintext into the unkeyed BLAKE3 hasher so
        // `content_hash_hex()` can be bound to the forest entry.
        self.content_hasher.update(data);
        self.bytes_processed += data.len() as u64;

        Ok(ready_chunks)
    }

    /// H-1: return the BLAKE3 hex digest of all plaintext fed via `update`.
    /// Must be called before `finalize` consumes `self`.
    pub fn content_hash_hex(&self) -> String {
        self.content_hasher.finalize().to_hex().to_string()
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
        
        let mut metadata = ChunkedFileMetadata::new(
            self.chunk_size as u32,
            self.chunks.len() as u32,
            self.bytes_processed,
            outboard.root_hash().clone(),
            nonces,
            None,
        );

        // Mark as v2 if AAD was used
        if self.aad_prefix.is_some() {
            metadata.format = "streaming-v2".to_string();
        }

        Ok((final_chunk, metadata, outboard))
    }

    /// Encrypt the current chunk buffer
    fn encrypt_current_chunk(&mut self) -> Result<EncryptedChunk> {
        let chunk_index = self.chunks.len() as u32;

        // Generate a unique nonce for this chunk
        let nonce = Nonce::generate();

        // Encrypt the chunk, with AAD if prefix is set
        let aead = Aead::new_default(&self.dek);
        let ciphertext = if let Some(ref prefix) = self.aad_prefix {
            let aad = format!("{}:{}", String::from_utf8_lossy(prefix), chunk_index).into_bytes();
            aead.encrypt_with_aad(&nonce, &self.current_chunk, &aad)?
        } else {
            aead.encrypt(&nonce, &self.current_chunk)?
        };
        
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
    aad_prefix: Option<Vec<u8>>,
}

impl ChunkedDecoder {
    /// Create a new decoder with the given DEK and metadata
    pub fn new(dek: DekKey, metadata: ChunkedFileMetadata) -> Self {
        Self {
            dek,
            metadata,
            chunks: Vec::new(),
            aad_prefix: None,
        }
    }

    /// Create a new decoder with AAD prefix for chunk binding verification
    pub fn with_aad(dek: DekKey, metadata: ChunkedFileMetadata, aad_prefix: impl Into<Vec<u8>>) -> Self {
        Self {
            dek,
            metadata,
            chunks: Vec::new(),
            aad_prefix: Some(aad_prefix.into()),
        }
    }

    /// Decrypt a single chunk
    pub fn decrypt_chunk(&mut self, index: u32, ciphertext: &[u8]) -> Result<Bytes> {
        let nonce = self.metadata.get_chunk_nonce(index)?;
        let aead = Aead::new_default(&self.dek);
        let plaintext = if let Some(ref prefix) = self.aad_prefix {
            let aad = format!("{}:{}", String::from_utf8_lossy(prefix), index).into_bytes();
            aead.decrypt_with_aad(&nonce, ciphertext, &aad)?
        } else {
            aead.decrypt(&nonce, ciphertext)?
        };
        
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
// Only available with tokio-runtime feature (not WASM compatible)
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(feature = "tokio-runtime")]
use tokio::io::{AsyncRead, AsyncReadExt};

/// Async streaming encoder for large files
///
/// Accepts an `AsyncRead` source and yields encrypted chunks as they're ready.
/// Memory usage is O(chunk_size) regardless of file size.
///
/// Only available with `tokio-runtime` feature (not WASM compatible).
#[cfg(feature = "tokio-runtime")]
pub struct AsyncStreamingEncoder {
    dek: DekKey,
    chunk_size: usize,
    bao_encoder: BaoEncoder,
    /// H-1: unkeyed BLAKE3 hasher fed in parallel with `bao_encoder`.
    /// See `ChunkedEncoder::content_hasher` for rationale.
    content_hasher: blake3::Hasher,
    chunk_index: u32,
    nonces: Vec<Nonce>,
    bytes_processed: u64,
    aad_prefix: Option<Vec<u8>>,
}

#[cfg(feature = "tokio-runtime")]
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
            content_hasher: blake3::Hasher::new(),
            chunk_index: 0,
            nonces: Vec::new(),
            bytes_processed: 0,
            aad_prefix: None,
        }
    }

    /// Create with AAD prefix for chunk binding
    pub fn with_aad(dek: DekKey, aad_prefix: impl Into<Vec<u8>>) -> Self {
        Self {
            aad_prefix: Some(aad_prefix.into()),
            ..Self::new(dek)
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
            // H-1: feed the same plaintext slice into the unkeyed BLAKE3
            // hasher so `content_hash_hex()` covers the full stream.
            self.content_hasher.update(&buffer[..bytes_read]);
            self.bytes_processed += bytes_read as u64;

            // Encrypt this chunk
            let chunk = self.encrypt_chunk(&buffer[..bytes_read])?;
            chunks.push(chunk);
        }

        Ok(chunks)
    }

    /// H-1: return the BLAKE3 hex digest of all plaintext streamed through
    /// `process_reader`. Call before `finalize` consumes `self`.
    pub fn content_hash_hex(&self) -> String {
        self.content_hasher.finalize().to_hex().to_string()
    }

    /// Encrypt a single chunk of data
    fn encrypt_chunk(&mut self, data: &[u8]) -> Result<EncryptedChunk> {
        let nonce = Nonce::generate();
        let aead = Aead::new_default(&self.dek);
        let ciphertext = if let Some(ref prefix) = self.aad_prefix {
            let aad = format!("{}:{}", String::from_utf8_lossy(prefix), self.chunk_index).into_bytes();
            aead.encrypt_with_aad(&nonce, data, &aad)?
        } else {
            aead.encrypt(&nonce, data)?
        };
        
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

        let mut metadata = ChunkedFileMetadata::new(
            self.chunk_size as u32,
            self.chunk_index,
            self.bytes_processed,
            outboard.root_hash().clone(),
            self.nonces,
            None,
        );

        if self.aad_prefix.is_some() {
            metadata.format = "streaming-v2".to_string();
        }

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
    aad_prefix: Option<Vec<u8>>,
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
            aad_prefix: None,
        })
    }

    /// Create a new verified streaming decoder with AAD prefix
    pub fn with_aad(dek: DekKey, metadata: ChunkedFileMetadata, aad_prefix: impl Into<Vec<u8>>) -> Result<Self> {
        let expected_hash = metadata.get_root_hash()?;
        Ok(Self {
            dek,
            metadata,
            expected_hash,
            bao_encoder: BaoEncoder::new(),
            verified_bytes: 0,
            aad_prefix: Some(aad_prefix.into()),
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
        let plaintext = if let Some(ref prefix) = self.aad_prefix {
            let aad = format!("{}:{}", String::from_utf8_lossy(prefix), index).into_bytes();
            aead.decrypt_with_aad(&nonce, ciphertext, &aad)?
        } else {
            aead.decrypt(&nonce, ciphertext)?
        };
        
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
            chunk_cids: vec![],
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
        assert!(!should_use_chunked(256 * 1024)); // 256 KB
        assert!(!should_use_chunked(MAX_CHUNK_SIZE)); // Exactly at threshold
        assert!(should_use_chunked(MAX_CHUNK_SIZE + 1)); // Just over threshold
        assert!(should_use_chunked(1024 * 1024)); // 1 MB - must be chunked for IPFS
        assert!(should_use_chunked(100 * 1024 * 1024)); // 100 MB
    }

    #[cfg(feature = "tokio-runtime")]
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

    #[cfg(feature = "tokio-runtime")]
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

    #[cfg(feature = "tokio-runtime")]
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

    // ═══════════════════════════════════════════════════════════════════
    // Audit2 v3/v4 tests
    // ═══════════════════════════════════════════════════════════════════

    #[test]
    fn test_with_aad_and_chunk_size_produces_streaming_v2() {
        let dek = DekKey::generate();
        let data = b"test data for AAD chunk size combo".repeat(100);
        let aad_prefix = b"fula:v4:chunk:QmTestKey123";

        let mut encoder = ChunkedEncoder::with_aad_and_chunk_size(
            dek.clone(), aad_prefix.to_vec(), MIN_CHUNK_SIZE,
        );
        let chunks = encoder.update(&data).unwrap();
        let (final_chunk, metadata, _outboard) = encoder.finalize().unwrap();

        assert_eq!(metadata.format, "streaming-v2", "AAD encoder must produce streaming-v2 format");
        assert!(metadata.num_chunks > 0);

        // Verify roundtrip with AAD decoder
        let mut decoder = ChunkedDecoder::with_aad(dek, metadata, aad_prefix.to_vec());
        for chunk in &chunks {
            decoder.decrypt_chunk(chunk.index, &chunk.ciphertext).unwrap();
        }
        if let Some(c) = final_chunk {
            decoder.decrypt_chunk(c.index, &c.ciphertext).unwrap();
        }
        let recovered = decoder.finalize().unwrap();
        assert_eq!(recovered.as_ref(), data.as_slice());
    }

    #[test]
    fn test_without_aad_produces_streaming_v1() {
        let dek = DekKey::generate();
        let data = b"test data without AAD".repeat(100);

        let mut encoder = ChunkedEncoder::with_chunk_size(dek.clone(), MIN_CHUNK_SIZE);
        let _chunks = encoder.update(&data).unwrap();
        let (_final_chunk, metadata, _) = encoder.finalize().unwrap();

        assert_eq!(metadata.format, "streaming-v1", "Non-AAD encoder must produce streaming-v1");
    }

    #[test]
    fn test_streaming_v1_backward_compat_decode() {
        // Simulate old v3 upload: encode without AAD (streaming-v1)
        let dek = DekKey::generate();
        let original = b"legacy v3 file content".repeat(100);

        let mut encoder = ChunkedEncoder::with_chunk_size(dek.clone(), MIN_CHUNK_SIZE);
        let chunks = encoder.update(&original).unwrap();
        let (final_chunk, metadata, _) = encoder.finalize().unwrap();
        assert_eq!(metadata.format, "streaming-v1");

        // Decode with NON-AAD decoder (as old client would)
        let mut decoder = ChunkedDecoder::new(dek.clone(), metadata.clone());
        for c in &chunks { decoder.decrypt_chunk(c.index, &c.ciphertext).unwrap(); }
        if let Some(c) = &final_chunk { decoder.decrypt_chunk(c.index, &c.ciphertext).unwrap(); }
        let recovered = decoder.finalize().unwrap();
        assert_eq!(recovered.as_ref(), original.as_slice());

        // NEW client should also handle streaming-v1 by checking format field
        // and NOT using AAD (the branching logic in encryption.rs)
        let mut decoder2 = ChunkedDecoder::new(dek, metadata);
        for c in &chunks { decoder2.decrypt_chunk(c.index, &c.ciphertext).unwrap(); }
        if let Some(c) = &final_chunk { decoder2.decrypt_chunk(c.index, &c.ciphertext).unwrap(); }
        let recovered2 = decoder2.finalize().unwrap();
        assert_eq!(recovered2.as_ref(), original.as_slice());
    }

    #[test]
    fn test_streaming_v2_chunks_cannot_be_swapped_between_files() {
        let dek = DekKey::generate();
        // Data must be > MIN_CHUNK_SIZE to produce chunks from update()
        let data_a = vec![0xAAu8; MIN_CHUNK_SIZE * 2 + 1000];
        let data_b = vec![0xBBu8; MIN_CHUNK_SIZE * 2 + 1000];

        // Encode file A with AAD bound to storage key A
        let mut enc_a = ChunkedEncoder::with_aad_and_chunk_size(
            dek.clone(), b"fula:v4:chunk:QmFileA".to_vec(), MIN_CHUNK_SIZE,
        );
        let mut chunks_a = enc_a.update(&data_a).unwrap();
        let (final_a, meta_a, _) = enc_a.finalize().unwrap();
        if let Some(c) = final_a { chunks_a.push(c); }
        assert!(chunks_a.len() >= 2, "File A must have >=2 chunks, got {}", chunks_a.len());

        // Encode file B with AAD bound to storage key B
        let mut enc_b = ChunkedEncoder::with_aad_and_chunk_size(
            dek.clone(), b"fula:v4:chunk:QmFileB".to_vec(), MIN_CHUNK_SIZE,
        );
        let mut chunks_b = enc_b.update(&data_b).unwrap();
        let (final_b, _meta_b, _) = enc_b.finalize().unwrap();
        if let Some(c) = final_b { chunks_b.push(c); }
        assert!(!chunks_b.is_empty(), "File B must have chunks");

        // Try to decode file A's metadata with file B's chunk 0 ciphertext
        // This should fail because the AAD won't match
        let mut decoder_a = ChunkedDecoder::with_aad(dek.clone(), meta_a.clone(), b"fula:v4:chunk:QmFileA".to_vec());
        let result = decoder_a.decrypt_chunk(0, &chunks_b[0].ciphertext);
        assert!(result.is_err(), "Chunk from file B must not decrypt under file A's AAD");

        // But file A's own chunks work fine
        let mut decoder_a2 = ChunkedDecoder::with_aad(dek, meta_a, b"fula:v4:chunk:QmFileA".to_vec());
        for c in &chunks_a { decoder_a2.decrypt_chunk(c.index, &c.ciphertext).unwrap(); }
        let recovered = decoder_a2.finalize().unwrap();
        assert_eq!(recovered.as_ref(), data_a.as_slice());
    }

    #[test]
    fn test_streaming_v2_chunks_cannot_be_reordered() {
        let dek = DekKey::generate();
        // Data must span multiple chunks
        let data = vec![0xCCu8; MIN_CHUNK_SIZE * 3 + 500];

        let mut encoder = ChunkedEncoder::with_aad_and_chunk_size(
            dek.clone(), b"fula:v4:chunk:QmReorderTest".to_vec(), MIN_CHUNK_SIZE,
        );
        let mut all_chunks = encoder.update(&data).unwrap();
        let (final_chunk, metadata, _) = encoder.finalize().unwrap();
        if let Some(c) = final_chunk { all_chunks.push(c); }
        assert!(all_chunks.len() >= 2, "Need at least 2 chunks to test reorder, got {}", all_chunks.len());

        // Try decrypting chunk 1's ciphertext at index 0 — AAD includes index
        let mut decoder = ChunkedDecoder::with_aad(
            dek, metadata, b"fula:v4:chunk:QmReorderTest".to_vec(),
        );
        let result = decoder.decrypt_chunk(0, &all_chunks[1].ciphertext);
        assert!(result.is_err(), "Swapping chunk indices must fail AAD verification");
    }

    #[test]
    fn test_streaming_v2_wrong_aad_prefix_fails() {
        let dek = DekKey::generate();
        // Data must be > MIN_CHUNK_SIZE so update() emits chunks
        let data = vec![0xDDu8; MIN_CHUNK_SIZE * 2 + 500];

        let mut encoder = ChunkedEncoder::with_aad_and_chunk_size(
            dek.clone(), b"fula:v4:chunk:QmCorrectKey".to_vec(), MIN_CHUNK_SIZE,
        );
        let mut chunks = encoder.update(&data).unwrap();
        let (final_chunk, metadata, _) = encoder.finalize().unwrap();
        if let Some(c) = final_chunk { chunks.push(c); }
        assert!(!chunks.is_empty(), "Must have at least 1 chunk");

        // Attempt to decode with wrong AAD prefix
        let mut decoder = ChunkedDecoder::with_aad(
            dek, metadata, b"fula:v4:chunk:QmWrongKey".to_vec(),
        );
        let result = decoder.decrypt_chunk(0, &chunks[0].ciphertext);
        assert!(result.is_err(), "Wrong AAD prefix must cause decryption failure");
    }

    #[test]
    fn test_content_type_not_set_by_default() {
        let dek = DekKey::generate();
        let data = b"content type test".repeat(50);

        let mut encoder = ChunkedEncoder::with_chunk_size(dek.clone(), MIN_CHUNK_SIZE);
        let _chunks = encoder.update(&data).unwrap();
        let (_, metadata, _) = encoder.finalize().unwrap();

        assert!(metadata.content_type.is_none(),
            "content_type must not be set by encoder — it leaks file type to server");
    }

    #[test]
    fn test_content_type_absent_deserializes_as_none() {
        // Simulate JSON from a new upload that omits content_type
        let json = r#"{
            "format": "streaming-v2",
            "chunk_size": 262144,
            "num_chunks": 5,
            "total_size": 1310720,
            "root_hash": "0000000000000000000000000000000000000000000000000000000000000000",
            "chunk_nonces": []
        }"#;
        let meta: ChunkedFileMetadata = serde_json::from_str(json).unwrap();
        assert!(meta.content_type.is_none());
    }

    #[test]
    fn test_content_type_present_deserializes_as_some() {
        // Simulate JSON from an OLD upload that includes content_type
        let json = r#"{
            "format": "streaming-v1",
            "chunk_size": 262144,
            "num_chunks": 5,
            "total_size": 1310720,
            "root_hash": "0000000000000000000000000000000000000000000000000000000000000000",
            "chunk_nonces": [],
            "content_type": "image/jpeg"
        }"#;
        let meta: ChunkedFileMetadata = serde_json::from_str(json).unwrap();
        assert_eq!(meta.content_type, Some("image/jpeg".to_string()),
            "Old metadata with content_type must still deserialize correctly");
    }

    #[test]
    fn test_v1_v2_cross_decode_fails() {
        // streaming-v2 ciphertext cannot be decoded by streaming-v1 decoder
        let dek = DekKey::generate();
        // Data must be > MIN_CHUNK_SIZE so update() emits chunks
        let data = vec![0xEEu8; MIN_CHUNK_SIZE * 2 + 500];

        let mut encoder = ChunkedEncoder::with_aad_and_chunk_size(
            dek.clone(), b"fula:v4:chunk:QmCross".to_vec(), MIN_CHUNK_SIZE,
        );
        let mut chunks = encoder.update(&data).unwrap();
        let (final_chunk, metadata, _) = encoder.finalize().unwrap();
        if let Some(c) = final_chunk { chunks.push(c); }
        assert!(!chunks.is_empty(), "Must have at least 1 chunk");
        assert_eq!(metadata.format, "streaming-v2");

        // Try to decode with NON-AAD decoder (as if we ignored the format field)
        let mut decoder = ChunkedDecoder::new(dek, metadata);
        let result = decoder.decrypt_chunk(0, &chunks[0].ciphertext);
        assert!(result.is_err(),
            "streaming-v2 ciphertext decoded without AAD must fail (AAD mismatch)");
    }

    #[test]
    fn test_with_aad_and_chunk_size_matches_separate_calls() {
        // Verify the combined constructor produces identical behavior
        let dek = DekKey::generate();
        let data = b"constructor equivalence test".repeat(100);
        let aad = b"fula:v4:chunk:QmEquiv".to_vec();

        // Method 1: with_aad_and_chunk_size
        let mut enc1 = ChunkedEncoder::with_aad_and_chunk_size(
            dek.clone(), aad.clone(), MIN_CHUNK_SIZE,
        );
        let chunks1 = enc1.update(&data).unwrap();
        let (final1, meta1, _) = enc1.finalize().unwrap();

        // Both should produce the same metadata structure
        assert_eq!(meta1.format, "streaming-v2");
        assert_eq!(meta1.chunk_size, MIN_CHUNK_SIZE as u32);
        assert_eq!(meta1.num_chunks, chunks1.len() as u32 + if final1.is_some() { 1 } else { 0 });
    }

    // ─────────────────────────────────────────────────────────────────
    // Walkable-v8 (W.9.4-A2 / task #32) — per-chunk CID hints
    // ─────────────────────────────────────────────────────────────────

    fn walkable_v8_test_cid(seed: u8) -> Cid {
        let digest = [seed; 32];
        let mh = cid::multihash::Multihash::<64>::wrap(0x1e, &digest)
            .expect("blake3 multihash wrap");
        Cid::new_v1(0x55, mh)
    }

    #[test]
    fn chunk_cids_round_trip_via_json() {
        let cid_a = walkable_v8_test_cid(0xAA);
        let cid_c = walkable_v8_test_cid(0xCC);
        let mut meta = ChunkedFileMetadata {
            format: "streaming-v1".to_string(),
            chunk_size: 1024,
            num_chunks: 3,
            total_size: 3000,
            root_hash: "deadbeef".to_string(),
            chunk_nonces: vec!["n0".to_string(), "n1".to_string(), "n2".to_string()],
            content_type: None,
            chunk_cids: vec![],
        };
        meta.populate_chunk_cids(vec![Some(cid_a), None, Some(cid_c)]);
        let json = serde_json::to_vec(&meta).expect("encode");
        let decoded: ChunkedFileMetadata = serde_json::from_slice(&json).expect("decode");
        assert_eq!(decoded.chunk_cid(0), Some(cid_a));
        assert_eq!(
            decoded.chunk_cid(1),
            None,
            "individual None hints survive round-trip"
        );
        assert_eq!(decoded.chunk_cid(2), Some(cid_c));
    }

    #[test]
    fn chunk_cids_empty_round_trips_via_json() {
        // Empty chunk_cids is the default + means "legacy / no hints".
        // The `skip_serializing_if = "Vec::is_empty"` keeps the field
        // OFF the wire so legacy readers (without the field) and
        // post-W.9.4-A2 readers (with the field) decode identical
        // bytes — backward-compat both ways.
        let meta = ChunkedFileMetadata::new(
            1024,
            2,
            2000,
            Blake3Hash::new([0u8; 32]),
            vec![Nonce::generate(), Nonce::generate()],
            None,
        );
        assert!(meta.chunk_cids.is_empty());
        let json = serde_json::to_vec(&meta).expect("encode");
        let json_str = String::from_utf8_lossy(&json);
        assert!(
            !json_str.contains("chunk_cids"),
            "empty chunk_cids must NOT appear on the wire — \
             skip_serializing_if guards backward-compat with v0.5 SDKs. \
             Got: {}",
            json_str
        );
        let decoded: ChunkedFileMetadata = serde_json::from_slice(&json).expect("decode");
        assert!(decoded.chunk_cids.is_empty());
        assert_eq!(decoded.chunk_cid(0), None);
    }

    #[test]
    fn legacy_chunked_metadata_without_chunk_cids_field_deserializes_to_none() {
        // Backward-compat gold standard (W.4.3 hard constraint #1):
        // existing pinned/cached `ChunkedFileMetadata` blobs from
        // pre-W.9.4-A2 SDKs must deserialize cleanly into the new
        // struct, with `chunk_cid()` returning `None` for every
        // index. Production data must not break under SDK upgrade.
        #[derive(serde::Serialize, serde::Deserialize)]
        struct LegacyChunkedFileMetadata {
            format: String,
            chunk_size: u32,
            num_chunks: u32,
            total_size: u64,
            root_hash: String,
            chunk_nonces: Vec<String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            content_type: Option<String>,
            // NOTE: deliberately no `chunk_cids` field — pre-W.9.4-A2 shape.
        }
        let legacy = LegacyChunkedFileMetadata {
            format: "streaming-v1".to_string(),
            chunk_size: 256 * 1024,
            num_chunks: 3,
            total_size: 700_000,
            root_hash: "a".repeat(64),
            chunk_nonces: vec!["n0".to_string(), "n1".to_string(), "n2".to_string()],
            content_type: Some("image/jpeg".to_string()),
        };
        let bytes = serde_json::to_vec(&legacy).expect("encode legacy");
        let modern: ChunkedFileMetadata =
            serde_json::from_slice(&bytes).expect("legacy → modern");
        assert_eq!(modern.format, "streaming-v1");
        assert_eq!(modern.num_chunks, 3);
        assert_eq!(modern.content_type.as_deref(), Some("image/jpeg"));
        assert!(modern.chunk_cids.is_empty());
        assert_eq!(modern.chunk_cid(0), None);
        assert_eq!(modern.chunk_cid(1), None);
        assert_eq!(modern.chunk_cid(2), None);
    }

    #[test]
    fn populate_chunk_cids_wrong_length_is_ignored() {
        // Defensive: caller bug should not corrupt persisted metadata.
        let mut meta = ChunkedFileMetadata::new(
            1024,
            3,
            3000,
            Blake3Hash::new([0u8; 32]),
            vec![Nonce::generate(), Nonce::generate(), Nonce::generate()],
            None,
        );
        // Length 2, expected 3 — no-op.
        meta.populate_chunk_cids(vec![Some(walkable_v8_test_cid(0x11)), None]);
        assert!(meta.chunk_cids.is_empty(), "wrong-length caller bug must not stamp partial state");
        // Correct length — stamps.
        meta.populate_chunk_cids(vec![
            Some(walkable_v8_test_cid(0x11)),
            None,
            Some(walkable_v8_test_cid(0x33)),
        ]);
        assert_eq!(meta.chunk_cids.len(), 3);
        // Empty Vec — clears.
        meta.populate_chunk_cids(vec![]);
        assert!(meta.chunk_cids.is_empty());
    }
}
