//! Chunked/streaming operations
//!
//! Functions for handling large files using chunked encryption.
//! Files above a certain threshold are automatically split into chunks.

use crate::api::types::*;

/// Default chunk size (256 KB)
pub const DEFAULT_CHUNK_SIZE: u32 = 256 * 1024;

/// Threshold for using chunked encryption (5 MB)
pub const CHUNKED_THRESHOLD: u64 = 5 * 1024 * 1024;

// ============================================================================
// Chunked Operations
// ============================================================================

/// Upload a large file using chunked encryption
///
/// The file is split into chunks, each encrypted separately.
/// This is more efficient for large files and enables partial downloads.
pub async fn put_chunked(
    client: &EncryptedClientHandle,
    bucket: String,
    key: String,
    data: Vec<u8>,
    chunk_size: Option<u32>,
) -> anyhow::Result<PutResult> {
    let guard = &*client.inner;
    let chunk_size = chunk_size.map(|s| s as usize);
    let result = guard.put_object_chunked(&bucket, &key, &data, chunk_size).await?;
    Ok(result.into())
}

/// Download and decrypt a chunked file
///
/// Automatically handles reassembly of chunks.
pub async fn get_chunked(
    client: &EncryptedClientHandle,
    bucket: String,
    key: String,
) -> anyhow::Result<Vec<u8>> {
    let guard = &*client.inner;
    let data = guard.get_object_chunked(&bucket, &key).await?;
    Ok(data.to_vec())
}

/// Download a range of bytes from a file
///
/// For chunked files, only the necessary chunks are downloaded.
/// This is efficient for large files when you only need part of the content.
pub async fn get_range(
    client: &EncryptedClientHandle,
    bucket: String,
    key: String,
    offset: u64,
    length: u64,
) -> anyhow::Result<Vec<u8>> {
    let guard = &*client.inner;
    let data = guard.get_object_range(&bucket, &key, offset, length).await?;
    Ok(data.to_vec())
}

/// Check if a file size warrants chunked upload
///
/// Returns true if the size is above the chunked threshold.
pub async fn should_use_chunked(size: u64) -> bool {
    size > CHUNKED_THRESHOLD
}
