//! Multipart upload operations
//!
//! Functions for uploading large files in multiple parts.
//! Supports progress tracking and resumable uploads.

use std::sync::Arc;
use bytes::Bytes;
use parking_lot::Mutex;

use crate::api::types::*;
use crate::api::error::{FulaError, FulaResult};

// ============================================================================
// Multipart Upload Operations
// ============================================================================

/// Start a new multipart upload
///
/// Returns a handle that can be used to upload parts.
pub async fn start_multipart(
    client: &FulaClientHandle,
    bucket: String,
    key: String,
) -> FulaResult<MultipartHandle> {
    let upload = fula_client::MultipartUpload::start(
        client.inner.clone(),
        &bucket,
        &key,
    ).await?;

    Ok(MultipartHandle {
        inner: Arc::new(Mutex::new(upload)),
        client: client.inner.clone(),
    })
}

/// Upload a part
///
/// Part numbers must be between 1 and 10000.
/// Parts can be uploaded in any order.
pub async fn upload_part(
    handle: &MultipartHandle,
    part_number: u32,
    data: Vec<u8>,
) -> FulaResult<()> {
    let mut upload = handle.inner.lock();
    upload.upload_part(part_number, Bytes::from(data)).await?;
    Ok(())
}

/// Complete the multipart upload
///
/// Assembles all uploaded parts into the final object.
/// Returns the ETag of the completed object.
pub async fn complete_multipart(handle: MultipartHandle) -> FulaResult<String> {
    let upload = Arc::try_unwrap(handle.inner)
        .map_err(|_| FulaError::Internal("Cannot complete: handle still in use".to_string()))?
        .into_inner();

    let etag = upload.complete().await?;
    Ok(etag)
}

/// Abort the multipart upload
///
/// Cancels the upload and removes any uploaded parts.
pub async fn abort_multipart(handle: MultipartHandle) -> FulaResult<()> {
    let upload = Arc::try_unwrap(handle.inner)
        .map_err(|_| FulaError::Internal("Cannot abort: handle still in use".to_string()))?
        .into_inner();

    upload.abort().await?;
    Ok(())
}

/// Get the upload ID
pub fn get_upload_id(handle: &MultipartHandle) -> String {
    let upload = handle.inner.lock();
    upload.upload_id().to_string()
}

/// Get the number of completed parts
pub fn get_completed_parts(handle: &MultipartHandle) -> u32 {
    let upload = handle.inner.lock();
    upload.completed_parts() as u32
}

// ============================================================================
// High-Level Helper
// ============================================================================

/// Upload a large file with automatic chunking
///
/// This is a convenience function that handles the entire multipart
/// upload process automatically, including progress reporting.
///
/// Note: For flutter_rust_bridge, progress streaming requires StreamSink.
/// This function provides a simpler interface without progress callbacks.
pub async fn upload_large_file_simple(
    client: &FulaClientHandle,
    bucket: String,
    key: String,
    data: Vec<u8>,
    chunk_size: Option<u32>,
) -> FulaResult<String> {
    let chunk_size = chunk_size.unwrap_or(5 * 1024 * 1024) as usize; // 5MB default
    let total_size = data.len();

    // Start multipart upload
    let mut upload = fula_client::MultipartUpload::start(
        client.inner.clone(),
        &bucket,
        &key,
    ).await?;

    // Upload parts
    let mut part_number = 1u32;
    let mut offset = 0;

    while offset < total_size {
        let end = std::cmp::min(offset + chunk_size, total_size);
        let part_data = Bytes::from(data[offset..end].to_vec());

        upload.upload_part(part_number, part_data).await?;

        offset = end;
        part_number += 1;
    }

    // Complete upload
    let etag = upload.complete().await?;
    Ok(etag)
}

// ============================================================================
// Progress Helpers
// ============================================================================

impl UploadProgress {
    /// Create a new progress struct
    pub fn new(
        bytes_uploaded: u64,
        total_bytes: u64,
        current_part: u32,
        total_parts: u32,
    ) -> Self {
        let percentage = if total_bytes > 0 {
            (bytes_uploaded as f64 / total_bytes as f64) * 100.0
        } else {
            0.0
        };

        Self {
            bytes_uploaded,
            total_bytes,
            current_part,
            total_parts,
            percentage,
        }
    }
}
