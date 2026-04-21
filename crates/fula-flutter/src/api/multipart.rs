//! Multipart upload operations
//!
//! Functions for uploading large files in multiple parts.
//! Supports progress tracking and resumable uploads.

use std::sync::Arc;
use bytes::Bytes;

use crate::api::types::*;

/// Default cap on concurrent part uploads per handle.
///
/// Four parts in flight gives a healthy throughput win over serial uploads
/// without saturating mobile bandwidth, exhausting file descriptors, or
/// triggering 429/503s from the pinning service. Tune per-upload via
/// [`start_multipart_with_concurrency`] if the network profile warrants it.
const DEFAULT_MAX_CONCURRENT_PARTS: u32 = 4;

// ============================================================================
// Multipart Upload Operations
// ============================================================================

/// Start a new multipart upload
///
/// Returns a handle that can be used to upload parts. Uses the default
/// concurrency cap (`DEFAULT_MAX_CONCURRENT_PARTS`) for `upload_part` calls.
pub async fn start_multipart(
    client: &FulaClientHandle,
    bucket: String,
    key: String,
) -> anyhow::Result<MultipartHandle> {
    start_multipart_with_concurrency(client, bucket, key, DEFAULT_MAX_CONCURRENT_PARTS).await
}

/// Start a new multipart upload with an explicit concurrency cap.
///
/// `max_concurrency` bounds how many `upload_part` calls can be in flight on
/// this handle at once. Values of 0 are coerced to 1 (fully serial).
pub async fn start_multipart_with_concurrency(
    client: &FulaClientHandle,
    bucket: String,
    key: String,
    max_concurrency: u32,
) -> anyhow::Result<MultipartHandle> {
    let upload = fula_client::MultipartUpload::start(
        client.inner.clone(),
        &bucket,
        &key,
    ).await?;

    let permits = max_concurrency.max(1) as usize;
    Ok(MultipartHandle {
        inner: Arc::new(upload),
        semaphore: Arc::new(Semaphore::new(permits)),
        client: client.inner.clone(),
    })
}

/// Upload a part
///
/// Part numbers must be between 1 and 10000.
/// Parts can be uploaded in any order, and concurrent calls on the same
/// handle run their HTTP I/O in parallel up to the handle's concurrency cap.
pub async fn upload_part(
    handle: &MultipartHandle,
    part_number: u32,
    data: Vec<u8>,
) -> anyhow::Result<()> {
    // Hold the permit across the HTTP PUT; release as soon as it's done.
    // tokio's Semaphore::acquire returns Result (Err only if the semaphore
    // was closed — impossible here since we own the Arc). async_lock's
    // returns a plain guard. Cfg-gate to unify.
    #[cfg(not(target_arch = "wasm32"))]
    let _permit = handle
        .semaphore
        .acquire()
        .await
        .map_err(|e| anyhow::anyhow!("multipart semaphore closed: {e}"))?;
    #[cfg(target_arch = "wasm32")]
    let _permit = handle.semaphore.acquire().await;

    handle.inner.upload_part(part_number, Bytes::from(data)).await?;
    Ok(())
}

/// Complete the multipart upload
///
/// Assembles all uploaded parts into the final object.
/// Returns the ETag of the completed object.
pub async fn complete_multipart(handle: MultipartHandle) -> anyhow::Result<String> {
    let etag = handle.inner.complete().await?;
    Ok(etag)
}

/// Abort the multipart upload
///
/// Cancels the upload and removes any uploaded parts.
pub async fn abort_multipart(handle: MultipartHandle) -> anyhow::Result<()> {
    handle.inner.abort().await?;
    Ok(())
}

/// Detach the multipart upload without aborting.
///
/// Suppresses the drop-time auto-abort so uploaded parts survive the
/// handle being GC'd. Use this when pausing a resumable upload — e.g.,
/// the user backgrounds the app mid-upload and you plan to resume later
/// with the same upload_id. Without detach, dropping the handle issues
/// a best-effort AbortMultipartUpload. (R4.)
pub async fn detach_multipart(handle: &MultipartHandle) {
    handle.inner.detach();
}

/// Get the upload ID
pub async fn get_upload_id(handle: &MultipartHandle) -> String {
    handle.inner.upload_id().to_string()
}

/// Get the number of completed parts
pub async fn get_completed_parts(handle: &MultipartHandle) -> u32 {
    handle.inner.completed_parts() as u32
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
) -> anyhow::Result<String> {
    let chunk_size = chunk_size.unwrap_or(5 * 1024 * 1024) as usize; // 5MB default
    let total_size = data.len();

    // Start multipart upload
    let upload = fula_client::MultipartUpload::start(
        client.inner.clone(),
        &bucket,
        &key,
    ).await?;

    // M-3: arm an auto-abort guard so any `?`-propagated error below will
    // spawn an AbortMultipartUpload instead of leaving S3 to charge for the
    // partial upload until the bucket lifecycle sweeps it.
    let abort_guard = fula_client::MultipartAbortGuard::new(
        client.inner.clone(),
        &bucket,
        &key,
        upload.upload_id().to_string(),
    );

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
    abort_guard.disarm();
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
