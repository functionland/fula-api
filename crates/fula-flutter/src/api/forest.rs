//! Forest/FlatNamespace operations
//!
//! These functions manage the encrypted file index (PrivateForest)
//! for organized file storage with human-readable paths.

use bytes::Bytes;
use anyhow::Context;

use crate::api::types::*;

// ============================================================================
// Forest Management
// ============================================================================

/// Load the forest index from storage.
///
/// For v7 (sharded-HAMT) forests the underlying `load_forest` returns a
/// marker error `"forest is sharded; use sharded API methods"` so that
/// callers using the monolithic `PrivateForest` API know to switch. All
/// real I/O paths on this client (`get_flat`, `put_flat`, â€¦) go through
/// `ensure_forest_loaded` which already handles the sharded path
/// transparently, so from a Flutter caller's perspective that marker is
/// not an error â€” the forest *is* loaded, just in sharded form. Swallow
/// the marker here so apps don't have to special-case it.
pub async fn load_forest(
    client: &EncryptedClientHandle,
    bucket: String,
) -> anyhow::Result<()> {
    let guard = client.inner.write().await;
    match guard.load_forest(&bucket).await {
        Ok(_) => Ok(()),
        Err(e) if e.to_string().contains("forest is sharded") => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// Save the forest index to storage
///
/// This is an alias for flush_forest. It saves any pending changes
/// in the forest cache to storage.
pub async fn save_forest(
    client: &EncryptedClientHandle,
    bucket: String,
) -> anyhow::Result<()> {
    let guard = client.inner.read().await;
    guard.flush_forest(&bucket).await?;
    Ok(())
}

/// Flush any pending forest changes to storage
pub async fn flush_forest(
    client: &EncryptedClientHandle,
    bucket: String,
) -> anyhow::Result<()> {
    let guard = client.inner.write().await;
    guard.flush_forest(&bucket).await?;
    Ok(())
}

/// Check if there are pending (unsaved) forest changes
pub async fn has_pending_changes(client: &EncryptedClientHandle, bucket: String) -> bool {
    let guard = client.inner.read().await;
    guard.has_pending_forest_changes(&bucket).await
}

/// Invalidate the cached forest for `bucket` (issue #36).
///
/// The encrypted client caches each bucket's forest for the client
/// lifetime, so a long-lived session never observes another device's
/// uploads — `list_from_forest` / `get_flat` keep resolving against the
/// session-stale index. Calling this drops the cached forest so the next
/// forest operation reloads it from storage and sees cross-device writes.
///
/// **Dirty-safe**: a forest with pending (unsaved) local changes is NOT
/// evicted — call [`flush_forest`] first to persist, then invalidate.
/// Use [`has_pending_changes`] to inspect. This mirrors the underlying
/// `EncryptedClient::invalidate_forest_cache` contract.
///
/// Typical app wiring: call on pull-to-refresh, tab-resume, reconnect,
/// or any cache-revalidation path, then re-run `list_from_forest`.
pub async fn invalidate_forest_cache(client: &EncryptedClientHandle, bucket: String) {
    let guard = client.inner.read().await;
    guard.invalidate_forest_cache(&bucket);
}

/// Invalidate every cached bucket forest on this client (issue #36).
///
/// Bulk variant of [`invalidate_forest_cache`]: all clean forests are
/// dropped; forests with pending (unsaved) changes are kept, matching
/// the per-bucket dirty-safe contract.
pub async fn invalidate_all_forest_caches(client: &EncryptedClientHandle) {
    let guard = client.inner.read().await;
    guard.invalidate_all_forest_caches();
}

// ============================================================================
// Flat Namespace Operations
// ============================================================================

/// Upload a file with immediate forest save
///
/// This is the recommended method for most use cases.
/// The file path is preserved in the encrypted forest index.
pub async fn put_flat(
    client: &EncryptedClientHandle,
    bucket: String,
    path: String,
    data: Vec<u8>,
    content_type: Option<String>,
) -> anyhow::Result<PutResult> {
    let guard = client.inner.write().await;
    let result = guard.put_object_flat(
        &bucket,
        &path,
        Bytes::from(data),
        content_type.as_deref(),
    ).await?;
    Ok(result.into())
}

/// Upload a file without immediate forest save (deferred)
///
/// Use this for batch uploads, then call `flush_forest` when done.
/// More efficient for uploading many files at once.
pub async fn put_flat_deferred(
    client: &EncryptedClientHandle,
    bucket: String,
    path: String,
    data: Vec<u8>,
    content_type: Option<String>,
) -> anyhow::Result<PutResult> {
    let guard = client.inner.write().await;
    let result = guard.put_object_flat_deferred(
        &bucket,
        &path,
        Bytes::from(data),
        content_type.as_deref(),
    ).await?;
    Ok(result.into())
}

/// Download a file by its path
pub async fn get_flat(
    client: &EncryptedClientHandle,
    bucket: String,
    path: String,
) -> anyhow::Result<Vec<u8>> {
    let guard = client.inner.read().await;
    let data = guard.get_object_flat(&bucket, &path).await?;
    Ok(data.to_vec())
}

/// Delete a file by its path
pub async fn delete_flat(
    client: &EncryptedClientHandle,
    bucket: String,
    path: String,
) -> anyhow::Result<()> {
    let guard = client.inner.write().await;
    guard.delete_object_flat(&bucket, &path).await?;
    Ok(())
}

/// List all files from the forest index (no network calls)
///
/// This reads from the local forest index, which is faster
/// than listing from the server.
pub async fn list_from_forest(
    client: &EncryptedClientHandle,
    bucket: String,
) -> anyhow::Result<Vec<FileMetadata>> {
    let guard = client.inner.read().await;
    let result = guard.list_files_from_forest(&bucket).await?;
    Ok(result.into_iter().map(|m| m.into()).collect())
}

// ============================================================================
// File-Path-Based Operations (avoids FFI memory overhead for large files)
// ============================================================================

/// Upload a file from a local path with immediate forest save
///
/// Unlike `put_flat`, this reads the file on the Rust side, avoiding the need
/// to pass the entire file contents across the Flutter-Rust FFI boundary.
/// This is critical for large files (1GB+) where passing `Vec<u8>` through
/// FFI would cause out-of-memory errors.
#[cfg(not(target_arch = "wasm32"))]
pub async fn put_flat_from_path(
    client: &EncryptedClientHandle,
    bucket: String,
    path: String,
    file_path: String,
    content_type: Option<String>,
) -> anyhow::Result<PutResult> {
    let data = tokio::fs::read(&file_path).await
        .with_context(|| format!("Failed to read file: {}", file_path))?;
    let guard = client.inner.write().await;
    let result = guard.put_object_flat(
        &bucket,
        &path,
        Bytes::from(data),
        content_type.as_deref(),
    ).await?;
    Ok(result.into())
}

#[cfg(target_arch = "wasm32")]
pub async fn put_flat_from_path(
    _client: &EncryptedClientHandle,
    _bucket: String,
    _path: String,
    _file_path: String,
    _content_type: Option<String>,
) -> anyhow::Result<PutResult> {
    anyhow::bail!("put_flat_from_path is not supported on WASM; read the file in Dart and call put_flat")
}

/// Upload a file from a local path without immediate forest save (deferred)
///
/// Same as `put_flat_from_path` but defers the forest save for batch efficiency.
#[cfg(not(target_arch = "wasm32"))]
pub async fn put_flat_from_path_deferred(
    client: &EncryptedClientHandle,
    bucket: String,
    path: String,
    file_path: String,
    content_type: Option<String>,
) -> anyhow::Result<PutResult> {
    let data = tokio::fs::read(&file_path).await
        .with_context(|| format!("Failed to read file: {}", file_path))?;
    let guard = client.inner.write().await;
    let result = guard.put_object_flat_deferred(
        &bucket,
        &path,
        Bytes::from(data),
        content_type.as_deref(),
    ).await?;
    Ok(result.into())
}

#[cfg(target_arch = "wasm32")]
pub async fn put_flat_from_path_deferred(
    _client: &EncryptedClientHandle,
    _bucket: String,
    _path: String,
    _file_path: String,
    _content_type: Option<String>,
) -> anyhow::Result<PutResult> {
    anyhow::bail!("put_flat_from_path_deferred is not supported on WASM; read the file in Dart and call put_flat_deferred")
}

// ============================================================================
// Resumable (chunked) upload (issue #17)
// ============================================================================

/// Upload a file from a local path with chunk-level resumable support.
///
/// Writes a manifest at `manifest_path` recording which chunks succeeded.
/// On clean completion the manifest is auto-deleted. On failure the
/// manifest stays on disk; call [`resume_flat_upload_from_path`] with the
/// SAME `manifest_path` AND the SAME `file_path` to pick up where this
/// attempt left off.
///
/// **Bytes contract.** The SDK's BAO root-hash check (F1 nonce-reuse
/// protection) on the resume path requires bit-identical `data` between
/// the original attempt and the resume. Metadata, permissions, mtime,
/// and the file's location on disk do NOT matter â€” only the bytes. If
/// the file changed between attempts, the resume fails fast with a
/// content-hash-mismatch error and the manifest stays on disk so the
/// caller can decide whether to give up or restart.
///
/// **Manifest path semantics.** Caller-owned local state, NOT bytes on
/// the storage backend. Recommended: place under the app's documents/
/// state directory, named by SyncTask ID or by hash of `(bucket, key)`.
/// Two concurrent calls against the SAME `manifest_path` are serialized
/// by the per-bucket write mutex (issue #16 + #17); the second caller
/// either re-finalizes the now-empty manifest cleanly or observes its
/// deletion and returns a typed error.
///
/// **WASM:** unsupported (no filesystem manifest available).
#[cfg(not(target_arch = "wasm32"))]
pub async fn put_flat_resumable_from_path(
    client: &EncryptedClientHandle,
    bucket: String,
    path: String,
    file_path: String,
    manifest_path: String,
    content_type: Option<String>,
) -> anyhow::Result<PutResult> {
    let data = tokio::fs::read(&file_path).await
        .with_context(|| format!("Failed to read file: {}", file_path))?;
    // Read lock at the bridge â€” per-bucket serialization lives inside
    // `EncryptedClient::put_object_encrypted_resumable` via the
    // `bucket_write_mutex` extension (issue #17). Different buckets
    // parallelize through this `read().await`.
    let guard = client.inner.read().await;
    let manifest = std::path::PathBuf::from(manifest_path);
    let result = guard.put_object_encrypted_resumable(
        &bucket,
        &path,
        Bytes::from(data),
        content_type.as_deref(),
        &manifest,
    ).await?;
    Ok(result.into())
}

#[cfg(target_arch = "wasm32")]
pub async fn put_flat_resumable_from_path(
    _client: &EncryptedClientHandle,
    _bucket: String,
    _path: String,
    _file_path: String,
    _manifest_path: String,
    _content_type: Option<String>,
) -> anyhow::Result<PutResult> {
    anyhow::bail!(
        "put_flat_resumable_from_path is not supported on WASM (no filesystem manifest); \
         use put_flat from WASM and retry from chunk 0 on failure"
    )
}

/// Resume a previously-failed chunked upload from its manifest file.
///
/// Reads the manifest, re-encrypts and uploads only the chunks that
/// didn't complete on the previous attempt, finalizes the index object,
/// and deletes the manifest on success. See
/// [`put_flat_resumable_from_path`] for the bytes contract and manifest
/// semantics.
///
/// **WASM:** unsupported (no filesystem manifest available).
#[cfg(not(target_arch = "wasm32"))]
pub async fn resume_flat_upload_from_path(
    client: &EncryptedClientHandle,
    manifest_path: String,
    file_path: String,
) -> anyhow::Result<PutResult> {
    let data = tokio::fs::read(&file_path).await
        .with_context(|| format!("Failed to read file: {}", file_path))?;
    // Read lock at the bridge â€” per-bucket serialization lives inside
    // `EncryptedClient::resume_upload`, which loads the manifest first
    // (bucket name lives there) and acquires the bucket_write_mutex
    // post-load (issue #17).
    let guard = client.inner.read().await;
    let manifest = std::path::PathBuf::from(manifest_path);
    let result = guard.resume_upload(&manifest, &data).await?;
    Ok(result.into())
}

#[cfg(target_arch = "wasm32")]
pub async fn resume_flat_upload_from_path(
    _client: &EncryptedClientHandle,
    _manifest_path: String,
    _file_path: String,
) -> anyhow::Result<PutResult> {
    anyhow::bail!(
        "resume_flat_upload_from_path is not supported on WASM (no filesystem manifest)"
    )
}

// ============================================================================
// Cooperative cancellation for chunked resumable uploads (issue #18)
// ============================================================================

/// Opaque handle to a cooperative cancellation flag for chunked
/// uploads. Wraps `Arc<AtomicBool>` so the flag can be cloned cheaply
/// across spawned tasks. Caller creates one via [`create_cancel_handle`],
/// passes it to a `_cancellable` upload function, and triggers cancel
/// via [`cancel_handle_trigger`].
///
/// **Cooperative semantics.** When the flag is triggered, chunks
/// already past the in-task check (up to
/// `MAX_CONCURRENT_CHUNK_UPLOADS = 16`) finish their PUTs; later
/// chunks short-circuit with `ClientError::Cancelled`. The manifest
/// on disk records exactly the chunks whose PUT completed, so a
/// subsequent `resume_flat_upload_from_path` picks up from there.
///
/// Clone-aliased: cloning the handle clones the inner `Arc`, so the
/// trigger fires for every caller observing any clone.
#[derive(Clone)]
pub struct CancelHandle {
    inner: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

/// Create a fresh, untriggered cancellation handle.
pub async fn create_cancel_handle() -> CancelHandle {
    CancelHandle {
        inner: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
    }
}

/// Trigger cancellation. Idempotent â€” second trigger is a no-op.
/// Any in-flight `_cancellable` upload using this handle (or a clone)
/// will short-circuit at its next chunk-PUT check.
pub async fn cancel_handle_trigger(handle: &CancelHandle) {
    handle.inner.store(true, std::sync::atomic::Ordering::Relaxed);
}

/// Check whether the handle has been triggered. Mostly useful for
/// tests and UI status checks; the upload functions themselves do
/// not need to be polled.
pub async fn cancel_handle_is_cancelled(handle: &CancelHandle) -> bool {
    handle.inner.load(std::sync::atomic::Ordering::Relaxed)
}

/// Cancellable variant of `put_flat_resumable_from_path`. Cancellation
/// semantics are documented on [`CancelHandle`].
#[cfg(not(target_arch = "wasm32"))]
pub async fn put_flat_resumable_from_path_cancellable(
    client: &EncryptedClientHandle,
    bucket: String,
    path: String,
    file_path: String,
    manifest_path: String,
    content_type: Option<String>,
    cancel: &CancelHandle,
) -> anyhow::Result<PutResult> {
    let data = tokio::fs::read(&file_path).await
        .with_context(|| format!("Failed to read file: {}", file_path))?;
    let guard = client.inner.read().await;
    let manifest = std::path::PathBuf::from(manifest_path);
    let result = guard.put_object_encrypted_resumable_with_cancel(
        &bucket,
        &path,
        Bytes::from(data),
        content_type.as_deref(),
        &manifest,
        Some(cancel.inner.clone()),
    ).await?;
    Ok(result.into())
}

#[cfg(target_arch = "wasm32")]
pub async fn put_flat_resumable_from_path_cancellable(
    _client: &EncryptedClientHandle,
    _bucket: String,
    _path: String,
    _file_path: String,
    _manifest_path: String,
    _content_type: Option<String>,
    _cancel: &CancelHandle,
) -> anyhow::Result<PutResult> {
    anyhow::bail!(
        "put_flat_resumable_from_path_cancellable is not supported on WASM"
    )
}

/// Cancellable variant of `resume_flat_upload_from_path`.
#[cfg(not(target_arch = "wasm32"))]
pub async fn resume_flat_upload_from_path_cancellable(
    client: &EncryptedClientHandle,
    manifest_path: String,
    file_path: String,
    cancel: &CancelHandle,
) -> anyhow::Result<PutResult> {
    let data = tokio::fs::read(&file_path).await
        .with_context(|| format!("Failed to read file: {}", file_path))?;
    let guard = client.inner.read().await;
    let manifest = std::path::PathBuf::from(manifest_path);
    let result = guard.resume_upload_with_cancel(
        &manifest,
        &data,
        Some(cancel.inner.clone()),
    ).await?;
    Ok(result.into())
}

#[cfg(target_arch = "wasm32")]
pub async fn resume_flat_upload_from_path_cancellable(
    _client: &EncryptedClientHandle,
    _manifest_path: String,
    _file_path: String,
    _cancel: &CancelHandle,
) -> anyhow::Result<PutResult> {
    anyhow::bail!(
        "resume_flat_upload_from_path_cancellable is not supported on WASM"
    )
}

/// Discard a resumable upload's local state and best-effort delete its
/// already-uploaded chunks on the storage backend (issue #20).
///
/// Use when the caller decides to give up on a cancelled or failed
/// upload rather than resume. **Idempotent** â€” calling on a manifest
/// that doesn't exist (e.g. already aborted, or SDK auto-deleted it on
/// a prior clean completion) succeeds as a no-op. This matches Phase C
/// "discard cancelled upload" UX semantics: pressing the button always
/// leaves the system in a clean state, regardless of prior state.
///
/// **NOT a graceful stop.** This is POST-cancel cleanup. For mid-flight
/// abort, see [`cancel_handle_trigger`] on a [`CancelHandle`] passed to
/// the `_cancellable` variants (issue #18).
///
/// **Lock scope.** `client.inner.read().await` â€” same as the resumable
/// bridge functions. The underlying `abort_upload` doesn't touch the
/// encrypted forest (only the raw storage backend for chunk deletes
/// plus the local manifest file), so B1's per-bucket write mutex is
/// not needed here.
#[cfg(not(target_arch = "wasm32"))]
pub async fn abort_resumable_upload(
    client: &EncryptedClientHandle,
    manifest_path: String,
) -> anyhow::Result<()> {
    let manifest = std::path::PathBuf::from(&manifest_path);
    // Idempotency short-circuit: missing manifest means cleanup already
    // happened (prior abort, or SDK auto-delete on a successful clean
    // upload). Surface as success â€” the caller's intent ("ensure this
    // upload's local state is gone") is already satisfied. Other I/O
    // errors during the abort itself (malformed manifest, permission
    // denied, etc.) DO propagate so corruption + path bugs don't get
    // silently swallowed.
    if !manifest.exists() {
        return Ok(());
    }
    let guard = client.inner.read().await;
    guard
        .abort_upload(&manifest)
        .await
        .with_context(|| {
            format!("Failed to abort resumable upload for manifest {}", manifest_path)
        })?;
    Ok(())
}

#[cfg(target_arch = "wasm32")]
pub async fn abort_resumable_upload(
    _client: &EncryptedClientHandle,
    _manifest_path: String,
) -> anyhow::Result<()> {
    anyhow::bail!(
        "abort_resumable_upload is not supported on WASM (no filesystem manifest)"
    )
}

/// Get the size of a file without reading it into memory
#[cfg(not(target_arch = "wasm32"))]
pub async fn get_file_size(file_path: String) -> anyhow::Result<u64> {
    let metadata = tokio::fs::metadata(&file_path).await
        .with_context(|| format!("Failed to get file metadata: {}", file_path))?;
    Ok(metadata.len())
}

#[cfg(target_arch = "wasm32")]
pub async fn get_file_size(_file_path: String) -> anyhow::Result<u64> {
    anyhow::bail!("get_file_size is not supported on WASM; use the browser File API in Dart")
}

// ============================================================================
// Upload progress (polling) — real per-chunk percentage for FxFiles
// ============================================================================
//
// The SDK reports cumulative byte progress via an `Arc<dyn Fn(u64,u64)>`
// callback invoked as each content chunk's PUT completes (web + native).
// Rather than a Dart `Stream` (FRB `StreamSink`), which has never been
// exercised through this repo's external codegen/publish pipeline, progress
// is surfaced with the SAME opaque-handle + polling pattern already proven
// for `MasterHealthEvent` and `CancelHandle`: the app creates a
// [`ProgressHandle`], passes it to a `_with_progress` upload, and reads the
// latest value on a timer via [`poll_progress`] while the upload future is
// pending. The handle's `Arc` lifecycle is the cleanup — no global registry,
// no key collisions, no leak on early-return/panic.

struct ProgressState {
    /// Highest cumulative bytes reported so far (monotonic via `fetch_max`).
    uploaded: std::sync::atomic::AtomicU64,
    /// Total bytes of the upload (constant once the first chunk reports).
    total: std::sync::atomic::AtomicU64,
}

/// Opaque handle to an upload's live progress. Cheap to clone (clones the
/// inner `Arc`); the upload tasks and the poller observe the same counters.
#[derive(Clone)]
pub struct ProgressHandle {
    inner: std::sync::Arc<ProgressState>,
}

/// Create a fresh progress handle (0 / 0). Pass it to a `_with_progress`
/// upload function and read it via [`poll_progress`].
pub async fn create_progress_handle() -> ProgressHandle {
    ProgressHandle {
        inner: std::sync::Arc::new(ProgressState {
            uploaded: std::sync::atomic::AtomicU64::new(0),
            total: std::sync::atomic::AtomicU64::new(0),
        }),
    }
}

/// Read the latest progress for an in-flight (or finished) upload. Safe to
/// call any time, from any thread; returns 0% before the first chunk lands.
///
/// **100% caveat:** cumulative bytes reach `total` when the LAST content
/// chunk's PUT returns — BEFORE the index PUT + forest-flush tail. UIs that
/// show a determinate bar should cap at <100% until their own completion
/// signal (the upload future resolving), mirroring the mobile clamp.
pub async fn poll_progress(handle: &ProgressHandle) -> UploadProgress {
    let uploaded = handle.inner.uploaded.load(std::sync::atomic::Ordering::Relaxed);
    let total = handle.inner.total.load(std::sync::atomic::Ordering::Relaxed);
    UploadProgress::new(uploaded, total, 0, 0)
}

/// Build the SDK progress callback that feeds a [`ProgressHandle`]. Private
/// (not an FRB binding). `fetch_max` keeps the displayed value monotonic
/// even though up to 16 concurrent chunk tasks report cumulative values in
/// nondeterministic order; `total` is the same on every call.
fn progress_cb(handle: &ProgressHandle) -> std::sync::Arc<dyn Fn(u64, u64) + Send + Sync> {
    let p = handle.inner.clone();
    std::sync::Arc::new(move |done, tot| {
        // Store `total` first so a poll landing mid-callback never reads a
        // nonzero `uploaded` against a still-zero `total` (transient 0% blip).
        p.total.store(tot, std::sync::atomic::Ordering::Relaxed);
        p.uploaded.fetch_max(done, std::sync::atomic::Ordering::Relaxed);
    })
}

/// [`put_flat`] with live progress (web + native). Drive a percentage by
/// polling [`poll_progress`] on the passed [`ProgressHandle`] while this
/// future runs.
pub async fn put_flat_with_progress(
    client: &EncryptedClientHandle,
    bucket: String,
    path: String,
    data: Vec<u8>,
    content_type: Option<String>,
    progress: &ProgressHandle,
) -> anyhow::Result<PutResult> {
    let cb = progress_cb(progress);
    let guard = client.inner.write().await;
    let result = guard
        .put_object_flat_with_progress(&bucket, &path, Bytes::from(data), content_type.as_deref(), cb)
        .await?;
    Ok(result.into())
}

/// [`put_flat_resumable_from_path_cancellable`] with live progress (native).
#[cfg(not(target_arch = "wasm32"))]
pub async fn put_flat_resumable_from_path_with_progress(
    client: &EncryptedClientHandle,
    bucket: String,
    path: String,
    file_path: String,
    manifest_path: String,
    content_type: Option<String>,
    cancel: &CancelHandle,
    progress: &ProgressHandle,
) -> anyhow::Result<PutResult> {
    let data = tokio::fs::read(&file_path)
        .await
        .with_context(|| format!("Failed to read file: {}", file_path))?;
    let cb = progress_cb(progress);
    let guard = client.inner.read().await;
    let manifest = std::path::PathBuf::from(manifest_path);
    let result = guard
        .put_object_encrypted_resumable_with_cancel_and_progress(
            &bucket,
            &path,
            Bytes::from(data),
            content_type.as_deref(),
            &manifest,
            Some(cancel.inner.clone()),
            Some(cb),
        )
        .await?;
    Ok(result.into())
}

#[cfg(target_arch = "wasm32")]
pub async fn put_flat_resumable_from_path_with_progress(
    _client: &EncryptedClientHandle,
    _bucket: String,
    _path: String,
    _file_path: String,
    _manifest_path: String,
    _content_type: Option<String>,
    _cancel: &CancelHandle,
    _progress: &ProgressHandle,
) -> anyhow::Result<PutResult> {
    anyhow::bail!(
        "put_flat_resumable_from_path_with_progress is not supported on WASM; \
         use put_flat_with_progress from WASM"
    )
}

/// [`resume_flat_upload_from_path_cancellable`] with live progress (native).
/// Progress continues from the chunks the interrupted attempt already
/// uploaded (the SDK seeds the counter), so the bar resumes mid-way.
#[cfg(not(target_arch = "wasm32"))]
pub async fn resume_flat_upload_from_path_with_progress(
    client: &EncryptedClientHandle,
    manifest_path: String,
    file_path: String,
    cancel: &CancelHandle,
    progress: &ProgressHandle,
) -> anyhow::Result<PutResult> {
    let data = tokio::fs::read(&file_path)
        .await
        .with_context(|| format!("Failed to read file: {}", file_path))?;
    let cb = progress_cb(progress);
    let guard = client.inner.read().await;
    let manifest = std::path::PathBuf::from(manifest_path);
    let result = guard
        .resume_upload_with_cancel_and_progress(
            &manifest,
            &data,
            Some(cancel.inner.clone()),
            Some(cb),
        )
        .await?;
    Ok(result.into())
}

#[cfg(target_arch = "wasm32")]
pub async fn resume_flat_upload_from_path_with_progress(
    _client: &EncryptedClientHandle,
    _manifest_path: String,
    _file_path: String,
    _cancel: &CancelHandle,
    _progress: &ProgressHandle,
) -> anyhow::Result<PutResult> {
    anyhow::bail!("resume_flat_upload_from_path_with_progress is not supported on WASM")
}

// ============================================================================
// Subtree Operations (for Sharing)
// ============================================================================

/// Extract a subtree from the forest for sharing
///
/// This creates a serialized subtree that can be shared with others.
/// The subtree includes all files under the given prefix.
pub async fn get_forest_subtree(
    client: &EncryptedClientHandle,
    bucket: String,
    prefix: String,
) -> anyhow::Result<ForestSubtree> {
    let guard = client.inner.read().await;
    let subtree = guard.get_forest_subtree(&bucket, &prefix).await?;

    // Serialize the subtree
    let serialized = serde_json::to_vec(&subtree)
        .context("Failed to serialize subtree")?;

    Ok(ForestSubtree { serialized })
}
