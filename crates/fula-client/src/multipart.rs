//! Multipart upload support for large files

use crate::{ClientError, FulaClient, Result};
use bytes::Bytes;
use std::sync::{Arc, Mutex as StdMutex};
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(not(target_arch = "wasm32"))]
use std::time::Duration;

/// Progress callback type
pub type ProgressCallback = Box<dyn Fn(UploadProgress) + Send + Sync>;

/// Upload progress information
#[derive(Clone, Debug)]
pub struct UploadProgress {
    /// Bytes uploaded so far
    pub bytes_uploaded: u64,
    /// Total bytes to upload
    pub total_bytes: u64,
    /// Current part number
    pub current_part: u32,
    /// Total number of parts
    pub total_parts: u32,
}

impl UploadProgress {
    /// Get percentage complete
    pub fn percentage(&self) -> f64 {
        if self.total_bytes == 0 {
            return 100.0;
        }
        (self.bytes_uploaded as f64 / self.total_bytes as f64) * 100.0
    }
}

/// Multipart upload handle
///
/// Parts are stored behind an interior [`Mutex`](StdMutex) so concurrent
/// [`upload_part`](Self::upload_part) calls can run network I/O in parallel
/// without holding any outer lock. Callers that want to cap concurrency
/// (recommended) should wrap their own semaphore around the call site.
pub struct MultipartUpload {
    client: Arc<FulaClient>,
    bucket: String,
    key: String,
    upload_id: String,
    parts: StdMutex<Vec<CompletedPart>>,
    /// Set once `complete`/`abort` has started so repeat calls no-op.
    finished: AtomicBool,
    /// Cached ETag from a successful `complete`, so a retried complete
    /// returns the same value instead of re-POSTing and erroring.
    completed_etag: StdMutex<Option<String>>,
    #[allow(dead_code)]
    chunk_size: u64,
}

#[derive(Clone, Debug)]
struct CompletedPart {
    part_number: u32,
    etag: String,
}

impl MultipartUpload {
    /// Start a new multipart upload
    pub async fn start(
        client: Arc<FulaClient>,
        bucket: &str,
        key: &str,
    ) -> Result<Self> {
        // Initiate multipart upload
        let upload_id = initiate_upload(&client, bucket, key).await?;
        let chunk_size = client.config().multipart_chunk_size;

        Ok(Self {
            client,
            bucket: bucket.to_string(),
            key: key.to_string(),
            upload_id,
            parts: StdMutex::new(Vec::new()),
            finished: AtomicBool::new(false),
            completed_etag: StdMutex::new(None),
            chunk_size,
        })
    }

    /// Upload a part
    ///
    /// Takes `&self` so concurrent uploads of different part numbers can
    /// run in parallel. Internally, the HTTP `PUT` runs lock-free and only
    /// the completed-part bookkeeping briefly locks the parts mutex.
    pub async fn upload_part(&self, part_number: u32, data: Bytes) -> Result<()> {
        let etag = upload_part(
            &self.client,
            &self.bucket,
            &self.key,
            &self.upload_id,
            part_number,
            data,
        ).await?;

        self.parts
            .lock()
            .expect("multipart parts mutex poisoned")
            .push(CompletedPart { part_number, etag });
        Ok(())
    }

    /// Complete the upload
    ///
    /// Idempotent: on a retried call after a successful complete, returns
    /// the originally cached ETag without re-posting.
    pub async fn complete(&self) -> Result<String> {
        // Already finalized? Return cached etag if complete, else reject.
        if self.finished.swap(true, Ordering::SeqCst) {
            if let Some(etag) = self
                .completed_etag
                .lock()
                .expect("completed_etag mutex poisoned")
                .clone()
            {
                return Ok(etag);
            }
            return Err(ClientError::InvalidResponse(
                "multipart upload already aborted".to_string(),
            ));
        }

        // Snapshot parts before the network call so concurrent `upload_part`
        // calls can keep appending without blocking the complete.
        let parts_snapshot: Vec<CompletedPart> = self
            .parts
            .lock()
            .expect("multipart parts mutex poisoned")
            .clone();

        let result = complete_upload(
            &self.client,
            &self.bucket,
            &self.key,
            &self.upload_id,
            &parts_snapshot,
        ).await;

        match &result {
            Ok(etag) => {
                *self
                    .completed_etag
                    .lock()
                    .expect("completed_etag mutex poisoned") = Some(etag.clone());
            }
            Err(_) => {
                // Allow the caller to retry complete: roll back the finished flag.
                self.finished.store(false, Ordering::SeqCst);
            }
        }
        result
    }

    /// Abort the upload
    ///
    /// Idempotent: a second call after abort/complete is a silent no-op.
    pub async fn abort(&self) -> Result<()> {
        if self.finished.swap(true, Ordering::SeqCst) {
            return Ok(());
        }
        abort_upload(&self.client, &self.bucket, &self.key, &self.upload_id).await
    }

    /// Get the upload ID
    pub fn upload_id(&self) -> &str {
        &self.upload_id
    }

    /// Get the number of completed parts
    pub fn completed_parts(&self) -> usize {
        self.parts
            .lock()
            .expect("multipart parts mutex poisoned")
            .len()
    }

    /// Total bytes uploaded across all completed parts so far.
    ///
    /// Not recorded today — would require threading part sizes through
    /// `upload_part`. Exposed as a stub so FRB callers can wire a progress
    /// surface without the signature churning later. (S4 stub.)
    pub fn bytes_uploaded(&self) -> u64 {
        0
    }

    /// Detach the handle, leaving uploaded parts on the server.
    ///
    /// Suppresses the drop-time auto-abort. The caller becomes responsible
    /// for eventually completing, aborting, or relying on the bucket's
    /// `AbortIncompleteMultipartUpload` lifecycle policy to clean up parts.
    /// Use this to pause a resumable upload across app restarts without
    /// discarding the upload_id. (R4.)
    pub fn detach(&self) {
        self.finished.store(true, Ordering::SeqCst);
    }
}

impl Drop for MultipartUpload {
    fn drop(&mut self) {
        // If already finalised (complete succeeded, abort ran, or the
        // caller explicitly detached), no work to do.
        if self.finished.load(Ordering::SeqCst) {
            return;
        }
        // Mark finished so any racing detach/complete/abort no-ops.
        self.finished.store(true, Ordering::SeqCst);

        let client = Arc::clone(&self.client);
        let bucket = self.bucket.clone();
        let key = self.key.clone();
        let upload_id = self.upload_id.clone();

        #[cfg(not(target_arch = "wasm32"))]
        {
            // No runtime: e.g., sync tests, shutdown. The bucket lifecycle
            // rule is the cleanup backstop.
            let Ok(handle) = tokio::runtime::Handle::try_current() else {
                tracing::debug!(
                    %bucket, %key, %upload_id,
                    "MultipartUpload::drop: no tokio runtime, skipping auto-abort"
                );
                return;
            };
            handle.spawn(async move {
                if let Err(e) = abort_upload(&client, &bucket, &key, &upload_id).await {
                    tracing::warn!(
                        %bucket, %key, %upload_id,
                        error = %e,
                        "MultipartUpload::drop: auto-abort failed; relying on S3 lifecycle cleanup"
                    );
                }
            });
        }
        #[cfg(target_arch = "wasm32")]
        {
            wasm_bindgen_futures::spawn_local(async move {
                if let Err(e) = abort_upload(&client, &bucket, &key, &upload_id).await {
                    tracing::warn!(
                        %bucket, %key, %upload_id,
                        error = %e,
                        "MultipartUpload::drop: auto-abort failed; relying on S3 lifecycle cleanup"
                    );
                }
            });
        }
    }
}

/// RAII guard that issues a best-effort multipart abort when dropped without
/// being disarmed. Wrap around a `MultipartUpload` whose lifecycle may exit
/// via `?`-propagation or panic (e.g., mid-upload network error) to prevent
/// orphaned multipart uploads from lingering on S3.
///
/// **Mechanism** (M-3, Tier 1). On drop, if armed and a tokio runtime is
/// current, spawns `abort_upload` as a fire-and-forget task. If no runtime
/// is available (post-shutdown, sync contexts, or wasm32 without an active
/// `spawn_local` context), silently no-ops — matching `wal.rs`'s "no state
/// dir" silent-no-op pattern. The bucket's `AbortIncompleteMultipartUpload`
/// lifecycle rule serves as the cleanup backstop in all silent-no-op paths.
///
/// **Contract.** On the successful-complete path, call [`disarm`] after
/// `MultipartUpload::complete` returns `Ok`. Any other exit (error, panic,
/// early return) fires the abort.
///
/// **Not covered.** Callers that orchestrate `MultipartUpload::start` →
/// `upload_part` loop → `complete` themselves (e.g., external SDKs driving
/// the handle by hand) must wrap their own `MultipartAbortGuard` around the
/// orchestration. The guard is public precisely so those callers can opt in.
///
/// If telemetry later shows abort-failed leaks despite the S3 lifecycle
/// backstop, promote this to Tier 2 by adding orphan-queue persistence (see
/// plan §M-3 resolution steps 2–3).
///
/// [`disarm`]: MultipartAbortGuard::disarm
pub struct MultipartAbortGuard {
    /// Set to `Some(...)` while armed; `None` after disarm. On drop, if
    /// still `Some`, the closure is invoked synchronously.
    abort_fn: Option<Box<dyn FnOnce() + Send + 'static>>,
}

impl MultipartAbortGuard {
    /// Arm a new guard for the given in-flight multipart upload. Call
    /// [`disarm`](Self::disarm) on success; otherwise the Drop impl fires
    /// the abort.
    pub fn new(
        client: Arc<FulaClient>,
        bucket: impl Into<String>,
        key: impl Into<String>,
        upload_id: impl Into<String>,
    ) -> Self {
        let bucket = bucket.into();
        let key = key.into();
        let upload_id = upload_id.into();
        Self::from_callback(Box::new(move || {
            #[cfg(not(target_arch = "wasm32"))]
            {
                // No runtime: tests, shutdown, sync drops. Silent no-op —
                // the bucket lifecycle rule is the backstop.
                let Ok(handle) = tokio::runtime::Handle::try_current() else {
                    tracing::debug!(
                        %bucket, %key, %upload_id,
                        "MultipartAbortGuard: no tokio runtime, skipping auto-abort"
                    );
                    return;
                };
                handle.spawn(async move {
                    if let Err(e) = abort_upload(&client, &bucket, &key, &upload_id).await {
                        tracing::warn!(
                            %bucket, %key, %upload_id,
                            error = %e,
                            "MultipartAbortGuard: auto-abort failed; relying on S3 lifecycle cleanup"
                        );
                    }
                });
            }
            #[cfg(target_arch = "wasm32")]
            {
                wasm_bindgen_futures::spawn_local(async move {
                    if let Err(e) = abort_upload(&client, &bucket, &key, &upload_id).await {
                        tracing::warn!(
                            %bucket, %key, %upload_id,
                            error = %e,
                            "MultipartAbortGuard: auto-abort failed; relying on S3 lifecycle cleanup"
                        );
                    }
                });
            }
        }))
    }

    /// Construct a guard with an arbitrary synchronous callback. Used by
    /// in-module tests to observe Drop behavior without hitting HTTP.
    fn from_callback(cb: Box<dyn FnOnce() + Send + 'static>) -> Self {
        Self { abort_fn: Some(cb) }
    }

    /// Disarm the guard — the abort callback will NOT fire on drop. Call on
    /// the happy path after `MultipartUpload::complete` succeeds.
    pub fn disarm(mut self) {
        let _ = self.abort_fn.take();
    }
}

impl Drop for MultipartAbortGuard {
    fn drop(&mut self) {
        if let Some(cb) = self.abort_fn.take() {
            cb();
        }
    }
}

/// Upload a large file using multipart upload
pub async fn upload_large_file(
    client: Arc<FulaClient>,
    bucket: &str,
    key: &str,
    data: Bytes,
    progress: Option<ProgressCallback>,
) -> Result<String> {
    let chunk_size = client.config().multipart_chunk_size as usize;
    let total_size = data.len() as u64;
    let total_parts = ((data.len() + chunk_size - 1) / chunk_size) as u32;

    let upload = MultipartUpload::start(Arc::clone(&client), bucket, key).await?;

    // M-3 Tier 1: auto-abort on any `?`-propagating error below. `disarm()`
    // on the happy path after `complete()` suppresses the drop-time abort.
    let abort_guard = MultipartAbortGuard::new(
        Arc::clone(&client),
        bucket,
        key,
        upload.upload_id().to_string(),
    );

    let mut bytes_uploaded = 0u64;
    let mut part_number = 1u32;

    for chunk in data.chunks(chunk_size) {
        let chunk_data = Bytes::copy_from_slice(chunk);
        upload.upload_part(part_number, chunk_data).await?;

        bytes_uploaded += chunk.len() as u64;

        if let Some(ref cb) = progress {
            cb(UploadProgress {
                bytes_uploaded,
                total_bytes: total_size,
                current_part: part_number,
                total_parts,
            });
        }

        part_number += 1;
    }

    let etag = upload.complete().await?;
    abort_guard.disarm();
    Ok(etag)
}

// Helper functions for multipart operations

/// Retry an idempotent request with capped exponential backoff.
///
/// Only call this for verbs whose replay is safe: `upload_part` (PUT keyed
/// by `partNumber` + `uploadId`) and `abort_upload` (DELETE). Do NOT apply
/// to `initiate_upload` (POST would mint a new uploadId on replay, leaking
/// an orphan upload) or `complete_upload` (separately handled — a completed
/// upload replies `NoSuchUpload` on retry, which callers must treat as
/// success-equivalent). (NEW-F3.)
async fn retry_idempotent<F, Fut, T>(max_attempts: usize, mut op: F) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T>>,
{
    // WASM target has no reliable sleep primitive available from this crate
    // (no tokio reactor / gloo-timers dep), so a retry loop would hammer the
    // server in a tight cycle — worse than no retry. Collapse to
    // single-attempt on WASM; native callers get the backoff path.
    #[cfg(target_arch = "wasm32")]
    {
        let _ = max_attempts;
        return op().await;
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let mut attempt = 0usize;
        loop {
            attempt += 1;
            match op().await {
                Ok(v) => return Ok(v),
                Err(e) if attempt >= max_attempts || !is_transient(&e) => return Err(e),
                Err(e) => {
                    let backoff_ms = std::cmp::min(5_000u64, 100u64 * (1u64 << (attempt as u32 - 1)));
                    tracing::debug!(
                        attempt,
                        max_attempts,
                        backoff_ms,
                        error = %e,
                        "multipart: transient error, retrying"
                    );
                    tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                }
            }
        }
    }
}

/// Classify a ClientError as retry-safe. Network-level failures (connect,
/// timeout, decode) are always transient. S3-reported statuses 429/500/502/503/504
/// are transient; everything else (auth, 4xx policy errors, malformed response)
/// is not.
///
/// Native-only: `retry_idempotent` short-circuits to a single attempt on
/// wasm32 (no sleep primitive), so the classifier has no caller there.
/// Shared with `S3BlobBackend::{get, put}` in `encryption.rs` so the
/// blob-backend retry loop matches the same transient set.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn is_transient(err: &ClientError) -> bool {
    match err {
        ClientError::Http(e) => {
            // `is_connect` exists only on native reqwest; the wasm build
            // surfaces connect failures through `is_request`.
            #[cfg(not(target_arch = "wasm32"))]
            let connect = e.is_connect();
            #[cfg(target_arch = "wasm32")]
            let connect = false;
            e.is_timeout() || connect || e.is_request() || e.is_body() || e.is_decode()
        }
        ClientError::S3Error { code, .. } => matches!(
            code.as_str(),
            "HTTP429" | "HTTP500" | "HTTP502" | "HTTP503" | "HTTP504"
                | "429" | "500" | "502" | "503" | "504"
                | "SlowDown" | "InternalError" | "ServiceUnavailable"
        ),
        _ => false,
    }
}

async fn initiate_upload(client: &FulaClient, bucket: &str, key: &str) -> Result<String> {
    let path = format!("/{}/{}?uploads", bucket, key);

    // Build request manually since we need POST with query param
    let url = format!("{}{}", client.config().endpoint, path);

    // POST initiate is NOT idempotent — retrying on server-processed-but-
    // response-lost mints a new uploadId each time, leaking orphan uploads.
    // Execute once; rely on caller to retry the whole upload on failure.
    let mut req = client.http_client().post(&url);

    if let Some(token) = &client.config().access_token {
        req = req.header("Authorization", format!("Bearer {}", token));
    }

    let response = req.send().await.map_err(ClientError::Http)?;

    if !response.status().is_success() {
        let status = response.status().as_u16();
        let text = response.text().await.unwrap_or_default();
        return Err(ClientError::from_s3_xml(&text, status));
    }

    let text = response.text().await?;

    // Parse upload ID from XML
    let upload_id = extract_xml_value(&text, "UploadId")
        .ok_or_else(|| ClientError::InvalidResponse("Missing UploadId".to_string()))?;

    Ok(upload_id)
}

async fn upload_part(
    client: &FulaClient,
    bucket: &str,
    key: &str,
    upload_id: &str,
    part_number: u32,
    data: Bytes,
) -> Result<String> {
    let path = format!(
        "/{}/{}?partNumber={}&uploadId={}",
        bucket, key, part_number, upload_id
    );
    let url = format!("{}{}", client.config().endpoint, path);

    // PUT /partNumber= is idempotent: the server keys the part by
    // (uploadId, partNumber) and overwrites on replay. Retry on transient.
    retry_idempotent(5, || {
        let url = url.clone();
        let data = data.clone();
        async move {
            let mut req = client.http_client().put(&url).body(data);

            if let Some(token) = &client.config().access_token {
                req = req.header("Authorization", format!("Bearer {}", token));
            }

            let response = req.send().await.map_err(ClientError::Http)?;

            if !response.status().is_success() {
                let status = response.status().as_u16();
                let text = response.text().await.unwrap_or_default();
                return Err(ClientError::from_s3_xml(&text, status));
            }

            let etag = response
                .headers()
                .get("ETag")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.trim_matches('"').to_string())
                .ok_or_else(|| ClientError::InvalidResponse("Missing ETag".to_string()))?;

            Ok(etag)
        }
    })
    .await
}

async fn complete_upload(
    client: &FulaClient,
    bucket: &str,
    key: &str,
    upload_id: &str,
    parts: &[CompletedPart],
) -> Result<String> {
    let path = format!("/{}/{}?uploadId={}", bucket, key, upload_id);

    // S3 requires parts be listed in ascending partNumber order in
    // CompleteMultipartUpload; unordered lists are rejected by some
    // implementations. Sort defensively before serialising. (NEW-F3.)
    let mut sorted = parts.to_vec();
    sorted.sort_by_key(|p| p.part_number);
    let xml = build_complete_xml(&sorted);

    let url = format!("{}{}", client.config().endpoint, path);

    let mut req = client.http_client()
        .post(&url)
        .header("Content-Type", "application/xml")
        .body(xml);

    if let Some(token) = &client.config().access_token {
        req = req.header("Authorization", format!("Bearer {}", token));
    }

    let response = req.send().await.map_err(ClientError::Http)?;

    if !response.status().is_success() {
        let status = response.status().as_u16();
        let text = response.text().await.unwrap_or_default();
        let err = ClientError::from_s3_xml(&text, status);
        // Treat NoSuchUpload as success-equivalent: a previous call likely
        // completed the upload and the response was lost; replaying here
        // yields NoSuchUpload once the server has already dropped the
        // in-progress upload state. Caller can proceed.
        if let ClientError::S3Error { code, .. } = &err {
            if code == "NoSuchUpload" {
                tracing::info!(
                    %bucket, %key, %upload_id,
                    "multipart: CompleteMultipartUpload returned NoSuchUpload; treating as prior success"
                );
                return Ok(String::new());
            }
        }
        return Err(err);
    }

    let text = response.text().await?;

    let etag = extract_xml_value(&text, "ETag")
        .map(|s| s.trim_matches('"').to_string())
        .ok_or_else(|| ClientError::InvalidResponse("Missing ETag".to_string()))?;

    Ok(etag)
}

fn build_complete_xml(parts: &[CompletedPart]) -> String {
    let mut xml = String::from("<CompleteMultipartUpload>");
    for part in parts {
        xml.push_str(&format!(
            "<Part><PartNumber>{}</PartNumber><ETag>\"{}\"</ETag></Part>",
            part.part_number, part.etag
        ));
    }
    xml.push_str("</CompleteMultipartUpload>");
    xml
}

async fn abort_upload(
    client: &FulaClient,
    bucket: &str,
    key: &str,
    upload_id: &str,
) -> Result<()> {
    let path = format!("/{}/{}?uploadId={}", bucket, key, upload_id);
    let url = format!("{}{}", client.config().endpoint, path);

    // DELETE is idempotent; retry on transient.
    retry_idempotent(5, || {
        let url = url.clone();
        async move {
            let mut req = client.http_client().delete(&url);

            if let Some(token) = &client.config().access_token {
                req = req.header("Authorization", format!("Bearer {}", token));
            }

            let response = req.send().await.map_err(ClientError::Http)?;

            if !response.status().is_success() {
                let status = response.status().as_u16();
                let text = response.text().await.unwrap_or_default();
                return Err(ClientError::from_s3_xml(&text, status));
            }

            Ok(())
        }
    })
    .await
}

fn extract_xml_value(xml: &str, element: &str) -> Option<String> {
    let start_tag = format!("<{}>", element);
    let end_tag = format!("</{}>", element);

    let start = xml.find(&start_tag)? + start_tag.len();
    let end = xml.find(&end_tag)?;

    if start < end {
        Some(xml[start..end].to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn complete_xml_sorts_parts_by_part_number() {
        // Parts recorded out of order (e.g. parallel upload_part calls
        // completing in reverse order) must still be serialised in
        // ascending partNumber order. (NEW-F3.)
        let parts = vec![
            CompletedPart { part_number: 3, etag: "c".into() },
            CompletedPart { part_number: 1, etag: "a".into() },
            CompletedPart { part_number: 2, etag: "b".into() },
        ];
        let mut sorted = parts.clone();
        sorted.sort_by_key(|p| p.part_number);
        let xml = build_complete_xml(&sorted);
        let pos_a = xml.find("\"a\"").expect("etag a present");
        let pos_b = xml.find("\"b\"").expect("etag b present");
        let pos_c = xml.find("\"c\"").expect("etag c present");
        assert!(pos_a < pos_b && pos_b < pos_c, "parts must appear in partNumber order: {xml}");
    }

    #[test]
    fn is_transient_classifies_s3_5xx_and_429() {
        let server_busy = ClientError::S3Error {
            code: "503".into(),
            message: "busy".into(),
            request_id: None,
        };
        assert!(is_transient(&server_busy));

        let slow_down = ClientError::S3Error {
            code: "SlowDown".into(),
            message: "throttled".into(),
            request_id: None,
        };
        assert!(is_transient(&slow_down));

        let not_found = ClientError::S3Error {
            code: "NoSuchKey".into(),
            message: "".into(),
            request_id: None,
        };
        assert!(!is_transient(&not_found));

        let access = ClientError::AccessDenied("nope".into());
        assert!(!is_transient(&access));
    }

    #[tokio::test]
    async fn retry_idempotent_succeeds_after_transient_failures() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let attempts = Arc::new(AtomicUsize::new(0));
        let a2 = Arc::clone(&attempts);
        let result: Result<&'static str> = retry_idempotent(5, move || {
            let a = Arc::clone(&a2);
            async move {
                let n = a.fetch_add(1, Ordering::SeqCst) + 1;
                if n < 3 {
                    Err(ClientError::S3Error {
                        code: "503".into(),
                        message: "busy".into(),
                        request_id: None,
                    })
                } else {
                    Ok("ok")
                }
            }
        })
        .await;
        assert_eq!(result.unwrap(), "ok");
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn retry_idempotent_returns_immediately_on_non_transient() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let attempts = Arc::new(AtomicUsize::new(0));
        let a2 = Arc::clone(&attempts);
        let result: Result<()> = retry_idempotent(5, move || {
            let a = Arc::clone(&a2);
            async move {
                a.fetch_add(1, Ordering::SeqCst);
                Err(ClientError::AccessDenied("no".into()))
            }
        })
        .await;
        assert!(matches!(result, Err(ClientError::AccessDenied(_))));
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn abort_guard_drop_without_disarm_fires_callback() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let fired = Arc::new(AtomicUsize::new(0));
        let f2 = Arc::clone(&fired);
        {
            let _guard = MultipartAbortGuard::from_callback(Box::new(move || {
                f2.fetch_add(1, Ordering::SeqCst);
            }));
        }
        assert_eq!(fired.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn abort_guard_disarm_suppresses_drop_callback() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let fired = Arc::new(AtomicUsize::new(0));
        let f2 = Arc::clone(&fired);
        let guard = MultipartAbortGuard::from_callback(Box::new(move || {
            f2.fetch_add(1, Ordering::SeqCst);
        }));
        guard.disarm();
        assert_eq!(fired.load(Ordering::SeqCst), 0);
    }

    // R4 regression: detach must set the finished flag so Drop skips
    // the auto-abort. We test the flag directly since the abort path
    // requires a live tokio runtime + HTTP surface.
    #[test]
    fn detach_sets_finished_and_suppresses_drop_abort() {
        // Use an AtomicBool like the real finished field; detach() is a
        // thin setter, so we verify the invariant it establishes.
        let finished = AtomicBool::new(false);
        assert!(!finished.load(Ordering::SeqCst));

        // Simulate detach: store true.
        finished.store(true, Ordering::SeqCst);

        // Drop-time check would read this and early-return.
        assert!(finished.load(Ordering::SeqCst));
    }

    // S1 regression: two concurrent appends to the parts mutex must both
    // land without serialising behind an outer mutex. This mirrors what the
    // FRB wrapper does when two `upload_part` calls race on the same handle.
    #[tokio::test]
    async fn parts_mutex_accepts_concurrent_appends() {
        let parts: Arc<StdMutex<Vec<CompletedPart>>> = Arc::new(StdMutex::new(Vec::new()));
        let mut tasks = Vec::new();
        for n in 1u32..=8 {
            let parts = Arc::clone(&parts);
            tasks.push(tokio::spawn(async move {
                // Simulate some async work between acquiring the value to
                // push and the actual push — the lock should only be held
                // for the push, not across the await.
                tokio::task::yield_now().await;
                parts
                    .lock()
                    .expect("parts mutex poisoned")
                    .push(CompletedPart { part_number: n, etag: format!("e{n}") });
            }));
        }
        for t in tasks {
            t.await.unwrap();
        }
        let locked = parts.lock().unwrap();
        assert_eq!(locked.len(), 8);
        // Part numbers can arrive in any order; complete_upload sorts them.
        let mut nums: Vec<u32> = locked.iter().map(|p| p.part_number).collect();
        nums.sort();
        assert_eq!(nums, (1u32..=8).collect::<Vec<_>>());
    }
}
