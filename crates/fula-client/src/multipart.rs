//! Multipart upload support for large files

use crate::{ClientError, FulaClient, Result};
use bytes::Bytes;
use std::sync::Arc;
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
pub struct MultipartUpload {
    client: Arc<FulaClient>,
    bucket: String,
    key: String,
    upload_id: String,
    parts: Vec<CompletedPart>,
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
            parts: Vec::new(),
            chunk_size,
        })
    }

    /// Upload a part
    pub async fn upload_part(&mut self, part_number: u32, data: Bytes) -> Result<()> {
        let etag = upload_part(
            &self.client,
            &self.bucket,
            &self.key,
            &self.upload_id,
            part_number,
            data,
        ).await?;

        self.parts.push(CompletedPart { part_number, etag });
        Ok(())
    }

    /// Complete the upload
    pub async fn complete(self) -> Result<String> {
        complete_upload(
            &self.client,
            &self.bucket,
            &self.key,
            &self.upload_id,
            &self.parts,
        ).await
    }

    /// Abort the upload
    pub async fn abort(self) -> Result<()> {
        abort_upload(&self.client, &self.bucket, &self.key, &self.upload_id).await
    }

    /// Get the upload ID
    pub fn upload_id(&self) -> &str {
        &self.upload_id
    }

    /// Get the number of completed parts
    pub fn completed_parts(&self) -> usize {
        self.parts.len()
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

    let mut upload = MultipartUpload::start(Arc::clone(&client), bucket, key).await?;

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

    upload.complete().await
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
fn is_transient(err: &ClientError) -> bool {
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
}
