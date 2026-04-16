//! Object operation handlers

use crate::pinning::{check_can_upload, pin_for_user, unpin_for_user};
use crate::{AppState, ApiError, S3ErrorCode};
use crate::state::UserSession;
use crate::xml;
use axum::{
    body::Body,
    extract::{Extension, Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use bytes::Bytes;
use fula_blockstore::{BlockStore, PinStore};
use fula_core::metadata::ObjectMetadata;
use fula_crypto::hashing::md5_hash;
use serde::Deserialize;
use std::sync::Arc;
use base64::{Engine as _, engine::general_purpose};

/// PUT /{bucket}/{key} - Put object
pub async fn put_object(
    State(state): State<Arc<AppState>>,
    Extension(session): Extension<UserSession>,
    Path((bucket_name, key)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    if !session.can_write() {
        return Err(ApiError::s3(S3ErrorCode::AccessDenied, "Write access required"));
    }

    // Check balance BEFORE storing data (if remote pinning is configured)
    let can_upload = check_can_upload(
        state.config.storage_api_url.as_deref(),
        Some(&session.jwt_token),
    ).await?;

    if !can_upload {
        return Err(ApiError::s3(
            S3ErrorCode::AccountProblem,
            "Insufficient credits. Please add FULA credits to continue.",
        ));
    }

    // Decode HTTP chunked transfer encoding if present in the body.
    // AWS CLI and other S3 clients may send chunked-encoded bodies that a
    // reverse proxy (e.g., nginx) forwards without decoding.
    let body = match try_decode_chunked(&headers, &body) {
        Some(decoded) => decoded,
        None => body,
    };

    // Store the data
    let cid = state.block_store.put_block(&body).await?;

    // Use CID as ETag (content-addressed identifier)
    // This is S3-compliant: AWS docs state "The ETag may or may not be an MD5 digest"
    let etag = cid.to_string();

    // Verify Content-MD5 if present (still uses MD5 for S3 compatibility)
    if let Some(md5_header) = headers.get("Content-MD5").and_then(|v| v.to_str().ok()) {
        if let Ok(expected_bytes) = general_purpose::STANDARD.decode(md5_header) {
            let expected_hex = hex::encode(expected_bytes);
            let actual_md5 = md5_hash(&body);
            if actual_md5 != expected_hex {
                return Err(ApiError::s3(S3ErrorCode::InvalidDigest, "The Content-MD5 you specified did not match what we received."));
            }
        } else {
            return Err(ApiError::s3(S3ErrorCode::InvalidDigest, "Invalid Content-MD5"));
        }
    }

    // Extract metadata from headers
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let mut metadata = ObjectMetadata::new(cid, body.len() as u64, etag.clone())
        .with_owner(&session.user_id);

    if let Some(ct) = content_type {
        metadata = metadata.with_content_type(ct);
    }

    // Extract user metadata (x-amz-meta-*)
    for (name, value) in headers.iter() {
        if let Some(key) = name.as_str().strip_prefix("x-amz-meta-") {
            if let Ok(v) = value.to_str() {
                metadata = metadata.with_user_metadata(key, v);
            }
        }
    }

    // Store in bucket (user-scoped)
    tracing::debug!(bucket = %bucket_name, "Opening user-scoped bucket");
    let mut bucket = state.bucket_manager.open_bucket_for_user(&session.hashed_user_id, &bucket_name).await
        .map_err(|e| {
            tracing::error!(error = %e, bucket = %bucket_name, "Failed to open bucket");
            e
        })?;

    tracing::debug!(key = %key, "Storing object metadata");
    bucket.put_object(key.clone(), metadata).await
        .map_err(|e| {
            tracing::error!(error = %e, key = %key, "Failed to put object");
            e
        })?;
    
    tracing::debug!("Flushing bucket");
    let bucket_root_cid = bucket.flush().await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to flush bucket");
            e
        })?;

    // Persist the bucket registry so the new root CID survives restarts.
    // This MUST succeed — otherwise the new tree root is lost on restart.
    // Use the user's JWT for pinning service authentication.
    state.bucket_manager.persist_registry_with_token(&session.jwt_token).await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to persist bucket registry after put_object — data may be lost on restart");
            ApiError::s3(S3ErrorCode::InternalError, "Failed to persist storage index. Please retry.")
        })?;

    // Pin the BUCKET ROOT CID to ensure tree structure survives GC.
    // This recursively pins all tree nodes AND all referenced object data.
    // NOTE: Pinning is async (fire-and-forget) to avoid blocking the response.
    {
        let block_store = Arc::clone(&state.block_store);
        let pin_name = format!("bucket:{}", bucket_name);
        let jwt_token = session.jwt_token.clone();
        tokio::spawn(async move {
            if let Err(e) = block_store.pin_with_token(&bucket_root_cid, Some(&pin_name), &jwt_token).await {
                tracing::warn!(cid = %bucket_root_cid, error = %e, "Failed to pin bucket root CID");
            } else {
                tracing::info!(cid = %bucket_root_cid, bucket = %pin_name, "Bucket root CID pinned (recursive)");
            }
        });
    }

    // Also pin to user's external pinning service if credentials provided
    // The session JWT is used as the default token if no X-Pinning-Token header is provided
    pin_for_user(&headers, &cid, Some(&key), state.config.pinning_service_endpoint.as_deref(), Some(&session.jwt_token)).await;

    Ok((
        StatusCode::OK,
        [("ETag", format!("\"{}\"", etag))],
        "",
    ).into_response())
}

/// GET /{bucket}/{key} - Get object with Range and conditional request support
pub async fn get_object(
    State(state): State<Arc<AppState>>,
    Extension(session): Extension<UserSession>,
    Path((bucket_name, key)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    if !session.can_read() {
        return Err(ApiError::s3(S3ErrorCode::AccessDenied, "Read access required"));
    }

    // User-scoped bucket access
    let bucket = state.bucket_manager.open_bucket_for_user(&session.hashed_user_id, &bucket_name).await?;

    let metadata = bucket.get_object(&key).await?
        .ok_or_else(|| ApiError::s3_with_resource(
            S3ErrorCode::NoSuchKey,
            "Object not found",
            format!("{}/{}", bucket_name, key),
        ))?;

    // Check delete marker
    if metadata.is_delete_marker {
        return Err(ApiError::s3_with_resource(
            S3ErrorCode::NoSuchKey,
            "Object is a delete marker",
            format!("{}/{}", bucket_name, key),
        ));
    }

    let etag = format!("\"{}\"", metadata.etag);
    let last_modified = metadata.last_modified;
    let last_modified_str = last_modified.format("%a, %d %b %Y %H:%M:%S GMT").to_string();

    // Handle If-None-Match (304 Not Modified)
    if let Some(if_none_match) = headers.get("If-None-Match").and_then(|v| v.to_str().ok()) {
        if if_none_match == etag || if_none_match == "*" {
            return Ok(Response::builder()
                .status(StatusCode::NOT_MODIFIED)
                .header("ETag", &etag)
                .header("Last-Modified", &last_modified_str)
                .body(Body::empty())
                .unwrap());
        }
    }

    // Handle If-Modified-Since (304 Not Modified)
    if let Some(if_modified_since) = headers.get("If-Modified-Since").and_then(|v| v.to_str().ok()) {
        if let Ok(since) = chrono::DateTime::parse_from_rfc2822(if_modified_since) {
            if last_modified <= since.with_timezone(&chrono::Utc) {
                return Ok(Response::builder()
                    .status(StatusCode::NOT_MODIFIED)
                    .header("ETag", &etag)
                    .header("Last-Modified", &last_modified_str)
                    .body(Body::empty())
                    .unwrap());
            }
        }
    }

    // Retrieve data from block store
    let data = state.block_store.get_block(&metadata.cid).await?;
    let total_size = data.len();

    // Handle Range request
    let range_header = headers.get("Range").and_then(|v| v.to_str().ok());
    let (status, body_data, content_range) = if let Some(range) = range_header {
        match parse_range_header(range, total_size) {
            Ok((start, end)) => {
                let content_range = format!("bytes {}-{}/{}", start, end, total_size);
                let slice = data.slice(start..=end);
                (StatusCode::PARTIAL_CONTENT, slice, Some(content_range))
            }
            Err(_) => {
                return Err(ApiError::s3(
                    S3ErrorCode::InvalidRange,
                    "Requested range not satisfiable",
                ));
            }
        }
    } else {
        (StatusCode::OK, data, None)
    };

    // Build response headers
    let mut response = Response::builder()
        .status(status)
        .header("ETag", &etag)
        .header("Content-Length", body_data.len().to_string())
        .header("Last-Modified", &last_modified_str)
        .header("Accept-Ranges", "bytes");

    if let Some(range) = content_range {
        response = response.header("Content-Range", range);
    }

    if let Some(ref ct) = metadata.content_type {
        response = response.header("Content-Type", ct);
    }

    if let Some(ref cc) = metadata.cache_control {
        response = response.header("Cache-Control", cc);
    }

    if let Some(ref cd) = metadata.content_disposition {
        response = response.header("Content-Disposition", cd);
    }

    if let Some(ref ce) = metadata.content_encoding {
        response = response.header("Content-Encoding", ce);
    }

    // Add user metadata
    for (k, v) in &metadata.user_metadata {
        response = response.header(format!("x-amz-meta-{}", k), v);
    }

    // Add version ID if present
    if let Some(ref version_id) = metadata.version_id {
        response = response.header("x-amz-version-id", version_id);
    }

    Ok(response.body(Body::from(body_data)).unwrap())
}

/// Attempt to decode HTTP chunked transfer encoding from a request body.
/// Returns Some(decoded) if the body was chunked-encoded, None otherwise.
///
/// This handles two cases:
/// 1. AWS `Content-Encoding: aws-chunked` with streaming SigV4 signatures
/// 2. Plain HTTP chunked TE where a reverse proxy stripped the Transfer-Encoding header
pub(crate) fn try_decode_chunked(headers: &HeaderMap, body: &Bytes) -> Option<Bytes> {
    let has_decoded_len = headers.get("x-amz-decoded-content-length").is_some();
    let has_aws_chunked = headers
        .get(header::CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.contains("aws-chunked"))
        .unwrap_or(false);

    if !has_decoded_len && !has_aws_chunked && !looks_like_chunked(body) {
        return None;
    }

    decode_chunked_body(body).map(|decoded| {
        tracing::info!(
            original_len = body.len(),
            decoded_len = decoded.len(),
            has_decoded_len,
            has_aws_chunked,
            "Decoded chunked request body"
        );
        decoded
    })
}

/// Check if a body appears to be HTTP chunked transfer-encoded.
fn looks_like_chunked(body: &[u8]) -> bool {
    if body.len() < 4 {
        return false;
    }

    // Find first \r\n (chunk-size line delimiter)
    let crlf_pos = match body.windows(2).position(|w| w == b"\r\n") {
        Some(pos) if pos > 0 && pos <= 100 => pos,
        _ => return false,
    };

    // Extract hex size (before any chunk extensions like ";chunk-signature=...")
    let size_line = match std::str::from_utf8(&body[..crlf_pos]) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let size_hex = size_line.split(';').next().unwrap_or("");

    let chunk_size = match usize::from_str_radix(size_hex.trim(), 16) {
        Ok(s) if s > 0 => s,
        _ => return false,
    };

    // Chunk data must fit within the remaining body
    let data_start = crlf_pos + 2;
    chunk_size <= body.len().saturating_sub(data_start)
}

/// Decode HTTP chunked transfer encoding from raw bytes.
/// Handles both plain chunked and aws-chunked (ignoring chunk extensions).
fn decode_chunked_body(body: &[u8]) -> Option<Bytes> {
    let mut decoded = Vec::new();
    let mut pos = 0;

    while pos < body.len() {
        let remaining = &body[pos..];

        // Find the \r\n ending the chunk-size line
        let crlf_pos = remaining.windows(2).position(|w| w == b"\r\n")?;

        if crlf_pos == 0 {
            // Empty line — skip
            pos += 2;
            continue;
        }

        // Parse chunk size (ignore extensions after ';')
        let size_line = std::str::from_utf8(&remaining[..crlf_pos]).ok()?;
        let size_hex = size_line.split(';').next()?;
        let chunk_size = usize::from_str_radix(size_hex.trim(), 16).ok()?;

        if chunk_size == 0 {
            break; // Terminal chunk
        }

        let data_start = pos + crlf_pos + 2;
        let data_end = data_start + chunk_size;

        if data_end > body.len() {
            return None; // Truncated — probably not chunked after all
        }

        decoded.extend_from_slice(&body[data_start..data_end]);

        // Skip the \r\n after chunk data
        pos = data_end;
        if pos + 2 <= body.len() && body[pos] == b'\r' && body[pos + 1] == b'\n' {
            pos += 2;
        }
    }

    if decoded.is_empty() {
        None
    } else {
        Some(Bytes::from(decoded))
    }
}

/// Parse Range header (e.g., "bytes=0-1023" or "bytes=500-" or "bytes=-500")
fn parse_range_header(range: &str, total_size: usize) -> Result<(usize, usize), ()> {
    let range = range.strip_prefix("bytes=").ok_or(())?;
    
    if let Some((start_str, end_str)) = range.split_once('-') {
        if start_str.is_empty() {
            // Suffix range: bytes=-500 means last 500 bytes
            let suffix_len: usize = end_str.parse().map_err(|_| ())?;
            let start = total_size.saturating_sub(suffix_len);
            Ok((start, total_size - 1))
        } else if end_str.is_empty() {
            // Range from start to end: bytes=500-
            let start: usize = start_str.parse().map_err(|_| ())?;
            if start >= total_size {
                return Err(());
            }
            Ok((start, total_size - 1))
        } else {
            // Normal range: bytes=0-1023
            let start: usize = start_str.parse().map_err(|_| ())?;
            let end: usize = end_str.parse().map_err(|_| ())?;
            if start > end || start >= total_size {
                return Err(());
            }
            Ok((start, end.min(total_size - 1)))
        }
    } else {
        Err(())
    }
}

/// HEAD /{bucket}/{key} - Head object
pub async fn head_object(
    State(state): State<Arc<AppState>>,
    Extension(session): Extension<UserSession>,
    Path((bucket_name, key)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    if !session.can_read() {
        return Err(ApiError::s3(S3ErrorCode::AccessDenied, "Read access required"));
    }

    // User-scoped bucket access
    let bucket = state.bucket_manager.open_bucket_for_user(&session.hashed_user_id, &bucket_name).await?;

    let metadata = bucket.get_object(&key).await?
        .ok_or_else(|| ApiError::s3_with_resource(
            S3ErrorCode::NoSuchKey,
            "Object not found",
            format!("{}/{}", bucket_name, key),
        ))?;

    let mut response = Response::builder()
        .status(StatusCode::OK)
        .header("ETag", format!("\"{}\"", metadata.etag))
        .header("Content-Length", metadata.size.to_string())
        .header("Last-Modified", metadata.last_modified.format("%a, %d %b %Y %H:%M:%S GMT").to_string());

    if let Some(ref ct) = metadata.content_type {
        response = response.header("Content-Type", ct);
    }

    // Add user metadata
    for (k, v) in &metadata.user_metadata {
        response = response.header(format!("x-amz-meta-{}", k), v);
    }

    Ok(response.body(Body::empty()).unwrap())
}

/// DELETE /{bucket}/{key} - Delete object
pub async fn delete_object(
    State(state): State<Arc<AppState>>,
    Extension(session): Extension<UserSession>,
    Path((bucket_name, key)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    if !session.can_write() {
        return Err(ApiError::s3(S3ErrorCode::AccessDenied, "Write access required"));
    }

    // User-scoped bucket access
    let mut bucket = state.bucket_manager.open_bucket_for_user(&session.hashed_user_id, &bucket_name).await?;

    // Capture the removed metadata so we can unpin the CID after the index
    // is successfully updated. Must unpin AFTER persist — if persist fails
    // and we've already unpinned, the data is gone but the index still
    // references it on next start (recoverable on re-upload, but bad UX).
    let removed = bucket.delete_object(&key).await?;
    bucket.flush().await?;

    // Persist the bucket registry so the updated root CID survives restarts.
    // This MUST succeed — otherwise the delete is lost on restart.
    state.bucket_manager.persist_registry_with_token(&session.jwt_token).await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to persist bucket registry after delete_object — change may be lost on restart");
            ApiError::s3(S3ErrorCode::InternalError, "Failed to persist storage index. Please retry.")
        })?;

    // Best-effort IPFS unpin (F-NEW). Must be refcount-safe: if any other key
    // in this bucket still references the same CID (client-side dedup, or two
    // keys coincidentally mapped to the same content), skip the unpin to avoid
    // losing pins for still-referenced data.
    //
    // Cross-bucket refcount is not checked here: each bucket's pinning is
    // scoped to its own index, and the pinning service tracks pins by
    // request_id — unpinning one bucket's pin does not affect other buckets'
    // pins of the same CID, since each was added as a separate pin.
    if let Some(removed_meta) = removed {
        let cid = removed_meta.cid;
        let still_referenced = match bucket
            .list_objects(None, None, None, None)
            .await
        {
            Ok(result) => result.objects.iter().any(|o| o.metadata.cid == cid),
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    cid = %cid,
                    "Could not enumerate bucket to refcount-check CID; skipping unpin conservatively"
                );
                true
            }
        };

        if !still_referenced {
            if let Err(e) = state.block_store.unpin(&cid).await {
                tracing::warn!(
                    cid = %cid,
                    error = %e,
                    "Failed to unpin from local IPFS (best-effort)"
                );
            }

            unpin_for_user(
                &headers,
                &cid,
                state.config.pinning_service_endpoint.as_deref(),
                Some(&session.jwt_token),
            )
            .await;
        } else {
            tracing::debug!(
                cid = %cid,
                bucket = %bucket_name,
                "Skipping unpin — CID still referenced by another key in the bucket"
            );
        }
    }

    Ok(StatusCode::NO_CONTENT.into_response())
}

/// Copy source header
#[derive(Debug, Deserialize)]
pub struct CopyParams {
    #[serde(rename = "x-amz-copy-source")]
    pub copy_source: Option<String>,
}

/// PUT /{bucket}/{key} with x-amz-copy-source - Copy object
pub async fn copy_object(
    State(state): State<Arc<AppState>>,
    Extension(session): Extension<UserSession>,
    Path((dest_bucket, dest_key)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    if !session.can_write() {
        return Err(ApiError::s3(S3ErrorCode::AccessDenied, "Write access required"));
    }

    let copy_source = headers
        .get("x-amz-copy-source")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| ApiError::s3(S3ErrorCode::InvalidArgument, "Missing x-amz-copy-source"))?;

    // Parse source bucket/key
    let source_path = copy_source.trim_start_matches('/');
    let (source_bucket, source_key) = source_path
        .split_once('/')
        .ok_or_else(|| ApiError::s3(S3ErrorCode::InvalidArgument, "Invalid copy source format"))?;

    // Get source object (user-scoped)
    let source_bucket_handle = state.bucket_manager.open_bucket_for_user(&session.hashed_user_id, source_bucket).await?;

    let source_metadata = source_bucket_handle.get_object(source_key).await?
        .ok_or_else(|| ApiError::s3_with_resource(
            S3ErrorCode::NoSuchKey,
            "Source object not found",
            copy_source,
        ))?;

    // Copy to destination (user-scoped)
    let mut dest_metadata = source_metadata.clone();
    dest_metadata.last_modified = chrono::Utc::now();
    dest_metadata.owner_id = Some(session.hashed_user_id.clone());

    let mut dest_bucket_handle = state.bucket_manager.open_bucket_for_user(&session.hashed_user_id, &dest_bucket).await?;

    dest_bucket_handle.put_object(dest_key, dest_metadata.clone()).await?;
    dest_bucket_handle.flush().await?;

    // Persist the bucket registry so the updated root CID survives restarts.
    // This MUST succeed — otherwise the copy is lost on restart.
    state.bucket_manager.persist_registry_with_token(&session.jwt_token).await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to persist bucket registry after copy_object — change may be lost on restart");
            ApiError::s3(S3ErrorCode::InternalError, "Failed to persist storage index. Please retry.")
        })?;

    let xml_response = xml::copy_object_result(
        dest_metadata.last_modified,
        &dest_metadata.etag,
    );

    Ok((
        StatusCode::OK,
        [("Content-Type", "application/xml")],
        xml_response,
    ).into_response())
}
