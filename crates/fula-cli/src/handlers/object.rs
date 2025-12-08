//! Object operation handlers

use crate::pinning::pin_for_user;
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
use fula_blockstore::BlockStore;
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

    // Store the data
    let cid = state.block_store.put_block(&body).await?;
    
    // Calculate ETag (MD5)
    let etag = md5_hash(&body);

    // Verify Content-MD5 if present
    if let Some(md5_header) = headers.get("Content-MD5").and_then(|v| v.to_str().ok()) {
        if let Ok(expected_bytes) = general_purpose::STANDARD.decode(md5_header) {
            let expected_hex = hex::encode(expected_bytes);
            if etag != expected_hex {
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

    // Store in bucket
    tracing::debug!(bucket = %bucket_name, "Opening bucket");
    let mut bucket = state.bucket_manager.open_bucket(&bucket_name).await
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
    bucket.flush().await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to flush bucket");
            e
        })?;

    // Pin to user's pinning service if credentials provided
    // Headers: X-Pinning-Service, X-Pinning-Token
    pin_for_user(&headers, &cid, Some(&key)).await;

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

    let bucket = state.bucket_manager.open_bucket(&bucket_name).await?;
    
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

    let bucket = state.bucket_manager.open_bucket(&bucket_name).await?;
    
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
) -> Result<Response, ApiError> {
    if !session.can_write() {
        return Err(ApiError::s3(S3ErrorCode::AccessDenied, "Write access required"));
    }

    let mut bucket = state.bucket_manager.open_bucket(&bucket_name).await?;
    bucket.delete_object(&key).await?;
    bucket.flush().await?;

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

    // Get source object
    let source_bucket_handle = state.bucket_manager.open_bucket(source_bucket).await?;
    let source_metadata = source_bucket_handle.get_object(source_key).await?
        .ok_or_else(|| ApiError::s3_with_resource(
            S3ErrorCode::NoSuchKey,
            "Source object not found",
            copy_source,
        ))?;

    // Copy to destination
    let mut dest_metadata = source_metadata.clone();
    dest_metadata.last_modified = chrono::Utc::now();
    dest_metadata.owner_id = Some(session.user_id.clone());

    let mut dest_bucket_handle = state.bucket_manager.open_bucket(&dest_bucket).await?;
    dest_bucket_handle.put_object(dest_key, dest_metadata.clone()).await?;
    dest_bucket_handle.flush().await?;

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
