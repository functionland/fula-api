//! Multipart upload handlers

use crate::{AppState, ApiError, S3ErrorCode};
use crate::pinning::{check_can_upload, pin_for_user};
use crate::state::UserSession;
use crate::multipart::UploadPart;
use crate::xml;
use super::object::try_decode_chunked;
use axum::{
    extract::{Extension, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use bytes::Bytes;
use fula_blockstore::{BlockStore, PinStore};
use fula_core::metadata::ObjectMetadata;
use serde::Deserialize;
use std::sync::Arc;

/// Query params for multipart operations
#[derive(Debug, Deserialize)]
pub struct MultipartParams {
    #[serde(rename = "uploadId")]
    pub upload_id: Option<String>,
    #[serde(rename = "partNumber")]
    pub part_number: Option<u32>,
    pub uploads: Option<String>,
}

/// POST /{bucket}/{key}?uploads - Initiate multipart upload
pub async fn create_multipart_upload(
    State(state): State<Arc<AppState>>,
    Extension(session): Extension<UserSession>,
    Path((bucket, key)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    if !session.can_write() {
        return Err(ApiError::s3(S3ErrorCode::AccessDenied, "Write access required"));
    }

    // Verify bucket exists for this user
    if !state.bucket_manager.bucket_exists_for_user(&session.hashed_user_id, &bucket) {
        return Err(ApiError::s3(S3ErrorCode::NoSuchBucket, "Bucket not found"));
    }

    // Extract content type
    let content_type = headers.get("Content-Type")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // Extract user metadata
    let mut metadata = std::collections::BTreeMap::new();
    for (name, value) in headers.iter() {
        if let Some(key) = name.as_str().strip_prefix("x-amz-meta-") {
            if let Ok(v) = value.to_str() {
                metadata.insert(key.to_string(), v.to_string());
            }
        }
    }

    // Security audit fix A3: Use hashed user ID
    let upload = state.multipart_manager.create_upload_with_metadata(
        bucket.clone(),
        key.clone(),
        session.hashed_user_id.clone(),
        content_type,
        metadata,
    );

    let xml_response = xml::initiate_multipart_upload_result(
        &bucket,
        &key,
        &upload.upload_id,
    );

    Ok((
        StatusCode::OK,
        [("Content-Type", "application/xml")],
        xml_response,
    ).into_response())
}

/// PUT /{bucket}/{key}?partNumber=N&uploadId=X - Upload part
pub async fn upload_part(
    State(state): State<Arc<AppState>>,
    Extension(session): Extension<UserSession>,
    Path((bucket, key)): Path<(String, String)>,
    Query(params): Query<MultipartParams>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    if !session.can_write() {
        return Err(ApiError::s3(S3ErrorCode::AccessDenied, "Write access required"));
    }

    let upload_id = params.upload_id
        .ok_or_else(|| ApiError::s3(S3ErrorCode::InvalidArgument, "Missing uploadId"))?;

    let part_number = params.part_number
        .ok_or_else(|| ApiError::s3(S3ErrorCode::InvalidArgument, "Missing partNumber"))?;

    // Validate part number
    if part_number < 1 || part_number > 10000 {
        return Err(ApiError::s3(
            S3ErrorCode::InvalidArgument,
            "Part number must be between 1 and 10000",
        ));
    }

    // Verify upload exists
    let upload = state.multipart_manager.get_upload(&upload_id)
        .ok_or_else(|| ApiError::s3(S3ErrorCode::NoSuchUpload, "Upload not found"))?;

    if upload.bucket != bucket || upload.key != key {
        return Err(ApiError::s3(S3ErrorCode::InvalidArgument, "Bucket/key mismatch"));
    }

    // Decode chunked encoding if present (same as put_object)
    let body = match try_decode_chunked(&headers, &body) {
        Some(decoded) => decoded,
        None => body,
    };

    // Store part data
    let cid = state.block_store.put_block(&body).await?;

    // Use CID as ETag for parts (content-addressed identifier)
    let etag = cid.to_string();

    let part = UploadPart::new(
        part_number,
        etag.clone(),
        body.len() as u64,
        cid.to_string(),
    );

    state.multipart_manager.add_part(&upload_id, part);

    Ok((
        StatusCode::OK,
        [("ETag", format!("\"{}\"", etag))],
        "",
    ).into_response())
}

/// POST /{bucket}/{key}?uploadId=X - Complete multipart upload
pub async fn complete_multipart_upload(
    State(state): State<Arc<AppState>>,
    Extension(session): Extension<UserSession>,
    Path((bucket, key)): Path<(String, String)>,
    Query(params): Query<MultipartParams>,
    headers: HeaderMap,
    _body: Bytes,
) -> Result<Response, ApiError> {
    if !session.can_write() {
        return Err(ApiError::s3(S3ErrorCode::AccessDenied, "Write access required"));
    }

    // Check balance BEFORE completing the upload (if remote pinning is configured)
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

    let upload_id = params.upload_id
        .ok_or_else(|| ApiError::s3(S3ErrorCode::InvalidArgument, "Missing uploadId"))?;

    // Get the upload
    let upload = state.multipart_manager.complete_upload(&upload_id)
        .ok_or_else(|| ApiError::s3(S3ErrorCode::NoSuchUpload, "Upload not found"))?;

    if upload.bucket != bucket || upload.key != key {
        return Err(ApiError::s3(S3ErrorCode::InvalidArgument, "Bucket/key mismatch"));
    }

    // Calculate final ETag using CIDs (S3 multipart format: {hash}-{partCount})
    // We hash the concatenated part CIDs to create a unique identifier
    let part_count = upload.parts.len();
    let mut cid_concat = String::new();
    for part in upload.sorted_parts() {
        cid_concat.push_str(&part.cid);
    }
    // Use BLAKE3 hash of concatenated CIDs, truncated to 32 hex chars for compatibility
    let hash = fula_crypto::hashing::hash(cid_concat.as_bytes());
    let hash_hex = hex::encode(&hash.as_bytes()[..16]); // First 16 bytes = 32 hex chars
    let final_etag = format!("{}-{}", hash_hex, part_count);

    // Calculate total size
    let total_size: u64 = upload.parts.values().map(|p| p.size).sum();

    // Collect all part CIDs for pinning
    let part_cids: Vec<cid::Cid> = upload.parts.values()
        .filter_map(|p| p.cid.parse().ok())
        .collect();

    // Create the final object metadata
    // In a real implementation, we'd create a DAG linking all parts
    let first_part_cid: cid::Cid = part_cids.first()
        .copied()
        .ok_or_else(|| ApiError::s3(S3ErrorCode::InvalidPart, "No parts uploaded"))?;

    // PII-safety: same rationale as the put_object handler — never persist
    // `session.user_id` (raw JWT sub, may be plaintext email for legacy
    // users). Use the hashed form. See handlers/object.rs:127 for the full
    // explanation; access control is unaffected.
    let mut metadata = ObjectMetadata::new(first_part_cid, total_size, final_etag.clone())
        .with_owner(&session.hashed_user_id);

    if let Some(ct) = upload.content_type {
        metadata = metadata.with_content_type(ct);
    }

    for (k, v) in upload.metadata {
        metadata = metadata.with_user_metadata(k, v);
    }

    // Serialize same-bucket index mutations (see `put_object` rationale).
    // Held across the open → put_object → flush → persist sequence so a
    // concurrent put_object/delete_object/copy_object can't race the
    // multipart completion and drop its index entry.
    let _bucket_guard = state
        .bucket_manager
        .bucket_write_lock(&session.hashed_user_id, &bucket)
        .lock_owned()
        .await;

    // Store in bucket (user-scoped)
    let mut bucket_handle = state.bucket_manager.open_bucket_for_user(&session.hashed_user_id, &bucket).await?;
    bucket_handle.put_object(key.clone(), metadata).await?;
    let bucket_root_cid = bucket_handle.flush().await?;

    // Persist the bucket registry so the new root CID survives restarts
    // Use the user's JWT for pinning service authentication
    if let Err(e) = state.bucket_manager.persist_registry_with_token(&session.jwt_token).await {
        tracing::warn!(error = %e, "Failed to persist bucket registry after complete_multipart_upload");
    }

    // Pin the BUCKET ROOT CID to ensure tree structure survives GC.
    // This recursively pins all tree nodes AND all referenced object data (including parts).
    // NOTE: Pinning is async (fire-and-forget) to avoid blocking the response.
    {
        let block_store = Arc::clone(&state.block_store);
        let pin_bucket = bucket.clone();
        let jwt_token = session.jwt_token.clone();
        tokio::spawn(async move {
            let pin_name = format!("bucket:{}", pin_bucket);
            if let Err(e) = block_store.pin_with_token(&bucket_root_cid, Some(&pin_name), &jwt_token).await {
                tracing::warn!(cid = %bucket_root_cid, error = %e, "Failed to pin bucket root CID");
            } else {
                tracing::info!(cid = %bucket_root_cid, bucket = %pin_name, "Bucket root CID pinned (recursive)");
            }
        });
    }

    // Also pin to user's external pinning service if credentials provided
    // The session JWT is used as the default token if no X-Pinning-Token header is provided
    pin_for_user(&headers, &first_part_cid, Some(&key), state.config.pinning_service_endpoint.as_deref(), Some(&session.jwt_token)).await;

    let location = format!("/{}/{}", bucket, key);
    let xml_response = xml::complete_multipart_upload_result(
        &location,
        &bucket,
        &key,
        &final_etag,
    );

    Ok((
        StatusCode::OK,
        [("Content-Type", "application/xml")],
        xml_response,
    ).into_response())
}

/// DELETE /{bucket}/{key}?uploadId=X - Abort multipart upload
pub async fn abort_multipart_upload(
    State(state): State<Arc<AppState>>,
    Extension(session): Extension<UserSession>,
    Path((bucket, key)): Path<(String, String)>,
    Query(params): Query<MultipartParams>,
) -> Result<Response, ApiError> {
    if !session.can_write() {
        return Err(ApiError::s3(S3ErrorCode::AccessDenied, "Write access required"));
    }

    let upload_id = params.upload_id
        .ok_or_else(|| ApiError::s3(S3ErrorCode::InvalidArgument, "Missing uploadId"))?;

    let upload = state.multipart_manager.abort_upload(&upload_id)
        .ok_or_else(|| ApiError::s3(S3ErrorCode::NoSuchUpload, "Upload not found"))?;

    if upload.bucket != bucket || upload.key != key {
        return Err(ApiError::s3(S3ErrorCode::InvalidArgument, "Bucket/key mismatch"));
    }

    // In a real implementation, we'd also clean up the stored parts

    Ok(StatusCode::NO_CONTENT.into_response())
}

/// GET /{bucket}/{key}?uploadId=X - List parts
pub async fn list_parts(
    State(state): State<Arc<AppState>>,
    Extension(session): Extension<UserSession>,
    Path((bucket, key)): Path<(String, String)>,
    Query(params): Query<MultipartParams>,
) -> Result<Response, ApiError> {
    if !session.can_read() {
        return Err(ApiError::s3(S3ErrorCode::AccessDenied, "Read access required"));
    }

    let upload_id = params.upload_id
        .ok_or_else(|| ApiError::s3(S3ErrorCode::InvalidArgument, "Missing uploadId"))?;

    let parts = state.multipart_manager.list_parts(&upload_id)
        .ok_or_else(|| ApiError::s3(S3ErrorCode::NoSuchUpload, "Upload not found"))?;

    let xml_response = xml::list_parts_result(
        &bucket,
        &key,
        &upload_id,
        &parts,
        false,
        1000,
    );

    Ok((
        StatusCode::OK,
        [("Content-Type", "application/xml")],
        xml_response,
    ).into_response())
}

/// GET /{bucket}?uploads - List multipart uploads
pub async fn list_multipart_uploads(
    State(state): State<Arc<AppState>>,
    Extension(session): Extension<UserSession>,
    Path(bucket): Path<String>,
) -> Result<Response, ApiError> {
    if !session.can_read() {
        return Err(ApiError::s3(S3ErrorCode::AccessDenied, "Read access required"));
    }

    let uploads = state.multipart_manager.list_uploads(&bucket);

    let xml_response = xml::list_multipart_uploads_result(
        &bucket,
        &uploads,
        false,
        1000,
    );

    Ok((
        StatusCode::OK,
        [("Content-Type", "application/xml")],
        xml_response,
    ).into_response())
}
