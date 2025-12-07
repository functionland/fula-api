//! Multipart upload handlers

use crate::{AppState, ApiError, S3ErrorCode};
use crate::state::UserSession;
use crate::multipart::UploadPart;
use crate::xml;
use axum::{
    extract::{Extension, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use bytes::Bytes;
use fula_blockstore::BlockStore;
use fula_core::metadata::ObjectMetadata;
use fula_crypto::hashing::md5_hash;
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

    // Verify bucket exists
    if !state.bucket_manager.bucket_exists(&bucket) {
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

    let upload = state.multipart_manager.create_upload_with_metadata(
        bucket.clone(),
        key.clone(),
        session.user_id.clone(),
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

    // Store part data
    let cid = state.block_store.put_block(&body).await?;
    let etag = md5_hash(&body);

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
    _body: Bytes,
) -> Result<Response, ApiError> {
    if !session.can_write() {
        return Err(ApiError::s3(S3ErrorCode::AccessDenied, "Write access required"));
    }

    let upload_id = params.upload_id
        .ok_or_else(|| ApiError::s3(S3ErrorCode::InvalidArgument, "Missing uploadId"))?;

    // Get the upload
    let upload = state.multipart_manager.complete_upload(&upload_id)
        .ok_or_else(|| ApiError::s3(S3ErrorCode::NoSuchUpload, "Upload not found"))?;

    if upload.bucket != bucket || upload.key != key {
        return Err(ApiError::s3(S3ErrorCode::InvalidArgument, "Bucket/key mismatch"));
    }

    // Calculate final ETag (MD5 of ETags + "-N")
    let part_count = upload.parts.len();
    let mut etag_concat = String::new();
    for part in upload.sorted_parts() {
        etag_concat.push_str(&part.etag);
    }
    let final_etag = format!("{}-{}", md5_hash(etag_concat.as_bytes()), part_count);

    // Calculate total size
    let total_size: u64 = upload.parts.values().map(|p| p.size).sum();

    // Create the final object metadata
    // In a real implementation, we'd create a DAG linking all parts
    let first_part_cid: cid::Cid = upload.parts.values().next()
        .map(|p| p.cid.parse().unwrap())
        .ok_or_else(|| ApiError::s3(S3ErrorCode::InvalidPart, "No parts uploaded"))?;

    let mut metadata = ObjectMetadata::new(first_part_cid, total_size, final_etag.clone())
        .with_owner(&session.user_id);

    if let Some(ct) = upload.content_type {
        metadata = metadata.with_content_type(ct);
    }

    for (k, v) in upload.metadata {
        metadata = metadata.with_user_metadata(k, v);
    }

    // Store in bucket
    let mut bucket_handle = state.bucket_manager.open_bucket(&bucket).await?;
    bucket_handle.put_object(key.clone(), metadata).await?;
    bucket_handle.flush().await?;

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
