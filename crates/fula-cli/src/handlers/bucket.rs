//! Bucket operation handlers

use crate::{AppState, ApiError, S3ErrorCode};
use crate::mcp_scope::McpAction;
use crate::state::UserSession;
use crate::xml;
use axum::{
    extract::{Extension, Path, Query, State},
    response::{IntoResponse, Response},
    http::StatusCode,
};
use fula_core::metadata::Owner;
use serde::Deserialize;
use std::sync::Arc;

/// PUT /{bucket} - Create bucket
pub async fn create_bucket(
    State(state): State<Arc<AppState>>,
    Extension(session): Extension<UserSession>,
    Path(bucket): Path<String>,
) -> Result<Response, ApiError> {
    if !session.can_write() {
        return Err(ApiError::s3(S3ErrorCode::AccessDenied, "Write access required"));
    }
    // P12: a scoped MCP token may only create its own scoped bucket (write perm).
    session.assert_mcp_scope(&bucket, None, McpAction::Write)?;

    // Security audit fix A3: Use hashed user ID for privacy
    let owner = Owner::new(&session.hashed_user_id)
        .with_display_name(session.display_name.clone().unwrap_or_default());

    // User-scoped bucket creation (each user has isolated namespace)
    state.bucket_manager.create_bucket_for_user(
        &session.hashed_user_id,
        bucket.clone(),
        owner,
    ).await?;

    Ok((
        StatusCode::OK,
        [("Location", format!("/{}", bucket))],
        "",
    ).into_response())
}

/// DELETE /{bucket} - Delete bucket
pub async fn delete_bucket(
    State(state): State<Arc<AppState>>,
    Extension(session): Extension<UserSession>,
    Path(bucket): Path<String>,
) -> Result<Response, ApiError> {
    if !session.can_write() {
        return Err(ApiError::s3(S3ErrorCode::AccessDenied, "Write access required"));
    }
    // P12: a scoped MCP token may only delete its own scoped bucket (write perm).
    session.assert_mcp_scope(&bucket, None, McpAction::Write)?;

    // User-scoped bucket deletion (user can only delete their own buckets)
    state.bucket_manager.delete_bucket_for_user(&session.hashed_user_id, &bucket).await?;

    Ok(StatusCode::NO_CONTENT.into_response())
}

/// HEAD /{bucket} - Check if bucket exists
pub async fn head_bucket(
    State(state): State<Arc<AppState>>,
    Extension(session): Extension<UserSession>,
    Path(bucket): Path<String>,
) -> Result<Response, ApiError> {
    // P12: a scoped MCP token may only HEAD its own scoped bucket (read perm).
    // (head_bucket has no can_read gate today; this adds the MCP fence only —
    // storage tokens with mcp_scope == None are unaffected.)
    session.assert_mcp_scope(&bucket, None, McpAction::Read)?;

    // User-scoped bucket check (user can only see their own buckets)
    if !state.bucket_manager.bucket_exists_for_user(&session.hashed_user_id, &bucket) {
        return Err(ApiError::s3(S3ErrorCode::NoSuchBucket, "Bucket not found"));
    }

    Ok(StatusCode::OK.into_response())
}

/// Query parameters for ListObjectsV2
#[derive(Debug, Deserialize)]
pub struct ListObjectsParams {
    #[serde(rename = "list-type")]
    pub list_type: Option<u8>,
    pub prefix: Option<String>,
    pub delimiter: Option<String>,
    #[serde(rename = "max-keys")]
    pub max_keys: Option<usize>,
    #[serde(rename = "continuation-token")]
    pub continuation_token: Option<String>,
    #[serde(rename = "start-after")]
    pub start_after: Option<String>,
    #[serde(rename = "fetch-owner")]
    pub fetch_owner: Option<bool>,
}

/// GET /{bucket} - List objects (ListObjectsV2)
pub async fn list_objects(
    State(state): State<Arc<AppState>>,
    Extension(session): Extension<UserSession>,
    Path(bucket_name): Path<String>,
    Query(params): Query<ListObjectsParams>,
) -> Result<Response, ApiError> {
    if !session.can_read() {
        return Err(ApiError::s3(S3ErrorCode::AccessDenied, "Read access required"));
    }
    // P12: a scoped MCP token may only LIST its own scoped bucket (list perm).
    // Bucket-level op (key=None); listing is confined to the bucket — the
    // results inside are already prefixed `ai/...` for a real MCP workspace.
    session.assert_mcp_scope(&bucket_name, None, McpAction::List)?;

    // User-scoped bucket access (user can only access their own buckets)
    let bucket = state.bucket_manager.open_bucket_for_user(&session.hashed_user_id, &bucket_name).await?;

    let result = bucket.list_objects(
        params.prefix.as_deref(),
        params.delimiter.as_deref(),
        params.start_after.as_deref().or(params.continuation_token.as_deref()),
        params.max_keys,
    ).await?;

    let objects: Vec<_> = result.objects
        .iter()
        .map(|o| (o.key.clone(), &o.metadata))
        .collect();

    let xml_response = xml::list_bucket_result(
        &bucket_name,
        &result.prefix,
        result.delimiter.as_deref(),
        result.max_keys,
        result.is_truncated,
        &objects,
        &result.common_prefixes,
        params.continuation_token.as_deref(),
        result.next_continuation_token.as_deref(),
    );

    Ok((
        StatusCode::OK,
        [("Content-Type", "application/xml")],
        xml_response,
    ).into_response())
}

/// GET /{bucket}?location - Get bucket location
pub async fn get_bucket_location(
    State(state): State<Arc<AppState>>,
    Extension(session): Extension<UserSession>,
    Path(bucket): Path<String>,
) -> Result<Response, ApiError> {
    // User-scoped bucket check
    if !state.bucket_manager.bucket_exists_for_user(&session.hashed_user_id, &bucket) {
        return Err(ApiError::s3(S3ErrorCode::NoSuchBucket, "Bucket not found"));
    }

    let xml_response = r#"<?xml version="1.0" encoding="UTF-8"?>
<LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/"></LocationConstraint>"#;

    Ok((
        StatusCode::OK,
        [("Content-Type", "application/xml")],
        xml_response,
    ).into_response())
}
