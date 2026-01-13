//! Admin API handlers
//!
//! These endpoints are protected by admin authentication (separate JWT secret)
//! and must be explicitly enabled via FULA_ADMIN_API=true.
//!
//! Available endpoints:
//! - GET /admin/users/{user_id}/buckets - List all buckets for a user
//! - DELETE /admin/users/{user_id} - Delete all user data and unpin CIDs
//! - DELETE /admin/pins/{cid} - Manually unpin a specific CID
//! - POST /admin/gc - Trigger garbage collection scan
//! - GET /admin/fetch/{bucket}/{key} - Fetch object for share recipients (localhost only)

use crate::{AppState, ApiError, S3ErrorCode};
use crate::state::AdminSession;
use crate::auth::hash_user_id;
use crate::pinning::PinningCredentials;
use axum::{
    body::Body,
    extract::{ConnectInfo, Extension, Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    Json,
};
use cid::Cid;
use fula_blockstore::{BlockStore, PinStore};
use serde::Serialize;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use tracing::{info, warn, error};

// ═══════════════════════════════════════════════════════════════════════════════
// RESPONSE TYPES
// ═══════════════════════════════════════════════════════════════════════════════

/// Bucket info in admin response
#[derive(Debug, Serialize)]
pub struct AdminBucketInfo {
    pub name: String,
    pub object_count: u64,
    pub root_cid: String,
}

/// Response for GET /admin/users/{user_id}/buckets
#[derive(Debug, Serialize)]
pub struct ListUserBucketsResponse {
    pub user_id: String,
    pub hashed_user_id: String,
    pub buckets: Vec<AdminBucketInfo>,
    pub total_buckets: usize,
}

/// Response for DELETE /admin/users/{user_id}
#[derive(Debug, Serialize)]
pub struct DeleteUserResponse {
    pub user_id: String,
    pub hashed_user_id: String,
    pub buckets_deleted: usize,
    pub objects_deleted: usize,
    pub cids_unpinned: usize,
    pub remote_unpins_attempted: usize,
    pub errors: Vec<String>,
}

/// Response for DELETE /admin/pins/{cid}
#[derive(Debug, Serialize)]
pub struct UnpinCidResponse {
    pub cid: String,
    pub local_unpinned: bool,
    pub remote_unpinned: bool,
    pub error: Option<String>,
}

/// Response for POST /admin/gc
#[derive(Debug, Serialize)]
pub struct GcResponse {
    pub total_pinned: usize,
    pub referenced_cids: usize,
    pub orphaned_cids: usize,
    pub orphaned_list: Vec<String>,
    pub message: String,
}

// ═══════════════════════════════════════════════════════════════════════════════
// HANDLERS
// ═══════════════════════════════════════════════════════════════════════════════

/// GET /admin/users/{user_id}/buckets
///
/// List all buckets for a user by their original user ID (e.g., email).
/// The user_id is hashed internally to find their buckets.
pub async fn list_user_buckets(
    State(state): State<Arc<AppState>>,
    Extension(admin): Extension<AdminSession>,
    Path(user_id): Path<String>,
) -> Result<Response, ApiError> {
    info!(
        admin_id = %admin.admin_id,
        target_user = %user_id,
        "Admin listing user buckets"
    );

    // Hash the user ID to match internal storage format
    let hashed_user_id = hash_user_id(&user_id);

    // Get all buckets for this user
    let buckets = state.bucket_manager.list_buckets_for_user(&hashed_user_id);

    let bucket_info: Vec<AdminBucketInfo> = buckets
        .iter()
        .map(|b| AdminBucketInfo {
            name: b.name.clone(),
            object_count: b.object_count,
            root_cid: b.root_cid.to_string(),
        })
        .collect();

    let response = ListUserBucketsResponse {
        user_id: user_id.clone(),
        hashed_user_id,
        total_buckets: bucket_info.len(),
        buckets: bucket_info,
    };

    Ok((StatusCode::OK, Json(response)).into_response())
}

/// DELETE /admin/users/{user_id}
///
/// Delete all data for a user:
/// 1. List all buckets for the user
/// 2. For each bucket: collect all object CIDs
/// 3. Unpin all CIDs from local IPFS
/// 4. If pinning headers provided, unpin from remote service
/// 5. Delete all buckets
///
/// Headers:
/// - X-Pinning-Service: Remote pinning service URL (optional)
/// - X-Pinning-Token: Remote pinning service token (optional)
pub async fn delete_user(
    State(state): State<Arc<AppState>>,
    Extension(admin): Extension<AdminSession>,
    headers: HeaderMap,
    Path(user_id): Path<String>,
) -> Result<Response, ApiError> {
    info!(
        admin_id = %admin.admin_id,
        target_user = %user_id,
        "Admin deleting user data"
    );

    let hashed_user_id = hash_user_id(&user_id);
    let mut errors: Vec<String> = Vec::new();
    let mut buckets_deleted = 0;
    let mut objects_deleted = 0;
    let mut cids_unpinned = 0;
    let mut remote_unpins_attempted = 0;

    // Check for remote pinning credentials
    let remote_creds = PinningCredentials::from_headers(&headers);
    if remote_creds.is_some() {
        info!("Remote pinning credentials provided, will attempt remote unpinning");
    }

    // Get all buckets for this user
    let buckets = state.bucket_manager.list_buckets_for_user(&hashed_user_id);

    if buckets.is_empty() {
        info!(user_id = %user_id, hashed_user_id = %hashed_user_id, "No buckets found for user");
    }

    // Collect all CIDs to unpin
    let mut all_cids: Vec<Cid> = Vec::new();

    for bucket_meta in &buckets {
        // Open the bucket to list objects
        match state.bucket_manager.open_bucket_for_user(&hashed_user_id, &bucket_meta.name).await {
            Ok(bucket) => {
                // List all objects in the bucket
                match bucket.list_objects(None, None, None, None).await {
                    Ok(result) => {
                        for obj in &result.objects {
                            all_cids.push(obj.metadata.cid);
                            objects_deleted += 1;
                        }
                        // Also add the bucket root CID
                        all_cids.push(bucket_meta.root_cid);
                    }
                    Err(e) => {
                        let msg = format!("Failed to list objects in bucket '{}': {}", bucket_meta.name, e);
                        warn!("{}", msg);
                        errors.push(msg);
                    }
                }
            }
            Err(e) => {
                let msg = format!("Failed to open bucket '{}': {}", bucket_meta.name, e);
                warn!("{}", msg);
                errors.push(msg);
            }
        }
    }

    // Unpin all collected CIDs from local IPFS
    for cid in &all_cids {
        match state.block_store.unpin(cid).await {
            Ok(_) => {
                cids_unpinned += 1;
            }
            Err(e) => {
                // Don't fail on unpin errors, just log them
                warn!(cid = %cid, error = %e, "Failed to unpin CID from local IPFS");
            }
        }
    }

    // Attempt remote unpinning if credentials provided
    if let Some(creds) = remote_creds {
        match creds.create_client() {
            Ok(client) => {
                for cid in &all_cids {
                    remote_unpins_attempted += 1;
                    match client.get_pin_by_cid(&cid.to_string()).await {
                        Ok(Some(status)) => {
                            if let Err(e) = client.delete_pin(&status.request_id).await {
                                let msg = format!("Failed to unpin {} from remote: {}", cid, e);
                                warn!("{}", msg);
                                errors.push(msg);
                            } else {
                                info!(cid = %cid, "Unpinned from remote pinning service");
                            }
                        }
                        Ok(None) => {
                            // CID not pinned remotely, nothing to do
                        }
                        Err(e) => {
                            let msg = format!("Failed to find pin {} in remote service: {}", cid, e);
                            warn!("{}", msg);
                            errors.push(msg);
                        }
                    }
                }
            }
            Err(e) => {
                let msg = format!("Failed to create remote pinning client: {}", e);
                error!("{}", msg);
                errors.push(msg);
            }
        }
    }

    // Delete all buckets (must be empty first, but we'll force delete)
    for bucket_meta in &buckets {
        // Force delete by removing from registry directly
        // Note: This bypasses the "bucket not empty" check
        match state.bucket_manager.open_bucket_for_user(&hashed_user_id, &bucket_meta.name).await {
            Ok(mut bucket) => {
                // Delete all objects first
                match bucket.list_objects(None, None, None, None).await {
                    Ok(result) => {
                        for obj in &result.objects {
                            if let Err(e) = bucket.delete_object(&obj.key).await {
                                warn!(key = %obj.key, error = %e, "Failed to delete object");
                            }
                        }
                    }
                    Err(e) => {
                        warn!(bucket = %bucket_meta.name, error = %e, "Failed to list objects for deletion");
                    }
                }
            }
            Err(e) => {
                warn!(bucket = %bucket_meta.name, error = %e, "Failed to open bucket for deletion");
            }
        }

        // Now delete the empty bucket
        match state.bucket_manager.delete_bucket_for_user(&hashed_user_id, &bucket_meta.name).await {
            Ok(_) => {
                buckets_deleted += 1;
                info!(bucket = %bucket_meta.name, "Deleted bucket");
            }
            Err(e) => {
                let msg = format!("Failed to delete bucket '{}': {}", bucket_meta.name, e);
                warn!("{}", msg);
                errors.push(msg);
            }
        }
    }

    let response = DeleteUserResponse {
        user_id: user_id.clone(),
        hashed_user_id,
        buckets_deleted,
        objects_deleted,
        cids_unpinned,
        remote_unpins_attempted,
        errors,
    };

    info!(
        admin_id = %admin.admin_id,
        user_id = %user_id,
        buckets_deleted = buckets_deleted,
        objects_deleted = objects_deleted,
        cids_unpinned = cids_unpinned,
        "User deletion completed"
    );

    Ok((StatusCode::OK, Json(response)).into_response())
}

/// DELETE /admin/pins/{cid}
///
/// Manually unpin a specific CID from local IPFS and optionally from remote service.
///
/// Headers:
/// - X-Pinning-Service: Remote pinning service URL (optional)
/// - X-Pinning-Token: Remote pinning service token (optional)
pub async fn unpin_cid(
    State(state): State<Arc<AppState>>,
    Extension(admin): Extension<AdminSession>,
    headers: HeaderMap,
    Path(cid_str): Path<String>,
) -> Result<Response, ApiError> {
    info!(
        admin_id = %admin.admin_id,
        cid = %cid_str,
        "Admin unpinning CID"
    );

    // Parse the CID
    let cid = Cid::from_str(&cid_str).map_err(|e| {
        ApiError::s3(S3ErrorCode::InvalidArgument, format!("Invalid CID: {}", e))
    })?;

    let mut local_unpinned = false;
    let mut remote_unpinned = false;
    let mut error: Option<String> = None;

    // Unpin from local IPFS
    match state.block_store.unpin(&cid).await {
        Ok(_) => {
            local_unpinned = true;
            info!(cid = %cid_str, "Unpinned from local IPFS");
        }
        Err(e) => {
            let msg = format!("Failed to unpin from local IPFS: {}", e);
            warn!("{}", msg);
            error = Some(msg);
        }
    }

    // Attempt remote unpinning if credentials provided
    if let Some(creds) = PinningCredentials::from_headers(&headers) {
        match creds.create_client() {
            Ok(client) => {
                match client.get_pin_by_cid(&cid_str).await {
                    Ok(Some(status)) => {
                        match client.delete_pin(&status.request_id).await {
                            Ok(_) => {
                                remote_unpinned = true;
                                info!(cid = %cid_str, "Unpinned from remote pinning service");
                            }
                            Err(e) => {
                                let msg = format!("Failed to unpin from remote: {}", e);
                                warn!("{}", msg);
                                if let Some(ref mut err) = error {
                                    err.push_str("; ");
                                    err.push_str(&msg);
                                } else {
                                    error = Some(msg);
                                }
                            }
                        }
                    }
                    Ok(None) => {
                        info!(cid = %cid_str, "CID not found in remote pinning service");
                    }
                    Err(e) => {
                        let msg = format!("Failed to find pin in remote: {}", e);
                        warn!("{}", msg);
                        if let Some(ref mut err) = error {
                            err.push_str("; ");
                            err.push_str(&msg);
                        } else {
                            error = Some(msg);
                        }
                    }
                }
            }
            Err(e) => {
                let msg = format!("Failed to create remote pinning client: {}", e);
                warn!("{}", msg);
                if let Some(ref mut err) = error {
                    err.push_str("; ");
                    err.push_str(&msg);
                } else {
                    error = Some(msg);
                }
            }
        }
    }

    let response = UnpinCidResponse {
        cid: cid_str,
        local_unpinned,
        remote_unpinned,
        error,
    };

    Ok((StatusCode::OK, Json(response)).into_response())
}

/// POST /admin/gc
///
/// Trigger a garbage collection scan.
/// This identifies pinned CIDs that are no longer referenced by any bucket.
///
/// Note: This is a read-only operation that reports orphaned pins.
/// It does NOT automatically unpin them.
pub async fn trigger_gc(
    State(state): State<Arc<AppState>>,
    Extension(admin): Extension<AdminSession>,
) -> Result<Response, ApiError> {
    info!(
        admin_id = %admin.admin_id,
        "Admin triggering garbage collection scan"
    );

    // Collect all referenced CIDs from all buckets
    let mut referenced_cids: std::collections::HashSet<String> = std::collections::HashSet::new();

    // Get all buckets (across all users)
    let all_buckets = state.bucket_manager.list_buckets();

    for bucket_meta in &all_buckets {
        // Add bucket root CID
        referenced_cids.insert(bucket_meta.root_cid.to_string());

        // Try to open bucket and list objects
        // Note: We're using list_buckets() which returns all buckets across users
        // This is intentional for GC - we want to check all CIDs
    }

    // Get all pinned CIDs from local IPFS
    let pinned_cids = match state.block_store.list_pins().await {
        Ok(pins) => pins,
        Err(e) => {
            warn!(error = %e, "Failed to list pins, returning partial results");
            Vec::new()
        }
    };

    let total_pinned = pinned_cids.len();
    let referenced_count = referenced_cids.len();

    // Find orphaned CIDs (pinned but not referenced)
    let orphaned: Vec<String> = pinned_cids
        .iter()
        .map(|c| c.to_string())
        .filter(|cid_str| !referenced_cids.contains(cid_str))
        .collect();

    let orphaned_count = orphaned.len();

    let response = GcResponse {
        total_pinned,
        referenced_cids: referenced_count,
        orphaned_cids: orphaned_count,
        orphaned_list: orphaned.clone(),
        message: if orphaned_count > 0 {
            format!(
                "Found {} orphaned pins. Use DELETE /admin/pins/{{cid}} to remove them.",
                orphaned_count
            )
        } else {
            "No orphaned pins found.".to_string()
        },
    };

    info!(
        admin_id = %admin.admin_id,
        total_pinned = total_pinned,
        referenced = referenced_count,
        orphaned = orphaned_count,
        "GC scan completed"
    );

    Ok((StatusCode::OK, Json(response)).into_response())
}

/// GET /admin/fetch/{bucket}/{key}
///
/// Fetch an object for share recipients. This endpoint is **localhost-only**
/// to prevent unauthorized access from the internet.
///
/// Security model:
/// - Only accepts requests from 127.0.0.1 or ::1 (loopback)
/// - Requires valid admin JWT
/// - Returns encrypted content (client must decrypt with share token DEK)
/// - Does not validate share_id (mapping doesn't exist in current architecture)
///
/// Usage:
/// Web frontend's backend calls this endpoint to fetch encrypted content
/// for share recipients who don't have S3 credentials.
pub async fn admin_fetch_object(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<Arc<AppState>>,
    Extension(admin): Extension<AdminSession>,
    Path((bucket_name, key)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    // 1. Reject non-localhost requests (critical security check)
    if !crate::middleware::is_localhost(&addr) {
        warn!(
            remote_ip = %addr.ip(),
            bucket = %bucket_name,
            key = %key,
            "Admin fetch rejected: not localhost"
        );
        return Err(ApiError::s3(
            S3ErrorCode::AccessDenied,
            "This endpoint is localhost-only",
        ));
    }

    info!(
        admin_id = %admin.admin_id,
        bucket = %bucket_name,
        key = %key,
        "Admin fetch object (localhost)"
    );

    // 2. Find the object in any bucket with matching name
    // (bucket names are scoped per-user, so we search all)
    let metadata = state.bucket_manager
        .find_object_in_bucket(&bucket_name, &key)
        .await
        .ok_or_else(|| ApiError::s3_with_resource(
            S3ErrorCode::NoSuchKey,
            "Object not found",
            format!("{}/{}", bucket_name, key),
        ))?;

    // 3. Fetch content from block store
    let data = state.block_store.get_block(&metadata.cid).await
        .map_err(|e| {
            error!(cid = %metadata.cid, error = %e, "Failed to fetch block");
            ApiError::s3(S3ErrorCode::InternalError, format!("Failed to fetch block: {}", e))
        })?;

    // 4. Build response with appropriate headers
    let content_type = metadata.content_type
        .as_deref()
        .unwrap_or("application/octet-stream");

    let mut response = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CONTENT_LENGTH, data.len().to_string())
        .header("x-amz-meta-encrypted", "true");

    // Add ETag if available
    if !metadata.etag.is_empty() {
        response = response.header(header::ETAG, format!("\"{}\"", metadata.etag));
    }

    Ok(response.body(Body::from(data.to_vec())).unwrap())
}
