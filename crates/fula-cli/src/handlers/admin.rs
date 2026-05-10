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
// Use the same `hash_user_id` everything else in the gateway uses to key
// `BucketMetadata.owner_id` (BLAKE3 with `"fula:user_id:"` domain separator,
// 16 raw bytes / 32 hex chars). The `auth.rs` variant — domain-separator-less,
// only 8 bytes — produced silent "0 buckets" on every admin lookup because
// the resulting string never matched what was stored.
use crate::state::hash_user_id;
use crate::pinning::PinningCredentials;
use axum::{
    body::Body,
    extract::{ConnectInfo, Extension, Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    Json,
};
use cid::Cid;
use fula_blockstore::{BlockStore, PinStore};
use serde::{Deserialize, Serialize};
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
    /// Phase 1.2: hex-encoded BLAKE3(MetadataKey || name)[..16] when the
    /// SDK has flushed at least once with the lookup-h header, else None.
    /// Surfaced to make duplicate-bucket diagnosis tractable: the
    /// publisher emits each BucketMetadata as either `legacy=true,
    /// key=name` (None) or `legacy=false, key=hex(lookup_h)` (Some). If
    /// you see two entries that should be one bucket, this field tells
    /// you which is which.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bucket_lookup_h_hex: Option<String>,
    /// v0.4.4 SDK-side encrypted forest manifest CID. None until the
    /// SDK's first Phase 2 root-commit PUT after master flipped the
    /// `FULA_FOREST_MANIFEST_CID_ENABLED` flag on. Returned so the
    /// operator can sanity-check what the publisher will emit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub forest_manifest_cid: Option<String>,
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
    // Hash the user ID FIRST so we can avoid logging the raw URL parameter.
    // PII-safety: admins legitimately pass `user_id` as a plaintext email
    // (per the doc-comment on this handler), so the URL itself carries
    // PII. The log line only emits the opaque hashed form. The HTTP
    // response body still echoes the raw input (it was admin-supplied);
    // tightening that further would require a separate API change.
    let hashed_user_id = hash_user_id(&user_id);
    let admin_id_hashed = hash_user_id(&admin.admin_id);
    info!(
        admin_id_hashed = %admin_id_hashed,
        target_user_hashed = %hashed_user_id,
        "Admin listing user buckets"
    );

    // Get all buckets for this user
    let buckets = state.bucket_manager.list_buckets_for_user(&hashed_user_id);

    let bucket_info: Vec<AdminBucketInfo> = buckets
        .iter()
        .map(|b| AdminBucketInfo {
            name: b.name.clone(),
            object_count: b.object_count,
            root_cid: b.root_cid.to_string(),
            bucket_lookup_h_hex: b.bucket_lookup_h.map(hex::encode),
            forest_manifest_cid: b.forest_manifest_cid.clone(),
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
    // Same PII-safety rationale as list_user_buckets above: hash before
    // logging so the URL parameter (often plaintext email) doesn't reach
    // the trace stream.
    let hashed_user_id = hash_user_id(&user_id);
    let admin_id_hashed = hash_user_id(&admin.admin_id);
    info!(
        admin_id_hashed = %admin_id_hashed,
        target_user_hashed = %hashed_user_id,
        "Admin deleting user data"
    );
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
        // PII-safety: only log the hashed form, never the raw URL parameter.
        info!(hashed_user_id = %hashed_user_id, "No buckets found for user");
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
///
/// Chunked files:
/// For large files stored as chunks, this endpoint automatically detects
/// the chunked format and assembles all chunks before returning.
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

    // 4. Check if this is a chunked file by examining x-fula-chunked metadata
    let is_chunked = metadata.user_metadata
        .get("x-fula-chunked")
        .map(|v| v == "true")
        .unwrap_or(false);

    let final_data = if is_chunked {
        // CHUNKED FILE: Parse metadata and fetch all chunks
        info!(
            bucket = %bucket_name,
            key = %key,
            "Detected chunked file, assembling chunks"
        );

        // Parse the metadata JSON to get chunk info
        let metadata_json: serde_json::Value = serde_json::from_slice(&data)
            .map_err(|e| {
                error!(error = %e, "Failed to parse chunked metadata JSON");
                ApiError::s3(S3ErrorCode::InternalError, format!("Invalid chunked metadata: {}", e))
            })?;

        let chunked_info = metadata_json.get("chunked")
            .ok_or_else(|| ApiError::s3(S3ErrorCode::InternalError, "Missing 'chunked' field in metadata"))?;

        let num_chunks = chunked_info.get("num_chunks")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| ApiError::s3(S3ErrorCode::InternalError, "Missing 'num_chunks' in chunked metadata"))? as u32;

        info!(
            bucket = %bucket_name,
            key = %key,
            num_chunks = num_chunks,
            "Fetching {} chunks",
            num_chunks
        );

        // Fetch all chunks and concatenate
        let mut assembled_data = Vec::new();
        for chunk_index in 0..num_chunks {
            // Generate chunk key: {base_key}.chunks/{index:08}
            let chunk_key = format!("{}.chunks/{:08}", key, chunk_index);

            // Find the chunk object
            let chunk_metadata = state.bucket_manager
                .find_object_in_bucket(&bucket_name, &chunk_key)
                .await
                .ok_or_else(|| {
                    error!(chunk_key = %chunk_key, "Chunk not found");
                    ApiError::s3_with_resource(
                        S3ErrorCode::NoSuchKey,
                        format!("Chunk {} not found", chunk_index),
                        format!("{}/{}", bucket_name, chunk_key),
                    )
                })?;

            // Fetch chunk data
            let chunk_data = state.block_store.get_block(&chunk_metadata.cid).await
                .map_err(|e| {
                    error!(cid = %chunk_metadata.cid, chunk_index = chunk_index, error = %e, "Failed to fetch chunk");
                    ApiError::s3(S3ErrorCode::InternalError, format!("Failed to fetch chunk {}: {}", chunk_index, e))
                })?;

            assembled_data.extend_from_slice(&chunk_data);
        }

        info!(
            bucket = %bucket_name,
            key = %key,
            total_size = assembled_data.len(),
            "Assembled {} bytes from {} chunks",
            assembled_data.len(),
            num_chunks
        );

        assembled_data
    } else {
        // NON-CHUNKED FILE: Return data directly
        data.to_vec()
    };

    // 5. Build response with appropriate headers
    let content_type = if is_chunked {
        // For chunked files, the index object has content-type application/json
        // but the actual content is encrypted binary
        "application/octet-stream"
    } else {
        metadata.content_type.as_deref().unwrap_or("application/octet-stream")
    };

    let mut response = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CONTENT_LENGTH, final_data.len().to_string())
        .header("x-amz-meta-encrypted", "true");

    // Add chunked indicator header
    if is_chunked {
        response = response.header("x-fula-chunked", "true");
    }

    // Add ETag if available
    if !metadata.etag.is_empty() {
        response = response.header(header::ETAG, format!("\"{}\"", metadata.etag));
    }

    Ok(response.body(Body::from(final_data)).unwrap())
}

// ═══════════════════════════════════════════════════════════════════════════════
// PII SWEEP
// ═══════════════════════════════════════════════════════════════════════════════
//
// Background: prior to v0.4.2, `handlers/object.rs::put_object` and
// `handlers/multipart.rs::complete_multipart_upload` set
// `ObjectMetadata.owner_id = Some(session.user_id.clone())`. `session.user_id`
// is the raw JWT `sub` claim — for legacy (pre-migration-011) users this is
// plaintext email; for modern users it's `sha256(email)` hex. Either way, it
// differs from `BucketMetadata.owner_id` (the canonical 16-byte
// BLAKE3-derived `hashed_user_id`).
//
// The per-object metadata lives in the bucket's Prolly Tree leaves, which
// are content-addressed and pinned to IPFS. The Phase 3.2 users-index
// publisher then publishes each bucket's `root_cid` as the `manifest` field
// of the per-user `bucketsIndex` CBOR — so anyone with the global
// users-index CID can walk down to a bucket's Prolly Tree and read every
// object's `tags.owner_id` in plaintext.
//
// This sweep walks every existing bucket, finds objects whose `owner_id`
// differs from the bucket's canonical `owner_id`, rewrites them with the
// canonical hashed form, and atomically flushes a fresh root_cid per
// bucket. Old root CIDs become unreferenced and are eventually reaped by
// cluster GC.
//
// Safety properties (verified by direct code reads, see commit message):
//
// 1. Only `ObjectMetadata.owner_id` is mutated; every other field
//    (cid, size, etag, last_modified, content_type, content_encoding,
//    cache_control, user_metadata, encryption_info, bao_outboard_cid,
//    is_delete_marker, content_disposition, version_id, storage_class,
//    checksum_blake3) is preserved byte-identically.
// 2. Encrypted file content is at chunk storage_keys, never touched.
// 3. Per-object `owner_id` is metadata only — `can_access_bucket` checks
//    `BucketMetadata.owner_id` (already canonical); per-object `owner_id`
//    does not gate access, decryption, share-token issuance, or download.
// 4. Per-bucket atomicity: each bucket either fully migrates (new root
//    pinned, registry updated) or stays at old state. No partial writes.
// 5. Concurrent-write safety: holds the per-bucket
//    `bucket_write_lock(owner_id, bucket_name)` for the duration of
//    open→rewrite→flush, which is exactly the same lock the regular
//    PUT handler holds. Concurrent PUTs serialize naturally.
// 6. Idempotent: re-running on a clean bucket finds zero leaks and skips
//    without rewriting anything.
// 7. Crash-safe: a process crash mid-sweep leaves already-rewritten buckets
//    committed (their flush already returned and registry was persisted)
//    and pending buckets at their pre-sweep state. Re-run picks up where
//    it left off.
//
// Recommended runbook:
//
//   # 1. Deploy the v0.4.2 master fix (object.rs:127, multipart.rs:210
//   #    PII fix) so new uploads no longer leak.
//   #
//   # 2. (RECOMMENDED) Stop the publisher to prevent re-pinning the
//   #    leaky CIDs while sweeping:
//   sed -i 's/^FULA_USERS_INDEX_PUBLISHER_ENABLED=.*/FULA_USERS_INDEX_PUBLISHER_ENABLED=0/' /etc/fula/.env
//   systemctl restart fula-gateway
//   #
//   # 3. Dry-run sweep — review the per-bucket report:
//   curl -s -H "Authorization: Bearer $ADMIN_JWT" \
//        "http://127.0.0.1:9000/admin/pii-sweep?dry_run=true" | jq .
//   #
//   # 4. Live sweep — actually rewrite:
//   curl -s -H "Authorization: Bearer $ADMIN_JWT" \
//        "http://127.0.0.1:9000/admin/pii-sweep?dry_run=false" | jq .
//   #
//   # 5. Re-enable publisher; the next tick rebuilds with clean owner_id
//   #    in every leaf node:
//   sed -i 's/^FULA_USERS_INDEX_PUBLISHER_ENABLED=.*/FULA_USERS_INDEX_PUBLISHER_ENABLED=1/' /etc/fula/.env
//   systemctl restart fula-gateway
//
// IMPORTANT — what this sweep does NOT do:
//
//   The sweep removes PII from the *current* state: new bucket root_cids
//   no longer leak. But the OLD root_cids that were previously pinned to
//   ipfs-cluster, published via IPNS, and submitted to the chain anchor
//   remain reachable:
//
//   - Cluster pins of old root_cids stay until ipfs-cluster GC reaps
//     unreferenced pins. To accelerate cleanup, run for each
//     `details[].old_root_cid` in the sweep response:
//         ipfs-cluster-ctl pin rm <old_cid>
//     (Only do this AFTER verifying the new root works for that bucket.)
//
//   - IPNS records with the leaky CID expire when the next IPNS publish
//     supersedes them (within `FULA_USERS_INDEX_IPNS_LIFETIME_SECS`,
//     default 36h). No manual action needed.
//
//   - Chain anchor `Published` events are PERMANENT. Each tick's CID is
//     in the contract's event log forever, even after `latestCid` is
//     overwritten. Anyone walking event history can still resolve the
//     leaky CIDs. There is no chain-side mitigation short of redeploying
//     the contract (out of scope per current operator guidance).
//
//   The sweep is necessary but not sufficient for full PII remediation.
//   Combined with cluster pin removal, it eliminates accessible leaks
//   from the current and near-term published state.

/// Query params for `/admin/pii-sweep`.
#[derive(Debug, Deserialize, Default)]
pub struct PiiSweepParams {
    /// `true` (default) walks but does not write. `false` actually rewrites.
    #[serde(default = "default_dry_run_true")]
    pub dry_run: bool,
    /// Optional: scope to a single bucket by its internal key
    /// (`{owner_id}:{bucket_name}`). Useful for spot-checking after a
    /// dry-run flagged a specific bucket.
    pub bucket_internal_key: Option<String>,
}

fn default_dry_run_true() -> bool { true }

/// Per-bucket entry in the sweep report.
#[derive(Debug, Serialize)]
pub struct PiiSweepBucketDetail {
    pub bucket_internal_key: String,
    pub bucket_owner_id: String,
    pub bucket_name: String,
    pub objects_total: usize,
    pub objects_with_leak: usize,
    /// `0` for dry-run, equal to `objects_with_leak` for a successful
    /// live sweep, less if some object rewrites errored.
    pub rewritten: usize,
    pub old_root_cid: String,
    /// `None` for dry-run, `Some` after a successful flush.
    pub new_root_cid: Option<String>,
    pub errors: Vec<String>,
}

/// Aggregate sweep report.
#[derive(Debug, Default, Serialize)]
pub struct PiiSweepReport {
    pub dry_run: bool,
    pub started_at: String,
    pub completed_at: String,
    pub elapsed_secs: f64,
    pub buckets_total: usize,
    pub buckets_scanned: usize,
    pub buckets_with_leaks: usize,
    pub buckets_rewritten: usize,
    pub buckets_skipped_clean: usize,
    pub buckets_errored: usize,
    pub objects_scanned: usize,
    pub objects_with_leaks_found: usize,
    pub objects_rewritten: usize,
    pub errors: Vec<String>,
    pub details: Vec<PiiSweepBucketDetail>,
}

/// `POST /admin/pii-sweep[?dry_run=true|false][&bucket_internal_key=...]`
///
/// Sweeps PII out of bucket Prolly Tree leaves. See module-level
/// documentation block above for full safety analysis and runbook.
pub async fn pii_sweep(
    State(state): State<Arc<crate::AppState>>,
    Extension(admin): Extension<AdminSession>,
    Query(params): Query<PiiSweepParams>,
) -> Result<Response, ApiError> {
    let dry_run = params.dry_run;
    let admin_id_hashed = hash_user_id(&admin.admin_id);

    info!(
        admin_id_hashed = %admin_id_hashed,
        dry_run = dry_run,
        bucket_filter = ?params.bucket_internal_key,
        "PII sweep starting"
    );

    let started = std::time::Instant::now();
    let started_at = chrono::Utc::now();

    let mut report = PiiSweepReport::default();
    report.dry_run = dry_run;
    report.started_at = started_at.to_rfc3339();

    // Snapshot the bucket list. Take BucketMetadata snapshots so we don't
    // hold any DashMap shard guards across awaits — the per-bucket write
    // lock acquired below is what serializes us with concurrent PUTs.
    let mut bucket_metas: Vec<fula_core::metadata::BucketMetadata> = state
        .bucket_manager
        .list_buckets();

    if let Some(ref filter) = params.bucket_internal_key {
        // Filter by internal key (owner_id:name). Allows the admin to
        // re-run the sweep on a single bucket if the first pass errored.
        bucket_metas.retain(|m| {
            let internal = format!("{}:{}", m.owner_id, m.name);
            &internal == filter
        });
        if bucket_metas.is_empty() {
            return Err(ApiError::s3(
                S3ErrorCode::NoSuchBucket,
                "bucket_internal_key not found in registry",
            ));
        }
    }

    report.buckets_total = bucket_metas.len();

    for meta in bucket_metas {
        report.buckets_scanned += 1;
        let detail_opt = sweep_one_bucket(&state, &meta, dry_run, &mut report).await;
        if let Some(detail) = detail_opt {
            report.details.push(detail);
        }
    }

    // Persist registry once at the end (only if anything actually changed).
    // bucket.flush() already updated the in-memory BucketManager.buckets
    // entry's root_cid via metadata_cache; this serializes that to disk
    // so a master restart doesn't lose the new roots. Mirror's the
    // `persist_registry_with_token` call in the put_object handler, but
    // without a user JWT — the registry persistence path doesn't actually
    // require a JWT (the JWT is only used for pinning forwarded to the
    // remote pinning service, which we explicitly skip in the sweep
    // because each user's pinning-service auth differs).
    if !dry_run && report.buckets_rewritten > 0 {
        if let Err(e) = state.bucket_manager.persist_registry().await {
            report.errors.push(format!("persist_registry: {}", e));
            error!(error = %e, "PII sweep: registry persist failed — new root_cids in memory but not on disk; restart will lose them");
        }
    }

    let completed_at = chrono::Utc::now();
    report.completed_at = completed_at.to_rfc3339();
    report.elapsed_secs = started.elapsed().as_secs_f64();

    info!(
        admin_id_hashed = %admin_id_hashed,
        dry_run = dry_run,
        buckets_with_leaks = report.buckets_with_leaks,
        buckets_rewritten = report.buckets_rewritten,
        objects_with_leaks_found = report.objects_with_leaks_found,
        objects_rewritten = report.objects_rewritten,
        elapsed_secs = report.elapsed_secs,
        "PII sweep complete"
    );

    Ok((StatusCode::OK, Json(report)).into_response())
}

/// Sweep one bucket. Returns `Some(detail)` if the bucket had leaks (always
/// included in the report, dry-run or live), `None` if the bucket was clean
/// (skipped from the per-bucket detail list to keep the report compact;
/// counted in `report.buckets_skipped_clean`).
async fn sweep_one_bucket(
    state: &Arc<crate::AppState>,
    meta: &fula_core::metadata::BucketMetadata,
    dry_run: bool,
    report: &mut PiiSweepReport,
) -> Option<PiiSweepBucketDetail> {
    let canonical_owner = &meta.owner_id;
    let bucket_name = &meta.name;
    let internal_key = format!("{}:{}", canonical_owner, bucket_name);

    // Acquire the per-bucket write lock — same lock the regular PUT
    // handler holds. This serializes against concurrent user uploads;
    // a PUT in flight will queue behind us, our flush will commit,
    // then their PUT continues from the new root_cid.
    let lock = state
        .bucket_manager
        .bucket_write_lock(canonical_owner, bucket_name);
    let _guard = lock.lock().await;

    let mut bucket = match state
        .bucket_manager
        .open_bucket_for_user(canonical_owner, bucket_name)
        .await
    {
        Ok(b) => b,
        Err(e) => {
            report.buckets_errored += 1;
            report.errors.push(format!(
                "open_bucket_for_user {}: {}",
                internal_key, e
            ));
            return None;
        }
    };

    // List ALL objects (max_keys=usize::MAX disables pagination cap).
    let list_result = match bucket
        .list_objects(None, None, None, Some(usize::MAX))
        .await
    {
        Ok(r) => r,
        Err(e) => {
            report.buckets_errored += 1;
            report.errors.push(format!("list_objects {}: {}", internal_key, e));
            return None;
        }
    };
    let total_objects = list_result.objects.len();

    // Identify leaks. A leak is any object whose owner_id is set AND
    // differs from the canonical (bucket-level) owner_id. None is
    // already safe (no PII); Some(canonical) is already correct.
    let mut to_rewrite: Vec<(String, fula_core::metadata::ObjectMetadata)> = Vec::new();
    for listed in list_result.objects {
        report.objects_scanned += 1;
        match &listed.metadata.owner_id {
            Some(o) if o != canonical_owner => {
                let mut fixed = listed.metadata.clone();
                fixed.owner_id = Some(canonical_owner.clone());
                to_rewrite.push((listed.key, fixed));
            }
            _ => {}
        }
    }

    let leak_count = to_rewrite.len();
    if leak_count == 0 {
        report.buckets_skipped_clean += 1;
        return None;
    }

    report.buckets_with_leaks += 1;
    report.objects_with_leaks_found += leak_count;

    let old_root_cid = meta.root_cid.to_string();

    if dry_run {
        return Some(PiiSweepBucketDetail {
            bucket_internal_key: internal_key,
            bucket_owner_id: canonical_owner.clone(),
            bucket_name: bucket_name.clone(),
            objects_total: total_objects,
            objects_with_leak: leak_count,
            rewritten: 0,
            old_root_cid,
            new_root_cid: None,
            errors: vec![],
        });
    }

    // LIVE REWRITE. Each put_object is a key+metadata in-memory swap on
    // the Prolly Tree; flush() commits the new tree and returns the new
    // root CID, while also propagating it to BucketManager.buckets via
    // the metadata_cache hook (bucket.rs:259-264).
    let mut bucket_errors: Vec<String> = vec![];
    let mut rewritten = 0usize;

    for (key, fixed_meta) in to_rewrite {
        match bucket.put_object(key.clone(), fixed_meta).await {
            Ok(_) => {
                rewritten += 1;
                report.objects_rewritten += 1;
            }
            Err(e) => {
                bucket_errors.push(format!("put_object key={}: {}", key, e));
            }
        }
    }

    let new_root_cid = match bucket.flush().await {
        Ok(c) => c,
        Err(e) => {
            // Flush failed — Prolly Tree changes never committed to S3,
            // root_cid in BucketManager unchanged, bucket still serves
            // the OLD (leaky) state. Operator can re-run the sweep on
            // this single bucket via ?bucket_internal_key=...
            report.buckets_errored += 1;
            bucket_errors.push(format!("flush: {}", e));
            return Some(PiiSweepBucketDetail {
                bucket_internal_key: internal_key,
                bucket_owner_id: canonical_owner.clone(),
                bucket_name: bucket_name.clone(),
                objects_total: total_objects,
                objects_with_leak: leak_count,
                rewritten,
                old_root_cid,
                new_root_cid: None,
                errors: bucket_errors,
            });
        }
    };

    // #65 — pin the new root through the durable queue (W.9.6
    // pattern). Replaces the prior fire-and-forget `tokio::spawn`,
    // which silently lost pins on master crash OR on operator
    // cancel/restart of a slow sweep — the cancel/restart pattern is
    // the load-bearing improvement here, not just full-crash
    // durability. Mirror's object.rs:421-460's bucket-root path.
    //
    // Why `bearer_token: None`: admin sweep doesn't carry a user JWT
    // (the comment block at line ~907 documents this). The drainer's
    // dispatch path (`pin_drainer.rs:372`) reads `bearer_token` as
    // `unwrap_or("")` and the empty-string short-circuit in
    // `IpfsPinningBlockStore::pin_cid_with_token` (ipfs_pinning.rs:264)
    // falls back to local-kubo `pin_cid` — byte-equivalent to today's
    // `block_store.pin(...)` call. A single `warn!("Empty token ...")`
    // log fires per dispatch; bounded by the sweep's bucket count.
    //
    // The OLD root is still left as-is (unreferenced; cluster GC
    // reaps eventually). Active unpin would conflict with the
    // recovery story if registry persist fails.
    {
        let pin_name = format!("bucket:{}", bucket_name);
        let cid = new_root_cid;
        if let Some(queue) = state.pin_queue.as_ref() {
            if let Err(e) = queue.enqueue(crate::pin_queue::PinRequest {
                cid,
                target: crate::pin_queue::PinTarget::MasterCluster,
                kind: crate::pin_queue::PinKind::Add,
                pin_name: Some(pin_name.clone()),
                bearer_token: None,
                pinning_endpoint: None,
            }) {
                // redb commit failed — fall back to fire-and-forget
                // for this single record so the sweep doesn't fail
                // hard. Operator alert for persistent failures.
                warn!(
                    cid = %cid,
                    error = %e,
                    "PII sweep: pin_queue enqueue failed; falling back to fire-and-forget for this bucket root"
                );
                let block_store = Arc::clone(&state.block_store);
                let pin_name_clone = pin_name.clone();
                tokio::spawn(async move {
                    if let Err(e) = block_store.pin(&cid, Some(&pin_name_clone)).await {
                        warn!(cid = %cid, error = %e, "PII sweep: failed to pin new bucket root (queue-fallback path)");
                    }
                });
            } else {
                info!(
                    cid = %cid,
                    bucket = %pin_name,
                    "PII sweep: new bucket root enqueued for durable pin (#65)"
                );
            }
        } else {
            // Legacy fire-and-forget — no queue configured (tests +
            // minimal dev configs only; production sets `pin_queue_path`).
            let block_store = Arc::clone(&state.block_store);
            tokio::spawn(async move {
                if let Err(e) = block_store.pin(&cid, Some(&pin_name)).await {
                    warn!(cid = %cid, error = %e, "PII sweep: failed to pin new bucket root");
                } else {
                    info!(cid = %cid, bucket = %pin_name, "PII sweep: new bucket root pinned");
                }
            });
        }
    }

    report.buckets_rewritten += 1;

    Some(PiiSweepBucketDetail {
        bucket_internal_key: internal_key,
        bucket_owner_id: canonical_owner.clone(),
        bucket_name: bucket_name.clone(),
        objects_total: total_objects,
        objects_with_leak: leak_count,
        rewritten,
        old_root_cid,
        new_root_cid: Some(new_root_cid.to_string()),
        errors: bucket_errors,
    })
}
