//! GC-recovery endpoint: `POST /api/v1/buckets/{bucket}/resolve-keys`.
//!
//! Read-only. Maps a batch of storage-keys (which a pre-v8 client derives but
//! whose CIDs it can't see, because the manifest carries no CID hints and the
//! server prolly index lost nodes to `ipfs repo gc`) to their pinned CIDs, by
//! querying the pinning DB **by pin name**. No prolly-index rebuild, no
//! decryption — this is what lets a client walk a gc-damaged bucket's forest by
//! CID with only a tiny server assist.
//!
//! Safety: scoped to a bucket the caller owns; and because a storage_key is
//! `BLAKE3(dek‖path‖salt)` derived from the caller's own secret, a caller can
//! only ever resolve its own keys. Querying by the (globally-unique) key name
//! also sidesteps the split-user_id issue (#26) — the lookup finds the pin
//! whatever `pins.user_id` it sits under. Returns 503 when
//! `FULA_PINS_DATABASE_URL` is unset (`state.pins_db == None`).

use std::collections::HashMap;
use std::sync::Arc;

use axum::{
    extract::{Extension, Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use sqlx::Row;

use crate::state::UserSession;
use crate::{ApiError, AppState, S3ErrorCode};

/// Cap the batch so a single request can't fan out an unbounded `ANY($1)` set.
const MAX_KEYS: usize = 1024;

#[derive(Debug, Deserialize)]
pub struct ResolveKeysRequest {
    pub keys: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ResolvedCid {
    pub cid: String,
    /// Pinned object size in bytes, when the pin row carries it. Informational
    /// (the fetched block is self-describing); best-effort.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct ResolvedKey {
    pub key: String,
    /// All pinned CIDs for this storage_key, newest-first. Multiple = multiple
    /// pinned versions (the client picks the one its walk needs); empty = the
    /// key has no live pin (genuinely lost, or never existed).
    pub cids: Vec<ResolvedCid>,
}

#[derive(Debug, Serialize)]
pub struct ResolveKeysResponse {
    pub bucket: String,
    pub keys: Vec<ResolvedKey>,
}

pub async fn resolve_bucket_keys(
    State(state): State<Arc<AppState>>,
    Extension(session): Extension<UserSession>,
    Path(bucket): Path<String>,
    Json(req): Json<ResolveKeysRequest>,
) -> Result<Response, ApiError> {
    if !session.can_read() {
        return Err(ApiError::s3(S3ErrorCode::AccessDenied, "Read access required"));
    }
    // P12 defense-in-depth: a scoped MCP token has NO business resolving
    // storage_key→CID (it would hand back CIDs for any of the user's buckets,
    // feeding the block-by-cid byte read and bypassing the bucket/prefix fence).
    // The middleware allowlist already blocks MCP from /api/v1/*; this is a
    // second, local fail-closed in case the route wiring ever changes.
    if session.mcp_scope.is_some() {
        return Err(ApiError::s3(S3ErrorCode::AccessDenied, "not available to MCP tokens"));
    }
    if req.keys.is_empty() {
        return Ok((
            StatusCode::OK,
            Json(ResolveKeysResponse { bucket, keys: vec![] }),
        )
            .into_response());
    }
    if req.keys.len() > MAX_KEYS {
        return Err(ApiError::s3(
            S3ErrorCode::InvalidArgument,
            format!("too many keys (max {MAX_KEYS})"),
        ));
    }
    // Only resolve keys for a bucket the caller owns.
    if !state
        .bucket_manager
        .bucket_exists_for_user(&session.hashed_user_id, &bucket)
    {
        return Err(ApiError::s3(S3ErrorCode::NoSuchBucket, "No such bucket"));
    }

    let pool = state.pins_db.as_ref().ok_or_else(|| {
        ApiError::s3(
            S3ErrorCode::ServiceUnavailable,
            "key resolver not configured (FULA_PINS_DATABASE_URL unset)",
        )
    })?;

    // A storage_key is pinned under one of two name shapes: the bare key, or
    // `object:{bucket}/{key}`. Build the candidate set and resolve in ONE batched
    // query, then group results back to the original key.
    let obj_prefix = format!("object:{}/", bucket);
    let mut candidates: Vec<String> = Vec::with_capacity(req.keys.len() * 2);
    for k in &req.keys {
        candidates.push(k.clone());
        candidates.push(format!("{}{}", obj_prefix, k));
    }

    let rows = sqlx::query(
        "SELECT name, cid, size FROM pins \
         WHERE name = ANY($1) AND status NOT IN ('deleted', 'failed') \
         ORDER BY updated_at DESC",
    )
    .bind(&candidates)
    .fetch_all(pool)
    .await
    .map_err(|e| ApiError::s3(S3ErrorCode::InternalError, format!("pins query failed: {e}")))?;

    let mut by_key: HashMap<String, Vec<ResolvedCid>> = HashMap::new();
    for row in rows {
        let name: String = match row.try_get("name") {
            Ok(n) => n,
            Err(_) => continue,
        };
        let cid: String = match row.try_get("cid") {
            Ok(c) => c,
            Err(_) => continue,
        };
        let size: Option<i64> = row.try_get("size").unwrap_or(None);
        let key = name
            .strip_prefix(&obj_prefix)
            .unwrap_or(name.as_str())
            .to_string();
        by_key.entry(key).or_default().push(ResolvedCid {
            cid,
            size: size.map(|s| s as u64),
        });
    }

    let keys = req
        .keys
        .iter()
        .map(|k| ResolvedKey {
            key: k.clone(),
            cids: by_key.remove(k).unwrap_or_default(),
        })
        .collect();

    Ok((StatusCode::OK, Json(ResolveKeysResponse { bucket, keys })).into_response())
}
