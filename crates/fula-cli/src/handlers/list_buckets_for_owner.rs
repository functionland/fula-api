//! `GET /api/v1/buckets/list` — return caller's authoritative bucket
//! list from master's in-memory `BucketManager`.
//!
//! Used by the client-side bucketsIndex writer (Phase 4) as Layer 1
//! of the multi-device merge protocol: before publishing a new
//! encrypted bucketsIndex the writer fetches this endpoint and unions
//! the returned blinded IDs into its local view. This makes
//! "lost-update wipe" structurally impossible — a stale device cannot
//! publish a narrower bucket set than master already has.
//!
//! NOT a privacy regression vs today's posture: master already sees
//! every PUT and tracks `(hashed_user_id → BucketMetadata)` in
//! `BucketManager`. This endpoint just exposes that state back to the
//! authenticated owner — same data, same identity, just a read API
//! that didn't exist before.

use std::sync::Arc;

use axum::{
    extract::{Extension, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;

use crate::state::UserSession;
use crate::AppState;

#[derive(Debug, Serialize)]
pub struct ListBucketsResponse {
    pub buckets: Vec<BucketEntry>,
}

#[derive(Debug, Serialize)]
pub struct BucketEntry {
    /// Bucket identifier as master sees it. For Mode B/C with newer
    /// blinding this is the HMAC-derived hex; for legacy buckets this
    /// is the plaintext name.
    pub bucket_id: String,
    /// Encrypted forest manifest CID for this bucket, if the user has
    /// uploaded one. `None` for buckets that exist in `BucketManager`
    /// but haven't yet had a manifest committed (e.g., freshly-created
    /// empty buckets).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub forest_manifest_cid: Option<String>,
    /// Number of objects master sees in this bucket. Useful for the
    /// client writer to spot drift (e.g., master has files we don't
    /// know about → trigger a forest reload before publishing).
    pub object_count: u64,
    /// Wall-clock timestamp of the most recent update to this bucket's
    /// metadata on master.
    pub updated_at_unix: u64,
}

/// `GET /api/v1/buckets/list`
pub async fn list_buckets_for_owner(
    State(state): State<Arc<AppState>>,
    Extension(session): Extension<UserSession>,
) -> Result<Response, Response> {
    let buckets = state
        .bucket_manager
        .list_buckets_for_user(&session.hashed_user_id);

    let response = ListBucketsResponse {
        buckets: buckets
            .into_iter()
            .map(|b| {
                // BucketMetadata is defined in fula-core::metadata. The
                // fields below mirror what's needed by the client
                // writer's merge step (Layer 1 of multi-device sync):
                // bucket identifier, the encrypted forest_manifest_cid
                // master tracks per bucket, current object count, and
                // a freshness timestamp. Same data master already uses
                // internally — no new privacy exposure.
                BucketEntry {
                    bucket_id: b.name,
                    forest_manifest_cid: b.forest_manifest_cid.clone(),
                    object_count: b.object_count,
                    updated_at_unix: b.last_modified.timestamp().max(0) as u64,
                }
            })
            .collect(),
    };

    Ok((StatusCode::OK, Json(response)).into_response())
}
