//! GC-recovery endpoint: `GET /api/v1/blocks/{cid}`.
//!
//! Read-only. Fetches a single pinned block by CID from the master's block
//! store, so a client can pull the exact forest/file blocks it discovers during
//! a by-CID walk of a gc-damaged bucket (no prolly-index lookup involved).
//!
//! Scope: the CID must be pinned on the platform — this keeps the endpoint from
//! acting as an open IPFS fetch proxy. A cross-user fetch leaks nothing anyway
//! (blocks are encrypted client-side), so this is defense-in-depth. Returns 503
//! when `FULA_PINS_DATABASE_URL` is unset, 404 when the CID isn't pinned, and
//! 410 (via the `BlockStoreError::Unavailable` → `Gone` mapping) when the block
//! is genuinely unavailable.

use std::str::FromStr;
use std::sync::Arc;

use axum::{
    body::Body,
    extract::{Extension, Path, State},
    http::{header, StatusCode},
    response::Response,
};
use cid::Cid;
use fula_blockstore::BlockStore;

use crate::state::UserSession;
use crate::{ApiError, AppState, S3ErrorCode};

pub async fn get_block_by_cid(
    State(state): State<Arc<AppState>>,
    Extension(session): Extension<UserSession>,
    Path(cid_str): Path<String>,
) -> Result<Response, ApiError> {
    if !session.can_read() {
        return Err(ApiError::s3(S3ErrorCode::AccessDenied, "Read access required"));
    }
    // P12 defense-in-depth: this fetches raw block bytes gated only on the CID
    // being pinned ANYWHERE on the platform (not ownership), so a scoped MCP
    // token here would read arbitrary out-of-scope bytes. The middleware
    // allowlist already blocks MCP from /api/v1/*; this is a second, local
    // fail-closed in case the route wiring ever changes.
    if session.mcp_scope.is_some() {
        return Err(ApiError::s3(S3ErrorCode::AccessDenied, "not available to MCP tokens"));
    }

    let cid = Cid::from_str(&cid_str)
        .map_err(|e| ApiError::s3(S3ErrorCode::InvalidArgument, format!("invalid CID: {e}")))?;

    // Gate on the CID being pinned on the platform (not an open proxy). Match
    // both the as-received form and the canonical form to tolerate CID encoding
    // variation between what resolve-keys returned and what's stored.
    let pool = state.pins_db.as_ref().ok_or_else(|| {
        ApiError::s3(
            S3ErrorCode::ServiceUnavailable,
            "block resolver not configured (FULA_PINS_DATABASE_URL unset)",
        )
    })?;
    let candidates = vec![cid_str.clone(), cid.to_string()];
    let pinned: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM pins WHERE cid = ANY($1) AND status NOT IN ('deleted', 'failed'))",
    )
    .bind(&candidates)
    .fetch_one(pool)
    .await
    .map_err(|e| ApiError::s3(S3ErrorCode::InternalError, format!("pin check failed: {e}")))?;
    if !pinned {
        return Err(ApiError::s3(
            S3ErrorCode::NoSuchKey,
            "block is not pinned on this platform",
        ));
    }

    // `?` maps BlockStoreError::Unavailable → Gone (410) so a genuinely-lost
    // block degrades cleanly instead of flagging the backend offline.
    let data = state.block_store.get_block(&cid).await?;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::CONTENT_LENGTH, data.len().to_string())
        .body(Body::from(data))
        .unwrap())
}
