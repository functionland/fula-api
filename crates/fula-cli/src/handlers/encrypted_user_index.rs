//! Encrypted bucketsIndex pin + latest-entry-lookup endpoints.
//!
//! These are part of the Phase 2 server surface for the per-entry
//! signed encrypted bucketsIndex architecture. They DO NOT touch any
//! existing per-user data, route, or behavior — they are strictly
//! additive endpoints under the `/api/v1/users-index/per-user` namespace.
//!
//! - `PUT /api/v1/users-index/per-user` — client uploads an encrypted
//!   bucketsIndex envelope (CBOR with v=3, nonce, ciphertext). Master
//!   pins the bytes under the dedicated GC-safe pin tag and returns
//!   the CID. Master CANNOT decrypt — the AEAD key (`K_index`) is
//!   seed-derived and never leaves the client.
//!
//! - `GET /api/v1/users-index/per-user/latest` — returns master's
//!   last-known signed entry for the calling user (looked up via
//!   `session.hashed_user_id`). Used by the client cold-start
//!   fast-path; client verifies the signature locally.

use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::{Extension, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};

use crate::state::UserSession;
use crate::AppState;
use fula_blockstore::{BlockStore, PinStore};

/// Pin tag used for every client-uploaded encrypted bucketsIndex blob.
/// Garbage-collection MUST treat this tag as a keep-alive root — the
/// blob is not referenced from the main bucket DAG and would otherwise
/// look orphan-able.
pub const PIN_TAG: &str = "fula-users-index-per-user";

/// Soft cap on per-upload size. Encrypted bucketsIndex bodies are
/// dominated by per-bucket entries (each ~200 bytes plaintext). At
/// 5000 buckets per user this is ~1 MB; 1 MiB gives a comfortable
/// margin while still capping pathological / malicious uploads.
const MAX_BODY_BYTES: usize = 1 * 1024 * 1024;

/// Response body for a successful pin.
#[derive(Debug, Serialize, Deserialize)]
pub struct PutEncryptedBucketsIndexResponse {
    pub cid: String,
    pub size: usize,
}

/// Response body for `GET /per-user/latest`. Mirrors the on-wire shape
/// of [`crate::entries_store::EntryRecord`] so the client can rebuild
/// the same struct it would otherwise decode from the global CBOR.
#[derive(Debug, Serialize, Deserialize)]
pub struct LatestEntryResponse {
    pub cid: String,
    pub sequence: u64,
    pub entry_pubkey_hex: String,
    pub signature_hex: String,
    pub envelope_version: u32,
    pub updated_at_unix: u64,
    /// Highest sequence master has ever accepted for this user.
    /// Client uses this on storage-clear recovery: `next_seq =
    /// highest_seq + 1`.
    pub highest_seq_ever_accepted: u64,
}

/// `PUT /api/v1/users-index/per-user`
///
/// Auth: standard user JWT middleware (caller's session must be
/// present). Body: raw bytes of the encrypted bucketsIndex envelope.
pub async fn put_encrypted_bucketsindex(
    State(state): State<Arc<AppState>>,
    Extension(_session): Extension<UserSession>,
    body: Bytes,
) -> Result<Response, Response> {
    if body.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "empty body").into_response());
    }
    if body.len() > MAX_BODY_BYTES {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            format!("body exceeds {} bytes", MAX_BODY_BYTES),
        )
            .into_response());
    }

    // Pin under our dedicated tag so GC keeps it alive. Block store
    // is content-addressed, so concurrent uploads of the same bytes
    // collapse to a single block (the CID is deterministic).
    let cid = state
        .block_store
        .put_block(&body)
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "put_block failed for encrypted bucketsIndex");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("put_block failed: {}", e),
            )
                .into_response()
        })?;

    if let Err(e) = state.block_store.pin(&cid, Some(PIN_TAG)).await {
        tracing::warn!(error = %e, cid = %cid, "pin failed for encrypted bucketsIndex");
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("pin failed: {}", e),
        )
            .into_response());
    }

    Ok((
        StatusCode::OK,
        Json(PutEncryptedBucketsIndexResponse {
            cid: cid.to_string(),
            size: body.len(),
        }),
    )
        .into_response())
}

/// `GET /api/v1/users-index/per-user/latest`
///
/// Returns the master's last-known signed entry for the caller.
/// Client verifies the signature locally; master CANNOT lie because
/// the signature was produced by the user's seed-derived key (master
/// has no copy of `K_entry_priv`).
pub async fn get_latest_entry(
    State(state): State<Arc<AppState>>,
    Extension(session): Extension<UserSession>,
) -> Result<Response, Response> {
    let entries_store = match state.entries_store.as_ref() {
        Some(s) => s,
        None => {
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                "entries store not configured",
            )
                .into_response());
        }
    };

    let Some(record) = entries_store.get(&session.hashed_user_id) else {
        return Err((StatusCode::NOT_FOUND, "no entry for this user").into_response());
    };

    Ok((
        StatusCode::OK,
        Json(LatestEntryResponse {
            cid: record.cid,
            sequence: record.sequence,
            entry_pubkey_hex: record.entry_pubkey_hex,
            signature_hex: record.signature_hex,
            envelope_version: record.envelope_version,
            updated_at_unix: record.updated_at_unix,
            highest_seq_ever_accepted: record.highest_seq_ever_accepted,
        }),
    )
        .into_response())
}
