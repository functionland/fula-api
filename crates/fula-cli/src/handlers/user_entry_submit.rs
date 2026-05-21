//! `PUT /api/v1/users-index/entry` — accept a client-signed entry
//! pointing at the caller's encrypted bucketsIndex CID.
//!
//! Strictly additive endpoint; touches no existing per-user data, no
//! existing routes, no existing handlers. Mode A users who never call
//! this endpoint keep their legacy plaintext `users[]` entry in the
//! global CBOR (preserved by the publisher in Phase 3).
//!
//! Pre-conditions verified by this handler before persisting:
//! 1. JSON body is well-formed.
//! 2. Hex fields decode cleanly (`entry_pubkey`, `signature`).
//! 3. Ed25519 signature verifies against `entry_pubkey` over the
//!    plan-defined payload (see [`fula_crypto::entry_signature_payload`]).
//! 4. TOFU binding holds: if there's already a record for this user,
//!    its `entry_pubkey_hex` must match the submitted one.
//! 5. Sequence is strictly greater than `highest_seq_ever_accepted`.
//!
//! All failure modes return distinct HTTP status codes so the client
//! writer can take an informed retry / surface decision (see plan §
//! "Multi-device sync — three layers").

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    extract::{Extension, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};

use cid::Cid;

use crate::entries_store::{EntryRecord, SubmitOutcome};
use crate::state::UserSession;
use crate::AppState;
use fula_blockstore::{BlockStore, PinStore};
use fula_crypto::{verify_entry_signature, ENTRY_PUBKEY_LEN, ENTRY_SIGNATURE_LEN};

/// Wire shape of the request body.
#[derive(Debug, Deserialize)]
pub struct PutEntryRequest {
    /// dag-cbor base32 CID of the encrypted bucketsIndex envelope.
    pub cid: String,
    /// Monotonic per-user sequence.
    pub sequence: u64,
    /// 32-byte Ed25519 public key, lowercase hex.
    pub entry_pubkey_hex: String,
    /// 64-byte Ed25519 detached signature, lowercase hex.
    pub signature_hex: String,
    /// Envelope format version this signature is bound to (currently
    /// always 3; surfaced as an explicit field so future envelope
    /// versions can co-exist without ambiguity).
    pub envelope_version: u32,
}

/// Wire shape of the response.
#[derive(Debug, Serialize)]
pub struct PutEntryResponse {
    pub user_key: String,
    pub sequence: u64,
    pub highest_seq_ever_accepted: u64,
}

/// `PUT /api/v1/users-index/entry`
pub async fn put_user_entry(
    State(state): State<Arc<AppState>>,
    Extension(session): Extension<UserSession>,
    Json(req): Json<PutEntryRequest>,
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

    // Decode hex fields. Length is validated against the Ed25519 sizes
    // exported from fula-crypto so callers get a precise error.
    let pubkey_bytes: [u8; ENTRY_PUBKEY_LEN] = match decode_fixed_hex(&req.entry_pubkey_hex) {
        Ok(b) => b,
        Err(e) => {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("entry_pubkey_hex invalid: {}", e),
            )
                .into_response());
        }
    };
    let sig_bytes: [u8; ENTRY_SIGNATURE_LEN] = match decode_fixed_hex(&req.signature_hex) {
        Ok(b) => b,
        Err(e) => {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("signature_hex invalid: {}", e),
            )
                .into_response());
        }
    };

    // Verify the signature BEFORE TOFU/sequence checks so that an
    // attacker who has a valid (cid, seq, sig) tuple for some user
    // cannot probe master's TOFU table by submitting different
    // pubkeys. The signature acts as the authentication primitive;
    // TOFU is the authorization layer on top.
    if !verify_entry_signature(
        &pubkey_bytes,
        &session.hashed_user_id,
        &req.cid,
        req.sequence,
        req.envelope_version,
        &sig_bytes,
    ) {
        return Err((StatusCode::UNAUTHORIZED, "signature invalid").into_response());
    }

    // Anti-poison check: the CID the caller is registering must
    // already be pinned on master (via the prior `PUT /per-user`
    // upload). This catches a class of legitimate-client bugs where
    // the writer uploads to one master and submits the entry to
    // another, plus malicious cases where an attacker tries to
    // register a CID pointing at content that isn't actually
    // available. The signature alone wouldn't catch this — we'd
    // accept it, master would serve it on `/per-user/latest`, and
    // clients would hit IPFS NotFound at cold-start.
    let parsed_cid = match req.cid.parse::<Cid>() {
        Ok(c) => c,
        Err(e) => {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("cid not parseable: {}", e),
            )
                .into_response());
        }
    };
    match state.block_store.pin_status(&parsed_cid).await {
        Ok(fula_blockstore::PinStatus::Pinned) => {}
        Ok(other) => {
            tracing::warn!(
                cid = %req.cid,
                status = ?other,
                "entry submit rejected: cid is not in Pinned status"
            );
            return Err((
                StatusCode::BAD_REQUEST,
                "cid not pinned by this master; upload via PUT /per-user first",
            )
                .into_response());
        }
        Err(e) => {
            // Network / store error talking to the pin store — log
            // and refuse rather than silently accepting an
            // unverifiable entry. Operator alert worthy.
            tracing::warn!(
                cid = %req.cid,
                error = %e,
                "pin_status check failed during entry submit; refusing entry"
            );
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                format!("pin status check failed: {}", e),
            )
                .into_response());
        }
    }

    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let candidate = EntryRecord {
        entry_pubkey_hex: req.entry_pubkey_hex.to_lowercase(),
        cid: req.cid.clone(),
        sequence: req.sequence,
        signature_hex: req.signature_hex.to_lowercase(),
        envelope_version: req.envelope_version,
        updated_at_unix: now_unix,
        highest_seq_ever_accepted: req.sequence,
    };

    match entries_store.try_submit(&session.hashed_user_id, candidate) {
        SubmitOutcome::Accepted => {
            let record = entries_store
                .get(&session.hashed_user_id)
                .expect("just inserted");
            Ok((
                StatusCode::OK,
                Json(PutEntryResponse {
                    user_key: session.hashed_user_id.clone(),
                    sequence: record.sequence,
                    highest_seq_ever_accepted: record.highest_seq_ever_accepted,
                }),
            )
                .into_response())
        }
        SubmitOutcome::PubkeyMismatch { bound } => {
            tracing::warn!(
                user_key = %session.hashed_user_id,
                submitted = %req.entry_pubkey_hex,
                bound = %bound,
                "TOFU binding rejected mismatched entry_pubkey"
            );
            // 403 is the right code: the request is authenticated
            // (signature was valid for the supplied pubkey) but the
            // pubkey isn't authorized for this user_key.
            Err((
                StatusCode::FORBIDDEN,
                format!("TOFU binding mismatch; bound pubkey is {}", bound),
            )
                .into_response())
        }
        SubmitOutcome::StaleSequence { current } => {
            // 409 Conflict — client should re-fetch /per-user/latest
            // and resign with sequence > current.
            Err((
                StatusCode::CONFLICT,
                format!(
                    "stale sequence; highest accepted = {}",
                    current
                ),
            )
                .into_response())
        }
    }
}

fn decode_fixed_hex<const N: usize>(s: &str) -> Result<[u8; N], String> {
    let bytes = hex::decode(s).map_err(|e| format!("not hex: {}", e))?;
    if bytes.len() != N {
        return Err(format!("expected {} bytes, got {}", N, bytes.len()));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}
