//! Object operation handlers

use crate::pinning::{check_can_upload, pin_for_user, unpin_for_user};
use crate::{AppState, ApiError, S3ErrorCode};
use crate::state::UserSession;
use crate::xml;
use axum::{
    body::Body,
    extract::{Extension, Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use bytes::Bytes;
use fula_blockstore::{BlockStore, BlockStoreError, PinStore};
use fula_core::metadata::ObjectMetadata;
use fula_crypto::hashing::md5_hash;
use serde::Deserialize;
use std::sync::Arc;
use base64::{Engine as _, engine::general_purpose};

/// PUT /{bucket}/{key} - Put object
pub async fn put_object(
    State(state): State<Arc<AppState>>,
    Extension(session): Extension<UserSession>,
    Path((bucket_name, key)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    if !session.can_write() {
        return Err(ApiError::s3(S3ErrorCode::AccessDenied, "Write access required"));
    }

    // Check balance BEFORE storing data (if remote pinning is configured)
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

    // Decode HTTP chunked transfer encoding if present in the body.
    // AWS CLI and other S3 clients may send chunked-encoded bodies that a
    // reverse proxy (e.g., nginx) forwards without decoding.
    let body = match try_decode_chunked(&headers, &body) {
        Some(decoded) => decoded,
        None => body,
    };

    // Serialize index-mutating operations on the same user-scoped bucket.
    // Without this, parallel chunk PUTs (fula-client fans out up to 16) all
    // open at the same root_cid, each flushes a tree containing only its
    // own key, and DashMap::insert last-writer-wins drops every other
    // mapping — leaving the chunk bytes in IPFS but the bucket index
    // pointing at only one of them. Held until the end of the handler so
    // the open → mutate → flush → persist sequence is atomic per bucket.
    let _bucket_guard = state
        .bucket_manager
        .bucket_write_lock(&session.hashed_user_id, &bucket_name)
        .lock_owned()
        .await;

    // Open bucket first so conditional-write guards can consult the current
    // stored ETag without doing extra I/O later. (Moved ahead of put_block.)
    tracing::debug!(bucket = %bucket_name, "Opening user-scoped bucket");
    let mut bucket = state.bucket_manager.open_bucket_for_user(&session.hashed_user_id, &bucket_name).await
        .map_err(|e| {
            tracing::error!(error = %e, bucket = %bucket_name, "Failed to open bucket");
            e
        })?;

    // RFC 7232 conditional-write preconditions. With the per-bucket write
    // lock held above, get_object + put_object now observe a consistent
    // snapshot for the same bucket; the client still needs retry-on-412
    // for cross-device races.
    let existing = bucket.get_object(&key).await?;
    let current_etag: Option<&str> = existing.as_ref().map(|m| m.etag.as_str());

    if let Some(h) = headers.get("If-Match").and_then(|v| v.to_str().ok()) {
        if !match_if_match(h, current_etag) {
            // TEMPORARY DIAGNOSTIC for #29 — compute the CID master
            // WOULD assign to the body that just arrived. If the SDK's
            // if_match equals this body_cid, the bug is "SDK uses the
            // NEW body's CID as If-Match" (would always 412 the very
            // first attempt). If if_match differs from BOTH current
            // AND body_cid, it's something else (stale cache, WAL
            // mis-restore, persisted state).
            let body_cid_str = {
                use cid::multihash::Multihash;
                let h = blake3::hash(&body);
                let mh = Multihash::<64>::wrap(0x1e, h.as_bytes())
                    .expect("blake3 multihash wrap");
                cid::Cid::new_v1(0x55, mh).to_string()
            };
            let dbg_body_cid = headers
                .get("x-amz-meta-fula-debug-body-cid")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("<no-sdk-rebuild>");
            let dbg_prior_etag = headers
                .get("x-amz-meta-fula-debug-prior-etag")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("<no-sdk-rebuild>");
            tracing::warn!(
                bucket = %bucket_name,
                key = %key,
                if_match = %h,
                current_etag = ?current_etag,
                master_computed_body_cid = %body_cid_str,
                sdk_debug_body_cid = %dbg_body_cid,
                sdk_debug_prior_etag = %dbg_prior_etag,
                "412 diag: if_match vs current vs body_cid"
            );
            return Err(ApiError::s3(
                S3ErrorCode::PreconditionFailed,
                "If-Match precondition failed",
            ));
        }
    }
    if let Some(h) = headers.get("If-None-Match").and_then(|v| v.to_str().ok()) {
        if !match_if_none_match(h, current_etag) {
            return Err(ApiError::s3(
                S3ErrorCode::PreconditionFailed,
                "If-None-Match precondition failed",
            ));
        }
    }

    // Phase 2 (decentralized ingress): empty-body mapping PUT. The chunk's
    // verified bytes were already streamed to a fula-ingest node; record only
    // the key→cid mapping here. Triple-gated: server flag (advertised via
    // /fula/capabilities, so well-behaved clients never send this to a
    // flag-off master), the header, and an empty body. The declared CID must
    // be raw(0x55)+blake3(0x1e) — the only addressing the ingest verifies —
    // and the block must be PRESENT in the blockstore (bitswap pulls it from
    // the ingest peer); absent ⇒ retryable 409 so the client falls back to a
    // full-bytes PUT. Storing nothing here is the point: the CID is
    // self-certifying, so reads stay tamper-evident end-to-end.
    let remote_cid_hdr = headers
        .get("x-amz-meta-fula-remote-cid")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let cid = if let Some(declared) = remote_cid_hdr {
        if !state.config.remote_cid_put_enabled {
            return Err(ApiError::s3(
                S3ErrorCode::InvalidRequest,
                "remote-cid PUT is not enabled on this master (probe /fula/capabilities)",
            ));
        }
        if !body.is_empty() {
            return Err(ApiError::s3(
                S3ErrorCode::InvalidRequest,
                "remote-cid PUT requires an empty body",
            ));
        }
        let declared_cid = cid::Cid::try_from(declared.as_str()).map_err(|e| {
            ApiError::s3(S3ErrorCode::InvalidRequest, format!("invalid remote cid: {e}"))
        })?;
        if declared_cid.codec() != 0x55 || declared_cid.hash().code() != 0x1e {
            return Err(ApiError::s3(
                S3ErrorCode::InvalidRequest,
                "remote cid must be raw (0x55) + blake3 (0x1e) — the addressing fula-ingest verifies",
            ));
        }
        match state.block_store.has_block(&declared_cid).await {
            Ok(true) => {}
            Ok(false) => {
                return Err(ApiError::s3(
                    S3ErrorCode::OperationAborted,
                    "declared block not present/retrievable yet — retry or fall back to a full-bytes PUT",
                ));
            }
            Err(e) => {
                tracing::warn!(error = %e, cid = %declared_cid, "remote-cid presence check failed");
                return Err(ApiError::s3(
                    S3ErrorCode::OperationAborted,
                    "block presence check failed — retry or fall back to a full-bytes PUT",
                ));
            }
        }
        tracing::debug!(bucket = %bucket_name, key = %key, cid = %declared_cid, "remote-cid PUT accepted (bytes via ingest)");
        declared_cid
    } else {
        // Store the data
        state.block_store.put_block(&body).await?
    };
    // Phase 2: a mapping PUT has an empty body — the chunk's TRUE size (as
    // stored on the ingest node) arrives in x-amz-meta-fula-remote-size so
    // billing/list/stat record the real byte count, never 0. Only honored on
    // the remote-cid path; bounded by max_body_size like a real body.
    let object_size: u64 = match (
        headers.get("x-amz-meta-fula-remote-size").and_then(|v| v.to_str().ok()),
        headers.get("x-amz-meta-fula-remote-cid").is_some(),
    ) {
        (Some(sz), true) => {
            let parsed = sz.parse::<u64>().map_err(|_| {
                ApiError::s3(S3ErrorCode::InvalidRequest, "invalid x-amz-meta-fula-remote-size")
            })?;
            if parsed == 0 || parsed > state.config.max_body_size as u64 {
                return Err(ApiError::s3(
                    S3ErrorCode::InvalidRequest,
                    "x-amz-meta-fula-remote-size out of range",
                ));
            }
            parsed
        }
        _ => body.len() as u64,
    };

    // Use CID as ETag (content-addressed identifier)
    // This is S3-compliant: AWS docs state "The ETag may or may not be an MD5 digest"
    let etag = cid.to_string();

    // Verify Content-MD5 if present (still uses MD5 for S3 compatibility)
    if let Some(md5_header) = headers.get("Content-MD5").and_then(|v| v.to_str().ok()) {
        if let Ok(expected_bytes) = general_purpose::STANDARD.decode(md5_header) {
            let expected_hex = hex::encode(expected_bytes);
            let actual_md5 = md5_hash(&body);
            if actual_md5 != expected_hex {
                return Err(ApiError::s3(S3ErrorCode::InvalidDigest, "The Content-MD5 you specified did not match what we received."));
            }
        } else {
            return Err(ApiError::s3(S3ErrorCode::InvalidDigest, "Invalid Content-MD5"));
        }
    }

    // Extract metadata from headers
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // PII-safety: store the OPAQUE hashed form, never the raw JWT sub.
    // `session.user_id` is the JWT `sub` as-is — for legacy users it's
    // a plaintext email; persisting it leaks PII into the bucket's
    // Prolly Tree leaves, which are content-addressed and pinned to
    // IPFS via Phase 3.2's users-index publisher. `session.hashed_user_id`
    // is the canonical 16-byte BLAKE3-derived form used everywhere else
    // (BucketMetadata.owner_id, can_access_bucket comparisons, the
    // COPY handler at line 694). Access control is unaffected — bucket-
    // level access is gated by `BucketMetadata.owner_id` which is
    // already correctly the hashed form.
    let mut metadata = ObjectMetadata::new(cid, object_size, etag.clone())
        .with_owner(&session.hashed_user_id);

    if let Some(ct) = content_type {
        metadata = metadata.with_content_type(ct);
    }

    // Extract user metadata (x-amz-meta-*). Internal Fula control
    // headers (consumed by the handler, not stored as object metadata)
    // are filtered out via `is_fula_control_header` — they would
    // otherwise pollute every object's persisted metadata.
    for (name, value) in headers.iter() {
        if let Some(key) = name.as_str().strip_prefix("x-amz-meta-") {
            if is_fula_control_header(key) {
                continue;
            }
            if let Ok(v) = value.to_str() {
                metadata = metadata.with_user_metadata(key, v);
            }
        }
    }

    tracing::debug!(key = %key, "Storing object metadata");
    bucket.put_object(key.clone(), metadata).await
        .map_err(|e| {
            tracing::error!(error = %e, key = %key, "Failed to put object");
            e
        })?;

    tracing::debug!("Flushing bucket");
    let bucket_root_cid = bucket.flush().await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to flush bucket");
            e
        })?;

    // Phase 1.2 of master-independent reads: if the SDK included
    // `x-amz-meta-fula-bucket-lookup-h` (set by `save_sharded_hamt_forest`
    // on Phase 1.5 page PUTs, Phase 1.6 dir-index PUT, and Phase 2 root
    // PUT — i.e. any flush-driven PUT — and by `save_forest` for v1
    // monolithic), populate-or-update the bucket-level `bucket_lookup_h`
    // field. REPLACE-ON-CHANGE — a user reinstalling FxFiles, signing in
    // on a second device with subtly different derivation inputs, or any
    // other legitimate session change updates the lookup_h on their next
    // PUT. The original Phase 1.2 set-once design left such users
    // permanently locked out of cold-start; replace-on-change self-heals.
    // Bucket ownership is enforced by the JWT auth on this PUT path, so
    // only the legitimate owner can write a different value here.
    //
    // Gated by env so we can stage the rollout: SDK always sends the
    // header (cheap); master only consumes it when ready. As of v0.4.1+
    // the SDK attaches it on page-level writes too, so deferred-upload
    // paths migrate without needing an explicit `flushForest` to fire
    // Phase 2.
    //
    // Failures are non-fatal — bad/missing headers must not break uploads.
    // Placement: AFTER bucket.flush() (so the flush has already replaced
    // the DashMap entry) and BEFORE persist_registry_with_token (so the
    // updated field gets serialized into the registry CBOR on this same
    // request, no extra IPFS write).
    let buckets_index_enabled = std::env::var("FULA_BUCKET_LOOKUP_H_ENABLED")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if buckets_index_enabled {
        if let Some(hex_str) = headers
            .get("x-amz-meta-fula-bucket-lookup-h")
            .and_then(|v| v.to_str().ok())
        {
            match parse_bucket_lookup_h_header(hex_str) {
                Ok(lookup_h) => {
                    match state.bucket_manager.populate_bucket_lookup_h(
                        &session.hashed_user_id,
                        &bucket_name,
                        lookup_h,
                    ) {
                        Ok(true) => tracing::debug!(
                            bucket = %bucket_name,
                            "Populated/updated bucket_lookup_h (Phase 1.2)"
                        ),
                        Ok(false) => { /* identical value already stored; no-op */ }
                        // BucketNotFound on a successful PUT to a real bucket
                        // is an internal-consistency violation — promote to
                        // error level so operators notice the signal.
                        Err(e) => tracing::error!(
                            error = %e,
                            bucket = %bucket_name,
                            user = %session.hashed_user_id,
                            "populate_bucket_lookup_h failed on a bucket that just accepted a PUT"
                        ),
                    }
                }
                Err(BucketLookupHError::WrongLength { actual }) => tracing::warn!(
                    actual_len = actual,
                    "x-amz-meta-fula-bucket-lookup-h: expected 16-byte hex (32 chars), got {} bytes",
                    actual
                ),
                Err(BucketLookupHError::InvalidHex(e)) => tracing::warn!(
                    error = %e,
                    "Failed to hex-decode x-amz-meta-fula-bucket-lookup-h"
                ),
            }
        }
    }

    // v0.4.4: SDK forest-manifest CID tracking. When the SDK PUTs its
    // encrypted forest manifest (Phase 2 root commit), it sends the
    // sentinel header `x-amz-meta-fula-forest-manifest: 1`. Master sees
    // the sentinel, takes the just-computed `cid` (which is the etag of
    // the bytes that just went into the bucket Prolly Tree at index_key),
    // and stores it on the BucketMetadata so the publisher can emit it
    // as `forest_manifest_cid` in the per-user bucketsIndex CBOR.
    //
    // Why a sentinel rather than the CID itself: master computes `cid`
    // server-side anyway (lines ~95 above) and is the source of truth
    // for content-addressing. SDK doesn't need to recompute and send it
    // — that just adds verification overhead. The sentinel says "this
    // PUT is the forest manifest; please record the CID".
    //
    // REPLACE semantics: every Phase 2 root commit produces a fresh CID
    // (encrypted manifest content includes a new sequence number), so
    // master always tracks the LATEST. `populate_forest_manifest_cid`
    // is idempotent on identical input (no extra dirty flag, no extra
    // registry persist) but DOES replace when the CID changed —
    // structurally identical to `populate_bucket_lookup_h` above.
    //
    // Env-flag gated (`FULA_FOREST_MANIFEST_CID_ENABLED`) so master can
    // stage the rollout independently of SDK rollout. Failures are
    // non-fatal — bad header parsing must not break uploads.
    let forest_manifest_enabled = std::env::var("FULA_FOREST_MANIFEST_CID_ENABLED")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if forest_manifest_enabled {
        let sentinel_present = headers
            .get("x-amz-meta-fula-forest-manifest")
            .and_then(|v| v.to_str().ok())
            .map(|s| s == "1" || s.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        if sentinel_present {
            // `cid` is the content-addressed CID master computed for this
            // PUT body (lines ~95 in this handler). It is the SDK's
            // encrypted forest manifest CID by construction — the SDK
            // sends the sentinel only on its Phase 2 root-commit PUT.
            match state.bucket_manager.populate_forest_manifest_cid(
                &session.hashed_user_id,
                &bucket_name,
                cid.to_string(),
            ) {
                Ok(true) => tracing::debug!(
                    bucket = %bucket_name,
                    cid = %cid,
                    "Populated forest_manifest_cid (v0.4.4)"
                ),
                Ok(false) => { /* identical to existing value; no-op */ }
                Err(e) => tracing::error!(
                    error = %e,
                    bucket = %bucket_name,
                    user = %session.hashed_user_id,
                    "populate_forest_manifest_cid failed on a bucket that just accepted a PUT"
                ),
            }
        }
    }

    // Persist the bucket registry so the new root CID survives restarts.
    // This MUST succeed — otherwise the new tree root is lost on restart.
    // Use the user's JWT for pinning service authentication.
    state.bucket_manager.persist_registry_with_token(&session.jwt_token).await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to persist bucket registry after put_object — data may be lost on restart");
            ApiError::s3(S3ErrorCode::InternalError, "Failed to persist storage index. Please retry.")
        })?;

    // W.9.6 — pin THIS object's body CID **explicitly** in addition
    // to the bucket-root recursive pin below. The bucket-root pin
    // recursively walks the Prolly Tree IPLD DAG, which transitively
    // covers leaf CIDs IF cluster's recursive-pin treats Prolly Tree
    // leaves' `cid` field as walkable IPLD links. This is the
    // pre-existing v7 contract; whether it holds for every leaf in
    // every Prolly Tree implementation is a property of
    // fula-blockstore + the cluster client. For walkable-v8 we
    // CANNOT afford a quiet gap — every HAMT internal-node CID,
    // every manifest-page CID, every chunk CID stamped into a
    // `LinkV2` / `PageRef.cid` / `storage_cid` field MUST be
    // DHT-discoverable for the W.9.4 reader's offline gateway race
    // to find it. So we belt-and-suspenders: enqueue the body's
    // CID directly. Cluster's pin API is idempotent at the CID
    // level, so a CID also covered by the recursive pin gets
    // pinned exactly once (no double work, no extra storage).
    if let Some(queue) = state.pin_queue.as_ref() {
        let object_pin_name = if key.starts_with("__fula_forest_v7_nodes/") {
            // HAMT internal node — load-bearing for walkable-v8
            // offline walks. Distinguishable in `pin ls` for
            // operator triage.
            format!("v8-node:{}", bucket_name)
        } else if key.starts_with("__fula_forest_") {
            format!("forest-meta:{}", bucket_name)
        } else {
            format!("object:{}/{}", bucket_name, key)
        };
        if let Err(e) = queue.enqueue(crate::pin_queue::PinRequest {
            cid,
            target: crate::pin_queue::PinTarget::MasterCluster,
            kind: crate::pin_queue::PinKind::Add,
            pin_name: Some(object_pin_name.clone()),
            bearer_token: Some(session.jwt_token.clone()),
            pinning_endpoint: None,
        }) {
            // Mirror the bucket-root path's fire-and-forget fallback
            // (no asymmetry — both routes preserve walkable-v8's
            // belt-and-suspenders guarantee). A redb commit failure
            // shouldn't silently drop the per-object pin since the
            // recursive bucket-root pin's transitive coverage is
            // not architecturally guaranteed for HAMT internal-node
            // ciphertexts.
            tracing::warn!(
                cid = %cid,
                key = %key,
                error = %e,
                "pin_queue enqueue (per-object) failed; falling back to fire-and-forget for this PUT"
            );
            let block_store = Arc::clone(&state.block_store);
            let jwt_token = session.jwt_token.clone();
            let pn = object_pin_name;
            tokio::spawn(async move {
                if let Err(e) = block_store
                    .pin_with_token(&cid, Some(&pn), &jwt_token)
                    .await
                {
                    tracing::warn!(
                        cid = %cid,
                        error = %e,
                        "Failed to pin per-object CID (queue-enqueue-fallback path)"
                    );
                }
            });
        }
    }

    // Local-retain GC-safety: pin this object/chunk block locally on the master
    // + record it in the backlog, so `ipfs repo gc` can't reclaim it until the
    // cluster confirms replication. Synchronous so the block is gc-safe before
    // we return 200; a local-pin failure is FATAL (propagates as 5xx) so we
    // never 200 a block that isn't gc-safe — the client retries. No-op when the
    // feature is disabled.
    if let Some(lr) = state.local_retain.as_ref() {
        // A large object stored via UnixFS chunking has a dag-pb root whose raw
        // leaves also need gc-protecting; a small object is a single raw block.
        // `retain_with_leaves` pins + tracks the root AND pins its leaves, so the
        // leaves are gc-safe WITHOUT a blanket `refs local` backfill (only Fula
        // data is ever pinned, never transient IPFS-network cache).
        const DAG_PB: u64 = 0x70;
        if cid.codec() == DAG_PB {
            lr.retain_with_leaves(&cid).await?;
        } else {
            lr.retain(&cid).await?;
        }
    }

    // W.9.6 — pin the BUCKET ROOT CID through the durable queue.
    // Cluster's recursive pin walks the bucket's Prolly Tree which
    // covers every object referenced from the bucket. With the
    // per-object pin above + this recursive pin, every CID gets
    // pinned at LEAST once (and at most a few times — idempotent at
    // cluster, so no harm).
    //
    // Routing:
    //   * `state.pin_queue = Some(_)` → durable enqueue; background
    //     drainer dispatches via `block_store.pin_with_token` with
    //     bounded concurrency + exp backoff retry. Returns 200 to
    //     the client immediately after the cheap redb commit.
    //     Pending pins survive a master crash.
    //   * `state.pin_queue = None` → legacy fire-and-forget. No
    //     retry, no crash safety. Tests + minimal dev configs only.
    //     Production deployments MUST set `pin_queue_path`.
    let pin_name = format!("bucket:{}", bucket_name);
    if let Some(queue) = state.pin_queue.as_ref() {
        if let Err(e) = queue.enqueue(crate::pin_queue::PinRequest {
            cid: bucket_root_cid,
            target: crate::pin_queue::PinTarget::MasterCluster,
            kind: crate::pin_queue::PinKind::Add,
            pin_name: Some(pin_name.clone()),
            bearer_token: Some(session.jwt_token.clone()),
            pinning_endpoint: None,
        }) {
            // redb commit failed — log and fall back to fire-and-
            // forget for this single request so the user's PUT
            // doesn't fail. The next request will try the queue
            // again; persistent failures here are an operator alert.
            tracing::warn!(
                cid = %bucket_root_cid,
                error = %e,
                "pin_queue enqueue (master) failed; falling back to fire-and-forget for this PUT"
            );
            let block_store = Arc::clone(&state.block_store);
            let jwt_token = session.jwt_token.clone();
            let pin_name_clone = pin_name.clone();
            tokio::spawn(async move {
                if let Err(e) = block_store
                    .pin_with_token(&bucket_root_cid, Some(&pin_name_clone), &jwt_token)
                    .await
                {
                    tracing::warn!(
                        cid = %bucket_root_cid,
                        error = %e,
                        "Failed to pin bucket root CID (queue-enqueue-fallback path)"
                    );
                }
            });
        } else {
            tracing::debug!(
                cid = %bucket_root_cid,
                bucket = %pin_name,
                "Bucket root CID enqueued for durable pin (W.9.6)"
            );
        }
    } else {
        // Legacy fire-and-forget — no queue configured.
        let block_store = Arc::clone(&state.block_store);
        let pin_name_clone = pin_name.clone();
        let jwt_token = session.jwt_token.clone();
        tokio::spawn(async move {
            if let Err(e) = block_store
                .pin_with_token(&bucket_root_cid, Some(&pin_name_clone), &jwt_token)
                .await
            {
                tracing::warn!(cid = %bucket_root_cid, error = %e, "Failed to pin bucket root CID");
            } else {
                tracing::info!(cid = %bucket_root_cid, bucket = %pin_name_clone, "Bucket root CID pinned (recursive)");
            }
        });
    }

    // Local-retain GC-safety for the bucket root (Prolly-Tree root) too. Same
    // fatal policy: a failed local pin of the forest root fails the PUT (5xx)
    // rather than 200-ing an index whose root block isn't gc-safe.
    if let Some(lr) = state.local_retain.as_ref() {
        lr.retain(&bucket_root_cid).await?;
    }

    // P0 — pin the bucket's index NODES (interior + leaves) for gc-safety.
    //
    // A `ProllyNode`'s child CIDs are serialized as plain strings, not IPLD
    // links, so the recursive `bucket:` cluster pin above covers ONLY the root
    // block — every interior/leaf index node is gc-exposed and was being lost to
    // `ipfs repo gc`. Pin each index node EXPLICITLY (cluster pin = durability;
    // FATAL local-retain = gc-safe-before-200, like the body/root pins). To
    // bound per-PUT work, pin only the DIFF vs the set we last CONFIRMED pinned
    // for this bucket: an absent/empty prior set means "pin ALL" (rollout-safe —
    // we never skip a still-unpinned shared node), and the prior set is updated
    // ONLY after a successful fatal pin. NO unpin here — dropping a superseded
    // node's pin by CID is unsafe across buckets that share an identical node
    // CID; reclaiming superseded index versions is a separate refcounted pass.
    if let (Some(queue), Some(ips), Some(lr)) = (
        state.pin_queue.as_ref(),
        state.index_pin_set.as_ref(),
        state.local_retain.as_ref(),
    ) {
        // FATAL enumerate (codex review): if we can't list the index nodes we
        // just committed, fail the PUT rather than leave a durable root whose
        // nodes are gc-exposed. Succeeds on a healthy/cluster-recoverable index;
        // only fails on a genuinely broken one (which already fails reads).
        let new_nodes = bucket.index_node_cids().await.map_err(|e| {
            tracing::error!(error = %e, bucket = %bucket_name, "index-node pin: enumerate failed after root committed — failing PUT so the index isn't left gc-exposed");
            ApiError::s3(S3ErrorCode::InternalError, "Failed to protect storage index. Please retry.")
        })?;
        if !new_nodes.is_empty() {
            let ips_key = format!("{}/{}", session.hashed_user_id, bucket_name);
            let prev: std::collections::HashSet<_> =
                ips.get(&ips_key).unwrap_or_default().into_iter().collect();
            // Pin only nodes not already in the last CONFIRMED-pinned set
            // (absent set ⇒ pin all ⇒ rollout-safe).
            let to_pin: Vec<_> = new_nodes
                .iter()
                .copied()
                .filter(|c| !prev.contains(c))
                .collect();
            // Nodes whose CLUSTER enqueue fails are pinned locally (gc-safe) but
            // are NOT recorded as confirmed, so the next flush re-attempts their
            // cluster pin (codex review: never strand a node on a single local
            // pin the verifier will never drop).
            let mut cluster_failed = std::collections::HashSet::new();
            let index_pin_name = format!("index-node:{}", bucket_name);
            for cid in &to_pin {
                if let Err(e) = queue.enqueue(crate::pin_queue::PinRequest {
                    cid: *cid,
                    target: crate::pin_queue::PinTarget::MasterCluster,
                    kind: crate::pin_queue::PinKind::Add,
                    pin_name: Some(index_pin_name.clone()),
                    bearer_token: Some(session.jwt_token.clone()),
                    pinning_endpoint: None,
                }) {
                    tracing::warn!(cid = %cid, error = %e, "index-node cluster-pin enqueue failed; re-attempt next flush");
                    cluster_failed.insert(*cid);
                }
                // FATAL local pin: never 200 a committed index whose nodes
                // aren't gc-safe. Genuine pin failure fails the PUT (client
                // retries); an already-pinned node is a fast no-op.
                lr.retain(cid).await?;
            }
            // Record nodes confirmed BOTH locally pinned AND cluster-enqueued
            // (all current nodes minus those whose cluster enqueue just failed),
            // so the diff baseline only skips truly-protected nodes.
            let confirmed: Vec<_> = new_nodes
                .iter()
                .copied()
                .filter(|c| !cluster_failed.contains(c))
                .collect();
            if let Err(e) = ips.put(&ips_key, &confirmed) {
                tracing::warn!(bucket = %bucket_name, error = %e, "index-pin-set: record failed (re-pins next flush)");
            }
            if !to_pin.is_empty() {
                tracing::debug!(
                    bucket = %bucket_name,
                    newly_pinned = to_pin.len(),
                    cluster_deferred = cluster_failed.len(),
                    index_nodes = new_nodes.len(),
                    "index-node pins applied (P0 gc-safety)"
                );
            }
        }
    }

    // Also pin THIS object's CID to the user's external pinning
    // service if credentials are configured. W.9.6: routes through
    // the same queue when `pin_queue_path` is set so user-external
    // pins also get durable retry. Falls back to the legacy
    // fire-and-forget `pin_for_user` when the queue is unconfigured.
    pin_for_user_via_queue(
        &state,
        &session.jwt_token,
        &headers,
        &cid,
        Some(&key),
    )
    .await;

    Ok((
        StatusCode::OK,
        [("ETag", format!("\"{}\"", etag))],
        "",
    ).into_response())
}

/// W.9.6 — pin to the user's external pinning service via the
/// durable queue when configured, falling back to the legacy
/// `pin_for_user` (fire-and-forget) when the queue is `None`.
///
/// Uses the same [`PinningCredentials::from_jwt`] header extraction
/// as `pin_for_user` so the wire contract (which headers consult,
/// which endpoint, which token) stays identical across the two
/// paths. Only the dispatch differs: queue → durable + retry,
/// legacy → fire-and-forget.
async fn pin_for_user_via_queue(
    state: &Arc<AppState>,
    jwt: &str,
    headers: &HeaderMap,
    cid: &cid::Cid,
    object_key: Option<&str>,
) {
    let queue = match state.pin_queue.as_ref() {
        Some(q) => q,
        None => {
            // Legacy fire-and-forget — preserves v0.5 behavior for
            // tests + minimal dev configs. Production should set
            // `pin_queue_path` so this branch is never taken.
            pin_for_user(
                headers,
                cid,
                object_key,
                state.config.pinning_service_endpoint.as_deref(),
                Some(jwt),
            )
            .await;
            return;
        }
    };

    // Extract user credentials with the same logic `pin_for_user`
    // uses. When the user has no pinning configured (no headers, no
    // server default), we skip enqueueing — there is nothing to
    // dispatch.
    let endpoint = state.config.pinning_service_endpoint.as_deref();
    if jwt.is_empty() {
        return;
    }
    let creds = match endpoint {
        Some(ep) => crate::pinning::PinningCredentials::from_jwt(headers, jwt, ep),
        None => crate::pinning::PinningCredentials::from_headers(headers),
    };
    let creds = match creds {
        Some(c) => c,
        None => return,
    };

    // Enqueue. Failure here is best-effort — a redb commit failure
    // shouldn't fail the user's PUT, since the master-cluster pin
    // path covers DHT availability for this CID anyway.
    let pin_name = object_key
        .map(|s| s.to_string())
        .or_else(|| creds.name.clone());
    if let Err(e) = queue.enqueue(crate::pin_queue::PinRequest {
        cid: *cid,
        target: crate::pin_queue::PinTarget::UserExternal,
        kind: crate::pin_queue::PinKind::Add,
        pin_name,
        bearer_token: Some(creds.token.clone()),
        pinning_endpoint: Some(creds.endpoint.clone()),
    }) {
        tracing::warn!(
            cid = %cid,
            error = %e,
            "pin_queue enqueue (user-external) failed; pin not retained for retry"
        );
    } else {
        tracing::debug!(
            cid = %cid,
            endpoint = %creds.endpoint,
            "User-external pin enqueued for durable pin (W.9.6)"
        );
    }
}

/// GET /{bucket}/{key} - Get object with Range and conditional request support
pub async fn get_object(
    State(state): State<Arc<AppState>>,
    Extension(session): Extension<UserSession>,
    Path((bucket_name, key)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    if !session.can_read() {
        return Err(ApiError::s3(S3ErrorCode::AccessDenied, "Read access required"));
    }

    // User-scoped bucket access
    let bucket = state.bucket_manager.open_bucket_for_user(&session.hashed_user_id, &bucket_name).await?;

    let metadata = match bucket.get_object(&key).await {
        Ok(Some(m)) => m,
        // GC-recovery read-fallback. A GET can miss the gc-damaged index TWO
        // ways: (a) the index has no entry for the key (`Ok(None)`), or (b) the
        // prolly index itself lost an interior node to `ipfs repo gc`, so it
        // can't even read the entry and returns `Err(BlockStore(NotFound|
        // Unavailable))`. BOTH are recovery candidates — resolve the key→CID
        // from the cluster pinset mirror and serve the block. Healthy reads
        // return `Ok(Some(m))` above and never reach here; any non-miss error
        // (auth / infra / etc.) is propagated unchanged (codex: don't recover
        // on errors that aren't a genuine block-miss).
        other => {
            let is_index_miss = matches!(
                &other,
                Ok(None)
                    | Err(fula_core::CoreError::BlockStore(
                        BlockStoreError::NotFound(_) | BlockStoreError::Unavailable(_)
                    ))
            );
            if !is_index_miss {
                // Auth / infra / other — propagate unchanged, no recovery.
                return Err(other.unwrap_err().into());
            }
            // Server-side cluster-mirror fallback first.
            if let Some(rec) =
                crate::recovery_fallback::try_recover_block(&state, &bucket_name, &key).await
            {
                return Ok(recovery_block_response(rec.data, rec.cid, &headers));
            }
            // The gateway can't serve it (not in the cluster mirror) — but the
            // block may still be reachable BY CID via the CLIENT's forest hints
            // (Walkable-v8 `chunk_cids` / `storage_cid`). Return 404 NoSuchKey
            // (NOT 410 Gone) so the client's by-CID recovery
            // (`get_object_with_recovery_known_cid`) engages — it fires on a
            // reachable-master 404 and NEVER on 410, racing public IPFS for the
            // hinted CID. A genuinely-lost block then fails that race and
            // surfaces a hard error; a still-reachable one is recovered.
            return Err(ApiError::s3_with_resource(
                S3ErrorCode::NoSuchKey,
                "Object not found (gc-orphaned index; client recovers by CID)",
                format!("{}/{}", bucket_name, key),
            ));
        }
    };

    // Check delete marker
    if metadata.is_delete_marker {
        return Err(ApiError::s3_with_resource(
            S3ErrorCode::NoSuchKey,
            "Object is a delete marker",
            format!("{}/{}", bucket_name, key),
        ));
    }

    let mut etag = format!("\"{}\"", metadata.etag);
    let last_modified = metadata.last_modified;
    let last_modified_str = last_modified.format("%a, %d %b %Y %H:%M:%S GMT").to_string();

    // TEMPORARY DIAGNOSTIC for #29 — log the etag we return so we can
    // pair it with the `match_if_match diag` line on the next PUT for
    // the same key. If GET-time etag != PUT-time current, the
    // ObjectMetadata.etag is being mutated by a sibling-key write.
    tracing::warn!(
        bucket = %bucket_name,
        key = %key,
        etag = %metadata.etag,
        cid = %metadata.cid,
        "GET diag: returning etag"
    );

    // Handle If-None-Match (304 Not Modified)
    if let Some(if_none_match) = headers.get("If-None-Match").and_then(|v| v.to_str().ok()) {
        if if_none_match == etag || if_none_match == "*" {
            return Ok(Response::builder()
                .status(StatusCode::NOT_MODIFIED)
                .header("ETag", &etag)
                .header("Last-Modified", &last_modified_str)
                .body(Body::empty())
                .unwrap());
        }
    }

    // Handle If-Modified-Since (304 Not Modified)
    if let Some(if_modified_since) = headers.get("If-Modified-Since").and_then(|v| v.to_str().ok()) {
        if let Ok(since) = chrono::DateTime::parse_from_rfc2822(if_modified_since) {
            if last_modified <= since.with_timezone(&chrono::Utc) {
                return Ok(Response::builder()
                    .status(StatusCode::NOT_MODIFIED)
                    .header("ETag", &etag)
                    .header("Last-Modified", &last_modified_str)
                    .body(Body::empty())
                    .unwrap());
            }
        }
    }

    // Retrieve data from block store. If the index points at a gc'd CID, the
    // block store returns the NARROW miss errors `NotFound`/`Unavailable` (NOT
    // infra errors like Timeout/Connection) — only those trigger the GC-recovery
    // read-fallback, which re-resolves the CURRENT CID from the cluster mirror
    // and serves it. On recovery, the served ETag becomes that CID (never the
    // stale index ETag). Any other error is propagated unchanged.
    let data = match state.block_store.get_block(&metadata.cid).await {
        Ok(d) => d,
        Err(BlockStoreError::NotFound(_) | BlockStoreError::Unavailable(_)) => {
            match crate::recovery_fallback::try_recover_block(&state, &bucket_name, &key).await {
                Some(rec) => {
                    etag = format!("\"{}\"", rec.cid);
                    rec.data
                }
                // Mirror can't serve it — hand off to the client's by-CID
                // recovery with a 404 (not 410), same as the index-miss path
                // above: the block may still be reachable by its hinted CID.
                None => {
                    return Err(ApiError::s3_with_resource(
                        S3ErrorCode::NoSuchKey,
                        "Object not found (gc-orphaned block; client recovers by CID)",
                        format!("{}/{}", bucket_name, key),
                    ))
                }
            }
        }
        Err(e) => return Err(e.into()),
    };
    let total_size = data.len();

    // Handle Range request
    let range_header = headers.get("Range").and_then(|v| v.to_str().ok());
    let (status, body_data, content_range) = if let Some(range) = range_header {
        match parse_range_header(range, total_size) {
            Ok((start, end)) => {
                let content_range = format!("bytes {}-{}/{}", start, end, total_size);
                let slice = data.slice(start..=end);
                (StatusCode::PARTIAL_CONTENT, slice, Some(content_range))
            }
            Err(_) => {
                return Err(ApiError::s3(
                    S3ErrorCode::InvalidRange,
                    "Requested range not satisfiable",
                ));
            }
        }
    } else {
        (StatusCode::OK, data, None)
    };

    // Build response headers
    let mut response = Response::builder()
        .status(status)
        .header("ETag", &etag)
        .header("Content-Length", body_data.len().to_string())
        .header("Last-Modified", &last_modified_str)
        .header("Accept-Ranges", "bytes");

    if let Some(range) = content_range {
        response = response.header("Content-Range", range);
    }

    if let Some(ref ct) = metadata.content_type {
        response = response.header("Content-Type", ct);
    }

    if let Some(ref cc) = metadata.cache_control {
        response = response.header("Cache-Control", cc);
    }

    if let Some(ref cd) = metadata.content_disposition {
        response = response.header("Content-Disposition", cd);
    }

    if let Some(ref ce) = metadata.content_encoding {
        response = response.header("Content-Encoding", ce);
    }

    // Add user metadata
    for (k, v) in &metadata.user_metadata {
        response = response.header(format!("x-amz-meta-{}", k), v);
    }

    // Add version ID if present
    if let Some(ref version_id) = metadata.version_id {
        response = response.header("x-amz-version-id", version_id);
    }

    Ok(response.body(Body::from(body_data)).unwrap())
}

/// Build the response for a block recovered via the GC read-fallback when the
/// index had NO metadata for the key (the index-miss case). The `ETag` is the
/// served CID (never a stale index ETag); a `Range` request is honored against
/// the recovered bytes; no `Content-Type`/user-metadata is claimed since the
/// index entry that carried them is gone.
fn recovery_block_response(
    data: Bytes,
    cid: impl std::fmt::Display,
    req_headers: &HeaderMap,
) -> Response {
    let etag = format!("\"{}\"", cid);
    let total = data.len();
    let (status, body, content_range) = match req_headers
        .get("Range")
        .and_then(|v| v.to_str().ok())
        .and_then(|r| parse_range_header(r, total).ok())
    {
        Some((start, end)) => (
            StatusCode::PARTIAL_CONTENT,
            data.slice(start..=end),
            Some(format!("bytes {}-{}/{}", start, end, total)),
        ),
        None => (StatusCode::OK, data, None),
    };
    let mut resp = Response::builder()
        .status(status)
        .header("ETag", &etag)
        .header("Content-Length", body.len().to_string())
        .header("Accept-Ranges", "bytes");
    if let Some(cr) = content_range {
        resp = resp.header("Content-Range", cr);
    }
    resp.body(Body::from(body)).unwrap()
}

/// Attempt to decode HTTP chunked transfer encoding from a request body.
/// Returns Some(decoded) if the body was chunked-encoded, None otherwise.
///
/// This handles two cases:
/// 1. AWS `Content-Encoding: aws-chunked` with streaming SigV4 signatures
/// 2. Plain HTTP chunked TE where a reverse proxy stripped the Transfer-Encoding header
pub(crate) fn try_decode_chunked(headers: &HeaderMap, body: &Bytes) -> Option<Bytes> {
    let has_decoded_len = headers.get("x-amz-decoded-content-length").is_some();
    let has_aws_chunked = headers
        .get(header::CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.contains("aws-chunked"))
        .unwrap_or(false);

    if !has_decoded_len && !has_aws_chunked && !looks_like_chunked(body) {
        return None;
    }

    decode_chunked_body(body).map(|decoded| {
        tracing::info!(
            original_len = body.len(),
            decoded_len = decoded.len(),
            has_decoded_len,
            has_aws_chunked,
            "Decoded chunked request body"
        );
        decoded
    })
}

/// Check if a body appears to be HTTP chunked transfer-encoded.
fn looks_like_chunked(body: &[u8]) -> bool {
    if body.len() < 4 {
        return false;
    }

    // Find first \r\n (chunk-size line delimiter)
    let crlf_pos = match body.windows(2).position(|w| w == b"\r\n") {
        Some(pos) if pos > 0 && pos <= 100 => pos,
        _ => return false,
    };

    // Extract hex size (before any chunk extensions like ";chunk-signature=...")
    let size_line = match std::str::from_utf8(&body[..crlf_pos]) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let size_hex = size_line.split(';').next().unwrap_or("");

    let chunk_size = match usize::from_str_radix(size_hex.trim(), 16) {
        Ok(s) if s > 0 => s,
        _ => return false,
    };

    // Chunk data must fit within the remaining body
    let data_start = crlf_pos + 2;
    chunk_size <= body.len().saturating_sub(data_start)
}

/// Decode HTTP chunked transfer encoding from raw bytes.
/// Handles both plain chunked and aws-chunked (ignoring chunk extensions).
fn decode_chunked_body(body: &[u8]) -> Option<Bytes> {
    let mut decoded = Vec::new();
    let mut pos = 0;

    while pos < body.len() {
        let remaining = &body[pos..];

        // Find the \r\n ending the chunk-size line
        let crlf_pos = remaining.windows(2).position(|w| w == b"\r\n")?;

        if crlf_pos == 0 {
            // Empty line — skip
            pos += 2;
            continue;
        }

        // Parse chunk size (ignore extensions after ';')
        let size_line = std::str::from_utf8(&remaining[..crlf_pos]).ok()?;
        let size_hex = size_line.split(';').next()?;
        let chunk_size = usize::from_str_radix(size_hex.trim(), 16).ok()?;

        if chunk_size == 0 {
            break; // Terminal chunk
        }

        let data_start = pos + crlf_pos + 2;
        let data_end = data_start + chunk_size;

        if data_end > body.len() {
            return None; // Truncated — probably not chunked after all
        }

        decoded.extend_from_slice(&body[data_start..data_end]);

        // Skip the \r\n after chunk data
        pos = data_end;
        if pos + 2 <= body.len() && body[pos] == b'\r' && body[pos + 1] == b'\n' {
            pos += 2;
        }
    }

    if decoded.is_empty() {
        None
    } else {
        Some(Bytes::from(decoded))
    }
}

/// Parse Range header (e.g., "bytes=0-1023" or "bytes=500-" or "bytes=-500")
fn parse_range_header(range: &str, total_size: usize) -> Result<(usize, usize), ()> {
    let range = range.strip_prefix("bytes=").ok_or(())?;
    
    if let Some((start_str, end_str)) = range.split_once('-') {
        if start_str.is_empty() {
            // Suffix range: bytes=-500 means last 500 bytes
            let suffix_len: usize = end_str.parse().map_err(|_| ())?;
            let start = total_size.saturating_sub(suffix_len);
            Ok((start, total_size - 1))
        } else if end_str.is_empty() {
            // Range from start to end: bytes=500-
            let start: usize = start_str.parse().map_err(|_| ())?;
            if start >= total_size {
                return Err(());
            }
            Ok((start, total_size - 1))
        } else {
            // Normal range: bytes=0-1023
            let start: usize = start_str.parse().map_err(|_| ())?;
            let end: usize = end_str.parse().map_err(|_| ())?;
            if start > end || start >= total_size {
                return Err(());
            }
            Ok((start, end.min(total_size - 1)))
        }
    } else {
        Err(())
    }
}

/// HEAD /{bucket}/{key} - Head object
pub async fn head_object(
    State(state): State<Arc<AppState>>,
    Extension(session): Extension<UserSession>,
    Path((bucket_name, key)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    if !session.can_read() {
        return Err(ApiError::s3(S3ErrorCode::AccessDenied, "Read access required"));
    }

    // User-scoped bucket access
    let bucket = state.bucket_manager.open_bucket_for_user(&session.hashed_user_id, &bucket_name).await?;

    let metadata = bucket.get_object(&key).await?
        .ok_or_else(|| ApiError::s3_with_resource(
            S3ErrorCode::NoSuchKey,
            "Object not found",
            format!("{}/{}", bucket_name, key),
        ))?;

    let mut response = Response::builder()
        .status(StatusCode::OK)
        .header("ETag", format!("\"{}\"", metadata.etag))
        .header("Content-Length", metadata.size.to_string())
        .header("Last-Modified", metadata.last_modified.format("%a, %d %b %Y %H:%M:%S GMT").to_string());

    if let Some(ref ct) = metadata.content_type {
        response = response.header("Content-Type", ct);
    }

    // Add user metadata
    for (k, v) in &metadata.user_metadata {
        response = response.header(format!("x-amz-meta-{}", k), v);
    }

    Ok(response.body(Body::empty()).unwrap())
}

/// DELETE /{bucket}/{key} - Delete object
pub async fn delete_object(
    State(state): State<Arc<AppState>>,
    Extension(session): Extension<UserSession>,
    Path((bucket_name, key)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    if !session.can_write() {
        return Err(ApiError::s3(S3ErrorCode::AccessDenied, "Write access required"));
    }

    // Serialize same-bucket index mutations (see `put_object` for rationale).
    let _bucket_guard = state
        .bucket_manager
        .bucket_write_lock(&session.hashed_user_id, &bucket_name)
        .lock_owned()
        .await;

    // User-scoped bucket access
    let mut bucket = state.bucket_manager.open_bucket_for_user(&session.hashed_user_id, &bucket_name).await?;

    // Capture the removed metadata so we can unpin the CID after the index
    // is successfully updated. Must unpin AFTER persist — if persist fails
    // and we've already unpinned, the data is gone but the index still
    // references it on next start (recoverable on re-upload, but bad UX).
    let removed = bucket.delete_object(&key).await?;
    bucket.flush().await?;

    // Persist the bucket registry so the updated root CID survives restarts.
    // This MUST succeed — otherwise the delete is lost on restart.
    state.bucket_manager.persist_registry_with_token(&session.jwt_token).await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to persist bucket registry after delete_object — change may be lost on restart");
            ApiError::s3(S3ErrorCode::InternalError, "Failed to persist storage index. Please retry.")
        })?;

    // Best-effort IPFS unpin (F-NEW). Must be refcount-safe: if any other key
    // in this bucket still references the same CID (client-side dedup, or two
    // keys coincidentally mapped to the same content), skip the unpin to avoid
    // losing pins for still-referenced data.
    //
    // Cross-bucket refcount is not checked here: each bucket's pinning is
    // scoped to its own index, and the pinning service tracks pins by
    // request_id — unpinning one bucket's pin does not affect other buckets'
    // pins of the same CID, since each was added as a separate pin.
    if let Some(removed_meta) = removed {
        let cid = removed_meta.cid;
        let still_referenced = match bucket
            .list_objects(None, None, None, None)
            .await
        {
            Ok(result) => result.objects.iter().any(|o| o.metadata.cid == cid),
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    cid = %cid,
                    "Could not enumerate bucket to refcount-check CID; skipping unpin conservatively"
                );
                true
            }
        };

        if !still_referenced {
            // Master-local unpin: stays sync best-effort. The failure
            // mode is "kubo briefly down"; the next user write
            // re-aligns state via the bucket-root pin queue. Per
            // #66's minimal-scope advisor brief: route only the
            // user-external unpin through the queue, not this one.
            if let Err(e) = state.block_store.unpin(&cid).await {
                tracing::warn!(
                    cid = %cid,
                    error = %e,
                    "Failed to unpin from local IPFS (best-effort)"
                );
            }

            // **#66 (2026-05-09)** — durable user-external unpin via
            // the pin queue. Replaces the prior fire-and-forget
            // `unpin_for_user(...)` which lost unpin requests on
            // master crash and silently leaked pin slots on the
            // user's pinning service. Pin/unpin "latest intent
            // wins" semantics handle the upload→delete→re-upload
            // race (the queue collapses both into one record per
            // (cid, target) and dispatches the most recent intent).
            //
            // Falls back to legacy fire-and-forget when the queue
            // isn't configured (tests + minimal dev), matching the
            // pin path's handling at object.rs:461-476.
            if !session.jwt_token.is_empty() {
                if let Some(queue) = state.pin_queue.as_ref() {
                    let creds = match state.config.pinning_service_endpoint.as_deref() {
                        Some(ep) => crate::pinning::PinningCredentials::from_jwt(
                            &headers,
                            &session.jwt_token,
                            ep,
                        ),
                        None => crate::pinning::PinningCredentials::from_headers(&headers),
                    };
                    if let Some(creds) = creds {
                        if let Err(e) = queue.enqueue(crate::pin_queue::PinRequest {
                            cid,
                            target: crate::pin_queue::PinTarget::UserExternal,
                            kind: crate::pin_queue::PinKind::Remove,
                            pin_name: None, // unpin doesn't need a label
                            bearer_token: Some(creds.token.clone()),
                            pinning_endpoint: Some(creds.endpoint.clone()),
                        }) {
                            tracing::warn!(
                                cid = %cid,
                                error = %e,
                                "pin_queue enqueue (user-external unpin) failed; falling back to fire-and-forget"
                            );
                            unpin_for_user(
                                &headers,
                                &cid,
                                state.config.pinning_service_endpoint.as_deref(),
                                Some(&session.jwt_token),
                            )
                            .await;
                        }
                    }
                } else {
                    unpin_for_user(
                        &headers,
                        &cid,
                        state.config.pinning_service_endpoint.as_deref(),
                        Some(&session.jwt_token),
                    )
                    .await;
                }
            }
        } else {
            tracing::debug!(
                cid = %cid,
                bucket = %bucket_name,
                "Skipping unpin — CID still referenced by another key in the bucket"
            );
        }
    }

    Ok(StatusCode::NO_CONTENT.into_response())
}

/// Copy source header
#[derive(Debug, Deserialize)]
pub struct CopyParams {
    #[serde(rename = "x-amz-copy-source")]
    pub copy_source: Option<String>,
}

/// PUT /{bucket}/{key} with x-amz-copy-source - Copy object
pub async fn copy_object(
    State(state): State<Arc<AppState>>,
    Extension(session): Extension<UserSession>,
    Path((dest_bucket, dest_key)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    if !session.can_write() {
        return Err(ApiError::s3(S3ErrorCode::AccessDenied, "Write access required"));
    }

    let copy_source = headers
        .get("x-amz-copy-source")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| ApiError::s3(S3ErrorCode::InvalidArgument, "Missing x-amz-copy-source"))?;

    // Parse source bucket/key
    let source_path = copy_source.trim_start_matches('/');
    let (source_bucket, source_key) = source_path
        .split_once('/')
        .ok_or_else(|| ApiError::s3(S3ErrorCode::InvalidArgument, "Invalid copy source format"))?;

    // Get source object (user-scoped). Read-only, so no write lock needed here.
    let source_bucket_handle = state.bucket_manager.open_bucket_for_user(&session.hashed_user_id, source_bucket).await?;

    let source_metadata = source_bucket_handle.get_object(source_key).await?
        .ok_or_else(|| ApiError::s3_with_resource(
            S3ErrorCode::NoSuchKey,
            "Source object not found",
            copy_source,
        ))?;
    drop(source_bucket_handle);

    // Copy to destination (user-scoped)
    let mut dest_metadata = source_metadata.clone();
    dest_metadata.last_modified = chrono::Utc::now();
    dest_metadata.owner_id = Some(session.hashed_user_id.clone());

    // Serialize same-bucket index mutations on the destination (see
    // `put_object` for rationale). Acquired after the source read so a copy
    // within the same bucket can still proceed without the reader holding
    // its own handle through the write.
    let _bucket_guard = state
        .bucket_manager
        .bucket_write_lock(&session.hashed_user_id, &dest_bucket)
        .lock_owned()
        .await;

    let mut dest_bucket_handle = state.bucket_manager.open_bucket_for_user(&session.hashed_user_id, &dest_bucket).await?;

    dest_bucket_handle.put_object(dest_key, dest_metadata.clone()).await?;
    dest_bucket_handle.flush().await?;

    // Persist the bucket registry so the updated root CID survives restarts.
    // This MUST succeed — otherwise the copy is lost on restart.
    state.bucket_manager.persist_registry_with_token(&session.jwt_token).await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to persist bucket registry after copy_object — change may be lost on restart");
            ApiError::s3(S3ErrorCode::InternalError, "Failed to persist storage index. Please retry.")
        })?;

    let xml_response = xml::copy_object_result(
        dest_metadata.last_modified,
        &dest_metadata.etag,
    );

    Ok((
        StatusCode::OK,
        [("Content-Type", "application/xml")],
        xml_response,
    ).into_response())
}

// ============================================================================
// RFC 7232 conditional-write helpers (If-Match / If-None-Match)
// ============================================================================
//
// S3 subset: strong ETags only. Weak validators (`W/"..."`) are rejected.
// Stored ETags are un-quoted CID strings (see ObjectMetadata::new); client
// sends quoted values, so parse_etag_list strips quotes before comparison.

/// RFC 7232 §3.1. True iff the If-Match precondition is satisfied.
pub(crate) fn match_if_match(header: &str, current: Option<&str>) -> bool {
    let h = header.trim();
    let result = if h == "*" {
        current.is_some()
    } else {
        match current {
            Some(cur) => parse_etag_list(h).any(|t| t == cur),
            None => false,
        }
    };
    // TEMPORARY DIAGNOSTIC for #29 — emits exactly what's compared on every
    // If-Match check. Remove once duplicate-bucket / 412-loop is closed.
    tracing::warn!(
        if_match = %h,
        current = ?current,
        result,
        "match_if_match diag"
    );
    result
}

/// RFC 7232 §3.2. True iff the If-None-Match precondition is satisfied.
pub(crate) fn match_if_none_match(header: &str, current: Option<&str>) -> bool {
    let h = header.trim();
    if h == "*" {
        return current.is_none();
    }
    let Some(cur) = current else { return true; };
    !parse_etag_list(h).any(|t| t == cur)
}

/// Parse a comma-separated list of strong quoted ETags. Weak validators
/// (`W/"..."`) and unquoted tokens are silently skipped.
fn parse_etag_list(s: &str) -> impl Iterator<Item = String> + '_ {
    s.split(',').filter_map(|tok| {
        let t = tok.trim();
        if t.starts_with("W/") || t.starts_with("w/") {
            return None;
        }
        let t = t.strip_prefix('"')?.strip_suffix('"')?;
        Some(t.to_string())
    })
}

// ============================================================
// Phase 1.2 wire-path helpers (master-side)
// ============================================================
//
// These are extracted out of the put_object handler so the
// header-parsing + control-header-filter logic can be unit-tested
// without spinning up the full HTTP server stack. Audit follow-up
// item #5: cover the wire path beyond the BucketManager-direct
// integration test in users_index_publisher.rs.

/// Internal Fula control headers (consumed by handler logic, NOT
/// persisted as object metadata). The list is `pub(crate)` so it
/// can be referenced from sibling modules; tests below assert it
/// stays in lockstep with the handler's filtering.
pub(crate) const FULA_CONTROL_HEADERS: &[&str] = &[
    "fula-bucket-lookup-h",
    // v0.4.4: sentinel header that says "this PUT is the SDK's
    // encrypted forest manifest". Consumed by the put_object handler
    // to populate `BucketMetadata.forest_manifest_cid`; never stored
    // as user_metadata on the object itself (would pollute every
    // forest-manifest object with a meaningless `=1` tag).
    "fula-forest-manifest",
    // Phase 2 (decentralized ingress): remote-cid mapping PUT controls —
    // consumed by the handler (declared CID + true byte size of the chunk
    // stored on the ingest node); never persisted as object metadata.
    "fula-remote-cid",
    "fula-remote-size",
];

/// Returns `true` if the given x-amz-meta key (already stripped of
/// the `x-amz-meta-` prefix) is a Fula control header — meaning it
/// should NOT end up in `ObjectMetadata.user_metadata` even though
/// it's a perfectly valid `x-amz-meta-*` name.
pub(crate) fn is_fula_control_header(stripped_key: &str) -> bool {
    FULA_CONTROL_HEADERS.contains(&stripped_key)
}

/// Parse error for the `x-amz-meta-fula-bucket-lookup-h` header
/// value. Three failure modes today; expanding this enum is
/// backward-compatible (the handler matches exhaustively).
#[derive(Debug)]
pub(crate) enum BucketLookupHError {
    /// hex::decode failed — non-hex characters in the value.
    InvalidHex(hex::FromHexError),
    /// Decoded byte length wasn't 16 (the only legal width per
    /// Phase 1.2 spec — `userKey`-equivalent 128-bit blinded key).
    WrongLength { actual: usize },
}

impl From<hex::FromHexError> for BucketLookupHError {
    fn from(e: hex::FromHexError) -> Self {
        BucketLookupHError::InvalidHex(e)
    }
}

/// Parse `x-amz-meta-fula-bucket-lookup-h` header value into a
/// 16-byte fixed array. Pure: no I/O, no allocations beyond the
/// transient hex::decode buffer. Used by `put_object` to convert
/// the wire-format string into the format
/// `BucketManager::populate_bucket_lookup_h` expects.
pub(crate) fn parse_bucket_lookup_h_header(
    hex_str: &str,
) -> Result<[u8; 16], BucketLookupHError> {
    let bytes = hex::decode(hex_str)?;
    if bytes.len() != 16 {
        return Err(BucketLookupHError::WrongLength { actual: bytes.len() });
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[cfg(test)]
mod phase_1_2_wire_tests {
    //! Phase 1.2 wire-path tests. Covers what the existing
    //! `users_index_publisher::test_run_tick_legacy_to_blinded_replaces_entry`
    //! test does NOT cover: the HTTP-layer header extraction +
    //! parsing logic that sits between an SDK request and a
    //! `populate_bucket_lookup_h` call.

    use super::*;
    use axum::http::{HeaderMap, HeaderName, HeaderValue};

    #[test]
    fn control_header_filter_includes_lookup_h() {
        // Audit gold: the lookup_h header IS recognized as a control
        // header. If someone removes it from FULA_CONTROL_HEADERS the
        // header would leak into user_metadata storage on every PUT.
        assert!(is_fula_control_header("fula-bucket-lookup-h"));
    }

    #[test]
    fn control_header_filter_excludes_arbitrary_user_metadata() {
        // Defensive: an app's own metadata keys must NOT be filtered.
        assert!(!is_fula_control_header("content-language"));
        assert!(!is_fula_control_header("x-fula-encrypted"));
        assert!(!is_fula_control_header(""));
    }

    #[test]
    fn parse_lookup_h_accepts_valid_32_char_hex() {
        // Mirrors what `compute_bucket_lookup_h_hex` produces in the
        // SDK: 32 lowercase hex chars = 16 bytes.
        let valid = "deadbeefcafebabefeedfacef00dbabe";
        let parsed = parse_bucket_lookup_h_header(valid).expect("valid 32-char hex");
        assert_eq!(parsed.len(), 16);
        assert_eq!(parsed[0], 0xde);
        assert_eq!(parsed[15], 0xbe);
    }

    #[test]
    fn parse_lookup_h_accepts_uppercase_hex() {
        // hex::decode is case-insensitive; we don't normalize.
        let valid = "DEADBEEFCAFEBABEFEEDFACEF00DBABE";
        let parsed = parse_bucket_lookup_h_header(valid).expect("uppercase ok");
        assert_eq!(parsed[0], 0xde);
    }

    #[test]
    fn parse_lookup_h_rejects_too_short() {
        // 30 hex chars = 15 bytes — one short.
        let too_short = "deadbeefcafebabefeedfacef00dba";
        match parse_bucket_lookup_h_header(too_short) {
            Err(BucketLookupHError::WrongLength { actual: 15 }) => {}
            other => panic!("expected WrongLength{{actual:15}}, got {:?}", other),
        }
    }

    #[test]
    fn parse_lookup_h_rejects_too_long() {
        // 34 hex chars = 17 bytes — one byte over.
        let too_long = "deadbeefcafebabefeedfacef00dbabe11";
        match parse_bucket_lookup_h_header(too_long) {
            Err(BucketLookupHError::WrongLength { actual: 17 }) => {}
            other => panic!("expected WrongLength{{actual:17}}, got {:?}", other),
        }
    }

    #[test]
    fn parse_lookup_h_rejects_non_hex_chars() {
        // 'z' is not a valid hex char; even at correct length this
        // fails with InvalidHex.
        let bad_chars = "zzadbeefcafebabefeedfacef00dbabe";
        match parse_bucket_lookup_h_header(bad_chars) {
            Err(BucketLookupHError::InvalidHex(_)) => {}
            other => panic!("expected InvalidHex, got {:?}", other),
        }
    }

    #[test]
    fn parse_lookup_h_rejects_empty_string() {
        // An empty header value reaches us as "" — must not parse
        // to a zero-byte array.
        match parse_bucket_lookup_h_header("") {
            Err(BucketLookupHError::WrongLength { actual: 0 }) => {}
            other => panic!("expected WrongLength{{actual:0}}, got {:?}", other),
        }
    }

    #[test]
    fn parse_lookup_h_rejects_odd_length_hex() {
        // 31 chars — odd-length is invalid per hex spec; hex::decode
        // returns OddLength, which we surface as InvalidHex.
        let odd = "deadbeefcafebabefeedfacef00dbab";
        match parse_bucket_lookup_h_header(odd) {
            Err(BucketLookupHError::InvalidHex(_)) => {}
            other => panic!("expected InvalidHex (odd length), got {:?}", other),
        }
    }

    /// End-to-end-ish wire-path simulation: from a real `HeaderMap`
    /// (as the put_object handler would receive), extract:
    /// - the user_metadata that should be persisted (lookup_h MUST
    ///   NOT appear there)
    /// - the parsed lookup_h bytes (MUST equal what the SDK sent)
    ///
    /// This is the critical regression guard for "old client uploads
    /// without header → no populate" vs "new client uploads with
    /// header → populate fires with correct bytes". The integration
    /// with `BucketManager` and the publisher is already covered by
    /// `users_index_publisher::test_run_tick_legacy_to_blinded_replaces_entry`.
    #[test]
    fn old_client_no_header_means_no_populate() {
        let mut headers = HeaderMap::new();
        // Old client sends content-type and a user metadata key; no
        // lookup_h header.
        headers.insert(
            HeaderName::from_static("content-type"),
            HeaderValue::from_static("image/jpeg"),
        );
        headers.insert(
            HeaderName::from_static("x-amz-meta-myapp-tag"),
            HeaderValue::from_static("vacation"),
        );

        // Wire-path step 1: lookup_h header absent → handler skips populate.
        let lookup_h_present = headers.get("x-amz-meta-fula-bucket-lookup-h").is_some();
        assert!(!lookup_h_present, "no header on old-client PUT");

        // Wire-path step 2: user_metadata extraction filters control
        // headers (none to filter here, but the loop must include the
        // app's own tag).
        let mut user_meta: Vec<(String, String)> = Vec::new();
        for (name, value) in headers.iter() {
            if let Some(key) = name.as_str().strip_prefix("x-amz-meta-") {
                if is_fula_control_header(key) {
                    continue;
                }
                if let Ok(v) = value.to_str() {
                    user_meta.push((key.to_string(), v.to_string()));
                }
            }
        }
        assert_eq!(user_meta, vec![("myapp-tag".to_string(), "vacation".to_string())]);
    }

    #[test]
    fn new_client_header_parses_and_does_not_leak_into_user_metadata() {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("content-type"),
            HeaderValue::from_static("image/jpeg"),
        );
        headers.insert(
            HeaderName::from_static("x-amz-meta-fula-bucket-lookup-h"),
            HeaderValue::from_static("aabbccddeeff00112233445566778899"),
        );
        headers.insert(
            HeaderName::from_static("x-amz-meta-myapp-tag"),
            HeaderValue::from_static("vacation"),
        );

        // Wire-path step 1: lookup_h header parses to expected bytes.
        let hex_str = headers
            .get("x-amz-meta-fula-bucket-lookup-h")
            .and_then(|v| v.to_str().ok())
            .expect("present");
        let parsed = parse_bucket_lookup_h_header(hex_str).expect("valid hex");
        assert_eq!(parsed, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
                            0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99]);

        // Wire-path step 2: user_metadata extraction MUST drop the
        // lookup_h header and keep the app's own tag.
        let mut user_meta: Vec<(String, String)> = Vec::new();
        for (name, value) in headers.iter() {
            if let Some(key) = name.as_str().strip_prefix("x-amz-meta-") {
                if is_fula_control_header(key) {
                    continue;
                }
                if let Ok(v) = value.to_str() {
                    user_meta.push((key.to_string(), v.to_string()));
                }
            }
        }
        assert_eq!(
            user_meta,
            vec![("myapp-tag".to_string(), "vacation".to_string())],
            "lookup_h header must NOT leak into user_metadata"
        );
    }
}

#[cfg(test)]
mod conditional_tests {
    use super::{match_if_match, match_if_none_match};

    #[test]
    fn if_match_star_requires_existing() {
        assert!(match_if_match("*", Some("abc")));
        assert!(!match_if_match("*", None));
    }

    #[test]
    fn if_none_match_star_requires_absent() {
        assert!(!match_if_none_match("*", Some("abc")));
        assert!(match_if_none_match("*", None));
    }

    #[test]
    fn if_match_single_tag() {
        assert!(match_if_match("\"abc\"", Some("abc")));
        assert!(!match_if_match("\"abc\"", Some("xyz")));
        assert!(!match_if_match("\"abc\"", None));
    }

    #[test]
    fn if_none_match_single_tag() {
        assert!(!match_if_none_match("\"abc\"", Some("abc")));
        assert!(match_if_none_match("\"abc\"", Some("xyz")));
        assert!(match_if_none_match("\"abc\"", None));
    }

    #[test]
    fn etag_list_any_matches() {
        assert!(match_if_match("\"a\", \"b\"", Some("b")));
        assert!(!match_if_match("\"a\", \"b\"", Some("c")));
        assert!(!match_if_none_match("\"a\", \"b\"", Some("a")));
    }

    #[test]
    fn weak_etag_rejected() {
        // Weak validators are filtered out — neither If-Match nor If-None-Match
        // can satisfy against them.
        assert!(!match_if_match("W/\"abc\"", Some("abc")));
        // If-None-Match with no valid tags in list vs an existing etag:
        // parse_etag_list returns empty, so .any() is false, so !false = true.
        assert!(match_if_none_match("W/\"abc\"", Some("abc")));
    }

    #[test]
    fn empty_or_whitespace_header() {
        assert!(!match_if_match("", Some("abc")));
        assert!(match_if_none_match("", Some("abc")));
        assert!(!match_if_match("   ", Some("abc")));
    }

    #[test]
    fn handles_surrounding_whitespace_in_list() {
        assert!(match_if_match("  \"x\"  ,  \"y\"  ", Some("y")));
    }
}
