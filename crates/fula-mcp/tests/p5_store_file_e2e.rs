//! Phase 5 — GATED live e2e of the `store_file` operation (the scoped write).
//!
//! This is the live-gateway counterpart to the offline tests in
//! `src/store.rs`. It exercises the full store→share→owner-read loop over the
//! REAL wire format, for BOTH a small single-block file and a large chunked
//! (>768 KB) file (the chunked case is the one nothing else in the suite
//! previously proved end-to-end through `store_file`):
//!
//!   1. Build a [`CapabilityBundle`] from a DEDICATED, random workspace secret
//!      (NOT the user's master key) + the test creds' `FULA_JWT` / `FULA_S3`,
//!      granting `ai/` read-write, with a SEPARATE freshly-generated "owner"
//!      keypair (the bundle holds only the owner's PUBLIC key).
//!   2. Call [`fula_mcp::store::store_file`] to write a unique blob into a
//!      disposable workspace bucket. This runs the real path: classify → build
//!      the `ai/<category>/<uuid>-<name>` key → `assert_in_scope` → encrypted
//!      `put_object_flat` → recover the per-file DEK from the object's own
//!      metadata → mint the owner share.
//!   3. As the OWNER (the separate keypair), `accept_share` the returned
//!      [`StoreOutcome::owner_share`] to recover the DEK + nonce / chunked
//!      metadata, then read the bytes back byte-identically via
//!      `get_object_with_share` and clean up.
//!
//! Why the byte read uses the workspace client: `get_object_with_share`
//! resolves the object by `storage_key`, but the underlying S3 GET is still
//! scoped by the caller's JWT to the caller's own buckets. To keep this test
//! SELF-CONTAINED (no dependency on the production cross-account share proxy) we
//! isolate exactly the P5 question — "does store_file produce an object the
//! OWNER's minted share can decrypt over the live format?" — by issuing the
//! share-read from the workspace client. The owner-side crypto (accept_share →
//! DEK) is identical to a cross-account read; only the byte fetch's JWT differs.
//! This mirrors `tests/p2_shared_scope_write_e2e.rs`.
//!
//! Double-gated so a plain `cargo test` stays green OFFLINE:
//!   1. `#[ignore]` — excluded from a normal run; needs `-- --ignored`.
//!   2. `FULA_E2E=1` — even under `--ignored`, the body is a no-op unless set.
//!
//! Credentials: the operator's local creds file (NOT committed), default
//! `C:\Users\ehsan\.claude\cache\e2e-credentials.env`, override via
//! `FULA_E2E_CREDS`. Dedicated test accounts, treated as production: writes only
//! into a unique disposable bucket and always cleans up.

use std::collections::HashMap;

use base64::Engine as _;
use bytes::Bytes;
use fula_crypto::{KekKeyPair, SecretKey, ShareRecipient};
use fula_mcp::capability::CapabilityBundle;
use fula_mcp::store::{store_file, WORKSPACE_BUCKET};
use rand::RngCore;

const DEFAULT_CREDS_PATH: &str = r"C:\Users\ehsan\.claude\cache\e2e-credentials.env";

/// Minimal `.env` parser (same shape as the P1/P2 e2e tests).
fn parse_env_file(contents: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for raw in contents.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim().to_string();
        let value = value.trim().trim_matches('"').trim_matches('\'').to_string();
        if !key.is_empty() {
            map.insert(key, value);
        }
    }
    map
}

fn cred(creds: &HashMap<String, String>, key: &str) -> Option<String> {
    creds
        .get(key)
        .cloned()
        .or_else(|| std::env::var(key).ok())
        .filter(|v| !v.is_empty())
}

/// Build the capability-bundle JSON from a random workspace secret + a random
/// MCP secret + the given owner public key + creds, granting `ai/` read-write.
fn bundle_json(endpoint: &str, jwt: &str, owner_public_b64: &str, timeout_secs: u64) -> String {
    let mut ws = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut ws);
    let mut mcp = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut mcp);
    let ws_b64 = base64::engine::general_purpose::STANDARD.encode(ws);
    let mcp_b64 = base64::engine::general_purpose::STANDARD.encode(mcp);
    format!(
        r#"{{
          "endpoint": {endpoint:?},
          "jwt": {jwt:?},
          "workspace_secret_b64": "{ws_b64}",
          "mcp_secret_b64": "{mcp_b64}",
          "owner_public_b64": "{owner_public_b64}",
          "timeout_secs": {timeout_secs},
          "grants": [
            {{ "scope": "ai/", "permissions": {{ "can_read": true, "can_write": true, "can_delete": true }} }}
          ]
        }}"#
    )
}

#[tokio::test]
#[ignore = "hits a live Fula gateway; run with FULA_E2E=1 and `-- --ignored`"]
async fn e2e_store_file_owner_reads_back_single_and_chunked() {
    // ---- Gate 2: opt-in even under --ignored ------------------------------
    if std::env::var("FULA_E2E").as_deref() != Ok("1") {
        eprintln!("FULA_E2E != 1 — skipping live P5 store_file e2e (expected offline).");
        return;
    }

    // ---- Load credentials -------------------------------------------------
    let creds_path =
        std::env::var("FULA_E2E_CREDS").unwrap_or_else(|_| DEFAULT_CREDS_PATH.to_string());
    let contents = std::fs::read_to_string(&creds_path)
        .unwrap_or_else(|e| panic!("FULA_E2E=1 but could not read creds file {creds_path}: {e}"));
    let creds = parse_env_file(&contents);

    let endpoint = cred(&creds, "FULA_S3").expect("FULA_S3 endpoint required");
    let jwt = cred(&creds, "FULA_JWT").expect("FULA_JWT required");
    let timeout_secs: u64 = cred(&creds, "FULA_TIMEOUT_SECS")
        .and_then(|s| s.parse().ok())
        .unwrap_or(120);

    // ---- The OWNER: a SEPARATE keypair; the bundle holds only its PUBLIC half.
    let mut owner_seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut owner_seed);
    let owner = KekKeyPair::from_secret_key(SecretKey::from_bytes(&owner_seed).unwrap());
    let owner_public_b64 =
        base64::engine::general_purpose::STANDARD.encode(owner.public_key().as_bytes());

    let cap = CapabilityBundle::from_json(&bundle_json(
        &endpoint,
        &jwt,
        &owner_public_b64,
        timeout_secs,
    ))
    .expect("capability bundle must parse");

    // NOTE: store_file always writes to the WORKSPACE_BUCKET constant. To keep
    // the run isolated and self-cleaning we create that bucket fresh at the
    // start (clean v7 forest) and tear it down at the end. If a prior aborted
    // run left it behind, create_bucket may report it exists — tolerated.
    let client = cap.workspace_client().expect("workspace client");
    let _ = client.create_bucket(WORKSPACE_BUCKET).await; // best-effort; may already exist

    // Two payloads: a small single-block file and a large (>768 KB) chunked one.
    let mut small = vec![0u8; 32 * 1024];
    rand::thread_rng().fill_bytes(&mut small);
    let mut large = vec![0u8; 1_500_000]; // > 768 KB chunked threshold
    rand::thread_rng().fill_bytes(&mut large);

    // Unique filenames so each run writes distinct keys (and so a leftover
    // bucket never collides). The image MIME routes to ai/image/...; the binary
    // routes to ai/file/... — exercising category→key routing live.
    let tag = uuid::Uuid::new_v4();
    let small_name = format!("p5-small-{tag}.png");
    let large_name = format!("p5-large-{tag}.bin");

    let outcome: Result<(), String> = async {
        // ───────────── Single-block via store_file ─────────────
        let small_out = store_file(
            &cap,
            Bytes::from(small.clone()),
            &small_name,
            Some("image/png"),
            None,
            None,
        )
        .await
        .map_err(|e| format!("store_file(small) failed: {e}"))?;

        // Routing sanity: image MIME → ai/image/, native bucket images-v8.
        if !small_out.key.starts_with("ai/image/") {
            return Err(format!("small key not under ai/image/: {}", small_out.key));
        }
        if small_out.native_bucket.as_deref() != Some("images-v8") {
            return Err(format!(
                "small native_bucket expected images-v8, got {:?}",
                small_out.native_bucket
            ));
        }

        // OWNER accepts the returned share + reads the bytes back.
        let accepted = ShareRecipient::new(&owner)
            .accept_share(&small_out.owner_share)
            .map_err(|e| format!("owner accept_share(small): {e}"))?;
        if !accepted.is_path_allowed(&small_out.storage_key) {
            return Err("owner: small file outside declared share scope".to_string());
        }
        let got = client
            .get_object_with_share(
                &small_out.bucket,
                &small_out.storage_key,
                &small_out.storage_key,
                &accepted,
            )
            .await
            .map_err(|e| format!("owner get_object_with_share(small): {e}"))?;
        if got.as_ref() != small.as_slice() {
            return Err(format!(
                "small round-trip mismatch: wrote {} bytes, owner read {}",
                small.len(),
                got.len()
            ));
        }

        // ───────────── Chunked via store_file ─────────────
        let large_out = store_file(
            &cap,
            Bytes::from(large.clone()),
            &large_name,
            Some("application/octet-stream"),
            None,
            None,
        )
        .await
        .map_err(|e| format!("store_file(large) failed: {e}"))?;

        if !large_out.key.starts_with("ai/file/") {
            return Err(format!("large key not under ai/file/: {}", large_out.key));
        }

        let accepted_large = ShareRecipient::new(&owner)
            .accept_share(&large_out.owner_share)
            .map_err(|e| format!("owner accept_share(large): {e}"))?;
        // The chunked share MUST carry chunked metadata (and no top-level nonce).
        if accepted_large.chunked_metadata.is_none() {
            return Err("large (chunked) share missing chunked_metadata".to_string());
        }
        if !accepted_large.is_path_allowed(&large_out.storage_key) {
            return Err("owner: large file outside declared share scope".to_string());
        }
        let got_large = client
            .get_object_with_share(
                &large_out.bucket,
                &large_out.storage_key,
                &large_out.storage_key,
                &accepted_large,
            )
            .await
            .map_err(|e| format!("owner get_object_with_share(large): {e}"))?;
        if got_large.as_ref() != large.as_slice() {
            return Err(format!(
                "large round-trip mismatch: wrote {} bytes, owner read {}",
                large.len(),
                got_large.len()
            ));
        }

        // Clean up both objects (best-effort; bucket teardown happens below).
        let _ = client
            .delete_object_flat(&small_out.bucket, &small_out.key)
            .await;
        let _ = client
            .delete_object_flat(&large_out.bucket, &large_out.key)
            .await;

        Ok(())
    }
    .await;

    // ---- Cleanup that ALWAYS runs -----------------------------------------
    match client.delete_bucket(WORKSPACE_BUCKET).await {
        Ok(()) => eprintln!("cleanup: deleted workspace bucket {WORKSPACE_BUCKET}"),
        Err(e) => eprintln!(
            "note: workspace bucket {WORKSPACE_BUCKET} left behind (forest-index objects remain; \
             expected — no encrypted-client API drains them): {e}"
        ),
    }

    outcome.unwrap_or_else(|e| panic!("P5 store_file e2e failed: {e}"));
    eprintln!(
        "P5 store_file e2e OK: AI stored single-block + chunked files, owner read both back \
         byte-identical via the minted share."
    );
}
