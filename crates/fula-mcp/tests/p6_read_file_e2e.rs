//! Phase 6 — GATED live e2e of the `read_file` operation (the scoped read).
//!
//! The live-gateway counterpart to the offline tests in `src/read.rs`. It
//! exercises both read modes over the REAL wire format:
//!
//!   A. WORKSPACE read — `store_file` a unique blob (small single-block AND
//!      large chunked >768 KB), then read it back byte-identically through
//!      [`fula_mcp::read::read_workspace_file`]. This is the AI reading its OWN
//!      files: the scope gate (`assert_in_scope(key, "ai", Read)`) passes and
//!      `get_object_flat` decrypts with the workspace secret.
//!
//!   B. GRANTED read — the owner mints an `owner → MCP` share token for a file
//!      and the MCP reads it through [`fula_mcp::read::read_granted_file`]:
//!      `accept_grant` → scope gate against the token's `path_scope` →
//!      `get_object_with_share` decrypts with the share DEK. To keep the test
//!      self-contained (no production cross-account proxy) we reuse the P5
//!      isolation trick: the bytes are fetched by the workspace client (the
//!      owner-side crypto — accept_share → DEK — is identical to a cross-account
//!      read; only the byte-fetch JWT differs). The owner here is a SEPARATE
//!      keypair; it recovers the file DEK from the object's own metadata exactly
//!      as `store_file` does, then mints the `owner → MCP` token.
//!
//! Double-gated so a plain `cargo test` stays green OFFLINE:
//!   1. `#[ignore]` — excluded from a normal run; needs `-- --ignored`.
//!   2. `FULA_E2E=1` — even under `--ignored`, the body is a no-op unless set.
//!
//! Credentials: the operator's local creds file (NOT committed), default
//! `C:\Users\ehsan\.claude\cache\e2e-credentials.env`, override via
//! `FULA_E2E_CREDS`. Dedicated test accounts, treated as production: writes only
//! into the disposable workspace bucket and always cleans up.

use std::collections::HashMap;

use base64::Engine as _;
use bytes::Bytes;
use fula_crypto::{DekKey, Decryptor, EncryptedData, KekKeyPair, SecretKey, ShareBuilder};
use fula_mcp::capability::CapabilityBundle;
use fula_mcp::read::{read_granted_file, read_workspace_file};
use fula_mcp::store::{store_file, WORKSPACE_BUCKET};
use rand::RngCore;

const DEFAULT_CREDS_PATH: &str = r"C:\Users\ehsan\.claude\cache\e2e-credentials.env";

/// Minimal `.env` parser (same shape as the P1/P2/P5 e2e tests).
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

/// Build the capability-bundle JSON from the given workspace secret + a random
/// MCP secret + owner public key + creds, with the supplied grants array. The
/// workspace secret is passed in (not random) so the test can recover file DEKs
/// with the SAME keypair the workspace client wrote them under (for the granted
/// path's owner-side DEK recovery).
fn bundle_json(
    endpoint: &str,
    jwt: &str,
    workspace_secret_b64: &str,
    mcp_secret_b64: &str,
    owner_public_b64: &str,
    timeout_secs: u64,
    grants_json: &str,
) -> String {
    format!(
        r#"{{
          "endpoint": {endpoint:?},
          "jwt": {jwt:?},
          "workspace_secret_b64": "{workspace_secret_b64}",
          "mcp_secret_b64": "{mcp_secret_b64}",
          "owner_public_b64": "{owner_public_b64}",
          "timeout_secs": {timeout_secs},
          "grants": {grants_json}
        }}"#
    )
}

#[tokio::test]
#[ignore = "hits a live Fula gateway; run with FULA_E2E=1 and `-- --ignored`"]
async fn e2e_read_file_workspace_and_granted() {
    // ---- Gate 2: opt-in even under --ignored ------------------------------
    if std::env::var("FULA_E2E").as_deref() != Ok("1") {
        eprintln!("FULA_E2E != 1 — skipping live P6 read_file e2e (expected offline).");
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

    // ---- Dedicated random workspace secret (NOT the user's master key) -----
    let mut ws = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut ws);
    let ws_b64 = base64::engine::general_purpose::STANDARD.encode(ws);
    // A known workspace keypair handle for the granted-path DEK recovery.
    let workspace_keypair =
        KekKeyPair::from_secret_key(SecretKey::from_bytes(&ws).unwrap());

    // ---- A SEPARATE owner keypair (the bundle holds only its PUBLIC half) ---
    let mut owner_seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut owner_seed);
    let owner = KekKeyPair::from_secret_key(SecretKey::from_bytes(&owner_seed).unwrap());
    let owner_public_b64 =
        base64::engine::general_purpose::STANDARD.encode(owner.public_key().as_bytes());

    // ---- A known MCP secret so we can pre-compute the storage_key grant -----
    // We do NOT know the storage_key until the file is written, so the bundle is
    // built in two stages: first with just the `ai/` grant (enough for the
    // workspace reads + the store), then we add the per-file granted scope and
    // rebuild for the granted-read leg. The MCP secret is fixed across both.
    let mut mcp = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut mcp);
    let mcp_b64 = base64::engine::general_purpose::STANDARD.encode(mcp);

    // Stage-1 bundle: ai/ read-write-delete (covers store + workspace reads).
    let grants_ai = r#"[{ "scope": "ai/", "permissions": { "can_read": true, "can_write": true, "can_delete": true } }]"#;
    let cap = CapabilityBundle::from_json(&bundle_json(
        &endpoint,
        &jwt,
        &ws_b64,
        &mcp_b64,
        &owner_public_b64,
        timeout_secs,
        grants_ai,
    ))
    .expect("stage-1 capability bundle must parse");

    let client = cap.workspace_client().expect("workspace client");
    let _ = client.create_bucket(WORKSPACE_BUCKET).await; // best-effort; may already exist

    // Two payloads: small single-block + large (>768 KB) chunked.
    let mut small = vec![0u8; 32 * 1024];
    rand::thread_rng().fill_bytes(&mut small);
    let mut large = vec![0u8; 1_500_000];
    rand::thread_rng().fill_bytes(&mut large);

    let tag = uuid::Uuid::new_v4();
    let small_name = format!("p6-small-{tag}.png");
    let large_name = format!("p6-large-{tag}.bin");

    let outcome: Result<(), String> = async {
        // ───────────── A. WORKSPACE READ (small + chunked) ─────────────
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

        // Read it back through read_workspace_file (the gate passes; own-secret
        // decrypt). MUST be byte-identical.
        let got_small = read_workspace_file(&cap, &small_out.key)
            .await
            .map_err(|e| format!("read_workspace_file(small) failed: {e}"))?;
        if got_small.as_ref() != small.as_slice() {
            return Err(format!(
                "small workspace read mismatch: wrote {} bytes, read {}",
                small.len(),
                got_small.len()
            ));
        }

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

        let got_large = read_workspace_file(&cap, &large_out.key)
            .await
            .map_err(|e| format!("read_workspace_file(large, chunked) failed: {e}"))?;
        if got_large.as_ref() != large.as_slice() {
            return Err(format!(
                "large (chunked) workspace read mismatch: wrote {} bytes, read {}",
                large.len(),
                got_large.len()
            ));
        }

        // Negative: a workspace read OUTSIDE ai/ must be DENIED (no I/O leak).
        // (Belt-and-suspenders against the live path; the offline tests already
        // prove the gate, this confirms it end-to-end too.)
        match read_workspace_file(&cap, "photos/not-mine.jpg").await {
            Err(fula_mcp::read::ReadError::Capability(_)) => {}
            other => {
                return Err(format!(
                    "out-of-scope workspace read should be Capability-denied, got {other:?}"
                ));
            }
        }

        // ───────────── B. GRANTED READ (owner → MCP) ─────────────
        // The owner shares the SMALL file with the MCP. To mint, the owner needs
        // the file's content DEK + nonce; recover them from the object's own
        // metadata exactly as store_file does (the test legitimately holds the
        // workspace keypair in this isolated setup).
        let storage_key = &small_out.storage_key;
        let enc_meta_json = client
            .get_object_encryption_metadata_with_fallback(WORKSPACE_BUCKET, storage_key)
            .await
            .map_err(|e| format!("granted: fetch enc metadata: {e}"))?;
        let meta: serde_json::Value = serde_json::from_str(&enc_meta_json)
            .map_err(|e| format!("granted: enc metadata not JSON: {e}"))?;
        let wrapped: EncryptedData = serde_json::from_value(
            meta.get("wrapped_key")
                .cloned()
                .ok_or_else(|| "granted: metadata missing wrapped_key".to_string())?,
        )
        .map_err(|e| format!("granted: malformed wrapped_key: {e}"))?;
        let dek: DekKey = Decryptor::new(&workspace_keypair)
            .decrypt_dek(&wrapped)
            .map_err(|e| format!("granted: unwrap DEK with workspace keypair: {e}"))?;
        let nonce_b64 = meta
            .get("nonce")
            .and_then(|n| n.as_str())
            .ok_or_else(|| "granted: small object metadata missing nonce".to_string())?
            .to_string();

        // Owner mints an owner→MCP share for the storage_key (path_scope =
        // storage_key, the granularity get_object_with_share checks against).
        let grant_token = ShareBuilder::new(&owner, cap.mcp_public_key(), &dek)
            .path_scope(storage_key)
            .read_only()
            .encryption_version(4)
            .nonce(nonce_b64)
            .build()
            .map_err(|e| format!("granted: mint owner→MCP share: {e}"))?;

        // The session must hold a Read grant EQUAL to the token scope (the P9
        // invariant). Rebuild the bundle adding that per-file grant.
        let granted_scope = storage_key.replace('"', "");
        let grants_two = format!(
            r#"[{{ "scope": "ai/", "permissions": {{ "can_read": true, "can_write": true, "can_delete": true }} }}, {{ "scope": {granted_scope:?}, "permissions": {{ "can_read": true, "can_write": false, "can_delete": false }} }}]"#
        );
        let cap_granted = CapabilityBundle::from_json(&bundle_json(
            &endpoint,
            &jwt,
            &ws_b64,
            &mcp_b64,
            &owner_public_b64,
            timeout_secs,
            &grants_two,
        ))
        .map_err(|e| format!("granted: stage-2 bundle parse: {e}"))?;

        // MCP reads the granted file: accept_grant → gate (scope == storage_key,
        // Read) → get_object_with_share. MUST be byte-identical to `small`.
        let got_granted = read_granted_file(
            &cap_granted,
            &grant_token,
            WORKSPACE_BUCKET,
            storage_key,
            storage_key,
        )
        .await
        .map_err(|e| format!("read_granted_file failed: {e}"))?;
        if got_granted.as_ref() != small.as_slice() {
            return Err(format!(
                "granted read mismatch: shared {} bytes, MCP read {}",
                small.len(),
                got_granted.len()
            ));
        }

        // Negative (live): an out-of-scope original_key under the SAME token must
        // be Capability-denied (the gate, not the wire). Append a sibling segment
        // to the storage_key so it shares a string prefix but a different segment.
        let footgun_key = format!("{storage_key}-evil");
        match read_granted_file(
            &cap_granted,
            &grant_token,
            WORKSPACE_BUCKET,
            storage_key,
            &footgun_key,
        )
        .await
        {
            Err(fula_mcp::read::ReadError::Capability(_)) => {}
            other => {
                return Err(format!(
                    "granted out-of-scope read should be Capability-denied, got {other:?}"
                ));
            }
        }

        // Clean up the two objects (bucket teardown happens below).
        let _ = client.delete_object_flat(&small_out.bucket, &small_out.key).await;
        let _ = client.delete_object_flat(&large_out.bucket, &large_out.key).await;

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

    outcome.unwrap_or_else(|e| panic!("P6 read_file e2e failed: {e}"));
    eprintln!(
        "P6 read_file e2e OK: AI read its own workspace files (single-block + chunked) \
         byte-identical, and read an owner-granted file via read_granted_file byte-identical; \
         out-of-scope reads denied pre-wire."
    );
}
