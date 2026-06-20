//! Phase 10 — GATED live e2e of the quota pre-check + write rate limiter.
//!
//! Two things this proves against the REAL gateway + credit service:
//!
//!   1. **The quota pre-check really runs and PASSES** for the funded test
//!      account. We assert the concrete [`QuotaDecision::Allowed`] from a direct
//!      [`CapabilityBundle::check_quota`] — NOT merely that `store_file`
//!      succeeded. This is the whole point of the 3-state decision: a silent
//!      `SkippedFailOpen` (endpoint unreachable / JWT rejected at the credit host
//!      / field renamed) would let an otherwise-broken check masquerade as a
//!      pass in a happy-path store. Asserting `Allowed` is what exercises the
//!      PRIMARY path, not just the fail-open fallback.
//!   2. **`store_file` succeeds end-to-end THROUGH the pre-check** (store → mint
//!      owner share → owner reads the bytes back byte-identically), i.e. the
//!      pre-check does not get in the way of a legitimate write.
//!
//!   3. (Optional, best-effort) the **rate limiter blocks a burst**: with a tiny
//!      configured burst we drain the bucket and show the next `store_file`
//!      fails fast with [`StoreError::RateLimited`] and NO upload.
//!
//! ## If the quota assertion is NOT `Allowed`, that is a DEPLOYMENT FINDING
//!
//! The session JWT is S3-scoped and the credit host (`cloud.fx.land`) is a
//! DIFFERENT host from the S3 endpoint (`s3.cloud.fx.land`). Whether a *session*
//! JWT (vs a billing API key) is accepted at the public credit host is genuinely
//! open. The 3-state variant tells you which fact you learned:
//!   - `SkippedFailOpen(HttpStatus)` → the JWT is not accepted at the credit host
//!     (the pre-check is always-fail-open in this deployment; the feature then
//!     only enforces at PUT-time — a real finding, not a code bug).
//!   - `SkippedFailOpen(Decode)` → the credit body's field differs from
//!     `canUpload`/`can_upload` (adjust the serde alias).
//!   - `Allowed` → field name AND cross-host JWT both confirmed (best case).
//!
//! The test panics with the actual variant so the run is self-diagnosing.
//!
//! Double-gated so a plain `cargo test` stays green OFFLINE:
//!   1. `#[ignore]` — excluded from a normal run; needs `-- --ignored`.
//!   2. `FULA_E2E=1` — even under `--ignored`, the body is a no-op unless set.
//!
//! Credentials: the operator's local creds file (NOT committed), default
//! `C:\Users\ehsan\.claude\cache\e2e-credentials.env`, override via
//! `FULA_E2E_CREDS`. The credit host defaults to `https://cloud.fx.land`
//! (per `.env.example`'s `STORAGE_API_URL`), overridable via a `STORAGE_API_URL`
//! cred/env key. Dedicated test account, treated as production: writes only into
//! a unique disposable bucket and always cleans up.

use std::collections::HashMap;

use base64::Engine as _;
use bytes::Bytes;
use fula_crypto::{KekKeyPair, SecretKey, ShareRecipient};
use fula_mcp::capability::CapabilityBundle;
use fula_mcp::quota::QuotaDecision;
use fula_mcp::store::{store_file, StoreError, WORKSPACE_BUCKET};
use rand::RngCore;

const DEFAULT_CREDS_PATH: &str = r"C:\Users\ehsan\.claude\cache\e2e-credentials.env";

/// The default credit/quota host (per `.env.example`'s `STORAGE_API_URL`).
const DEFAULT_STORAGE_API_URL: &str = "https://cloud.fx.land";

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

/// Build the capability-bundle JSON from a random workspace secret + a random
/// MCP secret + the given owner public key + creds, granting `ai/` read-write.
/// `storage_api_url` wires the P10 credit host; `write_burst` sets the rate cap.
fn bundle_json(
    endpoint: &str,
    jwt: &str,
    owner_public_b64: &str,
    timeout_secs: u64,
    storage_api_url: &str,
    write_burst: u32,
) -> String {
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
          "storage_api_url": {storage_api_url:?},
          "write_burst": {write_burst},
          "grants": [
            {{ "scope": "ai/", "permissions": {{ "can_read": true, "can_write": true, "can_delete": true }} }}
          ]
        }}"#
    )
}

#[tokio::test]
#[ignore = "hits a live Fula gateway + credit service; run with FULA_E2E=1 and `-- --ignored`"]
async fn e2e_quota_pre_check_allows_and_store_succeeds() {
    // ---- Gate 2: opt-in even under --ignored ------------------------------
    if std::env::var("FULA_E2E").as_deref() != Ok("1") {
        eprintln!("FULA_E2E != 1 — skipping live P10 quota/rate-limit e2e (expected offline).");
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
    let storage_api_url =
        cred(&creds, "STORAGE_API_URL").unwrap_or_else(|| DEFAULT_STORAGE_API_URL.to_string());

    // ---- The OWNER: a SEPARATE keypair; the bundle holds only its PUBLIC half.
    let mut owner_seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut owner_seed);
    let owner = KekKeyPair::from_secret_key(SecretKey::from_bytes(&owner_seed).unwrap());
    let owner_public_b64 =
        base64::engine::general_purpose::STANDARD.encode(owner.public_key().as_bytes());

    // Generous burst (20) so the store flow is never throttled by the limiter.
    let cap = CapabilityBundle::from_json(&bundle_json(
        &endpoint,
        &jwt,
        &owner_public_b64,
        timeout_secs,
        &storage_api_url,
        20,
    ))
    .expect("capability bundle must parse");

    // ───────────────────────── (1) THE QUOTA ASSERTION ─────────────────────────
    // Assert the CONCRETE Allowed verdict from a direct check — separately and
    // FIRST, so a non-Allowed result gives a clean, self-diagnosing failure
    // (rather than tangling with a later store/share error). The funded account
    // HAS quota, so a working endpoint + accepted JWT MUST return Allowed; any
    // other variant is a deployment/credential FINDING (see the module docs).
    let decision = cap.check_quota().await;
    match &decision {
        QuotaDecision::Allowed => {
            eprintln!("P10 e2e: quota pre-check returned Allowed (credit host + JWT confirmed).");
        }
        other => panic!(
            "P10 e2e: expected QuotaDecision::Allowed from the funded account, got {other:?}. \
             This is most likely a DEPLOYMENT/CREDENTIAL finding, not a P10 code bug:\n  \
             - SkippedFailOpen(HttpStatus) → the session JWT is not accepted at {storage_api_url} \
               (the pre-check is always-fail-open in this deployment; the feature still enforces \
               at PUT-time).\n  \
             - SkippedFailOpen(Decode) → the credit body field differs from canUpload/can_upload \
               (adjust the serde alias).\n  \
             - SkippedFailOpen(Transport) → the credit host was unreachable from this runner.\n  \
             The fail-open posture means a real write would still proceed; this assertion only \
             verifies the PRIMARY (checked-and-passed) path is exercised."
        ),
    }

    // ───────────────────────── (2) STORE THROUGH THE PRE-CHECK ─────────────────
    // store_file runs the SAME pre-check internally (Allowed → proceeds), then the
    // real encrypted upload. Prove the whole path works and the owner reads back.
    let client = cap.workspace_client().expect("workspace client");
    let _ = client.create_bucket(WORKSPACE_BUCKET).await; // best-effort; may already exist

    let mut payload = vec![0u8; 48 * 1024];
    rand::thread_rng().fill_bytes(&mut payload);
    let tag = uuid::Uuid::new_v4();
    let name = format!("p10-quota-{tag}.bin");

    let outcome: Result<(), String> = async {
        let out = store_file(
            &cap,
            Bytes::from(payload.clone()),
            &name,
            Some("application/octet-stream"),
            None,
            None,
        )
        .await
        .map_err(|e| format!("store_file failed THROUGH the pre-check: {e}"))?;

        // Owner accepts the minted share and reads the bytes back byte-identical.
        let accepted = ShareRecipient::new(&owner)
            .accept_share(&out.owner_share)
            .map_err(|e| format!("owner accept_share: {e}"))?;
        if !accepted.is_path_allowed(&out.storage_key) {
            return Err("owner: file outside declared share scope".to_string());
        }
        let got = client
            .get_object_with_share(&out.bucket, &out.storage_key, &out.storage_key, &accepted)
            .await
            .map_err(|e| format!("owner get_object_with_share: {e}"))?;
        if got.as_ref() != payload.as_slice() {
            return Err(format!(
                "round-trip mismatch: wrote {} bytes, owner read {}",
                payload.len(),
                got.len()
            ));
        }

        // ─────────── (3) OPTIONAL: the rate limiter blocks a burst ───────────
        // A SECOND bundle with burst=1, sharing the same creds/owner. Drain the
        // one token, then the next store must fail fast with RateLimited and NOT
        // upload anything (so there is nothing extra to clean up).
        let cap_rl = CapabilityBundle::from_json(&bundle_json(
            &endpoint,
            &jwt,
            &owner_public_b64,
            timeout_secs,
            &storage_api_url,
            1,
        ))
        .expect("rate-limit bundle must parse");
        assert!(cap_rl.try_consume_write_token(), "drain the single token");
        let blocked = store_file(
            &cap_rl,
            Bytes::from_static(b"should be rate limited"),
            "p10-burst.txt",
            Some("text/plain"),
            None,
            None,
        )
        .await;
        match blocked {
            Err(StoreError::RateLimited) => {
                eprintln!("P10 e2e: rate limiter blocked the burst as expected (no upload).");
            }
            other => {
                return Err(format!(
                    "expected RateLimited on a drained bucket, got {other:?}"
                ))
            }
        }

        // Clean up the one object we actually stored (bucket teardown below).
        let _ = client.delete_object_flat(&out.bucket, &out.key).await;
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

    outcome.unwrap_or_else(|e| panic!("P10 quota/rate-limit e2e failed: {e}"));
    eprintln!(
        "P10 quota/rate-limit e2e OK: quota pre-check returned Allowed, store_file succeeded \
         through the pre-check (owner read back byte-identical), and the rate limiter blocked a \
         drained-bucket burst."
    );
}
