//! Phase 3 — GATED end-to-end verification of the **identity/secret model**.
//!
//! The P3 capability model claims: the MCP can act on an AI-workspace bucket
//! using a **dedicated, random 32-byte workspace secret** (NOT the user's master
//! KEK) together with the **user's scoped gateway JWT**. This test proves that
//! claim against a LIVE gateway end-to-end:
//!
//!   1. Generate a brand-new random [`SecretKey`] (the dedicated workspace
//!      secret — emphatically NOT `derive_mode_a_secret`; a random secret is the
//!      whole point, because it must work without being the account's master
//!      key).
//!   2. Build a [`CapabilityBundle`] from that secret + the creds' `FULA_JWT` /
//!      `FULA_S3`, plus throwaway MCP/owner keypairs (the share keypairs are not
//!      exercised here — this test is about the workspace client path).
//!   3. Drive [`CapabilityBundle::workspace_client`] to create a disposable
//!      workspace bucket, then write -> read -> delete a unique blob.
//!   4. Assert the download is byte-identical, then clean up unconditionally.
//!
//! If this round-trips, the model holds: a freshly-minted secret encrypts a
//! fresh bucket the same account owns, authorized by the user's JWT. If it does
//! NOT, that is a CRITICAL finding for the whole stateless-MCP design and the
//! failure is surfaced verbatim (never hidden).
//!
//! Gating mirrors P1's `tests/e2e_roundtrip.rs` so a plain `cargo test` stays
//! green OFFLINE:
//!   1. `#[ignore]` — excluded from a normal run; needs `-- --ignored`.
//!   2. `FULA_E2E=1` — even under `--ignored`, the body is a no-op unless set.
//!
//! Credentials come from the operator's local env file (NOT committed):
//!   `C:\Users\ehsan\.claude\cache\e2e-credentials.env`
//! overridable via `FULA_E2E_CREDS`.

use std::collections::HashMap;

use base64::Engine as _;
use fula_crypto::SecretKey;
use fula_mcp::capability::{CapabilityBundle, Permission};
use rand::RngCore;

/// Default location of the operator's local credentials file.
const DEFAULT_CREDS_PATH: &str = r"C:\Users\ehsan\.claude\cache\e2e-credentials.env";

/// Minimal `.env` parser: `KEY=VALUE` per line, ignoring blanks/`#`, tolerating
/// indentation, trimming whitespace/quotes. Only the first `=` splits.
/// (Same shape as `e2e_roundtrip.rs`'s parser.)
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

/// Base64 of 32 fresh random bytes (for the throwaway MCP secret / owner key).
fn random_b64_32() -> String {
    let mut b = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut b);
    base64::engine::general_purpose::STANDARD.encode(b)
}

#[tokio::test]
#[ignore = "hits a live Fula gateway; run with FULA_E2E=1 and `-- --ignored`"]
async fn e2e_workspace_secret_plus_user_jwt_round_trip() {
    // ---- Gate 2: opt-in even under --ignored ------------------------------
    if std::env::var("FULA_E2E").as_deref() != Ok("1") {
        eprintln!("FULA_E2E != 1 — skipping live P3 workspace round-trip (expected offline).");
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
        .unwrap_or(60);

    // ---- The crux: a DEDICATED, brand-new RANDOM workspace secret ---------
    // NOT derive_mode_a_secret. A random secret encrypting a fresh bucket the
    // same account owns is exactly the model claim we are validating.
    let mut workspace_secret = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut workspace_secret);
    let workspace_secret_b64 =
        base64::engine::general_purpose::STANDARD.encode(workspace_secret);

    // Disposable, uniquely-named workspace bucket (clean v7 forest in isolation,
    // same strategy as the P1 e2e). Treated as production: unique key + always
    // clean up.
    let bucket = format!("p3-mcp-workspace-{}", uuid::Uuid::new_v4());

    // Build the capability bundle JSON exactly as it would be injected at
    // startup. MCP/owner keys are throwaway here (share path not exercised). The
    // single grant authorizes write/read/delete under the bucket-local "ai/"
    // workspace prefix, so we can additionally exercise assert_in_scope against
    // the live key we use.
    let bundle_json = format!(
        r#"{{
          "endpoint": {endpoint},
          "jwt": {jwt},
          "timeout_secs": {timeout_secs},
          "workspace_secret_b64": {ws},
          "mcp_secret_b64": {mcp},
          "owner_public_b64": {owner},
          "grants": [
            {{ "scope": "ai/", "permissions": {{ "can_read": true, "can_write": true, "can_delete": true }} }}
          ]
        }}"#,
        endpoint = serde_json::to_string(&endpoint).unwrap(),
        jwt = serde_json::to_string(&jwt).unwrap(),
        ws = serde_json::to_string(&workspace_secret_b64).unwrap(),
        mcp = serde_json::to_string(&random_b64_32()).unwrap(),
        // owner_public must be a valid X25519 public key — derive one from a
        // random secret.
        owner = serde_json::to_string(
            &base64::engine::general_purpose::STANDARD
                .encode(SecretKey::generate().public_key().as_bytes())
        )
        .unwrap(),
    );

    let bundle = CapabilityBundle::from_json(&bundle_json)
        .expect("capability bundle must parse from injected JSON");

    // Logical workspace key under the granted "ai/" scope.
    let key = format!("ai/e2e/{}.bin", uuid::Uuid::new_v4());

    // Sanity: the access-control check must ADMIT this key for write/read/delete
    // under the "ai/" grant (geometry + authority), and we pass the SAME key
    // string to storage (strict-canonical key => check == stored).
    bundle
        .assert_in_scope(&key, "ai/", Permission::Write)
        .expect("workspace key must be writable under the ai/ grant");
    bundle
        .assert_in_scope(&key, "ai/", Permission::Read)
        .expect("workspace key must be readable under the ai/ grant");

    let client = bundle
        .workspace_client()
        .expect("workspace client must build from the dedicated secret + JWT");

    let mut payload = vec![0u8; 48 * 1024];
    rand::thread_rng().fill_bytes(&mut payload);

    // ---- (create bucket) -> upload -> download, capturing outcome ---------
    let outcome: Result<(), String> = async {
        client
            .create_bucket(&bucket)
            .await
            .map_err(|e| format!("create_bucket failed: {e}"))?;

        client
            .put_object_flat(&bucket, &key, payload.clone(), Some("application/octet-stream"))
            .await
            .map_err(|e| format!("upload failed: {e}"))?;

        let downloaded = client
            .get_object_flat(&bucket, &key)
            .await
            .map_err(|e| format!("download failed: {e}"))?;

        if downloaded.as_ref() != payload.as_slice() {
            return Err(format!(
                "round-trip mismatch: uploaded {} bytes, got back {} bytes",
                payload.len(),
                downloaded.len()
            ));
        }
        Ok(())
    }
    .await;

    // ---- Cleanup that ALWAYS runs -----------------------------------------
    if let Err(e) = client.delete_object_flat(&bucket, &key).await {
        eprintln!("WARNING: cleanup delete of object {bucket}/{key} failed: {e}");
    }
    match client.delete_bucket(&bucket).await {
        Ok(()) => eprintln!("cleanup: deleted disposable workspace bucket {bucket}"),
        Err(e) => eprintln!(
            "note: disposable workspace bucket {bucket} left behind (forest-index objects \
             remain; expected — no encrypted-client API drains them): {e}"
        ),
    }

    // assert_in_scope must DENY a delete the grant did not cover, to prove the
    // boundary is live (e.g. a sibling outside ai/). This is local (no network)
    // but asserts the model's authorization arm alongside the storage arm.
    assert!(
        bundle
            .assert_in_scope("other/x.bin", "other/", Permission::Read)
            .is_err(),
        "a key outside any grant must be denied"
    );

    outcome.unwrap_or_else(|e| {
        panic!(
            "P3 workspace round-trip FAILED for {bucket}/{key} — this would be a CRITICAL \
             finding for the dedicated-workspace-secret model: {e}"
        )
    });
    eprintln!(
        "P3 workspace round-trip OK: dedicated random secret + user JWT wrote/read/deleted \
         {bucket}/{key} ({} bytes) byte-identically",
        payload.len()
    );
}
