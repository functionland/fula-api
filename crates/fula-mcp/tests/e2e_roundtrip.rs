//! Phase 1 — GATED end-to-end round-trip against a real Fula gateway.
//!
//! This proves the `fula-client` encrypted upload/download path round-trips
//! through the LIVE gateway using the app-derived Mode A secret:
//! `EncryptedClient::put_object_flat` (HPKE DEK-wrap + storage-key obfuscation +
//! chunked content encryption + forest index write) followed by
//! `get_object_flat` (forest lookup + decrypt) returns byte-identical data.
//!
//! Scope honesty: this is a SAME-CLIENT round-trip (this Rust code writes and
//! reads). It exercises the full server-side format and the app-compatible Mode
//! A key derivation, but it does NOT by itself prove cross-compatibility with
//! the FxFiles Flutter client — that would need a Flutter-produced object
//! decrypted here (or vice versa), or a Flutter golden fixture. The repo's
//! `tests/cross_platform_encryption_test.rs` / `tests/exact_flow_test.rs` cover
//! that cross-platform vector; this spike intentionally does not duplicate it.
//!
//! It is doubly gated so a plain `cargo test` stays green OFFLINE:
//!   1. `#[ignore]` — excluded from a normal run; needs `-- --ignored`.
//!   2. `FULA_E2E=1` — even under `--ignored`, the body is a no-op unless this
//!      env var is set, so `--ignored` on a machine without credentials/network
//!      doesn't fail.
//!
//! Credentials are read from the operator's local env file (NOT committed):
//!   `C:\Users\ehsan\.claude\cache\e2e-credentials.env`
//! with an override via the `FULA_E2E_CREDS` env var. These are DEDICATED TEST
//! accounts, but the test treats them as production: it writes only under a
//! unique `e2e-mcp-spike/{uuid}.bin` key and always cleans up after itself.

use std::collections::HashMap;
use std::time::Duration;

use fula_client::{Config, EncryptedClient, EncryptionConfig};
use fula_mcp::derive_mode_a_secret;
use rand::RngCore;

/// Default location of the operator's local credentials file.
const DEFAULT_CREDS_PATH: &str = r"C:\Users\ehsan\.claude\cache\e2e-credentials.env";

/// Minimal `.env` parser: `KEY=VALUE` per line, ignoring blank lines and `#`
/// comments, tolerating leading indentation (the real file is indented) and
/// trimming surrounding whitespace/quotes. Only the first `=` splits.
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

/// Fetch a key from the parsed creds first, then fall back to the process
/// environment (lets the operator override any single value inline).
fn cred<'a>(creds: &'a HashMap<String, String>, key: &str) -> Option<String> {
    creds
        .get(key)
        .cloned()
        .or_else(|| std::env::var(key).ok())
        .filter(|v| !v.is_empty())
}

#[tokio::test]
#[ignore = "hits a live Fula gateway; run with FULA_E2E=1 and `-- --ignored`"]
async fn e2e_encrypt_upload_download_decrypt_roundtrip() {
    // ---- Gate 2: opt-in even under --ignored ------------------------------
    if std::env::var("FULA_E2E").as_deref() != Ok("1") {
        eprintln!("FULA_E2E != 1 — skipping live e2e round-trip (this is expected offline).");
        return;
    }

    // ---- Load credentials -------------------------------------------------
    let creds_path = std::env::var("FULA_E2E_CREDS").unwrap_or_else(|_| DEFAULT_CREDS_PATH.to_string());
    let contents = std::fs::read_to_string(&creds_path)
        .unwrap_or_else(|e| panic!("FULA_E2E=1 but could not read creds file {creds_path}: {e}"));
    let creds = parse_env_file(&contents);

    let endpoint = cred(&creds, "FULA_S3").expect("FULA_S3 endpoint required");
    let jwt = cred(&creds, "FULA_JWT").expect("FULA_JWT required");
    // Bucket strategy: by DEFAULT create a fresh, uniquely-named disposable
    // bucket and tear it down at the end — this is the proven pattern used by
    // the repo's live `tests/v7_over_server_tests.rs` (`create_bucket` then
    // `put_object_flat`) and gives maximum isolation: a brand-new bucket has a
    // clean v7 forest, so the round-trip never trips over another run's (or a
    // GC-orphaned) forest state. An operator can instead target a specific,
    // already-existing bucket by setting `FULA_TEST_BUCKET`; in that case we do
    // NOT create or delete the bucket (only the single object we wrote).
    //
    // NOTE: we deliberately do NOT default to the creds file's `FULA_BUCKET`
    // (`other`): on the shared test account that bucket's forest currently
    // references a GC-orphaned index object, so any write to it fails with
    // `NoSuchKey (gc-orphaned index)` before our key is even involved.
    let explicit_bucket = cred(&creds, "FULA_TEST_BUCKET");
    let bucket = explicit_bucket
        .clone()
        .unwrap_or_else(|| format!("e2e-mcp-spike-{}", uuid::Uuid::new_v4()));
    let owns_bucket = explicit_bucket.is_none();
    let provider = cred(&creds, "FULA_TEST_PROVIDER").expect("FULA_TEST_PROVIDER required");
    let oauth_sub = cred(&creds, "FULA_TEST_OAUTH_SUB").expect("FULA_TEST_OAUTH_SUB required");
    let email = cred(&creds, "FULA_TEST_EMAIL").expect("FULA_TEST_EMAIL required");
    let timeout_secs: u64 = cred(&creds, "FULA_TIMEOUT_SECS")
        .and_then(|s| s.parse().ok())
        .unwrap_or(60);

    // ---- Build the encrypted client (Mode A) ------------------------------
    let secret = derive_mode_a_secret(&provider, &oauth_sub, &email)
        .expect("Mode A secret derivation must succeed");
    let config = Config::new(endpoint.clone())
        .with_token(jwt)
        .with_encryption()
        .with_timeout(Duration::from_secs(timeout_secs));
    let encryption = EncryptionConfig::from_secret_key(secret);
    let client = EncryptedClient::new(config, encryption).expect("client construction must succeed");

    // ---- Unique, isolated test object -------------------------------------
    let key = format!("e2e-mcp-spike/{}.bin", uuid::Uuid::new_v4());
    let mut payload = vec![0u8; 64 * 1024]; // 64 KiB unique blob
    rand::thread_rng().fill_bytes(&mut payload);

    // ---- (Create bucket) -> upload -> download, capturing the outcome -----
    // Run the round-trip in an inner async block that returns Result instead of
    // unwinding, so the cleanup below ALWAYS executes (no leaked object/bucket)
    // even on an assertion-worthy failure.
    let outcome: Result<(), String> = async {
        if owns_bucket {
            // Fresh disposable bucket — lazily create it (clean v7 forest).
            client
                .create_bucket(&bucket)
                .await
                .map_err(|e| format!("create_bucket failed: {e}"))?;
        }

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
    // Delete the file object first, then (only if we created it) the bucket.
    // Cleanup runs regardless of the round-trip outcome so a failure never
    // leaks the file we wrote. The round-trip `outcome` is what we assert on.
    if let Err(e) = client.delete_object_flat(&bucket, &key).await {
        eprintln!("WARNING: cleanup delete of object {bucket}/{key} failed: {e}");
    }
    if owns_bucket {
        // Best-effort bucket teardown. `delete_object_flat` removes the file's
        // data + its forest entry, but the bucket still holds the encrypted
        // forest-index objects themselves, which the encrypted client has no
        // public API to drain (that needs raw storage-key deletes — a P2
        // concern, since P2 operates on forests directly). So a non-empty
        // bucket here is EXPECTED, not an error: we attempt the delete and just
        // note when the gateway declines. The repo's own live e2e tests
        // (tests/v7_over_server_tests.rs) leave their disposable buckets behind
        // entirely; this is no worse, and the unique name keeps it isolated.
        match client.delete_bucket(&bucket).await {
            Ok(()) => eprintln!("cleanup: deleted disposable bucket {bucket}"),
            Err(e) => eprintln!(
                "note: disposable bucket {bucket} left behind (forest-index objects remain; \
                 expected — no encrypted-client API drains them): {e}"
            ),
        }
    }

    outcome.unwrap_or_else(|e| panic!("e2e round-trip failed for {bucket}/{key}: {e}"));
    eprintln!("e2e round-trip OK: {bucket}/{key} ({} bytes)", payload.len());
}
