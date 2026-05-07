//! End-to-end offline upload/download integration test against a real master.
//!
//! Mimics FxFiles' encrypted file-management flow: same `Config` flags
//! (health gate, block cache, gateway fallback all enabled), same
//! `EncryptionConfig` + FlatNamespace mode, same call sequence
//! (`put_object_flat` → `get_object_flat` → `list_files_from_forest`).
//! Validates the offline path at SDK level so app-level offline bugs
//! can be ruled out independently — if this test passes, FxFiles
//! offline reads should work using the same Config wiring.
//!
//! ## Running
//!
//! From `crates/fula-client/`, with PowerShell:
//!
//! ```powershell
//! $env:FULA_JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
//! $env:FULA_S3  = "https://s3.cloud.fx.land"
//! cargo test -p fula-client --test offline_e2e --release -- --ignored --nocapture
//! ```
//!
//! Or from the repo root in one line:
//!
//! ```bash
//! FULA_JWT="..." FULA_S3="https://s3.cloud.fx.land" \
//!   cargo test -p fula-client --test offline_e2e --release -- --ignored --nocapture
//! ```
//!
//! Optional environment variables:
//!
//! | Var                   | Default    | Purpose                                    |
//! |-----------------------|------------|--------------------------------------------|
//! | `FULA_BUCKET`         | `"other"`  | Target bucket (must exist on master)       |
//! | `FULA_TIMEOUT_SECS`   | `60`       | Per-request timeout for the master         |
//!
//! Marked `#[ignore]` so the standard `cargo test` skips it (it requires
//! a reachable master + valid creds). The `--ignored` flag in the
//! command above opts in.
//!
//! ## What this proves (and doesn't)
//!
//! Validates the offline LIST path end-to-end against the live master.
//! Skips the offline DOWNLOAD assertion because it depends on a still-
//! pending architectural extension (metadata caching) — see the inline
//! note in phase 2.
//!
//! Three phases share an on-disk block cache (a tempdir's `redb` file)
//! and a single `SecretKey` (so what's encrypted in phase 1a is
//! decryptable in phase 1b and phase 2):
//!
//! 1. **Phase 1a — Upload.** First client uploads a small payload via
//!    `put_object_flat` and drops. Master now has the encrypted chunk
//!    and forest manifest. PUTs do NOT populate the warm cache.
//!
//! 2. **Phase 1b — Fresh read populates warm cache.** Second client
//!    starts with an empty in-memory `forest_cache`, so the first
//!    `list_files_from_forest` and `get_object_flat` calls force real
//!    GETs to master. On each successful response, the cache hook in
//!    `get_object_with_offline_fallback` (`client.rs:660-685`)
//!    populates KEY_TO_CID + BLOCKS for the manifest and the chunk(s).
//!    This phase mimics the cross-device scenario the FxFiles offline
//!    path exists for: device A uploaded, device B is reading fresh.
//!    Without this dedicated phase, an upload-then-read flow inside
//!    one client never re-fetches the manifest after the upload, and
//!    the cache hook never gets the chance to populate.
//!
//! 3. **Phase 2 — OFFLINE.** Third client points at a bogus master
//!    URL (`http://127.0.0.1:1`, unreachable) but reuses the same
//!    `SecretKey` and on-disk cache path. In-memory state is empty
//!    again. List + download must succeed via:
//!      - master GET fails (connect error → `is_master_unreachable_error`)
//!      - `try_offline_fallback` looks up KEY_TO_CID for the storage
//!        key → hit (populated by phase 1b)
//!      - BLOCKS lookup for the resolved CID → hit (populated by
//!        phase 1b's master reads) → return bytes WITHOUT any network
//!        call (`client.rs:765-785`).
//!
//! Because phase 2 hits the BLOCKS cache, the test does NOT depend on
//! public IPFS gateways being reachable, the master's pinning chain
//! having replicated yet, or any network round-trip on the offline
//! side. It purely validates the warm-cache → CID-resolution → bytes
//! path that backs FxFiles' offline reads. Cold-start (Phase 3.3 IPNS
//! + chain) is a separate, harder test and is not exercised here.

use fula_client::{Config, EncryptedClient, EncryptionConfig};
use fula_crypto::keys::SecretKey;
use std::time::Duration;
use tempfile::TempDir;

/// Read an environment variable. Returns `None` (and prints a clear
/// notice) if missing or empty so the test gracefully skips when run
/// without credentials, instead of failing with a confusing assertion.
fn read_required_env(var: &str) -> Option<String> {
    match std::env::var(var) {
        Ok(v) if !v.is_empty() => Some(v),
        _ => {
            eprintln!(
                "[offline_e2e] {} is not set or empty — skipping the test. \
                 Set it to a real value to run.",
                var
            );
            None
        }
    }
}

/// Build an `EncryptedClient` with the same flags FxFiles ships in
/// production (`fula_api_service.dart:139-167`).
///
/// Two knobs are configurable per phase:
///   * `master_url`  — real S3 endpoint in phase 1, bogus in phase 2.
///   * `health_gate` — `true` matches production. Set `false` for the
///                     offline phase so the unreachable URL surfaces
///                     as a connect error on the first call (no need
///                     to wait for the gate's two-failure threshold).
fn build_client(
    master_url: &str,
    jwt: &str,
    cache_path: &std::path::Path,
    secret: SecretKey,
    health_gate: bool,
    timeout_secs: u64,
) -> EncryptedClient {
    let mut cfg = Config::new(master_url).with_token(jwt);
    cfg.timeout = Duration::from_secs(timeout_secs);

    // Mirror FxFiles config (fula_api_service.dart:151-167).
    cfg.health_gate_enabled = health_gate;
    cfg.health_gate_ttl = Duration::from_secs(30);

    cfg.block_cache_enabled = true;
    cfg.block_cache_path = Some(cache_path.to_path_buf());
    cfg.block_cache_max_bytes = 256 * 1024 * 1024;

    cfg.gateway_fallback_enabled = true;
    cfg.gateway_fallback_urls = Vec::new(); // SDK-shipped 6-gateway default
    cfg.gateway_race_concurrency = 3;

    let enc = EncryptionConfig::from_secret_key(secret);
    EncryptedClient::new(cfg, enc).expect("EncryptedClient construction must succeed")
}

/// Run the full e2e flow with a payload size of `payload_size_bytes` and
/// a `test_key_label` that goes into the file name. Lets us cover both the
/// single-object path (≤ 768 KB chunked threshold) and the chunked path
/// (> 768 KB, which is what almost every FxFiles photo / video / pdf hits)
/// without duplicating the test scaffolding.
async fn run_offline_upload_download_e2e(
    payload_size_bytes: usize,
    test_key_label: &str,
) {
    // ─── Inputs ───────────────────────────────────────────────────────
    let jwt = match read_required_env("FULA_JWT") {
        Some(v) => v,
        None => return,
    };
    let s3_url = match read_required_env("FULA_S3") {
        Some(v) => v,
        None => return,
    };
    let bucket = std::env::var("FULA_BUCKET")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "other".to_string());
    let timeout_secs: u64 = std::env::var("FULA_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(60);

    eprintln!("\n[offline_e2e:{}] master = {}", test_key_label, s3_url);
    eprintln!("[offline_e2e:{}] bucket = {}", test_key_label, bucket);
    eprintln!(
        "[offline_e2e:{}] timeout = {}s, payload size = {} bytes ({} path)",
        test_key_label,
        timeout_secs,
        payload_size_bytes,
        if payload_size_bytes > 768 * 1024 {
            "chunked"
        } else {
            "single-object"
        }
    );

    let cache_dir = TempDir::new().expect("tempdir for block cache");
    let cache_path = cache_dir.path().join("blocks.redb");

    let secret = SecretKey::generate();

    let test_key = format!(
        "fula-offline-e2e-{}-{}.bin",
        test_key_label,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    );
    // Deterministic payload of the requested size. For chunked tests
    // we want >768KB so the CHUNKED_THRESHOLD trips and the code goes
    // through `put_object_chunked_internal` (multi-chunk upload + index
    // object). The repeating pattern is content-irrelevant.
    let payload: Vec<u8> = (0..payload_size_bytes).map(|i| (i % 256) as u8).collect();

    eprintln!(
        "[offline_e2e:{}] test object = {} ({} bytes)",
        test_key_label,
        test_key,
        payload.len()
    );

    // ─── Phase 1a — Upload (creates the forest on master) ────────────
    eprintln!(
        "\n[offline_e2e:{}] phase 1a: UPLOAD — populate the master",
        test_key_label
    );
    {
        let client = build_client(
            &s3_url,
            &jwt,
            &cache_path,
            secret.clone(),
            true,
            timeout_secs,
        );
        client
            .put_object_flat(
                &bucket,
                &test_key,
                payload.clone(),
                Some("application/octet-stream"),
            )
            .await
            .expect("online upload must succeed against the real master");
        eprintln!(
            "[offline_e2e:{}]   upload OK ({} bytes)",
            test_key_label,
            payload.len()
        );
    }

    // ─── Phase 1b — Fresh client reads from master, populates cache ──
    eprintln!(
        "\n[offline_e2e:{}] phase 1b: FRESH READ — re-fetch from master, populate warm cache",
        test_key_label
    );
    {
        let client = build_client(
            &s3_url,
            &jwt,
            &cache_path,
            secret.clone(),
            true,
            timeout_secs,
        );
        let files = client
            .list_files_from_forest(&bucket)
            .await
            .expect("online list must succeed");
        assert!(
            files.iter().any(|f| f.original_key == test_key),
            "online list missing the just-uploaded file: {} (got {} files)",
            test_key,
            files.len()
        );
        eprintln!(
            "[offline_e2e:{}]   list OK ({} files in bucket, target found)",
            test_key_label,
            files.len()
        );

        let dl = client
            .get_object_flat(&bucket, &test_key)
            .await
            .expect("online download must succeed");
        assert_eq!(
            dl.as_ref(),
            payload.as_slice(),
            "online download bytes do not match the uploaded payload"
        );
        eprintln!(
            "[offline_e2e:{}]   download OK (bytes verified)",
            test_key_label
        );
    }

    // ─── Phase 2 — OFFLINE (warm cache hits) ─────────────────────────
    eprintln!(
        "\n[offline_e2e:{}] phase 2: OFFLINE — bogus master, expect warm-cache hits",
        test_key_label
    );
    {
        let client = build_client(
            "http://127.0.0.1:1",
            &jwt,
            &cache_path,
            secret,
            false,
            timeout_secs,
        );
        let files = client
            .list_files_from_forest(&bucket)
            .await
            .expect("offline list must succeed via warm-cache hits");
        assert!(
            files.iter().any(|f| f.original_key == test_key),
            "offline list missing the file: {} (got {} files)",
            test_key,
            files.len()
        );
        eprintln!(
            "[offline_e2e:{}]   list OK offline ({} files in bucket, target found)",
            test_key_label,
            files.len()
        );

        let dl = client
            .get_object_flat(&bucket, &test_key)
            .await
            .expect("offline download must succeed via warm-cache hits");
        assert_eq!(
            dl.as_ref(),
            payload.as_slice(),
            "offline download bytes do not match the original payload"
        );
        eprintln!(
            "[offline_e2e:{}]   download OK offline (bytes verified)",
            test_key_label
        );
    }

    eprintln!(
        "\n[offline_e2e:{}] PASS — offline encrypted upload/download works.",
        test_key_label
    );
}

/// Single-object path: payload below the 768 KB chunked threshold.
/// Exercises `put_object_flat` → single-block AEAD upload + the
/// HTTP-header `x-fula-encryption` round-trip stashed onto
/// `forest_entry.user_metadata`.
#[tokio::test]
#[ignore]
async fn offline_upload_download_single_object_e2e() {
    run_offline_upload_download_e2e(256, "single").await;
}

/// Chunked path: payload above the 768 KB threshold. Exercises
/// `put_object_chunked_internal` (index object + multiple chunk PUTs),
/// the offline-fallback wrapper for per-chunk fetches, and the
/// chunked-decrypt path (Bao streaming + per-chunk AAD-bound AEAD).
/// This covers the bulk of FxFiles content (photos / videos / PDFs).
#[tokio::test]
#[ignore]
async fn offline_upload_download_chunked_e2e() {
    // 1.5 MB → straddles the 768 KB threshold; produces 2-3 chunks.
    run_offline_upload_download_e2e(1_500_000, "chunked").await;
}

// Legacy entry-point name preserved for any CI workflow that
// references it; delegates to the single-object variant.
#[tokio::test]
#[ignore]
async fn offline_upload_download_e2e() {
    run_offline_upload_download_e2e(256, "single-legacy-alias").await;
}
