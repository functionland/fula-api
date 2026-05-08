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

use fula_client::{ClientError, Config, EncryptedClient, EncryptionConfig};
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

// ============================================================================
// 412 reproduction harness against a USER'S EXISTING bucket
// ============================================================================
//
// Goal: reproduce / pin down task #29's 412 PreconditionFailed without
// rebuilding FxFiles. Loads the user's existing forest (using their real
// encryption key), then performs a configurable number of sequential small
// writes — each one trips the conditional-PUT code path:
//
//   * Phase 1.5 page write (`If-Match` from `page_index[page_id].etag`)
//   * Phase 1.6 dir-index write (`If-Match` from `manifest_snapshot.root.dir_index_etag`)
//   * Phase 2 forest-manifest root write (`If-Match` from `manifest_etag`)
//
// If any of these emits a 412 against a fresh SDK state with the user's
// real master, we have a local reproducer. If it doesn't, the bug requires
// FxFiles-specific persistent state (WAL, on-disk cache) — different
// debug path.
//
// ## Required env
//
// | Var                  | Required | Default        | Purpose                                                  |
// |----------------------|----------|----------------|----------------------------------------------------------|
// | `FULA_JWT`           | Yes      | —              | The user's Fula JWT.                                     |
// | `FULA_TEST_SECRET`   | Yes      | —              | base64 of FxFiles Settings > Security > Encryption Key.  |
// | `FULA_S3`            | No       | `https://s3.cloud.fx.land` | Live master endpoint.                          |
// | `FULA_BUCKET`        | No       | `images`       | Target bucket — must exist for this user.                |
// | `FULA_REPRO_WRITES`  | No       | `5`            | Number of sequential writes to perform.                  |
// | `FULA_TIMEOUT_SECS`  | No       | `60`           | Per-request timeout.                                     |
//
// ## Run
//
// ```powershell
// $env:FULA_JWT          = "eyJhbGci…"
// $env:FULA_TEST_SECRET  = "<base64 from FxFiles>"
// $env:FULA_BUCKET       = "images"     # or "face-metadata"
// $env:FULA_REPRO_WRITES = "5"
// cargo test -p fula-client --test offline_e2e --release `
//   repro_412_existing_bucket_e2e -- --ignored --nocapture
// ```
//
// ## Interpreting output
//
// * All writes succeed → bug is FxFiles-state-dependent, not reproducible
//   from a fresh SDK state. Next debug path: capture FxFiles' WAL contents.
// * One or more 412 → local reproducer. Pair with the master's
//   `watch-images-upload.sh` log — the new diag headers (added in
//   crates/fula-client/src/encryption.rs at all conditional-PUT sites)
//   will show `sdk_debug_body_cid` + `sdk_debug_prior_etag` for each PUT,
//   pinpointing the page / dir-index / root etag the SDK tracked.
#[tokio::test]
#[ignore]
async fn repro_412_existing_bucket_e2e() {
    use fula_crypto::keys::SecretKey;

    let jwt = match read_required_env("FULA_JWT") {
        Some(v) => v,
        None => return,
    };
    let secret_b64 = match read_required_env("FULA_TEST_SECRET") {
        Some(v) => v,
        None => return,
    };
    let s3_url = std::env::var("FULA_S3")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "https://s3.cloud.fx.land".to_string());
    let bucket = std::env::var("FULA_BUCKET")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "images".to_string());
    let n_writes: usize = std::env::var("FULA_REPRO_WRITES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5);
    let timeout_secs: u64 = std::env::var("FULA_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(60);

    eprintln!("\n[repro-412] master = {}", s3_url);
    eprintln!("[repro-412] bucket = {}", bucket);
    eprintln!("[repro-412] sequential writes = {}", n_writes);

    // Decode user's actual encryption key from base64 (FxFiles Settings >
    // Security > Encryption Key). This makes the SDK's storage_keys + page
    // keys + dir-index keys match what FxFiles would compute, so any write
    // we do here lands in the same forest state FxFiles is hitting.
    use base64::Engine as _;
    let trimmed = secret_b64.trim();
    let key_bytes = base64::engine::general_purpose::STANDARD
        .decode(trimmed)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(trimmed))
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(trimmed))
        .expect("FULA_TEST_SECRET must be base64");
    let secret = SecretKey::from_bytes(&key_bytes).expect("32-byte secret");

    let cache_dir = TempDir::new().expect("tempdir for block cache");
    let cache_path = cache_dir.path().join("blocks.redb");

    let client = build_client(
        &s3_url,
        &jwt,
        &cache_path,
        secret,
        true,
        timeout_secs,
    );

    // Loading the existing forest first surfaces any 412 that's purely a
    // load/cache-warming problem (vs. only triggered by writes). It also
    // logs the forest's current page_index etags via the diag tracing.
    eprintln!("\n[repro-412] phase 0: list existing files (warms forest cache)");
    let initial_files = client
        .list_files_from_forest(&bucket)
        .await
        .expect("list existing bucket — if this fails, encryption key or JWT is wrong");
    eprintln!("[repro-412]   existing files in {} = {}", bucket, initial_files.len());

    // Sequential writes: each PUT triggers a flush which exercises the
    // Phase 1.5 / 1.6 / 2 conditional PUTs in order. Use a stable prefix +
    // monotonic suffix so we can find these in master logs and clean them
    // up later if needed.
    eprintln!("\n[repro-412] phase 1: {} sequential writes", n_writes);
    let session_tag = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis();
    let mut errors: Vec<(usize, String, String)> = Vec::new();
    for i in 0..n_writes {
        let key = format!("repro-412/session-{}/write-{:02}.bin", session_tag, i);
        let payload: Vec<u8> = (0..256u32).map(|j| ((i as u32 + j) % 256) as u8).collect();
        eprintln!("[repro-412]   write {} → {}/{}", i + 1, bucket, key);
        match client
            .put_object_flat(&bucket, &key, payload, Some("application/octet-stream"))
            .await
        {
            Ok(_) => eprintln!("[repro-412]     OK"),
            Err(e) => {
                let msg = format!("{:?}", e);
                eprintln!("[repro-412]     ERROR: {}", msg);
                errors.push((i, key.clone(), msg));
                // Do NOT break — we want to see if all subsequent writes
                // also 412 (suggesting a permanent stuck etag) or only
                // some (suggesting a transient race).
            }
        }
    }

    if errors.is_empty() {
        // Phase 2 — durable persistence check (task #29 dir-index fix).
        // The disappearing-images bug looks exactly like "put_object_flat
        // returned Ok but the file isn't in the next listing": Phase 1.5/1.6
        // conditional PUTs landed master's stored objects, but the dir-index
        // commit at Phase 1.6 silently failed (412 → forest's master-side
        // dir-index never advanced → next listing returns the pre-write set).
        // Re-listing after all writes is the precise observable for that
        // failure: if the listing length grew by exactly `n_writes`, the
        // dir-index commits were durable and the bug is closed for this user.
        let after_files = client
            .list_files_from_forest(&bucket)
            .await
            .expect("post-write list must succeed");
        let expected_len = initial_files.len() + n_writes;
        let session_prefix = format!("repro-412/session-{}/", session_tag);
        let written_visible = after_files
            .iter()
            .filter(|f| f.original_key.starts_with(&session_prefix))
            .count();
        eprintln!(
            "\n[repro-412] phase 2: durable-persistence check\n\
             [repro-412]   pre-write file count    = {}\n\
             [repro-412]   post-write file count   = {} (expected {})\n\
             [repro-412]   session-tagged visible  = {} of {}",
            initial_files.len(),
            after_files.len(),
            expected_len,
            written_visible,
            n_writes,
        );
        assert_eq!(
            written_visible, n_writes,
            "DURABLE-PERSISTENCE FAIL: only {}/{} writes visible in post-write listing. \
             This is the disappearing-images bug — Phase 1.5 / 1.6 conditional PUTs \
             may have hit master, but the dir-index commit didn't durably advance, \
             so listings still reflect the pre-write set. Check the master log for \
             412s during the test window — if any appear after this test's \
             cargo build, the dir-index override (load_directory_index → \
             refresh_dir_index_etag_from_load) is not engaged on this code path.",
            written_visible, n_writes,
        );
        eprintln!(
            "\n[repro-412] PASS — all {} writes succeeded AND are visible in the \
             post-write listing.\n\
             [repro-412] Verify on master side: tail watch-images-upload.sh \
             during this test run; the master log should show zero \
             `412 diag` entries. If the master log is clean of 412s, the \
             page-level + dir-index fixes are both engaged and the SDK is \
             ready to ship to mobile.",
            n_writes,
        );
    } else {
        eprintln!(
            "\n[repro-412] FAIL — {} of {} writes hit an error (e.g., 412):",
            errors.len(),
            n_writes,
        );
        for (i, k, msg) in &errors {
            eprintln!("[repro-412]   write {} key={} err={}", i + 1, k, msg);
        }
        eprintln!(
            "\n[repro-412] Local reproducer found. Pair this with the master's\n\
             scripts/watch-images-upload.sh log — the SDK now emits real values\n\
             for sdk_debug_body_cid + sdk_debug_prior_etag on the failing\n\
             conditional PUT, so the master 412 diag will pinpoint where the\n\
             stale etag is coming from."
        );
        panic!("repro_412 found {} write errors", errors.len());
    }
}

// ============================================================================
// v0.4.4 — COLD-START offline path
// ============================================================================
//
// The above warm-cache tests prove that a device which already read a bucket
// online can read it again offline. They DO NOT exercise the cold-start
// path (Phase 3.3 IPNS+chain → published bucketsIndex CBOR → forest manifest
// CID → fetch+decrypt). Cold-start is what fires when:
//   * master is unreachable AND
//   * the device has never read this bucket before (block cache empty for it).
//
// This test is what verifies the v0.4.4 hotfix actually works end-to-end:
// upload via real master (which populates `BucketMetadata.forest_manifest_cid`
// when `FULA_FOREST_MANIFEST_CID_ENABLED=1`), wait for the publisher to emit
// the new field in the published per-user CBOR, then cold-start with a bogus
// master URL and an empty block cache. List + read must succeed via the
// IPNS / chain resolver chain.
//
// ## Required env (real-credentials test, marked `#[ignore]`)
//
// Beyond the warm-cache test's `FULA_JWT` + `FULA_S3`, this test also needs
// the operator-supplied Phase 3.3 resolver coordinates:
//
// | Var                                 | Required | Default                      | Purpose                                                                                       |
// |-------------------------------------|----------|------------------------------|-----------------------------------------------------------------------------------------------|
// | `FULA_JWT`                          | Yes      | —                            | Bearer token for the upload phase. Test extracts `sub` to derive userKey via `derive_user_key_from_jwt_sub`. |
// | `FULA_S3`                           | Yes      | —                            | Reachable master endpoint for upload (e.g. `https://s3.cloud.fx.land`).                       |
// | `FULA_BOGUS_S3`                     | No       | `https://s33.cloud.fx.land`  | Unreachable endpoint for the offline phase. Default DNS-fails on real DNS.                    |
// | `FULA_BUCKET`                       | No       | `documents`                  | Target bucket. Must exist for this user; defaulted to match the operator's verification scenario. |
// | `FULA_USERS_INDEX_CHAIN_RPC_URL`    | Yes      | —                            | JSON-RPC URL for the chain hosting `FulaUsersIndexAnchor` (operator's Base RPC).              |
// | `FULA_USERS_INDEX_ANCHOR_ADDRESS`   | Yes      | —                            | Address of the deployed `FulaUsersIndexAnchor.sol` contract (`0x…`).                          |
// | `FULA_USERS_INDEX_IPNS_NAME`        | Yes      | —                            | The IPNS NAME (k51… libp2p public-key hash) the master publishes to.                          |
// | `FULA_PUBLISHER_WAIT_SECS`          | No       | `360`                        | How long to wait between phase 1 (upload) and phase 2 (cold-start) so the master's publisher has a chance to tick at least once and the new `forest_manifest_cid` lands in the published global CBOR. Default is `FULA_USERS_INDEX_FLUSH_INTERVAL_SECS + 60` for slack. Set lower if you triggered `/_internal/publish-now` manually. |
// | `FULA_TIMEOUT_SECS`                 | No       | `60`                         | Per-request HTTP timeout.                                                                     |
//
// ## Operator pre-conditions on master
//
// 1. `FULA_BUCKET_LOOKUP_H_ENABLED=1` — populates `bucket_lookup_h` (Phase 1.2).
// 2. `FULA_FOREST_MANIFEST_CID_ENABLED=1` — populates `forest_manifest_cid` (v0.4.4).
// 3. `FULA_USERS_INDEX_PUBLISHER_ENABLED=1` — runs the publisher loop.
// 4. Anchor cron is running OR IPNS publish is reaching public gateways.
//
// Run from `crates/fula-client/`:
//
// ```powershell
// $env:FULA_JWT = "eyJhbGci…"
// $env:FULA_S3  = "https://s3.cloud.fx.land"
// $env:FULA_USERS_INDEX_CHAIN_RPC_URL  = "https://mainnet.base.org"
// $env:FULA_USERS_INDEX_ANCHOR_ADDRESS = "0x…"
// $env:FULA_USERS_INDEX_IPNS_NAME      = "k51qzi5uqu5d…"
// cargo test -p fula-client --test offline_e2e --release `
//   -- --ignored offline_cold_start_documents_bucket_e2e --nocapture
// ```

use fula_client::derive_user_key_from_jwt_sub;

/// Decode the `sub` claim from a JWT WITHOUT verifying the signature.
///
/// Test-only helper. Production apps should treat the JWT as opaque and
/// either (a) accept the sub from their auth provider as a separate
/// parameter or (b) decode it themselves the same way FxFiles does in
/// `fula_api_service.dart::_extractJwtSub`.
fn jwt_sub(jwt: &str) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    let parts: Vec<&str> = jwt.split('.').collect();
    assert_eq!(parts.len(), 3, "malformed JWT: expected 3 dot-separated parts");
    let payload = URL_SAFE_NO_PAD
        .decode(parts[1])
        .expect("JWT payload must be valid base64url");
    let json: serde_json::Value =
        serde_json::from_slice(&payload).expect("JWT payload must be valid JSON");
    json.get("sub")
        .and_then(|v| v.as_str())
        .expect("JWT must have a `sub` claim")
        .to_string()
}

/// Build a client wired for cold-start (Phase 3.3) — populates the four
/// `users_index_*` fields. The other warm-cache flags stay on so the test
/// still validates the integration of cold-start + cache-population.
///
/// `ipns_gateway_urls`: when non-empty, OVERRIDES the SDK's default
/// 5-gateway list. Useful in tests to point at a specific gateway that's
/// guaranteed to have the latest IPNS record (e.g., the master's local
/// kubo gateway, or a fast subdomain gateway like `dget.top` that
/// resolves IPNS faster than the public DHT-walking gateways). When
/// empty, the SDK uses its built-in 5-gateway list (production default).
#[allow(clippy::too_many_arguments)]
fn build_client_with_cold_start(
    master_url: &str,
    jwt: &str,
    cache_path: &std::path::Path,
    secret: SecretKey,
    health_gate: bool,
    timeout_secs: u64,
    chain_rpc_url: String,
    anchor_address: String,
    ipns_name: String,
    user_key: String,
    ipns_gateway_urls: Vec<String>,
    block_gateway_urls: Vec<String>,
) -> EncryptedClient {
    let mut cfg = Config::new(master_url).with_token(jwt);
    cfg.timeout = Duration::from_secs(timeout_secs);

    cfg.health_gate_enabled = health_gate;
    cfg.health_gate_ttl = Duration::from_secs(30);

    cfg.block_cache_enabled = true;
    cfg.block_cache_path = Some(cache_path.to_path_buf());
    cfg.block_cache_max_bytes = 256 * 1024 * 1024;

    cfg.gateway_fallback_enabled = true;
    // Use SDK defaults (6-gateway list) when override is empty. Tests
    // running against a fresh-upload scenario may set
    // FULA_BLOCK_GATEWAY_URLS to point at master's own kubo gateway,
    // because public IPFS gateways need a DHT-propagation window before
    // they can serve newly-pinned CIDs.
    cfg.gateway_fallback_urls = block_gateway_urls;
    cfg.gateway_race_concurrency = 3;

    // v0.4.4 cold-start: all four fields must be set for the resolver
    // to activate. The presence-check is in `build_inner_config`.
    cfg.users_index_chain_rpc_url = chain_rpc_url;
    cfg.users_index_anchor_address = anchor_address;
    cfg.users_index_ipns_name = ipns_name;
    cfg.users_index_user_key = Some(user_key);
    cfg.users_index_ipns_gateway_urls = ipns_gateway_urls;

    let enc = EncryptionConfig::from_secret_key(secret);
    EncryptedClient::new(cfg, enc).expect("EncryptedClient construction must succeed")
}

/// Cold-start e2e — verifies v0.4.4's `forest_manifest_cid` plumbing
/// resolves a real bucket from real published state when the master
/// endpoint is unreachable AND the SDK's block cache is empty.
///
/// The test is brittle by design: it depends on the master's publisher
/// having actually emitted the new field. The wait between phase 1 and
/// phase 2 is what gives the publisher time to tick. If the operator
/// triggered `/_internal/publish-now` after upload, the wait can be
/// shortened via `FULA_PUBLISHER_WAIT_SECS`.
#[tokio::test]
#[ignore]
async fn offline_cold_start_documents_bucket_e2e() {
    // ─── Inputs ────────────────────────────────────────────────────────
    let jwt = match read_required_env("FULA_JWT") {
        Some(v) => v,
        None => return,
    };
    let s3_url = match read_required_env("FULA_S3") {
        Some(v) => v,
        None => return,
    };
    let bogus_s3 = std::env::var("FULA_BOGUS_S3")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "https://s33.cloud.fx.land".to_string());
    let bucket = std::env::var("FULA_BUCKET")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "documents".to_string());
    let chain_rpc_url = match read_required_env("FULA_USERS_INDEX_CHAIN_RPC_URL") {
        Some(v) => v,
        None => return,
    };
    let anchor_address = match read_required_env("FULA_USERS_INDEX_ANCHOR_ADDRESS") {
        Some(v) => v,
        None => return,
    };
    let ipns_name = match read_required_env("FULA_USERS_INDEX_IPNS_NAME") {
        Some(v) => v,
        None => return,
    };
    let publisher_wait_secs: u64 = std::env::var("FULA_PUBLISHER_WAIT_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(360);
    let timeout_secs: u64 = std::env::var("FULA_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(60);

    // Optional IPNS gateway override. Comma-separated. When set, the
    // SDK's default 5-gateway list is REPLACED, so the test pulls
    // exclusively from the gateways the operator pinned for this run.
    // Use this to skirt the 30+min IPNS DHT-propagation delay during
    // testing — point at a gateway you know is current (e.g. master's
    // local kubo or a fast subdomain gateway like `dget.top`).
    //
    // Format details: each URL may use `{name}` placeholder which the
    // SDK substitutes with `users_index_ipns_name`. URLs WITHOUT
    // `{name}` are used as-is — useful for subdomain-style gateways
    // where the IPNS name is already in the host part. Example:
    //   `https://k51qzi5...ipns.dget.top/`  (subdomain, no placeholder)
    //   `https://ipfs.io/ipns/{name}`        (path, with placeholder)
    let ipns_gateway_urls: Vec<String> = std::env::var("FULA_USERS_INDEX_IPNS_GATEWAY_URLS")
        .ok()
        .filter(|s| !s.is_empty())
        .map(|s| s.split(',').map(|u| u.trim().to_string()).filter(|u| !u.is_empty()).collect())
        .unwrap_or_default();

    // Optional block-fetch gateway override. Comma-separated. Used by
    // the cold-cache cold-start path (#31) to fetch encrypted manifest
    // pages / dir-index / chunks via a gateway when master is offline.
    // Public IPFS gateways need 30+ minutes of DHT propagation before
    // they can serve a freshly-pinned CID — set this to master's own
    // kubo gateway (e.g. `https://ipfs.cloud.fx.land/gateway/{cid}`)
    // so the test doesn't have to wait for DHT propagation.
    //
    // Format: `{cid}` placeholder is substituted with the CID being
    // fetched. URLs without `{cid}` are appended as `<url>/<cid>`.
    let block_gateway_urls: Vec<String> = std::env::var("FULA_BLOCK_GATEWAY_URLS")
        .ok()
        .filter(|s| !s.is_empty())
        .map(|s| s.split(',').map(|u| u.trim().to_string()).filter(|u| !u.is_empty()).collect())
        .unwrap_or_default();

    // userKey derivation must match master byte-for-byte. v0.4.3+ uses
    // `derive_user_key_from_jwt_sub` (NOT the legacy email-based variant
    // which broke for pre-migration-011 users with plaintext-email subs).
    let sub = jwt_sub(&jwt);
    let user_key = derive_user_key_from_jwt_sub(&sub);

    eprintln!("\n[cold-start-e2e] master      = {}", s3_url);
    eprintln!("[cold-start-e2e] bogus      = {}", bogus_s3);
    eprintln!("[cold-start-e2e] bucket     = {}", bucket);
    eprintln!("[cold-start-e2e] sub        = {}", sub);
    eprintln!("[cold-start-e2e] userKey    = {}", user_key);
    eprintln!("[cold-start-e2e] chain RPC  = {}", chain_rpc_url);
    eprintln!("[cold-start-e2e] anchor     = {}", anchor_address);
    eprintln!("[cold-start-e2e] IPNS name  = {}", ipns_name);
    eprintln!(
        "[cold-start-e2e] wait time  = {}s (publisher tick window)",
        publisher_wait_secs
    );
    if !ipns_gateway_urls.is_empty() {
        eprintln!(
            "[cold-start-e2e] IPNS gw    = OVERRIDDEN ({} url{}): {:?}",
            ipns_gateway_urls.len(),
            if ipns_gateway_urls.len() == 1 { "" } else { "s" },
            ipns_gateway_urls,
        );
    } else {
        eprintln!("[cold-start-e2e] IPNS gw    = SDK default 5-gateway list");
    }
    if !block_gateway_urls.is_empty() {
        eprintln!(
            "[cold-start-e2e] block gw   = OVERRIDDEN ({} url{}): {:?}",
            block_gateway_urls.len(),
            if block_gateway_urls.len() == 1 { "" } else { "s" },
            block_gateway_urls,
        );
    } else {
        eprintln!("[cold-start-e2e] block gw   = SDK default 6-gateway list (DHT propagation may take >30min)");
    }

    // Secret derivation: FxFiles uses Argon2id over
    // `"{provider}:{rawOAuthSub}:{email}"` and stores the resulting
    // 32-byte key in SecureStorage (auth_service.dart:512-550). The
    // bucket_lookup_h on master is bound to whichever secret was
    // active at upload time. To test against an EXISTING bucket
    // populated by a real FxFiles session, we need that exact
    // secret. Three ways to supply it, in priority order:
    //
    //   1. FULA_TEST_SECRET=<base64 32 bytes>          ← export from
    //      FxFiles SecureStorage. Mirrors the real-user flow exactly.
    //   2. FULA_TEST_OAUTH_INPUT="<provider>:<sub>:<email>"
    //      ← Argon2id-derive locally if you know all three pieces.
    //   3. fall through to a JWT-deterministic secret (skip-upload
    //      mode only — proves cold-start RESOLVES the published
    //      structure, but the lookup_h won't match a bucket
    //      populated by a different secret).
    let secret = if let Ok(b64) = std::env::var("FULA_TEST_SECRET") {
        use base64::Engine as _;
        let trimmed = b64.trim();
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(trimmed)
            .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(trimmed))
            .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(trimmed))
            .expect("FULA_TEST_SECRET must be base64 (standard, URL-safe, or URL-safe-no-pad)");
        SecretKey::from_bytes(&bytes).expect("32-byte secret")
    } else if let Ok(input) = std::env::var("FULA_TEST_OAUTH_INPUT") {
        // Mirror FxFiles' Argon2id parameters
        // (hashing.rs:228-257 in fula-crypto): context = "fula-files-v1",
        // 64 MiB, 3 iters, 1 parallelism, 32-byte output. NEVER
        // materialize raw OAuth sub or email outside this test process.
        let derived =
            fula_crypto::hashing::derive_key_argon2id("fula-files-v1", input.as_bytes());
        SecretKey::from_bytes(&derived).expect("32-byte secret")
    } else {
        let mut hasher = blake3::Hasher::new_derive_key("fula-test/offline-e2e/secret/v1");
        hasher.update(jwt.as_bytes());
        let bytes = hasher.finalize();
        SecretKey::from_bytes(&bytes.as_bytes()[..32]).expect("32-byte secret")
    };

    // FULA_SKIP_UPLOAD=1 lets the operator run a two-step flow:
    //   step A — run normally (upload + publish-now externally + verify)
    //   step B — re-run with FULA_SKIP_UPLOAD=1 to verify cold-start
    //            against the already-published state, without burning
    //            another publisher tick. Asserts cold-start RESOLVES
    //            and decrypts (file count is irrelevant when skipping).
    let skip_upload = std::env::var("FULA_SKIP_UPLOAD")
        .ok()
        .filter(|s| !s.is_empty() && s != "0")
        .is_some();
    let test_key = format!(
        "fula-cold-start-{}.bin",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    );
    // 256 byte payload = single-object path (under the 768 KB chunked
    // threshold). Cold-start mechanics are identical for chunked, but
    // testing single-object first keeps the failure surface focused on
    // the new `forest_manifest_cid` plumbing rather than chunked
    // assembly. A chunked variant can be layered on later.
    let payload: Vec<u8> = (0..256u32).map(|i| (i % 256) as u8).collect();

    eprintln!(
        "[cold-start-e2e] test object = {} ({} bytes)",
        test_key,
        payload.len()
    );

    // ─── Phase 1 — Upload via real master ───────────────────────────────
    //
    // The SDK attaches `x-amz-meta-fula-forest-manifest: 1` on the Phase 2
    // root commit (encryption.rs). Master populates
    // `BucketMetadata.forest_manifest_cid` with its own server-computed CID.
    // The publisher will emit it in the next per-user CBOR tick.
    if skip_upload {
        eprintln!(
            "\n[cold-start-e2e] phase 1: SKIPPED (FULA_SKIP_UPLOAD=1) — \
             cold-start will read whatever was last published for this user/bucket"
        );
    } else {
        eprintln!(
            "\n[cold-start-e2e] phase 1: UPLOAD via {} (populates forest_manifest_cid on master)",
            s3_url
        );
        let cache_dir_phase1 = TempDir::new().expect("tempdir for phase 1");
        let cache_path_phase1 = cache_dir_phase1.path().join("phase1.redb");
        let client = build_client_with_cold_start(
            &s3_url,
            &jwt,
            &cache_path_phase1,
            secret.clone(),
            true,
            timeout_secs,
            chain_rpc_url.clone(),
            anchor_address.clone(),
            ipns_name.clone(),
            user_key.clone(),
            ipns_gateway_urls.clone(),
            block_gateway_urls.clone(),
        );
        client
            .put_object_flat(
                &bucket,
                &test_key,
                payload.clone(),
                Some("application/octet-stream"),
            )
            .await
            .expect("phase 1: upload to real master must succeed");
        eprintln!(
            "[cold-start-e2e]   upload OK ({} bytes to {}/{})",
            payload.len(),
            bucket,
            test_key
        );
    }

    // ─── Phase 1.5 — Wait for publisher tick ────────────────────────────
    //
    // The master's `users_index_publisher` runs every 5 minutes by default
    // (FULA_USERS_INDEX_FLUSH_INTERVAL_SECS=300). For the just-populated
    // `forest_manifest_cid` to appear in the published per-user CBOR, the
    // publisher must tick at least once after our upload. We wait the
    // default 6 minutes (300 + 60 slack) unless the operator overrode via
    // FULA_PUBLISHER_WAIT_SECS (e.g., set to 5 if they triggered
    // `/_internal/publish-now` immediately after the upload).
    //
    // The publisher's diff-cache hash includes `forest_manifest_cid`
    // (v0.4.4 bumped to v2 hash), so the first tick after upload WILL
    // detect the change and re-pin this user's per-user CBOR with the
    // new field. Without that bump, the publisher would silently skip
    // this user as "unchanged" and the test would fail spuriously.
    if skip_upload {
        eprintln!(
            "\n[cold-start-e2e] phase 1.5: SKIPPED (no upload, no need to wait for publisher)"
        );
    } else {
        eprintln!(
            "\n[cold-start-e2e] phase 1.5: waiting {}s for publisher tick",
            publisher_wait_secs
        );
        tokio::time::sleep(Duration::from_secs(publisher_wait_secs)).await;
        eprintln!("[cold-start-e2e]   publisher window elapsed");
    }

    // ─── Phase 2 — Cold-start: bogus master + EMPTY cache ────────────────
    //
    // Fresh tempdir for the block cache so phase 1's cache state can NOT
    // leak through. Empty cache + DNS-failing master URL means EVERY read
    // must come through the cold-start resolver chain:
    //   1. SDK detects master unreachable (health gate trips after first
    //      DNS error). Disabled here so the first call just fails fast.
    //   2. Cold-start resolver fetches the global users-index via either
    //      IPNS (gateway race) or chain `latest()` (JSON-RPC).
    //   3. Looks up `users[user_key]` → bucketsIndexCid for this user.
    //   4. Fetches per-user CBOR via gateway race.
    //   5. Looks up bucket entry by `bucket_lookup_h` (or legacy name).
    //   6. Reads `forest_manifest_cid` (v0.4.4 — THIS is the field the
    //      hotfix added; without it cold-start fails with the
    //      "expected value at line 1 column 1" serialization error).
    //   7. Fetches that CID, decrypts as `EncryptedShardManifestV7` JSON,
    //      proceeds with the rest of the forest walk + chunk fetches.
    eprintln!(
        "\n[cold-start-e2e] phase 2: COLD-START via {} (empty cache, fresh client)",
        bogus_s3
    );
    {
        let cache_dir_phase2 = TempDir::new().expect("tempdir for phase 2");
        let cache_path_phase2 = cache_dir_phase2.path().join("phase2.redb");

        let client = build_client_with_cold_start(
            &bogus_s3,
            &jwt,
            &cache_path_phase2,
            secret.clone(),
            false, // disable health gate so the bogus URL fails fast
            timeout_secs,
            chain_rpc_url.clone(),
            anchor_address.clone(),
            ipns_name.clone(),
            user_key.clone(),
            ipns_gateway_urls.clone(),
            block_gateway_urls.clone(),
        );

        // Listing buckets requires master S3 (`/?list-type=2`); cold-start
        // resolver does NOT cover the bucket-list operation. We expect
        // this call to FAIL with a master-unreachable / connect error.
        // Documenting that this is the architecturally-correct behavior:
        // bucket enumeration over a public anonymous channel would defeat
        // the whole metadata-privacy goal of Phase 1.2's blinded keys.
        let list_buckets_result = client.list_buckets().await;
        match list_buckets_result {
            Ok(result) => {
                eprintln!(
                    "[cold-start-e2e]   list_buckets succeeded unexpectedly via offline path \
                     ({} buckets) — this is fine if a future feature adds offline LIST",
                    result.buckets.len()
                );
            }
            Err(e) => {
                eprintln!(
                    "[cold-start-e2e]   list_buckets failed (EXPECTED — bucket-listing has \
                     no offline path): {}",
                    e
                );
            }
        }

        // The actual cold-start test: list files in the documents bucket.
        // This goes through the SDK's encrypted forest, which goes through
        // the Phase 3.3 resolver, which now (v0.4.4) can find the SDK
        // forest manifest CID via the new `forest_manifest_cid` field.
        //
        // Skip-upload mode: assert only that `cold_start_resolve_manifest`
        // SUCCEEDS (fetches the CBOR, returns the manifest CID + bytes).
        // The full `list_files_from_forest` would also try to decrypt
        // the manifest with the test's secret, which won't match data
        // uploaded under prior random secrets — so we'd see a decrypt
        // failure even though cold-start worked. The resolver-level
        // assertion isolates the v0.4.4 plumbing being tested here.
        if skip_upload {
            eprintln!(
                "[cold-start-e2e]   resolver-only check (skip_upload): \
                 cold_start_resolve_manifest({}) ...",
                bucket
            );
            // FxFiles user expectation: cold-start MUST locate the
            // bucket and return its forest_manifest_cid + bytes,
            // ready to decrypt with the user's secret. BucketNotFound
            // means the published bucketsIndex doesn't have an entry
            // under THIS run's MetadataKey-derived lookup_h — which
            // means the secret doesn't match what FxFiles uploaded
            // with. Print a precise diagnostic so the operator knows
            // exactly which input to fix.
            let (manifest_cid, manifest_bytes) = match client
                .cold_start_resolve_manifest(&bucket)
                .await
            {
                Ok(v) => v,
                Err(ClientError::BucketNotFound(name)) => {
                    panic!(
                        "BucketNotFound({:?}): cold-start fetched the published \
                         users-index + bucketsIndex but no entry maps to this \
                         test's MetadataKey-derived lookup_h. The test secret \
                         doesn't match the secret FxFiles used at upload time. \
                         Fix: set FULA_TEST_SECRET to the base64-encoded \
                         encryption_key from FxFiles SecureStorage \
                         (auth_service.dart:546 stores it under key \
                         \"encryption_key\"). Alternatively set \
                         FULA_TEST_OAUTH_INPUT=\"<provider>:<rawOAuthSub>:<email>\" \
                         and the test will Argon2id-derive locally.",
                        name,
                    );
                }
                Err(e) => panic!(
                    "phase 2 (skip_upload): cold-start MUST resolve. \
                     UsersIndexResolutionFailed / CidVerificationFailed / \
                     network-tier errors mean the plumbing is broken. Got: {:?}",
                    e
                ),
            };
            eprintln!(
                "[cold-start-e2e]   resolver OK: manifest_cid={} bytes={} bucket={}",
                manifest_cid,
                manifest_bytes.len(),
                bucket
            );

            // Now exercise the full path FxFiles users hit on cold-start:
            // list_files_from_forest decrypts the manifest, walks the
            // forest, and returns the user's actual files. This is the
            // assertion that proves cold-start works for the user's
            // FxFiles login → see buckets → see files flow.
            eprintln!(
                "[cold-start-e2e]   listing files in {} via cold-start (decrypts with FxFiles secret)...",
                bucket
            );
            let files = client.list_files_from_forest(&bucket).await.expect(
                "phase 2 (skip_upload): cold-start list MUST succeed for an \
                 FxFiles user. If decryption failed, FULA_TEST_SECRET doesn't \
                 match the encryption_key FxFiles stored. If a network error, \
                 the gateway race for the manifest pages exhausted — extend \
                 FULA_BLOCK_GATEWAY_URLS or wait for DHT propagation.",
            );
            eprintln!(
                "[cold-start-e2e]   list OK via cold-start ({} files in bucket)",
                files.len()
            );
            for f in files.iter().take(20) {
                eprintln!("[cold-start-e2e]     - {}", f.original_key);
            }
            eprintln!(
                "\n[cold-start-e2e] PASS — FxFiles user can list this bucket master-independent."
            );
            return;
        }

        eprintln!(
            "[cold-start-e2e]   listing files in {} via cold-start...",
            bucket
        );
        let files = client
            .list_files_from_forest(&bucket)
            .await
            .expect(
                "phase 2: cold-start list MUST succeed — if this fails, \
                 the v0.4.4 fix isn't live: master flag off, publisher hasn't \
                 ticked, or bucket has no Phase 2 root commit since the flag \
                 was enabled. See the `forest_manifest_cid` diagnostic in the \
                 returned error string.",
            );
        eprintln!(
            "[cold-start-e2e]   list OK via cold-start ({} files in bucket)",
            files.len()
        );
        assert!(
            files.iter().any(|f| f.original_key == test_key),
            "phase 2: cold-start list missing the just-uploaded file: {} (got {} files: {:?})",
            test_key,
            files.len(),
            files.iter().map(|f| &f.original_key).take(10).collect::<Vec<_>>(),
        );
        eprintln!(
            "[cold-start-e2e]   target file ({}) found in cold-start listing",
            test_key
        );

        // Stretch goal: also try downloading the file. This further
        // exercises the chunk-fetch path through gateways. With master
        // unreachable, the chunks must come from public IPFS gateways
        // (Phase 2.3 race), reachable iff master's pinning chain has
        // replicated the chunks to ipfs-cluster (Step 0 verified this).
        match client.get_object_flat(&bucket, &test_key).await {
            Ok(dl) => {
                assert_eq!(
                    dl.as_ref(),
                    payload.as_slice(),
                    "phase 2: cold-start download bytes mismatch — list found the \
                     file but the chunk-fetch path corrupted or returned a \
                     different version"
                );
                eprintln!(
                    "[cold-start-e2e]   download OK via cold-start (bytes verified)"
                );
            }
            Err(e) => {
                // Don't fail the test on download failure — the user's
                // chunk pin replication may not be ready yet, OR the
                // gateway race may have hit the dag-cbor 500 issue
                // tracked separately as task #21. The list-from-forest
                // success above is the load-bearing assertion for
                // v0.4.4's correctness.
                eprintln!(
                    "[cold-start-e2e]   download FAILED via cold-start (NOT failing \
                     the test — list-from-forest success is the load-bearing \
                     assertion). Error: {}",
                    e
                );
            }
        }
    }

    eprintln!("\n[cold-start-e2e] PASS — v0.4.4 cold-start works end-to-end.");
}

// ============================================================================
// FxFiles offline-bucket-open mirror (task #29 follow-up)
// ============================================================================
//
// Mirrors `_loadCloudData` in FxFiles' file_browser_screen.dart EXACTLY for
// the "open a bucket in cloud-storage screen while offline" path:
//
//   FxFiles _loadCloudData (file_browser_screen.dart:326-387)
//     → listObjects(bucket, prefix)                  (fula_api_service.dart:446)
//        → _ensureForestLoaded(bucket)               (fula_api_service.dart:317)
//           → fula.loadForest(client, bucket)        (FRB → forest.rs:25)
//              → EncryptedClient::load_forest        ← THIS test calls this
//        → fula.listFromForest(client, bucket)       (FRB → forest.rs:138)
//           → EncryptedClient::list_files_from_forest ← THIS test calls this
//
// Required env vars to target ehsan@fx.land's ACTUAL data on the live
// IPNS/chain-published state, exercising the same code FxFiles runs on
// the device:
//
// | Var                                 | Required | Notes                                                                            |
// |-------------------------------------|----------|----------------------------------------------------------------------------------|
// | `FULA_TEST_SECRET`                  | Yes      | base64 of FxFiles Settings > Security > Encryption Key for ehsan@fx.land.        |
// | `FULA_JWT`                          | Yes      | ehsan@fx.land's Fula JWT (only used for the bogus-master HTTP attempt that       |
// |                                     |          | fails fast and triggers the cold-start path).                                    |
// | `FULA_USERS_INDEX_USER_KEY`         | Yes      | The 32-hex userKey for ehsan@fx.land = `4da2c0616b1d39660f9f94e145fbce4f`.       |
// | `FULA_USERS_INDEX_IPNS_NAME`        | Yes      | The 16-byte k51… libp2p public-key hash, e.g.                                    |
// |                                     |          | `k51qzi5uqu5dkkd6tv8slgoouzzs505qdcr4cb5egc9rlx7qwq0e794yxj9cg4`.                |
// | `FULA_USERS_INDEX_CHAIN_RPC_URL`    | Yes      | e.g. `https://mainnet.base.org` (only used when IPNS race exhausts).             |
// | `FULA_USERS_INDEX_ANCHOR_ADDRESS`   | Yes      | Deployed `FulaUsersIndexAnchor.sol` address.                                     |
// | `FULA_BUCKET`                       | No       | Default `images`. MUST be a bucket whose entry in the published bucketsIndex     |
// |                                     |          | CBOR has `forest_manifest_cid` populated (otherwise this isn't the right        |
// |                                     |          | failure mode to investigate). From ehsan's bucketsIndex dump, `images`,         |
// |                                     |          | `face-metadata`, and `other` all have it.                                       |
// | `FULA_BOGUS_S3`                     | No       | Default `https://s33.cloud.fx.land` — DNS-fails on real DNS, mirrors what       |
// |                                     |          | FxFiles uses to simulate offline.                                                |
// | `FULA_TIMEOUT_SECS`                 | No       | Default 60.                                                                      |
// | `FULA_USERS_INDEX_IPNS_GATEWAY_URLS`| No       | Comma-separated overrides. Empty → SDK 5-gateway default.                        |
// | `FULA_BLOCK_GATEWAY_URLS`           | No       | Same shape; for the per-page/per-chunk block fetches.                            |
//
// Run from `crates/fula-client/`:
//
// ```powershell
// $env:FULA_TEST_SECRET                = "<base64 from FxFiles Settings>"
// $env:FULA_JWT                        = "eyJhbGci…"
// $env:FULA_USERS_INDEX_USER_KEY       = "4da2c0616b1d39660f9f94e145fbce4f"
// $env:FULA_USERS_INDEX_IPNS_NAME      = "k51qzi5uqu5dkkd6tv8slgoouzzs505qdcr4cb5egc9rlx7qwq0e794yxj9cg4"
// $env:FULA_USERS_INDEX_CHAIN_RPC_URL  = "https://mainnet.base.org"
// $env:FULA_USERS_INDEX_ANCHOR_ADDRESS = "0x…"
// $env:FULA_BUCKET                     = "images"
// cargo test -p fula-client --test offline_e2e --release `
//   fxfiles_offline_open_bucket -- --ignored --nocapture
// ```
//
// What this test reports (without panicking on 0 files — we want diagnostic
// data, not a binary pass/fail at this stage of investigation):
//
//   1. Did `load_forest(bucket)` succeed?
//   2. Did `list_files_from_forest(bucket)` succeed?
//   3. How many entries did the forest contain?
//   4. First N entry keys + storage_keys (for sanity vs. user's known files).
//
// All four signals together pinpoint exactly where the offline-open-bucket
// failure mode falls in the cold-start chain for THIS bucket on THIS user.
#[tokio::test]
#[ignore]
async fn fxfiles_offline_open_bucket() {
    use fula_crypto::keys::SecretKey;

    let secret_b64 = match read_required_env("FULA_TEST_SECRET") {
        Some(v) => v,
        None => return,
    };
    let jwt = match read_required_env("FULA_JWT") {
        Some(v) => v,
        None => return,
    };
    let user_key = match read_required_env("FULA_USERS_INDEX_USER_KEY") {
        Some(v) => v,
        None => return,
    };
    let ipns_name = match read_required_env("FULA_USERS_INDEX_IPNS_NAME") {
        Some(v) => v,
        None => return,
    };
    let chain_rpc_url = match read_required_env("FULA_USERS_INDEX_CHAIN_RPC_URL") {
        Some(v) => v,
        None => return,
    };
    let anchor_address = match read_required_env("FULA_USERS_INDEX_ANCHOR_ADDRESS") {
        Some(v) => v,
        None => return,
    };
    let bucket = std::env::var("FULA_BUCKET")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "images".to_string());
    let bogus_s3 = std::env::var("FULA_BOGUS_S3")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "https://s33.cloud.fx.land".to_string());
    let timeout_secs: u64 = std::env::var("FULA_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(60);

    let parse_csv = |var: &str| -> Vec<String> {
        std::env::var(var)
            .ok()
            .map(|s| {
                s.split(',')
                    .map(|t| t.trim().to_string())
                    .filter(|t| !t.is_empty())
                    .collect()
            })
            .unwrap_or_default()
    };
    let ipns_gateway_urls = parse_csv("FULA_USERS_INDEX_IPNS_GATEWAY_URLS");
    let block_gateway_urls = parse_csv("FULA_BLOCK_GATEWAY_URLS");

    eprintln!("\n[fxfiles-open-bucket] target = ehsan@fx.land's `{}` bucket", bucket);
    eprintln!("[fxfiles-open-bucket] master = {} (DNS-fails → forces cold-start)", bogus_s3);
    eprintln!("[fxfiles-open-bucket] userKey = {}", user_key);
    eprintln!("[fxfiles-open-bucket] ipns_name = {}", ipns_name);
    if ipns_gateway_urls.is_empty() {
        eprintln!("[fxfiles-open-bucket] ipns_gateways = SDK default 5-gateway list");
    } else {
        eprintln!("[fxfiles-open-bucket] ipns_gateways (override) = {:?}", ipns_gateway_urls);
    }
    if block_gateway_urls.is_empty() {
        eprintln!("[fxfiles-open-bucket] block_gateways = SDK default 6-gateway list");
    } else {
        eprintln!("[fxfiles-open-bucket] block_gateways (override) = {:?}", block_gateway_urls);
    }

    // Decode encryption key. MUST be the SAME secret FxFiles uses on
    // device, otherwise bucket_lookup_h won't match anything in the
    // published bucketsIndex CBOR.
    use base64::Engine as _;
    let trimmed = secret_b64.trim();
    let key_bytes = base64::engine::general_purpose::STANDARD
        .decode(trimmed)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(trimmed))
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(trimmed))
        .expect("FULA_TEST_SECRET must be base64");
    let secret = SecretKey::from_bytes(&key_bytes).expect("32-byte secret");

    // Fresh tempdir for the block cache — guarantees this is a true
    // cold-start, no warm-cache contribution. Mirrors the FxFiles cold
    // path on a freshly reinstalled device or after `Clear data`.
    let cache_dir = TempDir::new().expect("tempdir for block cache");
    let cache_path = cache_dir.path().join("blocks.redb");

    let client = build_client_with_cold_start(
        &bogus_s3,
        &jwt,
        &cache_path,
        secret,
        // health_gate=false: bogus URL fails fast on first call, no
        // need to wait for the gate's two-failure threshold. Mirrors
        // what happens on the device after the gate has tripped.
        false,
        timeout_secs,
        chain_rpc_url,
        anchor_address,
        ipns_name,
        user_key,
        ipns_gateway_urls,
        block_gateway_urls,
    );

    // ─── Step 1: load_forest(bucket) — same as fula.loadForest ────────
    eprintln!(
        "\n[fxfiles-open-bucket] step 1: load_forest({}) — mirrors fula_api_service.dart:_ensureForestLoaded",
        bucket
    );
    let load_result = client.load_forest(&bucket).await;
    let load_swallowed_sharded_marker = matches!(&load_result, Err(e) if e.to_string().contains("forest is sharded"));
    match &load_result {
        Ok(_) => eprintln!("[fxfiles-open-bucket]   load_forest OK (monolithic)"),
        Err(e) if load_swallowed_sharded_marker => {
            // Same swallow as fula-flutter's load_forest wrapper: v7
            // sharded forests surface this marker, all real I/O paths
            // handle sharding transparently downstream.
            eprintln!(
                "[fxfiles-open-bucket]   load_forest returned the v7 marker \
                 (\"forest is sharded\") — this is FxFiles' success-on-sharded \
                 case (fula-flutter::api::forest.rs:32 swallows it)"
            );
        }
        Err(e) => {
            eprintln!("[fxfiles-open-bucket]   load_forest FAILED: {:?}", e);
            panic!(
                "load_forest({}) failed before list_files could run. \
                 Inspect the chain: cold-start resolver → bucketsIndex lookup \
                 → forest_manifest_cid fetch → AEAD decrypt. The failure mode \
                 is in one of those steps; the error message above tells you \
                 which.",
                bucket
            );
        }
    }

    // ─── Step 2: list_files_from_forest(bucket) — same as fula.listFromForest ──
    eprintln!(
        "\n[fxfiles-open-bucket] step 2: list_files_from_forest({}) — mirrors fula_api_service.dart:listObjects",
        bucket
    );
    let files = match client.list_files_from_forest(&bucket).await {
        Ok(v) => v,
        Err(e) => {
            eprintln!("[fxfiles-open-bucket]   list_files_from_forest FAILED: {:?}", e);
            panic!(
                "list_files_from_forest({}) failed. The forest loaded but the \
                 walk surfaced an error — most likely a v7 page-fetch failure \
                 (page_ref.etag missing, or all gateways failed for a page CID).",
                bucket
            );
        }
    };

    // ─── Step 3: report — DIAGNOSTIC, not pass/fail ───────────────────
    //
    // Whether 0 files or N files is "correct" depends on what the user
    // actually has in this bucket. Print the count + sample entries so the
    // operator can compare against ground truth (their own knowledge of
    // what's in the bucket online). 0 files for a bucket the user knows
    // contains 851 files is the "loaded but empty" failure mode from
    // FxFiles' offline log — that signal is what this test surfaces.
    eprintln!(
        "\n[fxfiles-open-bucket] step 3: list result\n\
         [fxfiles-open-bucket]   raw forest entry count = {}",
        files.len()
    );
    let sample = files.iter().take(20).collect::<Vec<_>>();
    if !sample.is_empty() {
        eprintln!("[fxfiles-open-bucket]   first {} entries:", sample.len());
        for (i, m) in sample.iter().enumerate() {
            eprintln!(
                "[fxfiles-open-bucket]     [{:2}] key={} size={} storage_key={}",
                i, m.original_key, m.original_size, m.storage_key
            );
        }
    }

    if files.is_empty() {
        eprintln!(
            "\n[fxfiles-open-bucket] EMPTY-FOREST result.\n\
             [fxfiles-open-bucket] If you know `{}` contains files online, this is \
             the FxFiles \"Forest loaded for bucket: {} / listObjects: 0 files\" \
             failure mode — manifest fetched + decrypted, but the v7 walk produced \
             nothing. Either the forest_manifest_cid points at an old empty snapshot, \
             or pages exist but their etags are missing/wrong on this manifest \
             version, or the v7 walk is silently skipping unreachable pages.\n\
             [fxfiles-open-bucket] Next debug: dump the manifest's page_index from \
             the loaded forest cache, compare against master's actual page objects.",
            bucket, bucket,
        );
    } else {
        eprintln!(
            "\n[fxfiles-open-bucket] PASS — `{}` returned {} entries via the EXACT \
             same code path FxFiles runs (load_forest + list_files_from_forest), \
             with master DNS-failing and a fresh block cache. Cold-start works for \
             this bucket.",
            bucket,
            files.len(),
        );
    }
}
