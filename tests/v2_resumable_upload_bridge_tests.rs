//! Bridge tests for `resume_upload` + `put_object_encrypted_resumable` exposure
//! through the fula-flutter FFI surface (issue #17).
//!
//! Today these functions are NOT exposed; the new bridge functions are:
//!   * `fula_flutter::api::forest::put_flat_resumable_from_path`
//!   * `fula_flutter::api::forest::resume_flat_upload_from_path`
//!
//! Until the bridge lands these tests fail to compile, which IS the proof
//! that the gap is real. Once the bridge lands:
//!
//!   * `test_put_flat_resumable_happy_path` — happy path: manifest auto-
//!     deletes on success, content reads back identical.
//!   * `test_resume_bridge_shape_smoke` — server dies mid-upload, manifest
//!     persists, fresh gateway + resume returns SOMETHING (Ok or typed
//!     Err). Documents the bridge shape works end-to-end; NOT a "resume
//!     actually completes" gate. The full resume-state correctness is
//!     covered by the SDK's internal logic which the bridge wraps.
//!   * `test_resume_rejects_tampered_bytes` — deterministic partial-
//!     manifest setup (interrupt with predictable timing), tamper file
//!     bytes between attempts, expect BAO mismatch error from the SDK's
//!     F1 nonce-reuse protection.
//!   * `test_concurrent_resume_same_manifest_path_serializes` — two
//!     concurrent `resume_flat_upload_from_path` calls against the SAME
//!     manifest_path must serialize (via the bucket_write_mutex from B1
//!     extended to cover the resumable path). Without protection the
//!     two callers race on the local manifest file (load/save/delete)
//!     and one or both can corrupt state. With protection, both calls
//!     complete (one may early-return because the other deleted the
//!     manifest).

use std::sync::Arc;
use std::time::Duration;
use tempfile::{NamedTempFile, TempDir};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

use fula_cli::{routes, AppState, GatewayConfig};

use fula_flutter::api::client::create_encrypted_client;
use fula_flutter::api::encrypted::enc_create_bucket;
use fula_flutter::api::forest::{
    get_flat,
    put_flat_resumable_from_path,
    resume_flat_upload_from_path,
};
use fula_flutter::api::types::{
    EncryptionConfig as FlutterEncCfg, FulaConfig, ObfuscationMode,
};

// ════════════════════════════════════════════════════════════════════════
// Test harness — spins up an in-memory gateway, hands back a kill handle.
// ════════════════════════════════════════════════════════════════════════

/// Spawn an in-memory gateway. Returns the endpoint URL and a task handle
/// that, when aborted, simulates the gateway dying mid-upload.
async fn spawn_gateway() -> (String, JoinHandle<()>) {
    let mut config = GatewayConfig::default();
    config.host = "127.0.0.1".to_string();
    config.port = 0;
    config.auth_enabled = false;
    config.use_memory_store = true;
    config.registry_cid_path = None;
    config.jwt_secret = Some("test-secret-issue-17".to_string());
    config.rate_limit_rps = 1_000_000;

    let state = Arc::new(AppState::new(config.clone()).await.unwrap());
    let app = routes::create_router(state);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    (format!("http://{}", addr), handle)
}

fn test_secret_key(label: &str) -> Vec<u8> {
    blake3::hash(format!("issue-17-{label}").as_bytes())
        .as_bytes()
        .to_vec()
}

fn flutter_config(endpoint: &str) -> FulaConfig {
    FulaConfig {
        endpoint: endpoint.to_string(),
        ..FulaConfig::default()
    }
}

fn enc_config(label: &str) -> FlutterEncCfg {
    FlutterEncCfg {
        secret_key: Some(test_secret_key(label)),
        enable_metadata_privacy: true,
        obfuscation_mode: ObfuscationMode::FlatNamespace,
    }
}

// ════════════════════════════════════════════════════════════════════════
// Test 1: happy path — manifest auto-deletes on success
// ════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_put_flat_resumable_happy_path() {
    let (endpoint, _server) = spawn_gateway().await;

    let client = create_encrypted_client(flutter_config(&endpoint), enc_config("happy"))
        .expect("create encrypted client");

    let bucket = "resumable-happy".to_string();
    enc_create_bucket(&client, bucket.clone())
        .await
        .expect("create bucket");

    // Small payload — single chunk path is fine for the happy-path
    // smoke test. The bridge wrapper is the same shape regardless of
    // chunk count.
    let payload = b"hello resumable bridge".to_vec();
    let file = NamedTempFile::new().expect("temp file");
    std::fs::write(file.path(), &payload).expect("write payload");
    let file_path = file.path().to_string_lossy().to_string();

    let manifest_dir = TempDir::new().expect("temp dir");
    let manifest_path = manifest_dir
        .path()
        .join("upload.manifest")
        .to_string_lossy()
        .to_string();

    let key = "/hello.txt".to_string();

    let result = put_flat_resumable_from_path(
        &client,
        bucket.clone(),
        key.clone(),
        file_path,
        manifest_path.clone(),
        None,
    )
    .await
    .expect("resumable upload should succeed on first try");

    assert!(!result.etag.is_empty(), "resumable upload returned empty etag");

    // Contract: on clean completion the manifest is deleted.
    assert!(
        !std::path::Path::new(&manifest_path).exists(),
        "manifest must be deleted after a successful upload; still present at {manifest_path}"
    );

    // Content reads back identical.
    let readback = get_flat(&client, bucket, key)
        .await
        .expect("read back via get_flat");
    assert_eq!(readback, payload, "readback bytes mismatch");
}

// ════════════════════════════════════════════════════════════════════════
// Test 2: bridge shape under mid-upload server failure
//
// Documents the bridge correctly forwards `(manifest_path, file_path)` to
// the SDK and surfaces a typed result. Does NOT prove "resume reconstructs
// to the same final etag as a clean upload" — the SDK's resume-state
// correctness is unit-tested separately. The bridge wrapper is a thin
// passthrough; this test guards against the shape regressing.
// ════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_resume_bridge_shape_smoke() {
    let (endpoint, server_handle) = spawn_gateway().await;

    let client = create_encrypted_client(flutter_config(&endpoint), enc_config("resume"))
        .expect("create encrypted client");

    let bucket = "resumable-resume".to_string();
    enc_create_bucket(&client, bucket.clone())
        .await
        .expect("create bucket");

    // ~6 MB content — exceeds the IPFS-block 1 MB threshold so the SDK
    // takes the chunked path with multiple chunk PUTs. Gives the abort
    // a window to interrupt mid-stream.
    let payload: Vec<u8> = (0..6 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
    let file = NamedTempFile::new().expect("temp file");
    std::fs::write(file.path(), &payload).expect("write payload");
    let file_path = file.path().to_string_lossy().to_string();

    let manifest_dir = TempDir::new().expect("temp dir");
    let manifest_path = manifest_dir
        .path()
        .join("upload.manifest")
        .to_string_lossy()
        .to_string();

    let key = "/large.bin".to_string();

    // Kick off the upload in the background, then abort the gateway
    // after a short delay so the SDK fails partway through. The exact
    // chunk count that lands varies; the manifest captures whatever
    // state the failure left.
    let upload_client = client.clone();
    let upload_bucket = bucket.clone();
    let upload_key = key.clone();
    let upload_file_path = file_path.clone();
    let upload_manifest_path = manifest_path.clone();
    let upload_task = tokio::spawn(async move {
        put_flat_resumable_from_path(
            &upload_client,
            upload_bucket,
            upload_key,
            upload_file_path,
            upload_manifest_path,
            None,
        )
        .await
    });

    // Let some chunks land before pulling the plug.
    tokio::time::sleep(Duration::from_millis(200)).await;
    server_handle.abort();
    // Brief grace for the abort to propagate.
    tokio::time::sleep(Duration::from_millis(100)).await;

    let first_attempt = upload_task.await.expect("join upload task");
    assert!(
        first_attempt.is_err(),
        "first attempt must fail because the gateway died mid-upload; got Ok({:?})",
        first_attempt.as_ref().map(|r| r.etag.clone()).ok()
    );

    // Manifest contract: failure leaves the manifest on disk so the
    // caller can resume.
    assert!(
        std::path::Path::new(&manifest_path).exists(),
        "manifest must persist after a mid-upload failure"
    );

    // SHAPE smoke (per the test name) — we've already proven the bridge's
    // contract under mid-upload failure: the call errored, the manifest
    // persists, the caller has the state needed to resume. That IS the
    // value of this test.
    //
    // Driving the resume against a FRESH gateway from here was the source
    // of issue #22's CI flakiness:
    //
    //   * The SDK's `resume_upload` trusts `manifest.chunks[i].uploaded`
    //     — chunks marked uploaded against gateway 1 are NOT re-PUT.
    //   * Gateway 2 has none of those chunks.
    //   * Resume writes the final index pointing at chunks that exist
    //     only on gateway 1 (now dead) — returns Ok.
    //   * A subsequent readback against gateway 2 fails because the
    //     chunks aren't there.
    //   * Whether the SDK returns Ok or Err depends on how many chunks
    //     landed before the abort fired — flaky timing.
    //
    // The real-world contract is "resume on the SAME backend the upload
    // started on." That's covered deterministically by
    // `v3_cancellable_upload_bridge_tests::test_cancel_mid_upload_stops_further_chunks`,
    // which uses issue #18's CancelHandle to interrupt the upload
    // mid-flight without killing the gateway — same backend across
    // abort+resume, chunks are still on the backend, round-trip readback
    // is deterministic. That test already covers what the cross-gateway
    // follow-up here was trying (and failing) to test.
    //
    // `key` was only consumed by the discarded readback; bind it to `_`
    // so removing the readback doesn't leave a dead-code warning.
    let _ = key;
}

// ════════════════════════════════════════════════════════════════════════
// Test 3: BAO content-hash check (F1) rejects tampered bytes on resume.
//
// Uses a 32 MB payload + 100ms pre-abort window — large enough that the
// upload is guaranteed to be mid-chunk-loop when the abort fires (the
// SDK takes hundreds of milliseconds to encrypt + PUT 32 MB of chunks
// against a real backend). Deterministic vs the previous 4 MB timing
// race. If the upload still completes within 100ms we have a different
// performance characteristic to investigate, not a flaky test.
// ════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_resume_rejects_tampered_bytes() {
    let (endpoint, server_handle) = spawn_gateway().await;

    let client = create_encrypted_client(flutter_config(&endpoint), enc_config("tamper"))
        .expect("create encrypted client");

    let bucket = "resumable-tamper".to_string();
    enc_create_bucket(&client, bucket.clone())
        .await
        .expect("create bucket");

    // 32 MB — comfortably above the threshold where the SDK can't finish
    // the chunked encrypt + PUT loop in <100ms against the in-memory
    // gateway. Deterministic partial-manifest state at abort time.
    let payload: Vec<u8> = (0..32 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
    let file = NamedTempFile::new().expect("temp file");
    std::fs::write(file.path(), &payload).expect("write payload");
    let file_path = file.path().to_string_lossy().to_string();

    let manifest_dir = TempDir::new().expect("temp dir");
    let manifest_path = manifest_dir
        .path()
        .join("upload.manifest")
        .to_string_lossy()
        .to_string();

    let upload_client = client.clone();
    let upload_bucket = bucket.clone();
    let upload_file_path = file_path.clone();
    let upload_manifest_path = manifest_path.clone();
    let upload_task = tokio::spawn(async move {
        put_flat_resumable_from_path(
            &upload_client,
            upload_bucket,
            "/large.bin".to_string(),
            upload_file_path,
            upload_manifest_path,
            None,
        )
        .await
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    server_handle.abort();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let _ = upload_task.await.expect("join upload task");

    // Deterministic by design: at 32 MB the chunked encrypt + PUT loop
    // can't finish in <100ms, so the manifest MUST be on disk. If this
    // assertion fails it's a real signal (test environment too fast?
    // payload too small?), not a flake.
    assert!(
        std::path::Path::new(&manifest_path).exists(),
        "manifest must persist after a mid-upload failure; if missing, the test \
         payload is too small to deterministically interrupt mid-flight (need to \
         scale up beyond 32 MB)"
    );

    // Tamper: flip one byte in the original file. The SDK's BAO root
    // hash check (encryption.rs, F1 nonce-reuse protection — locate via
    // grep for "BaoVerification" or "data content does not match")
    // must reject this on resume.
    let mut tampered = payload.clone();
    tampered[1024] ^= 0xff;
    std::fs::write(file.path(), &tampered).expect("write tampered payload");

    let (endpoint_resumed, _server2) = spawn_gateway().await;
    let resumed_client = create_encrypted_client(
        flutter_config(&endpoint_resumed),
        enc_config("tamper"),
    )
    .expect("create encrypted client (resume)");
    enc_create_bucket(&resumed_client, bucket.clone())
        .await
        .expect("re-create bucket on the new gateway");

    let resume_result = resume_flat_upload_from_path(
        &resumed_client,
        manifest_path.clone(),
        file_path.clone(),
    )
    .await;

    let err = resume_result.expect_err(
        "resume MUST reject tampered bytes (F1 nonce-reuse protection)",
    );
    let msg = err.to_string().to_lowercase();
    assert!(
        msg.contains("bao") || msg.contains("hash mismatch") || msg.contains("does not match"),
        "expected a BAO/content-hash-mismatch error, got: {err}"
    );
}

// ════════════════════════════════════════════════════════════════════════
// Test 4: concurrent resume on the same manifest_path must serialize.
//
// Codex's catch — Option 1 (bucket_write_mutex extension to resumable
// path) protects bucket state, but two concurrent `resume_upload` calls
// against the SAME local manifest can still race on the manifest file
// itself (load/save/delete). With the SDK's per-bucket mutex held
// across the resume operation, the second caller serializes behind the
// first. The first caller wins (deletes the manifest on success). The
// second caller observes the missing manifest and returns a typed
// error.
//
// Without serialization (pre-fix or with the mutex missing), both
// callers race on `wal::load` / `wal::clear` and one or both can
// corrupt state. This test gates the SDK extension to the resumable
// path.
// ════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_concurrent_resume_same_manifest_path_serializes() {
    let (endpoint, server_handle) = spawn_gateway().await;

    let client = create_encrypted_client(
        flutter_config(&endpoint),
        enc_config("concurrent-resume"),
    )
    .expect("create encrypted client");

    let bucket = "resumable-concurrent".to_string();
    enc_create_bucket(&client, bucket.clone())
        .await
        .expect("create bucket");

    let payload: Vec<u8> = (0..32 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
    let file = NamedTempFile::new().expect("temp file");
    std::fs::write(file.path(), &payload).expect("write payload");
    let file_path = file.path().to_string_lossy().to_string();

    let manifest_dir = TempDir::new().expect("temp dir");
    let manifest_path = manifest_dir
        .path()
        .join("upload.manifest")
        .to_string_lossy()
        .to_string();

    // Set up the partial-manifest state via the kick-off-then-abort
    // pattern.
    let upload_client = client.clone();
    let upload_bucket = bucket.clone();
    let upload_file_path = file_path.clone();
    let upload_manifest_path = manifest_path.clone();
    let upload_task = tokio::spawn(async move {
        put_flat_resumable_from_path(
            &upload_client,
            upload_bucket,
            "/large.bin".to_string(),
            upload_file_path,
            upload_manifest_path,
            None,
        )
        .await
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    server_handle.abort();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let _ = upload_task.await.expect("join upload task");
    assert!(
        std::path::Path::new(&manifest_path).exists(),
        "test prerequisite: manifest must exist after the interrupted upload"
    );

    // Spin up a fresh gateway and a fresh client for the concurrent
    // resume attempts. Same secret_key so both clients derive the same
    // forest/index keys.
    let (endpoint_resumed, _server2) = spawn_gateway().await;
    let resumed_client = Arc::new(
        create_encrypted_client(
            flutter_config(&endpoint_resumed),
            enc_config("concurrent-resume"),
        )
        .expect("create encrypted client (resume)"),
    );
    enc_create_bucket(&resumed_client, bucket.clone())
        .await
        .expect("re-create bucket on the new gateway");

    // Fire two concurrent resume calls against the SAME manifest_path.
    // With the SDK's bucket_write_mutex covering the resumable path
    // (Option 1), they serialize. Without it, they race on
    // wal::load/wal::clear of the manifest file.
    let resume_a = {
        let client = Arc::clone(&resumed_client);
        let manifest_path = manifest_path.clone();
        let file_path = file_path.clone();
        tokio::spawn(async move {
            resume_flat_upload_from_path(&client, manifest_path, file_path).await
        })
    };
    let resume_b = {
        let client = Arc::clone(&resumed_client);
        let manifest_path = manifest_path.clone();
        let file_path = file_path.clone();
        tokio::spawn(async move {
            resume_flat_upload_from_path(&client, manifest_path, file_path).await
        })
    };

    let result_a = resume_a.await.expect("join A");
    let result_b = resume_b.await.expect("join B");

    // Acceptable outcomes (in either order):
    //   * Both Ok: SDK detected the manifest was already finalized on
    //     the second call's pre-flight (current SDK behavior is to
    //     re-finalize idempotently when manifest.remaining() == 0).
    //   * One Ok + one typed Err pointing at a missing/finalized
    //     manifest: the winner deleted the manifest, the loser observes
    //     the absence and reports cleanly.
    //   * Two Errs: ONLY acceptable if both errors are the same
    //     well-defined "manifest not found / already finalized" shape
    //     — meaning the second caller saw the first's deletion AND
    //     the first hit a transport error pre-finalization. Even then
    //     no panic / no corruption is the actual gate.
    //
    // What we MUST NOT see: panics, BAO false-positives, or "manifest
    // corrupt" errors implying both callers wrote to the same file at
    // overlapping offsets.
    let bad = match (&result_a, &result_b) {
        (Err(e), _) | (_, Err(e)) => {
            let msg = e.to_string().to_lowercase();
            // BAO mismatch with unmodified bytes is the smoking gun
            // for an unprotected race that wrote chunks under wrong
            // seqs / nonces.
            msg.contains("bao") && !msg.contains("data content does not match")
                || msg.contains("corrupt")
                || msg.contains("invalid manifest")
        }
        _ => false,
    };
    assert!(
        !bad,
        "concurrent resume against same manifest produced a corruption-class error:\n\
         A = {:?}\n\
         B = {:?}",
        result_a, result_b,
    );
}
