//! Bridge tests for the cooperative cancellation token (issue #18).
//!
//! New API surface to be bridged:
//!   * `CancelHandle` type — opaque FRB handle wrapping `Arc<AtomicBool>`.
//!   * `create_cancel_handle()` / `cancel_handle_trigger()` /
//!     `cancel_handle_is_cancelled()`.
//!   * `put_flat_resumable_from_path_cancellable` — same as
//!     `put_flat_resumable_from_path` (issue #17) but accepts a
//!     `&CancelHandle`.
//!   * `resume_flat_upload_from_path_cancellable` — same as
//!     `resume_flat_upload_from_path` but cancellable.
//!
//! Until the bridge + SDK changes land, these tests fail to compile
//! (the imports below resolve to nothing). That IS the proof the gap
//! is real.
//!
//! Once the bridge lands:
//!
//!   * `test_cancel_handle_default_state` — newly-created handle is not
//!     cancelled. Sanity check of the opaque type.
//!   * `test_cancel_handle_trigger_flips_state` — trigger flips it.
//!     Idempotent (second trigger is a no-op).
//!   * `test_cancel_mid_upload_stops_further_chunks` — kick off a
//!     32 MB resumable upload, sleep ~100ms, trigger cancel. Verify:
//!       * the upload returns a typed cancellation error,
//!       * the manifest is still on disk (cancel ≠ abort_upload — the
//!         caller may want to resume later),
//!       * future `resume_flat_upload_from_path` against the same
//!         manifest + the unchanged file completes the upload.
//!   * `test_cancel_with_none_handle_equivalent_to_non_cancellable` —
//!     happy-path smoke: the cancellable variant with a never-triggered
//!     handle behaves identically to `put_flat_resumable_from_path`.

use std::sync::Arc;
use std::time::Duration;
use tempfile::{NamedTempFile, TempDir};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

use fula_cli::{routes, AppState, GatewayConfig};

use fula_flutter::api::client::create_encrypted_client;
use fula_flutter::api::encrypted::enc_create_bucket;
use fula_flutter::api::forest::{
    cancel_handle_is_cancelled,
    cancel_handle_trigger,
    create_cancel_handle,
    get_flat,
    put_flat_resumable_from_path_cancellable,
    resume_flat_upload_from_path,
};
use fula_flutter::api::types::{
    EncryptionConfig as FlutterEncCfg, FulaConfig, ObfuscationMode,
};

// ════════════════════════════════════════════════════════════════════════
// Harness (lifted from v2_resumable_upload_bridge_tests.rs)
// ════════════════════════════════════════════════════════════════════════

async fn spawn_gateway() -> (String, JoinHandle<()>) {
    let mut config = GatewayConfig::default();
    config.host = "127.0.0.1".to_string();
    config.port = 0;
    config.auth_enabled = false;
    config.use_memory_store = true;
    config.registry_cid_path = None;
    config.jwt_secret = Some("test-secret-issue-18".to_string());
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
    blake3::hash(format!("issue-18-{label}").as_bytes())
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
// Test 1: CancelHandle default state — newly created, not cancelled.
// ════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_cancel_handle_default_state() {
    let handle = create_cancel_handle();
    assert!(
        !cancel_handle_is_cancelled(&handle),
        "newly-created CancelHandle must not be in cancelled state"
    );
}

// ════════════════════════════════════════════════════════════════════════
// Test 2: trigger flips state; second trigger is idempotent.
// ════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_cancel_handle_trigger_flips_state() {
    let handle = create_cancel_handle();
    cancel_handle_trigger(&handle);
    assert!(
        cancel_handle_is_cancelled(&handle),
        "after trigger, CancelHandle must be in cancelled state"
    );
    // Second trigger must be a no-op (no panic, state stays cancelled).
    cancel_handle_trigger(&handle);
    assert!(
        cancel_handle_is_cancelled(&handle),
        "second trigger must not regress state"
    );
}

// ════════════════════════════════════════════════════════════════════════
// Test 3: cancel mid-upload returns typed error; manifest survives;
// subsequent resume against unchanged file completes.
// ════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_cancel_mid_upload_stops_further_chunks() {
    let (endpoint, _server) = spawn_gateway().await;

    let client = create_encrypted_client(flutter_config(&endpoint), enc_config("cancel-mid"))
        .expect("create encrypted client");

    let bucket = "cancel-mid-bucket".to_string();
    enc_create_bucket(&client, bucket.clone())
        .await
        .expect("create bucket");

    // 32 MB — deterministically multi-chunk; chunked encrypt + PUT can't
    // finish in <100ms against the in-memory gateway.
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

    let cancel = create_cancel_handle();

    // Kick off the upload; trigger cancel after 100ms.
    let upload_client = client.clone();
    let upload_bucket = bucket.clone();
    let upload_file_path = file_path.clone();
    let upload_manifest_path = manifest_path.clone();
    let upload_cancel = cancel.clone();
    let upload_task = tokio::spawn(async move {
        put_flat_resumable_from_path_cancellable(
            &upload_client,
            upload_bucket,
            "/cancel-test.bin".to_string(),
            upload_file_path,
            upload_manifest_path,
            None,
            &upload_cancel,
        )
        .await
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    cancel_handle_trigger(&cancel);

    let result = upload_task.await.expect("join upload task");
    let err = result.expect_err(
        "cancelled upload must return Err, not Ok (chunks already in flight \
         finishing is fine, but the API must signal cancellation)"
    );
    let msg = err.to_string().to_lowercase();
    assert!(
        msg.contains("cancel") || msg.contains("aborted"),
        "expected a Cancelled-class error, got: {err}"
    );

    // Manifest contract: cancel ≠ abort_upload. The manifest survives so
    // the caller can resume later (or call abort_upload to clean up).
    assert!(
        std::path::Path::new(&manifest_path).exists(),
        "cancellation must leave the manifest on disk for caller-driven \
         resume or abort; it's missing at {manifest_path}"
    );

    // Resume against the unchanged file should complete the upload.
    let resume_result = resume_flat_upload_from_path(
        &client,
        manifest_path.clone(),
        file_path.clone(),
    )
    .await
    .expect("resume after cancel must complete (same gateway, unchanged file)");
    assert!(!resume_result.etag.is_empty(), "resume returned empty etag");

    // Manifest gone after successful resume.
    assert!(
        !std::path::Path::new(&manifest_path).exists(),
        "manifest must be deleted after successful resume"
    );

    // Content reads back identical.
    let readback = get_flat(&client, bucket, "/cancel-test.bin".to_string())
        .await
        .expect("read back via get_flat");
    assert_eq!(
        readback, payload,
        "resumed-after-cancel content must match original"
    );
}

// ════════════════════════════════════════════════════════════════════════
// Test 4: cancellable variant with a never-triggered handle behaves
// identically to the non-cancellable function (regression check).
// ════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_cancel_with_never_triggered_handle_equivalent_to_non_cancellable() {
    let (endpoint, _server) = spawn_gateway().await;

    let client = create_encrypted_client(
        flutter_config(&endpoint),
        enc_config("cancel-equiv"),
    )
    .expect("create encrypted client");

    let bucket = "cancel-equiv-bucket".to_string();
    enc_create_bucket(&client, bucket.clone())
        .await
        .expect("create bucket");

    let payload = b"small payload, single chunk".to_vec();
    let file = NamedTempFile::new().expect("temp file");
    std::fs::write(file.path(), &payload).expect("write payload");
    let file_path = file.path().to_string_lossy().to_string();

    let manifest_dir = TempDir::new().expect("temp dir");
    let manifest_path = manifest_dir
        .path()
        .join("upload.manifest")
        .to_string_lossy()
        .to_string();

    let cancel = create_cancel_handle();
    // Never trigger.

    let result = put_flat_resumable_from_path_cancellable(
        &client,
        bucket.clone(),
        "/equiv-test.bin".to_string(),
        file_path,
        manifest_path.clone(),
        None,
        &cancel,
    )
    .await
    .expect("non-triggered cancel must allow upload to complete normally");

    assert!(!result.etag.is_empty(), "upload returned empty etag");
    assert!(
        !std::path::Path::new(&manifest_path).exists(),
        "manifest must be deleted after successful upload"
    );

    let readback = get_flat(&client, bucket, "/equiv-test.bin".to_string())
        .await
        .expect("read back");
    assert_eq!(readback, payload, "readback bytes mismatch");
}
