//! Issue #12 — `rewrap_object_dek` updates S3's `x-fula-encryption`
//! header during key rotation but does NOT update the forest entry's
//! `user_metadata["x-fula-encryption"]` mirror. After `rotate_bucket`,
//! the forest carries the OLD wrapped DEK while S3 has the NEW one.
//!
//! This breaks any offline read path that falls back to forest
//! user_metadata (the issue #11 `get_object_encryption_metadata_with_fallback`
//! helper, and `get_object_decrypted_inner`'s `get_meta` helper at
//! `encryption.rs:1453-1463`).
//!
//! Test design:
//!   1. Spin up local gateway, upload an encrypted file via
//!      `put_object_encrypted_with_type` (the path that populates
//!      `forest_entry.user_metadata["x-fula-encryption"]` per
//!      `encryption.rs:5955-5968`).
//!   2. Capture the BEFORE-rotation forest user_metadata.
//!   3. Sanity check: BEFORE rotation, forest and S3 metadata match.
//!   4. Run `rotate_bucket` with a fresh `KeyRotationManager`.
//!   5. Capture the AFTER-rotation forest user_metadata and S3 metadata.
//!   6. **Today (buggy):** forest is unchanged while S3 has new
//!      `wrapped_key` + bumped `kek_version`. Assertion fails.
//!   7. **After fix:** forest matches S3. Assertion passes.

use bytes::Bytes;
use fula_cli::{routes, AppState, GatewayConfig};
use fula_client::{Config as ClientConfig, EncryptedClient, EncryptionConfig as ClientEncCfg};
use fula_crypto::keys::SecretKey;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

async fn spawn_server() -> (String, JoinHandle<()>) {
    let mut config = GatewayConfig::default();
    config.host = "127.0.0.1".to_string();
    config.port = 0;
    config.auth_enabled = false;
    config.use_memory_store = true;
    config.registry_cid_path = None;
    config.jwt_secret = Some("test-secret-issue-12".to_string());
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

fn make_client(endpoint: &str) -> EncryptedClient {
    // Stable seed so the same EncryptedClient identity persists across the test.
    let seed = *blake3::hash(b"issue-12-test-seed-v1").as_bytes();
    let secret = SecretKey::from_bytes(&seed).expect("secret");
    let client_config = ClientConfig::new(endpoint).with_encryption();
    let enc_config = ClientEncCfg::from_secret_key(secret);
    EncryptedClient::new(client_config, enc_config).expect("encrypted client")
}

/// Read `x-fula-encryption` from S3 via HEAD.
async fn s3_enc_metadata(
    client: &EncryptedClient,
    bucket: &str,
    storage_key: &str,
) -> String {
    let head = client
        .inner()
        .head_object(bucket, storage_key)
        .await
        .expect("S3 head_object");
    head.metadata
        .get("x-fula-encryption")
        .cloned()
        .expect("x-fula-encryption header on S3")
}

/// Read `x-fula-encryption` from forest user_metadata, returning None if
/// the field isn't present (legacy upload). Returns `(storage_key, value)`.
async fn forest_enc_metadata(
    client: &EncryptedClient,
    bucket: &str,
    original_key: &str,
) -> (String, Option<String>) {
    let files = client
        .list_files_from_forest(bucket)
        .await
        .expect("list_files_from_forest");
    let entry = files
        .iter()
        .find(|m| m.original_key == original_key)
        .expect("uploaded file present in forest");
    (
        entry.storage_key.clone(),
        entry.user_metadata.get("x-fula-encryption").cloned(),
    )
}

/// **Should fail on current main; should pass after the issue #12 fix.**
///
/// After a `rotate_bucket` succeeds, the forest's local copy of
/// `x-fula-encryption` should match the new value on S3. Today it
/// doesn't — `rewrap_object_dek` (`encryption.rs:8822-8893`) only updates
/// S3.
#[tokio::test]
async fn issue_12_rotation_should_sync_forest_user_metadata() {
    let (endpoint, _server_handle) = spawn_server().await;
    let client = make_client(&endpoint);

    let bucket = "issue-12-bucket";
    let key = "/secret.txt";
    let plaintext = b"hello issue 12 rotation forest sync".to_vec();

    client.create_bucket(bucket).await.expect("create bucket");
    // Use the `put_object_flat` path (what FxFiles's `fula.putFlat` invokes).
    // This is the path that populates `forest_entry.user_metadata["x-fula-encryption"]`
    // per `encryption.rs:5955-5968`. The plain `put_object_encrypted` variant
    // does NOT touch the forest, so the test would have nothing to compare.
    client
        .put_object_flat(
            bucket,
            key,
            Bytes::from(plaintext.clone()),
            Some("application/octet-stream"),
        )
        .await
        .expect("put_object_flat");

    // Force a forest flush so the entry is durable. The rotation path
    // itself doesn't require flushed state, but the test wants a clean
    // before/after comparison on a persisted forest.
    client.flush_forest(bucket).await.ok();

    // Capture BEFORE-rotation state.
    let (storage_key, forest_before) =
        forest_enc_metadata(&client, bucket, key).await;
    let forest_before = forest_before.expect(
        "forest must carry x-fula-encryption after upload (encryption.rs:5955-5968). \
         If this fails, the upload path itself regressed.",
    );
    let s3_before = s3_enc_metadata(&client, bucket, &storage_key).await;

    // Sanity: before rotation, forest and S3 agree (this is what
    // encryption.rs:5955-5968 guarantees at upload time).
    assert_eq!(
        forest_before, s3_before,
        "pre-rotation invariant: forest user_metadata['x-fula-encryption'] \
         must match S3's x-fula-encryption header for fresh uploads"
    );

    // Run the rotation. `create_rotation_manager` returns a manager seeded
    // with the CURRENT KEK; `rotate_kek` generates a new keypair and bumps
    // the version. Without that call, `rewrap_dek` would re-wrap with the
    // same KEK and the test would be vacuous.
    let mut rotation_manager = client.create_rotation_manager();
    rotation_manager.rotate_kek().expect("rotate_kek (generate new KEK)");
    let report = client
        .rotate_bucket(bucket, &rotation_manager)
        .await
        .expect("rotate_bucket");
    // The bucket holds exactly one object (the main encrypted file).
    // `rotated` should be 1; forest objects are skipped automatically.
    assert!(
        report.rotated >= 1,
        "rotation should rewrap at least one object; report={:?}",
        report
    );

    // Capture AFTER-rotation state.
    let s3_after = s3_enc_metadata(&client, bucket, &storage_key).await;
    let (_, forest_after) = forest_enc_metadata(&client, bucket, key).await;
    let forest_after = forest_after
        .expect("forest entry must still carry x-fula-encryption after rotation");

    // Sanity: S3 changed (rotation actually happened).
    assert_ne!(
        s3_before, s3_after,
        "rotation must update S3's x-fula-encryption (sanity check)"
    );

    // THE LOAD-BEARING ASSERTION.
    //
    // After rotation, the forest's user_metadata MUST be in sync with S3.
    // Today this assertion fails because `rewrap_object_dek` (encryption.rs:8822-8893)
    // PUTs new metadata to S3 but never touches `forest_entry.user_metadata`.
    //
    // After the fix, this assertion passes — rotation updates the forest
    // entry too, marking the forest dirty so a subsequent flush persists.
    assert_eq!(
        forest_after, s3_after,
        "issue #12: after rotate_bucket, forest_entry.user_metadata['x-fula-encryption'] \
         must match S3's x-fula-encryption header. Currently `rewrap_object_dek` \
         (encryption.rs:8822-8893) updates S3 only and leaves the forest entry stale."
    );
}
