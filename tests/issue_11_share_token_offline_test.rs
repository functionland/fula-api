//! Issue #11 â€” offline share-token creation fails because
//! `crates/fula-flutter/src/api/sharing.rs:47,144` calls
//! `client.inner().head_object(...)` directly, bypassing the offline-fallback
//! infrastructure that the download path already uses
//! (`encryption.rs:1432-1463` + `forest_entry.user_metadata` fallback).
//!
//! This test reproduces the bug end-to-end through the FFI surface FxFiles
//! actually invokes:
//!   1. Spin up a local gateway, upload an encrypted file via FFI `put_encrypted`.
//!   2. Shut down the gateway (simulates the FxFiles `s33.cloud.fx.land`
//!      offline scenario from issue #11).
//!   3. Call the FFI `create_share_token` on the uploaded file.
//!   4. **Expected (post-fix):** `Ok(token_json)` â€” the wrapped DEK is in
//!      `forest_entry.user_metadata["x-fula-encryption"]` (populated at
//!      upload by `encryption.rs:5955-5968`), so no network call is needed.
//!   5. **Today (buggy):** `Err("Failed to fetch object metadata: HTTP error
//!      ... dns error ... No address associated with hostname")` â€”
//!      `sharing.rs:47` hits the now-dead gateway.
//!
//! Run with: `cargo test --test issue_11_share_token_offline_test -- --nocapture`

use fula_cli::{routes, AppState, GatewayConfig};
use fula_crypto::keys::KekKeyPair;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

use fula_flutter::api::client::create_encrypted_client;
use fula_flutter::api::encrypted::enc_create_bucket;
use fula_flutter::api::forest::{list_from_forest, put_flat};
use fula_flutter::api::sharing::create_share_token;
use fula_flutter::api::types::{
    EncryptionConfig as FlutterEncCfg, FulaConfig, ObfuscationMode,
};

/// Spawn an in-memory test gateway; returns `(endpoint_url, server_handle)`.
/// `server_handle.abort()` simulates the FxFiles offline scenario where the
/// configured master endpoint stops resolving.
async fn spawn_server() -> (String, JoinHandle<()>) {
    let mut config = GatewayConfig::default();
    config.host = "127.0.0.1".to_string();
    config.port = 0;
    config.auth_enabled = false;
    config.use_memory_store = true;
    config.registry_cid_path = None;
    config.jwt_secret = Some("test-secret-issue-11".to_string());
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

/// Build the deterministic 32-byte secret key fula_flutter expects. In real
/// FxFiles this is Argon2id over OAuth identity; for the test a constant is
/// fine â€” we just need the same key throughout the test.
fn test_secret_key() -> Vec<u8> {
    blake3::hash(b"issue-11-test-secret-key-v1").as_bytes().to_vec()
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// Main repro â€” end-to-end via the FFI surface FxFiles invokes
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

/// **Should fail on current main; should pass after the issue #11 fix.**
///
/// Calls the FFI `create_share_token` against a freshly-uploaded file AFTER
/// tearing down the gateway. The current implementation
/// (`fula-flutter/src/api/sharing.rs:47`) issues a HEAD against the dead
/// gateway and returns `Err("Failed to fetch object metadata: ...")`.
///
/// After the fix (read `x-fula-encryption` from `forest_entry.user_metadata`
/// first, fall back to `head_object` only on absence), this returns
/// `Ok(token_json)` because the wrapped DEK is in the local AEAD-protected
/// forest.
#[tokio::test]
async fn issue_11_create_share_token_should_work_offline() {
    // Step 1: real gateway up, upload via FFI.
    let (endpoint, server_handle) = spawn_server().await;

    let fula_config = FulaConfig {
        endpoint: endpoint.clone(),
        ..FulaConfig::default()
    };
    let enc_config = FlutterEncCfg {
        secret_key: Some(test_secret_key()),
        enable_metadata_privacy: true,
        // FxFiles uses FlatNamespace (`fula_api_service.dart:212-213`).
        obfuscation_mode: ObfuscationMode::FlatNamespace,
    };

    let handle = create_encrypted_client(fula_config, enc_config)
        .await.expect("create encrypted client");

    let bucket = "issue-11-bucket".to_string();
    let key = "/secret.txt".to_string();
    let plaintext = b"hello issue 11 offline share".to_vec();

    enc_create_bucket(&handle, bucket.clone())
        .await
        .expect("create bucket");

    // FxFiles uses `put_flat` (not `put_encrypted`) â€” `put_flat` populates
    // the forest entry, which is what the offline path relies on.
    put_flat(
        &handle,
        bucket.clone(),
        key.clone(),
        plaintext.clone(),
        None, // content_type
    )
    .await
    .expect("FFI put_flat upload");

    // Step 2: snapshot the storage_key via the offline-safe forest listing.
    // `list_from_forest` reads only the local forest â€” no network â€” so it
    // works both before and after we abort the gateway.
    let files = list_from_forest(&handle, bucket.clone())
        .await
        .expect("list_from_forest");
    let storage_key = files
        .iter()
        .find(|m| m.original_key == key)
        .map(|m| m.storage_key.clone())
        .expect("uploaded file present in forest");

    // Step 3: tear down the gateway. From here on any request that reaches
    // the master returns a connection error â€” exactly the FxFiles
    // `s33.cloud.fx.land` log signature.
    server_handle.abort();
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // Step 4: the FFI call that FxFiles' SharingService invokes. Recipient
    // public key is arbitrary; we're not testing recipient acceptance, just
    // that the SENDER can build the token offline.
    let recipient_pk = KekKeyPair::generate()
        .public_key()
        .as_bytes()
        .to_vec();

    let result = create_share_token(
        &handle,
        bucket.clone(),
        storage_key.clone(),
        recipient_pk,
        Some(chrono::Utc::now().timestamp() + 3600),
    )
    .await;

    // Load-bearing assertion.
    // Today: result.is_err() because sharing.rs:47 hit the dead gateway.
    // After the issue #11 fix: result.is_ok() because the wrapped DEK was
    // sourced from the local forest entry.
    assert!(
        result.is_ok(),
        "issue #11: create_share_token should succeed offline by reading \
         x-fula-encryption from forest_entry.user_metadata (see \
         encryption.rs:5955-5968 + encryption.rs:1453-1463). \
         Current failure: {:?}",
        result.err()
    );

    // Optional sanity on the returned token shape: it must be valid JSON
    // carrying a wrapped key the recipient could later unwrap.
    let token_json = result.unwrap();
    let parsed: serde_json::Value =
        serde_json::from_str(&token_json).expect("share token is JSON");
    assert!(
        parsed.get("wrapped_key").is_some(),
        "share token must include wrapped_key"
    );
}