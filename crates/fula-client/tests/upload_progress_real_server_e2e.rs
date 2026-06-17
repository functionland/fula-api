//! Real-server E2E for chunk-granular upload progress (FxFiles "show upload
//! %"). Uploads a LARGE (multi-chunk) encrypted file against the LIVE master
//! and asserts the SDK emits cumulative byte progress that reaches 100%, on
//! BOTH the web path (`put_object_flat_with_progress`) and the native
//! resumable path (`put_object_encrypted_resumable_with_cancel_and_progress`).
//! Each upload is round-tripped byte-for-byte so progress can't pass while
//! the upload itself is broken.
//!
//! `#[ignore]` — needs network + real credentials. Run (PowerShell, env from
//! `e2e-credentials.env`):
//!
//! ```powershell
//! cargo test -p fula-client --test upload_progress_real_server_e2e --release `
//!     -- --ignored --nocapture
//! ```
//!
//! Required env: `FULA_S3`, `FULA_JWT`, `FULA_TEST_PROVIDER`,
//! `FULA_TEST_OAUTH_SUB`, `FULA_TEST_EMAIL` (the Mode A derivation triple —
//! Argon2id("fula-files-v1", "{provider}:{sub}:{email}"), auth_service.dart
//! byte-for-byte). Fresh, uniquely-named buckets keep the test self-contained.

#![cfg(not(target_arch = "wasm32"))]

use bytes::Bytes;
use fula_client::{Config, EncryptedClient, EncryptionConfig};
use fula_crypto::keys::SecretKey;
use std::sync::{Arc, Mutex};

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("missing required env {name}"))
}

fn make_client() -> EncryptedClient {
    let s3 = env("FULA_S3");
    let jwt = env("FULA_JWT");
    let input = format!(
        "{}:{}:{}",
        env("FULA_TEST_PROVIDER"),
        env("FULA_TEST_OAUTH_SUB"),
        env("FULA_TEST_EMAIL"),
    );
    // Mode A secret = Argon2id("fula-files-v1", "{provider}:{sub}:{email}").
    let key = fula_crypto::hashing::derive_key_argon2id("fula-files-v1", input.as_bytes());
    let secret = SecretKey::from_bytes(&key).expect("32-byte secret from Argon2id");

    let mut config = Config::new(&s3).with_token(&jwt);
    config.walkable_v8_writer_enabled = true; // match FxFiles production
    EncryptedClient::new(config, EncryptionConfig::from_secret_key(secret))
        .expect("EncryptedClient::new")
}

fn fresh_bucket(tag: &str) -> String {
    let epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    format!("e2e-progress-{tag}-{epoch}-v8")
}

fn payload(size: usize) -> Vec<u8> {
    let mut data = vec![0u8; size];
    for (i, b) in data.iter_mut().enumerate() {
        *b = (i % 251) as u8; // non-trivial pattern => meaningful round-trip
    }
    data
}

fn progress_collector() -> (Arc<Mutex<Vec<(u64, u64)>>>, Arc<dyn Fn(u64, u64) + Send + Sync>) {
    let events: Arc<Mutex<Vec<(u64, u64)>>> = Arc::new(Mutex::new(Vec::new()));
    let ev = events.clone();
    let cb: Arc<dyn Fn(u64, u64) + Send + Sync> =
        Arc::new(move |done, tot| ev.lock().unwrap().push((done, tot)));
    (events, cb)
}

fn assert_progress_reaches_100(evs: &[(u64, u64)], total: u64) {
    assert!(!evs.is_empty(), "progress must be reported at least once");
    assert!(
        evs.iter().all(|(_, t)| *t == total),
        "every event's total must equal the file size ({total})"
    );
    for (done, _) in evs {
        assert!(*done <= total, "cumulative bytes must not exceed total");
    }
    let max_done = evs.iter().map(|(d, _)| *d).max().unwrap();
    assert_eq!(max_done, total, "progress must reach 100% (max cumulative == total)");
}

/// Web path: `put_object_flat_with_progress` (what FxFiles web uses).
#[tokio::test]
#[ignore = "real-server E2E; needs FULA_S3 + FULA_JWT + Mode A triple"]
async fn web_path_progress_reaches_100_against_real_master() {
    let client = make_client();
    let bucket = fresh_bucket("web");
    if let Err(e) = client.create_bucket(&bucket).await {
        eprintln!("[progress e2e] create_bucket({bucket}) returned {e} — continuing");
    }

    // 3 MiB > CHUNKED_THRESHOLD (768 KB) ⇒ multi-chunk concurrent upload.
    let data = payload(3 * 1024 * 1024);
    let total = data.len() as u64;
    let key_path = "/promo-web-progress.bin";

    let (events, cb) = progress_collector();
    client
        .put_object_flat_with_progress(
            &bucket,
            key_path,
            Bytes::from(data.clone()),
            Some("application/octet-stream"),
            cb,
        )
        .await
        .expect("web-path chunked upload must succeed against the live master");

    let evs = events.lock().unwrap().clone();
    eprintln!("[progress e2e] web path: {} events, max={}", evs.len(),
        evs.iter().map(|(d, _)| *d).max().unwrap_or(0));
    assert_progress_reaches_100(&evs, total);

    let got = client.get_object_flat(&bucket, key_path).await.expect("download");
    assert_eq!(&got[..], &data[..], "round-trip bytes must match");

    let _ = client.delete_object_flat(&bucket, key_path).await;
    let _ = client.delete_bucket(&bucket).await;
    eprintln!("[progress e2e] web path OK (bucket {bucket})");
}

/// Native path: `put_object_encrypted_resumable_with_cancel_and_progress`
/// (what FxFiles native uses, via the resumable bridge).
#[tokio::test]
#[ignore = "real-server E2E; needs FULA_S3 + FULA_JWT + Mode A triple"]
async fn native_resumable_progress_reaches_100_against_real_master() {
    let client = make_client();
    let bucket = fresh_bucket("native");
    if let Err(e) = client.create_bucket(&bucket).await {
        eprintln!("[progress e2e] create_bucket({bucket}) returned {e} — continuing");
    }

    let data = payload(3 * 1024 * 1024);
    let total = data.len() as u64;
    let key_path = "/promo-native-progress.bin";

    let manifest_dir = tempfile::TempDir::new().expect("manifest tempdir");
    let manifest_path = manifest_dir.path().join("e2e.manifest");

    let (events, cb) = progress_collector();
    client
        .put_object_encrypted_resumable_with_cancel_and_progress(
            &bucket,
            key_path,
            Bytes::from(data.clone()),
            Some("application/octet-stream"),
            &manifest_path,
            None,     // no cancel
            Some(cb), // progress
        )
        .await
        .expect("native resumable chunked upload must succeed against the live master");

    let evs = events.lock().unwrap().clone();
    eprintln!("[progress e2e] native path: {} events, max={}", evs.len(),
        evs.iter().map(|(d, _)| *d).max().unwrap_or(0));
    assert_progress_reaches_100(&evs, total);

    let got = client.get_object_flat(&bucket, key_path).await.expect("download");
    assert_eq!(&got[..], &data[..], "round-trip bytes must match");

    let _ = client.delete_object_flat(&bucket, key_path).await;
    let _ = client.delete_bucket(&bucket).await;
    eprintln!("[progress e2e] native path OK (bucket {bucket})");
}
