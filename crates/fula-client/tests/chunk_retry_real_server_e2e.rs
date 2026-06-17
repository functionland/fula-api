//! Real-server E2E (FxFiles #50): a LARGE (chunked) encrypted upload + round
//! trip against the LIVE master, exercising the per-chunk upload path end to
//! end with a real account's credentials. Confirms the SDK still uploads and
//! reads back a multi-chunk file after the per-chunk-retry change.
//!
//! `#[ignore]` — needs network + real credentials. Run (PowerShell, env from
//! `e2e-credentials.env`):
//!
//! ```powershell
//! cargo test -p fula-client --test chunk_retry_real_server_e2e --release `
//!     -- --ignored --nocapture
//! ```
//!
//! Required env: `FULA_S3`, `FULA_JWT`, `FULA_TEST_PROVIDER`,
//! `FULA_TEST_OAUTH_SUB`, `FULA_TEST_EMAIL` (the Mode A derivation triple —
//! Argon2id("fula-files-v1", "{provider}:{sub}:{email}"), auth_service.dart
//! byte-for-byte). A fresh, uniquely-named bucket is created so the test is
//! self-contained and never touches the account's real data.

#![cfg(not(target_arch = "wasm32"))]

use bytes::Bytes;
use fula_client::{Config, EncryptedClient, EncryptionConfig};
use fula_crypto::keys::SecretKey;

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("missing required env {name}"))
}

#[tokio::test]
#[ignore = "real-server E2E; needs FULA_S3 + FULA_JWT + Mode A triple"]
async fn large_chunked_upload_roundtrips_against_real_master() {
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
    let client = EncryptedClient::new(config, EncryptionConfig::from_secret_key(secret))
        .expect("EncryptedClient::new");

    // Fresh uniquely-named bucket → clean forest, never collides with real data.
    let epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let bucket = format!("e2e-chunkretry-{epoch}-v8");
    // Best-effort (the gateway may auto-create on first write; tolerate exists).
    if let Err(e) = client.create_bucket(&bucket).await {
        eprintln!("[#50 e2e] create_bucket({bucket}) returned {e} — continuing");
    }

    // 3 MiB > CHUNKED_THRESHOLD (768 KB) ⇒ multi-chunk concurrent upload — the
    // exact path that drops on the web without the per-chunk retry.
    let mut data = vec![0u8; 3 * 1024 * 1024];
    for (i, b) in data.iter_mut().enumerate() {
        *b = (i % 251) as u8; // non-trivial pattern so the round-trip is meaningful
    }
    let key_path = "/promo-video-e2e.bin";

    client
        .put_object_flat(
            &bucket,
            key_path,
            Bytes::from(data.clone()),
            Some("application/octet-stream"),
        )
        .await
        .expect("large chunked upload must succeed against the live master");

    // Round-trip: download + verify byte-identical (chunks stored + reassembled).
    let got = client
        .get_object_flat(&bucket, key_path)
        .await
        .expect("download must succeed");
    assert_eq!(got.len(), data.len(), "downloaded size mismatch");
    assert_eq!(&got[..], &data[..], "downloaded bytes must equal uploaded");

    // Best-effort cleanup so the test account doesn't accrue orphans.
    let _ = client.delete_object_flat(&bucket, key_path).await;
    let _ = client.delete_bucket(&bucket).await;

    eprintln!("[#50 e2e] OK: 3 MiB chunked upload + round-trip against {s3} (bucket {bucket})");
}
