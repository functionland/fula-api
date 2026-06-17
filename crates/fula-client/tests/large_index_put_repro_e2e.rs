//! REPRO PROBE (not a pass/fail gate): upload a LARGE multi-chunk file via the
//! web chunked code path (`put_object_flat` -> `put_object_chunked_internal`)
//! against the LIVE master, to reproduce the "index PUT after all chunks ->
//! ERR_CONNECTION_CLOSED / upstream prematurely closed" failure the user hit on
//! a ~470-chunk (~120 MB) upload. Prints the outcome + the unique bucket name so
//! the gateway logs can be grepped for that exact window. Round-trips on success.
//!
//! `#[ignore]` — needs network + real credentials. Run (PowerShell, env from
//! e2e-credentials.env):
//!   cargo test -p fula-client --test large_index_put_repro_e2e --release -- --ignored --nocapture
//!
//! Required env: FULA_S3, FULA_JWT, FULA_TEST_PROVIDER, FULA_TEST_OAUTH_SUB,
//! FULA_TEST_EMAIL (the Mode A derivation triple).

#![cfg(not(target_arch = "wasm32"))]

use bytes::Bytes;
use fula_client::{Config, EncryptedClient, EncryptionConfig};
use fula_crypto::keys::SecretKey;

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("missing required env {name}"))
}

#[tokio::test]
#[ignore = "real-server repro; needs FULA_S3 + FULA_JWT + Mode A triple"]
async fn large_chunked_upload_repro_against_real_master() {
    let s3 = env("FULA_S3");
    let jwt = env("FULA_JWT");
    let input = format!(
        "{}:{}:{}",
        env("FULA_TEST_PROVIDER"),
        env("FULA_TEST_OAUTH_SUB"),
        env("FULA_TEST_EMAIL"),
    );
    let key = fula_crypto::hashing::derive_key_argon2id("fula-files-v1", input.as_bytes());
    let secret = SecretKey::from_bytes(&key).expect("32-byte secret from Argon2id");

    let mut config = Config::new(&s3).with_token(&jwt);
    config.walkable_v8_writer_enabled = true; // match FxFiles production (stamps chunk_cids -> big index metadata)
    let client = EncryptedClient::new(config, EncryptionConfig::from_secret_key(secret))
        .expect("EncryptedClient::new");

    let epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let bucket = format!("e2e-bigindex-{epoch}-v8");
    eprintln!("[repro] BUCKET={bucket}  (grep gateway logs for this)");
    if let Err(e) = client.create_bucket(&bucket).await {
        eprintln!("[repro] create_bucket({bucket}) -> {e} (continuing)");
    }

    // ~120 MB -> ~480 chunks at 256 KB -> ~70 KB chunked-index metadata,
    // matching the user's failing upload.
    let size = 120 * 1024 * 1024;
    let mut data = vec![0u8; size];
    for (i, b) in data.iter_mut().enumerate() {
        *b = (i % 251) as u8;
    }
    let key_path = "/big-repro.bin";

    eprintln!("[repro] uploading {} bytes (~{} chunks) at {} ...", size, size / (256 * 1024), epoch);
    let started = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let result = client
        .put_object_flat(&bucket, key_path, Bytes::from(data.clone()), Some("application/octet-stream"))
        .await;
    let ended = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    match &result {
        Ok(r) => eprintln!("[repro] UPLOAD OK etag={} (started={started} ended={ended})", r.etag),
        Err(e) => eprintln!("[repro] UPLOAD FAILED: {e}  (started={started} ended={ended})"),
    }

    // Round-trip only if it uploaded.
    if let Ok(r) = &result {
        let _ = r;
        match client.get_object_flat(&bucket, key_path).await {
            Ok(got) => eprintln!("[repro] download OK, {} bytes, match={}", got.len(), &got[..] == &data[..]),
            Err(e) => eprintln!("[repro] download FAILED: {e}"),
        }
        let _ = client.delete_object_flat(&bucket, key_path).await;
    }
    let _ = client.delete_bucket(&bucket).await;

    // Surface the outcome as the test result so --nocapture shows it clearly,
    // but the eprintln above is the real signal regardless of pass/fail.
    result.expect("large chunked upload should succeed (FAILS = repro of the reported bug)");
}
