//! Phase 2 — LIVE ingest-route e2e (requires a running master + fula-ingest).
//!
//! Env (skip-without, offline_e2e convention):
//!   FULA_S3      master base URL (e.g. http://127.0.0.1:9000)
//!   FULA_JWT     bearer for the master (HS256 with the master's secret)
//!   FULA_INGEST  fula-ingest base URL (e.g. http://127.0.0.1:3601)
//!   FULA_BIG=1   also run the ≥1 GiB case (writes a temp file)
//!
//! Run: cargo test -p fula-client --test live_ingest_e2e --release -- --ignored --nocapture
//!
//! The runner script (fula-ota tests/e2e/phase-2/60-fidelity.sh) asserts the
//! ingest container's accepted-block log count INCREASES across this test —
//! the server-side proof that bytes flowed via the ingest node, not the
//! gateway.

#![cfg(not(target_arch = "wasm32"))]

use fula_client::{Config, EncryptedClient, EncryptionConfig};
use fula_crypto::keys::SecretKey;

fn env_or_skip(key: &str) -> Option<String> {
    match std::env::var(key) {
        Ok(v) if !v.is_empty() => Some(v),
        _ => {
            eprintln!("SKIP: {key} not set");
            None
        }
    }
}

fn client(s3: &str, jwt: &str, ingest: Option<&str>, v8: bool) -> EncryptedClient {
    let mut config = Config::new(s3).with_token(jwt);
    // The contended e2e box serializes 16 parallel chunk commits through the
    // per-bucket write lock (each including a registry persist+pin); under
    // load the queue tail exceeds the 30s default. Real deployments commit in
    // ~100ms — this is test-box headroom, not a product setting.
    config.timeout = std::time::Duration::from_secs(600);
    config.walkable_v8_writer_enabled = v8;
    if let Some(i) = ingest {
        config.ingest_endpoints = vec![i.to_string()];
    }
    let secret = SecretKey::generate();
    EncryptedClient::new(config, EncryptionConfig::from_secret_key(secret)).expect("client")
}

fn payload(len: usize) -> Vec<u8> {
    (0..len).map(|i| ((i * 31 + 7) % 251) as u8).collect()
}

/// Chunked upload routed via the ingest node, read back through the master —
/// full live round-trip of the Phase 2 byte path (client CID on).
#[tokio::test]
#[ignore]
async fn live_chunked_via_ingest_round_trip() {
    let (Some(s3), Some(jwt), Some(ingest)) = (
        env_or_skip("FULA_S3"),
        env_or_skip("FULA_JWT"),
        env_or_skip("FULA_INGEST"),
    ) else {
        return;
    };
    let c = client(&s3, &jwt, Some(&ingest), true);
    let bucket = "p2-live-ingest";
    let key = "/ingest/round-trip.bin";
    // >768 KiB → put_object_flat dispatches into put_object_chunked_internal
    // (the FxFiles photo/video path) where the ingest route lives.
    let data = payload(1_500_000);

    c.put_object_flat(bucket, key, data.clone(), Some("application/octet-stream"))
        .await
        .expect("chunked flat upload via ingest route");

    let got = c
        .get_object_flat(bucket, key)
        .await
        .expect("download after ingest-routed upload");
    assert_eq!(got.len(), data.len(), "length mismatch");
    assert_eq!(
        blake3::hash(&got),
        blake3::hash(&data),
        "content mismatch after ingest-routed round trip"
    );
}

/// Same upload with the v8 writer OFF — the ingest route must self-disable
/// (no pre-computed CIDs to declare) and the legacy path must round-trip.
#[tokio::test]
#[ignore]
async fn live_chunked_v8_off_legacy_round_trip() {
    let (Some(s3), Some(jwt)) = (env_or_skip("FULA_S3"), env_or_skip("FULA_JWT")) else {
        return;
    };
    let ingest = std::env::var("FULA_INGEST").ok();
    let c = client(&s3, &jwt, ingest.as_deref(), false);
    let bucket = "p2-live-legacy";
    let key = "/legacy/round-trip.bin";
    let data = payload(1_200_000);

    c.put_object_flat(bucket, key, data.clone(), Some("application/octet-stream"))
        .await
        .expect("chunked flat upload, v8 off");
    let got = c.get_object_flat(bucket, key).await.expect("download");
    assert_eq!(blake3::hash(&got), blake3::hash(&data));
}

/// Large-file chunked upload via the ingest route (scale invariant: many
/// thousands of chunks, bounded service-side memory). Gated on FULA_BIG=1.
///
/// Size = `FULA_BIG_MB` MiB (default 512 ≈ 2048 chunks at 256 KiB). The
/// 7.8 GB / 4-core e2e box swap-thrashes for 12h+ on a full 1 GiB because the
/// product buffers a whole file in RAM (`put_flat_from_path` → fs::read →
/// one Bytes) AND every chunk's metadata commit serializes through the
/// per-bucket lock; 512 MiB proves the same multi-thousand-chunk streaming +
/// ingest path in ~30-40 min here. To validate the literal ≥1 GiB on a
/// prod-class box: `FULA_BIG_MB=1024` (or higher). The product memory model
/// (full-file buffering) is flagged for prod large-file sizing.
#[tokio::test]
#[ignore]
async fn live_large_file_chunked_via_ingest() {
    if std::env::var("FULA_BIG").ok().as_deref() != Some("1") {
        eprintln!("SKIP: FULA_BIG != 1");
        return;
    }
    let (Some(s3), Some(jwt), Some(ingest)) = (
        env_or_skip("FULA_S3"),
        env_or_skip("FULA_JWT"),
        env_or_skip("FULA_INGEST"),
    ) else {
        return;
    };
    let size_mb: usize = std::env::var("FULA_BIG_MB")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(512);
    let size = size_mb * 1024 * 1024;

    let c = client(&s3, &jwt, Some(&ingest), true);
    let bucket = "p2-live-big";
    let key = "/big/large.bin";

    let data = payload(size); // size/256KiB chunks
    let want = blake3::hash(&data);
    let len = data.len();

    let started = std::time::Instant::now();
    // MOVE the payload — holding payload + a clone doubles RSS and OOM-kills
    // the run on this box (run #4, SIGKILL). `want`+`len` carry everything
    // verification needs.
    c.put_object_flat(bucket, key, data, Some("application/octet-stream"))
        .await
        .unwrap_or_else(|e| panic!("{size_mb} MiB chunked flat upload via ingest: {e:?}"));
    eprintln!("{size_mb} MiB upload took {:?} (~{} chunks)", started.elapsed(), len / (256 * 1024));

    let got = c.get_object_flat(bucket, key).await.expect("large-file download");
    assert_eq!(got.len(), len);
    assert_eq!(blake3::hash(&got), want, "large-file content mismatch");
}
