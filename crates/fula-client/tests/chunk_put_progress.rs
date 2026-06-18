//! TDD for chunk-granular upload progress (FxFiles "show upload %").
//!
//! A chunked `put_object_flat_with_progress` must report **cumulative**
//! bytes_uploaded as each chunk completes, with `total` = the file size and a
//! final event equal to `total` (100%). This is the real progress the SDK
//! previously didn't expose (apps only had a time-based estimate). RED before
//! the progress callback exists; GREEN after.

#![cfg(not(target_arch = "wasm32"))]

use bytes::Bytes;
use cid::multihash::Multihash;
use cid::Cid;
use fula_client::{Config, EncryptedClient, EncryptionConfig};
use fula_crypto::keys::SecretKey;
use std::sync::{Arc, Mutex};
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

fn blake3_raw_cid(data: &[u8]) -> Cid {
    let h = blake3::hash(data);
    let mh = Multihash::<64>::wrap(0x1e, h.as_bytes()).expect("blake3 multihash wrap");
    Cid::new_v1(0x55, mh)
}

/// 200 + matching ETag for every PUT so the W.9.3/W.9.4 self-verify accepts it.
struct EtagResponder;
impl Respond for EtagResponder {
    fn respond(&self, req: &Request) -> ResponseTemplate {
        ResponseTemplate::new(200).insert_header("ETag", blake3_raw_cid(&req.body).to_string())
    }
}

#[tokio::test]
async fn chunked_put_reports_cumulative_progress() {
    let server = MockServer::start().await;
    Mock::given(method("PUT")).respond_with(EtagResponder).mount(&server).await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;
    Mock::given(method("HEAD"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let mut config = Config::new(&server.uri()).with_token("test-jwt");
    config.walkable_v8_writer_enabled = true;
    let secret = SecretKey::generate();
    let client = EncryptedClient::new(config, EncryptionConfig::from_secret_key(secret))
        .expect("EncryptedClient::new");

    // 2 MiB > CHUNKED_THRESHOLD (768 KB) ⇒ ~3 chunks ⇒ multiple progress events.
    let data = vec![0xCDu8; 2 * 1024 * 1024];
    let total = data.len() as u64;

    let events: Arc<Mutex<Vec<(u64, u64)>>> = Arc::new(Mutex::new(Vec::new()));
    let ev = events.clone();
    let progress: Arc<dyn Fn(u64, u64) + Send + Sync> = Arc::new(move |done, tot| {
        ev.lock().unwrap().push((done, tot));
    });

    client
        .put_object_flat_with_progress(
            "videos-v8",
            "/promo.mp4",
            Bytes::from(data),
            Some("video/mp4"),
            progress,
        )
        .await
        .expect("chunked upload must succeed");

    let evs = events.lock().unwrap().clone();
    assert!(!evs.is_empty(), "progress must be reported at least once");
    assert!(
        evs.iter().all(|(_, t)| *t == total),
        "every event's total must equal the file size ({total})"
    );
    for (done, _) in &evs {
        assert!(*done <= total, "cumulative bytes must not exceed total");
    }
    // Under buffer_unordered(16) the completion order != push order, so assert
    // the MAX reported cumulative reaches total (not that the last-pushed does).
    let max_done = evs.iter().map(|(d, _)| *d).max().unwrap();
    assert_eq!(max_done, total, "progress must reach 100% (max cumulative == total)");
}

/// 0.6.14 wasm upload-cancel: a pre-set cancel flag must abort the chunked
/// upload with `ClientError::Cancelled` — every chunk short-circuits at the
/// closure-start check before its PUT (mirrors the native resumable cancel).
#[tokio::test]
async fn chunked_put_cancellable_aborts_when_flag_preset() {
    use std::sync::atomic::AtomicBool;

    let server = MockServer::start().await;
    Mock::given(method("PUT")).respond_with(EtagResponder).mount(&server).await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;
    Mock::given(method("HEAD"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let mut config = Config::new(&server.uri()).with_token("test-jwt");
    config.walkable_v8_writer_enabled = true;
    let secret = SecretKey::generate();
    let client = EncryptedClient::new(config, EncryptionConfig::from_secret_key(secret))
        .expect("EncryptedClient::new");

    // Multi-chunk file (2 MiB > 768 KB threshold).
    let data = vec![0xABu8; 2 * 1024 * 1024];
    // Pre-cancelled: the flag is already set before the upload starts.
    let cancel = Arc::new(AtomicBool::new(true));
    let progress: Arc<dyn Fn(u64, u64) + Send + Sync> = Arc::new(|_, _| {});

    let result = client
        .put_object_flat_with_progress_cancellable(
            "videos-v8",
            "/cancelled.bin",
            Bytes::from(data),
            Some("application/octet-stream"),
            progress,
            cancel,
        )
        .await;

    assert!(
        matches!(result, Err(fula_client::ClientError::Cancelled)),
        "a pre-set cancel flag must abort the chunked upload with Cancelled",
    );
}
