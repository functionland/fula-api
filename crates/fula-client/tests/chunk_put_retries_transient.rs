//! Regression test (FxFiles issue #50 follow-up): content-chunk PUTs must be
//! retried on a transient failure — on web AND native.
//!
//! The chunked content-upload path
//!   `put_object_flat` → `put_object_chunked_internal`
//!     → `FulaClient::put_object_with_metadata` → `request()`
//! does a single `send()` with NO retry on either target. The native
//! blob-backend retry loop (`S3BlobBackend::put`) only wraps the
//! `__fula_forest_v7_nodes/` class, and `retry_idempotent` only wraps the
//! S3-multipart path — neither covers the per-file content chunks. So a single
//! sporadic chunk-PUT drop (`ERR_CONNECTION_CLOSED` / 503 under the 16-wide
//! concurrent burst) fails the whole large upload.
//!
//! This drives a >768 KB (therefore chunked) encrypted upload through a
//! wiremock master that injects exactly ONE 503 on the first content/chunk PUT
//! and asserts the upload still succeeds. RED before the fix (no chunk retry),
//! GREEN after wrapping the chunk PUT in `retry_idempotent`.

#![cfg(not(target_arch = "wasm32"))]

use bytes::Bytes;
use cid::multihash::Multihash;
use cid::Cid;
use fula_client::{Config, EncryptedClient, EncryptionConfig};
use fula_crypto::keys::SecretKey;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

/// BLAKE3-raw CID of the body, returned as the ETag so the SDK's W.9.3 /
/// W.9.4 self-verify accepts the (retried) PUT response.
fn blake3_raw_cid(data: &[u8]) -> Cid {
    let h = blake3::hash(data);
    let mh = Multihash::<64>::wrap(0x1e, h.as_bytes()).expect("blake3 multihash wrap");
    Cid::new_v1(0x55, mh)
}

/// Injects ONE 503 on the first CONTENT PUT (the content chunks upload before
/// the per-file index object, and forest blobs live under `__fula_forest_*`,
/// so the first non-forest PUT is a chunk). Everything else gets 200 + a
/// matching ETag.
struct FlakeFirstChunkPut {
    injected: Arc<AtomicBool>,
    injected_count: Arc<AtomicUsize>,
}

impl Respond for FlakeFirstChunkPut {
    fn respond(&self, req: &Request) -> ResponseTemplate {
        let is_forest = req.url.path().contains("__fula_forest_");
        if !is_forest && !self.injected.swap(true, Ordering::SeqCst) {
            self.injected_count.fetch_add(1, Ordering::SeqCst);
            return ResponseTemplate::new(503);
        }
        let cid = blake3_raw_cid(&req.body);
        ResponseTemplate::new(200).insert_header("ETag", cid.to_string())
    }
}

#[tokio::test]
async fn chunked_upload_survives_one_transient_chunk_put() {
    let server = MockServer::start().await;
    let injected = Arc::new(AtomicBool::new(false));
    let injected_count = Arc::new(AtomicUsize::new(0));

    Mock::given(method("PUT"))
        .respond_with(FlakeFirstChunkPut {
            injected: injected.clone(),
            injected_count: injected_count.clone(),
        })
        .mount(&server)
        .await;
    // Fresh bucket → 404 GET → cold v7 forest bootstrap.
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;
    // The pre-fix failure path best-effort DELETEs already-uploaded chunks.
    Mock::given(method("DELETE"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;
    Mock::given(method("HEAD"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let mut config = Config::new(&server.uri()).with_token("test-jwt");
    config.walkable_v8_writer_enabled = true;
    let secret = SecretKey::generate();
    let enc_config = EncryptionConfig::from_secret_key(secret);
    let client = EncryptedClient::new(config, enc_config).expect("EncryptedClient::new");

    // 2 MiB > CHUNKED_THRESHOLD (768 KB) ⇒ chunked upload: several concurrent
    // chunk PUTs, one of which gets the injected 503.
    let data = vec![0xABu8; 2 * 1024 * 1024];

    let result = client
        .put_object_flat("videos-v8", "/promo.mp4", Bytes::from(data), Some("video/mp4"))
        .await;

    assert_eq!(
        injected_count.load(Ordering::SeqCst),
        1,
        "test must inject exactly one transient chunk 503"
    );
    assert!(
        result.is_ok(),
        "chunked upload must survive one transient chunk-PUT 503 via per-chunk \
         retry; got error: {:?}",
        result.err()
    );
}
