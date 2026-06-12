//! Phase 2 (decentralized ingress) — client routing matrix.
//!
//! Verifies the three load-bearing behaviors of `Config.ingest_endpoints`:
//!
//!  1. **Old master (no /fula/capabilities)** → the ingest route never
//!     activates; every chunk goes to the master as a full-bytes PUT
//!     (the misstore-on-old-master hazard the capability probe exists for).
//!  2. **Capable master + healthy ingest** → chunk BYTES go to the ingest
//!     node; the master receives ONLY empty-body mapping PUTs carrying
//!     `x-amz-meta-fula-remote-cid` (the declared blake3 CID) and
//!     `x-amz-meta-fula-remote-size` (the true ciphertext size).
//!  3. **Capable master + dead ingest** → transparent fallback: the upload
//!     still succeeds and the master sees full-bytes chunk PUTs.
//!
//! Chunk PUTs are identified by the `x-amz-meta-x-fula-chunk: true` header
//! the SDK stamps on every chunk (index objects / forest blobs lack it).

#![cfg(not(target_arch = "wasm32"))]

use bytes::Bytes;
use cid::multihash::Multihash;
use cid::Cid;
use fula_client::{Config, EncryptedClient, EncryptionConfig};
use fula_crypto::keys::SecretKey;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

fn blake3_raw_cid(data: &[u8]) -> Cid {
    let h = blake3::hash(data);
    let mh = Multihash::<64>::wrap(0x1e, h.as_bytes()).expect("blake3 multihash wrap");
    Cid::new_v1(0x55, mh)
}

/// Master-side recording responder. Mimics BOTH master generations:
/// for a normal bytes PUT it returns `ETag = blake3(body)` (what every
/// master does); for an empty-body mapping PUT it returns `ETag =
/// declared cid` (what a flag-on master does after its presence check).
/// Records per-class counters the assertions read back.
struct MasterResponder {
    chunk_full_bodies: Arc<AtomicUsize>,
    chunk_mapping_puts: Arc<AtomicUsize>,
    mapping_size_headers: Arc<Mutex<Vec<u64>>>,
}

impl Respond for MasterResponder {
    fn respond(&self, req: &Request) -> ResponseTemplate {
        let is_chunk = req
            .headers
            .get("x-amz-meta-x-fula-chunk")
            .map(|v| v.to_str().unwrap_or("") == "true")
            .unwrap_or(false);
        let remote_cid = req
            .headers
            .get("x-amz-meta-fula-remote-cid")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);

        if let Some(declared) = remote_cid {
            // Mapping PUT: must be empty-bodied; echo the declared cid as ETag.
            assert!(
                req.body.is_empty(),
                "mapping PUT must carry an EMPTY body, got {} bytes",
                req.body.len()
            );
            if is_chunk {
                self.chunk_mapping_puts.fetch_add(1, Ordering::SeqCst);
            }
            if let Some(sz) = req
                .headers
                .get("x-amz-meta-fula-remote-size")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<u64>().ok())
            {
                self.mapping_size_headers.lock().unwrap().push(sz);
            }
            return ResponseTemplate::new(200).insert_header("ETag", declared.as_str());
        }

        if is_chunk && !req.body.is_empty() {
            self.chunk_full_bodies.fetch_add(1, Ordering::SeqCst);
        }
        let cid = blake3_raw_cid(&req.body);
        ResponseTemplate::new(200).insert_header("ETag", cid.to_string())
    }
}

/// Ingest-side responder: verifies the declared cid matches the body
/// (what the real fula-ingest does) and counts accepted blocks + bytes.
struct IngestResponder {
    accepted: Arc<AtomicUsize>,
    bytes_seen: Arc<AtomicUsize>,
}

impl Respond for IngestResponder {
    fn respond(&self, req: &Request) -> ResponseTemplate {
        let declared = req
            .url
            .query_pairs()
            .find(|(k, _)| k == "cid")
            .map(|(_, v)| v.to_string())
            .unwrap_or_default();
        let actual = blake3_raw_cid(&req.body).to_string();
        assert_eq!(declared, actual, "client must declare the true blake3 CID");
        self.accepted.fetch_add(1, Ordering::SeqCst);
        self.bytes_seen.fetch_add(req.body.len(), Ordering::SeqCst);
        ResponseTemplate::new(200)
            .set_body_json(serde_json::json!({"cid": declared, "size": req.body.len()}))
    }
}

struct Counters {
    chunk_full_bodies: Arc<AtomicUsize>,
    chunk_mapping_puts: Arc<AtomicUsize>,
    mapping_size_headers: Arc<Mutex<Vec<u64>>>,
    ingest_accepted: Arc<AtomicUsize>,
    ingest_bytes: Arc<AtomicUsize>,
}

/// Build (master, ingest, counters); `advertise_capability` controls whether
/// the master exposes /fula/capabilities (old vs new build).
async fn setup(advertise_capability: bool) -> (MockServer, MockServer, Counters) {
    let master = MockServer::start().await;
    let ingest = MockServer::start().await;

    let c = Counters {
        chunk_full_bodies: Arc::new(AtomicUsize::new(0)),
        chunk_mapping_puts: Arc::new(AtomicUsize::new(0)),
        mapping_size_headers: Arc::new(Mutex::new(Vec::new())),
        ingest_accepted: Arc::new(AtomicUsize::new(0)),
        ingest_bytes: Arc::new(AtomicUsize::new(0)),
    };

    if advertise_capability {
        Mock::given(method("GET"))
            .and(path("/fula/capabilities"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"remoteCidPut": true})),
            )
            .mount(&master)
            .await;
    }
    Mock::given(method("PUT"))
        .respond_with(MasterResponder {
            chunk_full_bodies: c.chunk_full_bodies.clone(),
            chunk_mapping_puts: c.chunk_mapping_puts.clone(),
            mapping_size_headers: c.mapping_size_headers.clone(),
        })
        .mount(&master)
        .await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&master)
        .await;
    Mock::given(method("HEAD"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&master)
        .await;

    Mock::given(method("PUT"))
        .respond_with(IngestResponder {
            accepted: c.ingest_accepted.clone(),
            bytes_seen: c.ingest_bytes.clone(),
        })
        .mount(&ingest)
        .await;

    (master, ingest, c)
}

fn client_for(master_uri: &str, ingest_uri: Option<&str>) -> EncryptedClient {
    let mut config = Config::new(master_uri).with_token("test-jwt");
    config.walkable_v8_writer_enabled = true;
    if let Some(uri) = ingest_uri {
        config.ingest_endpoints = vec![uri.to_string()];
    }
    let secret = SecretKey::generate();
    EncryptedClient::new(config, EncryptionConfig::from_secret_key(secret)).expect("client")
}

/// 5 chunks of 64 KiB — well past the threshold with an explicit chunk size.
fn payload() -> Vec<u8> {
    (0..(5 * 64 * 1024)).map(|i| (i % 251) as u8).collect()
}

#[tokio::test]
async fn old_master_never_receives_the_new_protocol() {
    let (master, ingest, c) = setup(false).await;
    let client = client_for(&master.uri(), Some(&ingest.uri()));

    client
        .put_object_chunked("bucket-a", "/file.bin", &payload(), Some(64 * 1024))
        .await
        .expect("upload must succeed via legacy path");

    assert_eq!(
        c.ingest_accepted.load(Ordering::SeqCst),
        0,
        "ingest must never be used when the master lacks the capability"
    );
    assert_eq!(c.chunk_mapping_puts.load(Ordering::SeqCst), 0);
    assert!(
        c.chunk_full_bodies.load(Ordering::SeqCst) >= 5,
        "all chunks must arrive at the master as full bodies"
    );
}

#[tokio::test]
async fn capable_master_routes_bytes_through_ingest() {
    let (master, ingest, c) = setup(true).await;
    let client = client_for(&master.uri(), Some(&ingest.uri()));

    let data = payload();
    client
        .put_object_chunked("bucket-b", "/file.bin", &data, Some(64 * 1024))
        .await
        .expect("upload must succeed via ingest route");

    let accepted = c.ingest_accepted.load(Ordering::SeqCst);
    let mappings = c.chunk_mapping_puts.load(Ordering::SeqCst);
    assert!(accepted >= 5, "chunk bytes must hit the ingest node (got {accepted})");
    assert_eq!(
        c.chunk_full_bodies.load(Ordering::SeqCst),
        0,
        "no chunk should arrive at the master as a full body"
    );
    assert_eq!(accepted, mappings, "every ingest-accepted chunk needs its mapping PUT");
    // The true ciphertext sizes (plaintext + AEAD overhead) must be declared.
    let sizes = c.mapping_size_headers.lock().unwrap();
    assert_eq!(sizes.len(), mappings);
    assert!(sizes.iter().all(|&s| s > 0), "remote-size must never be 0");
    let total_ingest_bytes = c.ingest_bytes.load(Ordering::SeqCst) as u64;
    assert_eq!(
        sizes.iter().sum::<u64>(),
        total_ingest_bytes,
        "declared sizes must equal the bytes the ingest node stored"
    );
}

#[tokio::test]
async fn dead_ingest_falls_back_to_full_bytes() {
    let (master, _ingest, c) = setup(true).await;
    // Point at a port nothing listens on — connection refused, fast.
    let client = client_for(&master.uri(), Some("http://127.0.0.1:9"));

    client
        .put_object_chunked("bucket-c", "/file.bin", &payload(), Some(64 * 1024))
        .await
        .expect("upload must SUCCEED despite the dead ingest (transparent fallback)");

    assert_eq!(c.chunk_mapping_puts.load(Ordering::SeqCst), 0);
    assert!(
        c.chunk_full_bodies.load(Ordering::SeqCst) >= 5,
        "fallback must deliver every chunk as a full-bytes PUT"
    );
}

#[tokio::test]
async fn no_ingest_configured_is_byte_identical_legacy() {
    let (master, ingest, c) = setup(true).await;
    let client = client_for(&master.uri(), None);

    client
        .put_object_chunked("bucket-d", "/file.bin", &payload(), Some(64 * 1024))
        .await
        .expect("legacy upload");

    assert_eq!(c.ingest_accepted.load(Ordering::SeqCst), 0);
    assert_eq!(c.chunk_mapping_puts.load(Ordering::SeqCst), 0);
    assert!(c.chunk_full_bodies.load(Ordering::SeqCst) >= 5);
    drop(ingest);
}
