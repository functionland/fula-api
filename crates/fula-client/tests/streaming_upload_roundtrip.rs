//! Hermetic round-trip test for the PUSH-model streaming upload (P2 of
//! docs/web-streaming-resumable-upload-plan.md).
//!
//! Drives the streaming methods exactly as the FRB handle will —
//!   streaming_begin
//!     -> plan-only ChunkedEncoder (pass 1, fed arbitrary streaming slices)
//!     -> streaming_finalize_plan
//!     -> streaming_put_chunk loop (pass 2, encrypt-from-stored-nonce)
//!     -> streaming_finish (index + forest register + flush)
//! — against a STATEFUL wiremock that stores PUT bodies and serves them back on
//! GET, then downloads via `get_object_flat` and asserts BYTE-EXACT recovery.
//!
//! This is the P2 gate: it proves the streaming path produces a normally
//! downloadable, decryptable object. No network / no credentials.

#![cfg(not(target_arch = "wasm32"))]

use cid::multihash::Multihash;
use cid::Cid;
use fula_client::{Config, EncryptedClient, EncryptionConfig};
use fula_crypto::chunked::ChunkedEncoder;
use fula_crypto::keys::SecretKey;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

/// BLAKE3-raw CID of `data`, returned as the ETag so the SDK's walkable-v8
/// post-PUT self-verify accepts the response.
fn blake3_raw_cid(data: &[u8]) -> Cid {
    let h = blake3::hash(data);
    let mh = Multihash::<64>::wrap(0x1e, h.as_bytes()).expect("blake3 multihash wrap");
    Cid::new_v1(0x55, mh)
}

type Store = Arc<Mutex<HashMap<String, Vec<u8>>>>;

/// PUT: store the body keyed by URL path; ETag = BLAKE3-raw CID(body).
struct StorePut {
    store: Store,
}
impl Respond for StorePut {
    fn respond(&self, req: &Request) -> ResponseTemplate {
        let path = req.url.path().to_string();
        let cid = blake3_raw_cid(&req.body);
        self.store.lock().unwrap().insert(path, req.body.clone());
        ResponseTemplate::new(200).insert_header("ETag", cid.to_string())
    }
}

/// GET: serve the stored body (200 + matching ETag) or 404.
struct ServeGet {
    store: Store,
}
impl Respond for ServeGet {
    fn respond(&self, req: &Request) -> ResponseTemplate {
        match self.store.lock().unwrap().get(req.url.path()) {
            Some(body) => ResponseTemplate::new(200)
                .insert_header("ETag", blake3_raw_cid(body).to_string())
                .set_body_bytes(body.clone()),
            None => ResponseTemplate::new(404),
        }
    }
}

/// HEAD: 200 if stored, else 404 (cold-bootstrap probes a fresh bucket).
struct HeadProbe {
    store: Store,
}
impl Respond for HeadProbe {
    fn respond(&self, req: &Request) -> ResponseTemplate {
        if self.store.lock().unwrap().contains_key(req.url.path()) {
            ResponseTemplate::new(200)
        } else {
            ResponseTemplate::new(404)
        }
    }
}

#[tokio::test]
async fn streaming_upload_roundtrip_byte_exact() {
    let server = MockServer::start().await;
    let store: Store = Arc::new(Mutex::new(HashMap::new()));
    Mock::given(method("PUT"))
        .respond_with(StorePut { store: store.clone() })
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .respond_with(ServeGet { store: store.clone() })
        .mount(&server)
        .await;
    Mock::given(method("HEAD"))
        .respond_with(HeadProbe { store: store.clone() })
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;

    let mut config = Config::new(&server.uri()).with_token("test-jwt");
    config.walkable_v8_writer_enabled = true;
    let secret = SecretKey::generate();
    let enc_config = EncryptionConfig::from_secret_key(secret);
    let client = EncryptedClient::new(config, enc_config).expect("EncryptedClient::new");

    let bucket = "videos-v8";
    let key = "/promo.mp4";
    // Multi-chunk with a sub-chunk tail; non-trivial byte pattern.
    let mut data = vec![0u8; 700 * 1024 + 123];
    for (i, b) in data.iter_mut().enumerate() {
        *b = (i % 251) as u8;
    }

    // ---- streaming upload (push model; mirrors the FRB handle) ----
    let (storage_key, dek, wrapped_dek, kek_version) =
        client.streaming_begin(bucket, key).await.expect("streaming_begin");

    // pass 1: plan-only encoder, fed arbitrary streaming slices.
    let aad_prefix = format!("fula:v4:chunk:{}", storage_key);
    let mut encoder = ChunkedEncoder::with_aad_and_chunk_size(
        dek.clone(),
        aad_prefix.into_bytes(),
        64 * 1024,
    )
    .into_plan_only();
    for slice in data.chunks(100 * 1024) {
        encoder.update(slice).expect("plan update");
    }
    let (chunked_metadata, private_meta, encrypted_meta) = client
        .streaming_finalize_plan(encoder, &dek, &storage_key, key, Some("video/mp4"))
        .expect("streaming_finalize_plan");

    let cs = chunked_metadata.chunk_size as usize;
    let num_chunks = chunked_metadata.num_chunks as usize;
    assert!(num_chunks > 1, "test needs a multi-chunk file (got {num_chunks})");

    // pass 2: upload each chunk from its committed nonce.
    let mut chunk_cids = vec![None; num_chunks];
    for i in 0..num_chunks {
        let start = i * cs;
        let end = ((i + 1) * cs).min(data.len());
        let (_chunk_key, cid) = client
            .streaming_put_chunk(
                bucket,
                &storage_key,
                &chunked_metadata,
                i as u32,
                &data[start..end],
                &dek,
                true,
            )
            .await
            .expect("streaming_put_chunk");
        chunk_cids[i] = cid;
    }

    client
        .streaming_finish(
            bucket,
            key,
            &storage_key,
            &wrapped_dek,
            &encrypted_meta,
            kek_version,
            &private_meta,
            chunked_metadata,
            chunk_cids,
        )
        .await
        .expect("streaming_finish");

    // ---- download + verify byte-exact ----
    let downloaded = client
        .get_object_flat(bucket, key)
        .await
        .expect("get_object_flat");
    assert_eq!(
        downloaded.len(),
        data.len(),
        "round-trip length mismatch"
    );
    assert_eq!(
        downloaded.as_ref(),
        data.as_slice(),
        "streaming upload -> download must be byte-exact"
    );
}
