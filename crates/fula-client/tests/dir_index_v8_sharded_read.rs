//! plan-D5 (v8) — sharded directory-index READ path integration tests.
//!
//! Exercises `load_directory_index_sharded` end-to-end against a stateful
//! in-memory mock master (PUTs stash the body + return its BLAKE3-raw CID as
//! the ETag; GETs replay or 404). Two behaviours that the crypto-layer unit
//! tests cannot cover:
//!
//!   1. **Multi-shard round-trip**: files spread across many directories
//!      produce several dir-index shards; after a cache-invalidating reload the
//!      forest loads cleanly via the sharded read path and every file still
//!      round-trips.
//!   2. **Missing-shard → rebuild fallback** (advisor must-fix): if a dir-index
//!      shard object is gone, the sharded read returns `Ok(None)` and the
//!      caller transparently rebuilds the dir-index from the forest (the HAMT
//!      is the source of truth) — a missing shard must NEVER hard-fail or
//!      produce a truncated listing.

#![cfg(not(target_arch = "wasm32"))]

use bytes::Bytes;
use cid::multihash::Multihash;
use cid::Cid;
use fula_client::{Config, EncryptedClient, EncryptionConfig};
use fula_crypto::keys::{KeyManager, SecretKey};
use fula_crypto::private_forest::{derive_dir_index_shard_key, DIR_INDEX_V8_NUM_SHARDS};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

fn blake3_raw_cid(data: &[u8]) -> Cid {
    let h = blake3::hash(data);
    let mh = Multihash::<64>::wrap(0x1e, h.as_bytes()).expect("blake3 multihash wrap");
    Cid::new_v1(0x55, mh)
}

type Stash = Arc<Mutex<HashMap<String, Vec<u8>>>>;

/// PUT → stash the body keyed by URL path, return its BLAKE3-raw CID as the
/// ETag so the SDK's walkable-v8 self-verify accepts the round-trip.
struct PutResponder {
    stash: Stash,
}
impl Respond for PutResponder {
    fn respond(&self, req: &Request) -> ResponseTemplate {
        let path = req.url.path().to_string();
        let body = req.body.clone();
        let cid = blake3_raw_cid(&body);
        self.stash.lock().unwrap().insert(path, body);
        ResponseTemplate::new(200).insert_header("ETag", cid.to_string())
    }
}

/// GET → serve from the stash (with the matching ETag), or 404 if absent.
struct GetResponder {
    stash: Stash,
}
impl Respond for GetResponder {
    fn respond(&self, req: &Request) -> ResponseTemplate {
        let path = req.url.path().to_string();
        match self.stash.lock().unwrap().get(&path) {
            Some(bytes) => ResponseTemplate::new(200)
                .insert_header("ETag", blake3_raw_cid(bytes).to_string())
                .set_body_bytes(bytes.clone()),
            None => ResponseTemplate::new(404),
        }
    }
}

async fn setup() -> (MockServer, Stash, EncryptedClient, SecretKey) {
    let server = MockServer::start().await;
    let stash: Stash = Arc::new(Mutex::new(HashMap::new()));
    Mock::given(method("PUT"))
        .respond_with(PutResponder { stash: stash.clone() })
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .respond_with(GetResponder { stash: stash.clone() })
        .mount(&server)
        .await;
    Mock::given(method("HEAD"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    let mut config = Config::new(&server.uri()).with_token("test-jwt");
    config.walkable_v8_writer_enabled = true;
    let secret = SecretKey::generate();
    let client = EncryptedClient::new(config, EncryptionConfig::from_secret_key(secret.clone()))
        .expect("EncryptedClient::new");
    (server, stash, client, secret)
}

/// Files spread across many directories (so the dir-index spans several shards).
const FILES: &[&str] = &[
    "/docs/a.txt",
    "/docs/b.txt",
    "/docs/sub/c.txt",
    "/photos/2024/x.jpg",
    "/photos/2025/y.jpg",
    "/music/rock/song.mp3",
    "/music/jazz/tune.mp3",
    "/projects/fula/readme.md",
    "/projects/fula/src/lib.rs",
    "/a/b/c/d/e/deep.txt",
];

async fn write_and_flush(client: &EncryptedClient, bucket: &str) {
    for (i, f) in FILES.iter().enumerate() {
        let data = format!("payload-{}", i).into_bytes();
        client
            .put_object_flat_deferred(bucket, f, Bytes::from(data), None)
            .await
            .unwrap_or_else(|e| panic!("put {f}: {e:?}"));
    }
    client.flush_forest(bucket).await.expect("flush_forest");
}

/// Multi-shard v8 write → flush → reload → every file round-trips. The reload
/// loads the sharded dir-index via `load_directory_index_sharded`; if that path
/// errored on any shard the whole forest load would fail.
#[tokio::test]
async fn dir_index_v8_multi_dir_round_trip_reads_back() {
    let (_server, _stash, client, _secret) = setup().await;
    let bucket = "v8-multidir";
    write_and_flush(&client, bucket).await;

    // Force a fresh load from storage (evicts the in-memory forest), so the
    // next read re-fetches the manifest + sharded dir-index from the mock.
    client.invalidate_all_forest_caches();

    for (i, f) in FILES.iter().enumerate() {
        let got = client
            .get_object_flat(bucket, f)
            .await
            .unwrap_or_else(|e| panic!("get {f} after sharded reload: {e:?}"));
        assert_eq!(
            got.as_ref(),
            format!("payload-{}", i).as_bytes(),
            "round-trip mismatch for {f} after v8 sharded dir-index reload"
        );
    }
}

/// Missing dir-index shard objects → the sharded read returns `Ok(None)` and
/// the caller rebuilds the dir-index from the forest. Reads must STILL succeed
/// (the HAMT is intact) — never a hard-fail or truncated listing.
#[tokio::test]
async fn dir_index_v8_missing_shards_rebuild_from_forest() {
    let (_server, stash, client, secret) = setup().await;
    let bucket = "v8-missing-shards";
    write_and_flush(&client, bucket).await;
    client.invalidate_all_forest_caches();

    // Delete EVERY dir-index shard object from the mock store. The manifest
    // still references them, so the reload's sharded read will 404 on each →
    // Ok(None) → rebuild-from-forest.
    let km = KeyManager::from_secret_key(secret);
    let forest_dek = km.derive_path_key(&format!("forest:{bucket}"));
    {
        let mut s = stash.lock().unwrap();
        let mut removed = 0usize;
        for idx in 0..DIR_INDEX_V8_NUM_SHARDS {
            let shard_key = derive_dir_index_shard_key(&forest_dek, bucket, idx);
            // Object URL path is `/{bucket}/{storage_key}`.
            if s.remove(&format!("/{bucket}/{shard_key}")).is_some() {
                removed += 1;
            }
        }
        assert!(
            removed > 0,
            "test setup: expected at least one dir-index shard object to delete"
        );
    }

    // Every file must still read back — proving missing dir-index shards
    // degrade to rebuild-from-forest, not to a failed/empty read.
    for (i, f) in FILES.iter().enumerate() {
        let got = client
            .get_object_flat(bucket, f)
            .await
            .unwrap_or_else(|e| panic!("get {f} after dir-index shards removed: {e:?}"));
        assert_eq!(
            got.as_ref(),
            format!("payload-{}", i).as_bytes(),
            "missing dir-index shards must rebuild, not break the read for {f}"
        );
    }
}

/// The dir-index shard object URL paths actually present in the store, for the
/// given bucket — i.e. the NON-EMPTY shards the writer committed.
fn present_shard_paths(stash: &Stash, secret: &SecretKey, bucket: &str) -> Vec<String> {
    let km = KeyManager::from_secret_key(secret.clone());
    let forest_dek = km.derive_path_key(&format!("forest:{bucket}"));
    let s = stash.lock().unwrap();
    (0..DIR_INDEX_V8_NUM_SHARDS)
        .map(|idx| format!("/{bucket}/{}", derive_dir_index_shard_key(&forest_dek, bucket, idx)))
        .filter(|p| s.contains_key(p))
        .collect()
}

/// Delete EXACTLY ONE dir-index shard object (leave the rest intact) → the
/// sharded read hits ONE 404 → `Ok(None)` → full rebuild-from-forest. This is
/// the must-fix invariant: a single failed shard must force a rebuild, NOT a
/// skip-and-continue that silently drops that shard's directory entries.
#[tokio::test]
async fn dir_index_v8_single_missing_shard_rebuilds() {
    let (_server, stash, client, secret) = setup().await;
    let bucket = "v8-one-missing";
    write_and_flush(&client, bucket).await;
    client.invalidate_all_forest_caches();

    let present = present_shard_paths(&stash, &secret, bucket);
    assert!(present.len() >= 2, "need ≥2 non-empty shards to test a single deletion; got {}", present.len());
    stash.lock().unwrap().remove(&present[0]).expect("delete one shard object");

    for (i, f) in FILES.iter().enumerate() {
        let got = client
            .get_object_flat(bucket, f)
            .await
            .unwrap_or_else(|e| panic!("get {f} after ONE shard removed: {e:?}"));
        assert_eq!(got.as_ref(), format!("payload-{}", i).as_bytes());
    }
}

/// Corrupt EXACTLY ONE dir-index shard object's bytes → the sharded read's
/// decode/decrypt of that shard fails → `Ok(None)` → rebuild. Proves that a
/// tampered shard (not just a missing one) also rebuilds rather than surfacing
/// garbage or a truncated listing.
#[tokio::test]
async fn dir_index_v8_corrupt_shard_rebuilds() {
    let (_server, stash, client, secret) = setup().await;
    let bucket = "v8-one-corrupt";
    write_and_flush(&client, bucket).await;
    client.invalidate_all_forest_caches();

    let present = present_shard_paths(&stash, &secret, bucket);
    assert!(!present.is_empty(), "expected ≥1 non-empty shard");
    // Overwrite one shard object with non-decodable garbage.
    stash
        .lock()
        .unwrap()
        .insert(present[0].clone(), vec![0xFFu8; 64]);

    for (i, f) in FILES.iter().enumerate() {
        let got = client
            .get_object_flat(bucket, f)
            .await
            .unwrap_or_else(|e| panic!("get {f} after ONE shard corrupted: {e:?}"));
        assert_eq!(got.as_ref(), format!("payload-{}", i).as_bytes());
    }
}
