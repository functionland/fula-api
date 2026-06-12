//! Issue #36 — forest-cache invalidation behaviour the new fula-flutter /
//! fula-js bindings call through to.
//!
//! The encrypted client caches each bucket's forest for the CLIENT
//! LIFETIME: once loaded, `list_files_from_forest` / `get_object_flat`
//! resolve against memory and never observe another device's uploads.
//! `invalidate_forest_cache` / `invalidate_all_forest_caches` are the
//! escape hatch (drop the cached forest; next operation reloads from
//! storage) — issue #36 exposes them through the app-facing bindings.
//!
//! These tests pin the acceptance criteria from the issue at the
//! `EncryptedClient` layer (the layer both bindings delegate to):
//!
//!   1. After another client uploads to a bucket,
//!      `invalidate_forest_cache(bucket)` + `list_from_forest` on an
//!      EXISTING client returns the new file — no client rebuild.
//!   2. A dirty (unsaved local changes) forest is NOT evicted — the
//!      documented contract that makes the call safe to wire into
//!      arbitrary app refresh paths.
//!   3. `invalidate_all_forest_caches` drops every clean forest and
//!      keeps every dirty one.
//!
//! Same stateful conditional-PUT mock harness as
//! `issue_34_two_client_interop.rs` (self-contained per repo convention).

#![cfg(not(target_arch = "wasm32"))]

use bytes::Bytes;
use cid::multihash::Multihash;
use cid::Cid;
use fula_client::{Config, EncryptedClient, EncryptionConfig};
use fula_crypto::keys::SecretKey;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tempfile::TempDir;
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

// ───────────────────────────── stateful mock ────────────────────────────────

fn blake3_raw_cid(data: &[u8]) -> Cid {
    let h = blake3::hash(data);
    let mh = Multihash::<64>::wrap(0x1e, h.as_bytes()).expect("blake3 multihash wrap");
    Cid::new_v1(0x55, mh)
}

type Stash = Arc<Mutex<HashMap<String, Vec<u8>>>>;

fn header_value(req: &Request, name: &str) -> Option<String> {
    req.headers
        .iter()
        .find(|(k, _)| k.as_str().eq_ignore_ascii_case(name))
        .and_then(|(_, v)| v.to_str().ok())
        .map(|s| s.to_string())
}

struct PutResponder {
    stash: Stash,
}
impl Respond for PutResponder {
    fn respond(&self, req: &Request) -> ResponseTemplate {
        let path = req.url.path().to_string();
        let body = req.body.clone();
        let mut s = self.stash.lock().unwrap();

        if let Some(inm) = header_value(req, "If-None-Match") {
            if inm.trim() == "*" && s.contains_key(&path) {
                return ResponseTemplate::new(412);
            }
        }
        if let Some(im) = header_value(req, "If-Match") {
            let want = im.trim().trim_matches('"').to_string();
            let current = s.get(&path).map(|b| blake3_raw_cid(b).to_string());
            if current.as_deref() != Some(want.as_str()) {
                return ResponseTemplate::new(412);
            }
        }

        let cid = blake3_raw_cid(&body);
        s.insert(path, body);
        ResponseTemplate::new(200).insert_header("ETag", cid.to_string())
    }
}

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

struct HeadResponder {
    stash: Stash,
}
impl Respond for HeadResponder {
    fn respond(&self, req: &Request) -> ResponseTemplate {
        let path = req.url.path().to_string();
        match self.stash.lock().unwrap().get(&path) {
            Some(bytes) => ResponseTemplate::new(200)
                .insert_header("ETag", blake3_raw_cid(bytes).to_string())
                .insert_header("Content-Length", bytes.len().to_string()),
            None => ResponseTemplate::new(404),
        }
    }
}

async fn start_mock() -> (MockServer, Stash) {
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
        .respond_with(HeadResponder { stash: stash.clone() })
        .mount(&server)
        .await;
    (server, stash)
}

fn build_client(uri: &str, cache: &std::path::Path, secret: SecretKey) -> EncryptedClient {
    let mut config = Config::new(uri).with_token("test-jwt");
    config.walkable_v8_writer_enabled = true;
    config.block_cache_enabled = true;
    config.block_cache_path = Some(cache.to_path_buf());
    EncryptedClient::new(config, EncryptionConfig::from_secret_key(secret))
        .expect("EncryptedClient::new")
}

fn body_for(name: &str) -> Vec<u8> {
    format!("issue36-unique-payload::{name}").into_bytes()
}

/// Acceptance #1: an EXISTING long-lived client whose cached forest
/// predates another device's upload sees the new file after
/// `invalidate_forest_cache` + re-list — no client rebuild. Also pins
/// the bug premise this binding exists to escape: WITHOUT the
/// invalidate, the listing stays session-stale indefinitely.
#[tokio::test]
async fn stale_listing_refreshes_after_invalidate_without_client_rebuild() {
    let state = TempDir::new().expect("state dir");
    std::env::set_var("FULA_STATE_DIR", state.path());

    let (server, _stash) = start_mock().await;
    let secret = SecretKey::generate();
    let bucket = "issue36-stale-listing";

    let cache_a = TempDir::new().unwrap();
    let cache_b = TempDir::new().unwrap();
    let client_a = build_client(&server.uri(), &cache_a.path().join("a.redb"), secret.clone());
    let client_b = build_client(&server.uri(), &cache_b.path().join("b.redb"), secret.clone());

    // Device A writes two files; its forest is now cached in-session.
    for name in ["a-1", "a-2"] {
        client_a
            .put_object_flat(bucket, &format!("/docs/{name}.txt"), Bytes::from(body_for(name)), None)
            .await
            .unwrap_or_else(|e| panic!("client A put {name}: {e:?}"));
    }
    assert_eq!(
        client_a.list_files_from_forest(bucket).await.unwrap().len(),
        2,
        "device A baseline listing"
    );

    // Device B (another device, same user) uploads a third file.
    client_b
        .put_object_flat(bucket, "/docs/b-1.txt", Bytes::from(body_for("b-1")), None)
        .await
        .expect("client B put");

    // The bug premise (#36): device A's listing is pinned to its
    // session-cached forest and does NOT see B's upload, no matter how
    // much later it lists. If this assert ever fails, the SDK started
    // auto-revalidating and the binding's docs should be revisited.
    assert_eq!(
        client_a.list_files_from_forest(bucket).await.unwrap().len(),
        2,
        "without invalidation a long-lived session must (still) be \
         lifetime-pinned — this is the premise #36's binding escapes"
    );

    // THE FIX PATH: invalidate + re-list on the SAME client instance.
    client_a.invalidate_forest_cache(bucket);
    let listing = client_a.list_files_from_forest(bucket).await.unwrap();
    assert_eq!(
        listing.len(),
        3,
        "after invalidate_forest_cache the existing client must see the \
         cross-device upload, got: {:?}",
        listing.iter().map(|f| f.original_key.clone()).collect::<Vec<_>>()
    );

    // And the new file is fully readable through the refreshed forest.
    let got = client_a
        .get_object_flat(bucket, "/docs/b-1.txt")
        .await
        .expect("client A must download B's file after invalidate");
    assert_eq!(got.to_vec(), body_for("b-1"));
}

/// Acceptance #2: a forest carrying pending (unsaved) local changes is
/// NOT evicted — `invalidate_forest_cache` is safe to call from any app
/// refresh path without risking unflushed uploads.
#[tokio::test]
async fn dirty_forest_is_not_evicted_by_invalidate() {
    let state = TempDir::new().expect("state dir");
    std::env::set_var("FULA_STATE_DIR", state.path());

    let (server, _stash) = start_mock().await;
    let secret = SecretKey::generate();
    let bucket = "issue36-dirty-safe";

    let cache = TempDir::new().unwrap();
    let client = build_client(&server.uri(), &cache.path().join("c.redb"), secret.clone());

    // Deferred put: object uploaded, forest entry pending in memory only.
    client
        .put_object_flat_deferred(bucket, "/docs/pending.txt", Bytes::from(body_for("pending")), None)
        .await
        .expect("deferred put");
    assert!(
        client.has_pending_forest_changes(bucket).await,
        "setup: forest must be dirty before the invalidate"
    );

    // Invalidate MUST keep the dirty forest (and its pending entry).
    client.invalidate_forest_cache(bucket);
    assert!(
        client.has_pending_forest_changes(bucket).await,
        "issue #36 contract: a dirty forest is NOT evicted by \
         invalidate_forest_cache — eviction here would silently drop the \
         unsaved upload's index entry"
    );
    let listing = client.list_files_from_forest(bucket).await.unwrap();
    assert_eq!(listing.len(), 1, "pending entry must survive the invalidate");

    // Flush → clean → now invalidation takes effect, and the reloaded
    // forest still carries the (persisted) file.
    client.flush_forest(bucket).await.expect("flush");
    assert!(!client.has_pending_forest_changes(bucket).await);
    client.invalidate_forest_cache(bucket);
    let listing = client.list_files_from_forest(bucket).await.unwrap();
    assert_eq!(
        listing.len(),
        1,
        "after flush + invalidate the reloaded-from-storage forest must \
         still list the persisted file"
    );
}

/// Acceptance #3 (bulk variant): `invalidate_all_forest_caches` drops
/// every clean forest (so they refresh) and keeps every dirty one.
#[tokio::test]
async fn invalidate_all_drops_clean_forests_and_keeps_dirty_ones() {
    let state = TempDir::new().expect("state dir");
    std::env::set_var("FULA_STATE_DIR", state.path());

    let (server, _stash) = start_mock().await;
    let secret = SecretKey::generate();
    let clean_bucket = "issue36-all-clean";
    let dirty_bucket = "issue36-all-dirty";

    let cache_a = TempDir::new().unwrap();
    let cache_b = TempDir::new().unwrap();
    let client_a = build_client(&server.uri(), &cache_a.path().join("a.redb"), secret.clone());
    let client_b = build_client(&server.uri(), &cache_b.path().join("b.redb"), secret.clone());

    // clean_bucket: flushed write → clean cached forest on A.
    client_a
        .put_object_flat(clean_bucket, "/docs/clean-1.txt", Bytes::from(body_for("clean-1")), None)
        .await
        .expect("clean put");
    // dirty_bucket: deferred write → dirty cached forest on A.
    client_a
        .put_object_flat_deferred(dirty_bucket, "/docs/dirty-1.txt", Bytes::from(body_for("dirty-1")), None)
        .await
        .expect("dirty put");

    // Another device adds a second file to the CLEAN bucket.
    client_b
        .put_object_flat(clean_bucket, "/docs/clean-2.txt", Bytes::from(body_for("clean-2")), None)
        .await
        .expect("client B put");

    client_a.invalidate_all_forest_caches();

    // Clean bucket was dropped → re-list reloads and sees B's file.
    assert_eq!(
        client_a.list_files_from_forest(clean_bucket).await.unwrap().len(),
        2,
        "clean forest must have been dropped and refreshed by invalidate_all"
    );
    // Dirty bucket was kept → pending change and its entry survive.
    assert!(
        client_a.has_pending_forest_changes(dirty_bucket).await,
        "dirty forest must survive invalidate_all"
    );
    assert_eq!(
        client_a.list_files_from_forest(dirty_bucket).await.unwrap().len(),
        1,
        "dirty forest's pending entry must survive invalidate_all"
    );
}
