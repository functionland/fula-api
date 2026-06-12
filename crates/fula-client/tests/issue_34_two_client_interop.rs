//! Issue #34 — two-client interop guard for the sealed-flush fix.
//!
//! The #34 fix makes `flush_forest` write back a `Sealed` pointer state into
//! the in-memory HAMT after each successful node PUT, so flushes stop
//! re-uploading the whole ever-touched tree. This file proves the fix does
//! not change MULTI-CLIENT semantics: two clients (same user key, separate
//! devices) alternating writes against one stateful mock master that honors
//! conditional PUTs (`If-None-Match: *` / `If-Match`, 412 on mismatch —
//! exactly the master/S3 contract the production conflict arbiter relies on).
//!
//! The sequence under test is the report's exact worry — "user has two
//! clients and one writes and then the other one writes":
//!
//!   1. Client A writes 3 files via `put_object_flat` (flush per put → A's
//!      in-memory forest is fully SEALED).
//!   2. Client B (fresh instance, same secret) writes 3 files — B loads A's
//!      committed state from the master first, so its conditional flushes
//!      succeed and advance the manifest/page ETags past A's cached view.
//!   3. Client A writes a 4th file FROM ITS NOW-STALE SEALED FOREST. A's
//!      flush must hit 412 on the conditional PUT, evict its cache (sealed
//!      state discarded wholesale), reload B's winning state, replay its WAL
//!      (the 4th file's insert), and retry to success — the pre-existing
//!      NEW-7.2 reconcile protocol, with sealing now in the mix.
//!   4. After the reconcile, A can read B's writes.
//!   5. A THIRD fresh client must read all 7 files byte-exactly and list
//!      exactly 7 — nothing lost, nothing corrupted, no write clobbered.
//!
//! The test asserts the 412/backoff path actually fired (via the
//! `flush_backoff_count` metric), so a future change that accidentally makes
//! step 3 conflict-free cannot turn this into a vacuous pass.

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
// Same conditional-PUT mock as tests/dir_index_v8_wal_recovery_and_guard.rs
// (duplicated here because that file is feature-gated on test-fault-injection
// and this one intentionally runs in the default suite).

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

/// PUT that honors `If-None-Match: *` (412 if exists) and `If-Match: <etag>`
/// (412 if the stored body's CID differs) — the S3/master contract.
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
    format!("issue34-two-client-unique-payload::{name}").into_bytes()
}

#[tokio::test]
async fn two_clients_alternating_writes_compose_without_loss() {
    // Isolate the WAL/state dir from the developer machine. Both clients
    // share it (per-bucket WAL files), which is harmless for this sequential
    // alternation: every clean flush clears the bucket's WAL.
    let state = TempDir::new().expect("state dir");
    std::env::set_var("FULA_STATE_DIR", state.path());

    let (server, _stash) = start_mock().await;
    let secret = SecretKey::generate();
    let bucket = "issue34-two-client";

    let cache_a = TempDir::new().unwrap();
    let cache_b = TempDir::new().unwrap();
    let cache_c = TempDir::new().unwrap();
    let client_a = build_client(&server.uri(), &cache_a.path().join("a.redb"), secret.clone());
    let client_b = build_client(&server.uri(), &cache_b.path().join("b.redb"), secret.clone());

    // 1) Client A: three immediate-save puts. Each one flushes, so A's
    //    in-memory forest ends fully sealed.
    for name in ["a-1", "a-2", "a-3"] {
        client_a
            .put_object_flat(
                bucket,
                &format!("/docs/{name}.txt"),
                Bytes::from(body_for(name)),
                None,
            )
            .await
            .unwrap_or_else(|e| panic!("client A put {name}: {e:?}"));
    }

    // 2) Client B: loads A's committed state cold, then writes three files.
    //    B's conditional flushes advance the manifest/page ETags past A's
    //    cached (sealed) view.
    for name in ["b-1", "b-2", "b-3"] {
        client_b
            .put_object_flat(
                bucket,
                &format!("/docs/{name}.txt"),
                Bytes::from(body_for(name)),
                None,
            )
            .await
            .unwrap_or_else(|e| panic!("client B put {name}: {e:?}"));
    }

    // 3) Client A again, from its now-STALE sealed forest. The flush must
    //    412, evict the sealed state, reload B's winning state, replay the
    //    WAL insert, and retry to success.
    let backoffs_before = fula_client::flush_backoff_count();
    client_a
        .put_object_flat(
            bucket,
            "/docs/a-4.txt",
            Bytes::from(body_for("a-4")),
            None,
        )
        .await
        .expect("client A's stale-forest put must reconcile via 412-retry, not fail");
    let backoffs_after = fula_client::flush_backoff_count();
    assert!(
        backoffs_after > backoffs_before,
        "the two-client conflict must actually exercise the 412/backoff \
         reconcile path (backoff count {} -> {}); if this stops firing the \
         test has gone vacuous — investigate why A's stale ETags no longer \
         conflict",
        backoffs_before,
        backoffs_after
    );

    // 4) Post-reconcile, A's reloaded view contains B's writes.
    let b1_via_a = client_a
        .get_object_flat(bucket, "/docs/b-1.txt")
        .await
        .expect("client A must read B's write after reconcile");
    assert_eq!(b1_via_a.to_vec(), body_for("b-1"));

    // 5) A third fresh client reads EVERYTHING byte-exactly and the forest
    //    lists exactly the 7 files — no lost update, no corruption.
    let client_c = build_client(&server.uri(), &cache_c.path().join("c.redb"), secret.clone());
    for name in ["a-1", "a-2", "a-3", "a-4", "b-1", "b-2", "b-3"] {
        let got = client_c
            .get_object_flat(bucket, &format!("/docs/{name}.txt"))
            .await
            .unwrap_or_else(|e| panic!("client C get {name}: {e:?}"));
        assert_eq!(
            got.to_vec(),
            body_for(name),
            "{name} must round-trip byte-exactly through the two-client dance"
        );
    }
    let listing = client_c
        .list_files_from_forest(bucket)
        .await
        .expect("client C forest listing");
    assert_eq!(
        listing.len(),
        7,
        "forest must list exactly the 7 files written by A and B, got: {:?}",
        listing.iter().map(|f| f.original_key.clone()).collect::<Vec<_>>()
    );
}
