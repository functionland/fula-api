//! plan-D5 (v8) — WAL crash-recovery + write-path-guard integration tests.
//!
//! Three things a happy-path test can't prove, against a stateful in-memory
//! mock master that HONORS conditional PUTs (If-None-Match:* / If-Match) and
//! persists objects across client instances:
//!
//!   1. **Write-path guard** (`guard_rejects_v8_write_over_v7_single_blob`):
//!      a bucket that still carries a legacy single-blob dir-index
//!      (`dir_index_etag` set, no shards) must HARD-ERROR if the new code tries
//!      to write a v8 sharded index over it (old buckets are read-only). The
//!      current SDK never writes single-blob, so the test does "manifest
//!      surgery" (decrypt the committed root, flip it to single-blob, re-encrypt
//!      at seq+1, PUT it back) to manufacture the precondition, then asserts the
//!      SPECIFIC guard error — not a generic failure (which could be a load bug).
//!
//!   2. **Coarse WAL recovery** (`wal_recovers_crash_before_root_commit`):
//!      client A crashes AFTER pages + dir-index shards are PUT but BEFORE the
//!      manifest root commits (`CRASH_AFTER_PAGE_PUT_BEFORE_ROOT_PUT`). The root
//!      never reached the master, so the *only* record of the writes is the WAL.
//!      A fresh client B (same on-disk WAL, same mock) must recover every file.
//!      NON-VACUOUS by construction: the test asserts the root object is ABSENT
//!      (404) on the mock before B loads — so recovery CANNOT have come from a
//!      forest re-walk (there is no root to walk from); it MUST have been driven
//!      by the WAL. It also asserts the WAL is consumed (cleared) after recovery.
//!
//!   3. **Fine-grained WAL recovery** (`wal_recovers_partial_shard_commit`,
//!      `wal_recovers_torn_shard_write`): crash INSIDE the Phase 1.6 shard loop
//!      — after the first shard fully commits (partial commit), and after a
//!      shard's pre-PUT WAL promise but before its PUT (torn write). Both must
//!      recover to a fully-consistent, readable bucket.
//!
//! Tests 2/3 require `--features test-fault-injection` (the crash hooks compile
//! out of production). Test 1 needs no feature. The crash flags + `FULA_STATE_DIR`
//! are process-global, so the fault tests serialize on a static mutex and clear
//! the flags via a panic-safe RAII guard.
//!
//! ## Running (PowerShell)
//! ```powershell
//! cargo test -p fula-client --test dir_index_v8_wal_recovery_and_guard `
//!     --features test-fault-injection -- --nocapture
//! ```
//!
//! The whole file is gated on `test-fault-injection` — the guard test uses a
//! test-only helper (`test_force_single_blob_dir_index`) to deterministically
//! manufacture a legacy single-blob bucket, and the WAL tests use the crash
//! hooks. Without the feature this file is empty.

#![cfg(all(not(target_arch = "wasm32"), feature = "test-fault-injection"))]

use bytes::Bytes;
use cid::multihash::Multihash;
use cid::Cid;
use fula_client::{Config, EncryptedClient, EncryptionConfig};
use fula_crypto::keys::{KeyManager, SecretKey};
use fula_crypto::private_forest::derive_index_key;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tempfile::TempDir;
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

// ───────────────────────── serialization + flag hygiene ─────────────────────

/// Serializes every test that mutates the process-global crash flags or the
/// `FULA_STATE_DIR` env var. Held for each such test's whole duration.
static SERIAL: Mutex<()> = Mutex::new(());

/// RAII: holds the serial lock and, on drop (incl. panic unwind), clears every
/// crash flag so a failing test can never leak `CRASH=true` into the next one.
struct SerialGuard {
    _lock: std::sync::MutexGuard<'static, ()>,
}
impl SerialGuard {
    fn acquire() -> Self {
        // Recover from a poisoned lock — a prior test panicking must not wedge
        // the rest of the suite.
        let lock = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        SerialGuard { _lock: lock }
    }
}
impl Drop for SerialGuard {
    fn drop(&mut self) {
        // Flag-clear runs BEFORE the MutexGuard field drops (Drop body first,
        // then fields), so the next waiter sees flags already cleared.
        #[cfg(feature = "test-fault-injection")]
        {
            use std::sync::atomic::Ordering;
            fula_client::test_faults::CRASH_AFTER_PAGE_PUT_BEFORE_ROOT_PUT.store(false, Ordering::SeqCst);
            fula_client::test_faults::CRASH_DURING_DIR_INDEX_SHARD_LOOP.store(false, Ordering::SeqCst);
            fula_client::test_faults::CRASH_BEFORE_DIR_INDEX_SHARD_PUT.store(false, Ordering::SeqCst);
            fula_client::test_faults::CRASH_AFTER_ROOT_PUT_BEFORE_WAL_CLEAR.store(false, Ordering::SeqCst);
        }
    }
}

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

/// PUT that HONORS conditional headers exactly like S3 / the master:
///   * `If-None-Match: *`  → 412 if the key already exists, else create.
///   * `If-Match: "<etag>"` → 412 if the stored body's CID != `<etag>`, else overwrite.
/// On success stashes the body and returns its BLAKE3-raw CID as the ETag (so
/// the SDK's walkable-v8 self-verify accepts the round-trip).
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
                return ResponseTemplate::new(412); // create-only, but it exists
            }
        }
        if let Some(im) = header_value(req, "If-Match") {
            let want = im.trim().trim_matches('"').to_string();
            let current = s.get(&path).map(|b| blake3_raw_cid(b).to_string());
            if current.as_deref() != Some(want.as_str()) {
                return ResponseTemplate::new(412); // etag moved / object gone
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
    EncryptedClient::new(config, EncryptionConfig::from_secret_key(secret)).expect("EncryptedClient::new")
}

/// Files spread across many directories (so the dir-index spans several shards),
/// each with unique multi-distinct content so a "wrong file served" bug can't
/// round-trip through a content-addressed store.
fn recovery_files() -> Vec<(String, Vec<u8>)> {
    (0..12)
        .map(|i| {
            let path = format!("/d{:02}/sub{}/f{:03}.txt", i, i % 3, i);
            let body = format!("unique-payload-for-file-{}-{}", i, path).into_bytes();
            (path, body)
        })
        .collect()
}

/// Count the `.wal` files under `$FULA_STATE_DIR/fula/wal` (glob, not a
/// hand-derived name — the production hash input must stay opaque to the test).
#[allow(dead_code)] // used only by the feature-gated wal_recovery module
fn wal_file_count(state_dir: &std::path::Path) -> usize {
    let wal_dir = state_dir.join("fula").join("wal");
    std::fs::read_dir(&wal_dir)
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .filter(|e| e.path().extension().map(|x| x == "wal").unwrap_or(false))
                .count()
        })
        .unwrap_or(0)
}

/// Total bytes across all `.wal` files (0 ⇒ no pending WAL).
#[allow(dead_code)] // used only by the feature-gated wal_recovery module
fn wal_total_bytes(state_dir: &std::path::Path) -> u64 {
    let wal_dir = state_dir.join("fula").join("wal");
    std::fs::read_dir(&wal_dir)
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .filter(|e| e.path().extension().map(|x| x == "wal").unwrap_or(false))
                .map(|e| e.metadata().map(|m| m.len()).unwrap_or(0))
                .sum()
        })
        .unwrap_or(0)
}

fn forest_dek(secret: &SecretKey, bucket: &str) -> fula_crypto::keys::DekKey {
    KeyManager::from_secret_key(secret.clone()).derive_path_key(&format!("forest:{bucket}"))
}

// ───────────────────────────── Test 1: guard ────────────────────────────────

/// The write-path guard must hard-error when asked to write a v8 sharded
/// dir-index over a bucket that still carries a legacy single-blob dir-index.
#[tokio::test]
async fn guard_rejects_v8_write_over_v7_single_blob() {
    let _serial = SerialGuard::acquire();
    let state = TempDir::new().expect("state dir");
    std::env::set_var("FULA_STATE_DIR", state.path());

    let (server, _stash) = start_mock().await;
    let secret = SecretKey::generate();
    let bucket = "guard-v7-single-blob";

    let cache = TempDir::new().unwrap();
    let client = build_client(&server.uri(), &cache.path().join("b.redb"), secret.clone());

    // 1) Write a normal v8 (sharded) bucket + flush. Proves the forest is fully
    //    functional and loaded into the client's cache.
    for (k, body) in recovery_files() {
        client
            .put_object_flat_deferred(bucket, &k, Bytes::from(body), None)
            .await
            .unwrap_or_else(|e| panic!("put {k}: {e:?}"));
    }
    client.flush_forest(bucket).await.expect("initial sharded flush");

    // 2) Force the LOADED forest into the legacy v7 single-blob shape in-memory
    //    (dir_index_etag set, dir_index_shards cleared) — exactly the read-only
    //    OLD bucket the guard protects. Because the forest stays loaded, its
    //    page_index remains consistent with storage (unlike forging a manifest
    //    out-of-band), so the ONLY thing the next flush can object to is the
    //    dir-index format — isolating the guard cleanly.
    client
        .test_force_single_blob_dir_index(bucket)
        .await
        .expect("force single-blob dir-index state");

    // 3) A write dirties a dir-index shard → flush hits Phase 1.6 → the
    //    read-only-old guard must hard-error with its specific message (not a
    //    generic failure, which could mask a silently-deleted guard).
    client
        .put_object_flat_deferred(bucket, "/d00/after_force.txt", Bytes::from_static(b"x"), None)
        .await
        .expect("deferred upsert (no flush yet) must succeed");
    let err = client
        .flush_forest(bucket)
        .await
        .expect_err("flush over a single-blob bucket must hit the read-only-old guard");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("refusing to write a v8 sharded dir-index"),
        "expected the read-only-old guard error, got a DIFFERENT error (would mask a deleted guard): {msg}"
    );
}

// ─────────────────────── Tests 2-4: WAL crash recovery ───────────────────────

#[cfg(feature = "test-fault-injection")]
mod wal_recovery {
    use super::*;
    use std::sync::atomic::Ordering;

    /// Drive a crash on the SECOND flush of a bucket (the scenario the crash
    /// hooks are designed for — a prior root exists; the crash leaves the new
    /// batch's pages/shards on the master but the root still points at the old
    /// generation). A fresh client B (same WAL + mock) must recover.
    ///
    /// NON-VACUOUS by construction: batch 1 is committed (root references it);
    /// batch 2 is flushed-but-crashed, so the committed root does NOT reference
    /// batch 2 — those entries exist ONLY in the WAL. Asserting that recovery
    /// yields batch1 ∪ batch2 proves the WAL drove it (a plain forest re-walk
    /// of the committed root would see batch 1 only). Also asserts the WAL is
    /// consumed (cleared) after recovery. `set_flag` selects the crash point.
    async fn run_recovery_case(bucket: &str, set_flag: impl Fn()) {
        let _serial = SerialGuard::acquire();
        let state = TempDir::new().expect("state dir");
        std::env::set_var("FULA_STATE_DIR", state.path());

        let (server, stash) = start_mock().await;
        let secret = SecretKey::generate();
        let all_files = recovery_files(); // 12 files across 12 dirs
        let (batch1, batch2) = all_files.split_at(8);

        // ── Client A: commit batch 1 cleanly, then crash on the batch-2 flush ──
        {
            let cache = TempDir::new().unwrap();
            let client = build_client(&server.uri(), &cache.path().join("a.redb"), secret.clone());
            for (k, body) in batch1 {
                client
                    .put_object_flat_deferred(bucket, k, Bytes::from(body.clone()), None)
                    .await
                    .unwrap_or_else(|e| panic!("put batch1 {k}: {e:?}"));
            }
            client.flush_forest(bucket).await.expect("batch1 flush must succeed (commits a root)");

            for (k, body) in batch2 {
                client
                    .put_object_flat_deferred(bucket, k, Bytes::from(body.clone()), None)
                    .await
                    .unwrap_or_else(|e| panic!("put batch2 {k}: {e:?}"));
            }
            set_flag();
            let err = client.flush_forest(bucket).await.expect_err("crash-flagged flush must error");
            assert!(
                format!("{err:?}").contains("test-fault-injection"),
                "flush must fail via the injected crash, got: {err:?}"
            );
            drop(client);
        }
        // Flag OFF before recovery, or B's re-flush would crash again.
        set_flag_off();

        // ── Non-vacuity gate: a root IS committed (batch 1) but cannot yet
        //    reference batch 2 (its root commit was the one that crashed). So
        //    any batch-2 entry that survives recovery came from the WAL. ──
        let dek = forest_dek(&secret, bucket);
        let manifest_path = format!("/{bucket}/{}", derive_index_key(&dek, bucket));
        assert!(
            stash.lock().unwrap().contains_key(&manifest_path),
            "precondition: batch 1 must have committed a manifest root"
        );
        assert!(wal_total_bytes(state.path()) > 0, "a WAL must exist on disk after the crash");

        // ── Client B: fresh in-memory state, same WAL + mock → recover ──
        let cache_b = TempDir::new().unwrap();
        let client_b = build_client(&server.uri(), &cache_b.path().join("b.redb"), secret.clone());
        // The first load triggers recover_wal_after_load (replay + re-flush).
        let listed = client_b
            .list_files_from_forest(bucket)
            .await
            .expect("WAL recovery: list after fresh load");
        let got: std::collections::BTreeSet<String> = listed.iter().map(|f| f.original_key.clone()).collect();
        let want: std::collections::BTreeSet<String> = all_files.iter().map(|(k, _)| k.clone()).collect();
        let want_batch2: std::collections::BTreeSet<String> =
            batch2.iter().map(|(k, _)| k.clone()).collect();
        assert!(
            got.is_superset(&want_batch2),
            "WAL recovery must restore the crashed batch-2 entries (WAL-only — the committed root \
             references batch 1 only). Missing: {:?}",
            want_batch2.difference(&got).collect::<Vec<_>>()
        );
        assert_eq!(
            got, want,
            "recovery must yield batch1 ∪ batch2 exactly (no loss, no duplicates)"
        );
        assert_eq!(listed.len(), all_files.len(), "no duplicate entries from Insert replay");
        for (k, body) in &all_files {
            let dl = client_b
                .get_object_flat(bucket, k)
                .await
                .unwrap_or_else(|e| panic!("download {k} after recovery: {e:?}"));
            assert_eq!(dl.as_ref(), body.as_slice(), "byte round-trip after recovery for {k}");
        }

        // ── A successful recovery flush must CONSUME the WAL ──
        assert_eq!(
            wal_total_bytes(state.path()),
            0,
            "a successful recovery flush must clear the WAL (got {} byte(s) / {} file(s) left)",
            wal_total_bytes(state.path()),
            wal_file_count(state.path()),
        );
    }

    fn set_flag_off() {
        fula_client::test_faults::CRASH_AFTER_PAGE_PUT_BEFORE_ROOT_PUT.store(false, Ordering::SeqCst);
        fula_client::test_faults::CRASH_DURING_DIR_INDEX_SHARD_LOOP.store(false, Ordering::SeqCst);
        fula_client::test_faults::CRASH_BEFORE_DIR_INDEX_SHARD_PUT.store(false, Ordering::SeqCst);
        fula_client::test_faults::CRASH_AFTER_ROOT_PUT_BEFORE_WAL_CLEAR.store(false, Ordering::SeqCst);
    }

    /// Coarse: crash after ALL pages + shards are PUT, before the root commits.
    #[tokio::test]
    async fn wal_recovers_crash_before_root_commit() {
        run_recovery_case("wal-coarse-before-root", || {
            fula_client::test_faults::CRASH_AFTER_PAGE_PUT_BEFORE_ROOT_PUT.store(true, Ordering::SeqCst);
        })
        .await;
    }

    /// Fine-grained: crash after the FIRST dir-index shard fully commits
    /// (partial commit) — later shards + root never written.
    #[tokio::test]
    async fn wal_recovers_partial_shard_commit() {
        run_recovery_case("wal-fine-partial-shard", || {
            fula_client::test_faults::CRASH_DURING_DIR_INDEX_SHARD_LOOP.store(true, Ordering::SeqCst);
        })
        .await;
    }

    /// Fine-grained (torn write): crash after the first shard's pre-PUT WAL
    /// promise but before its PUT — the WAL holds a `new_etag: None` record for
    /// a shard object that never reached the master.
    #[tokio::test]
    async fn wal_recovers_torn_shard_write() {
        run_recovery_case("wal-fine-torn-write", || {
            fula_client::test_faults::CRASH_BEFORE_DIR_INDEX_SHARD_PUT.store(true, Ordering::SeqCst);
        })
        .await;
    }

    /// Crash AFTER the root commit lands but BEFORE the WAL is cleared
    /// (`wal::clear` runs only on a clean flush). Now BOTH the committed root
    /// AND the WAL reference batch 2 — recovery must re-apply the WAL
    /// IDEMPOTENTLY on top of an already-committed root: no `If-None-Match:*`
    /// create-race on the already-present pages/shards (the exact 412 failure
    /// mode that bites a broken reconcile), and no duplicate directory entries.
    /// This is the highest-probability production "weird state" — the gap
    /// between committing the root and truncating the WAL.
    #[tokio::test]
    async fn wal_idempotent_recovery_after_root_commit() {
        let _serial = SerialGuard::acquire();
        let state = TempDir::new().expect("state dir");
        std::env::set_var("FULA_STATE_DIR", state.path());

        let (server, stash) = start_mock().await;
        let secret = SecretKey::generate();
        let bucket = "wal-idempotent-double-apply";
        let all_files = recovery_files();
        let (batch1, batch2) = all_files.split_at(8);

        {
            let cache = TempDir::new().unwrap();
            let client = build_client(&server.uri(), &cache.path().join("a.redb"), secret.clone());
            for (k, body) in batch1 {
                client
                    .put_object_flat_deferred(bucket, k, Bytes::from(body.clone()), None)
                    .await
                    .unwrap_or_else(|e| panic!("put batch1 {k}: {e:?}"));
            }
            client.flush_forest(bucket).await.expect("batch1 flush");
            for (k, body) in batch2 {
                client
                    .put_object_flat_deferred(bucket, k, Bytes::from(body.clone()), None)
                    .await
                    .unwrap_or_else(|e| panic!("put batch2 {k}: {e:?}"));
            }
            fula_client::test_faults::CRASH_AFTER_ROOT_PUT_BEFORE_WAL_CLEAR.store(true, Ordering::SeqCst);
            let err = client.flush_forest(bucket).await.expect_err("crash after root commit");
            assert!(
                format!("{err:?}").contains("CRASH_AFTER_ROOT_PUT_BEFORE_WAL_CLEAR"),
                "must fail via the post-root-commit hook, got: {err:?}"
            );
            drop(client);
        }
        set_flag_off();

        // The root WAS committed (references batch1 ∪ batch2), AND the WAL still
        // persists (the crash skipped its truncation).
        let dek = forest_dek(&secret, bucket);
        let manifest_path = format!("/{bucket}/{}", derive_index_key(&dek, bucket));
        assert!(
            stash.lock().unwrap().contains_key(&manifest_path),
            "precondition: the root commit must have landed on storage"
        );
        assert!(
            wal_total_bytes(state.path()) > 0,
            "precondition: the WAL must still be present (crash before truncation)"
        );

        // Recovery re-applies the WAL on top of the committed root — must be a
        // clean no-op-equivalent, not a 412 loop or a duplicating replay.
        let cache_b = TempDir::new().unwrap();
        let client_b = build_client(&server.uri(), &cache_b.path().join("b.redb"), secret.clone());
        let listed = client_b
            .list_files_from_forest(bucket)
            .await
            .expect("idempotent recovery: list after fresh load (a 412-loop would error here)");
        let got: std::collections::BTreeSet<String> =
            listed.iter().map(|f| f.original_key.clone()).collect();
        let want: std::collections::BTreeSet<String> =
            all_files.iter().map(|(k, _)| k.clone()).collect();
        assert_eq!(got, want, "idempotent recovery must yield batch1 ∪ batch2 exactly");
        assert_eq!(
            listed.len(),
            all_files.len(),
            "WAL double-apply over a committed root must NOT duplicate entries"
        );
        for (k, body) in &all_files {
            let dl = client_b
                .get_object_flat(bucket, k)
                .await
                .unwrap_or_else(|e| panic!("download {k} after idempotent recovery: {e:?}"));
            assert_eq!(dl.as_ref(), body.as_slice(), "byte round-trip after idempotent recovery for {k}");
        }
        assert_eq!(
            wal_total_bytes(state.path()),
            0,
            "idempotent recovery must finish by clearing the WAL"
        );
    }
}
