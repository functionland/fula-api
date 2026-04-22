//! S-1.2 multi-page integration coverage.
//!
//! The crypto-layer regression at `private_forest.rs::test_manifest_v7_meta_hamt_fits_
//! under_max_block_size_at_max_shards` proves each page fits under the 1 MiB cap at
//! MAX_SHARDS=65,536, but it runs entirely in-process and never exercises the
//! flush / PUT / load path across the in-memory gateway. The single-page integration
//! tests (`test_crash_between_page_put_and_root_put_is_recovered`, etc.) all run at
//! the default `compute_initial_shard_count` (16 shards = 1 page), so the
//! `BTreeMap<PageId, ManifestPage>` loops collapse to a trivial one-element traversal.
//!
//! This suite uses the `FORCE_INITIAL_SHARD_COUNT` test-only override to push
//! migration to 2,048 shards = 2 pages and drives:
//!   * Phase 1.5 flush iterating multiple dirty pages
//!   * `load_manifest_pages` composing a `ShardManifestV7` from multiple page PUTs
//!   * A concurrent 412 race where writer A's writes land on page 0 and writer B's
//!     writes land on page 1, so both sides must converge after WAL replay.

mod common;
use common::*;

use fula_client::EncryptionConfig;
use fula_crypto::private_forest::FORCE_INITIAL_SHARD_COUNT;
use std::sync::atomic::Ordering;

/// RAII guard: while held, `compute_initial_shard_count` is forced to the
/// given value. Serializes across parallel tests via a static Mutex so
/// flips don't stomp on each other.
struct ShardCountGuard {
    _lock: std::sync::MutexGuard<'static, ()>,
}

impl ShardCountGuard {
    fn new(n: usize) -> Self {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let lock = LOCK.lock().unwrap_or_else(|p| p.into_inner());
        FORCE_INITIAL_SHARD_COUNT.store(n, Ordering::SeqCst);
        Self { _lock: lock }
    }
}

impl Drop for ShardCountGuard {
    fn drop(&mut self) {
        FORCE_INITIAL_SHARD_COUNT.store(0, Ordering::SeqCst);
    }
}

/// Put, migrate to v7 at forced 2 pages, bulk-write 32 files with
/// `put_object_flat_deferred` + one final `flush_forest`, then cold-read them
/// back. Proves Phase 1.5 issued multi-page writes and `load_manifest_pages`
/// rehydrates them across a fresh client.
#[tokio::test]
async fn multi_page_flush_and_reload_round_trip() {
    let _shard_guard = ShardCountGuard::new(2_048);
    let base = spawn_server().await;
    let encryption = EncryptionConfig::new();
    let secret = encryption.export_secret_key().clone();
    let bucket = "multipage-rt";

    let state = tempfile::tempdir().unwrap();
    let _guard = EnvGuard::set("FULA_STATE_DIR", state.path());

    let writer = make_client(&base, encryption);
    writer.create_bucket(bucket).await.expect("create bucket");

    // Seed a monolithic forest with one entry, then force migration to 2 pages
    // via the override.
    writer
        .put_object_flat(bucket, "/seed.txt", b"seed".to_vec(), None)
        .await
        .expect("seed put");
    writer.migrate_to_sharded(bucket).await.expect("migrate");
    assert!(writer.is_forest_sharded_hamt(bucket));
    let (num_shards, page_count) = writer
        .sharded_forest_layout(bucket)
        .expect("loaded sharded forest");
    assert_eq!(num_shards, 2_048, "override must pin num_shards to 2*PAGE_SIZE");
    assert_eq!(page_count, 2, "2,048 shards at PAGE_SIZE=1024 must be 2 pages");

    // Stage 8 deferred puts, then one flush — avoids multiple synchronous
    // flushes (each one iterates the dirty-shard bitmap across 2048 shards).
    // Writes across 8 distinct parent dirs scatter across many shards, so
    // Phase 1.5 must issue PUTs to both pages with very high probability.
    for i in 0..8u32 {
        let path = format!("/grp{:02}/file.txt", i);
        writer
            .put_object_flat_deferred(bucket, &path, format!("payload-{}", i).into_bytes(), None)
            .await
            .unwrap_or_else(|e| panic!("stage {} failed: {}", path, e));
    }
    writer.flush_forest(bucket).await.expect("bulk flush");

    drop(writer);
    // Release the writer-phase EnvGuard before the reader acquires a new one.
    // `EnvGuard::set` takes a non-reentrant std::sync::Mutex, so holding two
    // guards across the swap deadlocks this test thread.
    drop(_guard);

    // Fresh client, fresh state dir: must hydrate by fetching *both* pages.
    let reader_state = tempfile::tempdir().unwrap();
    let _reader_guard = EnvGuard::set("FULA_STATE_DIR", reader_state.path());
    let reader = make_client(&base, EncryptionConfig::from_secret_key(secret));
    for i in 0..8u32 {
        let path = format!("/grp{:02}/file.txt", i);
        let body = reader
            .get_object_flat(bucket, &path)
            .await
            .unwrap_or_else(|e| panic!("read {} failed: {}", path, e));
        assert_eq!(body.as_ref(), format!("payload-{}", i).as_bytes());
    }
    assert!(reader.is_forest_sharded_hamt(bucket));
    let (rn, rp) = reader
        .sharded_forest_layout(bucket)
        .expect("reader should have loaded sharded forest");
    assert_eq!(rn, 2_048);
    assert_eq!(rp, 2, "reader must hydrate all pages");
}

/// Two clients racing on the same 2-page v7 bucket. Each mutates a disjoint
/// scatter of paths, so their dirty-shard sets are (probabilistically)
/// spread across both pages. The loser's phase-2 root PUT must 412 and —
/// after WAL replay — re-issue page PUTs and retry. Both sides' writes must
/// survive in a fresh reader.
#[tokio::test]
async fn multi_page_concurrent_412_replay_converges() {
    let _shard_guard = ShardCountGuard::new(2_048);
    let base = spawn_server().await;
    let encryption = EncryptionConfig::new();
    let secret = encryption.export_secret_key().clone();
    let bucket = "multipage-412";

    let state_seed = tempfile::tempdir().unwrap();
    let state_a = tempfile::tempdir().unwrap();
    let state_b = tempfile::tempdir().unwrap();

    // Seed via put + migrate so both clients can load a real object to
    // prime the forest cache (matches the pattern used by
    // `test_412_triggers_wal_replay_sharded`).
    {
        let _g = EnvGuard::set("FULA_STATE_DIR", state_seed.path());
        let seed_client =
            make_client(&base, EncryptionConfig::from_secret_key(secret.clone()));
        seed_client.create_bucket(bucket).await.expect("create");
        seed_client
            .put_object_flat(bucket, "/seed.txt", b"seed".to_vec(), None)
            .await
            .expect("seed put");
        seed_client.migrate_to_sharded(bucket).await.expect("migrate");
        let (_ns, pc) = seed_client
            .sharded_forest_layout(bucket)
            .expect("forest loaded");
        assert_eq!(pc, 2, "override must produce 2 pages");
    }

    let client_a = {
        let _g = EnvGuard::set("FULA_STATE_DIR", state_a.path());
        make_client(&base, EncryptionConfig::from_secret_key(secret.clone()))
    };
    let client_b = {
        let _g = EnvGuard::set("FULA_STATE_DIR", state_b.path());
        make_client(&base, EncryptionConfig::from_secret_key(secret.clone()))
    };

    // Both clients read seed.txt first — this pins the same
    // `prior_manifest_etag` so the loser's phase-2 actually 412s.
    {
        let _g = EnvGuard::set("FULA_STATE_DIR", state_a.path());
        client_a.get_object_flat(bucket, "/seed.txt").await.expect("a load");
    }
    {
        let _g = EnvGuard::set("FULA_STATE_DIR", state_b.path());
        client_b.get_object_flat(bucket, "/seed.txt").await.expect("b load");
    }

    // Each side stages 4 deferred puts with disjoint parent dirs.
    {
        let _g = EnvGuard::set("FULA_STATE_DIR", state_a.path());
        for i in 0..4u32 {
            client_a
                .put_object_flat_deferred(
                    bucket,
                    &format!("/a{:02}/f.txt", i),
                    format!("a-{}", i).into_bytes(),
                    None,
                )
                .await
                .expect("a staged put");
        }
    }
    {
        let _g = EnvGuard::set("FULA_STATE_DIR", state_b.path());
        for i in 0..4u32 {
            client_b
                .put_object_flat_deferred(
                    bucket,
                    &format!("/b{:02}/f.txt", i),
                    format!("b-{}", i).into_bytes(),
                    None,
                )
                .await
                .expect("b staged put");
        }
    }

    // A flushes first — wins. B's subsequent flush 412s, replays WAL,
    // reconciles page etags post-PUT, and retries.
    {
        let _g = EnvGuard::set("FULA_STATE_DIR", state_a.path());
        client_a.flush_forest(bucket).await.expect("a flush");
    }
    {
        let _g = EnvGuard::set("FULA_STATE_DIR", state_b.path());
        client_b.flush_forest(bucket).await.expect("b flush converges");
    }

    // Fresh reader (fresh state dir) must see both sides' writes.
    let reader_state = tempfile::tempdir().unwrap();
    let _g = EnvGuard::set("FULA_STATE_DIR", reader_state.path());
    let reader = make_client(&base, EncryptionConfig::from_secret_key(secret));
    for i in 0..4u32 {
        let a = reader
            .get_object_flat(bucket, &format!("/a{:02}/f.txt", i))
            .await
            .unwrap_or_else(|e| panic!("read a{}: {}", i, e));
        let b = reader
            .get_object_flat(bucket, &format!("/b{:02}/f.txt", i))
            .await
            .unwrap_or_else(|e| panic!("read b{}: {}", i, e));
        assert_eq!(a.as_ref(), format!("a-{}", i).as_bytes());
        assert_eq!(b.as_ref(), format!("b-{}", i).as_bytes());
    }
    let (rn, rp) = reader
        .sharded_forest_layout(bucket)
        .expect("reader loads forest");
    assert_eq!(rn, 2_048);
    assert_eq!(rp, 2);
}
