//! Concurrent `put_object_flat` race tests.
//!
//! Tracks GitHub issue functionland/fula-api#16. Empirically demonstrates a
//! lost-update race in `EncryptedClient::put_object_flat` under concurrent
//! calls against the same v7/v8 sharded-HAMT bucket. The race lives in
//! `save_sharded_hamt_forest`'s "snapshot → release lock → network PUTs →
//! reconcile_flush against old snapshot" sequence — concurrent in-memory
//! upserts that land during the network round-trip get clobbered by the
//! reconcile.
//!
//! Today the race is masked by the `fula-flutter` bridge taking
//! `client.inner.write().await` around every put (forest.rs:81,167). Any
//! caller that loosens that serialization will hit the data-loss path.
//!
//! Fix landed 2026-05-22: per-bucket `tokio::sync::Mutex` in
//! `EncryptedClient` (field `bucket_write_mutex`) serializes every same-
//! bucket write path (`put_object_flat`, `put_object_flat_deferred`,
//! `flush_forest`, `delete_object_flat`, `migrate_to_sharded`,
//! `migrate_bucket_to_walkable_v8`). All 8 tests in this file now pass
//! against the fix. The v1-unreachable test stays `#[ignore]`d because
//! the v1 monolithic path is never reached in practice.
//!
//! ---
//! Naming note: the file is `v1_concurrent_put_race_tests.rs` for
//! historical reasons (initial diagnosis suspected v1 monolithic; turns
//! out v1 is auto-migrated and the real race is in v7/v8). The tests
//! themselves are v7/v8-focused.

mod common;

use common::*;
use fula_client::{EncryptedClient, EncryptionConfig};
use std::sync::Arc;

// ════════════════════════════════════════════════════════════════════════
// Helpers
// ════════════════════════════════════════════════════════════════════════

/// Build a fresh `EncryptedClient`, create `bucket`, seed it with a single
/// file, and explicitly migrate to v7 sharded-HAMT. This is the most direct
/// way to land a bucket on the racy path: it's already v7 by the time the
/// caller runs the race.
async fn fresh_v7_client(bucket: &str) -> Arc<EncryptedClient> {
    let base = spawn_server().await;
    #[allow(deprecated)]
    let encryption = EncryptionConfig::new();
    let client = Arc::new(make_client(&base, encryption));
    client.create_bucket(bucket).await.expect("create bucket");
    client
        .put_object_flat(bucket, "/seed.txt", b"seed".to_vec(), None)
        .await
        .expect("seed write");
    client
        .migrate_to_sharded(bucket)
        .await
        .expect("migrate to v7");
    assert!(
        client.is_forest_sharded_hamt(bucket),
        "test setup: bucket should be v7 sharded HAMT after migrate_to_sharded"
    );
    client
}

/// Same idea but takes the lazy-migration path: never calls
/// `migrate_to_sharded` explicitly. Instead, do a normal seed write +
/// invalidate the cache + list — which fires the lazy v1→v7 migration the
/// SDK runs on next read. Use this when we want to rule out
/// `migrate_to_sharded` itself as the cause of the race.
async fn naturally_v7_client(bucket: &str) -> Arc<EncryptedClient> {
    let base = spawn_server().await;
    #[allow(deprecated)]
    let encryption = EncryptionConfig::new();
    let client = Arc::new(make_client(&base, encryption));
    client.create_bucket(bucket).await.expect("create bucket");
    client
        .put_object_flat(bucket, "/seed.txt", b"seed".to_vec(), None)
        .await
        .expect("seed write");
    // Lazy migration trigger: invalidate then read.
    client.invalidate_forest_cache(bucket);
    let _ = client.list_directory(bucket, Some("/")).await;
    assert!(
        client.is_forest_sharded_hamt(bucket),
        "test setup: lazy migration should have produced v7 by now"
    );
    client
}

/// Spawn `n` concurrent `put_object_flat` calls writing distinct keys
/// `/race-{i:03}.txt`, await them all, assert every call returned Ok
/// (the race is silent — failures would be a different bug).
async fn race_distinct_keys(client: &Arc<EncryptedClient>, bucket: &str, n: usize) {
    let mut handles: Vec<tokio::task::JoinHandle<fula_client::Result<fula_client::PutObjectResult>>> =
        Vec::with_capacity(n);
    for i in 0..n {
        let c = client.clone();
        let bucket = bucket.to_string();
        handles.push(tokio::spawn(async move {
            let key = format!("/race-{i:03}.txt");
            let data = format!("payload-{i}").into_bytes();
            c.put_object_flat(&bucket, &key, data, None).await
        }));
    }
    for (i, h) in handles.into_iter().enumerate() {
        h.await
            .expect("join")
            .unwrap_or_else(|e| panic!("put {i} returned err: {e}"));
    }
}

/// Re-read the persisted forest from the server (bypassing any local
/// caching) and count every file the server claims to know about.
async fn count_persisted_files(client: &Arc<EncryptedClient>, bucket: &str) -> usize {
    client.invalidate_forest_cache(bucket);
    let listing = client
        .list_directory(bucket, Some("/"))
        .await
        .expect("list directory");
    listing.directories.values().map(|v| v.len()).sum()
}

// ════════════════════════════════════════════════════════════════════════
// v1 — auto-migrated; no race to test
// ════════════════════════════════════════════════════════════════════════

/// v1 monolithic buckets auto-migrate to v7 on first read (lazy migration
/// fires inside `list_directory` / `ensure_forest_loaded`). The original
/// v1 clone-mutate-reinsert race in `put_object_flat_deferred:6334-6352`
/// is therefore unreachable in steady state. Kept as an ignored
/// placeholder to document the investigation outcome.
#[tokio::test]
#[ignore = "v1 monolithic auto-migrates to v7 before any concurrent put can hit the v1 path"]
async fn test_v1_path_is_unreachable_due_to_lazy_migration() {
    // Intentionally empty — see doc.
}

// ════════════════════════════════════════════════════════════════════════
// v7/v8 sharded-HAMT — the actual race
// ════════════════════════════════════════════════════════════════════════

/// Baseline: 10 concurrent puts to distinct keys against an explicitly
/// migrated v7 bucket. All 10 must survive. Today: 9 of 10 are silently
/// lost (count=2 of expected 11).
#[tokio::test]
// Issue #16: previously `#[ignore]`'d; promoted after the per-bucket
// write-mutex fix in EncryptedClient closes the race.
async fn test_v7_concurrent_puts_distinct_keys_n10_explicit_migrate() {
    let bucket = "race-v7-distinct-n10-explicit";
    let client = fresh_v7_client(bucket).await;
    race_distinct_keys(&client, bucket, 10).await;
    let count = count_persisted_files(&client, bucket).await;
    assert_eq!(
        count,
        11, // 10 race + 1 seed
        "all 10 distinct-key puts must land in the persisted forest"
    );
}

/// Same race, but the bucket got to v7 via the lazy migration path —
/// rules out `migrate_to_sharded` itself as the trigger. If THIS fails
/// the race is definitely intrinsic to the v7 write path, not a
/// migration artifact.
#[tokio::test]
// Issue #16: previously `#[ignore]`'d; promoted after the per-bucket
// write-mutex fix. Verifies race is closed via the lazy-migration path too.
async fn test_v7_concurrent_puts_distinct_keys_n10_natural_migration() {
    let bucket = "race-v7-distinct-n10-natural";
    let client = naturally_v7_client(bucket).await;
    race_distinct_keys(&client, bucket, 10).await;
    let count = count_persisted_files(&client, bucket).await;
    assert_eq!(
        count,
        11,
        "all 10 distinct-key puts must land in the persisted forest \
         (lazy-migrated v7 bucket — proves race isn't migrate_to_sharded artifact)"
    );
}

/// Small concurrency: 2 racers. If even 2 concurrent puts collide, the
/// race is structural rather than depending on heavy contention.
#[tokio::test]
// Issue #16: previously `#[ignore]`'d; promoted after the per-bucket
// write-mutex fix in EncryptedClient closes the race.
async fn test_v7_concurrent_puts_n2() {
    let bucket = "race-v7-n2";
    let client = fresh_v7_client(bucket).await;
    race_distinct_keys(&client, bucket, 2).await;
    let count = count_persisted_files(&client, bucket).await;
    assert_eq!(count, 3, "both n=2 puts must land");
}

/// Mid concurrency: 5 racers — common upload-batch-size in real apps.
#[tokio::test]
// Issue #16: previously `#[ignore]`'d; promoted after the per-bucket
// write-mutex fix in EncryptedClient closes the race.
async fn test_v7_concurrent_puts_n5() {
    let bucket = "race-v7-n5";
    let client = fresh_v7_client(bucket).await;
    race_distinct_keys(&client, bucket, 5).await;
    let count = count_persisted_files(&client, bucket).await;
    assert_eq!(count, 6, "all n=5 puts must land");
}

/// High concurrency: 50 racers. Establishes the upper end of the test
/// matrix; if the fix solves n=50, it almost certainly solves smaller
/// configurations too. Run-time stays under a few seconds against the
/// in-memory gateway.
#[tokio::test]
// Issue #16: previously `#[ignore]`'d; promoted after the per-bucket
// write-mutex fix in EncryptedClient closes the race.
async fn test_v7_concurrent_puts_n50() {
    let bucket = "race-v7-n50";
    let client = fresh_v7_client(bucket).await;
    race_distinct_keys(&client, bucket, 50).await;
    let count = count_persisted_files(&client, bucket).await;
    assert_eq!(count, 51, "all n=50 puts must land");
}

/// Overlapping keys: 10 concurrent puts to the SAME path with different
/// payloads. The forest must end up with exactly one entry at that path
/// (idempotent-key semantics; the "last writer wins" content is allowed
/// to be any of the 10 payloads, but exactly ONE must be persisted).
/// This catches a different failure mode than distinct-key tests:
/// concurrent same-key writers can also corrupt internal page state if
/// the merge logic isn't careful.
#[tokio::test]
// Issue #16: previously `#[ignore]`'d; promoted after the per-bucket
// write-mutex fix in EncryptedClient closes the race. Overlapping-key
// concurrency.
async fn test_v7_concurrent_puts_same_key_one_winner() {
    let bucket = "race-v7-same-key";
    let client = fresh_v7_client(bucket).await;

    let key = "/contended.txt".to_string();
    let mut handles: Vec<tokio::task::JoinHandle<fula_client::Result<fula_client::PutObjectResult>>> =
        Vec::with_capacity(10);
    for i in 0..10 {
        let c = client.clone();
        let bucket = bucket.to_string();
        let key = key.clone();
        handles.push(tokio::spawn(async move {
            let data = format!("payload-{i}").into_bytes();
            c.put_object_flat(&bucket, &key, data, None).await
        }));
    }
    for (i, h) in handles.into_iter().enumerate() {
        h.await
            .expect("join")
            .unwrap_or_else(|e| panic!("put {i} returned err: {e}"));
    }

    // Exactly one entry at the contended key; the seed is still there.
    let count = count_persisted_files(&client, bucket).await;
    assert_eq!(
        count, 2,
        "1 contended-key entry + 1 seed = 2 total persisted entries"
    );

    // And readback must succeed — no corrupted entry / dangling key.
    let bytes = client
        .get_object_flat(bucket, &key)
        .await
        .expect("read back contended key");
    // The winning value must be one of the 10 payloads we wrote.
    let s = String::from_utf8(bytes.to_vec()).expect("utf-8 payload");
    assert!(
        (0..10).any(|i| s == format!("payload-{i}")),
        "readback content must be one of the 10 racing payloads, got: {s}"
    );
}

/// Mixed read-during-write: while 10 writers race, also run 5 readers
/// of the seed file. The seed read must always succeed and return the
/// correct content — the race must not corrupt reads of pre-existing
/// entries. (Today's race silently drops WRITES; this test guards
/// against a regression where the race would also corrupt READS.)
#[tokio::test]
// Issue #16: previously `#[ignore]`'d; promoted after the per-bucket
// write-mutex fix. Mixed read/write contention.
async fn test_v7_reads_during_concurrent_writes() {
    let bucket = "race-v7-mixed-rw";
    let client = fresh_v7_client(bucket).await;

    let mut write_handles: Vec<
        tokio::task::JoinHandle<fula_client::Result<fula_client::PutObjectResult>>,
    > = Vec::with_capacity(10);
    for i in 0..10 {
        let c = client.clone();
        let bucket = bucket.to_string();
        write_handles.push(tokio::spawn(async move {
            let key = format!("/race-{i:03}.txt");
            let data = format!("payload-{i}").into_bytes();
            c.put_object_flat(&bucket, &key, data, None).await
        }));
    }

    let mut read_handles: Vec<tokio::task::JoinHandle<fula_client::Result<bytes::Bytes>>> =
        Vec::with_capacity(5);
    for _ in 0..5 {
        let c = client.clone();
        let bucket = bucket.to_string();
        read_handles.push(tokio::spawn(async move {
            c.get_object_flat(&bucket, "/seed.txt").await
        }));
    }

    for (i, h) in write_handles.into_iter().enumerate() {
        h.await
            .expect("write join")
            .unwrap_or_else(|e| panic!("put {i} returned err: {e}"));
    }
    for (i, h) in read_handles.into_iter().enumerate() {
        let bytes = h
            .await
            .expect("read join")
            .unwrap_or_else(|e| panic!("read {i} returned err: {e}"));
        assert_eq!(
            bytes.as_ref(),
            b"seed",
            "seed reads must remain correct under concurrent writes"
        );
    }

    let count = count_persisted_files(&client, bucket).await;
    assert_eq!(count, 11, "all 10 writes must land alongside the seed");
}
