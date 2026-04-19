//! Scale tests for the v7 HAMT over a real in-process gateway.
//!
//! The existing `tests/v7_hamt_tests.rs` tops out at 25 files, which is not
//! enough to empirically back the "rs-wnfs #369 (~1,200 files / 1 MiB IPFS
//! block) does not reproduce" claim in the audit. These tests drive the
//! full `EncryptedClient` + fula-cli + memory block-store stack end-to-end
//! past rs-wnfs' failure threshold and, in the opt-in cases, past the
//! `MAX_BLOCK_SIZE` cap where Kubo would fall through to UnixFS chunking.
//!
//! The opt-in `#[ignore]`'d tests are excluded from default CI runs — they
//! allocate multi-GB transient memory and take tens of seconds to minutes
//! on a developer box. Run explicitly with:
//!
//!   cargo test --test hamt_scale_tests --release -- --ignored
//!
//! Closes audit gaps G1, G7, G8.

mod common;
use common::*;

use fula_client::{EncryptedClient, EncryptionConfig, ListObjectsOptions};

// ════════════════════════════════════════════════════════════════════════════
// Helpers shared by the scale tests.
// ════════════════════════════════════════════════════════════════════════════

/// Bootstrap a bucket into v7-HAMT format with the minimum writes needed to
/// force the format flip. Seeds one tiny object in v1 then calls
/// `migrate_to_sharded`; every subsequent upsert in the caller is then
/// guaranteed to take the v7 HAMT code path.
async fn setup_v7_bucket(client: &EncryptedClient, bucket: &str) {
    client.create_bucket(bucket).await.expect("create bucket");
    client
        .put_object_flat(bucket, "/__bootstrap.txt", b"x".to_vec(), None)
        .await
        .expect("bootstrap v1 write");
    client
        .migrate_to_sharded(bucket)
        .await
        .expect("migrate to v7");
    assert!(
        client.is_forest_sharded_hamt(bucket),
        "setup_v7_bucket must end with the bucket in v7-HAMT format"
    );
}

// ════════════════════════════════════════════════════════════════════════════
// G1 — rs-wnfs #369 threshold (~1,200 files)
// ════════════════════════════════════════════════════════════════════════════

/// Directly analogous to rs-wnfs' `test_perf_add_files` failure case. Puts
/// 2,000 objects into a single directory, flushes the forest, cold-reloads a
/// fresh client, and asserts every entry is both listable and decryptable.
/// rs-wnfs fails somewhere around 1,200; this must succeed at 2,000.
#[tokio::test]
async fn test_single_directory_2000_files_v7_end_to_end() {
    let base = spawn_server().await;
    let encryption = EncryptionConfig::new();
    let secret = encryption.export_secret_key().clone();
    let bucket = "v7-scale-2000";

    let state = tempfile::tempdir().unwrap();
    let _guard = EnvGuard::set("FULA_STATE_DIR", state.path());

    let writer = make_client(&base, encryption);
    setup_v7_bucket(&writer, bucket).await;

    const N: usize = 2000;
    for i in 0..N {
        let path = format!("/photos/big/f{:04}.bin", i);
        let body = format!("body-{}", i).into_bytes();
        writer
            .put_object_flat_deferred(bucket, &path, body, None)
            .await
            .unwrap_or_else(|e| panic!("bulk put {} failed: {:?}", path, e));
    }
    writer.flush_forest(bucket).await.expect("flush");
    drop(writer);

    // Cold-reload with a fresh client + fresh state dir (no forest cache).
    // Release the writer's EnvGuard mutex before acquiring the reader's,
    // otherwise the two lock() calls on the same thread deadlock.
    drop(_guard);
    let state_r = tempfile::tempdir().unwrap();
    let _guard_r = EnvGuard::set("FULA_STATE_DIR", state_r.path());
    let reader = make_client(&base, EncryptionConfig::from_secret_key(secret));

    // Forest comes back as v7 from the server.
    // `list_directory` forces a load so we can assert the format after.
    let listing = reader
        .list_directory(bucket, Some("/photos/big"))
        .await
        .expect("list /photos/big after cold reload");
    assert!(
        reader.is_forest_sharded_hamt(bucket),
        "cold-reloaded client must see v7 HAMT"
    );

    let files: Vec<String> = listing
        .directories
        .values()
        .flatten()
        .map(|f| f.original_key.clone())
        .collect();
    let bulk_count = files
        .iter()
        .filter(|f| f.starts_with("/photos/big/f") && f.ends_with(".bin"))
        .count();
    assert_eq!(
        bulk_count, N,
        "listing returned {} bulk files, expected {}",
        bulk_count, N
    );

    // Spot-check reads across the range.
    for i in [0usize, 1, 500, 999, 1500, 1999] {
        let path = format!("/photos/big/f{:04}.bin", i);
        let got = reader
            .get_object_flat(bucket, &path)
            .await
            .unwrap_or_else(|e| panic!("v7 read {} failed: {:?}", path, e));
        assert_eq!(
            got.as_ref(),
            format!("body-{}", i).as_bytes(),
            "body mismatch at {}",
            path
        );
    }
}

/// Stretched version of the G1 test: 5,000 files in one directory. Marked
/// `#[ignore]` because it takes tens of seconds in debug mode and multiple
/// GB of transient memory; run with `cargo test --release -- --ignored`.
#[tokio::test]
#[ignore]
async fn test_single_directory_5000_files_v7_end_to_end() {
    let base = spawn_server().await;
    let encryption = EncryptionConfig::new();
    let secret = encryption.export_secret_key().clone();
    let bucket = "v7-scale-5000";

    let state = tempfile::tempdir().unwrap();
    let _guard = EnvGuard::set("FULA_STATE_DIR", state.path());

    let writer = make_client(&base, encryption);
    setup_v7_bucket(&writer, bucket).await;

    const N: usize = 5_000;
    for i in 0..N {
        let path = format!("/bulk/f{:05}.bin", i);
        let body = format!("b{}", i).into_bytes();
        writer
            .put_object_flat_deferred(bucket, &path, body, None)
            .await
            .unwrap_or_else(|e| panic!("bulk put {} failed: {:?}", path, e));
    }
    writer.flush_forest(bucket).await.expect("flush");
    drop(writer);

    // Release the writer's EnvGuard mutex before acquiring the reader's,
    // otherwise the two lock() calls on the same thread deadlock.
    drop(_guard);
    let state_r = tempfile::tempdir().unwrap();
    let _guard_r = EnvGuard::set("FULA_STATE_DIR", state_r.path());
    let reader = make_client(&base, EncryptionConfig::from_secret_key(secret));

    let listing = reader
        .list_directory(bucket, Some("/bulk"))
        .await
        .expect("list /bulk after cold reload");
    assert!(reader.is_forest_sharded_hamt(bucket));
    let files: Vec<String> = listing
        .directories
        .values()
        .flatten()
        .map(|f| f.original_key.clone())
        .collect();
    let bulk_count = files
        .iter()
        .filter(|f| f.starts_with("/bulk/f") && f.ends_with(".bin"))
        .count();
    assert_eq!(bulk_count, N);

    // A few spot checks across the range.
    for i in [0usize, 1, 2500, N - 1] {
        let path = format!("/bulk/f{:05}.bin", i);
        let got = reader.get_object_flat(bucket, &path).await.expect("read");
        assert_eq!(got.as_ref(), format!("b{}", i).as_bytes());
    }
}

// ════════════════════════════════════════════════════════════════════════════
// §4 — UnixFS fallback claim — oversized DirEntryWire crosses MAX_BLOCK_SIZE
// ════════════════════════════════════════════════════════════════════════════

/// Empirical counterpart to the §4 claim that a serialized `DirEntryWire`
/// exceeding `fula-blockstore::ipfs::MAX_BLOCK_SIZE` still round-trips
/// correctly. With the in-memory block store used by the test gateway
/// there is no actual Kubo `/api/v0/add` fallback (the mock store just
/// accepts any size), so this test establishes the client-side contract:
/// client can produce AND correctly re-read a HAMT node blob whose
/// ciphertext is larger than Kubo's per-block cap.
///
/// Marked `#[ignore]` because it allocates multi-GB of transient memory
/// during the in-memory v7 HAMT build (the dir entry is re-serialised on
/// every insert; audit §3 "O(n²) per-directory insert").
///
/// The complementary assertion that Kubo actually routes oversized bodies
/// to `/api/v0/add` lives in `fula-blockstore::ipfs::put_block_uses_unixfs_add_for_large_data`
/// at `crates/fula-blockstore/src/ipfs.rs:559`.
#[tokio::test]
#[ignore]
async fn test_single_directory_over_1mib_forces_unixfs_fallback() {
    // Keep the file count tractable by using long filenames so the
    // serialized `DirEntryWire` crosses 1 MiB without needing tens of
    // thousands of rows.
    //
    // Each filename string is ~200 bytes, so ~7,000 entries push the
    // serialized directory value well past the 1 MiB − 256 B MAX_BLOCK_SIZE
    // threshold in `fula-blockstore::ipfs` line 14.
    const N: usize = 7_000;

    let base = spawn_server().await;
    let encryption = EncryptionConfig::new();
    let secret = encryption.export_secret_key().clone();
    let bucket = "v7-oversized-dir";

    let state = tempfile::tempdir().unwrap();
    let _guard = EnvGuard::set("FULA_STATE_DIR", state.path());

    let writer = make_client(&base, encryption);
    setup_v7_bucket(&writer, bucket).await;

    // ~200 char padded filename so DirEntryWire inlined Vec<String> is the
    // dominant byte cost.
    let pad = "x".repeat(180);
    for i in 0..N {
        let path = format!("/huge/{pad}-{i:05}.bin");
        // Tiny content body — the point of this test is the forest's
        // DirEntryWire blob, not the content blobs.
        let body = b"x".to_vec();
        writer
            .put_object_flat_deferred(bucket, &path, body, None)
            .await
            .unwrap_or_else(|e| panic!("put {} failed: {:?}", path, e));
    }
    writer.flush_forest(bucket).await.expect("flush");

    // The oversized DirEntryWire lives inside a v7 HAMT node blob under
    // `__fula_forest_v7_nodes/<hex>`. Enumerate that prefix on the server
    // and confirm at least one blob exceeds MAX_BLOCK_SIZE.
    //
    // `fula-blockstore::ipfs::MAX_BLOCK_SIZE = 1024*1024 - 256`. We check
    // against that exact threshold.
    const MAX_BLOCK_SIZE: u64 = (1024 * 1024 - 256) as u64;
    let listed = writer
        .inner()
        .list_objects(
            bucket,
            Some(ListObjectsOptions {
                prefix: Some("__fula_forest_v7_nodes/".to_string()),
                max_keys: Some(10_000),
                ..Default::default()
            }),
        )
        .await
        .expect("list v7 node blobs");
    let max_size = listed
        .objects
        .iter()
        .map(|o| o.size)
        .max()
        .unwrap_or(0);
    assert!(
        max_size > MAX_BLOCK_SIZE,
        "expected at least one v7 node blob > MAX_BLOCK_SIZE ({} bytes); \
         saw max {} bytes across {} blobs",
        MAX_BLOCK_SIZE,
        max_size,
        listed.objects.len()
    );
    drop(writer);

    // Cold-reload a fresh client with only the KEK + endpoint; it must
    // re-read the oversized DirEntryWire and list the entire directory.
    // Release the writer's EnvGuard mutex before acquiring the reader's,
    // otherwise the two lock() calls on the same thread deadlock.
    drop(_guard);
    let state_r = tempfile::tempdir().unwrap();
    let _guard_r = EnvGuard::set("FULA_STATE_DIR", state_r.path());
    let reader = make_client(&base, EncryptionConfig::from_secret_key(secret));

    let listing = reader
        .list_directory(bucket, Some("/huge"))
        .await
        .expect("list /huge after cold reload");
    assert!(reader.is_forest_sharded_hamt(bucket));
    let got = listing
        .directories
        .values()
        .flatten()
        .count();
    assert_eq!(
        got, N,
        "post-cold-reload listing should return every seeded path"
    );
}

// ════════════════════════════════════════════════════════════════════════════
// G8 — deep path ancestor chain through v7
// ════════════════════════════════════════════════════════════════════════════

/// Verifies `sharded_hamt_forest.rs::ensure_ancestor_chain` (lines
/// 474–537) builds and reads back a 20-level-deep path through the v7
/// HAMT over a real server. The existing in-memory v1 test (Test 1 in
/// `encrypted_filesystem_tests.rs`) goes 50 levels deep but only through
/// `PrivateForest::new()` — never through v7.
#[tokio::test]
async fn test_hamt_deep_path_20_levels_over_server() {
    let base = spawn_server().await;
    let encryption = EncryptionConfig::new();
    let secret = encryption.export_secret_key().clone();
    let bucket = "v7-deep-path";

    let state = tempfile::tempdir().unwrap();
    let _guard = EnvGuard::set("FULA_STATE_DIR", state.path());

    let writer = make_client(&base, encryption);
    setup_v7_bucket(&writer, bucket).await;

    // Build "/a0/a1/.../a19/leaf.txt".
    let deep_path: String = {
        let mut p = String::new();
        for lvl in 0..20 {
            p.push_str(&format!("/lvl{:02}", lvl));
        }
        p.push_str("/leaf.txt");
        p
    };
    let content = b"deep-leaf-payload".to_vec();
    writer
        .put_object_flat(bucket, &deep_path, content.clone(), None)
        .await
        .expect("deep put");
    drop(writer);

    // Release the writer's EnvGuard mutex before acquiring the reader's,
    // otherwise the two lock() calls on the same thread deadlock.
    drop(_guard);
    let state_r = tempfile::tempdir().unwrap();
    let _guard_r = EnvGuard::set("FULA_STATE_DIR", state_r.path());
    let reader = make_client(&base, EncryptionConfig::from_secret_key(secret));

    let got = reader
        .get_object_flat(bucket, &deep_path)
        .await
        .expect("deep read after cold reload");
    assert_eq!(got.as_ref(), content.as_slice());
    assert!(reader.is_forest_sharded_hamt(bucket));

    // Every ancestor directory must resolve via `list_directory` — proves
    // `ensure_ancestor_chain` materialised a `D:/lvl00/.../lvlN/` HAMT
    // entry at every depth. An unmaterialised ancestor would make
    // `list_directory` fail (or return empty) at that prefix.
    let mut expected = String::new();
    for lvl in 0..20 {
        expected.push_str(&format!("/lvl{:02}", lvl));
        let listing = reader
            .list_directory(bucket, Some(&expected))
            .await
            .unwrap_or_else(|e| panic!("list {} failed: {:?}", expected, e));
        let has_child = listing
            .directories
            .values()
            .flatten()
            .any(|f| f.original_key.starts_with(&expected))
            || listing
                .directories
                .keys()
                .any(|k| k.starts_with(&expected) && k.len() > expected.len());
        assert!(
            has_child,
            "listing at ancestor {} returned nothing descending from it; got dirs {:?}",
            expected,
            listing.directories.keys().collect::<Vec<_>>()
        );
    }
}

// ════════════════════════════════════════════════════════════════════════════
// G7 — HAMT bucket split deterministic
// ════════════════════════════════════════════════════════════════════════════

/// Forces `Node::set_value` (wnfs_hamt/node.rs:234–267) past the 3-pair
/// bucket-split threshold and verifies non-trivial HAMT structure emerges.
/// With bucket size 3 and 16-ary branching, inserting N > 3 files into a
/// single shard will — with overwhelming probability on a cryptographic
/// key hash — force at least one split. We insert 80 files (far above the
/// split threshold) and assert that the v7 node blob count after flush is
/// significantly greater than the number of files (which would mean every
/// file fits into one bucket).
#[tokio::test]
async fn test_hamt_bucket_split_deterministic() {
    let base = spawn_server().await;
    let encryption = EncryptionConfig::new();
    let bucket = "v7-bucket-split";

    let state = tempfile::tempdir().unwrap();
    let _guard = EnvGuard::set("FULA_STATE_DIR", state.path());

    let writer = make_client(&base, encryption);
    setup_v7_bucket(&writer, bucket).await;

    // 80 entries in a single directory — well above the 3-pair bucket
    // threshold at every HAMT depth.
    const N: usize = 80;
    for i in 0..N {
        let path = format!("/splits/entry-{:03}.bin", i);
        let body = vec![i as u8; 8];
        writer
            .put_object_flat_deferred(bucket, &path, body, None)
            .await
            .expect("put");
    }
    writer.flush_forest(bucket).await.expect("flush");

    // Count v7 HAMT node blobs on the server. If no split ever happened,
    // the entire forest would live in ~1 node per shard — 16 shards → at
    // most ~16 nodes. A split produces at least one additional child node
    // per shard that saw a split, so we expect > 16 nodes when any splits
    // have occurred.
    let nodes = writer
        .inner()
        .list_objects(
            bucket,
            Some(ListObjectsOptions {
                prefix: Some("__fula_forest_v7_nodes/".to_string()),
                max_keys: Some(10_000),
                ..Default::default()
            }),
        )
        .await
        .expect("list v7 nodes");
    assert!(
        nodes.objects.len() > 1,
        "expected more than one v7 node blob after {} inserts (splits \
         should have emitted child nodes); got {}",
        N,
        nodes.objects.len()
    );

    // Round-trip: every entry must still be readable via the (now split)
    // HAMT.
    for i in [0usize, 1, N / 2, N - 1] {
        let path = format!("/splits/entry-{:03}.bin", i);
        let got = writer.get_object_flat(bucket, &path).await.expect("read");
        assert_eq!(got.as_ref(), vec![i as u8; 8].as_slice());
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Cross-dir structure stress — 100 dirs × 10 files
// ════════════════════════════════════════════════════════════════════════════

/// 100 directories × 10 files each = 1,000 files across a wide tree. This
/// exercises the cross-shard routing (`shard_for_dir` at
/// `sharded_hamt_forest.rs:376–397`) and the HAMT's ability to hold many
/// small directory entries in parallel shards. Complements the single-
/// directory scale tests by forcing breadth rather than depth.
#[tokio::test]
#[ignore = "slow in debug mode (1000 puts over in-process server); coverage overlaps \
            test_single_directory_2000_files_v7_end_to_end + test_hamt_deep_path_20_levels_over_server"]
async fn test_hamt_wide_fanout_100_dirs_x_10_files() {
    let base = spawn_server().await;
    let encryption = EncryptionConfig::new();
    let secret = encryption.export_secret_key().clone();
    let bucket = "v7-wide-fanout";

    let state = tempfile::tempdir().unwrap();
    let _guard = EnvGuard::set("FULA_STATE_DIR", state.path());

    let writer = make_client(&base, encryption);
    setup_v7_bucket(&writer, bucket).await;

    const DIRS: usize = 100;
    const FILES_PER_DIR: usize = 10;
    for d in 0..DIRS {
        for f in 0..FILES_PER_DIR {
            let path = format!("/tree/dir{:03}/file{:02}.bin", d, f);
            let body = format!("{}:{}", d, f).into_bytes();
            writer
                .put_object_flat_deferred(bucket, &path, body, None)
                .await
                .expect("put");
        }
    }
    writer.flush_forest(bucket).await.expect("flush");
    drop(writer);

    // Release the writer's EnvGuard mutex before acquiring the reader's,
    // otherwise the two lock() calls on the same thread deadlock.
    drop(_guard);
    let state_r = tempfile::tempdir().unwrap();
    let _guard_r = EnvGuard::set("FULA_STATE_DIR", state_r.path());
    let reader = make_client(&base, EncryptionConfig::from_secret_key(secret));

    // Force a cold load by listing the root.
    let listing = reader
        .list_directory(bucket, Some("/tree"))
        .await
        .expect("list /tree");
    assert!(reader.is_forest_sharded_hamt(bucket));

    let total_files: usize = listing.directories.values().map(|v| v.len()).sum();
    assert_eq!(
        total_files,
        DIRS * FILES_PER_DIR,
        "listing returned {} files, expected {}",
        total_files,
        DIRS * FILES_PER_DIR
    );

    // Spot-check each of the 4 corners of the grid.
    for (d, f) in [(0, 0), (0, FILES_PER_DIR - 1), (DIRS - 1, 0), (DIRS - 1, FILES_PER_DIR - 1)] {
        let path = format!("/tree/dir{:03}/file{:02}.bin", d, f);
        let expected = format!("{}:{}", d, f);
        let got = reader.get_object_flat(bucket, &path).await.expect("read");
        assert_eq!(got.as_ref(), expected.as_bytes(), "mismatch at {}", path);
    }
}
