//! v7 HAMT over the real in-process gateway — scenarios that the in-memory
//! `PrivateForest` tests in `crates/fula-client/tests/encrypted_filesystem_tests.rs`
//! don't exercise.
//!
//! The existing suite operates on `PrivateForest::new()` directly, bypassing
//! `EncryptedClient` + `put_object_flat` + the S3-compatible server. This file
//! runs the same workloads through the full stack so the v7 HAMT code path in
//! `crates/fula-client/src/encryption.rs` (the shipped production path) gets
//! end-to-end coverage.
//!
//! `tests/hamt_scale_tests.rs` already covers the 2,000-file-per-directory
//! and 20-level-deep cases. This file adds:
//!   - a 50-level deep path (matches the in-memory `test_deep_folder_structure_50_levels`)
//!   - a 5 MB chunked upload/download cycle (the in-memory suite simulates
//!     this via mock sizes; here the actual chunked AEAD/Bao path fires —
//!     `encryption.rs:684-779` + `encryption.rs:901,1068`)

mod common;
use common::*;

use fula_client::EncryptionConfig;

// ════════════════════════════════════════════════════════════════════════════
// 50-level deep path through the v7 HAMT
// ════════════════════════════════════════════════════════════════════════════

/// Build a 50-segment path, put one file through `put_object_flat`, cold-reload
/// a second client with the same KEK, read the file back. Closes the
/// "deep ancestor chain builds correctly over server" gap — the in-memory
/// test at `encrypted_filesystem_tests.rs:35` doesn't touch
/// `ensure_ancestor_chain` at `sharded_hamt_forest.rs:474`.
#[tokio::test]
async fn test_v7_deep_folder_structure_50_levels_over_server() {
    let base = spawn_server().await;
    let encryption = EncryptionConfig::new();
    let secret = encryption.export_secret_key().clone();
    let bucket = "v7-deep-50-levels";

    let state = tempfile::tempdir().unwrap();
    let _guard = EnvGuard::set("FULA_STATE_DIR", state.path());

    let writer = make_client(&base, encryption);
    writer.create_bucket(bucket).await.expect("create bucket");

    // Bootstrap to v7 so the writes below exercise the HAMT code path, not
    // the legacy v1 path. The plan is explicit that v7-over-server is what
    // we want to characterise here.
    writer
        .put_object_flat(bucket, "/__bootstrap.txt", b"x".to_vec(), None)
        .await
        .expect("bootstrap write");
    writer
        .migrate_to_sharded(bucket)
        .await
        .expect("migrate to v7");
    assert!(
        writer.is_forest_sharded_hamt(bucket),
        "bucket must be v7 before deep-path test"
    );

    let segments: Vec<String> = (0..50).map(|i| format!("l{:02}", i)).collect();
    let deep_path = format!("/{}/deep-file.txt", segments.join("/"));
    let payload = b"content-at-the-bottom-of-a-50-level-tree";

    writer
        .put_object_flat(bucket, &deep_path, payload.to_vec(), None)
        .await
        .expect("put deep file");

    // Cold-reload: fresh client, fresh cache, same KEK. Forces the v7 forest
    // to be re-materialised from server-side node blobs.
    let reader = make_client(
        &base,
        EncryptionConfig::from_secret_key(secret),
    );
    let body = reader
        .get_object_flat(bucket, &deep_path)
        .await
        .expect("fetch deep file from fresh client");
    assert_eq!(body.as_ref(), payload, "round-trip payload mismatch");
    assert!(
        reader.is_forest_sharded_hamt(bucket),
        "reader must observe v7 on cold reload"
    );
}

// ════════════════════════════════════════════════════════════════════════════
// Chunked 5 MB upload/download through the v7 HAMT
// ════════════════════════════════════════════════════════════════════════════

/// Upload a file large enough to cross the 768 KB chunked-path threshold in
/// `encryption.rs:684-779`, then cold-reload a second client and re-read.
/// Asserts that:
///   - chunking fires (size >> 768 KB forces `encrypt_chunked` in `chunked.rs`),
///   - the Bao root-hash verify at `encryption.rs:1068` succeeds,
///   - the file is tracked by a single `F:/path/` entry in the v7 HAMT
///     (verified via the cold-reload listing).
///
/// The existing chunked tests in `tests/audit2_tests.rs` operate on
/// in-memory fixtures; this drives the chunked path through the v7 HAMT +
/// server combination that ships in production.
#[tokio::test]
async fn test_v7_large_chunked_file_over_server() {
    let base = spawn_server().await;
    let encryption = EncryptionConfig::new();
    let secret = encryption.export_secret_key().clone();
    let bucket = "v7-chunked-5mb";

    let state = tempfile::tempdir().unwrap();
    let _guard = EnvGuard::set("FULA_STATE_DIR", state.path());

    let writer = make_client(&base, encryption);
    writer.create_bucket(bucket).await.expect("create bucket");

    // Flip to v7 before the large write.
    writer
        .put_object_flat(bucket, "/__bootstrap.txt", b"x".to_vec(), None)
        .await
        .expect("bootstrap write");
    writer
        .migrate_to_sharded(bucket)
        .await
        .expect("migrate to v7");
    assert!(writer.is_forest_sharded_hamt(bucket));

    // 5 MB: well over the 768 KB single-shot threshold; produces
    // 5 MB / 256 KB = 20 chunks.
    let size = 5 * 1024 * 1024;
    let payload: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();

    writer
        .put_object_flat(bucket, "/big.bin", payload.clone(), None)
        .await
        .expect("put 5 MB");

    // Cold-reload: fresh client sees the v7 manifest + HAMT from server.
    let reader = make_client(
        &base,
        EncryptionConfig::from_secret_key(secret),
    );
    let body = reader
        .get_object_flat(bucket, "/big.bin")
        .await
        .expect("fetch 5 MB from fresh client");
    assert_eq!(body.len(), size, "round-trip length mismatch");
    assert_eq!(body.as_ref(), &payload[..], "round-trip content mismatch");

    // Structural check: exactly one file entry for /big.bin under /.
    let listing = reader
        .list_directory(bucket, Some("/"))
        .await
        .expect("list /");
    let big_count = listing
        .directories
        .values()
        .flatten()
        .filter(|f| f.original_key == "/big.bin")
        .count();
    assert_eq!(big_count, 1, "exactly one HAMT entry for /big.bin");
}
