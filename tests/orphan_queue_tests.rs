//! F7 integration tests: persistent orphan-cleanup queue.
//!
//! Covers the lifecycle of a failed `cleanup_orphaned_storage` call:
//! (a) a cleanup failure appends an entry to the queue, (b) a subsequent
//! cleanup call drains the queue once the failure condition is cleared,
//! (c) dedup prevents unbounded growth when the same storage key fails
//! repeatedly.
//!
//! The failure path is simulated with the `FORCE_ORPHAN_CLEANUP_MAIN_FAIL`
//! atomic exposed by the `test-fault-injection` feature — no network
//! disruption needed.

mod common;
use common::*;
use common::fault_injection::FaultScope;

use fula_client::EncryptionConfig;

fn orphan_queue_dir(state_dir: &std::path::Path) -> std::path::PathBuf {
    state_dir.join("fula").join("orphan-queue")
}

fn queue_file_count(state_dir: &std::path::Path) -> usize {
    let dir = orphan_queue_dir(state_dir);
    if !dir.exists() {
        return 0;
    }
    std::fs::read_dir(&dir)
        .map(|entries| entries.filter_map(|e| e.ok()).count())
        .unwrap_or(0)
}

fn queue_file_lines(state_dir: &std::path::Path) -> usize {
    let dir = orphan_queue_dir(state_dir);
    if !dir.exists() {
        return 0;
    }
    let mut total = 0usize;
    for e in std::fs::read_dir(&dir).unwrap().flatten() {
        let body = std::fs::read_to_string(e.path()).unwrap_or_default();
        total += body.lines().filter(|l| !l.trim().is_empty()).count();
    }
    total
}

/// Happy path: a failed cleanup lands in the queue; a clean subsequent
/// cleanup drains it.
///
/// The `bypass_orphan_cleanup_refcheck` guard is required because v7's
/// `storage_key_still_referenced` conservatively returns `true` for every
/// key (until v7 traversal is wired), which would short-circuit cleanup
/// before it ever reaches the queue-append code. All new buckets start v7.
#[tokio::test]
async fn test_orphan_queue_round_trip() {
    let base = spawn_server().await;
    let encryption = EncryptionConfig::new();
    let bucket = "orphan-round-trip";

    let state = tempfile::tempdir().unwrap();
    let _guard = EnvGuard::set("FULA_STATE_DIR", state.path());
    let _bypass = FaultScope::bypass_orphan_cleanup_refcheck();

    let client = make_client(&base, encryption);
    client.create_bucket(bucket).await.expect("create bucket");

    // Seed: put A under /x.txt. No overwrite yet → no cleanup fires.
    client.put_object_flat(bucket, "/x.txt", b"v-a".to_vec(), None)
        .await.expect("put A");
    assert_eq!(queue_file_count(state.path()), 0, "queue must be empty after first put");

    // Overwrite under the failure fault — cleanup fires for A's storage
    // key, main delete is forced-failed, and A is enqueued.
    {
        let _fault = FaultScope::orphan_cleanup_main_fail();
        client.put_object_flat(bucket, "/x.txt", b"v-b".to_vec(), None)
            .await.expect("put B under fault");
    }
    assert_eq!(
        queue_file_lines(state.path()),
        1,
        "failed cleanup must append exactly one orphan-queue entry",
    );

    // Clear the fault, overwrite again. This triggers cleanup for B (succeeds)
    // and — crucially — the lazy drain at the top of cleanup_orphaned_storage
    // retries A. Both go through, queue drops to empty.
    client.put_object_flat(bucket, "/x.txt", b"v-c".to_vec(), None)
        .await.expect("put C (no fault)");

    assert_eq!(
        queue_file_lines(state.path()),
        0,
        "drain must empty the queue once the failure is cleared",
    );

    // Final state: /x.txt should read back as v-c.
    let got = client.get_object_flat(bucket, "/x.txt")
        .await.expect("read C");
    assert_eq!(got.as_ref(), b"v-c");
}

/// Repeated cleanup failures on the same storage key do not grow the queue —
/// dedup on `storage_key` keeps it at exactly one entry.
#[tokio::test]
async fn test_orphan_queue_dedup_on_repeated_failure() {
    let base = spawn_server().await;
    let encryption = EncryptionConfig::new();
    let bucket = "orphan-dedup";

    let state = tempfile::tempdir().unwrap();
    let _guard = EnvGuard::set("FULA_STATE_DIR", state.path());
    let _bypass = FaultScope::bypass_orphan_cleanup_refcheck();

    let client = make_client(&base, encryption);
    client.create_bucket(bucket).await.expect("create bucket");

    // Seed A.
    client.put_object_flat(bucket, "/y.txt", b"v0".to_vec(), None)
        .await.expect("put A");

    // Under fault: overwrite multiple times. Each overwrite fails the
    // cleanup of the *previous* storage key. With dedup turned off we'd
    // see N-1 entries; with dedup on, each new storage_key contributes
    // exactly one line — and N becomes N-1 (the last put's storage_key
    // isn't cleaned up because nothing overwrites it).
    {
        let _fault = FaultScope::orphan_cleanup_main_fail();
        for i in 1..4 {
            client.put_object_flat(
                bucket, "/y.txt", format!("v{}", i).into_bytes(), None,
            ).await.expect("overwrite under fault");
        }
    }

    // Three overwrites under fault → 3 distinct failed cleanups →
    // three distinct `storage_key`s enqueued (no intra-key duplication).
    let lines = queue_file_lines(state.path());
    assert_eq!(
        lines, 3,
        "expected exactly 3 queue entries for 3 distinct failed cleanups, got {}",
        lines,
    );

    // Now overwrite once more, still under fault. The cleanup for the
    // previous iteration would try to enqueue a storage key that's NEW
    // (the just-succeeded-put storage key was v3's). So we'll see 4 entries
    // after — which demonstrates dedup is storage-key-specific, not
    // file-wide.
    {
        let _fault = FaultScope::orphan_cleanup_main_fail();
        client.put_object_flat(bucket, "/y.txt", b"v4".to_vec(), None)
            .await.expect("overwrite v4 under fault");
    }
    assert_eq!(
        queue_file_lines(state.path()),
        4,
        "each overwrite pins a distinct storage key; dedup is per-storage-key not per-path",
    );

    // Clear fault, one more overwrite. Drain kicks in — all 4 previously-failed
    // storage keys are revisited, and since the fault is cleared this time,
    // each delete succeeds → queue goes to empty.
    client.put_object_flat(bucket, "/y.txt", b"v5".to_vec(), None)
        .await.expect("drain cycle");

    assert_eq!(
        queue_file_lines(state.path()),
        0,
        "drain must empty all previously-queued entries on the next clean cleanup",
    );
}
