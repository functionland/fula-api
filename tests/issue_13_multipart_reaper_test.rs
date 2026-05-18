//! Issue #13 — multipart reaper never called.
//!
//! Today: `MultipartManager::cleanup_expired()` exists but is never invoked.
//! Abandoned multipart uploads accumulate in the DashMap unboundedly.
//!
//! After the fix:
//! - `cleanup_expired` returns `Vec<MultipartUpload>` (was: `usize`) so callers
//!   can log / metric the reaped sessions.
//! - `last_activity_at` is updated on `add_part`; expiry uses last-activity, not
//!   created-at — so slow legitimate uploads survive.
//! - Per-user concurrent-multipart cap enforced at `try_create_upload`.
//! - `start_reaper(manager, interval)` spawns the periodic sweeper.
//! - Reaper does NOT touch the blockstore — orphan chunks are left to the
//!   operator's IPFS GC. Direct deletion is unsafe in a content-addressed
//!   store because an "abandoned" CID may byte-equal a block reachable from
//!   a completed pinned DAG (CID dedup).
//!
//! These tests compile only against the post-fix API. On current `main` they
//! fail to compile, which is the intended "failing-first" signal.

use fula_cli::multipart::{MultipartError, MultipartManager, UploadPart};
use std::collections::BTreeMap;
use std::sync::Arc;

#[tokio::test]
async fn cleanup_expired_returns_reaped_uploads() {
    // Tiny expiry so we can age artificially.
    let mgr = MultipartManager::new(1);
    let upload = mgr
        .try_create_upload(
            "bucket".into(),
            "key1".into(),
            "user-a".into(),
            None,
            BTreeMap::new(),
        )
        .expect("first upload should succeed");
    let upload_id = upload.upload_id.clone();
    assert_eq!(mgr.upload_count(), 1);

    // Age the upload past expiry.
    mgr.test_age_last_activity(&upload_id, chrono::Duration::seconds(10));

    // After fix: cleanup_expired returns the reaped MultipartUpload list.
    let reaped = mgr.cleanup_expired();
    assert_eq!(reaped.len(), 1);
    assert_eq!(reaped[0].upload_id, upload_id);
    assert_eq!(mgr.upload_count(), 0);
}

#[tokio::test]
async fn cleanup_expired_uses_last_activity_not_created_at() {
    let mgr = MultipartManager::new(60);
    let upload = mgr
        .try_create_upload(
            "bucket".into(),
            "key".into(),
            "user".into(),
            None,
            BTreeMap::new(),
        )
        .unwrap();
    let upload_id = upload.upload_id.clone();

    // Age created_at past the expiry but keep last_activity recent —
    // simulating a slow but still-progressing upload.
    mgr.test_age_created_at(&upload_id, chrono::Duration::seconds(300));

    let reaped = mgr.cleanup_expired();
    assert_eq!(
        reaped.len(),
        0,
        "Slow legitimate upload (last_activity recent) must NOT be reaped"
    );
    assert_eq!(mgr.upload_count(), 1);
}

#[tokio::test]
async fn add_part_refreshes_last_activity() {
    let mgr = MultipartManager::new(60);
    let upload = mgr
        .try_create_upload(
            "bucket".into(),
            "key".into(),
            "user".into(),
            None,
            BTreeMap::new(),
        )
        .unwrap();
    let upload_id = upload.upload_id.clone();

    // Age last_activity past expiry.
    mgr.test_age_last_activity(&upload_id, chrono::Duration::seconds(120));

    // A part lands — should refresh last_activity_at.
    mgr.add_part(
        &upload_id,
        UploadPart::new(1, "etag1".into(), 100, "cid1".into()),
    );

    let reaped = mgr.cleanup_expired();
    assert_eq!(reaped.len(), 0, "add_part must refresh last_activity_at");
}

#[tokio::test]
async fn per_user_concurrent_upload_cap_rejects_overflow() {
    let mgr = MultipartManager::new(60).with_per_user_cap(8);

    // 8 uploads under the same owner: all accepted.
    for i in 0..8 {
        let res = mgr.try_create_upload(
            "bucket".into(),
            format!("key-{i}"),
            "user-a".into(),
            None,
            BTreeMap::new(),
        );
        assert!(res.is_ok(), "upload #{i} should succeed under cap");
    }

    // 9th rejected for same user.
    let res = mgr.try_create_upload(
        "bucket".into(),
        "key-overflow".into(),
        "user-a".into(),
        None,
        BTreeMap::new(),
    );
    assert!(
        matches!(res, Err(MultipartError::PerUserCapExceeded { .. })),
        "9th upload for same user must be rejected with PerUserCapExceeded"
    );

    // Different user is unaffected.
    let res = mgr.try_create_upload(
        "bucket".into(),
        "key-other".into(),
        "user-b".into(),
        None,
        BTreeMap::new(),
    );
    assert!(
        res.is_ok(),
        "different user must not be capped by user-a's count"
    );
}

#[tokio::test]
async fn complete_releases_per_user_slot() {
    let mgr = MultipartManager::new(60).with_per_user_cap(2);
    let u1 = mgr
        .try_create_upload(
            "bucket".into(),
            "key1".into(),
            "user".into(),
            None,
            BTreeMap::new(),
        )
        .unwrap();
    let _u2 = mgr
        .try_create_upload(
            "bucket".into(),
            "key2".into(),
            "user".into(),
            None,
            BTreeMap::new(),
        )
        .unwrap();
    // Cap hit at 2.
    let res = mgr.try_create_upload(
        "bucket".into(),
        "key3".into(),
        "user".into(),
        None,
        BTreeMap::new(),
    );
    assert!(res.is_err());

    // Complete u1 — frees the slot.
    mgr.complete_upload(&u1.upload_id).unwrap();
    let res = mgr.try_create_upload(
        "bucket".into(),
        "key3".into(),
        "user".into(),
        None,
        BTreeMap::new(),
    );
    assert!(res.is_ok(), "completed upload must release the user slot");
}

#[tokio::test]
async fn reaping_releases_per_user_slot() {
    let mgr = MultipartManager::new(1).with_per_user_cap(1);
    let u1 = mgr
        .try_create_upload(
            "bucket".into(),
            "key1".into(),
            "user".into(),
            None,
            BTreeMap::new(),
        )
        .unwrap();
    // Cap hit at 1.
    let res = mgr.try_create_upload(
        "bucket".into(),
        "key2".into(),
        "user".into(),
        None,
        BTreeMap::new(),
    );
    assert!(res.is_err());

    // Age u1 past expiry; cleanup should reap and free the slot.
    mgr.test_age_last_activity(&u1.upload_id, chrono::Duration::seconds(10));
    let reaped = mgr.cleanup_expired();
    assert_eq!(reaped.len(), 1);

    let res = mgr.try_create_upload(
        "bucket".into(),
        "key2".into(),
        "user".into(),
        None,
        BTreeMap::new(),
    );
    assert!(res.is_ok(), "reaped upload must release the user slot");
}

#[tokio::test]
async fn complete_and_reaper_race_no_double_remove() {
    let mgr = Arc::new(MultipartManager::new(1));
    let upload = mgr
        .try_create_upload(
            "bucket".into(),
            "key".into(),
            "user".into(),
            None,
            BTreeMap::new(),
        )
        .unwrap();
    let id = upload.upload_id.clone();
    mgr.test_age_last_activity(&id, chrono::Duration::seconds(10));

    // Race: complete and reaper at the same time.
    let mgr_c = Arc::clone(&mgr);
    let id_c = id.clone();
    let t1 = tokio::spawn(async move { mgr_c.complete_upload(&id_c) });
    let mgr_r = Arc::clone(&mgr);
    let t2 = tokio::spawn(async move { mgr_r.cleanup_expired() });

    let r1 = t1.await.unwrap();
    let r2 = t2.await.unwrap();
    let completed_won = r1.is_some();
    let reaper_won = r2.iter().any(|u| u.upload_id == id);
    assert!(
        completed_won ^ reaper_won,
        "exactly one of complete/reap must claim the upload (completed_won={completed_won}, reaper_won={reaper_won})",
    );
    assert_eq!(mgr.upload_count(), 0);
}

#[tokio::test]
async fn opportunistic_cleanup_on_create_reaps_expired_for_user() {
    // A user spamming Initiate without ever Completing should not accumulate
    // state between sweeps. `try_create_upload` does an opportunistic
    // last-activity sweep for the calling user before counting toward cap.
    let mgr = MultipartManager::new(1).with_per_user_cap(2);
    // Fill the cap.
    let u1 = mgr
        .try_create_upload(
            "bucket".into(),
            "k1".into(),
            "user".into(),
            None,
            BTreeMap::new(),
        )
        .unwrap();
    let u2 = mgr
        .try_create_upload(
            "bucket".into(),
            "k2".into(),
            "user".into(),
            None,
            BTreeMap::new(),
        )
        .unwrap();
    // 3rd hits the cap.
    let res = mgr.try_create_upload(
        "bucket".into(),
        "k3".into(),
        "user".into(),
        None,
        BTreeMap::new(),
    );
    assert!(res.is_err());

    // Age both past expiry.
    mgr.test_age_last_activity(&u1.upload_id, chrono::Duration::seconds(10));
    mgr.test_age_last_activity(&u2.upload_id, chrono::Duration::seconds(10));

    // 4th attempt: should opportunistically reap the user's expired uploads
    // and accept the new one.
    let res = mgr.try_create_upload(
        "bucket".into(),
        "k4".into(),
        "user".into(),
        None,
        BTreeMap::new(),
    );
    assert!(
        res.is_ok(),
        "opportunistic cleanup at create-time should reap user's expired uploads and accept the new one"
    );
}
