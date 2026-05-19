//! Issue [#10](https://github.com/functionland/fula-api/issues/10) —
//! Walkable-v8: force-rewrite v7 buckets to v8 on first master-up load.
//!
//! This test exercises the existing manual migration path
//! (`EncryptedClient::migrate_bucket_to_walkable_v8`) end-to-end against
//! a real in-process gateway:
//!
//! 1. **Phase A** — a client with `walkable_v8_writer_enabled = false`
//!    creates a bucket and uploads files. The resulting forest manifest
//!    uses the v7 wire format (`PointerWire::Link(StorageKey)` pointers
//!    on every HAMT internal node — no CID hints).
//! 2. **Phase B** — a fresh client with `walkable_v8_writer_enabled = true`
//!    loads the bucket via `list_files_from_forest`. Verifies the v8 reader
//!    can walk a v7-formatted bucket cleanly (a basic back-compat regression).
//! 3. **Phase C** — the v8 client invokes
//!    `migrate_bucket_to_walkable_v8(bucket)`. Asserts the call succeeds
//!    and reports a non-zero number of files re-upserted.
//! 4. **Phase D** — re-lists the bucket and verifies all the original files
//!    are still discoverable. Migration must be non-destructive at the
//!    data layer.
//! 5. **Phase E** — calls `migrate_bucket_to_walkable_v8` a SECOND time.
//!    Asserts identical file count (idempotent at the content level —
//!    a fact the function's contract guarantees even though the cascade
//!    re-upserts every leaf each invocation).
//!
//! ## What this test covers
//!
//! - ✅ The MANUAL migration mechanism works end-to-end.
//! - ✅ A v8 client can read a v7 bucket (back-compat).
//! - ✅ Migration is non-destructive — all files survive.
//! - ✅ Migration is idempotent at the content level.
//!
//! ## What this test does NOT cover (issue #10's remaining ask)
//!
//! Per issue [#10]'s acceptance criteria (step 3):
//!
//! > Applies the proposed migration (single SDK call, **no operator
//! > intervention**).
//!
//! The current implementation requires the caller to invoke
//! `migrate_bucket_to_walkable_v8` explicitly. The proposed AUTO-TRIGGER
//! (inside `load_forest_internal` after manifest decode, gated by a
//! "page_index has any `cid: None`" scan + a one-shot per-bucket marker
//! in `BlockCache::METADATA`) is NOT yet implemented. When that lands,
//! this test should be expanded to assert that **Phase B alone** (without
//! the explicit Phase C call) leaves the bucket in v8 state — i.e., a
//! subsequent `migrate_bucket_to_walkable_v8` call would be redundant.
//!
//! ## Why we don't assert "auto-migration fired" today
//!
//! The cleanest observable signal for auto-migration would be:
//!   (i) inspecting `ManifestSnapshot.root.page_index` for `cid: Some(_)`
//!       on every entry — requires a test-only accessor on `EncryptedClient`
//!       that isn't shipped, OR
//!   (ii) offline-walking the bucket after Phase B (would succeed only
//!       if every internal node now carries a LinkV2 cid hint) — requires
//!       a gateway mock + master-down simulation infrastructure that
//!       lives in `walkable_v8_offline_walk.rs` as a separate test.
//!
//! Neither is in this test's scope. The manual-migration regression
//! guard is the contribution; the auto-trigger assertion will land
//! alongside the fix itself.

mod common;
use common::*;

use bytes::Bytes;
use fula_client::{Config, EncryptedClient, EncryptionConfig};
use fula_crypto::keys::SecretKey;

const BUCKET: &str = "issue-10-v7-to-v8";
const N_FILES: usize = 5;

#[tokio::test]
async fn issue_10_v7_bucket_round_trips_through_walkable_v8_migration() {
    let base = spawn_server().await;
    let secret = SecretKey::generate();

    // ────────────────────────────────────────────────────────────────
    // Phase A — v7 writer creates the bucket.
    // ────────────────────────────────────────────────────────────────
    {
        let mut config = Config::new(&base).with_encryption();
        config.walkable_v8_writer_enabled = false;
        let v7_client = EncryptedClient::new(
            config,
            EncryptionConfig::from_secret_key(secret.clone()),
        )
        .expect("v7 EncryptedClient::new");
        v7_client
            .create_bucket(BUCKET)
            .await
            .expect("create_bucket");
        for i in 0..N_FILES {
            let key = format!("/file-{}.txt", i);
            let data = format!("issue-10-payload-{}", i).into_bytes();
            v7_client
                .put_object_flat_deferred(BUCKET, &key, Bytes::from(data), None)
                .await
                .expect("put_object_flat_deferred");
        }
        v7_client
            .flush_forest(BUCKET)
            .await
            .expect("flush_forest under v7 writer");
    }

    // ────────────────────────────────────────────────────────────────
    // Phase B — fresh v8 client loads the bucket. v8 reader on a v7
    // manifest must succeed (back-compat regression).
    // ────────────────────────────────────────────────────────────────
    let mut v8_config = Config::new(&base).with_encryption();
    v8_config.walkable_v8_writer_enabled = true;
    let v8_client = EncryptedClient::new(
        v8_config,
        EncryptionConfig::from_secret_key(secret.clone()),
    )
    .expect("v8 EncryptedClient::new");

    let files_pre = v8_client
        .list_files_from_forest(BUCKET)
        .await
        .expect("list_files_from_forest under v8 reader against v7 manifest");
    assert_eq!(
        files_pre.len(),
        N_FILES,
        "back-compat: v8 reader must surface every file from a v7-written manifest"
    );

    // ────────────────────────────────────────────────────────────────
    // Phase C — manual migration. The bug described in issue #10 is
    // that this call SHOULD be unnecessary (it should fire
    // automatically during Phase B), but is currently required.
    // ────────────────────────────────────────────────────────────────
    let migrated_count = v8_client
        .migrate_bucket_to_walkable_v8(BUCKET)
        .await
        .expect("migrate_bucket_to_walkable_v8 must succeed on a v7 bucket");
    assert!(
        migrated_count >= N_FILES,
        "migration must process at least every file in the bucket; got {} for N_FILES={}",
        migrated_count,
        N_FILES
    );

    // ────────────────────────────────────────────────────────────────
    // Phase D — verify data integrity post-migration.
    // ────────────────────────────────────────────────────────────────
    let files_post = v8_client
        .list_files_from_forest(BUCKET)
        .await
        .expect("list_files_from_forest after migration");
    assert_eq!(
        files_post.len(),
        N_FILES,
        "migration must be non-destructive — every file still discoverable"
    );

    // Verify the file SET matches (same storage_keys / same original_keys).
    let mut pre_keys: Vec<String> = files_pre.iter().map(|f| f.original_key.clone()).collect();
    let mut post_keys: Vec<String> = files_post.iter().map(|f| f.original_key.clone()).collect();
    pre_keys.sort();
    post_keys.sort();
    assert_eq!(
        pre_keys, post_keys,
        "migration must preserve the file set 1:1; pre and post original_keys must match"
    );

    // ────────────────────────────────────────────────────────────────
    // Phase E — idempotency at the content level. The cascade re-upserts
    // every leaf each invocation (the function isn't no-op-aware), but
    // the bucket's logical content stays identical.
    // ────────────────────────────────────────────────────────────────
    let migrated_count_2 = v8_client
        .migrate_bucket_to_walkable_v8(BUCKET)
        .await
        .expect("second migrate call must succeed");
    assert_eq!(
        migrated_count_2, migrated_count,
        "migration must report identical file count on a re-run (content-level idempotency)"
    );

    let files_after_2nd = v8_client
        .list_files_from_forest(BUCKET)
        .await
        .expect("list_files_from_forest after second migration");
    assert_eq!(
        files_after_2nd.len(),
        N_FILES,
        "second migration call must not change the file set"
    );
}

/// **Issue #10 acceptance test: auto-migration on first master-up load.**
///
/// Regression guard for the actual fix. Asserts that loading a v7-
/// formatted bucket through a v8-writer-enabled `EncryptedClient`
/// fires the auto-trigger transparently — no explicit
/// `migrate_bucket_to_walkable_v8` call, no operator intervention.
///
/// **Why we don't assert `manifest_has_v7_pointers() == false`:** the
/// in-process gateway under `spawn_server` uses `MemoryBlockStore`,
/// whose CID computation (`fula-blockstore/src/cid_utils.rs:60-70`)
/// wraps the BLAKE3 digest in a SHA2-256 multihash slot. The SDK's
/// `walkable_v8::local_blake3_raw_cid` produces a BLAKE3 multihash
/// CID (code `0x1e`). The two never agree, so
/// `verify_etag_against_expected_cid` deterministically returns
/// `None` against this gateway — `page_index[*].cid` stays `None` no
/// matter how many migrations run. (Real production master uses
/// IPFS `block/put?mhtype=blake3` which produces the matching
/// BLAKE3-multihash CID; this is a test-fixture-only artifact.)
///
/// The auto-trigger's load-bearing observable side effect IS the
/// per-device migration marker written by
/// `EncryptedClient::persist_walkable_v8_migration_marker`. The
/// marker is written **only** on `Ok(_)` return from
/// `migrate_bucket_to_walkable_v8`, so its existence post-load is a
/// faithful indicator that:
///   1. The gate inside `load_forest_internal` ManifestV7 fired
///      (`walkable_v8_writer_enabled` on, marker absent).
///   2. `manifest_has_v7_pointers()` returned true.
///   3. `migrate_bucket_to_walkable_v8` completed without error.
///   4. The marker write succeeded.
///
/// Before the fix lands, this test MUST fail (no marker file). After
/// the fix lands, it MUST pass (marker file present).
#[tokio::test]
async fn issue_10_v7_bucket_auto_migrates_on_first_v8_load() {
    let base = spawn_server().await;
    let secret = SecretKey::generate();
    let bucket = "issue-10-auto-migrate";

    // Process-isolated FULA_STATE_DIR — the marker check honours
    // this env var, and an earlier test on the same machine could
    // otherwise pre-populate the marker and silently mask the fix.
    // `EnvGuard` serializes the env mutation against other tests in
    // the same binary that swap FULA_STATE_DIR (see common/mod.rs).
    let state_dir = std::env::temp_dir().join(format!(
        "fula-issue10-auto-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&state_dir).expect("create state dir");
    let _env = EnvGuard::set("FULA_STATE_DIR", &state_dir);

    // Compute the marker path the fix will write to. Mirrors the
    // production implementation in
    // `crates/fula-client/src/encryption.rs:walkable_v8_marker_path`
    // (BLAKE3(bucket)[..16].hex prefix under
    // `<state>/fula/walkable-v8-migrated/`).
    let bucket_hash = blake3::hash(bucket.as_bytes());
    let bucket_id: String = hex::encode(&bucket_hash.as_bytes()[..16]);
    let expected_marker_path = state_dir
        .join("fula")
        .join("walkable-v8-migrated")
        .join(&bucket_id);

    // Phase A: write a v7 bucket (writer flag off).
    {
        let mut config = Config::new(&base).with_encryption();
        config.walkable_v8_writer_enabled = false;
        let v7_client = EncryptedClient::new(
            config,
            EncryptionConfig::from_secret_key(secret.clone()),
        )
        .expect("v7 EncryptedClient::new");
        v7_client.create_bucket(bucket).await.expect("create_bucket");
        for i in 0..N_FILES {
            let key = format!("/auto-{}.txt", i);
            let data = format!("issue-10-auto-{}", i).into_bytes();
            v7_client
                .put_object_flat_deferred(bucket, &key, Bytes::from(data), None)
                .await
                .expect("put_object_flat_deferred");
        }
        v7_client
            .flush_forest(bucket)
            .await
            .expect("flush_forest under v7 writer");
    }

    // Pre-condition: marker MUST be absent before the fresh v8
    // client loads the bucket. If something on the filesystem already
    // has it, the assertion below would pass spuriously.
    assert!(
        !expected_marker_path.exists(),
        "pre-condition failure: walkable-v8 marker already exists at {:?} \
         before the v8 client even loaded the bucket — test state leaked",
        expected_marker_path
    );

    // Phase B: load with a fresh v8 client. The auto-trigger fires
    // inside `load_forest_internal`'s ManifestV7 arm.
    let mut v8_config = Config::new(&base).with_encryption();
    v8_config.walkable_v8_writer_enabled = true;
    let v8_client = EncryptedClient::new(
        v8_config,
        EncryptionConfig::from_secret_key(secret.clone()),
    )
    .expect("v8 EncryptedClient::new");

    let files_after_load = v8_client
        .list_files_from_forest(bucket)
        .await
        .expect("list_files_from_forest under v8 client against v7 bucket");
    assert_eq!(
        files_after_load.len(),
        N_FILES,
        "load must surface every file"
    );

    // Load-bearing assertion: the marker file must exist after the
    // load. This proves the entire auto-trigger chain (gate fired →
    // migration succeeded → marker written) ran.
    assert!(
        expected_marker_path.exists(),
        "issue #10 fix not present: walkable-v8 migration marker \
         {:?} was not written after loading a v7 bucket through a \
         v8-writer-enabled client. The auto-trigger inside \
         `load_forest_internal`'s ManifestV7 arm did not fire — \
         lazy-per-shard cascade is the only migration path active.",
        expected_marker_path
    );

    // Defense-in-depth: explicit migrate call after the auto-trigger
    // ran must still succeed (cascade is content-idempotent).
    let migrated_count = v8_client
        .migrate_bucket_to_walkable_v8(bucket)
        .await
        .expect("explicit migrate after auto-trigger must still succeed");
    assert_eq!(
        migrated_count, N_FILES,
        "migrate's re-upsert cascade counts each leaf once per invocation"
    );

    // Second load with a NEW client (cold cache) must short-circuit
    // the auto-trigger via the marker check — no cascade, no flush,
    // no marker rewrite (the file timestamp shouldn't bump because
    // the persistence helper is idempotent). The simplest robust
    // check: data still listable, marker still exists.
    let v8_client_2 = EncryptedClient::new(
        Config::new(&base).with_encryption(),
        EncryptionConfig::from_secret_key(secret.clone()),
    )
    .expect("second v8 EncryptedClient::new");
    let files_second_load = v8_client_2
        .list_files_from_forest(bucket)
        .await
        .expect("second v8 load must succeed against the migrated bucket");
    assert_eq!(
        files_second_load.len(),
        N_FILES,
        "second cold-cache v8 load must see the same file set"
    );
    assert!(
        expected_marker_path.exists(),
        "marker must persist across subsequent loads"
    );

    // Hermeticity: clean up the marker so a re-run starts fresh.
    let _ = std::fs::remove_dir_all(&state_dir);
}

/// Counterpart test: verifies that `migrate_bucket_to_walkable_v8` returns
/// a clean `Config` error when called against a client that has the writer
/// flag disabled. This is a precondition the production trigger (once
/// shipped per issue #10) must respect — calling the migration with the
/// v7 writer would re-cascade as v7 pointers, defeating the migration.
#[tokio::test]
async fn issue_10_migration_refuses_to_run_with_v8_writer_disabled() {
    let base = spawn_server().await;
    let secret = SecretKey::generate();
    let bucket = "issue-10-refuses-with-v7-writer";

    // Create the bucket so the migration has SOMETHING to operate on
    // (otherwise we'd 404 on the bucket-not-found before reaching the
    // writer-flag check).
    {
        let mut config = Config::new(&base).with_encryption();
        config.walkable_v8_writer_enabled = false;
        let v7_client = EncryptedClient::new(
            config,
            EncryptionConfig::from_secret_key(secret.clone()),
        )
        .unwrap();
        v7_client.create_bucket(bucket).await.unwrap();
        v7_client
            .put_object_flat_deferred(bucket, "/one.txt", Bytes::from_static(b"x"), None)
            .await
            .unwrap();
        v7_client.flush_forest(bucket).await.unwrap();
    }

    // Now try to migrate with the v7 writer still active. Must refuse.
    let mut config = Config::new(&base).with_encryption();
    config.walkable_v8_writer_enabled = false;
    let client = EncryptedClient::new(
        config,
        EncryptionConfig::from_secret_key(secret),
    )
    .unwrap();
    let res = client.migrate_bucket_to_walkable_v8(bucket).await;
    assert!(
        res.is_err(),
        "migration must refuse when walkable_v8_writer_enabled = false; got Ok({:?})",
        res
    );
    let err_msg = format!("{}", res.unwrap_err());
    assert!(
        err_msg.contains("walkable_v8_writer_enabled"),
        "error message should reference the offending config flag; got: {}",
        err_msg
    );
}
