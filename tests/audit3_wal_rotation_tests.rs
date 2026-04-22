//! Audit3: WAL + Rotation-Journal Integrity Tests
//!
//! Covers the NEW-7.1 / NEW-7.2 / NEW-L.4 / NEW-L.7 fixes:
//! - Rotation journal MAC rejects forged lines
//! - Rotation journal exclusive file lock prevents interleaved writers
//! - 412 on manifest flush triggers WAL replay + retry against the winner
//!
//! The journal tests are file-level: they exercise the real `rotate_bucket_with_journal`
//! path end-to-end against an in-process gateway (see `spawn_server`), including the
//! KeyRotationManager round-trip, so the MAC derivation & line format are validated
//! as the rotation code actually emits them.
//!
//! The 412/WAL test drives two `EncryptedClient`s against the same bucket with
//! disjoint writes; the losing writer must replay its WAL and retry until the
//! forest is consistent on both sides.

use fula_cli::{AppState, GatewayConfig, routes};
use fula_client::{Config, EncryptedClient, EncryptionConfig};
use std::sync::Arc;
use tokio::net::TcpListener;

async fn spawn_server() -> String {
    let mut config = GatewayConfig::default();
    config.host = "127.0.0.1".to_string();
    config.port = 0;
    config.auth_enabled = false;
    config.use_memory_store = true;
    config.registry_cid_path = None;
    config.jwt_secret = Some("test-secret-123".to_string());

    let state = Arc::new(AppState::new(config.clone()).await.unwrap());
    let app = routes::create_router(state);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    format!("http://{}", addr)
}

fn make_client(endpoint: &str, encryption: EncryptionConfig) -> EncryptedClient {
    let config = Config::new(endpoint).with_encryption();
    EncryptedClient::new(config, encryption).expect("encrypted client")
}

// ═══════════════════════════════════════════════════════════════════════════
// NEW-7.1 — rotation journal MAC rejects forged/tampered lines
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_rotation_journal_mac_rejects_forged_line() {
    let base = spawn_server().await;
    let encryption = EncryptionConfig::new();
    let client = make_client(&base, encryption);
    let bucket = "rotj-forged";
    client.create_bucket(bucket).await.expect("create bucket");

    // Upload three encrypted objects so rotation has something to do.
    for k in ["/a.txt", "/b.txt", "/c.txt"] {
        client.put_object_encrypted(bucket, k, format!("body-{}", k).into_bytes())
            .await.expect("put_encrypted");
    }

    // Prepare a real rotation (v1 → v2). The client owns the v1 keypair; the
    // rotator generates v2 internally via `rotate_kek`.
    let mut rotator = client.create_rotation_manager();
    rotator.rotate_kek().expect("rotate kek");

    let journal_dir = tempfile::tempdir().unwrap();
    let journal_path = journal_dir.path().join("rotation.journal");

    // Pre-populate the journal with a single forged line pointing at a bogus
    // storage_key. The MAC is intentionally all-zeros so it cannot match any
    // value derived from the real per-bucket journal MAC key.
    std::fs::write(
        &journal_path,
        "forged-storage-key-that-never-existed\t0000000000000000000000000000000000000000000000000000000000000000\n",
    ).expect("write tampered journal");

    // Run rotation once. The forged line must be rejected (MAC mismatch) so
    // it cannot mask a real object from being rotated, and after a clean run
    // the journal file must be deleted (rotate_bucket_with_journal's cleanup path).
    let report = client.rotate_bucket_with_journal(bucket, &rotator, &journal_path)
        .await.expect("rotate");
    assert_eq!(report.failed, 0, "rotation failures: {:?}", report.failures);
    assert_eq!(report.rotated, 3,
        "all 3 legitimate objects must be rotated; forged 'already-done' line must not suppress real work");
    assert!(!journal_path.exists(),
        "journal must be cleared after a clean rotation (forged entry must not leave the file behind)");
}

// ═══════════════════════════════════════════════════════════════════════════
// NEW-L.4 — exclusive OS file lock on the rotation journal
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_rotation_journal_exclusive_lock() {
    let base = spawn_server().await;
    let encryption = EncryptionConfig::new();
    let client = make_client(&base, encryption);
    let bucket = "rotj-lock";
    client.create_bucket(bucket).await.expect("create bucket");

    // Need at least one encrypted object so rotation has to actually open the
    // journal for writing (before that it would short-circuit).
    for k in ["/x.txt", "/y.txt"] {
        client.put_object_encrypted(bucket, k, format!("body-{}", k).into_bytes())
            .await.expect("put_encrypted");
    }

    let mut rotator = client.create_rotation_manager();
    rotator.rotate_kek().expect("rotate kek");

    let journal_dir = tempfile::tempdir().unwrap();
    let journal_path = journal_dir.path().join("rotation.journal");

    // Pre-acquire an exclusive lock on the journal in this thread, then try
    // to rotate in a blocking task; the rotation must fail fast with RotationInProgress.
    use fs2::FileExt;
    let held = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&journal_path)
        .expect("open held");
    held.try_lock_exclusive().expect("hold lock");

    let err = client
        .rotate_bucket_with_journal(bucket, &rotator, &journal_path)
        .await
        .expect_err("must fail while journal is locked");

    // The typed error is exposed via `ClientError::RotationInProgress`.
    let msg = err.to_string();
    assert!(
        msg.contains("rotation") || msg.contains("Rotation") || msg.contains("locked"),
        "expected RotationInProgress-ish error, got: {}", msg,
    );

    // Drop the lock, retry — must now succeed.
    drop(held);
    let report = client
        .rotate_bucket_with_journal(bucket, &rotator, &journal_path)
        .await
        .expect("rotate after lock released");
    assert_eq!(report.failed, 0, "rotation failures: {:?}", report.failures);
}

// ═══════════════════════════════════════════════════════════════════════════
// NEW-7.2 — 412 on flush triggers WAL replay + retry against the winner
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_412_triggers_wal_replay_then_retry() {
    let base = spawn_server().await;

    // Two EncryptedClients sharing the SAME encryption keys (so they see the same
    // bucket+forest). They have separate forest caches AND separate state dirs —
    // the latter simulates two separate processes, each with its own WAL file, so
    // A's post-flush WAL clear cannot wipe B's pending entries.
    let encryption = EncryptionConfig::new();
    let secret = encryption.export_secret_key().clone();
    let enc_a = EncryptionConfig::from_secret_key(secret.clone());
    let enc_b = EncryptionConfig::from_secret_key(secret.clone());

    let bucket = "wal-race-bucket";

    let state_a = tempfile::tempdir().unwrap();
    let state_b = tempfile::tempdir().unwrap();
    let client_a_wal = state_a.path().to_path_buf();
    let client_b_wal = state_b.path().to_path_buf();

    // Seed the bucket with a forest-tracked file on a dedicated state dir so both
    // sides see a non-empty starting forest.
    {
        let _guard = EnvGuard::set("FULA_STATE_DIR", &client_a_wal);
        let seed_client = make_client(&base, EncryptionConfig::from_secret_key(secret.clone()));
        seed_client.create_bucket(bucket).await.expect("create bucket");
        seed_client.put_object_flat(bucket, "/seed.txt", b"seed".to_vec(), None)
            .await.expect("seed");
    }

    // Construct both clients BEFORE either flushes. This is what makes the 412
    // race real: they both pin the same prior_etag at load time; whichever one
    // flushes second must lose on the conditional PUT.
    let client_a = {
        let _guard = EnvGuard::set("FULA_STATE_DIR", &client_a_wal);
        make_client(&base, enc_a)
    };
    let client_b = {
        let _guard = EnvGuard::set("FULA_STATE_DIR", &client_b_wal);
        make_client(&base, enc_b)
    };

    // A loads the forest (pins E_M1).
    {
        let _guard = EnvGuard::set("FULA_STATE_DIR", &client_a_wal);
        let _ = client_a.get_object_flat(bucket, "/seed.txt").await.expect("a read seed");
    }
    // B loads the forest (pins the same E_M1).
    {
        let _guard = EnvGuard::set("FULA_STATE_DIR", &client_b_wal);
        let _ = client_b.get_object_flat(bucket, "/seed.txt").await.expect("b read seed");
    }

    // Both clients stage deferred writes. Their WALs are under their own state
    // dirs, so A's post-flush clear doesn't wipe B's.
    {
        let _guard = EnvGuard::set("FULA_STATE_DIR", &client_a_wal);
        client_a.put_object_flat_deferred(bucket, "/writer-a.txt", b"from-a".to_vec(), None)
            .await.expect("a put");
    }
    {
        let _guard = EnvGuard::set("FULA_STATE_DIR", &client_b_wal);
        client_b.put_object_flat_deferred(bucket, "/writer-b.txt", b"from-b".to_vec(), None)
            .await.expect("b put");
    }

    // A flushes first — its conditional PUT matches E_M1 and wins; S3 manifest
    // advances to E_M2.
    {
        let _guard = EnvGuard::set("FULA_STATE_DIR", &client_a_wal);
        client_a.flush_forest(bucket).await.expect("a flush");
    }

    // B flushes — its prior_etag (E_M1) is now stale → 412, WAL replay, retry
    // against the winning forest.
    {
        let _guard = EnvGuard::set("FULA_STATE_DIR", &client_b_wal);
        client_b.flush_forest(bucket).await.expect("b flush after retry");
    }

    // Fresh reader must see both sides' writes.
    let state_c = tempfile::tempdir().unwrap();
    let _guard = EnvGuard::set("FULA_STATE_DIR", state_c.path());
    let client_c = make_client(&base, EncryptionConfig::from_secret_key(secret));
    let a_body = client_c.get_object_flat(bucket, "/writer-a.txt").await.expect("read a");
    let b_body = client_c.get_object_flat(bucket, "/writer-b.txt").await.expect("read b");
    assert_eq!(a_body.as_ref(), b"from-a", "writer-a content must survive the race");
    assert_eq!(b_body.as_ref(), b"from-b", "writer-b content must survive the race");
}

// ═══════════════════════════════════════════════════════════════════════════
// NEW-7.2 — sharded forest: disjoint-shard writer race + WAL replay
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_412_triggers_wal_replay_sharded() {
    let base = spawn_server().await;

    let encryption = EncryptionConfig::new();
    let secret = encryption.export_secret_key().clone();
    let enc_a = EncryptionConfig::from_secret_key(secret.clone());
    let enc_b = EncryptionConfig::from_secret_key(secret.clone());

    let bucket = "wal-race-sharded";

    let state_a = tempfile::tempdir().unwrap();
    let state_b = tempfile::tempdir().unwrap();
    let client_a_wal = state_a.path().to_path_buf();
    let client_b_wal = state_b.path().to_path_buf();

    // Seed with one forest-tracked file, then force-migrate to sharded before the
    // race so the 412 path exercises save_sharded_forest rather than the monolithic
    // variant.
    {
        let _guard = EnvGuard::set("FULA_STATE_DIR", &client_a_wal);
        let seed_client = make_client(&base, EncryptionConfig::from_secret_key(secret.clone()));
        seed_client.create_bucket(bucket).await.expect("create bucket");
        seed_client.put_object_flat(bucket, "/seed.txt", b"seed".to_vec(), None)
            .await.expect("seed");
        seed_client.migrate_to_sharded(bucket).await.expect("migrate to sharded");
    }

    // Construct both clients first, then load both forests BEFORE either flushes.
    // This is what makes the 412 race real: both pin the same prior_manifest_etag.
    // The loser's phase-2 manifest PUT 412s against the winner's advanced etag;
    // for disjoint-shard writes its phase-1 shard PUT will ALREADY have succeeded,
    // leaving S3 shard seq > winner's manifest shard_sequences[idx]. The retry
    // must reconcile via WAL (see WalEntry::ShardWrote).
    let client_a = {
        let _guard = EnvGuard::set("FULA_STATE_DIR", &client_a_wal);
        make_client(&base, enc_a)
    };
    let client_b = {
        let _guard = EnvGuard::set("FULA_STATE_DIR", &client_b_wal);
        make_client(&base, enc_b)
    };

    // Both clients load the forest (pins same manifest etag).
    {
        let _guard = EnvGuard::set("FULA_STATE_DIR", &client_a_wal);
        let _ = client_a.get_object_flat(bucket, "/seed.txt").await.expect("a read seed");
    }
    {
        let _guard = EnvGuard::set("FULA_STATE_DIR", &client_b_wal);
        let _ = client_b.get_object_flat(bucket, "/seed.txt").await.expect("b read seed");
    }

    // Both stage deferred writes under different parent dirs (v6 routing maps
    // /a/* and /b/* to shards hashed from their parent path → usually disjoint).
    {
        let _guard = EnvGuard::set("FULA_STATE_DIR", &client_a_wal);
        for i in 0..4 {
            client_a.put_object_flat_deferred(
                bucket,
                &format!("/a/{:02}.txt", i),
                format!("a-{}", i).into_bytes(),
                None,
            ).await.expect("a put");
        }
    }
    {
        let _guard = EnvGuard::set("FULA_STATE_DIR", &client_b_wal);
        for i in 0..4 {
            client_b.put_object_flat_deferred(
                bucket,
                &format!("/b/{:02}.txt", i),
                format!("b-{}", i).into_bytes(),
                None,
            ).await.expect("b put");
        }
    }

    // A flushes first — wins the manifest race.
    {
        let _guard = EnvGuard::set("FULA_STATE_DIR", &client_a_wal);
        client_a.flush_forest(bucket).await.expect("a flush");
    }

    // B flushes — its cached manifest_etag is stale, so phase-2 412s. For
    // disjoint-shard writes, phase-1 already succeeded, so S3 shard B is
    // advanced beyond A's manifest view. WAL replay must reconcile.
    {
        let _guard = EnvGuard::set("FULA_STATE_DIR", &client_b_wal);
        client_b.flush_forest(bucket).await.expect("b flush after retry");
    }

    // Fresh reader (fresh state dir) must see both sides' writes.
    let state_c = tempfile::tempdir().unwrap();
    let _guard = EnvGuard::set("FULA_STATE_DIR", state_c.path());
    let client_c = make_client(&base, EncryptionConfig::from_secret_key(secret));
    for i in 0..4 {
        let a = client_c.get_object_flat(bucket, &format!("/a/{:02}.txt", i))
            .await.expect("read a");
        let b = client_c.get_object_flat(bucket, &format!("/b/{:02}.txt", i))
            .await.expect("read b");
        assert_eq!(a.as_ref(), format!("a-{}", i).as_bytes());
        assert_eq!(b.as_ref(), format!("b-{}", i).as_bytes());
    }
}

// Small helper to set FULA_STATE_DIR for the duration of a single test.
// Mutex-serialized to avoid env-var tearing across parallel tests.
struct EnvGuard {
    key: &'static str,
    prior: Option<std::ffi::OsString>,
    _lock: std::sync::MutexGuard<'static, ()>,
}

impl EnvGuard {
    fn set(key: &'static str, value: &std::path::Path) -> Self {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let lock = LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let prior = std::env::var_os(key);
        std::env::set_var(key, value);
        Self { key, prior, _lock: lock }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        match self.prior.take() {
            Some(v) => std::env::set_var(self.key, v),
            None => std::env::remove_var(self.key),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// M-2 — flush_forest retry loop sleeps with jittered backoff on 412 contention
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn flush_forest_backoff_under_contention() {
    // Two writers collide on the same bucket's manifest. The loser must:
    //  (1) retry the flush and succeed (existing NEW-7.2 behavior)
    //  (2) sleep at least 50ms of backoff before its retry PUT (M-2)
    //  (3) increment the observable flush_backoff_count counter (M-2)
    let base = spawn_server().await;

    let encryption = EncryptionConfig::new();
    let secret = encryption.export_secret_key().clone();
    let enc_a = EncryptionConfig::from_secret_key(secret.clone());
    let enc_b = EncryptionConfig::from_secret_key(secret.clone());

    let bucket = "m2-backoff-bucket";

    let state_a = tempfile::tempdir().unwrap();
    let state_b = tempfile::tempdir().unwrap();
    let client_a_wal = state_a.path().to_path_buf();
    let client_b_wal = state_b.path().to_path_buf();

    // Seed the bucket so both clients pin a real prior_etag.
    {
        let _guard = EnvGuard::set("FULA_STATE_DIR", &client_a_wal);
        let seed = make_client(&base, EncryptionConfig::from_secret_key(secret.clone()));
        seed.create_bucket(bucket).await.expect("create bucket");
        seed.put_object_flat(bucket, "/seed.txt", b"seed".to_vec(), None)
            .await.expect("seed");
    }

    let client_a = {
        let _guard = EnvGuard::set("FULA_STATE_DIR", &client_a_wal);
        make_client(&base, enc_a)
    };
    let client_b = {
        let _guard = EnvGuard::set("FULA_STATE_DIR", &client_b_wal);
        make_client(&base, enc_b)
    };

    // Both clients load the forest and pin the same prior_etag.
    {
        let _guard = EnvGuard::set("FULA_STATE_DIR", &client_a_wal);
        let _ = client_a.get_object_flat(bucket, "/seed.txt").await.expect("a read");
    }
    {
        let _guard = EnvGuard::set("FULA_STATE_DIR", &client_b_wal);
        let _ = client_b.get_object_flat(bucket, "/seed.txt").await.expect("b read");
    }

    // Both stage disjoint deferred writes so their flushes are a real race.
    {
        let _guard = EnvGuard::set("FULA_STATE_DIR", &client_a_wal);
        client_a.put_object_flat_deferred(bucket, "/a.txt", b"from-a".to_vec(), None)
            .await.expect("a put");
    }
    {
        let _guard = EnvGuard::set("FULA_STATE_DIR", &client_b_wal);
        client_b.put_object_flat_deferred(bucket, "/b.txt", b"from-b".to_vec(), None)
            .await.expect("b put");
    }

    // Winner flushes first.
    {
        let _guard = EnvGuard::set("FULA_STATE_DIR", &client_a_wal);
        client_a.flush_forest(bucket).await.expect("a flush");
    }

    // Snapshot the backoff counter + wall clock before the loser's flush.
    let backoff_before = fula_client::flush_backoff_count();
    let t0 = std::time::Instant::now();

    // Loser flushes — 412, WAL replay, sleep (M-2), retry against winner.
    {
        let _guard = EnvGuard::set("FULA_STATE_DIR", &client_b_wal);
        client_b.flush_forest(bucket).await.expect("b flush after retry");
    }

    let elapsed = t0.elapsed();
    let backoff_after = fula_client::flush_backoff_count();

    // M-2 assertion 1: the backoff counter advanced (sleep branch was taken).
    assert!(
        backoff_after > backoff_before,
        "flush_backoff_count did not advance: before={} after={}; retry loop did not sleep",
        backoff_before, backoff_after,
    );

    // M-2 assertion 2: at least one sleep of FLUSH_BACKOFF_BASE_MS (50ms)
    // elapsed within the B flush — proves the sleep actually fires, not just
    // that the counter was bumped. Tolerate small timer overshoot.
    assert!(
        elapsed >= std::time::Duration::from_millis(50),
        "B flush finished in {:?} — too fast for a 50ms+ backoff sleep to have fired",
        elapsed,
    );

    // Sanity: both writes survived (existing NEW-7.2 behavior unchanged).
    let state_c = tempfile::tempdir().unwrap();
    let _guard = EnvGuard::set("FULA_STATE_DIR", state_c.path());
    let client_c = make_client(&base, EncryptionConfig::from_secret_key(secret));
    let a = client_c.get_object_flat(bucket, "/a.txt").await.expect("read a");
    let b = client_c.get_object_flat(bucket, "/b.txt").await.expect("read b");
    assert_eq!(a.as_ref(), b"from-a");
    assert_eq!(b.as_ref(), b"from-b");
}
