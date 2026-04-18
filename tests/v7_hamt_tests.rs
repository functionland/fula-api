//! Forest v7 (HAMT-per-shard) integration tests.
//!
//! These tests drive a real `EncryptedClient` against an in-process gateway
//! (`spawn_server`) so the full HTTP + encryption + WAL + storage stack
//! exercises the v7 code paths end-to-end. They assert on the cached forest
//! format after migration to guard against a regression that silently re-routes
//! migrations back to v6 (which would still pass the CRUD tests but defeat the
//! whole point of v7).

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
    config.jwt_secret = Some("test-secret-v7".to_string());

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

/// Serializes mutation of FULA_STATE_DIR across parallel tests.
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
// Test 1 — migrate_to_sharded produces v7 (not v6) and basic CRUD works
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_v7_migration_produces_v7_format() {
    let base = spawn_server().await;
    let encryption = EncryptionConfig::new();
    let bucket = "v7-basic";

    let state = tempfile::tempdir().unwrap();
    let _guard = EnvGuard::set("FULA_STATE_DIR", state.path());

    let client = make_client(&base, encryption);
    client.create_bucket(bucket).await.expect("create bucket");

    client.put_object_flat(bucket, "/hello.txt", b"v1-value".to_vec(), None)
        .await.expect("seed v1 write");

    assert!(
        !client.is_forest_sharded_hamt(bucket),
        "bucket must still be v1 monolithic before migrate"
    );

    client.migrate_to_sharded(bucket).await.expect("migrate to v7");

    assert!(
        client.is_forest_sharded_hamt(bucket),
        "migrate_to_sharded must produce v7 (ShardedHamt), not v6"
    );
    assert!(
        !client.is_forest_sharded(bucket),
        "v7 must not show as v6 (Sharded)"
    );

    // Read after migration: the v1 entry must still be reachable through v7.
    let got = client.get_object_flat(bucket, "/hello.txt")
        .await.expect("read after v7 migration");
    assert_eq!(got.as_ref(), b"v1-value");

    // Write a fresh entry post-migration; it must land in v7 and be readable.
    client.put_object_flat(bucket, "/post-migrate.txt", b"v7-value".to_vec(), None)
        .await.expect("v7 write");
    let got2 = client.get_object_flat(bucket, "/post-migrate.txt")
        .await.expect("v7 read");
    assert_eq!(got2.as_ref(), b"v7-value");
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 2 — list_directory under v7 returns correct files per folder
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_v7_list_directory_correctness() {
    let base = spawn_server().await;
    let encryption = EncryptionConfig::new();
    let bucket = "v7-list";

    let state = tempfile::tempdir().unwrap();
    let _guard = EnvGuard::set("FULA_STATE_DIR", state.path());

    let client = make_client(&base, encryption);
    client.create_bucket(bucket).await.expect("create bucket");

    // Structure:
    //   /docs/a.txt, /docs/b.txt, /docs/c.txt
    //   /media/photos/p1.jpg, /media/photos/p2.jpg
    //   /README.txt
    let docs = ["/docs/a.txt", "/docs/b.txt", "/docs/c.txt"];
    let photos = ["/media/photos/p1.jpg", "/media/photos/p2.jpg"];
    for p in docs.iter().chain(photos.iter()).chain(std::iter::once(&"/README.txt")) {
        client.put_object_flat(bucket, p, p.as_bytes().to_vec(), None)
            .await.expect("seed file");
    }

    client.migrate_to_sharded(bucket).await.expect("migrate to v7");
    assert!(client.is_forest_sharded_hamt(bucket));

    // List /docs — must return exactly the three doc files.
    let docs_listing = client.list_directory(bucket, Some("/docs"))
        .await.expect("list /docs");
    let docs_files: Vec<String> = docs_listing.directories.values()
        .flatten()
        .map(|f| f.original_key.clone())
        .collect();
    for expected in docs.iter() {
        assert!(
            docs_files.iter().any(|f| f == expected),
            "docs listing missing {}, got {:?}", expected, docs_files
        );
    }

    // List /media/photos — must return both photos (and nothing from /docs).
    let photos_listing = client.list_directory(bucket, Some("/media/photos"))
        .await.expect("list /media/photos");
    let photo_files: Vec<String> = photos_listing.directories.values()
        .flatten()
        .map(|f| f.original_key.clone())
        .collect();
    for expected in photos.iter() {
        assert!(
            photo_files.iter().any(|f| f == expected),
            "photos listing missing {}, got {:?}", expected, photo_files
        );
    }
    assert!(
        !photo_files.iter().any(|f| f.starts_with("/docs/")),
        "photos listing leaked /docs content: {:?}", photo_files
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 3 — delete under v7 removes the entry (re-read fails)
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_v7_delete_reread_notfound() {
    let base = spawn_server().await;
    let encryption = EncryptionConfig::new();
    let bucket = "v7-delete";

    let state = tempfile::tempdir().unwrap();
    let _guard = EnvGuard::set("FULA_STATE_DIR", state.path());

    let client = make_client(&base, encryption);
    client.create_bucket(bucket).await.expect("create bucket");

    client.put_object_flat(bucket, "/keep.txt", b"keep".to_vec(), None)
        .await.expect("put keep");
    client.put_object_flat(bucket, "/remove.txt", b"remove".to_vec(), None)
        .await.expect("put remove");

    client.migrate_to_sharded(bucket).await.expect("migrate to v7");
    assert!(client.is_forest_sharded_hamt(bucket));

    // Sanity: both readable before delete.
    client.get_object_flat(bucket, "/keep.txt").await.expect("read keep pre-delete");
    client.get_object_flat(bucket, "/remove.txt").await.expect("read remove pre-delete");

    client.delete_object_flat(bucket, "/remove.txt")
        .await.expect("v7 delete");

    // Deleted entry must be gone.
    let removed_result = client.get_object_flat(bucket, "/remove.txt").await;
    assert!(
        removed_result.is_err(),
        "deleted v7 entry must not be readable, got {:?}",
        removed_result.map(|b| b.len())
    );

    // Sibling must survive the delete.
    let keep = client.get_object_flat(bucket, "/keep.txt")
        .await.expect("sibling entry must still be readable");
    assert_eq!(keep.as_ref(), b"keep");
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 4 — a fresh client with a new state dir can read a migrated v7 forest
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_v7_fresh_client_reads_migrated_bucket() {
    let base = spawn_server().await;
    let encryption = EncryptionConfig::new();
    let secret = encryption.export_secret_key().clone();
    let bucket = "v7-fresh-reader";

    // Writer populates the bucket and migrates.
    {
        let state = tempfile::tempdir().unwrap();
        let _guard = EnvGuard::set("FULA_STATE_DIR", state.path());
        let writer = make_client(&base, EncryptionConfig::from_secret_key(secret.clone()));
        writer.create_bucket(bucket).await.expect("create bucket");

        for i in 0..8 {
            writer.put_object_flat(
                bucket,
                &format!("/data/item-{:02}.bin", i),
                format!("payload-{}", i).into_bytes(),
                None,
            ).await.expect("seed");
        }

        writer.migrate_to_sharded(bucket).await.expect("migrate to v7");
        assert!(writer.is_forest_sharded_hamt(bucket));
    }

    // Fresh client, fresh state dir — no in-memory cache, must load v7 from S3.
    let state_r = tempfile::tempdir().unwrap();
    let _guard = EnvGuard::set("FULA_STATE_DIR", state_r.path());
    let reader = make_client(&base, EncryptionConfig::from_secret_key(secret));

    for i in 0..8 {
        let got = reader.get_object_flat(bucket, &format!("/data/item-{:02}.bin", i))
            .await.expect("fresh reader v7 get");
        assert_eq!(got.as_ref(), format!("payload-{}", i).as_bytes());
    }

    // After the first load, the fresh client must have cached v7 (not v6).
    assert!(
        reader.is_forest_sharded_hamt(bucket),
        "fresh client must load the migrated bucket as v7"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 5 — pre-v3 monolithic (v1) buckets stay v1 when they never cross the
// migration threshold. Guards task #27: the user base is 100% on v1; a
// regression that auto-migrates small buckets to v7 would break compatibility
// with pre-v7 clients that can only read v1.
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_v1_stays_v1_below_threshold() {
    let base = spawn_server().await;
    let encryption = EncryptionConfig::new();
    let bucket = "v1-stays-v1";

    let state = tempfile::tempdir().unwrap();
    let _guard = EnvGuard::set("FULA_STATE_DIR", state.path());

    let client = make_client(&base, encryption);
    client.create_bucket(bucket).await.expect("create bucket");

    // Write a handful of files — well under the 5,000 SHARDED_MIGRATION_THRESHOLD.
    for i in 0..25 {
        client.put_object_flat(
            bucket,
            &format!("/file-{:03}.txt", i),
            format!("body-{}", i).into_bytes(),
            None,
        ).await.expect("put");
    }

    // Read a few back to force forest load/cache hydration paths.
    for i in [0, 7, 24] {
        let got = client.get_object_flat(bucket, &format!("/file-{:03}.txt", i))
            .await.expect("read");
        assert_eq!(got.as_ref(), format!("body-{}", i).as_bytes());
    }

    // The bucket must NOT have been auto-migrated. Both sharded variants must
    // be false (i.e. the cache entry is still a monolithic forest).
    assert!(
        !client.is_forest_sharded(bucket),
        "small bucket must not auto-migrate to v6"
    );
    assert!(
        !client.is_forest_sharded_hamt(bucket),
        "small bucket must not auto-migrate to v7"
    );

    // Delete + re-read still works on v1.
    client.delete_object_flat(bucket, "/file-007.txt")
        .await.expect("v1 delete");
    let deleted = client.get_object_flat(bucket, "/file-007.txt").await;
    assert!(deleted.is_err(), "deleted v1 entry must not be readable");

    // Still v1 after a delete.
    assert!(!client.is_forest_sharded_hamt(bucket));
    assert!(!client.is_forest_sharded(bucket));
}
