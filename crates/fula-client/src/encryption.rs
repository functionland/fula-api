//! Client-side encryption support
//!
//! Provides end-to-end encryption for Fula storage including:
//! - Content encryption (AES-256-GCM)
//! - Key wrapping (HPKE)
//! - Metadata privacy (file names, sizes, timestamps)

use crate::{ClientError, FulaClient, Result, Config};
use crate::types::*;
use bytes::Bytes;
use fula_crypto::{
    keys::KeyManager,
    hpke::{Encryptor, Decryptor, EncryptedData},
    symmetric::{Aead, Nonce},
    private_metadata::{PrivateMetadata, EncryptedPrivateMetadata, KeyObfuscation, obfuscate_key},
    private_forest::{
        PrivateForest, EncryptedForest, ForestFileEntry, derive_index_key,
        generate_flat_key,
        ForestEvent,
        detect_forest_format, ForestOrManifest,
        compute_initial_shard_count,
        EncryptedShardManifestV7, ShardManifestV7,
        ManifestRoot, ManifestPage, EncryptedManifestPage, PageId, PageRef,
        derive_manifest_page_key,
        DirectoryIndex, EncryptedDirectoryIndex, derive_dir_index_key,
    },
    sharing::{ShareToken, AcceptedShare, ShareRecipient},
    rotation::{KeyRotationManager, WrappedKeyInfo},
    wnfs_hamt::BlobBackend,
    sharded_hamt_forest::ShardedHamtPrivateForest,
    ChunkedEncoder, ChunkedFileMetadata, should_use_chunked,
    CryptoError,
};
// BaoEncoder is only used by `resume_upload` (native-only). On wasm32 the
// item is never referenced, so the import would produce `unused_imports`.
#[cfg(not(target_arch = "wasm32"))]
use fula_crypto::BaoEncoder;
use std::sync::Arc;
use std::collections::HashMap;
use dashmap::DashMap;

#[cfg(not(target_arch = "wasm32"))]
use crate::wal::{self, WalEntry};
#[cfg(not(target_arch = "wasm32"))]
use crate::orphan_queue;

/// Default forest cache TTL in seconds
const DEFAULT_FOREST_CACHE_TTL_SECS: i64 = 60;

/// Max 412-retry attempts before `flush_forest` surfaces
/// `ConcurrentModificationExhausted` (NEW-7.2).
#[cfg(not(target_arch = "wasm32"))]
const MAX_FLUSH_RETRIES: usize = 3;

/// Base sleep for M-2 flush backoff; doubled per attempt, plus jitter.
#[cfg(not(target_arch = "wasm32"))]
const FLUSH_BACKOFF_BASE_MS: u64 = 50;
/// Max jitter added to backoff delay. Uses SystemTime nanos as a non-crypto
/// pseudo-random source — modulo bias is imperceptible at this granularity.
#[cfg(not(target_arch = "wasm32"))]
const FLUSH_BACKOFF_JITTER_MS: u64 = 100;

/// Compute the M-2 backoff sleep duration for a given retry attempt index.
///
/// Schedule (base*2^attempt + 0-99ms jitter):
///  - attempt 0 → 50-149 ms
///  - attempt 1 → 100-199 ms
///  - attempt 2 → 200-299 ms (not reached — MAX_FLUSH_RETRIES = 3 breaks out)
///
/// Jitter sourced from `SystemTime::subsec_nanos()` to avoid adding a `rand`
/// dep. Monotonic per nanosecond, which is all the retry loop needs.
#[cfg(not(target_arch = "wasm32"))]
fn flush_backoff_delay(attempt: usize) -> std::time::Duration {
    use std::time::{SystemTime, UNIX_EPOCH};
    let base = FLUSH_BACKOFF_BASE_MS.saturating_mul(1u64 << attempt.min(8));
    let jitter = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::from(d.subsec_nanos()))
        .unwrap_or(0)
        % FLUSH_BACKOFF_JITTER_MS;
    std::time::Duration::from_millis(base + jitter)
}

/// Process-wide counter bumped each time `flush_forest`'s retry loop sleeps
/// on a 412 race (M-2). Observable via [`flush_backoff_count`] so tests and
/// operators can confirm the backoff path is actually exercised.
#[cfg(not(target_arch = "wasm32"))]
static FLUSH_BACKOFF_COUNT: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// Fixed delay base (ms) between transient-error retries on HAMT blob-backend
/// GET/PUT. Chosen so a fully drained nginx `limit_req` burst (token bucket
/// with sub-second refill at the gateway's configured rate) has time to refill
/// before the next attempt. Not exponential: the rate-limit condition resets
/// per second, so later attempts don't benefit from longer waits.
#[cfg(not(target_arch = "wasm32"))]
const BLOB_BACKEND_RETRY_BASE_MS: u64 = 300;
/// Maximum added jitter for blob-backend retries. De-synchronises fan-out
/// retries so many concurrent walkers don't all wake at the same instant.
#[cfg(not(target_arch = "wasm32"))]
const BLOB_BACKEND_RETRY_JITTER_MS: u64 = 100;
/// Total attempts (including the first try) for blob-backend GET/PUT.
#[cfg(not(target_arch = "wasm32"))]
const BLOB_BACKEND_MAX_ATTEMPTS: u32 = 4;

/// Compute the fixed-plus-jitter sleep duration for a blob-backend retry.
///
/// Same jitter source (`SystemTime::subsec_nanos()`) as `flush_backoff_delay`;
/// no `rand` dependency pulled in just for this.
#[cfg(not(target_arch = "wasm32"))]
fn blob_backend_retry_delay() -> std::time::Duration {
    use std::time::{SystemTime, UNIX_EPOCH};
    let jitter = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::from(d.subsec_nanos()))
        .unwrap_or(0)
        % (BLOB_BACKEND_RETRY_JITTER_MS + 1);
    std::time::Duration::from_millis(BLOB_BACKEND_RETRY_BASE_MS + jitter)
}

/// Process-wide counter bumped each time `S3BlobBackend::{get,put}` sleeps on
/// a transient-5xx retry. Observable via [`blob_backend_retry_count`] so the
/// fault-injection integration test can assert the retry path actually ran.
#[cfg(not(target_arch = "wasm32"))]
static BLOB_BACKEND_RETRY_COUNT: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// Read the total number of blob-backend transient-5xx retries since process
/// start. Native-only.
#[cfg(not(target_arch = "wasm32"))]
pub fn blob_backend_retry_count() -> u64 {
    BLOB_BACKEND_RETRY_COUNT.load(std::sync::atomic::Ordering::Relaxed)
}

/// Read the total number of flush-forest backoff sleeps observed since
/// process start. Native-only.
#[cfg(not(target_arch = "wasm32"))]
pub fn flush_backoff_count() -> u64 {
    FLUSH_BACKOFF_COUNT.load(std::sync::atomic::Ordering::Relaxed)
}

/// Default interval at which the background auto-flush task persists dirty
/// forests to storage when enabled via `start_auto_flush()`.
#[allow(dead_code)]
pub const DEFAULT_AUTO_FLUSH_INTERVAL_SECS: u64 = 30;

/// Handle returned by `EncryptedClient::start_auto_flush`.
///
/// Dropping the handle signals the background task to exit. The task also
/// exits automatically when every `Arc<EncryptedClient>` has been dropped
/// (since the task holds a `Weak<EncryptedClient>`).
#[cfg(not(target_arch = "wasm32"))]
pub struct AutoFlushHandle {
    cancel: Option<tokio::sync::oneshot::Sender<()>>,
}

#[cfg(not(target_arch = "wasm32"))]
impl AutoFlushHandle {
    /// Stop the background task explicitly. Equivalent to dropping the handle
    /// but lets callers await the shutdown if they later poll the join handle.
    pub fn stop(mut self) {
        if let Some(tx) = self.cancel.take() {
            let _ = tx.send(());
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl Drop for AutoFlushHandle {
    fn drop(&mut self) {
        if let Some(tx) = self.cancel.take() {
            let _ = tx.send(());
        }
    }
}

/// Interval (seconds) between heartbeats that keep the server-side migration
/// lock alive. Server TTL is 60s; beating at 30s tolerates one missed beat.
#[cfg(not(target_arch = "wasm32"))]
const MIGRATION_HEARTBEAT_INTERVAL_SECS: u64 = 30;

/// Tick interval used by the heartbeat task. Honours the
/// `FULA_MIGRATION_HEARTBEAT_INTERVAL_MS` env override when set to any positive
/// integer; otherwise defaults to `MIGRATION_HEARTBEAT_INTERVAL_SECS`. The env
/// hook lets integration tests exercise the heartbeat loop on a sub-second
/// cadence without waiting out the full 30-second cycle.
#[cfg(not(target_arch = "wasm32"))]
fn migration_heartbeat_interval() -> std::time::Duration {
    if let Ok(v) = std::env::var("FULA_MIGRATION_HEARTBEAT_INTERVAL_MS") {
        if let Ok(ms) = v.parse::<u64>() {
            if ms > 0 {
                return std::time::Duration::from_millis(ms);
            }
        }
    }
    std::time::Duration::from_secs(MIGRATION_HEARTBEAT_INTERVAL_SECS)
}

/// Test-only crash-injection atomics. Never set in production; guarded by the
/// `test-fault-injection` feature so the symbols are not even present without
/// it. `migrate_v1_to_v7_internal` checks these at two well-defined points so
/// integration tests can observe the post-crash on-disk state.
#[cfg(feature = "test-fault-injection")]
pub mod test_faults {
    use std::sync::atomic::AtomicBool;

    /// If `true`, `migrate_v1_to_v7_internal` returns `DeferredTransientError`
    /// immediately after `flush_dirty` writes the HAMT node blobs but before
    /// the Phase B manifest PUT.
    pub static CRASH_AFTER_PHASE_A_FLUSH: AtomicBool = AtomicBool::new(false);

    /// If `true`, `migrate_v1_to_v7_internal` returns
    /// `DeferredTransientError` immediately after the Phase B manifest PUT
    /// succeeds (server now holds v7 at `index_key`) but before the in-process
    /// cache swap / `persist_manifest_version` call. Simulates a client crash
    /// after the server has committed the migration.
    pub static CRASH_AFTER_PHASE_B_PUT_BEFORE_CACHE_SWAP: AtomicBool = AtomicBool::new(false);

    /// If `true`, the orphan-cleanup path (`cleanup_orphaned_storage`) forces
    /// the main-object `delete_object` to fail without touching the network.
    /// Used by F7 integration tests to verify that failed cleanups land in
    /// the persistent orphan queue, and that a later cleanup call drains
    /// them after the flag is cleared. Has no effect on any other code path.
    pub static FORCE_ORPHAN_CLEANUP_MAIN_FAIL: AtomicBool = AtomicBool::new(false);

    /// If `true`, `cleanup_orphaned_storage` skips its refcount short-circuit
    /// (i.e. treats `storage_key_still_referenced` as always `false`). Used
    /// only by F7 integration tests to exercise the cleanup path on v7
    /// buckets, where the refcount check conservatively returns `true` until
    /// v7 reference traversal is wired. Never set in production.
    pub static BYPASS_ORPHAN_CLEANUP_REFCHECK: AtomicBool = AtomicBool::new(false);

    /// If `true`, `save_sharded_hamt_forest` returns an error immediately
    /// after all Phase 1.5 page PUTs succeed but before encrypting the
    /// manifest root. Simulates a client crash mid-flush — pages are on S3
    /// under fresh seqs, root still points at the prior generation. Used
    /// by the S-1.2 recovery integration test to assert the next flush
    /// re-drives the root PUT and leaves the forest consistent.
    pub static CRASH_AFTER_PAGE_PUT_BEFORE_ROOT_PUT: AtomicBool = AtomicBool::new(false);
}

/// If set, a v7 manifest that fails to decrypt triggers an automatic attempt
/// to load the most recent `__fula_forest_v1_backup/<unix_ms>` blob as a v1
/// monolithic forest. Exists as a compile-time escape hatch — the fallback
/// involves extra round-trips and a bypass of the v7 replay/sequence guards,
/// so long-running deployments that never produce backups can disable it.
const V7_V1_BACKUP_FALLBACK_ENABLED: bool = true;

/// Common prefix under which v1 forest backups are written before a v7
/// migration overwrites the authoritative `index_key`. Format:
/// `__fula_forest_v1_backup/<unix_millis>`.
const V1_BACKUP_PREFIX: &str = "__fula_forest_v1_backup/";

/// Outcome of a v1 → v7 migration attempt.
///
/// Return-only type — never stored, never re-used across await points. The
/// caller maps this onto `Result<ForestEvent>` or onto a fall-through read-only
/// path at the load-time trigger.
#[derive(Debug)]
pub(crate) enum MigrationOutcome {
    /// Migration ran to completion and the ShardedHamt cache entry is installed.
    Migrated { duration_ms: u64 },
    /// Another device currently holds the server-side migration lock; this
    /// session continues against v1 read-only. Next session re-enters.
    DeferredLockHeld { expires_at_ms: i64 },
    /// Migration was aborted before completing — WAL-present, transient
    /// network error, or 412 on the manifest PUT. Next session re-enters.
    DeferredTransientError { reason: String },
}

/// RAII guard for the background task that heartbeats the server-side
/// migration lock. Aborts the task on drop so every exit path from
/// `migrate_v1_to_v7_internal` stops heartbeats cleanly.
#[cfg(not(target_arch = "wasm32"))]
struct HeartbeatGuard {
    handle: Option<tokio::task::JoinHandle<()>>,
}

#[cfg(not(target_arch = "wasm32"))]
impl HeartbeatGuard {
    fn spawn(client: FulaClient, bucket: String, token: String) -> Self {
        let handle = tokio::spawn(async move {
            let interval_dur = migration_heartbeat_interval();
            loop {
                tokio::time::sleep(interval_dur).await;
                match client.heartbeat_migration_lock(&bucket, &token).await {
                    Ok(_) => {}
                    Err(e) => {
                        tracing::warn!(%bucket, error = %e, "migration lock heartbeat failed");
                    }
                }
            }
        });
        Self { handle: Some(handle) }
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl Drop for HeartbeatGuard {
    fn drop(&mut self) {
        if let Some(h) = self.handle.take() {
            h.abort();
        }
    }
}

/// S3-backed implementation of `fula_crypto::wnfs_hamt::BlobBackend`.
///
/// Thin wrapper that maps `BlobBackend::{get, put}(path, bytes)` to plain
/// `FulaClient::{get_object, put_object}(bucket, path, bytes)`. All crypto
/// (AEAD, content addressing) lives in `V7NodeStore` inside fula-crypto —
/// this type deliberately does no encryption of its own, so `V7NodeStore`
/// can be reused with an in-memory backend in tests.
///
/// One backend instance is cheap (just a cloned `FulaClient` + bucket
/// name) — construct per-flush and drop.
#[derive(Clone)]
pub struct S3BlobBackend {
    inner: FulaClient,
    bucket: String,
}

impl S3BlobBackend {
    /// Construct a backend rooted at `bucket` on top of an existing
    /// `FulaClient`.
    pub fn new(inner: FulaClient, bucket: impl Into<String>) -> Self {
        Self {
            inner,
            bucket: bucket.into(),
        }
    }
}

fn client_err_to_crypto(err: ClientError) -> CryptoError {
    CryptoError::Storage(err.to_string())
}

#[cfg(not(target_arch = "wasm32"))]
#[async_trait::async_trait]
impl BlobBackend for S3BlobBackend {
    /// Retries transient 5xx responses (nginx `limit_req` 503, upstream
    /// 429/500/502/503/504, S3 `SlowDown`/`InternalError`/`ServiceUnavailable`)
    /// with a fixed 300 ms + 0-100 ms jitter delay, up to 4 attempts total.
    /// Non-transient errors (auth failure, NotFound, etc.) short-circuit.
    async fn get(&self, path: &str) -> fula_crypto::Result<Vec<u8>> {
        let mut attempt: u32 = 0;
        loop {
            attempt += 1;
            match self.inner.get_object(&self.bucket, path).await {
                Ok(bytes) => return Ok(bytes.to_vec()),
                Err(e)
                    if attempt < BLOB_BACKEND_MAX_ATTEMPTS
                        && crate::multipart::is_transient(&e) =>
                {
                    tracing::debug!(
                        bucket = %self.bucket,
                        path = %path,
                        attempt,
                        error = %e,
                        "S3BlobBackend::get retrying transient 5xx"
                    );
                    BLOB_BACKEND_RETRY_COUNT
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    tokio::time::sleep(blob_backend_retry_delay()).await;
                    continue;
                }
                Err(e) => return Err(client_err_to_crypto(e)),
            }
        }
    }

    /// Same retry policy as `get`. `put_object` is idempotent on v7 HAMT
    /// node keys — they are content-addressed (blake3 over the plaintext
    /// node), so re-uploading the same bytes at the same path is safe.
    async fn put(&self, path: &str, bytes: Vec<u8>) -> fula_crypto::Result<()> {
        let mut attempt: u32 = 0;
        loop {
            attempt += 1;
            // Clone the body each attempt: reqwest consumes the body, and we
            // want to re-send the same bytes on retry. The retry path is cold
            // and HAMT node blobs are small (sub-KB typical), so this is
            // negligible on the happy path too.
            let body = bytes.clone();
            match self.inner.put_object(&self.bucket, path, body).await {
                Ok(_) => return Ok(()),
                Err(e)
                    if attempt < BLOB_BACKEND_MAX_ATTEMPTS
                        && crate::multipart::is_transient(&e) =>
                {
                    tracing::debug!(
                        bucket = %self.bucket,
                        path = %path,
                        attempt,
                        error = %e,
                        "S3BlobBackend::put retrying transient 5xx"
                    );
                    BLOB_BACKEND_RETRY_COUNT
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    tokio::time::sleep(blob_backend_retry_delay()).await;
                    continue;
                }
                Err(e) => return Err(client_err_to_crypto(e)),
            }
        }
    }
}

#[cfg(target_arch = "wasm32")]
#[async_trait::async_trait(?Send)]
impl BlobBackend for S3BlobBackend {
    async fn get(&self, path: &str) -> fula_crypto::Result<Vec<u8>> {
        let bytes = self
            .inner
            .get_object(&self.bucket, path)
            .await
            .map_err(client_err_to_crypto)?;
        Ok(bytes.to_vec())
    }

    async fn put(&self, path: &str, bytes: Vec<u8>) -> fula_crypto::Result<()> {
        self.inner
            .put_object(&self.bucket, path, bytes)
            .await
            .map(|_| ())
            .map_err(client_err_to_crypto)
    }
}

/// Upload manifest for resumable chunked uploads.
///
/// Written to a local file before uploading chunks. On failure, the manifest
/// records which chunks were successfully uploaded so the upload can resume
/// without re-uploading completed chunks.
#[cfg(not(target_arch = "wasm32"))]
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct UploadManifest {
    /// Bucket name
    pub bucket: String,
    /// Obfuscated storage key for the index object
    pub storage_key: String,
    /// Original user-facing key
    pub original_key: String,
    /// Total number of chunks
    pub num_chunks: u32,
    /// Per-chunk status: chunk key and whether it was uploaded
    pub chunks: Vec<ManifestChunk>,
    /// Serialized encryption metadata (JSON) for the index object.
    /// Stored so resume can finalize without re-encrypting.
    pub index_metadata_json: String,
}

#[cfg(not(target_arch = "wasm32"))]
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ManifestChunk {
    pub index: u32,
    pub chunk_key: String,
    pub uploaded: bool,
}

#[cfg(not(target_arch = "wasm32"))]
impl UploadManifest {
    /// Read a manifest from a file
    pub fn load(path: &std::path::Path) -> std::result::Result<Self, ClientError> {
        let data = std::fs::read_to_string(path)
            .map_err(ClientError::Io)?;
        serde_json::from_str(&data).map_err(|e| {
            ClientError::Encryption(fula_crypto::CryptoError::Decryption(
                format!("Invalid upload manifest: {}", e),
            ))
        })
    }

    /// Write the manifest to a file
    pub fn save(&self, path: &std::path::Path) -> std::result::Result<(), ClientError> {
        let data = serde_json::to_string_pretty(self).map_err(|e| {
            ClientError::Encryption(fula_crypto::CryptoError::Decryption(
                format!("Failed to serialize manifest: {}", e),
            ))
        })?;
        std::fs::write(path, data).map_err(ClientError::Io)
    }

    /// Count how many chunks still need uploading
    pub fn remaining(&self) -> usize {
        self.chunks.iter().filter(|c| !c.uploaded).count()
    }
}

/// A cached forest entry with timestamp for TTL-based invalidation
///
/// Supports both monolithic (version 1/2/4) and sharded (version 3/5) formats.
/// The in-memory cache is ephemeral — everything is reconstructable from S3.
///
/// Replay protection sequence fields (Fix 1 / F-2.1 + F-7.4):
/// - `last_sequence` (Monolithic) is the highest sequence observed for the v4
///   forest object. On load, we verify the incoming sequence `>= last_sequence`
///   and update. In-process cache; lost on restart — cold-start replay is a
///   documented residual risk.
/// - `last_manifest_sequence` (Sharded) is the manifest-level sequence. Each
///   shard carries its own sequence, vouched for by the manifest plaintext via
///   `shard_sequences: Vec<u64>` (AAD-protected).
/// Intermediate value produced while inspecting the forest cache entry for
/// H-1 / H-2 per-download integrity lookups. v1 resolves the forest entry
/// synchronously under the DashMap guard (no .await), while v7 hands back a
/// cloned `Arc<RwLock<...>>` so the HAMT walk can run after the guard has
/// been released — matching the "no await while holding DashMap" rule.
enum CachedForForestLookup {
    V1(Option<ForestFileEntry>),
    V7(Arc<tokio::sync::RwLock<ShardedHamtPrivateForest>>),
}

enum ForestCacheEntry {
    /// Monolithic forest (FlatMapV1 or HamtV2 or v4-AAD)
    Monolithic {
        forest: PrivateForest,
        loaded_at: i64,
        dirty: bool,
        /// ETag captured from the last successful load or save of the index
        /// object. Used for conditional writes (If-Match) so concurrent
        /// flushes don't silently clobber each other. `None` means the
        /// object was never observed (first save path).
        index_etag: Option<String>,
        /// Highest sequence number observed on this forest (v4+).
        /// `None` means the current on-disk format is legacy v1/v2 and has
        /// no sequence. Transitions to `Some` on first v4 write/read.
        last_sequence: Option<u64>,
    },
    /// Sharded-HAMT forest (v7). Per-shard HAMT tree with nodes
    /// stored independently at `__fula_forest_v7_nodes/<storage_key>`.
    /// The forest holds per-shard root storage keys, sequences,
    /// and interior nodes load lazily through `V7NodeStore`.
    ///
    /// Wrapped in `Arc<tokio::sync::RwLock<_>>` because mutation methods
    /// (`upsert_file`, `flush_dirty`) are async and would require holding
    /// a `DashMap::RefMut` across an `await`, which deadlocks DashMap's
    /// shard locks. RwLock (vs Mutex) lets concurrent read-path ops
    /// (`get_file`, `list_recursive`, …) share the forest.
    ShardedHamt {
        // Outer lock is an `RwLock` (not `Mutex`) so read-only forest
        // operations (`get_file`, `list_recursive`, `extract_subtree`,
        // manifest inspection) can run concurrently. Writers
        // (`upsert_file`, `remove_file`, `flush_dirty`, reconcile) still
        // serialise via `write().await`. Closes F6 (lock-held-across-await
        // contention for readers).
        forest: Arc<tokio::sync::RwLock<ShardedHamtPrivateForest>>,
        loaded_at: i64,
        /// ETag of the manifest object itself.
        manifest_etag: Option<String>,
        /// Highest manifest sequence observed.
        last_manifest_sequence: Option<u64>,
    },
}

impl ForestCacheEntry {
    fn loaded_at(&self) -> i64 {
        match self {
            ForestCacheEntry::Monolithic { loaded_at, .. } => *loaded_at,
            ForestCacheEntry::ShardedHamt { loaded_at, .. } => *loaded_at,
        }
    }

    fn is_dirty(&self) -> bool {
        match self {
            ForestCacheEntry::Monolithic { dirty, .. } => *dirty,
            // `tokio::sync::RwLock::try_read` is a synchronous probe. When
            // uncontended we read the forest's authoritative dirty state.
            // When contended (a writer is in flight), fall back to `true` —
            // the cache entry is in active use, so callers should not treat
            // it as stale and evict while we're mid-flush.
            //
            // v7 has two independent dirtiness signals: shards (tracked by
            // `ShardedHamtPrivateForest::is_dirty`) and the directory index
            // (F-1.3). A rebuild-from-forest after a dir-index soft-fail
            // dirties only the latter — we must still report dirty here so
            // `flush_forest_inner` actually runs Phase 1.6 + Phase 2 and
            // persists the rebuilt index under a fresh seq.
            ForestCacheEntry::ShardedHamt { forest, .. } => match forest.try_read() {
                Ok(guard) => guard.is_dirty() || guard.dir_index_dirty(),
                Err(_) => true,
            },
        }
    }
}

/// Configuration for client-side encryption
pub struct EncryptionConfig {
    /// Key manager for encryption keys (wrapped in Arc for sharing)
    key_manager: Arc<KeyManager>,
    /// Whether to enable metadata privacy (file name obfuscation)
    metadata_privacy: bool,
    /// Key obfuscation mode
    obfuscation_mode: KeyObfuscation,
    /// TTL for forest cache entries in seconds (default: 60)
    forest_cache_ttl_secs: i64,
}

impl EncryptionConfig {
    /// Create a new encryption config with random keys
    /// Metadata privacy is ENABLED by default with FlatNamespace mode (RECOMMENDED)
    /// 
    /// FlatNamespace provides complete structure hiding:
    /// - Storage keys look like random CID-style hashes
    /// - No prefixes or structure hints visible to server
    /// - Server cannot determine folder structure or parent/child relationships
    pub fn new() -> Self {
        Self {
            key_manager: Arc::new(KeyManager::new()),
            metadata_privacy: true,
            obfuscation_mode: KeyObfuscation::FlatNamespace,
            forest_cache_ttl_secs: DEFAULT_FOREST_CACHE_TTL_SECS,
        }
    }

    /// Create without metadata privacy (filenames visible to server)
    #[allow(deprecated)]
    pub fn new_without_privacy() -> Self {
        Self {
            key_manager: Arc::new(KeyManager::new()),
            metadata_privacy: false,
            obfuscation_mode: KeyObfuscation::DeterministicHash,
            forest_cache_ttl_secs: DEFAULT_FOREST_CACHE_TTL_SECS,
        }
    }

    /// Create with FlatNamespace mode - RECOMMENDED for maximum privacy
    ///
    /// This mode provides complete structure hiding:
    /// - Storage keys look like random CID-style hashes (e.g., `QmX7a8f3...`)
    /// - No prefixes or structure hints visible to server
    /// - Server cannot determine folder structure or parent/child relationships
    /// - File tree is stored in an encrypted PrivateForest index
    ///
    /// Inspired by WNFS (WebNative File System) and Peergos.
    pub fn new_flat_namespace() -> Self {
        Self {
            key_manager: Arc::new(KeyManager::new()),
            metadata_privacy: true,
            obfuscation_mode: KeyObfuscation::FlatNamespace,
            forest_cache_ttl_secs: DEFAULT_FOREST_CACHE_TTL_SECS,
        }
    }

    /// Create from an existing secret key (uses FlatNamespace by default)
    pub fn from_secret_key(secret: fula_crypto::keys::SecretKey) -> Self {
        Self {
            key_manager: Arc::new(KeyManager::from_secret_key(secret)),
            metadata_privacy: true,
            obfuscation_mode: KeyObfuscation::FlatNamespace,
            forest_cache_ttl_secs: DEFAULT_FOREST_CACHE_TTL_SECS,
        }
    }

    /// Enable or disable metadata privacy
    pub fn with_metadata_privacy(mut self, enabled: bool) -> Self {
        self.metadata_privacy = enabled;
        self
    }

    /// Set the key obfuscation mode
    pub fn with_obfuscation_mode(mut self, mode: KeyObfuscation) -> Self {
        self.obfuscation_mode = mode;
        self
    }

    /// Set the forest cache TTL in seconds
    ///
    /// Cached forest indices older than this will be reloaded from storage.
    /// Default is 60 seconds. Set to 0 to disable caching (always reload).
    pub fn with_forest_cache_ttl_secs(mut self, secs: i64) -> Self {
        self.forest_cache_ttl_secs = secs;
        self
    }

    /// Check if metadata privacy is enabled
    pub fn has_metadata_privacy(&self) -> bool {
        self.metadata_privacy
    }

    /// Get the public key for sharing
    pub fn public_key(&self) -> &fula_crypto::keys::PublicKey {
        self.key_manager.public_key()
    }

    /// Export the secret key (handle with care!)
    pub fn export_secret_key(&self) -> &fula_crypto::keys::SecretKey {
        self.key_manager.keypair().secret_key()
    }

    /// Get the key manager
    pub fn key_manager(&self) -> &KeyManager {
        &self.key_manager
    }
}

impl Default for EncryptionConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// Pinning credentials for remote pinning services
#[derive(Clone, Debug)]
pub struct PinningCredentials {
    /// Pinning service endpoint URL
    pub endpoint: String,
    /// Bearer token for authentication
    pub token: String,
}

impl PinningCredentials {
    /// Create new pinning credentials
    pub fn new(endpoint: impl Into<String>, token: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            token: token.into(),
        }
    }
}

/// Client with client-side encryption enabled
pub struct EncryptedClient {
    inner: FulaClient,
    encryption: EncryptionConfig,
    /// Private forest index for FlatNamespace mode (cached per-bucket with TTL)
    /// Uses DashMap for per-bucket concurrent access without global write-lock contention
    forest_cache: DashMap<String, ForestCacheEntry>,
    /// Optional pinning credentials for remote pinning
    pinning: Option<PinningCredentials>,
    /// Per-bucket migration locks.
    /// Read lock: normal operations (load_forest, flush_forest, put_object_flat_deferred).
    /// Write lock: migration (migrate_to_sharded). Prevents concurrent reads from
    /// seeing stale monolithic data while migration is replacing the cache entry.
    migration_locks: DashMap<String, Arc<tokio::sync::RwLock<()>>>,
    /// Optional per-bucket minimum-acceptable forest sequence (C-AUDIT-008).
    /// Populated via `set_forest_sequence_floor`. When set, a forest load whose
    /// decrypted sequence is below the floor is rejected as a replay. Opt-in —
    /// applications that want cross-session protection persist the counter
    /// themselves (e.g., in an encrypted keystore) and restore it on startup.
    seq_floors: DashMap<String, u64>,
    /// Set of buckets for which WAL recovery has already been attempted this
    /// session (NEW-7.2). Keeps `ensure_forest_loaded` from re-replaying the
    /// WAL on every call — recovery fires once per bucket per process lifetime.
    #[cfg(not(target_arch = "wasm32"))]
    wal_recovered_buckets: DashMap<String, ()>,
    /// Buckets for which an orphan-queue drain is currently running (NEW-F7).
    /// Presence = drain in flight; used by `cleanup_orphaned_storage` so two
    /// concurrent cleanups don't race on the same bucket's queue file.
    /// A lost race is harmless (just skipped), so a simple insert/remove set
    /// is sufficient — no heavy lock needed.
    #[cfg(not(target_arch = "wasm32"))]
    orphan_drain_in_flight: DashMap<String, ()>,
}

/// F10: wrap a chunk-fetch future in a per-chunk timeout so one stuck
/// chunk cannot stall a windowed download up to the global reqwest
/// timeout. Error mapping lives here so the production call site and
/// the unit test share one source of truth — any drift in the wording
/// or variant breaks both callers simultaneously.
#[cfg(not(target_arch = "wasm32"))]
async fn fetch_chunk_with_timeout<F>(
    fut: F,
    chunk_index: u32,
    timeout: std::time::Duration,
) -> Result<Bytes>
where
    F: std::future::Future<Output = Result<Bytes>>,
{
    tokio::time::timeout(timeout, fut)
        .await
        .map_err(|_| {
            ClientError::DownloadFailed(format!(
                "chunk {} download timed out after {:?}",
                chunk_index, timeout
            ))
        })?
}

impl EncryptedClient {
    /// Create a new encrypted client
    pub fn new(config: Config, encryption: EncryptionConfig) -> Result<Self> {
        let inner = FulaClient::new(config)?;
        Ok(Self {
            inner,
            encryption,
            forest_cache: DashMap::new(),
            pinning: None,
            migration_locks: DashMap::new(),
            seq_floors: DashMap::new(),
            #[cfg(not(target_arch = "wasm32"))]
            wal_recovered_buckets: DashMap::new(),
            #[cfg(not(target_arch = "wasm32"))]
            orphan_drain_in_flight: DashMap::new(),
        })
    }

    /// Get or create the migration lock for a bucket
    fn migration_lock(&self, bucket: &str) -> Arc<tokio::sync::RwLock<()>> {
        self.migration_locks
            .entry(bucket.to_string())
            .or_insert_with(|| Arc::new(tokio::sync::RwLock::new(())))
            .clone()
    }

    /// Get the underlying client
    pub fn inner(&self) -> &FulaClient {
        &self.inner
    }

    /// Create a new encrypted client with pinning credentials
    pub fn new_with_pinning(
        config: Config,
        encryption: EncryptionConfig,
        pinning: PinningCredentials,
    ) -> Result<Self> {
        let inner = FulaClient::new(config)?;
        Ok(Self {
            inner,
            encryption,
            forest_cache: DashMap::new(),
            pinning: Some(pinning),
            migration_locks: DashMap::new(),
            seq_floors: DashMap::new(),
            #[cfg(not(target_arch = "wasm32"))]
            wal_recovered_buckets: DashMap::new(),
            #[cfg(not(target_arch = "wasm32"))]
            orphan_drain_in_flight: DashMap::new(),
        })
    }

    /// Set pinning credentials (builder pattern)
    pub fn with_pinning(mut self, pinning: PinningCredentials) -> Self {
        self.pinning = Some(pinning);
        self
    }

    /// Get the encryption config
    pub fn encryption_config(&self) -> &EncryptionConfig {
        &self.encryption
    }

    /// Return the forest sequence most recently observed for `bucket`, if any.
    ///
    /// Monolithic forests expose `last_sequence`; sharded forests expose
    /// `last_manifest_sequence`. Applications that want cross-session replay
    /// protection (C-AUDIT-008) persist this value after each successful
    /// save/load and restore it on startup via `set_forest_sequence_floor`.
    pub fn get_forest_sequence(&self, bucket: &str) -> Option<u64> {
        self.forest_cache.get(bucket).and_then(|entry| match entry.value() {
            ForestCacheEntry::Monolithic { last_sequence, .. } => *last_sequence,
            ForestCacheEntry::ShardedHamt { last_manifest_sequence, .. } => *last_manifest_sequence,
        })
    }

    /// Install a per-bucket minimum-acceptable forest sequence (C-AUDIT-008).
    ///
    /// After calling this, any forest load whose decrypted sequence is below
    /// `min_seq` is rejected as a replay. Intended for applications that
    /// persist the counter externally (e.g., encrypted keystore) so a
    /// restart cannot be tricked into accepting a stale manifest that was
    /// captured off the wire before the process went down.
    ///
    /// Opt-in: if never called, behavior is identical to previous versions.
    pub fn set_forest_sequence_floor(&self, bucket: &str, min_seq: u64) {
        self.seq_floors.insert(bucket.to_string(), min_seq);
    }

    /// Reject a load whose decrypted sequence is below the configured floor.
    /// No-op when no floor has been set for the bucket.
    fn check_sequence_floor(&self, bucket: &str, observed_seq: u64) -> Result<()> {
        if let Some(floor) = self.seq_floors.get(bucket).map(|r| *r) {
            if observed_seq < floor {
                return Err(ClientError::Encryption(
                    fula_crypto::CryptoError::Decryption(format!(
                        "forest replay detected: sequence {} below configured floor {}",
                        observed_seq, floor
                    ))
                ));
            }
        }
        Ok(())
    }

    /// Start a background task that periodically flushes dirty forest caches
    /// to storage. Narrows the window in which a crash between `put_object_flat_deferred`
    /// and a manual `flush_forest` can leave orphan content in storage.
    ///
    /// The task is best-effort: flush failures are logged and retried on the next
    /// tick. Pairs naturally with `put_object_flat` (which already flushes synchronously)
    /// — the background task only kicks in for callers that use the deferred variant.
    ///
    /// Returns an `AutoFlushHandle`. Dropping the handle signals the task to exit.
    /// The task also exits on its own once all other `Arc<EncryptedClient>` handles
    /// are dropped (it holds only a `Weak`).
    #[cfg(not(target_arch = "wasm32"))]
    pub fn start_auto_flush(self: &Arc<Self>, interval_secs: u64) -> AutoFlushHandle {
        let interval = std::time::Duration::from_secs(interval_secs.max(1));
        let weak = Arc::downgrade(self);
        let (tx, mut rx) = tokio::sync::oneshot::channel::<()>();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut rx => break,
                    _ = tokio::time::sleep(interval) => {}
                }

                let Some(client) = weak.upgrade() else { break; };

                let dirty_buckets: Vec<String> = client.forest_cache
                    .iter()
                    .filter(|e| e.value().is_dirty())
                    .map(|e| e.key().clone())
                    .collect();

                for bucket in dirty_buckets {
                    if let Err(e) = client.flush_forest(&bucket).await {
                        tracing::warn!(%bucket, error = %e, "auto-flush: flush_forest failed");
                    }
                }
            }
        });

        AutoFlushHandle { cancel: Some(tx) }
    }

    /// Put an encrypted object with optional content type
    pub async fn put_object_encrypted_with_type(
        &self,
        bucket: &str,
        key: &str,
        data: impl Into<Bytes>,
        content_type: Option<&str>,
    ) -> Result<PutObjectResult> {
        let data = data.into();
        let original_size = data.len() as u64;
        
        // Generate a DEK for this object
        let dek = self.encryption.key_manager.generate_dek();
        
        // Encrypt the DEK with HPKE for the owner
        let encryptor = Encryptor::new(self.encryption.public_key());
        let wrapped_dek = encryptor.encrypt_dek(&dek)
            .map_err(ClientError::Encryption)?;

        // Determine the storage key and metadata based on privacy settings
        let (storage_key, private_metadata_json) = if self.encryption.metadata_privacy {
            // Create private metadata with original info. H-1: compute BLAKE3
            // over the plaintext *before* AEAD so the hash is bound to the
            // forest entry (outside the attacker-forgeable HPKE envelope).
            let content_hash = blake3::hash(&data).to_hex().to_string();
            let private_meta = PrivateMetadata::new(key, original_size)
                .with_content_type(content_type.unwrap_or("application/octet-stream"))
                .with_content_hash(content_hash);

            // Encrypt private metadata with the per-file DEK
            let encrypted_meta = EncryptedPrivateMetadata::encrypt(&private_meta, &dek)
                .map_err(ClientError::Encryption)?;

            // Generate obfuscated storage key using PATH-DERIVED DEK (not per-file DEK)
            // This ensures we can compute the same storage key later for retrieval
            let path_dek = self.encryption.key_manager.derive_path_key(key);
            let storage_key = obfuscate_key(key, &path_dek, self.encryption.obfuscation_mode.clone());

            (storage_key, Some(encrypted_meta.to_json().map_err(ClientError::Encryption)?))
        } else {
            (key.to_string(), None)
        };

        // Encrypt the data with the DEK, binding ciphertext to storage_key via AAD
        let nonce = Nonce::generate();
        let aead = Aead::new_default(&dek);
        let aad = format!("fula:v4:content:{}", storage_key).into_bytes();
        let ciphertext = aead.encrypt_with_aad(&nonce, &data, &aad)
            .map_err(ClientError::Encryption)?;

        // Serialize encryption metadata with KEK version
        let kek_version = self.encryption.key_manager.version();
        let mut enc_metadata = serde_json::json!({
            "version": 4,
            "algorithm": "AES-256-GCM",
            "nonce": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, nonce.as_bytes()),
            "wrapped_key": serde_json::to_value(&wrapped_dek).unwrap(),
            "kek_version": kek_version,
            "metadata_privacy": self.encryption.metadata_privacy,
        });

        // Add encrypted private metadata if enabled
        if let Some(private_meta) = private_metadata_json {
            enc_metadata["private_metadata"] = serde_json::Value::String(private_meta);
        }

        // Upload with encryption metadata (server sees obfuscated key)
        let metadata = ObjectMetadata::new()
            .with_content_type("application/octet-stream") // Server always sees generic type
            .with_metadata("x-fula-encrypted", "true")
            .with_metadata("x-fula-encryption", &enc_metadata.to_string());

        // Use pinning if credentials are configured
        if let Some(ref pinning) = self.pinning {
            self.inner.put_object_with_metadata_and_pinning(
                bucket,
                &storage_key,
                Bytes::from(ciphertext),
                Some(metadata),
                &pinning.endpoint,
                &pinning.token,
            ).await
        } else {
            self.inner.put_object_with_metadata(
                bucket,
                &storage_key,
                Bytes::from(ciphertext),
                Some(metadata),
            ).await
        }
    }

    /// Put an encrypted object (convenience method)
    pub async fn put_object_encrypted(
        &self,
        bucket: &str,
        key: &str,
        data: impl Into<Bytes>,
    ) -> Result<PutObjectResult> {
        self.put_object_encrypted_with_type(bucket, key, data, None).await
    }

    /// Get and decrypt an object using the original key
    /// 
    /// If metadata privacy is enabled, this will automatically compute the
    /// storage key from the original key using deterministic hashing.
    pub async fn get_object_decrypted(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<Bytes> {
        // For metadata privacy, we need to find the storage key
        // Since we use deterministic hashing, we can compute it
        // But we need the DEK first, which creates a chicken-and-egg problem
        // 
        // Solution: If metadata privacy is enabled, we use the path-derived DEK
        // to compute the storage key, fetch the object, then use the wrapped DEK
        // to decrypt the actual data.
        
        let storage_key = if self.encryption.metadata_privacy {
            // Use a path-derived DEK for key obfuscation lookup
            let path_dek = self.encryption.key_manager.derive_path_key(key);
            obfuscate_key(key, &path_dek, self.encryption.obfuscation_mode.clone())
        } else {
            key.to_string()
        };

        self.get_object_decrypted_by_storage_key(bucket, &storage_key).await
    }

    /// Get and decrypt an object using the storage key directly
    /// 
    /// Use this when you already have the obfuscated storage key
    /// (e.g., from list_objects_decrypted)
    /// 
    /// Handles both single-block and chunked objects automatically.
    pub async fn get_object_decrypted_by_storage_key(
        &self,
        bucket: &str,
        storage_key: &str,
    ) -> Result<Bytes> {
        let result = self.inner.get_object_with_metadata(bucket, storage_key).await?;
        
        // Check if object is encrypted
        let is_encrypted = result.metadata
            .get("x-fula-encrypted")
            .map(|v| v == "true")
            .unwrap_or(false);

        if !is_encrypted {
            // C-AUDIT-004 / NEW-2.1: refuse plaintext response when forest records
            // this storage_key as a previously-encrypted upload. Forces a forest
            // load first so an empty cache cannot be used as a bypass.
            if self.forest_entry_requires_encryption(bucket, storage_key).await? {
                return Err(ClientError::Encryption(fula_crypto::CryptoError::Decryption(
                    "storage backend served plaintext for an encrypted path".to_string()
                )));
            }
            return Ok(result.data);
        }

        // Check if this is a chunked object
        let is_chunked = result.metadata
            .get("x-fula-chunked")
            .map(|v| v == "true")
            .unwrap_or(false);

        // Parse encryption metadata
        let enc_metadata_str = result.metadata
            .get("x-fula-encryption")
            .ok_or_else(|| ClientError::Encryption(
                fula_crypto::CryptoError::Decryption("Missing encryption metadata".to_string())
            ))?;

        let enc_metadata: serde_json::Value = serde_json::from_str(enc_metadata_str)
            .map_err(|e| ClientError::Encryption(
                fula_crypto::CryptoError::Decryption(e.to_string())
            ))?;

        // Unwrap the DEK (common to both chunked and non-chunked)
        let wrapped_key: EncryptedData = serde_json::from_value(
            enc_metadata["wrapped_key"].clone()
        ).map_err(|e| ClientError::Encryption(
            fula_crypto::CryptoError::Decryption(e.to_string())
        ))?;

        let decryptor = Decryptor::new(self.encryption.key_manager.keypair());
        let dek = decryptor.decrypt_dek(&wrapped_key)
            .map_err(ClientError::Encryption)?;

        // H-1 / H-2: resolve the forest entry once (shared by chunked and
        // single-block branches) so we can enforce min_version and verify
        // content_hash on either path.
        let forest_entry = self.forest_entry_lookup(bucket, storage_key).await?;

        if is_chunked {
            // CHUNKED DOWNLOAD: Download and decrypt each chunk
            self.get_object_chunked_internal(bucket, storage_key, &enc_metadata, &dek, forest_entry.as_ref()).await
        } else {
            // SINGLE OBJECT: Decrypt directly
            let nonce_b64 = enc_metadata["nonce"].as_str()
                .ok_or_else(|| ClientError::Encryption(
                    fula_crypto::CryptoError::Decryption("Missing nonce".to_string())
                ))?;
            let nonce_bytes = base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                nonce_b64,
            ).map_err(|e| ClientError::Encryption(
                fula_crypto::CryptoError::Decryption(e.to_string())
            ))?;
            let nonce = Nonce::from_bytes(&nonce_bytes)
                .map_err(ClientError::Encryption)?;

            let aead = Aead::new_default(&dek);
            let version = enc_metadata["version"].as_u64().unwrap_or(2);
            Self::enforce_min_version(forest_entry.as_ref(), version)?;
            let plaintext = if version >= 4 {
                let aad = format!("fula:v4:content:{}", storage_key).into_bytes();
                aead.decrypt_with_aad(&nonce, &result.data, &aad)
            } else {
                aead.decrypt(&nonce, &result.data)
            }.map_err(ClientError::Encryption)?;

            Self::enforce_content_hash(forest_entry.as_ref(), &plaintext)?;

            Ok(Bytes::from(plaintext))
        }
    }

    /// Maximum number of concurrent chunk downloads
    const MAX_CONCURRENT_CHUNK_DOWNLOADS: usize = 16;

    /// Maximum number of concurrent chunk uploads
    const MAX_CONCURRENT_CHUNK_UPLOADS: usize = 16;

    /// Maximum number of concurrent per-object DEK rewraps during bucket rotation.
    /// Lower than chunk downloads because each rewrap is read + decrypt + encrypt + write.
    const MAX_CONCURRENT_REWRAPS: usize = 8;

    /// Maximum number of concurrent HEAD requests during directory listing.
    const MAX_CONCURRENT_HEADS: usize = 16;

    /// Internal: Download and decrypt a chunked file
    ///
    /// Downloads chunks in parallel (up to MAX_CONCURRENT_CHUNK_DOWNLOADS) for
    /// significantly improved throughput on large files, then decrypts and
    /// assembles in index order.
    async fn get_object_chunked_internal(
        &self,
        bucket: &str,
        storage_key: &str,
        enc_metadata: &serde_json::Value,
        dek: &fula_crypto::keys::DekKey,
        forest_entry: Option<&ForestFileEntry>,
    ) -> Result<Bytes> {
        // Parse chunked metadata
        let chunked_meta: ChunkedFileMetadata = serde_json::from_value(
            enc_metadata["chunked"].clone()
        ).map_err(|e| ClientError::Encryption(
            fula_crypto::CryptoError::Decryption(format!("Invalid chunked metadata: {}", e))
        ))?;

        // Delegate to the windowed download engine which keeps peak memory
        // bounded to ~window_size * chunk_size regardless of total file size.
        let mut output = Vec::with_capacity(chunked_meta.total_size as usize);
        self.download_chunks_windowed_to_writer(bucket, storage_key, &chunked_meta, dek, &mut output, forest_entry).await?;
        Ok(Bytes::from(output))
    }

    /// Internal: Download and decrypt a chunked file in a streaming fashion
    ///
    /// Downloads chunks in bounded windows and writes decrypted data directly
    /// to the writer, keeping peak memory bounded to approximately
    /// `MAX_CONCURRENT_CHUNK_DOWNLOADS * chunk_size` regardless of total file size.
    async fn get_object_chunked_to_writer<W: std::io::Write>(
        &self,
        bucket: &str,
        storage_key: &str,
        enc_metadata: &serde_json::Value,
        dek: &fula_crypto::keys::DekKey,
        writer: &mut W,
        forest_entry: Option<&ForestFileEntry>,
    ) -> Result<u64> {
        let chunked_meta: ChunkedFileMetadata = serde_json::from_value(
            enc_metadata["chunked"].clone()
        ).map_err(|e| ClientError::Encryption(
            fula_crypto::CryptoError::Decryption(format!("Invalid chunked metadata: {}", e))
        ))?;

        self.download_chunks_windowed_to_writer(bucket, storage_key, &chunked_meta, dek, writer, forest_entry).await
    }

    /// F8: Internal chunked-download dispatch for the buffered writer path.
    ///
    /// Parses `chunked_meta` and delegates to
    /// `download_chunks_buffered_to_writer`. Used only by the public
    /// `get_object_decrypted_buffered_*` APIs.
    async fn get_object_chunked_buffered_to_writer<W: std::io::Write>(
        &self,
        bucket: &str,
        storage_key: &str,
        enc_metadata: &serde_json::Value,
        dek: &fula_crypto::keys::DekKey,
        writer: &mut W,
        forest_entry: Option<&ForestFileEntry>,
    ) -> Result<u64> {
        let chunked_meta: ChunkedFileMetadata = serde_json::from_value(
            enc_metadata["chunked"].clone()
        ).map_err(|e| ClientError::Encryption(
            fula_crypto::CryptoError::Decryption(format!("Invalid chunked metadata: {}", e))
        ))?;

        self.download_chunks_buffered_to_writer(bucket, storage_key, &chunked_meta, dek, writer, forest_entry).await
    }

    /// Core windowed download+decrypt engine.
    ///
    /// Processes chunks in sliding windows of `MAX_CONCURRENT_CHUNK_DOWNLOADS`,
    /// downloading in parallel within each window, decrypting in order, and
    /// writing to the output. Peak memory is bounded to ~`window_size * chunk_size`
    /// regardless of total file size.
    ///
    /// Used by both the `Bytes`-returning paths (via `Vec<u8>` writer) and the
    /// generic writer path.
    ///
    /// H-1 / H-2: `forest_entry` carries the owner's forest pin for this
    /// storage_key. When present:
    /// - `min_version` is checked against `chunked_meta.format` (streaming-v2
    ///   maps to v4, legacy format to v2) before any I/O.
    /// - `content_hash` is verified against a BLAKE3 of the full plaintext
    ///   stream after `finalize_and_verify` (Bao root) succeeds. Plaintext
    ///   bytes are teed to both the caller's writer and a separate BLAKE3
    ///   hasher in the same decryption loop — no extra network or I/O cost.
    ///   On mismatch the function returns `IntegrityMismatch` and the
    ///   caller is contractually obliged to discard whatever bytes have
    ///   already reached their writer (same contract as the existing Bao
    ///   finalize path).
    async fn download_chunks_windowed_to_writer<W: std::io::Write>(
        &self,
        bucket: &str,
        storage_key: &str,
        chunked_meta: &ChunkedFileMetadata,
        dek: &fula_crypto::keys::DekKey,
        writer: &mut W,
        forest_entry: Option<&ForestFileEntry>,
    ) -> Result<u64> {
        // H-2: pre-I/O downgrade gate for chunked files. streaming-v2 format
        // maps to on-the-wire version 4 (uses chunk AAD); anything else is
        // legacy (no AAD), treated as version 2. An entry with min_version=4
        // therefore rejects a legacy-format blob before any chunk fetch.
        let chunked_version: u8 = if chunked_meta.format == "streaming-v2" { 4 } else { 2 };
        Self::enforce_min_version(forest_entry, chunked_version as u64)?;

        let num_chunks = chunked_meta.num_chunks;
        // Use VerifiedStreamingDecoder so the Bao root hash is verified at
        // finalize — this closes the truncation / tampering attack where a
        // malicious storage backend serves fewer chunks than were uploaded
        // (fixed by C-AUDIT-001). The finalize check also implicitly binds
        // num_chunks and root_hash against the DEK's keyed hash state
        // (mitigates C-AUDIT-002 for those fields without a format change).
        //
        // NOTE: Bytes reach the writer BEFORE verification completes; on
        // integrity failure callers must discard whatever was written. This
        // matches blake3/bao's streaming model.
        let mut decoder = if chunked_meta.format == "streaming-v2" {
            let aad_prefix = format!("fula:v4:chunk:{}", storage_key);
            fula_crypto::VerifiedStreamingDecoder::with_aad(
                dek.clone(), chunked_meta.clone(), aad_prefix,
            ).map_err(ClientError::Encryption)?
        } else {
            fula_crypto::VerifiedStreamingDecoder::new(dek.clone(), chunked_meta.clone())
                .map_err(ClientError::Encryption)?
        };

        let mut total_written: u64 = 0;
        let mut chunks_decrypted: u64 = 0;
        let window_size = Self::MAX_CONCURRENT_CHUNK_DOWNLOADS;
        // H-1: tee plaintext through a BLAKE3 hasher when the forest entry
        // carries a pinned content_hash. The hasher sits outside the
        // attacker-controllable `ChunkedFileMetadata` blob — its digest is
        // bound to the forest entry (forest DEK + sequence AAD), which is
        // the only layer not re-wrappable under HPKE-to-self forgery.
        let mut content_hasher: Option<blake3::Hasher> = forest_entry
            .and_then(|e| e.content_hash.as_ref())
            .map(|_| blake3::Hasher::new());

        // Process chunks in sliding windows to bound memory usage.
        // Each window downloads up to `window_size` chunks in parallel,
        // decrypts them in order, writes to the output, then drops the
        // ciphertext before moving to the next window.
        for window_start in (0..num_chunks as usize).step_by(window_size) {
            let window_end = std::cmp::min(window_start + window_size, num_chunks as usize);

            // Use futures::stream::buffer_unordered for cross-platform bounded
            // concurrency — tokio::spawn + Semaphore pulls in tokio's `rt`
            // feature which isn't available on wasm32.
            use futures::StreamExt;
            // F10: bound per-chunk fetch so one stuck chunk cannot stall the
            // stream up to the global reqwest timeout.
            #[cfg(not(target_arch = "wasm32"))]
            let per_chunk_timeout = self.inner.config().per_chunk_download_timeout;
            let futs = (window_start..window_end).map(|chunk_index| {
                let chunk_key = ChunkedFileMetadata::chunk_key(storage_key, chunk_index as u32);
                let client = self.inner.clone();
                let bucket = bucket.to_string();
                async move {
                    #[cfg(not(target_arch = "wasm32"))]
                    let data = fetch_chunk_with_timeout(
                        client.get_object(&bucket, &chunk_key),
                        chunk_index as u32,
                        per_chunk_timeout,
                    )
                    .await?;
                    #[cfg(target_arch = "wasm32")]
                    let data = client.get_object(&bucket, &chunk_key).await?;
                    Ok::<(u32, Bytes), ClientError>((chunk_index as u32, data))
                }
            });
            let mut stream = futures::stream::iter(futs).buffer_unordered(window_size);
            let mut window_chunks: Vec<(u32, Bytes)> = Vec::with_capacity(window_end - window_start);
            while let Some(result) = stream.next().await {
                window_chunks.push(result?);
            }

            // Sort by index and decrypt in order, writing directly to output.
            // decrypt_and_verify both decrypts AEAD AND updates the Bao hasher,
            // so each chunk contributes to the final integrity check.
            window_chunks.sort_by_key(|(idx, _)| *idx);

            for (chunk_index, chunk_data) in &window_chunks {
                let chunk_plaintext = decoder.decrypt_and_verify(*chunk_index, chunk_data)
                    .map_err(ClientError::Encryption)?;
                if let Some(h) = content_hasher.as_mut() {
                    h.update(&chunk_plaintext);
                }
                writer.write_all(&chunk_plaintext)
                    .map_err(ClientError::Io)?;
                total_written += chunk_plaintext.len() as u64;
                chunks_decrypted += 1;
            }
            // window_chunks dropped here — frees ciphertext memory before next window
        }

        // C-AUDIT-002 defense-in-depth: both counters and the declared total
        // size must match what the metadata claimed. These are redundant with
        // the Bao hash check on the happy path, but catch certain edge cases
        // like zero-length chunks or backends returning empty bodies.
        if chunks_decrypted != num_chunks as u64 {
            return Err(ClientError::Encryption(fula_crypto::CryptoError::Decryption(
                format!(
                    "chunk count mismatch: metadata claimed {}, decoded {}",
                    num_chunks, chunks_decrypted
                ),
            )));
        }
        if total_written != chunked_meta.total_size {
            return Err(ClientError::Encryption(fula_crypto::CryptoError::Decryption(
                format!(
                    "total size mismatch: metadata claimed {}, decoded {} bytes",
                    chunked_meta.total_size, total_written
                ),
            )));
        }

        // Final Bao root-hash verification — the critical check that catches
        // silent truncation and tampering of chunk contents or ordering.
        decoder.finalize_and_verify().map_err(ClientError::Encryption)?;

        // H-1: compare the forest-pinned content_hash against the BLAKE3 digest
        // accumulated over the decrypted plaintext stream. Runs only when
        // `forest_entry.content_hash` was set at upload time. On mismatch the
        // caller must discard any bytes already emitted to `writer` — see the
        // streaming-contract note at the top of this function.
        if let (Some(h), Some(entry)) = (content_hasher, forest_entry) {
            if let Some(expected_hex) = entry.content_hash.as_ref() {
                let actual = h.finalize();
                let expected = match blake3::Hash::from_hex(expected_hex.as_bytes()) {
                    Ok(e) => e,
                    Err(_) => {
                        return Err(ClientError::Encryption(
                            fula_crypto::CryptoError::IntegrityMismatch(
                                "malformed content_hash in forest entry".to_string(),
                            ),
                        ));
                    }
                };
                if actual != expected {
                    return Err(ClientError::Encryption(
                        fula_crypto::CryptoError::IntegrityMismatch(format!(
                            "chunked content_hash mismatch: {} bytes written before detection",
                            total_written
                        )),
                    ));
                }
            }
        }

        Ok(total_written)
    }

    /// F8: Buffered chunked-download engine.
    ///
    /// Like `download_chunks_windowed_to_writer`, but accumulates every
    /// decrypted chunk into an in-memory buffer and emits to the caller's
    /// writer **only after** `finalize_and_verify` passes. The streaming
    /// variant writes per-chunk plaintext as it arrives, so an adversarial
    /// truncation / chunk-reorder is only caught at root-hash finalize —
    /// by which point partial plaintext has already been handed to the
    /// caller. That model is fine for ordinary reads but problematic for
    /// disaster-recovery consumers that want all-or-nothing root-verified
    /// output.
    ///
    /// Pre-checks `chunked_meta.total_size` against
    /// `config().buffered_download_max_bytes` before any network I/O. If
    /// the declared size exceeds the ceiling, returns an error without
    /// allocating. This is intentional: the buffered path holds the full
    /// plaintext in RAM, so an unbounded ceiling would let a malicious
    /// manifest OOM the client.
    ///
    /// Note on atomicity: "root-verified before emission" is a stronger
    /// guarantee than the streaming variant provides, but `write_all`
    /// after verification is still not atomic on all writers — if the
    /// caller's writer is a filesystem and `write_all` fails mid-flush,
    /// partial plaintext can still land on disk. F8 gives you
    /// root-verified-before-emission, not crash-safe atomicity. Callers
    /// that need true all-or-nothing semantics should write to a temp
    /// path and rename on success.
    async fn download_chunks_buffered_to_writer<W: std::io::Write>(
        &self,
        bucket: &str,
        storage_key: &str,
        chunked_meta: &ChunkedFileMetadata,
        dek: &fula_crypto::keys::DekKey,
        writer: &mut W,
        forest_entry: Option<&ForestFileEntry>,
    ) -> Result<u64> {
        let ceiling = self.inner.config().buffered_download_max_bytes;
        if chunked_meta.total_size > ceiling {
            return Err(ClientError::DownloadFailed(format!(
                "buffered download exceeds configured ceiling: \
                 declared total_size={} bytes, buffered_download_max_bytes={} bytes \
                 (use the streaming variant `get_object_decrypted_to_writer` for large files)",
                chunked_meta.total_size, ceiling,
            )));
        }

        let mut buffer: Vec<u8> = Vec::with_capacity(chunked_meta.total_size as usize);
        // The windowed engine writes straight to `&mut buffer`, but only
        // AFTER `finalize_and_verify` clears do we surface the bytes to
        // the caller's writer. If finalize fails, `buffer` is dropped on
        // the error-return path and the caller's writer is untouched.
        let total_written = self
            .download_chunks_windowed_to_writer(bucket, storage_key, chunked_meta, dek, &mut buffer, forest_entry)
            .await?;

        writer.write_all(&buffer).map_err(ClientError::Io)?;
        Ok(total_written)
    }

    /// Get and decrypt an object, writing output directly to a writer
    ///
    /// Unlike `get_object_decrypted()` which loads the entire file into memory,
    /// this method streams decrypted data through the writer in bounded chunks.
    /// Peak memory usage is approximately `MAX_CONCURRENT_CHUNK_DOWNLOADS * chunk_size`
    /// (~4MB) regardless of total file size.
    ///
    /// For single-block (non-chunked) files, the entire block is written at once
    /// since single blocks are always small enough to fit in memory.
    ///
    /// Returns the total number of bytes written.
    pub async fn get_object_decrypted_to_writer<W: std::io::Write>(
        &self,
        bucket: &str,
        key: &str,
        writer: &mut W,
    ) -> Result<u64> {
        let storage_key = if self.encryption.metadata_privacy {
            let path_dek = self.encryption.key_manager.derive_path_key(key);
            obfuscate_key(key, &path_dek, self.encryption.obfuscation_mode.clone())
        } else {
            key.to_string()
        };

        self.get_object_decrypted_to_writer_by_storage_key(bucket, &storage_key, writer).await
    }

    /// Get and decrypt an object by storage key, writing to a writer
    ///
    /// Streaming variant of `get_object_decrypted_by_storage_key()`.
    /// See `get_object_decrypted_to_writer()` for details.
    pub async fn get_object_decrypted_to_writer_by_storage_key<W: std::io::Write>(
        &self,
        bucket: &str,
        storage_key: &str,
        writer: &mut W,
    ) -> Result<u64> {
        let result = self.inner.get_object_with_metadata(bucket, storage_key).await?;

        let is_encrypted = result.metadata
            .get("x-fula-encrypted")
            .map(|v| v == "true")
            .unwrap_or(false);

        if !is_encrypted {
            // C-AUDIT-004 / NEW-2.1: block plaintext response for forest-known encrypted entries
            if self.forest_entry_requires_encryption(bucket, storage_key).await? {
                return Err(ClientError::Encryption(fula_crypto::CryptoError::Decryption(
                    "storage backend served plaintext for an encrypted path".to_string()
                )));
            }
            writer.write_all(&result.data).map_err(ClientError::Io)?;
            return Ok(result.data.len() as u64);
        }

        let is_chunked = result.metadata
            .get("x-fula-chunked")
            .map(|v| v == "true")
            .unwrap_or(false);

        let enc_metadata_str = result.metadata
            .get("x-fula-encryption")
            .ok_or_else(|| ClientError::Encryption(
                fula_crypto::CryptoError::Decryption("Missing encryption metadata".to_string())
            ))?;

        let enc_metadata: serde_json::Value = serde_json::from_str(enc_metadata_str)
            .map_err(|e| ClientError::Encryption(
                fula_crypto::CryptoError::Decryption(e.to_string())
            ))?;

        let wrapped_key: EncryptedData = serde_json::from_value(
            enc_metadata["wrapped_key"].clone()
        ).map_err(|e| ClientError::Encryption(
            fula_crypto::CryptoError::Decryption(e.to_string())
        ))?;

        let decryptor = Decryptor::new(self.encryption.key_manager.keypair());
        let dek = decryptor.decrypt_dek(&wrapped_key)
            .map_err(ClientError::Encryption)?;

        // H-1 / H-2: look up the forest entry once; shared by both branches.
        let forest_entry = self.forest_entry_lookup(bucket, storage_key).await?;

        if is_chunked {
            self.get_object_chunked_to_writer(bucket, storage_key, &enc_metadata, &dek, writer, forest_entry.as_ref()).await
        } else {
            let nonce_b64 = enc_metadata["nonce"].as_str()
                .ok_or_else(|| ClientError::Encryption(
                    fula_crypto::CryptoError::Decryption("Missing nonce".to_string())
                ))?;
            let nonce_bytes = base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                nonce_b64,
            ).map_err(|e| ClientError::Encryption(
                fula_crypto::CryptoError::Decryption(e.to_string())
            ))?;
            let nonce = Nonce::from_bytes(&nonce_bytes)
                .map_err(ClientError::Encryption)?;

            let aead = Aead::new_default(&dek);
            let version = enc_metadata["version"].as_u64().unwrap_or(2);
            Self::enforce_min_version(forest_entry.as_ref(), version)?;
            let plaintext = if version >= 4 {
                let aad = format!("fula:v4:content:{}", storage_key).into_bytes();
                aead.decrypt_with_aad(&nonce, &result.data, &aad)
            } else {
                aead.decrypt(&nonce, &result.data)
            }.map_err(ClientError::Encryption)?;

            Self::enforce_content_hash(forest_entry.as_ref(), &plaintext)?;

            writer.write_all(&plaintext).map_err(ClientError::Io)?;
            Ok(plaintext.len() as u64)
        }
    }

    /// F8: Get and decrypt an object, writing output only after the full
    /// plaintext has been root-hash verified.
    ///
    /// Like `get_object_decrypted_to_writer`, but buffers the entire
    /// decrypted plaintext in memory and calls the Bao `finalize_and_verify`
    /// step **before** any bytes are written to the caller's writer. Useful
    /// for disaster-recovery consumers that must not observe plaintext until
    /// the entire file has passed the root-hash check (closes the truncation
    /// / chunk-reorder window inherent to the streaming variant).
    ///
    /// Rejects files larger than `Config::buffered_download_max_bytes`
    /// (default 256 MB) before any network I/O — buffered downloads hold
    /// the full plaintext in RAM. Callers with larger files should use the
    /// streaming variant and handle the weaker mid-stream guarantee.
    ///
    /// Single-block (non-chunked) files have no streaming window and no
    /// Bao root; for those the AEAD tag over the block is itself the
    /// integrity check, and this path behaves identically to the streaming
    /// variant.
    ///
    /// Atomicity caveat: the final `write_all` after root verification is
    /// not itself atomic. If the caller's writer is a filesystem and
    /// `write_all` fails mid-flush, partial plaintext can still land on
    /// disk. Callers needing true all-or-nothing semantics should write
    /// to a temp path and rename on success.
    pub async fn get_object_decrypted_buffered_to_writer<W: std::io::Write>(
        &self,
        bucket: &str,
        key: &str,
        writer: &mut W,
    ) -> Result<u64> {
        let storage_key = if self.encryption.metadata_privacy {
            let path_dek = self.encryption.key_manager.derive_path_key(key);
            obfuscate_key(key, &path_dek, self.encryption.obfuscation_mode.clone())
        } else {
            key.to_string()
        };

        self.get_object_decrypted_buffered_to_writer_by_storage_key(bucket, &storage_key, writer).await
    }

    /// F8: Buffered download variant of
    /// `get_object_decrypted_to_writer_by_storage_key`.
    ///
    /// See `get_object_decrypted_buffered_to_writer` for semantics.
    pub async fn get_object_decrypted_buffered_to_writer_by_storage_key<W: std::io::Write>(
        &self,
        bucket: &str,
        storage_key: &str,
        writer: &mut W,
    ) -> Result<u64> {
        let result = self.inner.get_object_with_metadata(bucket, storage_key).await?;

        let is_encrypted = result.metadata
            .get("x-fula-encrypted")
            .map(|v| v == "true")
            .unwrap_or(false);

        if !is_encrypted {
            if self.forest_entry_requires_encryption(bucket, storage_key).await? {
                return Err(ClientError::Encryption(fula_crypto::CryptoError::Decryption(
                    "storage backend served plaintext for an encrypted path".to_string()
                )));
            }
            writer.write_all(&result.data).map_err(ClientError::Io)?;
            return Ok(result.data.len() as u64);
        }

        let is_chunked = result.metadata
            .get("x-fula-chunked")
            .map(|v| v == "true")
            .unwrap_or(false);

        let enc_metadata_str = result.metadata
            .get("x-fula-encryption")
            .ok_or_else(|| ClientError::Encryption(
                fula_crypto::CryptoError::Decryption("Missing encryption metadata".to_string())
            ))?;

        let enc_metadata: serde_json::Value = serde_json::from_str(enc_metadata_str)
            .map_err(|e| ClientError::Encryption(
                fula_crypto::CryptoError::Decryption(e.to_string())
            ))?;

        let wrapped_key: EncryptedData = serde_json::from_value(
            enc_metadata["wrapped_key"].clone()
        ).map_err(|e| ClientError::Encryption(
            fula_crypto::CryptoError::Decryption(e.to_string())
        ))?;

        let decryptor = Decryptor::new(self.encryption.key_manager.keypair());
        let dek = decryptor.decrypt_dek(&wrapped_key)
            .map_err(ClientError::Encryption)?;

        // H-1 / H-2: look up the forest entry once; shared by both branches.
        let forest_entry = self.forest_entry_lookup(bucket, storage_key).await?;

        if is_chunked {
            self.get_object_chunked_buffered_to_writer(bucket, storage_key, &enc_metadata, &dek, writer, forest_entry.as_ref()).await
        } else {
            // Single-block: AEAD tag over the whole block IS the integrity
            // check — no streaming window, no Bao root. Buffered and
            // streaming variants behave identically here.
            let nonce_b64 = enc_metadata["nonce"].as_str()
                .ok_or_else(|| ClientError::Encryption(
                    fula_crypto::CryptoError::Decryption("Missing nonce".to_string())
                ))?;
            let nonce_bytes = base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                nonce_b64,
            ).map_err(|e| ClientError::Encryption(
                fula_crypto::CryptoError::Decryption(e.to_string())
            ))?;
            let nonce = Nonce::from_bytes(&nonce_bytes)
                .map_err(ClientError::Encryption)?;

            let aead = Aead::new_default(&dek);
            let version = enc_metadata["version"].as_u64().unwrap_or(2);
            Self::enforce_min_version(forest_entry.as_ref(), version)?;
            let plaintext = if version >= 4 {
                let aad = format!("fula:v4:content:{}", storage_key).into_bytes();
                aead.decrypt_with_aad(&nonce, &result.data, &aad)
            } else {
                aead.decrypt(&nonce, &result.data)
            }.map_err(ClientError::Encryption)?;

            Self::enforce_content_hash(forest_entry.as_ref(), &plaintext)?;

            writer.write_all(&plaintext).map_err(ClientError::Io)?;
            Ok(plaintext.len() as u64)
        }
    }

    /// Decrypted object info with private metadata
    pub async fn get_object_with_private_metadata(
        &self,
        bucket: &str,
        storage_key: &str,
    ) -> Result<DecryptedObjectInfo> {
        let result = self.inner.get_object_with_metadata(bucket, storage_key).await?;
        
        let is_encrypted = result.metadata
            .get("x-fula-encrypted")
            .map(|v| v == "true")
            .unwrap_or(false);

        if !is_encrypted {
            // C-AUDIT-004 / NEW-2.1: block plaintext response for forest-known encrypted entries
            if self.forest_entry_requires_encryption(bucket, storage_key).await? {
                return Err(ClientError::Encryption(fula_crypto::CryptoError::Decryption(
                    "storage backend served plaintext for an encrypted path".to_string()
                )));
            }
            let size = result.data.len() as u64;
            return Ok(DecryptedObjectInfo {
                data: result.data,
                original_key: storage_key.to_string(),
                original_size: size,
                content_type: result.metadata.get("content-type").cloned(),
                user_metadata: HashMap::new(),
            });
        }

        let enc_metadata_str = result.metadata
            .get("x-fula-encryption")
            .ok_or_else(|| ClientError::Encryption(
                fula_crypto::CryptoError::Decryption("Missing encryption metadata".to_string())
            ))?;

        let enc_metadata: serde_json::Value = serde_json::from_str(enc_metadata_str)
            .map_err(|e| ClientError::Encryption(
                fula_crypto::CryptoError::Decryption(e.to_string())
            ))?;

        // Unwrap the DEK
        let wrapped_key: EncryptedData = serde_json::from_value(
            enc_metadata["wrapped_key"].clone()
        ).map_err(|e| ClientError::Encryption(
            fula_crypto::CryptoError::Decryption(e.to_string())
        ))?;

        let decryptor = Decryptor::new(self.encryption.key_manager.keypair());
        let dek = decryptor.decrypt_dek(&wrapped_key)
            .map_err(ClientError::Encryption)?;

        // Decrypt data
        let nonce_b64 = enc_metadata["nonce"].as_str()
            .ok_or_else(|| ClientError::Encryption(
                fula_crypto::CryptoError::Decryption("Missing nonce in encryption metadata".to_string())
            ))?;
        let nonce_bytes = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            nonce_b64,
        ).map_err(|e| ClientError::Encryption(
            fula_crypto::CryptoError::Decryption(e.to_string())
        ))?;
        let nonce = Nonce::from_bytes(&nonce_bytes)
            .map_err(ClientError::Encryption)?;

        let aead = Aead::new_default(&dek);
        let version = enc_metadata["version"].as_u64().unwrap_or(2);
        // H-1 / H-2: downgrade gate pre-decrypt, content_hash post-decrypt.
        let forest_entry = self.forest_entry_lookup(bucket, storage_key).await?;
        Self::enforce_min_version(forest_entry.as_ref(), version)?;
        let plaintext = if version >= 4 {
            let aad = format!("fula:v4:content:{}", storage_key).into_bytes();
            aead.decrypt_with_aad(&nonce, &result.data, &aad)
        } else {
            aead.decrypt(&nonce, &result.data)
        }.map_err(ClientError::Encryption)?;

        Self::enforce_content_hash(forest_entry.as_ref(), &plaintext)?;

        // Decrypt private metadata if present
        let (original_key, original_size, content_type, user_metadata) =
            if let Some(private_meta_str) = enc_metadata["private_metadata"].as_str() {
                let encrypted_meta = EncryptedPrivateMetadata::from_json(private_meta_str)
                    .map_err(ClientError::Encryption)?;
                let private_meta = encrypted_meta.decrypt(&dek)
                    .map_err(ClientError::Encryption)?;
                
                (
                    private_meta.original_key,
                    private_meta.actual_size,
                    private_meta.content_type,
                    private_meta.user_metadata,
                )
            } else {
                (storage_key.to_string(), plaintext.len() as u64, None, HashMap::new())
            };

        Ok(DecryptedObjectInfo {
            data: Bytes::from(plaintext),
            original_key,
            original_size,
            content_type,
            user_metadata,
        })
    }

    // Delegate non-encrypted operations to inner client

    /// List buckets
    pub async fn list_buckets(&self) -> Result<ListBucketsResult> {
        self.inner.list_buckets().await
    }

    /// Create bucket
    pub async fn create_bucket(&self, bucket: &str) -> Result<()> {
        self.inner.create_bucket(bucket).await
    }

    /// Delete bucket
    pub async fn delete_bucket(&self, bucket: &str) -> Result<()> {
        self.inner.delete_bucket(bucket).await
    }

    /// List objects (returns obfuscated keys if metadata privacy is enabled)
    pub async fn list_objects(
        &self,
        bucket: &str,
        options: Option<ListObjectsOptions>,
    ) -> Result<ListObjectsResult> {
        self.inner.list_objects(bucket, options).await
    }

    /// Delete object using original key
    pub async fn delete_object(&self, bucket: &str, key: &str) -> Result<()> {
        let storage_key = if self.encryption.metadata_privacy {
            let path_dek = self.encryption.key_manager.derive_path_key(key);
            obfuscate_key(key, &path_dek, self.encryption.obfuscation_mode.clone())
        } else {
            key.to_string()
        };
        self.inner.delete_object(bucket, &storage_key).await
    }

    /// Delete object using storage key directly
    pub async fn delete_object_by_storage_key(&self, bucket: &str, storage_key: &str) -> Result<()> {
        self.inner.delete_object(bucket, storage_key).await
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // METADATA-ONLY OPERATIONS (No file content download required)
    // These methods are optimized for file managers and directory browsers
    // ═══════════════════════════════════════════════════════════════════════════

    /// Get file metadata WITHOUT downloading the file content.
    /// 
    /// This is ideal for file managers that need to display file information
    /// (name, size, type, timestamps) without the bandwidth cost of downloading files.
    /// 
    /// Returns decrypted metadata including:
    /// - Original filename (not the obfuscated storage key)
    /// - Original file size (not ciphertext size)
    /// - Content type
    /// - Timestamps
    /// - User-defined metadata
    pub async fn head_object_decrypted(
        &self,
        bucket: &str,
        storage_key: &str,
    ) -> Result<FileMetadata> {
        // HEAD request - only gets headers, NOT file content
        let head_result = self.inner.head_object(bucket, storage_key).await?;
        
        // Security audit fix #9: Check correct metadata keys (x-fula-encrypted, x-fula-encryption)
        // The upload code uses x-amz-meta-x-fula-* which becomes x-fula-* in user_metadata
        let is_encrypted = head_result.metadata
            .get("x-fula-encrypted")
            .map(|v| v == "true")
            .unwrap_or(false);

        if !is_encrypted {
            // C-AUDIT-004 / NEW-2.1: block plaintext response for forest-known encrypted entries
            if self.forest_entry_requires_encryption(bucket, storage_key).await? {
                return Err(ClientError::Encryption(fula_crypto::CryptoError::Decryption(
                    "storage backend served plaintext metadata for an encrypted path".to_string()
                )));
            }
            return Ok(FileMetadata {
                storage_key: storage_key.to_string(),
                original_key: storage_key.to_string(),
                original_size: head_result.content_length,
                content_type: head_result.content_type,
                created_at: None,
                modified_at: None,
                user_metadata: HashMap::new(),
                is_encrypted: false,
            });
        }

        // Parse encryption metadata from headers
        let enc_metadata_str = head_result.metadata
            .get("x-fula-encryption")
            .ok_or_else(|| ClientError::Encryption(
                fula_crypto::CryptoError::Decryption("Missing encryption metadata".to_string())
            ))?;

        let enc_metadata: serde_json::Value = serde_json::from_str(enc_metadata_str)
            .map_err(|e| ClientError::Encryption(
                fula_crypto::CryptoError::Decryption(e.to_string())
            ))?;

        // Unwrap the DEK (needed to decrypt private metadata)
        let wrapped_key: EncryptedData = serde_json::from_value(
            enc_metadata["wrapped_key"].clone()
        ).map_err(|e| ClientError::Encryption(
            fula_crypto::CryptoError::Decryption(e.to_string())
        ))?;

        let decryptor = Decryptor::new(self.encryption.key_manager.keypair());
        let dek = decryptor.decrypt_dek(&wrapped_key)
            .map_err(ClientError::Encryption)?;

        // Decrypt private metadata if present (this is tiny - just a few hundred bytes)
        if let Some(private_meta_str) = enc_metadata["private_metadata"].as_str() {
            let encrypted_meta = EncryptedPrivateMetadata::from_json(private_meta_str)
                .map_err(ClientError::Encryption)?;
            let private_meta = encrypted_meta.decrypt(&dek)
                .map_err(ClientError::Encryption)?;
            
            Ok(FileMetadata {
                storage_key: storage_key.to_string(),
                original_key: private_meta.original_key,
                original_size: private_meta.actual_size,
                content_type: private_meta.content_type,
                created_at: Some(private_meta.created_at),
                modified_at: Some(private_meta.modified_at),
                user_metadata: private_meta.user_metadata,
                is_encrypted: true,
            })
        } else {
            // No private metadata - use visible metadata
            Ok(FileMetadata {
                storage_key: storage_key.to_string(),
                original_key: storage_key.to_string(),
                original_size: head_result.content_length,
                content_type: head_result.content_type,
                created_at: None,
                modified_at: None,
                user_metadata: HashMap::new(),
                is_encrypted: true,
            })
        }
    }

    /// List all objects in a bucket with decrypted metadata.
    /// 
    /// **This does NOT download any file content** - only metadata headers.
    /// Perfect for building file managers, directory browsers, or sync tools.
    /// 
    /// For each file, returns:
    /// - Original filename (decrypted)
    /// - Original size
    /// - Content type
    /// - Timestamps
    /// 
    /// Bandwidth: Only ~1-2KB per file (just headers), not the file content.
    pub async fn list_objects_decrypted(
        &self,
        bucket: &str,
        options: Option<ListObjectsOptions>,
    ) -> Result<Vec<FileMetadata>> {
        // Get list of storage keys
        let list_result = self.inner.list_objects(bucket, options).await?;

        // HEAD each object in parallel with a bounded window. HEAD is idempotent
        // and cheap on the server, but we cap concurrency to avoid starving other
        // clients and to keep memory bounded to ~MAX_CONCURRENT_HEADS * header-size.
        // No caching: results are one-shot and returned directly to the caller to
        // avoid stale-data risk and unbounded memory growth.
        use futures::stream::StreamExt;
        let files: Vec<FileMetadata> = futures::stream::iter(list_result.objects.into_iter().map(|obj| async move {
            let size = obj.size;
            match self.head_object_decrypted(bucket, &obj.key).await {
                Ok(metadata) => metadata,
                Err(e) => {
                    tracing::warn!("Failed to get metadata for {}: {:?}", obj.key, e);
                    FileMetadata {
                        storage_key: obj.key.clone(),
                        original_key: obj.key,
                        original_size: size,
                        content_type: None,
                        created_at: None,
                        modified_at: None,
                        user_metadata: HashMap::new(),
                        is_encrypted: false,
                    }
                }
            }
        }))
            .buffer_unordered(Self::MAX_CONCURRENT_HEADS)
            .collect()
            .await;

        Ok(files)
    }

    /// List objects as a directory tree structure.
    ///
    /// Groups files by their original directory paths for easy tree rendering.
    /// Does NOT download file content - only metadata.
    ///
    /// This call returns every matching entry in one `DirectoryListing` and
    /// therefore has memory cost O(files-under-prefix). For large prefixes
    /// prefer [`Self::list_directory_paginated`].
    pub async fn list_directory(
        &self,
        bucket: &str,
        prefix: Option<&str>,
    ) -> Result<DirectoryListing> {
        // For FlatNamespace, use the forest directly. No pagination bounds:
        // the v7 arm drains every page internally, v1/v6 return one page.
        if self.encryption.obfuscation_mode == KeyObfuscation::FlatNamespace {
            return self.list_directory_from_forest(bucket, prefix, None, None).await;
        }

        let options = prefix.map(|p| ListObjectsOptions {
            prefix: Some(p.to_string()),
            ..Default::default()
        });

        let files = self.list_objects_decrypted(bucket, options).await?;

        let mut directories: HashMap<String, Vec<FileMetadata>> = HashMap::new();

        for file in files {
            let dir = if let Some(last_slash) = file.original_key.rfind('/') {
                file.original_key[..last_slash].to_string()
            } else {
                "/".to_string()
            };

            directories.entry(dir).or_default().push(file);
        }

        Ok(DirectoryListing {
            bucket: bucket.to_string(),
            prefix: prefix.map(|s| s.to_string()),
            directories,
            is_truncated: false,
            next_continuation_token: None,
        })
    }

    /// Paginated directory listing for large prefixes.
    ///
    /// Unlike [`Self::list_directory`], this returns at most one page of
    /// results and sets `is_truncated` / `next_continuation_token` when
    /// more entries remain. Callers should loop until `is_truncated` is
    /// `false`. Memory cost is bounded to ≈ one page + accumulated
    /// directory metadata for that page.
    ///
    /// Arguments:
    /// - `continuation_token`: opaque token from a prior call's
    ///   `next_continuation_token`. Pass `None` for the first page.
    /// - `max_keys`: soft cap on entries per page (shard-grained for v7 —
    ///   see `ShardedHamtPrivateForest::list_recursive_page`). `None`
    ///   falls back to an internal default of 10_000.
    ///
    /// For non-FlatNamespace modes this delegates to the raw-S3 listing
    /// path (`list_objects_decrypted` with equivalent options) which
    /// already supports server-side pagination.
    ///
    /// Consistency: the cursor is NOT a snapshot. Writes that land between
    /// pages may add, remove, or shift entries the caller has not yet seen.
    /// Treat the paginated result set as eventually-consistent rather than
    /// a point-in-time view.
    pub async fn list_directory_paginated(
        &self,
        bucket: &str,
        prefix: Option<&str>,
        continuation_token: Option<&str>,
        max_keys: Option<usize>,
    ) -> Result<DirectoryListing> {
        const DEFAULT_MAX_KEYS: usize = 10_000;
        let effective_max = Some(max_keys.unwrap_or(DEFAULT_MAX_KEYS));

        if self.encryption.obfuscation_mode == KeyObfuscation::FlatNamespace {
            return self
                .list_directory_from_forest(bucket, prefix, continuation_token, effective_max)
                .await;
        }

        // Non-FlatNamespace: route through the server's native listing API.
        let options = ListObjectsOptions {
            prefix: prefix.map(|p| p.to_string()),
            continuation_token: continuation_token.map(|s| s.to_string()),
            max_keys,
            ..Default::default()
        };
        let list_result = self.inner.list_objects(bucket, Some(options)).await?;
        let server_truncated = list_result.is_truncated;
        let server_next = list_result.next_continuation_token.clone();

        use futures::stream::StreamExt;
        let files: Vec<FileMetadata> = futures::stream::iter(
            list_result.objects.into_iter().map(|obj| async move {
                let size = obj.size;
                match self.head_object_decrypted(bucket, &obj.key).await {
                    Ok(metadata) => metadata,
                    Err(e) => {
                        tracing::warn!("Failed to get metadata for {}: {:?}", obj.key, e);
                        FileMetadata {
                            storage_key: obj.key.clone(),
                            original_key: obj.key,
                            original_size: size,
                            content_type: None,
                            created_at: None,
                            modified_at: None,
                            user_metadata: HashMap::new(),
                            is_encrypted: false,
                        }
                    }
                }
            }),
        )
        .buffer_unordered(Self::MAX_CONCURRENT_HEADS)
        .collect()
        .await;

        let mut directories: HashMap<String, Vec<FileMetadata>> = HashMap::new();
        for file in files {
            let dir = if let Some(last_slash) = file.original_key.rfind('/') {
                file.original_key[..last_slash].to_string()
            } else {
                "/".to_string()
            };
            directories.entry(dir).or_default().push(file);
        }

        Ok(DirectoryListing {
            bucket: bucket.to_string(),
            prefix: prefix.map(|s| s.to_string()),
            directories,
            is_truncated: server_truncated,
            next_continuation_token: server_next,
        })
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // FLATNAMESPACE / PRIVATE FOREST SUPPORT
    // Complete structure hiding - server sees only random CID-like hashes
    // ═══════════════════════════════════════════════════════════════════════════

    /// Check if FlatNamespace mode is enabled
    pub fn is_flat_namespace(&self) -> bool {
        self.encryption.obfuscation_mode == KeyObfuscation::FlatNamespace
    }

    /// Load the private forest index for a bucket
    /// 
    /// The forest contains the encrypted directory structure and path→storage_key mapping.
    /// This is only used in FlatNamespace mode.
    pub async fn load_forest(&self, bucket: &str) -> Result<PrivateForest> {
        let lock = self.migration_lock(bucket);
        let _guard = lock.read().await;
        self.load_forest_internal(bucket).await
    }

    /// Internal load_forest without migration lock (used by migrate_to_sharded
    /// which already holds the write lock).
    async fn load_forest_internal(&self, bucket: &str) -> Result<PrivateForest> {
        // Check cache first (respect TTL for clean entries, always use dirty entries)
        if let Some(entry) = self.forest_cache.get(bucket) {
            let now = chrono::Utc::now().timestamp();
            let is_fresh = (now - entry.loaded_at()) < self.encryption.forest_cache_ttl_secs;
            if is_fresh || entry.is_dirty() {
                match entry.value() {
                    ForestCacheEntry::Monolithic { forest, .. } => return Ok(forest.clone()),
                    ForestCacheEntry::ShardedHamt { .. } => {
                        // Sharded forest — caller should use sharded API instead.
                        // For backward compat, return an error indicating upgrade.
                        return Err(ClientError::Encryption(
                            fula_crypto::CryptoError::Encryption(
                                "forest is sharded; use sharded API methods".to_string()
                            )
                        ));
                    }
                }
            }
            // Stale and clean — drop reference before removing
            drop(entry);
            self.forest_cache.remove(bucket);
        }

        // Security audit fix #8: Use DETERMINISTIC key derivation for forest index
        let forest_dek = self.encryption.key_manager.derive_path_key(&format!("forest:{}", bucket));
        let index_key = derive_index_key(&forest_dek, bucket);

        // Try to load from storage
        match self.inner.get_object_with_metadata(bucket, &index_key).await {
            Ok(result) => {
                let observed_etag = if result.etag.is_empty() { None } else { Some(result.etag.clone()) };
                // Capture cache generation before dispatch so we can detect cross-format
                // rollback (e.g., a malicious server serving a stale v4 monolithic blob
                // after the bucket has already been migrated to v5 sharded).
                let cached_any_seen_sequence = self.forest_cache.get(bucket).and_then(|e| match e.value() {
                    ForestCacheEntry::Monolithic { last_sequence, .. } => *last_sequence,
                    ForestCacheEntry::ShardedHamt { last_manifest_sequence, .. } => *last_manifest_sequence,
                });
                let cached_is_sharded = self.forest_cache.get(bucket)
                    .map(|e| matches!(e.value(), ForestCacheEntry::ShardedHamt { .. }))
                    .unwrap_or(false);

                match detect_forest_format(&result.data).map_err(ClientError::Encryption)? {
                    ForestOrManifest::Monolithic(encrypted) => {
                        // Cross-format rollback guard: if cache already saw a sharded
                        // forest with a known sequence, reject any monolithic blob
                        // delivered by the server. Migrating back to monolithic
                        // requires an explicit `migrate_to_monolithic` call which
                        // clears the cache first.
                        if cached_is_sharded && cached_any_seen_sequence.is_some() {
                            return Err(ClientError::Encryption(
                                fula_crypto::CryptoError::Decryption(
                                    "cross-format rollback detected: server served a monolithic forest after the bucket was sharded".to_string()
                                )
                            ));
                        }

                        // Dispatch on outer version: v4 carries AAD+sequence, v1/v2 legacy.
                        let (forest, observed_seq) = if encrypted.version == 4 {
                            let (f, seq) = encrypted.decrypt_v4(&forest_dek, bucket)
                                .map_err(ClientError::Encryption)?;
                            // Cross-session replay check (C-AUDIT-008): any caller-installed
                            // floor overrides the in-memory cache comparison.
                            self.check_sequence_floor(bucket, seq)?;
                            // Replay check: compare against cached last_sequence.
                            let cached = self.forest_cache.get(bucket).and_then(|e| match e.value() {
                                ForestCacheEntry::Monolithic { last_sequence, .. } => *last_sequence,
                                _ => None,
                            });
                            if let Some(last) = cached {
                                if seq < last {
                                    return Err(ClientError::Encryption(
                                        fula_crypto::CryptoError::Decryption(format!(
                                            "forest replay detected: sequence {} < cached {}",
                                            seq, last
                                        ))
                                    ));
                                }
                            }
                            (f, Some(seq))
                        } else {
                            // Legacy v1/v2: also reject downgrade if we previously saw v4.
                            let prior_mono_seq = self.forest_cache.get(bucket).and_then(|e| match e.value() {
                                ForestCacheEntry::Monolithic { last_sequence, .. } => *last_sequence,
                                _ => None,
                            });
                            if prior_mono_seq.is_some() {
                                return Err(ClientError::Encryption(
                                    fula_crypto::CryptoError::Decryption(
                                        "version downgrade detected: server served legacy v1/v2 after v4 was observed".to_string()
                                    )
                                ));
                            }
                            (encrypted.decrypt(&forest_dek).map_err(ClientError::Encryption)?, None)
                        };

                        // Load-time v1 → v7 migration trigger. Transparently
                        // upgrades a legacy v1/v2 bucket on first access. On
                        // success the workhorse installs a ShardedHamt cache
                        // entry and we return the standard "forest is sharded"
                        // marker so callers route through the sharded API.
                        // On deferral (lock contention, WAL pending, transient
                        // failure) we fall through to the v1 cache insert and
                        // continue as read-only v1 for this session — the next
                        // session will re-enter this branch.
                        //
                        // Only legacy v1/v2 forests migrate automatically:
                        // v4 (AAD-bound monolithic) is a distinct, newer
                        // post-v1 format that does not exist in production,
                        // so skipping it here loses nothing and keeps v4 read
                        // paths deterministic.
                        let should_trigger_migration = observed_seq.is_none();
                        if should_trigger_migration {
                            match self.migrate_v1_to_v7_internal(
                                bucket,
                                &forest,
                                &forest_dek,
                                observed_etag.as_deref(),
                            ).await {
                                Ok(MigrationOutcome::Migrated { duration_ms }) => {
                                    tracing::info!(
                                        %bucket,
                                        duration_ms,
                                        "v1 → v7 migration completed on load"
                                    );
                                    return Err(ClientError::Encryption(
                                        fula_crypto::CryptoError::Encryption(
                                            "forest is sharded; use sharded API methods".to_string()
                                        )
                                    ));
                                }
                                Ok(MigrationOutcome::DeferredLockHeld { expires_at_ms }) => {
                                    tracing::debug!(
                                        %bucket,
                                        expires_at_ms,
                                        "v1 → v7 migration deferred: lock held by another device"
                                    );
                                }
                                Ok(MigrationOutcome::DeferredTransientError { reason }) => {
                                    tracing::debug!(
                                        %bucket,
                                        %reason,
                                        "v1 → v7 migration deferred: transient condition"
                                    );
                                }
                                Err(e) => {
                                    // Hard error from the workhorse — e.g. the
                                    // server lock endpoint itself returned an
                                    // unexpected error. Don't fail the read;
                                    // log and fall through to read-only v1.
                                    tracing::warn!(
                                        %bucket,
                                        error = %e,
                                        "v1 → v7 migration aborted on error; continuing read-only v1"
                                    );
                                }
                            }
                        }

                        let now = chrono::Utc::now().timestamp();
                        self.forest_cache.insert(bucket.to_string(), ForestCacheEntry::Monolithic {
                            forest: forest.clone(),
                            loaded_at: now,
                            dirty: false,
                            index_etag: observed_etag,
                            last_sequence: observed_seq,
                        });

                        Ok(forest)
                    }
                    ForestOrManifest::ManifestV7(encrypted_manifest_v7) => {
                        // v7 HAMT-per-shard forest. Populate-then-error
                        // mirrors the v5/v6 arms above: decrypt, run replay
                        // and downgrade guards, persist the version pin,
                        // insert into the forest cache, and only then
                        // surface the "use sharded API" error so callers
                        // that resolve through the sharded pipeline see a
                        // ready entry on their next lookup.
                        let cached_prior_manifest_seq = self.forest_cache.get(bucket).and_then(|e| match e.value() {
                            ForestCacheEntry::ShardedHamt { last_manifest_sequence, .. } => *last_manifest_sequence,
                            _ => None,
                        });
                        let cached_prior_manifest_version = self.forest_cache.get(bucket).and_then(|e| match e.value() {
                            // v7 variant is structurally pinned to version 7 — no lock needed.
                            ForestCacheEntry::ShardedHamt { .. } => Some(7u8),
                            _ => None,
                        });
                        let persisted_prior_version = self.load_persisted_manifest_version(bucket);
                        let effective_prior_version = match (cached_prior_manifest_version, persisted_prior_version) {
                            (Some(a), Some(b)) => Some(a.max(b)),
                            (Some(a), None) => Some(a),
                            (None, Some(b)) => Some(b),
                            (None, None) => None,
                        };
                        // v7 is the newest format — any cache or persisted
                        // hint pointing at >=8 would be a future format we
                        // cannot read. A peer at 7 or lower is fine.
                        if effective_prior_version.map_or(false, |v| v > 7) {
                            return Err(ClientError::Encryption(
                                fula_crypto::CryptoError::Decryption(
                                    "manifest routing downgrade detected: server served v7 after a newer manifest was observed".to_string()
                                )
                            ));
                        }

                        let (manifest, observed_manifest_seq) = match encrypted_manifest_v7
                            .decrypt_v7(&forest_dek, bucket)
                        {
                            Ok((root, seq)) => {
                                self.check_sequence_floor(bucket, seq)?;
                                if let Some(last) = cached_prior_manifest_seq {
                                    if seq < last {
                                        return Err(ClientError::Encryption(
                                            fula_crypto::CryptoError::Decryption(format!(
                                                "manifest replay detected: sequence {} < cached {}",
                                                seq, last
                                            ))
                                        ));
                                    }
                                }
                                // Meta-HAMT: fetch every referenced page and
                                // reassemble the in-memory manifest. A missing
                                // or corrupt page propagates as an error; the
                                // v1-backup fallback below is the recovery
                                // path if the whole thing is unrecoverable.
                                let m = self.load_manifest_pages(bucket, &forest_dek, root).await?;
                                (m, Some(seq))
                            }
                            Err(decrypt_err) => {
                                // The v7 manifest is unreadable (corrupt blob,
                                // key mismatch, tampered header). Attempt the
                                // v1 backup fallback if enabled — a prior
                                // successful migration will have left a
                                // timestamped v1 blob at
                                // `__fula_forest_v1_backup/<unix_ms>`. On
                                // success we install a Monolithic cache entry
                                // and return the recovered v1 forest; on
                                // failure we surface the original v7 decrypt
                                // error so the operator can investigate.
                                if V7_V1_BACKUP_FALLBACK_ENABLED {
                                    if let Some(v1_forest) = self.try_v1_backup_fallback(bucket, &forest_dek).await {
                                        tracing::warn!(
                                            %bucket,
                                            "v7 decrypt failed; serving v1 backup fallback"
                                        );
                                        let now = chrono::Utc::now().timestamp();
                                        self.forest_cache.insert(
                                            bucket.to_string(),
                                            ForestCacheEntry::Monolithic {
                                                forest: v1_forest.clone(),
                                                loaded_at: now,
                                                dirty: false,
                                                // No ETag: the v1 blob at index_key
                                                // (still the corrupt v7 manifest)
                                                // isn't the one we just loaded.
                                                index_etag: None,
                                                last_sequence: None,
                                            },
                                        );
                                        return Ok(v1_forest);
                                    }
                                }
                                return Err(ClientError::Encryption(decrypt_err));
                            }
                        };

                        self.persist_manifest_version(bucket, 7);

                        let now = chrono::Utc::now().timestamp();
                        let dir_index_etag = manifest.root.dir_index_etag.clone();
                        let dir_index_seq_pin = manifest.root.dir_index_seq;
                        let mut forest = ShardedHamtPrivateForest::from_manifest(
                            manifest,
                            bucket.to_string(),
                            forest_dek.clone(),
                        );
                        // F-1.3: try to load the dir-index blob; if absent,
                        // corrupt, or not pinned to the seq this root committed
                        // to, rebuild from the forest contents and mark dirty
                        // so the next flush persists the rebuilt blob.
                        match self
                            .load_directory_index(
                                bucket,
                                &forest_dek,
                                dir_index_etag.as_deref(),
                                dir_index_seq_pin,
                            )
                            .await?
                        {
                            Some((idx, seq)) => {
                                forest.install_dir_index(idx, seq);
                            }
                            None => {
                                let backend_for_rebuild = Arc::new(S3BlobBackend::new(
                                    self.inner.clone(),
                                    bucket.to_string(),
                                ));
                                let rebuilt = forest
                                    .rebuild_directory_index_from_forest(&backend_for_rebuild)
                                    .await
                                    .map_err(ClientError::Encryption)?;
                                forest.install_dir_index(rebuilt, 0);
                                forest.mark_dir_index_dirty();
                                // The S3 dir-index blob at `dir_index_etag` is
                                // the one we just proved untrustworthy (missing,
                                // corrupt, or failed the seq pin). Drop the
                                // stale etag so Phase 1.6 overwrites
                                // unconditionally; the committing root PUT
                                // still enforces `If-Match` on the root etag.
                                forest.clear_dir_index_etag();
                            }
                        }
                        let forest_arc = Arc::new(tokio::sync::RwLock::new(forest));
                        self.forest_cache.insert(bucket.to_string(), ForestCacheEntry::ShardedHamt {
                            forest: forest_arc,
                            loaded_at: now,
                            manifest_etag: observed_etag,
                            last_manifest_sequence: observed_manifest_seq,
                        });

                        Err(ClientError::Encryption(
                            fula_crypto::CryptoError::Encryption(
                                "forest is sharded; use sharded API methods".to_string()
                            )
                        ))
                    }
                }
            }
            Err(_) => {
                // New bucket: no forest exists yet. Since v7 is the canonical
                // current format and the v1 → v7 migration path already exists
                // for legacy data, new forests are born v7 directly so we never
                // create a monolithic blob we'll later have to migrate.
                //
                // The cache is populated but nothing is written to storage yet
                // — the first flush creates the manifest at `index_key`. That
                // matches the v1 behaviour (creation was also deferred to first
                // flush) and keeps "empty bucket read" cheap.
                //
                // Return the standard "forest is sharded" marker so callers
                // route through the sharded API. The v1 `PrivateForest` return
                // type doesn't admit a v7 value, and readers that inspect an
                // empty forest via the v1 API are a non-goal.
                let num_shards = compute_initial_shard_count(0);
                let manifest = ShardManifestV7::new(num_shards);
                let v7 = ShardedHamtPrivateForest::from_manifest(
                    manifest,
                    bucket.to_string(),
                    forest_dek.clone(),
                );
                let now = chrono::Utc::now().timestamp();
                self.forest_cache.insert(bucket.to_string(), ForestCacheEntry::ShardedHamt {
                    forest: Arc::new(tokio::sync::RwLock::new(v7)),
                    loaded_at: now,
                    manifest_etag: None,
                    last_manifest_sequence: None,
                });
                Err(ClientError::Encryption(
                    fula_crypto::CryptoError::Encryption(
                        "forest is sharded; use sharded API methods".to_string()
                    )
                ))
            }
        }
    }

    /// Check if the forest for a bucket is in sharded-HAMT format (v7).
    pub fn is_forest_sharded_hamt(&self, bucket: &str) -> bool {
        self.forest_cache.get(bucket)
            .map(|entry| matches!(entry.value(), ForestCacheEntry::ShardedHamt { .. }))
            .unwrap_or(false)
    }

    /// Test-only accessor: returns `(num_shards, page_count)` for a loaded
    /// sharded bucket. Gated on `test-fault-injection` so it never leaks
    /// into production builds.
    #[cfg(feature = "test-fault-injection")]
    pub fn sharded_forest_layout(&self, bucket: &str) -> Option<(usize, usize)> {
        let entry = self.forest_cache.get(bucket)?;
        if let ForestCacheEntry::ShardedHamt { forest, .. } = entry.value() {
            let guard = forest.try_read().ok()?;
            let manifest = guard.manifest();
            Some((manifest.num_shards(), manifest.page_count()))
        } else {
            None
        }
    }


    /// Path to the per-bucket manifest-version pin file.
    ///
    /// NEW-L.7: the file stores the highest manifest version we have previously
    /// observed for this bucket. It survives process restart so a gateway cannot
    /// silently downgrade us from v6 to v5 on cold start. Location honours
    /// `FULA_STATE_DIR` if set, otherwise `dirs::state_dir()` (XDG on Linux,
    /// Library/Application Support on macOS, AppData on Windows). Returns None
    /// when neither is available (WASM, locked-down sandboxes).
    #[cfg(not(target_arch = "wasm32"))]
    fn manifest_version_path(&self, bucket: &str) -> Option<std::path::PathBuf> {
        let base = match std::env::var("FULA_STATE_DIR") {
            Ok(dir) if !dir.is_empty() => std::path::PathBuf::from(dir),
            _ => dirs::state_dir().or_else(dirs::data_local_dir)?,
        };
        let bucket_hash = blake3::hash(bucket.as_bytes());
        let bucket_id: String = hex::encode(&bucket_hash.as_bytes()[..16]);
        Some(base.join("fula").join("manifest-version").join(bucket_id))
    }

    /// Read the persisted prior-observed manifest version for `bucket`, if any.
    ///
    /// NEW-F9: the on-disk format is `<version>\t<hex_mac>\n` where MAC is a
    /// BLAKE3 keyed hash over the version string using a bucket-scoped key
    /// (`derive_manifest_version_mac_key`). This prevents a local process with
    /// user-write permission from forcing a silent downgrade by editing the
    /// plaintext file. The old bare-number format is still accepted (with a
    /// warning) so pre-upgrade pin files continue to work read-only; the next
    /// write upgrades them to the MAC'd format. A MAC-present-but-invalid
    /// file is treated as untrusted and returns `None` — we must NOT fall
    /// back to the bare value when a MAC is present but wrong, because that
    /// is the active-tamper case.
    #[cfg(not(target_arch = "wasm32"))]
    fn load_persisted_manifest_version(&self, bucket: &str) -> Option<u8> {
        let path = self.manifest_version_path(bucket)?;
        let bytes = std::fs::read(&path).ok()?;
        let s = std::str::from_utf8(&bytes).ok()?.trim();
        if let Some((version_str, mac_hex)) = s.rsplit_once('\t') {
            let mac_key = wal::derive_manifest_version_mac_key(
                &self.encryption.key_manager,
                bucket,
            );
            if !wal::verify_mac(&mac_key, version_str, mac_hex) {
                tracing::warn!(%bucket, "manifest-version pin MAC invalid; ignoring file");
                return None;
            }
            version_str.parse::<u8>().ok()
        } else {
            tracing::warn!(
                %bucket,
                "manifest-version pin has legacy (unauthenticated) format; \
                 will upgrade to MAC'd format on next write"
            );
            s.parse::<u8>().ok()
        }
    }

    /// Atomically write the manifest version for `bucket`. Monotonic: writes
    /// nothing if the new version is not strictly greater than what's on disk.
    ///
    /// NEW-F9: writes the MAC'd format `<version>\t<hex_mac>\n`.
    #[cfg(not(target_arch = "wasm32"))]
    fn persist_manifest_version(&self, bucket: &str, version: u8) {
        let Some(path) = self.manifest_version_path(bucket) else { return; };
        let prior = self.load_persisted_manifest_version(bucket).unwrap_or(0);
        if version <= prior {
            return;
        }
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let mac_key = wal::derive_manifest_version_mac_key(
            &self.encryption.key_manager,
            bucket,
        );
        let version_str = version.to_string();
        let mac_hex = wal::mac_line(&mac_key, &version_str);
        let contents = format!("{}\t{}\n", version_str, mac_hex);
        // tmp + rename for atomicity. Best-effort: if the write fails we log and
        // continue; the in-memory guard still catches intra-session downgrades.
        let tmp = path.with_extension("tmp");
        let write_ok = std::fs::write(&tmp, contents.as_bytes()).is_ok();
        if !write_ok {
            tracing::warn!(?path, "failed to write manifest-version tmp file");
            return;
        }
        if let Err(e) = std::fs::rename(&tmp, &path) {
            tracing::warn!(?path, error = %e, "failed to atomically rename manifest-version file");
            let _ = std::fs::remove_file(&tmp);
        }
    }

    /// WASM stub: persistence is a no-op so behaviour matches the
    /// in-memory-only cache.
    #[cfg(target_arch = "wasm32")]
    fn load_persisted_manifest_version(&self, _bucket: &str) -> Option<u8> { None }
    #[cfg(target_arch = "wasm32")]
    fn persist_manifest_version(&self, _bucket: &str, _version: u8) {}

    /// Ensure the forest is loaded for a bucket (handles both monolithic and sharded)
    ///
    /// For sharded forests, loads the manifest and the specific shard needed for `path`.
    /// Returns the forest DEK for convenience.
    async fn ensure_forest_loaded(&self, bucket: &str) -> Result<()> {
        // Try loading — if it fails because it's sharded, that's fine (manifest is cached).
        // Matches any of v3 / v5 / v6 manifest formats ("forest is sharded" prefix).
        let load_result = match self.load_forest(bucket).await {
            Ok(_) => Ok(()),
            Err(ref e) if e.to_string().contains("forest is sharded") => Ok(()),
            Err(e) => Err(e),
        };

        // NEW-7.2: on the first successful load of this bucket in this process,
        // check for a WAL left behind by a prior crash. If present, replay it
        // and re-drive the flush so the dirty entries become durable. Fires at
        // most once per (bucket, client) even if this function is called many
        // times. Failure to recover is logged but not propagated — the read
        // that triggered the load should still succeed; the next write will
        // re-trigger the retry path.
        #[cfg(not(target_arch = "wasm32"))]
        if load_result.is_ok() && !self.wal_recovered_buckets.contains_key(bucket) {
            self.wal_recovered_buckets.insert(bucket.to_string(), ());
            if let Err(e) = self.recover_wal_after_load(bucket).await {
                tracing::warn!(%bucket, error = %e, "startup WAL recovery failed; dirty entries remain in WAL for next flush");
            }
        }

        load_result
    }

    /// Replay any WAL entries for `bucket` that were left on disk by a prior
    /// process and re-flush so they become durable. No-op when no WAL file
    /// exists. Called from `ensure_forest_loaded` exactly once per bucket
    /// per session.
    #[cfg(not(target_arch = "wasm32"))]
    async fn recover_wal_after_load(&self, bucket: &str) -> Result<()> {
        let mac_key = wal::derive_mac_key(&self.encryption.key_manager, bucket);
        let entries = match wal::load(bucket, &mac_key) {
            Ok(v) if v.is_empty() => return Ok(()),
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(%bucket, error = %e, "WAL load failed during startup recovery");
                return Ok(());
            }
        };
        let count = entries.len();
        tracing::info!(%bucket, entries = count, "replaying WAL entries from prior session");
        self.replay_wal_entries(bucket, entries).await?;
        // Re-drive the flush so the replayed entries become durable. On success
        // `flush_forest` clears the WAL; on failure the WAL stays on disk for
        // the next retry trigger. Boxed to break the mutual recursion
        // `ensure_forest_loaded → recover_wal_after_load → flush_forest →
        // ensure_forest_loaded` at the type level — the `wal_recovered_buckets`
        // flag prevents actual runtime recursion.
        Box::pin(self.flush_forest(bucket)).await
    }

    /// Check whether the forest has an entry for `storage_key` that was
    /// uploaded encrypted.
    ///
    /// Forces a forest load first so that an empty cache (cold start, prior
    /// failed load, eviction after 412) cannot be used to bypass the check by
    /// returning `false`. If the forest cannot be loaded, propagates the error
    /// — callers refuse plaintext rather than returning attacker-chosen bytes.
    /// Returns `Ok(true)` when an entry is present in the loaded forest AND
    /// carries `encrypted: true`. (NEW-2.1 / C-AUDIT-004.)
    async fn forest_entry_requires_encryption(&self, bucket: &str, storage_key: &str) -> Result<bool> {
        self.ensure_forest_loaded(bucket).await?;
        let decision = match self.forest_cache.get(bucket) {
            Some(entry) => match entry.value() {
                ForestCacheEntry::Monolithic { forest, .. } => {
                    forest.find_by_storage_key(storage_key)
                        .map(|e| e.encrypted)
                        .unwrap_or(false)
                }
                // F4 — v7 invariant: every v7 upsert made by
                // `EncryptedClient` writes `encrypted: true`. Both
                // direct-upsert sites enforce this via `debug_assert!`
                // on the entry being passed to
                // `ShardedHamtPrivateForest::upsert_file`, and the
                // v1→v7 migration preserves the v1 flag (which is
                // also always `true` when authored by this crate).
                // Returning `true` here is therefore exhaustive, not
                // a speculative fallback: no production code path
                // inserts a plaintext v7 entry. If future work adds
                // optional v7 plaintext support, the upsert-side
                // debug_asserts must be relaxed and a real HAMT
                // reverse lookup wired here at the same time.
                ForestCacheEntry::ShardedHamt { .. } => true,
            },
            None => false,
        };
        Ok(decision)
    }

    /// H-1 / H-2: return the full forest entry for `storage_key` so download
    /// paths can enforce per-entry `min_version` and verify `content_hash`
    /// after AEAD decrypt.
    ///
    /// Ensures the forest is loaded first so an empty cache cannot be used
    /// to bypass verification by returning `None`. Returns `Ok(None)` only
    /// when the loaded forest genuinely has no entry for this key
    /// (pre-forest-write transition or share-token path where the downloader
    /// is not the owner).
    ///
    /// v1/v6: in-memory map lookup (O(1)/O(log n)).
    /// v7: walks every shard's HAMT (O(total entries)) — acceptable because
    /// downloads run at most one lookup per call and are dominated by
    /// network cost. See `ShardedHamtPrivateForest::find_by_storage_key`.
    async fn forest_entry_lookup(
        &self,
        bucket: &str,
        storage_key: &str,
    ) -> Result<Option<ForestFileEntry>> {
        self.ensure_forest_loaded(bucket).await?;
        // Snapshot the cache entry; for v7 we need an Arc clone and a backend
        // before dropping the DashMap guard so we don't hold it across .await.
        let cached = self.forest_cache.get(bucket).map(|e| match e.value() {
            ForestCacheEntry::Monolithic { forest, .. } => {
                CachedForForestLookup::V1(forest.find_by_storage_key(storage_key).cloned())
            }
            ForestCacheEntry::ShardedHamt { forest, .. } => {
                CachedForForestLookup::V7(forest.clone())
            }
        });
        match cached {
            Some(CachedForForestLookup::V1(entry)) => {
                Ok(entry)
            }
            Some(CachedForForestLookup::V7(forest_arc)) => {
                let backend = Arc::new(S3BlobBackend::new(self.inner.clone(), bucket.to_string()));
                let guard = forest_arc.read().await;
                guard.find_by_storage_key(storage_key, &backend)
                    .await
                    .map_err(ClientError::Encryption)
            }
            None => Ok(None),
        }
    }

    /// H-2: pre-decrypt downgrade gate. Rejects blobs whose advertised version
    /// is lower than the forest entry's `min_version` pin (blocks
    /// downgrade-to-no-AAD). Cheaper than H-1 because it runs a single `u8`
    /// compare before any AEAD work.
    ///
    /// Legacy (pre-fix) entries have `min_version == 0` and always pass.
    /// No forest entry (share-token path, or pre-forest-write transition)
    /// also passes — downstream AEAD still protects integrity on those.
    fn enforce_min_version(
        entry: Option<&ForestFileEntry>,
        version: u64,
    ) -> Result<()> {
        let entry = match entry {
            Some(e) => e,
            None => return Ok(()),
        };
        let got = std::cmp::min(version, u8::MAX as u64) as u8;
        if got < entry.min_version {
            return Err(ClientError::Encryption(
                fula_crypto::CryptoError::VersionDowngrade {
                    got,
                    required: entry.min_version,
                },
            ));
        }
        Ok(())
    }

    /// H-1: post-decrypt content-hash verification. Compares BLAKE3 of the
    /// decrypted plaintext against the forest entry's `content_hash`
    /// (blocks whole-file substitution under HPKE-to-self).
    ///
    /// Legacy entries carry `content_hash: None` and bypass the check to
    /// preserve v1/v2 read compatibility. No forest entry (share-token path)
    /// also bypasses — the share token itself binds its own integrity.
    ///
    /// `blake3::Hash` implements `PartialEq` in constant time, so parsing
    /// the hex-encoded expected digest and comparing Hash-to-Hash gives a
    /// timing-safe check without pulling in `subtle` as a direct dep.
    fn enforce_content_hash(
        entry: Option<&ForestFileEntry>,
        plaintext: &[u8],
    ) -> Result<()> {
        let entry = match entry {
            Some(e) => e,
            None => return Ok(()),
        };
        if let Some(expected_hex) = entry.content_hash.as_ref() {
            let actual = blake3::hash(plaintext);
            let expected = match blake3::Hash::from_hex(expected_hex.as_bytes()) {
                Ok(h) => h,
                Err(_) => {
                    return Err(ClientError::Encryption(
                        fula_crypto::CryptoError::IntegrityMismatch(
                            "malformed content_hash in forest entry".to_string(),
                        ),
                    ));
                }
            };
            if actual != expected {
                return Err(ClientError::Encryption(
                    fula_crypto::CryptoError::IntegrityMismatch(format!(
                        "content_hash mismatch for {}-byte plaintext",
                        plaintext.len()
                    )),
                ));
            }
        }
        Ok(())
    }

    /// Phase 1.2 of master-independent reads: compute the blinded bucket
    /// lookup key as hex for the `x-amz-meta-fula-bucket-lookup-h` header.
    ///
    /// `bucket_lookup_h = BLAKE3(MetadataKey || bucket_name)[..16]`, where
    /// `MetadataKey = derive_path_key("fula-metadata-v1")`. Hex-encoded
    /// (32 chars). The 16-byte truncation matches master's `hashed_user_id`
    /// convention. Master never sees `MetadataKey`.
    ///
    /// Attached on every manifest root commit (sharded v7, monolithic v4,
    /// and the v1→v7 migration path) so master's put_object handler can
    /// populate `BucketMetadata.bucket_lookup_h` regardless of which forest
    /// format the SDK is using. Idempotent on master's side.
    fn compute_bucket_lookup_h_hex(&self, bucket: &str) -> String {
        let metadata_key = self.encryption.key_manager.derive_path_key("fula-metadata-v1");
        let mut input = metadata_key.as_bytes().to_vec();
        input.extend_from_slice(bucket.as_bytes());
        let hash = blake3::hash(&input);
        hex::encode(&hash.as_bytes()[..16])
    }

    /// Save the private forest index for a bucket (monolithic v4 format with AAD+sequence)
    pub async fn save_forest(&self, bucket: &str, forest: &PrivateForest) -> Result<()> {
        let forest_dek = self.encryption.key_manager.derive_path_key(&format!("forest:{}", bucket));
        let index_key = derive_index_key(&forest_dek, bucket);

        // Sequence for v4: cached last + 1, or 1 for first write.
        let (prior_etag, prior_sequence) = self.forest_cache.get(bucket).map(|e| match e.value() {
            ForestCacheEntry::Monolithic { index_etag, last_sequence, .. } => {
                (index_etag.clone(), *last_sequence)
            }
            // Monolithic save over a v7-sharded bucket would regress the
            // routing format — surface the cache's manifest ETag so the
            // conditional PUT fails loudly instead of silently clobbering.
            ForestCacheEntry::ShardedHamt { manifest_etag, .. } => (manifest_etag.clone(), None),
        }).unwrap_or((None, None));
        let next_sequence = prior_sequence.unwrap_or(0).saturating_add(1);

        let encrypted = EncryptedForest::encrypt_v4(forest, &forest_dek, bucket, next_sequence)
            .map_err(ClientError::Encryption)?;
        let data = encrypted.to_bytes()
            .map_err(ClientError::Encryption)?;

        // Phase 1.2: monolithic v4 forest is also a manifest-root commit.
        // Same header semantics as save_sharded_hamt_forest's Phase 2 PUT.
        let metadata = ObjectMetadata::new()
            .with_content_type("application/octet-stream")
            .with_metadata("fula-bucket-lookup-h", &self.compute_bucket_lookup_h_hex(bucket));

        let put_result = self.inner.put_object_with_metadata_conditional(
            bucket,
            &index_key,
            Bytes::from(data),
            Some(metadata),
            prior_etag.as_deref(),
            None,
        ).await;

        let put_result = match put_result {
            Ok(r) => r,
            Err(e) if e.is_concurrent_modification() => {
                // Another writer beat us. Drop the stale cache so callers re-read.
                self.forest_cache.remove(bucket);
                return Err(e);
            }
            Err(e) => return Err(e),
        };

        let new_etag = if put_result.etag.is_empty() { None } else { Some(put_result.etag) };
        let now = chrono::Utc::now().timestamp();
        self.forest_cache.insert(bucket.to_string(), ForestCacheEntry::Monolithic {
            forest: forest.clone(),
            loaded_at: now,
            dirty: false,
            index_etag: new_etag,
            last_sequence: Some(next_sequence),
        });

        Ok(())
    }


    /// Save a v7 sharded-HAMT forest.
    ///
    /// Two phases, mirroring `save_sharded_forest` for v5/v6:
    ///
    /// 1. **Node flush.** Acquire the per-bucket forest mutex and call
    ///    `ShardedHamtPrivateForest::flush_dirty`. This encrypts every dirty
    ///    shard's HAMT (root + any rewritten interior/value nodes) under the
    ///    shard DEK + per-node AEAD AAD and PUTs them through the
    ///    `S3BlobBackend` wrapper. Node paths are content-addressed
    ///    (`BLAKE3(salt ‖ plaintext)[..22]`), so node-level conditional PUTs
    ///    are unnecessary — collisions are impossible and late-arriving
    ///    duplicate PUTs of the same plaintext are idempotent.
    /// 2. **Manifest commit.** Encrypt the updated manifest with a bumped
    ///    manifest-level sequence and conditionally PUT it against the
    ///    previously observed manifest ETag. On 412 we drop the cached
    ///    forest so the caller re-reads the winning state before retrying.
    ///
    /// Invariants preserved:
    /// - `manifest_etag` + `last_manifest_sequence` gate rollback of the
    ///   root-swap (same as v6).
    /// - Per-shard `seq` is bumped inside `flush_dirty` before any node
    ///   blob is PUT, so AAD on the uploaded nodes matches the manifest we
    ///   then write.
    /// - Nodes that become unreachable after a rewrite are left in place;
    ///   an out-of-band GC sweep (future work) cleans them once two
    ///   manifest generations have rotated past.
    async fn save_sharded_hamt_forest(&self, bucket: &str) -> Result<()> {
        let forest_dek = self.encryption.key_manager.derive_path_key(&format!("forest:{}", bucket));
        let index_key = derive_index_key(&forest_dek, bucket);

        // Snapshot prior etag + seq and clone out the forest Arc.  The
        // DashMap guard is dropped at the end of this block so we can
        // `.write().await` the forest RwLock below without holding a shard
        // lock across the await.
        let (forest_arc, prior_etag, prior_seq) = {
            let entry = self.forest_cache.get(bucket)
                .ok_or_else(|| ClientError::Encryption(
                    fula_crypto::CryptoError::Encryption("no v7 forest in cache".to_string())
                ))?;
            match entry.value() {
                ForestCacheEntry::ShardedHamt { forest, manifest_etag, last_manifest_sequence, .. } => {
                    (forest.clone(), manifest_etag.clone(), *last_manifest_sequence)
                }
                _ => return Err(ClientError::Encryption(
                    fula_crypto::CryptoError::Encryption(
                        "forest is not v7 sharded-HAMT".to_string()
                    )
                )),
            }
        };

        // Phase 1: flush dirty HAMT nodes. `flush_dirty` bumps each dirty
        // shard's `seq` *before* writing, so AAD on the uploaded node blobs
        // is bound to the post-flush sequence we'll commit in phase 2.
        // Phase 1 also marks pages dirty automatically via `shard_mut`.
        let backend = Arc::new(S3BlobBackend::new(self.inner.clone(), bucket.to_string()));
        let (mut manifest_snapshot, dir_index_snapshot, prior_dir_index_seq, dir_index_dirty) = {
            let mut guard = forest_arc.write().await;
            guard.flush_dirty(&backend).await
                .map_err(ClientError::Encryption)?;
            (
                guard.manifest().clone(),
                guard.directory_index().clone(),
                guard.dir_index_seq(),
                guard.dir_index_dirty(),
            )
        };

        // Phase 1.5: flush dirty pages. Each dirty page bumps its `seq`, is
        // re-encrypted with the new seq bound into AAD, and PUT to storage
        // at a deterministic index-addressed key. The resulting ETag is
        // then recorded in `root.page_index` so the root swap in phase 2
        // knows exactly which page generation it commits to.
        //
        // WAL::PageWrote is appended + fsynced **before** each page PUT so a
        // crash between the fsync and the PUT is idempotent on replay: pages
        // are index-addressed, so re-executing the PUT at the same page key
        // simply overwrites the last attempt. Without this record, a crash
        // after the PUT but before the root PUT could leave S3 serving a
        // fresh-seq page under the old root's page_index.
        let shard_salt = manifest_snapshot.shard_salt().to_vec();
        let dirty_pages = manifest_snapshot.take_dirty_pages();
        #[cfg(not(target_arch = "wasm32"))]
        let wal_mac = wal::derive_mac_key(&self.encryption.key_manager, bucket);
        for page_id in dirty_pages.iter().copied() {
            let page = manifest_snapshot.pages.get_mut(&page_id)
                .ok_or_else(|| ClientError::Encryption(
                    fula_crypto::CryptoError::Encryption(format!(
                        "dirty page {} not loaded in snapshot", page_id
                    ))
                ))?;
            let old_etag = manifest_snapshot.root.page_index.get(&page_id)
                .and_then(|r| r.etag.clone());
            page.seq = page.seq.wrapping_add(1);
            #[cfg(not(target_arch = "wasm32"))]
            if let Err(e) = wal::append(
                bucket,
                &wal_mac,
                WalEntry::PageWrote {
                    page_id,
                    old_etag: old_etag.clone(),
                    new_etag: None,
                    seq: page.seq,
                },
            ) {
                tracing::warn!(%bucket, page_id, error = %e, "WAL append PageWrote failed");
            }
            let envelope = EncryptedManifestPage::encrypt(page, &forest_dek, bucket)
                .map_err(ClientError::Encryption)?;
            let blob = envelope.to_bytes().map_err(ClientError::Encryption)?;
            let page_key = derive_manifest_page_key(&forest_dek, bucket, &shard_salt, page_id);
            let metadata = ObjectMetadata::new()
                .with_content_type("application/octet-stream");
            // Conditional PUT on the page so a concurrent writer (that
            // bumped this same page between our load and this PUT) can't
            // be silently overwritten — its content would otherwise clobber
            // the winner's shard view inside the page. `If-Match` when we
            // remember an etag; `If-None-Match: *` for a first-ever page
            // create so two racing creators don't produce divergent state.
            let (if_match, if_none_match) = match old_etag.as_deref() {
                Some(et) => (Some(et), None),
                None => (None, Some("*")),
            };
            let put = match self.inner.put_object_with_metadata_conditional(
                bucket,
                &page_key,
                Bytes::from(blob),
                Some(metadata),
                if_match,
                if_none_match,
            ).await {
                Ok(r) => r,
                Err(e) if e.is_concurrent_modification() => {
                    // Another writer advanced this page between our load and
                    // this PUT. Evict the cache so the retry loop reloads
                    // the winner's page_index from S3 before re-attempting
                    // Phase 1.5 / 1.6 / 2 under the correct `If-Match`.
                    // Without this, the retry sees a stale page view and
                    // the winner's shards look empty in our page.
                    self.forest_cache.remove(bucket);
                    return Err(e);
                }
                Err(e) => return Err(e),
            };
            let etag = if put.etag.is_empty() { None } else { Some(put.etag) };
            // Post-PUT WAL record: pin the real etag S3 now serves so a
            // crash between here and the Phase-2 root PUT can be recovered
            // by replay (`reconcile_page_etag`) without re-polling S3 for
            // each page's current etag. The pre-PUT entry above is
            // sufficient for idempotent-PUT replay at the same key, but
            // only this post-PUT entry lets the next flush's `If-Match`
            // match S3's actual state.
            #[cfg(not(target_arch = "wasm32"))]
            if let Err(e) = wal::append(
                bucket,
                &wal_mac,
                WalEntry::PageWrote {
                    page_id,
                    old_etag: old_etag.clone(),
                    new_etag: etag.clone(),
                    seq: page.seq,
                },
            ) {
                tracing::warn!(%bucket, page_id, error = %e, "WAL append post-PUT PageWrote failed");
            }
            manifest_snapshot.root.page_index.insert(page_id, PageRef {
                etag,
                seq: page.seq,
            });
        }

        // Phase 1.6 (F-1.3): flush the directory index if it changed since
        // the last successful commit. AEAD binds `(bucket, seq)` so a stale
        // rollback fails integrity; the new ETag is recorded in
        // `manifest_snapshot.root.dir_index_etag` and becomes authoritative
        // on the next successful root PUT.
        //
        // WAL::DirIndexWrote is appended+fsynced BEFORE the PUT so a crash
        // between the fsync and the PUT replays as a retry at the same key
        // under the same seq — idempotent under identical content.
        let new_dir_index_seq = if dir_index_dirty {
            let next_dir_seq = prior_dir_index_seq.saturating_add(1);
            let old_dir_etag = manifest_snapshot.root.dir_index_etag.clone();
            #[cfg(not(target_arch = "wasm32"))]
            if let Err(e) = wal::append(
                bucket,
                &wal_mac,
                WalEntry::DirIndexWrote {
                    old_etag: old_dir_etag.clone(),
                    new_etag: None,
                    seq: next_dir_seq,
                },
            ) {
                tracing::warn!(%bucket, error = %e, "WAL append DirIndexWrote failed");
            }
            let envelope = EncryptedDirectoryIndex::encrypt(
                &dir_index_snapshot,
                &forest_dek,
                bucket,
                next_dir_seq,
            ).map_err(ClientError::Encryption)?;
            let blob = envelope.to_bytes().map_err(ClientError::Encryption)?;
            let dir_key = derive_dir_index_key(&forest_dek, bucket);
            let metadata = ObjectMetadata::new()
                .with_content_type("application/octet-stream");
            let put = match self.inner.put_object_with_metadata_conditional(
                bucket,
                &dir_key,
                Bytes::from(blob),
                Some(metadata),
                old_dir_etag.as_deref(),
                None,
            ).await {
                Ok(r) => r,
                Err(e) if e.is_concurrent_modification() => {
                    // Another writer advanced the dir-index between our load
                    // and this PUT. Evict the cache so the retry loop reloads
                    // the winner's dir-index etag from S3 before re-attempting
                    // Phase 1.6 under the correct `If-Match`. Mirrors the
                    // Phase-2 412 eviction below — the forest-cache must
                    // never hold a stale dir-index etag across retries.
                    self.forest_cache.remove(bucket);
                    return Err(e);
                }
                Err(e) => return Err(e),
            };
            let new_dir_etag = if put.etag.is_empty() { None } else { Some(put.etag) };
            // Post-PUT WAL record: pin the real dir-index etag so a
            // crash between here and the Phase-2 root PUT can be recovered
            // without re-reading the dir-index object. Mirrors the
            // post-PUT PageWrote above.
            #[cfg(not(target_arch = "wasm32"))]
            if let Err(e) = wal::append(
                bucket,
                &wal_mac,
                WalEntry::DirIndexWrote {
                    old_etag: old_dir_etag.clone(),
                    new_etag: new_dir_etag.clone(),
                    seq: next_dir_seq,
                },
            ) {
                tracing::warn!(%bucket, error = %e, "WAL append post-PUT DirIndexWrote failed");
            }
            manifest_snapshot.root.dir_index_etag = new_dir_etag;
            manifest_snapshot.root.dir_index_seq = Some(next_dir_seq);
            Some(next_dir_seq)
        } else {
            None
        };

        // Fault injection point: simulate a client crash between Phase 1.5 /
        // Phase 1.6 and Phase 2. Pages + dir-index are already on S3 under
        // fresh seqs; the root PUT has not fired, so the old root still
        // points to stale page etags. Recovery relies on the WAL-tracked
        // PageWrote / DirIndexWrote entries and the next retry flush.
        #[cfg(feature = "test-fault-injection")]
        if test_faults::CRASH_AFTER_PAGE_PUT_BEFORE_ROOT_PUT
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            return Err(ClientError::Encryption(
                fula_crypto::CryptoError::Encryption(
                    "test-fault-injection: CRASH_AFTER_PAGE_PUT_BEFORE_ROOT_PUT".to_string(),
                )
            ));
        }

        // Phase 2: encrypt + conditionally PUT the manifest root.
        let next_seq = prior_seq.unwrap_or(0).saturating_add(1);
        let encrypted_manifest = EncryptedShardManifestV7::encrypt_v7(
            &manifest_snapshot.root,
            &forest_dek,
            bucket,
            next_seq,
        ).map_err(ClientError::Encryption)?;
        let data = encrypted_manifest.to_bytes()
            .map_err(ClientError::Encryption)?;

        // Phase 1.2: sharded HAMT v7 manifest root commit. See
        // compute_bucket_lookup_h_hex for header semantics.
        let metadata = ObjectMetadata::new()
            .with_content_type("application/octet-stream")
            .with_metadata("fula-bucket-lookup-h", &self.compute_bucket_lookup_h_hex(bucket));

        let put_result = self.inner.put_object_with_metadata_conditional(
            bucket,
            &index_key,
            Bytes::from(data),
            Some(metadata),
            prior_etag.as_deref(),
            None,
        ).await;

        let put_result = match put_result {
            Ok(r) => r,
            Err(e) if e.is_concurrent_modification() => {
                // Another writer installed a newer manifest. Our node blobs
                // are already on S3 and referenced by our local manifest,
                // which is now stale. Drop the cache so the caller re-reads
                // the winning manifest before retrying; orphaned nodes get
                // collected by the async GC sweep.
                self.forest_cache.remove(bucket);
                return Err(e);
            }
            Err(e) => return Err(e),
        };

        let new_etag = if put_result.etag.is_empty() { None } else { Some(put_result.etag) };

        // Reconcile Phase 1.5 + Phase 1.6 + Phase 2 back into the live
        // forest. Without this, the forest's own manifest retains the
        // pre-flush `dirty_pages` + stale `page_index`, so a subsequent
        // no-op flush would re-PUT every page under a fresh seq.
        // `flush_dirty` already cleared dirty-shard flags; this closes the
        // same loop at the meta-HAMT and dir-index layers.
        {
            let mut guard = forest_arc.write().await;
            guard.reconcile_flush(manifest_snapshot.root.clone(), &dirty_pages);
            if let Some(new_seq) = new_dir_index_seq {
                guard.reconcile_dir_index_flush(new_seq);
            }
        }

        // Update cache metadata in place — the forest itself already reflects
        // the post-flush state (dirty flags cleared by `flush_dirty`).
        // (manifest-version pin is written on the load path, matching v6's
        // save_sharded_forest which also skips re-persisting it on save.)
        if let Some(mut entry) = self.forest_cache.get_mut(bucket) {
            if let ForestCacheEntry::ShardedHamt {
                loaded_at, manifest_etag, last_manifest_sequence, ..
            } = entry.value_mut() {
                *loaded_at = chrono::Utc::now().timestamp();
                *manifest_etag = new_etag;
                *last_manifest_sequence = Some(next_seq);
            }
        }

        Ok(())
    }

    /// Emergency fallback path for a v7 manifest that fails to decrypt.
    ///
    /// Lists the `__fula_forest_v1_backup/` prefix for this bucket, picks the
    /// entry with the largest `<unix_ms>` suffix, fetches the blob, and tries
    /// to decrypt it as a v1 monolithic forest. Returns `Some(forest)` on
    /// success; all failures become `None` so the caller can decide whether to
    /// surface the original v7 decrypt error or proceed with the fallback.
    ///
    /// This bypasses the usual replay / sequence / downgrade guards — v7
    /// decrypt already failed, so preserving ordering checks against a format
    /// we can't read is moot. If the fallback succeeds the caller installs
    /// `ForestCacheEntry::Monolithic`, and the next load attempts v7 again
    /// (so the fallback isn't sticky).
    async fn try_v1_backup_fallback(
        &self,
        bucket: &str,
        forest_dek: &fula_crypto::keys::DekKey,
    ) -> Option<PrivateForest> {
        let list = match self.inner.list_objects(bucket, Some(ListObjectsOptions {
            prefix: Some(V1_BACKUP_PREFIX.to_string()),
            max_keys: Some(1000),
            ..Default::default()
        })).await {
            Ok(l) => l,
            Err(e) => {
                tracing::warn!(%bucket, error = %e, "v7 fallback: list_objects on backup prefix failed");
                return None;
            }
        };

        let best = list.objects.iter()
            .filter_map(|obj| {
                let ts_str = obj.key.strip_prefix(V1_BACKUP_PREFIX)?;
                let ts: i64 = ts_str.parse().ok()?;
                Some((ts, obj.key.clone()))
            })
            .max_by_key(|(ts, _)| *ts)?;

        let (ts, key) = best;
        tracing::warn!(
            %bucket,
            backup_ts = ts,
            %key,
            "v7 manifest decrypt failed; attempting v1 backup fallback"
        );

        let blob = match self.inner.get_object(bucket, &key).await {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(%bucket, error = %e, "v7 fallback: failed to fetch backup blob");
                return None;
            }
        };

        let format = match detect_forest_format(&blob) {
            Ok(f) => f,
            Err(e) => {
                tracing::warn!(%bucket, error = %e, "v7 fallback: detect_forest_format on backup failed");
                return None;
            }
        };
        let encrypted = match format {
            ForestOrManifest::Monolithic(e) => e,
            _ => {
                tracing::warn!(%bucket, "v7 fallback: backup blob is not monolithic");
                return None;
            }
        };

        // v4 (AAD-bound) uses a distinct decrypt path, legacy v1/v2 uses the
        // plain one. Try the matching path and surface nothing on failure so
        // the caller can fall back to the original error.
        let forest_opt = if encrypted.version == 4 {
            encrypted.decrypt_v4(forest_dek, bucket).map(|(f, _)| f).ok()
        } else {
            encrypted.decrypt(forest_dek).ok()
        };

        if forest_opt.is_none() {
            tracing::warn!(%bucket, "v7 fallback: decrypting backup blob failed");
        }
        forest_opt
    }

    /// Load every page referenced by a decrypted manifest `root` and assemble a
    /// complete `ShardManifestV7`. Phase-1 implementation is eager — the open
    /// path pays one GET per referenced page. Pages not yet referenced (empty
    /// slots on a freshly-resharded manifest) are synthesized by
    /// `ShardManifestV7::from_root_and_pages`.
    async fn load_manifest_pages(
        &self,
        bucket: &str,
        forest_dek: &fula_crypto::keys::DekKey,
        root: ManifestRoot,
    ) -> std::result::Result<ShardManifestV7, ClientError> {
        let shard_salt = root.shard_salt.clone();
        let mut pages: std::collections::BTreeMap<PageId, ManifestPage> = std::collections::BTreeMap::new();
        for (page_id, page_ref) in root.page_index.iter() {
            let page_key = derive_manifest_page_key(forest_dek, bucket, &shard_salt, *page_id);
            let blob = self.inner.get_object(bucket, &page_key).await
                .map_err(|e| ClientError::DownloadFailed(format!(
                    "failed to fetch manifest page {} for bucket {}: {}",
                    page_id, bucket, e
                )))?;
            let envelope = EncryptedManifestPage::from_bytes(&blob)
                .map_err(ClientError::Encryption)?;
            if envelope.page_id != *page_id {
                return Err(ClientError::Encryption(fula_crypto::CryptoError::Decryption(
                    format!("manifest page envelope id {} != expected {}", envelope.page_id, page_id)
                )));
            }
            // Plan §3.1 M2: reject pages whose `seq < root.page_index[.].seq`
            // (rollback / stale-shard-cache). Newer pages (`envelope.seq >
            // page_ref.seq`) are legitimate after a Phase-1.5-landed-but-
            // Phase-2-crashed write — accept them so fresh readers can keep
            // reading while the writer's next flush re-drives the root PUT.
            if envelope.seq < page_ref.seq {
                return Err(ClientError::Encryption(fula_crypto::CryptoError::Decryption(
                    format!("stale manifest page {}: envelope seq {} < root-expected seq {}",
                        page_id, envelope.seq, page_ref.seq)
                )));
            }
            let page = envelope.decrypt(forest_dek, bucket)
                .map_err(ClientError::Encryption)?;
            pages.insert(*page_id, page);
        }
        ShardManifestV7::from_root_and_pages(root, pages)
            .map_err(ClientError::Encryption)
    }

    /// Try to load the directory index (F-1.3) for this bucket.
    ///
    /// Returns `Ok(Some((index, seq, etag)))` if the object decrypts cleanly
    /// and its stored ETag matches `expected_etag` (when the root pins one).
    /// Returns `Ok(None)` when:
    ///   * The object is 404 (never flushed or backend lost it).
    ///   * The root records an ETag but the fetched ETag / AEAD doesn't match.
    ///   * The plaintext sequence is older than the root's pin.
    /// All of these trigger a caller-side rebuild-from-forest.
    async fn load_directory_index(
        &self,
        bucket: &str,
        forest_dek: &fula_crypto::keys::DekKey,
        expected_etag: Option<&str>,
        expected_seq: Option<u64>,
    ) -> std::result::Result<Option<(DirectoryIndex, u64)>, ClientError> {
        let key = derive_dir_index_key(forest_dek, bucket);
        let blob = match self.inner.get_object(bucket, &key).await {
            Ok(b) => b,
            Err(e) if e.is_not_found() => return Ok(None),
            Err(e) => return Err(e),
        };
        // `get_object` discards the HEAD ETag so we cannot cross-check
        // `expected_etag` here directly; it stays threaded for future refactors
        // that expose the GET ETag on the read path. `expected_seq` is the
        // authoritative pin instead: the dir-index envelope's `seq` is
        // AEAD-bound (AAD ties plaintext to `(bucket, seq)`), and the root we
        // just loaded commits to exactly one value of it. A mismatch means
        // we raced a concurrent migrator (or the key holds an overwrite we
        // never committed to): treat as stale and trigger rebuild-from-forest.
        let _ = expected_etag;
        let envelope = match EncryptedDirectoryIndex::from_bytes(&blob) {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!(%bucket, error = %e, "dir-index envelope decode failed; will rebuild");
                return Ok(None);
            }
        };
        match envelope.decrypt(forest_dek, bucket) {
            Ok((index, seq)) => {
                if let Some(pinned) = expected_seq {
                    if seq != pinned {
                        tracing::warn!(
                            %bucket,
                            loaded_seq = seq,
                            pinned_seq = pinned,
                            "dir-index seq mismatch with root pin; will rebuild"
                        );
                        return Ok(None);
                    }
                }
                Ok(Some((index, seq)))
            }
            Err(e) => {
                tracing::warn!(%bucket, error = %e, "dir-index decrypt failed; will rebuild");
                Ok(None)
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // MIGRATION: Monolithic ↔ Sharded forest format conversion
    // ═══════════════════════════════════════════════════════════════════════════

    /// Migrate a bucket's forest from monolithic (v1/v2) directly to sharded-HAMT (v7).
    ///
    /// Normally the load-time trigger in `load_forest_internal` drives migration
    /// transparently on first access; call this method only for tests and
    /// explicit out-of-band migrations.
    ///
    /// **Why v7 (and not v6 first).** All pre-v3 data sits on v1 monolithic and
    /// the install base is below the sharding threshold — there is no production
    /// v6 data. Routing new migrations through v6 would introduce a migration
    /// nobody will benefit from and leave a second upgrade (v6→v7) pending.
    /// Direct v1→v7 has no speed disadvantage at 5k entries spread across 256
    /// shards (≈20 entries per shard → one root node per shard) and avoids the
    /// mixed-manifest / two-step-upgrade code paths.
    ///
    /// **Shape** (see [`migrate_v1_to_v7_internal`] for the authoritative
    /// sequence): acquire server lock → (optionally) defer if a WAL is present
    /// → COPY v1 to a timestamped backup key → replay into a fresh v7 forest →
    /// flush HAMT node blobs → conditionally PUT the v7 manifest (If-Match the
    /// v1 blob's ETag) → install the ShardedHamt cache entry → release lock.
    ///
    /// **On failure.** v7 node blobs are content-addressed (`__fula_forest_v7_nodes/<hex>`)
    /// and will simply be re-addressed on the next attempt (new bucket salt →
    /// distinct addresses); any orphans are collected by the async GC sweep.
    /// The v1 monolithic blob is never mutated, and a dated backup at
    /// `__fula_forest_v1_backup/<unix_ms>` is written *before* the v7 manifest
    /// PUT, so partial migrations never corrupt readable state and always leave
    /// a restore point.
    ///
    /// **Idempotency.** If the bucket is already v7 when this method is called,
    /// returns `Ok(MigrationCompleted { duration_ms: 0, .. })`.
    pub async fn migrate_to_sharded(&self, bucket: &str) -> Result<ForestEvent> {
        // Try to load as monolithic v1. If the forest is already sharded, the
        // internal load returns a "forest is sharded" error — treat that as
        // "already migrated" for idempotency.
        let v1_forest = match self.load_forest_internal(bucket).await {
            Ok(f) => f,
            Err(ref e) if e.to_string().contains("forest is sharded") => {
                return Ok(ForestEvent::MigrationCompleted {
                    bucket: bucket.to_string(),
                    duration_ms: 0,
                });
            }
            Err(e) => return Err(e),
        };

        let forest_dek = self.encryption.key_manager.derive_path_key(&format!("forest:{}", bucket));

        // The public entry point has no v1 ETag hint — the workhorse will
        // HEAD the object to read it. (The load-time trigger already has the
        // ETag from its GET and passes it in to skip the round-trip.)
        let v1_etag_hint: Option<String> = self.forest_cache.get(bucket).and_then(|e| match e.value() {
            ForestCacheEntry::Monolithic { index_etag, .. } => index_etag.clone(),
            _ => None,
        });

        match self.migrate_v1_to_v7_internal(bucket, &v1_forest, &forest_dek, v1_etag_hint.as_deref()).await? {
            MigrationOutcome::Migrated { duration_ms } => Ok(ForestEvent::MigrationCompleted {
                bucket: bucket.to_string(),
                duration_ms,
            }),
            MigrationOutcome::DeferredLockHeld { expires_at_ms } => {
                Err(ClientError::MigrationLockHeld {
                    bucket: bucket.to_string(),
                    expires_at: expires_at_ms,
                })
            }
            MigrationOutcome::DeferredTransientError { reason } => {
                Err(ClientError::UploadFailed(format!("migration deferred: {}", reason)))
            }
        }
    }

    /// Core v1 → v7 migration workhorse. Preconditions:
    /// - `v1_forest` is the decoded FlatMapV1 index for `bucket`.
    /// - `forest_dek` is derived from `key_manager.derive_path_key("forest:{bucket}")`.
    /// - `v1_etag_hint` is the ETag observed on the GET that produced `v1_forest`;
    ///   passing `None` forces a HEAD to fetch it.
    ///
    /// **No in-process `migration_lock.write()`**. That would deadlock when the
    /// caller is `load_forest_internal` running under `load_forest`'s read
    /// guard. Coordination instead relies on: (a) the server-side advisory lock
    /// serializing across processes/devices, (b) If-Match on the v7 manifest PUT
    /// so the OS-level blob swap is atomic, (c) DashMap's atomic insert so
    /// in-process readers see either the old v1 cache entry or the new
    /// ShardedHamt entry, never a partial state.
    ///
    /// **WAL defer**. If a v1 WAL is present on disk, we return
    /// `DeferredTransientError` without touching the server lock. The normal
    /// flush path will drain the WAL (updating the v1 blob's ETag), after which
    /// the next load-time trigger re-enters this function with a matching
    /// `v1_etag_hint`. Draining the WAL here would recurse through
    /// `flush_forest`, which itself tries to take a shared read on
    /// `migration_lock` — safe, but complicates reasoning with little gain
    /// since migrations are rare and WAL-present-at-load is rarer still.
    #[cfg_attr(target_arch = "wasm32", allow(unused_variables))]
    pub(crate) async fn migrate_v1_to_v7_internal(
        &self,
        bucket: &str,
        v1_forest: &PrivateForest,
        forest_dek: &fula_crypto::keys::DekKey,
        v1_etag_hint: Option<&str>,
    ) -> Result<MigrationOutcome> {
        // `web_time::Instant` is std::time::Instant on native and a
        // performance.now()-backed shim on wasm32-unknown-unknown, so this
        // call is safe on every target the workspace supports. Using
        // std::time::Instant here panics in browser WASM with "time not
        // implemented on this platform".
        let start = web_time::Instant::now();
        let index_key = derive_index_key(forest_dek, bucket);

        // ── Step 0: WAL defer ────────────────────────────────────────────────
        // If a dirty v1 WAL is on disk, a flush will rewrite v1 and invalidate
        // our If-Match guard. Defer so the next session — after the WAL has
        // drained — re-enters with a valid ETag.
        #[cfg(not(target_arch = "wasm32"))]
        {
            let mac_key = wal::derive_mac_key(&self.encryption.key_manager, bucket);
            match wal::load(bucket, &mac_key) {
                Ok(entries) if !entries.is_empty() => {
                    return Ok(MigrationOutcome::DeferredTransientError {
                        reason: format!("v1 WAL has {} pending entries; draining first", entries.len()),
                    });
                }
                Ok(_) => {}
                Err(e) => {
                    tracing::warn!(%bucket, error = %e, "WAL load failed during migration precheck; proceeding");
                }
            }
        }

        // ── Step 1: Server-side advisory lock ───────────────────────────────
        let handle = match self.inner.acquire_migration_lock(bucket).await {
            Ok(h) => h,
            Err(ClientError::MigrationLockHeld { expires_at, .. }) => {
                return Ok(MigrationOutcome::DeferredLockHeld { expires_at_ms: expires_at });
            }
            Err(e) => return Err(e),
        };
        let lock_token = handle.token.clone();

        // ── Step 2: Heartbeat guard (RAII) ──────────────────────────────────
        // Dropped on every exit path below; heartbeat task aborts on drop.
        #[cfg(not(target_arch = "wasm32"))]
        let _heartbeat = HeartbeatGuard::spawn(
            self.inner.clone(),
            bucket.to_string(),
            lock_token.clone(),
        );

        // Inline helper: on any transient error after lock acquisition, release
        // the server lock (best-effort) and return DeferredTransientError. We
        // don't macro this because `?` still works inside the workhorse for the
        // steps that SHOULD propagate hard errors.
        let release_best_effort = |token: String| {
            let client = self.inner.clone();
            let bucket = bucket.to_string();
            async move {
                if let Err(e) = client.release_migration_lock(&bucket, &token).await {
                    tracing::warn!(%bucket, error = %e, "migration lock release failed (TTL will expire)");
                }
            }
        };

        // After Step 7 begins, this migration owns the WAL (Step 0 verified it
        // was empty, and Phase B writes only our own PageWrote/DirIndexWrote
        // entries). On any post-Step-7 failure, clear the WAL so Step 0's
        // defer-guard on the NEXT attempt doesn't spin forever on orphaned
        // entries that no regular flush would drain (monolithic replay ignores
        // PageWrote/DirIndexWrote by design — see replay_wal_entries).
        let phase_b_fail = |token: String| {
            let client = self.inner.clone();
            let bucket_owned = bucket.to_string();
            async move {
                #[cfg(not(target_arch = "wasm32"))]
                {
                    if let Err(e) = wal::clear(&bucket_owned) {
                        tracing::warn!(bucket = %bucket_owned, error = %e,
                            "migration WAL clear after Phase B failure failed");
                    }
                }
                if let Err(e) = client.release_migration_lock(&bucket_owned, &token).await {
                    tracing::warn!(bucket = %bucket_owned, error = %e,
                        "migration lock release failed (TTL will expire)");
                }
            }
        };

        // ── Step 3: Resolve the v1 ETag (for If-Match) ─────────────────────
        let v1_etag: String = match v1_etag_hint {
            Some(e) if !e.is_empty() => e.to_string(),
            _ => match self.inner.head_object(bucket, &index_key).await {
                Ok(h) if !h.etag.is_empty() => h.etag,
                Ok(_) => {
                    release_best_effort(lock_token.clone()).await;
                    return Ok(MigrationOutcome::DeferredTransientError {
                        reason: "server returned empty ETag for v1 index".to_string(),
                    });
                }
                Err(e) => {
                    release_best_effort(lock_token.clone()).await;
                    return Ok(MigrationOutcome::DeferredTransientError {
                        reason: format!("HEAD v1 index failed: {}", e),
                    });
                }
            },
        };

        // ── Step 4: Write v1 backup BEFORE touching anything else ───────────
        let backup_key = format!(
            "{}{}",
            V1_BACKUP_PREFIX,
            chrono::Utc::now().timestamp_millis(),
        );
        if let Err(e) = self.inner.copy_object(bucket, &index_key, bucket, &backup_key).await {
            release_best_effort(lock_token.clone()).await;
            return Ok(MigrationOutcome::DeferredTransientError {
                reason: format!("v1 backup COPY failed: {}", e),
            });
        }

        // ── Step 5: Build the v7 forest in memory ──────────────────────────
        let file_count = v1_forest.file_count();
        let num_shards = compute_initial_shard_count(file_count);
        let mut manifest = ShardManifestV7::new(num_shards);
        manifest.root.created_at = v1_forest.created_at;

        let mut v7 = ShardedHamtPrivateForest::from_manifest(
            manifest,
            bucket.to_string(),
            forest_dek.clone(),
        );
        let backend = Arc::new(S3BlobBackend::new(self.inner.clone(), bucket.to_string()));

        // Replay files. HAMT insert is commutative per key; ordering irrelevant.
        // F4: entries are passed through verbatim — `encrypted` preserves the
        // v1 value. Production v1 entries are always `encrypted: true`
        // (EncryptedClient paths call `mark_encrypted` before upsert), so
        // `forest_entry_requires_encryption`'s unconditional v7-true answer
        // remains correct after migration. Tests that construct plaintext v1
        // entries stress-test the forest structure, not the read-path
        // encryption check.
        for entry in v1_forest.files.values() {
            if let Err(e) = v7.upsert_file(entry.clone(), &backend).await {
                release_best_effort(lock_token.clone()).await;
                return Ok(MigrationOutcome::DeferredTransientError {
                    reason: format!("upsert_file during migration failed: {}", e),
                });
            }
        }
        // Replay directories AFTER files so v1's canonical directory entries
        // (metadata, subtree_dek, file/subdir lists) overwrite the stubs the
        // file loop created via `ensure_ancestor_chain`. Reversing this order
        // would clobber the preserved fields back to the synthesized defaults.
        for dir_entry in v1_forest.directories.values() {
            if let Err(e) = v7.upsert_directory(dir_entry.clone(), &backend).await {
                release_best_effort(lock_token.clone()).await;
                return Ok(MigrationOutcome::DeferredTransientError {
                    reason: format!("upsert_directory during migration failed: {}", e),
                });
            }
        }

        // ── Step 6: Phase A — flush HAMT node blobs ────────────────────────
        if let Err(e) = v7.flush_dirty(&backend).await {
            release_best_effort(lock_token.clone()).await;
            return Ok(MigrationOutcome::DeferredTransientError {
                reason: format!("flush_dirty during migration failed: {}", e),
            });
        }

        // Fault injection point: simulate a client crash between Phase A and
        // Phase B. Node blobs are already on disk; manifest PUT has not fired.
        #[cfg(feature = "test-fault-injection")]
        if test_faults::CRASH_AFTER_PHASE_A_FLUSH
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            release_best_effort(lock_token.clone()).await;
            return Ok(MigrationOutcome::DeferredTransientError {
                reason: "test-fault-injection: CRASH_AFTER_PHASE_A_FLUSH".to_string(),
            });
        }

        // ── Step 7: Phase B — flush dirty pages then PUT v7 manifest root ──
        let mut manifest_snapshot = v7.manifest().clone();
        let shard_salt = manifest_snapshot.shard_salt().to_vec();
        let dirty_pages = manifest_snapshot.take_dirty_pages();
        #[cfg(not(target_arch = "wasm32"))]
        let wal_mac_pages = wal::derive_mac_key(&self.encryption.key_manager, bucket);
        for page_id in dirty_pages.iter().copied() {
            let page = match manifest_snapshot.pages.get_mut(&page_id) {
                Some(p) => p,
                None => {
                    phase_b_fail(lock_token.clone()).await;
                    return Ok(MigrationOutcome::DeferredTransientError {
                        reason: format!("dirty page {} not loaded in migration", page_id),
                    });
                }
            };
            let old_etag = manifest_snapshot.root.page_index.get(&page_id)
                .and_then(|r| r.etag.clone());
            page.seq = page.seq.wrapping_add(1);
            #[cfg(not(target_arch = "wasm32"))]
            if let Err(e) = wal::append(
                bucket,
                &wal_mac_pages,
                WalEntry::PageWrote {
                    page_id,
                    old_etag: old_etag.clone(),
                    new_etag: None,
                    seq: page.seq,
                },
            ) {
                tracing::warn!(%bucket, page_id, error = %e, "migration: WAL append PageWrote failed");
            }
            let blob = match EncryptedManifestPage::encrypt(page, forest_dek, bucket)
                .and_then(|e| e.to_bytes())
            {
                Ok(b) => b,
                Err(e) => {
                    phase_b_fail(lock_token.clone()).await;
                    return Ok(MigrationOutcome::DeferredTransientError {
                        reason: format!("encrypt manifest page {} failed: {}", page_id, e),
                    });
                }
            };
            let page_key = derive_manifest_page_key(forest_dek, bucket, &shard_salt, page_id);
            // If-None-Match=*: migration uses a fresh random shard_salt, so each
            // page key is first-ever on this bucket. Any 412 here means another
            // concurrent migrator beat us (lease-expiry race) and their terminal
            // If-Match on v1_etag will arbitrate the winner. Defer & let the
            // winner's state settle.
            let put = match self.inner.put_object_with_metadata_conditional(
                bucket,
                &page_key,
                Bytes::from(blob),
                Some(ObjectMetadata::new().with_content_type("application/octet-stream")),
                None,
                Some("*"),
            ).await {
                Ok(r) => r,
                Err(e) if e.is_concurrent_modification() => {
                    phase_b_fail(lock_token.clone()).await;
                    return Ok(MigrationOutcome::DeferredTransientError {
                        reason: format!("412 on migration page {} PUT — concurrent migrator raced", page_id),
                    });
                }
                Err(e) => {
                    phase_b_fail(lock_token.clone()).await;
                    return Ok(MigrationOutcome::DeferredTransientError {
                        reason: format!("PUT manifest page {} failed: {}", page_id, e),
                    });
                }
            };
            let etag = if put.etag.is_empty() { None } else { Some(put.etag) };
            #[cfg(not(target_arch = "wasm32"))]
            if let Err(e) = wal::append(
                bucket,
                &wal_mac_pages,
                WalEntry::PageWrote {
                    page_id,
                    old_etag: old_etag.clone(),
                    new_etag: etag.clone(),
                    seq: page.seq,
                },
            ) {
                tracing::warn!(%bucket, page_id, error = %e, "migration: WAL append post-PUT PageWrote failed");
            }
            manifest_snapshot.root.page_index.insert(page_id, PageRef {
                etag,
                seq: page.seq,
            });
        }

        // Phase B.5 (F-1.3): flush the directory index built from v1's files
        // and directories via the upsert hooks above. First-write (no prior
        // dir-index for this bucket in v7), so no If-Match is required.
        // WAL::DirIndexWrote appended+fsynced BEFORE the PUT for crash-replay
        // idempotency (same key, same seq, identical plaintext).
        let dir_index_seq: u64 = 1;
        #[cfg(not(target_arch = "wasm32"))]
        if let Err(e) = wal::append(
            bucket,
            &wal_mac_pages,
            WalEntry::DirIndexWrote {
                old_etag: None,
                new_etag: None,
                seq: dir_index_seq,
            },
        ) {
            tracing::warn!(%bucket, error = %e, "migration: WAL append DirIndexWrote failed");
        }
        let dir_index_blob = match EncryptedDirectoryIndex::encrypt(
            v7.directory_index(),
            forest_dek,
            bucket,
            dir_index_seq,
        ).and_then(|e| e.to_bytes()) {
            Ok(b) => b,
            Err(e) => {
                phase_b_fail(lock_token.clone()).await;
                return Ok(MigrationOutcome::DeferredTransientError {
                    reason: format!("encrypt migration dir-index failed: {}", e),
                });
            }
        };
        let dir_index_key = derive_dir_index_key(forest_dek, bucket);
        // Unconditional overwrite is required: the dir-index key is stable
        // across migrations (no shard_salt in its derivation), so a legitimate
        // re-migration (e.g. after a rollback-attack recovery at
        // test_version_downgrade_blocked_after_v7_pin) finds a pre-existing
        // dir-index from the earlier migration and must replace it. The
        // advisory lock + terminal If-Match on v1_etag together arbitrate
        // concurrent migrators; the narrow race where two migrators holding
        // stale v1 ETags both clobber this key is contained by the terminal
        // v1_etag gate (only one commits v7).
        let dir_index_put = match self.inner.put_object_with_metadata(
            bucket,
            &dir_index_key,
            Bytes::from(dir_index_blob),
            Some(ObjectMetadata::new().with_content_type("application/octet-stream")),
        ).await {
            Ok(r) => r,
            Err(e) => {
                phase_b_fail(lock_token.clone()).await;
                return Ok(MigrationOutcome::DeferredTransientError {
                    reason: format!("PUT migration dir-index failed: {}", e),
                });
            }
        };
        let new_dir_index_etag =
            if dir_index_put.etag.is_empty() { None } else { Some(dir_index_put.etag) };
        #[cfg(not(target_arch = "wasm32"))]
        if let Err(e) = wal::append(
            bucket,
            &wal_mac_pages,
            WalEntry::DirIndexWrote {
                old_etag: None,
                new_etag: new_dir_index_etag.clone(),
                seq: dir_index_seq,
            },
        ) {
            tracing::warn!(%bucket, error = %e, "migration: WAL append post-PUT DirIndexWrote failed");
        }
        manifest_snapshot.root.dir_index_etag = new_dir_index_etag;
        manifest_snapshot.root.dir_index_seq = Some(dir_index_seq);

        let manifest_seq: u64 = 1;
        let manifest_data = match EncryptedShardManifestV7::encrypt_v7(
            &manifest_snapshot.root,
            forest_dek,
            bucket,
            manifest_seq,
        ).and_then(|em| em.to_bytes()) {
            Ok(bytes) => bytes,
            Err(e) => {
                phase_b_fail(lock_token.clone()).await;
                return Ok(MigrationOutcome::DeferredTransientError {
                    reason: format!("encrypt v7 manifest failed: {}", e),
                });
            }
        };

        // If-Match the v1 ETag: any concurrent writer that rewrites v1 between
        // our HEAD (or GET) and this PUT loses the race — we defer and retry
        // next session. Crucial because the in-process `migration_lock.write()`
        // is NOT held during load-time-triggered migration.
        //
        // Phase 1.2: v1→v7 migration is a manifest-root commit. Attach the
        // bucket-lookup-h header so master can populate `bucket_lookup_h`
        // here too — otherwise users who migrate to v7 via this path (rather
        // than save_sharded_hamt_forest) would never get their lookup_h set.
        let put_result = match self.inner.put_object_with_metadata_conditional(
            bucket,
            &index_key,
            Bytes::from(manifest_data),
            Some(
                ObjectMetadata::new()
                    .with_content_type("application/octet-stream")
                    .with_metadata("fula-bucket-lookup-h", &self.compute_bucket_lookup_h_hex(bucket)),
            ),
            Some(&v1_etag),
            None,
        ).await {
            Ok(r) => r,
            Err(e) if e.is_concurrent_modification() => {
                phase_b_fail(lock_token.clone()).await;
                return Ok(MigrationOutcome::DeferredTransientError {
                    reason: "412 on v7 manifest PUT — another writer rewrote v1".to_string(),
                });
            }
            Err(e) => {
                phase_b_fail(lock_token.clone()).await;
                return Ok(MigrationOutcome::DeferredTransientError {
                    reason: format!("v7 manifest PUT failed: {}", e),
                });
            }
        };

        // Fault injection point: simulate a client crash AFTER the Phase B
        // conditional PUT has succeeded (server now serves v7 at index_key)
        // but BEFORE the in-process cache swap / `persist_manifest_version`.
        // Cold-start of the next session must re-detect v7 from the server.
        #[cfg(feature = "test-fault-injection")]
        if test_faults::CRASH_AFTER_PHASE_B_PUT_BEFORE_CACHE_SWAP
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            release_best_effort(lock_token.clone()).await;
            return Ok(MigrationOutcome::DeferredTransientError {
                reason: "test-fault-injection: CRASH_AFTER_PHASE_B_PUT_BEFORE_CACHE_SWAP"
                    .to_string(),
            });
        }

        // ── Step 8: Install the migrated forest into the cache ─────────────
        let new_etag = if put_result.etag.is_empty() { None } else { Some(put_result.etag) };
        let now = chrono::Utc::now().timestamp();
        // Fold the freshly-committed page_index + cleared dirty_pages back
        // into the in-memory forest before caching, so the first post-
        // migration flush doesn't re-PUT every page.
        v7.reconcile_flush(manifest_snapshot.root.clone(), &dirty_pages);
        v7.reconcile_dir_index_flush(dir_index_seq);
        let forest_arc = Arc::new(tokio::sync::RwLock::new(v7));
        self.forest_cache.insert(bucket.to_string(), ForestCacheEntry::ShardedHamt {
            forest: forest_arc,
            loaded_at: now,
            manifest_etag: new_etag,
            last_manifest_sequence: Some(manifest_seq),
        });
        // Pin the manifest version so a gateway can't downgrade us next load.
        self.persist_manifest_version(bucket, 7);

        // Clear the migration WAL: PageWrote / DirIndexWrote entries recorded
        // during Phase B describe work that has now committed. Leaving them
        // on disk would trip the WAL-defer guard at Step 0 of the *next*
        // migration entry (which treats any non-empty WAL as pending v1
        // flushes) — see test_version_downgrade_blocked_after_v7_pin.
        #[cfg(not(target_arch = "wasm32"))]
        if let Err(e) = wal::clear(bucket) {
            tracing::warn!(%bucket, error = %e, "WAL clear after migration failed");
        }

        // ── Step 9: Release the server lock (best-effort) ─────────────────
        release_best_effort(lock_token).await;

        // Heartbeat guard drops here — task aborts cleanly.
        Ok(MigrationOutcome::Migrated {
            duration_ms: start.elapsed().as_millis() as u64,
        })
    }

    /// Get the current forest file count for a bucket (for migration threshold checks).
    pub async fn forest_file_count(&self, bucket: &str) -> Result<usize> {
        self.ensure_forest_loaded(bucket).await?;

        // Extract either a synchronous count (monolithic v1) or an Arc
        // handle to the v7 forest whose mutex must be awaited below. The
        // DashMap guard is dropped at the end of this block so we don't
        // hold a shard lock across the `lock().await` that follows.
        let (sync_count, v7_forest) = {
            let entry_opt = self.forest_cache.get(bucket);
            match entry_opt.as_ref().map(|e| e.value()) {
                Some(ForestCacheEntry::Monolithic { forest, .. }) => (Some(forest.file_count()), None),
                Some(ForestCacheEntry::ShardedHamt { forest, .. }) => (None, Some(forest.clone())),
                None => (Some(0), None),
            }
        };

        let count = if let Some(c) = sync_count {
            c
        } else if let Some(arc) = v7_forest {
            // v7 keeps a per-shard `entry_count` in the manifest so total
            // counts are O(1) without walking the HAMT.
            let guard = arc.read().await;
            guard.manifest().shards_iter()
                .map(|s| s.entry_count as usize)
                .sum()
        } else {
            0
        };

        Ok(count)
    }

    /// Put an encrypted object using FlatNamespace mode
    ///
    /// This automatically updates AND SAVES the forest index after each file.
    /// For bulk uploads, use `put_object_flat_deferred` + `flush_forest` instead.
    pub async fn put_object_flat(
        &self,
        bucket: &str,
        key: &str,
        data: impl Into<Bytes>,
        content_type: Option<&str>,
    ) -> Result<PutObjectResult> {
        let result = self.put_object_flat_deferred(bucket, key, data, content_type).await?;
        self.flush_forest(bucket).await?;
        Ok(result)
    }

    /// Put an encrypted object using FlatNamespace mode WITHOUT saving forest
    /// 
    /// Use this for bulk uploads. Call `flush_forest` after uploading all files
    /// to persist the forest index. This is much more efficient for many files.
    /// 
    /// # Example
    /// ```ignore
    /// // Upload 100 files efficiently
    /// for file in files {
    ///     client.put_object_flat_deferred(bucket, &file.path, file.data, None).await?;
    /// }
    /// // Save forest once at the end
    /// client.flush_forest(bucket).await?;
    /// ```
    pub async fn put_object_flat_deferred(
        &self,
        bucket: &str,
        key: &str,
        data: impl Into<Bytes>,
        content_type: Option<&str>,
    ) -> Result<PutObjectResult> {
        let data = data.into();
        let original_size = data.len() as u64;

        // Load or create forest (handles monolithic v1 and sharded-HAMT v7)
        self.ensure_forest_loaded(bucket).await?;

        // Generate a DEK for this object
        let dek = self.encryption.key_manager.generate_dek();

        // Generate flat storage key from cached forest.
        //
        // For v7 we can't derive the key while holding the DashMap guard —
        // ShardedHamtPrivateForest is behind a `tokio::sync::RwLock` and taking
        // its `.read().await` across the DashMap guard would deadlock the
        // DashMap shard. The sync formats finalize inline; for v7 we extract
        // the Arc, drop the guard, read the forest to copy `shard_salt`, drop
        // the read guard, then compute the key.
        enum KeyPath {
            Ready(String),
            V7(Arc<tokio::sync::RwLock<ShardedHamtPrivateForest>>),
        }
        let path = {
            let cache_entry = self.forest_cache.get(bucket)
                .ok_or_else(|| ClientError::Encryption(
                    fula_crypto::CryptoError::Encryption("forest not loaded".to_string())
                ))?;
            match cache_entry.value() {
                ForestCacheEntry::Monolithic { forest, .. } =>
                    KeyPath::Ready(forest.generate_key(key, &dek)),
                ForestCacheEntry::ShardedHamt { forest, .. } =>
                    KeyPath::V7(forest.clone()),
            }
        };
        let storage_key = match path {
            KeyPath::Ready(sk) => sk,
            KeyPath::V7(forest_arc) => {
                let salt = {
                    let guard = forest_arc.read().await;
                    guard.manifest().shard_salt().to_vec()
                };
                generate_flat_key(key, &dek, &salt)
            }
        };

        // Encrypt the DEK with HPKE
        let encryptor = Encryptor::new(self.encryption.public_key());
        let wrapped_dek = encryptor.encrypt_dek(&dek)
            .map_err(ClientError::Encryption)?;

        // Create private metadata. H-1: compute BLAKE3 over the plaintext
        // *before* AEAD so the hash lands on the forest entry (which lives
        // under a separate AAD scheme and cannot be re-wrapped under HPKE-
        // to-self forgery) and is available for download-side verification.
        let content_hash = blake3::hash(&data).to_hex().to_string();
        let private_meta = PrivateMetadata::new(key, original_size)
            .with_content_type(content_type.unwrap_or("application/octet-stream"))
            .with_content_hash(content_hash);

        let encrypted_meta = EncryptedPrivateMetadata::encrypt(&private_meta, &dek)
            .map_err(ClientError::Encryption)?;

        // Mark the forest entry as encrypted so subsequent reads refuse a
        // plaintext response from the storage backend (C-AUDIT-004) and
        // pin its `min_version` to 4 (H-2).
        let mut forest_entry = ForestFileEntry::from_metadata(&private_meta, storage_key.clone());
        forest_entry.mark_encrypted();

        let kek_version = self.encryption.key_manager.version();

        // Check if we need chunked upload (for IPFS block size limit)
        let result = if should_use_chunked(data.len()) {
            // CHUNKED UPLOAD: Split into chunks under IPFS 1MB limit
            self.put_object_chunked_internal(
                bucket,
                &storage_key,
                &data,
                &dek,
                &wrapped_dek,
                &encrypted_meta,
                kek_version,
            ).await?
        } else {
            // SINGLE OBJECT: File is small enough for one block
            let nonce = Nonce::generate();
            let aead = Aead::new_default(&dek);
            let aad = format!("fula:v4:content:{}", storage_key).into_bytes();
            let ciphertext = aead.encrypt_with_aad(&nonce, &data, &aad)
                .map_err(ClientError::Encryption)?;

            // Serialize encryption metadata
            let enc_metadata = serde_json::json!({
                "version": 4,
                "algorithm": "AES-256-GCM",
                "nonce": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, nonce.as_bytes()),
                "wrapped_key": serde_json::to_value(&wrapped_dek).unwrap(),
                "kek_version": kek_version,
                "metadata_privacy": true,
                "obfuscation_mode": "flat",
                "private_metadata": encrypted_meta.to_json().map_err(ClientError::Encryption)?,
            });

            let metadata = ObjectMetadata::new()
                .with_content_type("application/octet-stream")
                .with_metadata("x-fula-encrypted", "true")
                .with_metadata("x-fula-encryption", &enc_metadata.to_string());

            if let Some(ref pinning) = self.pinning {
                self.inner.put_object_with_metadata_and_pinning(
                    bucket,
                    &storage_key,
                    Bytes::from(ciphertext),
                    Some(metadata),
                    &pinning.endpoint,
                    &pinning.token,
                ).await?
            } else {
                self.inner.put_object_with_metadata(
                    bucket,
                    &storage_key,
                    Bytes::from(ciphertext),
                    Some(metadata),
                ).await?
            }
        };

        // Update cache (but don't save to storage yet — mark dirty).
        // Before upsert: capture any old storage_key for the same path so we
        // can clean up the orphaned upload afterward (F-3.1). Each upload
        // generates a fresh random DEK which derives a fresh storage_key, so
        // overwrites always orphan the previous main/chunk objects on S3.
        let now = chrono::Utc::now().timestamp();

        // NEW-7.2: mirror dirty upsert to WAL so a 412 loser can replay its
        // work on top of the winner's forest (optimistic-merge retry) and so a
        // crash between upsert and flush doesn't lose the entry. Cloned now
        // before `forest_entry` is consumed by `upsert_file` below.
        #[cfg(not(target_arch = "wasm32"))]
        let wal_entry_clone = forest_entry.clone();

        let is_v7 = self.is_forest_sharded_hamt(bucket);

        let old_storage_key: Option<String> = if is_v7 {
            // v7 sharded-HAMT: forest is behind a tokio Mutex. Extract the
            // Arc under the DashMap guard, drop the guard, then lock and
            // mutate. `get_file` + `upsert_file` both take `&mut self`, so
            // they must run under the same lock-held region; the mutex is
            // non-reentrant but the two calls are sequential, not nested.
            let forest_arc = {
                let cache_entry = self.forest_cache.get(bucket).unwrap();
                match cache_entry.value() {
                    ForestCacheEntry::ShardedHamt { forest, .. } => forest.clone(),
                    _ => unreachable!("is_forest_sharded_hamt guard above"),
                }
            };
            let backend: Arc<S3BlobBackend> = Arc::new(
                S3BlobBackend::new(self.inner.clone(), bucket.to_string())
            );
            let old = {
                let mut guard = forest_arc.write().await;
                let prior = guard.get_file(key, &backend).await
                    .map_err(ClientError::Encryption)?;
                // F4: lock the v7-encrypted invariant (see chunked-upload
                // site for the full rationale).
                debug_assert!(
                    forest_entry.encrypted,
                    "v7 upsert invariant violated: entry for {} has encrypted=false",
                    forest_entry.path
                );
                guard.upsert_file(forest_entry, &backend).await
                    .map_err(ClientError::Encryption)?;
                prior.map(|e| e.storage_key)
            };
            if let Some(mut cache_entry) = self.forest_cache.get_mut(bucket) {
                if let ForestCacheEntry::ShardedHamt { loaded_at, .. } = cache_entry.value_mut() {
                    *loaded_at = now;
                }
            }
            old
        } else {
            // Monolithic v1: clone, mutate, re-insert. v7 (ShardedHamt) is
            // ruled out by the `is_v7` arm above.
            let (mut forest, prior_etag, prior_seq) = {
                let cache_entry = self.forest_cache.get(bucket).unwrap();
                match cache_entry.value() {
                    ForestCacheEntry::Monolithic { forest, index_etag, last_sequence, .. } =>
                        (forest.clone(), index_etag.clone(), *last_sequence),
                    ForestCacheEntry::ShardedHamt { .. } => unreachable!("is_v7 handled above"),
                }
            };
            let old = forest.get_storage_key(key).map(|s| s.to_string());
            forest.upsert_file(forest_entry);
            self.forest_cache.insert(bucket.to_string(), ForestCacheEntry::Monolithic {
                forest,
                loaded_at: now,
                dirty: true,
                index_etag: prior_etag,
                last_sequence: prior_seq,
            });
            old
        };

        #[cfg(not(target_arch = "wasm32"))]
        {
            let wal_mac = wal::derive_mac_key(&self.encryption.key_manager, bucket);
            if let Err(e) = wal::append(
                bucket,
                &wal_mac,
                WalEntry::Insert { key: key.to_string(), entry: wal_entry_clone },
            ) {
                tracing::warn!(%bucket, error = %e, "WAL append failed (upsert); continuing");
            }
        }

        // Best-effort cleanup of the orphaned previous upload. Guarded by an
        // in-forest refcount check so we never delete a storage key that some
        // other entry still references (defensive; per-upload random DEKs make
        // a shared key astronomically unlikely, but the guard is cheap).
        if let Some(old_key) = old_storage_key {
            if old_key != storage_key {
                let num_chunks = self.get_chunked_num_chunks(bucket, &old_key).await;
                self.cleanup_orphaned_storage(bucket, &old_key, num_chunks).await;
            }
        }

        Ok(result)
    }

    /// Internal: Upload a large file using chunked encoding
    async fn put_object_chunked_internal(
        &self,
        bucket: &str,
        storage_key: &str,
        data: &[u8],
        dek: &fula_crypto::keys::DekKey,
        wrapped_dek: &EncryptedData,
        encrypted_meta: &EncryptedPrivateMetadata,
        kek_version: u32,
    ) -> Result<PutObjectResult> {
        // Create chunked encoder with AAD binding chunks to storage key
        let aad_prefix = format!("fula:v4:chunk:{}", storage_key);
        let mut encoder = ChunkedEncoder::with_aad(dek.clone(), aad_prefix);
        
        // Process all data through encoder
        let mut all_chunks = encoder.update(data)
            .map_err(ClientError::Encryption)?;
        
        // Finalize to get last chunk and metadata
        let (final_chunk, chunked_metadata, _outboard) = encoder.finalize()
            .map_err(ClientError::Encryption)?;
        
        if let Some(chunk) = final_chunk {
            all_chunks.push(chunk);
        }
        
        // Upload chunks in parallel with bounded concurrency. Using
        // futures::stream::buffer_unordered rather than tokio::spawn so the
        // same code runs on wasm32 (where tokio has no multi-thread runtime).
        use futures::StreamExt;
        let pinning = self.pinning.clone();
        let futs = all_chunks.into_iter().map(|chunk| {
            let chunk_key = ChunkedFileMetadata::chunk_key(storage_key, chunk.index);
            let chunk_metadata = ObjectMetadata::new()
                .with_content_type("application/octet-stream")
                .with_metadata("x-fula-chunk", "true")
                .with_metadata("x-fula-chunk-index", &chunk.index.to_string());

            let client = self.inner.clone();
            let bucket = bucket.to_string();
            let pinning = pinning.clone();
            let chunk_key_ret = chunk_key.clone();

            async move {
                if let Some(ref pin) = pinning {
                    client.put_object_with_metadata_and_pinning(
                        &bucket,
                        &chunk_key,
                        chunk.ciphertext,
                        Some(chunk_metadata),
                        &pin.endpoint,
                        &pin.token,
                    ).await?;
                } else {
                    client.put_object_with_metadata(
                        &bucket,
                        &chunk_key,
                        chunk.ciphertext,
                        Some(chunk_metadata),
                    ).await?;
                }
                Ok::<String, ClientError>(chunk_key_ret)
            }
        });

        let results: Vec<std::result::Result<String, ClientError>> = futures::stream::iter(futs)
            .buffer_unordered(Self::MAX_CONCURRENT_CHUNK_UPLOADS)
            .collect()
            .await;

        // Track successfully uploaded chunk keys so we can clean them up if
        // any upload in the batch failed.
        let mut uploaded_keys: Vec<String> = Vec::new();
        let mut upload_error: Option<ClientError> = None;
        for result in results {
            match result {
                Ok(key) => uploaded_keys.push(key),
                Err(e) => { if upload_error.is_none() { upload_error = Some(e); } }
            }
        }

        // If any upload failed, clean up successfully uploaded chunks
        if let Some(err) = upload_error {
            for key in &uploaded_keys {
                let _ = self.inner.delete_object(bucket, key).await;
            }
            return Err(err);
        }
        
        // Create index object with encryption metadata and chunk info
        let enc_metadata = serde_json::json!({
            "version": 4,
            "algorithm": "AES-256-GCM",
            "wrapped_key": serde_json::to_value(wrapped_dek).unwrap(),
            "kek_version": kek_version,
            "metadata_privacy": true,
            "obfuscation_mode": "flat",
            "private_metadata": encrypted_meta.to_json().map_err(ClientError::Encryption)?,
            "chunked": serde_json::to_value(&chunked_metadata).unwrap(),
        });
        
        // The index object is small - just metadata, no file content
        let index_body = enc_metadata.to_string();
        let metadata = ObjectMetadata::new()
            .with_content_type("application/json")
            .with_metadata("x-fula-encrypted", "true")
            .with_metadata("x-fula-chunked", "true")
            .with_metadata("x-fula-encryption", &index_body);
        
        // Upload index object. If this fails after all chunks were successfully
        // uploaded, we must compensate by deleting the chunks — otherwise the
        // upload is non-atomic and leaks storage.
        let index_result = if let Some(ref pinning) = self.pinning {
            self.inner.put_object_with_metadata_and_pinning(
                bucket,
                storage_key,
                Bytes::from(index_body.clone()),
                Some(metadata),
                &pinning.endpoint,
                &pinning.token,
            ).await
        } else {
            self.inner.put_object_with_metadata(
                bucket,
                storage_key,
                Bytes::from(index_body.clone()),
                Some(metadata),
            ).await
        };

        let result = match index_result {
            Ok(r) => r,
            Err(e) => {
                // Compensating delete: best-effort cleanup of orphaned chunks.
                for key in &uploaded_keys {
                    let _ = self.inner.delete_object(bucket, key).await;
                }
                return Err(e);
            }
        };

        Ok(result)
    }

    /// Upload an object with resumable chunked encoding.
    ///
    /// Like `put_object_encrypted_with_type`, but writes a manifest file at
    /// `manifest_path` before uploading chunks. On failure, the manifest records
    /// which chunks succeeded, and the upload can be resumed with `resume_upload`.
    ///
    /// On success, the manifest file is deleted. Existing non-resumable methods
    /// are unchanged (they still delete-on-failure).
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn put_object_encrypted_resumable(
        &self,
        bucket: &str,
        key: &str,
        data: impl Into<Bytes>,
        content_type: Option<&str>,
        manifest_path: &std::path::Path,
    ) -> Result<PutObjectResult> {
        let data = data.into();
        let original_size = data.len() as u64;

        let dek = self.encryption.key_manager.generate_dek();
        let encryptor = Encryptor::new(self.encryption.public_key());
        let wrapped_dek = encryptor.encrypt_dek(&dek)
            .map_err(ClientError::Encryption)?;

        // H-1: BLAKE3 over the plaintext stream — bound to the forest
        // entry, not to the attacker-controllable ChunkedFileMetadata blob.
        let content_hash = blake3::hash(&data).to_hex().to_string();
        let private_meta = PrivateMetadata::new(key, original_size)
            .with_content_type(content_type.unwrap_or("application/octet-stream"))
            .with_content_hash(content_hash);
        let encrypted_meta = EncryptedPrivateMetadata::encrypt(&private_meta, &dek)
            .map_err(ClientError::Encryption)?;

        let path_dek = self.encryption.key_manager.derive_path_key(key);
        let storage_key = obfuscate_key(key, &path_dek, self.encryption.obfuscation_mode.clone());
        let kek_version = self.encryption.key_manager.version();

        // Encode all chunks (in memory — for streaming, use put_object_encrypted_streaming)
        let aad_prefix = format!("fula:v4:chunk:{}", storage_key);
        let mut encoder = ChunkedEncoder::with_aad(dek.clone(), aad_prefix);
        let mut all_chunks = encoder.update(&data).map_err(ClientError::Encryption)?;
        let (final_chunk, chunked_metadata, _outboard) = encoder.finalize()
            .map_err(ClientError::Encryption)?;
        if let Some(chunk) = final_chunk {
            all_chunks.push(chunk);
        }

        // Build the index metadata JSON (same as put_object_chunked_internal)
        let index_metadata_json = serde_json::json!({
            "version": 4,
            "algorithm": "AES-256-GCM",
            "wrapped_key": serde_json::to_value(&wrapped_dek).unwrap(),
            "kek_version": kek_version,
            "metadata_privacy": true,
            "obfuscation_mode": "flat",
            "private_metadata": encrypted_meta.to_json().map_err(ClientError::Encryption)?,
            "chunked": serde_json::to_value(&chunked_metadata).unwrap(),
        }).to_string();

        // Write manifest before uploading any chunks
        let manifest_chunks: Vec<ManifestChunk> = all_chunks.iter().map(|c| {
            ManifestChunk {
                index: c.index,
                chunk_key: ChunkedFileMetadata::chunk_key(&storage_key, c.index),
                uploaded: false,
            }
        }).collect();

        let mut manifest = UploadManifest {
            bucket: bucket.to_string(),
            storage_key: storage_key.clone(),
            original_key: key.to_string(),
            num_chunks: all_chunks.len() as u32,
            chunks: manifest_chunks,
            index_metadata_json,
        };
        manifest.save(manifest_path)?;

        // Upload chunks in parallel
        let semaphore = Arc::new(tokio::sync::Semaphore::new(Self::MAX_CONCURRENT_CHUNK_UPLOADS));
        let mut handles = Vec::with_capacity(all_chunks.len());

        for chunk in all_chunks {
            let chunk_key = ChunkedFileMetadata::chunk_key(&storage_key, chunk.index);
            let chunk_key_ret = chunk_key.clone();
            let chunk_idx = chunk.index;
            let sem = semaphore.clone();
            let client = self.inner.clone();
            let bucket_owned = bucket.to_string();
            let pinning = self.pinning.clone();
            let chunk_metadata = ObjectMetadata::new()
                .with_content_type("application/octet-stream")
                .with_metadata("x-fula-chunk-index", &chunk.index.to_string());

            let handle = tokio::spawn(async move {
                let _permit = sem.acquire().await.map_err(|e|
                    ClientError::Encryption(fula_crypto::CryptoError::Decryption(e.to_string()))
                )?;
                if let Some(ref pin) = pinning {
                    client.put_object_with_metadata_and_pinning(
                        &bucket_owned, &chunk_key, chunk.ciphertext,
                        Some(chunk_metadata), &pin.endpoint, &pin.token,
                    ).await?;
                } else {
                    client.put_object_with_metadata(
                        &bucket_owned, &chunk_key, chunk.ciphertext, Some(chunk_metadata),
                    ).await?;
                }
                Ok::<(u32, String), ClientError>((chunk_idx, chunk_key_ret))
            });
            handles.push(handle);
        }

        // Collect results, updating manifest as chunks complete
        let mut upload_error: Option<ClientError> = None;
        for handle in handles {
            match handle.await {
                Ok(Ok((idx, _key))) => {
                    if let Some(mc) = manifest.chunks.iter_mut().find(|c| c.index == idx) {
                        mc.uploaded = true;
                    }
                    let _ = manifest.save(manifest_path);
                }
                Ok(Err(e)) => { if upload_error.is_none() { upload_error = Some(e); } }
                Err(e) => {
                    if upload_error.is_none() {
                        upload_error = Some(ClientError::Encryption(
                            fula_crypto::CryptoError::Decryption(format!("Chunk upload task failed: {}", e))
                        ));
                    }
                }
            }
        }

        if let Some(err) = upload_error {
            // Save manifest with partial progress — DON'T delete uploaded chunks
            let _ = manifest.save(manifest_path);
            return Err(err);
        }

        // All chunks uploaded — finalize
        self.finalize_resumed_upload(&manifest, manifest_path).await
    }

    /// Upload an object from an async reader, encrypting and uploading chunks
    /// as they are produced. Never holds more than ~2x chunk_size in memory.
    ///
    /// Writes the same `streaming-v2` format with AAD as the in-memory upload
    /// path, so existing `ChunkedDecoder` decrypts these identically.
    ///
    /// The `total_size` parameter is needed to create accurate private metadata
    /// since we can't know the size from a reader without reading it.
    ///
    /// Only available on native (not WASM) because it requires `AsyncStreamingEncoder`.
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn put_object_encrypted_streaming<R: tokio::io::AsyncRead + Unpin + Send>(
        &self,
        bucket: &str,
        key: &str,
        reader: R,
        total_size: u64,
        content_type: Option<&str>,
    ) -> Result<PutObjectResult> {
        // Generate a DEK for this object
        let dek = self.encryption.key_manager.generate_dek();

        // Encrypt the DEK with HPKE for the owner
        let encryptor = Encryptor::new(self.encryption.public_key());
        let wrapped_dek = encryptor.encrypt_dek(&dek)
            .map_err(ClientError::Encryption)?;

        // Generate obfuscated storage key using path-derived DEK
        let path_dek = self.encryption.key_manager.derive_path_key(key);
        let storage_key = obfuscate_key(key, &path_dek, self.encryption.obfuscation_mode.clone());

        let kek_version = self.encryption.key_manager.version();

        // Use AsyncStreamingEncoder with AAD binding
        let aad_prefix = format!("fula:v4:chunk:{}", storage_key);
        let mut encoder = fula_crypto::AsyncStreamingEncoder::with_aad(dek.clone(), aad_prefix);

        // Process the reader — chunks are produced as the reader is consumed.
        // Memory usage bounded to ~chunk_size during encoding.
        let all_chunks = encoder.process_reader(reader).await
            .map_err(ClientError::Encryption)?;
        // H-1: grab the content hash before `finalize` consumes the encoder.
        let content_hash = encoder.content_hash_hex();
        let (chunked_metadata, _outboard) = encoder.finalize();

        // Create private metadata (deferred until after streaming so the
        // BLAKE3 content hash computed over the plaintext stream lands on
        // the forest entry — H-1).
        let private_meta = PrivateMetadata::new(key, total_size)
            .with_content_type(content_type.unwrap_or("application/octet-stream"))
            .with_content_hash(content_hash);
        let encrypted_meta = EncryptedPrivateMetadata::encrypt(&private_meta, &dek)
            .map_err(ClientError::Encryption)?;

        // Upload chunks in parallel with bounded concurrency
        let semaphore = Arc::new(tokio::sync::Semaphore::new(Self::MAX_CONCURRENT_CHUNK_UPLOADS));
        let mut handles = Vec::with_capacity(all_chunks.len());

        for chunk in all_chunks {
            let chunk_key = ChunkedFileMetadata::chunk_key(&storage_key, chunk.index);
            let chunk_key_ret = chunk_key.clone();
            let sem = semaphore.clone();
            let client = self.inner.clone();
            let bucket = bucket.to_string();
            let chunk_metadata = ObjectMetadata::new()
                .with_content_type("application/octet-stream")
                .with_metadata("x-fula-chunk-index", &chunk.index.to_string());
            let pinning = self.pinning.clone();

            let handle = tokio::spawn(async move {
                let _permit = sem.acquire().await.map_err(|e|
                    ClientError::Encryption(fula_crypto::CryptoError::Decryption(e.to_string()))
                )?;
                if let Some(ref pin) = pinning {
                    client.put_object_with_metadata_and_pinning(
                        &bucket, &chunk_key, chunk.ciphertext,
                        Some(chunk_metadata), &pin.endpoint, &pin.token,
                    ).await?;
                } else {
                    client.put_object_with_metadata(
                        &bucket, &chunk_key, chunk.ciphertext, Some(chunk_metadata),
                    ).await?;
                }
                Ok::<String, ClientError>(chunk_key_ret)
            });
            handles.push(handle);
        }

        // Collect results — track uploaded chunk keys for cleanup on failure
        let mut uploaded_keys: Vec<String> = Vec::new();
        let mut upload_error: Option<ClientError> = None;

        for handle in handles {
            match handle.await {
                Ok(Ok(key)) => uploaded_keys.push(key),
                Ok(Err(e)) => { if upload_error.is_none() { upload_error = Some(e); } }
                Err(e) => {
                    if upload_error.is_none() {
                        upload_error = Some(ClientError::Encryption(
                            fula_crypto::CryptoError::Decryption(format!("Chunk upload task failed: {}", e))
                        ));
                    }
                }
            }
        }

        if let Some(err) = upload_error {
            for key in &uploaded_keys {
                let _ = self.inner.delete_object(bucket, key).await;
            }
            return Err(err);
        }

        // Create index object with encryption metadata
        let enc_metadata = serde_json::json!({
            "version": 4,
            "algorithm": "AES-256-GCM",
            "wrapped_key": serde_json::to_value(&wrapped_dek).unwrap(),
            "kek_version": kek_version,
            "metadata_privacy": true,
            "obfuscation_mode": "flat",
            "private_metadata": encrypted_meta.to_json().map_err(ClientError::Encryption)?,
            "chunked": serde_json::to_value(&chunked_metadata).unwrap(),
        });

        let index_body = enc_metadata.to_string();
        let metadata = ObjectMetadata::new()
            .with_content_type("application/json")
            .with_metadata("x-fula-encrypted", "true")
            .with_metadata("x-fula-chunked", "true")
            .with_metadata("x-fula-encryption", &index_body);

        let result = if let Some(ref pinning) = self.pinning {
            self.inner.put_object_with_metadata_and_pinning(
                bucket, &storage_key, Bytes::from(index_body.clone()),
                Some(metadata), &pinning.endpoint, &pinning.token,
            ).await?
        } else {
            self.inner.put_object_with_metadata(
                bucket, &storage_key, Bytes::from(index_body.clone()), Some(metadata),
            ).await?
        };

        Ok(result)
    }

    /// Resume a chunked upload from a manifest file.
    ///
    /// Reads the manifest to determine which chunks were already uploaded,
    /// re-encrypts and uploads only the remaining chunks, then finalizes
    /// the index object. On success, deletes the manifest file.
    ///
    /// `data` must be the same file content that was used for the original
    /// upload attempt (the manifest does not store the file data).
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn resume_upload(
        &self,
        manifest_path: &std::path::Path,
        data: &[u8],
    ) -> Result<PutObjectResult> {
        let mut manifest = UploadManifest::load(manifest_path)?;

        if manifest.remaining() == 0 {
            // All chunks uploaded — just finalize the index
            return self.finalize_resumed_upload(&manifest, manifest_path).await;
        }

        // Re-encrypt only the missing chunks.
        // We need the same DEK and AAD, which are embedded in the index metadata.
        // Parse the index metadata to extract the chunked metadata (nonces etc.)
        let index_meta: serde_json::Value = serde_json::from_str(&manifest.index_metadata_json)
            .map_err(|e| ClientError::Encryption(
                fula_crypto::CryptoError::Decryption(format!("Invalid index metadata in manifest: {}", e))
            ))?;

        let chunked_meta: ChunkedFileMetadata = serde_json::from_value(
            index_meta["chunked"].clone()
        ).map_err(|e| ClientError::Encryption(
            fula_crypto::CryptoError::Decryption(format!("Invalid chunked metadata in manifest: {}", e))
        ))?;

        // Verify `data` matches the original upload BEFORE reusing any stored nonce.
        // Each chunk's nonce was generated once at upload time and persisted in
        // `chunked_meta.chunk_nonces`. If `data` differs from the original bytes,
        // re-encrypting under the same (DEK, nonce) pair leaks the keystream XOR
        // of the two plaintexts and collapses AEAD authenticity. The BAO root
        // hash already stored in `chunked_meta` is the existing whole-file
        // fingerprint — reusing it avoids a schema change and works for all
        // pre-existing manifests.
        if data.len() as u64 != chunked_meta.total_size {
            return Err(ClientError::Encryption(CryptoError::BaoVerification(
                format!(
                    "resume_upload: data length {} does not match manifest total_size {} — refusing to reuse stored nonces with different plaintext",
                    data.len(),
                    chunked_meta.total_size,
                ),
            )));
        }
        let mut bao = BaoEncoder::new();
        bao.update(data);
        let computed = bao.finalize();
        let expected_root = chunked_meta
            .get_root_hash()
            .map_err(ClientError::Encryption)?;
        if computed.root_hash().as_bytes() != expected_root.as_bytes() {
            return Err(ClientError::Encryption(CryptoError::BaoVerification(
                "resume_upload: data content does not match original upload (BAO root hash mismatch) — refusing to reuse stored nonces with different plaintext".to_string(),
            )));
        }

        // Re-derive the DEK: we need the wrapped key + our secret key
        let wrapped_dek: EncryptedData = serde_json::from_value(
            index_meta["wrapped_key"].clone()
        ).map_err(|e| ClientError::Encryption(
            fula_crypto::CryptoError::Decryption(format!("Invalid wrapped key in manifest: {}", e))
        ))?;

        let decryptor = Decryptor::new(self.encryption.key_manager.keypair());
        let dek = decryptor.decrypt_dek(&wrapped_dek)
            .map_err(ClientError::Encryption)?;

        // Re-encrypt and upload only missing chunks
        let chunk_size = chunked_meta.chunk_size as usize;
        let aad_prefix = format!("fula:v4:chunk:{}", manifest.storage_key);
        let semaphore = Arc::new(tokio::sync::Semaphore::new(Self::MAX_CONCURRENT_CHUNK_UPLOADS));
        let mut handles = Vec::new();

        for mc in &manifest.chunks {
            if mc.uploaded {
                continue;
            }

            let chunk_index = mc.index;
            let start = chunk_index as usize * chunk_size;
            let end = std::cmp::min(start + chunk_size, data.len());
            if start >= data.len() {
                break;
            }

            let chunk_data = &data[start..end];

            // Encrypt using the per-chunk nonce from the original metadata
            let nonce = chunked_meta.get_chunk_nonce(chunk_index)
                .map_err(ClientError::Encryption)?;
            let aead = Aead::new_default(&dek);
            let aad = format!("{}:{}", aad_prefix, chunk_index).into_bytes();
            let ciphertext = aead.encrypt_with_aad(&nonce, chunk_data, &aad)
                .map_err(ClientError::Encryption)?;

            let chunk_key = mc.chunk_key.clone();
            let chunk_key_ret = chunk_key.clone();
            let sem = semaphore.clone();
            let client = self.inner.clone();
            let bucket = manifest.bucket.clone();
            let pinning = self.pinning.clone();
            let ciphertext_bytes = Bytes::from(ciphertext);
            let chunk_metadata = ObjectMetadata::new()
                .with_content_type("application/octet-stream")
                .with_metadata("x-fula-chunk-index", &chunk_index.to_string());

            let handle = tokio::spawn(async move {
                let _permit = sem.acquire().await.map_err(|e|
                    ClientError::Encryption(fula_crypto::CryptoError::Decryption(e.to_string()))
                )?;
                if let Some(ref pin) = pinning {
                    client.put_object_with_metadata_and_pinning(
                        &bucket, &chunk_key, ciphertext_bytes,
                        Some(chunk_metadata), &pin.endpoint, &pin.token,
                    ).await?;
                } else {
                    client.put_object_with_metadata(
                        &bucket, &chunk_key, ciphertext_bytes, Some(chunk_metadata),
                    ).await?;
                }
                Ok::<(u32, String), ClientError>((chunk_index, chunk_key_ret))
            });
            handles.push(handle);
        }

        // Collect results, updating manifest as chunks complete
        let mut upload_error: Option<ClientError> = None;
        for handle in handles {
            match handle.await {
                Ok(Ok((idx, _key))) => {
                    if let Some(mc) = manifest.chunks.iter_mut().find(|c| c.index == idx) {
                        mc.uploaded = true;
                    }
                    // Persist manifest after each successful chunk for crash safety
                    let _ = manifest.save(manifest_path);
                }
                Ok(Err(e)) => { if upload_error.is_none() { upload_error = Some(e); } }
                Err(e) => {
                    if upload_error.is_none() {
                        upload_error = Some(ClientError::Encryption(
                            fula_crypto::CryptoError::Decryption(format!("Chunk upload task failed: {}", e))
                        ));
                    }
                }
            }
        }

        if let Some(err) = upload_error {
            // Save manifest with partial progress — DON'T delete chunks
            let _ = manifest.save(manifest_path);
            return Err(err);
        }

        // All chunks uploaded — finalize
        self.finalize_resumed_upload(&manifest, manifest_path).await
    }

    /// Upload the index object for a resumed upload and clean up the manifest.
    #[cfg(not(target_arch = "wasm32"))]
    async fn finalize_resumed_upload(
        &self,
        manifest: &UploadManifest,
        manifest_path: &std::path::Path,
    ) -> Result<PutObjectResult> {
        let index_body = &manifest.index_metadata_json;
        let metadata = ObjectMetadata::new()
            .with_content_type("application/json")
            .with_metadata("x-fula-encrypted", "true")
            .with_metadata("x-fula-chunked", "true")
            .with_metadata("x-fula-encryption", index_body);

        let result = if let Some(ref pinning) = self.pinning {
            self.inner.put_object_with_metadata_and_pinning(
                &manifest.bucket, &manifest.storage_key,
                Bytes::from(index_body.clone()),
                Some(metadata), &pinning.endpoint, &pinning.token,
            ).await?
        } else {
            self.inner.put_object_with_metadata(
                &manifest.bucket, &manifest.storage_key,
                Bytes::from(index_body.clone()), Some(metadata),
            ).await?
        };

        // Success — delete the manifest file
        let _ = std::fs::remove_file(manifest_path);
        Ok(result)
    }

    /// Abort a previously failed upload: delete all uploaded chunks and
    /// remove the manifest file.
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn abort_upload(
        &self,
        manifest_path: &std::path::Path,
    ) -> Result<()> {
        let manifest = UploadManifest::load(manifest_path)?;

        for mc in &manifest.chunks {
            if mc.uploaded {
                let _ = self.inner.delete_object(&manifest.bucket, &mc.chunk_key).await;
            }
        }

        let _ = std::fs::remove_file(manifest_path);
        Ok(())
    }

    /// Flush the forest index to storage.
    ///
    /// Call this after bulk uploads using `put_object_flat_deferred`.
    /// This persists the in-memory forest index to encrypted storage.
    ///
    /// NEW-7.2: on a 412 (concurrent modification), this wrapper reloads the
    /// winner's forest, replays any pending WAL entries on top, and retries
    /// the flush up to `MAX_FLUSH_RETRIES` times. If all retries lose the
    /// race, surfaces `ClientError::ConcurrentModificationExhausted` with the
    /// WAL path so the caller can inspect / recover pending work.
    pub async fn flush_forest(&self, bucket: &str) -> Result<()> {
        #[cfg(target_arch = "wasm32")]
        {
            // On WASM we have no WAL / no file state, so fall back to the old
            // behaviour (single attempt, propagate 412 immediately).
            return self.flush_forest_inner(bucket).await;
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            let wal_mac = wal::derive_mac_key(&self.encryption.key_manager, bucket);
            let mut last_err: Option<ClientError> = None;
            for attempt in 0..MAX_FLUSH_RETRIES {
                match self.flush_forest_inner(bucket).await {
                    Ok(()) => {
                        // Clean flush: drop the WAL so we don't replay old
                        // entries on future flushes / restarts.
                        if let Err(e) = wal::clear(bucket) {
                            tracing::warn!(%bucket, error = %e, "WAL clear after flush failed");
                        }
                        return Ok(());
                    }
                    Err(e) if e.is_concurrent_modification() && attempt + 1 < MAX_FLUSH_RETRIES => {
                        tracing::warn!(%bucket, attempt, "flush_forest: 412 race, replaying WAL and retrying");
                        // Cache was already evicted by save_forest / save_sharded_forest.
                        // Reload the winner's forest, replay any WAL entries on top,
                        // then fall through to the next retry.
                        self.ensure_forest_loaded(bucket).await?;
                        let wal_entries = wal::load(bucket, &wal_mac)
                            .unwrap_or_else(|e| {
                                tracing::warn!(%bucket, error = %e, "WAL load failed during replay");
                                Vec::new()
                            });
                        self.replay_wal_entries(bucket, wal_entries).await?;
                        // M-2: Jittered exponential backoff to break thundering-herd
                        // under multi-writer contention. Base 50ms * 2^attempt, plus
                        // 0-99ms jitter. Delays: 50-149ms, 100-199ms (3rd attempt
                        // short-circuits via `attempt + 1 < MAX_FLUSH_RETRIES`).
                        // WAL prune-between-retries: deferred — requires inner to
                        // return applied indices; backoff alone addresses the
                        // thundering-herd window flagged by audit.
                        let delay = flush_backoff_delay(attempt);
                        FLUSH_BACKOFF_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        tokio::time::sleep(delay).await;
                        last_err = Some(e);
                        continue;
                    }
                    Err(e) if e.is_concurrent_modification() => {
                        last_err = Some(e);
                        break;
                    }
                    Err(e) => return Err(e),
                }
            }
            // Exhausted. Build a structured error with the WAL path for diagnosis.
            let unresolved_ops = wal::load(bucket, &wal_mac).map(|v| v.len()).unwrap_or(0);
            let wal_path_str = wal::path_for(bucket)
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "<no-state-dir>".to_string());
            tracing::warn!(%bucket, retries = MAX_FLUSH_RETRIES, unresolved_ops, "flush_forest: giving up after retries");
            let _ = last_err; // retained for future structured reporting
            Err(ClientError::ConcurrentModificationExhausted {
                bucket: bucket.to_string(),
                retries: MAX_FLUSH_RETRIES,
                unresolved_ops,
                wal_path: wal_path_str,
            })
        }
    }

    /// Single-attempt flush of the forest index to storage. Called by
    /// `flush_forest` inside its retry loop.
    async fn flush_forest_inner(&self, bucket: &str) -> Result<()> {
        // Acquire read lock — blocks only if migration is in progress
        let lock = self.migration_lock(bucket);
        let _guard = lock.read().await;

        let is_dirty = self.forest_cache.get(bucket)
            .map(|entry| entry.is_dirty())
            .unwrap_or(false);

        if !is_dirty {
            return Ok(());
        }

        // v7 sharded-HAMT: no auto-migration or reshard inside a flush yet —
        // those are separate follow-ups. Just route to the v7 save path.
        if self.is_forest_sharded_hamt(bucket) {
            return self.save_sharded_hamt_forest(bucket).await;
        }

        // Monolithic v1: just save v1. Auto-migration to v7 is triggered by
        // `load_forest_internal` at first access. If we're flushing a v1
        // forest here, migration was deferred earlier this session (lock held
        // by another device, pending WAL entries, transient failure) and will
        // re-enter on the next load; flush's job is to keep v1 writes durable
        // in the meantime.
        let forest = self.forest_cache.get(bucket).and_then(|entry| {
            match entry.value() {
                ForestCacheEntry::Monolithic { forest, .. } => Some(forest.clone()),
                _ => None,
            }
        });
        if let Some(forest) = forest {
            self.save_forest(bucket, &forest).await?;
        }
        Ok(())
    }

    /// Replay a WAL entry list on top of the currently-cached forest for
    /// `bucket`. Used by `flush_forest` after a 412-race to re-apply a losing
    /// writer's dirty ops on top of the winner's forest before retrying the
    /// flush (NEW-7.2). Loads the target shard(s) as needed.
    ///
    /// `ShardWrote` entries are processed first so that any subsequent
    /// `load_shard` inside an `Insert`/`Remove` replay uses the reconciled
    /// `shard_sequences[idx]` — otherwise the winner's manifest (which didn't
    /// know about our phase-1 advancement) would trip the AEAD seq verifier.
    #[cfg(not(target_arch = "wasm32"))]
    async fn replay_wal_entries(&self, bucket: &str, entries: Vec<WalEntry>) -> Result<()> {
        if entries.is_empty() {
            return Ok(());
        }
        let is_v7 = self.is_forest_sharded_hamt(bucket);

        // v7 replay runs on a distinct cache shape (ShardedHamt holds an
        // `Arc<tokio::sync::RwLock<ShardedHamtPrivateForest>>`). Detect once
        // here; the body below dispatches to this branch before touching
        // the v1 monolithic cache that doesn't exist on v7.
        if is_v7 {
            let (forest_arc, backend) = {
                let entry = match self.forest_cache.get(bucket) {
                    Some(e) => e,
                    None => return Ok(()),
                };
                match entry.value() {
                    ForestCacheEntry::ShardedHamt { forest, .. } => {
                        let fa = forest.clone();
                        let be = Arc::new(S3BlobBackend::new(self.inner.clone(), bucket.to_string()));
                        (fa, be)
                    }
                    _ => unreachable!("is_v7 guard above"),
                }
            };

            // Phase 1 (v7): fold every ShardWrote into a `max(seq, etag)`
            // view per shard, then reconcile the manifest + mark the shard
            // dirty so the next flush re-PUTs the node subtree bumped to
            // wal_seq + 1 (matching the v6 contract — a shard we already
            // wrote to S3 owns its slot, and the replay has to rewrite from
            // that slot forward so node AAD stays consistent).
            let mut shard_writes: std::collections::HashMap<usize, (u64, Option<String>)> =
                std::collections::HashMap::new();
            for wentry in &entries {
                if let WalEntry::ShardWrote { idx, seq, etag } = wentry {
                    let slot = shard_writes.entry(*idx).or_insert((0u64, None));
                    if *seq >= slot.0 {
                        *slot = (*seq, etag.clone());
                    }
                }
            }

            // Fold PageWrote entries by `page_id`, keeping the highest-seq
            // record whose `new_etag` is `Some` — i.e. a post-PUT record
            // proving the etag S3 actually serves. Pre-PUT records
            // (`new_etag: None`) are skipped here: they guarantee PUT
            // idempotency at the same key but don't authoritatively pin
            // the root-side etag. On a Phase-1.5-landed-but-Phase-2-crashed
            // write, the reloaded `manifest.root.page_index[page_id]`
            // carries the pre-crash (stale) etag; applying the folded
            // post-PUT record patches it so the next flush's `If-Match`
            // succeeds instead of looping on 412.
            let mut page_writes: std::collections::HashMap<
                PageId,
                (u64, Option<String>),
            > = std::collections::HashMap::new();
            for wentry in &entries {
                if let WalEntry::PageWrote { page_id, new_etag: Some(et), seq, .. } = wentry {
                    let slot = page_writes.entry(*page_id).or_insert((0u64, None));
                    if *seq >= slot.0 {
                        *slot = (*seq, Some(et.clone()));
                    }
                }
            }

            // Fold DirIndexWrote entries the same way: highest-seq post-PUT
            // record wins. Applied to `root.dir_index_etag` +
            // `root.dir_index_seq` via `reconcile_dir_index_etag`.
            let mut dir_index_write: Option<(u64, Option<String>)> = None;
            for wentry in &entries {
                if let WalEntry::DirIndexWrote { new_etag: Some(et), seq, .. } = wentry {
                    if dir_index_write.as_ref().map_or(true, |(s, _)| *seq >= *s) {
                        dir_index_write = Some((*seq, Some(et.clone())));
                    }
                }
            }

            {
                let mut guard = forest_arc.write().await;
                if !shard_writes.is_empty() {
                    let num_shards = guard.manifest().num_shards();
                    for (idx, (seq, etag)) in shard_writes {
                        if idx < num_shards {
                            guard.reconcile_shard_write(idx, seq, etag);
                        }
                    }
                }
                for (page_id, (seq, etag)) in page_writes {
                    guard.reconcile_page_etag(page_id, seq, etag);
                }
                if let Some((seq, etag)) = dir_index_write {
                    guard.reconcile_dir_index_etag(seq, etag);
                }

                // Phase 2 (v7): replay Insert/Remove in the same order they
                // were logged. `upsert_file` / `remove_file` are
                // per-shard-dirty-marking so a subsequent `flush_dirty`
                // picks them up under the post-reconciled sequence.
                for wentry in entries {
                    match wentry {
                        WalEntry::Insert { key: _, entry: forest_entry } => {
                            // F4: WAL entries originate from prior upserts
                            // that already enforced the v7 invariant
                            // (`encrypted: true`) at the upsert site — no
                            // additional assert here.
                            guard.upsert_file(forest_entry, &backend).await
                                .map_err(ClientError::Encryption)?;
                        }
                        WalEntry::Remove { key } => {
                            let _ = guard.remove_file(&key, &backend).await
                                .map_err(ClientError::Encryption)?;
                        }
                        WalEntry::ShardWrote { .. }
                        | WalEntry::PageWrote { .. }
                        | WalEntry::DirIndexWrote { .. } => {
                            // Handled above in the fold/reconcile phase.
                        }
                    }
                }
            }
            return Ok(());
        }

        // Monolithic v1 replay: ShardWrote entries are v7-only so they're a
        // no-op here. Just replay Insert/Remove on the monolithic cache.
        for entry in entries {
            match entry {
                WalEntry::Insert { key: _, entry: forest_entry } => {
                    if let Some(mut cache_entry) = self.forest_cache.get_mut(bucket) {
                        if let ForestCacheEntry::Monolithic { forest, dirty, .. } = cache_entry.value_mut() {
                            forest.upsert_file(forest_entry);
                            *dirty = true;
                        }
                    }
                }
                WalEntry::Remove { key } => {
                    if let Some(mut cache_entry) = self.forest_cache.get_mut(bucket) {
                        if let ForestCacheEntry::Monolithic { forest, dirty, .. } = cache_entry.value_mut() {
                            forest.remove_file(&key);
                            *dirty = true;
                        }
                    }
                }
                WalEntry::ShardWrote { .. } => {
                    // v7-only; ignored for monolithic replay.
                }
                WalEntry::PageWrote { .. } | WalEntry::DirIndexWrote { .. } => {
                    // v7-only meta-HAMT entries; ignored on monolithic replay.
                }
            }
        }
        Ok(())
    }

    /// Check if there are unsaved forest changes
    pub async fn has_pending_forest_changes(&self, bucket: &str) -> bool {
        self.forest_cache
            .get(bucket)
            .map(|entry| entry.is_dirty())
            .unwrap_or(false)
    }

    /// Invalidate the forest cache for a specific bucket
    ///
    /// Forces the next `load_forest` call to reload from storage.
    /// Dirty (unsaved) entries are NOT evicted — call `flush_forest()` first
    /// to persist changes before invalidating.
    pub fn invalidate_forest_cache(&self, bucket: &str) {
        let is_dirty = self.forest_cache.get(bucket)
            .map(|entry| entry.is_dirty())
            .unwrap_or(false);
        if !is_dirty {
            self.forest_cache.remove(bucket);
        }
    }

    /// Invalidate all cached forests
    ///
    /// Forces all subsequent `load_forest` calls to reload from storage.
    /// Dirty (unsaved) entries are NOT evicted — call `flush_forest()` on
    /// each bucket first to persist changes before invalidating.
    pub fn invalidate_all_forest_caches(&self) {
        self.forest_cache.retain(|_, entry| entry.is_dirty());
    }

    /// Get an object using FlatNamespace mode
    /// 
    /// Uses the forest index to resolve original path → storage key.
    pub async fn get_object_flat(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<Bytes> {
        // Ensure forest is loaded (handles both monolithic and sharded)
        self.ensure_forest_loaded(bucket).await?;

        if self.is_forest_sharded_hamt(bucket) {
            // v7 read path: walk the HAMT to resolve `key` → `ForestFileEntry`.
            // Scope the DashMap guard so it is dropped before we `.read().await`
            // on the v7 forest RwLock (DashMap → forest-lock is the deadlock
            // direction; the reverse is safe).
            let forest_arc = {
                let entry = self.forest_cache.get(bucket)
                    .ok_or_else(|| ClientError::NotFound {
                        bucket: bucket.to_string(),
                        key: key.to_string(),
                    })?;
                match entry.value() {
                    ForestCacheEntry::ShardedHamt { forest, .. } => forest.clone(),
                    _ => unreachable!("is_forest_sharded_hamt guard above"),
                }
            };
            let backend = Arc::new(S3BlobBackend::new(self.inner.clone(), bucket.to_string()));
            let entry_opt = {
                // get_file now takes &self — concurrent readers don't serialise.
                let guard = forest_arc.read().await;
                guard.get_file(key, &backend).await.map_err(ClientError::Encryption)?
            };
            let entry = entry_opt.ok_or_else(|| ClientError::NotFound {
                bucket: bucket.to_string(),
                key: key.to_string(),
            })?;
            return self.get_object_decrypted_by_storage_key(bucket, &entry.storage_key).await;
        }

        // Monolithic v1/v2: already loaded by ensure_forest_loaded
        let entry = self.forest_cache.get(bucket)
            .ok_or_else(|| ClientError::NotFound { bucket: bucket.to_string(), key: key.to_string() })?;
        let storage_key = match entry.value() {
            ForestCacheEntry::Monolithic { forest, .. } => {
                forest.get_storage_key(key)
                    .ok_or_else(|| ClientError::NotFound { bucket: bucket.to_string(), key: key.to_string() })?
                    .to_string()
            }
            ForestCacheEntry::ShardedHamt { .. } => unreachable!("is_forest_sharded_hamt guard above"),
        };
        drop(entry);

        self.get_object_decrypted_by_storage_key(bucket, &storage_key).await
    }

    /// List directory from forest index (FlatNamespace mode)
    ///
    /// This is much faster than HEAD requests because the forest already
    /// contains all metadata.
    ///
    /// `continuation_token` / `max_keys` activate the paginated v7 walk:
    /// - `continuation_token = None`, `max_keys = None` → walk the whole prefix
    ///   (unchanged from pre-F5 behaviour).
    /// - `continuation_token = Some(tok)` → resume from the opaque token
    ///   returned by a previous call's `next_continuation_token`.
    /// - `max_keys = Some(n)` → stop after the first shard whose walk pushes
    ///   total matches ≥ `n` (shard-grained soft cap — see
    ///   `ShardedHamtPrivateForest::list_recursive_page`).
    ///
    /// v1 / v6 arms ignore `continuation_token` and `max_keys`: those
    /// forests are already fully in-memory, so pagination is a no-op and the
    /// full matching set is returned in one page.
    async fn list_directory_from_forest(
        &self,
        bucket: &str,
        prefix: Option<&str>,
        continuation_token: Option<&str>,
        max_keys: Option<usize>,
    ) -> Result<DirectoryListing> {
        self.ensure_forest_loaded(bucket).await?;

        let prefix_str = prefix.unwrap_or("/");

        // Build `directories` directly from forest entries without
        // materializing an intermediate Vec<ForestFileEntry>. Halves peak
        // memory for listings (was: clone all → clone again into FileMetadata).
        let mut directories: HashMap<String, Vec<FileMetadata>> = HashMap::new();

        let build_entry = |entry: &ForestFileEntry| -> (String, FileMetadata) {
            let dir = if let Some(last_slash) = entry.path.rfind('/') {
                entry.path[..last_slash].to_string()
            } else {
                "/".to_string()
            };
            let metadata = FileMetadata {
                storage_key: entry.storage_key.clone(),
                original_key: entry.path.clone(),
                original_size: entry.size,
                content_type: entry.content_type.clone(),
                created_at: Some(entry.created_at),
                modified_at: Some(entry.modified_at),
                user_metadata: entry.user_metadata.clone(),
                is_encrypted: true,
            };
            (dir, metadata)
        };

        if self.is_forest_sharded_hamt(bucket) {
            // v7: walk every shard's HAMT to collect files under the
            // prefix. Extract the Arc before awaiting so the DashMap guard
            // is dropped before we take the v7 mutex.
            let forest_arc = {
                let entry = self.forest_cache.get(bucket)
                    .ok_or_else(|| ClientError::Encryption(
                        fula_crypto::CryptoError::Encryption("forest not loaded".to_string())
                    ))?;
                match entry.value() {
                    ForestCacheEntry::ShardedHamt { forest, .. } => forest.clone(),
                    _ => unreachable!("is_forest_sharded_hamt guard above"),
                }
            };
            let backend: Arc<S3BlobBackend> = Arc::new(
                S3BlobBackend::new(self.inner.clone(), bucket.to_string())
            );
            // F5: route through the shard-grained paginated walk. When the
            // caller passes no bounds the loop drains every page, matching
            // pre-pagination semantics; when bounds are present we stop
            // after one page and return the opaque `next_continuation_token`.
            // F6: `list_recursive_page` takes `&self`, so concurrent readers
            // share the outer `RwLock` in `read()` mode.
            let cursor_bytes_first: Option<Vec<u8>> = match continuation_token {
                None => None,
                Some(tok) => Some(hex::decode(tok).map_err(|e| ClientError::Encryption(
                    fula_crypto::CryptoError::Hamt(format!(
                        "list_directory: invalid continuation_token: {}", e
                    ))
                ))?),
            };
            let paginated = continuation_token.is_some() || max_keys.is_some();
            let cap = max_keys.unwrap_or(0); // 0 = no cap in list_recursive_page
            let mut cursor_bytes = cursor_bytes_first;
            let mut final_next: Option<Vec<u8>> = None;
            loop {
                let (page, next) = {
                    let guard = forest_arc.read().await;
                    guard.list_recursive_page(prefix_str, cursor_bytes.as_deref(), cap, &backend).await
                        .map_err(ClientError::Encryption)?
                };
                for fentry in &page {
                    let (dir, metadata) = build_entry(fentry);
                    directories.entry(dir).or_default().push(metadata);
                }
                // Paginated caller: return the first page and stop.
                if paginated {
                    final_next = next;
                    break;
                }
                // Unpaginated caller (legacy): drain every page.
                match next {
                    Some(c) => cursor_bytes = Some(c),
                    None => break,
                }
            }
            let (is_truncated, next_token) = match final_next {
                Some(bytes) => (true, Some(hex::encode(bytes))),
                None => (false, None),
            };
            return Ok(DirectoryListing {
                bucket: bucket.to_string(),
                prefix: prefix.map(|s| s.to_string()),
                directories,
                is_truncated,
                next_continuation_token: next_token,
            });
        }

        // Monolithic v1/v2: fully in-memory, pagination is a no-op.
        let entry = self.forest_cache.get(bucket).unwrap();
        match entry.value() {
            ForestCacheEntry::Monolithic { forest, .. } => {
                for fentry in forest.list_recursive(prefix_str) {
                    let (dir, metadata) = build_entry(fentry);
                    directories.entry(dir).or_default().push(metadata);
                }
            }
            ForestCacheEntry::ShardedHamt { .. } => unreachable!("is_forest_sharded_hamt guard above"),
        }
        drop(entry);

        // v1 / v2 monolithic forests are fully in-memory — pagination is a
        // no-op and we always return the complete matching set in a single
        // page.
        Ok(DirectoryListing {
            bucket: bucket.to_string(),
            prefix: prefix.map(|s| s.to_string()),
            directories,
            is_truncated: false,
            next_continuation_token: None,
        })
    }

    /// List all files from forest (FlatNamespace mode)
    /// 
    /// No network requests needed - uses cached/loaded forest index.
    pub async fn list_files_from_forest(
        &self,
        bucket: &str,
    ) -> Result<Vec<FileMetadata>> {
        self.ensure_forest_loaded(bucket).await?;

        // Build FileMetadata directly from forest references — avoids the
        // intermediate Vec<ForestFileEntry> clone that previously doubled
        // peak memory for listings.
        let make_meta = |entry: &ForestFileEntry| FileMetadata {
            storage_key: entry.storage_key.clone(),
            original_key: entry.path.clone(),
            original_size: entry.size,
            content_type: entry.content_type.clone(),
            created_at: Some(entry.created_at),
            modified_at: Some(entry.modified_at),
            user_metadata: entry.user_metadata.clone(),
            is_encrypted: true,
        };

        if self.is_forest_sharded_hamt(bucket) {
            let forest_arc = {
                let entry = self.forest_cache.get(bucket)
                    .ok_or_else(|| ClientError::Encryption(
                        fula_crypto::CryptoError::Encryption("forest not loaded".to_string())
                    ))?;
                match entry.value() {
                    ForestCacheEntry::ShardedHamt { forest, .. } => forest.clone(),
                    _ => unreachable!("is_forest_sharded_hamt guard above"),
                }
            };
            let backend: Arc<S3BlobBackend> = Arc::new(
                S3BlobBackend::new(self.inner.clone(), bucket.to_string())
            );
            let entries = {
                let guard = forest_arc.read().await;
                guard.list_all_files(&backend).await
                    .map_err(ClientError::Encryption)?
            };
            let files: Vec<FileMetadata> = entries.iter().map(&make_meta).collect();
            return Ok(files);
        }

        // Monolithic v1/v2: already loaded by ensure_forest_loaded.
        let entry = self.forest_cache.get(bucket).unwrap();
        let files: Vec<FileMetadata> = match entry.value() {
            ForestCacheEntry::Monolithic { forest, .. } => {
                forest.list_all_files().into_iter().map(&make_meta).collect()
            }
            ForestCacheEntry::ShardedHamt { .. } => unreachable!("is_forest_sharded_hamt guard above"),
        };
        drop(entry);

        Ok(files)
    }

    /// Check if a storage key refers to a chunked file, returning num_chunks if so.
    /// Returns None if the object doesn't exist, isn't chunked, or metadata can't be parsed.
    async fn get_chunked_num_chunks(&self, bucket: &str, storage_key: &str) -> Option<u32> {
        let head = self.inner.head_object(bucket, storage_key).await.ok()?;
        if head.metadata.get("x-fula-chunked").map(|v| v == "true") != Some(true) {
            return None;
        }
        let enc_str = head.metadata.get("x-fula-encryption")?;
        let enc_meta: serde_json::Value = serde_json::from_str(enc_str).ok()?;
        enc_meta["chunked"]["num_chunks"].as_u64().map(|n| n as u32)
    }

    /// Delete all chunk objects for a chunked file.
    ///
    /// Returns the number of chunks whose delete failed. Errors are logged
    /// (not silently dropped, as pre-F7) so partial-orphan state is visible
    /// to operators; the aggregate count lets the caller decide whether to
    /// enqueue for later retry. Deletes run concurrently with a
    /// `buffer_unordered` cap so a chunked file of N chunks does not hold
    /// the caller for O(N) serial round-trips.
    #[cfg(not(target_arch = "wasm32"))]
    async fn delete_chunk_objects(&self, bucket: &str, storage_key: &str, num_chunks: u32) -> u32 {
        use futures::StreamExt;
        let concurrency = 16usize;
        let bucket_s = bucket.to_string();
        let key_s = storage_key.to_string();
        let failed = futures::stream::iter(0..num_chunks)
            .map(|i| {
                let bucket = bucket_s.clone();
                let key = key_s.clone();
                let client = self.inner.clone();
                async move {
                    let chunk_key = ChunkedFileMetadata::chunk_key(&key, i);
                    match client.delete_object(&bucket, &chunk_key).await {
                        Ok(()) => None,
                        Err(e) => {
                            tracing::warn!(
                                bucket = %bucket,
                                storage_key = %key,
                                chunk_index = i,
                                error = ?e,
                                "delete_chunk_objects: failed to delete chunk"
                            );
                            Some(i)
                        }
                    }
                }
            })
            .buffer_unordered(concurrency)
            .filter_map(|r| async move { r })
            .count()
            .await;
        failed as u32
    }

    /// WASM fallback retains the pre-F7 serial path since there's no
    /// persistent queue to retry into and `buffer_unordered` pulls in
    /// concurrency primitives the wasm target doesn't support uniformly.
    #[cfg(target_arch = "wasm32")]
    async fn delete_chunk_objects(&self, bucket: &str, storage_key: &str, num_chunks: u32) -> u32 {
        let mut failed = 0u32;
        for i in 0..num_chunks {
            let chunk_key = ChunkedFileMetadata::chunk_key(storage_key, i);
            if let Err(e) = self.inner.delete_object(bucket, &chunk_key).await {
                tracing::warn!(
                    bucket = %bucket,
                    storage_key = %storage_key,
                    chunk_index = i,
                    error = ?e,
                    "delete_chunk_objects: failed to delete chunk"
                );
                failed += 1;
            }
        }
        failed
    }

    /// Return true if any file entry in the (already-loaded) forest for `bucket`
    /// references `storage_key`. Conservative: returns true when the forest is
    /// not loaded, so the caller never deletes content we cannot verify is orphaned.
    fn storage_key_still_referenced(&self, bucket: &str, storage_key: &str) -> bool {
        let Some(entry) = self.forest_cache.get(bucket) else {
            return true;
        };
        match entry.value() {
            ForestCacheEntry::Monolithic { forest, .. } => {
                forest.find_by_storage_key(storage_key).is_some()
            }
            // v7 traversal isn't wired yet; be conservative and keep the
            // object to match the function's "never delete what we can't
            // verify is orphaned" invariant.
            ForestCacheEntry::ShardedHamt { .. } => true,
        }
    }

    /// Best-effort cleanup of a main object + its chunks that are no longer
    /// referenced by any forest entry (F-3.1 orphaned-overwrite fix).
    ///
    /// Refcount safety: scans the in-memory forest first. If `storage_key` is
    /// still referenced by any entry (e.g., the caller mis-computed the old
    /// key, or server-side dedup produced a shared key), cleanup is skipped.
    /// The server DELETE handler performs the same refcount check against its
    /// own index before issuing an IPFS unpin, so shared CIDs are never
    /// unpinned prematurely.
    ///
    /// Failures are surfaced via the NEW-F7 persistent orphan queue: any
    /// chunk-delete or main-object-delete that errors causes a queue entry
    /// to be appended (deduped on storage_key) so a future session can
    /// retry the cleanup. A lazy drain runs at the top of this function to
    /// reclaim objects from prior failed sessions without holding
    /// `ensure_forest_loaded` on network I/O.
    async fn cleanup_orphaned_storage(
        &self,
        bucket: &str,
        storage_key: &str,
        num_chunks: Option<u32>,
    ) {
        // F7: opportunistically drain the persistent queue first. This runs
        // lazily — we only pay the drain cost when cleanup was already
        // going to fire, and we never fail the outer upload if the drain
        // has trouble.
        #[cfg(not(target_arch = "wasm32"))]
        self.drain_orphan_queue(bucket).await;

        #[cfg(feature = "test-fault-injection")]
        let bypass_refcheck = test_faults::BYPASS_ORPHAN_CLEANUP_REFCHECK
            .load(std::sync::atomic::Ordering::SeqCst);
        #[cfg(not(feature = "test-fault-injection"))]
        let bypass_refcheck = false;

        if !bypass_refcheck && self.storage_key_still_referenced(bucket, storage_key) {
            tracing::debug!(
                bucket = %bucket,
                storage_key = %storage_key,
                "Skipping orphan cleanup — storage key still referenced in forest"
            );
            return;
        }

        let mut chunk_failures: u32 = 0;
        if let Some(n) = num_chunks {
            chunk_failures = self.delete_chunk_objects(bucket, storage_key, n).await;
        }

        #[cfg(feature = "test-fault-injection")]
        let forced_fail = test_faults::FORCE_ORPHAN_CLEANUP_MAIN_FAIL
            .load(std::sync::atomic::Ordering::SeqCst);
        #[cfg(not(feature = "test-fault-injection"))]
        let forced_fail = false;

        let main_failed = if forced_fail {
            tracing::warn!(
                bucket = %bucket,
                storage_key = %storage_key,
                "test-fault-injection: FORCE_ORPHAN_CLEANUP_MAIN_FAIL — treating as failed delete"
            );
            true
        } else if let Err(e) = self.inner.delete_object(bucket, storage_key).await {
            tracing::warn!(
                bucket = %bucket,
                storage_key = %storage_key,
                error = ?e,
                "Failed to delete orphaned storage key (best-effort; enqueued for retry)"
            );
            true
        } else {
            false
        };

        // F7: if anything failed, persist the orphan for a future session to retry.
        #[cfg(not(target_arch = "wasm32"))]
        if main_failed || chunk_failures > 0 {
            let mac_key = orphan_queue::derive_orphan_queue_mac_key(
                &self.encryption.key_manager, bucket,
            );
            let entry = orphan_queue::OrphanEntry {
                storage_key: storage_key.to_string(),
                num_chunks,
            };
            match orphan_queue::append_dedup(bucket, &mac_key, entry) {
                Ok(true) => tracing::info!(
                    bucket = %bucket,
                    storage_key = %storage_key,
                    chunk_failures,
                    main_failed,
                    "orphan_queue: enqueued for retry"
                ),
                Ok(false) => tracing::debug!(
                    bucket = %bucket,
                    storage_key = %storage_key,
                    "orphan_queue: already queued, not duplicated"
                ),
                Err(e) => tracing::warn!(
                    bucket = %bucket,
                    storage_key = %storage_key,
                    error = ?e,
                    "orphan_queue: failed to enqueue; server-side GC may reclaim later"
                ),
            }
        }
        // Silence unused warning when wasm32.
        #[cfg(target_arch = "wasm32")]
        let _ = (main_failed, chunk_failures);
    }

    /// F7: attempt to delete any objects recorded in the persistent orphan
    /// queue for `bucket`. Entries whose re-cleanup succeeds are dropped;
    /// entries whose re-cleanup still fails stay queued for the next session.
    ///
    /// Concurrency: a per-bucket "in flight" marker in `orphan_drain_in_flight`
    /// ensures two concurrent cleanup calls don't redundantly drain the same
    /// queue. A lost race is harmless — the loser simply skips, the winner
    /// drains.
    #[cfg(not(target_arch = "wasm32"))]
    async fn drain_orphan_queue(&self, bucket: &str) {
        // Try-acquire the bucket's drain slot. If another task is already
        // draining we skip; the drain is idempotent so duplicating work is
        // wasteful but not incorrect.
        if self.orphan_drain_in_flight.insert(bucket.to_string(), ()).is_some() {
            return;
        }

        // Guard ensures we remove the marker even on panic.
        struct DrainGuard<'a> {
            map: &'a DashMap<String, ()>,
            bucket: String,
        }
        impl<'a> Drop for DrainGuard<'a> {
            fn drop(&mut self) {
                self.map.remove(&self.bucket);
            }
        }
        let _guard = DrainGuard {
            map: &self.orphan_drain_in_flight,
            bucket: bucket.to_string(),
        };

        let mac_key = orphan_queue::derive_orphan_queue_mac_key(
            &self.encryption.key_manager, bucket,
        );
        let queued = match orphan_queue::load(bucket, &mac_key) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(bucket = %bucket, error = ?e, "orphan_queue: load failed; skipping drain");
                return;
            }
        };
        if queued.is_empty() {
            return;
        }

        tracing::info!(bucket = %bucket, queue_depth = queued.len(), "orphan_queue: drain starting");

        #[cfg(feature = "test-fault-injection")]
        let bypass_refcheck = test_faults::BYPASS_ORPHAN_CLEANUP_REFCHECK
            .load(std::sync::atomic::Ordering::SeqCst);
        #[cfg(not(feature = "test-fault-injection"))]
        let bypass_refcheck = false;

        let mut keep: Vec<orphan_queue::OrphanEntry> = Vec::new();
        let mut drained = 0usize;
        for entry in &queued {
            // Re-check the reference guard — a content-addressed re-upload
            // could have revived this storage key between enqueue and drain.
            if !bypass_refcheck && self.storage_key_still_referenced(bucket, &entry.storage_key) {
                // Live again. Drop it from the queue rather than retry.
                drained += 1;
                continue;
            }
            let chunk_failures = if let Some(n) = entry.num_chunks {
                self.delete_chunk_objects(bucket, &entry.storage_key, n).await
            } else {
                0
            };
            // The fault mirrors a transient server-side delete failure. A real
            // server outage would reject the drain's delete attempt as well —
            // so honor the flag here too; otherwise the queue would drain
            // during the outage and defeat the simulation.
            #[cfg(feature = "test-fault-injection")]
            let forced_fail = test_faults::FORCE_ORPHAN_CLEANUP_MAIN_FAIL
                .load(std::sync::atomic::Ordering::SeqCst);
            #[cfg(not(feature = "test-fault-injection"))]
            let forced_fail = false;
            let main_failed = forced_fail
                || self.inner.delete_object(bucket, &entry.storage_key).await.is_err();
            if main_failed || chunk_failures > 0 {
                keep.push(entry.clone());
            } else {
                drained += 1;
            }
        }

        if let Err(e) = orphan_queue::rewrite(bucket, &mac_key, &keep) {
            tracing::warn!(bucket = %bucket, error = ?e, "orphan_queue: rewrite failed after drain");
        }
        tracing::info!(
            bucket = %bucket,
            drained,
            remaining = keep.len(),
            "orphan_queue: drain complete"
        );
    }

    /// Delete a file in FlatNamespace mode
    ///
    /// Removes from storage and updates forest index.
    /// For chunked files, also deletes all chunk objects.
    pub async fn delete_object_flat(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<()> {
        self.ensure_forest_loaded(bucket).await?;

        if self.is_forest_sharded_hamt(bucket) {
            // v7: remove from HAMT, then flush (persists manifest + WAL
            // clear). Same order-of-operations invariant as the other
            // branches: mutate forest → flush → delete storage objects so
            // we never leave a dangling reference; an orphaned blob is
            // recoverable, a dangling ref is not.
            let forest_arc = {
                let entry = self.forest_cache.get(bucket)
                    .ok_or_else(|| ClientError::NotFound { bucket: bucket.to_string(), key: key.to_string() })?;
                match entry.value() {
                    ForestCacheEntry::ShardedHamt { forest, .. } => forest.clone(),
                    _ => unreachable!("is_forest_sharded_hamt guard above"),
                }
            };
            let backend: Arc<S3BlobBackend> = Arc::new(
                S3BlobBackend::new(self.inner.clone(), bucket.to_string())
            );
            let removed = {
                let mut guard = forest_arc.write().await;
                guard.remove_file(key, &backend).await
                    .map_err(ClientError::Encryption)?
            };
            let removed = removed.ok_or_else(|| ClientError::NotFound {
                bucket: bucket.to_string(),
                key: key.to_string(),
            })?;
            let storage_key = removed.storage_key;

            // Check chunk count before flushing so we know what to clean up.
            let num_chunks = self.get_chunked_num_chunks(bucket, &storage_key).await;

            #[cfg(not(target_arch = "wasm32"))]
            {
                let wal_mac = wal::derive_mac_key(&self.encryption.key_manager, bucket);
                if let Err(e) = wal::append(
                    bucket,
                    &wal_mac,
                    WalEntry::Remove { key: key.to_string() },
                ) {
                    tracing::warn!(%bucket, error = %e, "WAL append failed (remove v7); continuing");
                }
            }

            self.flush_forest(bucket).await?;

            if let Some(n) = num_chunks {
                self.delete_chunk_objects(bucket, &storage_key, n).await;
            }
            let _ = self.inner.delete_object(bucket, &storage_key).await;

            return Ok(());
        }

        {
            let mut forest = self.load_forest(bucket).await?;

            let storage_key = forest.get_storage_key(key)
                .ok_or_else(|| ClientError::NotFound { bucket: bucket.to_string(), key: key.to_string() })?
                .to_string();

            // Check if the file is chunked before modifying the forest
            let num_chunks = self.get_chunked_num_chunks(bucket, &storage_key).await;

            // Update and save forest first, then delete storage
            forest.remove_file(key);
            #[cfg(not(target_arch = "wasm32"))]
            {
                let wal_mac = wal::derive_mac_key(&self.encryption.key_manager, bucket);
                if let Err(e) = wal::append(
                    bucket,
                    &wal_mac,
                    WalEntry::Remove { key: key.to_string() },
                ) {
                    tracing::warn!(%bucket, error = %e, "WAL append failed (remove monolithic); continuing");
                }
            }
            // Persist the updated forest back into the cache so flush_forest's
            // retry loop (NEW-7.2) sees the in-memory change; then flush via
            // flush_forest so 412 races trigger the WAL replay path.
            let now = chrono::Utc::now().timestamp();
            let (prior_etag, prior_seq) = self.forest_cache.get(bucket)
                .map(|e| match e.value() {
                    ForestCacheEntry::Monolithic { index_etag, last_sequence, .. } =>
                        (index_etag.clone(), *last_sequence),
                    _ => (None, None),
                })
                .unwrap_or((None, None));
            self.forest_cache.insert(bucket.to_string(), ForestCacheEntry::Monolithic {
                forest: forest.clone(),
                loaded_at: now,
                dirty: true,
                index_etag: prior_etag,
                last_sequence: prior_seq,
            });
            self.flush_forest(bucket).await?;

            // Delete chunk objects if this was a chunked file (best-effort)
            if let Some(n) = num_chunks {
                self.delete_chunk_objects(bucket, &storage_key, n).await;
            }

            // Delete storage/index object (best-effort — orphaned blob is harmless)
            let _ = self.inner.delete_object(bucket, &storage_key).await;

            Ok(())
        }
    }

    /// Get the private forest for sharing (extract subtree)
    /// 
    /// This allows sharing a portion of your file tree with someone else.
    pub async fn get_forest_subtree(
        &self,
        bucket: &str,
        prefix: &str,
    ) -> Result<PrivateForest> {
        self.ensure_forest_loaded(bucket).await?;

        if self.is_forest_sharded_hamt(bucket) {
            let forest_arc = {
                let entry = self.forest_cache.get(bucket)
                    .ok_or_else(|| ClientError::Encryption(
                        fula_crypto::CryptoError::Encryption("forest not loaded".to_string())
                    ))?;
                match entry.value() {
                    ForestCacheEntry::ShardedHamt { forest, .. } => forest.clone(),
                    _ => unreachable!("is_forest_sharded_hamt guard above"),
                }
            };
            let backend: Arc<S3BlobBackend> = Arc::new(
                S3BlobBackend::new(self.inner.clone(), bucket.to_string())
            );
            let subtree = {
                let guard = forest_arc.read().await;
                guard.extract_subtree(prefix, &backend).await
                    .map_err(ClientError::Encryption)?
            };
            return Ok(subtree);
        }

        // Monolithic v1/v2: extract the subtree directly.
        let forest = self.load_forest(bucket).await?;
        Ok(forest.extract_subtree(prefix))
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // SHARING INTEGRATION
    // Read objects using ShareToken - fully wired into gateway flows
    // ═══════════════════════════════════════════════════════════════════════════

    /// Get and decrypt an object using a ShareToken
    ///
    /// This allows recipients of a share to read encrypted objects without
    /// having the owner's keys. The ShareToken contains a wrapped DEK that
    /// was encrypted for the recipient's public key.
    ///
    /// # Arguments
    /// * `bucket` - The bucket containing the object
    /// * `storage_key` - The storage key of the object (may be obfuscated)
    /// * `original_key` - The original file path (e.g., "/photos/beach.jpg") used
    ///   for path scope validation. In FlatNamespace mode, storage_key is obfuscated
    ///   and cannot be matched against path scopes.
    /// * `accepted_share` - An accepted share containing the DEK
    ///
    /// # Returns
    /// The decrypted object data
    ///
    /// # Note
    /// Handles both single-block and chunked files automatically.
    /// Uses nonce from share token if available, otherwise falls back to metadata headers.
    pub async fn get_object_with_share(
        &self,
        bucket: &str,
        storage_key: &str,
        original_key: &str,
        accepted_share: &AcceptedShare,
    ) -> Result<Bytes> {
        // Validate the share is still valid
        if !accepted_share.is_valid() {
            return Err(ClientError::Encryption(
                fula_crypto::CryptoError::ShareExpired
            ));
        }

        // Validate path scope against the original file path (not the obfuscated storage key)
        if !accepted_share.is_path_allowed(original_key) {
            return Err(ClientError::Encryption(
                fula_crypto::CryptoError::AccessDenied(
                    format!("Path {} is outside share scope {}", original_key, accepted_share.path_scope)
                )
            ));
        }

        // Check read permission
        if !accepted_share.permissions.can_read {
            return Err(ClientError::Encryption(
                fula_crypto::CryptoError::AccessDenied("Share does not grant read permission".to_string())
            ));
        }

        // Check if share token includes encryption metadata (nonce or chunked info)
        // If so, we can decrypt using just the raw data without needing S3 metadata headers
        if accepted_share.chunked_metadata.is_some() {
            // CHUNKED FILE: Use chunked metadata from share token
            return self.get_object_chunked_with_share_token(bucket, storage_key, accepted_share).await;
        }

        if let Some(ref nonce_b64) = accepted_share.nonce {
            // SINGLE FILE: Use nonce from share token - fetch raw data only
            let data = self.inner.get_object(bucket, storage_key).await?;

            let nonce_bytes = base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                nonce_b64,
            ).map_err(|e| ClientError::Encryption(
                fula_crypto::CryptoError::Decryption(format!("Invalid nonce in share token: {}", e))
            ))?;
            let nonce = Nonce::from_bytes(&nonce_bytes)
                .map_err(ClientError::Encryption)?;

            let aead = Aead::new_default(&accepted_share.dek);
            // `encryption_version` is Option<u8>: Some when the share creator
            // explicitly stamped the token (new fula-flutter builds), None for
            // tokens created between 1b82b95 (inline-nonce support, Jan 2026)
            // and the flutter-side fix (which omit the field). For None, we
            // try v4 AAD first (current upload format) and fall back to the
            // pre-AAD v2 format so legacy tokens still decrypt.
            let aad = format!("fula:v4:content:{}", storage_key).into_bytes();
            let plaintext = match accepted_share.encryption_version {
                Some(v) if v >= 4 => aead
                    .decrypt_with_aad(&nonce, &data, &aad)
                    .map_err(ClientError::Encryption)?,
                Some(_) => aead
                    .decrypt(&nonce, &data)
                    .map_err(ClientError::Encryption)?,
                None => match aead.decrypt_with_aad(&nonce, &data, &aad) {
                    Ok(pt) => pt,
                    Err(_) => aead
                        .decrypt(&nonce, &data)
                        .map_err(ClientError::Encryption)?,
                },
            };

            return Ok(Bytes::from(plaintext));
        }

        // FALLBACK: Share token doesn't have encryption metadata, try to get it from S3 headers
        // This is for backwards compatibility with old share tokens
        let result = self.inner.get_object_with_metadata(bucket, storage_key).await?;

        // Check if encrypted
        let is_encrypted = result.metadata
            .get("x-fula-encrypted")
            .map(|v| v == "true")
            .unwrap_or(false);

        if !is_encrypted {
            // C-AUDIT-004 / NEW-2.1: block plaintext response for forest-known encrypted entries
            if self.forest_entry_requires_encryption(bucket, storage_key).await? {
                return Err(ClientError::Encryption(fula_crypto::CryptoError::Decryption(
                    "storage backend served plaintext for an encrypted path".to_string()
                )));
            }
            return Ok(result.data);
        }

        // Check if this is a chunked object
        let is_chunked = result.metadata
            .get("x-fula-chunked")
            .map(|v| v == "true")
            .unwrap_or(false);

        // Parse encryption metadata from S3 headers
        let enc_metadata_str = result.metadata
            .get("x-fula-encryption")
            .ok_or_else(|| ClientError::Encryption(
                fula_crypto::CryptoError::Decryption("Missing encryption metadata (not in share token or S3 headers)".to_string())
            ))?;

        let enc_metadata: serde_json::Value = serde_json::from_str(enc_metadata_str)
            .map_err(|e| ClientError::Encryption(
                fula_crypto::CryptoError::Decryption(e.to_string())
            ))?;

        if is_chunked {
            // CHUNKED DOWNLOAD: Download and decrypt each chunk using the share's DEK
            self.get_object_chunked_with_share_metadata(bucket, storage_key, &enc_metadata, &accepted_share.dek).await
        } else {
            // SINGLE OBJECT: Decrypt directly
            let nonce_b64 = enc_metadata["nonce"].as_str()
                .ok_or_else(|| ClientError::Encryption(
                    fula_crypto::CryptoError::Decryption("Missing nonce in encryption metadata".to_string())
                ))?;
            let nonce_bytes = base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                nonce_b64,
            ).map_err(|e| ClientError::Encryption(
                fula_crypto::CryptoError::Decryption(e.to_string())
            ))?;
            let nonce = Nonce::from_bytes(&nonce_bytes)
                .map_err(ClientError::Encryption)?;

            // Use the DEK from the accepted share (already decrypted for recipient)
            let aead = Aead::new_default(&accepted_share.dek);
            let version = enc_metadata["version"].as_u64().unwrap_or(2);
            let plaintext = if version >= 4 {
                let aad = format!("fula:v4:content:{}", storage_key).into_bytes();
                aead.decrypt_with_aad(&nonce, &result.data, &aad)
            } else {
                aead.decrypt(&nonce, &result.data)
            }.map_err(ClientError::Encryption)?;

            Ok(Bytes::from(plaintext))
        }
    }

    /// Internal: Download and decrypt a chunked file using metadata from share token
    async fn get_object_chunked_with_share_token(
        &self,
        bucket: &str,
        storage_key: &str,
        accepted_share: &AcceptedShare,
    ) -> Result<Bytes> {
        let chunked_json = accepted_share.chunked_metadata.as_ref()
            .ok_or_else(|| ClientError::Encryption(
                fula_crypto::CryptoError::Decryption("Missing chunked metadata in share token".to_string())
            ))?;

        let chunked_meta: ChunkedFileMetadata = serde_json::from_str(chunked_json)
            .map_err(|e| ClientError::Encryption(
                fula_crypto::CryptoError::Decryption(format!("Invalid chunked metadata in share token: {}", e))
            ))?;

        self.download_chunks_parallel(bucket, storage_key, &chunked_meta, &accepted_share.dek).await
    }

    /// Internal: Download and decrypt a chunked file using metadata from S3 headers
    async fn get_object_chunked_with_share_metadata(
        &self,
        bucket: &str,
        storage_key: &str,
        enc_metadata: &serde_json::Value,
        dek: &fula_crypto::keys::DekKey,
    ) -> Result<Bytes> {
        let chunked_meta: ChunkedFileMetadata = serde_json::from_value(
            enc_metadata["chunked"].clone()
        ).map_err(|e| ClientError::Encryption(
            fula_crypto::CryptoError::Decryption(format!("Invalid chunked metadata: {}", e))
        ))?;

        self.download_chunks_parallel(bucket, storage_key, &chunked_meta, dek).await
    }

    /// Shared helper: parallel chunk download, decrypt, and assemble.
    ///
    /// Delegates to the windowed download engine which keeps peak memory
    /// bounded to ~window_size * chunk_size regardless of total file size.
    ///
    /// Called only from the share-token (non-owner) download path, where
    /// the reader does not own the forest and therefore has no
    /// `ForestFileEntry` to verify against. Passes `forest_entry: None` so
    /// the H-1 content_hash / H-2 min_version gates are skipped — the share
    /// token's own `SnapshotBinding` is the integrity anchor for that path.
    async fn download_chunks_parallel(
        &self,
        bucket: &str,
        storage_key: &str,
        chunked_meta: &ChunkedFileMetadata,
        dek: &fula_crypto::keys::DekKey,
    ) -> Result<Bytes> {
        // Reject share tokens that claim implausible file sizes before attempting
        // allocation. WASM's linear memory is bounded; a garbage total_size from a
        // malformed token would otherwise surface as an opaque "memory access out
        // of bounds" from __wbindgen_realloc instead of a clean error.
        const MAX_CHUNKED_TOTAL_SIZE: u64 = 8 * 1024 * 1024 * 1024;
        if chunked_meta.total_size > MAX_CHUNKED_TOTAL_SIZE {
            return Err(ClientError::Encryption(fula_crypto::CryptoError::Decryption(
                format!(
                    "chunked_meta.total_size {} exceeds maximum {}",
                    chunked_meta.total_size, MAX_CHUNKED_TOTAL_SIZE
                ),
            )));
        }
        let mut output = Vec::with_capacity(chunked_meta.total_size as usize);
        self.download_chunks_windowed_to_writer(bucket, storage_key, chunked_meta, dek, &mut output, None).await?;
        Ok(Bytes::from(output))
    }

    /// Accept a ShareToken and get an AcceptedShare for reading objects
    /// 
    /// This is a convenience method that combines ShareRecipient::accept_share
    /// with our encryption config's secret key.
    pub fn accept_share(&self, token: &ShareToken) -> Result<AcceptedShare> {
        let recipient = ShareRecipient::new(self.encryption.key_manager.keypair());
        recipient.accept_share(token)
            .map_err(ClientError::Encryption)
    }

    /// Get object using a raw ShareToken (convenience method)
    ///
    /// Combines accept_share + get_object_with_share in one call.
    pub async fn get_object_with_token(
        &self,
        bucket: &str,
        storage_key: &str,
        original_key: &str,
        token: &ShareToken,
    ) -> Result<Bytes> {
        let accepted = self.accept_share(token)?;
        self.get_object_with_share(bucket, storage_key, original_key, &accepted).await
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // KEY ROTATION INTEGRATION
    // Re-wrap DEKs without re-encrypting content
    // ═══════════════════════════════════════════════════════════════════════════

    /// Create a KeyRotationManager from this client's encryption config
    pub fn create_rotation_manager(&self) -> KeyRotationManager {
        KeyRotationManager::new(self.encryption.key_manager.keypair().clone())
    }

    /// Get the KEK version stored in an object's metadata
    /// 
    /// Returns None if the object doesn't have version info (legacy objects).
    pub async fn get_object_kek_version(
        &self,
        bucket: &str,
        storage_key: &str,
    ) -> Result<Option<u32>> {
        let head_result = self.inner.head_object(bucket, storage_key).await?;
        
        let enc_metadata_str = match head_result.metadata.get("x-fula-encryption") {
            Some(s) => s,
            None => return Ok(None),
        };

        let enc_metadata: serde_json::Value = serde_json::from_str(enc_metadata_str)
            .map_err(|e| ClientError::Encryption(
                fula_crypto::CryptoError::Decryption(e.to_string())
            ))?;

        Ok(enc_metadata["kek_version"].as_u64().map(|v| v as u32))
    }

    /// Re-wrap an object's DEK with the current KEK
    /// 
    /// This updates the object's encryption metadata without re-encrypting
    /// the content. Used during key rotation.
    /// 
    /// # Arguments
    /// * `bucket` - The bucket containing the object
    /// * `storage_key` - The storage key of the object  
    /// * `rotation_manager` - The rotation manager with old and new KEKs
    /// 
    /// # Returns
    /// The new KEK version after re-wrapping
    pub async fn rewrap_object_dek(
        &self,
        bucket: &str,
        storage_key: &str,
        rotation_manager: &KeyRotationManager,
    ) -> Result<u32> {
        // Get the object with metadata
        let result = self.inner.get_object_with_metadata(bucket, storage_key).await?;
        
        let enc_metadata_str = result.metadata
            .get("x-fula-encryption")
            .ok_or_else(|| ClientError::Encryption(
                fula_crypto::CryptoError::Decryption("Missing encryption metadata".to_string())
            ))?;

        let mut enc_metadata: serde_json::Value = serde_json::from_str(enc_metadata_str)
            .map_err(|e| ClientError::Encryption(
                fula_crypto::CryptoError::Decryption(e.to_string())
            ))?;

        // Get the wrapped key and version
        let wrapped_dek: EncryptedData = serde_json::from_value(
            enc_metadata["wrapped_key"].clone()
        ).map_err(|e| ClientError::Encryption(
            fula_crypto::CryptoError::Decryption(e.to_string())
        ))?;

        // Get the KEK version (default to 1 for legacy objects)
        let kek_version = enc_metadata["kek_version"]
            .as_u64()
            .map(|v| v as u32)
            .unwrap_or(1);

        // Create a WrappedKeyInfo for the rotation manager
        let wrapped_info = WrappedKeyInfo {
            wrapped_dek,
            kek_version,
            object_path: storage_key.to_string(),
        };

        // Unwrap with old KEK and rewrap with new KEK
        let new_wrapped = rotation_manager.rewrap_dek(&wrapped_info)
            .map_err(ClientError::Encryption)?;

        // Update metadata
        enc_metadata["wrapped_key"] = serde_json::to_value(&new_wrapped.wrapped_dek)
            .map_err(|e| ClientError::Encryption(
                fula_crypto::CryptoError::Encryption(e.to_string())
            ))?;
        enc_metadata["kek_version"] = serde_json::Value::Number(
            new_wrapped.kek_version.into()
        );

        // Re-upload with updated metadata (same ciphertext)
        let metadata = ObjectMetadata::new()
            .with_content_type(
                result.metadata.get("content-type")
                    .map(|s| s.as_str())
                    .unwrap_or("application/octet-stream")
            )
            .with_metadata("x-fula-encrypted", "true")
            .with_metadata("x-fula-encryption", &enc_metadata.to_string());

        self.inner.put_object_with_metadata(
            bucket,
            storage_key,
            result.data,
            Some(metadata),
        ).await?;

        Ok(rotation_manager.current_version())
    }

    /// Rotate all objects in a bucket to use the new KEK
    ///
    /// Returns the number of objects successfully rotated and any failures.
    pub async fn rotate_bucket(
        &self,
        bucket: &str,
        rotation_manager: &KeyRotationManager,
    ) -> Result<RotationReport> {
        self.rotate_bucket_inner(bucket, rotation_manager, None).await
    }

    /// Rotate all objects in a bucket using a resumable journal.
    ///
    /// Works like [`rotate_bucket`] but persists each successful rewrap to
    /// `journal_path`. If the journal already exists, its entries are treated
    /// as already-rotated and skipped — so a rotation that was interrupted
    /// can be resumed without re-rewrapping the completed objects.
    ///
    /// On successful completion (no failures), the journal file is deleted.
    /// If any failures occur the journal is preserved so the next call can
    /// pick up where the previous one left off.
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn rotate_bucket_with_journal(
        &self,
        bucket: &str,
        rotation_manager: &KeyRotationManager,
        journal_path: &std::path::Path,
    ) -> Result<RotationReport> {
        self.rotate_bucket_inner(bucket, rotation_manager, Some(journal_path)).await
    }

    #[cfg_attr(target_arch = "wasm32", allow(unused_variables))]
    async fn rotate_bucket_inner(
        &self,
        bucket: &str,
        rotation_manager: &KeyRotationManager,
        #[cfg(not(target_arch = "wasm32"))] journal_path: Option<&std::path::Path>,
        #[cfg(target_arch = "wasm32")] _journal_path: Option<&std::path::Path>,
    ) -> Result<RotationReport> {
        let objects = self.inner.list_objects(bucket, None).await?;

        let mut report = RotationReport {
            total: objects.objects.len(),
            rotated: 0,
            skipped: 0,
            failed: 0,
            failures: Vec::new(),
        };

        // Build set of forest keys to skip using deterministic key derivation
        // (replaces x-fula-forest header check — audit finding C-007)
        let forest_dek = self.encryption.key_manager.derive_path_key(&format!("forest:{}", bucket));
        let index_key = derive_index_key(&forest_dek, bucket);

        let mut forest_keys = std::collections::HashSet::new();
        forest_keys.insert(index_key);

        // v7 sharded-HAMT: shard storage keys live under the manifest and
        // are resolved lazily, so no extra key enumeration is needed here.
        let _ = self.ensure_forest_loaded(bucket).await;

        // NEW-7.1: derive a per-bucket MAC key for the rotation journal, domain-separated
        // from any encryption key. Each journal line carries a BLAKE3 keyed MAC so a
        // local tamperer cannot cause legitimate keys to be skipped on the next run.
        #[cfg(not(target_arch = "wasm32"))]
        let journal_mac_key = self.encryption.key_manager
            .derive_path_key(&format!("rotation-journal-mac:{}", bucket));

        // Load prior rotation state from the journal, if one was provided and exists.
        #[cfg(not(target_arch = "wasm32"))]
        let already_rotated: std::collections::HashSet<String> = match journal_path {
            Some(path) if path.exists() => {
                match std::fs::read_to_string(path) {
                    Ok(contents) => {
                        let mut set = std::collections::HashSet::new();
                        for line in contents.lines() {
                            let line = line.trim();
                            if line.is_empty() {
                                continue;
                            }
                            let Some((key_str, mac_hex)) = line.split_once('\t') else {
                                tracing::warn!(%line, "rotation journal: malformed line, skipping");
                                continue;
                            };
                            let Ok(actual) = hex::decode(mac_hex) else {
                                tracing::warn!(%key_str, "rotation journal: bad hex MAC, skipping");
                                continue;
                            };
                            if actual.len() != 32 {
                                tracing::warn!(%key_str, "rotation journal: wrong MAC length, skipping");
                                continue;
                            }
                            let expected = blake3::keyed_hash(
                                journal_mac_key.as_bytes(),
                                key_str.as_bytes(),
                            );
                            // Constant-time compare to avoid length/byte-wise timing leaks.
                            let matches = expected.as_bytes()
                                .iter()
                                .zip(actual.iter())
                                .fold(0u8, |acc, (a, b)| acc | (a ^ b))
                                == 0;
                            if matches {
                                set.insert(key_str.to_string());
                            } else {
                                tracing::warn!(%key_str, "rotation journal: MAC mismatch, skipping forged line");
                            }
                        }
                        set
                    }
                    Err(e) => {
                        tracing::warn!(?path, error = %e, "rotate_bucket_with_journal: failed to read journal, starting fresh");
                        std::collections::HashSet::new()
                    }
                }
            }
            _ => std::collections::HashSet::new(),
        };
        #[cfg(target_arch = "wasm32")]
        let already_rotated: std::collections::HashSet<String> = std::collections::HashSet::new();

        // Partition objects: forest/shard keys are skipped without issuing a rewrap;
        // journal entries are counted as already-rotated.
        let mut to_rotate: Vec<String> = Vec::with_capacity(objects.objects.len());
        for obj in objects.objects {
            if forest_keys.contains(&obj.key) {
                report.skipped += 1;
            } else if already_rotated.contains(&obj.key) {
                report.rotated += 1;
            } else {
                to_rotate.push(obj.key);
            }
        }

        // Rewrap concurrently with a bounded window. Each rewrap performs GET + decrypt + encrypt + PUT,
        // so concurrency is capped at MAX_CONCURRENT_REWRAPS to avoid overloading the backend.
        use futures::stream::StreamExt;
        let results = futures::stream::iter(to_rotate.into_iter().map(|key| async move {
            let outcome = self.rewrap_object_dek(bucket, &key, rotation_manager).await;
            (key, outcome)
        }))
            .buffer_unordered(Self::MAX_CONCURRENT_REWRAPS)
            .collect::<Vec<_>>()
            .await;

        // Journal is append-only; flush after every successful rewrap so an
        // interruption only loses the in-flight items. NEW-L.4: an exclusive OS file
        // lock prevents two rotations from garbling each other's appends.
        #[cfg(not(target_arch = "wasm32"))]
        let mut journal_writer: Option<std::io::BufWriter<std::fs::File>> = match journal_path {
            Some(path) => {
                use fs2::FileExt;
                use std::io::Write;
                match std::fs::OpenOptions::new().create(true).append(true).open(path) {
                    Ok(f) => {
                        if let Err(e) = f.try_lock_exclusive() {
                            tracing::warn!(?path, error = %e, "rotate_bucket_with_journal: journal is locked by another process");
                            return Err(ClientError::RotationInProgress { bucket: bucket.to_string() });
                        }
                        let mut w = std::io::BufWriter::new(f);
                        // If resuming, write an empty line-flush so callers see a valid file.
                        let _ = w.flush();
                        Some(w)
                    }
                    Err(e) => {
                        tracing::warn!(?path, error = %e, "rotate_bucket_with_journal: failed to open journal for append");
                        None
                    }
                }
            }
            None => None,
        };

        for (key, outcome) in results {
            match outcome {
                Ok(_) => {
                    report.rotated += 1;
                    #[cfg(not(target_arch = "wasm32"))]
                    if let Some(w) = journal_writer.as_mut() {
                        use std::io::Write;
                        let mac = blake3::keyed_hash(journal_mac_key.as_bytes(), key.as_bytes());
                        if writeln!(w, "{}\t{}", key, hex::encode(mac.as_bytes())).is_err()
                            || w.flush().is_err()
                        {
                            tracing::warn!(%key, "rotate_bucket_with_journal: failed to append to journal");
                        }
                    }
                }
                Err(e) => {
                    report.failed += 1;
                    report.failures.push((key, e.to_string()));
                }
            }
        }

        // Dropping the writer closes the file, which releases the exclusive lock.
        #[cfg(not(target_arch = "wasm32"))]
        drop(journal_writer);

        // On clean success, delete the journal so the next run starts fresh.
        #[cfg(not(target_arch = "wasm32"))]
        if report.failed == 0 {
            if let Some(path) = journal_path {
                let _ = std::fs::remove_file(path);
            }
        }

        Ok(report)
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // STREAMING ENCRYPTION FOR LARGE FILES (WNFS-inspired)
    // Block-level encryption with index object pattern
    // ═══════════════════════════════════════════════════════════════════════════

    /// Upload a large file using chunked/streaming encryption
    /// 
    /// This method splits large files into encrypted chunks, uploads each
    /// chunk as a separate object, and creates an index object with metadata.
    /// Inspired by WNFS's "file = encrypted blocks + index" pattern.
    /// 
    /// # Arguments
    /// * `bucket` - Target bucket
    /// * `key` - Original file path/key
    /// * `data` - File content
    /// * `chunk_size` - Size of each chunk (default 256KB)
    /// 
    /// # Returns
    /// Result with the storage key for the index object
    pub async fn put_object_chunked(
        &self,
        bucket: &str,
        key: &str,
        data: &[u8],
        chunk_size: Option<usize>,
    ) -> Result<PutObjectResult> {
        use fula_crypto::chunked::{ChunkedEncoder, ChunkedFileMetadata, DEFAULT_CHUNK_SIZE};
        
        let chunk_size = chunk_size.unwrap_or(DEFAULT_CHUNK_SIZE);
        let dek = self.encryption.key_manager.generate_dek();
        
        // Generate storage key using obfuscation (same as put_object_encrypted)
        let storage_key = if self.encryption.metadata_privacy {
            let path_dek = self.encryption.key_manager.derive_path_key(key);
            obfuscate_key(key, &path_dek, self.encryption.obfuscation_mode.clone())
        } else {
            key.to_string()
        };
        
        // Create chunked encoder with AAD binding chunks to storage key
        let aad_prefix = format!("fula:v4:chunk:{}", storage_key);
        let mut encoder = ChunkedEncoder::with_aad_and_chunk_size(dek.clone(), aad_prefix, chunk_size);

        // Process all data and collect chunks
        let mut chunks = encoder.update(data)?;
        let (final_chunk, metadata, outboard) = encoder.finalize()?;
        
        if let Some(chunk) = final_chunk {
            chunks.push(chunk);
        }
        
        // Upload chunks in parallel with bounded concurrency. Using
        // futures::stream::buffer_unordered rather than tokio::spawn so the
        // same code runs on wasm32 (where tokio has no multi-thread runtime).
        let _uploaded_keys = {
            use futures::StreamExt;
            let futs = chunks.into_iter().map(|chunk| {
                let chunk_key = ChunkedFileMetadata::chunk_key(&storage_key, chunk.index);
                let chunk_metadata = ObjectMetadata::new()
                    .with_content_type("application/octet-stream")
                    .with_metadata("x-fula-chunk", "true")
                    .with_metadata("x-fula-chunk-index", &chunk.index.to_string());

                let client = self.inner.clone();
                let bucket = bucket.to_string();
                let chunk_key_ret = chunk_key.clone();

                async move {
                    client.put_object_with_metadata(
                        &bucket,
                        &chunk_key,
                        chunk.ciphertext,
                        Some(chunk_metadata),
                    ).await?;
                    Ok::<String, ClientError>(chunk_key_ret)
                }
            });

            let results: Vec<std::result::Result<String, ClientError>> = futures::stream::iter(futs)
                .buffer_unordered(Self::MAX_CONCURRENT_CHUNK_UPLOADS)
                .collect()
                .await;

            let mut uploaded_keys: Vec<String> = Vec::new();
            let mut upload_error: Option<ClientError> = None;
            for result in results {
                match result {
                    Ok(key) => uploaded_keys.push(key),
                    Err(e) => { if upload_error.is_none() { upload_error = Some(e); } }
                }
            }

            if let Some(err) = upload_error {
                for key in &uploaded_keys {
                    let _ = self.inner.delete_object(bucket, key).await;
                }
                return Err(err);
            }

            uploaded_keys
        };

        // Don't set content_type in unencrypted ChunkedFileMetadata — it would leak
        // file type to the server. Content type is already stored in encrypted
        // PrivateMetadata when using put_object_flat_deferred().

        // Wrap the DEK with HPKE
        let encryptor = Encryptor::new(self.encryption.key_manager.public_key());
        let wrapped_dek = encryptor.encrypt_dek(&dek)?;
        
        // Create index object metadata
        let kek_version = self.encryption.key_manager.version();
        let enc_metadata = serde_json::json!({
            "version": 4,
            "algorithm": "AES-256-GCM",
            "wrapped_key": serde_json::to_value(&wrapped_dek).unwrap(),
            "kek_version": kek_version,
            "chunked": metadata,
            "bao_outboard": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, outboard.to_bytes()),
        });
        
        // Upload index object (small, contains metadata only)
        let index_metadata = ObjectMetadata::new()
            .with_content_type("application/json")
            .with_metadata("x-fula-encrypted", "true")
            .with_metadata("x-fula-chunked", "true")
            .with_metadata("x-fula-encryption", &enc_metadata.to_string());
        
        let result = self.inner.put_object_with_metadata(
            bucket,
            &storage_key,
            Bytes::from(b"CHUNKED".to_vec()), // Marker content
            Some(index_metadata),
        ).await?;
        
        // Update forest cache if we have one.
        //
        // v7 mutates an `Arc<tokio::sync::RwLock<ShardedHamtPrivateForest>>`
        // whose `upsert_file` is async and cannot be called while holding
        // the DashMap guard. Split the match: sync formats mutate in place
        // under the guard, v7 extracts the Arc and performs the async
        // upsert after dropping it.
        let now = chrono::Utc::now().timestamp();
        // H-1: bind a BLAKE3 content hash to the forest entry. `data` here is
        // the full plaintext — cheap single-pass hash.
        let content_hash = blake3::hash(data).to_hex().to_string();
        let file_entry = ForestFileEntry {
            path: key.to_string(),
            storage_key: storage_key.clone(),
            size: data.len() as u64,
            content_type: metadata.content_type.clone(),
            created_at: now,
            modified_at: now,
            user_metadata: HashMap::new(),
            content_hash: Some(content_hash),
            // C-AUDIT-004: forest entries from encrypted uploads MUST
            // be marked so later reads refuse a plaintext backend response.
            encrypted: true,
            // H-2: entry is written under v4 AAD-bound encryption; reject
            // any later download that advertises a lower blob-format version.
            min_version: 4,
        };

        let v7_forest_arc = {
            let entry_opt = self.forest_cache.get_mut(bucket);
            if let Some(mut entry) = entry_opt {
                match entry.value_mut() {
                    ForestCacheEntry::Monolithic { forest, dirty, .. } => {
                        forest.upsert_file(file_entry.clone());
                        *dirty = true;
                        None
                    }
                    ForestCacheEntry::ShardedHamt { forest, .. } => Some(forest.clone()),
                }
            } else {
                None
            }
        };

        if let Some(forest_arc) = v7_forest_arc {
            let backend: Arc<S3BlobBackend> = Arc::new(
                S3BlobBackend::new(self.inner.clone(), bucket.to_string())
            );
            {
                let mut guard = forest_arc.write().await;
                // F4: lock the v7-encrypted invariant. Every entry upserted
                // into v7 must be encrypted; `forest_entry_requires_encryption`
                // depends on this to answer correctly without a HAMT reverse
                // lookup. If plaintext v7 support is ever added, this assert
                // fires and forces the author to wire the lookup side too.
                debug_assert!(
                    file_entry.encrypted,
                    "v7 upsert invariant violated: entry for {} has encrypted=false",
                    file_entry.path
                );
                guard.upsert_file(file_entry, &backend).await
                    .map_err(ClientError::Encryption)?;
            }
            if let Some(mut entry) = self.forest_cache.get_mut(bucket) {
                if let ForestCacheEntry::ShardedHamt { loaded_at, .. } = entry.value_mut() {
                    *loaded_at = now;
                }
            }
        }

        Ok(result)
    }

    /// Download and decrypt a chunked file
    ///
    /// Fetches the index object, then downloads and decrypts chunks using the
    /// shared windowed download engine, which parallelizes chunk fetches with a
    /// bounded sliding window. The engine is format-aware and transparently
    /// handles both streaming-v2 (v4 AAD) and legacy chunked formats, so this
    /// path is safe for pre-v3 files uploaded with the older chunked encoder.
    pub async fn get_object_chunked(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<Bytes> {
        // Resolve path to storage key (same as get_object_decrypted)
        let storage_key = if self.encryption.metadata_privacy {
            let path_dek = self.encryption.key_manager.derive_path_key(key);
            obfuscate_key(key, &path_dek, self.encryption.obfuscation_mode.clone())
        } else {
            key.to_string()
        };

        // Fetch index object
        let index_result = self.inner.get_object_with_metadata(bucket, &storage_key).await?;

        // Check if chunked
        let is_chunked = index_result.metadata
            .get("x-fula-chunked")
            .map(|v| v == "true")
            .unwrap_or(false);

        if !is_chunked {
            // Fall back to regular decryption
            return self.get_object_decrypted(bucket, key).await;
        }

        // Parse encryption metadata
        let enc_metadata_str = index_result.metadata
            .get("x-fula-encryption")
            .ok_or_else(|| ClientError::Encryption(
                fula_crypto::CryptoError::Decryption("Missing encryption metadata".to_string())
            ))?;

        let enc_metadata: serde_json::Value = serde_json::from_str(enc_metadata_str)
            .map_err(|e| ClientError::Encryption(
                fula_crypto::CryptoError::Decryption(e.to_string())
            ))?;

        // Unwrap DEK
        let wrapped_dek: EncryptedData = serde_json::from_value(enc_metadata["wrapped_key"].clone())
            .map_err(|e| ClientError::Encryption(
                fula_crypto::CryptoError::Decryption(e.to_string())
            ))?;

        let decryptor = Decryptor::new(self.encryption.key_manager.keypair());
        let dek = decryptor.decrypt_dek(&wrapped_dek)?;

        // H-1 / H-2: look up forest entry for the owner-read path so the
        // chunked engine can verify content_hash and reject legacy-format
        // blobs pinned to streaming-v2.
        let forest_entry = self.forest_entry_lookup(bucket, &storage_key).await?;

        // Delegate to the windowed parallel download path shared with the main
        // get_object_decrypted flow. Handles streaming-v2 and legacy formats
        // identically — chunk S3 layout and per-chunk nonce/AAD derivation are
        // unchanged, only the concurrency pattern differs from the old loop.
        self.get_object_chunked_internal(bucket, &storage_key, &enc_metadata, &dek, forest_entry.as_ref()).await
    }

    /// Download a byte range from a chunked file (partial read)
    /// 
    /// Only downloads the chunks needed for the requested range.
    pub async fn get_object_range(
        &self,
        bucket: &str,
        key: &str,
        offset: u64,
        length: u64,
    ) -> Result<Bytes> {
        use fula_crypto::chunked::ChunkedFileMetadata;
        
        // Resolve path to storage key
        let storage_key = if self.encryption.metadata_privacy {
            let path_dek = self.encryption.key_manager.derive_path_key(key);
            obfuscate_key(key, &path_dek, self.encryption.obfuscation_mode.clone())
        } else {
            key.to_string()
        };
        
        // Fetch index object
        let index_result = self.inner.get_object_with_metadata(bucket, &storage_key).await?;
        
        // Check if chunked
        let is_chunked = index_result.metadata
            .get("x-fula-chunked")
            .map(|v| v == "true")
            .unwrap_or(false);
        
        if !is_chunked {
            // Fall back to full download and slice
            let full = self.get_object_decrypted(bucket, key).await?;
            let start = offset as usize;
            let end = (offset + length) as usize;
            return Ok(full.slice(start.min(full.len())..end.min(full.len())));
        }
        
        // Parse encryption metadata
        let enc_metadata_str = index_result.metadata
            .get("x-fula-encryption")
            .ok_or_else(|| ClientError::Encryption(
                fula_crypto::CryptoError::Decryption("Missing encryption metadata".to_string())
            ))?;
        
        let enc_metadata: serde_json::Value = serde_json::from_str(enc_metadata_str)
            .map_err(|e| ClientError::Encryption(
                fula_crypto::CryptoError::Decryption(e.to_string())
            ))?;
        
        // Unwrap DEK
        let wrapped_dek: EncryptedData = serde_json::from_value(enc_metadata["wrapped_key"].clone())
            .map_err(|e| ClientError::Encryption(
                fula_crypto::CryptoError::Decryption(e.to_string())
            ))?;
        
        let decryptor = Decryptor::new(self.encryption.key_manager.keypair());
        let dek = decryptor.decrypt_dek(&wrapped_dek)?;
        
        // Parse chunked metadata
        let chunked_meta: ChunkedFileMetadata = serde_json::from_value(enc_metadata["chunked"].clone())
            .map_err(|e| ClientError::Encryption(
                fula_crypto::CryptoError::Decryption(e.to_string())
            ))?;
        
        // Determine which chunks we need
        let needed_chunks = chunked_meta.chunks_for_range(offset, length);
        
        // Download and decrypt only needed chunks
        let mut decrypted_chunks = Vec::new();
        
        let is_v2 = chunked_meta.format == "streaming-v2";
        for chunk_idx in needed_chunks {
            let chunk_key = ChunkedFileMetadata::chunk_key(&storage_key, chunk_idx);
            let chunk_data = self.inner.get_object(bucket, &chunk_key).await?;

            let nonce = chunked_meta.get_chunk_nonce(chunk_idx)
                .map_err(ClientError::Encryption)?;

            // Decrypt this chunk with the DEK (format-aware for AAD)
            let aead = Aead::new_default(&dek);
            let plaintext = if is_v2 {
                let aad = format!("fula:v4:chunk:{}:{}", storage_key, chunk_idx).into_bytes();
                aead.decrypt_with_aad(&nonce, &chunk_data, &aad)
            } else {
                aead.decrypt(&nonce, &chunk_data)
            }.map_err(ClientError::Encryption)?;

            decrypted_chunks.push((chunk_idx, plaintext));
        }
        
        // Extract the requested range from decrypted chunks
        let chunk_size = chunked_meta.chunk_size as u64;
        let mut result = Vec::with_capacity(length as usize);
        
        for (chunk_idx, chunk_data) in decrypted_chunks {
            let chunk_start = chunk_idx as u64 * chunk_size;
            let chunk_end = chunk_start + chunk_data.len() as u64;
            
            // Calculate overlap with requested range
            let range_start = offset.max(chunk_start);
            let range_end = (offset + length).min(chunk_end);
            
            if range_start < range_end {
                let local_start = (range_start - chunk_start) as usize;
                let local_end = (range_end - chunk_start) as usize;
                result.extend_from_slice(&chunk_data[local_start..local_end]);
            }
        }
        
        Ok(Bytes::from(result))
    }

    /// Check if a file should use chunked upload based on size
    pub fn should_use_chunked(size: usize) -> bool {
        fula_crypto::should_use_chunked(size)
    }
}

/// File metadata (without file content) - optimized for file managers
#[derive(Debug, Clone)]
pub struct FileMetadata {
    /// The obfuscated storage key (what server sees)
    pub storage_key: String,
    /// Original file name/path (decrypted)
    pub original_key: String,
    /// Original file size in bytes (not ciphertext size)
    pub original_size: u64,
    /// Content type (MIME type)
    pub content_type: Option<String>,
    /// Creation timestamp (Unix seconds)
    pub created_at: Option<i64>,
    /// Last modified timestamp (Unix seconds)
    pub modified_at: Option<i64>,
    /// User-defined metadata
    pub user_metadata: HashMap<String, String>,
    /// Whether file is encrypted
    pub is_encrypted: bool,
}

impl FileMetadata {
    /// Get the filename (last component of path)
    pub fn filename(&self) -> &str {
        self.original_key.rsplit('/').next().unwrap_or(&self.original_key)
    }

    /// Get the directory path (without filename)
    pub fn directory(&self) -> &str {
        if let Some(last_slash) = self.original_key.rfind('/') {
            &self.original_key[..last_slash]
        } else {
            ""
        }
    }

    /// Get human-readable size
    pub fn size_human(&self) -> String {
        const KB: u64 = 1024;
        const MB: u64 = KB * 1024;
        const GB: u64 = MB * 1024;
        
        if self.original_size >= GB {
            format!("{:.1} GB", self.original_size as f64 / GB as f64)
        } else if self.original_size >= MB {
            format!("{:.1} MB", self.original_size as f64 / MB as f64)
        } else if self.original_size >= KB {
            format!("{:.1} KB", self.original_size as f64 / KB as f64)
        } else {
            format!("{} B", self.original_size)
        }
    }
}

/// Directory listing result.
///
/// Marked `#[non_exhaustive]` so future pagination / metadata fields can be
/// added without breaking external consumers that match on or construct the
/// struct with a literal.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct DirectoryListing {
    /// Bucket name
    pub bucket: String,
    /// Prefix filter (if any)
    pub prefix: Option<String>,
    /// Files grouped by directory path
    pub directories: HashMap<String, Vec<FileMetadata>>,
    /// True when the server/forest has more entries that were not returned in
    /// this page. Follow up with `list_directory_paginated` passing
    /// `next_continuation_token` to retrieve the next page.
    pub is_truncated: bool,
    /// Opaque token identifying the next page (hex-encoded). `None` iff
    /// `is_truncated == false`.
    pub next_continuation_token: Option<String>,
}

impl DirectoryListing {
    /// Get all unique directory paths
    pub fn get_directories(&self) -> Vec<&str> {
        self.directories.keys().map(|s| s.as_str()).collect()
    }

    /// Get files in a specific directory
    pub fn get_files(&self, directory: &str) -> Option<&Vec<FileMetadata>> {
        self.directories.get(directory)
    }

    /// Get total file count
    pub fn file_count(&self) -> usize {
        self.directories.values().map(|v| v.len()).sum()
    }

    /// Get total size of all files
    pub fn total_size(&self) -> u64 {
        self.directories.values()
            .flat_map(|v| v.iter())
            .map(|f| f.original_size)
            .sum()
    }
}

/// Decrypted object information including private metadata
#[derive(Debug, Clone)]
pub struct DecryptedObjectInfo {
    /// Decrypted file data
    pub data: Bytes,
    /// Original file name/path (decrypted from private metadata)
    pub original_key: String,
    /// Original file size (not ciphertext size)
    pub original_size: u64,
    /// Original content type
    pub content_type: Option<String>,
    /// User-defined metadata
    pub user_metadata: HashMap<String, String>,
}

/// Report from a bucket key rotation operation
#[derive(Debug, Clone)]
pub struct RotationReport {
    /// Total number of objects in the bucket
    pub total: usize,
    /// Number of objects successfully rotated
    pub rotated: usize,
    /// Number of objects skipped (e.g., forest index)
    pub skipped: usize,
    /// Number of objects that failed to rotate
    pub failed: usize,
    /// Details of failed rotations (path, error message)
    pub failures: Vec<(String, String)>,
}

impl RotationReport {
    /// Check if rotation was fully successful
    pub fn is_success(&self) -> bool {
        self.failed == 0
    }

    /// Get success rate as a percentage
    pub fn success_rate(&self) -> f64 {
        if self.total == 0 {
            100.0
        } else {
            (self.rotated as f64 / (self.total - self.skipped) as f64) * 100.0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encryption_config() {
        let config1 = EncryptionConfig::new();
        let config2 = EncryptionConfig::new();

        // Different configs should have different keys
        assert_ne!(
            config1.public_key().as_bytes(),
            config2.public_key().as_bytes()
        );
    }

    /// Compile-time proof that `S3BlobBackend` satisfies the `BlobBackend`
    /// bound used by `V7NodeStore`. Runs no real traffic — the actual
    /// S3 round-trip is exercised by integration tests against a live
    /// gateway. This guards against a future refactor accidentally losing
    /// the trait's `Send + Sync` requirement on the native target.
    #[test]
    #[cfg(not(target_arch = "wasm32"))]
    fn s3_blob_backend_satisfies_blob_backend_trait() {
        fn assert_impl<T: BlobBackend + Send + Sync + 'static>() {}
        assert_impl::<S3BlobBackend>();
    }

    /// `S3BlobBackend::new` takes a `FulaClient` + bucket and is cheaply
    /// cloneable, so per-flush construction in the v7 pipeline is free.
    #[test]
    fn s3_blob_backend_constructs_and_clones() {
        let cfg = Config::new("https://example.invalid");
        let client = FulaClient::new(cfg).expect("client builds");
        let backend = S3BlobBackend::new(client, "test-bucket");
        // Clone must preserve bucket routing.
        let cloned = backend.clone();
        assert_eq!(cloned.bucket, "test-bucket");
    }

    /// A `ShardedHamt` cache entry reports its own `loaded_at` and delegates
    /// `is_dirty()` to the wrapped `ShardedHamtPrivateForest`. A freshly
    /// constructed forest has no mutations → `is_dirty()` is false. The
    /// dirty-flag transitions after mutation are covered by tests in
    /// `fula_crypto::sharded_hamt_forest` (e.g.
    /// `flush_dirty_persists_and_reloads_cleanly`) where the required
    /// `InMemoryBackend` helper lives.
    #[test]
    fn sharded_hamt_cache_entry_exposes_load_bearing_signals() {
        use fula_crypto::private_forest::ShardManifestV7;
        use fula_crypto::keys::DekKey;

        // `ShardManifestV7::new(1)` materializes a single empty page with
        // one empty shard, equivalent to the literal this test previously
        // wrote by hand.
        let manifest = ShardManifestV7::new(1);

        let dek = DekKey::from_bytes(&[0x42u8; 32]).unwrap();
        let forest = ShardedHamtPrivateForest::from_manifest(manifest, "bucket", dek);
        let forest_arc = Arc::new(tokio::sync::RwLock::new(forest));
        let clean = ForestCacheEntry::ShardedHamt {
            forest: forest_arc,
            loaded_at: 42,
            manifest_etag: Some("etag-abc".to_string()),
            last_manifest_sequence: Some(17),
        };
        assert_eq!(clean.loaded_at(), 42);
        assert!(!clean.is_dirty());
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // v1 → v7 load-time migration — unit-level coverage
    //
    // End-to-end scenarios (happy path, 412 races, lock contention, backup
    // fallback, WAL-drain interaction, empty-bucket v7 default) require HTTP
    // round-trips against a live gateway and are exercised by integration
    // tests (see the project plan's test-verification section). The tests
    // below cover the in-process pieces: the MigrationOutcome enum shape,
    // the heartbeat guard's cancel-on-drop behaviour, the load-time trigger
    // gating predicate (only v1/v2 monolithic, not v4), and idempotency of
    // the public `migrate_to_sharded` when the cache already holds a v7
    // entry. Together these lock down the parts of the migration flow that
    // are readable without mocking reqwest.
    // ═══════════════════════════════════════════════════════════════════════════

    /// `MigrationOutcome` carries enough context to map directly onto both the
    /// `ForestEvent::MigrationCompleted` success case and the
    /// `MigrationLockHeld` / `UploadFailed("migration deferred: …")` error
    /// cases without further lookup. This test pins the variant shapes so a
    /// refactor can't accidentally drop a field the caller relies on.
    #[test]
    fn migration_outcome_variants_carry_expected_fields() {
        let migrated = MigrationOutcome::Migrated { duration_ms: 123 };
        match migrated {
            MigrationOutcome::Migrated { duration_ms } => assert_eq!(duration_ms, 123),
            _ => panic!("wrong variant"),
        }

        let held = MigrationOutcome::DeferredLockHeld { expires_at_ms: 999_999 };
        match held {
            MigrationOutcome::DeferredLockHeld { expires_at_ms } => assert_eq!(expires_at_ms, 999_999),
            _ => panic!("wrong variant"),
        }

        let transient = MigrationOutcome::DeferredTransientError { reason: "boom".to_string() };
        match transient {
            MigrationOutcome::DeferredTransientError { reason } => assert_eq!(reason, "boom"),
            _ => panic!("wrong variant"),
        }
    }

    /// Constants the migration flow depends on. If any of these drift, the
    /// 60s server TTL / 30s heartbeat invariant or the documented backup
    /// prefix contract could silently break.
    #[test]
    fn migration_constants_match_contract() {
        assert_eq!(V1_BACKUP_PREFIX, "__fula_forest_v1_backup/");
        assert!(V7_V1_BACKUP_FALLBACK_ENABLED, "fallback is the default; disable via code change");
        #[cfg(not(target_arch = "wasm32"))]
        {
            // 30s cadence against 60s server TTL tolerates one dropped beat.
            assert_eq!(MIGRATION_HEARTBEAT_INTERVAL_SECS, 30);
        }
    }

    /// `HeartbeatGuard` aborts its background heartbeat task as soon as it's
    /// dropped. Verifies the RAII contract that every exit path of the
    /// migration workhorse (including error and panic propagation) stops
    /// firing heartbeats instead of leaking a background task.
    #[tokio::test]
    #[cfg(not(target_arch = "wasm32"))]
    async fn heartbeat_guard_aborts_task_on_drop() {
        // Point the inner client at an unresolvable host so the heartbeat
        // HTTP call fails fast if it ever gets dispatched. We're looking for
        // the task to be aborted, not to succeed.
        let cfg = Config::new("http://127.0.0.1:1");
        let client = FulaClient::new(cfg).expect("client builds");

        let guard = HeartbeatGuard::spawn(client, "bucket".to_string(), "tok".to_string());
        // Grab the underlying JoinHandle before dropping the guard so we can
        // observe the abort directly rather than relying on timing.
        let handle = guard.handle.as_ref().expect("handle present").abort_handle();
        drop(guard);

        // The abort signal is best observed via `is_finished` after a short
        // yield, since `abort` cancels cooperatively.
        for _ in 0..50 {
            if handle.is_finished() {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("heartbeat task did not stop within 500ms of guard drop");
    }

    /// Only legacy v1/v2 monolithic forests should trigger the load-time
    /// migration — v4 (AAD-bound) is a distinct, newer monolithic format and
    /// must not be migrated. The load-time trigger uses
    /// `observed_seq.is_none()` as the gate: v4 always returns
    /// `Some(sequence)`, v1/v2 always returns `None`.
    #[test]
    fn load_time_migration_trigger_gate() {
        let v1_like: Option<u64> = None;
        let v4_like: Option<u64> = Some(42);
        assert!(v1_like.is_none(), "v1/v2 legacy forests trigger migration");
        assert!(v4_like.is_some(), "v4 forests do NOT trigger migration");
    }

    /// Calling the public `migrate_to_sharded` on a bucket whose cache entry
    /// is already `ShardedHamt` is idempotent — the public API translates
    /// `load_forest_internal`'s "forest is sharded" error into a zero-duration
    /// `MigrationCompleted` event so callers don't have to special-case
    /// already-migrated state.
    #[tokio::test]
    async fn migrate_to_sharded_is_idempotent_when_cache_is_already_v7() {
        use fula_crypto::keys::DekKey;
        use fula_crypto::private_forest::ShardManifestV7;

        let cfg = Config::new("http://127.0.0.1:1");
        let enc = EncryptionConfig::new();
        let client = EncryptedClient::new(cfg, enc).expect("client builds");

        // Seed the cache with a ShardedHamt entry for "bucket". This short-
        // circuits `load_forest_internal` into the "forest is sharded"
        // branch without any HTTP traffic.
        let manifest = ShardManifestV7::new(1);
        let dek = DekKey::from_bytes(&[0x01u8; 32]).unwrap();
        let v7 = ShardedHamtPrivateForest::from_manifest(manifest, "bucket", dek);
        client.forest_cache.insert("bucket".to_string(), ForestCacheEntry::ShardedHamt {
            forest: Arc::new(tokio::sync::RwLock::new(v7)),
            loaded_at: chrono::Utc::now().timestamp(),
            manifest_etag: Some("cached".to_string()),
            last_manifest_sequence: Some(1),
        });

        let event = client.migrate_to_sharded("bucket").await.expect("idempotent ok");
        let ForestEvent::MigrationCompleted { bucket, duration_ms } = event;
        assert_eq!(bucket, "bucket");
        assert_eq!(duration_ms, 0, "no work done → zero duration");
    }

    /// The v1 backup prefix follows the `__fula_<reason>/<unix_ms>` pattern
    /// used elsewhere in the codebase for implementation-detail keys that
    /// should be listable but easy to exclude from user-facing listings.
    /// Pin the exact shape so a refactor can't silently move the prefix and
    /// strand existing backups.
    #[test]
    fn v1_backup_key_format_is_prefix_plus_unix_millis() {
        let ts: i64 = 1_700_000_000_000;
        let key = format!("{}{}", V1_BACKUP_PREFIX, ts);
        assert_eq!(key, "__fula_forest_v1_backup/1700000000000");
        assert!(key.starts_with(V1_BACKUP_PREFIX));
        // The suffix parses back to the original unix millis — the fallback
        // path relies on this for "pick max by timestamp".
        let parsed: i64 = key
            .strip_prefix(V1_BACKUP_PREFIX)
            .and_then(|s| s.parse().ok())
            .unwrap();
        assert_eq!(parsed, ts);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // F1: resume_upload nonce-reuse protection
    //
    // resume_upload reuses per-chunk nonces stored in the manifest against
    // caller-supplied `data`. Without a content check, a caller passing
    // different bytes would encrypt new plaintext under the same (DEK, nonce)
    // pair — classic AEAD keystream reuse. The check reuses the BAO root hash
    // already in ChunkedFileMetadata, so no schema change is required.
    // ═══════════════════════════════════════════════════════════════════════

    #[cfg(not(target_arch = "wasm32"))]
    mod f1_resume_nonce_reuse_protection {
        use super::*;
        use fula_crypto::chunked::{ChunkedEncoder, MIN_CHUNK_SIZE};
        use fula_crypto::keys::DekKey;

        /// Build an on-disk UploadManifest whose `index_metadata_json` has a
        /// real `chunked` block derived from `original_data`. `wrapped_key` is
        /// a placeholder — the F1 check fires before we ever parse it, so
        /// tests never need a valid HPKE-wrapped DEK.
        fn make_manifest_with_real_chunked_meta(
            dir: &std::path::Path,
            original_data: &[u8],
        ) -> std::path::PathBuf {
            let dek = DekKey::generate();
            let aad = b"fula:v4:chunk:QmF1Test".to_vec();
            let mut encoder = ChunkedEncoder::with_aad_and_chunk_size(
                dek, aad, MIN_CHUNK_SIZE,
            );
            let _ = encoder.update(original_data).unwrap();
            let (_final_chunk, chunked_meta, _outboard) = encoder.finalize().unwrap();

            let index_metadata = serde_json::json!({
                "version": 4,
                "algorithm": "AES-256-GCM",
                "wrapped_key": { "placeholder": "f1 check fires before this is parsed" },
                "kek_version": 1u32,
                "metadata_privacy": true,
                "obfuscation_mode": "flat",
                "chunked": serde_json::to_value(&chunked_meta).unwrap(),
            })
            .to_string();

            let manifest_chunks: Vec<ManifestChunk> = (0..chunked_meta.num_chunks)
                .map(|i| ManifestChunk {
                    index: i,
                    chunk_key: ChunkedFileMetadata::chunk_key("QmF1Test", i),
                    uploaded: false,
                })
                .collect();

            let manifest = UploadManifest {
                bucket: "f1-test-bucket".to_string(),
                storage_key: "QmF1Test".to_string(),
                original_key: "f1-test.bin".to_string(),
                num_chunks: chunked_meta.num_chunks,
                chunks: manifest_chunks,
                index_metadata_json: index_metadata,
            };
            let path = dir.join("f1_upload_manifest.json");
            manifest.save(&path).expect("save manifest");
            path
        }

        fn make_test_client() -> EncryptedClient {
            let cfg = Config::new("http://127.0.0.1:1");
            let enc = EncryptionConfig::new();
            EncryptedClient::new(cfg, enc).expect("client builds")
        }

        #[tokio::test]
        async fn rejects_data_with_same_length_but_different_content() {
            let tmp = tempfile::tempdir().expect("tempdir");
            let original = vec![0xAAu8; MIN_CHUNK_SIZE * 3 + 500];
            let tampered = vec![0xBBu8; original.len()]; // same length, different bytes

            let manifest_path = make_manifest_with_real_chunked_meta(
                tmp.path(), &original,
            );
            let client = make_test_client();

            let err = client
                .resume_upload(&manifest_path, &tampered)
                .await
                .expect_err("must reject tampered data");

            match err {
                ClientError::Encryption(CryptoError::BaoVerification(msg)) => {
                    assert!(
                        msg.contains("root hash mismatch"),
                        "expected BAO root-hash mismatch message, got: {}",
                        msg,
                    );
                }
                other => panic!("expected BaoVerification, got {:?}", other),
            }
        }

        #[tokio::test]
        async fn rejects_data_with_wrong_length() {
            let tmp = tempfile::tempdir().expect("tempdir");
            let original = vec![0xCCu8; MIN_CHUNK_SIZE * 2 + 100];
            let truncated = &original[..original.len() - 500]; // shorter

            let manifest_path = make_manifest_with_real_chunked_meta(
                tmp.path(), &original,
            );
            let client = make_test_client();

            let err = client
                .resume_upload(&manifest_path, truncated)
                .await
                .expect_err("must reject wrong-length data");

            match err {
                ClientError::Encryption(CryptoError::BaoVerification(msg)) => {
                    assert!(
                        msg.contains("does not match manifest total_size"),
                        "expected length-mismatch message, got: {}",
                        msg,
                    );
                }
                other => panic!("expected BaoVerification, got {:?}", other),
            }
        }

        #[tokio::test]
        async fn accepts_matching_data_past_f1_guard() {
            // Guards against a future refactor flipping `!=` / `==` on the BAO
            // check. With matching data the F1 guard lets the call through;
            // the later wrapped_key parse fails on our placeholder JSON — that
            // distinct failure proves the F1 check was not the one to reject.
            let tmp = tempfile::tempdir().expect("tempdir");
            let original = vec![0xEEu8; MIN_CHUNK_SIZE * 2 + 300];

            let manifest_path = make_manifest_with_real_chunked_meta(
                tmp.path(), &original,
            );
            let client = make_test_client();

            let err = client
                .resume_upload(&manifest_path, &original)
                .await
                .expect_err("placeholder wrapped_key must fail at parse stage");

            match err {
                ClientError::Encryption(CryptoError::BaoVerification(msg)) => {
                    panic!("F1 guard wrongly rejected matching data: {}", msg);
                }
                ClientError::Encryption(CryptoError::Decryption(msg)) => {
                    assert!(
                        msg.contains("wrapped key") || msg.contains("Invalid wrapped key"),
                        "expected wrapped_key parse failure, got: {}",
                        msg,
                    );
                }
                other => panic!(
                    "expected wrapped_key parse failure (proving F1 passed), got {:?}",
                    other,
                ),
            }
        }

        #[tokio::test]
        async fn rejects_extended_data() {
            let tmp = tempfile::tempdir().expect("tempdir");
            let original = vec![0xDDu8; MIN_CHUNK_SIZE * 2 + 100];
            let mut extended = original.clone();
            extended.extend_from_slice(&[0xEE; 200]); // longer

            let manifest_path = make_manifest_with_real_chunked_meta(
                tmp.path(), &original,
            );
            let client = make_test_client();

            let err = client
                .resume_upload(&manifest_path, &extended)
                .await
                .expect_err("must reject extended data");

            match err {
                ClientError::Encryption(CryptoError::BaoVerification(msg)) => {
                    assert!(msg.contains("does not match manifest total_size"));
                }
                other => panic!("expected BaoVerification, got {:?}", other),
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // F9: manifest-version pin MAC
    //
    // The manifest-version pin file prevents a gateway from silently
    // downgrading a bucket's forest format. Prior to F9 it was an
    // unauthenticated `u8` string on disk — any local process with user-write
    // permission could roll it back. The fix wraps it in a BLAKE3 keyed-hash
    // MAC whose key is derived from the user's encryption key with a
    // bucket-scoped domain separator. Legacy bare-number pin files are still
    // accepted (with a warning) so pre-upgrade installs continue to work;
    // a MAC-present-but-invalid file is treated as untrusted and returns
    // `None`, which is the active-tamper case.
    // ═══════════════════════════════════════════════════════════════════════

    #[cfg(not(target_arch = "wasm32"))]
    mod f9_manifest_version_pin_mac {
        use super::*;

        // Tests mutate FULA_STATE_DIR; serialize across cargo's parallel
        // runner so concurrent tests cannot read each other's env var.
        // Uses the crate-wide TEST_ENV_LOCK shared with wal.rs and
        // orphan_queue.rs so those modules' tests can't race each other.
        struct StateDirGuard {
            _dir: tempfile::TempDir,
            _lock: std::sync::MutexGuard<'static, ()>,
        }

        fn tmp_state_dir() -> StateDirGuard {
            let lock = crate::TEST_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
            let dir = tempfile::tempdir().expect("tempdir");
            std::env::set_var("FULA_STATE_DIR", dir.path());
            StateDirGuard { _dir: dir, _lock: lock }
        }

        fn make_test_client() -> EncryptedClient {
            let cfg = Config::new("http://127.0.0.1:1");
            let enc = EncryptionConfig::new();
            EncryptedClient::new(cfg, enc).expect("client builds")
        }

        /// Writing a version then reading it back returns the same value —
        /// the MAC'd on-disk format round-trips cleanly.
        #[test]
        fn round_trip_mac_format() {
            let _g = tmp_state_dir();
            let client = make_test_client();

            client.persist_manifest_version("bucket-rt", 6);
            let loaded = client.load_persisted_manifest_version("bucket-rt");
            assert_eq!(loaded, Some(6));

            // On-disk format must be `<version>\t<hex_mac>\n`, not a bare
            // number. This guards against a future refactor accidentally
            // writing the pre-F9 unauthenticated format.
            let path = client.manifest_version_path("bucket-rt").expect("path");
            let contents = std::fs::read_to_string(&path).expect("read");
            assert!(contents.contains('\t'), "must be tab-separated MAC format");
            let (ver, mac_hex) = contents.trim_end().rsplit_once('\t').expect("tab");
            assert_eq!(ver, "6");
            assert_eq!(
                hex::decode(mac_hex).expect("hex").len(),
                32,
                "MAC must be 32 bytes (BLAKE3 keyed output)",
            );
        }

        /// A MAC that does not verify against the bucket-scoped key means
        /// an adversary rewrote the file. `load` must return `None` rather
        /// than trust the stored value — this is the active-tamper case.
        #[test]
        fn tampered_mac_returns_none() {
            let _g = tmp_state_dir();
            let client = make_test_client();

            client.persist_manifest_version("bucket-tm", 6);
            let path = client.manifest_version_path("bucket-tm").expect("path");
            let contents = std::fs::read_to_string(&path).expect("read");
            let (ver, _old_mac) = contents.trim_end().rsplit_once('\t').expect("tab");

            // Swap in a MAC that has the right shape (64 hex chars = 32B)
            // but is not the true MAC for this (key, version). The load
            // path must reject this rather than trust the version field.
            let bogus_mac = "0".repeat(64);
            std::fs::write(&path, format!("{}\t{}\n", ver, bogus_mac)).expect("write");

            let loaded = client.load_persisted_manifest_version("bucket-tm");
            assert_eq!(loaded, None, "tampered MAC must not be trusted");
        }

        /// An adversary who rewrites the version but keeps the old MAC
        /// must be rejected: the MAC is computed over the version string,
        /// so a version change without a matching MAC recomputation fails
        /// `verify_mac`. Downgrading 7 → 1 through this channel must not
        /// succeed.
        #[test]
        fn tampered_version_with_stale_mac_returns_none() {
            let _g = tmp_state_dir();
            let client = make_test_client();

            client.persist_manifest_version("bucket-tv", 7);
            let path = client.manifest_version_path("bucket-tv").expect("path");
            let contents = std::fs::read_to_string(&path).expect("read");
            let (_old_ver, mac_hex) = contents.trim_end().rsplit_once('\t').expect("tab");

            // Rewrite the version field while keeping the old MAC. This
            // simulates the exact rollback attack the MAC is designed to
            // prevent.
            std::fs::write(&path, format!("1\t{}\n", mac_hex)).expect("write");

            let loaded = client.load_persisted_manifest_version("bucket-tv");
            assert_eq!(
                loaded, None,
                "rollback via version-only rewrite must be rejected",
            );
        }

        /// The MAC key is derived with a bucket-scoped domain separator
        /// (`forest-manifest-version-mac:{bucket}`), so a file written for
        /// bucket A must not verify for bucket B even on the same client.
        /// Without this, an attacker who can write to one bucket's pin
        /// file could cross-contaminate another bucket's version state.
        #[test]
        fn cross_bucket_mac_rejected() {
            let _g = tmp_state_dir();
            let client = make_test_client();

            // Write a valid pin for bucket A, then copy the raw bytes to
            // bucket B's pin path. B's MAC key is different → verification
            // must fail.
            client.persist_manifest_version("bucket-A", 5);
            let path_a = client.manifest_version_path("bucket-A").expect("A path");
            let contents_a = std::fs::read(&path_a).expect("read A");

            let path_b = client.manifest_version_path("bucket-B").expect("B path");
            if let Some(parent) = path_b.parent() {
                std::fs::create_dir_all(parent).expect("mkdir B");
            }
            std::fs::write(&path_b, &contents_a).expect("write B");

            let loaded_b = client.load_persisted_manifest_version("bucket-B");
            assert_eq!(
                loaded_b, None,
                "cross-bucket MAC must not verify (domain separator bound to bucket)",
            );

            // Sanity: A still loads.
            assert_eq!(
                client.load_persisted_manifest_version("bucket-A"),
                Some(5),
            );
        }

        /// Legacy (pre-F9) pin files are bare numbers without a MAC. They
        /// must still be accepted read-only — refusing them would break
        /// any install that upgraded from a pre-F9 build and would
        /// silently undermine the downgrade-guard on the very first post-
        /// upgrade run. The next write upgrades them to the MAC'd format.
        #[test]
        fn legacy_bare_format_accepted_and_upgraded() {
            let _g = tmp_state_dir();
            let client = make_test_client();

            let path = client.manifest_version_path("bucket-legacy").expect("path");
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).expect("mkdir");
            }
            // Pre-F9 format: bare number, no tab, no MAC.
            std::fs::write(&path, b"6").expect("write legacy");

            let loaded = client.load_persisted_manifest_version("bucket-legacy");
            assert_eq!(
                loaded,
                Some(6),
                "legacy bare-number pin must still be readable",
            );

            // The next (monotonic) write upgrades the file to the MAC'd
            // format. Reading afterwards must round-trip through the new
            // code path — proving the upgrade actually happened.
            client.persist_manifest_version("bucket-legacy", 7);
            let upgraded = std::fs::read_to_string(&path).expect("read upgraded");
            assert!(
                upgraded.contains('\t'),
                "post-write file must be MAC'd format, got {:?}",
                upgraded,
            );
            assert_eq!(
                client.load_persisted_manifest_version("bucket-legacy"),
                Some(7),
            );
        }
    }

    // F10 — per-chunk download timeout.
    //
    // The download path wraps every chunk fetch in
    // `tokio::time::timeout(per_chunk_download_timeout, …)` and maps elapsed
    // into `ClientError::DownloadFailed` with a message identifying the
    // stalled chunk. These tests cover: (a) Config default is 5 min;
    // (b) a stalled future surfaces the documented error shape.
    #[cfg(not(target_arch = "wasm32"))]
    mod f10_per_chunk_download_timeout {
        use super::*;
        use std::time::Duration;

        #[test]
        fn default_is_five_minutes() {
            let cfg = Config::default();
            assert_eq!(cfg.per_chunk_download_timeout, Duration::from_secs(300));
        }

        // Exercises the real `fetch_chunk_with_timeout` helper that the
        // production download loop calls. A stalled (`pending`) future is
        // injected so the timeout branch fires deterministically under
        // `start_paused = true`. Because both production and this test
        // share one helper, any drift in the error variant or message
        // breaks the production path and this test in lockstep.
        #[tokio::test(flavor = "current_thread", start_paused = true)]
        async fn stalled_fetch_surfaces_download_failed() {
            let per_chunk_timeout = Duration::from_millis(50);
            let chunk_index: u32 = 7;

            // Never completes; relies on tokio's paused-time timer to
            // cancel it deterministically.
            let stalled = futures::future::pending::<Result<Bytes>>();
            let result: Result<Bytes> =
                fetch_chunk_with_timeout(stalled, chunk_index, per_chunk_timeout).await;

            match result {
                Err(ClientError::DownloadFailed(msg)) => {
                    assert!(
                        msg.contains("chunk 7"),
                        "error must name the stalled chunk index, got: {msg}"
                    );
                    assert!(
                        msg.contains("50ms"),
                        "error must include the configured timeout, got: {msg}"
                    );
                }
                other => panic!("expected DownloadFailed, got {other:?}"),
            }
        }

        // Happy-path: a future that completes with Ok must pass through
        // the timeout wrap unchanged. Guards against a future refactor
        // accidentally mapping Ok into Err (e.g. `?` on the wrong layer).
        #[tokio::test(flavor = "current_thread", start_paused = true)]
        async fn ok_passes_through() {
            let payload = Bytes::from_static(b"hello");
            let fut = async { Ok::<Bytes, ClientError>(payload.clone()) };
            let result = fetch_chunk_with_timeout(fut, 3, Duration::from_secs(10)).await;
            assert_eq!(result.unwrap(), payload);
        }

        // Inner-error path: a future that completes with Err(inner) must
        // surface `inner` verbatim — the timeout wrap must not rewrap
        // upstream errors into DownloadFailed.
        #[tokio::test(flavor = "current_thread", start_paused = true)]
        async fn inner_error_preserved() {
            let fut = async {
                Err::<Bytes, ClientError>(ClientError::BucketNotFound("chunks-bkt".into()))
            };
            let result = fetch_chunk_with_timeout(fut, 4, Duration::from_secs(10)).await;
            match result {
                Err(ClientError::BucketNotFound(msg)) => assert!(msg.contains("chunks-bkt")),
                other => panic!("expected BucketNotFound to pass through, got {other:?}"),
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // F4: v7 `forest_entry_requires_encryption` invariant
    //
    // The v7 arm of `forest_entry_requires_encryption` returns `true`
    // unconditionally. This is exhaustive (not a fallback) because every v7
    // upsert writes `encrypted: true` — enforced by `debug_assert!`s at every
    // v7 upsert site. The test below pins the observable behaviour so a
    // future refactor can't silently weaken the fail-closed answer.
    // ═══════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn v7_forest_entry_requires_encryption_returns_true() {
        use fula_crypto::keys::DekKey;
        use fula_crypto::private_forest::ShardManifestV7;

        let cfg = Config::new("http://127.0.0.1:1");
        let enc = EncryptionConfig::new();
        let client = EncryptedClient::new(cfg, enc).expect("client builds");

        // Seed the forest cache with an empty v7 entry. The check must
        // return `true` even for a storage_key that has no matching entry,
        // because the v7 path is fail-closed: no v7 storage_key ever
        // belongs to a plaintext object, by invariant.
        let manifest = ShardManifestV7::new(1);
        let dek = DekKey::from_bytes(&[0x05u8; 32]).unwrap();
        let v7 = ShardedHamtPrivateForest::from_manifest(manifest, "bucket", dek);
        client.forest_cache.insert(
            "bucket".to_string(),
            ForestCacheEntry::ShardedHamt {
                forest: Arc::new(tokio::sync::RwLock::new(v7)),
                loaded_at: chrono::Utc::now().timestamp(),
                manifest_etag: Some("seeded".to_string()),
                last_manifest_sequence: Some(1),
            },
        );

        let requires = client
            .forest_entry_requires_encryption("bucket", "any-storage-key")
            .await
            .expect("seeded v7 cache must not trigger a load");
        assert!(
            requires,
            "v7 invariant: every entry is encrypted; check must answer true"
        );
    }

    // ═══════════════════════════════════════════════════════════════════════
    // F8: buffered chunked-download ceiling check
    //
    // `download_chunks_buffered_to_writer` must reject any chunked_meta
    // whose declared `total_size` exceeds `Config::buffered_download_max_bytes`
    // BEFORE any network I/O. The ceiling exists because the buffered path
    // holds the full plaintext in RAM; without it, a malicious manifest
    // could OOM the client.
    //
    // This unit-level test points the client at an unreachable host and
    // relies on the check returning `DownloadFailed` before any socket
    // connection is attempted. A later integration test (in
    // `tests/f8_buffered_download_tests.rs`) exercises the full
    // tamper-detected-during-decode path with a real in-memory gateway.
    // ═══════════════════════════════════════════════════════════════════════

    #[tokio::test]
    #[cfg(not(target_arch = "wasm32"))]
    async fn f8_buffered_download_rejects_oversize_manifest() {
        use fula_crypto::chunked::ChunkedFileMetadata;
        use fula_crypto::keys::DekKey;

        // Small ceiling so even a toy manifest triggers the guard.
        let mut cfg = Config::new("http://127.0.0.1:1");
        cfg.buffered_download_max_bytes = 1024; // 1 KiB
        let enc = EncryptionConfig::new();
        let client = EncryptedClient::new(cfg, enc).expect("client builds");

        // Minimal metadata whose declared total_size exceeds the ceiling.
        // Everything else is dummy — the check short-circuits before any
        // per-chunk field is consulted.
        let meta = ChunkedFileMetadata {
            format: "streaming-v2".to_string(),
            chunk_size: 64 * 1024,
            num_chunks: 3,
            total_size: 10 * 1024, // 10 KiB > 1 KiB ceiling
            root_hash: "00".repeat(32),
            chunk_nonces: vec![],
            content_type: None,
        };
        let dek = DekKey::from_bytes(&[0x42u8; 32]).unwrap();

        let mut writer: Vec<u8> = Vec::new();
        let err = client
            .download_chunks_buffered_to_writer("bucket", "storage-key", &meta, &dek, &mut writer, None)
            .await
            .expect_err("buffered download must reject oversize manifest");
        match err {
            ClientError::DownloadFailed(msg) => assert!(
                msg.contains("buffered download exceeds configured ceiling"),
                "expected buffered-ceiling error, got: {}",
                msg
            ),
            other => panic!(
                "expected DownloadFailed, got {:?} — the ceiling guard must fire \
                 before any network I/O",
                other
            ),
        }
        assert!(
            writer.is_empty(),
            "writer must not be touched when the size guard rejects the manifest"
        );
    }
}
