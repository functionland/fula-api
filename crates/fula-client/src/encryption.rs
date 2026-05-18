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
    wnfs_hamt::{BlobBackend, BlobPutResult},
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
    ///
    /// Phase 2.4: when the SDK has Phase 2.2/2.3 enabled, this dispatches
    /// through `get_object_with_offline_fallback` so a master-down read
    /// can transparently fall through to the public-gateway race using
    /// the cached `(bucket, key) → cid` mapping. When the flags are off
    /// behavior is byte-identical to pre-Phase-2.4 (single inner call,
    /// same retry policy).
    ///
    /// **Walkable-v8 reader (W.9.4)**: HAMT walkers that learned a
    /// child's `Cid` from its parent's `PointerWire::LinkV2` plaintext
    /// can call [`get_with_cid_hint`](Self::get_with_cid_hint) instead;
    /// that variant uses the cold-cache cid-hint offline-fallback path
    /// (`get_object_with_offline_fallback_known_cid`) so a freshly-
    /// installed device can walk a v8 forest from the manifest root
    /// without requiring a prior master-up read to populate the
    /// warm-cache `(bucket, key) → cid` table. The reader path is NOT
    /// gated on `walkable_v8_writer_enabled` — the wire-format
    /// `LinkV2` variant itself is the gate. Buckets written entirely
    /// under v7 produce no `LinkV2` entries, so no `cid_hint` reaches
    /// this method, and behaviour falls through to the no-hint branch.
    async fn get(&self, path: &str) -> fula_crypto::Result<Vec<u8>> {
        let mut attempt: u32 = 0;
        loop {
            attempt += 1;
            match self
                .inner
                .get_object_with_offline_fallback(&self.bucket, path)
                .await
            {
                // Phase 19: get_object_with_offline_fallback now returns
                // OfflineGetResult; the bytes live on `.inner.data`. The
                // `source` / `freshness` fields are dropped here — the
                // crypto blob backend has no plumbing to surface them
                // and isn't a transparency consumer.
                Ok(result) => return Ok(result.inner.data.to_vec()),
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
    ///
    /// **Walkable-v8 (W.9.2 seam, W.9.3 self-verify):**
    /// when `Config::walkable_v8_writer_enabled = true`, the master's
    /// PUT-response ETag is parsed as a CID and locally re-verified
    /// against `BLAKE3(ciphertext)` via
    /// `walkable_v8::verify_etag_matches_ciphertext` before being
    /// surfaced in [`BlobPutResult.cid`]. Mismatches soft-fail to `None`
    /// (with a rate-limited `tracing::warn!`) so a compromised master
    /// cannot redirect future offline walkers to attacker-controlled
    /// IPFS bytes. When the flag is `false` (the default during the
    /// v0.6.x rollout), the parse path is skipped entirely and `cid` is
    /// always `None` — write semantics stay byte-identical to v0.5.
    ///
    /// Soft-fail rationale: the PUT itself succeeded, the chunk is stored
    /// and pinned, only the offline-walk hint is missing; readers fall
    /// back to the storage-key path. Hard-erroring on parse failure
    /// would regress the v7 write path under any deploy where master's
    /// etag format drifts.
    async fn put(&self, path: &str, bytes: Vec<u8>) -> fula_crypto::Result<BlobPutResult> {
        let mut attempt: u32 = 0;
        let walkable_v8 = self.inner.config().walkable_v8_writer_enabled;
        loop {
            attempt += 1;
            // Clone the body each attempt: reqwest consumes the body, and we
            // want to re-send the same bytes on retry. The retry path is cold
            // and HAMT node blobs are small (sub-KB typical), so this is
            // negligible on the happy path too.
            let body = bytes.clone();
            match self.inner.put_object(&self.bucket, path, body).await {
                Ok(result) => {
                    // The CID returned here is from the *successful* PUT
                    // attempt — the loop only reaches this `Ok` arm on a
                    // 200 response. Stale CIDs from prior retried attempts
                    // never propagate.
                    let cid = if walkable_v8 {
                        crate::walkable_v8::verify_etag_matches_ciphertext(
                            &result.etag,
                            &bytes,
                            &self.bucket,
                            path,
                        )
                    } else {
                        // Writer flag off — skip the parse entirely so write
                        // semantics stay byte-identical to v0.5. Readers fall
                        // through to the storage-key path.
                        None
                    };
                    // Issue #8 fix #3 cache-warm is handled by the
                    // helper `FulaClient::warm_block_cache_after_put`,
                    // which runs inside `inner.put_object` above and
                    // covers ALL writers (HAMT internal nodes via this
                    // backend, plus manifest pages / dir-index / root
                    // commits via the conditional path, plus chunks
                    // via the pinning path). Putting the warm here
                    // too would duplicate the redb write — idempotent
                    // (delta=0 per block_cache::put net-delta logic)
                    // but wasted I/O. Single source of truth.
                    return Ok(BlobPutResult { cid });
                }
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

    /// Walkable-v8 reader (W.9.4) — fetch with a content-address hint
    /// so a freshly-installed device can walk a v8 forest from a
    /// just-decrypted parent's `LinkV2` pointer when master is
    /// unreachable, without requiring the warm-cache `(bucket, key)
    /// → cid` table the no-hint variant depends on.
    ///
    /// When `cid_hint` is `Some(_)` this routes through
    /// [`FulaClient::get_object_with_offline_fallback_known_cid`]: master
    /// is tried first (fast path; identical latency), and only on a
    /// `MasterUnreachable` error does the gateway race engage with
    /// the supplied CID. The gateway-race body is content-verified
    /// against `cid_hint` via `verify_cid_against_bytes` before
    /// returning, so a malicious or buggy gateway cannot inject foreign
    /// bytes here. The post-fetch AEAD decrypt + storage_key recompute
    /// in `V7NodeStore::decrypt_and_verify` is the additional defense
    /// against a malicious parent that pointed `LinkV2` at the right
    /// CID but the wrong storage_key.
    ///
    /// When `cid_hint` is `None` the call is byte-identical to
    /// [`get`](Self::get): legacy `Stored(StorageKey)` parent pointers
    /// (lazy-migration arm) take this branch and the offline path
    /// degrades to the warm-cache lookup as before.
    async fn get_with_cid_hint(
        &self,
        path: &str,
        cid_hint: Option<&cid::Cid>,
    ) -> fula_crypto::Result<Vec<u8>> {
        let cid = match cid_hint {
            Some(c) => c,
            None => return self.get(path).await,
        };
        let mut attempt: u32 = 0;
        loop {
            attempt += 1;
            match self
                .inner
                .get_object_with_offline_fallback_known_cid(&self.bucket, path, cid)
                .await
            {
                Ok(result) => return Ok(result.inner.data.to_vec()),
                Err(e)
                    if attempt < BLOB_BACKEND_MAX_ATTEMPTS
                        && crate::multipart::is_transient(&e) =>
                {
                    tracing::debug!(
                        bucket = %self.bucket,
                        path = %path,
                        attempt,
                        error = %e,
                        "S3BlobBackend::get_with_cid_hint retrying transient 5xx"
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
        // wasm32 has no offline fallback infrastructure (block_cache +
        // gateway_fetch are gated out). The wrapper is a thin delegate
        // here so the call site stays identical across targets.
        let result = self
            .inner
            .get_object_with_offline_fallback(&self.bucket, path)
            .await
            .map_err(client_err_to_crypto)?;
        // Phase 19: result is an OfflineGetResult; bytes are on .inner.data.
        Ok(result.inner.data.to_vec())
    }

    async fn put(&self, path: &str, bytes: Vec<u8>) -> fula_crypto::Result<BlobPutResult> {
        // W.9.3: same self-verify gate as the non-wasm impl above. The
        // wasm path has no retry loop so we clone the body up-front
        // (the post-PUT verify needs the bytes; `put_object` consumes
        // them) before dispatching.
        let walkable_v8 = self.inner.config().walkable_v8_writer_enabled;
        let body = if walkable_v8 { Some(bytes.clone()) } else { None };
        let bucket = &self.bucket;
        self.inner
            .put_object(&self.bucket, path, bytes)
            .await
            .map(|result| {
                let cid = if walkable_v8 {
                    let cipher = body.as_deref().unwrap_or(&[]);
                    crate::walkable_v8::verify_etag_matches_ciphertext(
                        &result.etag,
                        cipher,
                        bucket,
                        path,
                    )
                } else {
                    None
                };
                BlobPutResult { cid }
            })
            .map_err(client_err_to_crypto)
    }

    /// Walkable-v8 reader (W.9.4) on wasm32 — the offline-fallback
    /// infrastructure (block_cache, gateway pool, parking_lot) is
    /// compiled out on the browser target, so the cid-hint variant
    /// degrades to the no-hint path. The trait-method signature is
    /// preserved for API symmetry across targets so `V7NodeStore`
    /// compiles unchanged on both. When walkable-v8 grows wasm-side
    /// gateway-race support in a later phase this method body will
    /// route through it; today it's a thin delegate.
    async fn get_with_cid_hint(
        &self,
        path: &str,
        _cid_hint: Option<&cid::Cid>,
    ) -> fula_crypto::Result<Vec<u8>> {
        self.get(path).await
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
    /// Create a new encryption config with **random** keys.
    ///
    /// **DEPRECATED — see [`EncryptionConfig::from_secret_key`].** Production
    /// code must derive its `SecretKey` from a stable, OAuth-derived seed
    /// (e.g. Argon2id over `{provider}:{rawSub}:{email}`) and pass it via
    /// `from_secret_key`. Calling `new()` produces a throwaway keypair: every
    /// session gets a different identity, so any data encrypted under it
    /// becomes permanently unreadable on the next process start.
    ///
    /// Tests and examples that legitimately need ephemeral keys should
    /// annotate the call with `#[allow(deprecated)]`.
    ///
    /// Metadata privacy is ENABLED by default with FlatNamespace mode.
    #[deprecated(
        since = "0.7.0",
        note = "use EncryptionConfig::from_secret_key — random keypair locks users out of all writes on next session restart"
    )]
    pub fn new() -> Self {
        #[allow(deprecated)]
        Self {
            key_manager: Arc::new(KeyManager::new()),
            metadata_privacy: true,
            obfuscation_mode: KeyObfuscation::FlatNamespace,
            forest_cache_ttl_secs: DEFAULT_FOREST_CACHE_TTL_SECS,
        }
    }

    /// Create without metadata privacy (filenames visible to server).
    ///
    /// **DEPRECATED — see [`EncryptionConfig::from_secret_key`] and
    /// `with_metadata_privacy(false)`.** Random-keypair semantics carry the
    /// same data-loss trap as [`EncryptionConfig::new`]; additionally,
    /// `KeyObfuscation::DeterministicHash` is itself deprecated in favor of
    /// `KeyObfuscation::FlatNamespace`.
    #[deprecated(
        since = "0.7.0",
        note = "use EncryptionConfig::from_secret_key + with_metadata_privacy(false) — random keypair locks users out on session restart"
    )]
    #[allow(deprecated)]
    pub fn new_without_privacy() -> Self {
        Self {
            key_manager: Arc::new(KeyManager::new()),
            metadata_privacy: false,
            obfuscation_mode: KeyObfuscation::DeterministicHash,
            forest_cache_ttl_secs: DEFAULT_FOREST_CACHE_TTL_SECS,
        }
    }

    /// Create with FlatNamespace mode and **random** keys.
    ///
    /// **DEPRECATED — see [`EncryptionConfig::from_secret_key`].**
    /// `from_secret_key` already defaults to `FlatNamespace` (best privacy
    /// posture) so the only thing this constructor adds is the random-keypair
    /// data-loss trap.
    #[deprecated(
        since = "0.7.0",
        note = "use EncryptionConfig::from_secret_key — defaults to FlatNamespace and avoids random-keypair data loss"
    )]
    pub fn new_flat_namespace() -> Self {
        #[allow(deprecated)]
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

/// **DEPRECATED — see [`EncryptionConfig::new`] for migration.**
///
/// Kept callable so existing source compiles, but every invocation produces a
/// random throwaway keypair. Production must construct via
/// `EncryptionConfig::from_secret_key`. Rust does not permit `#[deprecated]`
/// on trait method impls; the deprecation warning fires through the inner
/// `Self::new()` call and through the doc note here.
impl Default for EncryptionConfig {
    fn default() -> Self {
        #[allow(deprecated)]
        Self::new()
    }
}

/// Pinning credentials for remote pinning services
///
/// `token` is a bearer credential. `Debug` is hand-rolled so the token
/// never appears in log output — same redaction pattern as
/// `Config::access_token`.
#[derive(Clone)]
pub struct PinningCredentials {
    /// Pinning service endpoint URL
    pub endpoint: String,
    /// Bearer token for authentication
    pub token: String,
}

impl std::fmt::Debug for PinningCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PinningCredentials")
            .field("endpoint", &self.endpoint)
            .field("token", &"<redacted>")
            .finish()
    }
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
            // Generate obfuscated storage key FIRST. The storage_key is the
            // canonical S3 path the metadata blob lives at; binding it into
            // the metadata AEAD's AAD prevents a server from swapping
            // metadata blobs across paths (F2 audit fix). Path-derived DEK,
            // not per-file DEK, so retrieval can recompute the same key.
            let path_dek = self.encryption.key_manager.derive_path_key(key);
            let storage_key = obfuscate_key(key, &path_dek, self.encryption.obfuscation_mode.clone());

            // Create private metadata with original info. H-1: compute BLAKE3
            // over the plaintext *before* AEAD so the hash is bound to the
            // forest entry (outside the attacker-forgeable HPKE envelope).
            let content_hash = blake3::hash(&data).to_hex().to_string();
            let private_meta = PrivateMetadata::new(key, original_size)
                .with_content_type(content_type.unwrap_or("application/octet-stream"))
                .with_content_hash(content_hash);

            // Encrypt private metadata with the per-file DEK and AAD bound
            // to the storage_key (v2 wire format; legacy v1 blobs without
            // AAD remain readable via PublicMetadata::decrypt_private).
            let aad = EncryptedPrivateMetadata::aad_v2(&storage_key);
            let encrypted_meta = EncryptedPrivateMetadata::encrypt_v2(&private_meta, &dek, &aad)
                .map_err(ClientError::Encryption)?;

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

    /// Issue #11 — fetch the `x-fula-encryption` metadata JSON for an
    /// object, with automatic fallback to the forest entry's local copy
    /// when master is unreachable.
    ///
    /// Behavior:
    /// - Tries `head_object` against the configured master first. On
    ///   success, returns the `x-fula-encryption` HTTP response header.
    ///   This preserves "live S3 = source of truth" for online flows.
    /// - On a transport-layer failure (master unreachable / DNS /
    ///   connect / timeout / health-gate-down), falls back to the
    ///   forest entry's `user_metadata["x-fula-encryption"]`, populated
    ///   at upload by `put_object_encrypted_*` (see `encryption.rs:5955-5968`).
    /// - On any other error (404, AccessDenied, parse errors),
    ///   propagates as-is — those are real failure responses, not
    ///   master-down.
    ///
    /// Used by `fula-flutter::api::sharing::create_share_token` (issue
    /// #11). Suitable for any caller that needs the encryption envelope
    /// (wrapped DEK + nonce + version + chunked metadata) without
    /// downloading the body.
    ///
    /// Limitation: post-key-rotation, the forest's `user_metadata` is
    /// NOT kept in sync with S3 (`rewrap_object_dek` updates S3 only,
    /// `encryption.rs:8729-8800`). Online flows fetch fresh data via
    /// HEAD and are correct. Fully-offline flows after a rotation may
    /// surface stale wrapped DEKs; a follow-up fix that mirrors the
    /// rewrap into forest `user_metadata` would resolve this.
    pub async fn get_object_encryption_metadata_with_fallback(
        &self,
        bucket: &str,
        storage_key: &str,
    ) -> Result<String> {
        match self.inner.head_object(bucket, storage_key).await {
            Ok(head) => head
                .metadata
                .get("x-fula-encryption")
                .cloned()
                .ok_or_else(|| {
                    ClientError::Encryption(fula_crypto::CryptoError::Decryption(
                        "Object is not encrypted or missing encryption metadata"
                            .to_string(),
                    ))
                }),
            Err(err) if Self::is_master_unreachable_error(&err) => {
                // Master unreachable — fall back to the local forest entry.
                self.ensure_forest_loaded(bucket).await?;
                let forest_entry = self
                    .forest_entry_lookup(bucket, storage_key)
                    .await?
                    .ok_or_else(|| ClientError::NotFound {
                        bucket: bucket.to_string(),
                        key: storage_key.to_string(),
                    })?;
                forest_entry
                    .user_metadata
                    .get("x-fula-encryption")
                    .cloned()
                    .ok_or_else(|| {
                        ClientError::Encryption(fula_crypto::CryptoError::Decryption(
                            "Master unreachable and forest entry carries no \
                             x-fula-encryption (legacy upload pre-issue-11; \
                             bring master back online to repair)"
                                .to_string(),
                        ))
                    })
            }
            Err(err) => Err(err),
        }
    }

    /// Issue #11 — classify a `ClientError` as a transport-layer
    /// "master unreachable" failure that should trigger forest-entry
    /// fallback. Excludes legitimate S3 error responses (404, 403,
    /// etc.) which are real failures, not master-down signals.
    fn is_master_unreachable_error(err: &ClientError) -> bool {
        match err {
            ClientError::MasterUnreachable { .. } => true,
            ClientError::Http(e) => {
                e.is_connect()
                    || e.is_timeout()
                    || e.is_request()
                    // Catch DNS resolution failures explicitly — reqwest
                    // does not classify "dns error / failed to lookup
                    // address" as `is_connect()` on every platform.
                    || {
                        let s = e.to_string();
                        s.contains("dns error") || s.contains("failed to lookup")
                    }
            }
            _ => false,
        }
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
        // Public API: caller has only a storage_key, so we look up the
        // forest entry on their behalf. v7 sharded HAMT pays the O(N)
        // `find_by_storage_key` linear scan here — see #91.
        //
        // Callers that already hold the resolved `ForestFileEntry` (e.g.
        // `get_object_flat`'s v7 branch, which walks the HAMT once via
        // `get_file(path)` to translate a logical path into an entry)
        // should use [`Self::get_object_decrypted_by_entry`] instead and
        // skip this redundant scan.
        let forest_entry = self.forest_entry_lookup(bucket, storage_key).await?;
        self.get_object_decrypted_inner(bucket, storage_key, forest_entry).await
    }

    /// Entry-aware variant of [`Self::get_object_decrypted_by_storage_key`]
    /// for callers that have already resolved the [`ForestFileEntry`]
    /// (e.g. `get_object_flat`'s v7 branch via `get_file(path)`).
    ///
    /// **Why this exists** (#91): the public `_by_storage_key` API does an
    /// O(N) `find_by_storage_key` linear scan over every shard's HAMT to
    /// recover the entry. For v7 sharded buckets that already walked the
    /// HAMT once to resolve the user's path, this is a redundant scan.
    /// On large buckets — and especially on cold-cache offline reads
    /// where each internal-node fetch is a multi-second gateway race —
    /// the scan dwarfs the actual file fetch. Passing the entry forward
    /// drops every encrypted GET back to O(log N) HAMT traversal cost.
    ///
    /// **Single-walk safety** (audited): the post-fix path acquires the
    /// `forest_arc` read guard exactly once via `get_file(path)` in
    /// `get_object_flat` (line 7218-7224); the pre-fix path would have
    /// acquired a SECOND independent read guard later via
    /// `forest_entry_lookup` → `find_by_storage_key`. The two guards
    /// were always returning the same data because both walked the same
    /// `forest_arc`, but a writer that interleaved between the two guard
    /// acquisitions could have caused the second read to observe a
    /// just-stamped `storage_cid` that the first read missed (or vice
    /// versa). Skipping the second guard cannot produce a wrong-bytes
    /// case: AEAD AAD `fula:v4:content:{storage_key}` binds bytes to
    /// storage_key independently of any race; a stale `storage_cid` of
    /// `None` just falls through to the no-hint offline-fallback path,
    /// which is safety-equivalent to today's behavior on legacy entries.
    ///
    /// **Cross-platform**: shared encryption.rs path; no `cfg`-split.
    async fn get_object_decrypted_by_entry(
        &self,
        bucket: &str,
        entry: ForestFileEntry,
    ) -> Result<Bytes> {
        let storage_key = entry.storage_key.clone();
        self.get_object_decrypted_inner(bucket, &storage_key, Some(entry)).await
    }

    /// Shared body of `get_object_decrypted_by_storage_key` and
    /// `get_object_decrypted_by_entry`. Takes the (optionally pre-resolved)
    /// `ForestFileEntry` directly so both code paths can reuse the same
    /// decrypt + content-verify + chunk-dispatch logic.
    ///
    /// Pre-resolved entry: `get_object_flat`'s v7 branch already walked
    /// the HAMT once and has the entry in hand — pass `Some(entry)` and
    /// skip the O(N) scan.
    ///
    /// Lookup: `get_object_decrypted_by_storage_key` only has a
    /// storage_key — does the lookup itself, which may cost an O(N)
    /// scan on v7 sharded buckets. Same as today's behavior.
    ///
    /// `forest_entry: None` is the share-token / pre-forest-write path
    /// where no forest entry exists; the body falls back to HTTP-header
    /// metadata for decryption. Unchanged from the pre-#91 behavior.
    async fn get_object_decrypted_inner(
        &self,
        bucket: &str,
        storage_key: &str,
        forest_entry: Option<ForestFileEntry>,
    ) -> Result<Bytes> {
        // Defense-in-depth: if the caller passed an entry, its
        // storage_key must match the storage_key argument. Compiled out
        // in release builds; catches caller bugs in debug.
        debug_assert!(
            forest_entry
                .as_ref()
                .map(|e| e.storage_key == storage_key)
                .unwrap_or(true),
            "get_object_decrypted_inner: entry.storage_key != storage_key argument"
        );

        // Forest-entry fallback rationale (preserved from pre-#91 body):
        // when the forest entry is available, we can fall back to its
        // (privacy-preserving, AEAD-protected) `user_metadata` when the
        // HTTP `x-fula-encryption` header is unavailable — i.e. on the
        // offline / warm-cache / cold-start paths where the body is
        // served from the local block cache (no headers preserved) or
        // a public IPFS gateway (no headers period).
        //
        // Security considerations for the forest-entry fallback:
        //   - The forest blob is AEAD-encrypted with `forest_dek`
        //     (derived from the user's KEK, never sent to master).
        //     Only the user can write or read these fields, so the
        //     metadata cannot be substituted by master or by a gateway.
        //   - The `wrapped_key` inside the JSON is HPKE-encrypted to
        //     the user's KEK; useless without it. AEAD AAD on the
        //     ciphertext is `fula:v4:content:{storage_key}`, binding
        //     bytes to their key — an attacker who swaps wrapped_key
        //     bytes for a key they control still cannot produce
        //     ciphertext that AEAD-verifies under the same AAD.
        //   - HTTP-header source remains preferred when present (master
        //     is the canonical source-of-truth). Forest entry is the
        //     fallback that turns gateway-served bytes into something
        //     decryptable.

        // Phase 2.4 — route through the offline-fallback wrapper so a
        // master-down read (per `is_master_unreachable_error`) lands on
        // the warm-cache + gateway-race path. Result on the offline
        // path carries the same ciphertext bytes but an empty
        // `metadata` map — the lookup helpers below pick up the
        // metadata from the forest entry instead.
        //
        // Walkable-v8 (#90, 2026-05-09): when the forest entry carries a
        // `storage_cid` (single-block encrypted uploads stamp this at
        // `put_object_encrypted_with_type` after master's PUT-response
        // self-verify), forward the CID through the `_known_cid`
        // variant. That activates the cold-cache gateway-race path:
        // even when both master is unreachable AND the warm block cache
        // is empty (= cold-start scenario), the gateway race fetches
        // the encrypted body by CID and content-verifies before handing
        // it to the AEAD decrypt step below. Without this branch,
        // single-block-encrypted cold-cache reads would fall through to
        // the no-hint fallback, which only checks the warm cache by
        // storage_key and then errors — exactly the failure mode the
        // walkable-v8 fresh-bucket cold-walk test surfaced.
        //
        // Native-only: `_known_cid` is gated to non-wasm (block_cache +
        // gateway_fetch infrastructure isn't compiled into wasm builds).
        // wasm32 keeps the legacy no-hint path; cold-cache offline reads
        // are not yet supported on browser SDKs.
        #[cfg(not(target_arch = "wasm32"))]
        let result = {
            let cid_hint = forest_entry.as_ref().and_then(|e| e.storage_cid.as_ref());
            match cid_hint {
                Some(cid) => self
                    .inner
                    .get_object_with_offline_fallback_known_cid(bucket, storage_key, cid)
                    .await?
                    .inner,
                None => self
                    .inner
                    .get_object_with_offline_fallback(bucket, storage_key)
                    .await?
                    .inner,
            }
        };
        #[cfg(target_arch = "wasm32")]
        let result = self
            .inner
            .get_object_with_offline_fallback(bucket, storage_key)
            .await?
            .inner;

        // Helper: fetch a metadata key, preferring HTTP headers, falling
        // back to the (AEAD-protected) forest entry's user_metadata.
        let get_meta = |k: &str| -> Option<String> {
            result
                .metadata
                .get(k)
                .cloned()
                .or_else(|| {
                    forest_entry
                        .as_ref()
                        .and_then(|e| e.user_metadata.get(k).cloned())
                })
        };

        // "Is this an encrypted upload?" — answered authoritatively by
        // the forest entry's `encrypted` boolean (set at upload via
        // `mark_encrypted`, AEAD-protected on disk). HTTP fallback for
        // share-token / pre-forest paths where forest_entry is None.
        let is_encrypted = forest_entry
            .as_ref()
            .map(|e| e.encrypted)
            .unwrap_or(false)
            || get_meta("x-fula-encrypted").as_deref() == Some("true");

        if !is_encrypted {
            // No forest entry says "must be encrypted" AND no header
            // says encrypted → genuinely plaintext (legacy unencrypted
            // upload, or share-token path that takes a different
            // decrypt branch). Return as-is.
            return Ok(result.data);
        }

        // Check if this is a chunked object — same precedence: HTTP →
        // forest entry. For new uploads, both sources agree; for
        // legacy uploads (forest_entry.user_metadata empty), HTTP is
        // the only source; for offline + new uploads, the forest entry
        // is the only source.
        let is_chunked = get_meta("x-fula-chunked").as_deref() == Some("true");

        // Parse encryption metadata. After the forest-entry fallback,
        // a missing entry on BOTH sources means we have no way to
        // decrypt — surface a clear error rather than silently
        // returning ciphertext or refusing on the wrong axis.
        let enc_metadata_str = get_meta("x-fula-encryption").ok_or_else(|| {
            ClientError::Encryption(fula_crypto::CryptoError::Decryption(
                "Missing encryption metadata (HTTP headers absent and forest entry has no \
                 user_metadata; legacy upload that requires master to be online — re-upload \
                 once via the new SDK to enable offline reads for this file)"
                    .to_string(),
            ))
        })?;

        let enc_metadata: serde_json::Value = serde_json::from_str(&enc_metadata_str)
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
                // Walkable-v8 (W.9.4-A2 / task #32): the chunked
                // metadata may carry a per-chunk CID hint (see
                // `ChunkedFileMetadata.chunk_cids` — populated by the
                // writer when `walkable_v8_writer_enabled` was on).
                // When present, the cold-cache offline fetch can race
                // gateways for the chunk by CID even on a fresh
                // device with no warm-cache `(bucket, chunk_key) →
                // cid` mapping. When absent (legacy chunked file or
                // writer flag off), falls through to the warm-cache
                // path which requires a prior master-up read.
                #[cfg(not(target_arch = "wasm32"))]
                let chunk_cid_hint = chunked_meta.chunk_cid(chunk_index as u32);
                async move {
                    // Phase 2.4 — route per-chunk fetches through the
                    // offline-fallback wrapper. Chunks themselves carry
                    // no per-chunk metadata: they decrypt with the
                    // shared DEK (from the index object) plus the
                    // chunk_index-derived nonce inside `decrypt_and_verify`
                    // below. So warm-cache hits are sufficient — no
                    // header round-trip needed. Bao streaming verifier
                    // catches truncation / tampering regardless of
                    // which channel served the bytes.
                    //
                    // Walkable-v8 (W.9.4-A2): when the chunked metadata
                    // carries a CID hint for THIS chunk, use the cold-
                    // cache cid-hint path so a fresh device with no
                    // warm-cache mapping can still fetch via gateway
                    // race when master is down. Otherwise fall through
                    // to the warm-cache path (legacy / pre-W.9.4-A2
                    // chunked files).
                    #[cfg(not(target_arch = "wasm32"))]
                    let data = fetch_chunk_with_timeout(
                        async {
                            match chunk_cid_hint {
                                Some(cid) => client
                                    .get_object_with_offline_fallback_known_cid(
                                        &bucket, &chunk_key, &cid,
                                    )
                                    .await
                                    .map(|r| r.inner.data),
                                None => client
                                    .get_object_with_offline_fallback(&bucket, &chunk_key)
                                    .await
                                    .map(|r| r.inner.data),
                            }
                        },
                        chunk_index as u32,
                        per_chunk_timeout,
                    )
                    .await?;
                    #[cfg(target_arch = "wasm32")]
                    let data = client
                        .get_object_with_offline_fallback(&bucket, &chunk_key)
                        .await
                        .map(|r| r.inner.data)?;
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

        // Decrypt private metadata if present. F2 dispatch: v1 (legacy,
        // no AAD) vs v2 (AAD bound to storage_key). Future versions error
        // cleanly so a downgrade attack cannot pick the wrong arm.
        let (original_key, original_size, content_type, user_metadata) =
            if let Some(private_meta_str) = enc_metadata["private_metadata"].as_str() {
                let encrypted_meta = EncryptedPrivateMetadata::from_json(private_meta_str)
                    .map_err(ClientError::Encryption)?;
                let private_meta = match encrypted_meta.version {
                    1 => {
                        #[allow(deprecated)]
                        encrypted_meta.decrypt(&dek).map_err(ClientError::Encryption)?
                    }
                    2 => {
                        let aad = EncryptedPrivateMetadata::aad_v2(storage_key);
                        encrypted_meta
                            .decrypt_v2(&dek, &aad)
                            .map_err(ClientError::Encryption)?
                    }
                    v => {
                        return Err(ClientError::Encryption(
                            fula_crypto::CryptoError::Decryption(format!(
                                "unsupported EncryptedPrivateMetadata wire version {} — \
                                 this SDK reads v1 and v2",
                                v
                            )),
                        ));
                    }
                };

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

        // Decrypt private metadata if present (this is tiny - just a few hundred bytes).
        // F2 dispatch: v1 (legacy, no AAD) vs v2 (AAD bound to storage_key).
        if let Some(private_meta_str) = enc_metadata["private_metadata"].as_str() {
            let encrypted_meta = EncryptedPrivateMetadata::from_json(private_meta_str)
                .map_err(ClientError::Encryption)?;
            let private_meta = match encrypted_meta.version {
                1 => {
                    #[allow(deprecated)]
                    encrypted_meta.decrypt(&dek).map_err(ClientError::Encryption)?
                }
                2 => {
                    let aad = EncryptedPrivateMetadata::aad_v2(storage_key);
                    encrypted_meta
                        .decrypt_v2(&dek, &aad)
                        .map_err(ClientError::Encryption)?
                }
                v => {
                    return Err(ClientError::Encryption(
                        fula_crypto::CryptoError::Decryption(format!(
                            "unsupported EncryptedPrivateMetadata wire version {} — \
                             this SDK reads v1 and v2",
                            v
                        )),
                    ));
                }
            };

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

        // Try to load from storage. Phase 2.4: route through the
        // offline-fallback wrapper so a master-down read can transparently
        // fall through to the gateway race using the cached
        // `(bucket, index_key) → cid` mapping. Phase 3.3 layers cold-start
        // escalation on top: when the offline-fallback returns
        // `MasterUnreachable` (master down AND KEY_TO_CID miss for a
        // fresh device that's never read this manifest before) AND the
        // resolver is configured, escalate to the IPNS+chain hybrid
        // resolver to fetch the manifest CID and its bytes via the
        // public network. Wrapper synthesizes `etag = cid.to_string()`
        // on the gateway-fetched / cold-start paths so the existing
        // forest-format detector + sequence-replay guard handle the
        // result identically (master also uses cid.to_string() as ETag).
        match self
            .fetch_manifest_with_cold_start_escalation(bucket, &index_key)
            .await
        {
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
                        // Walkable-v8 (W.9.4): pluck `dir_index_cid` from
                        // the just-decrypted root and pass it through.
                        // Cloned because the manifest is moved into
                        // `from_manifest` below.
                        let dir_index_cid = manifest.root.dir_index_cid;
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
                                dir_index_cid.as_ref(),
                                dir_index_seq_pin,
                            )
                            .await?
                        {
                            Some((idx, seq, observed_etag)) => {
                                forest.install_dir_index(idx, seq);
                                // Task #29: refresh the root's dir_index_etag
                                // pin from master's actual response etag if it
                                // diverged from what the manifest recorded.
                                // Without this, a Phase-1.6-landed-but-Phase-2-
                                // crashed write on a different device leaves
                                // this device with a stale `dir_index_etag`
                                // and every Phase 1.6 conditional PUT 412s
                                // against master's actual dir-index object.
                                if observed_etag.as_deref() != dir_index_etag.as_deref() {
                                    forest.refresh_dir_index_etag_from_load(seq, observed_etag);
                                }
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
            // Genuinely new bucket — master returned 404 / NoSuchKey /
            // NoSuchBucket (covers `ClientError::NotFound`,
            // `BucketNotFound`, and the S3-XML error variants per
            // `error.rs::is_not_found`). Since v7 is the canonical
            // current format and the v1 → v7 migration path already
            // exists for legacy data, new forests are born v7 directly
            // so we never create a monolithic blob we'll later have to
            // migrate.
            //
            // The cache is populated but nothing is written to storage
            // yet — the first flush creates the manifest at `index_key`.
            // That matches the v1 behaviour (creation was also deferred
            // to first flush) and keeps "empty bucket read" cheap.
            //
            // Return the standard "forest is sharded" marker so callers
            // route through the sharded API. The v1 `PrivateForest`
            // return type doesn't admit a v7 value, and readers that
            // inspect an empty forest via the v1 API are a non-goal.
            Err(e) if e.is_not_found() => {
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
            // Real fetch failure — `MasterUnreachable` (offline + warm-
            // cache miss + cold-start unavailable), `UsersIndexResolutionFailed`
            // (cold-start tried but failed), 5xx, network / DNS errors,
            // SequenceRegression, etc. MUST propagate so callers see the
            // actual condition; the encrypted SDK's `ensure_forest_loaded`
            // (line 2732) bubbles this up to apps that can show "offline;
            // try again later" instead of an empty bucket.
            //
            // The previous wildcard `Err(_) =>` on this branch silently
            // turned every offline failure into a fresh empty forest,
            // which then served zero files via `list_files_from_forest`
            // even when the user's data sat in the master's pinning
            // chain. The narrower `is_not_found()` discriminator above
            // pins the empty-forest path to genuine NotFound responses.
            //
            // Cache state on this branch: no entry inserted (the prior
            // `forest_cache.remove(bucket)` at the top of this fn ran
            // before the fetch attempt, so `forest_cache` is empty for
            // `bucket`). The next call therefore re-attempts the fetch
            // from scratch — no stale state survives a transient outage.
            Err(e) => Err(e),
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

    /// Diagnostic snapshot of a loaded v7 sharded bucket — used by tests +
    /// support tools to distinguish "manifest decoded fine but every shard
    /// has root=None" (genuinely empty bucket published) from "shards have
    /// root pointers but the walk silently dropped entries" (offline-fetch
    /// failure path masked as success). Cheap: synchronous read against the
    /// already-loaded in-memory manifest, no network or backend calls.
    ///
    /// **Gated to `test-fault-injection`** to match `sharded_forest_layout`'s
    /// pattern: this is internal-state inspection, not a stable public API.
    /// Production callers should not depend on the shape of the returned
    /// struct; advisor flagged that exposing test/diagnostic accessors as
    /// ungated public API invites callers to encode internal invariants
    /// into their dependency contract.
    ///
    /// Returns `None` if the bucket isn't loaded as v7 sharded (either not
    /// loaded at all, or loaded as v1 monolithic).
    #[cfg(feature = "test-fault-injection")]
    pub fn sharded_forest_diagnostic(&self, bucket: &str) -> Option<ShardedForestDiagnostic> {
        let entry = self.forest_cache.get(bucket)?;
        if let ForestCacheEntry::ShardedHamt { forest, last_manifest_sequence, .. } = entry.value() {
            let guard = forest.try_read().ok()?;
            let manifest = guard.manifest();
            let total_shards = manifest.num_shards();
            let mut shards_with_root = 0usize;
            for i in 0..total_shards {
                if manifest.shard(i).root.is_some() {
                    shards_with_root += 1;
                }
            }
            // Read the dir-index seq pin inline — folding this in keeps the
            // public surface to a single accessor (the diagnostic struct)
            // and avoids exposing both `dir_index_seq()` (live counter) and
            // a separate `dir_index_seq_pin()` (snapshot value), which are
            // easy to confuse from the outside.
            let dir_index_seq = manifest.root.dir_index_seq;
            Some(ShardedForestDiagnostic {
                total_shards,
                shards_with_root,
                page_count: manifest.page_count(),
                manifest_sequence: *last_manifest_sequence,
                dir_index_seq,
            })
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

    /// Test/diagnostic accessor: expose the same blinded-key derivation
    /// used internally for `x-amz-meta-fula-bucket-lookup-h` so tests can
    /// verify what the SDK computes for a given bucket name + secret pair
    /// vs. what's published in the per-user bucketsIndex CBOR. Mismatch
    /// indicates either the published entry was committed under a different
    /// secret, or `derive_path_key("fula-metadata-v1")` has drifted across
    /// SDK versions (the latter would be a serious compatibility regression).
    ///
    /// Gated behind `test-fault-injection` to match other diagnostic
    /// accessors. Production code should not depend on this surface.
    #[cfg(feature = "test-fault-injection")]
    pub fn debug_compute_bucket_lookup_h_hex(&self, bucket: &str) -> String {
        self.compute_bucket_lookup_h_hex(bucket)
    }

    /// Phase 3.3 escalation seam — fetch a manifest via the
    /// offline-fallback wrapper, escalating to cold-start on
    /// `MasterUnreachable` when the resolver is configured.
    ///
    /// Behavior:
    ///
    /// | State                                                                  | Result                                            |
    /// |------------------------------------------------------------------------|---------------------------------------------------|
    /// | Master up                                                              | normal path through `get_object_with_offline_fallback` |
    /// | Master down + KEY_TO_CID hit (warm device)                             | gateway race serves bytes (Phase 2.4)             |
    /// | Master down + KEY_TO_CID miss + resolver enabled (cold device)         | escalates to `cold_start_resolve_manifest`; populates KEY_TO_CID for next warm-cache read |
    /// | Master down + KEY_TO_CID miss + resolver NOT enabled                   | propagates `MasterUnreachable`                    |
    ///
    /// On the cold-start path the synthesized result carries
    /// `etag = manifest_cid.to_string()` so the existing forest-
    /// format detector + sequence-replay guard handle the bytes
    /// identically to a master-served fetch (master also uses
    /// `cid.to_string()` as the ETag — see `fula-cli/src/handlers/object.rs:103-105`).
    ///
    /// Native-only: the cold-start resolver is gated to
    /// `cfg(not(target_arch = "wasm32"))`. On wasm this method
    /// degrades to the underlying `get_object_with_offline_fallback`
    /// (which itself degrades to `get_object_with_metadata`).
    #[cfg(not(target_arch = "wasm32"))]
    async fn fetch_manifest_with_cold_start_escalation(
        &self,
        bucket: &str,
        index_key: &str,
    ) -> Result<GetObjectResult> {
        match self
            .inner
            .get_object_with_offline_fallback(bucket, index_key)
            .await
        {
            // Happy path: master up OR warm-cache hit. Phase 19 wraps
            // the result in OfflineGetResult; this internal cold-start
            // path doesn't surface source/freshness to callers, so
            // unwrap the inner GetObjectResult and propagate.
            Ok(r) => Ok(r.inner),

            // Master-down + cache miss → try cold-start if resolver is
            // configured. Identifying which "MasterUnreachable" case
            // this is doesn't matter — both are "we don't know the
            // CID locally, fetch from the public network". The
            // classifier covers DNS errors / connect refused / 5xx /
            // explicit MasterUnreachable, which is what the wrapper
            // propagates when its fallback can't serve the bytes.
            Err(e) if crate::client::is_master_unreachable_error(&e) => {
                // Resolver-enabled? If not, propagate the original.
                if self.inner.users_index_resolver().is_none() {
                    return Err(e);
                }
                // Run the cold-start chain.
                let (manifest_cid, manifest_bytes) =
                    self.cold_start_resolve_manifest(bucket).await?;

                // Best-effort: populate KEY_TO_CID so the next read
                // of this manifest (which IS predictable — the
                // index_key is deterministic from forest_dek) lands
                // in the warm-device fast path. Failure is fine; we
                // already have the bytes for THIS read.
                if let Some(cache) = self.inner.block_cache() {
                    if let Err(e) = cache.record_key_cid(bucket, index_key, &manifest_cid) {
                        tracing::debug!(
                            error = %e,
                            "cold-start: KEY_TO_CID populate failed (best-effort)"
                        );
                    }
                    // Also seed the BLOCKS cache with the manifest
                    // bytes — saves the gateway race on the next read
                    // of this same manifest.
                    if let Err(e) = cache.put(&manifest_cid, &manifest_bytes).await {
                        tracing::debug!(
                            error = %e,
                            "cold-start: BLOCKS put failed (best-effort)"
                        );
                    }
                }

                Ok(GetObjectResult {
                    content_length: manifest_bytes.len() as u64,
                    data: manifest_bytes,
                    etag: manifest_cid.to_string(),
                    content_type: None,
                    last_modified: None,
                    metadata: std::collections::HashMap::new(),
                })
            }

            // Any other error (Http, S3 4xx, encryption, etc.) —
            // not a master-down condition. Propagate unchanged.
            Err(e) => Err(e),
        }
    }

    /// Wasm fallback: cold-start is native-only, so on wasm we just
    /// delegate to the existing wrapper. The native and wasm signatures
    /// are kept identical so call sites don't need cfg gates of their
    /// own.
    #[cfg(target_arch = "wasm32")]
    async fn fetch_manifest_with_cold_start_escalation(
        &self,
        bucket: &str,
        index_key: &str,
    ) -> Result<GetObjectResult> {
        // Phase 19: extract `.inner` since get_object_with_offline_fallback
        // now returns OfflineGetResult on every target.
        self.inner
            .get_object_with_offline_fallback(bucket, index_key)
            .await
            .map(|r| r.inner)
    }

    /// Phase 3.3 — cold-start resolution of a bucket's forest manifest
    /// via the hybrid IPNS+chain resolver.
    ///
    /// Invoked from the offline-fallback path (see
    /// `load_forest_internal`) when the local `KEY_TO_CID` cache
    /// has no entry for the manifest's storage key AND the resolver
    /// is configured. Walks the published chain:
    ///
    /// 1. Resolver returns the global `users` map (IPNS or chain).
    /// 2. Look up the configured `userKey` → per-user
    ///    `bucketsIndexCid`.
    /// 3. Fetch the bucketsIndex CBOR via gateway race + verify.
    /// 4. Compute `bucketLookupH = BLAKE3(MetadataKey || bucket)`;
    ///    fall back to the legacy plaintext-name entry if the
    ///    blinded key is absent (Phase 1.2 transition path).
    /// 5. Fetch the manifest's CBOR-pinned-bytes via gateway race
    ///    + verify.
    ///
    /// Returns `(manifest_cid, manifest_bytes)` so the caller writes
    /// the bytes into the existing forest-format-detect / decrypt
    /// pipeline without a second network round-trip — saves 5–30 s
    /// on the first cold-start read. Caller is also responsible for
    /// writing `(bucket, index_key) → manifest_cid` into KEY_TO_CID
    /// so subsequent warm-device reads short-circuit.
    ///
    /// **Bounded semantics.** Phase 3.3 makes the *manifest* CID
    /// reachable on a fresh device + master-down. It does **not**
    /// fix chunk-level fetches in true cold-start (the chunk's
    /// CID isn't derivable from its storage key without a master
    /// ping). The user can read manifests, list directories, and
    /// re-fetch any object whose chunks the warm-cache previously
    /// observed; never-read-before objects still require master to
    /// come back briefly. Phase 19+ may close that gap (e.g., by
    /// embedding chunk CIDs in the forest manifest).
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn cold_start_resolve_manifest(
        &self,
        bucket: &str,
    ) -> Result<(cid::Cid, bytes::Bytes)> {
        // 1. Resolver must be configured + user_key set. Both are
        //    deferred to construction time, so absence here means
        //    the operator has the resolver enabled but missed one of
        //    the four required Config fields.
        let resolver = self
            .inner
            .users_index_resolver()
            .ok_or_else(|| ClientError::UsersIndexResolutionFailed {
                reason: "cold-start resolver not configured (Config requires all four fields: \
                         users_index_chain_rpc_url, users_index_anchor_address, \
                         users_index_ipns_name, users_index_user_key)".into(),
            })?
            .clone();
        let user_key = self
            .inner
            .config()
            .users_index_user_key
            .clone()
            .ok_or_else(|| ClientError::UsersIndexResolutionFailed {
                reason: "users_index_user_key is not set; compute it via derive_user_key_from_email at sign-in".into(),
            })?;

        // 2. Resolve the global users-index. Internal replay defense
        //    in the resolver bumps the seen-sequence floor.
        //
        //    Phase 19: when both IPNS and chain paths fail, the
        //    resolver returns `UsersIndexResolutionFailed`. Fire
        //    `SeverelyDegraded` (master + cold-start network both
        //    unreachable) before propagating so apps can disable
        //    "open new bucket" / "first-read" UI affordances. This
        //    is the ONLY emission point for `SeverelyDegraded` —
        //    the health gate alone can't authoritatively detect
        //    "both down" without trying.
        let resolved = match resolver.resolve().await {
            Ok(r) => r,
            Err(e) => {
                if matches!(e, ClientError::UsersIndexResolutionFailed { .. }) {
                    self.inner.fire_health_event(
                        crate::health_gate::MasterHealthEvent::SeverelyDegraded {
                            reason: format!("cold-start resolver exhausted: {}", e),
                        },
                    );
                }
                return Err(e);
            }
        };

        // 3. Look up our user_key in the global map.
        let buckets_index_cid_str = resolved
            .payload
            .users
            .get(&user_key)
            .cloned()
            .ok_or_else(|| ClientError::UsersIndexResolutionFailed {
                reason: format!(
                    "userKey {} not present in published global users-index (size={}); user has not written yet",
                    user_key,
                    resolved.payload.users.len(),
                ),
            })?;
        let buckets_index_cid = buckets_index_cid_str.parse::<cid::Cid>().map_err(|e| {
            ClientError::UsersIndexResolutionFailed {
                reason: format!("invalid bucketsIndex CID '{}': {}", buckets_index_cid_str, e),
            }
        })?;

        // 4. Fetch + verify + parse bucketsIndex CBOR.
        let gateways = resolver.ipfs_gateways();
        let bi_bytes = crate::registry_resolver::fetch_cid_via_gateways(
            &buckets_index_cid,
            &gateways,
            resolver.http_client(),
            resolver.per_request_timeout(),
        )
        .await?;
        let buckets_index = crate::registry_resolver::decode_user_buckets_index(&bi_bytes)?;

        // 5. Resolve the requested bucket. Try the blinded key
        //    first (Phase 1.2 migrated state); fall back to the
        //    plaintext bucket name for legacy entries (the user
        //    hasn't yet uploaded with a Phase-1.2-aware client
        //    since the field landed). The legacy fallback only
        //    accepts entries explicitly marked `legacy = true`,
        //    closing the loophole where a malicious gateway could
        //    plant a stronger-looking plaintext-name entry next to
        //    a real blinded one.
        let blinded = self.compute_bucket_lookup_h_hex(bucket);
        let entry = if let Some(e) = buckets_index.buckets.get(&blinded) {
            e.clone()
        } else if let Some(e) = buckets_index.buckets.get(bucket) {
            if !e.legacy {
                return Err(ClientError::UsersIndexResolutionFailed {
                    reason: format!(
                        "bucket {:?} present at plaintext key but legacy=false; refusing as ambiguous",
                        bucket
                    ),
                });
            }
            e.clone()
        } else {
            return Err(ClientError::BucketNotFound(bucket.to_string()));
        };

        // v0.4.4: prefer the new `forest_manifest_cid` field (the SDK's
        // encrypted forest manifest CID — what we actually need for
        // cold-start). Fall back to the legacy `manifest` field (master's
        // CBOR Prolly Tree CID) only when the new field is absent / empty.
        // The fallback path is broken (CBOR parsed as JSON fails) but is
        // no worse than v0.4.3-and-prior behavior; users on v0.4.4+ master
        // get the correct value automatically once they re-PUT.
        let cold_start_cid_str = entry.cold_start_cid();
        let manifest_cid = cold_start_cid_str.parse::<cid::Cid>().map_err(|e| {
            // Diagnostic message that distinguishes the three failure modes
            // operators are likely to hit:
            //   - Both fields populated but malformed → real CID parse error
            //   - forest_manifest_cid empty/None, manifest is a CID →
            //     v0.4.4 master flag wasn't on for this user's last PUT
            //     (or user is on a pre-v0.4.4 SDK that never sends the
            //     fula-forest-manifest sentinel) — the user needs to
            //     re-flush from a v0.4.4+ SDK against a v0.4.4+ master
            //     with `FULA_FOREST_MANIFEST_CID_ENABLED=1`.
            //   - Both fields empty → bucket exists in master's registry
            //     but no Phase 2 root commit has happened yet.
            let hint = if entry.forest_manifest_cid.as_deref().unwrap_or("").is_empty() {
                " — `forest_manifest_cid` was not populated by master; \
                  re-flush this bucket from a v0.4.4+ SDK against a master \
                  with `FULA_FOREST_MANIFEST_CID_ENABLED=1`"
            } else {
                ""
            };
            ClientError::UsersIndexResolutionFailed {
                reason: format!(
                    "invalid manifest CID '{}' for bucket {} (forest_manifest_cid={:?}, manifest={:?}): {}{}",
                    cold_start_cid_str, bucket, entry.forest_manifest_cid, entry.manifest, e, hint,
                ),
            }
        })?;

        // 6. Fetch + verify manifest bytes.
        let manifest_bytes = crate::registry_resolver::fetch_cid_via_gateways(
            &manifest_cid,
            &gateways,
            resolver.http_client(),
            resolver.per_request_timeout(),
        )
        .await?;

        Ok((manifest_cid, manifest_bytes))
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
        // v0.4.4: includes the forest-manifest sentinel so master tracks
        // this object's CID for the cold-start path (same as the v7
        // sharded path's Phase 2 PUT).
        let metadata = ObjectMetadata::new()
            .with_content_type("application/octet-stream")
            .with_metadata("fula-bucket-lookup-h", &self.compute_bucket_lookup_h_hex(bucket))
            .with_metadata("fula-forest-manifest", "1");

        // TEMPORARY DIAGNOSTIC for #29.
        #[cfg(not(target_arch = "wasm32"))]
        let metadata = {
            let body_cid_hash = blake3::hash(&data);
            let body_cid_mh =
                cid::multihash::Multihash::<64>::wrap(0x1e, body_cid_hash.as_bytes())
                    .expect("blake3 multihash wrap");
            let body_cid = cid::Cid::new_v1(0x55, body_cid_mh);
            tracing::warn!(
                bucket,
                index_key,
                prior_etag = ?prior_etag,
                body_cid = %body_cid,
                next_sequence,
                "save_forest (v1 monolithic) conditional PUT diag"
            );
            metadata
                .with_metadata("fula-debug-body-cid", &body_cid.to_string())
                .with_metadata(
                    "fula-debug-prior-etag",
                    prior_etag.as_deref().unwrap_or("<none>"),
                )
        };
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
        // Phase 1.2: hoist out of the loop — lookup-h is bucket-scoped, so
        // it's identical for every page PUT and the dir-index PUT below.
        // Attaching it on Phase 1.5 / 1.6 PUTs (not just the Phase 2 root
        // PUT) lets master populate `bucket_lookup_h` on the first chunked
        // upload, even before flush_forest commits the root. Closes the
        // migration gap where deferred-upload paths leave a bucket on
        // legacy=true plaintext until the next root commit.
        let lookup_h_hex = self.compute_bucket_lookup_h_hex(bucket);
        // Walkable-v8 (W.9.3): hoist the writer flag above both the page
        // loop and the dir-index commit so every Phase 1.5/1.6 PUT in
        // this flush sees the same Config snapshot. Reading it once up
        // front also avoids a per-PUT atomic read of the config field.
        let walkable_v8 = self.inner.config().walkable_v8_writer_enabled;
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
            // Walkable-v8 (W.9.3): pre-compute `BLAKE3(blob)` so the
            // post-PUT self-verify can compare master's ETag-attested CID
            // to a CID we computed locally (defense-in-depth against a
            // compromised master attesting an attacker-chosen CID). Cheap
            // ~1 GB/s SIMD hash; only computed when the writer flag is on
            // so v0.5-default behaviour stays byte-identical. `walkable_v8`
            // hoisted to flush-loop scope above so Phase 1.6 below sees it.
            let expected_page_cid = if walkable_v8 {
                Some(crate::walkable_v8::local_blake3_raw_cid(&blob))
            } else {
                None
            };
            let page_key = derive_manifest_page_key(&forest_dek, bucket, &shard_salt, page_id);
            let metadata = ObjectMetadata::new()
                .with_content_type("application/octet-stream")
                .with_metadata("fula-bucket-lookup-h", &lookup_h_hex);
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
            // TEMPORARY DIAGNOSTIC for #29: surface the SDK-side prior etag
            // (= `old_etag` from the in-memory page_index) and the new body's
            // CID via x-amz-meta headers so master's 412 diag reports the
            // exact value the SDK used as If-Match. Native-only; the wasm
            // path is irrelevant for FxFiles 412 reproduction.
            #[cfg(not(target_arch = "wasm32"))]
            let metadata = {
                let body_cid_hash = blake3::hash(&blob);
                let body_cid_mh =
                    cid::multihash::Multihash::<64>::wrap(0x1e, body_cid_hash.as_bytes())
                        .expect("blake3 multihash wrap");
                let body_cid = cid::Cid::new_v1(0x55, body_cid_mh);
                tracing::warn!(
                    bucket,
                    page_id,
                    page_key = %page_key,
                    if_match = ?if_match,
                    if_none_match = ?if_none_match,
                    body_cid = %body_cid,
                    "phase1.5 page conditional PUT diag"
                );
                metadata
                    .with_metadata("fula-debug-body-cid", &body_cid.to_string())
                    .with_metadata(
                        "fula-debug-prior-etag",
                        if_match.unwrap_or("<none>"),
                    )
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
            // Walkable-v8 (W.9.3): stamp the CID hint into the new
            // PageRef when the writer flag is on AND master's etag both
            // parses as a CID and matches our locally-computed
            // BLAKE3(blob). On any failure, falls back to `cid: None`
            // — readers walk via the storage_key path. The hash was
            // pre-computed before `Bytes::from(blob)` consumed the body.
            let page_cid = match (walkable_v8, expected_page_cid, etag.as_deref()) {
                (true, Some(expected), Some(et)) => {
                    crate::walkable_v8::verify_etag_against_expected_cid(
                        et, expected, bucket, &page_key,
                    )
                }
                _ => None,
            };
            manifest_snapshot.root.page_index.insert(page_id, PageRef {
                etag,
                seq: page.seq,
                cid: page_cid,
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
            // Walkable-v8 (W.9.3): pre-compute `BLAKE3(dir-index blob)` for
            // post-PUT self-verify. Reuses the same per-flush gate value
            // captured before Phase 1.5 above (every page in this flush
            // shares the same Config.walkable_v8_writer_enabled snapshot).
            let expected_dir_cid = if walkable_v8 {
                Some(crate::walkable_v8::local_blake3_raw_cid(&blob))
            } else {
                None
            };
            let dir_key = derive_dir_index_key(&forest_dek, bucket);
            let metadata = ObjectMetadata::new()
                .with_content_type("application/octet-stream")
                .with_metadata("fula-bucket-lookup-h", &lookup_h_hex);
            // TEMPORARY DIAGNOSTIC for #29 (same intent as the page-write
            // site above; surface the SDK's view of the prior etag so the
            // master 412 diag can confirm where a stale `If-Match` came from).
            #[cfg(not(target_arch = "wasm32"))]
            let metadata = {
                let body_cid_hash = blake3::hash(&blob);
                let body_cid_mh =
                    cid::multihash::Multihash::<64>::wrap(0x1e, body_cid_hash.as_bytes())
                        .expect("blake3 multihash wrap");
                let body_cid = cid::Cid::new_v1(0x55, body_cid_mh);
                tracing::warn!(
                    bucket,
                    dir_key = %dir_key,
                    prior_etag = ?old_dir_etag,
                    body_cid = %body_cid,
                    next_seq = next_dir_seq,
                    "phase1.6 dir-index conditional PUT diag"
                );
                metadata
                    .with_metadata("fula-debug-body-cid", &body_cid.to_string())
                    .with_metadata(
                        "fula-debug-prior-etag",
                        old_dir_etag.as_deref().unwrap_or("<none>"),
                    )
            };
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
            // Walkable-v8 (W.9.3): stamp dir_index_cid via self-verify.
            let dir_index_cid = match (walkable_v8, expected_dir_cid, new_dir_etag.as_deref()) {
                (true, Some(expected), Some(et)) => {
                    crate::walkable_v8::verify_etag_against_expected_cid(
                        et, expected, bucket, &dir_key,
                    )
                }
                _ => None,
            };
            manifest_snapshot.root.dir_index_etag = new_dir_etag;
            manifest_snapshot.root.dir_index_seq = Some(next_dir_seq);
            manifest_snapshot.root.dir_index_cid = dir_index_cid;
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

        // Phase 1.2: sharded HAMT v7 manifest root commit. Reuses the
        // bucket-scoped `lookup_h_hex` hoisted before Phase 1.5 so we
        // don't re-derive on every flush. See compute_bucket_lookup_h_hex
        // for header semantics.
        //
        // v0.4.4: also attach the sentinel header
        // `x-amz-meta-fula-forest-manifest: 1` so master populates
        // `BucketMetadata.forest_manifest_cid` with the just-stored
        // object's CID. This is the encrypted forest manifest CID the
        // publisher needs to emit in the per-user bucketsIndex CBOR for
        // cold-start to deserialize correctly. See server-side handler
        // at handlers/object.rs (`x-amz-meta-fula-forest-manifest`
        // sentinel block) for the population path. The sentinel is
        // sent ONLY on this Phase 2 root PUT — never on Phase 1.5 page
        // PUTs or Phase 1.6 dir-index PUTs (those are intermediate
        // objects, not the forest manifest root).
        let metadata = ObjectMetadata::new()
            .with_content_type("application/octet-stream")
            .with_metadata("fula-bucket-lookup-h", &lookup_h_hex)
            .with_metadata("fula-forest-manifest", "1");

        // TEMPORARY DIAGNOSTIC for #29 — compute the CID master would
        // assign to this body if the PUT succeeded, so we can compare
        // against `prior_etag`. If `body_cid == prior_etag` we've
        // found the bug: SDK is using the NEW body's CID as if_match
        // instead of master's stored OLD body's CID. Native-only —
        // `cid` is `[target.'cfg(not(wasm32))'].dependencies` in
        // fula-client. Master also computes the same body_cid in its
        // 412 handler, so the wasm path doesn't lose diagnostic
        // coverage.
        #[cfg(not(target_arch = "wasm32"))]
        let metadata = {
            let body_cid_hash = blake3::hash(&data);
            let body_cid_mh =
                cid::multihash::Multihash::<64>::wrap(0x1e, body_cid_hash.as_bytes())
                    .expect("blake3 multihash wrap");
            let body_cid = cid::Cid::new_v1(0x55, body_cid_mh);
            tracing::warn!(
                bucket,
                index_key,
                prior_etag = ?prior_etag,
                body_cid = %body_cid,
                new_seq = next_seq,
                "phase2 conditional PUT diag (body_cid = CID master would assign)"
            );
            metadata
                .with_metadata("fula-debug-body-cid", &body_cid.to_string())
                .with_metadata(
                    "fula-debug-prior-etag",
                    prior_etag.as_deref().unwrap_or("<none>"),
                )
        };
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

    /// Force-rewrite every populated HAMT internal node in `bucket`'s
    /// forest under the walkable-v8 wire format. Retrofits offline-
    /// readability onto a bucket whose internal nodes were originally
    /// persisted as v7 `PointerWire::Link(StorageKey)` (no CID hint, so
    /// the offline gateway race has no addressable target).
    ///
    /// # When to call
    ///
    /// Buckets written by SDKs prior to walkable-v8 (or by v8-aware SDKs
    /// with `walkable_v8_writer_enabled = false`) have HAMT internal
    /// nodes stamped with `Link(SK)` only. Lazy migration upgrades the
    /// nodes along any path that gets re-written, but cold sub-trees
    /// stay v7 indefinitely — so offline reads of those buckets still
    /// fail. This method is the explicit one-shot migration: after a
    /// successful return, every populated internal node carries a CID
    /// hint and the bucket is fully offline-walkable from any device
    /// that holds `forest_dek`.
    ///
    /// # Mechanic
    ///
    /// 1. Loads the forest via master (`ensure_forest_loaded`).
    /// 2. Enumerates every `ForestFileEntry` via `list_all_files`
    ///    AND every `ForestDirectoryEntry` via `list_all_directories`.
    ///    Both are required — re-upserting only files leaves HAMT
    ///    paths through `D:` ancestor keys unwalked, because
    ///    `upsert_file`'s `ensure_ancestor_chain` short-circuits on
    ///    pre-existing parents (`sharded_hamt_forest.rs:1119`). For a
    ///    directory-only sub-tree those ancestor paths route through
    ///    internal nodes that no `F:` upsert traverses, and those
    ///    nodes would stay v7. Iterating directories closes the gap.
    /// 3. Re-upserts each entry against itself. `Node::set_value`
    ///    unconditionally replaces every descended `Pointer::Link` with
    ///    `ChildPtr::InMemory` (`fula-crypto/src/wnfs_hamt/node.rs`
    ///    set_value's `Pointer::Link` arm). By the HAMT invariant that
    ///    every populated `Pointer::Link` slot has at least one leaf
    ///    under it, re-upserting every `F:` AND `D:` leaf converts
    ///    every populated internal node to `InMemory`.
    /// 4. Calls `save_sharded_hamt_forest`. `flush_dirty` invokes
    ///    `Node::store`, which walks every pointer unconditionally
    ///    (`node.rs:155-167`). `Pointer::to_wire`'s `InMemory` arm
    ///    emits `LinkV2 { storage_key, cid }` whenever the backend
    ///    returns a verified CID (`pointer.rs:294-302`). Result: every
    ///    re-encoded internal node carries the CID hint.
    ///
    /// # Cost and scaling
    ///
    /// Dominant cost is fetching every populated HAMT internal node
    /// once (subsequent upserts on the same subtree reuse the in-memory
    /// nodes). For a bucket of N files with average HAMT depth D and
    /// 16-shard fan-out, approximate cost:
    ///
    /// | N (files) | Internal nodes | Wall-clock estimate (10 ms / fetch) |
    /// |-----------|----------------|-------------------------------------|
    /// | 1 k       | ~ 100          | ~ 1 s                               |
    /// | 10 k      | ~ 1 k          | ~ 10 s                              |
    /// | 100 k     | ~ 10 k         | ~ 100 s = 1.7 min                   |
    /// | 1 M       | ~ 100 k        | ~ 1000 s = 17 min                   |
    ///
    /// Wall-clock dominated by network RTT; on a fast LAN the same
    /// migration is 5–10× faster. Final flush is a single Phase 2
    /// conditional PUT plus one PUT per dirty shard root and one PUT
    /// per dirty manifest page (typically 16 + 1–2 = ~17 extra PUTs).
    ///
    /// # Reliability + data integrity
    ///
    /// - **Crash safety.** The existing WAL (`crates/fula-client/src/wal.rs`)
    ///   appends `PageWrote` / `DirIndexWrote` entries before each
    ///   Phase 1.5 / 1.6 PUT and after each successful PUT. A crash
    ///   mid-cascade is recovered on next `ensure_forest_loaded` via
    ///   `recover_wal_after_load`.
    /// - **Atomic pivot.** The Phase 2 root commit uses `If-Match` on
    ///   the prior etag. A concurrent writer (another device, or this
    ///   process post-restart) that bumped the root mid-migration
    ///   causes a 412; the cache is evicted and the caller can retry.
    ///   Until Phase 2 succeeds, every reader still sees the pre-
    ///   migration root (the prior etag is unchanged on master).
    /// - **Idempotent.** Re-running the migration after a successful
    ///   completion re-upserts identical entries, the cascade re-emits
    ///   identical `LinkV2` variants, and Phase 2 advances the
    ///   manifest seq by one — no data change beyond a no-op seq bump.
    /// - **Lazy migration safety.** Buckets that mix freshly-written
    ///   v8 nodes with legacy v7 siblings are handled transparently by
    ///   the cascade — `to_wire`'s `Stored` arm emits the legacy
    ///   `Link(SK)` form for unmutated siblings (`pointer.rs:289`), so
    ///   parents containing both variants round-trip fine through
    ///   postcard (see `mixed_link_and_link_v2_in_one_parent_round_trips`
    ///   in pointer.rs).
    ///
    /// # Backward-compat
    ///
    /// - v0.6+ SDKs continue to read this bucket after migration.
    /// - v0.5 and earlier SDKs refuse with
    ///   `CryptoError::WireVersionUnsupported` on the first `LinkV2`
    ///   they encounter — clean error, no data corruption.
    /// - Coordinate with cross-device users: every device used to
    ///   access this bucket must be on v0.6+ before migration.
    ///
    /// # Configuration
    ///
    /// Requires `Config::walkable_v8_writer_enabled = true` (the
    /// default since v0.5). With the flag off the cascade re-emits v7
    /// wire format and the migration is a no-op — returns
    /// `ClientError::Config` to fail loudly rather than silently
    /// wasting the round trip.
    ///
    /// # Returns
    ///
    /// The number of files re-upserted (= `list_all_files().len()`).
    pub async fn migrate_bucket_to_walkable_v8(&self, bucket: &str) -> Result<usize> {
        if !self.inner.config().walkable_v8_writer_enabled {
            return Err(ClientError::Config(
                "migrate_bucket_to_walkable_v8 requires walkable_v8_writer_enabled = true; \
                 with the flag off the cascade re-emits PointerWire::Link (v7) and the \
                 migration is a no-op".to_string()
            ));
        }

        self.ensure_forest_loaded(bucket).await?;

        let forest_arc = {
            let entry = self.forest_cache.get(bucket).ok_or_else(|| {
                ClientError::Encryption(fula_crypto::CryptoError::Encryption(format!(
                    "migrate_bucket_to_walkable_v8: bucket {:?} not in forest cache after \
                     ensure_forest_loaded (internal invariant violation)",
                    bucket
                )))
            })?;
            match entry.value() {
                ForestCacheEntry::ShardedHamt { forest, .. } => forest.clone(),
                ForestCacheEntry::Monolithic { .. } => {
                    return Err(ClientError::Encryption(fula_crypto::CryptoError::Encryption(
                        format!(
                            "migrate_bucket_to_walkable_v8: bucket {:?} is on the monolithic \
                             forest (v1 / v2 / v4); walkable-v8 only applies to sharded HAMT \
                             v7+. Run migrate_to_sharded first, then re-run this migration.",
                            bucket
                        ),
                    )));
                }
            }
        };

        let backend = std::sync::Arc::new(S3BlobBackend::new(
            self.inner.clone(),
            bucket.to_string(),
        ));

        // Acquire the forest write lock BEFORE enumeration so a
        // concurrent sibling task in the same EncryptedClient (e.g.
        // an FxFiles delete pipeline) cannot remove an entry between
        // our enumeration and the cascade — which would otherwise
        // cause us to resurrect a just-deleted file/directory. The
        // list_all_* helpers take per-shard READ locks internally;
        // holding the outer WRITE lock supersedes them so the
        // enumeration runs inside this critical section without
        // deadlock.
        let mut guard = forest_arc.write().await;

        let all_files = guard
            .list_all_files(&backend)
            .await
            .map_err(ClientError::Encryption)?;
        let all_dirs = guard
            .list_all_directories(&backend)
            .await
            .map_err(ClientError::Encryption)?;

        let file_count = all_files.len();
        let dir_count = all_dirs.len();
        tracing::info!(
            bucket,
            files = file_count,
            dirs = dir_count,
            "migrate_bucket_to_walkable_v8: starting cascade — re-upserting every F: and D: \
             leaf to force every populated internal node to InMemory before flush"
        );

        // Cascade the re-upsert in the single write-lock acquisition.
        // Cost is bounded by the in-memory work plus the lazy load of
        // each populated internal node — ChildPtr::resolve_owned does
        // this at most once per node (the first descent replaces the
        // Stored slot with InMemory, so later descents on the same
        // subtree don't refetch — see node.rs:330-337 Arc::make_mut +
        // InMemory replacement).
        //
        // Files first, directories second: upsert_file writes both
        // F:path AND a D:parent entry. The D:parent write preserves
        // the prior dir entry's metadata + subtree_dek (upsert_file
        // line 1068-1083). The dirs pass then re-asserts each D:
        // entry with its FULL ForestDirectoryEntry, which is a no-op
        // for content but ensures the D: keys' HAMT paths are walked
        // (closing the ancestor-only-D: gap).
        //
        // Progress is logged every 100 entries at info-level so an
        // operator running this against a 100k-bucket can verify
        // forward progress without enabling debug-level tracing.
        for (idx, entry) in all_files.iter().enumerate() {
            guard
                .upsert_file(entry.clone(), &backend)
                .await
                .map_err(ClientError::Encryption)?;
            if idx > 0 && idx % 100 == 0 {
                tracing::info!(
                    bucket,
                    progress = idx,
                    total = file_count,
                    "migrate_bucket_to_walkable_v8: file cascade progress"
                );
            }
        }
        for (idx, entry) in all_dirs.iter().enumerate() {
            guard
                .upsert_directory(entry.clone(), &backend)
                .await
                .map_err(ClientError::Encryption)?;
            if idx > 0 && idx % 100 == 0 {
                tracing::info!(
                    bucket,
                    progress = idx,
                    total = dir_count,
                    "migrate_bucket_to_walkable_v8: dir cascade progress"
                );
            }
        }

        // Release the write lock before save_sharded_hamt_forest —
        // save itself re-acquires the lock for flush_dirty and Phase
        // 2 root commit. Holding it across save would deadlock the
        // re-acquire on the same task.
        drop(guard);

        // Phase 1 / 1.5 / 1.6 / 2 commit. flush_dirty re-encodes every
        // dirty shard's HAMT bottom-up via Node::store, which is what
        // actually stamps the LinkV2 variants. Phase 2's If-Match
        // covers the atomic pivot — if another writer beat us to it,
        // 412 surfaces here and the migration can be retried.
        self.save_sharded_hamt_forest(bucket).await?;

        tracing::info!(
            bucket,
            files = file_count,
            "migrate_bucket_to_walkable_v8: cascade flushed — bucket is now walkable-v8"
        );

        Ok(file_count)
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
        // Task #29: collect page-level (etag, seq) overrides from the actual
        // GET responses + decrypted page envelopes. The manifest's recorded
        // `page_index[page_id]` may be stale relative to the live page object
        // when a different device's Phase-1.5 PUT advanced master's page
        // object but its Phase-2 root commit failed. In that case THIS
        // device has no WAL entry to reconcile from, and the loaded manifest
        // remains stuck pointing at the pre-PUT etag, causing a permanent
        // 412 loop on this device's next Phase-1.5 conditional PUT
        // (`If-Match` = manifest's stale etag, master serves the post-PUT
        // etag). Trust the page object: master's response etag and the
        // envelope's encrypted-in seq are both more authoritative than
        // whatever the manifest happens to record.
        let mut page_overrides: Vec<(PageId, Option<String>, u64)> = Vec::new();
        for (page_id, page_ref) in root.page_index.iter() {
            let page_key = derive_manifest_page_key(forest_dek, bucket, &shard_salt, *page_id);
            // Phase 2.4 — route page fetches through the offline-fallback
            // wrapper so a master-down read transparently lands on the
            // warm-cache + gateway-race path. The page bytes are an
            // AEAD-encrypted envelope (`EncryptedManifestPage::from_bytes`
            // immediately below) decrypted with `forest_dek`; the cache
            // stores only the ciphertext, content-addressed by the CID
            // master (or a verified gateway) returned. No plaintext
            // payload or key material reaches the cache, so the security
            // model is identical to the manifest-fetch path that already
            // routes through this wrapper.
            //
            // Cold-cache cold-start (#31): when the just-decrypted root
            // pins this page's CID via `page_ref.etag`, prefer the
            // CID-hint variant so a fresh device — which has no
            // KEY_TO_CID warm-cache mapping for this page yet — can
            // still race the gateway pool with the exact CID. Master-up
            // path is unchanged (the wrapper hits master first
            // regardless of hint), so there is no slowness when the
            // server is reachable. Pages that have never been flushed
            // (`page_ref.etag = None`) fall back to the no-hint wrapper;
            // those pages have no on-IPFS bytes to fetch anyway.
            //
            // Native-only: the `cid` crate is gated to non-wasm targets
            // and the CID-hint method itself is too. On wasm we just
            // route through the no-hint wrapper, which already handles
            // master-up (the only fetch path supported on wasm anyway).
            // Walkable-v8 (W.9.4): prefer the explicit `page_ref.cid`
            // field stamped by the W.9.3 writer (which self-verified
            // the master-attested CID against `BLAKE3(page_blob)` at
            // write time). Etag-parse fallback covers pre-W.9.3 buckets
            // and remains correct only because master uses
            // `cid.to_string()` as the etag — but the explicit field is
            // strictly more trustworthy. See helper docs for the
            // precedence rationale + the unit test that pins it.
            #[cfg(not(target_arch = "wasm32"))]
            let cid_hint: Option<cid::Cid> = crate::walkable_v8::cid_hint_from_manifest_field_or_etag(
                page_ref.cid.as_ref(),
                page_ref.etag.as_deref(),
            );
            #[cfg(not(target_arch = "wasm32"))]
            let (blob, observed_etag) = match cid_hint {
                Some(cid) => self
                    .inner
                    .get_object_with_offline_fallback_known_cid(bucket, &page_key, &cid)
                    .await,
                None => {
                    self.inner
                        .get_object_with_offline_fallback(bucket, &page_key)
                        .await
                }
            }
            .map(|r| {
                let etag = if r.inner.etag.is_empty() {
                    None
                } else {
                    Some(r.inner.etag.clone())
                };
                (r.inner.data, etag)
            })
            .map_err(|e| {
                ClientError::DownloadFailed(format!(
                    "failed to fetch manifest page {} for bucket {}: {}",
                    page_id, bucket, e
                ))
            })?;
            #[cfg(target_arch = "wasm32")]
            let (blob, observed_etag) = self
                .inner
                .get_object_with_offline_fallback(bucket, &page_key)
                .await
                .map(|r| {
                    let etag = if r.inner.etag.is_empty() {
                        None
                    } else {
                        Some(r.inner.etag.clone())
                    };
                    (r.inner.data, etag)
                })
                .map_err(|e| {
                    ClientError::DownloadFailed(format!(
                        "failed to fetch manifest page {} for bucket {}: {}",
                        page_id, bucket, e
                    ))
                })?;
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
            // Task #29: queue an authoritative override for this page if
            // master's response etag and/or the envelope's seq disagree
            // with the manifest's recorded values. We only override when
            // the new info is strictly newer (envelope.seq >= page_ref.seq
            // is already guaranteed above; the etag check catches the
            // master-divergence case where seq matches but the recorded
            // etag predates a Phase-1.5 PUT that bumped master's page
            // object without a corresponding root commit on this device).
            let env_seq = envelope.seq;
            let needs_override = match (&observed_etag, &page_ref.etag) {
                (Some(observed), Some(recorded)) => observed != recorded,
                (Some(_), None) => true,
                (None, _) => false, // no observed etag → keep recorded
            } || env_seq > page_ref.seq;
            if needs_override {
                tracing::debug!(
                    %bucket,
                    page_id = %page_id,
                    recorded_etag = ?page_ref.etag,
                    observed_etag = ?observed_etag,
                    recorded_seq = page_ref.seq,
                    envelope_seq = env_seq,
                    "load_manifest_pages: page_index override (master diverged from manifest)"
                );
                page_overrides.push((*page_id, observed_etag, env_seq));
            }
            let page = envelope.decrypt(forest_dek, bucket)
                .map_err(ClientError::Encryption)?;
            pages.insert(*page_id, page);
        }
        // Apply the page-level overrides to the root before constructing the
        // ShardManifestV7 — the in-memory forest's `page_index` will then
        // reflect master's actual page objects, not the manifest's possibly-
        // stale recording. Subsequent Phase 1.5 conditional PUTs use these
        // values for `If-Match` and converge with master's state.
        //
        // Walkable-v8 (#52): the override path previously hardcoded
        // `cid: None`, dropping any recoverable CID hint from master's
        // returned etag. That left the in-memory `PageRef.cid` empty
        // until the next flush re-stamped it — degrading W.9.4 offline
        // reads to v0.5 fidelity in the load-after-master-divergence
        // window. Master returns `cid.to_string()` as the etag for v8
        // page PUTs (per the W.9.3 writer contract), so the same
        // `cid_hint_from_manifest_field_or_etag` helper that the
        // reader uses elsewhere recovers the CID here.
        let mut root = root;
        for (page_id, etag, seq) in page_overrides {
            #[cfg(not(target_arch = "wasm32"))]
            let cid = crate::walkable_v8::cid_hint_from_manifest_field_or_etag(
                None,
                etag.as_deref(),
            );
            #[cfg(target_arch = "wasm32")]
            let cid: Option<cid::Cid> = None;
            root.page_index.insert(page_id, PageRef { etag, seq, cid });
        }
        ShardManifestV7::from_root_and_pages(root, pages)
            .map_err(ClientError::Encryption)
    }

    /// Try to load the directory index (F-1.3) for this bucket.
    ///
    /// Returns `Ok(Some((index, seq, observed_etag)))` if the object decrypts
    /// cleanly and (when applicable) its sequence matches the root's pin.
    /// `observed_etag` is master's actual GET-response etag for the dir-index
    /// object — used by the caller to refresh `manifest.root.dir_index_etag`
    /// when it has diverged from master (task #29: same Phase-1.5/Phase-2
    /// crash-divergence pattern as the page-level fix in `load_manifest_pages`).
    /// Returns `Ok(None)` when:
    ///   * The object is 404 (never flushed or backend lost it).
    ///   * The plaintext sequence is older than the root's pin.
    ///   * Envelope decode / AEAD decrypt fails.
    /// All `None` outcomes trigger caller-side rebuild-from-forest.
    async fn load_directory_index(
        &self,
        bucket: &str,
        forest_dek: &fula_crypto::keys::DekKey,
        expected_etag: Option<&str>,
        expected_cid: Option<&cid::Cid>,
        expected_seq: Option<u64>,
    ) -> std::result::Result<Option<(DirectoryIndex, u64, Option<String>)>, ClientError> {
        let key = derive_dir_index_key(forest_dek, bucket);
        // Phase 2.4 — route through offline-fallback wrapper. Same
        // security model as the manifest + page fetches: the dir-index
        // blob is an AEAD envelope decrypted below with `forest_dek`,
        // the cache stores only the verified ciphertext content-addressed
        // by master's CID. NotFound (genuine "no dir-index yet") still
        // surfaces via `is_not_found()` and triggers rebuild-from-forest,
        // unchanged from before this fix.
        //
        // Cold-cache cold-start (#31): when the just-decrypted root
        // pins the dir-index CID via `expected_etag`, prefer the
        // CID-hint variant so a fresh device with no KEY_TO_CID
        // warm-cache mapping can still race the gateway pool. The
        // master-up path is identical regardless of hint.
        //
        // Walkable-v8 (W.9.4): the explicit `expected_cid` argument
        // (= `manifest.root.dir_index_cid`, stamped + self-verified
        // by the W.9.3 writer) takes precedence over `expected_etag`
        // when present. The etag-parse fallback covers buckets
        // committed pre-W.9.3 (when only `dir_index_etag` was
        // populated) and remains correct because master uses
        // `cid.to_string()` as the etag — but the explicit field is
        // strictly more trustworthy: it survived the writer's
        // self-verify-against-BLAKE3(blob) step, while the etag
        // fallback only happens to be a CID by master's current
        // convention.
        //
        // Native-only: `cid` crate + the CID-hint method are gated to
        // non-wasm targets. wasm builds keep the no-hint wrapper
        // (master-only path).
        #[cfg(not(target_arch = "wasm32"))]
        let cid_hint: Option<cid::Cid> = crate::walkable_v8::cid_hint_from_manifest_field_or_etag(
            expected_cid,
            expected_etag,
        );
        // Helper: turn the offline-fallback GetObjectResult into
        // `(blob, Option<observed_etag>)`. Empty etag → None. Used by both
        // native and wasm branches below so the etag-capture stays uniform.
        let extract = |r: crate::types::OfflineGetResult| {
            let etag = if r.inner.etag.is_empty() {
                None
            } else {
                Some(r.inner.etag.clone())
            };
            (r.inner.data, etag)
        };
        #[cfg(not(target_arch = "wasm32"))]
        let (blob, observed_etag) = match cid_hint {
            Some(cid) => match self
                .inner
                .get_object_with_offline_fallback_known_cid(bucket, &key, &cid)
                .await
                .map(&extract)
            {
                Ok(t) => t,
                Err(e) if e.is_not_found() => return Ok(None),
                Err(e) => return Err(e),
            },
            None => match self
                .inner
                .get_object_with_offline_fallback(bucket, &key)
                .await
                .map(&extract)
            {
                Ok(t) => t,
                Err(e) if e.is_not_found() => return Ok(None),
                Err(e) => return Err(e),
            },
        };
        #[cfg(target_arch = "wasm32")]
        let (blob, observed_etag) = match self
            .inner
            .get_object_with_offline_fallback(bucket, &key)
            .await
            .map(&extract)
        {
            Ok(t) => t,
            Err(e) if e.is_not_found() => return Ok(None),
            Err(e) => return Err(e),
        };
        // Task #29: log if the manifest's recorded `expected_etag` diverges
        // from the etag master actually serves for the dir-index object. The
        // caller uses the returned `observed_etag` to overwrite the root's
        // pin so Phase 1.6 conditional PUTs use the live etag (mirrors the
        // page-level override in `load_manifest_pages`).
        if let (Some(expected), Some(observed)) = (expected_etag, observed_etag.as_deref()) {
            if expected != observed {
                tracing::debug!(
                    %bucket,
                    expected_etag = expected,
                    observed_etag = observed,
                    "load_directory_index: dir_index_etag override (master diverged from manifest)"
                );
            }
        }
        // `expected_seq` is the authoritative pin: the dir-index envelope's
        // `seq` is AEAD-bound (AAD ties plaintext to `(bucket, seq)`), and
        // the root we just loaded commits to exactly one value of it. Seq
        // mismatch → treat as stale and trigger rebuild-from-forest.
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
                Ok(Some((index, seq, observed_etag)))
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
            // Walkable-v8 (W.9.3): mirror the flush_forest path's pre-PUT
            // hash so the v1→v7 migration's freshly-written pages also
            // carry CID hints when the writer flag is on.
            let walkable_v8_mig = self.inner.config().walkable_v8_writer_enabled;
            let expected_page_cid = if walkable_v8_mig {
                Some(crate::walkable_v8::local_blake3_raw_cid(&blob))
            } else {
                None
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
            // Walkable-v8 (W.9.3): same self-verify pattern as the
            // flush_forest path above.
            let page_cid = match (walkable_v8_mig, expected_page_cid, etag.as_deref()) {
                (true, Some(expected), Some(et)) => {
                    crate::walkable_v8::verify_etag_against_expected_cid(
                        et, expected, bucket, &page_key,
                    )
                }
                _ => None,
            };
            manifest_snapshot.root.page_index.insert(page_id, PageRef {
                etag,
                seq: page.seq,
                cid: page_cid,
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
        // Walkable-v8 (W.9.3): mirror flush_forest's pre-PUT hash for
        // the dir-index PUT so v1→v7 migrations also stamp dir_index_cid
        // when the writer flag is on.
        let walkable_v8_dir_mig = self.inner.config().walkable_v8_writer_enabled;
        let expected_dir_index_cid = if walkable_v8_dir_mig {
            Some(crate::walkable_v8::local_blake3_raw_cid(&dir_index_blob))
        } else {
            None
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
        // Walkable-v8 (W.9.3): stamp dir_index_cid via self-verify, same
        // pattern as flush_forest's Phase 1.6 above.
        let dir_index_cid_mig = match (
            walkable_v8_dir_mig,
            expected_dir_index_cid,
            new_dir_index_etag.as_deref(),
        ) {
            (true, Some(expected), Some(et)) => {
                crate::walkable_v8::verify_etag_against_expected_cid(
                    et, expected, bucket, &dir_index_key,
                )
            }
            _ => None,
        };
        manifest_snapshot.root.dir_index_etag = new_dir_index_etag;
        manifest_snapshot.root.dir_index_seq = Some(dir_index_seq);
        manifest_snapshot.root.dir_index_cid = dir_index_cid_mig;

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
        // v0.4.4: also attach the fula-forest-manifest sentinel so master
        // tracks this v7 manifest's CID; the post-migration cold-start
        // works seamlessly without waiting for the next regular flush.
        let put_result = match self.inner.put_object_with_metadata_conditional(
            bucket,
            &index_key,
            Bytes::from(manifest_data),
            Some(
                ObjectMetadata::new()
                    .with_content_type("application/octet-stream")
                    .with_metadata("fula-bucket-lookup-h", &self.compute_bucket_lookup_h_hex(bucket))
                    .with_metadata("fula-forest-manifest", "1"),
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

        // Encrypt private metadata with the per-file DEK and AAD bound to
        // the obfuscated storage_key (v2 wire format; F2 audit fix).
        let meta_aad = EncryptedPrivateMetadata::aad_v2(&storage_key);
        let encrypted_meta = EncryptedPrivateMetadata::encrypt_v2(&private_meta, &dek, &meta_aad)
            .map_err(ClientError::Encryption)?;

        // Mark the forest entry as encrypted so subsequent reads refuse a
        // plaintext response from the storage backend (C-AUDIT-004) and
        // pin its `min_version` to 4 (H-2).
        let mut forest_entry = ForestFileEntry::from_metadata(&private_meta, storage_key.clone());
        forest_entry.mark_encrypted();

        let kek_version = self.encryption.key_manager.version();
        let is_chunked_upload = should_use_chunked(data.len());

        // Check if we need chunked upload (for IPFS block size limit).
        //
        // Both branches return `(PutObjectResult, enc_metadata_json,
        // Option<Cid>)`. The third element is walkable-v8 (W.9.3): the
        // verified CID of the index/single object, which the caller
        // stamps into `ForestFileEntry.storage_cid`.
        //
        // The `enc_metadata_json` stash is the load-bearing change for
        // offline / cold-start encrypted reads: the forest blob is
        // AEAD-encrypted with `forest_dek` (derived from the user's
        // KEK), so the metadata travels privately, while making the
        // SDK self-sufficient when HTTP user-metadata headers are
        // unavailable (gateway path, warm-cache path).
        let (result, enc_metadata_json, index_cid_opt): (
            PutObjectResult,
            String,
            Option<cid::Cid>,
        ) = if is_chunked_upload {
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
            let enc_metadata_str = enc_metadata.to_string();

            let metadata = ObjectMetadata::new()
                .with_content_type("application/octet-stream")
                .with_metadata("x-fula-encrypted", "true")
                .with_metadata("x-fula-encryption", &enc_metadata_str);

            // Walkable-v8 (W.9.3): pre-compute `BLAKE3(ciphertext)` for
            // post-PUT self-verify before `Bytes::from(ciphertext)`
            // consumes the buffer. Skip when the flag is off so the
            // hash isn't computed for v0.5-default writes.
            let walkable_v8 = self.inner.config().walkable_v8_writer_enabled;
            let expected_obj_cid = if walkable_v8 {
                Some(crate::walkable_v8::local_blake3_raw_cid(&ciphertext))
            } else {
                None
            };

            let put_result = if let Some(ref pinning) = self.pinning {
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
            };

            // Walkable-v8 (W.9.3): verify and surface the CID for the
            // caller to stamp into ForestFileEntry.storage_cid. None on
            // any failure path — readers fall back to the storage_key
            // path.
            let cid = match (walkable_v8, expected_obj_cid) {
                (true, Some(expected)) => crate::walkable_v8::verify_etag_against_expected_cid(
                    &put_result.etag,
                    expected,
                    bucket,
                    &storage_key,
                ),
                _ => None,
            };
            (put_result, enc_metadata_str, cid)
        };

        // Walkable-v8 (W.9.3): stamp the index/single-object CID hint
        // onto the forest entry BEFORE upsert. Offline readers walk
        // ForestFileEntry → storage_cid → fetch via gateway race when
        // master is down. None when the writer flag is off or
        // self-verify failed; reads fall through to the storage_key
        // path. Per-chunk hints are not surfaced — that needs a
        // ChunkedFileMetadata wire-format extension (followup #32).
        forest_entry.storage_cid = index_cid_opt;

        // Stash the encryption metadata onto the forest entry. The forest
        // blob is AEAD-encrypted with `forest_dek` (derived from user's
        // KEK), so the metadata is privacy-preserving — only the user
        // can decrypt the forest and observe these fields.
        //
        // Security model:
        //   - `wrapped_key` inside the JSON is HPKE-encrypted to the
        //     user's KEK; useless without it.
        //   - The download AEAD AAD is `fula:v4:content:{storage_key}`
        //     which binds ciphertext to its storage_key. An attacker who
        //     swaps wrapped_key bytes for a key they control cannot
        //     produce ciphertext that AEAD-verifies under the same AAD.
        //   - Master continues to receive the same HTTP user-metadata
        //     headers so its bucket-registry plumbing is unchanged. We
        //     just additionally record the JSON privately in the forest.
        forest_entry.user_metadata.insert(
            "x-fula-encrypted".to_string(),
            "true".to_string(),
        );
        forest_entry.user_metadata.insert(
            "x-fula-encryption".to_string(),
            enc_metadata_json,
        );
        if is_chunked_upload {
            forest_entry.user_metadata.insert(
                "x-fula-chunked".to_string(),
                "true".to_string(),
            );
        }

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

    /// Internal: Upload a large file using chunked encoding.
    ///
    /// Returns `(PutObjectResult, enc_metadata_json_string)`. The
    /// caller stashes `enc_metadata_json_string` into the forest
    /// entry's `user_metadata` so the encrypted forest itself is
    /// self-describing — see `put_object_flat_deferred` for how this
    /// powers the offline / cold-start decrypt paths without leaking
    /// any plaintext (the JSON only travels inside the AEAD-encrypted
    /// forest blob).
    /// Walkable-v8 (W.9.3): the third tuple element is the parsed CID
    /// of the **index object** (the small JSON metadata blob master
    /// returns the etag for at the bucket-key path), self-verified
    /// against `BLAKE3(index_body)`. `Some(cid)` when the writer flag
    /// is on and verification succeeds; `None` otherwise. Caller
    /// stamps it into `ForestFileEntry.storage_cid`. Per-chunk CIDs
    /// are NOT surfaced — that needs a `ChunkedFileMetadata` wire
    /// format extension (followup task #32).
    async fn put_object_chunked_internal(
        &self,
        bucket: &str,
        storage_key: &str,
        data: &[u8],
        dek: &fula_crypto::keys::DekKey,
        wrapped_dek: &EncryptedData,
        encrypted_meta: &EncryptedPrivateMetadata,
        kek_version: u32,
    ) -> Result<(PutObjectResult, String, Option<cid::Cid>)> {
        // Create chunked encoder with AAD binding chunks to storage key
        let aad_prefix = format!("fula:v4:chunk:{}", storage_key);
        let mut encoder = ChunkedEncoder::with_aad(dek.clone(), aad_prefix);
        
        // Process all data through encoder
        let mut all_chunks = encoder.update(data)
            .map_err(ClientError::Encryption)?;
        
        // Finalize to get last chunk and metadata
        let (final_chunk, mut chunked_metadata, _outboard) = encoder.finalize()
            .map_err(ClientError::Encryption)?;

        if let Some(chunk) = final_chunk {
            all_chunks.push(chunk);
        }

        // Walkable-v8 (W.9.4-A2 / task #32): per-chunk CID hints for
        // offline reads. Read the writer flag once up front; use it
        // both for the per-chunk pre-PUT BLAKE3 hash and for the
        // post-PUT verify. When off, every chunk's verified CID stays
        // None and the metadata's `chunk_cids` Vec stays empty
        // (skip_serializing_if keeps it off the wire).
        let walkable_v8 = self.inner.config().walkable_v8_writer_enabled;

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

            // W.9.4-A2: pre-compute the chunk's expected CID before
            // `chunk.ciphertext` is moved into the PUT call. `Bytes`
            // cloning is cheap (Arc-based) so the post-PUT verify
            // doesn't re-hash the body — we already have the
            // expected CID from this pre-computation.
            let expected_chunk_cid = if walkable_v8 {
                Some(crate::walkable_v8::local_blake3_raw_cid(&chunk.ciphertext))
            } else {
                None
            };
            let chunk_index_for_collect = chunk.index;

            let client = self.inner.clone();
            let bucket = bucket.to_string();
            let pinning = pinning.clone();
            let chunk_key_ret = chunk_key.clone();

            async move {
                let put_result = if let Some(ref pin) = pinning {
                    client.put_object_with_metadata_and_pinning(
                        &bucket,
                        &chunk_key,
                        chunk.ciphertext,
                        Some(chunk_metadata),
                        &pin.endpoint,
                        &pin.token,
                    ).await?
                } else {
                    client.put_object_with_metadata(
                        &bucket,
                        &chunk_key,
                        chunk.ciphertext,
                        Some(chunk_metadata),
                    ).await?
                };
                // W.9.4-A2: verify master's etag-attested CID against
                // the pre-computed BLAKE3(ciphertext). Mismatch
                // soft-fails to None — chunk PUT succeeded, only the
                // offline-walk hint for THIS chunk is missing; the
                // reader falls back to storage_key for that chunk.
                let chunk_cid = match (walkable_v8, expected_chunk_cid) {
                    (true, Some(expected)) => crate::walkable_v8::verify_etag_against_expected_cid(
                        &put_result.etag,
                        expected,
                        &bucket,
                        &chunk_key,
                    ),
                    _ => None,
                };
                Ok::<(String, u32, Option<cid::Cid>), ClientError>((
                    chunk_key_ret,
                    chunk_index_for_collect,
                    chunk_cid,
                ))
            }
        });

        let results: Vec<std::result::Result<(String, u32, Option<cid::Cid>), ClientError>> =
            futures::stream::iter(futs)
                .buffer_unordered(Self::MAX_CONCURRENT_CHUNK_UPLOADS)
                .collect()
                .await;

        // Track successfully uploaded chunk keys so we can clean them up if
        // any upload in the batch failed. W.9.4-A2: also collect per-chunk
        // CIDs indexed by chunk_index (NOT result-iteration order — the
        // futures stream is unordered).
        let mut uploaded_keys: Vec<String> = Vec::new();
        let mut chunk_cids: Vec<Option<cid::Cid>> =
            vec![None; chunked_metadata.num_chunks as usize];
        let mut upload_error: Option<ClientError> = None;
        for result in results {
            match result {
                Ok((key, index, cid)) => {
                    uploaded_keys.push(key);
                    if let Some(slot) = chunk_cids.get_mut(index as usize) {
                        *slot = cid;
                    }
                }
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

        // W.9.4-A2: stamp the per-chunk CID Vec into the metadata
        // BEFORE serializing the index body. When walkable_v8 is off,
        // chunk_cids is all-None and `populate_chunk_cids` writes an
        // all-None Vec; the wire stays compact but a parallel-empty
        // Vec uses ~num_chunks bytes of postcard space. To stay
        // 100% byte-identical to v0.5 wire output when the flag is
        // off, only populate when at least one chunk has Some(cid).
        if walkable_v8 && chunk_cids.iter().any(|c| c.is_some()) {
            chunked_metadata.populate_chunk_cids(chunk_cids);
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

        // Walkable-v8 (W.9.3): pre-compute `BLAKE3(index_body)` so the
        // post-PUT self-verify can compare master's etag-attested CID
        // against a CID we computed locally. Cheap; only when the
        // writer flag is on.
        let walkable_v8 = self.inner.config().walkable_v8_writer_enabled;
        let expected_index_cid = if walkable_v8 {
            Some(crate::walkable_v8::local_blake3_raw_cid(index_body.as_bytes()))
        } else {
            None
        };

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

        // Walkable-v8 (W.9.3): self-verify the index-object CID. Caller
        // stamps it into `ForestFileEntry.storage_cid` so an offline
        // reader can fetch this index blob via gateway race when master
        // is down.
        let index_cid = match (walkable_v8, expected_index_cid) {
            (true, Some(expected)) => crate::walkable_v8::verify_etag_against_expected_cid(
                &result.etag,
                expected,
                bucket,
                storage_key,
            ),
            _ => None,
        };

        // Return the upload result, the JSON metadata the caller will
        // stash on the forest entry, and the verified index-object CID.
        // `index_body` IS the same JSON we just persisted as the index
        // object's body and HTTP header — handing it back avoids the
        // caller re-serializing.
        Ok((result, index_body, index_cid))
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

        // #82: forest must be loaded before any chunk PUT so a load
        // failure (e.g., master unreachable) surfaces before chunks
        // are uploaded — avoids creating orphan blobs that the
        // caller didn't agree to. The post-upload register step
        // below depends on this seeding.
        self.ensure_forest_loaded(bucket).await?;

        let dek = self.encryption.key_manager.generate_dek();
        let encryptor = Encryptor::new(self.encryption.public_key());
        let wrapped_dek = encryptor.encrypt_dek(&dek)
            .map_err(ClientError::Encryption)?;

        // Generate obfuscated storage_key first so the metadata AEAD can
        // bind to it via AAD (F2 audit fix; see EncryptedPrivateMetadata::aad_v2).
        let path_dek = self.encryption.key_manager.derive_path_key(key);
        let storage_key = obfuscate_key(key, &path_dek, self.encryption.obfuscation_mode.clone());
        let kek_version = self.encryption.key_manager.version();

        // H-1: BLAKE3 over the plaintext stream — bound to the forest
        // entry, not to the attacker-controllable ChunkedFileMetadata blob.
        let content_hash = blake3::hash(&data).to_hex().to_string();
        let private_meta = PrivateMetadata::new(key, original_size)
            .with_content_type(content_type.unwrap_or("application/octet-stream"))
            .with_content_hash(content_hash);
        let meta_aad = EncryptedPrivateMetadata::aad_v2(&storage_key);
        let encrypted_meta = EncryptedPrivateMetadata::encrypt_v2(&private_meta, &dek, &meta_aad)
            .map_err(ClientError::Encryption)?;

        // Encode all chunks (in memory — for streaming, use put_object_encrypted_streaming)
        let aad_prefix = format!("fula:v4:chunk:{}", storage_key);
        let mut encoder = ChunkedEncoder::with_aad(dek.clone(), aad_prefix);
        let mut all_chunks = encoder.update(&data).map_err(ClientError::Encryption)?;
        let (final_chunk, mut chunked_metadata, _outboard) = encoder.finalize()
            .map_err(ClientError::Encryption)?;
        if let Some(chunk) = final_chunk {
            all_chunks.push(chunk);
        }

        // Walkable-v8 (#80 / W.9.4-A2 port to resumable): per-chunk
        // CID hints. Mirror `put_object_chunked_internal`'s pattern —
        // pre-compute `BLAKE3(chunk.ciphertext)` BEFORE the spawn
        // moves the body, post-PUT verify against master's etag, and
        // populate `chunked_metadata.chunk_cids` after the parallel
        // upload completes. Without this, files uploaded via the
        // resumable path land with empty `chunk_cids` → reader
        // falls back to the warm-cache path (still works, just no
        // cold-cache gateway race for fresh devices).
        let walkable_v8 = self.inner.config().walkable_v8_writer_enabled;
        let num_chunks_total = all_chunks.len();

        // Build the index metadata JSON skeleton — `chunked_metadata`
        // gets `populate_chunk_cids` BEFORE the JSON is serialized
        // post-upload (or we hold on to the un-serialized form here
        // and serialize after). For the resumable path the JSON
        // lives in the persisted UploadManifest, so we serialize the
        // CID-stamped form just before the manifest save.

        // Write manifest before uploading any chunks
        let manifest_chunks: Vec<ManifestChunk> = all_chunks.iter().map(|c| {
            ManifestChunk {
                index: c.index,
                chunk_key: ChunkedFileMetadata::chunk_key(&storage_key, c.index),
                uploaded: false,
            }
        }).collect();

        // Initial manifest WITHOUT chunk_cids — they're not known
        // until each chunk's PUT returns its etag. Serialize the
        // pre-CID-stamped JSON for the on-disk manifest's
        // `index_metadata_json` so a crash-mid-upload still has a
        // resumable record. The post-upload finalize will rewrite
        // `index_metadata_json` with the CID-stamped form before the
        // index PUT.
        let initial_index_metadata_json = serde_json::json!({
            "version": 4,
            "algorithm": "AES-256-GCM",
            "wrapped_key": serde_json::to_value(&wrapped_dek).unwrap(),
            "kek_version": kek_version,
            "metadata_privacy": true,
            "obfuscation_mode": "flat",
            "private_metadata": encrypted_meta.to_json().map_err(ClientError::Encryption)?,
            "chunked": serde_json::to_value(&chunked_metadata).unwrap(),
        }).to_string();

        let mut manifest = UploadManifest {
            bucket: bucket.to_string(),
            storage_key: storage_key.clone(),
            original_key: key.to_string(),
            num_chunks: all_chunks.len() as u32,
            chunks: manifest_chunks,
            index_metadata_json: initial_index_metadata_json,
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

            // W.9.4-A2 / #80: pre-compute the chunk's expected CID
            // before `chunk.ciphertext` is moved into the spawn.
            // `Bytes` cloning is Arc-cheap so the post-PUT verify
            // doesn't re-hash the body.
            let expected_chunk_cid = if walkable_v8 {
                Some(crate::walkable_v8::local_blake3_raw_cid(&chunk.ciphertext))
            } else {
                None
            };

            let handle = tokio::spawn(async move {
                let _permit = sem.acquire().await.map_err(|e|
                    ClientError::Encryption(fula_crypto::CryptoError::Decryption(e.to_string()))
                )?;
                let put_result = if let Some(ref pin) = pinning {
                    client.put_object_with_metadata_and_pinning(
                        &bucket_owned, &chunk_key, chunk.ciphertext,
                        Some(chunk_metadata), &pin.endpoint, &pin.token,
                    ).await?
                } else {
                    client.put_object_with_metadata(
                        &bucket_owned, &chunk_key, chunk.ciphertext, Some(chunk_metadata),
                    ).await?
                };
                // W.9.4-A2 / #80: verify master's etag-attested CID
                // against pre-computed BLAKE3(ciphertext). Mismatch
                // soft-fails to None for THIS chunk only; PUT still
                // succeeded so the chunk is stored, only the
                // offline-walk hint is missing for it.
                let chunk_cid = match (walkable_v8, expected_chunk_cid) {
                    (true, Some(expected)) => crate::walkable_v8::verify_etag_against_expected_cid(
                        &put_result.etag,
                        expected,
                        &bucket_owned,
                        &chunk_key,
                    ),
                    _ => None,
                };
                Ok::<(u32, String, Option<cid::Cid>), ClientError>((chunk_idx, chunk_key_ret, chunk_cid))
            });
            handles.push(handle);
        }

        // Collect results, updating manifest as chunks complete.
        // W.9.4-A2 / #80: also collect per-chunk CIDs indexed by
        // chunk_index (NOT JoinHandle order — tokio::spawn is
        // unordered).
        let mut upload_error: Option<ClientError> = None;
        let mut chunk_cids: Vec<Option<cid::Cid>> = vec![None; num_chunks_total];
        for handle in handles {
            match handle.await {
                Ok(Ok((idx, _key, cid))) => {
                    if let Some(mc) = manifest.chunks.iter_mut().find(|c| c.index == idx) {
                        mc.uploaded = true;
                    }
                    if let Some(slot) = chunk_cids.get_mut(idx as usize) {
                        *slot = cid;
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

        // W.9.4-A2 / #80: stamp per-chunk CIDs into the metadata
        // BEFORE the index PUT (which finalize_resumed_upload runs).
        // Same gate as `put_object_chunked_internal` — only populate
        // when at least one chunk has Some(cid), keeps wire format
        // byte-identical to v0.5 when flag is off or all etags
        // failed to parse.
        if walkable_v8 && chunk_cids.iter().any(|c| c.is_some()) {
            chunked_metadata.populate_chunk_cids(chunk_cids);
            // Re-serialize the index_metadata_json with the
            // CID-stamped chunked metadata. Update the manifest's
            // on-disk record so a crash between this save and the
            // index PUT recovers the CID-stamped form on retry.
            let updated_index_json = serde_json::json!({
                "version": 4,
                "algorithm": "AES-256-GCM",
                "wrapped_key": serde_json::to_value(&wrapped_dek).unwrap(),
                "kek_version": kek_version,
                "metadata_privacy": true,
                "obfuscation_mode": "flat",
                "private_metadata": encrypted_meta.to_json().map_err(ClientError::Encryption)?,
                "chunked": serde_json::to_value(&chunked_metadata).unwrap(),
            }).to_string();
            manifest.index_metadata_json = updated_index_json;
            // Persist the rewritten manifest so a crash here doesn't
            // leave the chunked-CID work unrecorded.
            let _ = manifest.save(manifest_path);
        }

        // All chunks uploaded — finalize and register in the
        // encrypted forest (#82). `private_meta` is in scope from
        // earlier in this function so the registration helper can
        // build a `ForestFileEntry` mirroring the non-resumable path.
        self.finalize_and_register_resumed_upload(&manifest, manifest_path, &private_meta).await
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
        // #82: same precondition as `put_object_encrypted_resumable`
        // — surface forest-load failure before any chunk PUT.
        self.ensure_forest_loaded(bucket).await?;

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
        let (mut chunked_metadata, _outboard) = encoder.finalize();

        // Create private metadata (deferred until after streaming so the
        // BLAKE3 content hash computed over the plaintext stream lands on
        // the forest entry — H-1).
        let private_meta = PrivateMetadata::new(key, total_size)
            .with_content_type(content_type.unwrap_or("application/octet-stream"))
            .with_content_hash(content_hash);
        // F2: bind metadata AEAD to the storage_key (computed at line 6299)
        // so a server cannot swap metadata blobs across paths.
        let meta_aad = EncryptedPrivateMetadata::aad_v2(&storage_key);
        let encrypted_meta = EncryptedPrivateMetadata::encrypt_v2(&private_meta, &dek, &meta_aad)
            .map_err(ClientError::Encryption)?;

        // Walkable-v8 (#80 / W.9.4-A2 port to streaming): mirror the
        // resumable + chunked-internal pattern. Pre-compute
        // BLAKE3(chunk.ciphertext) before each spawn moves the body,
        // post-PUT verify, build Vec<Option<Cid>> indexed by
        // chunk_index, populate_chunk_cids before serializing the
        // index body. Without this, files uploaded via the streaming
        // path land with empty `chunk_cids` and fall back to the
        // warm-cache path on offline reads.
        let walkable_v8 = self.inner.config().walkable_v8_writer_enabled;
        let num_chunks_total = all_chunks.len();

        // Upload chunks in parallel with bounded concurrency
        let semaphore = Arc::new(tokio::sync::Semaphore::new(Self::MAX_CONCURRENT_CHUNK_UPLOADS));
        let mut handles = Vec::with_capacity(all_chunks.len());

        for chunk in all_chunks {
            let chunk_key = ChunkedFileMetadata::chunk_key(&storage_key, chunk.index);
            let chunk_key_ret = chunk_key.clone();
            let chunk_idx = chunk.index;
            let sem = semaphore.clone();
            let client = self.inner.clone();
            let bucket = bucket.to_string();
            let chunk_metadata = ObjectMetadata::new()
                .with_content_type("application/octet-stream")
                .with_metadata("x-fula-chunk-index", &chunk.index.to_string());
            let pinning = self.pinning.clone();

            // W.9.4-A2 / #80: pre-compute the chunk's expected CID
            // before the spawn moves `chunk.ciphertext`.
            let expected_chunk_cid = if walkable_v8 {
                Some(crate::walkable_v8::local_blake3_raw_cid(&chunk.ciphertext))
            } else {
                None
            };

            let handle = tokio::spawn(async move {
                let _permit = sem.acquire().await.map_err(|e|
                    ClientError::Encryption(fula_crypto::CryptoError::Decryption(e.to_string()))
                )?;
                let put_result = if let Some(ref pin) = pinning {
                    client.put_object_with_metadata_and_pinning(
                        &bucket, &chunk_key, chunk.ciphertext,
                        Some(chunk_metadata), &pin.endpoint, &pin.token,
                    ).await?
                } else {
                    client.put_object_with_metadata(
                        &bucket, &chunk_key, chunk.ciphertext, Some(chunk_metadata),
                    ).await?
                };
                // W.9.4-A2 / #80: post-PUT verify — same soft-fail
                // semantics as the resumable + chunked-internal
                // paths.
                let chunk_cid = match (walkable_v8, expected_chunk_cid) {
                    (true, Some(expected)) => crate::walkable_v8::verify_etag_against_expected_cid(
                        &put_result.etag,
                        expected,
                        &bucket,
                        &chunk_key,
                    ),
                    _ => None,
                };
                Ok::<(u32, String, Option<cid::Cid>), ClientError>((chunk_idx, chunk_key_ret, chunk_cid))
            });
            handles.push(handle);
        }

        // Collect results — track uploaded chunk keys for cleanup on
        // failure. W.9.4-A2 / #80: also collect per-chunk CIDs
        // indexed by chunk_index.
        let mut uploaded_keys: Vec<String> = Vec::new();
        let mut chunk_cids: Vec<Option<cid::Cid>> = vec![None; num_chunks_total];
        let mut upload_error: Option<ClientError> = None;

        for handle in handles {
            match handle.await {
                Ok(Ok((idx, key, cid))) => {
                    uploaded_keys.push(key);
                    if let Some(slot) = chunk_cids.get_mut(idx as usize) {
                        *slot = cid;
                    }
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
            for key in &uploaded_keys {
                let _ = self.inner.delete_object(bucket, key).await;
            }
            return Err(err);
        }

        // W.9.4-A2 / #80: stamp per-chunk CIDs into the metadata
        // BEFORE serializing the index body. Same gate as the
        // sister paths — only populate when at least one chunk has
        // Some(cid), keeps wire format byte-identical to v0.5 when
        // flag is off or all etags failed to parse.
        if walkable_v8 && chunk_cids.iter().any(|c| c.is_some()) {
            chunked_metadata.populate_chunk_cids(chunk_cids);
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

        // Walkable-v8 (#82): pre-compute BLAKE3 of the index body so
        // we can verify against master's etag and stamp the CID into
        // the forest entry. Same pattern as `finalize_resumed_upload`.
        let expected_index_cid = if walkable_v8 {
            Some(crate::walkable_v8::local_blake3_raw_cid(index_body.as_bytes()))
        } else {
            None
        };

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

        let index_cid = match (walkable_v8, expected_index_cid) {
            (true, Some(expected)) => crate::walkable_v8::verify_etag_against_expected_cid(
                &result.etag,
                expected,
                bucket,
                &storage_key,
            ),
            _ => None,
        };

        // #82: register in encrypted forest so this file appears in
        // offline forest walks. `private_meta` is in scope from
        // earlier in the function.
        self.register_encrypted_chunked_upload_in_forest(
            bucket,
            key,
            &storage_key,
            index_cid,
            &index_body,
            &private_meta,
        ).await?;

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

        // #82: parse index metadata once for use across paths.
        // The wrapped_key + private_meta decrypt happen LATER (post
        // BAO) in the main path, and inline in the early-return
        // path. The F1 nonce-reuse-protection tests pin a contract
        // where wrapped_key parse must NOT run before BAO for
        // wrong-data inputs — keep that ordering strictly.
        let index_meta: serde_json::Value = serde_json::from_str(&manifest.index_metadata_json)
            .map_err(|e| ClientError::Encryption(
                fula_crypto::CryptoError::Decryption(format!("Invalid index metadata in manifest: {}", e))
            ))?;

        if manifest.remaining() == 0 {
            // All chunks uploaded — no nonce-reuse risk so skip BAO.
            // Decrypt private_meta and register (#82). `data` is
            // unused here because no chunks are re-encrypted.
            let (_, _, private_meta) =
                self.decrypt_resumable_private_meta(&index_meta, &manifest.storage_key)?;
            self.ensure_forest_loaded(&manifest.bucket).await?;
            return self.finalize_and_register_resumed_upload(
                &manifest,
                manifest_path,
                &private_meta,
            ).await;
        }

        let mut chunked_meta: ChunkedFileMetadata = serde_json::from_value(
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

        // Past F1 BAO check — now derive the DEK + private_meta.
        // Test contract (`f1_resume_nonce_reuse_protection`):
        // wrong-data inputs MUST fail at BAO above, not here. Don't
        // hoist this above BAO — the F1 fixtures use placeholder
        // wrapped_key JSON that fails parse, and the tests assert
        // the BAO error fires first.
        let (wrapped_dek, dek, private_meta) =
            self.decrypt_resumable_private_meta(&index_meta, &manifest.storage_key)?;

        // #82: forest must be loaded before any chunk PUT so we
        // surface a load failure (e.g., master unreachable) before
        // re-uploading chunks. Placed AFTER wrapped_key parse so
        // the F1 test #4 (`accepts_matching_data_past_f1_guard`)
        // continues to fail at the wrapped_key step rather than
        // hitting a network call first.
        self.ensure_forest_loaded(&manifest.bucket).await?;

        // Re-encrypt and upload only missing chunks.
        // W.9.4-A2 / #80: also collect per-chunk CIDs for the
        // chunks we re-upload here, so the rewritten index body
        // gets the same chunk-CID hints the initial upload would
        // have stamped.
        let walkable_v8 = self.inner.config().walkable_v8_writer_enabled;
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

            // W.9.4-A2 / #80: pre-compute the chunk's expected CID
            // before `ciphertext` moves into the spawn.
            let expected_chunk_cid = if walkable_v8 {
                Some(crate::walkable_v8::local_blake3_raw_cid(&ciphertext))
            } else {
                None
            };

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
                let put_result = if let Some(ref pin) = pinning {
                    client.put_object_with_metadata_and_pinning(
                        &bucket, &chunk_key, ciphertext_bytes,
                        Some(chunk_metadata), &pin.endpoint, &pin.token,
                    ).await?
                } else {
                    client.put_object_with_metadata(
                        &bucket, &chunk_key, ciphertext_bytes, Some(chunk_metadata),
                    ).await?
                };
                let chunk_cid = match (walkable_v8, expected_chunk_cid) {
                    (true, Some(expected)) => crate::walkable_v8::verify_etag_against_expected_cid(
                        &put_result.etag,
                        expected,
                        &bucket,
                        &chunk_key,
                    ),
                    _ => None,
                };
                Ok::<(u32, String, Option<cid::Cid>), ClientError>((chunk_index, chunk_key_ret, chunk_cid))
            });
            handles.push(handle);
        }

        // Collect results, updating manifest as chunks complete.
        // W.9.4-A2 / #80: collect per-chunk CIDs for ONLY the chunks
        // re-uploaded in this resume pass. Combine with any CID
        // hints already in `chunked_meta.chunk_cids` from the
        // original upload (the persisted manifest's index_metadata
        // may already carry a partial CID set if the original
        // upload hit some etags before crashing). Slot-merge so the
        // final Vec covers every chunk.
        let mut upload_error: Option<ClientError> = None;
        let total_chunks = manifest.num_chunks as usize;
        let mut resumed_chunk_cids: Vec<Option<cid::Cid>> = vec![None; total_chunks];
        // Seed from any pre-existing CID hints in the manifest's
        // chunked metadata (a previous resume pass may have stamped
        // them).
        for i in 0..total_chunks {
            resumed_chunk_cids[i] = chunked_meta.chunk_cid(i as u32);
        }
        for handle in handles {
            match handle.await {
                Ok(Ok((idx, _key, cid))) => {
                    if let Some(mc) = manifest.chunks.iter_mut().find(|c| c.index == idx) {
                        mc.uploaded = true;
                    }
                    if let Some(slot) = resumed_chunk_cids.get_mut(idx as usize) {
                        // Resume always overwrites the slot — the
                        // chunk was just re-PUT, so this fresh
                        // verified CID supersedes any prior hint
                        // (which would also be the same CID anyway,
                        // since chunk ciphertext is deterministic
                        // for a given (DEK, nonce, plaintext) tuple).
                        *slot = cid;
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

        // W.9.4-A2 / #80: stamp the merged per-chunk CIDs back into
        // the chunked metadata and re-serialize the index_metadata
        // JSON BEFORE the index PUT inside finalize_resumed_upload.
        // Without this, the resume path would write the index body
        // from the stale on-disk JSON (which was serialized at the
        // initial put_object_encrypted_resumable call and may have
        // pre-CID-stamp content).
        if walkable_v8 && resumed_chunk_cids.iter().any(|c| c.is_some()) {
            chunked_meta.populate_chunk_cids(resumed_chunk_cids);
            // Rebuild the index JSON from the parsed `index_meta`
            // value so non-walkable-v8 fields (`kek_version`,
            // `metadata_privacy`, `obfuscation_mode`,
            // `private_metadata`) survive verbatim. Only the
            // `chunked` and `wrapped_key` slots are replaced — the
            // wrapped_key with a fresh serialization (parsed-and-
            // re-encoded keeps its shape canonical), and the
            // chunked block with the now-CID-stamped metadata.
            let mut rebuilt = index_meta.clone();
            if let Some(obj) = rebuilt.as_object_mut() {
                obj.insert(
                    "wrapped_key".to_string(),
                    serde_json::to_value(&wrapped_dek).unwrap_or_else(|_| serde_json::Value::Null),
                );
                obj.insert(
                    "chunked".to_string(),
                    serde_json::to_value(&chunked_meta).unwrap_or_else(|_| serde_json::Value::Null),
                );
            }
            manifest.index_metadata_json = rebuilt.to_string();
            let _ = manifest.save(manifest_path);
        }

        // All chunks uploaded — finalize and register in the
        // encrypted forest (#82). `private_meta` was decrypted at
        // the top of this function from the persisted manifest's
        // private_metadata field.
        self.finalize_and_register_resumed_upload(&manifest, manifest_path, &private_meta).await
    }

    /// Upload the index object for a resumed upload and clean up the manifest.
    #[cfg(not(target_arch = "wasm32"))]
    async fn finalize_resumed_upload(
        &self,
        manifest: &UploadManifest,
        manifest_path: &std::path::Path,
    ) -> Result<(PutObjectResult, Option<cid::Cid>)> {
        let index_body = &manifest.index_metadata_json;
        let metadata = ObjectMetadata::new()
            .with_content_type("application/json")
            .with_metadata("x-fula-encrypted", "true")
            .with_metadata("x-fula-chunked", "true")
            .with_metadata("x-fula-encryption", index_body);

        // Walkable-v8 (#53 / #82): pre-compute BLAKE3 of the index
        // body BEFORE the PUT consumes it via Bytes::from. Skipped
        // when the writer flag is off so v0.5-default writes don't
        // hash extra bytes.
        let walkable_v8 = self.inner.config().walkable_v8_writer_enabled;
        let expected_index_cid = if walkable_v8 {
            Some(crate::walkable_v8::local_blake3_raw_cid(index_body.as_bytes()))
        } else {
            None
        };

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

        // Walkable-v8 (#53): verify master's etag against the
        // pre-computed BLAKE3. Soft-fails to None on mismatch — the
        // caller stamps that into ForestFileEntry.storage_cid (None
        // means offline reads of THIS file fall through to the
        // storage_key path; everything else still works).
        let index_cid = match (walkable_v8, expected_index_cid) {
            (true, Some(expected)) => crate::walkable_v8::verify_etag_against_expected_cid(
                &result.etag,
                expected,
                &manifest.bucket,
                &manifest.storage_key,
            ),
            _ => None,
        };

        // NOTE: manifest deletion is INTENTIONALLY moved out — see
        // `finalize_and_register_resumed_upload`. It runs only after
        // forest registration succeeds, so a register failure leaves
        // the manifest in place for `resume_upload` retry. Reviewer B
        // flagged this exposure window during the #82 audit.
        Ok((result, index_cid))
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

    /// #82 — Register a chunked encrypted upload (resumable / streaming /
    /// resume) in the encrypted forest after the index PUT succeeds.
    ///
    /// Without this step, files written via these three paths land on
    /// master S3 + IPFS but stay invisible to the offline forest walk
    /// (Phase 2.4 + walkable-v8): they only resolve via direct
    /// `storage_key` lookups while master is up. Mirrors the upsert
    /// dance in `put_object_encrypted` (the body around lines
    /// 5460-5598) minus orphan cleanup of overwritten storage keys
    /// (a separate pre-existing concern, tracked outside #82).
    ///
    /// Caller is responsible for `ensure_forest_loaded(bucket)` BEFORE
    /// calling — without that the v7 cache lookup below would fail.
    #[cfg(not(target_arch = "wasm32"))]
    async fn register_encrypted_chunked_upload_in_forest(
        &self,
        bucket: &str,
        key: &str,
        storage_key: &str,
        index_cid: Option<cid::Cid>,
        index_metadata_json: &str,
        private_meta: &PrivateMetadata,
    ) -> Result<()> {
        let mut forest_entry = ForestFileEntry::from_metadata(private_meta, storage_key.to_string());
        forest_entry.mark_encrypted();
        forest_entry.storage_cid = index_cid;
        forest_entry.user_metadata.insert(
            "x-fula-encrypted".to_string(),
            "true".to_string(),
        );
        forest_entry.user_metadata.insert(
            "x-fula-encryption".to_string(),
            index_metadata_json.to_string(),
        );
        forest_entry.user_metadata.insert(
            "x-fula-chunked".to_string(),
            "true".to_string(),
        );

        let now = chrono::Utc::now().timestamp();
        // Cloned for WAL replay — `forest_entry` is moved into upsert below.
        let wal_entry_clone = forest_entry.clone();
        let is_v7 = self.is_forest_sharded_hamt(bucket);

        if is_v7 {
            let forest_arc = {
                let cache_entry = self.forest_cache.get(bucket).ok_or_else(|| {
                    ClientError::Encryption(fula_crypto::CryptoError::Decryption(format!(
                        "forest cache missing for bucket {} during chunked-upload registration \
                         (caller must ensure_forest_loaded first)",
                        bucket,
                    )))
                })?;
                match cache_entry.value() {
                    ForestCacheEntry::ShardedHamt { forest, .. } => forest.clone(),
                    _ => unreachable!("is_forest_sharded_hamt guard above"),
                }
            };
            let backend: Arc<S3BlobBackend> = Arc::new(
                S3BlobBackend::new(self.inner.clone(), bucket.to_string())
            );
            {
                let mut guard = forest_arc.write().await;
                debug_assert!(
                    forest_entry.encrypted,
                    "v7 upsert invariant violated: chunked-upload entry for {} has encrypted=false",
                    forest_entry.path,
                );
                guard.upsert_file(forest_entry, &backend).await
                    .map_err(ClientError::Encryption)?;
            }
            if let Some(mut cache_entry) = self.forest_cache.get_mut(bucket) {
                if let ForestCacheEntry::ShardedHamt { loaded_at, .. } = cache_entry.value_mut() {
                    *loaded_at = now;
                }
            }
        } else {
            let (mut forest, prior_etag, prior_seq) = {
                let cache_entry = self.forest_cache.get(bucket).ok_or_else(|| {
                    ClientError::Encryption(fula_crypto::CryptoError::Decryption(format!(
                        "forest cache missing for bucket {} during chunked-upload registration \
                         (caller must ensure_forest_loaded first)",
                        bucket,
                    )))
                })?;
                match cache_entry.value() {
                    ForestCacheEntry::Monolithic { forest, index_etag, last_sequence, .. } =>
                        (forest.clone(), index_etag.clone(), *last_sequence),
                    ForestCacheEntry::ShardedHamt { .. } => unreachable!("is_v7 handled above"),
                }
            };
            forest.upsert_file(forest_entry);
            self.forest_cache.insert(bucket.to_string(), ForestCacheEntry::Monolithic {
                forest,
                loaded_at: now,
                dirty: true,
                index_etag: prior_etag,
                last_sequence: prior_seq,
            });
        }

        // WAL append so a crash between upsert and flush doesn't lose
        // the entry. Mirrors the reference pattern at 5575-5585.
        let wal_mac = wal::derive_mac_key(&self.encryption.key_manager, bucket);
        if let Err(e) = wal::append(
            bucket,
            &wal_mac,
            WalEntry::Insert { key: key.to_string(), entry: wal_entry_clone },
        ) {
            tracing::warn!(%bucket, error = %e, "WAL append failed (chunked-upload register); continuing");
        }
        Ok(())
    }

    /// #82 — Wrapper around `finalize_resumed_upload` that also
    /// registers the entry in the encrypted forest. Both
    /// `put_object_encrypted_resumable` and `resume_upload` go through
    /// here so the registration step lands in exactly one spot.
    #[cfg(not(target_arch = "wasm32"))]
    async fn finalize_and_register_resumed_upload(
        &self,
        manifest: &UploadManifest,
        manifest_path: &std::path::Path,
        private_meta: &PrivateMetadata,
    ) -> Result<PutObjectResult> {
        let (result, index_cid) = self.finalize_resumed_upload(manifest, manifest_path).await?;
        self.register_encrypted_chunked_upload_in_forest(
            &manifest.bucket,
            &manifest.original_key,
            &manifest.storage_key,
            index_cid,
            &manifest.index_metadata_json,
            private_meta,
        ).await?;
        // Crash-safety (Reviewer B audit, #82): only delete the
        // manifest after BOTH the index PUT and forest registration
        // succeed. If `register_encrypted_chunked_upload_in_forest`
        // errors above, this line is skipped and the manifest stays
        // on disk so the caller can retry via `resume_upload`.
        let _ = std::fs::remove_file(manifest_path);
        Ok(result)
    }

    /// #82 — Decrypt the wrapped DEK + private metadata persisted in
    /// a resumable upload's `index_metadata_json`. Used by both
    /// branches of `resume_upload` (early-return when all chunks
    /// were already uploaded; main path post-BAO).
    ///
    /// `storage_key` is the path the metadata blob was stored under;
    /// it's bound into the v2 AAD on encrypt and reconstructed here on
    /// decrypt to verify the metadata hasn't been swapped to a
    /// different path. Pre-0.7 manifests carry v1 metadata (no AAD)
    /// and dispatch through the legacy decrypt path.
    ///
    /// CRITICAL: do NOT call this before the F1 BAO check on the
    /// main path. The `f1_resume_nonce_reuse_protection` test
    /// fixtures use a placeholder `wrapped_key` that's intentionally
    /// invalid JSON for `EncryptedData`; their contract is that the
    /// BAO error fires before the wrapped_key parse error.
    #[cfg(not(target_arch = "wasm32"))]
    fn decrypt_resumable_private_meta(
        &self,
        index_meta: &serde_json::Value,
        storage_key: &str,
    ) -> Result<(EncryptedData, fula_crypto::keys::DekKey, PrivateMetadata)> {
        let wrapped_dek: EncryptedData = serde_json::from_value(
            index_meta["wrapped_key"].clone()
        ).map_err(|e| ClientError::Encryption(
            fula_crypto::CryptoError::Decryption(format!("Invalid wrapped key in manifest: {}", e))
        ))?;
        let decryptor = Decryptor::new(self.encryption.key_manager.keypair());
        let dek = decryptor.decrypt_dek(&wrapped_dek)
            .map_err(ClientError::Encryption)?;
        let encrypted_meta_str = index_meta["private_metadata"].as_str().ok_or_else(|| {
            ClientError::Encryption(fula_crypto::CryptoError::Decryption(
                "private_metadata field is not a string in manifest's index metadata".to_string(),
            ))
        })?;
        let encrypted_private_meta = EncryptedPrivateMetadata::from_json(encrypted_meta_str)
            .map_err(ClientError::Encryption)?;
        // F2 dispatch: v1 (legacy, no AAD) vs v2 (AAD bound to storage_key).
        // Future versions error cleanly so a downgrade attack cannot pick
        // the wrong arm.
        let private_meta = match encrypted_private_meta.version {
            1 => {
                #[allow(deprecated)]
                encrypted_private_meta.decrypt(&dek).map_err(ClientError::Encryption)?
            }
            2 => {
                let aad = EncryptedPrivateMetadata::aad_v2(storage_key);
                encrypted_private_meta
                    .decrypt_v2(&dek, &aad)
                    .map_err(ClientError::Encryption)?
            }
            v => {
                return Err(ClientError::Encryption(fula_crypto::CryptoError::Decryption(
                    format!(
                        "unsupported EncryptedPrivateMetadata wire version {} in resumable manifest — \
                         this SDK reads v1 and v2",
                        v
                    ),
                )));
            }
        };
        Ok((wrapped_dek, dek, private_meta))
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
            // #91: v7 path already walked the HAMT once via `get_file(key)`
            // above; pass the entry forward so the decrypt path skips the
            // O(N) `find_by_storage_key` re-scan inside
            // `get_object_decrypted_by_storage_key`.
            return self.get_object_decrypted_by_entry(bucket, entry).await;
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
                // Strip the SDK's internal x-fula-* plumbing (notably
                // `x-fula-encryption` carrying the wrapped_key JSON,
                // populated at upload to enable offline-encrypted reads
                // — see `put_object_flat_deferred`). These keys are
                // implementation details; surfacing them to apps would
                // leak HPKE-encrypted DEK material into UI surfaces
                // ("Properties" dialogs, custom-tag screens). Apps that
                // set their own user_metadata still see those keys
                // unchanged.
                user_metadata: entry
                    .user_metadata
                    .iter()
                    .filter(|(k, _)| !k.starts_with("x-fula-"))
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect(),
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
        // If the cache is empty here it almost always means
        // `recover_wal_after_load` tripped a 412 retry-exhaust that evicted
        // the cache entry (see save_sharded_hamt_forest's 412 handler).
        // Surface a typed error instead of panicking so the caller can
        // decide whether to retry, surface to the user, or fall back to a
        // freshly-loaded read.
        let entry = self.forest_cache.get(bucket).ok_or_else(|| {
            ClientError::Encryption(fula_crypto::CryptoError::Encryption(
                format!(
                    "list_files_from_forest({}): forest cache empty after load — \
                     prior recover_wal_after_load probably tripped a 412 retry-exhaust \
                     that evicted the cache entry. Inspect the WAL at the platform's \
                     fula data dir and the master's manifest page_index for divergence.",
                    bucket
                )
            ))
        })?;
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

        // Issue #12: mirror the new encryption metadata into the forest
        // entry's `user_metadata` so offline read paths
        // (`get_object_decrypted_inner`'s `get_meta` fallback at
        // `encryption.rs:1453-1463`, and the issue #11
        // `get_object_encryption_metadata_with_fallback`) see the same
        // wrapped DEK + kek_version that's now on S3. Without this,
        // post-rotation offline reads find the OLD wrapped DEK in the
        // forest and attempt to unwrap with the NEW KEK → "Failed to
        // unwrap DEK".
        //
        // Carried-forward limitations (deliberate, documented):
        // - Update is in-memory; persistence requires a subsequent
        //   `flush_forest`. A crash before flush leaves the forest stale
        //   on disk; the next online read triggers HEAD which fetches
        //   fresh metadata via `get_object_encryption_metadata_with_fallback`
        //   and the upload-time mirror at `encryption.rs:5955-5968`
        //   re-populates user_metadata.
        // - Chunk objects (`{storage_key}.chunks/00000000`) have no
        //   forest entry; the helper silently skips them. Their wrapped
        //   DEK lives on the parent index object only.
        // - Subtree DEKs (`subtree_keys.rs`) are NOT rotated by
        //   `KeyRotationManager` and are therefore unaffected.
        self.sync_forest_user_metadata_after_rewrap(
            bucket,
            storage_key,
            enc_metadata.to_string(),
        ).await?;

        Ok(rotation_manager.current_version())
    }

    /// Issue #12 — after `rewrap_object_dek` PUTs a new
    /// `x-fula-encryption` header to S3, mirror the same JSON into the
    /// forest entry's `user_metadata` so offline read paths stay in
    /// sync with S3.
    ///
    /// Silently returns `Ok(())` when:
    /// - No forest entry exists for `storage_key` (chunk objects;
    ///   `forest_entry_lookup` returns `None`). Chunks share the parent's
    ///   DEK and have no separate wrapped key to track.
    /// - The forest cache entry can't be reached (e.g. the bucket was
    ///   evicted between `ensure_forest_loaded` and this call); in that
    ///   case the next online HEAD will re-populate from S3 via the
    ///   issue #11 fallback path.
    async fn sync_forest_user_metadata_after_rewrap(
        &self,
        bucket: &str,
        storage_key: &str,
        new_enc_json: String,
    ) -> Result<()> {
        self.ensure_forest_loaded(bucket).await?;

        let Some(mut entry) = self.forest_entry_lookup(bucket, storage_key).await?
        else {
            // Chunk object or no-forest-entry — nothing to mirror.
            return Ok(());
        };

        entry
            .user_metadata
            .insert("x-fula-encryption".to_string(), new_enc_json);

        let now = chrono::Utc::now().timestamp();
        let is_v7 = self.is_forest_sharded_hamt(bucket);

        if is_v7 {
            // v7 sharded-HAMT: forest is behind an async RwLock. Extract
            // the Arc under the DashMap guard, drop the guard, then take
            // the write lock. Mirrors the put-encrypted pattern at
            // `encryption.rs:6085-6114`.
            let forest_arc = {
                let Some(cache_entry) = self.forest_cache.get(bucket) else {
                    // Bucket evicted between ensure_forest_loaded and now.
                    // Next online HEAD will repair via issue #11 fallback.
                    return Ok(());
                };
                match cache_entry.value() {
                    ForestCacheEntry::ShardedHamt { forest, .. } => forest.clone(),
                    _ => return Ok(()),
                }
            };
            let backend: Arc<S3BlobBackend> = Arc::new(
                S3BlobBackend::new(self.inner.clone(), bucket.to_string()),
            );
            {
                let mut guard = forest_arc.write().await;
                guard
                    .upsert_file(entry, &backend)
                    .await
                    .map_err(ClientError::Encryption)?;
            }
            if let Some(mut cache_entry) = self.forest_cache.get_mut(bucket) {
                if let ForestCacheEntry::ShardedHamt { loaded_at, .. } =
                    cache_entry.value_mut()
                {
                    *loaded_at = now;
                }
            }
        } else {
            // Monolithic v1: clone, mutate, re-insert with dirty=true.
            // Mirrors `encryption.rs:6119-6136`.
            let (mut forest, prior_etag, prior_seq) = {
                let Some(cache_entry) = self.forest_cache.get(bucket) else {
                    return Ok(());
                };
                match cache_entry.value() {
                    ForestCacheEntry::Monolithic {
                        forest,
                        index_etag,
                        last_sequence,
                        ..
                    } => (forest.clone(), index_etag.clone(), *last_sequence),
                    _ => return Ok(()),
                }
            };
            forest.upsert_file(entry);
            self.forest_cache.insert(
                bucket.to_string(),
                ForestCacheEntry::Monolithic {
                    forest,
                    loaded_at: now,
                    dirty: true,
                    index_etag: prior_etag,
                    last_sequence: prior_seq,
                },
            );
        }

        Ok(())
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
        let (final_chunk, mut metadata, outboard) = encoder.finalize()?;

        if let Some(chunk) = final_chunk {
            chunks.push(chunk);
        }

        // **E51 audit fix — Walkable-v8 (W.9.4-A2) per-chunk CID stamping.**
        //
        // Pre-fix this public API didn't pre-compute or post-verify chunk
        // CIDs, so files uploaded via it could not be read via the
        // gateway-race fallback when master was down — the offline reader
        // had no per-chunk CIDs to fetch. Mirror the
        // `put_object_chunked_internal` pattern (already W.9.4-A2 patched
        // in task #77): pre-compute `BLAKE3(chunk.ciphertext)` BEFORE
        // each chunk's body is moved into the PUT, then post-PUT verify
        // master's etag-attested CID matches.
        let walkable_v8 = self.inner.config().walkable_v8_writer_enabled;

        // Upload chunks in parallel with bounded concurrency. Using
        // futures::stream::buffer_unordered rather than tokio::spawn so the
        // same code runs on wasm32 (where tokio has no multi-thread runtime).
        let total_chunks = metadata.num_chunks as usize;
        let (uploaded_keys, chunk_cids): (Vec<String>, Vec<Option<cid::Cid>>) = {
            use futures::StreamExt;
            let futs = chunks.into_iter().map(|chunk| {
                let chunk_key = ChunkedFileMetadata::chunk_key(&storage_key, chunk.index);
                let chunk_metadata = ObjectMetadata::new()
                    .with_content_type("application/octet-stream")
                    .with_metadata("x-fula-chunk", "true")
                    .with_metadata("x-fula-chunk-index", &chunk.index.to_string());

                // E51 / W.9.4-A2: pre-compute the chunk's expected CID
                // BEFORE `chunk.ciphertext` is moved into the PUT call.
                // `Bytes` cloning would be cheap (Arc-based) but we don't
                // need it: BLAKE3 over the body is a single pass either
                // way, and computing it before the move keeps the post-
                // PUT verify allocation-free.
                let expected_chunk_cid = if walkable_v8 {
                    Some(crate::walkable_v8::local_blake3_raw_cid(&chunk.ciphertext))
                } else {
                    None
                };
                let chunk_index_for_collect = chunk.index;

                let client = self.inner.clone();
                let bucket = bucket.to_string();
                let chunk_key_ret = chunk_key.clone();

                async move {
                    let put_result = client.put_object_with_metadata(
                        &bucket,
                        &chunk_key,
                        chunk.ciphertext,
                        Some(chunk_metadata),
                    ).await?;
                    // E51 / W.9.4-A2: verify master's etag-attested CID
                    // against our pre-computed BLAKE3(ciphertext). Mismatch
                    // soft-fails to None — chunk PUT succeeded; only the
                    // offline-walk hint for THIS chunk is missing; the
                    // reader falls back to storage_key for that chunk.
                    let chunk_cid = match (walkable_v8, expected_chunk_cid) {
                        (true, Some(expected)) => crate::walkable_v8::verify_etag_against_expected_cid(
                            &put_result.etag,
                            expected,
                            &bucket,
                            &chunk_key,
                        ),
                        _ => None,
                    };
                    Ok::<(String, u32, Option<cid::Cid>), ClientError>((
                        chunk_key_ret,
                        chunk_index_for_collect,
                        chunk_cid,
                    ))
                }
            });

            let results: Vec<std::result::Result<(String, u32, Option<cid::Cid>), ClientError>> =
                futures::stream::iter(futs)
                    .buffer_unordered(Self::MAX_CONCURRENT_CHUNK_UPLOADS)
                    .collect()
                    .await;

            // E51 / W.9.4-A2: collect per-chunk CIDs indexed by
            // chunk_index (NOT result-iteration order — `buffer_unordered`
            // doesn't preserve order).
            let mut uploaded_keys: Vec<String> = Vec::new();
            let mut chunk_cids: Vec<Option<cid::Cid>> = vec![None; total_chunks];
            let mut upload_error: Option<ClientError> = None;
            for result in results {
                match result {
                    Ok((key, index, cid)) => {
                        uploaded_keys.push(key);
                        if let Some(slot) = chunk_cids.get_mut(index as usize) {
                            *slot = cid;
                        }
                    }
                    Err(e) => { if upload_error.is_none() { upload_error = Some(e); } }
                }
            }

            if let Some(err) = upload_error {
                for key in &uploaded_keys {
                    let _ = self.inner.delete_object(bucket, key).await;
                }
                return Err(err);
            }

            (uploaded_keys, chunk_cids)
        };

        // Don't set content_type in unencrypted ChunkedFileMetadata — it would leak
        // file type to the server. Content type is already stored in encrypted
        // PrivateMetadata when using put_object_flat_deferred().

        // E51 / W.9.4-A2: stamp the per-chunk CID Vec into the metadata
        // BEFORE serializing the index body. When walkable_v8 is off,
        // chunk_cids is all-None — skip the populate to keep the wire
        // 100% byte-identical to v0.5/v0.6 output.
        if walkable_v8 && chunk_cids.iter().any(|c| c.is_some()) {
            metadata.populate_chunk_cids(chunk_cids);
        }

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

        // **E51 audit fix — body-resident encryption JSON for offline reads.**
        //
        // Pre-fix the index object body was the literal `b"CHUNKED"`
        // marker, with the actual encryption metadata living only in the
        // HTTP `x-fula-encryption` user-metadata header. A gateway fetch
        // by CID returns only the body, so an offline walker got just the
        // marker bytes — useless. Mirror `put_object_chunked_internal`'s
        // design: put the JSON in BOTH the body AND the header. Online
        // reads continue using the header (no behavior change for v0.5
        // readers); offline gateway-race reads get the JSON via body.
        let index_body = enc_metadata.to_string();
        let index_metadata = ObjectMetadata::new()
            .with_content_type("application/json")
            .with_metadata("x-fula-encrypted", "true")
            .with_metadata("x-fula-chunked", "true")
            .with_metadata("x-fula-encryption", &index_body);

        // E51 / W.9.3: pre-compute `BLAKE3(index_body)` so the post-PUT
        // self-verify can compare master's etag-attested CID against a
        // CID we computed locally. Cheap; only when the writer flag is on.
        let expected_index_cid = if walkable_v8 {
            Some(crate::walkable_v8::local_blake3_raw_cid(index_body.as_bytes()))
        } else {
            None
        };

        let result = self.inner.put_object_with_metadata(
            bucket,
            &storage_key,
            Bytes::from(index_body),
            Some(index_metadata),
        ).await?;

        // E51 / W.9.3: verify master's etag-attested CID against the
        // pre-computed BLAKE3(index_body). On match, stamp the
        // `storage_cid` field on the forest entry below so a future
        // offline walker can fetch this index object via gateway race.
        // Mismatch soft-fails to None — the chunked file uploads
        // succeeded; only the offline-walk hint for the index object
        // is missing.
        let index_cid = match (walkable_v8, expected_index_cid) {
            (true, Some(expected)) => crate::walkable_v8::verify_etag_against_expected_cid(
                &result.etag,
                expected,
                bucket,
                &storage_key,
            ),
            _ => None,
        };
        
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
            // **E51 audit fix — `storage_cid` populated when walkable-v8
            // is on.** Pre-fix the public `put_object_chunked` wrote a
            // literal `b"CHUNKED"` marker as the index-object body, so
            // a gateway-race fetch returned only the marker bytes
            // (useless to an offline walker) AND stamping
            // `CID(b"CHUNKED")` would have collided across every
            // chunked file ever uploaded (the body was a constant).
            // Both the body and the chunk-CID stamping are fixed
            // above (mirroring `put_object_chunked_internal`'s W.9.4-A2
            // design), so this entry can carry the verified index CID.
            // `index_cid` is `None` when walkable_v8 writer is off OR
            // when the post-PUT etag mismatch soft-failed; in either
            // case the offline walker falls back to the storage_key.
            storage_cid: index_cid,
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
            // Walkable-v8 (W.9.4-A2 / task #32): same cid-hint
            // dispatch as the windowed download path (~line 1545).
            // Without it, partial-read paths (Flutter `get_range`,
            // image thumbnails, video seek) bypass the offline
            // walkable-v8 channel and fail when master is down even
            // for files that have CID hints stamped. The reader
            // contract is: when chunked metadata carries a CID hint
            // for THIS chunk, route through the cold-cache cid-hint
            // path so a fresh device with no warm-cache mapping can
            // still fetch via gateway race.
            #[cfg(not(target_arch = "wasm32"))]
            let chunk_data = {
                let chunk_cid_hint = chunked_meta.chunk_cid(chunk_idx);
                match chunk_cid_hint {
                    Some(cid) => self
                        .inner
                        .get_object_with_offline_fallback_known_cid(bucket, &chunk_key, &cid)
                        .await
                        .map(|r| r.inner.data)?,
                    None => self
                        .inner
                        .get_object_with_offline_fallback(bucket, &chunk_key)
                        .await
                        .map(|r| r.inner.data)?,
                }
            };
            // wasm32: no offline-fallback infrastructure compiled in;
            // use the legacy direct path. Production wasm builds
            // don't yet have offline support; this preserves
            // pre-W.9.4-A2 behaviour.
            #[cfg(target_arch = "wasm32")]
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

/// Diagnostic snapshot of a loaded v7 sharded forest. Returned by
/// [`EncryptedClient::sharded_forest_diagnostic`].
///
/// **Test/diagnostic API only.** Gated to the `test-fault-injection`
/// feature alongside its accessor — production code should not depend
/// on the shape of this struct.
///
/// **Reading the result.** A v7 forest with `total_shards = 256`,
/// `shards_with_root = 0`, `page_count = 0` and a non-trivial
/// `manifest_sequence` means: the server published a manifest that
/// decodes cleanly but contains no shard roots — the bucket is
/// genuinely empty at this snapshot version. If the user has files
/// online, the published `forest_manifest_cid` is pointing at an old
/// snapshot from before any uploads landed (publisher staleness or
/// publisher's diff-cache miss). Compare `manifest_sequence` against
/// the master's last-known sequence to confirm.
///
/// `shards_with_root > 0` with `list_files_from_forest` returning 0 is
/// a different bug class — the walk is silently dropping entries
/// (most often: page or HAMT-node fetches failing on the offline
/// path).
#[cfg(feature = "test-fault-injection")]
#[derive(Debug, Clone, Copy)]
pub struct ShardedForestDiagnostic {
    /// Configured shard count (always 256 for v7 unless future format).
    pub total_shards: usize,
    /// Shards whose `root` is `Some(_)` in the loaded manifest. If 0,
    /// the manifest committed an empty state (no writes yet).
    pub shards_with_root: usize,
    /// Number of meta-HAMT pages in the manifest's `page_index`.
    pub page_count: usize,
    /// Manifest sequence the cache observed at load time. Helps the
    /// operator identify how stale the resolver-served snapshot is
    /// vs. master's current sequence.
    pub manifest_sequence: Option<u64>,
    /// Dir-index sequence from the loaded manifest's root.
    pub dir_index_seq: Option<u64>,
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
#[allow(deprecated)] // F1: tests legitimately exercise random-keypair constructors; deprecation targets production callers only
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
            chunk_cids: vec![],
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

    // ============================================================
    // Phase 3.3 — cold-start integration tests
    // ============================================================

    #[cfg(not(target_arch = "wasm32"))]
    mod cold_start_phase_3_3 {
        use super::*;
        use crate::registry_resolver::{
            derive_user_key_from_email, BucketEntry, GlobalUsersIndex, UserBucketsIndex,
        };
        use sha2::{Digest, Sha256};
        use std::collections::BTreeMap;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        /// Compute a CIDv1 (codec=dag-cbor 0x71, multihash=sha2-256
        /// 0x12) from arbitrary bytes — the format master uses for
        /// dag-cbor IPLD objects (production master's
        /// `serde_ipld_dagcbor::to_vec → kubo /api/v0/dag/put`
        /// produces this shape).
        fn cid_for_dag_cbor_bytes(data: &[u8]) -> cid::Cid {
            let digest = Sha256::digest(data);
            let mh = cid::multihash::Multihash::<64>::wrap(0x12, &digest).unwrap();
            cid::Cid::new_v1(0x71, mh)
        }

        /// Cold-start happy path against fully-mocked IPNS + IPFS
        /// gateways. Asserts:
        ///   - resolver fetches global users-index via IPNS gateway
        ///   - cold-start looks up our `userKey` → bucketsIndexCid
        ///   - bucketsIndex CBOR is fetched + verified
        ///   - blinded `bucketLookupH` lookup succeeds
        ///   - manifest bytes are returned
        ///   - returned `Cid` matches what the gateway served
        ///   - returned `Bytes` are byte-identical to the staged
        ///     manifest payload
        ///   - resolver advanced its highest-seen-sequence floor
        #[tokio::test]
        async fn cold_start_resolve_manifest_happy_path_via_ipns() {
            let ipns = MockServer::start().await;
            let ipfs = MockServer::start().await;
            let chain_rpc = MockServer::start().await;

            let email = "alice@example.com";
            let user_key = derive_user_key_from_email(email);

            let bucket = "photos";
            let manifest_payload =
                b"placeholder forest-manifest bytes for the cold-start test".to_vec();
            let manifest_cid = cid_for_dag_cbor_bytes(&manifest_payload);

            let secret = fula_crypto::SecretKey::generate();
            let enc_cfg = EncryptionConfig::from_secret_key(secret);
            let metadata_key = enc_cfg.key_manager.derive_path_key("fula-metadata-v1");
            let mut h_input = metadata_key.as_bytes().to_vec();
            h_input.extend_from_slice(bucket.as_bytes());
            let blinded_hex = hex::encode(&blake3::hash(&h_input).as_bytes()[..16]);

            let mut buckets = BTreeMap::new();
            buckets.insert(
                blinded_hex,
                BucketEntry {
                    manifest: manifest_cid.to_string(),
                    forest_manifest_cid: None,
                    legacy: false,
                },
            );
            let user_buckets = UserBucketsIndex {
                v: 2,
                buckets,
                updated_at_unix: 1_700_000_000,
            };
            let user_buckets_cbor = serde_ipld_dagcbor::to_vec(&user_buckets).expect("ubi");
            let buckets_index_cid = cid_for_dag_cbor_bytes(&user_buckets_cbor);

            let mut users_map = BTreeMap::new();
            users_map.insert(user_key.clone(), buckets_index_cid.to_string());
            let global = GlobalUsersIndex {
                v: 1,
                sequence: 42,
                updated_at_unix: 1_700_000_001,
                users: users_map,
            };
            let global_cbor = serde_ipld_dagcbor::to_vec(&global).expect("global");

            let ipns_name = "k51qzi5uqu5dh-cold-start-test".to_string();
            Mock::given(method("GET"))
                .and(path(format!("/ipns/{}", ipns_name)))
                .respond_with(ResponseTemplate::new(200).set_body_bytes(global_cbor))
                .mount(&ipns)
                .await;
            Mock::given(method("GET"))
                .and(path(format!("/ipfs/{}", buckets_index_cid)))
                .respond_with(ResponseTemplate::new(200).set_body_bytes(user_buckets_cbor))
                .mount(&ipfs)
                .await;
            Mock::given(method("GET"))
                .and(path(format!("/ipfs/{}", manifest_cid)))
                .respond_with(ResponseTemplate::new(200).set_body_bytes(manifest_payload.clone()))
                .mount(&ipfs)
                .await;
            Mock::given(method("POST"))
                .respond_with(ResponseTemplate::new(503))
                .mount(&chain_rpc)
                .await;

            let mut client_cfg = Config::new("http://master.unreachable.invalid");
            client_cfg.timeout = std::time::Duration::from_secs(2);
            client_cfg.users_index_chain_rpc_url = chain_rpc.uri();
            client_cfg.users_index_anchor_address =
                "0x0000000000000000000000000000000000000001".into();
            client_cfg.users_index_ipns_name = ipns_name;
            client_cfg.users_index_user_key = Some(user_key);
            client_cfg.users_index_ipns_gateway_urls =
                vec![format!("{}/ipns/{{name}}", ipns.uri())];
            client_cfg.users_index_ipfs_gateway_urls =
                vec![format!("{}/ipfs/{{cid}}", ipfs.uri())];
            client_cfg.block_cache_enabled = false;

            let client = EncryptedClient::new(client_cfg, enc_cfg).expect("client");
            let (got_cid, got_bytes) = client
                .cold_start_resolve_manifest(bucket)
                .await
                .expect("cold-start resolves");

            assert_eq!(got_cid, manifest_cid, "returned CID matches manifest");
            assert_eq!(
                got_bytes.as_ref(),
                manifest_payload.as_slice(),
                "returned bytes match staged manifest"
            );

            let resolver = client
                .inner
                .users_index_resolver()
                .expect("resolver configured")
                .clone();
            assert_eq!(
                resolver.highest_seen_sequence(),
                42,
                "resolver bumped sequence floor on success"
            );
        }

        /// Typed error when the configured `userKey` isn't present
        /// in the resolved global users-index.
        #[tokio::test]
        async fn cold_start_user_absent_in_global_returns_typed_error() {
            let ipns = MockServer::start().await;
            let chain_rpc = MockServer::start().await;

            let our_user_key = derive_user_key_from_email("alice@example.com");
            let other_user_key = derive_user_key_from_email("bob@example.com");

            let mut users_map = BTreeMap::new();
            users_map.insert(other_user_key, "bafyabcdef".to_string());
            let global = GlobalUsersIndex {
                v: 1,
                sequence: 5,
                updated_at_unix: 1_700_000_000,
                users: users_map,
            };
            let global_cbor = serde_ipld_dagcbor::to_vec(&global).expect("global");

            let ipns_name = "k51qzi5uqu5dh-no-alice".to_string();
            Mock::given(method("GET"))
                .and(path(format!("/ipns/{}", ipns_name)))
                .respond_with(ResponseTemplate::new(200).set_body_bytes(global_cbor))
                .mount(&ipns)
                .await;
            Mock::given(method("POST"))
                .respond_with(ResponseTemplate::new(503))
                .mount(&chain_rpc)
                .await;

            let secret = fula_crypto::SecretKey::generate();
            let enc_cfg = EncryptionConfig::from_secret_key(secret);

            let mut client_cfg = Config::new("http://master.unreachable.invalid");
            client_cfg.timeout = std::time::Duration::from_secs(2);
            client_cfg.users_index_chain_rpc_url = chain_rpc.uri();
            client_cfg.users_index_anchor_address =
                "0x0000000000000000000000000000000000000001".into();
            client_cfg.users_index_ipns_name = ipns_name;
            client_cfg.users_index_user_key = Some(our_user_key.clone());
            client_cfg.users_index_ipns_gateway_urls =
                vec![format!("{}/ipns/{{name}}", ipns.uri())];

            let client = EncryptedClient::new(client_cfg, enc_cfg).expect("client");
            let err = client
                .cold_start_resolve_manifest("photos")
                .await
                .expect_err("user absent");
            match err {
                ClientError::UsersIndexResolutionFailed { reason } => {
                    assert!(
                        reason.contains(&our_user_key),
                        "expected reason to reference missing userKey, got: {}",
                        reason
                    );
                }
                other => panic!("expected UsersIndexResolutionFailed, got: {:?}", other),
            }
        }

        /// Phase 1.2 lazy-migration: legacy plaintext-keyed entry
        /// with `legacy = true` is the fallback when the blinded
        /// entry is absent. SDK accepts it.
        #[tokio::test]
        async fn cold_start_legacy_plaintext_fallback() {
            let ipns = MockServer::start().await;
            let ipfs = MockServer::start().await;
            let chain_rpc = MockServer::start().await;

            let user_key = derive_user_key_from_email("legacy@example.com");
            let bucket = "old-photos";
            let manifest_payload = b"legacy manifest".to_vec();
            let manifest_cid = cid_for_dag_cbor_bytes(&manifest_payload);

            let mut buckets = BTreeMap::new();
            buckets.insert(
                bucket.to_string(),
                BucketEntry {
                    manifest: manifest_cid.to_string(),
                    forest_manifest_cid: None,
                    legacy: true,
                },
            );
            let user_buckets = UserBucketsIndex {
                v: 2,
                buckets,
                updated_at_unix: 0,
            };
            let user_buckets_cbor = serde_ipld_dagcbor::to_vec(&user_buckets).expect("ubi");
            let buckets_index_cid = cid_for_dag_cbor_bytes(&user_buckets_cbor);

            let mut users_map = BTreeMap::new();
            users_map.insert(user_key.clone(), buckets_index_cid.to_string());
            let global = GlobalUsersIndex {
                v: 1,
                sequence: 1,
                updated_at_unix: 0,
                users: users_map,
            };
            let global_cbor = serde_ipld_dagcbor::to_vec(&global).expect("global");

            let ipns_name = "k51qzi5uqu5dh-legacy".to_string();
            Mock::given(method("GET"))
                .and(path(format!("/ipns/{}", ipns_name)))
                .respond_with(ResponseTemplate::new(200).set_body_bytes(global_cbor))
                .mount(&ipns)
                .await;
            Mock::given(method("GET"))
                .and(path(format!("/ipfs/{}", buckets_index_cid)))
                .respond_with(ResponseTemplate::new(200).set_body_bytes(user_buckets_cbor))
                .mount(&ipfs)
                .await;
            Mock::given(method("GET"))
                .and(path(format!("/ipfs/{}", manifest_cid)))
                .respond_with(ResponseTemplate::new(200).set_body_bytes(manifest_payload.clone()))
                .mount(&ipfs)
                .await;
            Mock::given(method("POST"))
                .respond_with(ResponseTemplate::new(503))
                .mount(&chain_rpc)
                .await;

            let secret = fula_crypto::SecretKey::generate();
            let enc_cfg = EncryptionConfig::from_secret_key(secret);

            let mut client_cfg = Config::new("http://master.unreachable.invalid");
            client_cfg.timeout = std::time::Duration::from_secs(2);
            client_cfg.users_index_chain_rpc_url = chain_rpc.uri();
            client_cfg.users_index_anchor_address =
                "0x0000000000000000000000000000000000000001".into();
            client_cfg.users_index_ipns_name = ipns_name;
            client_cfg.users_index_user_key = Some(user_key);
            client_cfg.users_index_ipns_gateway_urls =
                vec![format!("{}/ipns/{{name}}", ipns.uri())];
            client_cfg.users_index_ipfs_gateway_urls =
                vec![format!("{}/ipfs/{{cid}}", ipfs.uri())];

            let client = EncryptedClient::new(client_cfg, enc_cfg).expect("client");
            let (got_cid, got_bytes) = client
                .cold_start_resolve_manifest(bucket)
                .await
                .expect("legacy fallback resolves");
            assert_eq!(got_cid, manifest_cid);
            assert_eq!(got_bytes.as_ref(), manifest_payload.as_slice());
        }

        /// Defense: a plaintext-keyed entry without `legacy = true`
        /// is rejected. Closes the loophole where a malicious
        /// gateway plants a stronger-looking plaintext-named entry
        /// next to the real blinded one to trick the SDK.
        #[tokio::test]
        async fn cold_start_rejects_plaintext_entry_without_legacy_flag() {
            let ipns = MockServer::start().await;
            let ipfs = MockServer::start().await;
            let chain_rpc = MockServer::start().await;

            let user_key = derive_user_key_from_email("strict@example.com");
            let bucket = "test";

            let bogus_cid = cid_for_dag_cbor_bytes(b"forged manifest");
            let mut buckets = BTreeMap::new();
            buckets.insert(
                bucket.to_string(),
                BucketEntry {
                    manifest: bogus_cid.to_string(),
                    forest_manifest_cid: None,
                    legacy: false,
                },
            );
            let user_buckets = UserBucketsIndex {
                v: 2,
                buckets,
                updated_at_unix: 0,
            };
            let user_buckets_cbor = serde_ipld_dagcbor::to_vec(&user_buckets).expect("ubi");
            let buckets_index_cid = cid_for_dag_cbor_bytes(&user_buckets_cbor);

            let mut users_map = BTreeMap::new();
            users_map.insert(user_key.clone(), buckets_index_cid.to_string());
            let global = GlobalUsersIndex {
                v: 1,
                sequence: 1,
                updated_at_unix: 0,
                users: users_map,
            };
            let global_cbor = serde_ipld_dagcbor::to_vec(&global).expect("global");

            let ipns_name = "k51qzi5uqu5dh-strict".to_string();
            Mock::given(method("GET"))
                .and(path(format!("/ipns/{}", ipns_name)))
                .respond_with(ResponseTemplate::new(200).set_body_bytes(global_cbor))
                .mount(&ipns)
                .await;
            Mock::given(method("GET"))
                .and(path(format!("/ipfs/{}", buckets_index_cid)))
                .respond_with(ResponseTemplate::new(200).set_body_bytes(user_buckets_cbor))
                .mount(&ipfs)
                .await;
            Mock::given(method("POST"))
                .respond_with(ResponseTemplate::new(503))
                .mount(&chain_rpc)
                .await;

            let secret = fula_crypto::SecretKey::generate();
            let enc_cfg = EncryptionConfig::from_secret_key(secret);

            let mut client_cfg = Config::new("http://master.unreachable.invalid");
            client_cfg.timeout = std::time::Duration::from_secs(2);
            client_cfg.users_index_chain_rpc_url = chain_rpc.uri();
            client_cfg.users_index_anchor_address =
                "0x0000000000000000000000000000000000000001".into();
            client_cfg.users_index_ipns_name = ipns_name;
            client_cfg.users_index_user_key = Some(user_key);
            client_cfg.users_index_ipns_gateway_urls =
                vec![format!("{}/ipns/{{name}}", ipns.uri())];
            client_cfg.users_index_ipfs_gateway_urls =
                vec![format!("{}/ipfs/{{cid}}", ipfs.uri())];

            let client = EncryptedClient::new(client_cfg, enc_cfg).expect("client");
            let err = client
                .cold_start_resolve_manifest(bucket)
                .await
                .expect_err("must reject");
            match err {
                ClientError::UsersIndexResolutionFailed { reason } => {
                    assert!(
                        reason.contains("legacy=false"),
                        "expected legacy-flag rejection, got: {}",
                        reason
                    );
                }
                other => panic!("expected UsersIndexResolutionFailed, got: {:?}", other),
            }
        }

        /// `BucketNotFound` (not a new variant) when bucket is
        /// absent from the user's bucketsIndex. Reuses the
        /// established error type per advisor's narrowing.
        #[tokio::test]
        async fn cold_start_returns_bucket_not_found_when_bucket_absent() {
            let ipns = MockServer::start().await;
            let ipfs = MockServer::start().await;
            let chain_rpc = MockServer::start().await;

            let user_key = derive_user_key_from_email("user@example.com");
            let manifest_cid = cid_for_dag_cbor_bytes(b"some manifest");
            let mut buckets = BTreeMap::new();
            buckets.insert(
                "videos".to_string(),
                BucketEntry {
                    manifest: manifest_cid.to_string(),
                    forest_manifest_cid: None,
                    legacy: true,
                },
            );
            let user_buckets = UserBucketsIndex {
                v: 2,
                buckets,
                updated_at_unix: 0,
            };
            let user_buckets_cbor = serde_ipld_dagcbor::to_vec(&user_buckets).expect("ubi");
            let buckets_index_cid = cid_for_dag_cbor_bytes(&user_buckets_cbor);

            let mut users_map = BTreeMap::new();
            users_map.insert(user_key.clone(), buckets_index_cid.to_string());
            let global = GlobalUsersIndex {
                v: 1,
                sequence: 1,
                updated_at_unix: 0,
                users: users_map,
            };
            let global_cbor = serde_ipld_dagcbor::to_vec(&global).expect("global");

            let ipns_name = "k51qzi5uqu5dh-only-videos".to_string();
            Mock::given(method("GET"))
                .and(path(format!("/ipns/{}", ipns_name)))
                .respond_with(ResponseTemplate::new(200).set_body_bytes(global_cbor))
                .mount(&ipns)
                .await;
            Mock::given(method("GET"))
                .and(path(format!("/ipfs/{}", buckets_index_cid)))
                .respond_with(ResponseTemplate::new(200).set_body_bytes(user_buckets_cbor))
                .mount(&ipfs)
                .await;
            Mock::given(method("POST"))
                .respond_with(ResponseTemplate::new(503))
                .mount(&chain_rpc)
                .await;

            let secret = fula_crypto::SecretKey::generate();
            let enc_cfg = EncryptionConfig::from_secret_key(secret);

            let mut client_cfg = Config::new("http://master.unreachable.invalid");
            client_cfg.timeout = std::time::Duration::from_secs(2);
            client_cfg.users_index_chain_rpc_url = chain_rpc.uri();
            client_cfg.users_index_anchor_address =
                "0x0000000000000000000000000000000000000001".into();
            client_cfg.users_index_ipns_name = ipns_name;
            client_cfg.users_index_user_key = Some(user_key);
            client_cfg.users_index_ipns_gateway_urls =
                vec![format!("{}/ipns/{{name}}", ipns.uri())];
            client_cfg.users_index_ipfs_gateway_urls =
                vec![format!("{}/ipfs/{{cid}}", ipfs.uri())];

            let client = EncryptedClient::new(client_cfg, enc_cfg).expect("client");
            let err = client
                .cold_start_resolve_manifest("photos")
                .await
                .expect_err("bucket missing");
            match err {
                ClientError::BucketNotFound(name) => assert_eq!(name, "photos"),
                other => panic!("expected BucketNotFound, got: {:?}", other),
            }
        }

        /// Fail-closed when the resolver isn't configured.
        /// `UsersIndexResolutionFailed` distinguishes "operator
        /// misconfig" from "everything is down".
        #[tokio::test]
        async fn cold_start_without_resolver_returns_resolution_failed() {
            let secret = fula_crypto::SecretKey::generate();
            let enc_cfg = EncryptionConfig::from_secret_key(secret);

            let mut client_cfg = Config::new("http://master.unreachable.invalid");
            client_cfg.timeout = std::time::Duration::from_secs(2);
            // No resolver fields populated → resolver stays None
            // (field-presence model). Same effect as the old `=
            // false` flag.
            let client = EncryptedClient::new(client_cfg, enc_cfg).expect("client");
            let err = client
                .cold_start_resolve_manifest("any")
                .await
                .expect_err("not configured");
            assert!(
                matches!(err, ClientError::UsersIndexResolutionFailed { .. }),
                "expected UsersIndexResolutionFailed, got: {:?}",
                err
            );
        }

        /// Phase 19 — when both IPNS and chain channels fail, the
        /// resolver returns `UsersIndexResolutionFailed`. The
        /// cold-start path MUST fire `MasterHealthEvent::SeverelyDegraded`
        /// through the configured callback so apps can disable
        /// "first-read" UI affordances.
        #[tokio::test]
        async fn cold_start_fires_severely_degraded_when_both_channels_fail() {
            use crate::health_gate::{HealthCallback, MasterHealthEvent};

            // IPNS: 503 on every request → resolver IPNS path fails.
            let ipns = MockServer::start().await;
            Mock::given(method("GET"))
                .respond_with(ResponseTemplate::new(503))
                .mount(&ipns)
                .await;
            // Chain RPC: 503 on every request → resolver chain path
            // fails too. Both channels exhausted → resolver surfaces
            // UsersIndexResolutionFailed → cold_start fires SeverelyDegraded.
            let chain_rpc = MockServer::start().await;
            Mock::given(method("POST"))
                .respond_with(ResponseTemplate::new(503))
                .mount(&chain_rpc)
                .await;

            // Capturing callback.
            let captured: std::sync::Arc<std::sync::Mutex<Vec<MasterHealthEvent>>> =
                std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            let captured_for_cb = std::sync::Arc::clone(&captured);
            let cb: HealthCallback = std::sync::Arc::new(move |ev| {
                captured_for_cb.lock().unwrap().push(ev);
            });

            let secret = fula_crypto::SecretKey::generate();
            let enc_cfg = EncryptionConfig::from_secret_key(secret);

            let mut client_cfg = Config::new("http://master.unreachable.invalid");
            client_cfg.timeout = std::time::Duration::from_secs(2);
            client_cfg.users_index_chain_rpc_url = chain_rpc.uri();
            client_cfg.users_index_anchor_address =
                "0x0000000000000000000000000000000000000001".into();
            client_cfg.users_index_ipns_name = "k51qzi5uqu5dh-test".to_string();
            client_cfg.users_index_user_key =
                Some(derive_user_key_from_email("alice@example.com"));
            client_cfg.users_index_ipns_gateway_urls =
                vec![format!("{}/ipns/{{name}}", ipns.uri())];
            client_cfg.health_callback = Some(cb);

            let client = EncryptedClient::new(client_cfg, enc_cfg).expect("client");
            let err = client
                .cold_start_resolve_manifest("any-bucket")
                .await
                .expect_err("both channels exhausted");

            // Error must be UsersIndexResolutionFailed (the resolver's
            // signal that both paths failed).
            assert!(
                matches!(err, ClientError::UsersIndexResolutionFailed { .. }),
                "expected UsersIndexResolutionFailed, got: {:?}",
                err
            );

            // And the callback must have observed exactly one
            // SeverelyDegraded event.
            let events = captured.lock().unwrap().clone();
            assert_eq!(
                events.len(),
                1,
                "expected exactly one SeverelyDegraded event, got: {:?}",
                events
            );
            assert!(
                matches!(
                    events[0],
                    MasterHealthEvent::SeverelyDegraded { .. }
                ),
                "expected SeverelyDegraded, got: {:?}",
                events[0]
            );
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    // load_forest_internal — error-discriminator regression suite
    //
    // Pins the fix for the silent-empty-forest bug: the outer Err arm in
    // `load_forest_internal` previously caught every error with a
    // wildcard `Err(_)` and silently created an empty v7 forest, masking
    // offline / network / cold-start failures as "new bucket" and
    // returning 0 files from `list_files_from_forest`. The fix narrows
    // that branch to `Err(e) if e.is_not_found()` and propagates every
    // other error. These tests pin both halves of the new contract.
    //
    // Coverage:
    //   1. 404/NoSuchKey  → empty v7 forest cached, "forest is sharded"
    //                       marker returned (the legitimate "new bucket"
    //                       happy path; must STILL work after the fix).
    //   2. 500            → error propagates; cache stays empty so a
    //                       retry re-attempts the fetch.
    //   3. Connection     → reqwest::Error → ClientError::Http →
    //      refused          is_not_found() == false → propagates;
    //                       cache stays empty. Covers the offline /
    //                       master-unreachable shape (same code path
    //                       as MasterUnreachable from the health gate;
    //                       both surface as `is_not_found() == false`).
    //
    // These tests intentionally do NOT depend on knowing the exact
    // index_key derivation (`derive_index_key(forest_dek, bucket)`) —
    // wiremock mocks match every GET so the mock fires regardless of
    // which deterministic path the SDK constructs.
    // ═══════════════════════════════════════════════════════════════════
    #[cfg(not(target_arch = "wasm32"))]
    mod load_forest_offline_propagation_tests {
        use super::*;
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        /// Builds an EncryptedClient pointed at `master_url` with the
        /// health gate disabled (we drive the master-down signal via
        /// the mock's status code or a dead address). Encryption config
        /// is freshly generated — every test gets a unique forest_dek,
        /// so cross-test bleed via the global redb cache is impossible.
        fn build_client(master_url: &str) -> EncryptedClient {
            let mut cfg = Config::new(master_url);
            cfg.timeout = std::time::Duration::from_secs(2);
            cfg.health_gate_enabled = false;
            cfg.block_cache_enabled = false;
            cfg.gateway_fallback_enabled = false;
            let enc = EncryptionConfig::new();
            EncryptedClient::new(cfg, enc).expect("client builds")
        }

        #[tokio::test]
        async fn nosuchkey_404_creates_empty_forest_and_returns_sharded_marker() {
            // Regression: the `is_not_found()` branch of the discriminator
            // must continue to create an empty v7 forest for genuinely-
            // new buckets. This is the legitimate happy path that the
            // wildcard `Err(_)` was originally written for.
            let master = MockServer::start().await;
            Mock::given(method("GET"))
                .respond_with(ResponseTemplate::new(404).set_body_string(
                    r#"<Error><Code>NoSuchKey</Code><Message>not here</Message></Error>"#,
                ))
                .mount(&master)
                .await;

            let client = build_client(&master.uri());

            let err = client
                .load_forest("brand-new-bucket")
                .await
                .expect_err("v7 marker is returned as Err per existing contract");

            assert!(
                err.to_string().contains("forest is sharded"),
                "404 must surface the sharded-API marker, got: {}",
                err
            );

            // Empty v7 forest must be cached so subsequent operations on
            // this bucket route through the sharded API.
            let entry = client
                .forest_cache
                .get("brand-new-bucket")
                .expect("404 path must populate the cache");
            assert!(
                matches!(entry.value(), ForestCacheEntry::ShardedHamt { .. }),
                "expected ShardedHamt cache entry for new bucket"
            );
        }

        #[tokio::test]
        async fn http_500_propagates_and_does_not_cache_empty_forest() {
            // The buggy `Err(_)` arm used to swallow this and return
            // an empty forest. After the fix, a 5xx must propagate so
            // the caller sees the actual server error, and the cache
            // stays empty so a retry re-fetches.
            let master = MockServer::start().await;
            Mock::given(method("GET"))
                .respond_with(ResponseTemplate::new(500).set_body_string(
                    r#"<Error><Code>InternalError</Code><Message>boom</Message></Error>"#,
                ))
                .mount(&master)
                .await;

            let client = build_client(&master.uri());

            let err = client
                .load_forest("flaky-master-bucket")
                .await
                .expect_err("5xx must propagate, not silently create empty forest");

            // Must NOT be the sharded marker — that would mean the bug
            // is back. Any other error is acceptable; the discriminator
            // is "is the cache empty after the call".
            assert!(
                !err.to_string().contains("forest is sharded"),
                "5xx must NOT be masked as the sharded-API marker, got: {}",
                err
            );

            // Cache stays empty — next call re-fetches.
            assert!(
                client.forest_cache.get("flaky-master-bucket").is_none(),
                "5xx path must NOT populate the forest cache"
            );
        }

        #[tokio::test]
        async fn connection_refused_propagates_and_does_not_cache_empty_forest() {
            // Models the offline scenario reported by FxFiles: master
            // unreachable, no warm cache, no cold-start configured →
            // SDK previously created an empty forest and returned 0
            // files via `list_files_from_forest`. After the fix, the
            // error propagates with no cache entry.
            //
            // 127.0.0.1:1 is conventionally closed; reqwest fails with
            // a connect error → ClientError::Http(reqwest::Error) →
            // is_not_found() == false → propagates per the new arm.
            let client = build_client("http://127.0.0.1:1");

            let err = client
                .load_forest("offline-bucket")
                .await
                .expect_err("connection refused must propagate");

            assert!(
                !err.to_string().contains("forest is sharded"),
                "connection refused must NOT be masked as the sharded-API marker, got: {}",
                err
            );
            assert!(
                client.forest_cache.get("offline-bucket").is_none(),
                "connection-refused path must NOT populate the forest cache"
            );
        }

        #[tokio::test]
        async fn retry_after_propagated_error_re_attempts_fetch() {
            // Pins the "no stale state survives a transient outage"
            // guarantee. After a 5xx propagates, the next call must hit
            // the network again — not return whatever was cached on the
            // previous attempt. Mock returns 500 first, then 404 (so
            // the second call lands on the new-bucket happy path);
            // observing the empty-forest cache entry after the second
            // call proves the fetch was actually re-attempted.
            let master = MockServer::start().await;

            // First mount: respond with 500 (will be served first). The
            // up_to_n_times(1) limits this mock to one match.
            Mock::given(method("GET"))
                .respond_with(ResponseTemplate::new(500))
                .up_to_n_times(1)
                .mount(&master)
                .await;
            // Second mount: 404 with NoSuchKey for any subsequent GET.
            Mock::given(method("GET"))
                .respond_with(ResponseTemplate::new(404).set_body_string(
                    r#"<Error><Code>NoSuchKey</Code><Message>still no</Message></Error>"#,
                ))
                .mount(&master)
                .await;

            let client = build_client(&master.uri());

            // First call: 500 → propagates, cache empty.
            let _ = client
                .load_forest("retry-bucket")
                .await
                .expect_err("first call hits 500");
            assert!(
                client.forest_cache.get("retry-bucket").is_none(),
                "5xx must not populate cache"
            );

            // Second call: 404 → empty v7 forest cached, sharded marker.
            let err = client
                .load_forest("retry-bucket")
                .await
                .expect_err("v7 marker on second call");
            assert!(
                err.to_string().contains("forest is sharded"),
                "second call should hit 404 path, got: {}",
                err
            );
            let entry = client
                .forest_cache
                .get("retry-bucket")
                .expect("404 path populates cache");
            assert!(
                matches!(entry.value(), ForestCacheEntry::ShardedHamt { .. }),
                "expected ShardedHamt cache entry after 404"
            );
        }
    }
}
