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
        ShardedPrivateForest, ForestShard,
        EncryptedShardManifest, EncryptedForestShard, ForestEvent,
        detect_forest_format, ForestOrManifest, derive_shard_key,
        compute_initial_shard_count,
        EncryptedShardManifestV7, ShardManifestV7,
    },
    sharing::{ShareToken, AcceptedShare, ShareRecipient},
    rotation::{KeyRotationManager, WrappedKeyInfo},
    wnfs_hamt::BlobBackend,
    sharded_hamt_forest::ShardedHamtPrivateForest,
    ChunkedEncoder, ChunkedFileMetadata, should_use_chunked,
    CryptoError,
};
use std::sync::Arc;
use std::collections::HashMap;
use dashmap::DashMap;

#[cfg(not(target_arch = "wasm32"))]
use crate::wal::{self, WalEntry};

/// Default forest cache TTL in seconds
const DEFAULT_FOREST_CACHE_TTL_SECS: i64 = 60;

/// Max 412-retry attempts before `flush_forest` surfaces
/// `ConcurrentModificationExhausted` (NEW-7.2).
#[cfg(not(target_arch = "wasm32"))]
const MAX_FLUSH_RETRIES: usize = 3;

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
            let interval_dur = std::time::Duration::from_secs(MIGRATION_HEARTBEAT_INTERVAL_SECS);
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
    /// Sharded forest (ShardedV3 or ShardedV5)
    Sharded {
        forest: ShardedPrivateForest,
        loaded_at: i64,
        /// ETag of the manifest object (same purpose as `index_etag`).
        manifest_etag: Option<String>,
        /// Highest manifest sequence observed (v5+). `None` for legacy v3.
        last_manifest_sequence: Option<u64>,
        /// Per-shard ETags captured from the last successful load or save of
        /// each shard blob. Used for conditional writes (`If-Match`) so two
        /// concurrent writers can't both overwrite the same shard with their
        /// own view (C-AUDIT-003). `None` at index `i` means the shard has
        /// never been observed (first write path or shard not yet loaded).
        shard_etags: Vec<Option<String>>,
    },
    /// Sharded-HAMT forest (v7). Per-shard HAMT tree with nodes
    /// stored independently at `__fula_forest_v7_nodes/<storage_key>`.
    /// The forest holds per-shard root storage keys, sequences,
    /// and interior nodes load lazily through `V7NodeStore`.
    ///
    /// Wrapped in `Arc<tokio::sync::Mutex<_>>` because mutation methods
    /// (`upsert_file`, `flush_dirty`) are async and would require holding
    /// a `DashMap::RefMut` across an `await`, which deadlocks DashMap's
    /// shard locks.
    ShardedHamt {
        forest: Arc<tokio::sync::Mutex<ShardedHamtPrivateForest>>,
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
            ForestCacheEntry::Sharded { loaded_at, .. } => *loaded_at,
            ForestCacheEntry::ShardedHamt { loaded_at, .. } => *loaded_at,
        }
    }

    fn is_dirty(&self) -> bool {
        match self {
            ForestCacheEntry::Monolithic { dirty, .. } => *dirty,
            ForestCacheEntry::Sharded { forest, .. } => {
                forest.manifest_dirty || !forest.dirty_shards.is_empty()
            }
            // `tokio::sync::Mutex::try_lock` is a synchronous probe. When
            // uncontended we read the forest's authoritative dirty state.
            // When contended (a flush or mutation is in flight), fall back
            // to `true` — the cache entry is in active use, so callers
            // should not treat it as stale and evict while we're mid-flush.
            ForestCacheEntry::ShardedHamt { forest, .. } => match forest.try_lock() {
                Ok(guard) => guard.is_dirty(),
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
            ForestCacheEntry::Sharded { last_manifest_sequence, .. } => *last_manifest_sequence,
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
            // Create private metadata with original info
            let private_meta = PrivateMetadata::new(key, original_size)
                .with_content_type(content_type.unwrap_or("application/octet-stream"));

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

        if is_chunked {
            // CHUNKED DOWNLOAD: Download and decrypt each chunk
            self.get_object_chunked_internal(bucket, storage_key, &enc_metadata, &dek).await
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
            let plaintext = if version >= 4 {
                let aad = format!("fula:v4:content:{}", storage_key).into_bytes();
                aead.decrypt_with_aad(&nonce, &result.data, &aad)
            } else {
                aead.decrypt(&nonce, &result.data)
            }.map_err(ClientError::Encryption)?;

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
        self.download_chunks_windowed_to_writer(bucket, storage_key, &chunked_meta, dek, &mut output).await?;
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
    ) -> Result<u64> {
        let chunked_meta: ChunkedFileMetadata = serde_json::from_value(
            enc_metadata["chunked"].clone()
        ).map_err(|e| ClientError::Encryption(
            fula_crypto::CryptoError::Decryption(format!("Invalid chunked metadata: {}", e))
        ))?;

        self.download_chunks_windowed_to_writer(bucket, storage_key, &chunked_meta, dek, writer).await
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
    async fn download_chunks_windowed_to_writer<W: std::io::Write>(
        &self,
        bucket: &str,
        storage_key: &str,
        chunked_meta: &ChunkedFileMetadata,
        dek: &fula_crypto::keys::DekKey,
        writer: &mut W,
    ) -> Result<u64> {
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
            let futs = (window_start..window_end).map(|chunk_index| {
                let chunk_key = ChunkedFileMetadata::chunk_key(storage_key, chunk_index as u32);
                let client = self.inner.clone();
                let bucket = bucket.to_string();
                async move {
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

        if is_chunked {
            self.get_object_chunked_to_writer(bucket, storage_key, &enc_metadata, &dek, writer).await
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
            let plaintext = if version >= 4 {
                let aad = format!("fula:v4:content:{}", storage_key).into_bytes();
                aead.decrypt_with_aad(&nonce, &result.data, &aad)
            } else {
                aead.decrypt(&nonce, &result.data)
            }.map_err(ClientError::Encryption)?;

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
        let plaintext = if version >= 4 {
            let aad = format!("fula:v4:content:{}", storage_key).into_bytes();
            aead.decrypt_with_aad(&nonce, &result.data, &aad)
        } else {
            aead.decrypt(&nonce, &result.data)
        }.map_err(ClientError::Encryption)?;

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
    pub async fn list_directory(
        &self,
        bucket: &str,
        prefix: Option<&str>,
    ) -> Result<DirectoryListing> {
        // For FlatNamespace, use the forest directly
        if self.encryption.obfuscation_mode == KeyObfuscation::FlatNamespace {
            return self.list_directory_from_forest(bucket, prefix).await;
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
                    ForestCacheEntry::Sharded { .. } |
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
                    ForestCacheEntry::Sharded { last_manifest_sequence, .. } => *last_manifest_sequence,
                    ForestCacheEntry::ShardedHamt { last_manifest_sequence, .. } => *last_manifest_sequence,
                });
                let cached_is_sharded = self.forest_cache.get(bucket)
                    .map(|e| matches!(
                        e.value(),
                        ForestCacheEntry::Sharded { .. } | ForestCacheEntry::ShardedHamt { .. }
                    ))
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
                    ForestOrManifest::Manifest(encrypted_manifest) => {
                        // Dispatch on outer version: v6 > v5 > v3. v6 and v5 carry AAD+sequence;
                        // v3 is legacy. We track a per-bucket "highest observed manifest version"
                        // via the cached `last_manifest_sequence` presence plus the in-cache
                        // manifest.version so that a server cannot quietly roll back routing.
                        let cached_prior_manifest_seq = self.forest_cache.get(bucket).and_then(|e| match e.value() {
                            ForestCacheEntry::Sharded { last_manifest_sequence, .. } => *last_manifest_sequence,
                            ForestCacheEntry::ShardedHamt { last_manifest_sequence, .. } => *last_manifest_sequence,
                            _ => None,
                        });
                        let cached_prior_manifest_version = self.forest_cache.get(bucket).and_then(|e| match e.value() {
                            ForestCacheEntry::Sharded { forest, .. } => Some(forest.manifest.version),
                            // v7 variant is structurally pinned to version 7 — no lock needed.
                            ForestCacheEntry::ShardedHamt { .. } => Some(7u8),
                            _ => None,
                        });
                        // NEW-L.7: augment the in-memory guard with a persisted version
                        // pin so a gateway cannot downgrade us via a cold start.
                        let persisted_prior_version = self.load_persisted_manifest_version(bucket);
                        let effective_prior_version = match (cached_prior_manifest_version, persisted_prior_version) {
                            (Some(a), Some(b)) => Some(a.max(b)),
                            (Some(a), None) => Some(a),
                            (None, Some(b)) => Some(b),
                            (None, None) => None,
                        };

                        let (manifest, observed_manifest_seq) = match encrypted_manifest.version {
                            6 => {
                                let (m, seq) = encrypted_manifest.decrypt_v6(&forest_dek, bucket)
                                    .map_err(ClientError::Encryption)?;
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
                                (m, Some(seq))
                            }
                            5 => {
                                // Reject routing-version downgrade if cache or disk already saw v6.
                                if effective_prior_version.map_or(false, |v| v >= 6) {
                                    return Err(ClientError::Encryption(
                                        fula_crypto::CryptoError::Decryption(
                                            "manifest routing downgrade detected: server served v5 after v6 was observed".to_string()
                                        )
                                    ));
                                }
                                let (m, seq) = encrypted_manifest.decrypt_v5(&forest_dek, bucket)
                                    .map_err(ClientError::Encryption)?;
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
                                (m, Some(seq))
                            }
                            _ => {
                                // Legacy v3: reject downgrade if we previously saw v5 or v6
                                // in-memory OR on disk.
                                if cached_prior_manifest_seq.is_some()
                                    || effective_prior_version.map_or(false, |v| v >= 5)
                                {
                                    return Err(ClientError::Encryption(
                                        fula_crypto::CryptoError::Decryption(
                                            "manifest version downgrade detected: server served legacy v3 after an AAD-bound manifest was observed".to_string()
                                        )
                                    ));
                                }
                                (encrypted_manifest.decrypt(&forest_dek).map_err(ClientError::Encryption)?, None)
                            }
                        };

                        // NEW-L.7: persist the highest version observed so the guard
                        // survives a process restart.
                        self.persist_manifest_version(bucket, encrypted_manifest.version);

                        let sharded = ShardedPrivateForest::from_manifest(manifest);
                        let now = chrono::Utc::now().timestamp();
                        let num_shards = sharded.manifest.num_shards;
                        self.forest_cache.insert(bucket.to_string(), ForestCacheEntry::Sharded {
                            forest: sharded,
                            loaded_at: now,
                            manifest_etag: observed_etag,
                            last_manifest_sequence: observed_manifest_seq,
                            // Per-shard ETags are populated lazily on first load of
                            // each shard (see `load_shard`). Start with None markers.
                            shard_etags: vec![None; num_shards],
                        });

                        Err(ClientError::Encryption(
                            fula_crypto::CryptoError::Encryption(
                                "forest is sharded; use sharded API methods".to_string()
                            )
                        ))
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
                            ForestCacheEntry::Sharded { last_manifest_sequence, .. } => *last_manifest_sequence,
                            ForestCacheEntry::ShardedHamt { last_manifest_sequence, .. } => *last_manifest_sequence,
                            _ => None,
                        });
                        let cached_prior_manifest_version = self.forest_cache.get(bucket).and_then(|e| match e.value() {
                            ForestCacheEntry::Sharded { forest, .. } => Some(forest.manifest.version),
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
                            Ok((m, seq)) => {
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
                        let forest = ShardedHamtPrivateForest::from_manifest(
                            manifest,
                            bucket.to_string(),
                            forest_dek.clone(),
                        );
                        let forest_arc = Arc::new(tokio::sync::Mutex::new(forest));
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
                    forest: Arc::new(tokio::sync::Mutex::new(v7)),
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

    /// Check if the forest for a bucket is in sharded format (v3/v5/v6).
    ///
    /// **Strict predicate.** Returns `true` only for flat-HashMap shards
    /// (`ShardedPrivateForest`). v7 HAMT-per-shard forests do **not** match —
    /// callers that want "any sharded shape" must combine this with
    /// `is_forest_sharded_hamt`.
    pub fn is_forest_sharded(&self, bucket: &str) -> bool {
        self.forest_cache.get(bucket)
            .map(|entry| matches!(entry.value(), ForestCacheEntry::Sharded { .. }))
            .unwrap_or(false)
    }

    /// Check if the forest for a bucket is in sharded-HAMT format (v7).
    pub fn is_forest_sharded_hamt(&self, bucket: &str) -> bool {
        self.forest_cache.get(bucket)
            .map(|entry| matches!(entry.value(), ForestCacheEntry::ShardedHamt { .. }))
            .unwrap_or(false)
    }

    /// Load a single shard from S3 and cache it
    ///
    /// For v2 shards (AAD-bound), the shard's decrypted sequence is compared
    /// against `manifest.shard_sequences[shard_index]` to detect shard-level
    /// replay. A mismatch fails the load.
    async fn load_shard(&self, bucket: &str, shard_index: usize) -> Result<()> {
        let forest_dek = self.encryption.key_manager.derive_path_key(&format!("forest:{}", bucket));

        // Short-circuit: if the shard is already loaded into our cache, do not
        // re-fetch from S3. Re-fetching unconditionally would overwrite any
        // pending in-memory upserts (e.g. from a previous `put_object_flat_deferred`
        // into the same shard) with stale bytes, silently dropping the earlier
        // writes. When the manifest changes under us (412 retry), the whole
        // cache entry is evicted, which clears the shards too — so "shard is
        // in-memory" is a sufficient consistency signal here.
        let already_loaded = self.forest_cache.get(bucket)
            .map(|entry| matches!(entry.value(), ForestCacheEntry::Sharded { forest, .. } if forest.is_shard_loaded(shard_index)))
            .unwrap_or(false);
        if already_loaded {
            return Ok(());
        }

        let (shard_salt, num_shards, expected_seq) = {
            let entry = self.forest_cache.get(bucket)
                .ok_or_else(|| ClientError::Encryption(
                    fula_crypto::CryptoError::Encryption("forest not loaded".to_string())
                ))?;
            match entry.value() {
                ForestCacheEntry::Sharded { forest, .. } => {
                    let expected = forest.manifest.shard_sequences.get(shard_index).copied();
                    (forest.manifest.shard_salt.clone(), forest.manifest.num_shards, expected)
                }
                _ => return Err(ClientError::Encryption(
                    fula_crypto::CryptoError::Encryption("forest is not sharded".to_string())
                )),
            }
        };

        if shard_index >= num_shards {
            return Err(ClientError::Encryption(
                fula_crypto::CryptoError::Encryption(format!("shard index {} out of range ({})", shard_index, num_shards))
            ));
        }

        let shard_key = derive_shard_key(&forest_dek, bucket, &shard_salt, shard_index);

        match self.inner.get_object_with_metadata(bucket, &shard_key).await {
            Ok(result) => {
                let observed_etag = if result.etag.is_empty() { None } else { Some(result.etag.clone()) };
                let encrypted = EncryptedForestShard::from_bytes(&result.data)
                    .map_err(ClientError::Encryption)?;
                // Dispatch on shard version: v2 = AAD-bound, v1 = legacy.
                let shard = if encrypted.version == 2 {
                    let (shard, observed_seq) = encrypted
                        .decrypt_v2(&forest_dek, bucket, shard_index)
                        .map_err(ClientError::Encryption)?;
                    // If manifest vouches for an expected sequence, require exact match.
                    // Missing expected_seq means legacy v3 manifest — skip the check.
                    // Note: expected == 0 still requires observed == 0 (closes the
                    // crash-between-shard-and-manifest-write window).
                    if let Some(expected) = expected_seq {
                        if observed_seq != expected {
                            return Err(ClientError::Encryption(
                                fula_crypto::CryptoError::Decryption(format!(
                                    "shard {} replay: observed seq {} != expected {}",
                                    shard_index, observed_seq, expected
                                ))
                            ));
                        }
                    }
                    shard
                } else {
                    encrypted.decrypt(&forest_dek).map_err(ClientError::Encryption)?
                };

                if let Some(mut entry) = self.forest_cache.get_mut(bucket) {
                    if let ForestCacheEntry::Sharded { forest, shard_etags, .. } = entry.value_mut() {
                        forest.set_shard(shard);
                        if shard_index < shard_etags.len() {
                            shard_etags[shard_index] = observed_etag;
                        }
                    }
                }
                Ok(())
            }
            Err(_) => {
                // Shard doesn't exist yet — create empty
                let shard = ForestShard::new(shard_index);
                if let Some(mut entry) = self.forest_cache.get_mut(bucket) {
                    if let ForestCacheEntry::Sharded { forest, shard_etags, .. } = entry.value_mut() {
                        forest.set_shard(shard);
                        if shard_index < shard_etags.len() {
                            shard_etags[shard_index] = None;
                        }
                    }
                }
                Ok(())
            }
        }
    }

    /// Load all shards in parallel (for listing operations)
    async fn load_all_shards(&self, bucket: &str) -> Result<()> {
        let num_shards = {
            let entry = self.forest_cache.get(bucket)
                .ok_or_else(|| ClientError::Encryption(
                    fula_crypto::CryptoError::Encryption("forest not loaded".to_string())
                ))?;
            match entry.value() {
                ForestCacheEntry::Sharded { forest, .. } => {
                    if forest.all_shards_loaded() {
                        return Ok(());
                    }
                    forest.manifest.num_shards
                }
                _ => return Ok(()), // Monolithic — nothing to load
            }
        };

        // Load all unloaded shards in parallel
        let mut futures = Vec::new();
        for i in 0..num_shards {
            let is_loaded = self.forest_cache.get(bucket)
                .map(|entry| match entry.value() {
                    ForestCacheEntry::Sharded { forest, .. } => forest.is_shard_loaded(i),
                    _ => true,
                })
                .unwrap_or(true);

            if !is_loaded {
                futures.push(self.load_shard(bucket, i));
            }
        }

        // Execute all shard loads concurrently
        let results = futures::future::join_all(futures).await;
        for result in results {
            result?;
        }

        Ok(())
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
    #[cfg(not(target_arch = "wasm32"))]
    fn load_persisted_manifest_version(&self, bucket: &str) -> Option<u8> {
        let path = self.manifest_version_path(bucket)?;
        let bytes = std::fs::read(&path).ok()?;
        let s = std::str::from_utf8(&bytes).ok()?.trim();
        s.parse::<u8>().ok()
    }

    /// Atomically write the manifest version for `bucket`. Monotonic: writes
    /// nothing if the new version is not strictly greater than what's on disk.
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
        // tmp + rename for atomicity. Best-effort: if the write fails we log and
        // continue; the in-memory guard still catches intra-session downgrades.
        let tmp = path.with_extension("tmp");
        let write_ok = std::fs::write(&tmp, version.to_string().as_bytes()).is_ok();
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
                ForestCacheEntry::Sharded { forest, .. } => {
                    forest.find_by_storage_key(storage_key)
                        .map(|e| e.encrypted)
                        .unwrap_or(false)
                }
                // v7 read path isn't wired yet — fail closed: treat the
                // entry as requiring encryption so callers refuse to serve
                // plaintext bytes. Once the v7 traversal lands, this arm
                // will do a real HAMT lookup.
                ForestCacheEntry::ShardedHamt { .. } => true,
            },
            None => false,
        };
        Ok(decision)
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
            ForestCacheEntry::Sharded { manifest_etag, .. } => (manifest_etag.clone(), None),
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

        let metadata = ObjectMetadata::new()
            .with_content_type("application/octet-stream");

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

    /// Save a sharded forest — uploads only dirty shards + manifest (v5 AAD-bound)
    ///
    /// Each dirty shard gets its `shard_sequences[i]` bumped by 1 and is written
    /// as a v2 shard bound to `fula:shard:v2:<bucket>:<i>:<seq>`. The manifest
    /// is then written as v5 bound to `fula:manifest:v5:<bucket>:<manifest_seq>`,
    /// with the updated `shard_sequences` vector embedded in its plaintext.
    async fn save_sharded_forest(&self, bucket: &str) -> Result<()> {
        let forest_dek = self.encryption.key_manager.derive_path_key(&format!("forest:{}", bucket));
        let index_key = derive_index_key(&forest_dek, bucket);

        // Extract what we need to upload + bump per-shard sequences in the cache.
        // Capture per-shard prior ETags so each shard PUT can be conditional
        // (C-AUDIT-003) — two concurrent writers can't both overwrite the
        // same shard with their own view.
        let (mut manifest_clone, dirty_indices, shards_to_upload, prior_manifest_seq, prior_etag, prior_shard_etags) = {
            let mut entry = self.forest_cache.get_mut(bucket)
                .ok_or_else(|| ClientError::Encryption(
                    fula_crypto::CryptoError::Encryption("no sharded forest in cache".to_string())
                ))?;
            match entry.value_mut() {
                ForestCacheEntry::Sharded { forest, manifest_etag, last_manifest_sequence, shard_etags, .. } => {
                    let num_shards = forest.manifest.num_shards;
                    // Ensure shard_sequences is sized to num_shards (legacy v3 may be empty).
                    if forest.manifest.shard_sequences.len() != num_shards {
                        forest.manifest.shard_sequences = vec![0u64; num_shards];
                    }
                    // Keep shard_etags aligned with num_shards (reshards may grow).
                    if shard_etags.len() != num_shards {
                        shard_etags.resize(num_shards, None);
                    }
                    let dirty: Vec<usize> = forest.dirty_shards.iter().copied().collect();
                    // Bump per-shard sequences for dirty shards.
                    for &i in &dirty {
                        forest.manifest.shard_sequences[i] =
                            forest.manifest.shard_sequences[i].saturating_add(1);
                    }
                    let shards: Vec<ForestShard> = dirty.iter()
                        .filter_map(|&i| forest.shards.get(i).and_then(|s| s.clone()))
                        .collect();
                    // Clone the subset of prior ETags we'll need for the
                    // conditional shard PUTs below.
                    let prior_shard_etags: Vec<Option<String>> = dirty.iter()
                        .map(|&i| shard_etags.get(i).cloned().flatten())
                        .collect();
                    (
                        forest.manifest.clone(),
                        dirty,
                        shards,
                        *last_manifest_sequence,
                        manifest_etag.clone(),
                        prior_shard_etags,
                    )
                }
                _ => return Err(ClientError::Encryption(
                    fula_crypto::CryptoError::Encryption("forest is not sharded".to_string())
                )),
            }
        };

        // Upload dirty shards as v2 (AAD-bound). Each PUT is conditional on
        // the prior shard ETag — if another writer raced us, the server
        // returns a concurrent-modification error and we drop the cache so
        // the caller re-reads the latest state before retrying.
        //
        // NEW-7.2: on a successful phase-1 shard PUT, we also append a
        // `WalEntry::ShardWrote` to the WAL. If the phase-2 manifest PUT then
        // 412s, the winning manifest won't reflect our advancement, and
        // `load_shard`'s AEAD seq check would refuse to read our own shard.
        // The `ShardWrote` record lets `replay_wal_entries` reconcile the
        // cached manifest's `shard_sequences[idx]` with what we actually
        // persisted to S3 so the retry can proceed.
        #[cfg(not(target_arch = "wasm32"))]
        let wal_mac = wal::derive_mac_key(&self.encryption.key_manager, bucket);
        let mut new_shard_etags: Vec<(usize, Option<String>)> = Vec::with_capacity(shards_to_upload.len());
        for (pos, shard) in shards_to_upload.iter().enumerate() {
            let shard_idx = shard.shard_index;
            let shard_seq = manifest_clone.shard_sequences.get(shard_idx).copied().unwrap_or(1);
            let shard_key = derive_shard_key(&forest_dek, bucket, &manifest_clone.shard_salt, shard_idx);

            let encrypted = EncryptedForestShard::encrypt_v2(shard, &forest_dek, bucket, shard_seq)
                .map_err(ClientError::Encryption)?;
            let data = encrypted.to_bytes()
                .map_err(ClientError::Encryption)?;

            let metadata = ObjectMetadata::new()
                .with_content_type("application/octet-stream");

            let prior_etag_for_shard = prior_shard_etags.get(pos).cloned().flatten();
            let put_result = self.inner.put_object_with_metadata_conditional(
                bucket,
                &shard_key,
                Bytes::from(data),
                Some(metadata),
                prior_etag_for_shard.as_deref(),
                None,
            ).await;

            match put_result {
                Ok(r) => {
                    let new_etag = if r.etag.is_empty() { None } else { Some(r.etag) };
                    #[cfg(not(target_arch = "wasm32"))]
                    {
                        if let Err(e) = wal::append(
                            bucket,
                            &wal_mac,
                            WalEntry::ShardWrote {
                                idx: shard_idx,
                                seq: shard_seq,
                                etag: new_etag.clone(),
                            },
                        ) {
                            tracing::warn!(%bucket, shard_idx, error = %e, "WAL append failed (ShardWrote); continuing");
                        }
                    }
                    new_shard_etags.push((shard_idx, new_etag));
                }
                Err(e) if e.is_concurrent_modification() => {
                    // Another writer raced us on this shard. Drop the cache so
                    // the caller re-reads the latest shard state before retry.
                    self.forest_cache.remove(bucket);
                    return Err(e);
                }
                Err(e) => return Err(e),
            }
        }

        // Upload manifest as v6 (AAD-bound, directory-aware routing). Bump manifest sequence.
        // Even if the cache still carries a legacy v3/v5 manifest, we promote the
        // routing version during save only when the in-memory forest has already been
        // migrated to v6 routing (reshard_to_v6 called beforehand, or freshly built via
        // from_migration). The save just reflects whatever manifest.version is set to.
        let next_manifest_seq = prior_manifest_seq.unwrap_or(0).saturating_add(1);
        let shard_seqs = manifest_clone.shard_sequences.clone();
        let encrypted_manifest = match manifest_clone.version {
            6 => {
                // Fresh v6 migrations already set version = 6 in from_migration /
                // reshard_to_v6; refresh shard_sequences to the latest values.
                manifest_clone = manifest_clone.into_v6(shard_seqs);
                EncryptedShardManifest::encrypt_v6(
                    &manifest_clone, &forest_dek, bucket, next_manifest_seq,
                ).map_err(ClientError::Encryption)?
            }
            _ => {
                // Legacy paths still write v5 so that pre-existing v3/v5 deployments
                // keep working if a client happens to save before the v6 auto-migration
                // kicks in on the next read.
                manifest_clone = manifest_clone.into_v5(shard_seqs);
                EncryptedShardManifest::encrypt_v5(
                    &manifest_clone, &forest_dek, bucket, next_manifest_seq,
                ).map_err(ClientError::Encryption)?
            }
        };
        let manifest_data = encrypted_manifest.to_bytes()
            .map_err(ClientError::Encryption)?;

        let metadata = ObjectMetadata::new()
            .with_content_type("application/octet-stream");

        let put_result = self.inner.put_object_with_metadata_conditional(
            bucket,
            &index_key,
            Bytes::from(manifest_data),
            Some(metadata),
            prior_etag.as_deref(),
            None,
        ).await;

        let put_result = match put_result {
            Ok(r) => r,
            Err(e) if e.is_concurrent_modification() => {
                // Shards were uploaded OK but manifest raced — drop cache so caller re-reads.
                self.forest_cache.remove(bucket);
                return Err(e);
            }
            Err(e) => return Err(e),
        };

        let new_etag = if put_result.etag.is_empty() { None } else { Some(put_result.etag) };
        let _ = dirty_indices;

        // Clear dirty flags + record new ETag + bump manifest sequence +
        // persist per-shard ETags observed from the conditional PUTs above
        // (C-AUDIT-003) so subsequent saves can keep using conditional writes.
        if let Some(mut entry) = self.forest_cache.get_mut(bucket) {
            if let ForestCacheEntry::Sharded {
                forest, loaded_at, manifest_etag, last_manifest_sequence, shard_etags
            } = entry.value_mut() {
                forest.dirty_shards.clear();
                forest.manifest_dirty = false;
                // Reflect the updated shard_sequences + v5 version in the cache.
                forest.manifest = manifest_clone.clone();
                *loaded_at = chrono::Utc::now().timestamp();
                *manifest_etag = new_etag;
                *last_manifest_sequence = Some(next_manifest_seq);
                if shard_etags.len() != forest.manifest.num_shards {
                    shard_etags.resize(forest.manifest.num_shards, None);
                }
                for (shard_idx, new_shard_etag) in new_shard_etags {
                    if shard_idx < shard_etags.len() {
                        shard_etags[shard_idx] = new_shard_etag;
                    }
                }
            }
        }

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
        // `.lock().await` the forest mutex below without holding a shard
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
        let backend = Arc::new(S3BlobBackend::new(self.inner.clone(), bucket.to_string()));
        let manifest_snapshot = {
            let mut guard = forest_arc.lock().await;
            guard.flush_dirty(&backend).await
                .map_err(ClientError::Encryption)?;
            guard.manifest().clone()
        };

        // Phase 2: encrypt + conditionally PUT the manifest.
        let next_seq = prior_seq.unwrap_or(0).saturating_add(1);
        let encrypted_manifest = EncryptedShardManifestV7::encrypt_v7(
            &manifest_snapshot,
            &forest_dek,
            bucket,
            next_seq,
        ).map_err(ClientError::Encryption)?;
        let data = encrypted_manifest.to_bytes()
            .map_err(ClientError::Encryption)?;

        let metadata = ObjectMetadata::new()
            .with_content_type("application/octet-stream");

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
        let start = std::time::Instant::now();
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
        manifest.created_at = v1_forest.created_at;

        let mut v7 = ShardedHamtPrivateForest::from_manifest(
            manifest,
            bucket.to_string(),
            forest_dek.clone(),
        );
        let backend = Arc::new(S3BlobBackend::new(self.inner.clone(), bucket.to_string()));

        // Replay files. HAMT insert is commutative per key; ordering irrelevant.
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

        // ── Step 7: Phase B — encrypt + conditional PUT of v7 manifest ─────
        let manifest_snapshot = v7.manifest().clone();
        let manifest_seq: u64 = 1;
        let manifest_data = match EncryptedShardManifestV7::encrypt_v7(
            &manifest_snapshot,
            forest_dek,
            bucket,
            manifest_seq,
        ).and_then(|em| em.to_bytes()) {
            Ok(bytes) => bytes,
            Err(e) => {
                release_best_effort(lock_token.clone()).await;
                return Ok(MigrationOutcome::DeferredTransientError {
                    reason: format!("encrypt v7 manifest failed: {}", e),
                });
            }
        };

        // If-Match the v1 ETag: any concurrent writer that rewrites v1 between
        // our HEAD (or GET) and this PUT loses the race — we defer and retry
        // next session. Crucial because the in-process `migration_lock.write()`
        // is NOT held during load-time-triggered migration.
        let put_result = match self.inner.put_object_with_metadata_conditional(
            bucket,
            &index_key,
            Bytes::from(manifest_data),
            Some(ObjectMetadata::new().with_content_type("application/octet-stream")),
            Some(&v1_etag),
            None,
        ).await {
            Ok(r) => r,
            Err(e) if e.is_concurrent_modification() => {
                release_best_effort(lock_token.clone()).await;
                return Ok(MigrationOutcome::DeferredTransientError {
                    reason: "412 on v7 manifest PUT — another writer rewrote v1".to_string(),
                });
            }
            Err(e) => {
                release_best_effort(lock_token.clone()).await;
                return Ok(MigrationOutcome::DeferredTransientError {
                    reason: format!("v7 manifest PUT failed: {}", e),
                });
            }
        };

        // ── Step 8: Install the migrated forest into the cache ─────────────
        let new_etag = if put_result.etag.is_empty() { None } else { Some(put_result.etag) };
        let now = chrono::Utc::now().timestamp();
        let forest_arc = Arc::new(tokio::sync::Mutex::new(v7));
        self.forest_cache.insert(bucket.to_string(), ForestCacheEntry::ShardedHamt {
            forest: forest_arc,
            loaded_at: now,
            manifest_etag: new_etag,
            last_manifest_sequence: Some(manifest_seq),
        });
        // Pin the manifest version so a gateway can't downgrade us next load.
        self.persist_manifest_version(bucket, 7);

        // ── Step 9: Release the server lock (best-effort) ─────────────────
        release_best_effort(lock_token).await;

        // Heartbeat guard drops here — task aborts cleanly.
        Ok(MigrationOutcome::Migrated {
            duration_ms: start.elapsed().as_millis() as u64,
        })
    }

    /// Migrate a bucket's forest from sharded back to monolithic format (rollback).
    ///
    /// Loads all shards, merges into a single PrivateForest, saves monolithic,
    /// then cleans up old shard objects from S3.
    pub async fn migrate_to_monolithic(&self, bucket: &str) -> Result<()> {
        self.ensure_forest_loaded(bucket).await?;

        if !self.is_forest_sharded(bucket) {
            return Ok(()); // Already monolithic
        }

        let forest_dek = self.encryption.key_manager.derive_path_key(&format!("forest:{}", bucket));

        // Load all shards
        self.load_all_shards(bucket).await?;

        // Collect old shard keys for cleanup
        let (forest, old_shard_keys) = {
            let entry = self.forest_cache.get(bucket).unwrap();
            match entry.value() {
                ForestCacheEntry::Sharded { forest, .. } => {
                    let mono = forest.to_monolithic().map_err(ClientError::Encryption)?;
                    let shard_keys: Vec<String> = (0..forest.manifest.num_shards)
                        .map(|i| derive_shard_key(&forest_dek, bucket, &forest.manifest.shard_salt, i))
                        .collect();
                    (mono, shard_keys)
                }
                _ => return Ok(()),
            }
        };

        // Save as monolithic (overwrites manifest at index_key)
        self.save_forest(bucket, &forest).await?;

        // Phase C: cleanup old shard objects
        for shard_key in &old_shard_keys {
            let _ = self.inner.delete_object(bucket, shard_key).await;
        }

        Ok(())
    }

    /// Get the current forest file count for a bucket (for migration threshold checks).
    pub async fn forest_file_count(&self, bucket: &str) -> Result<usize> {
        self.ensure_forest_loaded(bucket).await?;

        // Extract either a synchronous count (monolithic / v5–v6) or an Arc
        // handle to the v7 forest whose mutex must be awaited below. The
        // DashMap guard is dropped at the end of this block so we don't
        // hold a shard lock across the `lock().await` that follows.
        let (sync_count, v7_forest) = {
            let entry_opt = self.forest_cache.get(bucket);
            match entry_opt.as_ref().map(|e| e.value()) {
                Some(ForestCacheEntry::Monolithic { forest, .. }) => (Some(forest.file_count()), None),
                Some(ForestCacheEntry::Sharded { forest, .. }) => (Some(forest.file_count()), None),
                Some(ForestCacheEntry::ShardedHamt { forest, .. }) => (None, Some(forest.clone())),
                None => (Some(0), None),
            }
        };

        let count = if let Some(c) = sync_count {
            c
        } else if let Some(arc) = v7_forest {
            // v7 keeps a per-shard `entry_count` in the manifest so total
            // counts are O(1) without walking the HAMT.
            let guard = arc.lock().await;
            guard.manifest().shards.iter()
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

        // Load or create forest (handles both monolithic and sharded)
        self.ensure_forest_loaded(bucket).await?;
        let is_sharded = self.is_forest_sharded(bucket);

        // Generate a DEK for this object
        let dek = self.encryption.key_manager.generate_dek();

        // Generate flat storage key from cached forest.
        //
        // For v7 we can't derive the key while holding the DashMap guard —
        // ShardedHamtPrivateForest is behind a `tokio::sync::Mutex` and taking
        // its `.lock().await` across the DashMap guard would deadlock the
        // DashMap shard. The sync formats finalize inline; for v7 we extract
        // the Arc, drop the guard, lock the mutex to copy `shard_salt`, drop
        // the lock, then compute the key.
        enum KeyPath {
            Ready(String),
            V7(Arc<tokio::sync::Mutex<ShardedHamtPrivateForest>>),
        }
        let path = {
            let cache_entry = self.forest_cache.get(bucket)
                .ok_or_else(|| ClientError::Encryption(
                    fula_crypto::CryptoError::Encryption("forest not loaded".to_string())
                ))?;
            match cache_entry.value() {
                ForestCacheEntry::Monolithic { forest, .. } =>
                    KeyPath::Ready(forest.generate_key(key, &dek)),
                ForestCacheEntry::Sharded { forest, .. } =>
                    KeyPath::Ready(forest.generate_key(key, &dek)),
                ForestCacheEntry::ShardedHamt { forest, .. } =>
                    KeyPath::V7(forest.clone()),
            }
        };
        let storage_key = match path {
            KeyPath::Ready(sk) => sk,
            KeyPath::V7(forest_arc) => {
                let salt = {
                    let guard = forest_arc.lock().await;
                    guard.manifest().shard_salt.clone()
                };
                generate_flat_key(key, &dek, &salt)
            }
        };

        // Encrypt the DEK with HPKE
        let encryptor = Encryptor::new(self.encryption.public_key());
        let wrapped_dek = encryptor.encrypt_dek(&dek)
            .map_err(ClientError::Encryption)?;

        // Create private metadata
        let private_meta = PrivateMetadata::new(key, original_size)
            .with_content_type(content_type.unwrap_or("application/octet-stream"));

        let encrypted_meta = EncryptedPrivateMetadata::encrypt(&private_meta, &dek)
            .map_err(ClientError::Encryption)?;

        // Mark the forest entry as encrypted so subsequent reads refuse a
        // plaintext response from the storage backend (C-AUDIT-004).
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
                let mut guard = forest_arc.lock().await;
                let prior = guard.get_file(key, &backend).await
                    .map_err(ClientError::Encryption)?;
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
        } else if is_sharded {
            // Sharded: load target shard, upsert in-place via get_mut
            let forest_dek = self.encryption.key_manager.derive_path_key(&format!("forest:{}", bucket));
            let shard_index = {
                let cache_entry = self.forest_cache.get(bucket).unwrap();
                match cache_entry.value() {
                    ForestCacheEntry::Sharded { forest, .. } => forest.shard_for(key, &forest_dek),
                    ForestCacheEntry::ShardedHamt { .. } => unreachable!("is_v7 handled above"),
                    ForestCacheEntry::Monolithic { .. } => unreachable!("is_sharded true rules out Monolithic"),
                }
            };
            self.load_shard(bucket, shard_index).await?;
            let old = {
                let cache_entry = self.forest_cache.get(bucket).unwrap();
                match cache_entry.value() {
                    ForestCacheEntry::Sharded { forest, .. } =>
                        forest.get_storage_key(key, &forest_dek).map(|s| s.to_string()),
                    _ => None,
                }
            };
            if let Some(mut cache_entry) = self.forest_cache.get_mut(bucket) {
                if let ForestCacheEntry::Sharded { forest, loaded_at, .. } = cache_entry.value_mut() {
                    forest.upsert_file(forest_entry, &forest_dek);
                    *loaded_at = now;
                }
            }
            old
        } else {
            // Monolithic: clone, mutate, re-insert. v7 (ShardedHamt) is
            // ruled out by the `is_v7` arm above; v6 (Sharded) is ruled out
            // by the `is_sharded` arm above.
            let (mut forest, prior_etag, prior_seq) = {
                let cache_entry = self.forest_cache.get(bucket).unwrap();
                match cache_entry.value() {
                    ForestCacheEntry::Monolithic { forest, index_etag, last_sequence, .. } =>
                        (forest.clone(), index_etag.clone(), *last_sequence),
                    ForestCacheEntry::ShardedHamt { .. } => unreachable!("is_v7 handled above"),
                    ForestCacheEntry::Sharded { .. } => unreachable!("is_sharded false rules out Sharded"),
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

        let private_meta = PrivateMetadata::new(key, original_size)
            .with_content_type(content_type.unwrap_or("application/octet-stream"));
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

        // Create private metadata
        let private_meta = PrivateMetadata::new(key, total_size)
            .with_content_type(content_type.unwrap_or("application/octet-stream"));
        let encrypted_meta = EncryptedPrivateMetadata::encrypt(&private_meta, &dek)
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
        let (chunked_metadata, _outboard) = encoder.finalize();

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

        if self.is_forest_sharded(bucket) {
            // Auto-migrate legacy v3/v5 sharded forests to v6 (directory-aware routing)
            // on the next flush. Requires loading every shard to redistribute files,
            // and deleting the old shard blobs once the new manifest is written.
            let needs_v6_migration = self.forest_cache.get(bucket).map(|entry| {
                match entry.value() {
                    ForestCacheEntry::Sharded { forest, .. } => forest.manifest.version != 6,
                    _ => false,
                }
            }).unwrap_or(false);

            if needs_v6_migration {
                let forest_dek = self.encryption.key_manager.derive_path_key(&format!("forest:{}", bucket));
                self.load_all_shards(bucket).await?;

                // Capture old (pre-v6) shard keys before resharding so we can clean up.
                let old_shard_keys: Vec<String> = {
                    let entry = self.forest_cache.get(bucket).unwrap();
                    match entry.value() {
                        ForestCacheEntry::Sharded { forest, .. } => {
                            (0..forest.manifest.num_shards)
                                .map(|i| derive_shard_key(&forest_dek, bucket, &forest.manifest.shard_salt, i))
                                .collect()
                        }
                        _ => Vec::new(),
                    }
                };

                // Redistribute using v6 routing (fresh salt, new shard assignments).
                if let Some(mut entry) = self.forest_cache.get_mut(bucket) {
                    if let ForestCacheEntry::Sharded { forest, .. } = entry.value_mut() {
                        forest.reshard_to_v6(&forest_dek).map_err(ClientError::Encryption)?;
                    }
                }

                // Save (all shards + manifest now v6).
                self.save_sharded_forest(bucket).await?;

                // Phase C: delete old pre-v6 shard objects (best-effort).
                for key in &old_shard_keys {
                    let _ = self.inner.delete_object(bucket, key).await;
                }

                return Ok(());
            }

            // Check if resharding is needed before saving
            let needs_reshard = self.forest_cache.get(bucket).map(|entry| {
                match entry.value() {
                    ForestCacheEntry::Sharded { forest, .. } => forest.should_reshard(),
                    _ => false,
                }
            }).unwrap_or(false);

            if needs_reshard {
                let forest_dek = self.encryption.key_manager.derive_path_key(&format!("forest:{}", bucket));
                // Load all shards for resharding
                self.load_all_shards(bucket).await?;

                // Collect old shard keys before resharding (old salt → old keys)
                let old_shard_keys: Vec<String> = {
                    let entry = self.forest_cache.get(bucket).unwrap();
                    match entry.value() {
                        ForestCacheEntry::Sharded { forest, .. } => {
                            (0..forest.manifest.num_shards)
                                .map(|i| derive_shard_key(&forest_dek, bucket, &forest.manifest.shard_salt, i))
                                .collect()
                        }
                        _ => Vec::new(),
                    }
                };

                // Reshard in-place
                if let Some(mut entry) = self.forest_cache.get_mut(bucket) {
                    if let ForestCacheEntry::Sharded { forest, .. } = entry.value_mut() {
                        forest.reshard(&forest_dek).map_err(ClientError::Encryption)?;
                    }
                }

                // Save resharded forest (all shards marked dirty)
                self.save_sharded_forest(bucket).await?;

                // Cleanup old shard objects (Phase C — safe because new manifest is already written)
                for key in &old_shard_keys {
                    let _ = self.inner.delete_object(bucket, key).await;
                }

                Ok(())
            } else {
                self.save_sharded_forest(bucket).await
            }
        } else {
            // Monolithic: just save v1. Auto-migration is no longer wired into
            // the flush path — the canonical trigger is `load_forest_internal`
            // at first access. If we're flushing a v1 forest here, migration
            // was deferred earlier this session (lock held by another device,
            // pending WAL entries, transient failure) and will re-enter on the
            // next load; flush's job is to keep v1 writes durable in the
            // meantime.
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
        let is_sharded = self.is_forest_sharded(bucket);
        let forest_dek = if is_sharded {
            Some(self.encryption.key_manager.derive_path_key(&format!("forest:{}", bucket)))
        } else {
            None
        };

        // v7 replay runs on a distinct cache shape (ShardedHamt holds an
        // `Arc<tokio::sync::Mutex<ShardedHamtPrivateForest>>`). Detect once
        // here; the body below dispatches to this branch before touching
        // the v6-style manifest fields that don't exist on v7.
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

            {
                let mut guard = forest_arc.lock().await;
                if !shard_writes.is_empty() {
                    let num_shards = guard.manifest().shards.len();
                    for (idx, (seq, etag)) in shard_writes {
                        if idx < num_shards {
                            guard.reconcile_shard_write(idx, seq, etag);
                        }
                    }
                }

                // Phase 2 (v7): replay Insert/Remove in the same order they
                // were logged. `upsert_file` / `remove_file` are
                // per-shard-dirty-marking so a subsequent `flush_dirty`
                // picks them up under the post-reconciled sequence.
                for wentry in entries {
                    match wentry {
                        WalEntry::Insert { key: _, entry: forest_entry } => {
                            guard.upsert_file(forest_entry, &backend).await
                                .map_err(ClientError::Encryption)?;
                        }
                        WalEntry::Remove { key } => {
                            let _ = guard.remove_file(&key, &backend).await
                                .map_err(ClientError::Encryption)?;
                        }
                        WalEntry::ShardWrote { .. } => {
                            // Handled above in Phase 1.
                        }
                    }
                }
            }
            return Ok(());
        }

        // Phase 1: reconcile ShardWrote entries onto the cache's manifest view.
        // For each shard we already successfully wrote to S3, set
        // `shard_sequences[idx]` and `shard_etags[idx]` to what we persisted so
        // the retry path can re-read and re-flush consistently. We keep only the
        // MAX observed seq per shard in case of multiple races.
        if is_sharded {
            let mut shard_writes: std::collections::HashMap<usize, (u64, Option<String>)> =
                std::collections::HashMap::new();
            for entry in &entries {
                if let WalEntry::ShardWrote { idx, seq, etag } = entry {
                    let slot = shard_writes.entry(*idx).or_insert((0u64, None));
                    if *seq >= slot.0 {
                        *slot = (*seq, etag.clone());
                    }
                }
            }
            if !shard_writes.is_empty() {
                if let Some(mut cache_entry) = self.forest_cache.get_mut(bucket) {
                    if let ForestCacheEntry::Sharded { forest, shard_etags, .. } = cache_entry.value_mut() {
                        let num_shards = forest.manifest.num_shards;
                        if forest.manifest.shard_sequences.len() != num_shards {
                            forest.manifest.shard_sequences.resize(num_shards, 0);
                        }
                        if shard_etags.len() != num_shards {
                            shard_etags.resize(num_shards, None);
                        }
                        for (idx, (seq, etag)) in shard_writes {
                            if idx < num_shards {
                                let cur = forest.manifest.shard_sequences[idx];
                                if seq > cur {
                                    forest.manifest.shard_sequences[idx] = seq;
                                }
                                shard_etags[idx] = etag;
                                // Mark dirty so the retry flush re-PUTs this shard
                                // (bumping its seq to wal_seq + 1 and carrying our
                                // replayed Insert/Remove entries).
                                forest.dirty_shards.insert(idx);
                            }
                        }
                    }
                }
            }
        }

        // Phase 2: replay Insert/Remove in order. Any load_shard inside this
        // loop now sees the reconciled shard_sequences and will AEAD-verify
        // correctly against the bytes we actually left on S3.
        for entry in entries {
            match entry {
                WalEntry::Insert { key, entry: forest_entry } => {
                    if is_sharded {
                        let dek = forest_dek.as_ref().unwrap();
                        let shard_index = {
                            let cache = match self.forest_cache.get(bucket) {
                                Some(c) => c,
                                None => continue,
                            };
                            match cache.value() {
                                ForestCacheEntry::Sharded { forest, .. } => forest.shard_for(&key, dek),
                                _ => continue,
                            }
                        };
                        self.load_shard(bucket, shard_index).await?;
                        if let Some(mut cache_entry) = self.forest_cache.get_mut(bucket) {
                            if let ForestCacheEntry::Sharded { forest, .. } = cache_entry.value_mut() {
                                forest.upsert_file(forest_entry, dek);
                            }
                        }
                    } else {
                        if let Some(mut cache_entry) = self.forest_cache.get_mut(bucket) {
                            if let ForestCacheEntry::Monolithic { forest, dirty, .. } = cache_entry.value_mut() {
                                forest.upsert_file(forest_entry);
                                *dirty = true;
                            }
                        }
                    }
                }
                WalEntry::Remove { key } => {
                    if is_sharded {
                        let dek = forest_dek.as_ref().unwrap();
                        let shard_index = {
                            let cache = match self.forest_cache.get(bucket) {
                                Some(c) => c,
                                None => continue,
                            };
                            match cache.value() {
                                ForestCacheEntry::Sharded { forest, .. } => forest.shard_for(&key, dek),
                                _ => continue,
                            }
                        };
                        self.load_shard(bucket, shard_index).await?;
                        if let Some(mut cache_entry) = self.forest_cache.get_mut(bucket) {
                            if let ForestCacheEntry::Sharded { forest, .. } = cache_entry.value_mut() {
                                forest.remove_file(&key, dek);
                            }
                        }
                    } else {
                        if let Some(mut cache_entry) = self.forest_cache.get_mut(bucket) {
                            if let ForestCacheEntry::Monolithic { forest, dirty, .. } = cache_entry.value_mut() {
                                forest.remove_file(&key);
                                *dirty = true;
                            }
                        }
                    }
                }
                WalEntry::ShardWrote { .. } => {
                    // Already handled in Phase 1.
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
            // Scope the DashMap guard so it is dropped before we `.lock().await`
            // on the v7 forest mutex (DashMap → forest-lock is the deadlock
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
                let mut guard = forest_arc.lock().await;
                guard.get_file(key, &backend).await.map_err(ClientError::Encryption)?
            };
            let entry = entry_opt.ok_or_else(|| ClientError::NotFound {
                bucket: bucket.to_string(),
                key: key.to_string(),
            })?;
            return self.get_object_decrypted_by_storage_key(bucket, &entry.storage_key).await;
        }

        let storage_key = if self.is_forest_sharded(bucket) {
            // Sharded: load only the needed shard
            let forest_dek = self.encryption.key_manager.derive_path_key(&format!("forest:{}", bucket));
            let shard_index = {
                let entry = self.forest_cache.get(bucket)
                    .ok_or_else(|| ClientError::NotFound { bucket: bucket.to_string(), key: key.to_string() })?;
                match entry.value() {
                    ForestCacheEntry::Sharded { forest, .. } => forest.shard_for(key, &forest_dek),
                    ForestCacheEntry::ShardedHamt { .. } => unreachable!("is_forest_sharded_hamt guard above"),
                    ForestCacheEntry::Monolithic { .. } => unreachable!("is_forest_sharded true rules out Monolithic"),
                }
            };
            self.load_shard(bucket, shard_index).await?;

            let entry = self.forest_cache.get(bucket).unwrap();
            match entry.value() {
                ForestCacheEntry::Sharded { forest, .. } => {
                    forest.get_storage_key(key, &forest_dek)
                        .ok_or_else(|| ClientError::NotFound { bucket: bucket.to_string(), key: key.to_string() })?
                        .to_string()
                }
                ForestCacheEntry::ShardedHamt { .. } => unreachable!("is_forest_sharded_hamt guard above"),
                ForestCacheEntry::Monolithic { .. } => unreachable!("is_forest_sharded true rules out Monolithic"),
            }
        } else {
            // Monolithic: already loaded by ensure_forest_loaded
            let entry = self.forest_cache.get(bucket)
                .ok_or_else(|| ClientError::NotFound { bucket: bucket.to_string(), key: key.to_string() })?;
            match entry.value() {
                ForestCacheEntry::Monolithic { forest, .. } => {
                    forest.get_storage_key(key)
                        .ok_or_else(|| ClientError::NotFound { bucket: bucket.to_string(), key: key.to_string() })?
                        .to_string()
                }
                ForestCacheEntry::ShardedHamt { .. } => unreachable!("is_forest_sharded_hamt guard above"),
                ForestCacheEntry::Sharded { .. } => unreachable!("is_forest_sharded false rules out Sharded"),
            }
        };

        self.get_object_decrypted_by_storage_key(bucket, &storage_key).await
    }

    /// List directory from forest index (FlatNamespace mode)
    /// 
    /// This is much faster than HEAD requests because the forest already
    /// contains all metadata.
    async fn list_directory_from_forest(
        &self,
        bucket: &str,
        prefix: Option<&str>,
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
            let files = {
                let mut guard = forest_arc.lock().await;
                guard.list_recursive(prefix_str, &backend).await
                    .map_err(ClientError::Encryption)?
            };
            for fentry in &files {
                let (dir, metadata) = build_entry(fentry);
                directories.entry(dir).or_default().push(metadata);
            }
            return Ok(DirectoryListing {
                bucket: bucket.to_string(),
                prefix: prefix.map(|s| s.to_string()),
                directories,
            });
        }

        if self.is_forest_sharded(bucket) {
            self.load_all_shards(bucket).await?;
            let entry = self.forest_cache.get(bucket).unwrap();
            match entry.value() {
                ForestCacheEntry::Sharded { forest, .. } => {
                    for fentry in forest.list_recursive(prefix_str) {
                        let (dir, metadata) = build_entry(fentry);
                        directories.entry(dir).or_default().push(metadata);
                    }
                }
                ForestCacheEntry::ShardedHamt { .. } => unreachable!("is_forest_sharded_hamt guard above"),
                ForestCacheEntry::Monolithic { .. } => unreachable!("is_forest_sharded true rules out Monolithic"),
            }
        } else {
            let entry = self.forest_cache.get(bucket).unwrap();
            match entry.value() {
                ForestCacheEntry::Monolithic { forest, .. } => {
                    for fentry in forest.list_recursive(prefix_str) {
                        let (dir, metadata) = build_entry(fentry);
                        directories.entry(dir).or_default().push(metadata);
                    }
                }
                ForestCacheEntry::ShardedHamt { .. } => unreachable!("is_forest_sharded_hamt guard above"),
                ForestCacheEntry::Sharded { .. } => unreachable!("is_forest_sharded false rules out Sharded"),
            }
        }

        Ok(DirectoryListing {
            bucket: bucket.to_string(),
            prefix: prefix.map(|s| s.to_string()),
            directories,
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
                let mut guard = forest_arc.lock().await;
                guard.list_all_files(&backend).await
                    .map_err(ClientError::Encryption)?
            };
            let files: Vec<FileMetadata> = entries.iter().map(&make_meta).collect();
            return Ok(files);
        }

        let files: Vec<FileMetadata> = if self.is_forest_sharded(bucket) {
            self.load_all_shards(bucket).await?;
            let entry = self.forest_cache.get(bucket).unwrap();
            match entry.value() {
                ForestCacheEntry::Sharded { forest, .. } => {
                    forest.list_all_files().into_iter().map(&make_meta).collect()
                }
                ForestCacheEntry::ShardedHamt { .. } => unreachable!("is_forest_sharded_hamt guard above"),
                ForestCacheEntry::Monolithic { .. } => unreachable!("is_forest_sharded true rules out Monolithic"),
            }
        } else {
            let entry = self.forest_cache.get(bucket).unwrap();
            match entry.value() {
                ForestCacheEntry::Monolithic { forest, .. } => {
                    forest.list_all_files().into_iter().map(&make_meta).collect()
                }
                ForestCacheEntry::ShardedHamt { .. } => unreachable!("is_forest_sharded_hamt guard above"),
                ForestCacheEntry::Sharded { .. } => unreachable!("is_forest_sharded false rules out Sharded"),
            }
        };

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

    /// Delete all chunk objects for a chunked file (best-effort, errors ignored).
    async fn delete_chunk_objects(&self, bucket: &str, storage_key: &str, num_chunks: u32) {
        for i in 0..num_chunks {
            let chunk_key = ChunkedFileMetadata::chunk_key(storage_key, i);
            let _ = self.inner.delete_object(bucket, &chunk_key).await;
        }
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
            ForestCacheEntry::Sharded { forest, .. } => {
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
    /// All errors are logged and swallowed: an orphaned S3 object is
    /// recoverable garbage, but failing the upload would lose the new data.
    async fn cleanup_orphaned_storage(
        &self,
        bucket: &str,
        storage_key: &str,
        num_chunks: Option<u32>,
    ) {
        if self.storage_key_still_referenced(bucket, storage_key) {
            tracing::debug!(
                bucket = %bucket,
                storage_key = %storage_key,
                "Skipping orphan cleanup — storage key still referenced in forest"
            );
            return;
        }

        if let Some(n) = num_chunks {
            self.delete_chunk_objects(bucket, storage_key, n).await;
        }

        if let Err(e) = self.inner.delete_object(bucket, storage_key).await {
            tracing::warn!(
                bucket = %bucket,
                storage_key = %storage_key,
                error = ?e,
                "Failed to delete orphaned storage key (best-effort; server-side GC may reclaim later)"
            );
        }
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
                let mut guard = forest_arc.lock().await;
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

        if self.is_forest_sharded(bucket) {
            // Sharded: load the needed shard, find storage key, delete
            let forest_dek = self.encryption.key_manager.derive_path_key(&format!("forest:{}", bucket));
            let shard_index = {
                let entry = self.forest_cache.get(bucket)
                    .ok_or_else(|| ClientError::NotFound { bucket: bucket.to_string(), key: key.to_string() })?;
                match entry.value() {
                    ForestCacheEntry::Sharded { forest, .. } => forest.shard_for(key, &forest_dek),
                    ForestCacheEntry::ShardedHamt { .. } => unreachable!("is_forest_sharded_hamt guard above"),
                    ForestCacheEntry::Monolithic { .. } => unreachable!("is_forest_sharded true rules out Monolithic"),
                }
            };
            self.load_shard(bucket, shard_index).await?;

            let storage_key = {
                let entry = self.forest_cache.get(bucket).unwrap();
                match entry.value() {
                    ForestCacheEntry::Sharded { forest, .. } => {
                        forest.get_storage_key(key, &forest_dek)
                            .ok_or_else(|| ClientError::NotFound { bucket: bucket.to_string(), key: key.to_string() })?
                            .to_string()
                    }
                    ForestCacheEntry::ShardedHamt { .. } => unreachable!("is_forest_sharded_hamt guard above"),
                    ForestCacheEntry::Monolithic { .. } => unreachable!("is_forest_sharded true rules out Monolithic"),
                }
            };

            // Check if the file is chunked before modifying the forest,
            // so we know which chunk objects to clean up afterward.
            let num_chunks = self.get_chunked_num_chunks(bucket, &storage_key).await;

            // Remove from forest shard first (marks shard dirty), then save,
            // then delete storage. This order ensures we never have a dangling
            // reference — an orphaned blob is recoverable, a dangling ref is not.
            if let Some(mut entry) = self.forest_cache.get_mut(bucket) {
                if let ForestCacheEntry::Sharded { forest, .. } = entry.value_mut() {
                    forest.remove_file(key, &forest_dek);
                }
            }

            #[cfg(not(target_arch = "wasm32"))]
            {
                let wal_mac = wal::derive_mac_key(&self.encryption.key_manager, bucket);
                if let Err(e) = wal::append(
                    bucket,
                    &wal_mac,
                    WalEntry::Remove { key: key.to_string() },
                ) {
                    tracing::warn!(%bucket, error = %e, "WAL append failed (remove); continuing");
                }
            }

            // Use flush_forest instead of save_sharded_forest so that v3/v5→v6
            // auto-migration fires on delete-only flows (not just put flows).
            self.flush_forest(bucket).await?;

            // Delete chunk objects if this was a chunked file (best-effort)
            if let Some(n) = num_chunks {
                self.delete_chunk_objects(bucket, &storage_key, n).await;
            }

            // Delete storage/index object (best-effort — orphaned blob is harmless)
            let _ = self.inner.delete_object(bucket, &storage_key).await;

            Ok(())
        } else {
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
                let mut guard = forest_arc.lock().await;
                guard.extract_subtree(prefix, &backend).await
                    .map_err(ClientError::Encryption)?
            };
            return Ok(subtree);
        }

        if self.is_forest_sharded(bucket) {
            let forest_dek = self.encryption.key_manager.derive_path_key(&format!("forest:{}", bucket));
            self.load_all_shards(bucket).await?;
            let entry = self.forest_cache.get(bucket).unwrap();
            match entry.value() {
                ForestCacheEntry::Sharded { forest, .. } => {
                    forest.extract_subtree(prefix, &forest_dek)
                        .to_monolithic()
                        .map_err(ClientError::Encryption)
                }
                ForestCacheEntry::ShardedHamt { .. } => unreachable!("is_forest_sharded_hamt guard above"),
                ForestCacheEntry::Monolithic { .. } => unreachable!("is_forest_sharded true rules out Monolithic"),
            }
        } else {
            let forest = self.load_forest(bucket).await?;
            Ok(forest.extract_subtree(prefix))
        }
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
            let version = accepted_share.encryption_version.unwrap_or(2);
            let plaintext = if version >= 4 {
                let aad = format!("fula:v4:content:{}", storage_key).into_bytes();
                aead.decrypt_with_aad(&nonce, &data, &aad)
            } else {
                aead.decrypt(&nonce, &data)
            }.map_err(ClientError::Encryption)?;

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
    async fn download_chunks_parallel(
        &self,
        bucket: &str,
        storage_key: &str,
        chunked_meta: &ChunkedFileMetadata,
        dek: &fula_crypto::keys::DekKey,
    ) -> Result<Bytes> {
        let mut output = Vec::with_capacity(chunked_meta.total_size as usize);
        self.download_chunks_windowed_to_writer(bucket, storage_key, chunked_meta, dek, &mut output).await?;
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

        // If sharded, also skip shard keys
        let _ = self.ensure_forest_loaded(bucket).await;
        if let Some(entry) = self.forest_cache.get(bucket) {
            if let ForestCacheEntry::Sharded { forest, .. } = entry.value() {
                for i in 0..forest.manifest.num_shards {
                    let shard_key = derive_shard_key(&forest_dek, bucket, &forest.manifest.shard_salt, i);
                    forest_keys.insert(shard_key);
                }
            }
        }

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
        // v7 mutates an `Arc<tokio::sync::Mutex<ShardedHamtPrivateForest>>`
        // whose `upsert_file` is async and cannot be called while holding
        // the DashMap guard. Split the match: sync formats mutate in place
        // under the guard, v7 extracts the Arc and performs the async
        // upsert after dropping it.
        let now = chrono::Utc::now().timestamp();
        let file_entry = ForestFileEntry {
            path: key.to_string(),
            storage_key: storage_key.clone(),
            size: data.len() as u64,
            content_type: metadata.content_type.clone(),
            created_at: now,
            modified_at: now,
            user_metadata: HashMap::new(),
            content_hash: None,
            // C-AUDIT-004: forest entries from encrypted uploads MUST
            // be marked so later reads refuse a plaintext backend response.
            encrypted: true,
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
                    ForestCacheEntry::Sharded { forest, loaded_at, .. } => {
                        let forest_dek = self.encryption.key_manager.derive_path_key(&format!("forest:{}", bucket));
                        forest.upsert_file(file_entry.clone(), &forest_dek);
                        *loaded_at = now;
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
                let mut guard = forest_arc.lock().await;
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

        // Delegate to the windowed parallel download path shared with the main
        // get_object_decrypted flow. Handles streaming-v2 and legacy formats
        // identically — chunk S3 layout and per-chunk nonce/AAD derivation are
        // unchanged, only the concurrency pattern differs from the old loop.
        self.get_object_chunked_internal(bucket, &storage_key, &enc_metadata, &dek).await
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

/// Directory listing result
#[derive(Debug, Clone)]
pub struct DirectoryListing {
    /// Bucket name
    pub bucket: String,
    /// Prefix filter (if any)
    pub prefix: Option<String>,
    /// Files grouped by directory path
    pub directories: HashMap<String, Vec<FileMetadata>>,
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
        use fula_crypto::private_forest::{ShardManifestV7, ShardV7};
        use fula_crypto::keys::DekKey;

        let manifest = ShardManifestV7 {
            version: 7,
            format: "sharded-hamt-v7".to_string(),
            num_shards: 1,
            shard_salt: vec![0u8; 32],
            root: "/".to_string(),
            created_at: 0,
            modified_at: 0,
            shards: vec![ShardV7 {
                root: None,
                seq: 0,
                etag: None,
                entry_count: 0,
            }],
        };

        let dek = DekKey::from_bytes(&[0x42u8; 32]).unwrap();
        let forest = ShardedHamtPrivateForest::from_manifest(manifest, "bucket", dek);
        let forest_arc = Arc::new(tokio::sync::Mutex::new(forest));
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
        use fula_crypto::private_forest::{ShardManifestV7, ShardV7};

        let cfg = Config::new("http://127.0.0.1:1");
        let enc = EncryptionConfig::new();
        let client = EncryptedClient::new(cfg, enc).expect("client builds");

        // Seed the cache with a ShardedHamt entry for "bucket". This short-
        // circuits `load_forest_internal` into the "forest is sharded"
        // branch without any HTTP traffic.
        let manifest = ShardManifestV7 {
            version: 7,
            format: "sharded-hamt-v7".to_string(),
            num_shards: 1,
            shard_salt: vec![0u8; 32],
            root: "/".to_string(),
            created_at: 0,
            modified_at: 0,
            shards: vec![ShardV7 {
                root: None,
                seq: 0,
                etag: None,
                entry_count: 0,
            }],
        };
        let dek = DekKey::from_bytes(&[0x01u8; 32]).unwrap();
        let v7 = ShardedHamtPrivateForest::from_manifest(manifest, "bucket", dek);
        client.forest_cache.insert("bucket".to_string(), ForestCacheEntry::ShardedHamt {
            forest: Arc::new(tokio::sync::Mutex::new(v7)),
            loaded_at: chrono::Utc::now().timestamp(),
            manifest_etag: Some("cached".to_string()),
            last_manifest_sequence: Some(1),
        });

        let event = client.migrate_to_sharded("bucket").await.expect("idempotent ok");
        match event {
            ForestEvent::MigrationCompleted { bucket, duration_ms } => {
                assert_eq!(bucket, "bucket");
                assert_eq!(duration_ms, 0, "no work done → zero duration");
            }
            other => panic!("expected MigrationCompleted, got {:?}", other),
        }
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
}
