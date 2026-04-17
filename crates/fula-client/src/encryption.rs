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
        ShardedPrivateForest, ForestShard,
        EncryptedShardManifest, EncryptedForestShard, ForestEvent,
        detect_forest_format, ForestOrManifest, derive_shard_key,
        compute_initial_shard_count, SHARDED_MIGRATION_THRESHOLD,
    },
    sharing::{ShareToken, AcceptedShare, ShareRecipient},
    rotation::{KeyRotationManager, WrappedKeyInfo},
    ChunkedEncoder, ChunkedFileMetadata, should_use_chunked,
};
use std::sync::Arc;
use std::collections::HashMap;
use dashmap::DashMap;

/// Default forest cache TTL in seconds
const DEFAULT_FOREST_CACHE_TTL_SECS: i64 = 60;

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
}

impl ForestCacheEntry {
    fn loaded_at(&self) -> i64 {
        match self {
            ForestCacheEntry::Monolithic { loaded_at, .. } => *loaded_at,
            ForestCacheEntry::Sharded { loaded_at, .. } => *loaded_at,
        }
    }

    fn is_dirty(&self) -> bool {
        match self {
            ForestCacheEntry::Monolithic { dirty, .. } => *dirty,
            ForestCacheEntry::Sharded { forest, .. } => {
                forest.manifest_dirty || !forest.dirty_shards.is_empty()
            }
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
            // C-AUDIT-004: refuse plaintext response when forest records this
            // storage_key as a previously-encrypted upload. Prevents a
            // malicious backend from returning attacker-chosen plaintext.
            if self.forest_entry_requires_encryption(bucket, storage_key) {
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

            let semaphore = Arc::new(tokio::sync::Semaphore::new(window_size));
            let mut handles = Vec::with_capacity(window_end - window_start);

            for chunk_index in window_start..window_end {
                let chunk_key = ChunkedFileMetadata::chunk_key(storage_key, chunk_index as u32);
                let client = self.inner.clone();
                let bucket = bucket.to_string();
                let sem = semaphore.clone();

                let handle = tokio::spawn(async move {
                    let _permit = sem.acquire().await.map_err(|e|
                        ClientError::Encryption(fula_crypto::CryptoError::Decryption(e.to_string()))
                    )?;
                    let data = client.get_object(&bucket, &chunk_key).await?;
                    Ok::<(u32, Bytes), ClientError>((chunk_index as u32, data))
                });

                handles.push(handle);
            }

            // Collect window results
            let mut window_chunks: Vec<(u32, Bytes)> = Vec::with_capacity(window_end - window_start);
            for handle in handles {
                let (idx, data) = handle.await
                    .map_err(|e| ClientError::Encryption(
                        fula_crypto::CryptoError::Decryption(format!("Chunk download task failed: {}", e))
                    ))??;
                window_chunks.push((idx, data));
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
            // C-AUDIT-004: block plaintext response for forest-known encrypted entries
            if self.forest_entry_requires_encryption(bucket, storage_key) {
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
            // C-AUDIT-004: block plaintext response for forest-known encrypted entries
            if self.forest_entry_requires_encryption(bucket, storage_key) {
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
            // C-AUDIT-004: block plaintext response for forest-known encrypted entries
            if self.forest_entry_requires_encryption(bucket, storage_key) {
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
                    ForestCacheEntry::Sharded { .. } => {
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
                });
                let cached_is_sharded = self.forest_cache.get(bucket)
                    .map(|e| matches!(e.value(), ForestCacheEntry::Sharded { .. }))
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
                            _ => None,
                        });
                        let cached_prior_manifest_version = self.forest_cache.get(bucket).and_then(|e| match e.value() {
                            ForestCacheEntry::Sharded { forest, .. } => Some(forest.manifest.version),
                            _ => None,
                        });

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
                                // Reject routing-version downgrade if cache already saw v6.
                                if cached_prior_manifest_version == Some(6) {
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
                                // Legacy v3: reject downgrade if we previously saw v5 or v6.
                                if cached_prior_manifest_seq.is_some() {
                                    return Err(ClientError::Encryption(
                                        fula_crypto::CryptoError::Decryption(
                                            "manifest version downgrade detected: server served legacy v3 after an AAD-bound manifest was observed".to_string()
                                        )
                                    ));
                                }
                                (encrypted_manifest.decrypt(&forest_dek).map_err(ClientError::Encryption)?, None)
                            }
                        };

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
                }
            }
            Err(_) => {
                // No forest exists yet - create empty one (monolithic for new users)
                let forest = PrivateForest::new();
                let now = chrono::Utc::now().timestamp();
                self.forest_cache.insert(bucket.to_string(), ForestCacheEntry::Monolithic {
                    forest: forest.clone(),
                    loaded_at: now,
                    dirty: false,
                    index_etag: None,
                    last_sequence: None,
                });
                Ok(forest)
            }
        }
    }

    /// Check if the forest for a bucket is in sharded format
    pub fn is_forest_sharded(&self, bucket: &str) -> bool {
        self.forest_cache.get(bucket)
            .map(|entry| matches!(entry.value(), ForestCacheEntry::Sharded { .. }))
            .unwrap_or(false)
    }

    /// Load a single shard from S3 and cache it
    ///
    /// For v2 shards (AAD-bound), the shard's decrypted sequence is compared
    /// against `manifest.shard_sequences[shard_index]` to detect shard-level
    /// replay. A mismatch fails the load.
    async fn load_shard(&self, bucket: &str, shard_index: usize) -> Result<()> {
        let forest_dek = self.encryption.key_manager.derive_path_key(&format!("forest:{}", bucket));

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

    /// Ensure the forest is loaded for a bucket (handles both monolithic and sharded)
    ///
    /// For sharded forests, loads the manifest and the specific shard needed for `path`.
    /// Returns the forest DEK for convenience.
    async fn ensure_forest_loaded(&self, bucket: &str) -> Result<()> {
        // Try loading — if it fails because it's sharded, that's fine (manifest is cached).
        // Matches any of v3 / v5 / v6 manifest formats ("forest is sharded" prefix).
        match self.load_forest(bucket).await {
            Ok(_) => Ok(()),
            Err(ref e) if e.to_string().contains("forest is sharded") => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Check whether the forest has an entry for `storage_key` that was
    /// uploaded encrypted.
    ///
    /// Returns `true` only when an entry is present in the currently loaded
    /// forest AND carries `encrypted: true`. For sharded forests whose shards
    /// haven't been loaded yet, this returns `false` (best-effort check),
    /// which is acceptable: the enforcement is defense-in-depth that kicks in
    /// whenever the forest is loaded (the common case for authenticated
    /// sessions). Used to block malicious backends from returning plaintext
    /// for paths that the client uploaded encrypted (C-AUDIT-004).
    fn forest_entry_requires_encryption(&self, bucket: &str, storage_key: &str) -> bool {
        match self.forest_cache.get(bucket) {
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
            },
            None => false,
        }
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

    // ═══════════════════════════════════════════════════════════════════════════
    // MIGRATION: Monolithic ↔ Sharded forest format conversion
    // ═══════════════════════════════════════════════════════════════════════════

    /// Migrate a bucket's forest from monolithic to sharded format.
    ///
    /// Call this explicitly to migrate early, or let `flush_forest()` auto-migrate
    /// when the file count crosses `SHARDED_MIGRATION_THRESHOLD` (5,000).
    ///
    /// Crash-safe: new shards are written first, then the manifest overwrites the
    /// old monolithic blob at `index_key`. Old format is gone once manifest is written.
    ///
    /// Acquires an exclusive (write) migration lock for this bucket. Concurrent
    /// `load_forest` / `flush_forest` / `put_object_flat_deferred` calls will
    /// block on the read lock until migration completes. Shard uploads run in
    /// parallel to minimize lock hold time.
    pub async fn migrate_to_sharded(&self, bucket: &str) -> Result<ForestEvent> {
        let lock = self.migration_lock(bucket);
        let _guard = lock.write().await;

        let start = std::time::Instant::now();

        // Load the current monolithic forest (bypass read lock — we hold write)
        let forest = self.load_forest_internal(bucket).await?;
        let file_count = forest.file_count();
        let num_shards = compute_initial_shard_count(file_count);

        let forest_dek = self.encryption.key_manager.derive_path_key(&format!("forest:{}", bucket));
        let index_key = derive_index_key(&forest_dek, bucket);

        // Convert to sharded. `from_migration` now produces a v6 manifest
        // (directory-aware routing) so that all files land in the shard of
        // their parent directory from the first write.
        let mut sharded = ShardedPrivateForest::from_migration(forest, &forest_dek, num_shards);
        // Initialize per-shard sequences at 1 — every shard is being written for the first time.
        sharded.manifest.shard_sequences = vec![1u64; sharded.manifest.num_shards];

        // Phase A: upload all shard blobs in parallel as v2 (AAD-bound).
        // Collect uploaded shard keys so we can compensate (delete them) if
        // Phase B fails — otherwise a failed migration leaks orphan shards.
        let semaphore = Arc::new(tokio::sync::Semaphore::new(16));
        let mut handles = Vec::new();

        for i in 0..sharded.manifest.num_shards {
            if let Some(shard) = sharded.shards.get(i).and_then(|s| s.as_ref()) {
                let shard_key = derive_shard_key(&forest_dek, bucket, &sharded.manifest.shard_salt, i);
                let shard_seq = sharded.manifest.shard_sequences[i];
                let encrypted = EncryptedForestShard::encrypt_v2(
                    shard, &forest_dek, bucket, shard_seq,
                ).map_err(ClientError::Encryption)?;
                let data = encrypted.to_bytes().map_err(ClientError::Encryption)?;

                let client = self.inner.clone();
                let bucket_owned = bucket.to_string();
                let sem = semaphore.clone();
                let shard_key_for_task = shard_key.clone();

                let handle = tokio::spawn(async move {
                    let _permit = sem.acquire().await.map_err(|e|
                        ClientError::Encryption(fula_crypto::CryptoError::Encryption(e.to_string()))
                    )?;
                    client.put_object_with_metadata(
                        &bucket_owned,
                        &shard_key_for_task,
                        Bytes::from(data),
                        Some(ObjectMetadata::new().with_content_type("application/octet-stream")),
                    ).await?;
                    Ok::<String, ClientError>(shard_key_for_task)
                });
                handles.push(handle);
            }
        }

        // Collect shard upload results, tracking successfully uploaded keys
        // so we can compensate on Phase B failure.
        let mut uploaded_shard_keys: Vec<String> = Vec::with_capacity(handles.len());
        let mut phase_a_error: Option<ClientError> = None;
        for handle in handles {
            match handle.await {
                Ok(Ok(key)) => uploaded_shard_keys.push(key),
                Ok(Err(e)) => {
                    if phase_a_error.is_none() { phase_a_error = Some(e); }
                }
                Err(e) => {
                    if phase_a_error.is_none() {
                        phase_a_error = Some(ClientError::Encryption(
                            fula_crypto::CryptoError::Encryption(format!("Shard upload task failed: {}", e))
                        ));
                    }
                }
            }
        }

        if let Some(err) = phase_a_error {
            // Best-effort cleanup: delete any shards that DID succeed.
            for key in &uploaded_shard_keys {
                let _ = self.inner.delete_object(bucket, key).await;
            }
            return Err(err);
        }

        // Phase B: overwrite index_key with new manifest (v6 AAD-bound, sequence=1,
        // directory-aware routing). `from_migration` already set version=6; we
        // call into_v6 to lock in the current shard_sequences snapshot.
        let manifest_seq: u64 = 1;
        sharded.manifest = sharded.manifest.clone().into_v6(sharded.manifest.shard_sequences.clone());
        let encrypted_manifest = EncryptedShardManifest::encrypt_v6(
            &sharded.manifest, &forest_dek, bucket, manifest_seq,
        ).map_err(ClientError::Encryption)?;
        let manifest_data = encrypted_manifest.to_bytes().map_err(ClientError::Encryption)?;

        let manifest_put = self.inner.put_object_with_metadata(
            bucket,
            &index_key,
            Bytes::from(manifest_data),
            Some(ObjectMetadata::new().with_content_type("application/octet-stream")),
        ).await;

        let put_result = match manifest_put {
            Ok(r) => r,
            Err(e) => {
                // Manifest failed — roll back Phase A by deleting uploaded shards.
                // Without this, the shards remain orphaned because the monolithic
                // forest is still authoritative.
                for key in &uploaded_shard_keys {
                    let _ = self.inner.delete_object(bucket, key).await;
                }
                return Err(e);
            }
        };

        // Update cache (under write lock — no concurrent readers can see stale data)
        let new_etag = if put_result.etag.is_empty() { None } else { Some(put_result.etag) };
        let now = chrono::Utc::now().timestamp();
        let mut clean_forest = sharded;
        clean_forest.dirty_shards.clear();
        clean_forest.manifest_dirty = false;
        let num_shards = clean_forest.manifest.num_shards;
        self.forest_cache.insert(bucket.to_string(), ForestCacheEntry::Sharded {
            forest: clean_forest,
            loaded_at: now,
            manifest_etag: new_etag,
            last_manifest_sequence: Some(manifest_seq),
            // Phase A uploads were unconditional (first write for migrated bucket).
            // We don't have per-shard ETags to record here yet; they'll be
            // populated on the first read/write of each shard after migration.
            shard_etags: vec![None; num_shards],
        });

        let duration = start.elapsed();
        Ok(ForestEvent::MigrationCompleted {
            bucket: bucket.to_string(),
            duration_ms: duration.as_millis() as u64,
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

        let count = self.forest_cache.get(bucket).map(|entry| {
            match entry.value() {
                ForestCacheEntry::Monolithic { forest, .. } => forest.file_count(),
                ForestCacheEntry::Sharded { forest, .. } => forest.file_count(),
            }
        }).unwrap_or(0);

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

        // Generate flat storage key from cached forest
        let storage_key = {
            let cache_entry = self.forest_cache.get(bucket)
                .ok_or_else(|| ClientError::Encryption(
                    fula_crypto::CryptoError::Encryption("forest not loaded".to_string())
                ))?;
            match cache_entry.value() {
                ForestCacheEntry::Monolithic { forest, .. } => forest.generate_key(key, &dek),
                ForestCacheEntry::Sharded { forest, .. } => forest.generate_key(key, &dek),
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

        let old_storage_key: Option<String> = if is_sharded {
            // Sharded: load target shard, upsert in-place via get_mut
            let forest_dek = self.encryption.key_manager.derive_path_key(&format!("forest:{}", bucket));
            let shard_index = {
                let cache_entry = self.forest_cache.get(bucket).unwrap();
                match cache_entry.value() {
                    ForestCacheEntry::Sharded { forest, .. } => forest.shard_for(key, &forest_dek),
                    _ => unreachable!(),
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
            // Monolithic: clone, mutate, re-insert
            let (mut forest, prior_etag, prior_seq) = {
                let cache_entry = self.forest_cache.get(bucket).unwrap();
                match cache_entry.value() {
                    ForestCacheEntry::Monolithic { forest, index_etag, last_sequence, .. } =>
                        (forest.clone(), index_etag.clone(), *last_sequence),
                    _ => unreachable!(),
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
        
        // Upload chunks in parallel with bounded concurrency
        let semaphore = Arc::new(tokio::sync::Semaphore::new(Self::MAX_CONCURRENT_CHUNK_UPLOADS));
        let mut handles = Vec::with_capacity(all_chunks.len());

        for chunk in all_chunks {
            let chunk_key = ChunkedFileMetadata::chunk_key(storage_key, chunk.index);
            let chunk_metadata = ObjectMetadata::new()
                .with_content_type("application/octet-stream")
                .with_metadata("x-fula-chunk", "true")
                .with_metadata("x-fula-chunk-index", &chunk.index.to_string());

            let client = self.inner.clone();
            let bucket = bucket.to_string();
            let sem = semaphore.clone();
            let pinning = self.pinning.clone();
            let chunk_key_ret = chunk_key.clone();

            let handle = tokio::spawn(async move {
                let _permit = sem.acquire().await.map_err(|e|
                    ClientError::Encryption(fula_crypto::CryptoError::Decryption(e.to_string()))
                )?;
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

    /// Flush the forest index to storage
    ///
    /// Call this after bulk uploads using `put_object_flat_deferred`.
    /// This persists the in-memory forest index to encrypted storage.
    pub async fn flush_forest(&self, bucket: &str) -> Result<()> {
        // Acquire read lock — blocks only if migration is in progress
        let lock = self.migration_lock(bucket);
        let _guard = lock.read().await;

        let is_dirty = self.forest_cache.get(bucket)
            .map(|entry| entry.is_dirty())
            .unwrap_or(false);

        if !is_dirty {
            return Ok(());
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
            // Monolithic: check if auto-migration should happen
            let file_count = self.forest_cache.get(bucket).map(|entry| {
                match entry.value() {
                    ForestCacheEntry::Monolithic { forest, .. } => forest.file_count(),
                    _ => 0,
                }
            }).unwrap_or(0);

            if file_count >= SHARDED_MIGRATION_THRESHOLD {
                // Auto-migrate to sharded format
                self.migrate_to_sharded(bucket).await?;
                Ok(())
            } else {
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

        let storage_key = if self.is_forest_sharded(bucket) {
            // Sharded: load only the needed shard
            let forest_dek = self.encryption.key_manager.derive_path_key(&format!("forest:{}", bucket));
            let shard_index = {
                let entry = self.forest_cache.get(bucket)
                    .ok_or_else(|| ClientError::NotFound { bucket: bucket.to_string(), key: key.to_string() })?;
                match entry.value() {
                    ForestCacheEntry::Sharded { forest, .. } => forest.shard_for(key, &forest_dek),
                    _ => unreachable!(),
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
                _ => unreachable!(),
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
                _ => unreachable!(),
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
                _ => unreachable!(),
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
                _ => unreachable!(),
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

        let files: Vec<FileMetadata> = if self.is_forest_sharded(bucket) {
            self.load_all_shards(bucket).await?;
            let entry = self.forest_cache.get(bucket).unwrap();
            match entry.value() {
                ForestCacheEntry::Sharded { forest, .. } => {
                    forest.list_all_files().into_iter().map(&make_meta).collect()
                }
                _ => unreachable!(),
            }
        } else {
            let entry = self.forest_cache.get(bucket).unwrap();
            match entry.value() {
                ForestCacheEntry::Monolithic { forest, .. } => {
                    forest.list_all_files().into_iter().map(&make_meta).collect()
                }
                _ => unreachable!(),
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

        if self.is_forest_sharded(bucket) {
            // Sharded: load the needed shard, find storage key, delete
            let forest_dek = self.encryption.key_manager.derive_path_key(&format!("forest:{}", bucket));
            let shard_index = {
                let entry = self.forest_cache.get(bucket)
                    .ok_or_else(|| ClientError::NotFound { bucket: bucket.to_string(), key: key.to_string() })?;
                match entry.value() {
                    ForestCacheEntry::Sharded { forest, .. } => forest.shard_for(key, &forest_dek),
                    _ => unreachable!(),
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
                    _ => unreachable!(),
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
            self.save_forest(bucket, &forest).await?;

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
                _ => unreachable!(),
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
            // C-AUDIT-004: block plaintext response for forest-known encrypted entries
            if self.forest_entry_requires_encryption(bucket, storage_key) {
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

        // Load prior rotation state from the journal, if one was provided and exists.
        #[cfg(not(target_arch = "wasm32"))]
        let already_rotated: std::collections::HashSet<String> = match journal_path {
            Some(path) if path.exists() => {
                match std::fs::read_to_string(path) {
                    Ok(contents) => contents
                        .lines()
                        .map(|s| s.trim())
                        .filter(|s| !s.is_empty())
                        .map(|s| s.to_string())
                        .collect(),
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
        // interruption only loses the in-flight items.
        #[cfg(not(target_arch = "wasm32"))]
        let mut journal_writer: Option<std::io::BufWriter<std::fs::File>> = match journal_path {
            Some(path) => {
                use std::io::Write;
                match std::fs::OpenOptions::new().create(true).append(true).open(path) {
                    Ok(f) => {
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
                        if writeln!(w, "{}", key).is_err() || w.flush().is_err() {
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
        
        // Upload chunks in parallel with bounded concurrency
        let _uploaded_keys = {
            let semaphore = Arc::new(tokio::sync::Semaphore::new(Self::MAX_CONCURRENT_CHUNK_UPLOADS));
            let mut handles = Vec::with_capacity(chunks.len());

            for chunk in chunks {
                let chunk_key = ChunkedFileMetadata::chunk_key(&storage_key, chunk.index);
                let chunk_metadata = ObjectMetadata::new()
                    .with_content_type("application/octet-stream")
                    .with_metadata("x-fula-chunk", "true")
                    .with_metadata("x-fula-chunk-index", &chunk.index.to_string());

                let client = self.inner.clone();
                let bucket = bucket.to_string();
                let sem = semaphore.clone();
                let chunk_key_ret = chunk_key.clone();

                let handle = tokio::spawn(async move {
                    let _permit = sem.acquire().await.map_err(|e|
                        ClientError::Encryption(fula_crypto::CryptoError::Decryption(e.to_string()))
                    )?;
                    client.put_object_with_metadata(
                        &bucket,
                        &chunk_key,
                        chunk.ciphertext,
                        Some(chunk_metadata),
                    ).await?;
                    Ok::<String, ClientError>(chunk_key_ret)
                });

                handles.push(handle);
            }

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
        
        // Update forest cache if we have one
        if let Some(mut entry) = self.forest_cache.get_mut(bucket) {
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
            match entry.value_mut() {
                ForestCacheEntry::Monolithic { forest, dirty, .. } => {
                    forest.upsert_file(file_entry);
                    *dirty = true;
                }
                ForestCacheEntry::Sharded { forest, loaded_at, .. } => {
                    let forest_dek = self.encryption.key_manager.derive_path_key(&format!("forest:{}", bucket));
                    forest.upsert_file(file_entry, &forest_dek);
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
}
