//! Bucket management for S3-compatible storage

use crate::{
    CoreError, Result,
    metadata::{BucketMetadata, ObjectMetadata, Owner},
    prolly::ProllyTree,
};
use cid::Cid;
use chrono::Utc;
use fula_blockstore::{BlockStore, PinStore};
use std::sync::Arc;
use std::path::Path;
use dashmap::DashMap;
use serde::{Serialize, Deserialize};
use tracing::{instrument, info, warn, error};

/// Configuration for bucket behavior
#[derive(Clone, Debug)]
pub struct BucketConfig {
    /// Enable versioning
    pub versioning: bool,
    /// Default storage class
    pub storage_class: crate::metadata::StorageClass,
    /// Maximum keys per listing
    pub max_keys: usize,
}

impl Default for BucketConfig {
    fn default() -> Self {
        Self {
            versioning: false,
            storage_class: crate::metadata::StorageClass::Standard,
            max_keys: 1000,
        }
    }
}

/// A bucket containing objects indexed by a Prolly Tree
pub struct Bucket<S: BlockStore> {
    /// Bucket metadata
    metadata: BucketMetadata,
    /// Object index (key -> ObjectMetadata)
    index: ProllyTree<String, ObjectMetadata, S>,
    /// Configuration
    config: BucketConfig,
    /// Reference to bucket metadata cache for updates
    metadata_cache: Option<Arc<DashMap<String, BucketMetadata>>>,
    /// Key used in the metadata cache (may differ from metadata.name for user-scoped buckets)
    cache_key: Option<String>,
}

impl<S: BlockStore> Bucket<S> {
    /// Create a new bucket
    pub async fn create(
        name: String,
        owner: Owner,
        store: Arc<S>,
        config: BucketConfig,
    ) -> Result<Self> {
        // Validate bucket name
        validate_bucket_name(&name)?;

        let index: ProllyTree<String, ObjectMetadata, S> = ProllyTree::new(Arc::clone(&store));
        
        // Create initial empty root
        let mut index_mut = index;
        let root_cid = index_mut.flush().await?;

        let metadata = BucketMetadata::new(name, owner.id.clone(), root_cid);

        Ok(Self {
            metadata,
            index: index_mut,
            config,
            metadata_cache: None,
            cache_key: None,
        })
    }

    /// Load an existing bucket
    pub async fn load(
        metadata: BucketMetadata,
        store: Arc<S>,
        config: BucketConfig,
        metadata_cache: Option<Arc<DashMap<String, BucketMetadata>>>,
    ) -> Result<Self> {
        let index = ProllyTree::load(store, metadata.root_cid).await?;
        Ok(Self {
            metadata,
            index,
            config,
            metadata_cache,
            cache_key: None,
        })
    }

    /// Load an existing bucket with a specific cache key
    /// Used for user-scoped buckets where the cache key differs from the bucket name
    pub async fn load_with_cache_key(
        metadata: BucketMetadata,
        store: Arc<S>,
        config: BucketConfig,
        metadata_cache: Option<Arc<DashMap<String, BucketMetadata>>>,
        cache_key: String,
    ) -> Result<Self> {
        let index = ProllyTree::load(store, metadata.root_cid).await?;
        Ok(Self {
            metadata,
            index,
            config,
            metadata_cache,
            cache_key: Some(cache_key),
        })
    }

    /// Get bucket name
    pub fn name(&self) -> &str {
        &self.metadata.name
    }

    /// Get bucket metadata
    pub fn metadata(&self) -> &BucketMetadata {
        &self.metadata
    }

    /// Get an object by key
    #[instrument(skip(self))]
    pub async fn get_object(&self, key: &str) -> Result<Option<ObjectMetadata>> {
        self.index.get(&key.to_string()).await
    }

    /// Put an object
    #[instrument(skip(self, metadata))]
    pub async fn put_object(&mut self, key: String, metadata: ObjectMetadata) -> Result<()> {
        validate_object_key(&key)?;
        
        // Update bucket stats
        if let Some(existing) = self.index.get(&key).await? {
            self.metadata.total_size -= existing.size;
        } else {
            self.metadata.object_count += 1;
        }
        self.metadata.total_size += metadata.size;
        self.metadata.last_modified = Utc::now();

        self.index.set(key, metadata).await
    }

    /// Delete an object
    #[instrument(skip(self))]
    pub async fn delete_object(&mut self, key: &str) -> Result<Option<ObjectMetadata>> {
        let removed = self.index.remove(&key.to_string()).await?;
        
        if let Some(ref obj) = removed {
            self.metadata.object_count -= 1;
            self.metadata.total_size -= obj.size;
            self.metadata.last_modified = Utc::now();
        }
        
        Ok(removed)
    }

    /// List objects with optional prefix and delimiter
    #[instrument(skip(self))]
    pub async fn list_objects(
        &self,
        prefix: Option<&str>,
        delimiter: Option<&str>,
        start_after: Option<&str>,
        max_keys: Option<usize>,
    ) -> Result<ListObjectsResult> {
        let max = max_keys.unwrap_or(self.config.max_keys);
        let prefix_str = prefix.unwrap_or("");
        
        // Get matching entries using bounded traversal (avoids loading entire tree).
        // When a delimiter is present, some entries become common_prefixes and don't
        // count toward `max`, so we request extra to avoid under-fetching.
        let fetch_limit = if delimiter.is_some() { max * 3 } else { max };
        let start_key = start_after.map(|s| s.to_string());
        let all_entries = self.index.list_prefix_bounded(
            prefix_str.as_bytes(),
            start_key.as_ref(),
            fetch_limit,
        ).await?;

        let mut objects = Vec::new();
        let mut common_prefixes = std::collections::BTreeSet::new();
        let mut is_truncated = false;
        let mut next_marker = None;

        for (key, metadata) in all_entries {
            // Check max keys (authoritative truncation)
            if objects.len() >= max {
                is_truncated = true;
                next_marker = Some(key.clone());
                break;
            }

            // Handle delimiter (folder grouping)
            if let Some(delim) = delimiter {
                let suffix = &key[prefix_str.len()..];
                if let Some(pos) = suffix.find(delim) {
                    // This is a "folder" - add to common prefixes
                    let common_prefix = format!("{}{}{}", prefix_str, &suffix[..pos], delim);
                    common_prefixes.insert(common_prefix);
                    continue;
                }
            }

            objects.push(ListedObject {
                key,
                metadata,
            });
        }

        Ok(ListObjectsResult {
            name: self.metadata.name.clone(),
            prefix: prefix_str.to_string(),
            delimiter: delimiter.map(|s| s.to_string()),
            max_keys: max,
            is_truncated,
            objects,
            common_prefixes: common_prefixes.into_iter().collect(),
            next_continuation_token: next_marker,
        })
    }

    /// Copy an object within the bucket
    pub async fn copy_object(&mut self, source_key: &str, dest_key: &str) -> Result<ObjectMetadata> {
        let source = self.get_object(source_key).await?
            .ok_or_else(|| CoreError::ObjectNotFound {
                bucket: self.metadata.name.clone(),
                key: source_key.to_string(),
            })?;

        // Create a new metadata with updated timestamp
        let mut dest_metadata = source.clone();
        dest_metadata.last_modified = Utc::now();

        self.put_object(dest_key.to_string(), dest_metadata.clone()).await?;
        Ok(dest_metadata)
    }

    /// Get object count
    pub fn object_count(&self) -> u64 {
        self.metadata.object_count
    }

    /// Get total size
    pub fn total_size(&self) -> u64 {
        self.metadata.total_size
    }

    /// Flush changes and return the new root CID
    pub async fn flush(&mut self) -> Result<Cid> {
        let root_cid = self.index.flush().await?;
        self.metadata.root_cid = root_cid;

        // Update the metadata cache if we have a reference to it
        // Use cache_key if set (for user-scoped buckets), otherwise use bucket name
        if let Some(ref cache) = self.metadata_cache {
            let key = self.cache_key.clone().unwrap_or_else(|| self.metadata.name.clone());
            cache.insert(key, self.metadata.clone());
        }

        Ok(root_cid)
    }
}

/// Result of listing objects
#[derive(Debug, Clone)]
pub struct ListObjectsResult {
    pub name: String,
    pub prefix: String,
    pub delimiter: Option<String>,
    pub max_keys: usize,
    pub is_truncated: bool,
    pub objects: Vec<ListedObject>,
    pub common_prefixes: Vec<String>,
    pub next_continuation_token: Option<String>,
}

/// A listed object
#[derive(Debug, Clone)]
pub struct ListedObject {
    pub key: String,
    pub metadata: ObjectMetadata,
}

/// Serializable bucket registry for persistence (v1: monolithic)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BucketRegistry {
    /// Version for future migrations
    pub version: u32,
    /// All bucket metadata (v1 only — v2 uses shard_cids instead)
    #[serde(default)]
    pub buckets: Vec<BucketMetadata>,
}

impl BucketRegistry {
    /// Current registry version (still write v1 when under threshold)
    pub const CURRENT_VERSION: u32 = 1;

    /// Create a new v1 registry from bucket metadata
    pub fn new(buckets: Vec<BucketMetadata>) -> Self {
        Self {
            version: Self::CURRENT_VERSION,
            buckets,
        }
    }
}

/// V2 sharded registry root (stored at the registry CID).
/// Small manifest — just shard pointers. Each shard is a separate IPLD block.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BucketRegistryV2 {
    /// Always 2 for v2 format
    pub version: u32,
    /// Number of shards
    pub num_shards: usize,
    /// One CID per shard
    #[serde(with = "cid_vec_serde")]
    pub shard_cids: Vec<Cid>,
}

/// A single shard of the v2 registry (stored separately in IPFS)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegistryShard {
    /// Shard index (for verification)
    pub shard_index: usize,
    /// Buckets in this shard
    pub buckets: Vec<BucketMetadata>,
}

/// Threshold: switch to v2 sharded format when bucket count exceeds this.
/// Below this, v1 monolithic is fine (well under 1MB).
const SHARDED_REGISTRY_THRESHOLD: usize = 500;

/// Default number of registry shards when migrating to v2
const DEFAULT_REGISTRY_SHARDS: usize = 16;

/// Minimal struct to probe the `version` field from a DAG-CBOR registry block
/// without requiring the full schema to match.
#[derive(Deserialize)]
struct VersionProbe {
    #[serde(default = "version_probe_default")]
    version: u32,
}

fn version_probe_default() -> u32 {
    1
}

/// serde helper for Vec<Cid>
mod cid_vec_serde {
    use cid::Cid;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(cids: &[Cid], s: S) -> Result<S::Ok, S::Error> {
        let strings: Vec<String> = cids.iter().map(|c| c.to_string()).collect();
        strings.serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Cid>, D::Error> {
        let strings = Vec::<String>::deserialize(d)?;
        strings
            .into_iter()
            .map(|s| s.parse().map_err(serde::de::Error::custom))
            .collect()
    }
}

/// Bucket manager for handling multiple buckets
pub struct BucketManager<S: BlockStore + PinStore> {
    /// Block store
    store: Arc<S>,
    /// Bucket metadata cache
    buckets: Arc<DashMap<String, BucketMetadata>>,
    /// Secondary index: display name → list of internal keys.
    /// Enables O(1) admin lookup by display name instead of scanning all buckets.
    name_index: Arc<DashMap<String, Vec<String>>>,
    /// Default configuration
    default_config: BucketConfig,
    /// Path to store the registry CID (for persistence)
    registry_cid_path: Option<std::path::PathBuf>,
    /// Dirty flag: true if buckets have been modified since last persist.
    /// Avoids redundant serialization + IPFS writes on every object put.
    dirty: std::sync::atomic::AtomicBool,
}

impl<S: BlockStore + PinStore> BucketManager<S> {
    /// Create a new bucket manager
    pub fn new(store: Arc<S>) -> Self {
        Self {
            store,
            buckets: Arc::new(DashMap::new()),
            name_index: Arc::new(DashMap::new()),
            default_config: BucketConfig::default(),
            registry_cid_path: None,
            dirty: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Create a new bucket manager with persistence enabled
    pub fn with_persistence(store: Arc<S>, registry_cid_path: impl AsRef<Path>) -> Self {
        Self {
            store,
            buckets: Arc::new(DashMap::new()),
            name_index: Arc::new(DashMap::new()),
            default_config: BucketConfig::default(),
            registry_cid_path: Some(registry_cid_path.as_ref().to_path_buf()),
            dirty: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Rebuild the name_index from the current buckets DashMap
    fn rebuild_name_index(&self) {
        self.name_index.clear();
        for entry in self.buckets.iter() {
            let internal_key = entry.key().clone();
            let display_name = entry.value().name.clone();
            self.name_index
                .entry(display_name)
                .or_insert_with(Vec::new)
                .push(internal_key);
        }
    }

    /// Add a single entry to the name index
    fn index_add(&self, display_name: &str, internal_key: &str) {
        self.name_index
            .entry(display_name.to_string())
            .or_insert_with(Vec::new)
            .push(internal_key.to_string());
    }

    /// Remove a single entry from the name index
    fn index_remove(&self, display_name: &str, internal_key: &str) {
        if let Some(mut keys) = self.name_index.get_mut(display_name) {
            keys.retain(|k| k != internal_key);
            if keys.is_empty() {
                drop(keys);
                self.name_index.remove(display_name);
            }
        }
    }

    /// Load bucket registry from IPFS on startup
    /// Returns the number of buckets loaded
    pub async fn load_registry(&self) -> Result<usize> {
        let cid_path = match &self.registry_cid_path {
            Some(p) => p,
            None => {
                info!("No registry CID path configured, starting with empty registry");
                return Ok(0);
            }
        };

        // Read CID from file
        let cid_str = match std::fs::read_to_string(cid_path) {
            Ok(s) => s.trim().to_string(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                info!(path = %cid_path.display(), "Registry CID file not found, starting fresh");
                return Ok(0);
            }
            Err(e) => {
                error!(path = %cid_path.display(), error = %e, "Failed to read registry CID file");
                return Err(CoreError::StorageError(format!(
                    "Failed to read registry CID: {}",
                    e
                )));
            }
        };

        if cid_str.is_empty() {
            info!("Registry CID file is empty, starting fresh");
            return Ok(0);
        }

        // Parse CID
        let cid: Cid = cid_str.parse().map_err(|e: cid::Error| {
            CoreError::StorageError(format!("Invalid registry CID '{}': {}", cid_str, e))
        })?;

        info!(cid = %cid, "Loading bucket registry from IPFS");

        // Fetch raw block from IPFS with retry logic and exponential backoff.
        // We fetch bytes instead of get_ipld<BucketRegistry> so we can probe the
        // version field first and then deserialize as v1 or v2.
        let max_attempts = 5;
        let mut attempts = 0;
        let mut delay = std::time::Duration::from_secs(1);

        let raw_bytes = loop {
            match self.store.get_block(&cid).await {
                Ok(bytes) => break bytes,
                Err(e) if attempts < max_attempts - 1 => {
                    attempts += 1;
                    warn!(
                        attempt = attempts,
                        max_attempts = max_attempts,
                        delay_secs = delay.as_secs(),
                        error = %e,
                        cid = %cid,
                        "Failed to fetch registry from IPFS, retrying..."
                    );
                    tokio::time::sleep(delay).await;
                    delay *= 2; // Exponential backoff
                }
                Err(e) => {
                    error!(
                        cid = %cid,
                        error = %e,
                        attempts = max_attempts,
                        "Failed to load registry from IPFS after all retry attempts"
                    );
                    return Err(CoreError::StorageError(format!(
                        "Failed to load registry from IPFS after {} attempts: {}",
                        max_attempts, e
                    )));
                }
            }
        };

        // Probe the version field to determine format
        let probe: VersionProbe = serde_ipld_dagcbor::from_slice(&raw_bytes).map_err(|e| {
            CoreError::StorageError(format!("Failed to probe registry version: {}", e))
        })?;

        let all_buckets: Vec<BucketMetadata> = if probe.version >= 2 {
            // V2 sharded format: manifest + per-shard blocks
            info!(version = probe.version, "Loading v2 sharded registry");
            let manifest: BucketRegistryV2 =
                serde_ipld_dagcbor::from_slice(&raw_bytes).map_err(|e| {
                    CoreError::StorageError(format!("Failed to deserialize v2 manifest: {}", e))
                })?;

            let mut buckets = Vec::new();
            for (i, shard_cid) in manifest.shard_cids.iter().enumerate() {
                let shard: RegistryShard = self.store.get_ipld(shard_cid).await.map_err(|e| {
                    CoreError::StorageError(format!(
                        "Failed to load registry shard {} ({}): {}",
                        i, shard_cid, e
                    ))
                })?;
                buckets.extend(shard.buckets);
            }
            buckets
        } else {
            // V1 monolithic format
            let registry: BucketRegistry =
                serde_ipld_dagcbor::from_slice(&raw_bytes).map_err(|e| {
                    CoreError::StorageError(format!("Failed to deserialize v1 registry: {}", e))
                })?;

            if registry.version > BucketRegistry::CURRENT_VERSION {
                warn!(
                    stored_version = registry.version,
                    current_version = BucketRegistry::CURRENT_VERSION,
                    "Registry version is newer than supported, some features may not work"
                );
            }

            registry.buckets
        };

        // Populate the in-memory cache
        // IMPORTANT: Use the same key format as create_bucket_for_user: {owner_id}:{name}
        // This ensures buckets from different users with the same name don't collide
        let count = all_buckets.len();
        for bucket_meta in all_buckets {
            let internal_key = Self::scoped_bucket_key(&bucket_meta.owner_id, &bucket_meta.name);
            info!(
                bucket = %bucket_meta.name,
                owner_id = %bucket_meta.owner_id,
                internal_key = %internal_key,
                "Restoring bucket from registry"
            );
            self.buckets.insert(internal_key, bucket_meta);
        }

        // Build the secondary name index for O(1) admin lookups
        self.rebuild_name_index();

        info!(bucket_count = count, "Bucket registry loaded successfully");
        Ok(count)
    }

    /// Persist the bucket registry to IPFS (uses local pinning, no remote auth)
    pub async fn persist_registry(&self) -> Result<Cid> {
        self.persist_registry_internal(None).await
    }

    /// Persist the bucket registry to IPFS with user-provided authentication token
    /// This forwards the user's JWT to the remote pinning service
    pub async fn persist_registry_with_token(&self, token: &str) -> Result<Cid> {
        self.persist_registry_internal(Some(token)).await
    }

    /// Internal implementation for registry persistence.
    ///
    /// Uses v1 monolithic format when bucket count <= SHARDED_REGISTRY_THRESHOLD,
    /// auto-upgrades to v2 sharded format when it exceeds the threshold.
    async fn persist_registry_internal(&self, token: Option<&str>) -> Result<Cid> {
        // Collect all bucket metadata
        let buckets: Vec<BucketMetadata> = self.buckets.iter().map(|r| r.value().clone()).collect();
        let bucket_count = buckets.len();

        info!(bucket_count = bucket_count, "Persisting bucket registry to IPFS");

        let cid = if bucket_count > SHARDED_REGISTRY_THRESHOLD {
            // V2 sharded format: partition buckets into shards
            self.persist_registry_v2(buckets, token).await?
        } else {
            // V1 monolithic: all buckets in one block
            let registry = BucketRegistry::new(buckets);
            self.store.put_ipld(&registry).await.map_err(|e| {
                CoreError::StorageError(format!("Failed to store registry in IPFS: {}", e))
            })?
        };

        // Pin the registry for persistence (with or without user token)
        if let Some(t) = token {
            self.store.pin_with_token(&cid, Some("fula-bucket-registry"), t).await.map_err(|e| {
                CoreError::StorageError(format!("Failed to pin registry: {}", e))
            })?;
        } else {
            self.store.pin(&cid, Some("fula-bucket-registry")).await.map_err(|e| {
                CoreError::StorageError(format!("Failed to pin registry: {}", e))
            })?;
        }

        // Save CID to local file if path is configured
        if let Some(ref path) = self.registry_cid_path {
            // Ensure parent directory exists
            if let Some(parent) = path.parent() {
                if !parent.exists() {
                    std::fs::create_dir_all(parent).map_err(|e| {
                        CoreError::StorageError(format!(
                            "Failed to create directory {}: {}",
                            parent.display(),
                            e
                        ))
                    })?;
                }
            }

            // Backup existing CID file before overwriting to prevent data loss
            if path.exists() {
                let backup_path = path.with_extension("cid.bak");
                if let Err(e) = std::fs::copy(path, &backup_path) {
                    warn!(
                        error = %e,
                        backup_path = %backup_path.display(),
                        "Failed to backup registry CID file"
                    );
                } else {
                    info!(
                        backup_path = %backup_path.display(),
                        "Backed up previous registry CID"
                    );
                }
            }

            std::fs::write(path, cid.to_string()).map_err(|e| {
                CoreError::StorageError(format!(
                    "Failed to write registry CID to {}: {}",
                    path.display(),
                    e
                ))
            })?;

            info!(cid = %cid, path = %path.display(), "Registry CID saved to file");
        }

        self.dirty.store(false, std::sync::atomic::Ordering::Relaxed);
        Ok(cid)
    }

    /// Persist bucket registry in v2 sharded format.
    /// Partitions buckets into shards, stores each shard separately, then
    /// stores a small manifest with shard CIDs as the root block.
    async fn persist_registry_v2(
        &self,
        buckets: Vec<BucketMetadata>,
        token: Option<&str>,
    ) -> Result<Cid> {
        let num_shards = DEFAULT_REGISTRY_SHARDS;
        let mut shards: Vec<Vec<BucketMetadata>> = (0..num_shards).map(|_| Vec::new()).collect();

        // Partition by hash(owner_id) % num_shards
        for bucket in buckets {
            let hash = {
                let mut hasher = std::collections::hash_map::DefaultHasher::new();
                std::hash::Hash::hash(&bucket.owner_id, &mut hasher);
                std::hash::Hasher::finish(&hasher) as usize
            };
            shards[hash % num_shards].push(bucket);
        }

        // Store each shard as a separate IPLD block
        let mut shard_cids = Vec::with_capacity(num_shards);
        for (i, shard_buckets) in shards.into_iter().enumerate() {
            let shard = RegistryShard {
                shard_index: i,
                buckets: shard_buckets,
            };
            let shard_cid = self.store.put_ipld(&shard).await.map_err(|e| {
                CoreError::StorageError(format!("Failed to store registry shard {}: {}", i, e))
            })?;
            shard_cids.push(shard_cid);
        }

        // Store the v2 manifest (small — just CID pointers)
        let manifest = BucketRegistryV2 {
            version: 2,
            num_shards,
            shard_cids,
        };
        let cid = self.store.put_ipld(&manifest).await.map_err(|e| {
            CoreError::StorageError(format!("Failed to store v2 registry manifest: {}", e))
        })?;

        // Pin the root manifest
        if let Some(t) = token {
            self.store.pin_with_token(&cid, Some("fula-bucket-registry-v2"), t).await.map_err(|e| {
                CoreError::StorageError(format!("Failed to pin v2 registry: {}", e))
            })?;
        } else {
            self.store.pin(&cid, Some("fula-bucket-registry-v2")).await.map_err(|e| {
                CoreError::StorageError(format!("Failed to pin v2 registry: {}", e))
            })?;
        }

        info!(cid = %cid, num_shards = num_shards, "Persisted v2 sharded registry");
        Ok(cid)
    }

    /// Create a new bucket
    #[instrument(skip(self))]
    pub async fn create_bucket(
        &self,
        name: String,
        owner: Owner,
    ) -> Result<BucketMetadata> {
        tracing::debug!(bucket_name = %name, "Creating bucket");
        
        // Check if bucket already exists
        if self.buckets.contains_key(&name) {
            return Err(CoreError::BucketAlreadyExists(name));
        }

        let bucket = Bucket::create(
            name.clone(),
            owner,
            Arc::clone(&self.store),
            self.default_config.clone(),
        ).await?;

        let metadata = bucket.metadata().clone();
        tracing::debug!(bucket_name = %name, root_cid = %metadata.root_cid, "Bucket created in IPFS, adding to registry");
        
        self.buckets.insert(name.clone(), metadata.clone());
        self.index_add(&metadata.name, &name);
        self.dirty.store(true, std::sync::atomic::Ordering::Relaxed);

        // Persist the registry after adding a bucket
        if let Err(e) = self.persist_registry().await {
            warn!(error = %e, "Failed to persist registry after bucket creation");
            // Don't fail the operation, bucket is still created in memory
        }

        tracing::info!(bucket_name = %name, total_buckets = %self.buckets.len(), "Bucket registered successfully");

        Ok(metadata)
    }

    /// Get bucket metadata
    pub fn get_bucket_metadata(&self, name: &str) -> Option<BucketMetadata> {
        self.buckets.get(name).map(|r| r.clone())
    }

    /// Open a bucket for operations
    pub async fn open_bucket(&self, name: &str) -> Result<Bucket<S>> {
        tracing::debug!(bucket_name = %name, registered_buckets = ?self.buckets.iter().map(|r| r.key().clone()).collect::<Vec<_>>(), "Opening bucket");
        
        let metadata = self.buckets.get(name)
            .map(|r| r.clone())
            .ok_or_else(|| {
                tracing::error!(bucket_name = %name, "Bucket not found in registry");
                CoreError::BucketNotFound(name.to_string())
            })?;

        Bucket::load(
            metadata,
            Arc::clone(&self.store),
            self.default_config.clone(),
            Some(Arc::clone(&self.buckets)),
        ).await
    }

    /// Delete a bucket
    pub async fn delete_bucket(&self, name: &str) -> Result<()> {
        let bucket = self.open_bucket(name).await?;

        if bucket.object_count() > 0 {
            return Err(CoreError::PreconditionFailed(
                "Bucket is not empty".to_string(),
            ));
        }

        // Remove from name index before removing from buckets
        let display_name = bucket.metadata().name.clone();
        self.index_remove(&display_name, name);
        self.buckets.remove(name);
        self.dirty.store(true, std::sync::atomic::Ordering::Relaxed);

        // Persist the registry after removing a bucket
        if let Err(e) = self.persist_registry().await {
            warn!(error = %e, "Failed to persist registry after bucket deletion");
            // Don't fail the operation, bucket is still deleted from memory
        }

        Ok(())
    }

    /// List all buckets
    pub fn list_buckets(&self) -> Vec<BucketMetadata> {
        self.buckets.iter().map(|r| r.clone()).collect()
    }

    /// Check if bucket exists
    pub fn bucket_exists(&self, name: &str) -> bool {
        self.buckets.contains_key(name)
    }

    // =========================================================================
    // User-scoped bucket operations (per-user isolation)
    // =========================================================================

    /// Generate internal bucket key with user namespace
    /// Format: {user_id}:{bucket_name}
    fn scoped_bucket_key(user_id: &str, bucket_name: &str) -> String {
        format!("{}:{}", user_id, bucket_name)
    }

    /// Check if bucket exists for this user
    pub fn bucket_exists_for_user(&self, user_id: &str, name: &str) -> bool {
        let key = Self::scoped_bucket_key(user_id, name);
        self.buckets.contains_key(&key)
    }

    /// Create a new bucket scoped to user
    #[instrument(skip(self))]
    pub async fn create_bucket_for_user(
        &self,
        user_id: &str,
        name: String,
        owner: Owner,
    ) -> Result<BucketMetadata> {
        let internal_key = Self::scoped_bucket_key(user_id, &name);
        tracing::debug!(bucket_name = %name, internal_key = %internal_key, "Creating user-scoped bucket");

        // Validate the display name
        validate_bucket_name(&name)?;

        // Check if bucket already exists for this user
        if self.buckets.contains_key(&internal_key) {
            return Err(CoreError::BucketAlreadyExists(name));
        }

        // Create the bucket with the display name (not the internal key)
        let bucket = Bucket::create(
            name.clone(),
            owner,
            Arc::clone(&self.store),
            self.default_config.clone(),
        ).await?;

        let metadata = bucket.metadata().clone();
        tracing::debug!(bucket_name = %name, internal_key = %internal_key, root_cid = %metadata.root_cid, "Bucket created in IPFS");

        // Store with internal key, but metadata contains display name
        self.buckets.insert(internal_key.clone(), metadata.clone());
        self.index_add(&metadata.name, &internal_key);
        self.dirty.store(true, std::sync::atomic::Ordering::Relaxed);

        // Persist the registry after adding a bucket
        if let Err(e) = self.persist_registry().await {
            warn!(error = %e, "Failed to persist registry after bucket creation");
        }

        tracing::info!(bucket_name = %name, internal_key = %internal_key, total_buckets = %self.buckets.len(), "User-scoped bucket registered");

        Ok(metadata)
    }

    /// Open a bucket for a specific user
    pub async fn open_bucket_for_user(&self, user_id: &str, name: &str) -> Result<Bucket<S>> {
        let internal_key = Self::scoped_bucket_key(user_id, name);
        tracing::debug!(bucket_name = %name, internal_key = %internal_key, "Opening user-scoped bucket");

        let metadata = self.buckets.get(&internal_key)
            .map(|r| r.clone())
            .ok_or_else(|| {
                tracing::error!(bucket_name = %name, internal_key = %internal_key, "User-scoped bucket not found");
                CoreError::BucketNotFound(name.to_string())
            })?;

        // Use load_with_cache_key so flush() updates the correct entry
        Bucket::load_with_cache_key(
            metadata,
            Arc::clone(&self.store),
            self.default_config.clone(),
            Some(Arc::clone(&self.buckets)),
            internal_key,
        ).await
    }

    /// Delete a bucket for a specific user
    pub async fn delete_bucket_for_user(&self, user_id: &str, name: &str) -> Result<()> {
        let internal_key = Self::scoped_bucket_key(user_id, name);

        let bucket = self.open_bucket_for_user(user_id, name).await?;

        if bucket.object_count() > 0 {
            return Err(CoreError::PreconditionFailed(
                "Bucket is not empty".to_string(),
            ));
        }

        self.index_remove(name, &internal_key);
        self.buckets.remove(&internal_key);
        self.dirty.store(true, std::sync::atomic::Ordering::Relaxed);

        // Persist the registry after removing a bucket
        if let Err(e) = self.persist_registry().await {
            warn!(error = %e, "Failed to persist registry after bucket deletion");
        }

        Ok(())
    }

    /// Get bucket metadata for a specific user
    pub fn get_bucket_metadata_for_user(&self, user_id: &str, name: &str) -> Option<BucketMetadata> {
        let internal_key = Self::scoped_bucket_key(user_id, name);
        self.buckets.get(&internal_key).map(|r| r.clone())
    }

    /// List all buckets for a specific user
    /// Returns buckets with their display names (not internal keys)
    pub fn list_buckets_for_user(&self, user_id: &str) -> Vec<BucketMetadata> {
        let prefix = format!("{}:", user_id);
        self.buckets
            .iter()
            .filter(|r| r.key().starts_with(&prefix))
            .map(|r| r.value().clone())
            .collect()
    }

    /// Find a bucket by display name that contains a specific object key
    ///
    /// Uses the secondary name index for O(1) lookup of matching buckets
    /// instead of scanning all buckets. This is used by admin endpoints
    /// where the user context is not known.
    ///
    /// Returns the object metadata if found.
    pub async fn find_object_in_bucket(&self, display_name: &str, key: &str) -> Option<crate::metadata::ObjectMetadata> {
        tracing::debug!(
            target_bucket = %display_name,
            target_key = %key,
            "Searching for object in bucket via name index"
        );

        // Use name index for O(1) lookup of internal keys with this display name
        let internal_keys: Vec<String> = match self.name_index.get(display_name) {
            Some(keys) => keys.clone(),
            None => {
                tracing::debug!(
                    target_bucket = %display_name,
                    "No buckets found with this display name"
                );
                return None;
            }
        };

        for internal_key in &internal_keys {
            let metadata = match self.buckets.get(internal_key) {
                Some(m) => m.clone(),
                None => continue,
            };

            tracing::debug!(
                internal_key = %internal_key,
                bucket_name = %metadata.name,
                root_cid = %metadata.root_cid,
                object_count = metadata.object_count,
                "Found matching bucket, attempting to load"
            );

            match Bucket::load(
                metadata,
                Arc::clone(&self.store),
                self.default_config.clone(),
                None,
            ).await {
                Ok(bucket) => {
                    match bucket.get_object(key).await {
                        Ok(Some(obj_meta)) => {
                            tracing::debug!(
                                bucket = %display_name,
                                key = %key,
                                cid = %obj_meta.cid,
                                "Found object"
                            );
                            return Some(obj_meta);
                        }
                        Ok(None) => {
                            tracing::debug!(
                                bucket = %display_name,
                                key = %key,
                                "Object not found in this bucket"
                            );
                        }
                        Err(e) => {
                            tracing::warn!(
                                bucket = %display_name,
                                key = %key,
                                error = %e,
                                "Error getting object from bucket"
                            );
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        bucket = %display_name,
                        internal_key = %internal_key,
                        error = %e,
                        "Failed to load bucket"
                    );
                }
            }
        }

        tracing::debug!(
            target_bucket = %display_name,
            target_key = %key,
            matching_buckets = internal_keys.len(),
            "Object not found in any matching bucket"
        );
        None
    }
}

/// Validate bucket name according to S3 rules
fn validate_bucket_name(name: &str) -> Result<()> {
    if name.len() < 3 || name.len() > 63 {
        return Err(CoreError::InvalidBucketName(
            "Bucket name must be between 3 and 63 characters".to_string(),
        ));
    }

    if !name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '.') {
        return Err(CoreError::InvalidBucketName(
            "Bucket name can only contain lowercase letters, numbers, hyphens, and periods".to_string(),
        ));
    }

    if name.starts_with('-') || name.ends_with('-') {
        return Err(CoreError::InvalidBucketName(
            "Bucket name cannot start or end with a hyphen".to_string(),
        ));
    }

    Ok(())
}

/// Validate object key
fn validate_object_key(key: &str) -> Result<()> {
    if key.is_empty() {
        return Err(CoreError::InvalidObjectKey("Key cannot be empty".to_string()));
    }

    if key.len() > 1024 {
        return Err(CoreError::InvalidObjectKey(
            "Key cannot exceed 1024 characters".to_string(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use fula_blockstore::MemoryBlockStore;

    #[test]
    fn test_bucket_name_validation() {
        assert!(validate_bucket_name("my-bucket").is_ok());
        assert!(validate_bucket_name("my.bucket.name").is_ok());
        assert!(validate_bucket_name("bucket123").is_ok());
        
        assert!(validate_bucket_name("ab").is_err()); // Too short
        assert!(validate_bucket_name("-bucket").is_err()); // Starts with hyphen
        assert!(validate_bucket_name("Bucket").is_err()); // Uppercase
    }

    #[tokio::test]
    async fn test_bucket_operations() {
        let store = Arc::new(MemoryBlockStore::new());
        let owner = Owner::new("user123");
        
        let mut bucket = Bucket::create(
            "test-bucket".to_string(),
            owner,
            store,
            BucketConfig::default(),
        ).await.unwrap();

        // Put object
        let cid = fula_blockstore::cid_utils::create_cid(
            b"test",
            fula_blockstore::cid_utils::CidCodec::Raw,
        );
        let metadata = ObjectMetadata::new(cid, 100, "abc123".to_string());
        bucket.put_object("test-key".to_string(), metadata).await.unwrap();

        // Get object
        let retrieved = bucket.get_object("test-key").await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().size, 100);

        // List objects
        let list = bucket.list_objects(None, None, None, None).await.unwrap();
        assert_eq!(list.objects.len(), 1);
    }

    #[tokio::test]
    async fn test_bucket_manager() {
        let store = Arc::new(MemoryBlockStore::new());
        let manager = BucketManager::new(store);

        let owner = Owner::new("user123");
        manager.create_bucket("bucket1".to_string(), owner.clone()).await.unwrap();
        manager.create_bucket("bucket2".to_string(), owner).await.unwrap();

        assert!(manager.bucket_exists("bucket1"));
        assert!(manager.bucket_exists("bucket2"));
        assert!(!manager.bucket_exists("bucket3"));

        let buckets = manager.list_buckets();
        assert_eq!(buckets.len(), 2);
    }

    #[tokio::test]
    async fn test_bucket_registry_serialization() {
        use crate::metadata::BucketMetadata;
        
        let cid = fula_blockstore::cid_utils::create_cid(
            b"root",
            fula_blockstore::cid_utils::CidCodec::DagCbor,
        );
        
        let buckets = vec![
            BucketMetadata::new("bucket1".to_string(), "owner1".to_string(), cid),
            BucketMetadata::new("bucket2".to_string(), "owner2".to_string(), cid),
        ];
        
        let registry = BucketRegistry::new(buckets);
        assert_eq!(registry.version, BucketRegistry::CURRENT_VERSION);
        assert_eq!(registry.buckets.len(), 2);
        
        // Test serialization roundtrip
        let serialized = serde_json::to_string(&registry).unwrap();
        let deserialized: BucketRegistry = serde_json::from_str(&serialized).unwrap();
        
        assert_eq!(deserialized.version, registry.version);
        assert_eq!(deserialized.buckets.len(), registry.buckets.len());
        assert_eq!(deserialized.buckets[0].name, "bucket1");
        assert_eq!(deserialized.buckets[1].name, "bucket2");
    }

    #[tokio::test]
    async fn test_bucket_manager_persistence() {
        use tempfile::tempdir;

        let temp_dir = tempdir().unwrap();
        let cid_path = temp_dir.path().join("registry.cid");

        // Create a shared store that simulates IPFS persistence
        let store = Arc::new(MemoryBlockStore::new());

        // Use a consistent user_id for testing (this matches production flow)
        let user_id = "user123";

        // Create manager with persistence and add buckets
        {
            let manager = BucketManager::with_persistence(Arc::clone(&store), &cid_path);

            let owner = Owner::new(user_id);
            // Use create_bucket_for_user to match production behavior (per-user bucket isolation)
            manager.create_bucket_for_user(user_id, "persist-bucket1".to_string(), owner.clone()).await.unwrap();
            manager.create_bucket_for_user(user_id, "persist-bucket2".to_string(), owner).await.unwrap();

            assert_eq!(manager.list_buckets().len(), 2);

            // Verify CID file was created
            assert!(cid_path.exists(), "Registry CID file should exist");
        }

        // Create a new manager and load the registry
        {
            let manager = BucketManager::with_persistence(Arc::clone(&store), &cid_path);

            // Initially empty
            assert_eq!(manager.list_buckets().len(), 0);

            // Load from persisted registry
            let loaded_count = manager.load_registry().await.unwrap();
            assert_eq!(loaded_count, 2, "Should load 2 buckets from registry");

            // Verify buckets are restored (use user-scoped check to match how they were created)
            assert!(manager.bucket_exists_for_user(user_id, "persist-bucket1"));
            assert!(manager.bucket_exists_for_user(user_id, "persist-bucket2"));
            assert_eq!(manager.list_buckets().len(), 2);
        }
    }

    #[tokio::test]
    async fn test_bucket_manager_persistence_empty_start() {
        use tempfile::tempdir;

        let temp_dir = tempdir().unwrap();
        let cid_path = temp_dir.path().join("nonexistent.cid");

        let store = Arc::new(MemoryBlockStore::new());
        let manager = BucketManager::with_persistence(store, &cid_path);

        // Should gracefully handle missing CID file
        let loaded_count = manager.load_registry().await.unwrap();
        assert_eq!(loaded_count, 0, "Should start with 0 buckets when CID file doesn't exist");
    }

    #[tokio::test]
    async fn test_registry_v2_sharded_roundtrip() {
        use crate::metadata::BucketMetadata;
        use tempfile::tempdir;

        let temp_dir = tempdir().unwrap();
        let cid_path = temp_dir.path().join("registry.cid");
        let store = Arc::new(MemoryBlockStore::new());

        // Build a bucket list larger than the sharding threshold so
        // persist_registry_internal writes v2 format.
        let manager = BucketManager::with_persistence(Arc::clone(&store), &cid_path);
        let root_cid = fula_blockstore::cid_utils::create_cid(
            b"root",
            fula_blockstore::cid_utils::CidCodec::DagCbor,
        );

        let bucket_count = SHARDED_REGISTRY_THRESHOLD + 10;
        for i in 0..bucket_count {
            let owner_id = format!("owner_{}", i % 50); // 50 distinct owners
            let name = format!("bucket_{}", i);
            let meta = BucketMetadata::new(name.clone(), owner_id.clone(), root_cid);
            let key = BucketManager::<MemoryBlockStore>::scoped_bucket_key(&owner_id, &name);
            manager.buckets.insert(key, meta);
        }

        // Persist — should choose v2 because count > threshold
        manager.persist_registry().await.unwrap();
        assert!(cid_path.exists());

        // Verify root block is v2 format
        let cid_str = std::fs::read_to_string(&cid_path).unwrap();
        let cid: Cid = cid_str.parse().unwrap();
        let raw = store.get_block(&cid).await.unwrap();
        let probe: VersionProbe =
            serde_ipld_dagcbor::from_slice(&raw).unwrap();
        assert_eq!(probe.version, 2, "Root block should be v2 after sharded persist");

        // Load into a fresh manager — exercises v2 load path
        let manager2 = BucketManager::with_persistence(Arc::clone(&store), &cid_path);
        let loaded = manager2.load_registry().await.unwrap();
        assert_eq!(loaded, bucket_count, "Should reload all buckets from v2 shards");

        // Spot-check a few buckets
        assert!(manager2.buckets.contains_key(
            &BucketManager::<MemoryBlockStore>::scoped_bucket_key("owner_0", "bucket_0")
        ));
        // bucket_count-1 = 509, owner = 509 % 50 = 9
        let last_idx = bucket_count - 1;
        let last_owner = format!("owner_{}", last_idx % 50);
        assert!(manager2.buckets.contains_key(
            &BucketManager::<MemoryBlockStore>::scoped_bucket_key(&last_owner, &format!("bucket_{}", last_idx))
        ));
    }

    #[tokio::test]
    async fn test_registry_v1_loaded_by_new_code() {
        // Ensure the v2-aware load_registry can still read v1 format
        use crate::metadata::BucketMetadata;
        use tempfile::tempdir;

        let temp_dir = tempdir().unwrap();
        let cid_path = temp_dir.path().join("registry.cid");
        let store = Arc::new(MemoryBlockStore::new());

        // Manually store a v1 registry
        let root_cid = fula_blockstore::cid_utils::create_cid(
            b"root",
            fula_blockstore::cid_utils::CidCodec::DagCbor,
        );
        let buckets = vec![
            BucketMetadata::new("alpha".to_string(), "user_a".to_string(), root_cid),
            BucketMetadata::new("beta".to_string(), "user_b".to_string(), root_cid),
        ];
        let registry = BucketRegistry::new(buckets);
        let cid = store.put_ipld(&registry).await.unwrap();
        std::fs::write(&cid_path, cid.to_string()).unwrap();

        // Load with the new version-aware code
        let manager = BucketManager::with_persistence(Arc::clone(&store), &cid_path);
        let loaded = manager.load_registry().await.unwrap();
        assert_eq!(loaded, 2);
        assert!(manager.buckets.contains_key(
            &BucketManager::<MemoryBlockStore>::scoped_bucket_key("user_a", "alpha")
        ));
        assert!(manager.buckets.contains_key(
            &BucketManager::<MemoryBlockStore>::scoped_bucket_key("user_b", "beta")
        ));
    }
}
