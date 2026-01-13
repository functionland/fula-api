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
        
        // Get all matching entries
        let all_entries = self.index.list_prefix(prefix_str.as_bytes()).await?;
        
        let mut objects = Vec::new();
        let mut common_prefixes = std::collections::BTreeSet::new();
        let mut is_truncated = false;
        let mut next_marker = None;

        for (key, metadata) in all_entries {
            // Apply start_after filter
            if let Some(start) = start_after {
                if key.as_str() <= start {
                    continue;
                }
            }

            // Check max keys
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

/// Serializable bucket registry for persistence
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BucketRegistry {
    /// Version for future migrations
    pub version: u32,
    /// All bucket metadata
    pub buckets: Vec<BucketMetadata>,
}

impl BucketRegistry {
    /// Current registry version
    pub const CURRENT_VERSION: u32 = 1;

    /// Create a new registry from bucket metadata
    pub fn new(buckets: Vec<BucketMetadata>) -> Self {
        Self {
            version: Self::CURRENT_VERSION,
            buckets,
        }
    }
}

/// Bucket manager for handling multiple buckets
pub struct BucketManager<S: BlockStore + PinStore> {
    /// Block store
    store: Arc<S>,
    /// Bucket metadata cache
    buckets: Arc<DashMap<String, BucketMetadata>>,
    /// Default configuration
    default_config: BucketConfig,
    /// Path to store the registry CID (for persistence)
    registry_cid_path: Option<std::path::PathBuf>,
}

impl<S: BlockStore + PinStore> BucketManager<S> {
    /// Create a new bucket manager
    pub fn new(store: Arc<S>) -> Self {
        Self {
            store,
            buckets: Arc::new(DashMap::new()),
            default_config: BucketConfig::default(),
            registry_cid_path: None,
        }
    }

    /// Create a new bucket manager with persistence enabled
    pub fn with_persistence(store: Arc<S>, registry_cid_path: impl AsRef<Path>) -> Self {
        Self {
            store,
            buckets: Arc::new(DashMap::new()),
            default_config: BucketConfig::default(),
            registry_cid_path: Some(registry_cid_path.as_ref().to_path_buf()),
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

        // Fetch registry from IPFS
        let registry: BucketRegistry = self.store.get_ipld(&cid).await.map_err(|e| {
            CoreError::StorageError(format!("Failed to load registry from IPFS: {}", e))
        })?;

        // Validate version
        if registry.version > BucketRegistry::CURRENT_VERSION {
            warn!(
                stored_version = registry.version,
                current_version = BucketRegistry::CURRENT_VERSION,
                "Registry version is newer than supported, some features may not work"
            );
        }

        // Populate the in-memory cache
        let count = registry.buckets.len();
        for bucket_meta in registry.buckets {
            info!(bucket = %bucket_meta.name, "Restoring bucket from registry");
            self.buckets.insert(bucket_meta.name.clone(), bucket_meta);
        }

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

    /// Internal implementation for registry persistence
    async fn persist_registry_internal(&self, token: Option<&str>) -> Result<Cid> {
        // Collect all bucket metadata
        let buckets: Vec<BucketMetadata> = self.buckets.iter().map(|r| r.value().clone()).collect();
        let registry = BucketRegistry::new(buckets);

        info!(bucket_count = registry.buckets.len(), "Persisting bucket registry to IPFS");

        // Store as IPLD (DAG-CBOR)
        let cid = self.store.put_ipld(&registry).await.map_err(|e| {
            CoreError::StorageError(format!("Failed to store registry in IPFS: {}", e))
        })?;

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

            std::fs::write(path, cid.to_string()).map_err(|e| {
                CoreError::StorageError(format!(
                    "Failed to write registry CID to {}: {}",
                    path.display(),
                    e
                ))
            })?;

            info!(cid = %cid, path = %path.display(), "Registry CID saved to file");
        }

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

        self.buckets.remove(name);
        
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

        self.buckets.remove(&internal_key);

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
    /// Searches all users' buckets for one with matching display name that contains the key.
    /// This is used by admin endpoints where the user context is not known.
    ///
    /// Returns the object metadata if found.
    pub async fn find_object_in_bucket(&self, display_name: &str, key: &str) -> Option<crate::metadata::ObjectMetadata> {
        let bucket_count = self.buckets.len();
        let bucket_names: Vec<String> = self.buckets.iter()
            .map(|r| format!("{} (key={})", r.value().name.clone(), r.key().clone()))
            .collect();
        tracing::debug!(
            target_bucket = %display_name,
            target_key = %key,
            total_buckets = bucket_count,
            available_buckets = ?bucket_names,
            "Searching for object in bucket"
        );

        // Iterate through all buckets
        let mut matching_buckets = 0;
        for entry in self.buckets.iter() {
            let metadata = entry.value();
            if metadata.name == display_name {
                matching_buckets += 1;
                tracing::debug!(
                    internal_key = %entry.key(),
                    bucket_name = %metadata.name,
                    root_cid = %metadata.root_cid,
                    object_count = metadata.object_count,
                    "Found matching bucket, attempting to load"
                );

                // Try to load this bucket and find the object
                match Bucket::load(
                    metadata.clone(),
                    Arc::clone(&self.store),
                    self.default_config.clone(),
                    None, // Don't need cache updates for read-only
                ).await {
                    Ok(bucket) => {
                        // List first few objects for debugging
                        if let Ok(list_result) = bucket.list_objects(None, None, None, Some(10)).await {
                            let object_keys: Vec<&str> = list_result.objects.iter()
                                .map(|o| o.key.as_str())
                                .collect();
                            tracing::debug!(
                                bucket = %display_name,
                                object_keys = ?object_keys,
                                "Sample of objects in bucket"
                            );
                        }

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
                            internal_key = %entry.key(),
                            error = %e,
                            "Failed to load bucket"
                        );
                    }
                }
            }
        }

        tracing::debug!(
            target_bucket = %display_name,
            target_key = %key,
            matching_buckets = matching_buckets,
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
        
        // Create manager with persistence and add buckets
        {
            let manager = BucketManager::with_persistence(Arc::clone(&store), &cid_path);
            
            let owner = Owner::new("user123");
            manager.create_bucket("persist-bucket1".to_string(), owner.clone()).await.unwrap();
            manager.create_bucket("persist-bucket2".to_string(), owner).await.unwrap();
            
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
            
            // Verify buckets are restored
            assert!(manager.bucket_exists("persist-bucket1"));
            assert!(manager.bucket_exists("persist-bucket2"));
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
}
