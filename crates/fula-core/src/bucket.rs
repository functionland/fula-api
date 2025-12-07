//! Bucket management for S3-compatible storage

use crate::{
    CoreError, Result,
    metadata::{BucketMetadata, ObjectMetadata, Owner},
    prolly::ProllyTree,
};
use cid::Cid;
use chrono::Utc;
use fula_blockstore::BlockStore;
use std::sync::Arc;
use dashmap::DashMap;
use tracing::instrument;

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
        })
    }

    /// Load an existing bucket
    pub async fn load(
        metadata: BucketMetadata,
        store: Arc<S>,
        config: BucketConfig,
    ) -> Result<Self> {
        let index = ProllyTree::load(store, metadata.root_cid).await?;
        Ok(Self {
            metadata,
            index,
            config,
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

/// Bucket manager for handling multiple buckets
pub struct BucketManager<S: BlockStore> {
    /// Block store
    store: Arc<S>,
    /// Bucket metadata cache
    buckets: DashMap<String, BucketMetadata>,
    /// Default configuration
    default_config: BucketConfig,
}

impl<S: BlockStore> BucketManager<S> {
    /// Create a new bucket manager
    pub fn new(store: Arc<S>) -> Self {
        Self {
            store,
            buckets: DashMap::new(),
            default_config: BucketConfig::default(),
        }
    }

    /// Create a new bucket
    #[instrument(skip(self))]
    pub async fn create_bucket(
        &self,
        name: String,
        owner: Owner,
    ) -> Result<BucketMetadata> {
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
        self.buckets.insert(name, metadata.clone());
        
        Ok(metadata)
    }

    /// Get bucket metadata
    pub fn get_bucket_metadata(&self, name: &str) -> Option<BucketMetadata> {
        self.buckets.get(name).map(|r| r.clone())
    }

    /// Open a bucket for operations
    pub async fn open_bucket(&self, name: &str) -> Result<Bucket<S>> {
        let metadata = self.buckets.get(name)
            .map(|r| r.clone())
            .ok_or_else(|| CoreError::BucketNotFound(name.to_string()))?;

        Bucket::load(metadata, Arc::clone(&self.store), self.default_config.clone()).await
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
}
