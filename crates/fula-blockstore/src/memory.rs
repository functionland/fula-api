//! In-memory block store for testing and caching

use crate::{BlockStore, BlockStoreError, Result};
use async_trait::async_trait;
use bytes::Bytes;
use cid::Cid;
use dashmap::DashMap;
use std::sync::Arc;

/// An in-memory block store
#[derive(Clone, Default)]
pub struct MemoryBlockStore {
    blocks: Arc<DashMap<Cid, Bytes>>,
}

impl MemoryBlockStore {
    /// Create a new empty memory store
    pub fn new() -> Self {
        Self {
            blocks: Arc::new(DashMap::new()),
        }
    }

    /// Get the number of blocks stored
    pub fn len(&self) -> usize {
        self.blocks.len()
    }

    /// Check if the store is empty
    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    /// Clear all blocks
    pub fn clear(&self) {
        self.blocks.clear();
    }

    /// Get total size of all blocks
    pub fn total_size(&self) -> u64 {
        self.blocks.iter().map(|entry| entry.value().len() as u64).sum()
    }

    /// List all CIDs
    pub fn list_cids(&self) -> Vec<Cid> {
        self.blocks.iter().map(|entry| *entry.key()).collect()
    }
}

#[async_trait]
impl BlockStore for MemoryBlockStore {
    async fn put_block(&self, data: &[u8]) -> Result<Cid> {
        let cid = crate::cid_utils::create_cid(data, crate::cid_utils::CidCodec::Raw);
        self.blocks.insert(cid, Bytes::copy_from_slice(data));
        Ok(cid)
    }

    async fn get_block(&self, cid: &Cid) -> Result<Bytes> {
        self.blocks
            .get(cid)
            .map(|entry| entry.value().clone())
            .ok_or_else(|| BlockStoreError::NotFound(*cid))
    }

    async fn has_block(&self, cid: &Cid) -> Result<bool> {
        Ok(self.blocks.contains_key(cid))
    }

    async fn delete_block(&self, cid: &Cid) -> Result<()> {
        self.blocks.remove(cid);
        Ok(())
    }

    async fn block_size(&self, cid: &Cid) -> Result<u64> {
        self.blocks
            .get(cid)
            .map(|entry| entry.value().len() as u64)
            .ok_or_else(|| BlockStoreError::NotFound(*cid))
    }

    async fn put_ipld<T: serde::Serialize + Send + Sync>(&self, data: &T) -> Result<Cid> {
        let bytes = serde_ipld_dagcbor::to_vec(data)
            .map_err(|e| BlockStoreError::Serialization(e.to_string()))?;
        let cid = crate::cid_utils::create_cid(&bytes, crate::cid_utils::CidCodec::DagCbor);
        self.blocks.insert(cid, Bytes::from(bytes));
        Ok(cid)
    }

    async fn get_ipld<T: serde::de::DeserializeOwned>(&self, cid: &Cid) -> Result<T> {
        let bytes = self.get_block(cid).await?;
        serde_ipld_dagcbor::from_slice(&bytes)
            .map_err(|e| BlockStoreError::Deserialization(e.to_string()))
    }
}

/// LRU-cached wrapper around any block store
pub struct CachedBlockStore<S: BlockStore> {
    inner: S,
    cache: Arc<parking_lot::Mutex<lru::LruCache<Cid, Bytes>>>,
}

impl<S: BlockStore> CachedBlockStore<S> {
    /// Create a new cached store with the given capacity
    pub fn new(inner: S, capacity: usize) -> Self {
        Self {
            inner,
            cache: Arc::new(parking_lot::Mutex::new(lru::LruCache::new(
                std::num::NonZeroUsize::new(capacity).unwrap(),
            ))),
        }
    }

    /// Clear the cache
    pub fn clear_cache(&self) {
        self.cache.lock().clear();
    }

    /// Get cache statistics
    pub fn cache_len(&self) -> usize {
        self.cache.lock().len()
    }
}

#[async_trait]
impl<S: BlockStore> BlockStore for CachedBlockStore<S> {
    async fn put_block(&self, data: &[u8]) -> Result<Cid> {
        let cid = self.inner.put_block(data).await?;
        self.cache.lock().put(cid, Bytes::copy_from_slice(data));
        Ok(cid)
    }

    async fn get_block(&self, cid: &Cid) -> Result<Bytes> {
        // Check cache first
        if let Some(data) = self.cache.lock().get(cid) {
            return Ok(data.clone());
        }

        // Fetch from inner store
        let data = self.inner.get_block(cid).await?;
        self.cache.lock().put(*cid, data.clone());
        Ok(data)
    }

    async fn has_block(&self, cid: &Cid) -> Result<bool> {
        if self.cache.lock().contains(cid) {
            return Ok(true);
        }
        self.inner.has_block(cid).await
    }

    async fn delete_block(&self, cid: &Cid) -> Result<()> {
        self.cache.lock().pop(cid);
        self.inner.delete_block(cid).await
    }

    async fn block_size(&self, cid: &Cid) -> Result<u64> {
        if let Some(data) = self.cache.lock().get(cid) {
            return Ok(data.len() as u64);
        }
        self.inner.block_size(cid).await
    }

    async fn put_ipld<T: serde::Serialize + Send + Sync>(&self, data: &T) -> Result<Cid> {
        self.inner.put_ipld(data).await
    }

    async fn get_ipld<T: serde::de::DeserializeOwned>(&self, cid: &Cid) -> Result<T> {
        self.inner.get_ipld(cid).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_memory_store_basic() {
        let store = MemoryBlockStore::new();
        
        let data = b"Hello, World!";
        let cid = store.put_block(data).await.unwrap();
        
        assert!(store.has_block(&cid).await.unwrap());
        
        let retrieved = store.get_block(&cid).await.unwrap();
        assert_eq!(data.as_slice(), retrieved.as_ref());
    }

    #[tokio::test]
    async fn test_memory_store_not_found() {
        let store = MemoryBlockStore::new();
        let fake_cid = crate::cid_utils::create_cid(b"not stored", crate::cid_utils::CidCodec::Raw);
        
        let result = store.get_block(&fake_cid).await;
        assert!(matches!(result, Err(BlockStoreError::NotFound(_))));
    }

    #[tokio::test]
    async fn test_memory_store_delete() {
        let store = MemoryBlockStore::new();
        
        let cid = store.put_block(b"delete me").await.unwrap();
        assert!(store.has_block(&cid).await.unwrap());
        
        store.delete_block(&cid).await.unwrap();
        assert!(!store.has_block(&cid).await.unwrap());
    }

    #[tokio::test]
    async fn test_memory_store_ipld() {
        let store = MemoryBlockStore::new();
        
        #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
        struct TestData {
            name: String,
            value: i32,
        }
        
        let data = TestData {
            name: "test".to_string(),
            value: 42,
        };
        
        let cid = store.put_ipld(&data).await.unwrap();
        let retrieved: TestData = store.get_ipld(&cid).await.unwrap();
        
        assert_eq!(data, retrieved);
    }

    #[tokio::test]
    async fn test_cached_store() {
        let inner = MemoryBlockStore::new();
        let cached = CachedBlockStore::new(inner, 100);
        
        let data = b"cached data";
        let cid = cached.put_block(data).await.unwrap();
        
        // Should be in cache
        assert_eq!(cached.cache_len(), 1);
        
        // Get should hit cache
        let retrieved = cached.get_block(&cid).await.unwrap();
        assert_eq!(data.as_slice(), retrieved.as_ref());
    }
}
