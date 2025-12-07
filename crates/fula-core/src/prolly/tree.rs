//! Prolly Tree implementation

use super::{BoundaryHasher, Pointer, ProllyNode, DEFAULT_BRANCHING_FACTOR};
use crate::Result;
use cid::Cid;
use fula_blockstore::BlockStore;
use serde::{de::DeserializeOwned, Serialize};
use std::sync::Arc;
use tracing::instrument;

/// Configuration for Prolly Tree behavior
#[derive(Clone, Debug)]
pub struct ProllyConfig {
    /// Target branching factor
    pub branching_factor: usize,
    /// Boundary bits for chunking
    pub boundary_bits: u8,
    /// Maximum entries per leaf node
    pub max_leaf_entries: usize,
}

impl Default for ProllyConfig {
    fn default() -> Self {
        Self {
            branching_factor: DEFAULT_BRANCHING_FACTOR,
            boundary_bits: 5,
            max_leaf_entries: 64,
        }
    }
}

/// A Prolly Tree for indexing bucket contents
pub struct ProllyTree<K, V, S: BlockStore> {
    /// The root node
    root: Arc<ProllyNode<K, V>>,
    /// Root CID (if persisted)
    root_cid: Option<Cid>,
    /// Block store for persistence
    store: Arc<S>,
    /// Configuration (reserved for future split logic)
    #[allow(dead_code)]
    config: ProllyConfig,
    /// Boundary hasher (reserved for future split logic)
    #[allow(dead_code)]
    boundary_hasher: BoundaryHasher,
}

impl<K, V, S> ProllyTree<K, V, S>
where
    K: Clone + Ord + Serialize + DeserializeOwned + AsRef<[u8]> + Send + Sync + std::fmt::Debug,
    V: Clone + Serialize + DeserializeOwned + Send + Sync + std::fmt::Debug,
    S: BlockStore,
{
    /// Create a new empty tree
    pub fn new(store: Arc<S>) -> Self {
        Self::with_config(store, ProllyConfig::default())
    }

    /// Create with custom configuration
    pub fn with_config(store: Arc<S>, config: ProllyConfig) -> Self {
        Self {
            root: Arc::new(ProllyNode::new_leaf()),
            root_cid: None,
            store,
            boundary_hasher: BoundaryHasher::new(config.boundary_bits),
            config,
        }
    }

    /// Load a tree from an existing root CID
    pub async fn load(store: Arc<S>, root_cid: Cid) -> Result<Self> {
        let root: ProllyNode<K, V> = store.get_ipld(&root_cid).await?;
        Ok(Self {
            root: Arc::new(root),
            root_cid: Some(root_cid),
            store,
            config: ProllyConfig::default(),
            boundary_hasher: BoundaryHasher::default(),
        })
    }

    /// Get the root CID
    pub fn root_cid(&self) -> Option<&Cid> {
        self.root_cid.as_ref()
    }

    /// Check if the tree is empty
    pub fn is_empty(&self) -> bool {
        self.root.is_empty()
    }

    /// Get a value by key
    #[instrument(skip(self))]
    pub async fn get(&self, key: &K) -> Result<Option<V>> {
        self.get_from_node(&self.root, key).await
    }

    /// Recursive get implementation
    fn get_from_node<'a>(
        &'a self,
        node: &'a ProllyNode<K, V>,
        key: &'a K,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Option<V>>> + Send + 'a>> {
        Box::pin(async move {
            if node.is_leaf {
                return Ok(node.get(key).cloned());
            }

            // For internal nodes, find the right child
            for pointer in &node.pointers {
                match pointer {
                    Pointer::Values(entries) => {
                        for entry in entries {
                            if &entry.key == key {
                                return Ok(Some(entry.value.clone()));
                            }
                        }
                    }
                    Pointer::Link(cid) => {
                        let child: ProllyNode<K, V> = self.store.get_ipld(cid).await?;
                        if let Some(v) = self.get_from_node(&child, key).await? {
                            return Ok(Some(v));
                        }
                    }
                }
            }

            Ok(None)
        })
    }

    /// Insert or update a key-value pair
    #[instrument(skip(self, value))]
    pub async fn set(&mut self, key: K, value: V) -> Result<()> {
        {
            let root = Arc::make_mut(&mut self.root);
            root.insert(key, value);
        }
        
        // TODO: Implement node splitting when entries exceed max_leaf_entries
        // For now, leaves can grow unbounded

        // Invalidate cached root CID
        self.root_cid = None;
        
        Ok(())
    }

    /// Remove a key
    #[instrument(skip(self))]
    pub async fn remove(&mut self, key: &K) -> Result<Option<V>> {
        let root = Arc::make_mut(&mut self.root);
        let removed = root.remove(key);
        
        // Invalidate cached root CID
        if removed.is_some() {
            self.root_cid = None;
        }
        
        Ok(removed)
    }

    /// Flush the tree to storage and return the root CID
    #[instrument(skip(self))]
    pub async fn flush(&mut self) -> Result<Cid> {
        if let Some(cid) = &self.root_cid {
            return Ok(*cid);
        }

        let cid = self.flush_node(&self.root).await?;
        self.root_cid = Some(cid);
        Ok(cid)
    }

    /// Flush a node and all its children
    async fn flush_node(&self, node: &ProllyNode<K, V>) -> Result<Cid> {
        // First flush all child links
        let updated_node = node.clone();
        
        for (_i, pointer) in node.pointers.iter().enumerate() {
            if let Pointer::Values(_) = pointer {
                // Values are stored inline, nothing to do
            }
            // Links are already persisted
        }

        // Store this node
        let cid = self.store.put_ipld(&updated_node).await?;
        Ok(cid)
    }

    /// Iterate over all key-value pairs in order
    pub async fn iter(&self) -> Result<Vec<(K, V)>> {
        let mut result = Vec::new();
        self.collect_entries(&self.root, &mut result).await?;
        result.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(result)
    }

    /// Collect entries from a node
    async fn collect_entries(
        &self,
        node: &ProllyNode<K, V>,
        result: &mut Vec<(K, V)>,
    ) -> Result<()> {
        for pointer in &node.pointers {
            match pointer {
                Pointer::Values(entries) => {
                    for entry in entries {
                        result.push((entry.key.clone(), entry.value.clone()));
                    }
                }
                Pointer::Link(cid) => {
                    let child: ProllyNode<K, V> = self.store.get_ipld(cid).await?;
                    Box::pin(self.collect_entries(&child, result)).await?;
                }
            }
        }
        Ok(())
    }

    /// List keys with a prefix
    pub async fn list_prefix(&self, prefix: &[u8]) -> Result<Vec<(K, V)>> {
        let all = self.iter().await?;
        Ok(all
            .into_iter()
            .filter(|(k, _)| k.as_ref().starts_with(prefix))
            .collect())
    }

    /// Count entries
    pub async fn len(&self) -> Result<usize> {
        let entries = self.iter().await?;
        Ok(entries.len())
    }

    /// Get statistics about the tree
    pub fn stats(&self) -> TreeStats {
        TreeStats {
            is_leaf: self.root.is_leaf,
            level: self.root.level,
            pointer_count: self.root.len(),
            has_root_cid: self.root_cid.is_some(),
        }
    }
}

/// Tree statistics
#[derive(Debug, Clone)]
pub struct TreeStats {
    pub is_leaf: bool,
    pub level: u8,
    pub pointer_count: usize,
    pub has_root_cid: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use fula_blockstore::MemoryBlockStore;

    #[tokio::test]
    async fn test_tree_basic_operations() {
        let store = Arc::new(MemoryBlockStore::new());
        let mut tree: ProllyTree<String, String, _> = ProllyTree::new(store);

        // Insert
        tree.set("key1".to_string(), "value1".to_string()).await.unwrap();
        tree.set("key2".to_string(), "value2".to_string()).await.unwrap();

        // Get
        assert_eq!(
            tree.get(&"key1".to_string()).await.unwrap(),
            Some("value1".to_string())
        );
        assert_eq!(
            tree.get(&"key2".to_string()).await.unwrap(),
            Some("value2".to_string())
        );
        assert_eq!(tree.get(&"key3".to_string()).await.unwrap(), None);
    }

    #[tokio::test]
    async fn test_tree_remove() {
        let store = Arc::new(MemoryBlockStore::new());
        let mut tree: ProllyTree<String, String, _> = ProllyTree::new(store);

        tree.set("key1".to_string(), "value1".to_string()).await.unwrap();
        let removed = tree.remove(&"key1".to_string()).await.unwrap();
        
        assert_eq!(removed, Some("value1".to_string()));
        assert_eq!(tree.get(&"key1".to_string()).await.unwrap(), None);
    }

    #[tokio::test]
    async fn test_tree_flush_and_load() {
        let store = Arc::new(MemoryBlockStore::new());
        
        let cid = {
            let mut tree: ProllyTree<String, String, _> = ProllyTree::new(Arc::clone(&store));
            tree.set("key1".to_string(), "value1".to_string()).await.unwrap();
            tree.flush().await.unwrap()
        };

        // Load from CID
        let tree: ProllyTree<String, String, _> = ProllyTree::load(store, cid).await.unwrap();
        assert_eq!(
            tree.get(&"key1".to_string()).await.unwrap(),
            Some("value1".to_string())
        );
    }

    #[tokio::test]
    async fn test_tree_iteration() {
        let store = Arc::new(MemoryBlockStore::new());
        let mut tree: ProllyTree<String, i32, _> = ProllyTree::new(store);

        tree.set("c".to_string(), 3).await.unwrap();
        tree.set("a".to_string(), 1).await.unwrap();
        tree.set("b".to_string(), 2).await.unwrap();

        let entries = tree.iter().await.unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0], ("a".to_string(), 1));
        assert_eq!(entries[1], ("b".to_string(), 2));
        assert_eq!(entries[2], ("c".to_string(), 3));
    }

    #[tokio::test]
    async fn test_tree_prefix_listing() {
        let store = Arc::new(MemoryBlockStore::new());
        let mut tree: ProllyTree<String, i32, _> = ProllyTree::new(store);

        tree.set("photos/2024/a.jpg".to_string(), 1).await.unwrap();
        tree.set("photos/2024/b.jpg".to_string(), 2).await.unwrap();
        tree.set("photos/2025/c.jpg".to_string(), 3).await.unwrap();
        tree.set("docs/readme.md".to_string(), 4).await.unwrap();

        let photos_2024 = tree.list_prefix(b"photos/2024/").await.unwrap();
        assert_eq!(photos_2024.len(), 2);

        let all_photos = tree.list_prefix(b"photos/").await.unwrap();
        assert_eq!(all_photos.len(), 3);
    }
}
