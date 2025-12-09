//! Prolly Tree implementation
//!
//! A content-addressed B+ tree variant optimized for IPLD/IPFS storage.
//! Implements automatic node splitting to stay under IPFS's 1MB block limit.
//!
//! # Architecture
//!
//! Based on research from:
//! - **WNFS HAMT**: Hash Array Mapped Trie with hash-based routing
//! - **Peergos CHAMP**: Compressed Hash-Array Mapped Prefix-tree
//! - **Prolly Trees**: Content-addressed boundaries for deterministic structure
//!
//! # Node Splitting Strategy
//!
//! When a leaf node exceeds `max_leaf_entries`:
//! 1. Entries are sorted by key
//! 2. Entries are split into chunks of `max_leaf_entries` each
//! 3. Each chunk becomes a child leaf node
//! 4. A new internal node is created with links to children
//! 5. This process recurses if needed (for very large trees)
//!
//! # Block Size Guarantees
//!
//! With default settings (max_leaf_entries=64), each node stays well under
//! IPFS's 1MB limit even with large keys/values (~1KB each).

use super::{BoundaryHasher, NodeEntry, Pointer, ProllyNode, DEFAULT_BRANCHING_FACTOR};
use crate::Result;
use cid::Cid;
use fula_blockstore::BlockStore;
use serde::{de::DeserializeOwned, Serialize};
use std::sync::Arc;
use tracing::instrument;

/// Maximum serialized size for a single IPFS block (conservative limit)
/// Reserved for future size-based splitting heuristics
#[allow(dead_code)]
const MAX_BLOCK_SIZE: usize = 900_000; // 900KB, well under 1MB

/// Configuration for Prolly Tree behavior
#[derive(Clone, Debug)]
pub struct ProllyConfig {
    /// Target branching factor for internal nodes
    pub branching_factor: usize,
    /// Boundary bits for content-based chunking
    pub boundary_bits: u8,
    /// Maximum entries per leaf node before splitting
    /// With 1KB entries, 64 entries ≈ 64KB per node (safe margin)
    pub max_leaf_entries: usize,
    /// Maximum children per internal node
    pub max_children: usize,
}

impl Default for ProllyConfig {
    fn default() -> Self {
        Self {
            branching_factor: DEFAULT_BRANCHING_FACTOR,
            boundary_bits: 5,
            max_leaf_entries: 64,
            max_children: 256,
        }
    }
}

impl ProllyConfig {
    /// Create config optimized for small entries (< 100 bytes each)
    pub fn for_small_entries() -> Self {
        Self {
            max_leaf_entries: 256,
            max_children: 512,
            ..Default::default()
        }
    }

    /// Create config optimized for large entries (> 1KB each)
    pub fn for_large_entries() -> Self {
        Self {
            max_leaf_entries: 32,
            max_children: 128,
            ..Default::default()
        }
    }
}

/// A Prolly Tree for indexing bucket contents
///
/// Implements a content-addressed B+ tree with automatic node splitting.
/// All nodes are stored as IPLD blocks, enabling efficient synchronization
/// and deduplication across IPFS nodes.
pub struct ProllyTree<K, V, S: BlockStore> {
    /// The root node (may be leaf or internal)
    root: Arc<ProllyNode<K, V>>,
    /// Root CID (if persisted, None if dirty)
    root_cid: Option<Cid>,
    /// Block store for persistence
    store: Arc<S>,
    /// Configuration for tree behavior
    config: ProllyConfig,
    /// Boundary hasher for content-based chunking (reserved for future use)
    #[allow(dead_code)]
    boundary_hasher: BoundaryHasher,
    /// Whether the tree has uncommitted changes
    dirty: bool,
}

impl<K, V, S> ProllyTree<K, V, S>
where
    K: Clone + Ord + Serialize + DeserializeOwned + AsRef<[u8]> + Send + Sync + std::fmt::Debug,
    V: Clone + Serialize + DeserializeOwned + Send + Sync + std::fmt::Debug,
    S: BlockStore,
{
    /// Create a new empty tree with default configuration
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
            dirty: false,
        }
    }

    /// Load a tree from an existing root CID
    pub async fn load(store: Arc<S>, root_cid: Cid) -> Result<Self> {
        Self::load_with_config(store, root_cid, ProllyConfig::default()).await
    }

    /// Load a tree with custom configuration
    pub async fn load_with_config(store: Arc<S>, root_cid: Cid, config: ProllyConfig) -> Result<Self> {
        let root: ProllyNode<K, V> = store.get_ipld(&root_cid).await?;
        Ok(Self {
            root: Arc::new(root),
            root_cid: Some(root_cid),
            store,
            boundary_hasher: BoundaryHasher::new(config.boundary_bits),
            config,
            dirty: false,
        })
    }

    /// Get the root CID (None if tree has uncommitted changes)
    pub fn root_cid(&self) -> Option<&Cid> {
        self.root_cid.as_ref()
    }

    /// Check if the tree is empty
    pub fn is_empty(&self) -> bool {
        self.root.is_empty()
    }

    /// Check if there are uncommitted changes
    pub fn is_dirty(&self) -> bool {
        self.dirty
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
    ///
    /// If the resulting node exceeds `max_leaf_entries`, the tree is automatically
    /// restructured by splitting nodes. This ensures each node stays under the
    /// IPFS block size limit.
    #[instrument(skip(self, value))]
    pub async fn set(&mut self, key: K, value: V) -> Result<()> {
        // For a leaf root, insert directly and check for split
        if self.root.is_leaf {
            {
                let root = Arc::make_mut(&mut self.root);
                root.insert(key, value);
            }

            // Check if we need to split
            let entry_count = self.count_leaf_entries_direct(&self.root);
            if entry_count > self.config.max_leaf_entries {
                self.split_root().await?;
            }
        } else {
            // For internal nodes, we need to collect all entries, add the new one,
            // then rebuild. This is expensive but ensures correctness.
            // A production system would use proper B-tree insert routing.
            let mut all_entries = self.iter().await?;
            
            // Check if key exists and update, or add new
            let mut found = false;
            for (k, v) in &mut all_entries {
                if k == &key {
                    *v = value.clone();
                    found = true;
                    break;
                }
            }
            if !found {
                all_entries.push((key, value));
            }
            all_entries.sort_by(|a, b| a.0.cmp(&b.0));
            
            // Rebuild the tree from scratch
            self.rebuild_from_entries(all_entries).await?;
        }

        // Mark as dirty and invalidate cached CID
        self.dirty = true;
        self.root_cid = None;
        
        Ok(())
    }

    /// Rebuild the entire tree from a sorted list of entries
    async fn rebuild_from_entries(&mut self, entries: Vec<(K, V)>) -> Result<()> {
        if entries.is_empty() {
            self.root = Arc::new(ProllyNode::new_leaf());
            return Ok(());
        }

        if entries.len() <= self.config.max_leaf_entries {
            // Fits in a single leaf
            let node_entries: Vec<NodeEntry<K, V>> = entries
                .into_iter()
                .map(|(k, v)| NodeEntry::new(k, v))
                .collect();
            self.root = Arc::new(ProllyNode::leaf_with_entries(node_entries));
            return Ok(());
        }

        // Need to split into multiple leaves
        let chunk_size = self.config.max_leaf_entries;
        let chunks: Vec<_> = entries.chunks(chunk_size).collect();

        // Create and store leaf nodes
        let mut leaf_cids = Vec::with_capacity(chunks.len());
        for chunk in chunks {
            let child_entries: Vec<NodeEntry<K, V>> = chunk
                .iter()
                .map(|(k, v)| NodeEntry::new(k.clone(), v.clone()))
                .collect();
            
            let child_node = ProllyNode::leaf_with_entries(child_entries);
            let child_cid = self.store.put_ipld(&child_node).await?;
            leaf_cids.push(child_cid);
        }

        // Build internal tree structure if needed
        if leaf_cids.len() > self.config.max_children {
            let new_root = self.create_internal_tree(leaf_cids, 1).await?;
            self.root = Arc::new(new_root);
        } else {
            let mut new_root = ProllyNode::<K, V>::new_internal(1);
            for cid in leaf_cids {
                new_root.pointers.push(Pointer::Link(cid));
            }
            self.root = Arc::new(new_root);
        }

        Ok(())
    }

    /// Split the root node when it exceeds max_leaf_entries
    async fn split_root(&mut self) -> Result<()> {
        // Collect all entries from the current root (sorted)
        let mut entries = self.collect_all_entries(&self.root);
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        
        if entries.len() <= self.config.max_leaf_entries {
            return Ok(()); // No split needed
        }

        self.rebuild_from_entries(entries).await
    }

    /// Recursively create internal nodes when there are too many children
    fn create_internal_tree<'a>(
        &'a self,
        cids: Vec<Cid>,
        level: u8,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<ProllyNode<K, V>>> + Send + 'a>> {
        Box::pin(async move {
            if cids.len() <= self.config.max_children {
                // Create a single internal node with all CIDs
                let mut node = ProllyNode::<K, V>::new_internal(level);
                for cid in cids {
                    node.pointers.push(Pointer::Link(cid));
                }
                return Ok(node);
            }

            // Too many children, create intermediate internal nodes
            let chunk_size = self.config.max_children;
            let mut child_cids = Vec::new();

            for chunk in cids.chunks(chunk_size) {
                let mut internal_node = ProllyNode::<K, V>::new_internal(level);
                for cid in chunk {
                    internal_node.pointers.push(Pointer::Link(*cid));
                }
                let child_cid = self.store.put_ipld(&internal_node).await?;
                child_cids.push(child_cid);
            }

            // Recurse to create higher level if needed
            self.create_internal_tree(child_cids, level + 1).await
        })
    }

    /// Remove a key from the tree
    #[instrument(skip(self))]
    pub async fn remove(&mut self, key: &K) -> Result<Option<V>> {
        if self.root.is_leaf {
            let root = Arc::make_mut(&mut self.root);
            let removed = root.remove(key);
            
            if removed.is_some() {
                self.dirty = true;
                self.root_cid = None;
            }
            
            return Ok(removed);
        }

        // For internal trees, collect all, remove, rebuild
        let mut all_entries = self.iter().await?;
        let mut removed_value = None;
        
        all_entries.retain(|(k, v)| {
            if k == key {
                removed_value = Some(v.clone());
                false
            } else {
                true
            }
        });

        if removed_value.is_some() {
            self.rebuild_from_entries(all_entries).await?;
            self.dirty = true;
            self.root_cid = None;
        }
        
        Ok(removed_value)
    }

    /// Count entries directly in a leaf node (no recursion)
    fn count_leaf_entries_direct(&self, node: &ProllyNode<K, V>) -> usize {
        let mut count = 0;
        for pointer in &node.pointers {
            if let Pointer::Values(values) = pointer {
                count += values.len();
            }
        }
        count
    }

    /// Flush the tree to storage and return the root CID
    ///
    /// Persists the current root node (and any unsaved children) to IPFS.
    /// After flushing, the tree is no longer dirty.
    #[instrument(skip(self))]
    pub async fn flush(&mut self) -> Result<Cid> {
        // Return cached CID if tree hasn't changed
        if let Some(cid) = &self.root_cid {
            return Ok(*cid);
        }

        // Store the root node
        let cid = self.store.put_ipld(&*self.root).await?;
        
        // Cache the CID and mark as clean
        self.root_cid = Some(cid);
        self.dirty = false;
        
        Ok(cid)
    }

    /// Collect all entries from a node as (key, value) pairs
    fn collect_all_entries(&self, node: &ProllyNode<K, V>) -> Vec<(K, V)> {
        let mut result = Vec::new();
        for pointer in &node.pointers {
            if let Pointer::Values(values) = pointer {
                for entry in values {
                    result.push((entry.key.clone(), entry.value.clone()));
                }
            }
        }
        result
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

    // ═══════════════════════════════════════════════════════════════════════════
    // NODE SPLITTING TESTS
    // ═══════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn test_node_splitting_triggers_at_threshold() {
        let store = Arc::new(MemoryBlockStore::new());
        
        // Use small max_leaf_entries for testing
        let config = ProllyConfig {
            max_leaf_entries: 10,
            max_children: 4,
            ..Default::default()
        };
        let mut tree: ProllyTree<String, i32, _> = ProllyTree::with_config(store, config);

        // Insert enough entries to trigger a split (>10)
        for i in 0..15 {
            tree.set(format!("key_{:03}", i), i).await.unwrap();
        }

        // Tree should have been split (root is now internal)
        let stats = tree.stats();
        assert!(!stats.is_leaf, "Root should be internal after split");
        assert!(stats.pointer_count > 1, "Root should have multiple children");
        
        // All entries should still be retrievable
        for i in 0..15 {
            let value = tree.get(&format!("key_{:03}", i)).await.unwrap();
            assert_eq!(value, Some(i), "Entry {} should exist", i);
        }
    }

    #[tokio::test]
    async fn test_node_splitting_100_entries() {
        let store = Arc::new(MemoryBlockStore::new());
        
        let config = ProllyConfig {
            max_leaf_entries: 10,
            max_children: 10,
            ..Default::default()
        };
        let mut tree: ProllyTree<String, String, _> = ProllyTree::with_config(store, config);

        // Insert 100 entries
        for i in 0..100 {
            let key = format!("file_{:04}.txt", i);
            let value = format!("content_{}", i);
            tree.set(key, value).await.unwrap();
        }

        // Verify tree structure
        let stats = tree.stats();
        assert!(!stats.is_leaf, "Root should be internal with 100 entries");

        // Verify all entries are retrievable
        for i in 0..100 {
            let key = format!("file_{:04}.txt", i);
            let expected = format!("content_{}", i);
            let actual = tree.get(&key).await.unwrap();
            assert_eq!(actual, Some(expected), "Entry {} should exist", i);
        }

        // Verify iteration returns all entries
        let all_entries = tree.iter().await.unwrap();
        assert_eq!(all_entries.len(), 100, "Should have 100 entries");
    }

    #[tokio::test]
    async fn test_node_splitting_1000_entries() {
        let store = Arc::new(MemoryBlockStore::new());
        
        let config = ProllyConfig {
            max_leaf_entries: 32,
            max_children: 32,
            ..Default::default()
        };
        let mut tree: ProllyTree<String, String, _> = ProllyTree::with_config(store, config);

        // Insert 1000 entries (simulating real workload)
        for i in 0..1000 {
            let key = format!("bucket/folder_{:02}/file_{:04}.bin", i / 100, i);
            let value = format!("data_{}", i);
            tree.set(key, value).await.unwrap();
        }

        // Verify length
        let len = tree.len().await.unwrap();
        assert_eq!(len, 1000, "Tree should have 1000 entries");

        // Spot check some entries
        for i in [0, 100, 500, 999] {
            let key = format!("bucket/folder_{:02}/file_{:04}.bin", i / 100, i);
            let expected = format!("data_{}", i);
            let actual = tree.get(&key).await.unwrap();
            assert_eq!(actual, Some(expected), "Entry {} should exist", i);
        }

        // Verify tree is split
        let stats = tree.stats();
        assert!(!stats.is_leaf, "Root should be internal with 1000 entries");
    }

    #[tokio::test]
    async fn test_split_tree_flush_and_reload() {
        let store = Arc::new(MemoryBlockStore::new());
        
        let config = ProllyConfig {
            max_leaf_entries: 10,
            max_children: 10,
            ..Default::default()
        };
        
        // Create tree, insert entries, flush
        let cid = {
            let mut tree: ProllyTree<String, i32, _> = 
                ProllyTree::with_config(Arc::clone(&store), config.clone());
            
            for i in 0..50 {
                tree.set(format!("key_{:03}", i), i).await.unwrap();
            }
            
            tree.flush().await.unwrap()
        };

        // Reload and verify
        let tree: ProllyTree<String, i32, _> = 
            ProllyTree::load_with_config(store, cid, config).await.unwrap();
        
        // All entries should be retrievable from reloaded tree
        for i in 0..50 {
            let value = tree.get(&format!("key_{:03}", i)).await.unwrap();
            assert_eq!(value, Some(i), "Entry {} should exist after reload", i);
        }

        // Verify iteration works on reloaded tree
        let all = tree.iter().await.unwrap();
        assert_eq!(all.len(), 50);
    }

    #[tokio::test]
    async fn test_split_preserves_sort_order() {
        let store = Arc::new(MemoryBlockStore::new());
        
        let config = ProllyConfig {
            max_leaf_entries: 5,
            max_children: 5,
            ..Default::default()
        };
        let mut tree: ProllyTree<String, i32, _> = ProllyTree::with_config(store, config);

        // Insert in random order
        let keys = ["z", "m", "a", "x", "f", "c", "y", "b", "n", "d", "e", "g"];
        for (i, key) in keys.iter().enumerate() {
            tree.set(key.to_string(), i as i32).await.unwrap();
        }

        // Iteration should return sorted keys
        let entries = tree.iter().await.unwrap();
        let sorted_keys: Vec<_> = entries.iter().map(|(k, _)| k.as_str()).collect();
        
        let mut expected: Vec<_> = keys.to_vec();
        expected.sort();
        
        assert_eq!(sorted_keys, expected, "Keys should be sorted after split");
    }

    #[tokio::test]
    async fn test_update_existing_key_after_split() {
        let store = Arc::new(MemoryBlockStore::new());
        
        let config = ProllyConfig {
            max_leaf_entries: 5,
            ..Default::default()
        };
        let mut tree: ProllyTree<String, String, _> = ProllyTree::with_config(store, config);

        // Insert enough to trigger split
        for i in 0..20 {
            tree.set(format!("key_{:02}", i), format!("value_{}", i)).await.unwrap();
        }

        // Update an existing key
        tree.set("key_10".to_string(), "UPDATED".to_string()).await.unwrap();

        // Verify update
        let value = tree.get(&"key_10".to_string()).await.unwrap();
        assert_eq!(value, Some("UPDATED".to_string()));

        // Verify other entries unchanged
        let value = tree.get(&"key_05".to_string()).await.unwrap();
        assert_eq!(value, Some("value_5".to_string()));
    }

    #[tokio::test]
    async fn test_dirty_flag() {
        let store = Arc::new(MemoryBlockStore::new());
        let mut tree: ProllyTree<String, String, _> = ProllyTree::new(store);

        // New tree is not dirty
        assert!(!tree.is_dirty());

        // After insert, tree is dirty
        tree.set("key".to_string(), "value".to_string()).await.unwrap();
        assert!(tree.is_dirty());

        // After flush, tree is not dirty
        tree.flush().await.unwrap();
        assert!(!tree.is_dirty());

        // After another insert, tree is dirty again
        tree.set("key2".to_string(), "value2".to_string()).await.unwrap();
        assert!(tree.is_dirty());
    }

    #[tokio::test]
    async fn test_multi_level_tree_deep_nesting() {
        let store = Arc::new(MemoryBlockStore::new());
        
        // Very small limits to force multiple levels
        let config = ProllyConfig {
            max_leaf_entries: 4,
            max_children: 4,
            ..Default::default()
        };
        let mut tree: ProllyTree<String, i32, _> = ProllyTree::with_config(store, config);

        // Insert enough entries to force 2+ levels: 64 entries = 16 leaves = 4 level-1 nodes
        for i in 0..64 {
            tree.set(format!("key_{:03}", i), i).await.unwrap();
        }

        // Verify all entries
        for i in 0..64 {
            let value = tree.get(&format!("key_{:03}", i)).await.unwrap();
            assert_eq!(value, Some(i), "Entry {} should exist", i);
        }

        // Flush and verify stats
        tree.flush().await.unwrap();
        let stats = tree.stats();
        assert!(!stats.is_leaf);
        assert!(stats.level >= 1, "Should have at least 2 levels");
    }

    #[tokio::test]
    async fn test_config_presets() {
        // Test for_small_entries config
        let config = ProllyConfig::for_small_entries();
        assert_eq!(config.max_leaf_entries, 256);
        assert_eq!(config.max_children, 512);

        // Test for_large_entries config
        let config = ProllyConfig::for_large_entries();
        assert_eq!(config.max_leaf_entries, 32);
        assert_eq!(config.max_children, 128);
    }
}
