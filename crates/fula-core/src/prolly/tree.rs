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
    ///
    /// For internal nodes with boundary keys (v2 format), uses binary search
    /// to route to the correct child in O(log n). For legacy nodes without
    /// boundaries, falls back to scanning all children (same as old behavior).
    fn get_from_node<'a>(
        &'a self,
        node: &'a ProllyNode<K, V>,
        key: &'a K,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Option<V>>> + Send + 'a>> {
        Box::pin(async move {
            if node.is_leaf {
                return Ok(node.get(key).cloned());
            }

            // Fast path: v2 nodes with boundary keys — binary search O(log n)
            if node.has_boundaries() {
                let idx = node.find_child_index(key);
                if let Some(cid) = node.pointers[idx].as_cid() {
                    let child: ProllyNode<K, V> = self.store.get_ipld(cid).await?;
                    return self.get_from_node(&child, key).await;
                }
                return Ok(None);
            }

            // Legacy fallback: scan all children (v1 format without boundaries)
            for pointer in &node.pointers {
                match pointer {
                    Pointer::Values(entries) => {
                        for entry in entries {
                            if &entry.key == key {
                                return Ok(Some(entry.value.clone()));
                            }
                        }
                    }
                    Pointer::Link(cid) | Pointer::LinkWithBoundary { cid, .. } => {
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
    /// For leaf roots, inserts directly and splits if needed.
    /// For internal roots with boundary keys (v2), descends to the correct
    /// child leaf, inserts there, and rebuilds only the affected path.
    /// For legacy internal roots (v1), falls back to collect-all-rebuild.
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
            // Collect all entries, add/update, and rebuild.
            // For v2 trees this rebuild produces LinkWithBoundary pointers.
            // A future optimization can do path-only descent, but this is
            // correct and the rebuild itself is O(n) which is acceptable
            // while get/remove/list benefit from O(log n) routing.
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

            // Rebuild the tree — now produces v2 LinkWithBoundary pointers
            self.rebuild_from_entries(all_entries).await?;
        }

        // Mark as dirty and invalidate cached CID
        self.dirty = true;
        self.root_cid = None;

        Ok(())
    }

    /// Rebuild the entire tree from a sorted list of entries.
    ///
    /// Always writes v2 format (LinkWithBoundary) for internal nodes,
    /// enabling O(log n) routing on subsequent reads. Old v1 trees
    /// self-upgrade to v2 on the next write via this path.
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

        // Create and store leaf nodes, collecting (cid, max_key) for each
        let mut leaf_children: Vec<(Cid, K)> = Vec::with_capacity(chunks.len());
        for chunk in chunks {
            let child_entries: Vec<NodeEntry<K, V>> = chunk
                .iter()
                .map(|(k, v)| NodeEntry::new(k.clone(), v.clone()))
                .collect();

            // The last key in the sorted chunk is the max_key for this child
            let max_key = chunk.last().unwrap().0.clone();

            let child_node = ProllyNode::leaf_with_entries(child_entries);
            let child_cid = self.store.put_ipld(&child_node).await?;
            leaf_children.push((child_cid, max_key));
        }

        // Build internal tree structure if needed
        if leaf_children.len() > self.config.max_children {
            let new_root = self.create_internal_tree(leaf_children, 1).await?;
            self.root = Arc::new(new_root);
        } else {
            let mut new_root = ProllyNode::<K, V>::new_internal(1);
            for (cid, max_key) in leaf_children {
                new_root.add_child_with_boundary(cid, max_key);
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

    /// Recursively create internal nodes when there are too many children.
    ///
    /// Each child is a `(Cid, max_key)` pair. Internal nodes are always written
    /// in v2 format (LinkWithBoundary) so reads can use binary search.
    fn create_internal_tree<'a>(
        &'a self,
        children: Vec<(Cid, K)>,
        level: u8,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<ProllyNode<K, V>>> + Send + 'a>> {
        Box::pin(async move {
            if children.len() <= self.config.max_children {
                // Create a single internal node with all children
                let mut node = ProllyNode::<K, V>::new_internal(level);
                for (cid, max_key) in children {
                    node.add_child_with_boundary(cid, max_key);
                }
                return Ok(node);
            }

            // Too many children — create intermediate internal nodes
            let chunk_size = self.config.max_children;
            let mut next_level_children: Vec<(Cid, K)> = Vec::new();

            for chunk in children.chunks(chunk_size) {
                let mut internal_node = ProllyNode::<K, V>::new_internal(level);
                for (cid, max_key) in chunk {
                    internal_node.add_child_with_boundary(*cid, max_key.clone());
                }
                // The max_key of this intermediate node is the max_key of its last child
                let group_max_key = chunk.last().unwrap().1.clone();
                let child_cid = self.store.put_ipld(&internal_node).await?;
                next_level_children.push((child_cid, group_max_key));
            }

            // Recurse to create higher level if needed
            self.create_internal_tree(next_level_children, level + 1).await
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

    /// Collect the CIDs of every node in the (flushed) index tree: the root
    /// plus every internal and leaf node reachable from it.
    ///
    /// Used by the index-node pinning prevention fix. A `ProllyNode`'s child
    /// CIDs are serialized as plain strings (not IPLD links), so `ipfs pin -r`
    /// / cluster recursive pins cover ONLY the root block — every non-root node
    /// is gc-exposed. Pinning each CID returned here makes the whole index
    /// gc-safe. Requires a flushed tree (`flush` first).
    ///
    /// NOTE: this walks the tree via `get_ipld`, so for an already-degraded
    /// tree it fetches missing nodes via the (cluster-fallback) store — that
    /// re-localizes them as a side effect but cannot enumerate a node that is
    /// gone fleet-wide (its subtree is then unreachable, and the fetch errors).
    pub async fn collect_node_cids(&self) -> Result<Vec<Cid>> {
        let root_cid = self.root_cid.ok_or_else(|| {
            crate::CoreError::StorageError(
                "collect_node_cids requires a flushed tree (call flush first)".to_string(),
            )
        })?;
        let mut cids = vec![root_cid];
        let mut visited = std::collections::HashSet::new();
        visited.insert(root_cid);
        self.collect_descendant_cids(&self.root, &mut cids, &mut visited)
            .await?;
        Ok(cids)
    }

    /// Like [`collect_node_cids`](Self::collect_node_cids) but for an ARBITRARY
    /// root CID loaded from the store (not the in-memory root). Used to compute
    /// the SUPERSEDED node set on a flush: `old_root`'s nodes minus the new
    /// root's nodes are the index blocks to unpin so `gc` can reclaim old index
    /// versions (otherwise every flush accumulates an un-reclaimable tree).
    ///
    /// Errors if `root_cid`'s node (or any descendant) is unavailable — caller
    /// should treat that as "can't diff, pin-current-only" rather than fatal.
    pub async fn collect_node_cids_at(&self, root_cid: Cid) -> Result<Vec<Cid>> {
        let mut cids = vec![root_cid];
        let mut visited = std::collections::HashSet::new();
        visited.insert(root_cid);
        let root_node: ProllyNode<K, V> = self.store.get_ipld(&root_cid).await?;
        self.collect_descendant_cids(&root_node, &mut cids, &mut visited)
            .await?;
        Ok(cids)
    }

    /// Recursively append the CIDs of all child nodes (internal + leaf) below
    /// `node`. Mirrors the `collect_prefix_bounded` traversal but records node
    /// CIDs instead of entries.
    ///
    /// `visited` dedupes shared subtrees (and guards the cryptographically
    /// impossible but cheap-to-rule-out CID cycle); `MAX_INDEX_NODES` caps a
    /// pathological/corrupt stored tree so an admin probe can't recurse or fetch
    /// unboundedly.
    fn collect_descendant_cids<'a>(
        &'a self,
        node: &'a ProllyNode<K, V>,
        cids: &'a mut Vec<Cid>,
        visited: &'a mut std::collections::HashSet<Cid>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
        const MAX_INDEX_NODES: usize = 10_000_000;
        Box::pin(async move {
            for pointer in &node.pointers {
                if let Pointer::Link(cid) | Pointer::LinkWithBoundary { cid, .. } = pointer {
                    // Skip already-seen nodes (shared subtree / cycle guard).
                    if !visited.insert(*cid) {
                        continue;
                    }
                    cids.push(*cid);
                    if cids.len() > MAX_INDEX_NODES {
                        return Err(crate::CoreError::StorageError(format!(
                            "index node count exceeds {MAX_INDEX_NODES} — refusing to walk (corrupt tree?)"
                        )));
                    }
                    let child: ProllyNode<K, V> = self.store.get_ipld(cid).await?;
                    self.collect_descendant_cids(&child, cids, visited).await?;
                }
            }
            Ok(())
        })
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

    /// Collect entries from a node (handles both v1 Link and v2 LinkWithBoundary)
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
                Pointer::Link(cid) | Pointer::LinkWithBoundary { cid, .. } => {
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

    /// List keys with a prefix, bounded by start_after and max_keys.
    ///
    /// For v2 trees (with boundary keys), uses binary search to skip
    /// children that can't contain matching keys — avoids loading the
    /// entire tree for paginated queries. For v1 trees, falls back to
    /// `list_prefix()` and applies filters in-memory.
    pub async fn list_prefix_bounded(
        &self,
        prefix: &[u8],
        start_after: Option<&K>,
        max_keys: usize,
    ) -> Result<Vec<(K, V)>> {
        // Collect matching entries from the tree using bounded traversal
        let mut result = Vec::new();
        self.collect_prefix_bounded(&self.root, prefix, start_after, max_keys, &mut result)
            .await?;
        result.sort_by(|a, b| a.0.cmp(&b.0));

        // Apply start_after and max_keys after sort (entries from multiple
        // children may interleave before sorting).
        let filtered: Vec<(K, V)> = result
            .into_iter()
            .filter(|(k, _)| {
                if let Some(after) = start_after {
                    k > after
                } else {
                    true
                }
            })
            .take(max_keys)
            .collect();

        Ok(filtered)
    }

    /// Bounded prefix traversal: descend only into children whose key range
    /// could contain keys matching `prefix` and `start_after`.
    fn collect_prefix_bounded<'a>(
        &'a self,
        node: &'a ProllyNode<K, V>,
        prefix: &'a [u8],
        start_after: Option<&'a K>,
        max_keys: usize,
        result: &'a mut Vec<(K, V)>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            if node.is_leaf {
                // Leaf: collect matching entries
                for pointer in &node.pointers {
                    if let Pointer::Values(entries) = pointer {
                        for entry in entries {
                            if entry.key.as_ref().starts_with(prefix) {
                                result.push((entry.key.clone(), entry.value.clone()));
                            }
                        }
                    }
                }
                return Ok(());
            }

            // Internal node with v2 boundaries — skip children outside range
            if node.has_boundaries() {
                for (idx, pointer) in node.pointers.iter().enumerate() {
                    if let Pointer::LinkWithBoundary { cid, max_key } = pointer {
                        // Skip children whose entire range is before start_after
                        if let Some(after) = start_after {
                            if max_key <= after {
                                continue;
                            }
                        }

                        // Skip children whose entire range is before the prefix.
                        // If max_key < prefix, all keys in this child are < prefix.
                        if max_key.as_ref() < prefix {
                            continue;
                        }

                        // If the prefix range is entirely before this child's
                        // min range, we can stop. For the first child, min is
                        // conceptually -infinity; for subsequent children, min is
                        // the previous child's max_key + 1. We approximate: if
                        // idx > 0, check if previous child's max_key >= all
                        // possible prefix matches. A simpler heuristic: if this
                        // child's max_key starts past the prefix end, and the
                        // previous sibling already covered the prefix, stop.
                        // However, prefix end isn't easily computed for byte
                        // prefixes. So we conservatively descend into any child
                        // that could overlap and rely on the leaf filter + max_keys
                        // to bound total work.
                        let _ = idx; // suppress unused warning

                        // Early exit if we have enough results already
                        if result.len() >= max_keys * 2 {
                            // Collected enough — the caller will sort+truncate.
                            // Factor of 2 allows for start_after filtering.
                            return Ok(());
                        }

                        let child: ProllyNode<K, V> = self.store.get_ipld(cid).await?;
                        self.collect_prefix_bounded(
                            &child,
                            prefix,
                            start_after,
                            max_keys,
                            result,
                        )
                        .await?;
                    }
                }
                return Ok(());
            }

            // Legacy v1: scan all children (same as before)
            for pointer in &node.pointers {
                match pointer {
                    Pointer::Values(entries) => {
                        for entry in entries {
                            if entry.key.as_ref().starts_with(prefix) {
                                result.push((entry.key.clone(), entry.value.clone()));
                            }
                        }
                    }
                    Pointer::Link(cid) | Pointer::LinkWithBoundary { cid, .. } => {
                        let child: ProllyNode<K, V> = self.store.get_ipld(cid).await?;
                        self.collect_prefix_bounded(
                            &child,
                            prefix,
                            start_after,
                            max_keys,
                            result,
                        )
                        .await?;
                    }
                }
            }
            Ok(())
        })
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
    async fn collect_node_cids_covers_root_and_all_children() {
        let store = Arc::new(MemoryBlockStore::new());
        let mut tree: ProllyTree<String, i32, _> = ProllyTree::new(Arc::clone(&store));
        // Insert enough entries to force internal nodes (> max_leaf_entries = 64).
        for i in 0..200 {
            tree.set(format!("key{:04}", i), i).await.unwrap();
        }
        let root = tree.flush().await.unwrap();

        let cids = tree.collect_node_cids().await.unwrap();

        // Root is included and the tree has internal structure (multiple nodes).
        assert!(cids.contains(&root), "root cid must be collected");
        assert!(cids.len() > 1, "expected internal nodes; got {}", cids.len());
        // All collected CIDs are unique.
        let unique: std::collections::HashSet<_> = cids.iter().collect();
        assert_eq!(unique.len(), cids.len(), "collected node cids must be unique");
        // Every collected CID is a real, fetchable ProllyNode (confirms they are
        // index nodes, not object/value CIDs).
        for cid in &cids {
            let _node: ProllyNode<String, i32> = store.get_ipld(cid).await.unwrap();
        }

        // Walking from the same root CID via the store yields the same set —
        // this is exactly what the flush diff uses to enumerate the OLD root's
        // nodes (to unpin superseded index blocks).
        let cids_at = tree.collect_node_cids_at(root).await.unwrap();
        let set_now: std::collections::HashSet<_> = cids.iter().copied().collect();
        let set_at: std::collections::HashSet<_> = cids_at.iter().copied().collect();
        assert_eq!(
            set_now, set_at,
            "collect_node_cids_at(root) must match collect_node_cids"
        );
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

    // ═══════════════════════════════════════════════════════════════════════════
    // V2 BOUNDARY KEY TESTS
    // ═══════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn test_internal_nodes_have_boundary_keys() {
        let store = Arc::new(MemoryBlockStore::new());
        let config = ProllyConfig {
            max_leaf_entries: 5,
            max_children: 5,
            ..Default::default()
        };
        let mut tree: ProllyTree<String, i32, _> = ProllyTree::with_config(store, config);

        // Insert enough to trigger a split
        for i in 0..20 {
            tree.set(format!("key_{:02}", i), i).await.unwrap();
        }

        // Root should be internal with boundary keys (v2 format)
        assert!(!tree.root.is_leaf);
        assert!(
            tree.root.has_boundaries(),
            "Internal nodes must use LinkWithBoundary (v2 format)"
        );

        // Every child pointer should be LinkWithBoundary
        for pointer in &tree.root.pointers {
            assert!(
                matches!(pointer, Pointer::LinkWithBoundary { .. }),
                "Expected LinkWithBoundary, got {:?}",
                pointer
            );
        }
    }

    #[tokio::test]
    async fn test_boundary_keys_are_correct() {
        let store = Arc::new(MemoryBlockStore::new());
        let config = ProllyConfig {
            max_leaf_entries: 4,
            max_children: 256,
            ..Default::default()
        };
        let mut tree: ProllyTree<String, i32, _> =
            ProllyTree::with_config(Arc::clone(&store), config);

        for i in 0..20 {
            tree.set(format!("key_{:02}", i), i).await.unwrap();
        }

        // Verify boundary keys are in sorted order and non-overlapping
        let mut prev_max: Option<String> = None;
        for pointer in &tree.root.pointers {
            if let Pointer::LinkWithBoundary { cid, max_key } = pointer {
                // Each boundary should be > previous boundary
                if let Some(ref prev) = prev_max {
                    assert!(
                        max_key > prev,
                        "Boundary keys must be ascending: {:?} should be > {:?}",
                        max_key,
                        prev
                    );
                }

                // The max_key should equal the last key in the child leaf
                let child: ProllyNode<String, i32> = store.get_ipld(cid).await.unwrap();
                let last = child.last_key().unwrap();
                assert_eq!(
                    max_key, last,
                    "Boundary key should equal last key in child"
                );

                prev_max = Some(max_key.clone());
            }
        }
    }

    #[tokio::test]
    async fn test_v2_get_routes_to_correct_child() {
        let store = Arc::new(MemoryBlockStore::new());
        let config = ProllyConfig {
            max_leaf_entries: 5,
            max_children: 256,
            ..Default::default()
        };
        let mut tree: ProllyTree<String, String, _> = ProllyTree::with_config(store, config);

        // Insert entries spanning multiple children
        for i in 0..25 {
            tree.set(format!("item_{:02}", i), format!("val_{}", i))
                .await
                .unwrap();
        }

        assert!(tree.root.has_boundaries());

        // Every key should be findable via boundary-routed get
        for i in 0..25 {
            let key = format!("item_{:02}", i);
            let val = tree.get(&key).await.unwrap();
            assert_eq!(val, Some(format!("val_{}", i)));
        }

        // Non-existent keys should return None
        assert_eq!(tree.get(&"item_99".to_string()).await.unwrap(), None);
        assert_eq!(tree.get(&"aaa".to_string()).await.unwrap(), None);
        assert_eq!(tree.get(&"zzz".to_string()).await.unwrap(), None);
    }

    #[tokio::test]
    async fn test_v2_flush_reload_preserves_boundaries() {
        let store = Arc::new(MemoryBlockStore::new());
        let config = ProllyConfig {
            max_leaf_entries: 5,
            max_children: 5,
            ..Default::default()
        };

        let cid = {
            let mut tree: ProllyTree<String, i32, _> =
                ProllyTree::with_config(Arc::clone(&store), config.clone());
            for i in 0..30 {
                tree.set(format!("k_{:02}", i), i).await.unwrap();
            }
            assert!(tree.root.has_boundaries());
            tree.flush().await.unwrap()
        };

        // Reload from CID
        let tree: ProllyTree<String, i32, _> =
            ProllyTree::load_with_config(Arc::clone(&store), cid, config).await.unwrap();

        // Root should still have boundaries after reload
        assert!(
            tree.root.has_boundaries(),
            "Boundaries must survive flush+reload"
        );

        // All entries still retrievable via boundary routing
        for i in 0..30 {
            let val = tree.get(&format!("k_{:02}", i)).await.unwrap();
            assert_eq!(val, Some(i));
        }
    }

    #[tokio::test]
    async fn test_v1_legacy_tree_still_readable() {
        // Simulate a v1 tree by manually constructing Link(Cid) pointers
        let store = Arc::new(MemoryBlockStore::new());

        // Create leaf nodes manually
        let leaf1 = ProllyNode::<String, i32>::leaf_with_entries(vec![
            NodeEntry::new("a".to_string(), 1),
            NodeEntry::new("b".to_string(), 2),
        ]);
        let leaf2 = ProllyNode::<String, i32>::leaf_with_entries(vec![
            NodeEntry::new("c".to_string(), 3),
            NodeEntry::new("d".to_string(), 4),
        ]);

        let cid1 = store.put_ipld(&leaf1).await.unwrap();
        let cid2 = store.put_ipld(&leaf2).await.unwrap();

        // Build a v1-style internal node with Link (no boundary)
        let mut root = ProllyNode::<String, i32>::new_internal(1);
        root.add_child(cid1);  // Legacy Link(Cid)
        root.add_child(cid2);  // Legacy Link(Cid)

        assert!(!root.has_boundaries(), "v1 nodes should not have boundaries");

        let root_cid = store.put_ipld(&root).await.unwrap();

        // Load the v1 tree
        let tree: ProllyTree<String, i32, _> =
            ProllyTree::load(Arc::clone(&store), root_cid).await.unwrap();

        // All keys should still be found via legacy scan
        assert_eq!(tree.get(&"a".to_string()).await.unwrap(), Some(1));
        assert_eq!(tree.get(&"b".to_string()).await.unwrap(), Some(2));
        assert_eq!(tree.get(&"c".to_string()).await.unwrap(), Some(3));
        assert_eq!(tree.get(&"d".to_string()).await.unwrap(), Some(4));
        assert_eq!(tree.get(&"e".to_string()).await.unwrap(), None);

        // Iteration should work
        let entries = tree.iter().await.unwrap();
        assert_eq!(entries.len(), 4);
    }

    #[tokio::test]
    async fn test_v1_tree_upgrades_to_v2_on_write() {
        let store = Arc::new(MemoryBlockStore::new());

        // Manually construct a v1 tree (Link without boundaries)
        let leaf1 = ProllyNode::<String, i32>::leaf_with_entries(vec![
            NodeEntry::new("a".to_string(), 1),
            NodeEntry::new("b".to_string(), 2),
            NodeEntry::new("c".to_string(), 3),
        ]);
        let leaf2 = ProllyNode::<String, i32>::leaf_with_entries(vec![
            NodeEntry::new("d".to_string(), 4),
            NodeEntry::new("e".to_string(), 5),
            NodeEntry::new("f".to_string(), 6),
        ]);

        let cid1 = store.put_ipld(&leaf1).await.unwrap();
        let cid2 = store.put_ipld(&leaf2).await.unwrap();

        let mut root = ProllyNode::<String, i32>::new_internal(1);
        root.add_child(cid1);
        root.add_child(cid2);
        let root_cid = store.put_ipld(&root).await.unwrap();

        // Load the v1 tree
        let config = ProllyConfig {
            max_leaf_entries: 4,
            ..Default::default()
        };
        let mut tree: ProllyTree<String, i32, _> =
            ProllyTree::load_with_config(Arc::clone(&store), root_cid, config).await.unwrap();

        assert!(!tree.root.has_boundaries(), "Loaded v1 tree should not have boundaries");

        // Write a new entry — triggers rebuild which upgrades to v2
        tree.set("g".to_string(), 7).await.unwrap();

        // After write, root should now have v2 boundaries
        if !tree.root.is_leaf {
            assert!(
                tree.root.has_boundaries(),
                "After set(), v1 tree should upgrade to v2 format"
            );
        }

        // All entries (old + new) still accessible
        for (k, expected) in [("a", 1), ("b", 2), ("c", 3), ("d", 4), ("e", 5), ("f", 6), ("g", 7)] {
            let val = tree.get(&k.to_string()).await.unwrap();
            assert_eq!(val, Some(expected), "Key '{}' should be {}", k, expected);
        }
    }

    #[tokio::test]
    async fn test_v2_remove_preserves_boundaries() {
        let store = Arc::new(MemoryBlockStore::new());
        let config = ProllyConfig {
            max_leaf_entries: 5,
            max_children: 256,
            ..Default::default()
        };
        let mut tree: ProllyTree<String, i32, _> = ProllyTree::with_config(store, config);

        for i in 0..20 {
            tree.set(format!("key_{:02}", i), i).await.unwrap();
        }

        assert!(tree.root.has_boundaries());

        // Remove a key
        let removed = tree.remove(&"key_10".to_string()).await.unwrap();
        assert_eq!(removed, Some(10));

        // Tree should still have boundaries after remove
        if !tree.root.is_leaf {
            assert!(tree.root.has_boundaries());
        }

        // Remaining entries still accessible
        assert_eq!(tree.get(&"key_10".to_string()).await.unwrap(), None);
        assert_eq!(tree.get(&"key_05".to_string()).await.unwrap(), Some(5));
        assert_eq!(tree.get(&"key_15".to_string()).await.unwrap(), Some(15));

        let all = tree.iter().await.unwrap();
        assert_eq!(all.len(), 19);
    }

    #[tokio::test]
    async fn test_v2_multi_level_boundaries() {
        let store = Arc::new(MemoryBlockStore::new());
        // Force 3 levels: 64 entries / 4 per leaf = 16 leaves / 4 per internal = 4 level-1 nodes
        let config = ProllyConfig {
            max_leaf_entries: 4,
            max_children: 4,
            ..Default::default()
        };
        let mut tree: ProllyTree<String, i32, _> = ProllyTree::with_config(store, config);

        for i in 0..64 {
            tree.set(format!("key_{:03}", i), i).await.unwrap();
        }

        // Root should be internal with boundaries
        assert!(!tree.root.is_leaf);
        assert!(tree.root.has_boundaries());
        assert!(tree.root.level >= 2, "Should be level 2+ for 64 entries with max_children=4");

        // All entries retrievable via multi-level boundary routing
        for i in 0..64 {
            let val = tree.get(&format!("key_{:03}", i)).await.unwrap();
            assert_eq!(val, Some(i), "Entry {} missing", i);
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // BOUNDED PREFIX LISTING TESTS (R-1.2)
    // ═══════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn test_list_prefix_bounded_basic() {
        let store = Arc::new(MemoryBlockStore::new());
        let config = ProllyConfig {
            max_leaf_entries: 5,
            ..Default::default()
        };
        let mut tree: ProllyTree<String, i32, _> = ProllyTree::with_config(store, config);

        tree.set("photos/a.jpg".to_string(), 1).await.unwrap();
        tree.set("photos/b.jpg".to_string(), 2).await.unwrap();
        tree.set("photos/c.jpg".to_string(), 3).await.unwrap();
        tree.set("docs/readme.md".to_string(), 4).await.unwrap();
        tree.set("docs/notes.txt".to_string(), 5).await.unwrap();

        let result = tree.list_prefix_bounded(b"photos/", None, 100).await.unwrap();
        assert_eq!(result.len(), 3);

        let result = tree.list_prefix_bounded(b"docs/", None, 100).await.unwrap();
        assert_eq!(result.len(), 2);

        let result = tree.list_prefix_bounded(b"videos/", None, 100).await.unwrap();
        assert_eq!(result.len(), 0);
    }

    #[tokio::test]
    async fn test_list_prefix_bounded_max_keys() {
        let store = Arc::new(MemoryBlockStore::new());
        let config = ProllyConfig {
            max_leaf_entries: 5,
            ..Default::default()
        };
        let mut tree: ProllyTree<String, i32, _> = ProllyTree::with_config(store, config);

        for i in 0..20 {
            tree.set(format!("file_{:02}.txt", i), i).await.unwrap();
        }

        // max_keys = 5 should return exactly 5
        let result = tree.list_prefix_bounded(b"file_", None, 5).await.unwrap();
        assert_eq!(result.len(), 5);

        // They should be the first 5 in sorted order
        assert_eq!(result[0].0, "file_00.txt");
        assert_eq!(result[4].0, "file_04.txt");
    }

    #[tokio::test]
    async fn test_list_prefix_bounded_start_after() {
        let store = Arc::new(MemoryBlockStore::new());
        let config = ProllyConfig {
            max_leaf_entries: 5,
            ..Default::default()
        };
        let mut tree: ProllyTree<String, i32, _> = ProllyTree::with_config(store, config);

        for i in 0..20 {
            tree.set(format!("item_{:02}", i), i).await.unwrap();
        }

        // Start after "item_10" — should skip 00..10
        let after = "item_10".to_string();
        let result = tree
            .list_prefix_bounded(b"item_", Some(&after), 5)
            .await
            .unwrap();

        assert_eq!(result.len(), 5);
        assert_eq!(result[0].0, "item_11");
        assert_eq!(result[4].0, "item_15");
    }

    #[tokio::test]
    async fn test_list_prefix_bounded_pagination() {
        let store = Arc::new(MemoryBlockStore::new());
        let config = ProllyConfig {
            max_leaf_entries: 5,
            ..Default::default()
        };
        let mut tree: ProllyTree<String, i32, _> = ProllyTree::with_config(store, config);

        for i in 0..30 {
            tree.set(format!("obj_{:02}", i), i).await.unwrap();
        }

        // Simulate pagination: page 1
        let page1 = tree.list_prefix_bounded(b"obj_", None, 10).await.unwrap();
        assert_eq!(page1.len(), 10);
        assert_eq!(page1[0].0, "obj_00");
        assert_eq!(page1[9].0, "obj_09");

        // Page 2: start after last key of page 1
        let page2 = tree
            .list_prefix_bounded(b"obj_", Some(&page1[9].0), 10)
            .await
            .unwrap();
        assert_eq!(page2.len(), 10);
        assert_eq!(page2[0].0, "obj_10");
        assert_eq!(page2[9].0, "obj_19");

        // Page 3
        let page3 = tree
            .list_prefix_bounded(b"obj_", Some(&page2[9].0), 10)
            .await
            .unwrap();
        assert_eq!(page3.len(), 10);
        assert_eq!(page3[0].0, "obj_20");
        assert_eq!(page3[9].0, "obj_29");

        // Page 4: should be empty
        let page4 = tree
            .list_prefix_bounded(b"obj_", Some(&page3[9].0), 10)
            .await
            .unwrap();
        assert_eq!(page4.len(), 0);
    }

    #[tokio::test]
    async fn test_list_prefix_bounded_on_large_tree() {
        let store = Arc::new(MemoryBlockStore::new());
        let config = ProllyConfig {
            max_leaf_entries: 10,
            max_children: 10,
            ..Default::default()
        };
        let mut tree: ProllyTree<String, i32, _> = ProllyTree::with_config(store, config);

        // Build a multi-level tree
        for i in 0..200 {
            tree.set(format!("data/{:03}.bin", i), i).await.unwrap();
        }

        assert!(tree.root.has_boundaries());

        // Bounded query should return correct results
        let result = tree
            .list_prefix_bounded(b"data/", None, 10)
            .await
            .unwrap();
        assert_eq!(result.len(), 10);
        assert_eq!(result[0].0, "data/000.bin");
        assert_eq!(result[9].0, "data/009.bin");

        // With start_after
        let after = "data/099.bin".to_string();
        let result = tree
            .list_prefix_bounded(b"data/", Some(&after), 5)
            .await
            .unwrap();
        assert_eq!(result.len(), 5);
        assert_eq!(result[0].0, "data/100.bin");
    }
}
