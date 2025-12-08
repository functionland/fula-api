//! HAMT-based index for large file trees (WNFS-inspired)
//!
//! This module implements a Hash Array Mapped Trie (HAMT) for indexing
//! large numbers of files, borrowing the sharding pattern from WNFS
//! while keeping Fula's simpler key-value semantics.
//!
//! ## Design
//!
//! Instead of storing all files in a flat `HashMap<String, ForestFileEntry>`,
//! we use a HAMT structure that:
//! - Shards entries by BLAKE3 hash of the path
//! - Allows O(log N) lookups, inserts, and deletes
//! - Enables lazy loading of subtrees
//!
//! ## Compatibility
//!
//! - PrivateForest API: unchanged, internal representation only
//! - Versioning: `HamtV2` format distinguished from `FlatMapV1`
//! - Migration: automatic on load/save

// Unused imports removed - we use blake3 directly
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Maximum entries per bucket before splitting
const BUCKET_SIZE: usize = 8;

/// Maximum HAMT depth
const MAX_DEPTH: usize = 16;

/// Hash a path to get its HAMT key
fn hash_path(path: &str) -> [u8; 32] {
    *blake3::hash(path.as_bytes()).as_bytes()
}

/// Get the nibble (4 bits) at a specific level from a hash
fn get_nibble(hash: &[u8; 32], level: usize) -> usize {
    let byte_index = level / 2;
    let nibble = if level % 2 == 0 {
        (hash[byte_index] >> 4) & 0x0F
    } else {
        hash[byte_index] & 0x0F
    };
    nibble as usize
}

/// A HAMT-based index for file entries
/// 
/// This provides O(log N) access to file entries while allowing
/// lazy loading and efficient serialization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HamtIndex<V: Clone> {
    /// Version for format evolution
    pub version: u8,
    /// Root node of the HAMT
    pub root: HamtNode<V>,
    /// Total number of entries
    pub count: usize,
}

/// A node in the HAMT tree
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum HamtNode<V: Clone> {
    /// Empty node
    Empty,
    /// Leaf node with a bucket of entries
    Bucket {
        entries: Vec<(String, V)>,
    },
    /// Internal node with children
    Branch {
        /// Bitmap indicating which children exist
        bitmap: u16,
        /// Child nodes (only for set bits in bitmap)
        children: Vec<HamtNode<V>>,
    },
}

impl<V: Clone> Default for HamtIndex<V> {
    fn default() -> Self {
        Self::new()
    }
}

impl<V: Clone> HamtIndex<V> {
    /// Create a new empty HAMT index
    pub fn new() -> Self {
        Self {
            version: 2,
            root: HamtNode::Empty,
            count: 0,
        }
    }

    /// Insert or update an entry
    pub fn insert(&mut self, path: String, value: V) {
        let hash = hash_path(&path);
        let old_root = std::mem::replace(&mut self.root, HamtNode::Empty);
        let (new_root, was_update) = old_root.insert(path, value, &hash, 0);
        self.root = new_root;
        if !was_update {
            self.count += 1;
        }
    }

    /// Get an entry by path
    pub fn get(&self, path: &str) -> Option<&V> {
        let hash = hash_path(path);
        self.root.get(path, &hash, 0)
    }

    /// Remove an entry by path
    pub fn remove(&mut self, path: &str) -> Option<V> {
        let hash = hash_path(path);
        let old_root = std::mem::replace(&mut self.root, HamtNode::Empty);
        let (new_root, removed) = old_root.remove(path, &hash, 0);
        self.root = new_root;
        if removed.is_some() {
            self.count -= 1;
        }
        removed
    }

    /// Check if the index contains a path
    pub fn contains(&self, path: &str) -> bool {
        self.get(path).is_some()
    }

    /// Get the number of entries
    pub fn len(&self) -> usize {
        self.count
    }

    /// Check if the index is empty
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Iterate over all entries
    pub fn iter(&self) -> HamtIterator<'_, V> {
        HamtIterator::new(&self.root)
    }

    /// Iterate over entries with a path prefix
    pub fn iter_prefix<'a>(&'a self, prefix: &'a str) -> impl Iterator<Item = (&'a String, &'a V)> + 'a {
        self.iter().filter(move |(path, _)| path.starts_with(prefix))
    }

    /// Convert from a HashMap (for migration from FlatMapV1)
    pub fn from_hashmap(map: HashMap<String, V>) -> Self {
        let mut index = Self::new();
        for (path, value) in map {
            index.insert(path, value);
        }
        index
    }

    /// Convert to a HashMap (for backward compatibility)
    pub fn to_hashmap(&self) -> HashMap<String, V> {
        self.iter()
            .map(|(path, value)| (path.clone(), value.clone()))
            .collect()
    }
}

impl<V: Clone> HamtNode<V> {
    /// Insert a value, returning the new node and whether it was an update
    fn insert(self, path: String, value: V, hash: &[u8; 32], level: usize) -> (Self, bool) {
        match self {
            HamtNode::Empty => {
                (HamtNode::Bucket {
                    entries: vec![(path, value)],
                }, false)
            }
            HamtNode::Bucket { mut entries } => {
                // Check if updating existing
                for (i, (p, _)) in entries.iter().enumerate() {
                    if p == &path {
                        entries[i] = (path, value);
                        return (HamtNode::Bucket { entries }, true);
                    }
                }

                // Add to bucket
                entries.push((path, value));

                // Check if we need to split
                if entries.len() > BUCKET_SIZE && level < MAX_DEPTH {
                    // Split into a branch
                    let mut branch = HamtNode::new_branch();
                    for (p, v) in entries {
                        let h = hash_path(&p);
                        branch = branch.insert(p, v, &h, level).0;
                    }
                    (branch, false)
                } else {
                    (HamtNode::Bucket { entries }, false)
                }
            }
            HamtNode::Branch { bitmap, mut children } => {
                let nibble = get_nibble(hash, level);
                let bit = 1u16 << nibble;
                let index = (bitmap & (bit - 1)).count_ones() as usize;

                if bitmap & bit != 0 {
                    // Child exists, recurse
                    let child = children.remove(index);
                    let (new_child, was_update) = child.insert(path, value, hash, level + 1);
                    children.insert(index, new_child);
                    (HamtNode::Branch { bitmap, children }, was_update)
                } else {
                    // Create new child
                    let new_child = HamtNode::Bucket {
                        entries: vec![(path, value)],
                    };
                    children.insert(index, new_child);
                    (HamtNode::Branch {
                        bitmap: bitmap | bit,
                        children,
                    }, false)
                }
            }
        }
    }

    /// Get a value by path
    fn get<'a>(&'a self, path: &str, hash: &[u8; 32], level: usize) -> Option<&'a V> {
        match self {
            HamtNode::Empty => None,
            HamtNode::Bucket { entries } => {
                entries.iter()
                    .find(|(p, _)| p == path)
                    .map(|(_, v)| v)
            }
            HamtNode::Branch { bitmap, children } => {
                let nibble = get_nibble(hash, level);
                let bit = 1u16 << nibble;
                
                if bitmap & bit != 0 {
                    let index = (bitmap & (bit - 1)).count_ones() as usize;
                    children[index].get(path, hash, level + 1)
                } else {
                    None
                }
            }
        }
    }

    /// Remove a value by path
    fn remove(self, path: &str, hash: &[u8; 32], level: usize) -> (Self, Option<V>) {
        match self {
            HamtNode::Empty => (HamtNode::Empty, None),
            HamtNode::Bucket { mut entries } => {
                if let Some(idx) = entries.iter().position(|(p, _)| p == path) {
                    let (_, value) = entries.remove(idx);
                    if entries.is_empty() {
                        (HamtNode::Empty, Some(value))
                    } else {
                        (HamtNode::Bucket { entries }, Some(value))
                    }
                } else {
                    (HamtNode::Bucket { entries }, None)
                }
            }
            HamtNode::Branch { bitmap, mut children } => {
                let nibble = get_nibble(hash, level);
                let bit = 1u16 << nibble;

                if bitmap & bit != 0 {
                    let index = (bitmap & (bit - 1)).count_ones() as usize;
                    let child = children.remove(index);
                    let (new_child, removed) = child.remove(path, hash, level + 1);

                    match new_child {
                        HamtNode::Empty => {
                            // Child became empty, remove it
                            let new_bitmap = bitmap & !bit;
                            if children.is_empty() {
                                (HamtNode::Empty, removed)
                            } else {
                                (HamtNode::Branch {
                                    bitmap: new_bitmap,
                                    children,
                                }, removed)
                            }
                        }
                        _ => {
                            children.insert(index, new_child);
                            (HamtNode::Branch { bitmap, children }, removed)
                        }
                    }
                } else {
                    (HamtNode::Branch { bitmap, children }, None)
                }
            }
        }
    }

    /// Create a new empty branch
    fn new_branch() -> Self {
        HamtNode::Branch {
            bitmap: 0,
            children: Vec::new(),
        }
    }
}

/// Iterator over HAMT entries
pub struct HamtIterator<'a, V: Clone> {
    stack: Vec<&'a HamtNode<V>>,
    current_bucket: Option<std::slice::Iter<'a, (String, V)>>,
}

impl<'a, V: Clone> HamtIterator<'a, V> {
    fn new(root: &'a HamtNode<V>) -> Self {
        let mut stack = Vec::new();
        stack.push(root);
        Self {
            stack,
            current_bucket: None,
        }
    }
}

impl<'a, V: Clone> Iterator for HamtIterator<'a, V> {
    type Item = (&'a String, &'a V);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            // Try to get from current bucket
            if let Some(ref mut bucket_iter) = self.current_bucket {
                if let Some((path, value)) = bucket_iter.next() {
                    return Some((path, value));
                }
                self.current_bucket = None;
            }

            // Get next node from stack
            let node = self.stack.pop()?;

            match node {
                HamtNode::Empty => continue,
                HamtNode::Bucket { entries } => {
                    self.current_bucket = Some(entries.iter());
                }
                HamtNode::Branch { children, .. } => {
                    // Push children in reverse order for correct traversal
                    for child in children.iter().rev() {
                        self.stack.push(child);
                    }
                }
            }
        }
    }
}

/// Sharded prefix index for efficient prefix queries
/// 
/// This is a simpler alternative to full HAMT that still provides
/// sharding benefits for large directories.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardedIndex<V: Clone> {
    /// Version for format evolution
    pub version: u8,
    /// Number of shards (power of 2)
    pub num_shards: usize,
    /// Sharded buckets keyed by path hash prefix
    pub shards: Vec<HashMap<String, V>>,
    /// Total entry count
    pub count: usize,
}

impl<V: Clone> Default for ShardedIndex<V> {
    fn default() -> Self {
        Self::new(16) // 16 shards by default
    }
}

impl<V: Clone> ShardedIndex<V> {
    /// Create a new sharded index with the given number of shards
    pub fn new(num_shards: usize) -> Self {
        let num_shards = num_shards.next_power_of_two();
        Self {
            version: 2,
            num_shards,
            shards: (0..num_shards).map(|_| HashMap::new()).collect(),
            count: 0,
        }
    }

    /// Get the shard index for a path
    fn shard_for(&self, path: &str) -> usize {
        let hash = blake3::hash(path.as_bytes());
        let first_byte = hash.as_bytes()[0] as usize;
        first_byte % self.num_shards
    }

    /// Insert or update an entry
    pub fn insert(&mut self, path: String, value: V) {
        let shard = self.shard_for(&path);
        if self.shards[shard].insert(path, value).is_none() {
            self.count += 1;
        }
    }

    /// Get an entry by path
    pub fn get(&self, path: &str) -> Option<&V> {
        let shard = self.shard_for(path);
        self.shards[shard].get(path)
    }

    /// Remove an entry by path
    pub fn remove(&mut self, path: &str) -> Option<V> {
        let shard = self.shard_for(path);
        let removed = self.shards[shard].remove(path);
        if removed.is_some() {
            self.count -= 1;
        }
        removed
    }

    /// Get the number of entries
    pub fn len(&self) -> usize {
        self.count
    }

    /// Check if the index is empty
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Iterate over all entries
    pub fn iter(&self) -> impl Iterator<Item = (&String, &V)> + '_ {
        self.shards.iter().flat_map(|shard| shard.iter())
    }

    /// Iterate over entries with a path prefix
    pub fn iter_prefix<'a>(&'a self, prefix: &'a str) -> impl Iterator<Item = (&'a String, &'a V)> + 'a {
        self.iter().filter(move |(path, _)| path.starts_with(prefix))
    }

    /// Convert from a HashMap
    pub fn from_hashmap(map: HashMap<String, V>) -> Self {
        let mut index = Self::new(16);
        for (path, value) in map {
            index.insert(path, value);
        }
        index
    }

    /// Convert to a HashMap
    pub fn to_hashmap(&self) -> HashMap<String, V> {
        self.iter()
            .map(|(path, value)| (path.clone(), value.clone()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hamt_basic_operations() {
        let mut index: HamtIndex<String> = HamtIndex::new();
        
        // Insert
        index.insert("/photos/beach.jpg".to_string(), "cid1".to_string());
        index.insert("/photos/mountain.jpg".to_string(), "cid2".to_string());
        index.insert("/documents/report.pdf".to_string(), "cid3".to_string());
        
        assert_eq!(index.len(), 3);
        
        // Get
        assert_eq!(index.get("/photos/beach.jpg"), Some(&"cid1".to_string()));
        assert_eq!(index.get("/photos/mountain.jpg"), Some(&"cid2".to_string()));
        assert_eq!(index.get("/nonexistent"), None);
        
        // Update
        index.insert("/photos/beach.jpg".to_string(), "cid1-updated".to_string());
        assert_eq!(index.get("/photos/beach.jpg"), Some(&"cid1-updated".to_string()));
        assert_eq!(index.len(), 3); // Count unchanged
        
        // Remove
        let removed = index.remove("/photos/beach.jpg");
        assert_eq!(removed, Some("cid1-updated".to_string()));
        assert_eq!(index.len(), 2);
        assert_eq!(index.get("/photos/beach.jpg"), None);
    }

    #[test]
    fn test_hamt_many_entries() {
        let mut index: HamtIndex<u32> = HamtIndex::new();
        
        // Insert many entries to trigger splitting
        for i in 0..1000 {
            index.insert(format!("/files/file_{:04}.txt", i), i);
        }
        
        assert_eq!(index.len(), 1000);
        
        // Verify all entries
        for i in 0..1000 {
            let path = format!("/files/file_{:04}.txt", i);
            assert_eq!(index.get(&path), Some(&i));
        }
    }

    #[test]
    fn test_hamt_prefix_iteration() {
        let mut index: HamtIndex<String> = HamtIndex::new();
        
        index.insert("/photos/2023/jan/1.jpg".to_string(), "a".to_string());
        index.insert("/photos/2023/jan/2.jpg".to_string(), "b".to_string());
        index.insert("/photos/2023/feb/1.jpg".to_string(), "c".to_string());
        index.insert("/documents/report.pdf".to_string(), "d".to_string());
        
        let photos: Vec<_> = index.iter_prefix("/photos/2023/jan/").collect();
        assert_eq!(photos.len(), 2);
        
        let docs: Vec<_> = index.iter_prefix("/documents/").collect();
        assert_eq!(docs.len(), 1);
    }

    #[test]
    fn test_hamt_hashmap_conversion() {
        let mut map = HashMap::new();
        map.insert("/a".to_string(), 1);
        map.insert("/b".to_string(), 2);
        map.insert("/c".to_string(), 3);
        
        let index = HamtIndex::from_hashmap(map.clone());
        let recovered = index.to_hashmap();
        
        assert_eq!(map, recovered);
    }

    #[test]
    fn test_sharded_index_basic() {
        let mut index: ShardedIndex<String> = ShardedIndex::new(4);
        
        index.insert("/a".to_string(), "1".to_string());
        index.insert("/b".to_string(), "2".to_string());
        index.insert("/c".to_string(), "3".to_string());
        
        assert_eq!(index.len(), 3);
        assert_eq!(index.get("/a"), Some(&"1".to_string()));
        assert_eq!(index.get("/nonexistent"), None);
        
        let removed = index.remove("/b");
        assert_eq!(removed, Some("2".to_string()));
        assert_eq!(index.len(), 2);
    }

    #[test]
    fn test_sharded_distribution() {
        let index: ShardedIndex<u32> = {
            let mut idx = ShardedIndex::new(16);
            for i in 0..1000 {
                idx.insert(format!("/file_{}", i), i);
            }
            idx
        };
        
        // Verify entries are distributed across shards
        let shard_sizes: Vec<_> = index.shards.iter().map(|s| s.len()).collect();
        
        // No shard should be empty with 1000 entries and 16 shards
        for (i, size) in shard_sizes.iter().enumerate() {
            assert!(*size > 0, "Shard {} is empty", i);
        }
        
        // Total should match
        let total: usize = shard_sizes.iter().sum();
        assert_eq!(total, 1000);
    }
}
