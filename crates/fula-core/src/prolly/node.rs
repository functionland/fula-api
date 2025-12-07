//! Prolly Tree node types

use cid::Cid;
use serde::{Deserialize, Serialize};
use std::fmt;

/// An entry in a Prolly Tree node
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeEntry<K, V> {
    /// The key
    pub key: K,
    /// The value
    pub value: V,
}

impl<K, V> NodeEntry<K, V> {
    /// Create a new entry
    pub fn new(key: K, value: V) -> Self {
        Self { key, value }
    }
}

/// A pointer to a child node or inline values
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Pointer<K, V> {
    /// Inline values (leaf-level bucket)
    Values(Vec<NodeEntry<K, V>>),
    /// Link to a child node
    Link(#[serde(with = "cid_serde")] Cid),
}

impl<K, V> Pointer<K, V> {
    /// Check if this is a link
    pub fn is_link(&self) -> bool {
        matches!(self, Pointer::Link(_))
    }

    /// Check if this is values
    pub fn is_values(&self) -> bool {
        matches!(self, Pointer::Values(_))
    }

    /// Get the CID if this is a link
    pub fn as_cid(&self) -> Option<&Cid> {
        match self {
            Pointer::Link(cid) => Some(cid),
            _ => None,
        }
    }

    /// Get the values if this is a values pointer
    pub fn as_values(&self) -> Option<&[NodeEntry<K, V>]> {
        match self {
            Pointer::Values(v) => Some(v),
            _ => None,
        }
    }
}

/// A node in the Prolly Tree
#[derive(Clone, Serialize, Deserialize)]
pub struct ProllyNode<K, V> {
    /// Bitmask indicating which slots are occupied
    #[serde(with = "serde_bytes")]
    pub bitmask: Vec<u8>,
    /// Pointers to children or values
    pub pointers: Vec<Pointer<K, V>>,
    /// Whether this is a leaf node
    pub is_leaf: bool,
    /// Level in the tree (0 = leaf)
    pub level: u8,
}

impl<K, V> ProllyNode<K, V>
where
    K: Clone + Ord,
    V: Clone,
{
    /// Create a new empty leaf node
    pub fn new_leaf() -> Self {
        Self {
            bitmask: vec![0u8; 2], // 16 bits
            pointers: Vec::new(),
            is_leaf: true,
            level: 0,
        }
    }

    /// Create a new internal node
    pub fn new_internal(level: u8) -> Self {
        Self {
            bitmask: vec![0u8; 2],
            pointers: Vec::new(),
            is_leaf: false,
            level,
        }
    }

    /// Create a leaf node with entries
    pub fn leaf_with_entries(entries: Vec<NodeEntry<K, V>>) -> Self {
        let mut node = Self::new_leaf();
        if !entries.is_empty() {
            node.pointers.push(Pointer::Values(entries));
            node.bitmask[0] = 0x01; // Mark first slot as occupied
        }
        node
    }

    /// Check if the node is empty
    pub fn is_empty(&self) -> bool {
        self.pointers.is_empty()
    }

    /// Get the number of pointers
    pub fn len(&self) -> usize {
        self.pointers.len()
    }

    /// Get all entries (flattened from all value pointers)
    pub fn entries(&self) -> Vec<&NodeEntry<K, V>> {
        let mut result = Vec::new();
        for pointer in &self.pointers {
            if let Pointer::Values(values) = pointer {
                for entry in values {
                    result.push(entry);
                }
            }
        }
        result
    }

    /// Get a value by key (linear search within node)
    pub fn get(&self, key: &K) -> Option<&V> {
        for pointer in &self.pointers {
            if let Pointer::Values(values) = pointer {
                for entry in values {
                    if &entry.key == key {
                        return Some(&entry.value);
                    }
                }
            }
        }
        None
    }

    /// Insert or update a key-value pair
    pub fn insert(&mut self, key: K, value: V) {
        // Find existing entry
        for pointer in &mut self.pointers {
            if let Pointer::Values(values) = pointer {
                for entry in values.iter_mut() {
                    if entry.key == key {
                        entry.value = value;
                        return;
                    }
                }
            }
        }

        // Add new entry
        if self.pointers.is_empty() {
            self.pointers.push(Pointer::Values(vec![NodeEntry::new(key, value)]));
            self.bitmask[0] = 0x01;
        } else if let Some(Pointer::Values(values)) = self.pointers.last_mut() {
            values.push(NodeEntry::new(key, value));
            // Sort to maintain order
            values.sort_by(|a, b| a.key.cmp(&b.key));
        }
    }

    /// Remove a key
    pub fn remove(&mut self, key: &K) -> Option<V> {
        for pointer in &mut self.pointers {
            if let Pointer::Values(values) = pointer {
                if let Some(pos) = values.iter().position(|e| &e.key == key) {
                    let entry = values.remove(pos);
                    return Some(entry.value);
                }
            }
        }
        None
    }

    /// Add a child link
    pub fn add_child(&mut self, cid: Cid) {
        self.pointers.push(Pointer::Link(cid));
    }

    /// Get all child CIDs
    pub fn child_cids(&self) -> Vec<Cid> {
        self.pointers
            .iter()
            .filter_map(|p| p.as_cid().copied())
            .collect()
    }

    /// Check if the bitmask bit at index is set
    pub fn is_bit_set(&self, index: usize) -> bool {
        let byte_idx = index / 8;
        let bit_idx = index % 8;
        if byte_idx >= self.bitmask.len() {
            return false;
        }
        (self.bitmask[byte_idx] >> bit_idx) & 1 == 1
    }

    /// Set the bitmask bit at index
    pub fn set_bit(&mut self, index: usize) {
        let byte_idx = index / 8;
        let bit_idx = index % 8;
        while byte_idx >= self.bitmask.len() {
            self.bitmask.push(0);
        }
        self.bitmask[byte_idx] |= 1 << bit_idx;
    }

    /// Count set bits in bitmask up to index
    pub fn count_bits_before(&self, index: usize) -> usize {
        let mut count = 0;
        for i in 0..index {
            if self.is_bit_set(i) {
                count += 1;
            }
        }
        count
    }
}

impl<K: fmt::Debug, V: fmt::Debug> fmt::Debug for ProllyNode<K, V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProllyNode")
            .field("is_leaf", &self.is_leaf)
            .field("level", &self.level)
            .field("pointers_count", &self.pointers.len())
            .finish()
    }
}

impl<K, V> Default for ProllyNode<K, V>
where
    K: Clone + Ord,
    V: Clone,
{
    fn default() -> Self {
        Self::new_leaf()
    }
}

mod cid_serde {
    use cid::Cid;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(cid: &Cid, s: S) -> Result<S::Ok, S::Error> {
        cid.to_string().serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Cid, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// Serializable format for a Prolly Tree root
#[allow(dead_code)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProllyTreeSerializable<K, V> {
    pub root: ProllyNode<K, V>,
    pub version: String,
    pub structure: String,
}

#[allow(dead_code)]
impl<K, V> ProllyTreeSerializable<K, V> {
    pub fn new(root: ProllyNode<K, V>) -> Self {
        Self {
            root,
            version: crate::STORAGE_VERSION.to_string(),
            structure: "prolly-tree".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_entry() {
        let entry = NodeEntry::new("key".to_string(), 42);
        assert_eq!(entry.key, "key");
        assert_eq!(entry.value, 42);
    }

    #[test]
    fn test_leaf_node() {
        let mut node: ProllyNode<String, i32> = ProllyNode::new_leaf();
        assert!(node.is_leaf);
        assert!(node.is_empty());

        node.insert("a".to_string(), 1);
        node.insert("b".to_string(), 2);

        assert_eq!(node.get(&"a".to_string()), Some(&1));
        assert_eq!(node.get(&"b".to_string()), Some(&2));
        assert_eq!(node.get(&"c".to_string()), None);
    }

    #[test]
    fn test_node_remove() {
        let mut node: ProllyNode<String, i32> = ProllyNode::new_leaf();
        node.insert("a".to_string(), 1);
        node.insert("b".to_string(), 2);

        let removed = node.remove(&"a".to_string());
        assert_eq!(removed, Some(1));
        assert_eq!(node.get(&"a".to_string()), None);
    }

    #[test]
    fn test_bitmask_operations() {
        let mut node: ProllyNode<String, i32> = ProllyNode::new_leaf();
        
        assert!(!node.is_bit_set(5));
        node.set_bit(5);
        assert!(node.is_bit_set(5));
        
        node.set_bit(10);
        assert_eq!(node.count_bits_before(11), 2);
    }
}
