//! CRDT (Conflict-free Replicated Data Types) for metadata management
//!
//! Provides conflict-free concurrent updates for bucket metadata like
//! tags, ACLs, and custom headers.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use chrono::{DateTime, Utc};

/// A Last-Write-Wins Register
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LWWRegister<T> {
    value: T,
    timestamp: DateTime<Utc>,
    node_id: String,
}

impl<T: Clone> LWWRegister<T> {
    /// Create a new register
    pub fn new(value: T, node_id: impl Into<String>) -> Self {
        Self {
            value,
            timestamp: Utc::now(),
            node_id: node_id.into(),
        }
    }

    /// Get the current value
    pub fn value(&self) -> &T {
        &self.value
    }

    /// Get the timestamp
    pub fn timestamp(&self) -> DateTime<Utc> {
        self.timestamp
    }

    /// Update the value
    pub fn set(&mut self, value: T) {
        self.value = value;
        self.timestamp = Utc::now();
    }

    /// Merge with another register (LWW semantics)
    pub fn merge(&mut self, other: &Self) {
        if other.timestamp > self.timestamp
            || (other.timestamp == self.timestamp && other.node_id > self.node_id)
        {
            self.value = other.value.clone();
            self.timestamp = other.timestamp;
            self.node_id = other.node_id.clone();
        }
    }
}

/// An Observed-Remove Set (OR-Set)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ORSet<T: Ord + Clone> {
    /// Elements with their unique tags
    elements: BTreeMap<T, BTreeSet<String>>,
    /// Tombstones (removed element tags)
    tombstones: BTreeMap<T, BTreeSet<String>>,
    /// Node identifier
    node_id: String,
    /// Counter for generating unique tags
    counter: u64,
}

impl<T: Ord + Clone> ORSet<T> {
    /// Create a new empty OR-Set
    pub fn new(node_id: impl Into<String>) -> Self {
        Self {
            elements: BTreeMap::new(),
            tombstones: BTreeMap::new(),
            node_id: node_id.into(),
            counter: 0,
        }
    }

    /// Add an element
    pub fn add(&mut self, element: T) {
        self.counter += 1;
        let tag = format!("{}:{}", self.node_id, self.counter);
        
        self.elements
            .entry(element)
            .or_insert_with(BTreeSet::new)
            .insert(tag);
    }

    /// Remove an element (all observed instances)
    pub fn remove(&mut self, element: &T) {
        if let Some(tags) = self.elements.remove(element) {
            self.tombstones
                .entry(element.clone())
                .or_insert_with(BTreeSet::new)
                .extend(tags);
        }
    }

    /// Check if element is present
    pub fn contains(&self, element: &T) -> bool {
        self.elements.contains_key(element)
    }

    /// Get all elements
    pub fn elements(&self) -> Vec<&T> {
        self.elements.keys().collect()
    }

    /// Merge with another OR-Set
    pub fn merge(&mut self, other: &Self) {
        // Merge elements
        for (element, tags) in &other.elements {
            let entry = self.elements.entry(element.clone()).or_insert_with(BTreeSet::new);
            entry.extend(tags.iter().cloned());
        }

        // Merge tombstones
        for (element, tags) in &other.tombstones {
            let entry = self.tombstones.entry(element.clone()).or_insert_with(BTreeSet::new);
            entry.extend(tags.iter().cloned());
        }

        // Remove tombstoned tags from elements
        for (element, tombstone_tags) in &self.tombstones {
            if let Some(element_tags) = self.elements.get_mut(element) {
                for tag in tombstone_tags {
                    element_tags.remove(tag);
                }
                if element_tags.is_empty() {
                    self.elements.remove(element);
                }
            }
        }
    }

    /// Get the size
    pub fn len(&self) -> usize {
        self.elements.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.elements.is_empty()
    }
}

/// A CRDT Map with LWW semantics for values
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LWWMap<K: Ord + Clone, V: Clone> {
    entries: BTreeMap<K, LWWRegister<Option<V>>>,
    node_id: String,
}

impl<K: Ord + Clone, V: Clone> LWWMap<K, V> {
    /// Create a new empty map
    pub fn new(node_id: impl Into<String>) -> Self {
        Self {
            entries: BTreeMap::new(),
            node_id: node_id.into(),
        }
    }

    /// Insert a key-value pair
    pub fn insert(&mut self, key: K, value: V) {
        let register = LWWRegister::new(Some(value), &self.node_id);
        self.entries.insert(key, register);
    }

    /// Remove a key
    pub fn remove(&mut self, key: &K) {
        if let Some(register) = self.entries.get_mut(key) {
            register.set(None);
        }
    }

    /// Get a value
    pub fn get(&self, key: &K) -> Option<&V> {
        self.entries.get(key).and_then(|r| r.value().as_ref())
    }

    /// Check if key exists
    pub fn contains_key(&self, key: &K) -> bool {
        self.get(key).is_some()
    }

    /// Get all keys with values
    pub fn keys(&self) -> Vec<&K> {
        self.entries
            .iter()
            .filter(|(_, v)| v.value().is_some())
            .map(|(k, _)| k)
            .collect()
    }

    /// Get all key-value pairs
    pub fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
        self.entries
            .iter()
            .filter_map(|(k, v)| v.value().as_ref().map(|val| (k, val)))
    }

    /// Merge with another map
    pub fn merge(&mut self, other: &Self) {
        for (key, other_register) in &other.entries {
            match self.entries.get_mut(key) {
                Some(register) => register.merge(other_register),
                None => {
                    self.entries.insert(key.clone(), other_register.clone());
                }
            }
        }
    }

    /// Get the size (non-tombstoned entries)
    pub fn len(&self) -> usize {
        self.entries.values().filter(|r| r.value().is_some()).count()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// CRDT-based metadata for buckets
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CRDTMetadata {
    /// Tags (CRDT Map)
    pub tags: LWWMap<String, String>,
    /// ACL entries (OR-Set of permission strings)
    pub acl: ORSet<String>,
    /// Custom headers (CRDT Map)
    pub headers: LWWMap<String, String>,
}

impl CRDTMetadata {
    /// Create new metadata
    pub fn new(node_id: impl Into<String>) -> Self {
        let node_id = node_id.into();
        Self {
            tags: LWWMap::new(&node_id),
            acl: ORSet::new(&node_id),
            headers: LWWMap::new(&node_id),
        }
    }

    /// Merge with another metadata instance
    pub fn merge(&mut self, other: &Self) {
        self.tags.merge(&other.tags);
        self.acl.merge(&other.acl);
        self.headers.merge(&other.headers);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lww_register() {
        let mut reg1 = LWWRegister::new(10, "node1");
        let mut reg2 = LWWRegister::new(20, "node2");

        // Sleep to ensure different timestamps
        std::thread::sleep(std::time::Duration::from_millis(10));
        reg2.set(30);

        reg1.merge(&reg2);
        assert_eq!(*reg1.value(), 30);
    }

    #[test]
    fn test_or_set() {
        let mut set1 = ORSet::new("node1");
        let mut set2 = ORSet::new("node2");

        set1.add("a".to_string());
        set1.add("b".to_string());
        set2.add("b".to_string());
        set2.add("c".to_string());

        set1.merge(&set2);
        
        assert!(set1.contains(&"a".to_string()));
        assert!(set1.contains(&"b".to_string()));
        assert!(set1.contains(&"c".to_string()));
    }

    #[test]
    fn test_or_set_remove() {
        let mut set1 = ORSet::new("node1");
        let mut set2 = ORSet::new("node2");

        set1.add("x".to_string());
        set2.merge(&set1);

        set1.remove(&"x".to_string());
        set2.add("x".to_string()); // Concurrent add

        set1.merge(&set2);
        
        // Add wins over remove in OR-Set
        assert!(set1.contains(&"x".to_string()));
    }

    #[test]
    fn test_lww_map() {
        let mut map1 = LWWMap::new("node1");
        let mut map2 = LWWMap::new("node2");

        map1.insert("a".to_string(), 1);
        map1.insert("b".to_string(), 2);
        map2.insert("b".to_string(), 3);
        map2.insert("c".to_string(), 4);

        std::thread::sleep(std::time::Duration::from_millis(10));
        map2.insert("b".to_string(), 30); // Later write

        map1.merge(&map2);

        assert_eq!(map1.get(&"a".to_string()), Some(&1));
        assert_eq!(map1.get(&"b".to_string()), Some(&30));
        assert_eq!(map1.get(&"c".to_string()), Some(&4));
    }

    #[test]
    fn test_crdt_metadata() {
        let mut meta1 = CRDTMetadata::new("node1");
        let mut meta2 = CRDTMetadata::new("node2");

        meta1.tags.insert("project".to_string(), "alpha".to_string());
        meta2.tags.insert("status".to_string(), "active".to_string());

        meta1.acl.add("user:read".to_string());
        meta2.acl.add("admin:write".to_string());

        meta1.merge(&meta2);

        assert_eq!(meta1.tags.get(&"project".to_string()), Some(&"alpha".to_string()));
        assert_eq!(meta1.tags.get(&"status".to_string()), Some(&"active".to_string()));
        assert!(meta1.acl.contains(&"user:read".to_string()));
        assert!(meta1.acl.contains(&"admin:write".to_string()));
    }
}
