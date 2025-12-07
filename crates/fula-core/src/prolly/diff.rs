//! Diff and merge operations for Prolly Trees

use super::ProllyNode;
use serde::{Deserialize, Serialize};

/// Type of change in a diff
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChangeType {
    /// Key was added
    Add,
    /// Key was removed
    Remove,
    /// Value was modified
    Modify,
}

/// A key-value change between two tree versions
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyValueChange<K, V> {
    /// The key that changed
    pub key: K,
    /// Type of change
    pub change_type: ChangeType,
    /// Old value (for Remove and Modify)
    pub old_value: Option<V>,
    /// New value (for Add and Modify)
    pub new_value: Option<V>,
}

impl<K, V> KeyValueChange<K, V> {
    /// Create an add change
    pub fn add(key: K, value: V) -> Self {
        Self {
            key,
            change_type: ChangeType::Add,
            old_value: None,
            new_value: Some(value),
        }
    }

    /// Create a remove change
    pub fn remove(key: K, value: V) -> Self {
        Self {
            key,
            change_type: ChangeType::Remove,
            old_value: Some(value),
            new_value: None,
        }
    }

    /// Create a modify change
    pub fn modify(key: K, old: V, new: V) -> Self {
        Self {
            key,
            change_type: ChangeType::Modify,
            old_value: Some(old),
            new_value: Some(new),
        }
    }
}

/// Compute the diff between two Prolly Tree nodes
pub fn diff_trees<K, V>(
    base: &ProllyNode<K, V>,
    other: &ProllyNode<K, V>,
) -> Vec<KeyValueChange<K, V>>
where
    K: Clone + Ord + Eq,
    V: Clone + PartialEq,
{
    let mut changes = Vec::new();

    // Collect all entries from both trees
    let base_entries: Vec<_> = base.entries();
    let other_entries: Vec<_> = other.entries();

    // Build maps for efficient lookup
    let mut base_map: std::collections::BTreeMap<&K, &V> = std::collections::BTreeMap::new();
    for entry in &base_entries {
        base_map.insert(&entry.key, &entry.value);
    }

    let mut other_map: std::collections::BTreeMap<&K, &V> = std::collections::BTreeMap::new();
    for entry in &other_entries {
        other_map.insert(&entry.key, &entry.value);
    }

    // Find additions and modifications
    for (key, new_value) in &other_map {
        match base_map.get(key) {
            Some(old_value) => {
                if old_value != new_value {
                    changes.push(KeyValueChange::modify(
                        (*key).clone(),
                        (*old_value).clone(),
                        (*new_value).clone(),
                    ));
                }
            }
            None => {
                changes.push(KeyValueChange::add((*key).clone(), (*new_value).clone()));
            }
        }
    }

    // Find removals
    for (key, old_value) in &base_map {
        if !other_map.contains_key(key) {
            changes.push(KeyValueChange::remove((*key).clone(), (*old_value).clone()));
        }
    }

    // Sort by key for deterministic order
    changes.sort_by(|a, b| a.key.cmp(&b.key));

    changes
}

/// Three-way merge of Prolly Trees
/// 
/// Given a base tree and two divergent trees, compute a merged result.
/// Uses Last-Write-Wins for conflicts based on the provided timestamp extractor.
#[allow(dead_code)]
pub fn merge_trees<K, V, F>(
    base: &ProllyNode<K, V>,
    tree_a: &ProllyNode<K, V>,
    tree_b: &ProllyNode<K, V>,
    resolve_conflict: F,
) -> ProllyNode<K, V>
where
    K: Clone + Ord + Eq,
    V: Clone + PartialEq,
    F: Fn(&K, &V, &V) -> V,
{
    // Compute diffs from base
    let diff_a = diff_trees(base, tree_a);
    let diff_b = diff_trees(base, tree_b);

    // Start with base state
    let mut result = base.clone();

    // Build a map of changes from A
    let mut a_changes: std::collections::BTreeMap<K, KeyValueChange<K, V>> =
        std::collections::BTreeMap::new();
    for change in diff_a {
        a_changes.insert(change.key.clone(), change);
    }

    // Apply B changes, resolving conflicts with A
    for change_b in diff_b {
        let key = change_b.key.clone();
        
        if let Some(change_a) = a_changes.remove(&key) {
            // Both modified the same key - conflict!
            match (&change_a.change_type, &change_b.change_type) {
                (ChangeType::Modify, ChangeType::Modify) => {
                    // Both modified - use conflict resolver
                    let resolved = resolve_conflict(
                        &key,
                        change_a.new_value.as_ref().unwrap(),
                        change_b.new_value.as_ref().unwrap(),
                    );
                    result.insert(key, resolved);
                }
                (ChangeType::Remove, ChangeType::Modify) => {
                    // A removed, B modified - B wins (modification takes precedence)
                    result.insert(key, change_b.new_value.unwrap());
                }
                (ChangeType::Modify, ChangeType::Remove) => {
                    // A modified, B removed - A wins (modification takes precedence)
                    result.insert(key, change_a.new_value.unwrap());
                }
                (ChangeType::Add, ChangeType::Add) => {
                    // Both added - use conflict resolver
                    let resolved = resolve_conflict(
                        &key,
                        change_a.new_value.as_ref().unwrap(),
                        change_b.new_value.as_ref().unwrap(),
                    );
                    result.insert(key, resolved);
                }
                _ => {
                    // Other combinations - apply B's change
                    apply_change(&mut result, change_b);
                }
            }
        } else {
            // No conflict - apply B's change
            apply_change(&mut result, change_b);
        }
    }

    // Apply remaining A changes (no conflicts)
    for (_, change) in a_changes {
        apply_change(&mut result, change);
    }

    result
}

/// Apply a change to a node
#[allow(dead_code)]
fn apply_change<K, V>(node: &mut ProllyNode<K, V>, change: KeyValueChange<K, V>)
where
    K: Clone + Ord,
    V: Clone,
{
    match change.change_type {
        ChangeType::Add | ChangeType::Modify => {
            if let Some(value) = change.new_value {
                node.insert(change.key, value);
            }
        }
        ChangeType::Remove => {
            node.remove(&change.key);
        }
    }
}

/// Last-Write-Wins resolver using timestamps
#[allow(dead_code)]
pub fn lww_resolver<V, F>(timestamp_fn: F) -> impl Fn(&str, &V, &V) -> V
where
    V: Clone,
    F: Fn(&V) -> i64,
{
    move |_key, a, b| {
        if timestamp_fn(a) >= timestamp_fn(b) {
            a.clone()
        } else {
            b.clone()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prolly::NodeEntry;

    #[test]
    fn test_diff_empty_trees() {
        let tree1: ProllyNode<String, i32> = ProllyNode::new_leaf();
        let tree2: ProllyNode<String, i32> = ProllyNode::new_leaf();
        
        let diff = diff_trees(&tree1, &tree2);
        assert!(diff.is_empty());
    }

    #[test]
    fn test_diff_additions() {
        let tree1: ProllyNode<String, i32> = ProllyNode::new_leaf();
        let tree2 = ProllyNode::leaf_with_entries(vec![
            NodeEntry::new("a".to_string(), 1),
            NodeEntry::new("b".to_string(), 2),
        ]);
        
        let diff = diff_trees(&tree1, &tree2);
        assert_eq!(diff.len(), 2);
        assert_eq!(diff[0].change_type, ChangeType::Add);
        assert_eq!(diff[1].change_type, ChangeType::Add);
    }

    #[test]
    fn test_diff_removals() {
        let tree1 = ProllyNode::leaf_with_entries(vec![
            NodeEntry::new("a".to_string(), 1),
        ]);
        let tree2: ProllyNode<String, i32> = ProllyNode::new_leaf();
        
        let diff = diff_trees(&tree1, &tree2);
        assert_eq!(diff.len(), 1);
        assert_eq!(diff[0].change_type, ChangeType::Remove);
    }

    #[test]
    fn test_diff_modifications() {
        let tree1 = ProllyNode::leaf_with_entries(vec![
            NodeEntry::new("a".to_string(), 1),
        ]);
        let tree2 = ProllyNode::leaf_with_entries(vec![
            NodeEntry::new("a".to_string(), 2),
        ]);
        
        let diff = diff_trees(&tree1, &tree2);
        assert_eq!(diff.len(), 1);
        assert_eq!(diff[0].change_type, ChangeType::Modify);
        assert_eq!(diff[0].old_value, Some(1));
        assert_eq!(diff[0].new_value, Some(2));
    }

    #[test]
    fn test_three_way_merge() {
        let base = ProllyNode::leaf_with_entries(vec![
            NodeEntry::new("a".to_string(), 1),
            NodeEntry::new("b".to_string(), 2),
        ]);

        let mut tree_a = base.clone();
        tree_a.insert("a".to_string(), 10); // Modify a
        tree_a.insert("c".to_string(), 3);  // Add c

        let mut tree_b = base.clone();
        tree_b.insert("b".to_string(), 20); // Modify b
        tree_b.insert("d".to_string(), 4);  // Add d

        let merged = merge_trees(&base, &tree_a, &tree_b, |_, a, _b| a.clone());

        assert_eq!(merged.get(&"a".to_string()), Some(&10));
        assert_eq!(merged.get(&"b".to_string()), Some(&20));
        assert_eq!(merged.get(&"c".to_string()), Some(&3));
        assert_eq!(merged.get(&"d".to_string()), Some(&4));
    }
}
