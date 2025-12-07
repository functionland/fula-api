//! Prolly Tree implementation for bucket indexing
//!
//! Prolly Trees (Probabilistic B-Trees) combine properties of B-Trees and Merkle Trees:
//! - Content-defined boundaries for structural sharing
//! - O(log n) lookups, inserts, and deletes
//! - Efficient diff and merge operations
//! - Verifiable via Merkle proofs

mod node;
mod tree;
mod hash;
mod diff;

pub use node::{ProllyNode, NodeEntry, Pointer};
pub use tree::{ProllyTree, ProllyConfig};
pub use hash::{HashNibbles, HashPrefix, BoundaryHasher};
pub use diff::{KeyValueChange, ChangeType, diff_trees};

/// Default branching factor (average entries per node)
pub const DEFAULT_BRANCHING_FACTOR: usize = 32;

/// Default boundary pattern bits
pub const DEFAULT_BOUNDARY_BITS: u8 = 5;

/// Maximum node size in bytes
pub const MAX_NODE_SIZE: usize = 4096;
