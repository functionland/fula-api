// Fula-native HAMT adapted from rs-wnfs/wnfs-hamt (Apache-2.0). See NOTICE.
//
// This module vendors only the tree-logic portions of wnfs-hamt. Node blobs
// are persisted through the fula-native `HamtNodeStore` seam (AEAD-encrypted
// outside this module), not through wnfs-common's `BlockStore`. Wire format
// is postcard, not CBOR/IPLD, and children are addressed by a 22-byte
// `StorageKey` rather than a `Cid`.

pub(crate) mod constants;
pub(crate) mod hash_nibbles;
pub(crate) mod node;
pub(crate) mod pointer;
pub(crate) mod store;
pub mod v7_store;

pub(crate) use node::Node;
pub(crate) use pointer::{ChildPtr, Pair, Pointer};
pub(crate) use store::{HamtNodeBytes, HamtNodeStore, STORAGE_KEY_LEN, StorageKey};
pub use v7_store::{BlobBackend, V7NodeStore, V7_NODE_PREFIX};
