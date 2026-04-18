// Vendored and stripped from rs-wnfs/wnfs-hamt/src/pointer.rs (Apache-2.0). See NOTICE.
//
// `BlockStore + Cid + Storable` have been replaced with the fula-native
// `HamtNodeStore + StorageKey` seam, and CBOR/IPLD serialization has been
// replaced with postcard wire types (`PointerWire`).

use super::constants::HAMT_VALUES_BUCKET_SIZE;
use super::node::Node;
use super::store::{HamtNodeStore, StorageKey};
use crate::hashing::Hasher;
use crate::{CryptoError, Result};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::fmt::Debug;
use std::sync::Arc;

//--------------------------------------------------------------------------------------------------
// In-memory types
//--------------------------------------------------------------------------------------------------

/// A key/value pair held in a `Pointer::Values` bucket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pair<K, V> {
    pub key: K,
    pub value: V,
}

impl<K, V> Pair<K, V> {
    pub fn new(key: K, value: V) -> Self {
        Self { key, value }
    }
}

/// A link from a parent HAMT node to a child node.
///
/// `InMemory` holds an unpersisted subtree — a child produced by recent
/// mutations that hasn't been written to the store yet. `Stored` holds a
/// content-addressed pointer into the backing store; the child is fetched
/// and decoded on demand via `resolve_owned`.
///
/// This mirrors wnfs-common's `Link<Arc<T>>` split but is content-addressed
/// by a fula `StorageKey` rather than a libipld `Cid`.
pub enum ChildPtr<K, V, H>
where
    H: Hasher,
{
    InMemory(Arc<Node<K, V, H>>),
    Stored(StorageKey),
}

/// Each bit in the bitmask of a HAMT node maps to one `Pointer`. A `Pointer`
/// is either a flat bucket of key/value `Pair`s or a link to a child node.
pub enum Pointer<K, V, H>
where
    H: Hasher,
{
    Values(Vec<Pair<K, V>>),
    Link(ChildPtr<K, V, H>),
}

//--------------------------------------------------------------------------------------------------
// Wire format
//--------------------------------------------------------------------------------------------------

/// On-disk (post-encryption) representation of a `Pointer`. Encoded via
/// postcard for deterministic, compact output so plaintext content-addressing
/// produces stable `StorageKey`s across re-encodes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum PointerWire<K, V> {
    Values(Vec<(K, V)>),
    Link(StorageKey),
}

//--------------------------------------------------------------------------------------------------
// Impls
//--------------------------------------------------------------------------------------------------

impl<K, V, H> ChildPtr<K, V, H>
where
    K: Clone + Serialize + DeserializeOwned + Send + Sync,
    V: Clone + Serialize + DeserializeOwned + Send + Sync,
    H: Hasher + Send + Sync,
{
    /// Resolve the child node, loading and decoding it from the store when
    /// the link is a `Stored` reference. The returned `Arc` is shared with
    /// the in-memory form when already resident.
    pub async fn resolve_owned(
        &self,
        store: &(impl HamtNodeStore + ?Sized),
    ) -> Result<Arc<Node<K, V, H>>> {
        match self {
            ChildPtr::InMemory(n) => Ok(Arc::clone(n)),
            ChildPtr::Stored(key) => {
                let node = Node::<K, V, H>::load(key, store).await?;
                Ok(Arc::new(node))
            }
        }
    }
}

impl<K, V, H> Pointer<K, V, H>
where
    K: Clone + AsRef<[u8]> + Serialize + DeserializeOwned + Send + Sync,
    V: Clone + Serialize + DeserializeOwned + Send + Sync,
    H: Hasher + Send + Sync,
{
    /// Collapse a `Link` subtree back into a flat `Values` bucket when
    /// possible, so that two trees reached via different edit orders have
    /// the same shape — the history-independence invariant that keeps
    /// content-addressing deterministic.
    ///
    /// Only meaningful for a `Link` pointer; calling on `Values` is a bug.
    pub async fn canonicalize(
        self,
        store: &(impl HamtNodeStore + ?Sized),
    ) -> Result<Option<Self>> {
        match self {
            Pointer::Link(child_ptr) => {
                let node = child_ptr.resolve_owned(store).await?;
                match node.pointers.len() {
                    0 => Ok(None),
                    1 if matches!(node.pointers[0], Pointer::Values(_)) => {
                        Ok(Some(node.pointers[0].clone()))
                    }
                    2..=HAMT_VALUES_BUCKET_SIZE if node.count_values().is_ok() => {
                        let mut values: Vec<Pair<K, V>> = node
                            .pointers
                            .iter()
                            .filter_map(|p| match p {
                                Pointer::Values(values) => Some(values.clone()),
                                _ => None,
                            })
                            .flatten()
                            .collect();

                        if values.len() > HAMT_VALUES_BUCKET_SIZE {
                            return Ok(Some(Pointer::Link(ChildPtr::InMemory(node))));
                        }

                        values.sort_unstable_by(|a, b| H::hash(&a.key).cmp(&H::hash(&b.key)));
                        Ok(Some(Pointer::Values(values)))
                    }
                    _ => Ok(Some(Pointer::Link(ChildPtr::InMemory(node)))),
                }
            }
            Pointer::Values(_) => Err(CryptoError::Hamt(
                "canonicalize called on a Values pointer".into(),
            )),
        }
    }

    /// Serialize this pointer to its on-disk form. Child subtrees that are
    /// `InMemory` are recursively persisted first so their `StorageKey`s can
    /// be embedded in the parent's wire form.
    pub async fn to_wire(
        &self,
        store: &(impl HamtNodeStore + ?Sized),
    ) -> Result<PointerWire<K, V>> {
        match self {
            Pointer::Values(pairs) => {
                let pairs = pairs
                    .iter()
                    .map(|p| (p.key.clone(), p.value.clone()))
                    .collect();
                Ok(PointerWire::Values(pairs))
            }
            Pointer::Link(ChildPtr::Stored(key)) => Ok(PointerWire::Link(*key)),
            Pointer::Link(ChildPtr::InMemory(child)) => {
                let key = child.store(store).await?;
                Ok(PointerWire::Link(key))
            }
        }
    }

}

// `from_wire` lives in a looser impl so `Node::load` (which also drops the
// `AsRef<[u8]>` bound) can decode a pointer without forcing the bound on K.
impl<K, V, H> Pointer<K, V, H>
where
    H: Hasher,
{
    /// Inverse of `to_wire`. Never triggers a store access: `Link` children
    /// stay as `Stored` references and are resolved on demand during
    /// traversal.
    pub fn from_wire(wire: PointerWire<K, V>) -> Self {
        match wire {
            PointerWire::Values(kvs) => Pointer::Values(
                kvs.into_iter()
                    .map(|(key, value)| Pair { key, value })
                    .collect(),
            ),
            PointerWire::Link(key) => Pointer::Link(ChildPtr::Stored(key)),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait impls — trivial derives re-written because of the generic bound on H
//--------------------------------------------------------------------------------------------------

impl<K: Clone, V: Clone, H: Hasher> Clone for ChildPtr<K, V, H> {
    fn clone(&self) -> Self {
        match self {
            ChildPtr::InMemory(n) => ChildPtr::InMemory(Arc::clone(n)),
            ChildPtr::Stored(k) => ChildPtr::Stored(*k),
        }
    }
}

impl<K: Clone, V: Clone, H: Hasher> Clone for Pointer<K, V, H> {
    fn clone(&self) -> Self {
        match self {
            Pointer::Values(v) => Pointer::Values(v.clone()),
            Pointer::Link(l) => Pointer::Link(l.clone()),
        }
    }
}

impl<K: Debug, V: Debug, H: Hasher> Debug for ChildPtr<K, V, H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChildPtr::InMemory(n) => f.debug_tuple("InMemory").field(n).finish(),
            ChildPtr::Stored(k) => f.debug_tuple("Stored").field(&hex::encode(k)).finish(),
        }
    }
}

impl<K: Debug, V: Debug, H: Hasher> Debug for Pointer<K, V, H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Pointer::Values(v) => f.debug_tuple("Values").field(v).finish(),
            Pointer::Link(l) => f.debug_tuple("Link").field(l).finish(),
        }
    }
}

impl<K: Clone, V: Clone, H: Hasher> Default for Pointer<K, V, H> {
    fn default() -> Self {
        Pointer::Values(Vec::new())
    }
}

impl<K: PartialEq, V: PartialEq, H: Hasher> PartialEq for Pointer<K, V, H> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Pointer::Values(a), Pointer::Values(b)) => a == b,
            // Link equality is only structurally meaningful when both sides are
            // stored; in-memory links can differ bit-for-bit yet represent
            // equivalent subtrees until both are persisted.
            (Pointer::Link(ChildPtr::Stored(a)), Pointer::Link(ChildPtr::Stored(b))) => a == b,
            _ => false,
        }
    }
}
