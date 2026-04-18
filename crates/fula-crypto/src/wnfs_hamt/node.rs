// Vendored and stripped from rs-wnfs/wnfs-hamt/src/node.rs (Apache-2.0). See NOTICE.
//
// CBOR/IPLD serialization (`serde_ipld_dagcbor`, `Cid`, `Storable`) has been
// replaced with postcard wire types and the fula-native `HamtNodeStore` seam.
// `BitArray` was replaced with a `u16` bitmask — the operations we use are all
// basic bit math and `u16` needs no external crate.
//
// Diff / merge / get_node_at / get_by_hash / remove_by_hash are deferred to
// phase 2; only the set/get/remove/flat_map/store/load set is included here.

use super::constants::{HAMT_BITMASK_BIT_SIZE, HAMT_VALUES_BUCKET_SIZE};
use super::hash_nibbles::HashNibbles;
use super::pointer::{ChildPtr, Pair, Pointer, PointerWire};
use super::store::{HamtNodeStore, StorageKey};
use crate::hashing::Hasher;
use crate::{CryptoError, Result};
use async_recursion::async_recursion;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::fmt::{self, Debug, Formatter};
use std::marker::PhantomData;
use std::sync::Arc;

//--------------------------------------------------------------------------------------------------
// Type definitions
//--------------------------------------------------------------------------------------------------

/// In-memory form of a single HAMT tree node.
///
/// `bitmask` encodes which of the 16 slots are occupied; `pointers` holds only
/// the slots marked in the bitmask, in ascending slot order, so that
/// `pointers[get_value_index(bit)]` yields the pointer for a given bit. That
/// invariant is the core of the HAMT's compact on-disk layout.
pub struct Node<K, V, H = crate::hashing::Blake3Hasher>
where
    H: Hasher,
{
    pub(crate) bitmask: u16,
    pub(crate) pointers: Vec<Pointer<K, V, H>>,
    _phantom: PhantomData<H>,
}

/// On-disk (post-encryption) representation of a node. Serialized with
/// postcard for determinism; the hash of these bytes (under the bucket salt)
/// is the node's `StorageKey`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct NodeWire<K, V> {
    pub bitmask: u16,
    pub pointers: Vec<PointerWire<K, V>>,
}

//--------------------------------------------------------------------------------------------------
// Impls: public API
//--------------------------------------------------------------------------------------------------

impl<K, V, H> Node<K, V, H>
where
    K: Clone + AsRef<[u8]> + Serialize + DeserializeOwned + Send + Sync,
    V: Clone + Serialize + DeserializeOwned + Send + Sync,
    H: Hasher + Send + Sync,
{
    /// Insert or update `value` at `key`.
    pub async fn set(
        self: &mut Arc<Self>,
        key: K,
        value: V,
        store: &(impl HamtNodeStore + ?Sized),
    ) -> Result<()> {
        let hash = H::hash(&key);
        self.set_value(&mut HashNibbles::new(&hash), key, value, store)
            .await
    }

    /// Fetch the value at `key`, descending into stored subtrees on demand.
    pub async fn get(
        &self,
        key: &K,
        store: &(impl HamtNodeStore + ?Sized),
    ) -> Result<Option<V>> {
        let hash = H::hash(key);
        Ok(self
            .get_value(&mut HashNibbles::new(&hash), store)
            .await?
            .map(|pair| pair.value))
    }

    /// Remove the entry at `key` and return its key/value pair if present.
    pub async fn remove(
        self: &mut Arc<Self>,
        key: &K,
        store: &(impl HamtNodeStore + ?Sized),
    ) -> Result<Option<Pair<K, V>>> {
        let hash = H::hash(key);
        self.remove_value(&mut HashNibbles::new(&hash), store).await
    }

    /// True iff no slots are occupied at this level (does not traverse into
    /// children — callers asking about the whole tree want `count_values` or
    /// `flat_map`).
    pub fn is_empty(&self) -> bool {
        self.bitmask == 0
    }

    /// Count the pairs stored directly in this node's `Values` buckets.
    /// Returns an error if any pointer is a `Link`, because the caller would
    /// have to recurse (and the recursive count lives on `flat_map`).
    pub fn count_values(&self) -> Result<usize> {
        let mut len = 0;
        for p in &self.pointers {
            match p {
                Pointer::Values(values) => len += values.len(),
                Pointer::Link(_) => {
                    return Err(CryptoError::Hamt(
                        "count_values reached a Link pointer".into(),
                    ));
                }
            }
        }
        Ok(len)
    }

    /// Compute the index into `pointers` corresponding to a bitmask bit. Only
    /// defined when the bit is set; the caller is expected to check
    /// `bitmask & (1 << bit) != 0` first.
    pub(crate) fn get_value_index(&self, bit_index: usize) -> usize {
        debug_assert!(bit_index < HAMT_BITMASK_BIT_SIZE);
        let lower_mask = if bit_index == 0 {
            0
        } else {
            (1u16 << bit_index) - 1
        };
        (self.bitmask & lower_mask).count_ones() as usize
    }

    //----------------------------------------------------------------------------------------------
    // Persistence
    //----------------------------------------------------------------------------------------------

    /// Serialize this node (recursively persisting any in-memory children)
    /// and write the resulting plaintext bytes to the store. Returns the
    /// content-addressed key the store assigned.
    #[cfg_attr(not(target_arch = "wasm32"), async_recursion)]
    #[cfg_attr(target_arch = "wasm32", async_recursion(?Send))]
    pub async fn store(&self, store: &(impl HamtNodeStore + ?Sized)) -> Result<StorageKey> {
        let mut wire_pointers = Vec::with_capacity(self.pointers.len());
        for p in &self.pointers {
            wire_pointers.push(p.to_wire(store).await?);
        }
        let wire = NodeWire {
            bitmask: self.bitmask,
            pointers: wire_pointers,
        };
        let bytes = postcard::to_allocvec(&wire)
            .map_err(|e| CryptoError::Serialization(format!("encode hamt node: {e}")))?;
        store.put_node(bytes).await
    }

    //----------------------------------------------------------------------------------------------
    // Iteration
    //----------------------------------------------------------------------------------------------

    /// Visit every leaf `Pair` in the subtree, applying `f` and collecting
    /// results. Stored children are fetched on demand.
    #[cfg_attr(not(target_arch = "wasm32"), async_recursion)]
    #[cfg_attr(target_arch = "wasm32", async_recursion(?Send))]
    pub async fn flat_map<F, T>(
        &self,
        f: &F,
        store: &(impl HamtNodeStore + ?Sized),
    ) -> Result<Vec<T>>
    where
        F: Fn(&Pair<K, V>) -> Result<T> + Send + Sync,
        T: Send,
    {
        let mut out = Vec::new();
        for p in &self.pointers {
            match p {
                Pointer::Values(values) => {
                    for pair in values {
                        out.push(f(pair)?);
                    }
                }
                Pointer::Link(child_ptr) => {
                    let child = child_ptr.resolve_owned(store).await?;
                    out.extend(child.flat_map(f, store).await?);
                }
            }
        }
        Ok(out)
    }

    //----------------------------------------------------------------------------------------------
    // Core recursive operations
    //----------------------------------------------------------------------------------------------

    /// Set a value at the path described by `hashnibbles`. Takes
    /// `&mut Arc<Self>` so copy-on-write can reuse the existing Arc when
    /// possible and clone the node only when shared.
    pub fn set_value<'a>(
        self: &'a mut Arc<Self>,
        hashnibbles: &'a mut HashNibbles<'_>,
        key: K,
        value: V,
        store: &'a (impl HamtNodeStore + ?Sized),
    ) -> AsyncBoxFut<'a, Result<()>>
    where
        K: 'a,
        V: 'a,
    {
        Box::pin(async move {
            let bit_index = hashnibbles.try_next()?;
            let bit = 1u16 << bit_index;
            let value_index = self.get_value_index(bit_index);

            // Copy-on-write: promote to uniquely-owned if shared, then mutate.
            let node = Arc::make_mut(self);

            // Slot was empty: drop a fresh single-pair bucket into it.
            if node.bitmask & bit == 0 {
                node.pointers
                    .insert(value_index, Pointer::Values(vec![Pair { key, value }]));
                node.bitmask |= bit;
                return Ok(());
            }

            match &mut node.pointers[value_index] {
                Pointer::Values(values) => {
                    // Existing bucket at this slot — either update in place,
                    // append, or split once the bucket is full.
                    if let Some(i) = values
                        .iter()
                        .position(|p| &H::hash(&p.key) == hashnibbles.digest)
                    {
                        values[i] = Pair::new(key, value);
                    } else if values.len() < HAMT_VALUES_BUCKET_SIZE {
                        // Keep the bucket sorted by key-hash so the on-disk
                        // shape is insertion-order independent.
                        let insert_at = values
                            .iter()
                            .position(|p| H::hash(&p.key) > *hashnibbles.digest)
                            .unwrap_or(values.len());
                        values.insert(insert_at, Pair::new(key, value));
                    } else {
                        // Bucket is full — split into a subtree at the next
                        // level of the trie.
                        let cursor = hashnibbles.get_cursor();
                        let taken = std::mem::take(values);
                        let mut sub_node: Arc<Node<K, V, H>> =
                            Arc::new(Node::<K, V, H>::default());
                        for Pair { key: k, value: v } in
                            taken.into_iter().chain(Some(Pair::new(key, value)))
                        {
                            let h = H::hash(&k);
                            let mut sub_nibbles = HashNibbles::with_cursor(&h, cursor);
                            // Recurse into the fresh sub-node to place each
                            // evicted pair at its next-nibble slot.
                            Node::<K, V, H>::set_value(
                                &mut sub_node,
                                &mut sub_nibbles,
                                k,
                                v,
                                store,
                            )
                            .await?;
                        }
                        node.pointers[value_index] =
                            Pointer::Link(ChildPtr::InMemory(sub_node));
                    }
                }
                Pointer::Link(child_ptr) => {
                    // Descend into the existing subtree, mutate a local copy,
                    // and re-attach as an in-memory link (the previous stored
                    // copy, if any, becomes garbage that's collected later).
                    let mut child = child_ptr.resolve_owned(store).await?;
                    Node::<K, V, H>::set_value(&mut child, hashnibbles, key, value, store).await?;
                    node.pointers[value_index] = Pointer::Link(ChildPtr::InMemory(child));
                }
            }

            Ok(())
        })
    }

    /// Walk down to the leaf for `hashnibbles` and return a clone of the
    /// matching pair, if any. Reads only; never persists.
    #[cfg_attr(not(target_arch = "wasm32"), async_recursion)]
    #[cfg_attr(target_arch = "wasm32", async_recursion(?Send))]
    pub async fn get_value(
        &self,
        hashnibbles: &mut HashNibbles,
        store: &(impl HamtNodeStore + ?Sized),
    ) -> Result<Option<Pair<K, V>>> {
        let bit_index = hashnibbles.try_next()?;
        let bit = 1u16 << bit_index;

        if self.bitmask & bit == 0 {
            return Ok(None);
        }

        let value_index = self.get_value_index(bit_index);
        match &self.pointers[value_index] {
            Pointer::Values(values) => Ok(values
                .iter()
                .find(|p| &H::hash(&p.key) == hashnibbles.digest)
                .cloned()),
            Pointer::Link(child_ptr) => {
                let child = child_ptr.resolve_owned(store).await?;
                child.get_value(hashnibbles, store).await
            }
        }
    }

    /// Remove a value and, when the resulting subtree is small enough, fold
    /// it back up into a `Values` bucket at the parent. The
    /// `canonicalize`-on-shrink step is what keeps the tree's final shape
    /// insertion-order independent.
    pub fn remove_value<'a>(
        self: &'a mut Arc<Self>,
        hashnibbles: &'a mut HashNibbles<'_>,
        store: &'a (impl HamtNodeStore + ?Sized),
    ) -> AsyncBoxFut<'a, Result<Option<Pair<K, V>>>>
    where
        K: 'a,
        V: 'a,
    {
        Box::pin(async move {
            let bit_index = hashnibbles.try_next()?;
            let bit = 1u16 << bit_index;

            if self.bitmask & bit == 0 {
                return Ok(None);
            }

            let value_index = self.get_value_index(bit_index);
            let node = Arc::make_mut(self);

            let removed = match &mut node.pointers[value_index] {
                Pointer::Values(values) if values.len() == 1 => {
                    // Last entry in the bucket — drop the whole slot.
                    if &H::hash(&values[0].key) != hashnibbles.digest {
                        None
                    } else {
                        node.bitmask &= !bit;
                        match node.pointers.remove(value_index) {
                            Pointer::Values(mut v) => Some(v.pop().unwrap()),
                            _ => unreachable!(),
                        }
                    }
                }
                Pointer::Values(values) => match values
                    .iter()
                    .position(|p| &H::hash(&p.key) == hashnibbles.digest)
                {
                    Some(i) => Some(values.remove(i)),
                    None => None,
                },
                Pointer::Link(child_ptr) => {
                    let mut child = child_ptr.resolve_owned(store).await?;
                    let removed =
                        Node::<K, V, H>::remove_value(&mut child, hashnibbles, store).await?;
                    if removed.is_some() {
                        match Pointer::Link(ChildPtr::InMemory(child))
                            .canonicalize(store)
                            .await?
                        {
                            Some(canonical) => {
                                node.pointers[value_index] = canonical;
                            }
                            None => {
                                // Subtree collapsed to empty — drop this slot.
                                node.bitmask &= !bit;
                                node.pointers.remove(value_index);
                            }
                        }
                    } else {
                        node.pointers[value_index] = Pointer::Link(ChildPtr::InMemory(child));
                    }
                    removed
                }
            };
            Ok(removed)
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Impls: persistence — callable without the `AsRef<[u8]>` bound on K so that
// `ChildPtr::resolve_owned` (which has no such bound) can round-trip bytes.
//--------------------------------------------------------------------------------------------------

impl<K, V, H> Node<K, V, H>
where
    K: Clone + Serialize + DeserializeOwned + Send + Sync,
    V: Clone + Serialize + DeserializeOwned + Send + Sync,
    H: Hasher + Send + Sync,
{
    /// Fetch and decode the node at `key`. Children remain as `Stored`
    /// references and are not pre-fetched — resolution is lazy per access.
    pub async fn load(
        key: &StorageKey,
        store: &(impl HamtNodeStore + ?Sized),
    ) -> Result<Self> {
        let bytes = store.get_node(key).await?;
        let wire: NodeWire<K, V> = postcard::from_bytes(&bytes)
            .map_err(|e| CryptoError::Serialization(format!("decode hamt node: {e}")))?;
        Ok(Self::from_wire(wire))
    }

    fn from_wire(wire: NodeWire<K, V>) -> Self {
        let pointers = wire
            .pointers
            .into_iter()
            .map(Pointer::from_wire)
            .collect();
        Self {
            bitmask: wire.bitmask,
            pointers,
            _phantom: PhantomData,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// BoxFuture alias — Send on native, !Send on wasm32, matching wnfs's CondSync pattern.
//--------------------------------------------------------------------------------------------------

#[cfg(not(target_arch = "wasm32"))]
pub(crate) type AsyncBoxFut<'a, T> = futures::future::BoxFuture<'a, T>;

#[cfg(target_arch = "wasm32")]
pub(crate) type AsyncBoxFut<'a, T> = futures::future::LocalBoxFuture<'a, T>;

//--------------------------------------------------------------------------------------------------
// Trait impls
//--------------------------------------------------------------------------------------------------

impl<K: Clone, V: Clone, H: Hasher> Clone for Node<K, V, H> {
    fn clone(&self) -> Self {
        Self {
            bitmask: self.bitmask,
            pointers: self.pointers.clone(),
            _phantom: PhantomData,
        }
    }
}

impl<K, V, H: Hasher> Default for Node<K, V, H> {
    fn default() -> Self {
        Self {
            bitmask: 0,
            pointers: Vec::with_capacity(HAMT_BITMASK_BIT_SIZE),
            _phantom: PhantomData,
        }
    }
}

impl<K: PartialEq, V: PartialEq, H: Hasher> PartialEq for Node<K, V, H> {
    fn eq(&self, other: &Self) -> bool {
        self.bitmask == other.bitmask && self.pointers == other.pointers
    }
}

impl<K: Debug, V: Debug, H: Hasher> Debug for Node<K, V, H> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Node")
            .field("bitmask", &format!("{:016b}", self.bitmask))
            .field("pointers", &self.pointers)
            .finish()
    }
}

//--------------------------------------------------------------------------------------------------
// Tests — behavioural round-trips against an in-memory store that skips
// encryption. These guard the tree-logic edits (direct recursion across
// `Box::pin(async move)` with elided inner lifetimes on `HashNibbles`) made
// while vendoring; compilation alone doesn't prove they're sound.
//--------------------------------------------------------------------------------------------------

#[cfg(all(test, not(target_arch = "wasm32")))]
mod round_trip_tests {
    use super::*;
    use super::super::store::{HamtNodeBytes, HamtNodeStore, STORAGE_KEY_LEN};
    use crate::hashing::Blake3Hasher;
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// In-memory `HamtNodeStore` that skips encryption. Content-addresses by
    /// `BLAKE3(bytes)[..22]` and re-hashes on read so any tampered entry
    /// surfaces as a test failure rather than silently corrupting the tree.
    struct InMemoryStore {
        blobs: Mutex<HashMap<StorageKey, Vec<u8>>>,
    }

    impl InMemoryStore {
        fn new() -> Self {
            Self {
                blobs: Mutex::new(HashMap::new()),
            }
        }

        fn compute_key(bytes: &[u8]) -> StorageKey {
            let h = blake3::hash(bytes);
            let mut k = [0u8; STORAGE_KEY_LEN];
            k.copy_from_slice(&h.as_bytes()[..STORAGE_KEY_LEN]);
            k
        }
    }

    #[async_trait::async_trait]
    impl HamtNodeStore for InMemoryStore {
        async fn get_node(&self, key: &StorageKey) -> Result<HamtNodeBytes> {
            let bytes = {
                let blobs = self.blobs.lock().unwrap();
                blobs
                    .get(key)
                    .ok_or_else(|| {
                        CryptoError::Hamt(format!("missing node: {}", hex::encode(key)))
                    })?
                    .clone()
            };
            let recomputed = Self::compute_key(&bytes);
            if &recomputed != key {
                return Err(CryptoError::Hamt("content-address mismatch".into()));
            }
            Ok(bytes)
        }

        async fn put_node(&self, bytes: HamtNodeBytes) -> Result<StorageKey> {
            let k = Self::compute_key(&bytes);
            self.blobs.lock().unwrap().insert(k, bytes);
            Ok(k)
        }
    }

    type TestNode = Node<Vec<u8>, u64, Blake3Hasher>;

    /// Insert, lookup, store/load round-trip, then remove — verifies the
    /// full lifecycle including the split + canonicalize paths that never
    /// executed during `hash_nibbles`-only testing. 40 entries across 16
    /// top-level nibble slots forces several slots past
    /// `HAMT_VALUES_BUCKET_SIZE = 3` and triggers subtree splits.
    #[tokio::test]
    async fn round_trip_insert_get_store_load_remove() {
        let store = InMemoryStore::new();
        let mut root: Arc<TestNode> = Arc::new(TestNode::default());

        let pairs: Vec<(Vec<u8>, u64)> = (0u64..40)
            .map(|i| (format!("key-{:03}", i).into_bytes(), i * 10))
            .collect();

        for (k, v) in &pairs {
            root.set(k.clone(), *v, &store).await.unwrap();
        }

        for (k, v) in &pairs {
            let got = root.get(k, &store).await.unwrap();
            assert_eq!(got, Some(*v), "lookup mismatch for {:?}", k);
        }

        let missing = root.get(&b"not-a-key".to_vec(), &store).await.unwrap();
        assert_eq!(missing, None);

        // Persist the whole tree, reload from bytes, re-verify every lookup.
        let root_key = root.store(&store).await.unwrap();
        let loaded: TestNode = TestNode::load(&root_key, &store).await.unwrap();
        for (k, v) in &pairs {
            let got = loaded.get(k, &store).await.unwrap();
            assert_eq!(got, Some(*v), "post-load lookup mismatch for {:?}", k);
        }

        for (k, v) in &pairs {
            let removed = root.remove(k, &store).await.unwrap();
            assert_eq!(
                removed.map(|p| p.value),
                Some(*v),
                "remove mismatch for {:?}",
                k
            );
        }
        assert!(root.is_empty(), "root should be empty after all removes");
    }

    /// Second `set` with the same key must overwrite, not create a duplicate
    /// bucket entry.
    #[tokio::test]
    async fn overwrite_existing_key() {
        let store = InMemoryStore::new();
        let mut root: Arc<TestNode> = Arc::new(TestNode::default());

        let k = b"dup-key".to_vec();
        root.set(k.clone(), 1, &store).await.unwrap();
        root.set(k.clone(), 2, &store).await.unwrap();

        assert_eq!(root.get(&k, &store).await.unwrap(), Some(2));

        let removed = root.remove(&k, &store).await.unwrap();
        assert_eq!(removed.map(|p| p.value), Some(2));
        assert!(root.is_empty());
    }

    /// Remove of a never-inserted key returns `None` and leaves the tree
    /// structurally unchanged.
    #[tokio::test]
    async fn remove_missing_key_is_noop() {
        let store = InMemoryStore::new();
        let mut root: Arc<TestNode> = Arc::new(TestNode::default());

        root.set(b"present".to_vec(), 7, &store).await.unwrap();
        let got = root.remove(&b"absent".to_vec(), &store).await.unwrap();
        assert!(got.is_none());
        assert_eq!(root.get(&b"present".to_vec(), &store).await.unwrap(), Some(7));
    }
}
