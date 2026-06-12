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
use super::store::{HamtNodeStore, NodePutResult, StorageKey};
use crate::hashing::Hasher;
use crate::{CryptoError, Result};
use async_recursion::async_recursion;
use cid::Cid;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::fmt::{self, Debug, Formatter};
use std::marker::PhantomData;
use std::sync::Arc;

/// Cap on concurrent sibling fetches during `flat_map` traversal. HAMT
/// fan-out is up to 16 per node (bitmask is `u16`), so this cap fully
/// covers a single level without over-subscribing I/O. Recursion still
/// happens inside each branch; worst-case in-flight futures compound as
/// `cap^depth`, but HAMT depth is logarithmic in entries per shard
/// (~log_16), which keeps peak memory bounded in practice.
const FLAT_MAP_SIBLING_CONCURRENCY: usize = 16;

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
    /// content-addressed key the store assigned, alongside an optional
    /// CID hint (W.9.2): `Some(_)` when the underlying `BlobBackend`
    /// returned one in `BlobPutResult.cid` (e.g. master S3's `ETag`),
    /// `None` for in-memory backends or when the etag failed to parse.
    #[cfg_attr(not(target_arch = "wasm32"), async_recursion)]
    #[cfg_attr(target_arch = "wasm32", async_recursion(?Send))]
    pub async fn store(&self, store: &(impl HamtNodeStore + ?Sized)) -> Result<NodePutResult> {
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

    /// Issue #34 — like [`store`](Self::store), but with WRITE-BACK: every
    /// `InMemory` child that persists successfully is downgraded in place
    /// to `ChildPtr::Sealed { storage_key, cid, node }`, so the NEXT store
    /// of this tree emits the recorded reference instead of re-uploading
    /// the unchanged subtree.
    ///
    /// Why this exists: `store(&self)` cannot record that a child was
    /// persisted, so in a long-lived session the `InMemory` set grows
    /// monotonically (every mutation path stays "dirty" forever) and every
    /// flush re-serializes, re-encrypts, and re-PUTs the whole ever-touched
    /// tree — O(N²) total upload cost for N sequential single-file puts
    /// (issue #34). With sealing, a flush PUTs exactly the nodes mutated
    /// since the previous flush plus this root: O(depth) per flush.
    ///
    /// Persisted bytes are IDENTICAL to `store`'s: a sealed child re-emits
    /// the same `PointerWire::Link`/`LinkV2` its original PUT produced
    /// (same plaintext → same content-addressed storage_key), so readers —
    /// including pre-#34 SDKs — cannot distinguish the two writers. Pinned
    /// by `issue_34_sealing_and_legacy_store_produce_identical_roots`.
    ///
    /// Error handling: if a child's recursive store fails, that child is
    /// restored to `InMemory` and the error propagates — the in-memory
    /// tree stays fully intact and a retry re-persists exactly the
    /// still-unsealed remainder. Children that already sealed earlier in
    /// the walk keep their seal (their PUTs succeeded; the references are
    /// durable and content-addressed).
    ///
    /// Takes `self: &mut Arc<Self>` (same copy-on-write receiver as
    /// [`set`](Self::set)) because the seal mutates pointers in place;
    /// recursion is hand-boxed like `set_value` since `async_recursion`
    /// and arbitrary-self receivers don't mix.
    pub fn store_sealing<'a>(
        self: &'a mut Arc<Self>,
        store: &'a (impl HamtNodeStore + ?Sized),
    ) -> AsyncBoxFut<'a, Result<NodePutResult>>
    where
        K: 'a,
        V: 'a,
    {
        Box::pin(async move {
            let node = Arc::make_mut(self);
            let mut wire_pointers = Vec::with_capacity(node.pointers.len());
            for p in node.pointers.iter_mut() {
                let wire = match p {
                    Pointer::Values(pairs) => PointerWire::Values(
                        pairs
                            .iter()
                            .map(|pr| (pr.key.clone(), pr.value.clone()))
                            .collect(),
                    ),
                    Pointer::Link(ChildPtr::Stored(key)) => PointerWire::Link(*key),
                    Pointer::Link(ChildPtr::StoredV2 { storage_key, cid }) => {
                        PointerWire::LinkV2 {
                            storage_key: *storage_key,
                            cid: cid.clone(),
                        }
                    }
                    // Already persisted by a prior sealing pass and not
                    // mutated since (a mutation would have re-attached the
                    // subtree as InMemory): emit the recorded reference,
                    // zero I/O.
                    Pointer::Link(ChildPtr::Sealed { storage_key, cid, .. }) => match cid {
                        Some(cid) => PointerWire::LinkV2 {
                            storage_key: *storage_key,
                            cid: cid.clone(),
                        },
                        None => PointerWire::Link(*storage_key),
                    },
                    Pointer::Link(child @ ChildPtr::InMemory(_)) => {
                        // Take the Arc out so the recursive seal can run
                        // with refcount-preserving `&mut Arc` semantics
                        // (a transient placeholder sits in the slot only
                        // across this block — both exits below overwrite
                        // it before anything else can observe the tree).
                        let taken = std::mem::replace(
                            child,
                            ChildPtr::Stored([0u8; super::store::STORAGE_KEY_LEN]),
                        );
                        let ChildPtr::InMemory(mut child_arc) = taken else {
                            unreachable!("match arm guarantees InMemory");
                        };
                        match Node::<K, V, H>::store_sealing(&mut child_arc, store).await {
                            Ok(result) => {
                                let wire = match result.cid {
                                    Some(ref cid) => PointerWire::LinkV2 {
                                        storage_key: result.storage_key,
                                        cid: cid.clone(),
                                    },
                                    None => PointerWire::Link(result.storage_key),
                                };
                                *child = ChildPtr::Sealed {
                                    storage_key: result.storage_key,
                                    cid: result.cid,
                                    node: child_arc,
                                };
                                wire
                            }
                            Err(e) => {
                                // Restore the child so the in-memory tree
                                // is never left pointing at the
                                // placeholder; the caller can retry the
                                // flush and re-persist what's left.
                                *child = ChildPtr::InMemory(child_arc);
                                return Err(e);
                            }
                        }
                    }
                };
                wire_pointers.push(wire);
            }
            let wire = NodeWire {
                bitmask: node.bitmask,
                pointers: wire_pointers,
            };
            let bytes = postcard::to_allocvec(&wire)
                .map_err(|e| CryptoError::Serialization(format!("encode hamt node: {e}")))?;
            store.put_node(bytes).await
        })
    }

    //----------------------------------------------------------------------------------------------
    // Iteration
    //----------------------------------------------------------------------------------------------

    /// Visit every leaf `Pair` in the subtree, applying `f` and collecting
    /// results. Stored children are fetched on demand.
    ///
    /// Sibling `Pointer::Link` children are resolved concurrently (bounded
    /// by `FLAT_MAP_SIBLING_CONCURRENCY`), since their storage keys are all
    /// already known from the current node's decrypted pointer list. The
    /// down-path chain inside each branch is still serial — that's a
    /// requirement of the AEAD node encryption model (a child's storage
    /// key is only known after its parent is decrypted). Input pointer
    /// order is preserved in the output.
    ///
    /// **Walkable-v8 (W.9.5 / #37) — fetch-order obfuscation.** The
    /// per-pointer future list is shuffled before being passed to
    /// `stream::buffered`, so a network observer watching the offline
    /// gateway-race traffic for a single HAMT node sees an unpredictable
    /// fetch order rather than the bitmask-order that would otherwise
    /// leak intra-node topology. Output ordering is restored by sorting
    /// on the original pointer index after collection — the docstring's
    /// "input pointer order is preserved" contract is unchanged.
    /// The cost is one `Vec::shuffle` per recursion (O(N) where N ≤ 16)
    /// and a sort of the same size; both negligible vs. the network
    /// fetch cost they're being interleaved with.
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
        use futures::stream::{self, StreamExt, TryStreamExt};
        use rand::seq::SliceRandom;
        // Build the per-pointer future list with `std::iter::Iterator::map`
        // (not `StreamExt::map`) so each future's captured lifetimes bind to
        // `self` / `f` / `store` concretely. `StreamExt::map` infers an HRTB
        // that the `async_recursion` macro's rewritten body can't satisfy.
        //
        // W.9.5 / #37: each future carries its `original_idx` in the
        // tuple so we can re-sort post-fetch and preserve the
        // declared output-ordering contract regardless of which fetch
        // order the buffered stream actually drove.
        let mut per_pointer_futs: Vec<_> = self
            .pointers
            .iter()
            .enumerate()
            .map(|(original_idx, p)| async move {
                let v: Vec<T> = match p {
                    Pointer::Values(values) => {
                        values.iter().map(f).collect::<Result<Vec<T>>>()?
                    }
                    Pointer::Link(child_ptr) => {
                        let child = child_ptr.resolve_owned(store).await?;
                        child.flat_map(f, store).await?
                    }
                };
                Ok::<(usize, Vec<T>), crate::error::CryptoError>((original_idx, v))
            })
            .collect();

        // Shuffle the future order so a network observer can't infer
        // pointer-index ↔ fetch-time correlation. `thread_rng` works on
        // wasm32 via the `getrandom/js` feature already enabled in
        // `fula-crypto/Cargo.toml`'s `wasm` feature gate.
        per_pointer_futs.shuffle(&mut rand::thread_rng());

        let mut per_pointer: Vec<(usize, Vec<T>)> = stream::iter(per_pointer_futs)
            .buffered(FLAT_MAP_SIBLING_CONCURRENCY)
            .try_collect()
            .await?;
        // Restore original pointer order to honour the docstring
        // contract. Stable sort over a small (≤ 16-element) Vec is
        // cheap.
        per_pointer.sort_by_key(|(idx, _)| *idx);
        Ok(per_pointer.into_iter().flat_map(|(_, v)| v).collect())
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
    ///
    /// Test-only after W.9.4: production code paths all funnel through
    /// [`load_with_cid_hint`] (which forwards a `None` hint when the
    /// caller's parent pointer was a legacy `Stored` variant). The
    /// unit-test round-trip suites in this module + `v7_store::tests`
    /// still exercise the simpler signature, so it stays available
    /// behind `#[cfg(test)]`.
    #[cfg(test)]
    pub async fn load(
        key: &StorageKey,
        store: &(impl HamtNodeStore + ?Sized),
    ) -> Result<Self> {
        let bytes = store.get_node(key).await?;
        // #81: classify postcard errors — `DeserializeBadEnum` (an
        // unknown variant tag, e.g. v0.5 SDK reading a v0.6
        // walkable-v8 `LinkV2` blob) maps to the typed
        // `CryptoError::WireVersionUnsupported` so operators can
        // filter telemetry on the variant rather than substring-
        // matching the generic `Serialization` error.
        let wire: NodeWire<K, V> = postcard::from_bytes(&bytes)
            .map_err(|e| CryptoError::classify_postcard_decode(e, "decode hamt node"))?;
        Ok(Self::from_wire(wire))
    }

    /// Walkable-v8 (W.9.4) — load with a content-address hint forwarded
    /// to the storage layer. Used by `ChildPtr::resolve_owned` when the
    /// parent's pointer is `PointerWire::LinkV2 { storage_key, cid }`,
    /// so an offline-aware `HamtNodeStore` can fetch via gateway race
    /// when master is unreachable. `cid_hint = None` is byte-identical
    /// to [`load`] — used for the legacy `Stored(StorageKey)` arm
    /// during lazy migration.
    ///
    /// Distinct from `load` so existing callers don't have to thread
    /// `Option<&Cid>` through their stacks; the dispatcher in
    /// `ChildPtr::resolve_owned` is the single load-bearing fan-out.
    pub async fn load_with_cid_hint(
        key: &StorageKey,
        cid_hint: Option<&Cid>,
        store: &(impl HamtNodeStore + ?Sized),
    ) -> Result<Self> {
        let bytes = store.get_node_with_cid_hint(key, cid_hint).await?;
        // #81: classify postcard errors — `DeserializeBadEnum` (an
        // unknown variant tag, e.g. v0.5 SDK reading a v0.6
        // walkable-v8 `LinkV2` blob) maps to the typed
        // `CryptoError::WireVersionUnsupported` so operators can
        // filter telemetry on the variant rather than substring-
        // matching the generic `Serialization` error.
        let wire: NodeWire<K, V> = postcard::from_bytes(&bytes)
            .map_err(|e| CryptoError::classify_postcard_decode(e, "decode hamt node"))?;
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
    use super::super::store::{HamtNodeBytes, HamtNodeStore, NodePutResult, STORAGE_KEY_LEN};
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

        async fn put_node(&self, bytes: HamtNodeBytes) -> Result<NodePutResult> {
            let k = Self::compute_key(&bytes);
            self.blobs.lock().unwrap().insert(k, bytes);
            Ok(NodePutResult { storage_key: k, cid: None })
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
        let root_key = root.store(&store).await.unwrap().storage_key;
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

    /// W.9.5 / #37 — fetch-order obfuscation regression guard.
    ///
    /// `flat_map` shuffles the per-pointer future list to hide
    /// intra-node topology from a network observer. The OUTPUT
    /// ordering must still be deterministic (preserves the docstring
    /// contract). This test pins both properties:
    ///
    /// 1. **Output is stable**: collect multiple times, every result
    ///    Vec must be identical (same plaintext leaves in the same
    ///    order regardless of which fetch order the buffered stream
    ///    drove).
    /// 2. **Fetch order is randomized**: an instrumented backend that
    ///    records the ORDER it receives `get_node` calls in MUST see
    ///    different sequences across runs (with high probability).
    ///
    /// Without (2), a future refactor that drops `shuffle()` would
    /// silently regress the privacy property — the test catches it.
    #[tokio::test]
    async fn flat_map_shuffles_fetch_order_but_preserves_output_order() {
        use std::sync::Mutex;

        // Backend that records every `get_node` call's storage_key
        // in receipt order — so we can compare orderings across
        // multiple `flat_map` runs.
        struct OrderTrackingStore {
            inner: InMemoryStore,
            fetch_order: Mutex<Vec<StorageKey>>,
        }
        impl OrderTrackingStore {
            fn new() -> Self {
                Self {
                    inner: InMemoryStore::new(),
                    fetch_order: Mutex::new(Vec::new()),
                }
            }
            fn observed_order(&self) -> Vec<StorageKey> {
                self.fetch_order.lock().unwrap().clone()
            }
            fn reset_order(&self) {
                self.fetch_order.lock().unwrap().clear();
            }
        }
        #[async_trait::async_trait]
        impl HamtNodeStore for OrderTrackingStore {
            async fn get_node(&self, key: &StorageKey) -> Result<HamtNodeBytes> {
                self.fetch_order.lock().unwrap().push(*key);
                self.inner.get_node(key).await
            }
            async fn put_node(&self, bytes: HamtNodeBytes) -> Result<NodePutResult> {
                self.inner.put_node(bytes).await
            }
        }

        let store = OrderTrackingStore::new();
        let mut root: Arc<TestNode> = Arc::new(TestNode::default());
        // Plant enough entries that several slots split into Link
        // pointers (which is what triggers the shuffle path —
        // Pointer::Values arms don't fetch). 64 entries across 16
        // top-level nibbles forces at least 4 sibling Link
        // pointers under the root; that's enough to make the
        // observed-order distribution non-degenerate.
        for i in 0u64..64 {
            let k = format!("shuffle-key-{:04}", i).into_bytes();
            root.set(k, i, &store).await.unwrap();
        }
        // Persist + reload from the store so subsequent flat_maps
        // actually fetch (the in-memory tree would otherwise short-
        // circuit through `Arc::clone` and never call `get_node`).
        let root_key = root.store(&store).await.unwrap().storage_key;
        let f = |pair: &Pair<Vec<u8>, u64>| Ok(pair.value);

        // Capture output + fetch order across multiple runs.
        let mut all_outputs: Vec<Vec<u64>> = Vec::new();
        let mut all_orders: Vec<Vec<StorageKey>> = Vec::new();
        for _ in 0..5 {
            store.reset_order();
            let reloaded: TestNode = TestNode::load(&root_key, &store).await.unwrap();
            let out = reloaded.flat_map(&f, &store).await.unwrap();
            all_outputs.push(out);
            all_orders.push(store.observed_order());
        }

        // (1) Output ORDERING (not just multiset) is stable across
        // runs. The shuffle affects fetch order, NOT output —
        // `sort_by_key((original_idx, _))` after `try_collect`
        // restores the input-pointer order before flatten. Compare
        // unsorted outputs so a regression that drops the
        // `sort_by_key` is caught here (with `out.sort()` applied,
        // such a regression would still preserve the multiset and
        // pass — Reviewer A flagged this).
        for i in 1..all_outputs.len() {
            assert_eq!(
                all_outputs[0], all_outputs[i],
                "output ORDER must be deterministic across runs (run {}); \
                 if this fires, sort_by_key after flat_map's try_collect \
                 was likely dropped",
                i
            );
        }
        // Sanity: every output must contain all 64 plaintexts (multiset
        // check, independent of ordering).
        assert_eq!(all_outputs[0].len(), 64);
        let mut sorted = all_outputs[0].clone();
        sorted.sort();
        let expected: Vec<u64> = (0u64..64).collect();
        assert_eq!(sorted, expected, "missing plaintext value(s)");

        // (2) Setup must actually exercise the shuffle. If
        // `HAMT_VALUES_BUCKET_SIZE` changes or BLAKE3 happens to
        // cluster all 64 entries into one nibble, we'd shuffle a
        // 1-pointer Vec and the next assertion would always pass
        // for the wrong reason. Require a non-trivial fetch count
        // across the runs so a regression in test setup fails loud
        // instead of masking a regression in the shuffle.
        let total_fetches: usize = all_orders.iter().map(|o| o.len()).sum();
        assert!(
            total_fetches >= 10,
            "test setup degenerate: only {} get_node calls across 5 runs — \
             not enough Pointer::Link splits to exercise the shuffle. \
             Likely cause: HAMT_VALUES_BUCKET_SIZE changed or the entry \
             count is too small for the current value. Bump entry count.",
            total_fetches
        );

        // (3) Fetch order is randomized. Across 5 runs, at least
        // TWO orderings must differ. For K splittable subtrees,
        // P(5 runs all identical) = 1/(K!)^4 — vanishingly small
        // for the K ≥ 4 we just enforced via (2). If `shuffle()`
        // is silently removed, ALL runs produce the same bitmask-
        // ordered fetch sequence and this fires immediately.
        let distinct_orders: std::collections::HashSet<Vec<StorageKey>> =
            all_orders.iter().cloned().collect();
        assert!(
            distinct_orders.len() >= 2,
            "fetch-order obfuscation regression: 5 runs of flat_map produced \
             only {} distinct fetch orderings — expected ≥ 2 from the \
             shuffle. If `flat_map` was refactored to drop the per_pointer_futs.shuffle() \
             call, this assertion catches it.",
            distinct_orders.len()
        );
    }

    // =====================================================================
    // Issue #34 — write-amplification regression guards.
    //
    // History: before the fix, `store(&self)` persisted every `InMemory`
    // child but could never downgrade it, so the InMemory set grew
    // monotonically and every flush re-PUT the ENTIRE ever-touched tree —
    // O(N²) total upload cost for N sequential puts (pinned at commit
    // 74ec299 / 2ed7fe0: two consecutive stores of an unchanged 64-entry
    // tree each re-PUT all ~12 nodes). The fix is `store_sealing`, which
    // write-backs persisted children as `ChildPtr::Sealed`. These tests
    // are the inverted pins plus the integrity guarantees of the fix.
    // =====================================================================

    use std::sync::atomic::{AtomicUsize, Ordering};

    struct PutCountingStore {
        inner: InMemoryStore,
        puts: AtomicUsize,
        /// When `Some(n)`, the n-th put_node call (1-based) fails once.
        fail_on_put: std::sync::Mutex<Option<usize>>,
    }

    impl PutCountingStore {
        fn new() -> Self {
            Self {
                inner: InMemoryStore::new(),
                puts: AtomicUsize::new(0),
                fail_on_put: std::sync::Mutex::new(None),
            }
        }

        fn puts(&self) -> usize {
            self.puts.load(Ordering::Relaxed)
        }
    }

    #[async_trait::async_trait]
    impl HamtNodeStore for PutCountingStore {
        async fn get_node(&self, key: &StorageKey) -> Result<HamtNodeBytes> {
            self.inner.get_node(key).await
        }
        async fn put_node(&self, bytes: HamtNodeBytes) -> Result<NodePutResult> {
            let n = self.puts.fetch_add(1, Ordering::Relaxed) + 1;
            let should_fail = {
                let mut guard = self.fail_on_put.lock().unwrap();
                if *guard == Some(n) {
                    *guard = None; // fail exactly once
                    true
                } else {
                    false
                }
            };
            if should_fail {
                return Err(CryptoError::Hamt(format!(
                    "injected put_node failure on call {}",
                    n
                )));
            }
            self.inner.put_node(bytes).await
        }
    }

    /// Build the deterministic 64-entry test tree (fixed keys → fixed
    /// BLAKE3-driven shape; most root slots split past
    /// HAMT_VALUES_BUCKET_SIZE = 3, producing a multi-node tree).
    async fn build_issue34_tree(store: &PutCountingStore) -> Arc<TestNode> {
        let mut root: Arc<TestNode> = Arc::new(TestNode::default());
        for i in 0u64..64 {
            let k = format!("issue34-key-{:04}", i).into_bytes();
            root.set(k, i, store).await.unwrap();
        }
        root
    }

    /// Assert every entry of the 64-entry test tree reads back correctly
    /// through `node` (resolving Sealed/Stored children as needed), with
    /// `overridden` taking precedence for mutated keys.
    async fn assert_issue34_tree_complete(
        node: &TestNode,
        store: &PutCountingStore,
        overridden: &[(u64, u64)],
    ) {
        for i in 0u64..64 {
            let k = format!("issue34-key-{:04}", i).into_bytes();
            let want = overridden
                .iter()
                .find(|(idx, _)| *idx == i)
                .map(|(_, v)| *v)
                .unwrap_or(i);
            let got = node.get(&k, store).await.unwrap();
            assert_eq!(
                got,
                Some(want),
                "entry {} must survive sealing round-trips intact",
                i
            );
        }
    }

    /// Issue #34 FIXED — `store_sealing` write-backs persisted children, so
    /// re-storing an unchanged tree re-PUTs ONLY the root node (1 PUT, same
    /// content address), not the whole tree. The legacy `store(&self)` also
    /// benefits once the tree is sealed (its `to_wire` emits the recorded
    /// references). A subsequent single-key mutation re-PUTs only the
    /// touched path. This is the inverted form of the original pin
    /// `issue_34_store_reputs_entire_unchanged_in_memory_tree`.
    #[tokio::test]
    async fn issue_34_fixed_store_sealing_skips_unchanged_subtrees() {
        let store = PutCountingStore::new();
        let mut root = build_issue34_tree(&store).await;

        // First sealing store: persists the full tree once.
        let first_key = root.store_sealing(&store).await.unwrap().storage_key;
        let first = store.puts();
        assert!(
            first >= 5,
            "setup degenerate: 64 entries should split into several nodes, \
             got only {} PUTs",
            first
        );

        // Second sealing store, NO mutation: children are Sealed, so only
        // the root is re-PUT (content-addressed → identical key, and the
        // PUT itself is idempotent on the backend).
        let second_key = root.store_sealing(&store).await.unwrap().storage_key;
        let second = store.puts() - first;
        assert_eq!(first_key, second_key, "unchanged tree → same content address");
        assert_eq!(
            second, 1,
            "issue #34 regression: re-storing an unchanged sealed tree must \
             PUT only the root node, got {} PUTs (pre-fix behaviour was {} — \
             the whole tree)",
            second, first
        );

        // Legacy store(&self) on the sealed tree: also root-only now, and
        // the same bytes → same key. (Pre-fix this was the amplifying path.)
        let third_key = root.store(&store).await.unwrap().storage_key;
        let third = store.puts() - first - second;
        assert_eq!(first_key, third_key, "legacy store must emit identical bytes");
        assert_eq!(
            third, 1,
            "legacy store() of a sealed tree must also be root-only, got {}",
            third
        );

        // Mutate ONE key: only the touched path unseals; the next sealing
        // store re-PUTs the path (root + its branch), not the tree.
        let mutated = format!("issue34-key-{:04}", 7).into_bytes();
        root.set(mutated, 7_000, &store).await.unwrap();
        let before = store.puts();
        let fourth_key = root.store_sealing(&store).await.unwrap().storage_key;
        let fourth = store.puts() - before;
        assert_ne!(first_key, fourth_key, "mutation must change the root address");
        assert!(
            (2..=4).contains(&fourth),
            "single-key mutation must re-PUT only the touched path \
             (root + 1-2 nodes), got {} PUTs",
            fourth
        );

        // INTEGRITY — through the live (sealed) tree...
        assert_issue34_tree_complete(&root, &store, &[(7, 7_000)]).await;
        // ...and through a cold reload of the final root from the backend
        // (proves the sealed flush persisted a complete, correct tree).
        let reloaded: TestNode = TestNode::load(&fourth_key, &store).await.unwrap();
        assert_issue34_tree_complete(&reloaded, &store, &[(7, 7_000)]).await;
    }

    /// Issue #34 — NO-CORRUPTION equivalence proof: `store_sealing`
    /// persists byte-identical state to the legacy `store`. Same inserts →
    /// same content-addressed root key (content addressing makes root-key
    /// equality transitive over the whole tree: identical root bytes embed
    /// identical child keys, which address identical child plaintexts).
    /// Readers — including pre-fix SDKs — cannot distinguish the writers.
    #[tokio::test]
    async fn issue_34_sealing_and_legacy_store_produce_identical_roots() {
        let store_legacy = PutCountingStore::new();
        let root_legacy = build_issue34_tree(&store_legacy).await;
        let key_legacy = root_legacy.store(&store_legacy).await.unwrap().storage_key;

        let store_sealed = PutCountingStore::new();
        let mut root_sealed = build_issue34_tree(&store_sealed).await;
        let key_sealed = root_sealed
            .store_sealing(&store_sealed)
            .await
            .unwrap()
            .storage_key;

        assert_eq!(
            key_legacy, key_sealed,
            "store_sealing must persist byte-identical state to store() — \
             a divergence here means the fix changed the on-disk format and \
             could corrupt interop with already-uploaded data"
        );

        // Both persisted trees round-trip completely from their backends.
        let from_legacy: TestNode =
            TestNode::load(&key_legacy, &store_legacy).await.unwrap();
        assert_issue34_tree_complete(&from_legacy, &store_legacy, &[]).await;
        let from_sealed: TestNode =
            TestNode::load(&key_sealed, &store_sealed).await.unwrap();
        assert_issue34_tree_complete(&from_sealed, &store_sealed, &[]).await;
    }

    /// Issue #34 — error-path integrity: if a node PUT fails mid-seal, the
    /// in-memory tree must remain fully intact (no placeholder left in any
    /// slot), already-sealed children keep their seal, and a retry must
    /// succeed and produce the exact same root as a never-failed run.
    #[tokio::test]
    async fn issue_34_store_sealing_failure_leaves_tree_intact_and_retryable() {
        // Control: the root key a clean run produces.
        let control_store = PutCountingStore::new();
        let mut control_root = build_issue34_tree(&control_store).await;
        let control_key = control_root
            .store_sealing(&control_store)
            .await
            .unwrap()
            .storage_key;
        let control_puts = control_store.puts();

        // Failing run: inject a one-shot failure on the 3rd put_node.
        let store = PutCountingStore::new();
        let mut root = build_issue34_tree(&store).await;
        *store.fail_on_put.lock().unwrap() = Some(3);
        let err = root.store_sealing(&store).await;
        assert!(err.is_err(), "injected failure must surface");

        // The tree must still be completely readable in memory — the
        // placeholder installed during sealing must never survive an
        // error exit.
        assert_issue34_tree_complete(&root, &store, &[]).await;

        // Retry: succeeds, costs at most a clean run (children sealed
        // before the failure are skipped), and lands on the identical
        // content address.
        let before_retry = store.puts();
        let retry_key = root.store_sealing(&store).await.unwrap().storage_key;
        let retry_puts = store.puts() - before_retry;
        assert_eq!(
            retry_key, control_key,
            "retry after a failed seal must converge on the same persisted \
             state as a never-failed run"
        );
        assert!(
            retry_puts <= control_puts,
            "retry must not re-PUT children that sealed before the failure \
             (retry: {}, clean run: {})",
            retry_puts,
            control_puts
        );

        // And the persisted tree is complete.
        let reloaded: TestNode = TestNode::load(&retry_key, &store).await.unwrap();
        assert_issue34_tree_complete(&reloaded, &store, &[]).await;
    }
}
