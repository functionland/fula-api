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
use cid::Cid;
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
///
/// **Walkable-v8 (plan section W.9.1)**: `StoredV2` extends `Stored` with a
/// CID hint — the master-returned `BLAKE3(ciphertext)` raw-codec address —
/// so an offline reader can fetch this child via public IPFS gateway without
/// going through master. The `storage_key` is retained for online walks and
/// for the writer-side conditional-PUT story (Phase 1.5/1.6/2 If-Match).
/// Both addresses refer to the same encrypted node ciphertext; they
/// authenticate each other indirectly via fetch-then-verify (gateway returns
/// bytes whose hash matches `cid`, AEAD decryption with `forest_dek` then
/// confirms the plaintext is the same content `storage_key` was derived
/// from).
pub enum ChildPtr<K, V, H>
where
    H: Hasher,
{
    InMemory(Arc<Node<K, V, H>>),
    Stored(StorageKey),
    StoredV2 {
        storage_key: StorageKey,
        cid: Cid,
    },
    /// Issue #34 — persisted AND still memory-resident.
    ///
    /// Produced by `Node::store_sealing` when an `InMemory` child has been
    /// successfully PUT: the subtree stays resident (reads resolve from
    /// memory with zero I/O, exactly like `InMemory`), but store paths now
    /// emit the recorded `storage_key`/`cid` reference WITHOUT re-uploading
    /// the subtree. This is the write-back state that `InMemory` was
    /// missing: before it existed, a flushed-but-resident subtree could
    /// only be represented as `InMemory`, so every subsequent flush
    /// re-serialized, re-encrypted (fresh nonce), and re-PUT the whole
    /// ever-touched tree — O(N²) total upload cost for N sequential puts.
    ///
    /// Never serialized as a distinct wire variant: `to_wire` maps it to
    /// the same `PointerWire::Link`/`LinkV2` the original PUT produced, so
    /// the on-disk format is byte-identical to pre-#34 writers. Any
    /// mutation through `set_value`/`remove_value`/`canonicalize` resolves
    /// the Arc and re-attaches the subtree as `InMemory`, invalidating the
    /// seal for exactly the changed path.
    ///
    /// `cid` is `Some` only when the backend attested one on the original
    /// PUT (walkable-v8 master); mirrors the `LinkV2`-vs-`Link` split.
    Sealed {
        storage_key: StorageKey,
        cid: Option<Cid>,
        node: Arc<Node<K, V, H>>,
    },
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
///
/// **Wire-version compatibility (walkable-v8 plan, section W.3.2).** Variant
/// tags are part of the on-disk contract:
///
/// | Variant   | Tag | Introduced | Read by   | Written by    |
/// |-----------|-----|------------|-----------|---------------|
/// | `Values`  | 0   | v7         | v7+, v8+  | v7+           |
/// | `Link`    | 1   | v7         | v7+, v8+  | v7+           |
/// | `LinkV2`  | 2   | v8         | v8+       | v8+ (opt-in)  |
///
/// A v7-only deserializer (an SDK that has never been recompiled with the
/// `LinkV2` variant) fails on tag `2` with postcard's "unknown variant"
/// error. This is the intended forward-incompatibility boundary — old SDKs
/// see a typed error rather than data corruption when they encounter
/// v8-format blobs. We rely on postcard's own enum-variant discrimination
/// here; do **not** add a leading magic byte (postcard's varint length
/// prefix on the outer `Vec<PointerWire>` collides with small magic values
/// when the Vec happens to have that many elements).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum PointerWire<K, V> {
    Values(Vec<(K, V)>),
    Link(StorageKey),
    /// Walkable-v8 variant. Pairs the master-S3 storage key with the CID
    /// master returned in its PUT response (= `BLAKE3(ciphertext)`
    /// raw-codec). The `cid` field lets a reader fetch this child via
    /// public IPFS gateway (offline mode) without going through master.
    /// See `ChildPtr::StoredV2` for the in-memory counterpart.
    LinkV2 {
        storage_key: StorageKey,
        cid: Cid,
    },
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
    /// the link is a `Stored` or `StoredV2` reference. The returned `Arc` is
    /// shared with the in-memory form when already resident.
    ///
    /// **Walkable-v8 (W.9.4)**: when this is a `StoredV2 { storage_key, cid }`
    /// link, the embedded `cid` is forwarded to the storage layer as a
    /// content-address hint via `Node::load_with_cid_hint`. An offline-
    /// aware `HamtNodeStore` (e.g. `V7NodeStore` over `S3BlobBackend`)
    /// uses it to engage the gateway race when master is unreachable; an
    /// in-memory test store ignores it and falls through to the regular
    /// fetch. Either way, the post-fetch integrity pipeline
    /// (`V7NodeStore::decrypt_and_verify`) recomputes
    /// `BLAKE3(bucket_salt ‖ plaintext)[..22]` and compares to
    /// `storage_key` — the third integrity layer that defends against a
    /// malicious parent that pointed `LinkV2` at the right CID but the
    /// wrong storage_key.
    ///
    /// **Reader path is NOT gated on `walkable_v8_writer_enabled`.**
    /// The wire-format variant itself is the gate: when the writer flag
    /// is off, no `LinkV2` entries get persisted, so no `cid_hint`
    /// reaches the store. Buckets written entirely under v7 stay on
    /// the legacy `Stored` arm (no hint, no offline-walk capability —
    /// same behaviour as today). Adding a separate reader flag for
    /// "symmetry" with the writer would be a bug: it would break a
    /// legitimately-flagged-on bucket whenever the user toggled the
    /// flag back off mid-session.
    pub async fn resolve_owned(
        &self,
        store: &(impl HamtNodeStore + ?Sized),
    ) -> Result<Arc<Node<K, V, H>>> {
        match self {
            ChildPtr::InMemory(n) => Ok(Arc::clone(n)),
            ChildPtr::Stored(key) => {
                // Legacy v7 arm — no CID hint available. Pass `None` so
                // the store falls back to its `get_node` path; on master-
                // down this surfaces the ordinary warm-cache offline
                // path (Phase 2.4) which itself can fail with
                // `MasterUnreachable` for cold buckets. Keeps lazy-
                // migration semantics from W.4.2.
                let node =
                    Node::<K, V, H>::load_with_cid_hint(key, None, store).await?;
                Ok(Arc::new(node))
            }
            ChildPtr::StoredV2 { storage_key, cid } => {
                // Walkable-v8 arm — forward both the storage_key (for
                // master-S3 routing AND post-fetch storage_key recompute)
                // and the cid (for cold-cache gateway race).
                let node = Node::<K, V, H>::load_with_cid_hint(
                    storage_key,
                    Some(cid),
                    store,
                )
                .await?;
                Ok(Arc::new(node))
            }
            // Issue #34 — the subtree is persisted but still resident;
            // serve it from memory exactly like `InMemory`. No I/O, no
            // integrity re-check needed: these are the same plaintext
            // nodes the seal-time PUT serialized.
            ChildPtr::Sealed { node, .. } => Ok(Arc::clone(node)),
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
    ///
    /// **Walkable-v8 note (W.9.3 will revisit this).** When this function
    /// re-wraps a subtree as `Pointer::Link(ChildPtr::InMemory(node))`
    /// (the "still-needs-to-be-a-subtree" branches below), any CID hint
    /// that was on the input `StoredV2` link is intentionally dropped —
    /// the in-memory subtree must be re-persisted by the caller, which
    /// will produce a fresh CID. W.9.3's writer wiring should NOT assume
    /// a `StoredV2` survives canonicalize; it must re-stamp the CID after
    /// the subsequent persist.
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
    ///
    /// **Walkable-v8 (W.9.1 plumbing, W.9.3 writer integration):**
    ///
    /// | Child variant            | Wire variant emitted                                  |
    /// |--------------------------|--------------------------------------------------------|
    /// | `ChildPtr::Stored(key)`  | `PointerWire::Link(key)` — unchanged stored sibling.  |
    /// |                          | We don't have a CID for an unmutated stored child;    |
    /// |                          | upgrading it would require an extra fetch+rehash. So  |
    /// |                          | legacy children stay as `Link` until they themselves  |
    /// |                          | get re-persisted (lazy migration, plan W.4.2).        |
    /// | `ChildPtr::StoredV2{..}` | `PointerWire::LinkV2 { .. }` — preserve the CID hint  |
    /// |                          | a previous flush (or load) gave us.                   |
    /// | `ChildPtr::InMemory(c)`  | `PointerWire::LinkV2 { storage_key, cid }` when the   |
    /// |                          | freshly-persisted child's `NodePutResult.cid` is      |
    /// |                          | `Some(_)` — i.e. when the underlying `BlobBackend`    |
    /// |                          | (typically `S3BlobBackend` with `walkable_v8_writer_  |
    /// |                          | enabled = true`) surfaced a master-attested CID for   |
    /// |                          | the ciphertext. Falls back to `PointerWire::Link`     |
    /// |                          | when `cid` is `None` (writer flag off, in-memory test |
    /// |                          | backend, or master returned an unparseable etag).     |
    ///
    /// **Mixed-variant parents are normal**: a parent re-persisted after one
    /// child mutation will contain `Link(SK)` for unchanged siblings AND
    /// `LinkV2 { SK, cid }` for the freshly-stored child. This is correct
    /// — old SDKs that don't know `LinkV2` already refuse such a parent
    /// cleanly via postcard's "unknown variant 2" error (see
    /// `legacy_v7_decoder_errors_on_v8_link_v2_blob` test in this file),
    /// and v8 SDKs handle both variants on `from_wire` (see
    /// `mixed_link_and_link_v2_in_one_parent_round_trips`).
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
            Pointer::Link(ChildPtr::StoredV2 { storage_key, cid }) => Ok(PointerWire::LinkV2 {
                storage_key: *storage_key,
                cid: cid.clone(),
            }),
            // Issue #34 — already persisted by a prior `store_sealing`
            // pass; emit the recorded reference WITHOUT re-uploading the
            // subtree. Wire form matches what the original PUT produced
            // (`LinkV2` when the backend attested a CID, legacy `Link`
            // otherwise), so persisted bytes are identical to a pre-#34
            // writer's.
            Pointer::Link(ChildPtr::Sealed { storage_key, cid, .. }) => match cid {
                Some(cid) => Ok(PointerWire::LinkV2 {
                    storage_key: *storage_key,
                    cid: cid.clone(),
                }),
                None => Ok(PointerWire::Link(*storage_key)),
            },
            Pointer::Link(ChildPtr::InMemory(child)) => {
                let result = child.store(store).await?;
                match result.cid {
                    Some(cid) => Ok(PointerWire::LinkV2 {
                        storage_key: result.storage_key,
                        cid,
                    }),
                    None => Ok(PointerWire::Link(result.storage_key)),
                }
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
    /// stay as `Stored` (legacy) or `StoredV2` (walkable-v8) references and
    /// are resolved on demand during traversal.
    pub fn from_wire(wire: PointerWire<K, V>) -> Self {
        match wire {
            PointerWire::Values(kvs) => Pointer::Values(
                kvs.into_iter()
                    .map(|(key, value)| Pair { key, value })
                    .collect(),
            ),
            PointerWire::Link(key) => Pointer::Link(ChildPtr::Stored(key)),
            PointerWire::LinkV2 { storage_key, cid } => {
                Pointer::Link(ChildPtr::StoredV2 { storage_key, cid })
            }
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
            ChildPtr::StoredV2 { storage_key, cid } => ChildPtr::StoredV2 {
                storage_key: *storage_key,
                cid: cid.clone(),
            },
            ChildPtr::Sealed { storage_key, cid, node } => ChildPtr::Sealed {
                storage_key: *storage_key,
                cid: cid.clone(),
                node: Arc::clone(node),
            },
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
            ChildPtr::StoredV2 { storage_key, cid } => f
                .debug_struct("StoredV2")
                .field("storage_key", &hex::encode(storage_key))
                .field("cid", cid)
                .finish(),
            ChildPtr::Sealed { storage_key, cid, node } => f
                .debug_struct("Sealed")
                .field("storage_key", &hex::encode(storage_key))
                .field("cid", cid)
                .field("node", node)
                .finish(),
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
            // StoredV2 equality requires both the storage_key AND the CID
            // hint to match — two `StoredV2` referring to the same logical
            // child but recorded with different CIDs (e.g. one stamped from
            // an old PUT, one from a fresh PUT with a different nonce hence
            // different ciphertext-hash) are NOT considered equal at this
            // layer. Cross-variant comparison (`Stored` vs `StoredV2`) is
            // intentionally `false` to keep the v8-format-vs-v7-format
            // distinction observable in tests.
            (
                Pointer::Link(ChildPtr::StoredV2 { storage_key: a_sk, cid: a_cid }),
                Pointer::Link(ChildPtr::StoredV2 { storage_key: b_sk, cid: b_cid }),
            ) => a_sk == b_sk && a_cid == b_cid,
            // Sealed equality compares the persisted identity only
            // (storage_key is the content address; cid mirrors the
            // LinkV2/Link split). The resident `node` Arc is deliberately
            // not compared — it is derived state, same rationale as the
            // InMemory `false` arm above. Cross-variant comparison
            // (Sealed vs Stored/StoredV2/InMemory) stays `false` so the
            // sealed-vs-loaded distinction remains observable in tests.
            (
                Pointer::Link(ChildPtr::Sealed { storage_key: a_sk, cid: a_cid, .. }),
                Pointer::Link(ChildPtr::Sealed { storage_key: b_sk, cid: b_cid, .. }),
            ) => a_sk == b_sk && a_cid == b_cid,
            _ => false,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Walkable-v8 wire format tests (W.9.1)
//--------------------------------------------------------------------------------------------------
//
// These tests pin the on-disk wire-format contract for `PointerWire` so that
// a future refactor can't silently break the version-dispatch story. The
// load-bearing properties they assert:
//
//   1. Each variant round-trips through postcard losslessly.
//   2. The variant index of `LinkV2` is the postcard discriminator `2` —
//      the value an old (v7-only) deserializer doesn't recognise.
//   3. A v7-only deserializer (modelled here as `LegacyPointerWire` with
//      only `Values` and `Link` variants) errors cleanly on a v8-format
//      `LinkV2` blob.
//   4. The v8 deserializer reads a v7-format `Link` blob (legacy data
//      written by an SDK pre-walkable-v8 round-trips fine).
//
// If anyone changes the variant order or removes a variant, these tests
// must fail loudly — that's by design.

#[cfg(test)]
mod walkable_v8_wire_tests {
    use super::*;
    use super::super::store::STORAGE_KEY_LEN;
    use cid::Cid;
    use cid::multihash::Multihash;

    fn test_storage_key() -> StorageKey {
        let mut k = [0u8; STORAGE_KEY_LEN];
        for (i, b) in k.iter_mut().enumerate() {
            *b = i as u8;
        }
        k
    }

    fn test_cid() -> Cid {
        // BLAKE3 multihash code = 0x1e, 32-byte digest. Mirrors what master
        // returns in its PUT-response ETag header
        // (`crates/fula-cli/src/handlers/object.rs:103-137`).
        let digest = [0xABu8; 32];
        let mh = Multihash::<64>::wrap(0x1e, &digest).expect("BLAKE3 multihash wrap");
        // Codec 0x55 = raw, matching master's CID format for object bodies.
        Cid::new_v1(0x55, mh)
    }

    #[test]
    fn pointer_wire_values_roundtrip() {
        let original: PointerWire<Vec<u8>, u64> = PointerWire::Values(vec![
            (b"key-a".to_vec(), 1),
            (b"key-b".to_vec(), 2),
        ]);
        let encoded = postcard::to_allocvec(&original).expect("encode");
        // Postcard writes enum variant index as the leading byte for small
        // tags. Values is variant 0.
        assert_eq!(encoded[0], 0, "Values is variant 0 in the wire format");
        let decoded: PointerWire<Vec<u8>, u64> =
            postcard::from_bytes(&encoded).expect("decode");
        assert_eq!(decoded, original);
    }

    #[test]
    fn pointer_wire_link_legacy_roundtrip() {
        let original: PointerWire<Vec<u8>, u64> = PointerWire::Link(test_storage_key());
        let encoded = postcard::to_allocvec(&original).expect("encode");
        assert_eq!(encoded[0], 1, "Link is variant 1 in the wire format");
        let decoded: PointerWire<Vec<u8>, u64> =
            postcard::from_bytes(&encoded).expect("decode");
        assert_eq!(decoded, original);
    }

    #[test]
    fn pointer_wire_link_v2_roundtrip() {
        let original: PointerWire<Vec<u8>, u64> = PointerWire::LinkV2 {
            storage_key: test_storage_key(),
            cid: test_cid(),
        };
        let encoded = postcard::to_allocvec(&original).expect("encode");
        // LinkV2 must be variant 2 — this is the load-bearing
        // version-dispatch byte for walkable-v8 (plan W.3.2). Old
        // deserializers that only know variants 0 and 1 must error here.
        assert_eq!(
            encoded[0], 2,
            "LinkV2 is variant 2 in the wire format — do not change this. \
             A v7-only deserializer relies on tag 2 being unknown to surface \
             a typed error rather than corrupting state."
        );
        let decoded: PointerWire<Vec<u8>, u64> =
            postcard::from_bytes(&encoded).expect("decode");
        assert_eq!(decoded, original);
    }

    /// A v7-only enum (only Values + Link variants) — simulates a
    /// v0.5-or-earlier SDK that has never been recompiled to know about
    /// `LinkV2`. Reading a v8-format `LinkV2` blob into this enum must
    /// produce a typed error.
    #[derive(Debug, Serialize, Deserialize)]
    enum LegacyPointerWire<K, V> {
        Values(Vec<(K, V)>),
        Link(StorageKey),
    }

    #[test]
    fn legacy_v7_decoder_errors_on_v8_link_v2_blob() {
        let v8_blob: PointerWire<Vec<u8>, u64> = PointerWire::LinkV2 {
            storage_key: test_storage_key(),
            cid: test_cid(),
        };
        let encoded = postcard::to_allocvec(&v8_blob).expect("encode");

        let result: std::result::Result<LegacyPointerWire<Vec<u8>, u64>, _> =
            postcard::from_bytes(&encoded);
        assert!(
            result.is_err(),
            "v7-only deserializer must error on v8 LinkV2 blob \
             (forward-incompatibility boundary), got {:?}",
            result
        );
    }

    #[test]
    fn v8_decoder_reads_legacy_v7_link_blob() {
        // A v7 SDK encoded a `Link(StorageKey)` blob. A v8 SDK reading the
        // same bucket must decode it identically — no upgrade-on-read,
        // legacy data stays accessible until the user happens to write to
        // it (W.4.2: lazy migration on next write).
        let v7_blob = LegacyPointerWire::<Vec<u8>, u64>::Link(test_storage_key());
        let encoded = postcard::to_allocvec(&v7_blob).expect("encode");

        let decoded: PointerWire<Vec<u8>, u64> =
            postcard::from_bytes(&encoded).expect("decode v7 blob via v8 deserializer");
        assert_eq!(decoded, PointerWire::Link(test_storage_key()));
    }

    #[test]
    fn v8_decoder_reads_legacy_v7_values_blob() {
        let v7_blob = LegacyPointerWire::<Vec<u8>, u64>::Values(vec![
            (b"a".to_vec(), 10),
            (b"b".to_vec(), 20),
        ]);
        let encoded = postcard::to_allocvec(&v7_blob).expect("encode");

        let decoded: PointerWire<Vec<u8>, u64> =
            postcard::from_bytes(&encoded).expect("decode v7 values blob via v8 deserializer");
        match decoded {
            PointerWire::Values(pairs) => {
                assert_eq!(pairs.len(), 2);
                assert_eq!(pairs[0], (b"a".to_vec(), 10));
                assert_eq!(pairs[1], (b"b".to_vec(), 20));
            }
            other => panic!("expected Values, got {:?}", other),
        }
    }

    /// Mixed-variant parent (W.9.3 advisor blind-spot): a parent
    /// re-persisted after one child mutation legitimately contains
    /// `Link(SK)` for unchanged stored siblings AND `LinkV2 { SK, cid }`
    /// for the freshly-stored child. This is the realistic case during
    /// lazy migration (plan W.4.2): a v8-aware writer mutates one
    /// subtree, the parent re-encodes, untouched stored children stay
    /// in the legacy `Link` variant, the mutated child gets the new
    /// `LinkV2`. Both must round-trip through postcard losslessly.
    ///
    /// Without this test the existing single-variant tests above pass
    /// even if `from_wire`/`to_wire` mishandle a mixed `Vec<PointerWire>`.
    /// The mixed-Vec encoding is what real production blobs look like
    /// after the writer flag flips on, so this is the load-bearing
    /// migration-correctness test for the wire format.
    #[test]
    fn mixed_link_and_link_v2_in_one_parent_round_trips() {
        let sk_legacy = test_storage_key();
        let mut sk_modern = sk_legacy;
        sk_modern[0] ^= 0xFF; // distinct from sk_legacy
        let cid_modern = test_cid();

        // A real parent's wire form is `postcard(Vec<PointerWire>)`.
        // Mix all three variant tags in one Vec: a Values bucket, a
        // legacy Link, and a v8 LinkV2. This is structurally the same
        // shape `Node::store` produces on a parent that has one
        // freshly-mutated child and untouched siblings.
        let wire: Vec<PointerWire<Vec<u8>, u64>> = vec![
            PointerWire::Values(vec![(b"untouched-bucket-key".to_vec(), 99)]),
            PointerWire::Link(sk_legacy),
            PointerWire::LinkV2 {
                storage_key: sk_modern,
                cid: cid_modern.clone(),
            },
        ];
        let encoded = postcard::to_allocvec(&wire).expect("encode mixed Vec");
        let decoded: Vec<PointerWire<Vec<u8>, u64>> =
            postcard::from_bytes(&encoded).expect("decode mixed Vec");
        assert_eq!(decoded.len(), 3);
        match &decoded[0] {
            PointerWire::Values(pairs) => {
                assert_eq!(pairs.len(), 1);
                assert_eq!(pairs[0], (b"untouched-bucket-key".to_vec(), 99));
            }
            other => panic!("expected Values, got {:?}", other),
        }
        match &decoded[1] {
            PointerWire::Link(sk) => assert_eq!(*sk, sk_legacy),
            other => panic!("expected legacy Link, got {:?}", other),
        }
        match &decoded[2] {
            PointerWire::LinkV2 { storage_key, cid } => {
                assert_eq!(*storage_key, sk_modern);
                assert_eq!(*cid, cid_modern);
            }
            other => panic!("expected LinkV2, got {:?}", other),
        }

        // Cross-check that the encoded wire actually contains every
        // variant tag it ought to. The leading byte of each variant in
        // the contiguous postcard stream is the discriminator (0/1/2).
        // We can't index into `encoded` to find the tag bytes directly
        // without knowing each variant's payload length, but we CAN
        // confirm the encoding doesn't accidentally collapse two
        // variants by re-encoding decoded and comparing byte-for-byte.
        let re_encoded = postcard::to_allocvec(&decoded).expect("re-encode");
        assert_eq!(
            encoded, re_encoded,
            "mixed-variant Vec must round-trip byte-for-byte through postcard \
             — defends against a future serialize impl that silently reorders \
             variants by tag, which would change how an old SDK reads the \
             same blob"
        );
    }

    /// A v7-only deserializer (only Values + Link) on a mixed Vec must
    /// fail at the FIRST `LinkV2` it tries to decode — postcard streams
    /// the Vec contiguously, so once the unknown variant is hit, the
    /// reader cannot recover. This pins the forward-incompatibility
    /// boundary for parents written by a v8 SDK on a bucket old SDKs
    /// might still read.
    #[test]
    fn legacy_v7_decoder_errors_on_mixed_parent_with_link_v2() {
        let sk_legacy = test_storage_key();
        let mut sk_modern = sk_legacy;
        sk_modern[0] ^= 0xFF;
        let v8_blob: Vec<PointerWire<Vec<u8>, u64>> = vec![
            PointerWire::Link(sk_legacy),
            PointerWire::LinkV2 {
                storage_key: sk_modern,
                cid: test_cid(),
            },
        ];
        let encoded = postcard::to_allocvec(&v8_blob).expect("encode");

        let result: std::result::Result<Vec<LegacyPointerWire<Vec<u8>, u64>>, _> =
            postcard::from_bytes(&encoded);
        assert!(
            result.is_err(),
            "v7-only deserializer must error on a mixed Vec the moment it \
             encounters the LinkV2 element — guarantees old SDKs surface a \
             clean WireVersionUnsupported, never silently truncate the parent's \
             child list. got: {:?}",
            result
        );
    }

    /// Full integration round-trip: in-memory `ChildPtr::StoredV2` → `Pointer`
    /// → `to_wire` → bytes → `from_wire` → `Pointer` → `ChildPtr::StoredV2`.
    /// The 5 tests above each cover one hop of this chain in isolation; this
    /// test fuses them so a typo in `to_wire`'s `LinkV2` arm or `from_wire`'s
    /// would surface here even if each isolated test still passed.
    #[tokio::test]
    async fn child_ptr_stored_v2_full_pipeline_roundtrip() {
        use crate::hashing::Blake3Hasher;
        use crate::wnfs_hamt::v7_store::InMemoryBackend;
        use crate::wnfs_hamt::v7_store::V7NodeStore;
        use crate::keys::DekKey;
        use std::sync::Arc;

        // Build a real V7NodeStore so `to_wire` has a place to defer to for
        // the `InMemory` arm (we don't exercise it here, but `to_wire`'s
        // signature requires a store).
        let backend = Arc::new(InMemoryBackend::new());
        let store = V7NodeStore::new(
            "bucket-walkable-v8",
            /* shard_idx = */ 0,
            vec![0xFE; 16],
            DekKey::from_bytes(&[0x77u8; 32]).unwrap(),
            backend.clone(),
        );

        // Construct a Pointer that holds a `StoredV2` child.
        let original_sk = test_storage_key();
        let original_cid = test_cid();
        let pointer: Pointer<Vec<u8>, u64, Blake3Hasher> =
            Pointer::Link(ChildPtr::StoredV2 {
                storage_key: original_sk,
                cid: original_cid.clone(),
            });

        // to_wire must produce LinkV2 with the same fields.
        let wire = pointer.to_wire(&store).await.expect("to_wire");
        match &wire {
            PointerWire::LinkV2 { storage_key, cid } => {
                assert_eq!(*storage_key, original_sk);
                assert_eq!(*cid, original_cid);
            }
            other => panic!("expected LinkV2, got {:?}", other),
        }

        // Encode and decode through postcard.
        let encoded = postcard::to_allocvec(&wire).expect("encode");
        assert_eq!(encoded[0], 2, "must produce v8 wire variant tag");
        let decoded: PointerWire<Vec<u8>, u64> =
            postcard::from_bytes(&encoded).expect("decode");

        // from_wire must reconstruct the StoredV2 child verbatim.
        let reconstructed: Pointer<Vec<u8>, u64, Blake3Hasher> =
            Pointer::from_wire(decoded);
        match reconstructed {
            Pointer::Link(ChildPtr::StoredV2 { storage_key, cid }) => {
                assert_eq!(storage_key, original_sk);
                assert_eq!(cid, original_cid);
            }
            other => panic!("expected ChildPtr::StoredV2, got {:?}", other),
        }
    }
}
