// Fula-native storage seam for the vendored HAMT. Replaces wnfs-common's
// `BlockStore`. Node blobs are AEAD-encrypted *outside* this trait; the trait
// sees plaintext bytes only. See plan: /root/.claude/plans/do-a-thorough-line-cheeky-taco.md

use crate::Result;
use cid::Cid;

/// Truncation width for the content-addressed node key, matching fula's
/// existing `generate_flat_key` width so AEAD AAD layouts stay uniform
/// across shard bodies and HAMT nodes.
pub const STORAGE_KEY_LEN: usize = 22;

/// Content-addressed key for a HAMT node blob.
///
/// Derived as `BLAKE3(bucket_salt ‖ plaintext_node_bytes)[..STORAGE_KEY_LEN]`.
/// Plaintext-based hashing (not ciphertext) preserves cross-revision dedup for
/// unchanged subtrees; the per-bucket salt prevents cross-bucket correlation
/// by an external observer of the backing object store.
pub type StorageKey = [u8; STORAGE_KEY_LEN];

/// Plaintext bytes of a HAMT node, pre-AEAD.
pub type HamtNodeBytes = Vec<u8>;

/// Outcome of persisting a HAMT node through `HamtNodeStore::put_node`
/// or `Node::store` (walkable-v8 / W.9.2).
///
/// Carries the existing `storage_key` (the master-S3 routing identifier
/// derived from `BLAKE3(bucket_salt ‖ plaintext)[..22]`) plus an optional
/// `cid` returned by the underlying `BlobBackend` after the ciphertext has
/// been written.
///
/// `cid` is `Some` when the backend exposes a content-address for the
/// ciphertext (e.g. master S3 returns the CID via `ETag` after a successful
/// PUT) and `None` otherwise (in-memory test backends, bench backends, or
/// any backend whose `BlobPutResult.cid` came back `None` because the etag
/// failed to parse). W.9.3 stamps `Some(_)` values into parent-pointer
/// `LinkV2` variants so a v8 reader can walk via IPFS gateways without
/// master; `None` falls through to the legacy v7 storage-key path, which is
/// always pinned alongside the ciphertext.
#[derive(Debug, Clone, Copy)]
pub struct NodePutResult {
    pub storage_key: StorageKey,
    pub cid: Option<Cid>,
}

/// Storage trait the HAMT uses to read and write node blobs.
///
/// Implementors are responsible for:
///   * AEAD-encrypting plaintext node bytes with the owning shard's DEK and
///     binding `b"fula:hamt-node:v7:" ‖ bucket_id ‖ shard_idx_u16_be ‖ shard_seq_u64_be`
///     into the AAD (replay-resistance);
///   * Content-addressing with `BLAKE3(bucket_salt ‖ plaintext_node_bytes)`
///     truncated to `STORAGE_KEY_LEN` (dedup + integrity);
///   * Verifying the retrieved plaintext's content hash before returning it
///     from `get_node` (forgery-resistance).
///
/// The tree logic in `wnfs_hamt::node` only ever sees plaintext bytes and
/// opaque `StorageKey`s.
///
/// `put_node` returns a [`NodePutResult`]: backward-compat consumers extract
/// `.storage_key`; W.9.3+ writers also use `.cid` to stamp CID hints into
/// parent pointers (see `PointerWire::LinkV2`).
///
/// **Walkable-v8 (W.9.4) — `get_node_with_cid_hint`**: the cid-hint variant
/// lets the HAMT walker forward a child's `Cid` (learned from the parent's
/// `PointerWire::LinkV2` plaintext) down to the storage layer so a
/// master-down walk can continue over public IPFS. Default impl ignores the
/// hint and falls through to `get_node` — appropriate for in-memory test
/// stores that have no offline channel. **The integrity contract is
/// unchanged** even when a hint is supplied: every retrieved plaintext
/// MUST still have its content hash recomputed and compared to `key`.
/// The cid-hint only changes WHERE the bytes come from; the post-fetch
/// validation defends against parent-pointer manipulation between layers.
#[cfg(not(target_arch = "wasm32"))]
#[async_trait::async_trait]
pub trait HamtNodeStore: Send + Sync {
    async fn get_node(&self, key: &StorageKey) -> Result<HamtNodeBytes>;
    async fn put_node(&self, bytes: HamtNodeBytes) -> Result<NodePutResult>;

    /// Walkable-v8 (W.9.4) — fetch a node with an optional content-address
    /// hint. Default impl ignores the hint and falls through to
    /// [`get_node`]. `V7NodeStore` overrides to forward the hint to its
    /// backing `BlobBackend::get_with_cid_hint`; the post-fetch
    /// `recomputed == key` check stays in place so a redirected fetch
    /// (different storage_key than the parent claimed) is rejected even
    /// when the gateway content-address verify passes.
    async fn get_node_with_cid_hint(
        &self,
        key: &StorageKey,
        _cid_hint: Option<&Cid>,
    ) -> Result<HamtNodeBytes> {
        self.get_node(key).await
    }
}

#[cfg(target_arch = "wasm32")]
#[async_trait::async_trait(?Send)]
pub trait HamtNodeStore {
    async fn get_node(&self, key: &StorageKey) -> Result<HamtNodeBytes>;
    async fn put_node(&self, bytes: HamtNodeBytes) -> Result<NodePutResult>;

    /// Walkable-v8 (W.9.4) — fetch a node with an optional content-address
    /// hint. Default impl ignores the hint and falls through to
    /// [`get_node`]. On wasm32 the offline-fallback infrastructure is
    /// compiled out so the `S3BlobBackend` override is a thin delegate;
    /// the trait surface is symmetric across targets so cross-target
    /// callers don't need `cfg` gating.
    async fn get_node_with_cid_hint(
        &self,
        key: &StorageKey,
        _cid_hint: Option<&Cid>,
    ) -> Result<HamtNodeBytes> {
        self.get_node(key).await
    }
}
