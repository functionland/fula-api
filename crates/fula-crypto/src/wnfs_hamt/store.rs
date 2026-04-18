// Fula-native storage seam for the vendored HAMT. Replaces wnfs-common's
// `BlockStore`. Node blobs are AEAD-encrypted *outside* this trait; the trait
// sees plaintext bytes only. See plan: /root/.claude/plans/do-a-thorough-line-cheeky-taco.md

use crate::Result;

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
#[cfg(not(target_arch = "wasm32"))]
#[async_trait::async_trait]
pub trait HamtNodeStore: Send + Sync {
    async fn get_node(&self, key: &StorageKey) -> Result<HamtNodeBytes>;
    async fn put_node(&self, bytes: HamtNodeBytes) -> Result<StorageKey>;
}

#[cfg(target_arch = "wasm32")]
#[async_trait::async_trait(?Send)]
pub trait HamtNodeStore {
    async fn get_node(&self, key: &StorageKey) -> Result<HamtNodeBytes>;
    async fn put_node(&self, bytes: HamtNodeBytes) -> Result<StorageKey>;
}
