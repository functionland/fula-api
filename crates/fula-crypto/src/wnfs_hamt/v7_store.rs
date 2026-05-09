// V7 node storage: AEAD-encrypted, content-addressed HAMT node blobs.
//
// This module bridges the pure tree logic (`node.rs`, `pointer.rs`) with the
// actual backing object store. It owns the two pieces of crypto that can't
// live in the tree itself:
//
//   * Content-addressing via `compute_v7_node_key` — `BLAKE3(bucket_salt ‖
//     plaintext)[..V7_STORAGE_KEY_LEN]`, for cross-revision dedup and integrity.
//   * Per-node AEAD with AAD `hamt_node_v7_aad(bucket, shard_idx)` — bucket
//     and shard pinning only — using the owning shard's DEK. Replay
//     resistance at the shard-seq layer lives in the manifest (ETag +
//     `manifest.shards[i].seq`); a seq-bound node AAD would invalidate
//     untouched subtree ciphertexts on every path-of-change flush and is
//     therefore intentionally omitted.
//
// The raw bytes layer is abstracted behind `BlobBackend` so this module can be
// exercised with an in-memory backend in fula-crypto tests, and fula-client can
// plug in an S3-backed implementation without any crypto logic living there.
//
// See plan: /root/.claude/plans/do-a-thorough-line-cheeky-taco.md (search: "V7NodeStore").

use super::store::{HamtNodeBytes, HamtNodeStore, NodePutResult, STORAGE_KEY_LEN, StorageKey};
use crate::keys::DekKey;
use crate::private_forest::{
    V7StorageKey, V7_STORAGE_KEY_LEN, compute_v7_node_key, hamt_node_v7_aad,
};
use crate::symmetric::{Aead, AeadCipher, Nonce};
use crate::{CryptoError, Result};
use cid::Cid;
use std::sync::Arc;

// The content-addressed key width used by the vendored HAMT and the v7
// manifest must stay identical — parent nodes store children as
// `StorageKey`, while the manifest stores shard roots as `V7StorageKey`.
// A compile-time check keeps a future drift from silently corrupting one
// layer or the other.
const _: () = assert!(V7_STORAGE_KEY_LEN == STORAGE_KEY_LEN);

/// Object-path prefix for v7 HAMT node blobs in the backing store.
pub const V7_NODE_PREFIX: &str = "__fula_forest_v7_nodes/";

/// On-the-wire layout for an encrypted v7 node blob.
///
/// Format: `nonce (12B) || ciphertext+tag (N+16 B)`. The nonce is stored
/// inline with the ciphertext — the content-addressed key derives from the
/// *plaintext*, so different encryptions of the same plaintext (different
/// nonces) still map to the same storage key, preserving dedup.
const NONCE_LEN: usize = 12;

/// Outcome of [`BlobBackend::put`] (walkable-v8 / W.9.2).
///
/// `cid` is the content-address the backend reports for the ciphertext that
/// was just persisted. `Some(_)` when the backend exposes one (e.g. master S3
/// returns it as the `ETag` header on PUT 200), `None` for backends that
/// don't (in-memory test backends, bench backends) or when the etag failed
/// to parse as a CID. **CID parse failure is always a soft-fail to `None`,
/// never an error**: the PUT itself succeeded; the offline-walk hint just
/// isn't available, and the v7 storage-key path serves the read.
///
/// Future-extension point: more fields can be added without breaking the
/// trait surface (e.g. a `version_id` for backends with versioning).
#[derive(Debug, Clone)]
pub struct BlobPutResult {
    pub cid: Option<Cid>,
}

impl BlobPutResult {
    /// Construct a result that carries no CID hint. Suitable for in-memory
    /// or test backends that have no notion of a master-stamped etag.
    pub fn none() -> Self {
        Self { cid: None }
    }

    /// Construct a result with a known CID. Currently unused (W.9.2 PUT
    /// impls direct-construct via `BlobPutResult { cid }` because they
    /// already have an `Option<Cid>` from `etag.parse().ok()`). Retained
    /// for W.9.3+ writer integration where `BlobBackend` impls that
    /// always have a definite CID (e.g. an in-memory backend that
    /// computes the ciphertext CID locally for tests) can call this
    /// directly instead of going through `Some(_)`.
    #[allow(dead_code)]
    pub fn with_cid(cid: Cid) -> Self {
        Self { cid: Some(cid) }
    }
}

/// Minimal storage-backend interface used by [`V7NodeStore`].
///
/// Implementors provide opaque get/put by path. All crypto (AEAD + content
/// addressing) lives in `V7NodeStore` and is backend-independent.
///
/// `put` is unconditional (last-write-wins). Because the path is derived from
/// the plaintext hash, two honest writers producing the same plaintext will
/// write identical objects — conflict resolution for v7 always lives at the
/// manifest ETag level, never per node.
///
/// `put` returns a [`BlobPutResult`]; the `cid` field carries the master's
/// PUT-response ETag parsed as a [`Cid`] for walkable-v8. Backends that
/// don't have a CID (test, bench) return `BlobPutResult::none()`.
///
/// **Walkable-v8 (W.9.4) — `get_with_cid_hint`**: the cid-hint variant lets
/// a caller that learned a child's `Cid` from a parent's `PointerWire::LinkV2`
/// plaintext request the same bytes via the offline-aware path: when the
/// backend is master-aware (e.g. `S3BlobBackend`), this routes through the
/// gateway race so a master-down bucket walk continues over public IPFS.
/// The default impl ignores the hint and delegates to [`get`] — backends
/// that don't have a master/gateway distinction (in-memory test backends)
/// keep the simpler `get` semantics. The hint is **advisory**: callers
/// must NOT skip subsequent integrity checks (AEAD + storage_key recompute)
/// just because a CID was supplied — those layers defend against parent-
/// pointer manipulation independently of the gateway content-address check.
#[cfg(not(target_arch = "wasm32"))]
#[async_trait::async_trait]
pub trait BlobBackend: Send + Sync {
    async fn get(&self, path: &str) -> Result<Vec<u8>>;
    async fn put(&self, path: &str, bytes: Vec<u8>) -> Result<BlobPutResult>;

    /// Walkable-v8 (W.9.4) — fetch with an optional content-address
    /// hint. Default impl ignores the hint and falls through to [`get`];
    /// `S3BlobBackend` overrides to use the cold-cache gateway-race
    /// fallback when `cid_hint` is `Some` and master is unreachable.
    async fn get_with_cid_hint(
        &self,
        path: &str,
        _cid_hint: Option<&Cid>,
    ) -> Result<Vec<u8>> {
        self.get(path).await
    }
}

#[cfg(target_arch = "wasm32")]
#[async_trait::async_trait(?Send)]
pub trait BlobBackend {
    async fn get(&self, path: &str) -> Result<Vec<u8>>;
    async fn put(&self, path: &str, bytes: Vec<u8>) -> Result<BlobPutResult>;

    /// Walkable-v8 (W.9.4) — fetch with an optional content-address
    /// hint. Default impl ignores the hint and falls through to [`get`].
    /// On wasm32 the offline-fallback infrastructure (block_cache +
    /// gateway race) is gated out, so the override on `S3BlobBackend`
    /// is currently a thin no-op delegate; the trait surface stays
    /// symmetric across targets so cross-target call sites compile
    /// without `cfg` gating.
    async fn get_with_cid_hint(
        &self,
        path: &str,
        _cid_hint: Option<&Cid>,
    ) -> Result<Vec<u8>> {
        self.get(path).await
    }
}

/// AEAD-encrypted, content-addressed node store for a v7 shard.
///
/// The AAD binds `(bucket, shard_idx)` only. `shard_seq` is *not* bound —
/// HAMT flushes are path-of-change, so seq-bound AAD would strand ciphertexts
/// in untouched subtrees on the next flush. Replay resistance for shard root
/// swaps lives at the manifest layer (ETag + `manifest.shards[i].seq`), and
/// forgery-resistance for a given node comes from content-addressing the
/// plaintext under `BLAKE3(bucket_salt ‖ plaintext)[..22]`.
///
/// Fields are kept minimal and all of them participate in integrity checks:
///   * `bucket`, `shard_idx` feed the per-node AAD.
///   * `bucket_salt` feeds the content-address hash.
///   * `shard_dek` is the AEAD key (the same DEK that wraps the shard manifest).
///   * `inner` is the byte backend; does no crypto of its own.
pub struct V7NodeStore<B: BlobBackend> {
    bucket: String,
    shard_idx: u16,
    bucket_salt: Vec<u8>,
    shard_dek: DekKey,
    inner: Arc<B>,
}

impl<B: BlobBackend> V7NodeStore<B> {
    /// Construct a node store for a given shard.
    ///
    /// The same constructor is used by both writers and readers — there is no
    /// per-flush seq binding at this layer, so a reader can be built with
    /// `(bucket, shard_idx, bucket_salt, shard_dek)` and successfully read
    /// every node ever written to the shard under the current DEK.
    pub fn new(
        bucket: impl Into<String>,
        shard_idx: u16,
        bucket_salt: Vec<u8>,
        shard_dek: DekKey,
        inner: Arc<B>,
    ) -> Self {
        Self {
            bucket: bucket.into(),
            shard_idx,
            bucket_salt,
            shard_dek,
            inner,
        }
    }

    /// Object path for a content-addressed node key.
    fn object_path(key: &StorageKey) -> String {
        let mut s = String::with_capacity(V7_NODE_PREFIX.len() + key.len() * 2);
        s.push_str(V7_NODE_PREFIX);
        s.push_str(&hex::encode(key));
        s
    }

    fn aad(&self) -> Vec<u8> {
        hamt_node_v7_aad(&self.bucket, self.shard_idx)
    }
}

impl<B: BlobBackend + 'static> V7NodeStore<B> {
    /// Walkable-v8 (W.9.4) — shared decrypt + integrity-check pipeline used
    /// by both `get_node` and `get_node_with_cid_hint`. Centralised here so
    /// the offline cid-hint variant cannot accidentally drop the
    /// `recomputed == key` check that defends against parent-pointer
    /// manipulation (the third integrity layer per advisor design notes).
    ///
    /// Three layers, all enforced regardless of which `BlobBackend.get*`
    /// variant supplied `blob`:
    ///   1. AEAD decrypt under shard DEK with `(bucket, shard_idx)` AAD —
    ///      defends cross-bucket / cross-shard replay.
    ///   2. Recompute `BLAKE3(bucket_salt ‖ plaintext)[..22]` and compare
    ///      to the caller-supplied `key` — defends a redirect where the
    ///      gateway returns valid-CID bytes whose plaintext addresses a
    ///      DIFFERENT storage_key than the parent's pointer claimed.
    ///   3. (Out of this function: gateway content-address verify happens
    ///      inside `get_object_with_offline_fallback_known_cid`.)
    fn decrypt_and_verify(
        &self,
        key: &StorageKey,
        blob: Vec<u8>,
    ) -> Result<HamtNodeBytes> {
        if blob.len() < NONCE_LEN {
            return Err(CryptoError::Decryption(
                "v7 node blob shorter than nonce".into(),
            ));
        }
        let (nonce_bytes, ciphertext) = blob.split_at(NONCE_LEN);
        let nonce = Nonce::from_bytes(nonce_bytes)?;
        let aad = self.aad();
        let aead = Aead::new(&self.shard_dek, AeadCipher::ChaCha20Poly1305);
        let plaintext = aead.decrypt_with_aad(&nonce, ciphertext, &aad)?;

        // Belt-and-suspenders: AEAD already authenticated the ciphertext
        // against AAD, but re-derive the content hash from the plaintext to
        // catch any path/key mix-up in the caller — and, on the cid-hint
        // path, to reject a malicious parent that pointed at the right
        // cid but the wrong storage_key.
        let recomputed = compute_v7_node_key(&self.bucket_salt, &plaintext);
        if recomputed.as_slice() != key.as_slice() {
            return Err(CryptoError::Hamt(
                "v7 node content-address mismatch".into(),
            ));
        }
        Ok(plaintext)
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[async_trait::async_trait]
impl<B: BlobBackend + 'static> HamtNodeStore for V7NodeStore<B> {
    async fn get_node(&self, key: &StorageKey) -> Result<HamtNodeBytes> {
        let path = Self::object_path(key);
        let blob = self.inner.get(&path).await?;
        self.decrypt_and_verify(key, blob)
    }

    /// Walkable-v8 (W.9.4) — forward `cid_hint` to the backing
    /// `BlobBackend::get_with_cid_hint` so the offline gateway race
    /// engages when master is unreachable, then run the same
    /// `decrypt_and_verify` pipeline as `get_node`. The `recomputed
    /// == key` check is preserved verbatim — a malicious parent
    /// pointing at `LinkV2 { storage_key: A, cid: hash_of_B }` would
    /// pass the gateway content-address check (bytes hash to the
    /// supplied cid) but fail at this layer (plaintext hashes to B,
    /// not the requested A).
    async fn get_node_with_cid_hint(
        &self,
        key: &StorageKey,
        cid_hint: Option<&Cid>,
    ) -> Result<HamtNodeBytes> {
        let path = Self::object_path(key);
        let blob = self.inner.get_with_cid_hint(&path, cid_hint).await?;
        self.decrypt_and_verify(key, blob)
    }

    async fn put_node(&self, bytes: HamtNodeBytes) -> Result<NodePutResult> {
        let key_v7: V7StorageKey = compute_v7_node_key(&self.bucket_salt, &bytes);
        // V7StorageKey and StorageKey are both [u8; 22]; asserted by construction.
        let key: StorageKey = key_v7;
        let nonce = Nonce::generate();
        let aad = self.aad();
        let aead = Aead::new(&self.shard_dek, AeadCipher::ChaCha20Poly1305);
        let ciphertext = aead.encrypt_with_aad(&nonce, &bytes, &aad)?;

        let mut blob = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        blob.extend_from_slice(nonce.as_bytes());
        blob.extend_from_slice(&ciphertext);

        let path = Self::object_path(&key);
        let put_result = self.inner.put(&path, blob).await?;
        Ok(NodePutResult { storage_key: key, cid: put_result.cid })
    }
}

#[cfg(target_arch = "wasm32")]
#[async_trait::async_trait(?Send)]
impl<B: BlobBackend + 'static> HamtNodeStore for V7NodeStore<B> {
    async fn get_node(&self, key: &StorageKey) -> Result<HamtNodeBytes> {
        let path = Self::object_path(key);
        let blob = self.inner.get(&path).await?;
        self.decrypt_and_verify(key, blob)
    }

    async fn get_node_with_cid_hint(
        &self,
        key: &StorageKey,
        cid_hint: Option<&Cid>,
    ) -> Result<HamtNodeBytes> {
        let path = Self::object_path(key);
        let blob = self.inner.get_with_cid_hint(&path, cid_hint).await?;
        self.decrypt_and_verify(key, blob)
    }

    async fn put_node(&self, bytes: HamtNodeBytes) -> Result<NodePutResult> {
        let key_v7: V7StorageKey = compute_v7_node_key(&self.bucket_salt, &bytes);
        let key: StorageKey = key_v7;
        let nonce = Nonce::generate();
        let aad = self.aad();
        let aead = Aead::new(&self.shard_dek, AeadCipher::ChaCha20Poly1305);
        let ciphertext = aead.encrypt_with_aad(&nonce, &bytes, &aad)?;

        let mut blob = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        blob.extend_from_slice(nonce.as_bytes());
        blob.extend_from_slice(&ciphertext);

        let path = Self::object_path(&key);
        let put_result = self.inner.put(&path, blob).await?;
        Ok(NodePutResult { storage_key: key, cid: put_result.cid })
    }
}

/// Test-only in-memory `BlobBackend` shared across `fula-crypto` test modules.
///
/// Moved out of the v7_store test submodule so the higher-level
/// `sharded_hamt_forest` tests can exercise the v7 engine end-to-end without
/// reinventing a backend or pulling in the encrypted client storage.
#[cfg(test)]
pub(crate) struct InMemoryBackend {
    objects: std::sync::Mutex<std::collections::HashMap<String, Vec<u8>>>,
}

#[cfg(test)]
impl InMemoryBackend {
    pub(crate) fn new() -> Self {
        Self {
            objects: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    pub(crate) fn get_sync(&self, path: &str) -> Option<Vec<u8>> {
        self.objects.lock().unwrap().get(path).cloned()
    }

    pub(crate) fn overwrite_sync(&self, path: &str, bytes: Vec<u8>) {
        self.objects
            .lock()
            .unwrap()
            .insert(path.to_string(), bytes);
    }

    pub(crate) fn object_count(&self) -> usize {
        self.objects.lock().unwrap().len()
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
#[async_trait::async_trait]
impl BlobBackend for InMemoryBackend {
    async fn get(&self, path: &str) -> Result<Vec<u8>> {
        self.objects
            .lock()
            .unwrap()
            .get(path)
            .cloned()
            .ok_or_else(|| CryptoError::Hamt(format!("object not found: {}", path)))
    }

    async fn put(&self, path: &str, bytes: Vec<u8>) -> Result<BlobPutResult> {
        self.objects
            .lock()
            .unwrap()
            .insert(path.to_string(), bytes);
        // In-memory backend does not have a master-stamped etag; v8 readers
        // see `cid: None` and fall through to the storage_key path.
        Ok(BlobPutResult::none())
    }
}

#[cfg(all(test, target_arch = "wasm32"))]
#[async_trait::async_trait(?Send)]
impl BlobBackend for InMemoryBackend {
    async fn get(&self, path: &str) -> Result<Vec<u8>> {
        self.objects
            .lock()
            .unwrap()
            .get(path)
            .cloned()
            .ok_or_else(|| CryptoError::Hamt(format!("object not found: {}", path)))
    }

    async fn put(&self, path: &str, bytes: Vec<u8>) -> Result<BlobPutResult> {
        self.objects
            .lock()
            .unwrap()
            .insert(path.to_string(), bytes);
        // In-memory backend does not have a master-stamped etag; v8 readers
        // see `cid: None` and fall through to the storage_key path.
        Ok(BlobPutResult::none())
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use crate::hashing::Blake3Hasher;
    use crate::wnfs_hamt::node::Node;

    fn test_dek() -> DekKey {
        DekKey::from_bytes(&[0x42u8; 32]).unwrap()
    }

    fn test_salt() -> Vec<u8> {
        vec![0xAB; 16]
    }

    type TestNode = Node<Vec<u8>, u64, Blake3Hasher>;

    #[tokio::test]
    async fn round_trip_store_load_through_v7_node_store() {
        let backend = Arc::new(InMemoryBackend::new());
        let store = V7NodeStore::new(
            "bucket-alpha",
            /* shard_idx = */ 0x1234,
            test_salt(),
            test_dek(),
            backend.clone(),
        );

        let mut root: Arc<TestNode> = Arc::new(TestNode::default());
        for i in 0u64..20u64 {
            let k = format!("key-{:03}", i).into_bytes();
            root.set(k, i, &store).await.unwrap();
        }

        let root_key = root.store(&store).await.unwrap().storage_key;

        // Load from a freshly-constructed store (simulates a separate reader
        // on the same bucket/shard) and confirm every entry.
        let reader_store = V7NodeStore::new(
            "bucket-alpha",
            0x1234,
            test_salt(),
            test_dek(),
            backend.clone(),
        );
        let loaded: TestNode = TestNode::load(&root_key, &reader_store).await.unwrap();

        for i in 0u64..20u64 {
            let k = format!("key-{:03}", i).into_bytes();
            let v = loaded.get(&k, &reader_store).await.unwrap();
            assert_eq!(v, Some(i));
        }
    }

    #[tokio::test]
    async fn put_node_is_content_addressed_and_deterministic() {
        let backend = Arc::new(InMemoryBackend::new());
        let store = V7NodeStore::new(
            "b",
            0,
            test_salt(),
            test_dek(),
            backend.clone(),
        );

        let plaintext: Vec<u8> = (0..64u8).collect();
        let key1 = store.put_node(plaintext.clone()).await.unwrap().storage_key;
        let key2 = store.put_node(plaintext.clone()).await.unwrap().storage_key;
        assert_eq!(key1, key2, "content-addressed key must be deterministic");

        // The nonce is random → ciphertext differs, but the stored path is
        // the same, so the second write just overwrites the first.
        let path = V7NodeStore::<InMemoryBackend>::object_path(&key1);
        assert!(backend.get_sync(&path).is_some());
    }

    #[tokio::test]
    async fn get_node_rejects_wrong_shard_idx() {
        let backend = Arc::new(InMemoryBackend::new());
        let writer = V7NodeStore::new(
            "b",
            /* shard_idx = */ 5,
            test_salt(),
            test_dek(),
            backend.clone(),
        );
        let plaintext = b"payload".to_vec();
        let key = writer.put_node(plaintext.clone()).await.unwrap().storage_key;

        // A reader that mislabels the shard index must fail AEAD.
        let wrong_shard = V7NodeStore::new(
            "b",
            /* shard_idx = */ 6,
            test_salt(),
            test_dek(),
            backend.clone(),
        );
        assert!(wrong_shard.get_node(&key).await.is_err());
    }

    #[tokio::test]
    async fn get_node_rejects_wrong_bucket() {
        let backend = Arc::new(InMemoryBackend::new());
        let writer = V7NodeStore::new(
            "bucket-a",
            0,
            test_salt(),
            test_dek(),
            backend.clone(),
        );
        let key = writer.put_node(b"payload".to_vec()).await.unwrap().storage_key;

        let wrong_bucket = V7NodeStore::new(
            "bucket-b",
            0,
            test_salt(),
            test_dek(),
            backend.clone(),
        );
        assert!(wrong_bucket.get_node(&key).await.is_err());
    }

    #[tokio::test]
    async fn get_node_rejects_tampered_blob() {
        let backend = Arc::new(InMemoryBackend::new());
        let store = V7NodeStore::new(
            "b",
            0,
            test_salt(),
            test_dek(),
            backend.clone(),
        );
        let key = store.put_node(b"untampered".to_vec()).await.unwrap().storage_key;

        // Flip one byte in the ciphertext region (past the 12-byte nonce).
        let path = V7NodeStore::<InMemoryBackend>::object_path(&key);
        let mut blob = backend.get_sync(&path).unwrap();
        let idx = NONCE_LEN + 2;
        blob[idx] ^= 0xFF;
        backend.overwrite_sync(&path, blob);

        assert!(store.get_node(&key).await.is_err());
    }
}
