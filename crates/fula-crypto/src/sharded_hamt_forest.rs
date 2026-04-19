// v7 sharded-HAMT forest: mutation engine on top of `wnfs_hamt::Node`.
//
// This module owns the pure, backend-agnostic logic for upsert/remove/get/
// list and copy-on-write flush of a v7 forest. It composes over the vendored
// HAMT tree (`crate::wnfs_hamt::Node`) and the AEAD-encrypted node store
// (`crate::wnfs_hamt::V7NodeStore`); the only concrete I/O dependency is the
// `BlobBackend` trait, which fula-client supplies at runtime and our tests
// supply as an in-memory map.
//
// Key layout inside a shard's HAMT:
//   * File entries use key `b"F:" ‖ path.as_bytes()` → `HamtEntry::File`.
//   * Directory entries use key `b"D:" ‖ path.as_bytes()` → `HamtEntry::Dir`.
//   * Values are stored together in one HAMT so that `list_directory` can be
//     serviced by a `get(b"D:"‖dir)` + k parallel `get(b"F:"‖child)` hops in
//     *one* shard (dir-local routing guarantees this), rather than walking
//     every leaf — the core scalability win of the v7 design.
//
// Scope of this file:
//   * Types: `HamtEntry`, `LoadedShard`, `ShardedHamtPrivateForest`.
//   * Operations: `upsert_file`, `remove_file`, `get_file`, `list_directory`,
//     `flush_dirty`.
//   * Explicitly NOT covered here (belongs to fula-client or a later phase):
//     - Manifest encryption / PUT with conditional ETag
//     - WAL integration
//     - `list_all_files` / full-bucket enumeration
//     - Garbage collection of latent empty-directory `D:` entries left by
//       `remove_file` (matches v1's asymmetric ensure-on-upsert /
//       don't-prune-on-remove contract; a separate GC pass is a future phase).
//
// See plan: /root/.claude/plans/do-a-thorough-line-cheeky-taco.md
// (section: "Integration points in fula" and "Design addition for v7").

use crate::hashing::Blake3Hasher;
use crate::keys::DekKey;
use crate::private_forest::{
    ForestDirectoryEntry, ForestFileEntry, PrivateForest, ShardManifestV7, shard_for_path_v6,
};
use crate::subtree_keys::EncryptedSubtreeDek;
use crate::wnfs_hamt::{BlobBackend, V7NodeStore};
use crate::{CryptoError, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

// `Node` / `Pair` are crate-private today; re-export inside this module for brevity.
use crate::wnfs_hamt::node::Node;
use crate::wnfs_hamt::pointer::Pair;

/// Either a file or a directory entry stored in a shard's HAMT.
///
/// The flat HAMT key is type-tagged (`b"F:"` / `b"D:"`) so a bare `path`
/// collision between a file and a directory is impossible — they hash to
/// different nibble paths.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum HamtEntry {
    /// File metadata entry.
    File(ForestFileEntry),
    /// Directory metadata entry (child paths, metadata, subtree DEK).
    Dir(ForestDirectoryEntry),
}

// ----- Wire types ------------------------------------------------------------
//
// The public `HamtEntry` is defined above with the real `ForestFileEntry` /
// `ForestDirectoryEntry` types, but those carry serde attributes that are
// incompatible with postcard's strict wire format:
//   * `ForestDirectoryEntry.subtree_dek` uses
//     `#[serde(skip_serializing_if = "Option::is_none")]`, which emits
//     nothing for `None` — postcard always expects an `Option` discriminant.
//   * `ForestFileEntry.user_metadata` is a `HashMap<String,String>`; HashMap
//     iteration order is not guaranteed to be stable, which would break the
//     content-addressed storage key (two logically-equal entries could hash
//     to different node blobs across serializations).
//
// The wire types mirror the field set but use `BTreeMap` for stable key
// ordering and drop the `skip_serializing_if` attribute, making them safe
// to postcard-serialize as the HAMT value type. Conversion happens only at
// the `upsert_file` / `get_file` boundaries.

#[derive(Clone, Debug, Serialize, Deserialize)]
enum HamtEntryWire {
    File(FileEntryWire),
    Dir(DirEntryWire),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct FileEntryWire {
    path: String,
    storage_key: String,
    size: u64,
    content_type: Option<String>,
    created_at: i64,
    modified_at: i64,
    content_hash: Option<String>,
    user_metadata: BTreeMap<String, String>,
    encrypted: bool,
    /// Minimum blob-format version for this entry (H-2). `0` = legacy,
    /// `4` = written under AAD-bound v4 encryption and requires the
    /// download path to reject lower advertised versions. `#[serde(default)]`
    /// keeps wire compatibility with pre-H-2 shard blobs that lack the
    /// field — postcard's strict decoder will fail without this attribute.
    #[serde(default)]
    min_version: u8,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct DirEntryWire {
    path: String,
    files: Vec<String>,
    subdirs: Vec<String>,
    metadata: Option<BTreeMap<String, String>>,
    subtree_dek: Option<EncryptedSubtreeDek>,
}

impl From<ForestFileEntry> for FileEntryWire {
    fn from(e: ForestFileEntry) -> Self {
        Self {
            path: e.path,
            storage_key: e.storage_key,
            size: e.size,
            content_type: e.content_type,
            created_at: e.created_at,
            modified_at: e.modified_at,
            content_hash: e.content_hash,
            user_metadata: e.user_metadata.into_iter().collect(),
            encrypted: e.encrypted,
            min_version: e.min_version,
        }
    }
}

impl From<FileEntryWire> for ForestFileEntry {
    fn from(w: FileEntryWire) -> Self {
        Self {
            path: w.path,
            storage_key: w.storage_key,
            size: w.size,
            content_type: w.content_type,
            created_at: w.created_at,
            modified_at: w.modified_at,
            content_hash: w.content_hash,
            user_metadata: w.user_metadata.into_iter().collect::<HashMap<_, _>>(),
            encrypted: w.encrypted,
            min_version: w.min_version,
        }
    }
}

impl From<ForestDirectoryEntry> for DirEntryWire {
    fn from(e: ForestDirectoryEntry) -> Self {
        Self {
            path: e.path,
            files: e.files,
            subdirs: e.subdirs,
            metadata: e.metadata.map(|m| m.into_iter().collect()),
            subtree_dek: e.subtree_dek,
        }
    }
}

impl From<DirEntryWire> for ForestDirectoryEntry {
    fn from(w: DirEntryWire) -> Self {
        Self {
            path: w.path,
            files: w.files,
            subdirs: w.subdirs,
            metadata: w
                .metadata
                .map(|m| m.into_iter().collect::<HashMap<_, _>>()),
            subtree_dek: w.subtree_dek,
        }
    }
}

impl From<HamtEntry> for HamtEntryWire {
    fn from(e: HamtEntry) -> Self {
        match e {
            HamtEntry::File(f) => HamtEntryWire::File(f.into()),
            HamtEntry::Dir(d) => HamtEntryWire::Dir(d.into()),
        }
    }
}

impl From<HamtEntryWire> for HamtEntry {
    fn from(w: HamtEntryWire) -> Self {
        match w {
            HamtEntryWire::File(f) => HamtEntry::File(f.into()),
            HamtEntryWire::Dir(d) => HamtEntry::Dir(d.into()),
        }
    }
}

/// Type-tag prefix for file keys in the HAMT.
const FILE_KEY_PREFIX: &[u8] = b"F:";
/// Type-tag prefix for directory keys in the HAMT.
const DIR_KEY_PREFIX: &[u8] = b"D:";

/// Build the HAMT key for a file path.
fn file_key(path: &str) -> Vec<u8> {
    let mut k = Vec::with_capacity(FILE_KEY_PREFIX.len() + path.len());
    k.extend_from_slice(FILE_KEY_PREFIX);
    k.extend_from_slice(path.as_bytes());
    k
}

/// Build the HAMT key for a directory path.
fn dir_key(path: &str) -> Vec<u8> {
    let mut k = Vec::with_capacity(DIR_KEY_PREFIX.len() + path.len());
    k.extend_from_slice(DIR_KEY_PREFIX);
    k.extend_from_slice(path.as_bytes());
    k
}

/// Normalize a directory path (strip trailing slash except for root; ensure
/// leading slash). Matches `PrivateForest::normalize_dir_path`.
fn normalize_dir_path(dir_path: &str) -> String {
    if dir_path.is_empty() || dir_path == "/" {
        return "/".to_string();
    }
    let trimmed = dir_path.trim_end_matches('/');
    if trimmed.starts_with('/') {
        trimmed.to_string()
    } else {
        format!("/{}", trimmed)
    }
}

/// Return the normalized parent directory of a file path.
fn parent_dir_of(file_path: &str) -> String {
    match file_path.rfind('/') {
        Some(0) => "/".to_string(),
        Some(idx) => file_path[..idx].to_string(),
        None => "/".to_string(),
    }
}

/// Return the parent directory of a *directory* path, or `None` if the
/// argument is the root. Input is assumed to be a normalized dir path:
/// `/a/b` → `Some("/a")`; `/a` → `Some("/")`; `/` → `None`.
fn dir_parent_of(dir: &str) -> Option<String> {
    if dir == "/" {
        return None;
    }
    match dir.rfind('/') {
        Some(0) => Some("/".to_string()),
        Some(idx) => Some(dir[..idx].to_string()),
        None => Some("/".to_string()),
    }
}

/// Routing-shape for a directory path so it lands in the same shard as its
/// direct children. Files hash `parent_dir_for_routing(file)` which ends in
/// `/`; directories need to hash `dir + "/"` to match.
fn dir_routing_path(dir_path: &str) -> String {
    if dir_path == "/" || dir_path.ends_with('/') {
        dir_path.to_string()
    } else {
        format!("{}/", dir_path)
    }
}

/// Per-shard HAMT, in the three states needed to distinguish "have not
/// touched the object store yet" from "touched, found empty" from "touched,
/// loaded a root". The middle state matters because it flips from
/// `NotLoaded` → `LoadedEmpty` without any network I/O, and subsequent reads
/// can short-circuit without retrying.
#[derive(Debug)]
enum LoadedShard {
    /// The shard root (per the manifest) has not been materialized yet.
    NotLoaded,
    /// Manifest said `root = None` — the HAMT is conceptually an empty tree.
    /// Mutations promote to `Loaded` on first write.
    LoadedEmpty,
    /// In-memory HAMT root, possibly with `ChildPtr::Stored` links that
    /// still need to be resolved lazily via the backend on access.
    Loaded(Arc<ForestHamt>),
}

/// Concrete HAMT type used by the sharded forest (monomorphizes `Node` over
/// the forest's `K`/`V`/`H` choices).
///
/// `V` is the postcard-safe wire type; conversion to the public `HamtEntry`
/// happens only at the API boundary (upsert/get/list).
type ForestHamt = Node<Vec<u8>, HamtEntryWire, Blake3Hasher>;

/// In-memory working state for a v7 forest bucket.
///
/// Holds the decrypted manifest plus one lazily-loaded HAMT per shard. Not
/// serializable by itself — the serializable artifact is the `ShardManifestV7`
/// handed back by `flush_dirty`, which the caller encrypts and PUTs under
/// its conditional-write contract (out of scope for this module).
pub struct ShardedHamtPrivateForest {
    manifest: ShardManifestV7,
    // Per-shard lazy-load cache. Wrapping each slot in its own RwLock is what
    // lets the public read API (`get_file`, `list_recursive`, …) take `&self`
    // instead of `&mut self`: the only mutation a read path needs is
    // `NotLoaded → {LoadedEmpty | Loaded}` on first access, and that mutation
    // is per-slot so reads against distinct shards never contend.
    //
    // Closes F6 (forest lock held across await) when callers put this
    // forest behind an async `RwLock` and call `.read().await` on the
    // read path: many concurrent readers can then proceed in parallel rather
    // than serialising through one outer `Mutex`.
    //
    // Uses `async_lock::RwLock` (tokio-free) so the crate stays wasm-clean
    // when the `tokio-runtime` feature is disabled.
    loaded_shards: Vec<async_lock::RwLock<LoadedShard>>,
    dirty_shards: Vec<bool>,
    forest_dek: DekKey,
    bucket: String,
}

impl ShardedHamtPrivateForest {
    /// Wrap an existing manifest (e.g. decrypted from storage) for in-memory
    /// mutation. All shards start as `NotLoaded` and are materialized on
    /// first access.
    pub fn from_manifest(
        manifest: ShardManifestV7,
        bucket: impl Into<String>,
        forest_dek: DekKey,
    ) -> Self {
        let num = manifest.num_shards;
        Self {
            manifest,
            loaded_shards: (0..num)
                .map(|_| async_lock::RwLock::new(LoadedShard::NotLoaded))
                .collect(),
            dirty_shards: vec![false; num],
            forest_dek,
            bucket: bucket.into(),
        }
    }

    /// Create a brand-new empty forest with `num_shards` empty HAMT roots.
    /// Rounded up to the next power of two and clamped by
    /// `ShardManifestV7::new`.
    pub fn new(
        bucket: impl Into<String>,
        forest_dek: DekKey,
        num_shards: usize,
    ) -> Self {
        let manifest = ShardManifestV7::new(num_shards);
        let actual_num = manifest.num_shards;
        Self {
            manifest,
            // Brand-new shards are known-empty — no need to go through a
            // `NotLoaded → LoadedEmpty` transition that would query the
            // backend for objects that cannot exist yet.
            loaded_shards: (0..actual_num)
                .map(|_| async_lock::RwLock::new(LoadedShard::LoadedEmpty))
                .collect(),
            dirty_shards: vec![false; actual_num],
            forest_dek,
            bucket: bucket.into(),
        }
    }

    /// Immutable reference to the manifest — callers needing the bytes to
    /// encrypt and PUT should flush first, then call this.
    pub fn manifest(&self) -> &ShardManifestV7 {
        &self.manifest
    }

    /// Bucket identifier (used for AAD). Immutable for the life of this
    /// value.
    pub fn bucket(&self) -> &str {
        &self.bucket
    }

    /// DEK (forest-level) — exposed so the caller can encrypt the manifest
    /// in the same key hierarchy without re-deriving.
    pub fn forest_dek(&self) -> &DekKey {
        &self.forest_dek
    }

    /// True if any shard has uncommitted in-memory mutations.
    pub fn is_dirty(&self) -> bool {
        self.dirty_shards.iter().any(|d| *d)
    }

    /// Indices of shards with uncommitted mutations — sorted ascending.
    pub fn dirty_shard_indices(&self) -> Vec<usize> {
        self.dirty_shards
            .iter()
            .enumerate()
            .filter_map(|(i, d)| if *d { Some(i) } else { None })
            .collect()
    }

    /// Total entry count (files + directories) across all shards. O(num_shards).
    ///
    /// Includes latent empty `D:` entries left by `remove_file` — v7 matches
    /// v1's asymmetric contract where `upsert_file` populates the ancestor
    /// chain via `ensure_ancestor_chain` but `remove_file` does not prune
    /// empty dirs. Suitable for reshard-decision accounting; callers that
    /// need a user-facing file count should enumerate and filter to
    /// `HamtEntry::File`.
    pub fn entry_count(&self) -> u64 {
        self.manifest.entry_count()
    }

    /// Route a file path to its owning shard using the v6 dir-local scheme.
    fn shard_for_file(&self, file_path: &str) -> usize {
        shard_for_path_v6(
            file_path,
            &self.forest_dek,
            &self.manifest.shard_salt,
            self.manifest.num_shards,
        )
    }

    /// Route a directory path to the shard its children live in, by
    /// re-shaping to the trailing-slash form that `parent_dir_for_routing`
    /// returns for files.
    fn shard_for_dir(&self, dir_path: &str) -> usize {
        let routing = dir_routing_path(dir_path);
        shard_for_path_v6(
            &routing,
            &self.forest_dek,
            &self.manifest.shard_salt,
            self.manifest.num_shards,
        )
    }

    /// Build the per-shard node store used for reads and writes.
    ///
    /// The store binds `(bucket, shard_idx)` into node AAD. `shard_seq` is
    /// deliberately absent from node AAD — HAMT flushes only rewrite nodes on
    /// the path of change, so a seq-bound AAD would invalidate untouched
    /// subtree ciphertexts on every flush. Replay protection for shard root
    /// swaps lives at the manifest layer (ETag + `manifest.shards[i].seq`).
    fn reader_store_for<B: BlobBackend + 'static>(
        &self,
        shard_idx: usize,
        backend: &Arc<B>,
    ) -> V7NodeStore<B> {
        V7NodeStore::new(
            self.bucket.clone(),
            shard_idx as u16,
            self.manifest.shard_salt.clone(),
            self.forest_dek.clone(),
            backend.clone(),
        )
    }

    /// Materialize a shard's root if not already loaded. Idempotent; a
    /// manifest with `root = None` resolves to `LoadedEmpty` without any
    /// backend traffic.
    ///
    /// Takes `&self` (not `&mut self`) so read-only callers can invoke it
    /// without forcing the whole forest behind an exclusive lock. Uses a
    /// fast-path `.read()` check to skip the load when a concurrent caller
    /// has already materialized the shard, then a double-checked `.write()`
    /// to avoid racing two loaders on the same NotLoaded shard.
    async fn ensure_shard_loaded<B: BlobBackend + 'static>(
        &self,
        shard_idx: usize,
        backend: &Arc<B>,
    ) -> Result<()> {
        // Fast path: shard is already resolved (LoadedEmpty or Loaded).
        if !matches!(*self.loaded_shards[shard_idx].read().await, LoadedShard::NotLoaded) {
            return Ok(());
        }
        // Slow path: take the shard's write lock, re-check, then load. The
        // re-check handles the case where another task transitioned
        // NotLoaded → Loaded while we were waiting for the write lock.
        let mut guard = self.loaded_shards[shard_idx].write().await;
        if !matches!(&*guard, LoadedShard::NotLoaded) {
            return Ok(());
        }
        match self.manifest.shards[shard_idx].root {
            None => {
                *guard = LoadedShard::LoadedEmpty;
            }
            Some(root_key) => {
                let store = self.reader_store_for(shard_idx, backend);
                let node: ForestHamt = Node::load(&root_key, &store).await?;
                *guard = LoadedShard::Loaded(Arc::new(node));
            }
        }
        Ok(())
    }

    /// Take ownership of (or create) the in-memory root for writing. Leaves
    /// the slot temporarily as `NotLoaded` — the caller MUST reinstall the
    /// returned Arc (possibly mutated via `Arc::make_mut` inside `Node::set`)
    /// via `install_loaded_root_into` before the guard drops.
    fn take_loaded_root_from(guard: &mut LoadedShard) -> Arc<ForestHamt> {
        match std::mem::replace(guard, LoadedShard::NotLoaded) {
            LoadedShard::NotLoaded => {
                unreachable!("callers must ensure_shard_loaded before take_loaded_root")
            }
            LoadedShard::LoadedEmpty => Arc::new(ForestHamt::default()),
            LoadedShard::Loaded(node) => node,
        }
    }

    /// Reinstall a shard root after mutation.
    fn install_loaded_root_into(guard: &mut LoadedShard, node: Arc<ForestHamt>) {
        *guard = LoadedShard::Loaded(node);
    }

    /// Walk up from `leaf_dir` toward `/`, ensuring each ancestor's `D:`
    /// entry lists its immediate child in `subdirs`. Short-circuits as soon
    /// as an ancestor already records the child — by induction, if `/a`
    /// lists `/a/b` as a subdir then the chain from `/a` up to `/` was
    /// already wired up by the prior upsert that first wrote it.
    ///
    /// Each ancestor may route to a *different* shard than the leaf (routing
    /// hashes the dir path + "/"), so this helper can dirty multiple shards
    /// per call on the first write down a fresh path; subsequent writes in
    /// the same directory short-circuit on the first hop and dirty only the
    /// leaf shard.
    async fn ensure_ancestor_chain<B: BlobBackend + 'static>(
        &mut self,
        leaf_dir: &str,
        backend: &Arc<B>,
    ) -> Result<()> {
        let mut current = leaf_dir.to_string();
        while let Some(parent) = dir_parent_of(&current) {
            let shard_idx = self.shard_for_dir(&parent);
            self.ensure_shard_loaded(shard_idx, backend).await?;
            let reader = self.reader_store_for(shard_idx, backend);
            let parent_key = dir_key(&parent);

            // Take the shard's write lock for the read-then-mutate sequence.
            // The write method holds `&mut self`, so the outer lock in the
            // caller (fula-client) guarantees exclusive access — this
            // per-shard lock is primarily there to satisfy the interior-
            // mutability API on `&self` read paths.
            let mut guard = self.loaded_shards[shard_idx].write().await;

            let prior_parent = match &*guard {
                LoadedShard::NotLoaded => unreachable!("ensure_shard_loaded above"),
                LoadedShard::LoadedEmpty => None,
                LoadedShard::Loaded(node) => node.get(&parent_key, &reader).await?,
            };

            let (new_parent_entry, freshly_created) =
                match prior_parent.map(HamtEntry::from) {
                    Some(HamtEntry::Dir(mut d)) => {
                        if d.subdirs.contains(&current) {
                            return Ok(());
                        }
                        d.subdirs.push(current.clone());
                        (d, false)
                    }
                    Some(HamtEntry::File(_)) => {
                        return Err(CryptoError::Hamt(format!(
                            "directory key D:{} resolved to a File entry — type-tagged HAMT invariant violated",
                            parent
                        )));
                    }
                    None => (
                        ForestDirectoryEntry {
                            path: parent.clone(),
                            files: Vec::new(),
                            subdirs: vec![current.clone()],
                            metadata: None,
                            subtree_dek: None,
                        },
                        true,
                    ),
                };

            let mut root = Self::take_loaded_root_from(&mut *guard);
            root.set(
                parent_key,
                HamtEntryWire::from(HamtEntry::Dir(new_parent_entry)),
                &reader,
            )
            .await?;
            Self::install_loaded_root_into(&mut *guard, root);
            drop(guard);

            if freshly_created {
                let shard = &mut self.manifest.shards[shard_idx];
                shard.entry_count = shard.entry_count.saturating_add(1);
            }
            self.dirty_shards[shard_idx] = true;

            current = parent;
        }
        Ok(())
    }

    //----------------------------------------------------------------------------------------------
    // Public mutation API
    //----------------------------------------------------------------------------------------------

    /// Insert or update the file entry for `entry.path` and add it to its
    /// parent directory's child list. Both writes land in the same shard
    /// (dir-local routing).
    ///
    /// Marks the owning shard dirty. The caller persists the update via
    /// `flush_dirty`.
    pub async fn upsert_file<B: BlobBackend + 'static>(
        &mut self,
        entry: ForestFileEntry,
        backend: &Arc<B>,
    ) -> Result<()> {
        let file_path = entry.path.clone();
        let parent = parent_dir_of(&file_path);

        let shard_idx = self.shard_for_file(&file_path);
        debug_assert_eq!(
            shard_idx,
            self.shard_for_dir(&parent),
            "dir-local routing invariant: file and its parent directory must share a shard"
        );

        self.ensure_shard_loaded(shard_idx, backend).await?;

        // Read the existing dir entry first (so we can merge the new child
        // in) and discover whether the file was already present (so we can
        // maintain entry_count without a second descent).
        let reader = self.reader_store_for(shard_idx, backend);
        let file_lookup_key = file_key(&file_path);
        let dir_lookup_key = dir_key(&parent);

        // Acquire the shard's write lock across the entire read-then-mutate
        // sequence. Writers take `&mut self` on the outer forest, so under
        // the fula-client outer `RwLock` no reader can observe a torn state.
        let mut guard = self.loaded_shards[shard_idx].write().await;

        let (had_file, prior_dir) = match &*guard {
            LoadedShard::NotLoaded => unreachable!("ensure_shard_loaded above"),
            LoadedShard::LoadedEmpty => (false, None),
            LoadedShard::Loaded(node) => {
                let prior_file = node.get(&file_lookup_key, &reader).await?;
                let dir_val = node.get(&dir_lookup_key, &reader).await?;
                (prior_file.is_some(), dir_val)
            }
        };

        // Compose the updated directory entry. If absent, synthesize a
        // fresh one with just this child; if present (and is a Dir), append
        // our file path if not already there. The ancestor chain above
        // `parent` is populated by `ensure_ancestor_chain` after this
        // shard's writes — matches v1's `ensure_directory` semantics so
        // `get_directory("/a")` resolves after a single
        // `upsert_file("/a/b/c.txt")`.
        let had_dir = prior_dir.is_some();
        let new_dir_entry: ForestDirectoryEntry = match prior_dir.map(HamtEntry::from) {
            Some(HamtEntry::Dir(mut d)) => {
                if !d.files.contains(&file_path) {
                    d.files.push(file_path.clone());
                }
                d
            }
            Some(HamtEntry::File(_)) => {
                return Err(CryptoError::Hamt(format!(
                    "directory key D:{} resolved to a File entry — type-tagged HAMT invariant violated",
                    parent
                )));
            }
            None => ForestDirectoryEntry {
                path: parent.clone(),
                files: vec![file_path.clone()],
                subdirs: Vec::new(),
                metadata: None,
                subtree_dek: None,
            },
        };

        // Take the root for mutation, perform both writes, reinstall.
        let mut root = Self::take_loaded_root_from(&mut *guard);
        root.set(
            file_lookup_key,
            HamtEntryWire::from(HamtEntry::File(entry)),
            &reader,
        )
        .await?;
        root.set(
            dir_lookup_key,
            HamtEntryWire::from(HamtEntry::Dir(new_dir_entry)),
            &reader,
        )
        .await?;
        Self::install_loaded_root_into(&mut *guard, root);
        drop(guard);

        // Entry-count accounting: each new unique key adds 1. `Node::set`
        // overwrites in place when the key already exists, so we only count
        // the first occurrence. `saturating_add` is defensive: a u32 of
        // 4 billion entries is already well past any realistic shard size,
        // but we refuse to wrap silently.
        let shard = &mut self.manifest.shards[shard_idx];
        if !had_file {
            shard.entry_count = shard.entry_count.saturating_add(1);
        }
        if !had_dir {
            shard.entry_count = shard.entry_count.saturating_add(1);
        }
        self.dirty_shards[shard_idx] = true;

        // Populate the directory chain above `parent`. Short-circuits on
        // first ancestor that already lists its child, so steady-state
        // writes in a pre-existing directory only touch the leaf shard.
        self.ensure_ancestor_chain(&parent, backend).await?;

        Ok(())
    }

    /// Insert or update a directory entry keyed by its exact path.
    ///
    /// Used by the v1→v7 migration to preserve directories that v1 recorded
    /// in its `directories` map but which have no file children — plain
    /// `upsert_file` only populates `D:` entries via `ensure_ancestor_chain`
    /// so leaf dirs without files would be silently dropped. This helper
    /// writes `D:<path>` directly, then calls `ensure_ancestor_chain` so the
    /// parent chain lists it. Idempotent: re-calling with the same entry is
    /// a no-op from the caller's perspective (overwrites the value in place).
    ///
    /// Marks the owning shard dirty. The caller persists via `flush_dirty`.
    pub async fn upsert_directory<B: BlobBackend + 'static>(
        &mut self,
        entry: ForestDirectoryEntry,
        backend: &Arc<B>,
    ) -> Result<()> {
        let dir_path = entry.path.clone();
        let shard_idx = self.shard_for_dir(&dir_path);
        self.ensure_shard_loaded(shard_idx, backend).await?;

        let reader = self.reader_store_for(shard_idx, backend);
        let lookup_key = dir_key(&dir_path);

        let mut guard = self.loaded_shards[shard_idx].write().await;

        let prior = match &*guard {
            LoadedShard::NotLoaded => unreachable!("ensure_shard_loaded above"),
            LoadedShard::LoadedEmpty => None,
            LoadedShard::Loaded(node) => node.get(&lookup_key, &reader).await?,
        };
        let had_dir = match prior.as_ref().map(|w| HamtEntry::from(w.clone())) {
            Some(HamtEntry::Dir(_)) => true,
            Some(HamtEntry::File(_)) => {
                return Err(CryptoError::Hamt(format!(
                    "directory key D:{} resolved to a File entry — type-tagged HAMT invariant violated",
                    dir_path
                )));
            }
            None => false,
        };

        let mut root = Self::take_loaded_root_from(&mut *guard);
        root.set(
            lookup_key,
            HamtEntryWire::from(HamtEntry::Dir(entry)),
            &reader,
        )
        .await?;
        Self::install_loaded_root_into(&mut *guard, root);
        drop(guard);

        if !had_dir {
            let shard = &mut self.manifest.shards[shard_idx];
            shard.entry_count = shard.entry_count.saturating_add(1);
        }
        self.dirty_shards[shard_idx] = true;

        // Wire this dir into its ancestor chain so `list_directory(parent)`
        // reports it. Root ("/") short-circuits immediately inside the helper.
        self.ensure_ancestor_chain(&dir_path, backend).await?;

        Ok(())
    }

    /// Remove the file at `path` and scrub it from its parent's child list.
    /// Returns the removed entry if it existed.
    ///
    /// Like `upsert_file`, both mutations land in the same shard and are
    /// committed together on the next `flush_dirty`.
    pub async fn remove_file<B: BlobBackend + 'static>(
        &mut self,
        path: &str,
        backend: &Arc<B>,
    ) -> Result<Option<ForestFileEntry>> {
        let parent = parent_dir_of(path);
        let shard_idx = self.shard_for_file(path);
        self.ensure_shard_loaded(shard_idx, backend).await?;

        let reader = self.reader_store_for(shard_idx, backend);
        let file_lookup_key = file_key(path);
        let dir_lookup_key = dir_key(&parent);

        let mut guard = self.loaded_shards[shard_idx].write().await;

        // Short-circuit: empty shard can't contain this file.
        if matches!(&*guard, LoadedShard::LoadedEmpty) {
            return Ok(None);
        }

        // Pull the existing dir entry so we can rewrite it without the
        // removed child.
        let prior_dir = match &*guard {
            LoadedShard::NotLoaded => unreachable!("ensure_shard_loaded above"),
            LoadedShard::LoadedEmpty => unreachable!("short-circuited above"),
            LoadedShard::Loaded(node) => node.get(&dir_lookup_key, &reader).await?,
        };

        let mut root = Self::take_loaded_root_from(&mut *guard);
        let removed_pair = root.remove(&file_lookup_key, &reader).await?;

        let removed_file: Option<ForestFileEntry> = match removed_pair {
            Some(pair) => match HamtEntry::from(pair.value) {
                HamtEntry::File(f) => Some(f),
                HamtEntry::Dir(_) => {
                    // Inconsistent type tag — restore the root and fail loudly.
                    Self::install_loaded_root_into(&mut *guard, root);
                    return Err(CryptoError::Hamt(format!(
                        "file key F:{} resolved to a Dir entry — type-tagged HAMT invariant violated",
                        path
                    )));
                }
            },
            None => None,
        };

        // If we actually removed the file, patch the dir entry. We do NOT
        // prune the `D:` entry when its file list becomes empty — this
        // matches v1's asymmetric contract where `ensure_directory`
        // populates ancestors on upsert but `remove_file` leaves them
        // alone. Keeping the entry avoids a prune-and-recreate race with
        // concurrent writers and an entangled ancestor-chain teardown; a
        // separate GC pass can reclaim latent empty dirs if ever needed.
        if removed_file.is_some() {
            match prior_dir.map(HamtEntry::from) {
                Some(HamtEntry::Dir(mut d)) => {
                    d.files.retain(|p| p != path);
                    root.set(
                        dir_lookup_key,
                        HamtEntryWire::from(HamtEntry::Dir(d)),
                        &reader,
                    )
                    .await?;
                }
                Some(HamtEntry::File(_)) => {
                    Self::install_loaded_root_into(&mut *guard, root);
                    return Err(CryptoError::Hamt(format!(
                        "directory key D:{} resolved to a File entry — type-tagged HAMT invariant violated",
                        parent
                    )));
                }
                None => {
                    // No parent dir entry — nothing to scrub.
                }
            }
        }

        Self::install_loaded_root_into(&mut *guard, root);
        drop(guard);

        if removed_file.is_some() {
            let shard = &mut self.manifest.shards[shard_idx];
            shard.entry_count = shard.entry_count.saturating_sub(1);
            self.dirty_shards[shard_idx] = true;
        }

        Ok(removed_file)
    }

    /// Fetch a file by its logical path. Lazy — only the nodes along the
    /// hash path are fetched, not the whole shard.
    ///
    /// Takes `&self` so concurrent readers can share a forest wrapped in
    /// an async `RwLock` (`async_lock::RwLock` or `tokio::sync::RwLock`).
    pub async fn get_file<B: BlobBackend + 'static>(
        &self,
        path: &str,
        backend: &Arc<B>,
    ) -> Result<Option<ForestFileEntry>> {
        let shard_idx = self.shard_for_file(path);
        self.ensure_shard_loaded(shard_idx, backend).await?;

        let reader = self.reader_store_for(shard_idx, backend);
        let key = file_key(path);

        let guard = self.loaded_shards[shard_idx].read().await;
        match &*guard {
            LoadedShard::NotLoaded => unreachable!("ensure_shard_loaded above"),
            LoadedShard::LoadedEmpty => Ok(None),
            LoadedShard::Loaded(node) => match node.get(&key, &reader).await? {
                Some(wire) => match HamtEntry::from(wire) {
                    HamtEntry::File(f) => Ok(Some(f)),
                    HamtEntry::Dir(_) => Err(CryptoError::Hamt(format!(
                        "file key F:{} resolved to a Dir entry — type-tagged HAMT invariant violated",
                        path
                    ))),
                },
                None => Ok(None),
            },
        }
    }

    /// Fetch a directory entry by path. Used by listing callers to walk the
    /// `files: Vec<String>` / `subdirs: Vec<String>` children in parallel.
    pub async fn get_directory<B: BlobBackend + 'static>(
        &self,
        dir_path: &str,
        backend: &Arc<B>,
    ) -> Result<Option<ForestDirectoryEntry>> {
        let normalized = normalize_dir_path(dir_path);
        let shard_idx = self.shard_for_dir(&normalized);
        self.ensure_shard_loaded(shard_idx, backend).await?;

        let reader = self.reader_store_for(shard_idx, backend);
        let key = dir_key(&normalized);

        let guard = self.loaded_shards[shard_idx].read().await;
        match &*guard {
            LoadedShard::NotLoaded => unreachable!("ensure_shard_loaded above"),
            LoadedShard::LoadedEmpty => Ok(None),
            LoadedShard::Loaded(node) => match node.get(&key, &reader).await? {
                Some(wire) => match HamtEntry::from(wire) {
                    HamtEntry::Dir(d) => Ok(Some(d)),
                    HamtEntry::File(_) => Err(CryptoError::Hamt(format!(
                        "directory key D:{} resolved to a File entry — type-tagged HAMT invariant violated",
                        normalized
                    ))),
                },
                None => Ok(None),
            },
        }
    }

    /// List direct children of a directory as `ForestFileEntry` values. Only
    /// the owning shard is touched (dir-local routing); HAMT lookups for
    /// each child are independent and can be issued in parallel by a
    /// higher-level caller if desired.
    pub async fn list_directory<B: BlobBackend + 'static>(
        &self,
        dir_path: &str,
        backend: &Arc<B>,
    ) -> Result<Vec<ForestFileEntry>> {
        let dir_entry = self.get_directory(dir_path, backend).await?;
        let children = match dir_entry {
            Some(d) => d.files,
            None => return Ok(Vec::new()),
        };

        // Every child of `dir` hashes into the same shard, so we can reuse
        // the reader we already primed.
        let shard_idx = self.shard_for_dir(&normalize_dir_path(dir_path));
        let reader = self.reader_store_for(shard_idx, backend);

        let mut out = Vec::with_capacity(children.len());
        let guard = self.loaded_shards[shard_idx].read().await;
        match &*guard {
            LoadedShard::NotLoaded => unreachable!("get_directory loaded this above"),
            LoadedShard::LoadedEmpty => {
                // Shard loaded empty but we found a dir entry — impossible,
                // but handle gracefully.
                return Ok(Vec::new());
            }
            LoadedShard::Loaded(node) => {
                for child in children {
                    if let Some(wire) = node.get(&file_key(&child), &reader).await? {
                        if let HamtEntry::File(f) = HamtEntry::from(wire) {
                            out.push(f);
                        }
                    }
                    // Silently skip type-mismatches here (a stale dir entry
                    // pointing at a removed file is possible across crashes
                    // and is not an integrity failure of the HAMT itself).
                }
            }
        }
        Ok(out)
    }

    //----------------------------------------------------------------------------------------------
    // WAL reconciliation
    //----------------------------------------------------------------------------------------------

    /// Fold a logged `ShardWrote` record into this in-memory forest so the
    /// next `flush_dirty` re-PUTs from the post-recorded sequence.
    ///
    /// Contract (mirrors v6's `shard_sequences` / `shard_etags` reconcile):
    ///   * `manifest.shards[idx].seq` advances to `max(current, observed)`.
    ///   * `manifest.shards[idx].etag` is overwritten with the observed
    ///     ETag (may be `None` if the server didn't return one).
    ///   * The shard is marked dirty so the next flush bumps seq further
    ///     and rewrites the nodes under the newly-bound AAD.
    ///
    /// Silently ignores `idx >= num_shards` — a replay log from a prior
    /// shape could legitimately reference a shard that no longer exists
    /// after reshard; dropping the record is safer than reviving it.
    pub fn reconcile_shard_write(
        &mut self,
        idx: usize,
        observed_seq: u64,
        observed_etag: Option<String>,
    ) {
        if idx >= self.manifest.shards.len() {
            return;
        }
        let cur = self.manifest.shards[idx].seq;
        if observed_seq > cur {
            self.manifest.shards[idx].seq = observed_seq;
        }
        self.manifest.shards[idx].etag = observed_etag;
        self.dirty_shards[idx] = true;
    }

    //----------------------------------------------------------------------------------------------
    // Full-bucket enumeration
    //----------------------------------------------------------------------------------------------

    /// Walk every shard's HAMT and collect every `HamtEntry`. Used as the
    /// substrate for `list_all_files`, `list_all_directories`, and
    /// `extract_subtree`. Loads each shard's root once; interior nodes are
    /// fetched lazily through the per-shard `V7NodeStore`.
    ///
    /// Cost is O(total entries + tree overhead) — for 256 shards with many
    /// entries each, the full walk can touch every node blob. Callers that
    /// need only direct children of one directory should use
    /// `list_directory` instead; this method is intended for bulk-sync /
    /// sharing flows.
    async fn collect_all_entries<B: BlobBackend + 'static>(
        &self,
        backend: &Arc<B>,
    ) -> Result<Vec<HamtEntry>> {
        let num = self.manifest.shards.len();
        let mut all = Vec::new();
        for shard_idx in 0..num {
            self.ensure_shard_loaded(shard_idx, backend).await?;
            let reader = self.reader_store_for(shard_idx, backend);
            let guard = self.loaded_shards[shard_idx].read().await;
            match &*guard {
                LoadedShard::NotLoaded => unreachable!("ensure_shard_loaded above"),
                LoadedShard::LoadedEmpty => {}
                LoadedShard::Loaded(node) => {
                    let wires: Vec<HamtEntryWire> = node
                        .flat_map(
                            &|pair: &Pair<Vec<u8>, HamtEntryWire>| Ok(pair.value.clone()),
                            &reader,
                        )
                        .await?;
                    all.reserve(wires.len());
                    for w in wires {
                        all.push(HamtEntry::from(w));
                    }
                }
            }
        }
        Ok(all)
    }

    /// Collect every `ForestFileEntry` across every shard.
    ///
    /// Equivalent to `PrivateForest::list_all_files` / `ShardedPrivateForest::
    /// list_all_files` on v1 and v6 forests, returning owned entries.
    pub async fn list_all_files<B: BlobBackend + 'static>(
        &self,
        backend: &Arc<B>,
    ) -> Result<Vec<ForestFileEntry>> {
        let all = self.collect_all_entries(backend).await?;
        Ok(all
            .into_iter()
            .filter_map(|e| match e {
                HamtEntry::File(f) => Some(f),
                HamtEntry::Dir(_) => None,
            })
            .collect())
    }

    /// H-1 / H-2: reverse lookup — find a file entry by its `storage_key`.
    ///
    /// Walks every shard's HAMT because storage_key is not an index. This
    /// is O(total entries) and is only intended for the per-download
    /// verification path (`forest_entry_lookup`), which runs at most once
    /// per object read and is dwarfed by network cost. Callers with a
    /// logical path should prefer `get_file(path)` (O(log n)).
    pub async fn find_by_storage_key<B: BlobBackend + 'static>(
        &self,
        storage_key: &str,
        backend: &Arc<B>,
    ) -> Result<Option<ForestFileEntry>> {
        let all = self.list_all_files(backend).await?;
        Ok(all.into_iter().find(|f| f.storage_key == storage_key))
    }

    /// Collect every `ForestDirectoryEntry` across every shard.
    pub async fn list_all_directories<B: BlobBackend + 'static>(
        &self,
        backend: &Arc<B>,
    ) -> Result<Vec<ForestDirectoryEntry>> {
        let all = self.collect_all_entries(backend).await?;
        Ok(all
            .into_iter()
            .filter_map(|e| match e {
                HamtEntry::Dir(d) => Some(d),
                HamtEntry::File(_) => None,
            })
            .collect())
    }

    /// Collect every file whose `path` starts with `prefix`.
    ///
    /// Prefix-filtered variant of `list_all_files`. Still walks every shard
    /// (prefix doesn't correspond to a single shard under dir-local routing
    /// once nested children are considered). Matches the semantics of
    /// `PrivateForest::list_recursive` on v1 forests.
    ///
    /// Callers that need to page results (F5) should use
    /// [`Self::list_recursive_page`] — this method still loads every match
    /// into memory at once, kept for legacy / small-dataset callers.
    pub async fn list_recursive<B: BlobBackend + 'static>(
        &self,
        prefix: &str,
        backend: &Arc<B>,
    ) -> Result<Vec<ForestFileEntry>> {
        let all = self.list_all_files(backend).await?;
        Ok(all.into_iter().filter(|f| f.path.starts_with(prefix)).collect())
    }

    /// Paginated variant of [`Self::list_recursive`].
    ///
    /// Walks shards starting from `cursor` (or shard 0 if `None`), emits every
    /// file whose `path` begins with `prefix`, and stops *after the first
    /// shard whose walk pushes the running total ≥ `max_keys`* — or once all
    /// shards are exhausted. Returns `(page, next_cursor)`. When
    /// `next_cursor` is `None` the caller has seen the whole prefix.
    ///
    /// `max_keys` is a **soft cap, not a hard cap**. Page granularity is one
    /// shard: a shard is either fully walked or skipped. If a single shard
    /// contains more than `max_keys` matches, the returned page will contain
    /// all of them (we cannot resume mid-shard because a v7 HAMT's
    /// `flat_map` traversal has no stable ordering we could bookmark).
    /// `max_keys == 0` means "no cap — walk every shard".
    ///
    /// The cursor is an opaque `Vec<u8>`; callers should treat it as a
    /// black-box token. Encoding today: postcard-encoded `u32` next-shard
    /// index; future refinements (within-shard offsets) would extend the
    /// opaque cursor without breaking the signature.
    pub async fn list_recursive_page<B: BlobBackend + 'static>(
        &self,
        prefix: &str,
        cursor: Option<&[u8]>,
        max_keys: usize,
        backend: &Arc<B>,
    ) -> Result<(Vec<ForestFileEntry>, Option<Vec<u8>>)> {
        let num = self.manifest.shards.len() as u32;
        let start = match cursor {
            None => 0u32,
            Some(bytes) => postcard::from_bytes::<u32>(bytes).map_err(|e| {
                CryptoError::Hamt(format!("list_recursive_page: invalid cursor: {}", e))
            })?,
        };
        if start >= num {
            return Ok((Vec::new(), None));
        }

        let mut out: Vec<ForestFileEntry> = Vec::new();
        let mut next_shard = start;
        while (next_shard as usize) < num as usize {
            let shard_idx = next_shard as usize;
            self.ensure_shard_loaded(shard_idx, backend).await?;
            let reader = self.reader_store_for(shard_idx, backend);
            let guard = self.loaded_shards[shard_idx].read().await;
            match &*guard {
                LoadedShard::NotLoaded => unreachable!("ensure_shard_loaded above"),
                LoadedShard::LoadedEmpty => {}
                LoadedShard::Loaded(node) => {
                    let wires: Vec<HamtEntryWire> = node
                        .flat_map(
                            &|pair: &Pair<Vec<u8>, HamtEntryWire>| Ok(pair.value.clone()),
                            &reader,
                        )
                        .await?;
                    for w in wires {
                        if let HamtEntry::File(f) = HamtEntry::from(w) {
                            if f.path.starts_with(prefix) {
                                out.push(f);
                            }
                        }
                    }
                }
            }
            drop(guard);
            next_shard = next_shard.saturating_add(1);

            // Stop once we've filled the page. `max_keys == 0` means
            // "no cap" — callers that want unbounded listing can use
            // `list_recursive` instead, but we accept this for symmetry.
            if max_keys > 0 && out.len() >= max_keys {
                break;
            }
        }

        let next_cursor = if (next_shard as usize) >= num as usize {
            None
        } else {
            Some(postcard::to_allocvec(&next_shard).map_err(|e| {
                CryptoError::Hamt(format!("list_recursive_page: cursor encode: {}", e))
            })?)
        };
        Ok((out, next_cursor))
    }

    /// Extract a subtree rooted at `prefix` into a fresh monolithic
    /// `PrivateForest`. Used by sharing flows that want to hand an isolated
    /// view of a portion of the namespace to a recipient.
    ///
    /// The subtree carries all files whose path starts with `prefix`, and
    /// every directory that either lives under `prefix` or is an ancestor
    /// of it (so recipients can resolve the path chain). The result is a
    /// `FlatMapV1` forest — intentional, because the whole point of the
    /// export is that it's a small, self-contained, monolithic artifact.
    pub async fn extract_subtree<B: BlobBackend + 'static>(
        &self,
        prefix: &str,
        backend: &Arc<B>,
    ) -> Result<PrivateForest> {
        let all = self.collect_all_entries(backend).await?;

        let mut subtree = PrivateForest::new();
        subtree.root = prefix.to_string();

        for e in all {
            match e {
                HamtEntry::File(f) => {
                    if f.path.starts_with(prefix) {
                        subtree.files.insert(f.path.clone(), f);
                    }
                }
                HamtEntry::Dir(d) => {
                    // Keep dirs inside the subtree AND dirs that are
                    // ancestors of the prefix (so the caller can walk the
                    // path down). Matches `PrivateForest::extract_subtree`.
                    if d.path.starts_with(prefix) || prefix.starts_with(&d.path) {
                        subtree.directories.insert(d.path.clone(), d);
                    }
                }
            }
        }

        Ok(subtree)
    }

    //----------------------------------------------------------------------------------------------
    // Flush
    //----------------------------------------------------------------------------------------------

    /// Persist every dirty shard's in-memory HAMT to the backend and update
    /// the manifest's per-shard `root`/`seq`. Returns a borrow of the
    /// (now up-to-date) manifest so the caller can encrypt and PUT it.
    ///
    /// Contract:
    ///   * Each dirty shard's `seq` is incremented and written into the
    ///     manifest. The bumped `seq` is **not** part of per-node AAD
    ///     (node AAD binds only `(bucket, shard_idx)`); instead `seq` plus
    ///     the manifest's ETag give replay protection against stale shard
    ///     root swaps. This lets the HAMT flush rewrite only the path of
    ///     mutated nodes while untouched subtree ciphertexts stay readable.
    ///   * If a shard's in-memory HAMT is empty, the root is recorded as
    ///     `None` and no nodes are written.
    ///   * Failures leave partial state: the shard whose `Node::store` fails
    ///     keeps its pre-flush root pointer but its `seq` has already been
    ///     bumped. Callers are expected to treat flush failure as
    ///     non-recoverable and drop the in-memory forest rather than
    ///     continuing to mutate it.
    pub async fn flush_dirty<B: BlobBackend + 'static>(
        &mut self,
        backend: &Arc<B>,
    ) -> Result<&ShardManifestV7> {
        for idx in 0..self.manifest.shards.len() {
            if !self.dirty_shards[idx] {
                continue;
            }

            // Bump the manifest's per-shard sequence. This protects the
            // *root pointer* swap in the manifest, not individual node
            // ciphertexts — those are bound by `(bucket, shard_idx)` only
            // so that path-of-change flushes don't strand untouched
            // subtree nodes sealed under older sequences.
            let new_seq = self.manifest.shards[idx].seq.wrapping_add(1);
            self.manifest.shards[idx].seq = new_seq;

            let store: V7NodeStore<B> = V7NodeStore::new(
                self.bucket.clone(),
                idx as u16,
                self.manifest.shard_salt.clone(),
                self.forest_dek.clone(),
                backend.clone(),
            );

            let new_root = {
                let guard = self.loaded_shards[idx].read().await;
                match &*guard {
                    LoadedShard::NotLoaded => {
                        return Err(CryptoError::Hamt(format!(
                            "shard {} marked dirty but NotLoaded — internal invariant violation",
                            idx
                        )));
                    }
                    LoadedShard::LoadedEmpty => None,
                    LoadedShard::Loaded(node) => {
                        if node.is_empty() {
                            None
                        } else {
                            Some(node.store(&store).await?)
                        }
                    }
                }
            };

            self.manifest.shards[idx].root = new_root;
            self.dirty_shards[idx] = false;
        }
        self.manifest.touch();
        Ok(&self.manifest)
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use crate::keys::DekKey;
    use crate::wnfs_hamt::v7_store::InMemoryBackend;
    use std::collections::HashSet;

    fn test_dek() -> DekKey {
        DekKey::from_bytes(&[0x33u8; 32]).unwrap()
    }

    fn file_entry(path: &str, size: u64) -> ForestFileEntry {
        ForestFileEntry {
            path: path.to_string(),
            storage_key: format!("Qm{}", hex::encode(blake3::hash(path.as_bytes()).as_bytes())),
            size,
            content_type: Some("application/octet-stream".to_string()),
            created_at: 0,
            modified_at: 0,
            content_hash: None,
            user_metadata: Default::default(),
            encrypted: true,
            min_version: 0,
        }
    }

    #[tokio::test]
    async fn upsert_get_round_trip_in_memory() {
        let backend = Arc::new(InMemoryBackend::new());
        let mut forest = ShardedHamtPrivateForest::new("bucket-a", test_dek(), 16);

        let e = file_entry("/a/b/c.txt", 42);
        forest.upsert_file(e.clone(), &backend).await.unwrap();

        let got = forest.get_file("/a/b/c.txt", &backend).await.unwrap();
        assert_eq!(got.as_ref().map(|f| f.size), Some(42));
        assert_eq!(got.as_ref().map(|f| f.path.as_str()), Some("/a/b/c.txt"));
        assert!(forest.is_dirty());
        // Exact dirty-shard count depends on whether "/" and "/a" route to
        // the leaf shard or different shards (salt-dependent); the
        // `first_deep_upsert_dirties_multiple_shards` test pins the lower
        // bound. Here we just verify that upsert dirties *something*.
        assert!(!forest.dirty_shard_indices().is_empty());
    }

    #[tokio::test]
    async fn upsert_updates_parent_dir_entry_same_shard() {
        let backend = Arc::new(InMemoryBackend::new());
        let mut forest = ShardedHamtPrivateForest::new("bucket-a", test_dek(), 16);

        forest
            .upsert_file(file_entry("/x/y/one.txt", 1), &backend)
            .await
            .unwrap();
        forest
            .upsert_file(file_entry("/x/y/two.txt", 2), &backend)
            .await
            .unwrap();

        // Both file leaves hit the same shard via dir-local routing: the
        // `D:/x/y` entry in that shard lists both children.
        let leaf_shard_1 = forest.shard_for_file("/x/y/one.txt");
        let leaf_shard_2 = forest.shard_for_file("/x/y/two.txt");
        assert_eq!(leaf_shard_1, leaf_shard_2);

        let dir = forest.get_directory("/x/y", &backend).await.unwrap();
        let dir = dir.expect("parent directory must be materialized");
        let mut got: HashSet<_> = dir.files.iter().cloned().collect();
        let want: HashSet<_> = ["/x/y/one.txt".to_string(), "/x/y/two.txt".to_string()]
            .into_iter()
            .collect();
        assert_eq!(got.len(), 2);
        got.retain(|p| want.contains(p));
        assert_eq!(got.len(), 2);
    }

    #[tokio::test]
    async fn list_directory_returns_direct_children_only() {
        let backend = Arc::new(InMemoryBackend::new());
        let mut forest = ShardedHamtPrivateForest::new("bucket-a", test_dek(), 16);

        forest
            .upsert_file(file_entry("/root/a.txt", 1), &backend)
            .await
            .unwrap();
        forest
            .upsert_file(file_entry("/root/b.txt", 2), &backend)
            .await
            .unwrap();
        forest
            .upsert_file(file_entry("/root/sub/c.txt", 3), &backend)
            .await
            .unwrap();

        let listing = forest.list_directory("/root", &backend).await.unwrap();
        let paths: HashSet<_> = listing.iter().map(|f| f.path.clone()).collect();
        assert_eq!(paths.len(), 2);
        assert!(paths.contains("/root/a.txt"));
        assert!(paths.contains("/root/b.txt"));
        assert!(!paths.contains("/root/sub/c.txt"));
    }

    #[tokio::test]
    async fn remove_file_scrubs_parent_child_list() {
        let backend = Arc::new(InMemoryBackend::new());
        let mut forest = ShardedHamtPrivateForest::new("bucket-a", test_dek(), 16);

        forest
            .upsert_file(file_entry("/dir/a.txt", 1), &backend)
            .await
            .unwrap();
        forest
            .upsert_file(file_entry("/dir/b.txt", 2), &backend)
            .await
            .unwrap();

        let removed = forest
            .remove_file("/dir/a.txt", &backend)
            .await
            .unwrap();
        assert_eq!(removed.map(|f| f.path), Some("/dir/a.txt".to_string()));

        let gone = forest.get_file("/dir/a.txt", &backend).await.unwrap();
        assert!(gone.is_none());

        let listing = forest.list_directory("/dir", &backend).await.unwrap();
        assert_eq!(listing.len(), 1);
        assert_eq!(listing[0].path, "/dir/b.txt");
    }

    #[tokio::test]
    async fn remove_file_leaves_empty_directory_entry() {
        let backend = Arc::new(InMemoryBackend::new());
        let mut forest = ShardedHamtPrivateForest::new("bucket-a", test_dek(), 16);

        forest
            .upsert_file(file_entry("/solo/only.txt", 9), &backend)
            .await
            .unwrap();
        forest
            .remove_file("/solo/only.txt", &backend)
            .await
            .unwrap();

        // v1-compatible semantics: `remove_file` does not prune empty
        // directory entries. The `D:/solo` entry persists with an empty
        // `files` list; a latent-dir GC pass can reclaim it out-of-band.
        let d = forest
            .get_directory("/solo", &backend)
            .await
            .unwrap()
            .expect("empty directory entry must remain after last-child removal");
        assert!(d.files.is_empty());
    }

    #[tokio::test]
    async fn entry_count_tracks_upsert_and_remove() {
        let backend = Arc::new(InMemoryBackend::new());
        let mut forest = ShardedHamtPrivateForest::new("bucket-a", test_dek(), 16);

        // Empty forest → zero.
        assert_eq!(forest.entry_count(), 0);

        // Two files under /d/ → 4 entries:
        //   leaf shard: F:/d/a.txt, F:/d/b.txt, D:/d   (3)
        //   root shard: D:/                            (1)
        // Ancestor chain is populated on upsert to match v1's
        // `ensure_directory` semantics.
        forest
            .upsert_file(file_entry("/d/a.txt", 1), &backend)
            .await
            .unwrap();
        forest
            .upsert_file(file_entry("/d/b.txt", 2), &backend)
            .await
            .unwrap();
        assert_eq!(forest.entry_count(), 4);

        // Overwriting an existing file must not bump entry_count.
        forest
            .upsert_file(file_entry("/d/a.txt", 10), &backend)
            .await
            .unwrap();
        assert_eq!(forest.entry_count(), 4);

        // Remove one file → -1 (the file). D:/d stays populated with /d/b.txt.
        forest.remove_file("/d/a.txt", &backend).await.unwrap();
        assert_eq!(forest.entry_count(), 3);

        // Remove the last file → -1 (file only). D:/d and D:/ persist as
        // latent empty entries per v1's no-prune asymmetry.
        forest.remove_file("/d/b.txt", &backend).await.unwrap();
        assert_eq!(forest.entry_count(), 2);
    }

    #[tokio::test]
    async fn flush_dirty_persists_and_reloads_cleanly() {
        let backend = Arc::new(InMemoryBackend::new());
        // 256 shards keeps routing-collision probability between `/` and
        // `/shared/` negligible (was 1/16 on the prior 16-shard choice,
        // which flaked the `populated.len() == 2` assertion below). With
        // 256 shards the odds of the two hashing to the same slot are
        // 1/256 ≈ 0.4%; if that ever fires we can pin a fixed salt via
        // `from_manifest`.
        let mut forest = ShardedHamtPrivateForest::new("bucket-a", test_dek(), 256);

        let inputs: Vec<_> = (0..20)
            .map(|i| file_entry(&format!("/shared/file-{:03}.bin", i), i as u64))
            .collect();
        for e in &inputs {
            forest.upsert_file(e.clone(), &backend).await.unwrap();
        }

        // Sanity: still dirty before flush.
        assert!(forest.is_dirty());
        let manifest = forest.flush_dirty(&backend).await.unwrap().clone();
        assert!(!forest.is_dirty());

        // Two shards populated after flush: the leaf shard holding all
        // `/shared/*` files plus `D:/shared` (21 entries), and the shard
        // owning `D:/` which the ancestor chain pinned (1 entry).
        let populated: Vec<&crate::private_forest::ShardV7> = manifest
            .shards
            .iter()
            .filter(|s| s.root.is_some())
            .collect();
        assert_eq!(populated.len(), 2, "leaf shard + root-dir shard");
        let leaf = populated
            .iter()
            .find(|s| s.entry_count == 21)
            .expect("leaf shard with 20 files + D:/shared");
        let root = populated
            .iter()
            .find(|s| s.entry_count == 1)
            .expect("root-dir shard with D:/");
        assert_eq!(leaf.seq, 1, "leaf shard seq bumps 0 → 1 on first flush");
        assert_eq!(root.seq, 1, "root-dir shard seq bumps 0 → 1 on first flush");

        // Reload via from_manifest and confirm every entry round-trips.
        let mut reopened =
            ShardedHamtPrivateForest::from_manifest(manifest, "bucket-a", test_dek());
        for want in &inputs {
            let got = reopened.get_file(&want.path, &backend).await.unwrap();
            assert_eq!(got.map(|f| f.size), Some(want.size));
        }
    }

    #[tokio::test]
    async fn second_flush_bumps_seq_only_for_dirty_shards() {
        let backend = Arc::new(InMemoryBackend::new());
        // 256 shards: the assertions below are sensitive to `/ga`, `/gb`, and
        // `/` routing to distinct shards. With 16 shards the random shard
        // salt made that collision ~1.2% probable per run; 256 shards drops
        // the probability to ~0.005% and the explicit three-way guard below
        // covers the residual.
        let mut forest = ShardedHamtPrivateForest::new("bucket-a", test_dek(), 256);

        forest
            .upsert_file(file_entry("/ga/a.txt", 1), &backend)
            .await
            .unwrap();
        let m1 = forest.flush_dirty(&backend).await.unwrap().clone();

        // After first flush the `/ga` leaf shard and the root-dir shard
        // are both populated (ancestor chain pinned `D:/`). Their shard
        // indices are stable across calls since routing is deterministic.
        let ga_leaf_idx = forest.shard_for_file("/ga/a.txt");
        let root_dir_idx = forest.shard_for_dir("/");
        assert!(m1.shards[ga_leaf_idx].root.is_some());
        assert_eq!(m1.shards[ga_leaf_idx].seq, 1);
        assert!(m1.shards[root_dir_idx].root.is_some());
        assert_eq!(m1.shards[root_dir_idx].seq, 1);

        // A second write under a *different* top-level directory dirties
        // its own leaf shard AND the root-dir shard (because `D:/` now
        // also lists `/gb` in its subdirs). The `/ga` leaf shard was not
        // re-touched, so its seq must stay at 1.
        forest
            .upsert_file(file_entry("/gb/beta.txt", 2), &backend)
            .await
            .unwrap();
        let m2 = forest.flush_dirty(&backend).await.unwrap().clone();

        let gb_leaf_idx = forest.shard_for_file("/gb/beta.txt");
        // Only assert the "unchanged" / "first-touched" cases when the three
        // shards are actually distinct. A collision (between `ga_leaf_idx`,
        // `gb_leaf_idx`, and `root_dir_idx`) is negligibly rare with 256
        // shards but harmless to skip when it happens.
        if ga_leaf_idx != gb_leaf_idx && ga_leaf_idx != root_dir_idx {
            assert_eq!(
                m2.shards[ga_leaf_idx].seq, 1,
                "first-flush leaf shard must keep seq=1 when not re-dirtied"
            );
        }
        if gb_leaf_idx != ga_leaf_idx && gb_leaf_idx != root_dir_idx {
            assert_eq!(m2.shards[gb_leaf_idx].seq, 1);
        }
        assert_eq!(
            m2.shards[root_dir_idx].seq, 2,
            "root-dir shard must re-bump when a new top-level dir joins D:/'s subdirs"
        );
    }

    #[tokio::test]
    async fn reopen_with_tampered_root_fails() {
        // `shard_seq` is intentionally NOT bound into per-node AAD — binding
        // it there would strand untouched subtree ciphertexts after the next
        // path-of-change flush (see the design note on `hamt_node_v7_aad`).
        // Replay protection for shard root *swaps* lives at the manifest
        // layer (ETag + `manifest.shards[i].seq`), not per-node.
        //
        // What we can still exercise at the node layer: tamper a manifest
        // root pointer and confirm load fails. Either the backend has no
        // object at the forged key, or (on a lucky collision) AEAD rejects
        // the wrong ciphertext.
        let backend = Arc::new(InMemoryBackend::new());
        let mut forest = ShardedHamtPrivateForest::new("bucket-a", test_dek(), 16);
        forest
            .upsert_file(file_entry("/seq/x.txt", 1), &backend)
            .await
            .unwrap();
        let mut manifest = forest.flush_dirty(&backend).await.unwrap().clone();
        let leaf_idx = forest.shard_for_file("/seq/x.txt");
        let mut tampered_root = manifest.shards[leaf_idx].root.expect("populated shard");
        tampered_root[0] ^= 0xFF;
        manifest.shards[leaf_idx].root = Some(tampered_root);

        let mut reopened =
            ShardedHamtPrivateForest::from_manifest(manifest, "bucket-a", test_dek());
        let err = reopened.get_file("/seq/x.txt", &backend).await;
        assert!(err.is_err(), "tampered shard root must fail to load");
    }

    #[tokio::test]
    async fn wrong_bucket_cannot_decrypt_foreign_nodes() {
        let backend = Arc::new(InMemoryBackend::new());
        let mut alice = ShardedHamtPrivateForest::new("alice-bucket", test_dek(), 16);
        alice
            .upsert_file(file_entry("/secret.txt", 42), &backend)
            .await
            .unwrap();
        let alice_manifest = alice.flush_dirty(&backend).await.unwrap().clone();

        // A different bucket label (but same DEK + backend) must fail AEAD
        // because the AAD binds the bucket id.
        let mut mallory = ShardedHamtPrivateForest::from_manifest(
            alice_manifest,
            "mallory-bucket",
            test_dek(),
        );
        let err = mallory.get_file("/secret.txt", &backend).await;
        assert!(err.is_err(), "cross-bucket reuse must fail AEAD");
    }

    #[tokio::test]
    async fn upsert_creates_full_ancestor_chain() {
        // A single deep upsert must pin every ancestor directory entry —
        // this is the v1 `ensure_directory` contract that `list_directory`
        // and folder navigation depend on.
        let backend = Arc::new(InMemoryBackend::new());
        let mut forest = ShardedHamtPrivateForest::new("bucket-a", test_dek(), 16);

        forest
            .upsert_file(file_entry("/a/b/c.txt", 99), &backend)
            .await
            .unwrap();

        let leaf = forest
            .get_directory("/a/b", &backend)
            .await
            .unwrap()
            .expect("/a/b must exist after deep upsert");
        assert_eq!(leaf.path, "/a/b");
        assert_eq!(leaf.files, vec!["/a/b/c.txt".to_string()]);
        assert!(leaf.subdirs.is_empty());

        let mid = forest
            .get_directory("/a", &backend)
            .await
            .unwrap()
            .expect("/a must be pinned by ancestor-chain walk");
        assert_eq!(mid.path, "/a");
        assert!(mid.files.is_empty());
        assert_eq!(mid.subdirs, vec!["/a/b".to_string()]);

        let root = forest
            .get_directory("/", &backend)
            .await
            .unwrap()
            .expect("/ must be pinned by ancestor-chain walk");
        assert_eq!(root.path, "/");
        assert!(root.files.is_empty());
        assert_eq!(root.subdirs, vec!["/a".to_string()]);
    }

    #[tokio::test]
    async fn second_upsert_same_dir_short_circuits() {
        // Once `/a/b`'s ancestor chain is wired up by the first upsert, a
        // second upsert into the same directory must NOT re-dirty any
        // ancestor shards — only the leaf shard flips.
        let backend = Arc::new(InMemoryBackend::new());
        let mut forest = ShardedHamtPrivateForest::new("bucket-a", test_dek(), 16);

        forest
            .upsert_file(file_entry("/a/b/one.txt", 1), &backend)
            .await
            .unwrap();
        // Commit so dirty flags clear; we observe the next upsert in isolation.
        forest.flush_dirty(&backend).await.unwrap();
        assert!(!forest.is_dirty());

        forest
            .upsert_file(file_entry("/a/b/two.txt", 2), &backend)
            .await
            .unwrap();

        // Ancestor chain short-circuits on the first hop (D:/a already
        // lists /a/b in subdirs), so only the leaf shard is dirty.
        assert_eq!(
            forest.dirty_shard_indices().len(),
            1,
            "steady-state upsert in an established dir must touch exactly one shard"
        );
    }

    #[tokio::test]
    async fn first_deep_upsert_dirties_multiple_shards() {
        // A single upsert into a brand-new deep path must dirty at least the
        // leaf shard and the shard owning `D:/`. Intermediate ancestors
        // (e.g. `/a`) may or may not collide into the same shard depending
        // on the salt, so the count is `>= 2` rather than a specific value.
        let backend = Arc::new(InMemoryBackend::new());
        let mut forest = ShardedHamtPrivateForest::new("bucket-a", test_dek(), 16);

        forest
            .upsert_file(file_entry("/a/b/c.txt", 7), &backend)
            .await
            .unwrap();

        let dirty = forest.dirty_shard_indices();
        assert!(
            dirty.len() >= 2,
            "first deep upsert must dirty the leaf shard and at least one ancestor shard; got {:?}",
            dirty
        );
    }

    /// Exercises the v1→v7 migration pipeline end-to-end at the HAMT layer
    /// — the same two-loop (files then dirs) sequence performed by
    /// `FulaEncryption::migrate_to_sharded`, against an InMemoryBackend so
    /// we can verify persistence + reload without the network plumbing.
    ///
    /// Covers the blocker raised in pre-done review: proves that a
    /// migrated v7 forest is actually readable (and that `upsert_directory`
    /// does not clobber the canonical child lists populated by the file
    /// loop).
    #[tokio::test]
    async fn migration_pipeline_round_trip_files_and_dirs() {
        use crate::private_forest::{
            ForestDirectoryEntry, PrivateForest, ShardManifestV7,
        };

        // ─── Fixture: v1 monolithic forest ──────────────────────────────────
        let mut v1 = PrivateForest::new();
        v1.created_at = 1_700_000_000; // recognizably old timestamp

        let f1 = file_entry("/docs/readme.md", 10);
        let f2 = file_entry("/docs/notes.txt", 20);
        let f3 = file_entry("/deep/a/b/c/leaf.bin", 30);
        v1.upsert_file(f1.clone());
        v1.upsert_file(f2.clone());
        v1.upsert_file(f3.clone());

        // Sanity: v1 populated its directories map for ancestors.
        assert!(v1.directories.contains_key("/docs"));
        assert!(v1.directories.contains_key("/deep/a/b/c"));

        // Simulate an explicit directory metadata carry-over — realistic
        // motivator for keeping `upsert_directory` in the migration path.
        if let Some(d) = v1.directories.get_mut("/docs") {
            let mut m = std::collections::HashMap::new();
            m.insert("label".to_string(), "docs".to_string());
            d.metadata = Some(m);
        }

        // ─── Migration ──────────────────────────────────────────────────────
        let backend = Arc::new(InMemoryBackend::new());
        let mut manifest = ShardManifestV7::new(16);
        manifest.created_at = v1.created_at; // mirror the client-side carryover

        let mut v7 = ShardedHamtPrivateForest::from_manifest(
            manifest,
            "bucket-a",
            test_dek(),
        );

        // Files first (so the dir loop overwrites with v1's canonical
        // metadata), matching the client-side `migrate_to_sharded` order.
        for entry in v1.files.values() {
            v7.upsert_file(entry.clone(), &backend).await.unwrap();
        }
        for dir in v1.directories.values() {
            v7.upsert_directory(dir.clone(), &backend).await.unwrap();
        }

        v7.flush_dirty(&backend).await.unwrap();
        let snapshot = v7.manifest().clone();
        assert_eq!(snapshot.created_at, 1_700_000_000, "created_at carried forward");

        // ─── Reload a fresh forest from the persisted manifest ──────────────
        let mut reopened = ShardedHamtPrivateForest::from_manifest(
            snapshot,
            "bucket-a",
            test_dek(),
        );

        // Every file resolves by exact path.
        for want in [&f1, &f2, &f3] {
            let got = reopened.get_file(&want.path, &backend).await.unwrap();
            assert_eq!(
                got.map(|f| f.size),
                Some(want.size),
                "file {} lost across migration round-trip",
                want.path
            );
        }

        // Directory listings return v1's canonical child set — the file
        // loop's ensure_ancestor_chain + the dir loop's `upsert_directory`
        // converge on the same list without either clobbering the other.
        let docs_children = reopened.list_directory("/docs", &backend).await.unwrap();
        let mut docs_paths: Vec<String> = docs_children.iter().map(|f| f.path.clone()).collect();
        docs_paths.sort();
        assert_eq!(docs_paths, vec!["/docs/notes.txt", "/docs/readme.md"]);

        // Dir metadata carried over — would be `None` if the dir loop had
        // been dropped or if the file loop had overwritten `upsert_directory`.
        let docs_dir: ForestDirectoryEntry =
            reopened.get_directory("/docs", &backend).await.unwrap().unwrap();
        assert!(docs_dir.metadata.is_some(), "metadata preserved from v1 entry");

        // Deep nested path resolves through the full ancestor chain.
        let deep_leaf = reopened
            .list_directory("/deep/a/b/c", &backend)
            .await
            .unwrap();
        assert_eq!(deep_leaf.len(), 1);
        assert_eq!(deep_leaf[0].path, "/deep/a/b/c/leaf.bin");
    }

    /// Scalability coverage: push every shard deep past the depth-0 regime
    /// and verify the HAMT still round-trips every entry after flush +
    /// reload.
    ///
    /// Each HAMT node has 16 slots (`2^HAMT_BITMASK_BIT_SIZE` = 16) and each
    /// slot holds up to `HAMT_VALUES_BUCKET_SIZE = 3` inline values, so a
    /// root-only node tops out at ~48 entries before splits. `num_shards`
    /// is clamped to [16, MAX_SHARDS] by `ShardManifestV7::new`, so we can't
    /// funnel everything to shard 0. Instead we insert 3_000 entries: across
    /// 16 shards with dir-local routing that's ~180+ per shard, well past
    /// the split threshold and into depth ≥ 2 at multiple nodes.
    ///
    /// This guards against split/merge/descent bugs that would be invisible
    /// in the small-N (< 48 entries/shard) regime used by every other test
    /// in this module.
    #[tokio::test]
    async fn deep_hamt_round_trip_3k_entries() {
        let backend = Arc::new(InMemoryBackend::new());
        // 16 shards is the minimum the manifest allows — we want the
        // per-shard density as high as possible to force multi-level HAMT
        // structure (≥ 180 entries/shard average for 3_000 inserts).
        let mut forest = ShardedHamtPrivateForest::new("scale-bucket", test_dek(), 16);

        let total: usize = 3_000;
        let inputs: Vec<ForestFileEntry> = (0..total)
            .map(|i| {
                // Vary two path components so dir-local routing still hits
                // multiple shards (otherwise every file under `/bulk/` lands
                // in one shard via parent-dir hashing). The `g{0..=97}`
                // group varies the parent directory so routing spreads, and
                // the per-file suffix keeps keys unique.
                let path = format!("/bulk/g{:02}/k{:05}.bin", i % 97, i);
                file_entry(&path, i as u64)
            })
            .collect();
        for e in &inputs {
            forest.upsert_file(e.clone(), &backend).await.unwrap();
        }

        let manifest = forest.flush_dirty(&backend).await.unwrap().clone();
        assert!(!forest.is_dirty());

        // Multiple shards populated (dir-local routing spreads the `g??`
        // groups across shards). Total entry_count across the manifest
        // covers every file plus every directory ancestor that was
        // materialized along the way.
        let total_entries: u64 = manifest.shards.iter().map(|s| s.entry_count as u64).sum();
        assert!(
            total_entries >= total as u64,
            "manifest entry_count sum {} must cover all {} files plus ancestor dirs",
            total_entries,
            total
        );
        let populated: Vec<&crate::private_forest::ShardV7> = manifest
            .shards
            .iter()
            .filter(|s| s.root.is_some())
            .collect();
        assert!(
            populated.len() >= 2,
            "dir-local routing should populate multiple shards (got {})",
            populated.len()
        );
        // Depth-growth sanity: at least one shard must hold enough entries
        // that its HAMT is forced past the single-root-node regime
        // (≤ 16 slots × 3 values = 48 inline entries before a split).
        let deepest = populated
            .iter()
            .map(|s| s.entry_count)
            .max()
            .unwrap_or(0);
        assert!(
            deepest > 48,
            "deepest shard entry_count {} must exceed single-node capacity (48) \
             to guarantee depth ≥ 2 is exercised",
            deepest
        );

        // Reload from the persisted manifest — forces every get_file call
        // to descend through real encrypted node blobs, not in-memory
        // cache.
        let mut reopened =
            ShardedHamtPrivateForest::from_manifest(manifest, "scale-bucket", test_dek());

        // Spot-check the extremes and a middle slice; a per-entry loop
        // through all 3_000 would add runtime without extra coverage beyond
        // what `list_all_files` already asserts below.
        for idx in [0usize, 1, 2, 17, 255, 999, 1_500, 2_500, 2_998, 2_999] {
            let want = &inputs[idx];
            let got = reopened.get_file(&want.path, &backend).await.unwrap();
            let got = got.unwrap_or_else(|| panic!("missing path {}", want.path));
            assert_eq!(got.size, want.size, "size mismatch at idx {}", idx);
            assert_eq!(got.path, want.path, "path mismatch at idx {}", idx);
        }

        // Full-enumeration path walks every node blob. Verifies no entries
        // were dropped by a split/merge bug somewhere in the middle of the
        // tree.
        let all = reopened.list_all_files(&backend).await.unwrap();
        assert_eq!(
            all.len(),
            total,
            "list_all_files must return every inserted file"
        );
        let want_paths: HashSet<String> = inputs.iter().map(|e| e.path.clone()).collect();
        let got_paths: HashSet<String> = all.iter().map(|f| f.path.clone()).collect();
        assert_eq!(got_paths, want_paths, "every path must survive the round trip");

        // Remove a slice spread across the key space and verify the tree
        // stays consistent after split/merge traffic at different subtrees.
        let removed_idxs = [0usize, 500, 1_000, 1_500, 2_000, 2_500, 2_999];
        for idx in removed_idxs {
            reopened
                .remove_file(&inputs[idx].path, &backend)
                .await
                .unwrap();
        }
        let manifest2 = reopened.flush_dirty(&backend).await.unwrap().clone();
        let mut reopened2 =
            ShardedHamtPrivateForest::from_manifest(manifest2, "scale-bucket", test_dek());

        for idx in removed_idxs {
            let got = reopened2
                .get_file(&inputs[idx].path, &backend)
                .await
                .unwrap();
            assert!(got.is_none(), "idx {} should have been removed", idx);
        }
        // Remaining entries still reachable.
        for idx in [1usize, 17, 501, 1_001, 1_501, 2_001, 2_501, 2_998] {
            let want = &inputs[idx];
            let got = reopened2.get_file(&want.path, &backend).await.unwrap();
            assert!(got.is_some(), "idx {} ({}) should still exist", idx, want.path);
        }

        // Final enumeration must show exactly the expected count.
        let all_after_rm = reopened2.list_all_files(&backend).await.unwrap();
        assert_eq!(
            all_after_rm.len(),
            total - removed_idxs.len(),
            "remaining count after removals"
        );
    }

    // F6 — concurrent readers on `Arc<RwLock<ShardedHamtPrivateForest>>`
    // must be able to run in parallel once wrapped in `.read().await`
    // guards. Before the F6 refactor the public read API took `&mut self`,
    // which forced every reader to serialize through one outer `Mutex`.
    // This test is a structural proof that the API surface now supports
    // many concurrent readers on a shared forest; a thread panic would
    // be observed as a join failure.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn f6_concurrent_readers_share_forest() {
        let backend = Arc::new(InMemoryBackend::new());
        let mut forest = ShardedHamtPrivateForest::new("bucket-f6", test_dek(), 16);
        for i in 0..50 {
            let path = format!("/d/f{:03}.bin", i);
            forest.upsert_file(file_entry(&path, i as u64), &backend).await.unwrap();
        }
        let _ = forest.flush_dirty(&backend).await.unwrap();

        let shared = Arc::new(tokio::sync::RwLock::new(forest));
        let mut tasks = Vec::new();
        for t in 0..16 {
            let shared = shared.clone();
            let backend = backend.clone();
            tasks.push(tokio::spawn(async move {
                // Each task holds a read guard across a listing + several
                // per-file lookups. With a `Mutex` outer lock these would
                // serialize; with `RwLock::read().await` they must proceed
                // in parallel without deadlocking.
                let guard = shared.read().await;
                let all = guard.list_recursive("/d/", &backend).await.unwrap();
                assert_eq!(all.len(), 50);
                for i in 0..5 {
                    let idx = (t * 5 + i) % 50;
                    let path = format!("/d/f{:03}.bin", idx);
                    let got = guard.get_file(&path, &backend).await.unwrap();
                    assert_eq!(got.unwrap().size, idx as u64);
                }
            }));
        }
        for task in tasks {
            task.await.unwrap();
        }
    }

    // F5 — `list_recursive_page` returns shard-grained pages and round-trips
    // through its opaque cursor to cover every matching file.
    #[tokio::test]
    async fn f5_list_recursive_page_covers_all_matches() {
        let backend = Arc::new(InMemoryBackend::new());
        let mut forest = ShardedHamtPrivateForest::new("bucket-f5", test_dek(), 16);
        let total = 200usize;
        for i in 0..total {
            let path = format!("/x/f{:04}.bin", i);
            forest.upsert_file(file_entry(&path, i as u64), &backend).await.unwrap();
        }
        let _ = forest.flush_dirty(&backend).await.unwrap();

        let mut seen: HashSet<String> = HashSet::new();
        let mut cursor: Option<Vec<u8>> = None;
        let mut pages = 0usize;
        loop {
            let (page, next) = forest
                .list_recursive_page("/x/", cursor.as_deref(), 25, &backend)
                .await
                .unwrap();
            for f in page {
                assert!(seen.insert(f.path), "duplicate path across pages");
            }
            pages += 1;
            match next {
                Some(c) => cursor = Some(c),
                None => break,
            }
            assert!(pages < 1000, "pagination failed to terminate");
        }
        assert_eq!(seen.len(), total, "paginated walk must see every match");
    }
}
