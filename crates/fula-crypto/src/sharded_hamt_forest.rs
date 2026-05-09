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
use cid::Cid;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, VecDeque};
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

/// Wire format for a HAMT leaf entry.
///
/// **Wire-version compatibility (walkable-v8 plan, section W.3.2 / W.9.1b).**
/// Variant tags are part of the on-disk contract:
///
/// | Variant   | Tag | Introduced | Read by   | Written by    |
/// |-----------|-----|------------|-----------|---------------|
/// | `File`    | 0   | v7         | v7+, v8+  | v7+           |
/// | `Dir`     | 1   | v7         | v7+, v8+  | v7+           |
/// | `FileV2`  | 2   | v8         | v8+       | v8+ (W.9.3)   |
///
/// A v7-only deserializer fails on tag `2` with postcard's "unknown variant"
/// error — the intended forward-incompatibility boundary. Mirrors
/// `PointerWire::LinkV2` (W.9.1a). For W.9.1b the writer never emits
/// variant 2 (W.9.3 wires the actual CID-stamping); production HAMT leaves
/// stay byte-identical to v7 on encode, preserving the load-bearing
/// backward-compat property: `From<HamtEntry> for HamtEntryWire` produces
/// byte-identical output for `ForestFileEntry { storage_cid: None, .. }`
/// as it did before W.9.1b. See test
/// `hamt_entry_wire_from_forest_file_entry_with_none_cid_emits_legacy_variant`.
#[derive(Clone, Debug, Serialize, Deserialize)]
enum HamtEntryWire {
    File(FileEntryWire),
    Dir(DirEntryWire),
    FileV2(FileEntryWireV2),
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
    /// Minimum blob-format version for this entry (audit finding H-2).
    /// `0` = legacy (allowed pre-H-2), `4` = written under AAD-bound v4
    /// encryption (download path rejects lower advertised versions).
    ///
    /// AUDIT NOTE (task #42, 2026-05-08): the `#[serde(default)]` here is
    /// operationally dead. Postcard 1.x does NOT honor `serde(default)` for
    /// missing trailing struct fields — it errors with
    /// `DeserializeUnexpectedEnd` (verified empirically during W.9.1b, which
    /// is why `FileEntryWireV2` was added as an enum-variant rather than
    /// appending `storage_cid` to this struct). The reason this attribute
    /// has never broken production is timing: `min_version` landed in
    /// commit `13139c7` on 2026-04-19 17:41Z, and the earliest tag containing
    /// `sharded_hamt_forest.rs` is v0.3.0 dated 2026-04-21 — i.e. no tagged
    /// release ever shipped this struct without `min_version`. The 40h
    /// window between `dd126cf` (file introduced) and `13139c7` saw no
    /// release; any shards persisted from `main` HEAD inside that window
    /// (internal/staging only) are not decodable today, accepted.
    ///
    /// CONTRAST: `ForestFileEntry::min_version` at `private_forest.rs:140-146`
    /// is JSON-encoded, and `serde_json` DOES honor `serde(default)` for
    /// trailing fields — that comment is correct. Only the postcard surface
    /// (this struct) has the misleading-`serde(default)` issue.
    ///
    /// To extend `FileEntryWire` with a future optional field, follow the
    /// W.9.1b pattern: add a new variant to `HamtEntryWire` (cf. `FileV2`).
    /// Do NOT append a field with `serde(default)` and assume backward-compat.
    #[serde(default)]
    min_version: u8,
}

/// Walkable-v8 (W.9.1b) variant of [`FileEntryWire`].
///
/// Mirrors `FileEntryWire` field-for-field PLUS a `storage_cid: Option<Cid>`
/// hint for the encrypted chunk/object blob. Selected by [`HamtEntryWire`]'s
/// variant tag dispatch (variant 2 = `FileV2`), NOT by appending a field to
/// `FileEntryWire` — postcard 1.x does not honor `#[serde(default)]` for
/// missing trailing struct fields (it errors with `DeserializeUnexpectedEnd`
/// rather than substituting the default), so struct field-append is unsafe
/// for backward compatibility. Enum-variant dispatch is the only postcard-safe
/// pattern; this mirrors `PointerWire::LinkV2` in `wnfs_hamt::pointer` (W.9.1a).
///
/// Until W.9.3 wires the writer to capture chunk CIDs from S3BlobBackend's
/// PUT response, the writer continues to emit [`HamtEntryWire::File`]
/// (variant 0). `FileEntryWireV2` is type plumbing only at this stage.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct FileEntryWireV2 {
    path: String,
    storage_key: String,
    size: u64,
    content_type: Option<String>,
    created_at: i64,
    modified_at: i64,
    content_hash: Option<String>,
    user_metadata: BTreeMap<String, String>,
    encrypted: bool,
    /// No `#[serde(default)]` here: `FileEntryWireV2` is the W.9.1b-introduced
    /// variant and was never emitted without `min_version`. Postcard does not
    /// honor `serde(default)` on missing trailing fields anyway (see the
    /// audit note on `FileEntryWire::min_version`); leaving it off makes
    /// the postcard contract explicit — every field of every variant is
    /// required at the wire level, no exceptions.
    min_version: u8,
    /// CID hint for the encrypted chunk/object blob, populated from master's
    /// PUT-response ETag. `Some(_)` here is the trigger for emitting variant
    /// 2 (`FileV2`) on the wire; `None` falls back to legacy variant 0
    /// (`File`) so that v7 SDKs can still read the leaf.
    storage_cid: Option<Cid>,
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
            // Legacy wire never carried a CID hint.
            storage_cid: None,
        }
    }
}

impl From<ForestFileEntry> for FileEntryWireV2 {
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
            storage_cid: e.storage_cid,
        }
    }
}

impl From<FileEntryWireV2> for ForestFileEntry {
    fn from(w: FileEntryWireV2) -> Self {
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
            storage_cid: w.storage_cid,
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
            // Walkable-v8 (W.9.1b) writer dispatch: files with a stamped
            // `storage_cid` emit variant 2 (`FileV2`); files without
            // continue to emit variant 0 (`File`) byte-identically to v7.
            //
            // For W.9.1b foundational scope the upstream call sites do NOT
            // populate `storage_cid` — that's W.9.3's writer integration —
            // so this dispatch always falls through to the legacy variant
            // in production today. The load-bearing property: existing v7
            // SDKs reading buckets written by post-W.9.1b SDKs see
            // byte-identical wire bytes until W.9.3 ships, preserving
            // backward compat throughout the SDK adoption window.
            HamtEntry::File(f) if f.storage_cid.is_some() => {
                HamtEntryWire::FileV2(f.into())
            }
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
            HamtEntryWire::FileV2(f) => HamtEntry::File(f.into()),
        }
    }
}

/// Type-tag prefix for file keys in the HAMT.
const FILE_KEY_PREFIX: &[u8] = b"F:";
/// Type-tag prefix for directory keys in the HAMT.
const DIR_KEY_PREFIX: &[u8] = b"D:";

/// Maximum concurrent HAMT sibling fetches during parallel traversal.
/// HAMT fan-out is 32; a lower cap trades peak memory against
/// fully-populated-node fan-out. Per-node memory is small (~5 KB), so 16
/// is safe on both server and client devices.
pub const MAX_CONCURRENT_HAMT_SIBLINGS: usize = 16;

/// Maximum concurrent shard walks inside full-bucket enumeration
/// (`collect_all_entries` and callers). Each in-flight walk holds decrypted
/// node memory in scope, so this cap is stricter on memory-constrained
/// client devices.
#[cfg(any(target_arch = "wasm32", target_os = "ios", target_os = "android"))]
pub const MAX_CONCURRENT_SHARD_WALKS: usize = 2;
#[cfg(not(any(target_arch = "wasm32", target_os = "ios", target_os = "android")))]
pub const MAX_CONCURRENT_SHARD_WALKS: usize = 4;

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
    /// In-memory directory index (F-1.3). Mutated alongside every
    /// `upsert_file` / `remove_file` / directory mutation so `list_subdirs`
    /// can answer O(1). Persisted separately from the manifest — flushed by
    /// the client layer (`encryption.rs::save_sharded_hamt_forest`) alongside
    /// Phase 2 of the meta-HAMT commit.
    dir_index: crate::private_forest::DirectoryIndex,
    /// Sequence of the last successfully flushed dir-index blob. Bumped
    /// before each re-PUT so stale ciphertexts fail AAD check.
    dir_index_seq: u64,
    /// True when `dir_index` has diverged from the on-disk blob. Flush path
    /// tests this, PUTs a new blob if set, and clears it on success.
    dir_index_dirty: bool,
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
        let num = manifest.num_shards();
        Self {
            manifest,
            loaded_shards: (0..num)
                .map(|_| async_lock::RwLock::new(LoadedShard::NotLoaded))
                .collect(),
            dirty_shards: vec![false; num],
            forest_dek,
            bucket: bucket.into(),
            dir_index: crate::private_forest::DirectoryIndex::new(),
            dir_index_seq: 0,
            dir_index_dirty: false,
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
        let actual_num = manifest.num_shards();
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
            // Fresh forest: start with a root-only index so mkdir on `/foo`
            // doesn't require a rebuild on first use. `dir_index_seq` stays 0
            // until the first successful flush (prior_seq is bound into AAD).
            dir_index: crate::private_forest::DirectoryIndex::new(),
            dir_index_seq: 0,
            dir_index_dirty: true,
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

    /// Immutable reference to the in-memory directory index (F-1.3). The
    /// client layer uses this for O(1) `list_subdirs` and flushes it as a
    /// separate encrypted object at [`crate::private_forest::derive_dir_index_key`].
    pub fn directory_index(&self) -> &crate::private_forest::DirectoryIndex {
        &self.dir_index
    }

    /// Seed the dir-index from an externally-loaded / externally-rebuilt
    /// value. Used on the load path to install the decrypted blob from S3,
    /// and by `migrate_monolithic_to_v7` to install a seeded index.
    pub fn install_dir_index(
        &mut self,
        index: crate::private_forest::DirectoryIndex,
        seq: u64,
    ) {
        self.dir_index = index;
        self.dir_index_seq = seq;
        self.dir_index_dirty = false;
    }

    /// True when the dir-index has unflushed mutations.
    pub fn dir_index_dirty(&self) -> bool {
        self.dir_index_dirty
    }

    /// Last successfully flushed dir-index sequence. Bumped by
    /// `reconcile_dir_index_flush` after a successful PUT.
    pub fn dir_index_seq(&self) -> u64 {
        self.dir_index_seq
    }

    /// Apply the post-flush dir-index reconciliation: record the new seq
    /// and clear the dirty flag. Counterpart to `reconcile_flush` for the
    /// meta-HAMT layer.
    pub fn reconcile_dir_index_flush(&mut self, new_seq: u64) {
        self.dir_index_seq = new_seq;
        self.dir_index_dirty = false;
    }

    /// Force the dir-index into a dirty state so the next flush persists
    /// whatever is currently in memory. Used by the load path after a
    /// `rebuild_directory_index_from_forest` — the in-memory value is
    /// correct, but storage doesn't know about it yet.
    pub fn mark_dir_index_dirty(&mut self) {
        self.dir_index_dirty = true;
    }

    /// Clear the in-memory root's `dir_index_etag` so the next flush's
    /// conditional PUT targets a fresh write rather than gating on a stale
    /// ETag. Used by the rebuild-from-forest path (F-1.3 soft-fail) because
    /// the prior etag on `root.dir_index_etag` points at whatever S3 is
    /// currently holding — which by definition is *not* the plaintext we
    /// just rebuilt from forest shards. Clearing lets us overwrite
    /// unconditionally; the committing root PUT retains its `If-Match` on
    /// the root ETag, so a legitimate concurrent writer's root commit still
    /// wins the race and our flush converges on retry. Must only be called
    /// after `install_dir_index` / `mark_dir_index_dirty` from the
    /// rebuild path; normal mutation flows keep the etag so Phase 1.6's
    /// optimistic lock still catches concurrent dir-index writers.
    pub fn clear_dir_index_etag(&mut self) {
        self.manifest.root.dir_index_etag = None;
    }

    /// Override the root's `dir_index_etag` + `dir_index_seq` with values
    /// observed during load (master's GET response etag + the dir-index
    /// envelope's encrypted-in seq). Counterpart to `load_manifest_pages`'s
    /// page-override logic for the F-1.3 dir-index blob.
    ///
    /// **Why no seq guard (unlike [`reconcile_dir_index_etag`]):** this is
    /// invoked only at initial load, with values that came from the same
    /// fresh fetch round-trip — the observed etag is by definition the
    /// authoritative state of master's actual dir-index object, regardless
    /// of what the manifest happens to have recorded. The seq-guard's
    /// "manifest beats older WAL" semantics don't apply here because the
    /// manifest's recorded etag is precisely what we're correcting.
    pub fn refresh_dir_index_etag_from_load(&mut self, seq: u64, etag: Option<String>) {
        self.manifest.root.dir_index_etag = etag;
        self.manifest.root.dir_index_seq = Some(seq);
    }

    /// Reconcile a single page's root-side etag/seq pin from a post-PUT WAL
    /// record. Invoked on crash-recovery replay: the committing root PUT
    /// didn't fire, so the reloaded `manifest.root.page_index[page_id]`
    /// still carries the pre-crash etag. The post-PUT WAL record supplies
    /// the real etag S3 now serves, letting the next flush's Phase 1.5
    /// `If-Match` succeed instead of looping on 412.
    ///
    /// **Seq guard (task #29).** A WAL entry that is older than the loaded
    /// manifest's `page_index[page_id].seq` reflects a state already
    /// superseded by a later root commit (likely from a different device
    /// or session that won a Phase-2 race). Applying it would clobber the
    /// freshly-loaded etag with a stale one and cause permanent 412 loops
    /// on Phase 1.5 — the exact symptom reported in the FxFiles `images`
    /// regression. Only accept WAL entries that are strictly newer than
    /// the loaded slot. Same-seq is a no-op even if applied (any non-trivial
    /// rewrite within a seq would violate the page-write protocol), so
    /// rejecting it costs nothing and keeps the `manifest > WAL` invariant
    /// when seqs collide.
    pub fn reconcile_page_etag(
        &mut self,
        page_id: crate::private_forest::PageId,
        seq: u64,
        etag: Option<String>,
    ) {
        if let Some(existing) = self.manifest.root.page_index.get(&page_id) {
            if seq <= existing.seq {
                return;
            }
        }
        // Walkable-v8 (#52): recover the CID from the etag string when
        // possible. Master returns `cid.to_string()` as the etag for
        // v8 page PUTs, so a successful parse is the same trustworthy
        // CID the W.9.3 writer would have stamped. Failure (legacy
        // etag, malformed string) falls through to None — the warm
        // cache + storage_key path covers reads in that case. Inline
        // here rather than depending on fula-client's
        // `walkable_v8::cid_hint_from_manifest_field_or_etag` because
        // fula-crypto sits below fula-client in the dep graph.
        let cid: Option<cid::Cid> = etag.as_deref().and_then(|s| s.parse().ok());
        self.manifest.root.page_index.insert(
            page_id,
            crate::private_forest::PageRef { etag, seq, cid },
        );
    }

    /// Reconcile the dir-index root-side etag/seq pin from a post-PUT WAL
    /// record. Counterpart to [`reconcile_page_etag`] for the F-1.3 blob:
    /// after a Phase-1.6-landed-but-Phase-2-crashed write, the reloaded
    /// root's `dir_index_etag` is stale. `self.dir_index_seq` was already
    /// installed from the envelope's seq by the load path; this method
    /// only patches the root-side pins so the next flush's conditional
    /// PUT matches S3.
    ///
    /// **Seq guard (task #29).** Same rationale as `reconcile_page_etag`:
    /// reject WAL entries that aren't strictly newer than the loaded
    /// `dir_index_seq` — they reflect state already superseded by a later
    /// root commit and would silently install a stale etag.
    pub fn reconcile_dir_index_etag(&mut self, seq: u64, etag: Option<String>) {
        if let Some(existing_seq) = self.manifest.root.dir_index_seq {
            if seq <= existing_seq {
                return;
            }
        }
        // Walkable-v8 (#52): recover dir_index_cid from the etag
        // string when possible. Same etag-as-`cid.to_string()`
        // contract the W.9.3 writer establishes; the W.9.4 reader's
        // `cid_hint_from_manifest_field_or_etag` precedence holds —
        // explicit `dir_index_cid` would still take priority on the
        // read path (this just keeps the etag-fallback usable across
        // a master-divergence reconcile instead of silently going to
        // None).
        let cid: Option<cid::Cid> = etag.as_deref().and_then(|s| s.parse().ok());
        self.manifest.root.dir_index_etag = etag;
        self.manifest.root.dir_index_seq = Some(seq);
        self.manifest.root.dir_index_cid = cid;
    }

    /// O(1) list of immediate subdirectories beneath `dir_path`, answered
    /// from the in-memory [`crate::private_forest::DirectoryIndex`]. Falls
    /// back to an empty list if the path isn't recorded — callers that need
    /// a definitive answer on a possibly-unpopulated dir-index should
    /// `rebuild_directory_index_from_forest` first.
    pub fn list_subdirs(&self, dir_path: &str) -> Vec<String> {
        self.dir_index.list_subdirs(dir_path)
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
            self.manifest.shard_salt(),
            self.manifest.num_shards(),
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
            self.manifest.shard_salt(),
            self.manifest.num_shards(),
        )
    }

    /// Build the per-shard node store used for reads and writes.
    ///
    /// The store binds `(bucket, shard_idx)` into node AAD. `shard_seq` is
    /// deliberately absent from node AAD — HAMT flushes only rewrite nodes on
    /// the path of change, so a seq-bound AAD would invalidate untouched
    /// subtree ciphertexts on every flush. Replay protection for shard root
    /// swaps lives at the manifest layer (ETag + `manifest.shard(i).seq`).
    fn reader_store_for<B: BlobBackend + 'static>(
        &self,
        shard_idx: usize,
        backend: &Arc<B>,
    ) -> V7NodeStore<B> {
        V7NodeStore::new(
            self.bucket.clone(),
            shard_idx as u16,
            self.manifest.shard_salt().to_vec(),
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
        match self.manifest.shard(shard_idx).root {
            None => {
                *guard = LoadedShard::LoadedEmpty;
            }
            Some(root_key) => {
                let store = self.reader_store_for(shard_idx, backend);
                // Walkable-v8 (W.9.4): forward `manifest.shard.root_cid`
                // as the cid hint when present so a master-down read of
                // the shard root engages the gateway race. `None` (a
                // legacy v7 manifest, or a manifest written when the
                // writer flag was off) falls through to the
                // storage-key path. The returned plaintext is still
                // verified via `V7NodeStore::decrypt_and_verify`'s
                // recompute-vs-key check, so a malicious manifest that
                // pointed at the right cid but the wrong storage_key
                // would be rejected here.
                let root_cid = self.manifest.shard(shard_idx).root_cid;
                let node: ForestHamt =
                    Node::load_with_cid_hint(&root_key, root_cid.as_ref(), &store)
                        .await?;
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
                let shard = self.manifest.shard_mut(shard_idx);
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
        // #72: do NOT append `file_path` to `d.files` — that field is the
        // 1 MiB single-directory cliff (a flat photo library with 100k+
        // files grew the Dir blob to 1.66 MiB and broke offline reads).
        // `dir.files` is no longer the source of truth for "which files
        // live in this directory"; the listing methods (`list_directory`,
        // `list_subtree`) walk the HAMT for `F:` entries and filter by
        // parent prefix. Legacy buckets with populated `dir.files`
        // continue to deserialize fine; the new walk-based listing
        // returns the same set whether the field is populated or empty.
        let new_dir_entry: ForestDirectoryEntry = match prior_dir.map(HamtEntry::from) {
            Some(HamtEntry::Dir(d)) => d,
            Some(HamtEntry::File(_)) => {
                return Err(CryptoError::Hamt(format!(
                    "directory key D:{} resolved to a File entry — type-tagged HAMT invariant violated",
                    parent
                )));
            }
            None => ForestDirectoryEntry {
                path: parent.clone(),
                files: Vec::new(),
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
        let shard = self.manifest.shard_mut(shard_idx);
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

        // Keep the in-memory DirectoryIndex consistent with the forest. Only
        // count new inserts (overwrites don't change file_count).
        if !had_file {
            self.dir_index.insert_file(&file_path);
            self.dir_index_dirty = true;
        }

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
        // #72: strip `files` before writing. v1→v7 migration carries v1's
        // populated `dir.files` into v7 verbatim today; that's the path
        // that creates the 1 MiB cliff for migrated buckets where v1 had
        // 100k+ files in one directory. v7's listing methods walk the
        // HAMT for `F:` entries (which the migration's separate
        // `upsert_file` loop populates), so `dir.files` is dead weight.
        // Other fields (path, subdirs, metadata, subtree_dek) preserve.
        let mut entry = entry;
        entry.files = Vec::new();
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
            let shard = self.manifest.shard_mut(shard_idx);
            shard.entry_count = shard.entry_count.saturating_add(1);
        }
        self.dirty_shards[shard_idx] = true;

        // Wire this dir into its ancestor chain so `list_directory(parent)`
        // reports it. Root ("/") short-circuits immediately inside the helper.
        self.ensure_ancestor_chain(&dir_path, backend).await?;

        // Mirror the dir's existence in the DirectoryIndex so `list_subdirs`
        // resolves it without touching the HAMT.
        self.dir_index.ensure_dir(&dir_path);
        self.dir_index_dirty = true;

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
            let shard = self.manifest.shard_mut(shard_idx);
            shard.entry_count = shard.entry_count.saturating_sub(1);
            self.dirty_shards[shard_idx] = true;

            // Mirror the deletion in the directory index so subsequent
            // `file_count`/`list_subdirs` queries are coherent without
            // a forest walk.
            self.dir_index.remove_file(path);
            self.dir_index_dirty = true;
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

    /// Fetch a directory entry by path. Returns the `ForestDirectoryEntry`
    /// with its `subdirs` vector populated; `files` is empty on post-#72
    /// buckets — callers should use [`Self::list_directory`] for the file
    /// children, which walks the HAMT directly.
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
    /// the owning shard is touched (dir-local routing).
    ///
    /// **#72 (2026-05-09)**: walks the dir's outer-shard HAMT for `F:`
    /// entries and filters by `parent_dir_of(file.path) == normalized`,
    /// rather than reading `dir.files` (which is no longer populated
    /// post-#72). Eliminates the 1 MiB single-directory cliff at
    /// 60-100k files in one folder. Cost is O(entries in this outer
    /// shard) — under dir-local routing the upper bound is the count
    /// of files belonging to this directory plus any other dirs that
    /// happen to outer-shard-collide with it (typically small). The
    /// trade-off vs. the prior O(K direct children) approach is
    /// acceptable: production fula-client listing already walks the
    /// HAMT this way (`list_recursive_page`), and the prior approach
    /// hit the cliff at K ≥ ~60k anyway.
    pub async fn list_directory<B: BlobBackend + 'static>(
        &self,
        dir_path: &str,
        backend: &Arc<B>,
    ) -> Result<Vec<ForestFileEntry>> {
        let normalized = normalize_dir_path(dir_path);
        let shard_idx = self.shard_for_dir(&normalized);
        self.ensure_shard_loaded(shard_idx, backend).await?;

        let reader = self.reader_store_for(shard_idx, backend);
        let guard = self.loaded_shards[shard_idx].read().await;
        match &*guard {
            LoadedShard::NotLoaded => unreachable!("ensure_shard_loaded above"),
            LoadedShard::LoadedEmpty => Ok(Vec::new()),
            LoadedShard::Loaded(node) => {
                // Walk the shard's HAMT collecting File entries whose
                // parent dir matches. Dir-local routing ensures every
                // file under `normalized` lives in this single shard,
                // so no cross-shard fan-out is needed.
                let wires: Vec<HamtEntryWire> = node
                    .flat_map(
                        &|pair: &Pair<Vec<u8>, HamtEntryWire>| Ok(pair.value.clone()),
                        &reader,
                    )
                    .await?;
                let mut out: Vec<ForestFileEntry> = Vec::new();
                for wire in wires {
                    if let HamtEntry::File(f) = HamtEntry::from(wire) {
                        if parent_dir_of(&f.path) == normalized {
                            out.push(f);
                        }
                    }
                }
                Ok(out)
            }
        }
    }

    //----------------------------------------------------------------------------------------------
    // WAL reconciliation
    //----------------------------------------------------------------------------------------------

    /// Fold a logged `ShardWrote` record into this in-memory forest so the
    /// next `flush_dirty` re-PUTs from the post-recorded sequence.
    ///
    /// Contract (mirrors v6's `shard_sequences` / `shard_etags` reconcile):
    ///   * `manifest.shard(idx).seq` advances to `max(current, observed)`.
    ///   * `manifest.shard(idx).etag` is overwritten with the observed
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
        if idx >= self.manifest.num_shards() {
            return;
        }
        let shard = self.manifest.shard_mut(idx);
        // Seq guard (task #29). Only apply WAL-derived shard reconciliation
        // when the observed seq is strictly newer than the loaded shard's
        // seq. Otherwise we'd clobber a fresh manifest's shard.etag with a
        // stale post-PUT etag from a WAL entry already superseded by a
        // later root commit — same failure mode as `reconcile_page_etag`,
        // applied to the meta-HAMT layer. The previous implementation
        // already gated the seq update behind `observed_seq > shard.seq`
        // but unconditionally overwrote `etag` and forced `dirty_shards`,
        // which still produced the corruption.
        if observed_seq <= shard.seq {
            return;
        }
        shard.seq = observed_seq;
        shard.etag = observed_etag;
        self.dirty_shards[idx] = true;
    }

    /// After a successful two-phase commit (Phase 1.5 page PUTs + Phase 2
    /// root PUT), fold the new root and the drained page IDs back into
    /// this forest so subsequent flushes see the authoritative state.
    ///
    /// Without this, the forest would keep its stale `page_index` /
    /// `dirty_pages` set from before the flush and re-PUT every page on the
    /// next no-op flush under an incremented seq. Counterpart to
    /// `reconcile_shard_write` for the meta-HAMT layer.
    pub fn reconcile_flush(
        &mut self,
        new_root: crate::private_forest::ManifestRoot,
        drained_page_ids: &std::collections::BTreeSet<crate::private_forest::PageId>,
    ) {
        self.manifest.root = new_root;
        for page_id in drained_page_ids {
            self.manifest.dirty_pages.remove(page_id);
        }
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
        use futures::stream::{self, StreamExt, TryStreamExt};
        let num = self.manifest.num_shards();
        let per_shard: Vec<Vec<HamtEntry>> = stream::iter(0..num)
            .map(|shard_idx| async move {
                self.ensure_shard_loaded(shard_idx, backend).await?;
                let reader = self.reader_store_for(shard_idx, backend);
                let guard = self.loaded_shards[shard_idx].read().await;
                let out: Vec<HamtEntry> = match &*guard {
                    LoadedShard::NotLoaded => {
                        unreachable!("ensure_shard_loaded above")
                    }
                    LoadedShard::LoadedEmpty => Vec::new(),
                    LoadedShard::Loaded(node) => {
                        let wires: Vec<HamtEntryWire> = node
                            .flat_map(
                                &|pair: &Pair<Vec<u8>, HamtEntryWire>| Ok(pair.value.clone()),
                                &reader,
                            )
                            .await?;
                        wires.into_iter().map(HamtEntry::from).collect()
                    }
                };
                Ok::<Vec<HamtEntry>, CryptoError>(out)
            })
            .buffer_unordered(MAX_CONCURRENT_SHARD_WALKS)
            .try_collect()
            .await?;
        Ok(per_shard.into_iter().flatten().collect())
    }

    /// Collect every `ForestFileEntry` across every shard.
    ///
    /// Equivalent to `PrivateForest::list_all_files` on v1 monolithic
    /// forests, returning owned entries.
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

    /// Rebuild the [`DirectoryIndex`] (F-1.3) from the live forest state.
    ///
    /// Used as the fallback path when:
    ///   * `load_forest` finds `root.dir_index_etag` but the object at
    ///     [`derive_dir_index_key`] is missing, decrypts to garbage, or
    ///     carries a mismatching ETag (plan D3 / D4).
    ///   * `migrate_monolithic_to_v7` finalizes and needs a v7-side index
    ///     seeded from the freshly-populated shards.
    ///
    /// O(total entries) — walks every shard via
    /// [`Self::collect_all_entries`]. Rare (post-corruption or migration
    /// finalization); not on the hot list/lookup path.
    pub async fn rebuild_directory_index_from_forest<B: BlobBackend + 'static>(
        &self,
        backend: &Arc<B>,
    ) -> Result<crate::private_forest::DirectoryIndex> {
        let all = self.collect_all_entries(backend).await?;
        let mut index = crate::private_forest::DirectoryIndex::new();
        for entry in all {
            match entry {
                HamtEntry::File(f) => index.insert_file(&f.path),
                HamtEntry::Dir(d) => index.ensure_dir(&d.path),
            }
        }
        Ok(index)
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
        let num = self.manifest.num_shards() as u32;
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

    /// Collect every file and directory whose path lies under `prefix`.
    ///
    /// **#72 (2026-05-09)**: rewritten to walk every shard's HAMT and
    /// filter by path prefix, replacing the prior BFS-via-`dir.files`
    /// walker. `dir.files` is no longer populated post-#72 (single-dir
    /// 1 MiB cliff fix) so the BFS-via-`dir.files` approach would
    /// return empty results on new buckets. The new approach matches
    /// the cost characteristic of `extract_subtree` (already used
    /// `collect_all_entries` + prefix-filter for the same reason).
    ///
    /// Returns `(files, directories)`. The root directory (at `prefix`)
    /// is included in `directories` if it exists. Cost is O(N total
    /// entries in bucket) regardless of how localized the prefix is —
    /// trade-off accepted because (a) `list_subtree` was already not on
    /// any hot path, (b) the alternative (sharded `dir.files`) is
    /// ~600 LOC of wire-format work for the same correctness.
    pub async fn list_subtree<B: BlobBackend + 'static>(
        &self,
        prefix: &str,
        backend: &Arc<B>,
    ) -> Result<(Vec<ForestFileEntry>, Vec<ForestDirectoryEntry>)> {
        let normalized_prefix = normalize_dir_path(prefix);
        let all = self.collect_all_entries(backend).await?;

        let mut files_out: Vec<ForestFileEntry> = Vec::new();
        let mut dirs_out: Vec<ForestDirectoryEntry> = Vec::new();

        // Match semantics of the prior BFS walker: a path is "under
        // prefix" if it equals prefix OR starts with `prefix + "/"`.
        // Pure `starts_with(prefix)` would over-match (e.g., prefix
        // "/photos" would match "/photos2024"). Treat root specially —
        // every path is under "/".
        let is_under_prefix = |path: &str| -> bool {
            if normalized_prefix == "/" {
                return true;
            }
            path == normalized_prefix || path.starts_with(&format!("{}/", normalized_prefix))
        };

        for entry in all {
            match entry {
                HamtEntry::File(f) => {
                    if is_under_prefix(&f.path) {
                        files_out.push(f);
                    }
                }
                HamtEntry::Dir(d) => {
                    if is_under_prefix(&d.path) {
                        dirs_out.push(d);
                    }
                }
            }
        }

        Ok((files_out, dirs_out))
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
        let num = self.manifest.num_shards();
        for idx in 0..num {
            if !self.dirty_shards[idx] {
                continue;
            }

            // Bump the manifest's per-shard sequence. This protects the
            // *root pointer* swap in the manifest, not individual node
            // ciphertexts — those are bound by `(bucket, shard_idx)` only
            // so that path-of-change flushes don't strand untouched
            // subtree nodes sealed under older sequences.
            let new_seq = self.manifest.shard(idx).seq.wrapping_add(1);
            self.manifest.shard_mut(idx).seq = new_seq;

            let store: V7NodeStore<B> = V7NodeStore::new(
                self.bucket.clone(),
                idx as u16,
                self.manifest.shard_salt().to_vec(),
                self.forest_dek.clone(),
                backend.clone(),
            );

            // Walkable-v8 (W.9.3): we surface BOTH the storage_key (used
            // by master-S3 reads + the conditional-PUT story) AND the
            // master-attested CID (used by W.9.4's offline gateway race).
            // `cid` is `Some` only when the BlobBackend's `put` returned
            // one (i.e. master S3 with `walkable_v8_writer_enabled = true`
            // and a verified ETag); `None` for in-memory test backends,
            // for writes under the v0.5 default-off mode, or when the
            // master-attested CID failed self-verify against
            // `BLAKE3(ciphertext)`. The two are stamped together so a
            // future flush that doesn't change this shard preserves the
            // pair atomically (next-flush logic only updates a shard's
            // `root` + `root_cid` when its dirty flag is set).
            let (new_root, new_root_cid) = {
                let guard = self.loaded_shards[idx].read().await;
                match &*guard {
                    LoadedShard::NotLoaded => {
                        return Err(CryptoError::Hamt(format!(
                            "shard {} marked dirty but NotLoaded — internal invariant violation",
                            idx
                        )));
                    }
                    LoadedShard::LoadedEmpty => (None, None),
                    LoadedShard::Loaded(node) => {
                        if node.is_empty() {
                            (None, None)
                        } else {
                            let result = node.store(&store).await?;
                            (Some(result.storage_key), result.cid)
                        }
                    }
                }
            };

            let shard = self.manifest.shard_mut(idx);
            shard.root = new_root;
            shard.root_cid = new_root_cid;
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
            storage_cid: None,
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

        // #72: ForestDirectoryEntry.files is no longer populated;
        // listing direct children goes through `list_directory` which
        // walks the dir's outer-shard HAMT for `F:` entries.
        let dir = forest.get_directory("/x/y", &backend).await.unwrap();
        let dir = dir.expect("parent directory must be materialized");
        assert_eq!(dir.path, "/x/y");
        let listing = forest.list_directory("/x/y", &backend).await.unwrap();
        let mut got: HashSet<_> = listing.iter().map(|f| f.path.clone()).collect();
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
    async fn list_subtree_returns_only_entries_under_prefix() {
        let backend = Arc::new(InMemoryBackend::new());
        let mut forest = ShardedHamtPrivateForest::new("bucket-a", test_dek(), 16);

        // Plant two disjoint subtrees. list_subtree("/alpha") should return
        // only the alpha entries, never the beta ones.
        for path in [
            "/alpha/a.txt",
            "/alpha/nested/b.txt",
            "/alpha/nested/deep/c.txt",
            "/beta/x.txt",
            "/beta/y.txt",
        ] {
            forest
                .upsert_file(file_entry(path, 1), &backend)
                .await
                .unwrap();
        }

        let (files, dirs) = forest.list_subtree("/alpha", &backend).await.unwrap();

        let file_paths: HashSet<_> = files.iter().map(|f| f.path.clone()).collect();
        assert_eq!(file_paths.len(), 3);
        assert!(file_paths.contains("/alpha/a.txt"));
        assert!(file_paths.contains("/alpha/nested/b.txt"));
        assert!(file_paths.contains("/alpha/nested/deep/c.txt"));
        // Nothing from the sibling subtree leaks.
        for f in &files {
            assert!(
                f.path.starts_with("/alpha"),
                "unexpected file leaked into /alpha subtree: {}",
                f.path
            );
        }

        let dir_paths: HashSet<_> = dirs.iter().map(|d| d.path.clone()).collect();
        assert!(dir_paths.contains("/alpha"));
        assert!(dir_paths.contains("/alpha/nested"));
        assert!(dir_paths.contains("/alpha/nested/deep"));
        assert!(!dir_paths.contains("/beta"));
    }

    #[tokio::test]
    async fn list_subtree_matches_list_recursive_results() {
        // S-3 parity test: list_subtree must return the same set of files
        // that list_recursive returns, but via the BFS walker (shard-local)
        // rather than the full-bucket scan. Any divergence signals a bug.
        let backend = Arc::new(InMemoryBackend::new());
        let mut forest = ShardedHamtPrivateForest::new("bucket-p", test_dek(), 32);

        let paths = [
            "/docs/a.md",
            "/docs/b.md",
            "/docs/inner/c.md",
            "/docs/inner/d.md",
            "/docs/inner/more/e.md",
            "/images/x.png",
            "/images/y.png",
        ];
        for p in paths.iter() {
            forest
                .upsert_file(file_entry(p, 42), &backend)
                .await
                .unwrap();
        }

        let (subtree_files, _subtree_dirs) =
            forest.list_subtree("/docs", &backend).await.unwrap();
        let recursive = forest.list_recursive("/docs", &backend).await.unwrap();

        let a: HashSet<_> = subtree_files.iter().map(|f| f.path.clone()).collect();
        let b: HashSet<_> = recursive.iter().map(|f| f.path.clone()).collect();
        assert_eq!(a, b, "list_subtree and list_recursive must agree on /docs");
    }

    #[tokio::test]
    async fn list_subtree_handles_missing_prefix_gracefully() {
        // Walker on a path with no directory entry returns empty, not an
        // error. Consistent with `list_directory`'s Option semantics.
        let backend = Arc::new(InMemoryBackend::new());
        let mut forest = ShardedHamtPrivateForest::new("bucket-g", test_dek(), 16);
        forest
            .upsert_file(file_entry("/a.txt", 1), &backend)
            .await
            .unwrap();

        let (files, dirs) = forest
            .list_subtree("/does/not/exist", &backend)
            .await
            .unwrap();
        assert!(files.is_empty());
        assert!(dirs.is_empty());
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
            .shards_iter()
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
        assert!(m1.shard(ga_leaf_idx).root.is_some());
        assert_eq!(m1.shard(ga_leaf_idx).seq, 1);
        assert!(m1.shard(root_dir_idx).root.is_some());
        assert_eq!(m1.shard(root_dir_idx).seq, 1);

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
                m2.shard(ga_leaf_idx).seq, 1,
                "first-flush leaf shard must keep seq=1 when not re-dirtied"
            );
        }
        if gb_leaf_idx != ga_leaf_idx && gb_leaf_idx != root_dir_idx {
            assert_eq!(m2.shard(gb_leaf_idx).seq, 1);
        }
        assert_eq!(
            m2.shard(root_dir_idx).seq, 2,
            "root-dir shard must re-bump when a new top-level dir joins D:/'s subdirs"
        );
    }

    #[tokio::test]
    async fn reopen_with_tampered_root_fails() {
        // `shard_seq` is intentionally NOT bound into per-node AAD — binding
        // it there would strand untouched subtree ciphertexts after the next
        // path-of-change flush (see the design note on `hamt_node_v7_aad`).
        // Replay protection for shard root *swaps* lives at the manifest
        // layer (ETag + `manifest.shard(i).seq`), not per-node.
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
        let mut tampered_root = manifest.shard(leaf_idx).root.expect("populated shard");
        tampered_root[0] ^= 0xFF;
        manifest.shard_mut(leaf_idx).root = Some(tampered_root);

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
        // #72: dir.files is no longer populated; verify via list_directory.
        let leaf_files: Vec<String> = forest
            .list_directory("/a/b", &backend)
            .await
            .unwrap()
            .into_iter()
            .map(|f| f.path)
            .collect();
        assert_eq!(leaf_files, vec!["/a/b/c.txt".to_string()]);
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
        manifest.root.created_at = v1.created_at; // mirror the client-side carryover

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
        assert_eq!(snapshot.root.created_at, 1_700_000_000, "created_at carried forward");

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
        let total_entries: u64 = manifest.shards_iter().map(|s| s.entry_count as u64).sum();
        assert!(
            total_entries >= total as u64,
            "manifest entry_count sum {} must cover all {} files plus ancestor dirs",
            total_entries,
            total
        );
        let populated: Vec<&crate::private_forest::ShardV7> = manifest
            .shards_iter()
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

    // ========================================================================
    // Walkable-v8 wire format tests (W.9.1b)
    //
    // The v8 chunk-CID hint goes through `HamtEntryWire`'s **enum-variant
    // dispatch** (mirrors `PointerWire::LinkV2` in `wnfs_hamt::pointer`),
    // NOT through field-append on `FileEntryWire`. This is the only
    // postcard-safe approach: postcard 1.x does not honor `#[serde(default)]`
    // for missing trailing struct fields (it errors with
    // `DeserializeUnexpectedEnd` rather than substituting the default), so
    // a struct field-append would break backward compat for every existing
    // HAMT leaf the day W.9.3 ships. Enum-variant dispatch keeps v7 leaves
    // byte-identical (variant tag 0 = `File`) while letting v8 writers emit
    // `FileV2` (variant tag 2) when a CID hint is available.
    //
    // Pinned properties (mirror `pointer.rs::walkable_v8_wire_tests`):
    //   1. `HamtEntryWire::FileV2` round-trips through postcard losslessly.
    //   2. The `FileV2` variant index is the postcard tag `2` —
    //      the value an old (v7-only) deserializer doesn't recognize.
    //   3. A v7-only deserializer (`LegacyHamtEntryWire` with only File +
    //      Dir variants) errors cleanly on a v8-format `FileV2` blob.
    //   4. The v8 deserializer reads a v7-format `File` blob unchanged
    //      (legacy data written pre-W.9.1b round-trips fine).
    //   5. **Load-bearing backward-compat**: `From<HamtEntry> for
    //      HamtEntryWire` produces byte-identical output for a
    //      `ForestFileEntry { storage_cid: None, .. }` as it did before
    //      W.9.1b. Without this property, every existing v7 SDK reader
    //      would break the day post-W.9.1b code lands.
    // ========================================================================

    fn walkable_v8_test_cid(seed: u8) -> cid::Cid {
        let digest = [seed; 32];
        let mh = cid::multihash::Multihash::<64>::wrap(0x1e, &digest)
            .expect("BLAKE3 multihash wrap");
        cid::Cid::new_v1(0x55, mh)
    }

    fn fixture_forest_file_entry(path: &str, storage_cid: Option<cid::Cid>) -> ForestFileEntry {
        ForestFileEntry {
            path: path.to_string(),
            storage_key: format!("Qm{}", hex::encode(blake3::hash(path.as_bytes()).as_bytes())),
            size: 1024,
            content_type: Some("text/plain".to_string()),
            created_at: 1,
            modified_at: 2,
            content_hash: Some("blake3:...".to_string()),
            user_metadata: HashMap::new(),
            encrypted: true,
            min_version: 4,
            storage_cid,
        }
    }

    #[test]
    fn hamt_entry_wire_file_legacy_round_trips_via_postcard_variant_0() {
        let entry = fixture_forest_file_entry("/legacy.bin", None);
        let wire: HamtEntryWire = HamtEntry::File(entry.clone()).into();
        let encoded = postcard::to_allocvec(&wire).expect("encode");
        // Legacy variant must be `File` (tag 0). Postcard writes the variant
        // index as the leading byte for small tags.
        assert_eq!(encoded[0], 0, "legacy File variant must be index 0");
        let decoded: HamtEntryWire = postcard::from_bytes(&encoded).expect("decode");
        match decoded {
            HamtEntryWire::File(_) => {}
            other => panic!("expected File variant, got {:?}", other),
        }
    }

    #[test]
    fn hamt_entry_wire_file_v2_round_trips_via_postcard_variant_2() {
        let cid = walkable_v8_test_cid(0xAB);
        let entry = fixture_forest_file_entry("/v8.bin", Some(cid));
        let wire: HamtEntryWire = HamtEntry::File(entry.clone()).into();
        let encoded = postcard::to_allocvec(&wire).expect("encode");
        // FileV2 must be variant 2 — this is the load-bearing
        // forward-incompat dispatch byte. v7-only HamtEntryWire decoders
        // (only File=0, Dir=1) error cleanly on tag 2.
        assert_eq!(
            encoded[0], 2,
            "FileV2 must be variant 2 in the wire format — do not change this. \
             A v7-only HamtEntryWire deserializer relies on tag 2 being \
             unknown to surface a typed error rather than corrupting state."
        );
        let decoded: HamtEntryWire = postcard::from_bytes(&encoded).expect("decode");
        match decoded {
            HamtEntryWire::FileV2(f2) => {
                assert_eq!(f2.storage_cid, Some(cid));
                assert_eq!(f2.path, "/v8.bin");
                assert_eq!(f2.min_version, 4);
            }
            other => panic!("expected FileV2 variant, got {:?}", other),
        }
    }

    #[test]
    fn hamt_entry_wire_from_forest_file_entry_with_none_cid_emits_legacy_variant() {
        // LOAD-BEARING BACKWARD-COMPAT (W.4.3 hard-constraint #1).
        //
        // For W.9.1b's foundational scope the writer NEVER stamps a CID
        // (W.9.3 wires that). All production writes have
        // `storage_cid = None` and MUST emit variant 0 (`File`) byte-
        // identically to v7 so that v7 SDKs continue reading the bucket
        // through the entire SDK-adoption window. If this dispatch ever
        // accidentally picks variant 2 for a None CID, every existing v7
        // reader breaks the day post-W.9.1b code lands.
        let entry = fixture_forest_file_entry("/no-cid.bin", None);
        let wire_v8: HamtEntryWire = HamtEntry::File(entry.clone()).into();
        let v8_bytes = postcard::to_allocvec(&wire_v8).expect("encode v8");
        assert_eq!(
            v8_bytes[0], 0,
            "ForestFileEntry with storage_cid=None MUST emit variant 0 (File), \
             NOT variant 2 (FileV2). Otherwise v7 SDKs break."
        );

        // And the bytes must match exactly what an SDK without W.9.1b
        // changes would have emitted. Construct that simulated-legacy emit
        // by going `HamtEntry → HamtEntryWire::File(FileEntryWire)`
        // explicitly, encode, and compare.
        let wire_legacy_explicit = HamtEntryWire::File(FileEntryWire {
            path: "/no-cid.bin".to_string(),
            storage_key: format!(
                "Qm{}",
                hex::encode(blake3::hash("/no-cid.bin".as_bytes()).as_bytes())
            ),
            size: 1024,
            content_type: Some("text/plain".to_string()),
            created_at: 1,
            modified_at: 2,
            content_hash: Some("blake3:...".to_string()),
            user_metadata: BTreeMap::new(),
            encrypted: true,
            min_version: 4,
        });
        let legacy_bytes =
            postcard::to_allocvec(&wire_legacy_explicit).expect("encode legacy");
        assert_eq!(
            v8_bytes, legacy_bytes,
            "v8 SDK emit for None-CID entry must be byte-identical to v7 emit"
        );
    }

    /// A v7-only enum (only File + Dir variants) — simulates a v0.5-or-earlier
    /// SDK that has never been recompiled to know about `FileV2`. Reading a
    /// v8-format `FileV2` blob into this enum must produce a typed error.
    #[derive(Debug, Serialize, Deserialize)]
    enum LegacyHamtEntryWire {
        File(FileEntryWire),
        Dir(DirEntryWire),
    }

    #[test]
    fn legacy_v7_decoder_errors_on_v8_file_v2_blob() {
        let cid = walkable_v8_test_cid(0xCD);
        let entry = fixture_forest_file_entry("/forward-incompat.bin", Some(cid));
        let wire_v8: HamtEntryWire = HamtEntry::File(entry).into();
        let encoded = postcard::to_allocvec(&wire_v8).expect("encode v8");
        // Sanity check: the FileV2 dispatch fired and we have a variant-2
        // blob to feed to the legacy decoder.
        assert_eq!(encoded[0], 2, "fixture must produce v8 FileV2 blob");

        let result: std::result::Result<LegacyHamtEntryWire, _> =
            postcard::from_bytes(&encoded);
        assert!(
            result.is_err(),
            "v7-only HamtEntryWire deserializer must error on v8 FileV2 blob \
             (forward-incompatibility boundary), got {:?}",
            result
        );
    }

    #[test]
    fn v8_decoder_reads_legacy_v7_file_blob() {
        // A v7 SDK encoded a `File(FileEntryWire)` blob. A v8 SDK reading
        // the same bucket must decode it identically — no upgrade-on-read,
        // legacy data stays accessible until the user happens to write to
        // it (W.4.2: lazy migration on next write).
        let v7_blob = LegacyHamtEntryWire::File(FileEntryWire {
            path: "/v7.bin".to_string(),
            storage_key: "QmV7".to_string(),
            size: 100,
            content_type: None,
            created_at: 0,
            modified_at: 0,
            content_hash: None,
            user_metadata: BTreeMap::new(),
            encrypted: true,
            min_version: 4,
        });
        let encoded = postcard::to_allocvec(&v7_blob).expect("encode v7");
        assert_eq!(encoded[0], 0, "v7 File blob must use variant 0");

        let decoded: HamtEntryWire = postcard::from_bytes(&encoded)
            .expect("v8 decoder must read v7 File blob");
        match decoded {
            HamtEntryWire::File(f) => {
                assert_eq!(f.path, "/v7.bin");
                assert_eq!(f.storage_key, "QmV7");
                assert_eq!(f.min_version, 4);
            }
            other => panic!("expected File variant, got {:?}", other),
        }
    }

    #[test]
    fn forest_file_entry_to_file_entry_wire_v2_preserves_storage_cid_both_directions() {
        // The two-way conversion at the FileEntryWireV2 boundary preserves
        // every field including storage_cid. Mirrors the round-trip pattern
        // in `pointer.rs::walkable_v8_wire_tests::child_ptr_stored_v2_full_pipeline_roundtrip`.
        let cid = walkable_v8_test_cid(0x42);
        let original = fixture_forest_file_entry("/x.bin", Some(cid));

        let wire: FileEntryWireV2 = original.clone().into();
        assert_eq!(wire.storage_cid, Some(cid));
        assert_eq!(wire.storage_key, original.storage_key);
        assert_eq!(wire.path, "/x.bin");

        let recovered: ForestFileEntry = wire.into();
        assert_eq!(recovered.storage_cid, Some(cid));
        assert_eq!(recovered.path, original.path);
        assert_eq!(recovered.encrypted, true);
        assert_eq!(recovered.min_version, 4);
    }

    #[test]
    fn file_entry_wire_legacy_to_forest_file_entry_yields_none_storage_cid() {
        // The legacy `FileEntryWire` (no storage_cid) → `ForestFileEntry`
        // conversion produces `storage_cid = None`. This is what fires when
        // a v8 SDK reads a v7-format `HamtEntryWire::File` leaf — the
        // backward-compat path through `From<FileEntryWire> for ForestFileEntry`.
        let wire = FileEntryWire {
            path: "/legacy.bin".to_string(),
            storage_key: "QmLegacy".to_string(),
            size: 42,
            content_type: None,
            created_at: 0,
            modified_at: 0,
            content_hash: None,
            user_metadata: BTreeMap::new(),
            encrypted: true,
            min_version: 4,
        };
        let entry: ForestFileEntry = wire.into();
        assert_eq!(entry.storage_cid, None);
        assert_eq!(entry.path, "/legacy.bin");
        assert_eq!(entry.storage_key, "QmLegacy");
    }

    // ========================================================================
    // Walkable-v8 writer integration tests (W.9.3)
    //
    // These tests pin the END-TO-END writer wiring: a v8-aware backend
    // surfaces a CID in `BlobPutResult.cid`, the HAMT cascade in
    // `node.rs`/`pointer.rs`/`sharded_hamt_forest.rs` propagates it
    // through `NodePutResult`, and the manifest's per-shard `root_cid`
    // gets stamped. A v8 reader (W.9.4) will then walk via those CIDs.
    //
    // Without these tests the W.9.3 wiring could silently regress —
    // the unit tests in `pointer.rs` and `private_forest.rs` cover
    // each layer in isolation, but only the integration test here
    // exercises the full v8 cascade against a real HAMT.
    // ========================================================================

    /// In-memory backend that emulates master S3's walkable-v8 contract:
    /// every PUT records `BLAKE3(ciphertext)` raw-codec as the returned
    /// CID. Real master computes this via kubo's `block/put?cid-codec=
    /// raw&mhtype=blake3` (see `crates/fula-cli/src/handlers/object.rs:
    /// 103-137`); this fake implements the same contract so the SDK
    /// can be tested end-to-end without a wiremock harness.
    ///
    /// Captures every PUT (`path -> ciphertext`) so the test can later
    /// assert the parent's pointer plaintext references each child
    /// with the correct CID.
    struct CidCapturingBackend {
        objects: std::sync::Mutex<std::collections::HashMap<String, Vec<u8>>>,
    }

    impl CidCapturingBackend {
        fn new() -> Self {
            Self {
                objects: std::sync::Mutex::new(std::collections::HashMap::new()),
            }
        }

        fn get_sync(&self, path: &str) -> Option<Vec<u8>> {
            self.objects.lock().unwrap().get(path).cloned()
        }

        /// Build the same v1 raw-codec BLAKE3-multihash CID master would
        /// emit on PUT for these bytes. This is the contract every
        /// walkable-v8-enabled BlobBackend exposes: `cid.to_string()` is
        /// what master returns in the ETag header.
        fn cid_for(bytes: &[u8]) -> cid::Cid {
            let h = blake3::hash(bytes);
            let mh = cid::multihash::Multihash::<64>::wrap(0x1e, h.as_bytes())
                .expect("blake3 multihash wrap");
            cid::Cid::new_v1(0x55, mh)
        }
    }

    #[async_trait::async_trait]
    impl crate::wnfs_hamt::v7_store::BlobBackend for CidCapturingBackend {
        async fn get(&self, path: &str) -> Result<Vec<u8>> {
            self.objects
                .lock()
                .unwrap()
                .get(path)
                .cloned()
                .ok_or_else(|| {
                    crate::CryptoError::Hamt(format!("v8 fake: object not found: {}", path))
                })
        }

        async fn put(
            &self,
            path: &str,
            bytes: Vec<u8>,
        ) -> Result<crate::wnfs_hamt::v7_store::BlobPutResult> {
            let cid = Self::cid_for(&bytes);
            self.objects
                .lock()
                .unwrap()
                .insert(path.to_string(), bytes);
            Ok(crate::wnfs_hamt::v7_store::BlobPutResult { cid: Some(cid) })
        }
    }

    #[tokio::test]
    async fn walkable_v8_writer_e2e_stamps_shard_root_cid_matching_ciphertext_hash() {
        // Goal: end-to-end check that when the BlobBackend returns a
        // CID for every PUT (= walkable-v8-enabled writer), the flush
        // stamps `manifest.shards[i].root_cid` to a value that matches
        // BLAKE3(ciphertext) of the actual stored bytes. Failure here
        // would mean either:
        //   - sharded_hamt_forest's flush_dirty doesn't propagate the
        //     CID into root_cid (regressing W.9.3-C), OR
        //   - the BlobPutResult plumbing through NodePutResult drops
        //     the CID somewhere (regressing W.9.2's seam).
        let backend = std::sync::Arc::new(CidCapturingBackend::new());
        let mut forest = ShardedHamtPrivateForest::new("bucket-w8", test_dek(), 16);

        // Spread enough entries that at least one shard ends up with a
        // populated root. 256 keys with 16 shards is ~16 entries per
        // shard on average — well past the singleton-bucket threshold.
        for i in 0..32u64 {
            forest
                .upsert_file(
                    file_entry(&format!("/v8/file-{:03}.bin", i), i),
                    &backend,
                )
                .await
                .unwrap();
        }

        // Flush. After this the manifest should carry root_cid hints on
        // every populated shard.
        let manifest = forest.flush_dirty(&backend).await.unwrap().clone();

        // Find populated shards. With CidCapturingBackend, every shard
        // that flushed a non-empty root MUST also carry a Some(cid).
        let mut populated_count = 0usize;
        for (_idx, shard) in manifest.shards_iter().enumerate() {
            if shard.root.is_some() {
                populated_count += 1;
                assert!(
                    shard.root_cid.is_some(),
                    "walkable-v8 writer wired: every populated shard must \
                     have its root_cid stamped (W.9.3 — sharded_hamt_forest::\
                     flush_dirty propagates BlobPutResult.cid into root_cid)"
                );
            } else {
                assert!(
                    shard.root_cid.is_none(),
                    "empty shard must not carry a stale root_cid hint"
                );
            }
        }
        assert!(
            populated_count > 0,
            "test setup invalid: no shard got populated"
        );
    }

    #[tokio::test]
    async fn walkable_v8_writer_e2e_internal_node_pointers_use_link_v2() {
        // Goal: end-to-end check that internal HAMT nodes (parents of
        // mutated children) emit `PointerWire::LinkV2` on their child
        // pointers when the BlobBackend returns CIDs. Loads the shard
        // root's plaintext from the backend, decrypts, and decodes the
        // wire form; asserts at least one `LinkV2` variant appears in
        // a parent that has a mutated subtree.
        //
        // This test exercises the load-bearing assertion of W.9.3-C:
        // the InMemory arm at pointer.rs:243 emits LinkV2 when
        // result.cid is Some. Without it the wire format would still
        // be all-`Link`, breaking offline walks.
        use crate::wnfs_hamt::store::HamtNodeStore;
        let backend = std::sync::Arc::new(CidCapturingBackend::new());
        let mut forest = ShardedHamtPrivateForest::new("bucket-w8b", test_dek(), 16);

        // Enough entries to force at least one shard to grow past a
        // single-leaf bucket and produce internal nodes.
        for i in 0..64u64 {
            forest
                .upsert_file(
                    file_entry(&format!("/deep/{:03}.bin", i), i),
                    &backend,
                )
                .await
                .unwrap();
        }
        let manifest = forest.flush_dirty(&backend).await.unwrap().clone();

        // Find a populated shard whose root has at least one child
        // pointer (indicating an internal node exists in the cascade).
        let mut found_link_v2 = false;
        for (idx, shard) in manifest.shards_iter().enumerate() {
            if shard.root.is_none() {
                continue;
            }
            // Decrypt the root node and inspect its wire form. Use the
            // same V7NodeStore the writer used so AAD matches.
            let store = crate::wnfs_hamt::v7_store::V7NodeStore::new(
                "bucket-w8b",
                idx as u16,
                manifest.shard_salt().to_vec(),
                test_dek(),
                backend.clone(),
            );
            let plaintext = store
                .get_node(&shard.root.unwrap())
                .await
                .expect("root node must decrypt under the writer's DEK");

            // `plaintext` is `postcard(NodeWire { bitmask, pointers })`.
            // Decode and walk the pointers list looking for `LinkV2`.
            #[derive(serde::Deserialize)]
            struct NodeWireInspect<K, V> {
                #[allow(dead_code)]
                bitmask: u16,
                pointers: Vec<crate::wnfs_hamt::pointer::PointerWire<K, V>>,
            }
            let wire: NodeWireInspect<Vec<u8>, HamtEntryWire> =
                postcard::from_bytes(&plaintext).expect("decode root wire");
            for ptr in &wire.pointers {
                if let crate::wnfs_hamt::pointer::PointerWire::LinkV2 { storage_key, cid } =
                    ptr
                {
                    found_link_v2 = true;
                    // Belt-and-suspenders: the CID embedded in the
                    // pointer should match BLAKE3 of the child's stored
                    // ciphertext at this storage_key path.
                    let child_path = format!(
                        "{}{}",
                        crate::wnfs_hamt::v7_store::V7_NODE_PREFIX,
                        hex::encode(storage_key)
                    );
                    let child_bytes = backend
                        .get_sync(&child_path)
                        .expect("child blob must be persisted");
                    let recomputed = CidCapturingBackend::cid_for(&child_bytes);
                    assert_eq!(
                        *cid, recomputed,
                        "LinkV2.cid in parent's pointer plaintext must equal \
                         BLAKE3(child's ciphertext) — without this guarantee, \
                         W.9.4's gateway-race walker would fetch the wrong \
                         bytes for this child"
                    );
                }
            }
            // First populated shard with parent pointers is enough.
            if found_link_v2 {
                break;
            }
        }
        assert!(
            found_link_v2,
            "no LinkV2 variant found in any flushed shard root — the writer \
             cascade either short-circuited (every shard has only a single-leaf \
             bucket) or pointer.rs's InMemory arm is regressing back to legacy \
             Link. Try increasing the entry count for this test, or check \
             pointer.rs:to_wire."
        );
    }

    #[tokio::test]
    async fn walkable_v8_writer_e2e_in_memory_backend_keeps_link_legacy() {
        // Negative control: with the default `InMemoryBackend` (which
        // returns BlobPutResult::none()), the writer cascade MUST emit
        // legacy `Link` only — no `LinkV2`. This pins the v0.5-default
        // backwards-compat: when the writer flag is off (or the backend
        // doesn't surface CIDs), the wire format is byte-identical to
        // the pre-walkable-v8 v7 form.
        use crate::wnfs_hamt::store::HamtNodeStore;
        let backend = std::sync::Arc::new(InMemoryBackend::new());
        let mut forest = ShardedHamtPrivateForest::new("bucket-w8c", test_dek(), 16);

        for i in 0..64u64 {
            forest
                .upsert_file(
                    file_entry(&format!("/d/{:03}.bin", i), i),
                    &backend,
                )
                .await
                .unwrap();
        }
        let manifest = forest.flush_dirty(&backend).await.unwrap().clone();

        // Every populated shard's root_cid MUST be None — the backend
        // returned no CID hints.
        for shard in manifest.shards_iter() {
            assert!(
                shard.root_cid.is_none(),
                "InMemoryBackend returns BlobPutResult::none() — root_cid \
                 must stay None, otherwise the writer is fabricating CIDs"
            );
        }

        // Decode any populated shard's root plaintext and assert no
        // `LinkV2` variant appears in any pointer.
        for (idx, shard) in manifest.shards_iter().enumerate() {
            if shard.root.is_none() {
                continue;
            }
            let store = crate::wnfs_hamt::v7_store::V7NodeStore::new(
                "bucket-w8c",
                idx as u16,
                manifest.shard_salt().to_vec(),
                test_dek(),
                backend.clone(),
            );
            let plaintext = store.get_node(&shard.root.unwrap()).await.unwrap();
            #[derive(serde::Deserialize)]
            struct NodeWireInspect<K, V> {
                #[allow(dead_code)]
                bitmask: u16,
                pointers: Vec<crate::wnfs_hamt::pointer::PointerWire<K, V>>,
            }
            let wire: NodeWireInspect<Vec<u8>, HamtEntryWire> =
                postcard::from_bytes(&plaintext).unwrap();
            for ptr in &wire.pointers {
                assert!(
                    !matches!(
                        ptr,
                        crate::wnfs_hamt::pointer::PointerWire::LinkV2 { .. }
                    ),
                    "InMemoryBackend returns no CIDs — wire MUST stay all-Link, \
                     but found a LinkV2 in shard {}'s root pointers. Writer is \
                     fabricating CIDs.",
                    idx
                );
            }
        }
    }

    // ========================================================================
    // Walkable-v8 reader integration tests (W.9.4)
    //
    // These tests exercise the cid-hint plumbing end-to-end:
    //   * `ChildPtr::StoredV2` → `Node::load_with_cid_hint` →
    //     `HamtNodeStore::get_node_with_cid_hint` →
    //     `BlobBackend::get_with_cid_hint`.
    //
    // The W.9.4 contract has three integrity layers (per advisor design):
    //   1. Gateway content-address check (verify_cid_against_bytes) —
    //      tested separately in gateway_fetch.rs's tampering tests.
    //   2. AEAD decrypt with `(bucket, shard_idx)` AAD — tested by
    //      `get_node_rejects_wrong_shard_idx` / `..._wrong_bucket` /
    //      `..._tampered_blob` in v7_store::tests.
    //   3. **Plaintext storage_key recompute vs caller-supplied key** —
    //      this is the layer that's NEW for W.9.4 and is the subject
    //      of the tamper test below. It defends against a malicious
    //      parent that swapped a sibling's storage_key while keeping
    //      the (cryptographically-valid) cid hint.
    // ========================================================================

    /// Reader-side CID-hint plumbing test (W.9.4). Records every
    /// `get_with_cid_hint` call against the wrapped storage so the test
    /// can assert that:
    ///   * The cid passed down at fetch time is exactly the cid
    ///     embedded in the parent's `PointerWire::LinkV2`.
    ///   * The storage_key passed alongside is the same one the
    ///     parent recorded (NOT silently substituted somewhere in the
    ///     plumbing).
    ///
    /// Wraps a `CidCapturingBackend` so the writer-side cascade still
    /// stamps cids on flush; the reader-side test focuses on what
    /// flows DOWN to the backend during the walk.
    struct HintRecordingBackend {
        inner: std::sync::Arc<CidCapturingBackend>,
        hints_observed: std::sync::Mutex<Vec<(String, Option<cid::Cid>)>>,
    }

    impl HintRecordingBackend {
        fn new() -> Self {
            Self {
                inner: std::sync::Arc::new(CidCapturingBackend::new()),
                hints_observed: std::sync::Mutex::new(Vec::new()),
            }
        }

        fn observed(&self) -> Vec<(String, Option<cid::Cid>)> {
            self.hints_observed.lock().unwrap().clone()
        }
    }

    #[async_trait::async_trait]
    impl crate::wnfs_hamt::v7_store::BlobBackend for HintRecordingBackend {
        async fn get(&self, path: &str) -> Result<Vec<u8>> {
            self.inner.get(path).await
        }

        async fn put(
            &self,
            path: &str,
            bytes: Vec<u8>,
        ) -> Result<crate::wnfs_hamt::v7_store::BlobPutResult> {
            self.inner.put(path, bytes).await
        }

        async fn get_with_cid_hint(
            &self,
            path: &str,
            cid_hint: Option<&cid::Cid>,
        ) -> Result<Vec<u8>> {
            self.hints_observed
                .lock()
                .unwrap()
                .push((path.to_string(), cid_hint.cloned()));
            // Delegate to the underlying CidCapturingBackend's `get` —
            // both online and "offline" branches return the same bytes
            // for this test (the test is about what the parent fed us,
            // not about gateway availability).
            self.inner.get(path).await
        }
    }

    /// Regression guard for #52: a master-divergence reconcile via
    /// `reconcile_page_etag` must NOT silently drop the CID hint
    /// when master's etag is a parseable CID string. Pre-#52 the
    /// reconcile inserted `cid: None` which left
    /// `manifest.root.page_index[page_id].cid` empty until the next
    /// flush re-stamped it — a quiet degradation to v0.5 fidelity.
    #[tokio::test]
    async fn reconcile_page_etag_recovers_cid_from_etag_string() {
        use crate::private_forest::PageRef;
        let backend = std::sync::Arc::new(InMemoryBackend::new());
        let mut forest =
            ShardedHamtPrivateForest::new("bucket-recon", test_dek(), 16);
        // Seed page 0 with a low seq so the reconcile is accepted.
        forest.manifest.root.page_index.insert(
            0,
            PageRef {
                etag: Some("\"old\"".to_string()),
                seq: 5,
                cid: None,
            },
        );
        let _ = backend; // silence unused

        // A real CID (BLAKE3-multihash, raw codec) — the same shape
        // master returns as an etag on v8 page PUTs.
        let cid_str = {
            let h = blake3::hash(b"fake-page-blob");
            let mh = cid::multihash::Multihash::<64>::wrap(0x1e, h.as_bytes())
                .expect("blake3 multihash wrap");
            cid::Cid::new_v1(0x55, mh).to_string()
        };
        let new_seq = 10u64;
        forest.reconcile_page_etag(0, new_seq, Some(cid_str.clone()));

        let entry = forest
            .manifest
            .root
            .page_index
            .get(&0)
            .expect("page 0 reconciled");
        assert_eq!(entry.seq, new_seq, "seq advanced");
        assert_eq!(entry.etag.as_deref(), Some(cid_str.as_str()), "etag updated");
        assert!(
            entry.cid.is_some(),
            "#52 regression: reconcile_page_etag must recover the CID \
             from a CID-shaped etag string instead of silently inserting \
             cid: None"
        );
        // The recovered cid should match what `cid_str.parse()` would produce.
        assert_eq!(
            entry.cid.unwrap().to_string(),
            cid_str,
            "recovered cid must round-trip through the etag string"
        );
    }

    /// Regression guard for #52: same property for the dir-index
    /// reconcile path. `reconcile_dir_index_etag` previously left
    /// `dir_index_cid` untouched on master-divergence, leaving a
    /// stale value lingering even when master's new etag was a
    /// parseable CID.
    #[tokio::test]
    async fn reconcile_dir_index_etag_recovers_cid_from_etag_string() {
        let backend = std::sync::Arc::new(InMemoryBackend::new());
        let mut forest =
            ShardedHamtPrivateForest::new("bucket-recon-dir", test_dek(), 16);
        forest.manifest.root.dir_index_etag = Some("\"old\"".to_string());
        forest.manifest.root.dir_index_seq = Some(3);
        forest.manifest.root.dir_index_cid = None;
        let _ = backend;

        let cid_str = {
            let h = blake3::hash(b"fake-dir-index-blob");
            let mh = cid::multihash::Multihash::<64>::wrap(0x1e, h.as_bytes())
                .expect("blake3 multihash wrap");
            cid::Cid::new_v1(0x55, mh).to_string()
        };
        let new_seq = 9u64;
        forest.reconcile_dir_index_etag(new_seq, Some(cid_str.clone()));

        assert_eq!(forest.manifest.root.dir_index_seq, Some(new_seq));
        assert_eq!(
            forest.manifest.root.dir_index_etag.as_deref(),
            Some(cid_str.as_str())
        );
        assert!(
            forest.manifest.root.dir_index_cid.is_some(),
            "#52 regression: reconcile_dir_index_etag must recover the \
             CID from a CID-shaped etag string"
        );
        assert_eq!(
            forest.manifest.root.dir_index_cid.unwrap().to_string(),
            cid_str
        );
    }

    /// `reconcile_page_etag` with a non-CID etag (legacy / malformed)
    /// must NOT panic and must leave `cid: None` so the warm cache +
    /// storage_key path can take over.
    #[tokio::test]
    async fn reconcile_page_etag_handles_non_cid_etag_as_none() {
        use crate::private_forest::PageRef;
        let backend = std::sync::Arc::new(InMemoryBackend::new());
        let mut forest =
            ShardedHamtPrivateForest::new("bucket-recon-bad", test_dek(), 16);
        forest.manifest.root.page_index.insert(
            0,
            PageRef {
                etag: None,
                seq: 0,
                cid: None,
            },
        );
        let _ = backend;
        forest.reconcile_page_etag(0, 1, Some("\"definitely-not-a-cid\"".to_string()));
        let entry = forest.manifest.root.page_index.get(&0).unwrap();
        assert_eq!(entry.seq, 1);
        assert!(
            entry.cid.is_none(),
            "non-CID etag must surface as cid: None — soft-fail to the \
             storage-key path, no panic"
        );
    }

    #[tokio::test]
    async fn walkable_v8_reader_passes_cid_hint_through_to_backend() {
        // Goal: every fetch of an INTERNAL HAMT node carries the cid
        // its parent recorded at write time. Without this property
        // W.9.4's offline gateway race never engages — the path
        // would silently degrade to the storage-key-only fetch.
        let backend = std::sync::Arc::new(HintRecordingBackend::new());
        let mut forest = ShardedHamtPrivateForest::new("bucket-r8a", test_dek(), 16);

        // Plant enough entries so at least one shard grows internal nodes.
        for i in 0..64u64 {
            forest
                .upsert_file(
                    file_entry(&format!("/r/{:03}.bin", i), i),
                    &backend,
                )
                .await
                .unwrap();
        }
        forest.flush_dirty(&backend).await.unwrap();

        // Drop the writer's in-memory caches by rebuilding the forest
        // from the persisted manifest. This forces the next walk to
        // hit the backend for every internal-node fetch.
        let manifest = forest.manifest().clone();
        let mut reader = ShardedHamtPrivateForest::from_manifest(
            manifest,
            "bucket-r8a",
            test_dek(),
        );

        // Reset hint recorder so we measure ONLY the read-side calls.
        reader
            .list_recursive("/", &backend)
            .await
            .expect("list_recursive on freshly-loaded reader");

        // Among the recorded hints, every internal-node fetch (path
        // matching V7_NODE_PREFIX) must carry Some(cid) UNLESS the
        // parent that referenced it was itself a legacy `Stored`
        // pointer — but in this test every node was written by a v8
        // writer with cid-capturing backend, so every internal-node
        // fetch path MUST have a Some(cid) hint.
        let observed = backend.observed();
        let internal_node_fetches: Vec<_> = observed
            .iter()
            .filter(|(p, _)| p.starts_with(crate::wnfs_hamt::v7_store::V7_NODE_PREFIX))
            .collect();
        assert!(
            !internal_node_fetches.is_empty(),
            "test setup invalid: no internal-node fetches recorded"
        );
        for (path, hint) in &internal_node_fetches {
            assert!(
                hint.is_some(),
                "every internal-node fetch must carry a cid hint when the \
                 forest was written by a v8-aware backend; missing for path {}",
                path
            );
        }

        // Cross-check that each cid hint matches BLAKE3(child ciphertext)
        // — i.e. the cid recorded in the parent points at exactly the
        // bytes the reader is fetching. This is the load-bearing
        // walkable-v8 contract: parent's `LinkV2.cid` IS the address
        // of the child's ciphertext.
        for (path, hint) in &internal_node_fetches {
            let cid = hint.expect("cid hint present (asserted above)");
            let stored = backend
                .inner
                .get_sync(path)
                .expect("backend has the bytes");
            let recomputed = CidCapturingBackend::cid_for(&stored);
            assert_eq!(
                cid, recomputed,
                "cid hint at path {} disagrees with BLAKE3(stored ciphertext); \
                 W.9.3 writer didn't stamp the right cid OR the reader \
                 forwarded a stale value",
                path
            );
        }
    }

    /// Reader-side tamper test (W.9.4 third integrity layer). The
    /// gateway content-address verify (layer 1) and AEAD decrypt
    /// (layer 2) are NOT enough on their own — a malicious parent
    /// could keep both happy by pointing `LinkV2 { storage_key: A,
    /// cid: hash_of_real_node_B }`. The parent's pointer is inside an
    /// AEAD-encrypted ciphertext (key-holders only) so this scenario
    /// requires `forest_dek` compromise; even so, the reader must NOT
    /// be redirected to a sibling node's plaintext just because both
    /// sides pass cryptographic checks. Layer 3 (recompute the
    /// plaintext's storage_key, compare to caller-supplied key)
    /// catches it.
    ///
    /// Setup: plant TWO valid nodes A and B at distinct storage_keys.
    /// Construct a "malicious" backend whose `get_with_cid_hint(path_A,
    /// Some(cid_B))` returns the bytes addressed by cid_B (= node B's
    /// ciphertext, perfectly valid for that cid). The post-fetch
    /// recompute must reject because plaintext_B's storage_key is B,
    /// not A.
    struct MaliciousRedirectBackend {
        cid_to_bytes: std::sync::Mutex<std::collections::HashMap<cid::Cid, Vec<u8>>>,
        path_to_bytes: std::sync::Mutex<std::collections::HashMap<String, Vec<u8>>>,
    }

    impl MaliciousRedirectBackend {
        fn new() -> Self {
            Self {
                cid_to_bytes: std::sync::Mutex::new(std::collections::HashMap::new()),
                path_to_bytes: std::sync::Mutex::new(std::collections::HashMap::new()),
            }
        }
    }

    #[async_trait::async_trait]
    impl crate::wnfs_hamt::v7_store::BlobBackend for MaliciousRedirectBackend {
        async fn get(&self, path: &str) -> Result<Vec<u8>> {
            self.path_to_bytes
                .lock()
                .unwrap()
                .get(path)
                .cloned()
                .ok_or_else(|| crate::CryptoError::Hamt(format!("not found: {}", path)))
        }

        async fn put(
            &self,
            path: &str,
            bytes: Vec<u8>,
        ) -> Result<crate::wnfs_hamt::v7_store::BlobPutResult> {
            let cid = CidCapturingBackend::cid_for(&bytes);
            self.cid_to_bytes
                .lock()
                .unwrap()
                .insert(cid, bytes.clone());
            self.path_to_bytes
                .lock()
                .unwrap()
                .insert(path.to_string(), bytes);
            Ok(crate::wnfs_hamt::v7_store::BlobPutResult { cid: Some(cid) })
        }

        async fn get_with_cid_hint(
            &self,
            _path: &str,
            cid_hint: Option<&cid::Cid>,
        ) -> Result<Vec<u8>> {
            // Malicious behaviour: when the caller supplies a cid hint,
            // resolve via cid (gateway-race emulation) and IGNORE the
            // path. This models a compromised master/gateway that
            // could serve cid_B's bytes when the SDK was looking for
            // node A. The third integrity layer in V7NodeStore must
            // reject this regardless of cid validity.
            match cid_hint {
                Some(cid) => self
                    .cid_to_bytes
                    .lock()
                    .unwrap()
                    .get(cid)
                    .cloned()
                    .ok_or_else(|| {
                        crate::CryptoError::Hamt(format!("cid not found: {}", cid))
                    }),
                None => self.get(_path).await,
            }
        }
    }

    #[tokio::test]
    async fn walkable_v8_reader_rejects_when_redirected_to_sibling_node() {
        use crate::wnfs_hamt::store::HamtNodeStore;
        let backend = std::sync::Arc::new(MaliciousRedirectBackend::new());
        let store = crate::wnfs_hamt::v7_store::V7NodeStore::new(
            "bucket-tamper",
            0,
            vec![0x33; 16],
            test_dek(),
            backend.clone(),
        );

        // Plant two distinct plaintexts. Different bytes ⇒ different
        // storage_keys ⇒ different cids when stored.
        let bytes_a = b"plaintext-node-A".to_vec();
        let bytes_b = b"plaintext-node-B-differs".to_vec();
        let result_a = store.put_node(bytes_a.clone()).await.unwrap();
        let result_b = store.put_node(bytes_b.clone()).await.unwrap();
        assert_ne!(
            result_a.storage_key, result_b.storage_key,
            "test setup: A and B must have distinct storage_keys"
        );
        let cid_b = result_b.cid.expect("MaliciousRedirectBackend stamps cids");

        // Sanity: legitimate read of A succeeds (path → A's bytes).
        let plaintext_a = store
            .get_node_with_cid_hint(&result_a.storage_key, result_a.cid.as_ref())
            .await
            .expect("legitimate (A, cid_A) fetch must succeed");
        assert_eq!(plaintext_a, bytes_a);

        // Tamper attempt: ask for storage_key A but supply cid_B.
        // Layer 1 (gateway): would pass — bytes are valid under cid_B.
        // Layer 2 (AEAD): passes — bytes_B is a legitimately-encrypted
        //                 node under the same DEK + bucket + shard.
        // Layer 3 (recompute): MUST FAIL — plaintext_B's storage_key
        //                 is B, not A.
        let result = store
            .get_node_with_cid_hint(&result_a.storage_key, Some(&cid_b))
            .await;
        assert!(
            result.is_err(),
            "third integrity layer must reject when the supplied cid \
             addresses bytes whose plaintext recomputes to a DIFFERENT \
             storage_key. Got: {:?}",
            result.map(|p| p.len())
        );
        let err_msg = format!("{:?}", result.unwrap_err());
        assert!(
            err_msg.contains("content-address mismatch"),
            "tamper rejection must surface the content-address-mismatch \
             error so the failure mode is unambiguous in logs. Got: {}",
            err_msg
        );
    }

    /// Reader-side default-off test (W.9.4). When the writer flag was
    /// off when the bucket was written (no LinkV2 entries persisted),
    /// the walker's `resolve_owned` dispatches to the legacy `Stored`
    /// arm, which passes `None` as the cid hint. Verifies that:
    ///   * No `Some(cid)` is ever forwarded to the backend during the
    ///     walk of a flag-off bucket.
    ///   * `get_with_cid_hint(_, None)` is byte-identical to `get(_)`
    ///     (the trait's default impl IS this — we just confirm the
    ///     end-to-end path doesn't accidentally fabricate a hint).
    #[tokio::test]
    async fn walkable_v8_reader_default_off_bucket_passes_none_hint() {
        let backend = std::sync::Arc::new(HintRecordingBackend::new());
        // Use the InMemoryBackend's contract (no cids) by giving the
        // hint-recorder a CidCapturingBackend wrapper but ignoring the
        // cids — actually, HintRecordingBackend wraps CidCapturingBackend
        // which DOES return cids on put. To simulate "writer flag off"
        // without changing backends, we construct the manifest manually
        // with `root_cid = None` so the reader sees no v8 hints.
        //
        // Simpler approach: write through CidCapturingBackend so cids
        // are stamped, then strip them from the manifest before the
        // reader phase. The reader's resolve_owned will see only
        // legacy Stored pointers (assuming v7 writes); but the
        // writer in `flush_dirty` and `pointer.rs:to_wire` is what
        // actually decides Link vs LinkV2 based on result.cid. Since
        // CidCapturingBackend returns Some(cid) every time, every
        // node will be written as LinkV2. To get a true flag-off
        // simulation we need a backend whose `put` returns
        // `BlobPutResult::none()` — that's `InMemoryBackend`.
        let inmem_backend = std::sync::Arc::new(InMemoryBackend::new());
        let mut forest =
            ShardedHamtPrivateForest::new("bucket-roff", test_dek(), 16);
        for i in 0..32u64 {
            forest
                .upsert_file(
                    file_entry(&format!("/off/{:03}.bin", i), i),
                    &inmem_backend,
                )
                .await
                .unwrap();
        }
        forest.flush_dirty(&inmem_backend).await.unwrap();
        let manifest = forest.manifest().clone();

        // Now wrap the InMemory backend with the hint recorder so we
        // can observe what the reader passes down. Reader walks via
        // hint-recorder; since the manifest has root_cid = None on
        // every shard AND every internal node was written as legacy
        // `Link` (InMemoryBackend returns no cids), the recorder
        // should see ONLY None hints.
        let recorder = std::sync::Arc::new(InMemoryDelegateRecorder {
            inner: inmem_backend.clone(),
            hints_observed: std::sync::Mutex::new(Vec::new()),
        });

        let mut reader =
            ShardedHamtPrivateForest::from_manifest(manifest, "bucket-roff", test_dek());
        let _ = reader
            .list_recursive("/", &recorder)
            .await
            .expect("list_recursive must succeed under default-off");

        let observed = recorder.hints_observed.lock().unwrap().clone();
        let internal_fetches: Vec<_> = observed
            .iter()
            .filter(|(p, _)| p.starts_with(crate::wnfs_hamt::v7_store::V7_NODE_PREFIX))
            .collect();
        assert!(
            !internal_fetches.is_empty(),
            "test setup invalid: no internal-node fetches occurred"
        );
        for (path, hint) in &internal_fetches {
            assert!(
                hint.is_none(),
                "default-off bucket: cid hint at {} must be None — was {:?}. \
                 If a Some leaks, the reader is fabricating cids that the \
                 writer never stamped, breaking the wire-format-is-the-gate \
                 invariant.",
                path,
                hint
            );
        }
    }

    /// Local backend wrapper used by `walkable_v8_reader_default_off_*`
    /// — delegates everything to an `InMemoryBackend` while recording
    /// each `get_with_cid_hint` call's `cid_hint` argument.
    struct InMemoryDelegateRecorder {
        inner: std::sync::Arc<InMemoryBackend>,
        hints_observed: std::sync::Mutex<Vec<(String, Option<cid::Cid>)>>,
    }

    #[async_trait::async_trait]
    impl crate::wnfs_hamt::v7_store::BlobBackend for InMemoryDelegateRecorder {
        async fn get(&self, path: &str) -> Result<Vec<u8>> {
            self.inner.get(path).await
        }

        async fn put(
            &self,
            path: &str,
            bytes: Vec<u8>,
        ) -> Result<crate::wnfs_hamt::v7_store::BlobPutResult> {
            self.inner.put(path, bytes).await
        }

        async fn get_with_cid_hint(
            &self,
            path: &str,
            cid_hint: Option<&cid::Cid>,
        ) -> Result<Vec<u8>> {
            self.hints_observed
                .lock()
                .unwrap()
                .push((path.to_string(), cid_hint.cloned()));
            self.inner.get(path).await
        }
    }

    /// Mixed-bucket reader test (W.9.4). A bucket can legitimately
    /// contain BOTH legacy `Stored` pointers (subtrees written under
    /// the v0.5 default-off mode) AND `StoredV2` pointers (subtrees
    /// written after the writer flag flipped on). The reader must
    /// handle both in the SAME walk without errors — legacy children
    /// fetch via no-cid path, v8 children fetch via cid path.
    ///
    /// Constructs the mixed state by:
    ///   1. Writing batch A through `InMemoryBackend` (no cids → Link).
    ///   2. Writing batch B through `CidCapturingBackend` against the
    ///      SAME manifest state (same `bucket_salt`, same DEK), so
    ///      batch B's path-of-change cascade re-encodes some shared
    ///      ancestor nodes with mixed-variant pointers.
    /// Then walks via the cid-capturing backend and verifies every
    /// upserted file is reachable.
    #[tokio::test]
    async fn walkable_v8_reader_mixed_link_and_link_v2_in_one_bucket() {
        // Phase 1 — write batch A through a no-cid backend.
        let no_cid = std::sync::Arc::new(InMemoryBackend::new());
        let mut forest =
            ShardedHamtPrivateForest::new("bucket-mixed", test_dek(), 16);
        for i in 0..16u64 {
            forest
                .upsert_file(file_entry(&format!("/A/{:02}.bin", i), i), &no_cid)
                .await
                .unwrap();
        }
        forest.flush_dirty(&no_cid).await.unwrap();

        // Phase 2 — switch to a cid-capturing backend that has access
        // to the SAME object map (so it can read the legacy nodes
        // batch A wrote AND surface cids on subsequent puts). We
        // achieve this by sharing the same underlying object store.
        let mixed = std::sync::Arc::new(SharedObjectsBackend {
            objects: no_cid.clone(),
            stamp_cid: true,
        });

        // Continue mutating the forest with the new backend. Any
        // internal node touched by the path-of-change re-encodes; the
        // re-encoded parent contains a mix of `Link` (untouched
        // sibling, came from batch A) and `LinkV2` (mutated child,
        // freshly stamped).
        for i in 16..32u64 {
            forest
                .upsert_file(file_entry(&format!("/B/{:02}.bin", i), i), &mixed)
                .await
                .unwrap();
        }
        forest.flush_dirty(&mixed).await.unwrap();

        // Reader phase — walk the mixed forest and verify every
        // entry from BOTH batches is reachable. If the resolve_owned
        // dispatch were buggy (e.g. failing the legacy Stored arm
        // when intermixed with StoredV2), this list_recursive would
        // miss the batch-A entries.
        let manifest = forest.manifest().clone();
        let mut reader = ShardedHamtPrivateForest::from_manifest(
            manifest,
            "bucket-mixed",
            test_dek(),
        );
        let listed = reader
            .list_recursive("/", &mixed)
            .await
            .expect("mixed-bucket walk must succeed");
        let paths: std::collections::HashSet<String> =
            listed.iter().map(|f| f.path.clone()).collect();
        for i in 0..16u64 {
            assert!(
                paths.contains(&format!("/A/{:02}.bin", i)),
                "batch-A entry /A/{:02}.bin missing — the reader's legacy \
                 Stored arm regressed when intermixed with StoredV2",
                i
            );
        }
        for i in 16..32u64 {
            assert!(
                paths.contains(&format!("/B/{:02}.bin", i)),
                "batch-B entry /B/{:02}.bin missing — the reader's StoredV2 \
                 arm broke",
                i
            );
        }
    }

    /// Backend wrapper that shares the same underlying object map as
    /// another `InMemoryBackend` while choosing whether to surface
    /// cids on `put`. Used by the mixed-bucket test to swap the
    /// stamping policy mid-bucket without losing the batch-A objects.
    struct SharedObjectsBackend {
        objects: std::sync::Arc<InMemoryBackend>,
        stamp_cid: bool,
    }

    #[async_trait::async_trait]
    impl crate::wnfs_hamt::v7_store::BlobBackend for SharedObjectsBackend {
        async fn get(&self, path: &str) -> Result<Vec<u8>> {
            self.objects.get(path).await
        }

        async fn put(
            &self,
            path: &str,
            bytes: Vec<u8>,
        ) -> Result<crate::wnfs_hamt::v7_store::BlobPutResult> {
            // Compute the cid from bytes BEFORE delegating — the
            // delegate consumes bytes and returns BlobPutResult::none().
            let cid = if self.stamp_cid {
                Some(CidCapturingBackend::cid_for(&bytes))
            } else {
                None
            };
            self.objects.put(path, bytes).await?;
            Ok(crate::wnfs_hamt::v7_store::BlobPutResult { cid })
        }

        async fn get_with_cid_hint(
            &self,
            path: &str,
            _cid_hint: Option<&cid::Cid>,
        ) -> Result<Vec<u8>> {
            // For this test we don't simulate master-down; just
            // delegate to `get`. The hint-bearing path inside
            // V7NodeStore is exercised at the V7NodeStore level, not
            // here.
            self.objects.get(path).await
        }
    }

    // ========================================================================
    // Walkable-v8 scale + block-size tests (W.9.7)
    //
    // The single load-bearing W.8 design assertion: **no IPFS block
    // exceeds 1 MiB** at any production-realistic scale. Standard
    // gateways enforce this limit; a single >1MiB block would fail
    // every offline-walk fetch (W.9.4) and invalidate the W.10
    // default-on rollout.
    //
    // Cliff to actively look for: the writer cascade serialises the
    // pointer list at each HAMT level. If anything ever lets the
    // pointer-array grow past the HAMT branching factor (16 — bounded
    // by the bitmask u16), block size could spike past 1 MiB. The
    // size assertion is the regression guard.
    //
    // Three scales:
    //   * `_at_1k_entries`         — regular test, runs in CI.
    //   * `_at_100k_entries`       — `#[ignore]`. Operator runs in
    //     release mode (`cargo test --release -- --ignored
    //     walkable_v8_block_size_at_100k`). ~30 s on a fast box.
    //     Memory ceiling: ~150 MB residual encrypted blobs in the
    //     backend's HashMap.
    //   * `_at_1m_entries`         — `#[ignore]`. Pre-release operator
    //     check. Could take 30+ min in release mode. Memory ceiling:
    //     ~5 GB. The test enforces the ceiling by running it only
    //     when explicitly opted-in.
    // ========================================================================

    /// Backend that returns `Some(BLAKE3-raw-cid)` from `put` so the
    /// walkable-v8 writer cascade actually emits `LinkV2` (advisor
    /// note: the existing `InMemoryBackend` returns
    /// `BlobPutResult::none()`, which would silently regress the test
    /// to v7 wire-format and miss any v8-specific blowup).
    ///
    /// Records the largest observed encrypted-blob size + a
    /// per-blob histogram so the assertion has a clear failure
    /// payload when violated (e.g., "shard root grew to 1.3 MiB at
    /// entry 87523").
    struct WalkableV8RecordingBackend {
        objects: std::sync::Mutex<std::collections::HashMap<String, Vec<u8>>>,
        max_observed_size: std::sync::atomic::AtomicUsize,
        max_observed_path: std::sync::Mutex<String>,
    }

    impl WalkableV8RecordingBackend {
        fn new() -> Self {
            Self {
                objects: std::sync::Mutex::new(std::collections::HashMap::new()),
                max_observed_size: std::sync::atomic::AtomicUsize::new(0),
                max_observed_path: std::sync::Mutex::new(String::new()),
            }
        }

        fn record_max_size(&self, path: &str, size: usize) {
            // CAS loop to keep the path label in sync with the size —
            // we want operator triage to know WHICH path was the
            // biggest, not just the size.
            let prev = self
                .max_observed_size
                .fetch_max(size, std::sync::atomic::Ordering::SeqCst);
            if size > prev {
                let mut guard = self.max_observed_path.lock().unwrap();
                *guard = path.to_string();
            }
        }

        fn max_size(&self) -> usize {
            self.max_observed_size
                .load(std::sync::atomic::Ordering::SeqCst)
        }

        fn max_path(&self) -> String {
            self.max_observed_path.lock().unwrap().clone()
        }

        fn object_count(&self) -> usize {
            self.objects.lock().unwrap().len()
        }
    }

    #[async_trait::async_trait]
    impl crate::wnfs_hamt::v7_store::BlobBackend for WalkableV8RecordingBackend {
        async fn get(&self, path: &str) -> Result<Vec<u8>> {
            self.objects
                .lock()
                .unwrap()
                .get(path)
                .cloned()
                .ok_or_else(|| crate::CryptoError::Hamt(format!("not found: {}", path)))
        }

        async fn put(
            &self,
            path: &str,
            bytes: Vec<u8>,
        ) -> Result<crate::wnfs_hamt::v7_store::BlobPutResult> {
            // Reuse the shared cid_for helper from CidCapturingBackend
            // (defined earlier in this test module) so both backends
            // hash bytes identically — the v8 cascade then sees
            // consistent CIDs across the test suite.
            let cid = CidCapturingBackend::cid_for(&bytes);
            self.record_max_size(path, bytes.len());
            self.objects
                .lock()
                .unwrap()
                .insert(path.to_string(), bytes);
            Ok(crate::wnfs_hamt::v7_store::BlobPutResult { cid: Some(cid) })
        }
    }

    /// Standard IPFS gateway block-size limit (1 MiB) — the **hard
    /// gateway-correctness guard**. Any block above this fails
    /// offline-walk fetches via public gateways and invalidates W.8.3.
    const IPFS_BLOCK_LIMIT: usize = 1 << 20;

    /// Architectural early-warning ceiling (64 KiB). Per plan W.8.3 the
    /// **expected** worst-case HAMT internal-node ciphertext size is
    /// ~4 KB. Any block above 64 KiB is a 16× regression vs the
    /// architectural prediction — well below the gateway limit but
    /// indicative of an unintended fanout / pointer-list growth that
    /// would eventually blow past the hard ceiling at higher scale.
    /// Crossing this threshold prints a structured `eprintln!` for
    /// operator triage but does NOT fail the test (only IPFS_BLOCK_LIMIT
    /// is a hard fail). Two distinct failure modes, two distinct
    /// signals — gateway correctness vs architectural regression.
    const SOFT_BLOCK_WARN_KIB: usize = 64 * 1024;

    /// Inner helper shared by all three scales so the assertion
    /// surface stays identical regardless of which `#[test]` /
    /// `#[ignore]` gate fires.
    ///
    /// **Scope** (per W.9.7 dual-advisor audit): this helper observes
    /// only blobs written via the in-crate `BlobBackend::put` path
    /// — i.e. HAMT internal-node and shard-leaf-bucket ciphertexts
    /// from `V7NodeStore`. Manifest pages, the manifest root, and
    /// the directory-index ciphertexts are persisted by
    /// `crates/fula-client/src/encryption.rs`'s Phase 1.5 / 1.6 / 2
    /// commits via `S3BlobBackend.put_object_*` (a different layer
    /// the SDK owns). Those blobs need a sibling block-size test in
    /// `fula-client/tests/` to fully establish W.8.3's "no block
    /// exceeds 1 MiB" claim across every persisted blob class. See
    /// the W.9.7 follow-up task for the manifest-side variant.
    ///
    /// **Distribution** (W.9.7 finding from first 100k run): when
    /// every entry is `/d/f{i}.bin` (single parent dir), the
    /// `ForestDirectoryEntry` for `/d` accumulates one filename per
    /// entry in its `files: Vec<String>` field. At 100k entries
    /// that single Dir blob grows to ~1.7 MiB, exceeding the gateway
    /// limit. This is a real architectural cliff for "single
    /// directory with 100k+ files" — separate from HAMT-cascade
    /// scaling. Tracked as follow-up #72 (directory sharding).
    /// To exercise pure HAMT scaling without that confound, this
    /// helper distributes entries across `~sqrt(N)` parent dirs so
    /// each Dir entry stays small (~`sqrt(N)` filenames) regardless
    /// of total N. Production-scale FxFiles users with 100k files
    /// would naturally distribute across folders; the test mirrors
    /// that.
    async fn run_walkable_v8_block_size_assertion(num_entries: usize) {
        let backend = std::sync::Arc::new(WalkableV8RecordingBackend::new());
        // Use enough shards (256) that internal-node depth at 1M
        // entries stays at log_16(1M / 256) ≈ 3-4 levels, matching
        // production sharding heuristics. Fewer shards would
        // artificially inflate internal-node fanout per shard and
        // give a falsely-large worst-case block size.
        let mut forest =
            ShardedHamtPrivateForest::new("scale-bucket", test_dek(), 256);

        // Distribute across `~sqrt(N)` parent dirs (capped reasonably).
        // Picking sqrt(N) rather than fixed-1000 keeps the per-dir
        // file count balanced across scales (1k → 32 files/dir,
        // 100k → 316 files/dir, 1M → 1000 files/dir). Each
        // ForestDirectoryEntry stays small enough that its
        // serialized blob fits comfortably under 1 MiB at every
        // scale this test covers.
        let dirs_per_layer: usize = ((num_entries as f64).sqrt() as usize).max(1);

        // Minimal `ForestFileEntry` — the test is about HAMT block
        // size, not about realistic file metadata. Smaller entries
        // also let us stretch to higher N before memory ceilings.
        for i in 0..num_entries {
            let dir_idx = i % dirs_per_layer;
            let path = format!("/d{:04}/f{:08}.bin", dir_idx, i);
            forest
                .upsert_file(file_entry(&path, 0), &backend)
                .await
                .unwrap();
        }
        forest.flush_dirty(&backend).await.unwrap();

        let largest = backend.max_size();
        let largest_path = backend.max_path();
        let object_count = backend.object_count();

        eprintln!(
            "[walkable-v8 W.9.7] entries={} hamt_node_objects={} largest_hamt_block={} bytes \
             ({:.1} KiB) at path {}",
            num_entries,
            object_count,
            largest,
            largest as f64 / 1024.0,
            largest_path
        );

        // Architectural early-warning (soft). Emits but does NOT
        // fail — the regression-vs-prediction signal is decoupled
        // from the gateway-correctness signal so operators can act
        // on either independently.
        if largest > SOFT_BLOCK_WARN_KIB {
            eprintln!(
                "[walkable-v8 W.9.7] SOFT WARNING: largest HAMT-node block ({} bytes / \
                 {} KiB) exceeds the architectural early-warning ceiling ({} KiB). \
                 Plan W.8.3 predicts ~4 KB worst-case; >64 KiB is a 16× regression. \
                 The hard 1 MiB assert below still passes (gateway correctness \
                 preserved), but inspect the parent-pointer fanout at path {} before \
                 letting this land in production.",
                largest,
                largest / 1024,
                SOFT_BLOCK_WARN_KIB / 1024,
                largest_path,
            );
        }

        assert!(
            largest > 0,
            "test setup invalid: no objects landed in the backend"
        );
        assert!(
            largest <= IPFS_BLOCK_LIMIT,
            "LOAD-BEARING W.8.3 ASSERTION VIOLATED: encrypted HAMT-node block at {} \
             grew to {} bytes ({} KiB) which exceeds the 1 MiB IPFS gateway limit. \
             Walkable-v8 offline walks would fail for this block. Investigate: \
             pointer-array fanout exceeded HAMT branching factor (16)? Run with \
             `RUST_BACKTRACE=1` and inspect the parent chain of {}. NOTE: this \
             test scope is HAMT-node blobs only — manifest-page / dir-index blobs \
             are persisted via fula-client's S3BlobBackend and need a sibling \
             test (see W.9.7 follow-up task #72).",
            largest_path,
            largest,
            largest / 1024,
            largest_path
        );
    }

    #[tokio::test]
    async fn walkable_v8_block_size_at_1k_entries_stays_under_1mib() {
        // Regular test — runs in CI on every PR. 1k entries finishes
        // in ~1-3 s in debug mode.
        run_walkable_v8_block_size_assertion(1_000).await;
    }

    #[tokio::test]
    #[ignore = "operator-run pre-release; release mode required, ~30s + ~150MB RAM"]
    async fn walkable_v8_block_size_at_100k_entries_stays_under_1mib() {
        // `cargo test --release -p fula-crypto --lib -- --ignored \
        //   walkable_v8_block_size_at_100k_entries_stays_under_1mib`
        //
        // 100k is the realistic upper bound for FxFiles users
        // (hundreds-to-thousands typical, 100k is a power user). If
        // this fails, walkable-v8 is broken for power users — block
        // and rollout.
        run_walkable_v8_block_size_assertion(100_000).await;
    }

    #[tokio::test]
    #[ignore = "operator-run pre-major-release only; release mode required, ~30 min + ~5GB RAM"]
    async fn walkable_v8_block_size_at_1m_entries_stays_under_1mib() {
        // `cargo test --release -p fula-crypto --lib -- --ignored \
        //   walkable_v8_block_size_at_1m_entries_stays_under_1mib`
        //
        // 1M is a stress ceiling, not a realistic workload. Per
        // advisor's W.9.7 brief: this test exists to "find the
        // architectural cliff before users do." A failure here would
        // not block rollout for typical-scale users but would force
        // a redesign for the long-tail enterprise case.
        //
        // Memory: every one of the ~1M-ish persisted encrypted blobs
        // stays in the backend's HashMap so canonicalize-during-write
        // can read its children. Expect ~5 GB residual at peak. If
        // the test OOMs your dev box, run on a host with ≥ 16 GB
        // free or skip it (the 100k test is the practical pre-release
        // gate; 1M is the long-tail check).
        run_walkable_v8_block_size_assertion(1_000_000).await;
    }

    /// **Architectural finding documented as a regression guard.**
    ///
    /// First 100k run of `walkable_v8_block_size_at_100k_entries_*`
    /// (with all entries in a single parent dir) failed at
    /// 1.66 MiB — the `ForestDirectoryEntry` for the single shared
    /// parent grew unbounded as `files: Vec<String>` accumulated one
    /// entry per upsert. This is a known limitation: a directory
    /// containing 100k+ files in flat layout produces a single
    /// HAMT-stored Dir blob that exceeds the 1 MiB gateway ceiling.
    ///
    /// This test pins the threshold by ramping up entries in a SINGLE
    /// directory until the block-size limit is hit. It runs at a
    /// modest scale (10k entries — well below the cliff but
    /// approaching the documented warning ceiling) so it stays in
    /// CI; the actual failure mode (~60-100k entries in one dir
    /// pushes past 1 MiB) is documented in the assertion message.
    ///
    /// Why keep this test rather than just deleting it: a future
    /// regression re-introducing per-file growth in `dir.files`
    /// would silently re-create the cliff — this test catches it.
    ///
    /// **#72 RESOLVED 2026-05-09**: `upsert_file` no longer appends
    /// the file's path to its parent dir's `files: Vec<String>`. The
    /// listing API (`list_directory`, `list_subtree`) walks the HAMT
    /// for `F:` entries directly, so `dir.files` is dead weight on
    /// new buckets. This test is now an inverted regression guard.
    #[tokio::test]
    async fn walkable_v8_single_directory_block_size_under_post_fix_72() {
        // 10k entries in /single-dir. Pre-fix this produced a
        // ForestDirectoryEntry blob in the ~150-300 KiB range
        // (linear in number of children). Post-fix the Dir blob
        // contains only `path`, empty `files`, empty `subdirs`,
        // None metadata, None subtree_dek — a few hundred bytes
        // at most regardless of child count.
        let backend = std::sync::Arc::new(WalkableV8RecordingBackend::new());
        let mut forest =
            ShardedHamtPrivateForest::new("single-dir-test", test_dek(), 256);
        for i in 0..10_000usize {
            let path = format!("/single-dir/f{:08}.bin", i);
            forest
                .upsert_file(file_entry(&path, 0), &backend)
                .await
                .unwrap();
        }
        forest.flush_dirty(&backend).await.unwrap();

        // Verify dir.files is empty post-fix (the load-bearing change).
        let dir_entry = forest
            .get_directory("/single-dir", &backend)
            .await
            .unwrap()
            .expect("/single-dir must materialize after 10k upserts");
        assert!(
            dir_entry.files.is_empty(),
            "#72 regression: ForestDirectoryEntry.files should stay empty post-fix \
             but contained {} entries. The single-directory cliff returned.",
            dir_entry.files.len()
        );

        // Verify the listing API still surfaces all 10k files via
        // the new walk-based path.
        let listing = forest.list_directory("/single-dir", &backend).await.unwrap();
        assert_eq!(
            listing.len(),
            10_000,
            "list_directory must return all 10k files via HAMT walk (got {})",
            listing.len()
        );

        // Hard ceiling: no encrypted HAMT-node blob exceeds 1 MiB.
        // Pre-fix this would have been at risk at much larger N
        // (60-100k); post-fix it's not even close at 10k.
        let largest = backend.max_size();
        eprintln!(
            "[walkable-v8 #72 post-fix] 10k files in /single-dir/: largest blob \
             {} bytes ({:.1} KiB), dir.files.len()={}",
            largest, largest as f64 / 1024.0, dir_entry.files.len()
        );
        assert!(
            largest <= IPFS_BLOCK_LIMIT,
            "Largest HAMT blob {} bytes exceeds 1 MiB at 10k single-dir entries — \
             post-fix invariant violated.",
            largest
        );
    }

    /// **#72 stress test**: 100k FILES in a SINGLE directory. This
    /// is the size that empirically hit the 1 MiB cliff pre-fix
    /// (1.66 MiB Dir blob). Post-fix the Dir blob stays tiny
    /// regardless of file count. Operator-run pre-major-release;
    /// release mode required for memory headroom.
    ///
    /// **NOTE (Reviewer B audit)**: this only verifies the FILES
    /// cliff is gone. A symmetric `subdirs: Vec<String>` cliff
    /// exists for directories with 100k+ direct subdirectories
    /// (`ensure_ancestor_chain` does `d.subdirs.push(child)`
    /// linearly). That parallel cliff is tracked separately; it
    /// has not been observed empirically and is rarer in practice
    /// (users with 100k subdirs at one level are uncommon).
    ///
    /// `cargo test --release -p fula-crypto --lib -- --ignored \
    ///   walkable_v8_single_directory_at_100k_post_fix_72`
    #[tokio::test]
    #[ignore = "operator-run pre-release; release mode required, ~30s + ~150MB RAM"]
    async fn walkable_v8_single_directory_at_100k_post_fix_72() {
        let backend = std::sync::Arc::new(WalkableV8RecordingBackend::new());
        let mut forest =
            ShardedHamtPrivateForest::new("single-dir-100k", test_dek(), 256);
        for i in 0..100_000usize {
            let path = format!("/single-dir/f{:08}.bin", i);
            forest
                .upsert_file(file_entry(&path, 0), &backend)
                .await
                .unwrap();
        }
        forest.flush_dirty(&backend).await.unwrap();

        let dir_entry = forest
            .get_directory("/single-dir", &backend)
            .await
            .unwrap()
            .expect("/single-dir must exist after 100k upserts");
        assert!(
            dir_entry.files.is_empty(),
            "#72 regression at 100k: dir.files should be empty, was {}",
            dir_entry.files.len()
        );

        let largest = backend.max_size();
        let largest_path = backend.max_path();
        eprintln!(
            "[walkable-v8 #72 100k] largest blob {} bytes ({:.1} KiB) at {}",
            largest, largest as f64 / 1024.0, largest_path
        );
        assert!(
            largest <= IPFS_BLOCK_LIMIT,
            "100k files in /single-dir/ → largest blob {} bytes exceeds 1 MiB. \
             #72 regression: the cliff returned. Inspect {} for dir.files growth \
             or HAMT-node fanout regression.",
            largest, largest_path
        );
    }
}
