//! Private Forest - Encrypted directory index for complete structure hiding
//!
//! Inspired by WNFS (WebNative File System) and Peergos, this module implements
//! a "private forest" - an encrypted index that stores the file system structure
//! while presenting only opaque, random-looking keys to the storage layer.
//!
//! # Design Goals
//!
//! 1. **Complete Structure Hiding**: Server sees only random CID-like hashes
//! 2. **No Prefix Leakage**: Unlike `e/hash`, keys look like `Qm...` (CID-style)
//! 3. **Encrypted Index**: File tree stored encrypted in the bucket itself
//! 4. **Efficient Browsing**: File manager can list/browse without downloading content
//! 5. **Sharing Support**: Share subtrees by sharing encrypted index portions
//! 6. **Key Rotation**: Re-encrypt index without re-encrypting all files
//!
//! # Architecture
//!
//! ```text
//! Storage Layer (What Server Sees):
//! ┌─────────────────────────────────────────────────┐
//! │ QmX7a8f3e2d1c9b4a5e6f7d8c9a0b1e2f3a4b5c6d7e8f9 │ <- file data
//! │ QmY9c4b2a1d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1 │ <- file data
//! │ QmZ3e5d7c9a1b2f4e6d8a0c2e4b6d8f0a2c4e6b8d0f2a4 │ <- file data
//! │ QmINDEX...                                       │ <- encrypted index
//! │                                                  │
//! │ Server CANNOT determine:                         │
//! │   - Which is index vs data                       │
//! │   - Folder structure                             │
//! │   - Parent/child relationships                   │
//! │   - File count per folder                        │
//! └─────────────────────────────────────────────────┘
//!
//! Decrypted View (What Client Sees):
//! ┌─────────────────────────────────────────────────┐
//! │ /                                                │
//! │ ├── photos/                                      │
//! │ │   ├── vacation/                                │
//! │ │   │   ├── beach.jpg (1.2 MB)                  │
//! │ │   │   └── sunset.jpg (800 KB)                 │
//! │ │   └── family.jpg (2.1 MB)                     │
//! │ └── documents/                                   │
//! │     └── report.pdf (156 KB)                     │
//! └─────────────────────────────────────────────────┘
//! ```

use crate::{
    CryptoError, Result,
    keys::DekKey,
    symmetric::{Aead, Nonce},
    private_metadata::PrivateMetadata,
    hamt_index::HamtIndex,
};
use cid::Cid;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// Forest format version
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ForestFormat {
    /// Original flat HashMap (version 1)
    FlatMapV1,
    /// HAMT-backed index (version 2) for large forests
    HamtV2,
    /// HAMT-per-shard (version 7) — each shard is a content-addressed HAMT
    /// rather than a flat HashMap, so a single shard can scale to millions of
    /// entries without any client materializing the whole shard.
    ShardedHamtV7,
}

impl Default for ForestFormat {
    fn default() -> Self {
        ForestFormat::FlatMapV1
    }
}

/// The forest index key derivation domain
const INDEX_KEY_DOMAIN: &str = "fula/private-forest/index/v1";

/// Generate a flat, CID-like storage key (no prefixes)
/// 
/// The key looks like a content-addressed hash:
/// `Qm` + 44 hex chars = 46 char total (similar to IPFS CIDv0)
pub fn generate_flat_key(original_path: &str, dek: &DekKey, salt: &[u8]) -> String {
    let mut hasher = blake3::Hasher::new_derive_key("fula/flat-namespace/key/v1");
    hasher.update(dek.as_bytes());
    hasher.update(original_path.as_bytes());
    hasher.update(salt);
    let hash = hasher.finalize();
    
    // Format like a CID: Qm + 44 hex chars
    format!("Qm{}", hex::encode(&hash.as_bytes()[..22]))
}

/// Generate a random flat key (for RandomUuid equivalent in flat namespace)
pub fn generate_random_flat_key() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 22];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    format!("Qm{}", hex::encode(bytes))
}

/// Derive the storage key for the index itself
/// This is deterministic so the client can find it
pub fn derive_index_key(dek: &DekKey, bucket: &str) -> String {
    let mut hasher = blake3::Hasher::new_derive_key(INDEX_KEY_DOMAIN);
    hasher.update(dek.as_bytes());
    hasher.update(bucket.as_bytes());
    let hash = hasher.finalize();
    format!("Qm{}", hex::encode(&hash.as_bytes()[..22]))
}

/// A file entry in the private forest
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ForestFileEntry {
    /// The original file path
    pub path: String,
    /// The opaque storage key (CID-like)
    pub storage_key: String,
    /// File size in bytes
    pub size: u64,
    /// Content type (MIME)
    pub content_type: Option<String>,
    /// Created timestamp (Unix seconds)
    pub created_at: i64,
    /// Modified timestamp (Unix seconds)
    pub modified_at: i64,
    /// Content hash (BLAKE3)
    pub content_hash: Option<String>,
    /// User metadata
    #[serde(default)]
    pub user_metadata: HashMap<String, String>,
    /// Whether the underlying object MUST be fetched via the encrypted
    /// download path. `true` for new encrypted uploads; legacy entries
    /// deserialize as `false` via `#[serde(default)]`. The client uses this
    /// to reject a malicious storage backend that returns
    /// `x-fula-encrypted: false` for a path that was uploaded encrypted
    /// (audit finding C-AUDIT-004).
    #[serde(default)]
    pub encrypted: bool,
    /// Minimum blob-format version the client must accept for this entry.
    /// `0` on legacy entries (pre-H-2); `4` once the entry is written under
    /// v4 AAD-bound encryption. Read paths reject blobs whose declared
    /// `version` is below this floor (audit finding H-2, defense-in-depth
    /// against downgrade-to-no-AAD when a bucket mixes v1/v2 legacy data).
    #[serde(default)]
    pub min_version: u8,
    /// Walkable-v8 (W.9.1b): CID hint for the encrypted chunk/object blob,
    /// populated from master's PUT-response ETag. `None` for legacy v7 file
    /// entries — readers fall back to fetching the chunk via the master S3
    /// path keyed on `storage_key`. W.9.3 wires the writer to populate this
    /// from the ETag returned by S3BlobBackend; W.9.4 wires the offline
    /// reader to fetch by CID via gateway race when master is unreachable.
    /// `#[serde(default)]` keeps existing CBOR/JSON-pinned forest blobs
    /// deserializing cleanly into the new struct (Phase 1.2-style lazy
    /// migration).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage_cid: Option<Cid>,
}

impl ForestFileEntry {
    /// Create from private metadata and storage key.
    ///
    /// Callers that created this entry in response to a successful encrypted
    /// upload should call `mark_encrypted()` afterwards so later reads can
    /// enforce that the object is not served in plaintext.
    pub fn from_metadata(metadata: &PrivateMetadata, storage_key: String) -> Self {
        Self {
            path: metadata.original_key.clone(),
            storage_key,
            size: metadata.actual_size,
            content_type: metadata.content_type.clone(),
            created_at: metadata.created_at,
            modified_at: metadata.modified_at,
            content_hash: metadata.content_hash.clone(),
            user_metadata: metadata.user_metadata.clone(),
            encrypted: false,
            min_version: 0,
            storage_cid: None,
        }
    }

    /// Mark this entry as "must be fetched encrypted" and pin it to the
    /// v4 blob-format floor. Used by the client immediately after a
    /// successful encrypted PUT so future reads (a) refuse to accept a
    /// plaintext response from the storage backend (C-AUDIT-004), and
    /// (b) refuse to honor an attacker-authored v2-format (no-AAD) blob
    /// at the same storage_key (H-2).
    pub fn mark_encrypted(&mut self) {
        self.encrypted = true;
        if self.min_version < 4 {
            self.min_version = 4;
        }
    }

    /// Get filename from path
    pub fn filename(&self) -> &str {
        self.path.rsplit('/').next().unwrap_or(&self.path)
    }

    /// Get parent directory
    pub fn parent_dir(&self) -> &str {
        if let Some(idx) = self.path.rfind('/') {
            &self.path[..idx]
        } else {
            ""
        }
    }
}

/// A directory entry in the private forest
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct ForestDirectoryEntry {
    /// The directory path
    pub path: String,
    /// Direct child file paths (not storage keys)
    pub files: Vec<String>,
    /// Direct child directory paths
    pub subdirs: Vec<String>,
    /// Directory metadata (optional)
    pub metadata: Option<HashMap<String, String>>,
    /// Encrypted subtree DEK (for Cryptree-style key hierarchy)
    /// If present, files under this directory use this subtree's DEK
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subtree_dek: Option<crate::subtree_keys::EncryptedSubtreeDek>,
}

/// The private forest - an encrypted index of the entire file system
/// 
/// Supports two internal formats:
/// - **FlatMapV1**: Original HashMap-based storage (default)
/// - **HamtV2**: HAMT-backed storage for large forests (1000+ files)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivateForest {
    /// Version of the forest format
    pub version: u8,
    /// Storage format (FlatMapV1 or HamtV2)
    #[serde(default)]
    pub format: ForestFormat,
    /// Salt used for key derivation (random per forest)
    #[serde(with = "hex_serde")]
    pub salt: Vec<u8>,
    /// All files indexed by their original path (FlatMapV1)
    #[serde(default)]
    pub files: HashMap<String, ForestFileEntry>,
    /// HAMT-backed file index (HamtV2) - only populated when format is HamtV2
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub files_hamt: Option<HamtIndex<ForestFileEntry>>,
    /// Directory structure (path -> directory info)
    pub directories: HashMap<String, ForestDirectoryEntry>,
    /// Root directory path (usually "/")
    pub root: String,
    /// Creation timestamp
    pub created_at: i64,
    /// Last modified timestamp
    pub modified_at: i64,
}

mod hex_serde {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        hex::decode(&s).map_err(serde::de::Error::custom)
    }
}

/// Threshold for automatic migration to HAMT format
const HAMT_MIGRATION_THRESHOLD: usize = 1000;

impl PrivateForest {
    /// Normalize a directory path for consistent HashMap lookups.
    /// Strips trailing slash (except for root "/") and ensures leading slash.
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

    /// Create a new empty private forest (FlatMapV1 format)
    pub fn new() -> Self {
        Self::with_format(ForestFormat::FlatMapV1)
    }

    /// Create a new empty private forest with HAMT format
    pub fn new_hamt() -> Self {
        Self::with_format(ForestFormat::HamtV2)
    }

    /// Create a new empty private forest with specified format
    pub fn with_format(format: ForestFormat) -> Self {
        use rand::RngCore;
        let mut salt = vec![0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        
        let now = crate::time::now_timestamp();

        let mut directories = HashMap::new();
        directories.insert("/".to_string(), ForestDirectoryEntry {
            path: "/".to_string(),
            files: Vec::new(),
            subdirs: Vec::new(),
            metadata: None,
            subtree_dek: None,
        });

        let (files, files_hamt) = match format {
            ForestFormat::FlatMapV1 => (HashMap::new(), None),
            ForestFormat::HamtV2 => (HashMap::new(), Some(HamtIndex::new())),
            ForestFormat::ShardedHamtV7 => unreachable!("ShardedHamtV7 uses ShardedHamtPrivateForest, not PrivateForest"),
        };

        Self {
            version: 2,
            format,
            salt,
            files,
            files_hamt,
            directories,
            root: "/".to_string(),
            created_at: now,
            modified_at: now,
        }
    }

    /// Get the current format
    pub fn format(&self) -> &ForestFormat {
        &self.format
    }

    /// Migrate from FlatMapV1 to HamtV2 format
    /// 
    /// This is useful when the forest grows beyond the HAMT threshold.
    pub fn migrate_to_hamt(&mut self) {
        if self.format == ForestFormat::HamtV2 {
            return; // Already HAMT
        }

        let mut hamt = HamtIndex::new();
        for (path, entry) in self.files.drain() {
            hamt.insert(path, entry);
        }

        self.files_hamt = Some(hamt);
        self.format = ForestFormat::HamtV2;
        self.version = 2;
        self.touch();
    }

    /// Migrate from HamtV2 back to FlatMapV1 format (for small forests)
    pub fn migrate_to_flat(&mut self) {
        if self.format == ForestFormat::FlatMapV1 {
            return; // Already flat
        }

        if let Some(hamt) = self.files_hamt.take() {
            self.files = hamt.to_hashmap();
        }

        self.format = ForestFormat::FlatMapV1;
        self.version = 1;
        self.touch();
    }

    /// Check if migration to HAMT is recommended
    pub fn should_migrate_to_hamt(&self) -> bool {
        self.format == ForestFormat::FlatMapV1 && self.file_count() >= HAMT_MIGRATION_THRESHOLD
    }

    /// Update the modified timestamp
    fn touch(&mut self) {
        self.modified_at = crate::time::now_timestamp();
    }

    /// Generate a storage key for a new file
    pub fn generate_key(&self, original_path: &str, dek: &DekKey) -> String {
        generate_flat_key(original_path, dek, &self.salt)
    }

    /// Add or update a file in the forest
    /// 
    /// Works with both FlatMapV1 and HamtV2 formats.
    pub fn upsert_file(&mut self, entry: ForestFileEntry) {
        let path = entry.path.clone();
        let parent = entry.parent_dir().to_string();
        
        // Ensure parent directories exist
        self.ensure_directory(&parent);
        
        // Add file to parent's file list
        if let Some(dir) = self.directories.get_mut(&parent) {
            if !dir.files.contains(&path) {
                dir.files.push(path.clone());
            }
        }
        
        self.touch();
        
        // Insert into the appropriate storage
        match self.format {
            ForestFormat::FlatMapV1 => {
                self.files.insert(path, entry);
                
                // Auto-migrate to HAMT if we've grown past the threshold
                if self.should_migrate_to_hamt() {
                    self.migrate_to_hamt();
                }
            }
            ForestFormat::HamtV2 => {
                if let Some(ref mut hamt) = self.files_hamt {
                    hamt.insert(path, entry);
                }
            }
            ForestFormat::ShardedHamtV7 => unreachable!("ShardedHamtV7 uses ShardedHamtPrivateForest, not PrivateForest"),
        }
    }

    /// Ensure a directory and all parent directories exist
    fn ensure_directory(&mut self, path: &str) {
        if path.is_empty() || path == "/" {
            return;
        }
        
        let normalized = if path.starts_with('/') {
            path.to_string()
        } else {
            format!("/{}", path)
        };
        
        if self.directories.contains_key(&normalized) {
            return;
        }
        
        // Create the directory
        self.directories.insert(normalized.clone(), ForestDirectoryEntry {
            path: normalized.clone(),
            files: Vec::new(),
            subdirs: Vec::new(),
            metadata: None,
            subtree_dek: None,
        });
        
        // Add to parent's subdirs
        if let Some(parent_idx) = normalized.rfind('/') {
            let parent = if parent_idx == 0 {
                "/".to_string()
            } else {
                normalized[..parent_idx].to_string()
            };
            
            self.ensure_directory(&parent);
            
            if let Some(parent_dir) = self.directories.get_mut(&parent) {
                if !parent_dir.subdirs.contains(&normalized) {
                    parent_dir.subdirs.push(normalized);
                }
            }
        }
    }

    /// Remove a file from the forest
    /// 
    /// Works with both FlatMapV1 and HamtV2 formats.
    pub fn remove_file(&mut self, path: &str) -> Option<ForestFileEntry> {
        let entry = match self.format {
            ForestFormat::FlatMapV1 => self.files.remove(path),
            ForestFormat::HamtV2 => self.files_hamt.as_mut().and_then(|h| h.remove(path)),
            ForestFormat::ShardedHamtV7 => unreachable!("ShardedHamtV7 uses ShardedHamtPrivateForest, not PrivateForest"),
        };

        if let Some(ref e) = entry {
            let parent = e.parent_dir().to_string();
            if let Some(dir) = self.directories.get_mut(&parent) {
                dir.files.retain(|f| f != path);
            }
            self.touch();
        }
        entry
    }

    /// Get a file by path
    /// 
    /// Works with both FlatMapV1 and HamtV2 formats.
    pub fn get_file(&self, path: &str) -> Option<&ForestFileEntry> {
        match self.format {
            ForestFormat::FlatMapV1 => self.files.get(path),
            ForestFormat::HamtV2 => self.files_hamt.as_ref().and_then(|h| h.get(path)),
            ForestFormat::ShardedHamtV7 => unreachable!("ShardedHamtV7 uses ShardedHamtPrivateForest, not PrivateForest"),
        }
    }

    /// Get storage key for a path
    pub fn get_storage_key(&self, path: &str) -> Option<&str> {
        self.get_file(path).map(|f| f.storage_key.as_str())
    }

    /// List all files as a Vec (works with both formats)
    pub fn list_all_files(&self) -> Vec<&ForestFileEntry> {
        match self.format {
            ForestFormat::FlatMapV1 => self.files.values().collect(),
            ForestFormat::HamtV2 => self.files_hamt.as_ref()
                .map(|h| h.iter().map(|(_, v)| v).collect())
                .unwrap_or_default(),
            ForestFormat::ShardedHamtV7 => unreachable!("ShardedHamtV7 uses ShardedHamtPrivateForest, not PrivateForest"),
        }
    }

    /// List files in a directory (non-recursive)
    pub fn list_directory(&self, dir_path: &str) -> Vec<&ForestFileEntry> {
        let normalized = Self::normalize_dir_path(dir_path);

        if let Some(dir) = self.directories.get(&normalized) {
            dir.files.iter()
                .filter_map(|path| self.get_file(path))
                .collect()
        } else {
            Vec::new()
        }
    }

    /// List subdirectories of a directory
    pub fn list_subdirs(&self, dir_path: &str) -> Vec<&str> {
        let normalized = Self::normalize_dir_path(dir_path);

        if let Some(dir) = self.directories.get(&normalized) {
            dir.subdirs.iter().map(|s| s.as_str()).collect()
        } else {
            Vec::new()
        }
    }

    /// List files recursively under a path
    ///
    /// Works with both FlatMapV1 and HamtV2 formats.
    pub fn list_recursive(&self, prefix: &str) -> Vec<&ForestFileEntry> {
        // #84: path-component-aware filter — `/photos` must not match
        // `/photosold/legacy.jpg`. The helper normalizes both operands
        // internally, so the raw caller-supplied prefix is fine.
        self.list_all_files()
            .into_iter()
            .filter(|f| path_under_prefix_v1(&f.path, prefix))
            .collect()
    }

    /// Get total file count
    pub fn file_count(&self) -> usize {
        match self.format {
            ForestFormat::FlatMapV1 => self.files.len(),
            ForestFormat::HamtV2 => self.files_hamt.as_ref().map(|h| h.len()).unwrap_or(0),
            ForestFormat::ShardedHamtV7 => unreachable!("ShardedHamtV7 uses ShardedHamtPrivateForest, not PrivateForest"),
        }
    }

    /// Get total size of all files
    pub fn total_size(&self) -> u64 {
        self.list_all_files().iter().map(|f| f.size).sum()
    }

    /// Find file by storage key (reverse lookup)
    /// 
    /// Works with both FlatMapV1 and HamtV2 formats.
    pub fn find_by_storage_key(&self, storage_key: &str) -> Option<&ForestFileEntry> {
        self.list_all_files().into_iter().find(|f| f.storage_key == storage_key)
    }

    /// Extract a subtree for sharing
    ///
    /// Works with both FlatMapV1 and HamtV2 formats.
    pub fn extract_subtree(&self, prefix: &str) -> PrivateForest {
        let mut subtree = PrivateForest::new();
        subtree.salt = self.salt.clone();
        subtree.root = prefix.to_string();

        // Copy matching files via the (now path-component-aware)
        // `list_recursive` — picks up the #84 fix automatically.
        for entry in self.list_recursive(prefix) {
            subtree.files.insert(entry.path.clone(), entry.clone());
        }

        // Copy matching directories. A directory belongs in the subtree
        // when it lives under `prefix` OR is an ancestor of `prefix`
        // (so the recipient can resolve the path chain). Both checks
        // use `path_under_prefix_v1` so neither one byte-prefix-overmatches
        // a sibling. (Pre-fix `path.starts_with(prefix) || prefix.starts_with(path)`
        // matched `/foo` as an ancestor of `/foobar` and `/foobar` as a
        // descendant of `/foo`.) The helper normalizes both operands.
        for (path, dir) in &self.directories {
            if path_under_prefix_v1(path, prefix)
                || path_under_prefix_v1(prefix, path)
            {
                subtree.directories.insert(path.clone(), dir.clone());
            }
        }

        subtree
    }
}

/// #84 helper — normalize a caller-supplied path prefix to the form used
/// by [`path_under_prefix_v1`].
///
/// Strips trailing slashes (so `/photos` and `/photos/` are equivalent),
/// ensures a leading slash, and treats empty input as root. Identical
/// semantics to `sharded_hamt_forest::normalize_dir_path`; duplicated
/// here to avoid pulling the v7 module into v1's read paths.
fn normalize_path_component_prefix(prefix: &str) -> String {
    if prefix.is_empty() || prefix == "/" {
        return "/".to_string();
    }
    let trimmed = prefix.trim_end_matches('/');
    if trimmed.starts_with('/') {
        trimmed.to_string()
    } else {
        format!("/{}", trimmed)
    }
}

/// #84 helper — path-component-aware "is `path` under `prefix`?" check.
///
/// **Both operands are normalized inside the helper.** Callers may pass
/// either operand in non-canonical form (`foo` vs `/foo`, `/foo/`) and
/// get consistent results. This matches `sharded_hamt_forest::path_under_prefix`
/// so v1 and v7 behave identically, and it's the load-bearing property
/// for `extract_subtree`'s symmetric ancestor branch — that branch
/// passes a directory entry's `path` as the helper's second argument,
/// and v1's directory map can hold legacy non-canonical keys.
///
/// A path is "under" the prefix iff (after normalization) it equals the
/// prefix OR begins with `prefix + "/"`. The root prefix `/` matches
/// every path. Replaces raw `path.starts_with(prefix)` in v1 monolithic
/// listing/extraction surfaces.
fn path_under_prefix_v1(path: &str, prefix: &str) -> bool {
    let normalized_prefix = normalize_path_component_prefix(prefix);
    let normalized_path = normalize_path_component_prefix(path);
    if normalized_prefix == "/" {
        return true;
    }
    normalized_path == normalized_prefix
        || normalized_path.starts_with(&format!("{}/", normalized_prefix))
}

impl Default for PrivateForest {
    fn default() -> Self {
        Self::new()
    }
}

/// Encrypted private forest (what gets stored)
///
/// Version semantics:
/// - v1/v2: legacy monolithic forest, no AAD, no replay protection.
/// - v4: monolithic forest with AAD bound to `fula:forest:v4:<bucket>:<sequence>`
///   and an outer `sequence` counter for replay detection.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedForest {
    /// Version of the encryption format
    pub version: u8,
    /// Encrypted forest data
    #[serde(with = "base64_serde")]
    pub ciphertext: Vec<u8>,
    /// Nonce used for encryption
    #[serde(with = "base64_serde")]
    pub nonce: Vec<u8>,
    /// Monotonic sequence counter (v4+). Bound into AAD to prevent replay.
    ///
    /// Present only for version >= 4. Legacy v1/v2 blobs omit this field
    /// to preserve on-disk format compatibility.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub sequence: Option<u64>,
}

mod base64_serde {
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&base64::engine::general_purpose::STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        base64::engine::general_purpose::STANDARD
            .decode(&s)
            .map_err(serde::de::Error::custom)
    }
}

/// Compute the AAD for a v4 monolithic forest.
///
/// Bound to bucket + sequence to prevent replay of an older forest snapshot
/// by a malicious or compromised storage server.
pub fn forest_v4_aad(bucket: &str, sequence: u64) -> Vec<u8> {
    format!("fula:forest:v4:{}:{}", bucket, sequence).into_bytes()
}

impl EncryptedForest {
    /// Encrypt a private forest with a DEK (legacy v1, no AAD).
    ///
    /// **DEPRECATED — use [`EncryptedForest::encrypt_v4`].** v4 binds the
    /// ciphertext to the bucket and a monotonic sequence for replay
    /// protection. v1 is preserved for legacy round-trip / fixtures and the
    /// few pre-v4 call sites that still compile against it; production
    /// flushes go through v7 (sharded HAMT) which has its own AAD binding.
    #[deprecated(
        since = "0.7.0",
        note = "use EncryptedForest::encrypt_v4(forest, dek, bucket, sequence) — v1 is no-AAD and master can replay older snapshots"
    )]
    pub fn encrypt(forest: &PrivateForest, dek: &DekKey) -> Result<Self> {
        let json = serde_json::to_vec(forest)
            .map_err(|e| CryptoError::Serialization(e.to_string()))?;

        let nonce = Nonce::generate();
        let aead = Aead::new_default(dek);
        let ciphertext = aead.encrypt(&nonce, &json)?;

        Ok(Self {
            version: 1,
            ciphertext,
            nonce: nonce.as_bytes().to_vec(),
            sequence: None,
        })
    }

    /// Encrypt a private forest with a DEK and AAD binding (v4).
    ///
    /// Produces an [`EncryptedForest`] with `version = 4` and a monotonic
    /// `sequence` counter. The sequence and bucket are bound into the AEAD
    /// via AAD, so any rollback attempt by a malicious storage server fails
    /// the AEAD tag check.
    pub fn encrypt_v4(
        forest: &PrivateForest,
        dek: &DekKey,
        bucket: &str,
        sequence: u64,
    ) -> Result<Self> {
        let json = serde_json::to_vec(forest)
            .map_err(|e| CryptoError::Serialization(e.to_string()))?;

        let nonce = Nonce::generate();
        let aead = Aead::new_default(dek);
        let aad = forest_v4_aad(bucket, sequence);
        let ciphertext = aead.encrypt_with_aad(&nonce, &json, &aad)?;

        Ok(Self {
            version: 4,
            ciphertext,
            nonce: nonce.as_bytes().to_vec(),
            sequence: Some(sequence),
        })
    }

    /// Decrypt a private forest with a DEK (legacy v1/v2, no AAD).
    ///
    /// Errors on any v4+ blob: those formats bind the AEAD to bucket name
    /// and a monotonic sequence and MUST be decrypted via
    /// [`EncryptedForest::decrypt_v4`]. Without that dispatch, a caller
    /// holding a v4 blob would either silently fail the AEAD check (today)
    /// or — if a future legacy decrypt path was ever broadened — silently
    /// strip the replay-protection. Failing closed here makes the
    /// version-mismatch surface visible.
    pub fn decrypt(&self, dek: &DekKey) -> Result<PrivateForest> {
        if self.version >= 4 {
            return Err(CryptoError::Decryption(format!(
                "EncryptedForest version {} requires decrypt_v4(dek, bucket) — \
                 legacy decrypt is for versions 1 and 2 only",
                self.version
            )));
        }
        let nonce = Nonce::from_bytes(&self.nonce)?;
        let aead = Aead::new_default(dek);
        let plaintext = aead.decrypt(&nonce, &self.ciphertext)?;

        serde_json::from_slice(&plaintext)
            .map_err(|e| CryptoError::Serialization(e.to_string()))
    }

    /// Decrypt a v4 forest with a DEK, verifying bucket binding via AAD.
    ///
    /// Returns the decrypted forest plus the bound sequence. Callers should
    /// compare the returned sequence against their cached last-seen sequence
    /// to detect replay.
    pub fn decrypt_v4(&self, dek: &DekKey, bucket: &str) -> Result<(PrivateForest, u64)> {
        if self.version != 4 {
            return Err(CryptoError::Decryption(format!(
                "expected EncryptedForest version 4, got {}",
                self.version
            )));
        }
        let sequence = self.sequence.ok_or_else(|| {
            CryptoError::Decryption("v4 EncryptedForest missing sequence field".to_string())
        })?;
        let nonce = Nonce::from_bytes(&self.nonce)?;
        let aead = Aead::new_default(dek);
        let aad = forest_v4_aad(bucket, sequence);
        let plaintext = aead.decrypt_with_aad(&nonce, &self.ciphertext, &aad)?;
        let forest: PrivateForest = serde_json::from_slice(&plaintext)
            .map_err(|e| CryptoError::Serialization(e.to_string()))?;
        Ok((forest, sequence))
    }

    /// Serialize to bytes for storage
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self)
            .map_err(|e| CryptoError::Serialization(e.to_string()))
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        serde_json::from_slice(bytes)
            .map_err(|e| CryptoError::Serialization(e.to_string()))
    }
}

// ============================================================================
// Shard routing helpers (shared by v7 ShardedHamtPrivateForest)
// ============================================================================

/// Maximum number of shards.
///
/// Raised from 4,096 → 65,536 in S-1.2 once the manifest was split from a
/// single serialized blob into a two-level structure (a small root indexing
/// up to [`MAX_PAGES`] `ManifestPage`s, each carrying `PAGE_SIZE` shards).
/// The 2-byte shard-routing hash in [`shard_for_path_v6`] already supports
/// this width, so lifting the ceiling required no wire-format bump beyond
/// the meta-HAMT layout.
pub const MAX_SHARDS: usize = 65_536;

/// Shards per manifest page. Each page serializes to its own encrypted S3
/// object so no single blob approaches the 1 MiB cap even at `MAX_SHARDS`.
///
/// Sized so that a fully-populated page (1,024 shards × ~60 B metadata) is
/// ~65 KB plaintext, well under the [`MAX_MANIFEST_BLOCK_SIZE`] guard.
pub const PAGE_SIZE: usize = 1_024;

/// Maximum number of manifest pages (= [`MAX_SHARDS`] / [`PAGE_SIZE`]).
pub const MAX_PAGES: usize = MAX_SHARDS / PAGE_SIZE;

/// Upper bound on any encrypted manifest block (root or page). Matches the
/// 1 MiB block cap used by the blockstore layer; enforced inside
/// `encrypt_v7` / `EncryptedManifestPage::encrypt` so a growing shard table
/// surfaces as a bounded error before publish rather than a silent
/// `put_block` failure downstream.
const MAX_MANIFEST_BLOCK_SIZE: usize = 1024 * 1024;

/// Domain for shard key derivation
const SHARD_KEY_DOMAIN: &str = "fula/private-forest/shard/v1";

/// Domain for manifest-page key derivation.
const MANIFEST_PAGE_KEY_DOMAIN: &str = "fula/private-forest/manifest-page/v1";

/// KDF domain for the per-bucket directory-index storage key.
///
/// One encrypted object per bucket, stored under a key derived from this
/// domain + (forest_dek, bucket). Distinct domain from index/shard/page KDFs
/// so the resulting key cannot collide with any shard or manifest object.
const DIR_INDEX_KEY_DOMAIN: &str = "fula/private-forest/dir-index/v1";

/// Domain for shard assignment
const SHARD_ASSIGN_DOMAIN: &str = "fula/private-forest/shard-assign/v1";

/// Identifier of a manifest page. `u16` gives headroom beyond the current
/// [`MAX_PAGES`] budget (64) so the wire format doesn't need a migration if
/// the page width is ever lowered.
pub type PageId = u16;

/// Which page owns the shard at `shard_idx` under [`PAGE_SIZE`].
#[inline]
pub fn page_id_for_shard(shard_idx: usize) -> PageId {
    (shard_idx / PAGE_SIZE) as PageId
}

/// Slot within its owning page for `shard_idx`.
#[inline]
pub fn shard_slot_in_page(shard_idx: usize) -> usize {
    shard_idx % PAGE_SIZE
}

/// Derive the S3 storage key for a specific shard
///
/// Deterministic from (forest_dek, bucket, shard_salt, shard_index).
/// No need to store shard keys — they can always be recomputed.
pub fn derive_shard_key(forest_dek: &DekKey, bucket: &str, shard_salt: &[u8], shard_index: usize) -> String {
    let mut hasher = blake3::Hasher::new_derive_key(SHARD_KEY_DOMAIN);
    hasher.update(forest_dek.as_bytes());
    hasher.update(bucket.as_bytes());
    hasher.update(shard_salt);
    hasher.update(&(shard_index as u32).to_le_bytes());
    let hash = hasher.finalize();
    format!("Qm{}", hex::encode(&hash.as_bytes()[..22]))
}

/// Derive the S3 storage key for a specific manifest page.
///
/// Deterministic from (forest_dek, bucket, shard_salt, page_id) — same KDF
/// family as [`derive_shard_key`] with a distinct domain so the keys never
/// collide with shard blobs. Pages are **index-addressed**, not
/// content-addressed: re-PUT under the same key overwrites in place so a
/// failed page write leaves no orphans.
pub fn derive_manifest_page_key(
    forest_dek: &DekKey,
    bucket: &str,
    shard_salt: &[u8],
    page_id: PageId,
) -> String {
    let mut hasher = blake3::Hasher::new_derive_key(MANIFEST_PAGE_KEY_DOMAIN);
    hasher.update(forest_dek.as_bytes());
    hasher.update(bucket.as_bytes());
    hasher.update(shard_salt);
    hasher.update(&page_id.to_le_bytes());
    let hash = hasher.finalize();
    format!("Qm{}", hex::encode(&hash.as_bytes()[..22]))
}

/// Derive the S3 storage key for a bucket's directory index.
///
/// One object per bucket, keyed deterministically off `(forest_dek, bucket)`.
/// Distinct KDF domain from shard / page / forest-index keys so derivations
/// cannot alias. No salt: there is exactly one dir-index per bucket, and
/// overwrites happen in place via conditional PUT with `If-Match`.
pub fn derive_dir_index_key(forest_dek: &DekKey, bucket: &str) -> String {
    let mut hasher = blake3::Hasher::new_derive_key(DIR_INDEX_KEY_DOMAIN);
    hasher.update(forest_dek.as_bytes());
    hasher.update(bucket.as_bytes());
    let hash = hasher.finalize();
    format!("Qm{}", hex::encode(&hash.as_bytes()[..22]))
}

/// Canonicalize a path to the directory used for v6 shard routing.
///
/// Always returns a non-empty string ending in `/`. Examples:
/// - `/a/b/c.txt` → `/a/b/`
/// - `/file.txt`  → `/`
/// - `/a/b/`      → `/a/b/`
/// - ``           → `/`
/// - `/`          → `/`
///
/// Directories route to themselves so `list_directory` can find files by
/// loading only the shard that owns the directory.
pub fn parent_dir_for_routing(path: &str) -> String {
    if path.is_empty() || path == "/" {
        return "/".to_string();
    }
    if path.ends_with('/') {
        return path.to_string();
    }
    match path.rfind('/') {
        Some(0) => "/".to_string(),
        Some(idx) => format!("{}/", &path[..idx]),
        None => "/".to_string(),
    }
}

/// Determine which shard a file path belongs to under v6 routing.
///
/// Hashes the parent directory (canonicalized via [`parent_dir_for_routing`])
/// rather than the full path. All files sharing a parent directory land in
/// the same shard, which gives directory-locality for `list_directory` and
/// common co-edit patterns without leaking the directory structure to the
/// server (the DEK is mixed into the hash, so shard IDs remain indistinct).
///
/// Uses two bytes of hash output (u16 range, up to 65,536) so shard counts
/// above today's `MAX_SHARDS` = 4,096 stay wire-compatible if the manifest
/// format later evolves to a meta-HAMT (see deferred S-1.2).
pub fn shard_for_path_v6(path: &str, dek: &DekKey, shard_salt: &[u8], num_shards: usize) -> usize {
    let parent = parent_dir_for_routing(path);
    let mut hasher = blake3::Hasher::new_derive_key(SHARD_ASSIGN_DOMAIN);
    hasher.update(dek.as_bytes());
    hasher.update(parent.as_bytes());
    hasher.update(shard_salt);
    let hash = hasher.finalize();
    let bytes = hash.as_bytes();
    let idx = u16::from_le_bytes([bytes[0], bytes[1]]) as usize;
    idx % num_shards
}

/// Compute the initial shard count for migration based on file count
///
/// `max(16, next_power_of_two(file_count / 5000))`
pub fn compute_initial_shard_count(file_count: usize) -> usize {
    #[cfg(feature = "test-fault-injection")]
    {
        let forced = FORCE_INITIAL_SHARD_COUNT.load(std::sync::atomic::Ordering::Relaxed);
        if forced > 0 {
            return forced.min(MAX_SHARDS);
        }
    }
    let target = file_count / 5000;
    let pow2 = target.next_power_of_two().max(1);
    pow2.max(16).min(MAX_SHARDS)
}

/// Test-only override for `compute_initial_shard_count`. Non-zero values
/// (clamped to `MAX_SHARDS`) short-circuit the file-count heuristic so
/// integration tests can force multi-page manifests without populating
/// millions of files. Off by default; only compiled when the crate's
/// `test-fault-injection` feature is on.
#[cfg(feature = "test-fault-injection")]
pub static FORCE_INITIAL_SHARD_COUNT: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// Events emitted during v1 → v7 migration for app-level notifications
#[derive(Clone, Debug)]
pub enum ForestEvent {
    /// Migration completed
    MigrationCompleted {
        bucket: String,
        duration_ms: u64,
    },
}

//--------------------------------------------------------------------------------------------------
// v7 sharded-HAMT forest
//
// Per-shard flat HashMap (v5/v6) is replaced with a content-addressed HAMT
// rooted at `ShardV7::root`. A single shard can now scale to millions of
// entries without any client materializing the whole shard. See the v7 plan
// at /root/.claude/plans/do-a-thorough-line-cheeky-taco.md.
//--------------------------------------------------------------------------------------------------

/// Width of a v7 HAMT node storage key. Mirrors
/// `wnfs_hamt::store::STORAGE_KEY_LEN` so the public v7 schema doesn't need
/// to expose the internal `wnfs_hamt` module.
pub const V7_STORAGE_KEY_LEN: usize = 22;

/// Content-addressed storage key for a v7 HAMT node blob.
///
/// Derived as `BLAKE3(bucket_salt ‖ plaintext_node_bytes)[..V7_STORAGE_KEY_LEN]`.
/// The per-bucket salt (from [`ShardManifestV7::shard_salt`](ShardManifestV7::shard_salt)) prevents an
/// external observer from correlating structurally-identical nodes across
/// buckets; plaintext hashing (not ciphertext) preserves cross-revision
/// dedup of unchanged subtrees.
pub type V7StorageKey = [u8; V7_STORAGE_KEY_LEN];

mod v7_storage_key_serde {
    use super::V7_STORAGE_KEY_LEN;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(
        key: &Option<[u8; V7_STORAGE_KEY_LEN]>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        match key {
            Some(bytes) => s.serialize_some(&hex::encode(bytes)),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<Option<[u8; V7_STORAGE_KEY_LEN]>, D::Error> {
        let s: Option<String> = Option::deserialize(d)?;
        match s {
            Some(hex_str) => {
                let bytes = hex::decode(&hex_str).map_err(serde::de::Error::custom)?;
                if bytes.len() != V7_STORAGE_KEY_LEN {
                    return Err(serde::de::Error::custom(format!(
                        "v7 storage key must be {} bytes, got {}",
                        V7_STORAGE_KEY_LEN,
                        bytes.len()
                    )));
                }
                let mut arr = [0u8; V7_STORAGE_KEY_LEN];
                arr.copy_from_slice(&bytes);
                Ok(Some(arr))
            }
            None => Ok(None),
        }
    }
}

/// Per-shard metadata in a v7 sharded-HAMT manifest.
///
/// `root` points to this shard's HAMT root node. `None` means the shard is
/// empty — no node has been written yet. On every committed mutation the
/// root advances to the newly-written root node; intermediate nodes become
/// unreachable and are GC'd lazily.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShardV7 {
    /// HAMT root node key; `None` when the shard has no entries.
    #[serde(with = "v7_storage_key_serde", default)]
    pub root: Option<V7StorageKey>,

    /// Monotonic per-shard sequence counter. Paired with the manifest's
    /// conditional-PUT ETag, this protects shard root swaps against replay:
    /// a stale manifest re-upload is rejected by S3 on ETag mismatch, and
    /// within a winning generation `seq` gives an ordering invariant for
    /// WAL-driven retry. It is *not* part of per-node AAD — see
    /// [`hamt_node_v7_aad`] for why.
    pub seq: u64,

    /// Conditional-PUT ETag of the last written manifest generation for this
    /// shard. `None` before the first successful flush.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub etag: Option<String>,

    /// Entry count held in this shard (files + directories). Maintained on
    /// each flush so top-level `file_count()` and shard-growth heuristics
    /// stay O(num_shards) without walking any HAMT.
    pub entry_count: u32,

    /// Walkable-v8 (W.9.1b): CID hint for this shard's HAMT root node blob,
    /// populated from master's PUT-response ETag (= `BLAKE3(ciphertext)`
    /// raw-codec). `None` for legacy v7 manifests — readers fall back to
    /// fetching the root node via master S3 at the path keyed on `root`.
    /// W.9.3 wires the writer to stamp this from the BlobBackend's PUT
    /// response; W.9.4 wires the offline reader to use it for the gateway
    /// race when master is unreachable. `#[serde(default)]` keeps existing
    /// JSON-pinned ManifestPage blobs deserializing cleanly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_cid: Option<Cid>,
}

impl ShardV7 {
    /// Fresh, empty shard — no HAMT nodes written, sequence 0.
    pub fn new() -> Self {
        Self {
            root: None,
            seq: 0,
            etag: None,
            entry_count: 0,
            root_cid: None,
        }
    }

    /// True when the shard holds no entries.
    pub fn is_empty(&self) -> bool {
        self.root.is_none() && self.entry_count == 0
    }
}

impl Default for ShardV7 {
    fn default() -> Self {
        Self::new()
    }
}

/// Pointer to a manifest page from the root.
///
/// Binds two things the root needs to validate a page read:
///   * `etag`: the last-known S3 ETag, used for `If-Match` on re-PUT.
///   * `seq`: the expected monotonic sequence. Readers reject a page whose
///     plaintext `seq` is lower than this (M2 — staleness detection).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PageRef {
    /// ETag returned by S3 on the last successful PUT; `None` before the
    /// first flush of this page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub etag: Option<String>,
    /// Expected monotonic page sequence (≥ whichever seq the reader sees).
    pub seq: u64,
    /// Walkable-v8 (W.9.1b): CID hint for the encrypted manifest page blob,
    /// populated from master's PUT-response ETag (= `BLAKE3(ciphertext)`
    /// raw-codec). `None` on legacy v7 roots — readers fall back to fetching
    /// the page via master S3 at the path keyed on `derive_page_index_key`.
    /// W.9.3 wires the writer to stamp this from the PUT response; W.9.4
    /// wires the offline reader to use it for the gateway race when master
    /// is unreachable. `#[serde(default)]` keeps existing JSON-pinned
    /// ManifestRoot blobs deserializing cleanly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cid: Option<Cid>,
}

/// plan-D5 — pointer to one sharded directory-index object from the manifest
/// root. The dir-index analogue of [`PageRef`]: binds the `etag` (for
/// `If-Match` on re-PUT and master-divergence detection), the expected
/// monotonic `seq` (readers reject a shard whose plaintext `seq` is below
/// this — rollback / staleness), and the walkable-v8 `cid` hint (offline
/// gateway-race fetch). Present in `ManifestRoot.dir_index_shards` only for
/// NON-EMPTY shards.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirIndexShardRef {
    /// ETag returned by S3 on the last successful PUT of this shard object;
    /// `None` before its first flush.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub etag: Option<String>,
    /// Expected monotonic shard sequence. Readers reject a shard whose
    /// plaintext `seq` is below this.
    pub seq: u64,
    /// Walkable-v8 CID hint for this shard's encrypted blob (from master's
    /// PUT-response ETag, self-verified against `BLAKE3(ciphertext)`). `None`
    /// when the walkable-v8 writer is off; readers then fall back to the
    /// storage-key fetch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cid: Option<Cid>,
}

/// Root of the two-level manifest.
///
/// This is what [`EncryptedShardManifestV7`] wraps. Pages carry the bulk of
/// the data (shard metadata); the root stays small enough that even at
/// [`MAX_SHARDS`] = 65,536 the encrypted root object is tens of KB, well
/// under [`MAX_MANIFEST_BLOCK_SIZE`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestRoot {
    /// Manifest format version (= 7).
    pub version: u8,
    /// Format identifier for human-readable introspection.
    pub format: String,
    /// Number of shards (power of 2, capped at [`MAX_SHARDS`]).
    pub num_shards: usize,
    /// Random 32-byte salt used for shard routing and for content-hashing
    /// HAMT node plaintext. Prevents cross-bucket correlation of
    /// structurally identical nodes.
    #[serde(with = "hex_serde")]
    pub shard_salt: Vec<u8>,
    /// Root directory path (usually "/").
    pub root: String,
    /// Creation timestamp (Unix seconds).
    pub created_at: i64,
    /// Last-modified timestamp (Unix seconds).
    pub modified_at: i64,
    /// Index of manifest pages: `page_id → PageRef`. A missing entry means
    /// the page has never been flushed (shards in it are all-empty), so no
    /// page blob exists in S3 yet.
    #[serde(default)]
    pub page_index: BTreeMap<PageId, PageRef>,
    /// ETag of the encrypted [`DirectoryIndex`] object (F-1.3). `None` on
    /// buckets that have not yet flushed the dir-index.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dir_index_etag: Option<String>,
    /// Sequence number of the [`DirectoryIndex`] blob this root commits to.
    /// AEAD-bound inside the dir-index envelope — a reader that fetches the
    /// dir-index under this root MUST reject any plaintext whose `seq` does
    /// not equal this value. Pins both rollback (serving an older dir-index
    /// for this root) and forward-drift (serving a newer dir-index written
    /// by a concurrent migrator under a different root), closing the race
    /// where `dir_index_etag` alone is insufficient because `load_object`
    /// discards S3's HEAD ETag. `None` before the first successful flush.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dir_index_seq: Option<u64>,
    /// Walkable-v8 (W.9.3 — completes W.9.1b's wire-format extension):
    /// CID hint for the encrypted [`DirectoryIndex`] blob, populated from
    /// master's PUT-response ETag (= `BLAKE3(ciphertext)` raw-codec).
    ///
    /// `None` on legacy v7 roots and on every write where
    /// `walkable_v8_writer_enabled = false` — readers fall back to fetching
    /// the dir-index via master S3 at the path keyed on
    /// `derive_dir_index_key(forest_dek, bucket)`. With the writer enabled,
    /// W.9.4's offline reader uses this CID for the gateway race when master
    /// is unreachable, completing the dir-index portion of cold-start
    /// walkability.
    ///
    /// `#[serde(default)]` keeps every existing JSON-pinned
    /// `EncryptedShardManifestV7` blob deserializing cleanly into the new
    /// struct — the no-migration property for production data.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dir_index_cid: Option<Cid>,
    /// plan-D5 — per-shard pointers for the SHARDED directory index (v8).
    /// `shard_idx → DirIndexShardRef` for each NON-EMPTY shard. A non-empty
    /// map means this bucket uses the sharded dir-index and the reader MUST
    /// route through the v8 path; an empty map (the default, and every legacy
    /// v7 bucket) means the single-blob `dir_index_etag`/`dir_index_seq`/
    /// `dir_index_cid` fields above are authoritative. The two are mutually
    /// exclusive by construction — a v8 write leaves the legacy fields `None`.
    /// `#[serde(default, skip_serializing_if)]` keeps every existing v7
    /// manifest blob deserializing cleanly (field absent → empty map) and
    /// keeps v7 manifests byte-identical on the wire.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub dir_index_shards: BTreeMap<u8, DirIndexShardRef>,
}

impl ManifestRoot {
    fn fresh(num_shards: usize) -> Self {
        use rand::RngCore;
        let num_shards = num_shards.next_power_of_two().max(16).min(MAX_SHARDS);
        let mut shard_salt = vec![0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut shard_salt);

        let now = crate::time::now_timestamp();

        Self {
            version: 7,
            format: "sharded-hamt-v7".to_string(),
            num_shards,
            shard_salt,
            root: "/".to_string(),
            created_at: now,
            modified_at: now,
            page_index: BTreeMap::new(),
            dir_index_etag: None,
            dir_index_seq: None,
            dir_index_cid: None,
            dir_index_shards: BTreeMap::new(),
        }
    }

    /// How many pages a fully-populated manifest with this `num_shards` has.
    pub fn page_count(&self) -> usize {
        self.num_shards.div_ceil(PAGE_SIZE)
    }
}

/// One page of the meta-HAMT manifest.
///
/// Carries a contiguous slice of per-shard metadata: shards
/// `[page_id * PAGE_SIZE, page_id * PAGE_SIZE + shards.len())`. The
/// trailing page is short when `num_shards < MAX_SHARDS` and not an exact
/// multiple of `PAGE_SIZE` — today `num_shards` is always a power of two,
/// so every page is either full or the sole page of a sub-`PAGE_SIZE`
/// manifest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestPage {
    /// Which page this is; self-describing so an out-of-slot ciphertext
    /// cannot be accepted even if AAD binding were somehow bypassed.
    pub page_id: PageId,
    /// Monotonic page sequence. Incremented on every re-PUT (M2) so a
    /// reader whose root records seq N rejects a page with plaintext
    /// seq < N.
    pub seq: u64,
    /// Per-shard metadata for this page.
    pub shards: Vec<ShardV7>,
}

impl ManifestPage {
    fn empty(page_id: PageId, shards_in_page: usize) -> Self {
        Self {
            page_id,
            seq: 0,
            shards: (0..shards_in_page).map(|_| ShardV7::new()).collect(),
        }
    }
}

/// v7 sharded-HAMT manifest (in-memory representation).
///
/// The persisted form is the two-level meta-HAMT: a [`ManifestRoot`] in the
/// index blob (wrapped by [`EncryptedShardManifestV7`]) pointing at up to
/// [`MAX_PAGES`] [`ManifestPage`]s (each wrapped by [`EncryptedManifestPage`]).
/// Accessor methods [`shard`], [`shard_mut`], [`shards_iter`] hide the page
/// layout so mutation code looks identical to the old flat-`Vec` API.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShardManifestV7 {
    /// Root metadata persisted in the index blob.
    pub root: ManifestRoot,
    /// Pages loaded in memory, keyed by `page_id`. A fresh manifest and a
    /// fully-loaded manifest both carry every page in `0..page_count()`; a
    /// lazily-loaded manifest may omit pages that haven't been touched yet.
    pub pages: BTreeMap<PageId, ManifestPage>,
    /// Pages mutated since the last successful flush. The flush path drains
    /// this set, bumps each dirty page's `seq`, and PUTs it. Not persisted
    /// — reconstructed on each mutation.
    pub dirty_pages: BTreeSet<PageId>,
}

impl ShardManifestV7 {
    /// Fresh v7 manifest with `num_shards` empty shards across
    /// `ceil(num_shards / PAGE_SIZE)` fully-materialized pages.
    ///
    /// `num_shards` is rounded up to the next power of two and clamped to
    /// `[16, MAX_SHARDS]`.
    pub fn new(num_shards: usize) -> Self {
        let root = ManifestRoot::fresh(num_shards);
        let actual_num = root.num_shards;
        let page_count = root.page_count();
        let mut pages = BTreeMap::new();
        for page_id in 0..page_count as PageId {
            let first_slot = (page_id as usize) * PAGE_SIZE;
            let shards_in_page = (actual_num - first_slot).min(PAGE_SIZE);
            pages.insert(page_id, ManifestPage::empty(page_id, shards_in_page));
        }
        Self {
            root,
            pages,
            dirty_pages: BTreeSet::new(),
        }
    }

    /// Reassemble a manifest from a decrypted root + its (already-loaded)
    /// pages. Used by the open path in fula-client after fetching the root
    /// and each page referenced by `root.page_index`.
    ///
    /// Validates that every page's `seq` is ≥ the seq recorded in the root
    /// (staleness rejection, M2); returns an error if a page's contents
    /// pre-date the root. Pages not referenced by `page_index` (i.e.
    /// all-empty, never flushed) are synthesized on demand so shard
    /// accessors never see a gap.
    pub fn from_root_and_pages(
        root: ManifestRoot,
        pages_in: BTreeMap<PageId, ManifestPage>,
    ) -> Result<Self> {
        for (page_id, page) in pages_in.iter() {
            if page.page_id != *page_id {
                return Err(CryptoError::Serialization(format!(
                    "manifest page_id mismatch: map key {} vs payload {}",
                    page_id, page.page_id
                )));
            }
            if let Some(expected) = root.page_index.get(page_id) {
                if page.seq < expected.seq {
                    return Err(CryptoError::Decryption(format!(
                        "stale manifest page {}: plaintext seq {} < root-expected seq {}",
                        page_id, page.seq, expected.seq
                    )));
                }
            }
        }

        let mut pages = pages_in;
        let page_count = root.page_count();
        for page_id in 0..page_count as PageId {
            pages.entry(page_id).or_insert_with(|| {
                let first_slot = (page_id as usize) * PAGE_SIZE;
                let shards_in_page = (root.num_shards - first_slot).min(PAGE_SIZE);
                ManifestPage::empty(page_id, shards_in_page)
            });
        }

        Ok(Self {
            root,
            pages,
            dirty_pages: BTreeSet::new(),
        })
    }

    /// Total shard count (wire-format quantity; equals `self.root.num_shards`).
    #[inline]
    pub fn num_shards(&self) -> usize {
        self.root.num_shards
    }

    /// Shard-routing salt (lives in the root).
    #[inline]
    pub fn shard_salt(&self) -> &[u8] {
        &self.root.shard_salt
    }

    /// Root directory path ("/" on fresh buckets).
    #[inline]
    pub fn root_path(&self) -> &str {
        &self.root.root
    }

    /// Number of pages this manifest has at its current shard count.
    #[inline]
    pub fn page_count(&self) -> usize {
        self.root.page_count()
    }

    fn page_for(&self, shard_idx: usize) -> &ManifestPage {
        let page_id = page_id_for_shard(shard_idx);
        self.pages.get(&page_id).unwrap_or_else(|| {
            panic!(
                "manifest page {} not loaded for shard {} (num_shards={})",
                page_id, shard_idx, self.root.num_shards
            )
        })
    }

    fn page_for_mut(&mut self, shard_idx: usize) -> &mut ManifestPage {
        let page_id = page_id_for_shard(shard_idx);
        self.dirty_pages.insert(page_id);
        let num = self.root.num_shards;
        self.pages.get_mut(&page_id).unwrap_or_else(|| {
            panic!(
                "manifest page {} not loaded for shard {} (num_shards={})",
                page_id, shard_idx, num
            )
        })
    }

    /// Immutable access to shard `idx`. Panics if `idx >= num_shards()` or
    /// if the page containing it has not been loaded — matches the old
    /// `manifest.shards[idx]` semantics exactly.
    pub fn shard(&self, shard_idx: usize) -> &ShardV7 {
        let slot = shard_slot_in_page(shard_idx);
        let page = self.page_for(shard_idx);
        &page.shards[slot]
    }

    /// Mutable access to shard `idx`. Marks the owning page dirty.
    pub fn shard_mut(&mut self, shard_idx: usize) -> &mut ShardV7 {
        let slot = shard_slot_in_page(shard_idx);
        let page = self.page_for_mut(shard_idx);
        &mut page.shards[slot]
    }

    /// Iterate over every shard in canonical `[0, num_shards)` order.
    pub fn shards_iter(&self) -> impl Iterator<Item = &ShardV7> + '_ {
        self.pages.values().flat_map(|p| p.shards.iter())
    }

    /// Mark every loaded page as dirty; used sparingly (e.g. reshard) since
    /// it forces full re-PUT of the manifest.
    pub fn mark_all_pages_dirty(&mut self) {
        let ids: Vec<PageId> = self.pages.keys().copied().collect();
        self.dirty_pages.extend(ids);
    }

    /// Drain the dirty-page set, returning the pages to re-PUT.
    pub fn take_dirty_pages(&mut self) -> BTreeSet<PageId> {
        std::mem::take(&mut self.dirty_pages)
    }

    /// Refresh the modified timestamp.
    pub fn touch(&mut self) {
        self.root.modified_at = crate::time::now_timestamp();
    }

    /// Total entries across all shards (O(num_shards), not O(N)).
    pub fn entry_count(&self) -> u64 {
        self.shards_iter().map(|s| s.entry_count as u64).sum()
    }
}

/// Compute the AAD for a v7 shard manifest-root wrapper.
///
/// Distinct prefix from v5/v6 so a ciphertext of another format cannot be
/// accepted in a v7 slot — format-downgrade is detected at AEAD verification
/// rather than relying on the plaintext version field. Since S-1.2 this
/// binds only the manifest root; pages carry their own AAD
/// (see [`manifest_page_aad`]).
pub fn manifest_v7_aad(bucket: &str, sequence: u64) -> Vec<u8> {
    format!("fula:manifest:v7:{}:{}", bucket, sequence).into_bytes()
}

/// Compute the AAD for a v7 manifest page.
///
/// Binds `(bucket, page_id, seq)` so that:
///   * A page PUT for a different bucket cannot be swapped in under
///     [`derive_manifest_page_key`]'s deterministic key.
///   * A page with an older `seq` cannot impersonate a newer one even if an
///     adversary could overwrite the S3 slot out-of-band — the AAD seals the
///     seq at encryption time, so any plaintext-seq mismatch at decrypt
///     aborts before round-tripping JSON.
pub fn manifest_page_aad(bucket: &str, page_id: PageId, seq: u64) -> Vec<u8> {
    format!("fula:v4:manifest-page:{}:{}:{}", bucket, page_id, seq).into_bytes()
}

/// Compute the AAD for a v7 directory-index blob.
///
/// Binds `(bucket, seq)` so that a stale dir-index (older seq than the
/// manifest root expects) fails AEAD before its plaintext is trusted for
/// listings. Distinct prefix from shard / page / manifest-root AADs so a
/// ciphertext of another kind can never be accepted in the dir-index slot.
pub fn dir_index_aad(bucket: &str, seq: u64) -> Vec<u8> {
    format!("fula:v4:dir-index:{}:{}", bucket, seq).into_bytes()
}

/// Compute the AAD for a v7 HAMT node blob.
///
/// Binds `bucket_id` and `shard_idx` (u16 big-endian) so a node from a
/// different bucket or shard fails AEAD verification. Tree position (depth,
/// bitmap slot) is deliberately NOT in the AAD — position is bound
/// *structurally* by the parent node's recorded child [`V7StorageKey`], which
/// is what preserves cross-revision dedup of unchanged subtrees under
/// plaintext content-addressing.
///
/// `shard_seq` is intentionally absent: HAMT flushes only rewrite the path of
/// mutated nodes, so a seq bump would invalidate untouched subtree
/// ciphertexts whose AAD was sealed under an older seq. Replay protection
/// lives at the manifest layer (`manifest.shard(i).seq` + ETag), and
/// forgery-resistance comes from content-addressing the plaintext bytes.
pub fn hamt_node_v7_aad(bucket: &str, shard_idx: u16) -> Vec<u8> {
    let prefix = b"fula:hamt-node:v7:";
    let mut aad = Vec::with_capacity(prefix.len() + bucket.len() + 2);
    aad.extend_from_slice(prefix);
    aad.extend_from_slice(bucket.as_bytes());
    aad.extend_from_slice(&shard_idx.to_be_bytes());
    aad
}

/// Compute a content-addressed v7 node key from the plaintext node bytes.
///
/// `BLAKE3(bucket_salt ‖ plaintext)[..V7_STORAGE_KEY_LEN]`. Hashing the
/// plaintext (not ciphertext) preserves cross-revision dedup for unchanged
/// subtrees; the per-bucket salt prevents cross-bucket correlation of
/// structurally identical plaintext (e.g. empty nodes) by an external
/// observer of the backing object store.
pub fn compute_v7_node_key(bucket_salt: &[u8], plaintext: &[u8]) -> V7StorageKey {
    let mut hasher = blake3::Hasher::new();
    hasher.update(bucket_salt);
    hasher.update(plaintext);
    let digest = hasher.finalize();
    let mut key = [0u8; V7_STORAGE_KEY_LEN];
    key.copy_from_slice(&digest.as_bytes()[..V7_STORAGE_KEY_LEN]);
    key
}

/// Encrypted v7 sharded-HAMT manifest (what gets stored at the index_key).
///
/// Version 7 is always AAD-bound; there is no legacy variant.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedShardManifestV7 {
    /// Version of the encryption format (= 7).
    pub version: u8,
    /// AEAD ciphertext covering the serialized [`ShardManifestV7`].
    #[serde(with = "base64_serde")]
    pub ciphertext: Vec<u8>,
    /// Nonce used for encryption.
    #[serde(with = "base64_serde")]
    pub nonce: Vec<u8>,
    /// Monotonic manifest sequence counter bound into the AAD.
    pub sequence: u64,
}

impl EncryptedShardManifestV7 {
    /// Encrypt a [`ManifestRoot`] under the manifest-root AAD.
    ///
    /// Since S-1.2 only the root is wrapped here; per-page ciphertexts live
    /// in [`EncryptedManifestPage`] and are PUT to keys derived via
    /// [`derive_manifest_page_key`].
    pub fn encrypt_v7(
        root: &ManifestRoot,
        dek: &DekKey,
        bucket: &str,
        sequence: u64,
    ) -> Result<Self> {
        let json = serde_json::to_vec(root)
            .map_err(|e| CryptoError::Serialization(e.to_string()))?;

        if json.len() >= MAX_MANIFEST_BLOCK_SIZE {
            return Err(CryptoError::Serialization(format!(
                "v7 manifest-root plaintext size {} bytes exceeds MAX_MANIFEST_BLOCK_SIZE ({} bytes); \
                 page_index count {} is too high for a single-block root. Consider lowering PAGE_SIZE \
                 to pack more pages, or add a third indirection level.",
                json.len(),
                MAX_MANIFEST_BLOCK_SIZE,
                root.page_index.len()
            )));
        }

        let nonce = Nonce::generate();
        let aead = Aead::new_default(dek);
        let aad = manifest_v7_aad(bucket, sequence);
        let ciphertext = aead.encrypt_with_aad(&nonce, &json, &aad)?;

        Ok(Self {
            version: 7,
            ciphertext,
            nonce: nonce.as_bytes().to_vec(),
            sequence,
        })
    }

    /// Decrypt a v7 manifest root, verifying bucket + sequence via AAD.
    ///
    /// Rejects any non-v7 wrapper so that a downgraded v3/v5/v6 ciphertext
    /// cannot pass the version check silently. Returns the root only — the
    /// caller must load referenced pages separately (via `page_index`) and
    /// pass them to [`ShardManifestV7::from_root_and_pages`].
    pub fn decrypt_v7(&self, dek: &DekKey, bucket: &str) -> Result<(ManifestRoot, u64)> {
        if self.version != 7 {
            return Err(CryptoError::Decryption(format!(
                "expected EncryptedShardManifestV7 version 7, got {}",
                self.version
            )));
        }
        let nonce = Nonce::from_bytes(&self.nonce)?;
        let aead = Aead::new_default(dek);
        let aad = manifest_v7_aad(bucket, self.sequence);
        let plaintext = aead.decrypt_with_aad(&nonce, &self.ciphertext, &aad)?;
        let root: ManifestRoot = serde_json::from_slice(&plaintext)
            .map_err(|e| CryptoError::Serialization(e.to_string()))?;
        Ok((root, self.sequence))
    }

    /// Serialize to bytes for storage.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self)
            .map_err(|e| CryptoError::Serialization(e.to_string()))
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        serde_json::from_slice(bytes)
            .map_err(|e| CryptoError::Serialization(e.to_string()))
    }
}

/// Encrypted v7 manifest page (S-1.2).
///
/// One per page; stored at a key derived from
/// [`derive_manifest_page_key`]. Each page carries a `seq` bound into its
/// AAD — a stale blob (older seq than the root expects) fails AEAD.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedManifestPage {
    /// Version of the encryption format (= 7).
    pub version: u8,
    /// Which page this ciphertext belongs to.
    pub page_id: PageId,
    /// AEAD ciphertext covering the serialized [`ManifestPage`].
    #[serde(with = "base64_serde")]
    pub ciphertext: Vec<u8>,
    /// Nonce used for encryption.
    #[serde(with = "base64_serde")]
    pub nonce: Vec<u8>,
    /// Page sequence bound into the AAD (matches the plaintext's own `seq`).
    pub seq: u64,
}

impl EncryptedManifestPage {
    /// Encrypt a manifest page with its `(page_id, seq)`-bound AAD.
    pub fn encrypt(page: &ManifestPage, dek: &DekKey, bucket: &str) -> Result<Self> {
        let json = serde_json::to_vec(page)
            .map_err(|e| CryptoError::Serialization(e.to_string()))?;

        if json.len() >= MAX_MANIFEST_BLOCK_SIZE {
            return Err(CryptoError::Serialization(format!(
                "manifest page plaintext size {} bytes exceeds MAX_MANIFEST_BLOCK_SIZE ({} bytes); \
                 page_id={} shard_count={}. Lower PAGE_SIZE or trim per-shard metadata.",
                json.len(),
                MAX_MANIFEST_BLOCK_SIZE,
                page.page_id,
                page.shards.len()
            )));
        }

        let nonce = Nonce::generate();
        let aead = Aead::new_default(dek);
        let aad = manifest_page_aad(bucket, page.page_id, page.seq);
        let ciphertext = aead.encrypt_with_aad(&nonce, &json, &aad)?;

        Ok(Self {
            version: 7,
            page_id: page.page_id,
            ciphertext,
            nonce: nonce.as_bytes().to_vec(),
            seq: page.seq,
        })
    }

    /// Decrypt a manifest page, verifying bucket + page_id + seq via AAD.
    ///
    /// On success, the returned page's `page_id` and `seq` always match the
    /// envelope — a mismatch means the storage backend returned a page from
    /// a different slot or a tampered blob.
    pub fn decrypt(&self, dek: &DekKey, bucket: &str) -> Result<ManifestPage> {
        if self.version != 7 {
            return Err(CryptoError::Decryption(format!(
                "expected EncryptedManifestPage version 7, got {}",
                self.version
            )));
        }
        let nonce = Nonce::from_bytes(&self.nonce)?;
        let aead = Aead::new_default(dek);
        let aad = manifest_page_aad(bucket, self.page_id, self.seq);
        let plaintext = aead.decrypt_with_aad(&nonce, &self.ciphertext, &aad)?;
        let page: ManifestPage = serde_json::from_slice(&plaintext)
            .map_err(|e| CryptoError::Serialization(e.to_string()))?;
        if page.page_id != self.page_id {
            return Err(CryptoError::Decryption(format!(
                "page_id mismatch: envelope {} vs plaintext {}",
                self.page_id, page.page_id
            )));
        }
        if page.seq != self.seq {
            return Err(CryptoError::Decryption(format!(
                "page seq mismatch: envelope {} vs plaintext {}",
                self.seq, page.seq
            )));
        }
        Ok(page)
    }

    /// Serialize to bytes for storage.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self)
            .map_err(|e| CryptoError::Serialization(e.to_string()))
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        serde_json::from_slice(bytes)
            .map_err(|e| CryptoError::Serialization(e.to_string()))
    }
}

/// Per-directory summary cached in the bucket-level [`DirectoryIndex`].
///
/// Holds everything required to answer `list_subdirs(path)` and
/// `directory_file_count(path)` in O(1). File entries themselves continue
/// to live inside the shard HAMTs — the index only tracks topology.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct DirEntry {
    /// Immediate child directory names (not full paths). `BTreeSet` so
    /// listings are deterministic and set-union under concurrent mkdir
    /// replay (plan D7).
    #[serde(default)]
    pub subdirs: std::collections::BTreeSet<String>,
    /// Count of files whose parent directory is this node. Not a sum over
    /// subtree — callers that need total sizes walk the forest explicitly.
    #[serde(default)]
    pub file_count: u32,
}

/// Bucket-scoped directory index (F-1.3).
///
/// Maps normalized directory path (`/`, `/a`, `/a/b`) → [`DirEntry`]. One
/// object per bucket, encrypted via [`EncryptedDirectoryIndex`], conditionally
/// PUT with `If-Match` so concurrent writers can't silently clobber each
/// other. `list_subdirs` resolves to a single `HashMap` lookup; without the
/// index, sharded v7 mode would have to walk every shard's HAMT.
///
/// Refilled from the live forest via
/// [`rebuild_directory_index_from_forest`] when the etag in the manifest
/// root doesn't match S3 (plan D3/D4).
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct DirectoryIndex {
    /// Format version. Bump if wire shape changes.
    #[serde(default = "DirectoryIndex::default_version")]
    pub version: u8,
    /// Directory topology. Keys are normalized via
    /// [`DirectoryIndex::normalize_dir_path`]; always absolute, always leading
    /// `/`, never trailing `/` except for the root.
    #[serde(default)]
    pub entries: HashMap<String, DirEntry>,
}

impl DirectoryIndex {
    fn default_version() -> u8 { 1 }

    /// Canonical form used as both a hash key and an index lookup target.
    /// `""` and `/` both normalize to `/`; trailing slashes are stripped;
    /// leading slash is ensured.
    pub fn normalize_dir_path(dir_path: &str) -> String {
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

    /// Parent directory for a normalized path (produced by
    /// [`normalize_dir_path`]). `/` has no parent → returns `None`.
    pub fn parent_of(norm_path: &str) -> Option<String> {
        if norm_path == "/" {
            return None;
        }
        match norm_path.rfind('/') {
            Some(0) => Some("/".to_string()),
            Some(idx) => Some(norm_path[..idx].to_string()),
            None => None,
        }
    }

    /// Leaf directory name — the last `/` segment of a normalized path.
    pub fn leaf_name(norm_path: &str) -> Option<String> {
        if norm_path == "/" {
            return None;
        }
        match norm_path.rfind('/') {
            Some(idx) => Some(norm_path[idx + 1..].to_string()),
            None => None,
        }
    }

    /// Fresh empty index containing just the root.
    pub fn new() -> Self {
        let mut entries = HashMap::new();
        entries.insert("/".to_string(), DirEntry::default());
        Self {
            version: Self::default_version(),
            entries,
        }
    }

    /// O(1) list of immediate subdirectory names for `dir_path`.
    pub fn list_subdirs(&self, dir_path: &str) -> Vec<String> {
        let norm = Self::normalize_dir_path(dir_path);
        self.entries
            .get(&norm)
            .map(|de| de.subdirs.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// O(1) file-count lookup for `dir_path`.
    pub fn file_count(&self, dir_path: &str) -> u32 {
        let norm = Self::normalize_dir_path(dir_path);
        self.entries.get(&norm).map(|de| de.file_count).unwrap_or(0)
    }

    /// Ensure every ancestor of `norm_dir` exists, threading child-pointers
    /// from each parent down to its immediate child. Idempotent: repeated
    /// calls for the same path never duplicate children (BTreeSet insert).
    ///
    /// Returns the entry keys this call ACTUALLY changed (a created child, or
    /// a parent whose `subdirs` gained a segment) — used by the v8 sharded
    /// dir-index for precise per-shard dirty tracking. An idempotent call that
    /// changes nothing returns an empty Vec. Keys may repeat; callers dedupe.
    pub fn ensure_dir(&mut self, dir_path: &str) -> Vec<String> {
        let norm = Self::normalize_dir_path(dir_path);
        let mut changed = Vec::new();
        if norm == "/" {
            if !self.entries.contains_key("/") {
                self.entries.insert("/".to_string(), DirEntry::default());
                changed.push("/".to_string());
            }
            return changed;
        }
        // Walk from root down, creating missing parents and linking each
        // new child in via its parent's `subdirs`.
        let mut cursor = String::from("/");
        // Ensure root exists.
        if !self.entries.contains_key("/") {
            self.entries.insert("/".to_string(), DirEntry::default());
            changed.push("/".to_string());
        }
        for segment in norm.trim_start_matches('/').split('/') {
            let parent = cursor.clone();
            let child = if parent == "/" {
                format!("/{}", segment)
            } else {
                format!("{}/{}", parent, segment)
            };
            if !self.entries.contains_key(&child) {
                self.entries.insert(child.clone(), DirEntry::default());
                changed.push(child.clone());
            }
            if let Some(parent_entry) = self.entries.get_mut(&parent) {
                // `BTreeSet::insert` returns true iff the segment was new, i.e.
                // the parent's `subdirs` actually changed.
                if parent_entry.subdirs.insert(segment.to_string()) {
                    changed.push(parent.clone());
                }
            }
            cursor = child;
        }
        changed
    }

    /// Record that one file has been added under `file_path`'s parent
    /// directory. Ensures the parent directory (and its ancestors) exist.
    ///
    /// Returns the entry keys this call changed (the parent's `file_count`
    /// always changes, plus any ancestors `ensure_dir` created).
    pub fn insert_file(&mut self, file_path: &str) -> Vec<String> {
        let parent = parent_dir_of_file(file_path);
        let mut changed = self.ensure_dir(&parent);
        if let Some(de) = self.entries.get_mut(&parent) {
            de.file_count = de.file_count.saturating_add(1);
            changed.push(parent);
        }
        changed
    }

    /// Record that one file has been removed from `file_path`'s parent
    /// directory. Saturating: an over-remove (replay double-count) is
    /// harmless rather than wrapping.
    ///
    /// Returns the affected entry key (the parent whose `file_count` changed),
    /// or empty if the parent isn't tracked.
    pub fn remove_file(&mut self, file_path: &str) -> Vec<String> {
        let parent = parent_dir_of_file(file_path);
        if let Some(de) = self.entries.get_mut(&parent) {
            de.file_count = de.file_count.saturating_sub(1);
            return vec![parent];
        }
        Vec::new()
    }

    /// Remove a directory node and unlink it from its parent's `subdirs`.
    /// Does NOT cascade to children — caller decides whether to prune the
    /// subtree (matches v1 `PrivateForest::remove_directory` semantics).
    pub fn remove_dir(&mut self, dir_path: &str) {
        let norm = Self::normalize_dir_path(dir_path);
        if norm == "/" {
            return; // Never remove root.
        }
        self.entries.remove(&norm);
        if let (Some(parent), Some(leaf)) = (Self::parent_of(&norm), Self::leaf_name(&norm)) {
            if let Some(parent_entry) = self.entries.get_mut(&parent) {
                parent_entry.subdirs.remove(&leaf);
            }
        }
    }
}

/// Parent directory path for a file path. Always normalized.
fn parent_dir_of_file(file_path: &str) -> String {
    let norm = if file_path.starts_with('/') {
        file_path.to_string()
    } else {
        format!("/{}", file_path)
    };
    match norm.rfind('/') {
        Some(0) => "/".to_string(),
        Some(idx) => norm[..idx].to_string(),
        None => "/".to_string(),
    }
}

/// Encrypted directory index stored at [`derive_dir_index_key`].
///
/// Envelope structure mirrors [`EncryptedShardManifestV7`]: one AEAD
/// ciphertext over the JSON-serialized [`DirectoryIndex`], with a monotonic
/// `sequence` bound into AAD so a stale blob can never be replayed in place
/// of a newer one even if an attacker overwrote the S3 slot.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedDirectoryIndex {
    /// Envelope version (= 7, tracks the broader v7 format family).
    pub version: u8,
    /// AEAD ciphertext over serialized [`DirectoryIndex`].
    #[serde(with = "base64_serde")]
    pub ciphertext: Vec<u8>,
    /// Nonce used for encryption.
    #[serde(with = "base64_serde")]
    pub nonce: Vec<u8>,
    /// Monotonic sequence bound into AAD.
    pub sequence: u64,
}

impl EncryptedDirectoryIndex {
    /// Encrypt a [`DirectoryIndex`] under the dir-index AAD at `(bucket, sequence)`.
    pub fn encrypt(
        index: &DirectoryIndex,
        dek: &DekKey,
        bucket: &str,
        sequence: u64,
    ) -> Result<Self> {
        let json = serde_json::to_vec(index)
            .map_err(|e| CryptoError::Serialization(e.to_string()))?;

        // **D1 audit fix — clearer hard-cliff error.**
        //
        // The IPFS-block-size cap (`MAX_MANIFEST_BLOCK_SIZE`, 1 MiB) is a
        // hard limit: hitting it makes `flush_forest` fail and the user
        // cannot write new files into this bucket until they delete
        // entries. Pre-fix the error message only said the cap was hit;
        // post-fix it tells the operator (a) what state the bucket is
        // actually in, (b) why existing data is still readable, and
        // (c) the two recovery paths.
        //
        // The proper fix is prefix-sharded directory indices ("plan D5",
        // tracked separately) — once shipped, dir-indices grow
        // horizontally by sharding across multiple S3 blobs instead of
        // fitting all entries into one. Until then, this error is the
        // load-bearing operator signal.
        //
        // Soft-threshold warning at 80% would be ideal, but `fula-crypto`
        // deliberately carries no `tracing` / `log` dependency. Callers
        // that want pre-cliff observability can sample `index.entries.len()`
        // themselves and emit warnings at their layer.
        if json.len() >= MAX_MANIFEST_BLOCK_SIZE {
            return Err(CryptoError::Serialization(format!(
                "directory-index plaintext size {} bytes exceeds the {} byte block cap \
                 ({} entries). The bucket has accumulated more directory metadata than fits \
                 in a single IPFS block; new file writes to this bucket will continue to \
                 fail until either: (a) the user re-organizes existing files into fewer / \
                 shallower directories so the dir-index shrinks below {} bytes; or (b) the \
                 SDK ships prefix-sharded dir-indices (plan D5). Existing data in this \
                 bucket remains readable; only NEW writes are blocked.",
                json.len(),
                MAX_MANIFEST_BLOCK_SIZE,
                index.entries.len(),
                MAX_MANIFEST_BLOCK_SIZE,
            )));
        }

        let nonce = Nonce::generate();
        let aead = Aead::new_default(dek);
        let aad = dir_index_aad(bucket, sequence);
        let ciphertext = aead.encrypt_with_aad(&nonce, &json, &aad)?;

        Ok(Self {
            version: 7,
            ciphertext,
            nonce: nonce.as_bytes().to_vec(),
            sequence,
        })
    }

    /// Decrypt + verify the dir-index. Returns the inner [`DirectoryIndex`]
    /// along with the sealed `sequence` so the caller can cross-check the
    /// manifest root's pin.
    pub fn decrypt(&self, dek: &DekKey, bucket: &str) -> Result<(DirectoryIndex, u64)> {
        if self.version != 7 {
            return Err(CryptoError::Decryption(format!(
                "expected EncryptedDirectoryIndex version 7, got {}",
                self.version
            )));
        }
        let nonce = Nonce::from_bytes(&self.nonce)?;
        let aead = Aead::new_default(dek);
        let aad = dir_index_aad(bucket, self.sequence);
        let plaintext = aead.decrypt_with_aad(&nonce, &self.ciphertext, &aad)?;
        let index: DirectoryIndex = serde_json::from_slice(&plaintext)
            .map_err(|e| CryptoError::Serialization(e.to_string()))?;
        Ok((index, self.sequence))
    }

    /// Serialize envelope to bytes for storage.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self)
            .map_err(|e| CryptoError::Serialization(e.to_string()))
    }

    /// Deserialize envelope from storage bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        serde_json::from_slice(bytes)
            .map_err(|e| CryptoError::Serialization(e.to_string()))
    }
}

/// plan-D5 — directory-index sharding (version-8 per-shard envelopes).
///
/// Splits a [`DirectoryIndex`] into [`DIR_INDEX_V8_NUM_SHARDS`] hash-prefix
/// shards, each stored as its OWN AEAD object at [`derive_dir_index_shard_key`]
/// and bound to `(bucket, shard_idx, seq)` via AAD. This lifts the 1 MiB
/// single-blob cliff (`MAX_MANIFEST_BLOCK_SIZE`) that the v7
/// [`EncryptedDirectoryIndex`] hits at ~30k directories: 16 shards raise the
/// effective ceiling to ~16× that.
///
/// **Storage model.** Each shard is an independent object (NOT one blob
/// holding all 16), index-addressed at a deterministic key and overwritten in
/// place. The manifest root records, per non-empty shard, a
/// [`DirIndexShardRef`] `{etag, seq, cid}` in `dir_index_shards` — mirroring
/// the manifest-page model (`page_index` / [`PageRef`]). The client writes
/// only the shards that changed since the last flush (per-shard dirty
/// tracking), so the common case re-PUTs one small shard, not the whole index.
///
/// **Routing is KEYED** (audit fix): the shard a directory lands in is
/// `BLAKE3_keyed(route_key, dir_path)` where
/// `route_key = derive_dir_index_route_key(forest_dek, bucket)`. Keying the
/// routing — rather than the unkeyed constant-prefix hash of the original D5
/// draft — denies an external observer the "known-path confirmation oracle"
/// (guess a path, compute its shard locally, watch whether that shard object
/// grew on a write). The path is plaintext in memory at routing time, so
/// keying costs nothing.
///
/// **Per-shard sequence** is monotonic and bound into the shard AAD. The
/// reader rejects a shard whose plaintext `seq` is below the root's pinned
/// `DirIndexShardRef.seq` (rollback / staleness — mirrors the page seq check
/// in `load_manifest_pages`).

/// plan-D5 — fixed shard count. Locked at 16; changing it is a coordinated
/// reader+writer migration because the shard a path routes to depends on it.
pub const DIR_INDEX_V8_NUM_SHARDS: u8 = 16;

/// plan-D5 — AAD domain separator for v8 shard ciphertexts. Distinct from the
/// v7 `dir_index_aad` prefix so a v7 reader cannot accept a v8 ciphertext (and
/// vice-versa). Full AAD:
/// `DIR_INDEX_V8_AAD_PREFIX || bucket || ':' || shard_idx || ':' || seq_le`.
const DIR_INDEX_V8_AAD_PREFIX: &[u8] = b"fula:dir-index:v8:";

/// KDF context for the keyed shard-routing key (per bucket).
const DIR_INDEX_ROUTE_KEY_DOMAIN: &str = "fula/private-forest/dir-index-route/v1";

/// KDF domain for the per-shard storage key. Distinct from the v7 dir-index,
/// shard, page, and node domains so the derived keys never alias.
const DIR_INDEX_SHARD_KEY_DOMAIN: &str = "fula/private-forest/dir-index-shard/v1";

/// Maximum plaintext size of a single shard's serialized sub-index.
///
/// The hard cap is the 1 MiB IPFS block limit on the *serialized envelope*
/// ([`EncryptedDirectoryIndexShard::to_bytes`]), which base64-encodes the
/// ciphertext (+16 B AEAD tag) and nonce — ~1.34× the plaintext plus a little
/// JSON overhead. 700 KiB of plaintext therefore yields a <1 MiB envelope with
/// comfortable margin. [`EncryptedDirectoryIndexShard::encrypt`] fails LOUDLY
/// at this bound rather than producing an object the blockstore would reject
/// downstream. At 16 shards this corresponds to an ~11 MiB total dir-index
/// (≈ several hundred thousand directories), far beyond any expected bucket; a
/// bucket that trips it needs plan-D5b (more shards, or an internally-sharded
/// `DirEntry.subdirs`).
const DIR_INDEX_SHARD_MAX_PLAINTEXT: usize = 700 * 1024;

/// plan-D5 — derive the per-bucket keyed-routing key. Deterministic from
/// `(forest_dek, bucket)` under [`DIR_INDEX_ROUTE_KEY_DOMAIN`], so every reader
/// and writer of the same bucket routes identically, while an external
/// observer (who lacks `forest_dek`) cannot predict which shard a known path
/// lands in.
pub fn derive_dir_index_route_key(forest_dek: &DekKey, bucket: &str) -> [u8; 32] {
    let mut material = Vec::with_capacity(forest_dek.as_bytes().len() + bucket.len());
    material.extend_from_slice(forest_dek.as_bytes());
    material.extend_from_slice(bucket.as_bytes());
    blake3::derive_key(DIR_INDEX_ROUTE_KEY_DOMAIN, &material)
}

/// plan-D5 — keyed shard index in `0..DIR_INDEX_V8_NUM_SHARDS` for `dir_path`
/// under the bucket's `route_key`. Keyed (audit fix) so the mapping is
/// unguessable without `forest_dek`.
pub fn shard_index_for_path(dir_path: &str, route_key: &[u8; 32]) -> u8 {
    let h = blake3::keyed_hash(route_key, dir_path.as_bytes());
    h.as_bytes()[0] & 0x0F
}

/// plan-D5 — deterministic storage key for one dir-index shard object,
/// `(forest_dek, bucket, shard_idx)` under [`DIR_INDEX_SHARD_KEY_DOMAIN`].
/// Index-addressed (overwritten in place); distinct KDF domain so it can never
/// collide with the v7 dir-index key, a shard key, a page key, or a node key.
pub fn derive_dir_index_shard_key(forest_dek: &DekKey, bucket: &str, shard_idx: u8) -> String {
    let mut hasher = blake3::Hasher::new_derive_key(DIR_INDEX_SHARD_KEY_DOMAIN);
    hasher.update(forest_dek.as_bytes());
    hasher.update(bucket.as_bytes());
    hasher.update(&[shard_idx]);
    let hash = hasher.finalize();
    format!("Qm{}", hex::encode(&hash.as_bytes()[..22]))
}

/// plan-D5 — route every entry of `index` into its shard's sub-index under
/// `route_key`. Returns only NON-EMPTY shards (a shard with no entries has no
/// object and no `DirIndexShardRef`). One O(D) in-memory pass; the caller then
/// encrypts + PUTs only the shards it needs (its dirty set).
pub fn split_directory_index_into_shards(
    index: &DirectoryIndex,
    route_key: &[u8; 32],
) -> BTreeMap<u8, DirectoryIndex> {
    let mut shards: BTreeMap<u8, DirectoryIndex> = BTreeMap::new();
    for (path, entry) in &index.entries {
        let idx = shard_index_for_path(path, route_key);
        shards
            .entry(idx)
            .or_insert_with(|| DirectoryIndex {
                version: index.version,
                entries: HashMap::new(),
            })
            .entries
            .insert(path.clone(), entry.clone());
    }
    shards
}

/// plan-D5 — AAD for one v8 shard ciphertext. Binds bucket, shard index,
/// and the shard's sequence so a ciphertext cannot be cross-shard-swapped,
/// cross-bucket-replayed, or replayed against a different sequence.
///
/// The variable-length `bucket` is LENGTH-PREFIXED (advisor fix) so the AAD is
/// injective regardless of bucket charset: distinct `(bucket, shard_idx, seq)`
/// triples can never produce the same AAD bytes. (The older v4/v7 AADs use
/// `:`-delimited string formatting and rely on the S3 bucket charset excluding
/// `:`; v8 is a fresh wire format with no deployed data, so it adopts the
/// stronger, charset-independent encoding.)
fn dir_index_v8_aad(bucket: &str, shard_idx: u8, sequence: u64) -> Vec<u8> {
    // prefix || bucket_len_le(4) || bucket || shard_idx(1) || sequence_le(8)
    let blen = bucket.len() as u32;
    let mut aad =
        Vec::with_capacity(DIR_INDEX_V8_AAD_PREFIX.len() + 4 + bucket.len() + 1 + 8);
    aad.extend_from_slice(DIR_INDEX_V8_AAD_PREFIX);
    aad.extend_from_slice(&blen.to_le_bytes());
    aad.extend_from_slice(bucket.as_bytes());
    aad.push(shard_idx);
    aad.extend_from_slice(&sequence.to_le_bytes());
    aad
}

/// plan-D5 — one encrypted directory-index shard (version 8).
///
/// Stored as its own object at [`derive_dir_index_shard_key`]. The
/// `(shard_idx, seq)` it carries are also bound into the AEAD AAD, so the
/// envelope is self-describing AND tamper-evident on those fields. The reader
/// additionally pins `seq` against the manifest root's [`DirIndexShardRef`] to
/// reject rollback.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedDirectoryIndexShard {
    /// Envelope version (= 8).
    pub version: u8,
    /// 0-indexed shard position (< [`DIR_INDEX_V8_NUM_SHARDS`]).
    pub shard_idx: u8,
    /// Monotonic per-shard sequence, bound into the AAD.
    pub seq: u64,
    /// Nonce used for encryption.
    #[serde(with = "base64_serde")]
    pub nonce: Vec<u8>,
    /// AEAD ciphertext over the per-shard sub-`DirectoryIndex` JSON.
    #[serde(with = "base64_serde")]
    pub ciphertext: Vec<u8>,
}

impl EncryptedDirectoryIndexShard {
    pub fn shard_idx(&self) -> u8 {
        self.shard_idx
    }

    pub fn seq(&self) -> u64 {
        self.seq
    }

    /// Encrypt one shard's sub-index. `sub_index` MUST contain only entries
    /// that route to `shard_idx` (use [`split_directory_index_into_shards`]).
    ///
    /// Fails LOUDLY with [`CryptoError::Serialization`] if the serialized
    /// sub-index exceeds [`DIR_INDEX_SHARD_MAX_PLAINTEXT`] — a clear error
    /// here beats an over-1-MiB object the blockstore rejects later.
    pub fn encrypt(
        sub_index: &DirectoryIndex,
        dek: &DekKey,
        bucket: &str,
        shard_idx: u8,
        seq: u64,
    ) -> Result<Self> {
        let json = serde_json::to_vec(sub_index)
            .map_err(|e| CryptoError::Serialization(e.to_string()))?;
        if json.len() >= DIR_INDEX_SHARD_MAX_PLAINTEXT {
            return Err(CryptoError::Serialization(format!(
                "dir-index shard {} plaintext size {} bytes exceeds the per-shard cap of {} bytes \
                 ({} entries in this shard). The shard's serialized envelope would approach the \
                 1 MiB IPFS block limit. This bucket has an unusually large / skewed directory set; \
                 it needs plan-D5b (more shards, or an internally-sharded DirEntry.subdirs). Existing \
                 data remains readable; only NEW writes to this shard are blocked.",
                shard_idx,
                json.len(),
                DIR_INDEX_SHARD_MAX_PLAINTEXT,
                sub_index.entries.len(),
            )));
        }
        let nonce = Nonce::generate();
        let aead = Aead::new_default(dek);
        let aad = dir_index_v8_aad(bucket, shard_idx, seq);
        let ciphertext = aead.encrypt_with_aad(&nonce, &json, &aad)?;
        Ok(Self {
            version: 8,
            shard_idx,
            seq,
            nonce: nonce.as_bytes().to_vec(),
            ciphertext,
        })
    }

    /// Decrypt + verify one shard, returning its sub-index and sealed `seq`.
    ///
    /// Verifies `version == 8`, AEAD (AAD binds bucket + shard_idx + seq), and
    /// — belt-and-suspenders, since AAD already binds `shard_idx` — that every
    /// entry routes back to this shard under the bucket's keyed routing
    /// (derived internally from `(dek, bucket)`). The CALLER is responsible for
    /// the rollback pin: reject the returned `seq` if it is below the manifest
    /// root's `DirIndexShardRef.seq` (see `load_directory_index`).
    pub fn decrypt(&self, dek: &DekKey, bucket: &str) -> Result<(DirectoryIndex, u64)> {
        if self.version != 8 {
            return Err(CryptoError::Decryption(format!(
                "expected EncryptedDirectoryIndexShard version 8, got {}",
                self.version
            )));
        }
        // Reject an out-of-range shard_idx up front (strictness). A legitimate
        // shard always has `shard_idx < DIR_INDEX_V8_NUM_SHARDS` (the routing
        // nibble); AEAD already binds shard_idx, so an out-of-range value can
        // only come from a corrupt/forged blob — fail closed early.
        if self.shard_idx >= DIR_INDEX_V8_NUM_SHARDS {
            return Err(CryptoError::Decryption(format!(
                "dir-index shard_idx {} out of range (>= {})",
                self.shard_idx, DIR_INDEX_V8_NUM_SHARDS
            )));
        }
        let nonce = Nonce::from_bytes(&self.nonce)?;
        let aead = Aead::new_default(dek);
        let aad = dir_index_v8_aad(bucket, self.shard_idx, self.seq);
        let plaintext = aead.decrypt_with_aad(&nonce, &self.ciphertext, &aad)?;
        let sub: DirectoryIndex = serde_json::from_slice(&plaintext)
            .map_err(|e| CryptoError::Serialization(e.to_string()))?;
        let route_key = derive_dir_index_route_key(dek, bucket);
        for path in sub.entries.keys() {
            let routed = shard_index_for_path(path, &route_key);
            if routed != self.shard_idx {
                return Err(CryptoError::Decryption(format!(
                    "dir-index shard {} contains path '{}' that routes to shard {}",
                    self.shard_idx, path, routed
                )));
            }
        }
        Ok((sub, self.seq))
    }

    /// Serialize this shard's envelope for storage. MUST fit one IPFS block
    /// (`MAX_MANIFEST_BLOCK_SIZE`); `encrypt`'s plaintext guard keeps it so.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self)
            .map_err(|e| CryptoError::Serialization(e.to_string()))
    }

    /// Deserialize a shard envelope from storage bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        serde_json::from_slice(bytes)
            .map_err(|e| CryptoError::Serialization(e.to_string()))
    }
}

/// Result of detecting the format at the index_key
pub enum ForestOrManifest {
    /// Monolithic forest (version 1, 2, or 4).
    Monolithic(EncryptedForest),
    /// Sharded-HAMT manifest (version 7).
    ManifestV7(EncryptedShardManifestV7),
}

/// Detect whether bytes at the index_key are a monolithic forest or sharded-HAMT manifest
///
/// Reads the outer `version` field to determine the format without decrypting.
///
/// Version mapping:
/// - 1, 2, 4    → monolithic `EncryptedForest` (v4 carries AAD+sequence).
/// - 7          → sharded-HAMT `EncryptedShardManifestV7`; each shard stores
///                a content-addressed HAMT root rather than a flat HashMap.
///
/// Intermediate sharded formats (v3/v5/v6) were removed after the v1 → v7
/// direct migration path was adopted; encountering one today is an error.
pub fn detect_forest_format(bytes: &[u8]) -> Result<ForestOrManifest> {
    let parsed: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|e| CryptoError::Serialization(e.to_string()))?;

    match parsed.get("version").and_then(|v| v.as_u64()) {
        Some(1) | Some(2) | Some(4) => {
            Ok(ForestOrManifest::Monolithic(EncryptedForest::from_bytes(bytes)?))
        }
        Some(7) => {
            Ok(ForestOrManifest::ManifestV7(EncryptedShardManifestV7::from_bytes(bytes)?))
        }
        Some(v @ (3 | 5 | 6)) => Err(CryptoError::Encryption(format!(
            "legacy sharded forest version {} is no longer supported (v1 → v7 direct migration)",
            v
        ))),
        Some(v) => Err(CryptoError::Encryption(format!("unsupported forest version: {}", v))),
        None => Err(CryptoError::Serialization("missing version field in forest data".to_string())),
    }
}


#[cfg(test)]
#[allow(deprecated)] // F2: tests legitimately exercise the legacy v1 (no-AAD) encrypt path; deprecation targets production callers only
mod tests {
    use super::*;

    #[test]
    fn test_flat_key_generation() {
        let dek = DekKey::generate();
        let salt = vec![0u8; 32];
        
        let key1 = generate_flat_key("/photos/beach.jpg", &dek, &salt);
        let key2 = generate_flat_key("/photos/beach.jpg", &dek, &salt);
        let key3 = generate_flat_key("/photos/sunset.jpg", &dek, &salt);
        
        // Same inputs = same output
        assert_eq!(key1, key2);
        // Different inputs = different output
        assert_ne!(key1, key3);
        // Looks like a CID
        assert!(key1.starts_with("Qm"));
        assert_eq!(key1.len(), 46);
        // No structural hints
        assert!(!key1.contains('/'));
        assert!(!key1.contains("photo"));
    }

    #[test]
    fn test_random_flat_key() {
        let key1 = generate_random_flat_key();
        let key2 = generate_random_flat_key();
        
        assert_ne!(key1, key2);
        assert!(key1.starts_with("Qm"));
        assert_eq!(key1.len(), 46);
    }

    #[test]
    fn test_private_forest_basic() {
        let dek = DekKey::generate();
        let mut forest = PrivateForest::new();
        
        // Add a file
        let metadata = PrivateMetadata::new("/photos/beach.jpg", 1024);
        let storage_key = forest.generate_key("/photos/beach.jpg", &dek);
        let entry = ForestFileEntry::from_metadata(&metadata, storage_key.clone());
        
        forest.upsert_file(entry);
        
        // Verify
        assert_eq!(forest.file_count(), 1);
        assert!(forest.get_file("/photos/beach.jpg").is_some());
        assert_eq!(forest.get_storage_key("/photos/beach.jpg"), Some(storage_key.as_str()));
        
        // Storage key should be flat (no structure hints)
        assert!(storage_key.starts_with("Qm"));
        assert!(!storage_key.contains('/'));
    }

    #[test]
    fn test_directory_structure() {
        let dek = DekKey::generate();
        let mut forest = PrivateForest::new();
        
        // Add files in different directories
        let files = vec![
            "/photos/vacation/beach.jpg",
            "/photos/vacation/sunset.jpg",
            "/photos/family.jpg",
            "/documents/report.pdf",
        ];
        
        for path in &files {
            let metadata = PrivateMetadata::new(*path, 1024);
            let storage_key = forest.generate_key(path, &dek);
            let entry = ForestFileEntry::from_metadata(&metadata, storage_key);
            forest.upsert_file(entry);
        }
        
        // Check directory listing
        let vacation_files = forest.list_directory("/photos/vacation");
        assert_eq!(vacation_files.len(), 2);
        
        let photos_files = forest.list_directory("/photos");
        assert_eq!(photos_files.len(), 1); // Only direct children
        
        let subdirs = forest.list_subdirs("/photos");
        assert!(subdirs.contains(&"/photos/vacation"));
        
        // Recursive listing
        let all_photos = forest.list_recursive("/photos");
        assert_eq!(all_photos.len(), 3);
    }

    #[test]
    fn test_forest_encryption_roundtrip() {
        let dek = DekKey::generate();
        let mut forest = PrivateForest::new();
        
        // Add some files
        let metadata = PrivateMetadata::new("/secret/file.txt", 500)
            .with_content_type("text/plain");
        let storage_key = forest.generate_key("/secret/file.txt", &dek);
        let entry = ForestFileEntry::from_metadata(&metadata, storage_key);
        forest.upsert_file(entry);
        
        // Encrypt
        let encrypted = EncryptedForest::encrypt(&forest, &dek).unwrap();
        
        // Decrypt with same key
        let decrypted = encrypted.decrypt(&dek).unwrap();
        
        assert_eq!(decrypted.file_count(), 1);
        let file = decrypted.get_file("/secret/file.txt").unwrap();
        assert_eq!(file.size, 500);
        assert_eq!(file.content_type, Some("text/plain".to_string()));
    }

    #[test]
    fn test_wrong_key_fails() {
        let dek1 = DekKey::generate();
        let dek2 = DekKey::generate();
        
        let forest = PrivateForest::new();
        let encrypted = EncryptedForest::encrypt(&forest, &dek1).unwrap();
        
        assert!(encrypted.decrypt(&dek2).is_err());
    }

    #[test]
    fn test_subtree_extraction() {
        let dek = DekKey::generate();
        let mut forest = PrivateForest::new();
        
        // Add files
        for path in &["/photos/a.jpg", "/photos/b.jpg", "/docs/report.pdf"] {
            let metadata = PrivateMetadata::new(*path, 100);
            let storage_key = forest.generate_key(path, &dek);
            let entry = ForestFileEntry::from_metadata(&metadata, storage_key);
            forest.upsert_file(entry);
        }
        
        // Extract photos subtree
        let subtree = forest.extract_subtree("/photos");
        
        assert_eq!(subtree.file_count(), 2);
        assert!(subtree.get_file("/photos/a.jpg").is_some());
        assert!(subtree.get_file("/docs/report.pdf").is_none());
    }

    #[test]
    fn test_find_by_storage_key() {
        let dek = DekKey::generate();
        let mut forest = PrivateForest::new();
        
        let metadata = PrivateMetadata::new("/test.txt", 100);
        let storage_key = forest.generate_key("/test.txt", &dek);
        let entry = ForestFileEntry::from_metadata(&metadata, storage_key.clone());
        forest.upsert_file(entry);
        
        let found = forest.find_by_storage_key(&storage_key);
        assert!(found.is_some());
        assert_eq!(found.unwrap().path, "/test.txt");
    }

    #[test]
    fn test_hamt_forest_basic() {
        let dek = DekKey::generate();
        let mut forest = PrivateForest::new_hamt();
        
        assert_eq!(forest.format(), &ForestFormat::HamtV2);
        
        // Add files
        for i in 0..10 {
            let path = format!("/file_{}.txt", i);
            let metadata = PrivateMetadata::new(&path, 100);
            let storage_key = forest.generate_key(&path, &dek);
            let entry = ForestFileEntry::from_metadata(&metadata, storage_key);
            forest.upsert_file(entry);
        }
        
        assert_eq!(forest.file_count(), 10);
        assert!(forest.get_file("/file_5.txt").is_some());
    }

    #[test]
    fn test_hamt_migration() {
        let dek = DekKey::generate();
        let mut forest = PrivateForest::new();
        
        assert_eq!(forest.format(), &ForestFormat::FlatMapV1);
        
        // Add files
        for i in 0..50 {
            let path = format!("/file_{}.txt", i);
            let metadata = PrivateMetadata::new(&path, 100);
            let storage_key = forest.generate_key(&path, &dek);
            let entry = ForestFileEntry::from_metadata(&metadata, storage_key);
            forest.upsert_file(entry);
        }
        
        // Manually migrate to HAMT
        forest.migrate_to_hamt();
        
        assert_eq!(forest.format(), &ForestFormat::HamtV2);
        assert_eq!(forest.file_count(), 50);
        assert!(forest.get_file("/file_25.txt").is_some());
        
        // Migrate back to flat
        forest.migrate_to_flat();
        
        assert_eq!(forest.format(), &ForestFormat::FlatMapV1);
        assert_eq!(forest.file_count(), 50);
        assert!(forest.get_file("/file_25.txt").is_some());
    }

    #[test]
    fn test_hamt_operations() {
        let dek = DekKey::generate();
        let mut forest = PrivateForest::new_hamt();
        
        // Add files
        let metadata = PrivateMetadata::new("/photos/beach.jpg", 1024);
        let storage_key = forest.generate_key("/photos/beach.jpg", &dek);
        let entry = ForestFileEntry::from_metadata(&metadata, storage_key.clone());
        forest.upsert_file(entry);
        
        // Get
        assert!(forest.get_file("/photos/beach.jpg").is_some());
        assert_eq!(forest.get_storage_key("/photos/beach.jpg"), Some(storage_key.as_str()));
        
        // Remove
        let removed = forest.remove_file("/photos/beach.jpg");
        assert!(removed.is_some());
        assert!(forest.get_file("/photos/beach.jpg").is_none());
        assert_eq!(forest.file_count(), 0);
    }

    #[test]
    fn test_hamt_serialization_roundtrip() {
        let dek = DekKey::generate();
        let mut forest = PrivateForest::new_hamt();
        
        // Add files
        for i in 0..20 {
            let path = format!("/files/doc_{}.txt", i);
            let metadata = PrivateMetadata::new(&path, 100 + i as u64);
            let storage_key = forest.generate_key(&path, &dek);
            let entry = ForestFileEntry::from_metadata(&metadata, storage_key);
            forest.upsert_file(entry);
        }
        
        // Encrypt
        let encrypted = EncryptedForest::encrypt(&forest, &dek).unwrap();
        
        // Decrypt
        let decrypted = encrypted.decrypt(&dek).unwrap();
        
        assert_eq!(decrypted.format(), &ForestFormat::HamtV2);
        assert_eq!(decrypted.file_count(), 20);
        assert!(decrypted.get_file("/files/doc_10.txt").is_some());
    }

    // ========================================================================
    // Sharded Forest Tests (S-001)
    // ========================================================================

    #[test]
    fn test_shard_key_derivation_determinism() {
        let dek = DekKey::generate();
        let salt = vec![42u8; 32];

        let key1 = derive_shard_key(&dek, "my-bucket", &salt, 0);
        let key2 = derive_shard_key(&dek, "my-bucket", &salt, 0);
        assert_eq!(key1, key2, "same inputs must produce same shard key");

        // Different shard indices produce different keys
        let key3 = derive_shard_key(&dek, "my-bucket", &salt, 1);
        assert_ne!(key1, key3, "different shard indices must differ");

        // Keys look like CID hashes
        assert!(key1.starts_with("Qm"), "shard key must start with Qm");
        assert_eq!(key1.len(), 46, "shard key must be 46 chars");
    }


    #[test]
    fn test_compute_initial_shard_count() {
        assert_eq!(compute_initial_shard_count(0), 16);
        assert_eq!(compute_initial_shard_count(100), 16);
        assert_eq!(compute_initial_shard_count(5_000), 16);
        assert_eq!(compute_initial_shard_count(10_000), 16);
        assert_eq!(compute_initial_shard_count(50_000), 16);
        // Stays at 16 for most users (handles up to ~160K files per shard at threshold)

        // Post-S-1.2 meta-HAMT, MAX_SHARDS=65,536. target = file_count / 5_000,
        // rounded up to a power of two, then clamped to [16, MAX_SHARDS].
        //   1.28M → target 256 → 256 shards.
        //   20M   → target 4,000 → next pow2 4,096.
        //   100M  → target 20,000 → next pow2 32,768.
        //   300M+ → saturates at 65,536.
        assert_eq!(compute_initial_shard_count(1_280_000), 256);
        assert_eq!(compute_initial_shard_count(20_000_000), 4_096);
        assert_eq!(compute_initial_shard_count(100_000_000), 32_768);
        assert_eq!(compute_initial_shard_count(330_000_000), MAX_SHARDS);
        assert_eq!(compute_initial_shard_count(usize::MAX / 2), MAX_SHARDS);
    }

    #[test]
    fn test_manifest_v7_meta_hamt_fits_under_max_block_size_at_max_shards() {
        // S-1.2 regression gate: under the meta-HAMT layout, *every*
        // serialized block (root + each page) must fit under
        // MAX_MANIFEST_BLOCK_SIZE at MAX_SHARDS=65,536. If this ever fails,
        // either PAGE_SIZE has crept up or per-shard metadata has grown
        // past the page budget — time to revisit the layout.
        let dek = DekKey::generate();
        let mut manifest = ShardManifestV7::new(MAX_SHARDS);
        assert_eq!(manifest.num_shards(), MAX_SHARDS);
        assert_eq!(manifest.page_count(), MAX_PAGES);

        // Populate every shard with realistic worst-case metadata: a root
        // storage key, a non-zero sequence, an entry_count, and an ETag.
        for i in 0..MAX_SHARDS {
            let shard = manifest.shard_mut(i);
            shard.root = Some([0xAB; V7_STORAGE_KEY_LEN]);
            shard.seq = (i as u64) * 3;
            shard.entry_count = 100 + i as u32;
            shard.etag = Some(format!("\"etag-shard-{:05}\"", i));
        }

        // Populate the root's page_index with worst-case entries so the
        // root itself picks up its full serialized size (one entry per
        // page, each carrying an etag string).
        for page_id in 0..MAX_PAGES as PageId {
            manifest.root.page_index.insert(
                page_id,
                PageRef {
                    etag: Some(format!("\"etag-page-{:03}\"", page_id)),
                    seq: 1,
                    cid: None,
                },
            );
        }
        manifest.root.dir_index_etag = Some("\"etag-dir-index\"".to_string());
        manifest.root.dir_index_seq = Some(42);

        // Encrypt each page and the root, assert each stays under the cap.
        for (page_id, page) in manifest.pages.iter() {
            let ep = EncryptedManifestPage::encrypt(page, &dek, "bkt")
                .expect("page must encrypt under the block cap");
            let wire = ep.ciphertext.len() + ep.nonce.len() + 16;
            assert!(
                wire < 1024 * 1024,
                "encrypted page {} wire size {} must stay under 1 MiB",
                page_id,
                wire
            );
            let decoded = ep.decrypt(&dek, "bkt").expect("page decrypts");
            assert_eq!(decoded.page_id, *page_id);
            assert_eq!(decoded.shards.len(), PAGE_SIZE);
        }

        let er = EncryptedShardManifestV7::encrypt_v7(&manifest.root, &dek, "bkt", 1)
            .expect("root must encrypt under the block cap");
        let wire = er.ciphertext.len() + er.nonce.len() + 16;
        assert!(
            wire < 1024 * 1024,
            "encrypted root wire size {} must stay under 1 MiB at MAX_SHARDS={}",
            wire,
            MAX_SHARDS
        );
        let (decoded_root, seq) = er.decrypt_v7(&dek, "bkt").expect("root decrypts");
        assert_eq!(seq, 1);
        assert_eq!(decoded_root.num_shards, MAX_SHARDS);
        assert_eq!(decoded_root.page_index.len(), MAX_PAGES);
        assert_eq!(decoded_root.dir_index_etag.as_deref(), Some("\"etag-dir-index\""));
        assert_eq!(decoded_root.dir_index_seq, Some(42));
    }

    #[test]
    fn test_manifest_page_seq_monotonic_rejects_stale() {
        // M2: a page whose plaintext seq is older than the seq expected by
        // the root must be rejected on load.
        let dek = DekKey::generate();
        let mut root = ManifestRoot::fresh(16);
        // Root expects page 0 at seq=5.
        root.page_index.insert(
            0,
            PageRef {
                etag: Some("\"etag\"".to_string()),
                seq: 5,
                cid: None,
            },
        );
        let mut stale_page = ManifestPage::empty(0, 16);
        stale_page.seq = 3;
        let mut pages = BTreeMap::new();
        pages.insert(0u16, stale_page);

        let err = ShardManifestV7::from_root_and_pages(root, pages)
            .expect_err("stale page must be rejected");
        let msg = format!("{err:?}");
        assert!(msg.contains("stale manifest page"), "got {msg}");
    }


    #[test]
    fn test_detect_forest_format_monolithic() {
        let dek = DekKey::generate();
        let forest = PrivateForest::new();
        let encrypted = EncryptedForest::encrypt(&forest, &dek).unwrap();
        let bytes = encrypted.to_bytes().unwrap();

        match detect_forest_format(&bytes).unwrap() {
            ForestOrManifest::Monolithic(_) => {} // expected
            ForestOrManifest::ManifestV7(_) => panic!("expected monolithic"),
        }
    }


    // ============================================================================
    // Fix 1 (F-2.1 + F-7.4): AAD-bound forest/manifest/shard v4/v5/v2 tests
    // ============================================================================

    #[test]
    fn test_forest_v4_roundtrip() {
        let dek = DekKey::generate();
        let mut forest = PrivateForest::new();
        forest.upsert_file(ForestFileEntry {
            path: "/a.txt".to_string(),
            storage_key: "QmABC".to_string(),
            size: 10,
            content_type: None,
            created_at: 0,
            modified_at: 0,
            user_metadata: HashMap::new(),
            content_hash: None,
            encrypted: false,
            min_version: 0,
            storage_cid: None,
        });

        let enc = EncryptedForest::encrypt_v4(&forest, &dek, "bucket-1", 7).unwrap();
        assert_eq!(enc.version, 4);
        assert_eq!(enc.sequence, Some(7));

        let (dec, seq) = enc.decrypt_v4(&dek, "bucket-1").unwrap();
        assert_eq!(seq, 7);
        assert_eq!(dec.file_count(), 1);
    }

    #[test]
    fn test_forest_v4_wrong_bucket_fails() {
        let dek = DekKey::generate();
        let forest = PrivateForest::new();
        let enc = EncryptedForest::encrypt_v4(&forest, &dek, "bucket-1", 1).unwrap();
        let err = enc.decrypt_v4(&dek, "bucket-2");
        assert!(err.is_err(), "decrypt with wrong bucket must fail");
    }

    #[test]
    fn test_forest_v4_replay_tampered_sequence_fails() {
        let dek = DekKey::generate();
        let forest = PrivateForest::new();
        let mut enc = EncryptedForest::encrypt_v4(&forest, &dek, "b", 5).unwrap();
        // Server flips outer sequence to try to replay — AAD tag check must fail.
        enc.sequence = Some(6);
        let err = enc.decrypt_v4(&dek, "b");
        assert!(err.is_err(), "tampered sequence must fail AAD verification");
    }

    #[test]
    fn test_forest_v1_legacy_still_decrypts() {
        let dek = DekKey::generate();
        let forest = PrivateForest::new();
        let enc = EncryptedForest::encrypt(&forest, &dek).unwrap();
        assert_eq!(enc.version, 1);
        assert!(enc.sequence.is_none());
        // Legacy decrypt must still work (backward compat).
        let _ = enc.decrypt(&dek).unwrap();
    }

    #[test]
    fn test_detect_forest_format_v4() {
        let dek = DekKey::generate();
        let forest = PrivateForest::new();
        let ef4 = EncryptedForest::encrypt_v4(&forest, &dek, "b", 1).unwrap();
        let bytes4 = ef4.to_bytes().unwrap();
        match detect_forest_format(&bytes4).unwrap() {
            ForestOrManifest::Monolithic(_) => {}
            _ => panic!("expected Monolithic for v4"),
        }
    }

    #[test]
    fn test_detect_forest_format_rejects_legacy_sharded_versions() {
        // v3/v5/v6 forests were removed after v1 → v7 direct migration was
        // adopted. detect_forest_format must now reject them with a clear
        // error rather than silently accepting.
        for v in [3u64, 5, 6] {
            let bytes = format!(r#"{{"version":{}}}"#, v).into_bytes();
            let err = match detect_forest_format(&bytes) {
                Err(e) => e,
                Ok(_) => panic!("expected error for legacy v{}", v),
            };
            let msg = format!("{}", err);
            assert!(
                msg.contains("legacy sharded") && msg.contains(&v.to_string()),
                "expected legacy-sharded error for v{}, got: {}",
                v, msg
            );
        }
    }

    #[test]
    fn test_parent_dir_for_routing() {
        assert_eq!(parent_dir_for_routing("/a/b/c.txt"), "/a/b/");
        assert_eq!(parent_dir_for_routing("/file.txt"), "/");
        assert_eq!(parent_dir_for_routing("/a/b/"), "/a/b/");
        assert_eq!(parent_dir_for_routing("/"), "/");
        assert_eq!(parent_dir_for_routing(""), "/");
        assert_eq!(parent_dir_for_routing("/a"), "/");
    }

    #[test]
    fn test_shard_for_path_v6_directory_locality() {
        let dek = DekKey::generate();
        let salt = vec![0u8; 32];
        let num_shards = 16;

        // All files sharing the same parent directory land in the same shard.
        let dir_a = [
            "/dir_a/1.txt",
            "/dir_a/2.txt",
            "/dir_a/very_long_filename.data",
        ];
        let idx_a = shard_for_path_v6(dir_a[0], &dek, &salt, num_shards);
        for path in &dir_a {
            assert_eq!(shard_for_path_v6(path, &dek, &salt, num_shards), idx_a);
        }

        // Files in a different parent directory hash independently (may or may not
        // differ, but over enough directories at least some differ).
        let mut seen = std::collections::HashSet::new();
        for d in 0..32 {
            let p = format!("/d{}/file.txt", d);
            seen.insert(shard_for_path_v6(&p, &dek, &salt, num_shards));
        }
        assert!(seen.len() > 1, "v6 routing should spread directories across shards");
    }

    #[test]
    fn test_shard_manifest_v7_shape() {
        let m = ShardManifestV7::new(16);
        assert_eq!(m.root.version, 7);
        assert_eq!(m.root.format, "sharded-hamt-v7");
        assert_eq!(m.num_shards(), 16);
        assert_eq!(m.shard_salt().len(), 32);
        assert!(m.shards_iter().all(|s| s.is_empty()));
        assert_eq!(m.entry_count(), 0);

        // num_shards is rounded up to the next power of two and floored at 16.
        let big = ShardManifestV7::new(100);
        assert_eq!(big.num_shards(), 128);
        let tiny = ShardManifestV7::new(1);
        assert_eq!(tiny.num_shards(), 16);
    }

    #[test]
    fn test_shard_manifest_v7_encrypt_decrypt_roundtrip() {
        let dek = DekKey::generate();
        let mut manifest = ShardManifestV7::new(16);
        manifest.shard_mut(3).root = Some([0xAB; V7_STORAGE_KEY_LEN]);
        manifest.shard_mut(3).seq = 42;
        manifest.shard_mut(3).entry_count = 17;
        manifest.shard_mut(3).etag = Some("\"abc123\"".to_string());

        // Root encrypts independently of pages in the meta-HAMT scheme.
        let em = EncryptedShardManifestV7::encrypt_v7(&manifest.root, &dek, "bucket-x", 1).unwrap();
        assert_eq!(em.version, 7);
        assert_eq!(em.sequence, 1);

        let (decoded_root, seq) = em.decrypt_v7(&dek, "bucket-x").unwrap();
        assert_eq!(seq, 1);
        assert_eq!(decoded_root.version, 7);
        assert_eq!(decoded_root.num_shards, 16);

        // Wrong bucket binding fails (AAD mismatch).
        assert!(em.decrypt_v7(&dek, "different-bucket").is_err());

        // Shard-level data lives in pages; verify page round-trip.
        let page = manifest
            .pages
            .get(&0)
            .expect("page 0 is populated on a fresh 16-shard manifest");
        let ep = EncryptedManifestPage::encrypt(page, &dek, "bucket-x").unwrap();
        let decoded_page = ep.decrypt(&dek, "bucket-x").unwrap();
        assert_eq!(decoded_page.shards[3].root, Some([0xAB; V7_STORAGE_KEY_LEN]));
        assert_eq!(decoded_page.shards[3].seq, 42);
        assert_eq!(decoded_page.shards[3].entry_count, 17);
        assert_eq!(decoded_page.shards[3].etag.as_deref(), Some("\"abc123\""));
    }

    #[test]
    fn test_detect_forest_format_v7() {
        let dek = DekKey::generate();
        let manifest = ShardManifestV7::new(16);
        let em = EncryptedShardManifestV7::encrypt_v7(&manifest.root, &dek, "b", 1).unwrap();
        let bytes = em.to_bytes().unwrap();
        match detect_forest_format(&bytes).unwrap() {
            ForestOrManifest::ManifestV7(_) => {}
            _ => panic!("expected ManifestV7 for v7"),
        }
    }

    #[test]
    fn test_hamt_node_v7_aad_shape() {
        // Confirm the structural binding: prefix + bucket + u16_be(shard).
        let aad = hamt_node_v7_aad("bucket-a", 0x0102);
        let mut expected = Vec::new();
        expected.extend_from_slice(b"fula:hamt-node:v7:");
        expected.extend_from_slice(b"bucket-a");
        expected.extend_from_slice(&0x0102u16.to_be_bytes());
        assert_eq!(aad, expected);

        // Distinct buckets / shards produce distinct AADs. Sequence is NOT in
        // AAD — HAMT flush only rewrites path-of-change nodes, so a seq-bound
        // AAD would invalidate untouched subtree ciphertexts. Replay
        // resistance lives at the manifest layer (ETag + manifest shard seq).
        assert_ne!(hamt_node_v7_aad("b", 0), hamt_node_v7_aad("c", 0));
        assert_ne!(hamt_node_v7_aad("b", 0), hamt_node_v7_aad("b", 1));
    }

    // ============================================================================
    // Walkable-v8 wire format tests (W.9.1b)
    //
    // Pin the on-disk contract for the new `Option<Cid>` fields on `PageRef`,
    // `ShardV7`, and `ForestFileEntry`. The load-bearing properties:
    //
    //   1. `Some(cid)` round-trips through the production serializer
    //      (serde_json — what `EncryptedShardManifestV7`/`EncryptedManifestPage`/
    //      `EncryptedForest` use).
    //   2. `None` round-trips losslessly (Phase 1.5/1.6/2 writers stamping
    //      `None` until W.9.3 wires the CID-stamping seam should not produce
    //      surprising decode failures).
    //   3. **Backward-compat gold standard.** A "legacy" struct without the
    //      new field, serialized as JSON, deserializes cleanly into the new
    //      struct with the new field as `None`. This is the same pattern
    //      `metadata.rs::LegacyBucketMetadata` uses for `bucket_lookup_h`
    //      forward-compat (Phase 1.2's hard constraint #1: existing pinned
    //      blobs must deserialize without migration).
    //
    // If anyone changes a field name or removes `#[serde(default)]`, these
    // tests must fail loudly — that's by design.
    // ============================================================================

    /// Helper: produce a stable BLAKE3-multihash CIDv1 with raw codec — the
    /// exact format master returns in its PUT-response ETag header. Mirrors
    /// the helper in `wnfs_hamt::pointer::walkable_v8_wire_tests::test_cid`.
    fn walkable_v8_test_cid(seed: u8) -> cid::Cid {
        let digest = [seed; 32];
        let mh = cid::multihash::Multihash::<64>::wrap(0x1e, &digest)
            .expect("BLAKE3 multihash wrap");
        cid::Cid::new_v1(0x55, mh)
    }

    #[test]
    fn page_ref_v8_some_cid_round_trips_via_json() {
        let cid = walkable_v8_test_cid(0xAB);
        let original = PageRef {
            etag: Some("\"some-etag\"".to_string()),
            seq: 7,
            cid: Some(cid),
        };
        let json = serde_json::to_vec(&original).expect("encode PageRef");
        let decoded: PageRef = serde_json::from_slice(&json).expect("decode PageRef");
        assert_eq!(decoded, original);
        assert_eq!(decoded.cid, Some(cid));
    }

    #[test]
    fn page_ref_v8_none_cid_round_trips_via_json() {
        let original = PageRef {
            etag: Some("\"e\"".to_string()),
            seq: 1,
            cid: None,
        };
        let json = serde_json::to_vec(&original).expect("encode");
        let decoded: PageRef = serde_json::from_slice(&json).expect("decode");
        assert_eq!(decoded, original);
        assert_eq!(decoded.cid, None);
    }

    #[test]
    fn page_ref_legacy_json_without_cid_field_deserializes_to_none() {
        // BACKWARD-COMPAT GOLD STANDARD (W.4.3 hard-constraint #1):
        // existing v7 ManifestRoot blobs pinned to IPFS BEFORE this field
        // was added must deserialize cleanly into the new PageRef struct,
        // with cid = None. Production data must not break.
        #[derive(Serialize, Deserialize)]
        struct LegacyPageRef {
            #[serde(default, skip_serializing_if = "Option::is_none")]
            etag: Option<String>,
            seq: u64,
            // NOTE: deliberately no `cid` field — pre-W.9.1b shape.
        }

        let legacy = LegacyPageRef {
            etag: Some("\"etag-page-007\"".to_string()),
            seq: 42,
        };
        let bytes = serde_json::to_vec(&legacy).expect("encode legacy");
        let modern: PageRef = serde_json::from_slice(&bytes)
            .expect("legacy PageRef → modern PageRef");
        assert_eq!(modern.etag.as_deref(), Some("\"etag-page-007\""));
        assert_eq!(modern.seq, 42);
        // The critical assertion — serde(default) preserves the
        // no-migration property for existing JSON-pinned ManifestRoot blobs.
        assert_eq!(modern.cid, None);
    }

    #[test]
    fn shard_v7_v8_some_root_cid_round_trips_via_json() {
        let cid = walkable_v8_test_cid(0xCD);
        let original = ShardV7 {
            root: Some([0x11; V7_STORAGE_KEY_LEN]),
            seq: 9,
            etag: Some("\"shard-etag\"".to_string()),
            entry_count: 3,
            root_cid: Some(cid),
        };
        let json = serde_json::to_vec(&original).expect("encode");
        let decoded: ShardV7 = serde_json::from_slice(&json).expect("decode");
        assert_eq!(decoded, original);
        assert_eq!(decoded.root_cid, Some(cid));
    }

    #[test]
    fn shard_v7_v8_none_root_cid_round_trips_via_json() {
        let original = ShardV7::new();
        let json = serde_json::to_vec(&original).expect("encode");
        let decoded: ShardV7 = serde_json::from_slice(&json).expect("decode");
        assert_eq!(decoded, original);
        assert_eq!(decoded.root_cid, None);
    }

    #[test]
    fn shard_v7_legacy_json_without_root_cid_deserializes_to_none() {
        // Mirrors the LegacyBucketMetadata pattern (metadata.rs:454-523):
        // a struct with the same shape as ShardV7 but WITHOUT the new
        // `root_cid` field. Existing ManifestPage blobs pinned to IPFS
        // before W.9.1b must keep deserializing into the new struct.
        #[derive(Serialize, Deserialize)]
        struct LegacyShardV7 {
            #[serde(with = "v7_storage_key_serde", default)]
            root: Option<V7StorageKey>,
            seq: u64,
            #[serde(skip_serializing_if = "Option::is_none", default)]
            etag: Option<String>,
            entry_count: u32,
            // NOTE: deliberately no `root_cid` field — pre-W.9.1b shape.
        }

        let legacy = LegacyShardV7 {
            root: Some([0xEF; V7_STORAGE_KEY_LEN]),
            seq: 11,
            etag: Some("\"e\"".to_string()),
            entry_count: 5,
        };
        let bytes = serde_json::to_vec(&legacy).expect("encode legacy ShardV7");
        let modern: ShardV7 = serde_json::from_slice(&bytes)
            .expect("legacy ShardV7 → modern ShardV7");
        assert_eq!(modern.root, Some([0xEF; V7_STORAGE_KEY_LEN]));
        assert_eq!(modern.seq, 11);
        assert_eq!(modern.entry_count, 5);
        assert_eq!(modern.root_cid, None);
    }

    #[test]
    fn forest_file_entry_v8_some_storage_cid_round_trips_via_json() {
        let cid = walkable_v8_test_cid(0x12);
        let original = ForestFileEntry {
            path: "/a.txt".to_string(),
            storage_key: "QmABC".to_string(),
            size: 100,
            content_type: Some("text/plain".to_string()),
            created_at: 1,
            modified_at: 2,
            content_hash: Some("abc".to_string()),
            user_metadata: HashMap::new(),
            encrypted: true,
            min_version: 4,
            storage_cid: Some(cid),
        };
        let json = serde_json::to_vec(&original).expect("encode");
        let decoded: ForestFileEntry = serde_json::from_slice(&json).expect("decode");
        assert_eq!(decoded.storage_cid, Some(cid));
        assert_eq!(decoded.storage_key, "QmABC");
        assert_eq!(decoded.path, "/a.txt");
    }

    #[test]
    fn forest_file_entry_v8_none_storage_cid_round_trips_via_json() {
        let original = ForestFileEntry {
            path: "/b.txt".to_string(),
            storage_key: "QmDEF".to_string(),
            size: 0,
            content_type: None,
            created_at: 0,
            modified_at: 0,
            content_hash: None,
            user_metadata: HashMap::new(),
            encrypted: false,
            min_version: 0,
            storage_cid: None,
        };
        let json = serde_json::to_vec(&original).expect("encode");
        let decoded: ForestFileEntry = serde_json::from_slice(&json).expect("decode");
        assert_eq!(decoded.storage_cid, None);
    }

    #[test]
    fn forest_file_entry_legacy_json_without_storage_cid_deserializes_to_none() {
        // BACKWARD-COMPAT GOLD STANDARD: an `EncryptedForest` (v1 monolithic
        // mode) pinned to IPFS before W.9.1b carries `ForestFileEntry`s in
        // their pre-walkable-v8 shape. A v8 SDK opening such a forest must
        // get `storage_cid = None` and otherwise see all the original fields
        // unchanged.
        #[derive(Serialize, Deserialize)]
        struct LegacyForestFileEntry {
            path: String,
            storage_key: String,
            size: u64,
            content_type: Option<String>,
            created_at: i64,
            modified_at: i64,
            content_hash: Option<String>,
            #[serde(default)]
            user_metadata: HashMap<String, String>,
            #[serde(default)]
            encrypted: bool,
            #[serde(default)]
            min_version: u8,
            // NOTE: deliberately no `storage_cid` field — pre-W.9.1b shape.
        }

        let legacy = LegacyForestFileEntry {
            path: "/photos/cat.jpg".to_string(),
            storage_key: "QmCat123".to_string(),
            size: 4096,
            content_type: Some("image/jpeg".to_string()),
            created_at: 1_700_000_000,
            modified_at: 1_700_000_500,
            content_hash: Some("blake3:...".to_string()),
            user_metadata: HashMap::new(),
            encrypted: true,
            min_version: 4,
        };
        let bytes = serde_json::to_vec(&legacy).expect("encode legacy entry");
        let modern: ForestFileEntry = serde_json::from_slice(&bytes)
            .expect("legacy ForestFileEntry → modern");
        assert_eq!(modern.path, "/photos/cat.jpg");
        assert_eq!(modern.storage_key, "QmCat123");
        assert_eq!(modern.size, 4096);
        assert_eq!(modern.content_type.as_deref(), Some("image/jpeg"));
        assert_eq!(modern.encrypted, true);
        assert_eq!(modern.min_version, 4);
        // The critical assertion — serde(default) preserves the
        // no-migration property for existing pinned `EncryptedForest` blobs.
        assert_eq!(modern.storage_cid, None);
    }

    #[test]
    fn manifest_root_and_page_carry_walkable_v8_cid_hints_through_full_round_trip() {
        // Integration round-trip: build a ShardManifestV7, populate every
        // walkable-v8 surface (page_index[*].cid, shards[*].root_cid,
        // dir_index_cid), encrypt + decrypt, assert every CID hint
        // survives. This is the load-bearing end-to-end check that the
        // new fields don't get lost anywhere in the encrypt/decrypt
        // envelope path.
        let dek = DekKey::generate();
        let mut manifest = ShardManifestV7::new(16);

        let shard0_cid = walkable_v8_test_cid(0x01);
        let shard5_cid = walkable_v8_test_cid(0x02);
        let page0_cid = walkable_v8_test_cid(0x03);
        let dir_index_cid = walkable_v8_test_cid(0x04);

        // Stamp the v8 hints on a few shards in page 0.
        let p0 = manifest.pages.get_mut(&0).unwrap();
        p0.shards[0].root = Some([0xA0; V7_STORAGE_KEY_LEN]);
        p0.shards[0].root_cid = Some(shard0_cid);
        p0.shards[5].root = Some([0xA5; V7_STORAGE_KEY_LEN]);
        p0.shards[5].root_cid = Some(shard5_cid);

        // Stamp a v8 hint on the page-index entry pointing at page 0.
        manifest.root.page_index.insert(
            0,
            PageRef {
                etag: Some("\"etag-page-0\"".to_string()),
                seq: 1,
                cid: Some(page0_cid),
            },
        );
        // Stamp the dir-index v8 hint (W.9.3 — completes W.9.1b
        // wire-format extension; previously only `dir_index_etag` +
        // `dir_index_seq` existed).
        manifest.root.dir_index_etag = Some("\"etag-dir\"".to_string());
        manifest.root.dir_index_seq = Some(99);
        manifest.root.dir_index_cid = Some(dir_index_cid);

        // Round-trip the page through encrypt/decrypt.
        let ep = EncryptedManifestPage::encrypt(p0, &dek, "bkt-w8")
            .expect("page encrypts");
        let decoded_page = ep.decrypt(&dek, "bkt-w8").expect("page decrypts");
        assert_eq!(decoded_page.shards[0].root_cid, Some(shard0_cid));
        assert_eq!(decoded_page.shards[5].root_cid, Some(shard5_cid));
        // Untouched shards stay None.
        assert_eq!(decoded_page.shards[1].root_cid, None);
        assert_eq!(decoded_page.shards[15].root_cid, None);

        // Round-trip the root.
        let er = EncryptedShardManifestV7::encrypt_v7(&manifest.root, &dek, "bkt-w8", 1)
            .expect("root encrypts");
        let (decoded_root, _seq) = er.decrypt_v7(&dek, "bkt-w8").expect("root decrypts");
        assert_eq!(decoded_root.page_index.get(&0).and_then(|r| r.cid), Some(page0_cid));
        assert_eq!(decoded_root.dir_index_cid, Some(dir_index_cid));
        // Verify dir_index_etag + dir_index_seq still round-trip alongside
        // the new dir_index_cid field — defends against accidentally
        // breaking a sibling field while adding the v8 hint.
        assert_eq!(decoded_root.dir_index_etag.as_deref(), Some("\"etag-dir\""));
        assert_eq!(decoded_root.dir_index_seq, Some(99));
    }

    #[test]
    fn manifest_root_dir_index_cid_some_round_trips_via_json() {
        let mut root = ManifestRoot::fresh(16);
        let cid = walkable_v8_test_cid(0xD1);
        root.dir_index_etag = Some("\"e\"".to_string());
        root.dir_index_seq = Some(7);
        root.dir_index_cid = Some(cid);
        let json = serde_json::to_vec(&root).expect("encode");
        let decoded: ManifestRoot = serde_json::from_slice(&json).expect("decode");
        assert_eq!(decoded.dir_index_cid, Some(cid));
        assert_eq!(decoded.dir_index_seq, Some(7));
        assert_eq!(decoded.dir_index_etag.as_deref(), Some("\"e\""));
    }

    #[test]
    fn manifest_root_dir_index_cid_none_round_trips_via_json() {
        let root = ManifestRoot::fresh(16);
        assert!(root.dir_index_cid.is_none(), "fresh root has no v8 hint");
        let json = serde_json::to_vec(&root).expect("encode");
        let decoded: ManifestRoot = serde_json::from_slice(&json).expect("decode");
        assert_eq!(decoded.dir_index_cid, None);
        // skip_serializing_if = "Option::is_none" should keep the field
        // absent in the wire form so cross-version JSON stays minimal.
        let json_str = String::from_utf8_lossy(&json);
        assert!(
            !json_str.contains("dir_index_cid"),
            "None must not appear on the wire — skip_serializing_if guard \
             prevents needless bloat (and keeps cross-version JSON byte-stable \
             when the writer is gated off). got: {}",
            json_str
        );
    }

    #[test]
    fn manifest_root_legacy_json_without_dir_index_cid_deserializes_to_none() {
        // BACKWARD-COMPAT GOLD STANDARD (W.4.3 hard-constraint #1):
        // existing v7 ManifestRoot blobs pinned to IPFS BEFORE this field
        // was added must deserialize cleanly into the new ManifestRoot
        // struct, with dir_index_cid = None. Production data must not
        // break — same property as the PageRef + ShardV7 + ForestFileEntry
        // legacy tests above.
        //
        // The legacy struct mirrors ManifestRoot's pre-W.9.3 shape, with
        // every existing field present except `dir_index_cid`. A v8 SDK
        // opening such a manifest must populate the new field as None.
        #[derive(Serialize, Deserialize)]
        struct LegacyManifestRoot {
            version: u8,
            format: String,
            num_shards: usize,
            #[serde(with = "hex_serde")]
            shard_salt: Vec<u8>,
            root: String,
            created_at: i64,
            modified_at: i64,
            #[serde(default)]
            page_index: BTreeMap<PageId, PageRef>,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            dir_index_etag: Option<String>,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            dir_index_seq: Option<u64>,
            // NOTE: deliberately no `dir_index_cid` field — pre-W.9.3 shape.
        }

        let legacy = LegacyManifestRoot {
            version: 7,
            format: "sharded-hamt-v7".to_string(),
            num_shards: 64,
            shard_salt: vec![0xAB; 32],
            root: "/".to_string(),
            created_at: 1_700_000_000,
            modified_at: 1_700_000_500,
            page_index: BTreeMap::new(),
            dir_index_etag: Some("\"e-pre-v8\"".to_string()),
            dir_index_seq: Some(13),
        };
        let bytes = serde_json::to_vec(&legacy).expect("encode legacy");
        let modern: ManifestRoot = serde_json::from_slice(&bytes)
            .expect("legacy ManifestRoot → modern ManifestRoot");
        assert_eq!(modern.version, 7);
        assert_eq!(modern.num_shards, 64);
        assert_eq!(modern.shard_salt, vec![0xAB; 32]);
        assert_eq!(modern.dir_index_etag.as_deref(), Some("\"e-pre-v8\""));
        assert_eq!(modern.dir_index_seq, Some(13));
        // The critical assertion — serde(default) preserves the
        // no-migration property for existing JSON-pinned ManifestRoot
        // blobs that pre-date W.9.3.
        assert_eq!(modern.dir_index_cid, None);
    }

    // ----------------------------------------------------------------------
    // #84 — prefix-overmatch regression guard (v1 monolithic path)
    // ----------------------------------------------------------------------
    //
    // Same bug shape as the v7 sharded variant: `PrivateForest::list_recursive`
    // (line 544) normalizes the prefix but still uses `starts_with(&normalized)`,
    // and `extract_subtree` (line 585) inherits the bug via list_recursive.
    // With prefix `/photos` and a file at `/photosold/legacy.jpg`, both
    // surfaces wrongly include the sibling.

    #[test]
    fn list_recursive_does_not_overmatch_sibling_prefix_84_v1() {
        let dek = DekKey::generate();
        let mut forest = PrivateForest::new();

        for path in &[
            "/photos/cat.jpg",
            "/photos/dog.jpg",
            "/photosold/legacy.jpg",
            "/other/x.txt",
        ] {
            let metadata = PrivateMetadata::new(*path, 100);
            let storage_key = forest.generate_key(path, &dek);
            let entry = ForestFileEntry::from_metadata(&metadata, storage_key);
            forest.upsert_file(entry);
        }

        let listing: std::collections::HashSet<String> = forest
            .list_recursive("/photos")
            .into_iter()
            .map(|f| f.path.clone())
            .collect();

        assert!(
            listing.contains("/photos/cat.jpg") && listing.contains("/photos/dog.jpg"),
            "v1 list_recursive('/photos') must include all /photos/* files; got {:?}",
            listing
        );
        assert!(
            !listing.contains("/photosold/legacy.jpg"),
            "v1 list_recursive('/photos') must NOT include /photosold/legacy.jpg \
             (sibling-prefix overmatch). got {:?}",
            listing
        );
    }

    #[test]
    fn extract_subtree_does_not_overmatch_sibling_prefix_84_v1() {
        let dek = DekKey::generate();
        let mut forest = PrivateForest::new();

        for path in &["/photos/cat.jpg", "/photosold/legacy.jpg"] {
            let metadata = PrivateMetadata::new(*path, 100);
            let storage_key = forest.generate_key(path, &dek);
            let entry = ForestFileEntry::from_metadata(&metadata, storage_key);
            forest.upsert_file(entry);
        }

        let subtree = forest.extract_subtree("/photos");

        assert!(
            subtree.get_file("/photos/cat.jpg").is_some(),
            "v1 extract_subtree('/photos') must include /photos/cat.jpg",
        );
        assert!(
            subtree.get_file("/photosold/legacy.jpg").is_none(),
            "v1 extract_subtree('/photos') must NOT include /photosold/legacy.jpg \
             (sibling-prefix overmatch)",
        );
    }

    /// #84 — legacy v1 entries with non-canonical (no-leading-slash)
    /// paths must still be surfaced by canonical prefix queries.
    /// See the v7 sharded counterpart for the rationale.
    #[test]
    fn list_recursive_finds_legacy_no_leading_slash_path_84_v1() {
        let dek = DekKey::generate();
        let mut forest = PrivateForest::new();

        let metadata = PrivateMetadata::new("foo/cat.jpg", 100); // no leading slash
        let storage_key = forest.generate_key("foo/cat.jpg", &dek);
        let entry = ForestFileEntry::from_metadata(&metadata, storage_key);
        forest.upsert_file(entry);

        // Canonical query should still find the legacy entry.
        let listing: std::collections::HashSet<String> = forest
            .list_recursive("/foo")
            .into_iter()
            .map(|f| f.path.clone())
            .collect();
        assert!(
            listing.contains("foo/cat.jpg"),
            "v1 list_recursive('/foo') must surface legacy non-canonical \
             entry 'foo/cat.jpg' via path normalization in the comparison. \
             got {:?}",
            listing
        );
    }

    /// #84 — v1 monolithic mirror of the dir-ancestor branch test in
    /// `sharded_hamt_forest.rs`. Pre-fix `extract_subtree`'s directory
    /// loop used `prefix.starts_with(path)` which is true for
    /// `"/foo".starts_with("/foobar")` is false but
    /// `"/foobar".starts_with("/foo")` is true — wrongly including
    /// `/foobar` as a "descendant" of `/foo`. The other direction
    /// (`path.starts_with(prefix)`) was the file-branch overmatch.
    /// Post-fix both directions go through `path_under_prefix_v1`.
    // ----------------------------------------------------------------------
    // plan-D5 — directory-index prefix sharding regression guards.
    //
    // Pre-D5, `EncryptedDirectoryIndex::encrypt` serializes the entire
    // `DirectoryIndex` to a single JSON, encrypts as one blob, and rejects
    // anything ≥ `MAX_MANIFEST_BLOCK_SIZE` (1 MiB). At ~30k+ entries the
    // cliff triggers and **NEW writes to that bucket fail until the user
    // re-organizes** (D1 surfaces this in the error message). Existing
    // data remains readable; only writes are blocked.
    //
    // Test 1 documents the cliff exists today (encrypts a 30k-entry index
    // and asserts the existing v7 path errors with the documented cliff
    // message). It passes both pre- and post-fix because the v7 envelope
    // contract is unchanged.
    //
    // Test 2 asserts the post-fix property: the per-shard
    // `EncryptedDirectoryIndexShard` path (plan-D5 / v8) handles the same
    // 30k-entry index without hitting the cliff, splitting it across
    // keyed-routed shards each well under the 1 MiB block cap.
    // ----------------------------------------------------------------------

    /// Build a DirectoryIndex large enough to push the JSON serialization
    /// past `MAX_MANIFEST_BLOCK_SIZE` (1 MiB). Separate function so the
    /// pre- and post-fix tests share the construction.
    ///
    /// Uses a 100-section × 300-leaf pattern (= 30k+ leaf dirs, 100
    /// section dirs, plus root) rather than 30k flat top-level dirs.
    /// The flat pattern would put root's 30k-subdir BTreeSet into one
    /// hash-prefix shard, making that single shard ~660 KB by itself —
    /// still well under the 1 MiB cliff but skewing the per-shard
    /// distribution. Real-world directory trees aren't 30k-flat-children;
    /// the scattered pattern below better models the expected workload.
    ///
    /// Known limitation (plan-D5b): under N=16 hash-prefix sharding, a
    /// pathologically flat tree where root has 100k+ direct children
    /// would still concentrate ~1 MiB of subdir-set JSON into one
    /// shard. A future plan-D5b could shard `DirEntry.subdirs`
    /// internally, similar to #72/#83's HAMT-walk replacement of the
    /// cliff-prone Vec<String> field.
    #[cfg(test)]
    fn build_d5_cliff_index() -> DirectoryIndex {
        let mut index = DirectoryIndex::new();
        for section in 0..100 {
            for leaf in 0..300 {
                index.ensure_dir(&format!("/sec{:03}/dir{:06}", section, leaf));
            }
        }
        index
    }

    /// plan-D5 / Test 1 — confirms the cliff exists in the v7 single-blob
    /// path. This is a regression guard: if this test starts failing, it
    /// means somebody silently lifted the cap in the v7 envelope, which
    /// would break the cross-version compat invariant (v7 readers MUST be
    /// able to bound block size).
    #[test]
    fn dir_index_v7_30k_entries_hits_1mib_cliff_d5() {
        let dek = DekKey::generate();
        let index = build_d5_cliff_index();

        // Independently confirm the JSON exceeds the cap so the test is
        // self-explanatory if it ever starts erroring elsewhere.
        let json_len = serde_json::to_vec(&index)
            .expect("serialize DirectoryIndex")
            .len();
        assert!(
            json_len > 1_048_576,
            "test setup precondition: 30k-entry index must produce >1 MiB JSON; got {} bytes",
            json_len
        );

        let result = EncryptedDirectoryIndex::encrypt(&index, &dek, "bucket-d5-pre", 1);
        let err = result.expect_err("v7 encrypt must reject >=1 MiB plaintext");
        let msg = format!("{}", err);
        assert!(
            msg.contains("exceeds the 1048576 byte block cap"),
            "expected the documented cliff error from D1, got: {}",
            msg
        );
        assert!(
            msg.contains("(plan D5)"),
            "expected the error to mention plan D5 as the proper fix, got: {}",
            msg
        );
    }

    /// Test helper — encrypt every NON-EMPTY shard of `index` (mirrors the
    /// client write path applied to ALL shards at once), keyed by shard_idx.
    #[cfg(test)]
    fn encrypt_all_dir_index_shards(
        index: &DirectoryIndex,
        dek: &DekKey,
        bucket: &str,
        seq: u64,
    ) -> std::collections::BTreeMap<u8, EncryptedDirectoryIndexShard> {
        let route_key = derive_dir_index_route_key(dek, bucket);
        split_directory_index_into_shards(index, &route_key)
            .into_iter()
            .map(|(idx, sub)| {
                let env = EncryptedDirectoryIndexShard::encrypt(&sub, dek, bucket, idx, seq)
                    .expect("encrypt shard");
                (idx, env)
            })
            .collect()
    }

    /// Test helper — decrypt + merge a set of shard envelopes back into one
    /// `DirectoryIndex` (mirrors the client read-path merge), enforcing the
    /// per-shard seq floor against `expected_seq`.
    #[cfg(test)]
    fn decrypt_merge_dir_index_shards(
        shards: &std::collections::BTreeMap<u8, EncryptedDirectoryIndexShard>,
        dek: &DekKey,
        bucket: &str,
        expected_seq: u64,
    ) -> Result<DirectoryIndex> {
        // Start from a TRULY-empty index (not `DirectoryIndex::new()`, which
        // pre-seeds a root "/" entry) and fill purely from the shards — this
        // mirrors the real client read path, where the shards collectively
        // hold every entry including the root.
        let mut merged = DirectoryIndex {
            version: 1,
            entries: std::collections::HashMap::new(),
        };
        for (idx, env) in shards {
            let (sub, seq) = env.decrypt(dek, bucket)?;
            assert!(
                seq >= expected_seq,
                "shard {} seq {} below floor {}",
                idx, seq, expected_seq
            );
            merged.entries.extend(sub.entries);
        }
        Ok(merged)
    }

    /// plan-D5 — a 30k-entry index that hits the v7 cliff is handled by
    /// sharding: every non-empty shard's serialized envelope fits well
    /// under the 1 MiB IPFS block cap, and decrypt+merge reproduces the
    /// original DirectoryIndex.
    #[test]
    fn dir_index_v8_30k_entries_handled_via_sharding_d5() {
        let dek = DekKey::generate();
        let index = build_d5_cliff_index();
        let bucket = "bucket-d5-post";
        let seq = 1u64;

        let shards = encrypt_all_dir_index_shards(&index, &dek, bucket, seq);
        assert!(!shards.is_empty(), "30k entries must populate shards");
        assert!(shards.len() <= DIR_INDEX_V8_NUM_SHARDS as usize);

        // Every shard's serialized envelope must comfortably fit one IPFS
        // block (assert < 256 KiB to surface a regression long before the
        // 1 MiB cliff returns).
        for (idx, env) in &shards {
            let bytes = env.to_bytes().expect("serialize shard");
            assert!(
                bytes.len() < 256 * 1024,
                "shard {} serialized to {} bytes; want < 256 KiB",
                idx,
                bytes.len()
            );
        }

        let decoded = decrypt_merge_dir_index_shards(&shards, &dek, bucket, seq)
            .expect("decrypt+merge round-trip");
        assert_eq!(
            decoded.entries, index.entries,
            "sharded round-trip must reconstruct the original DirectoryIndex"
        );
    }

    /// plan-D5 — small-input round-trip. Few directories → only a handful
    /// of non-empty shards, each round-trips and merges back identically.
    #[test]
    fn dir_index_v8_small_input_round_trips_d5() {
        let dek = DekKey::generate();
        let bucket = "bucket-d5-small";
        let mut index = DirectoryIndex::new();
        for path in &["/photos", "/photos/2024", "/photos/2024/jan", "/docs", "/docs/tax"] {
            index.ensure_dir(path);
        }

        let shards = encrypt_all_dir_index_shards(&index, &dek, bucket, 7);
        assert!(!shards.is_empty());
        let decoded = decrypt_merge_dir_index_shards(&shards, &dek, bucket, 7)
            .expect("round-trip");
        assert_eq!(decoded.entries, index.entries);
    }

    /// plan-D5 (audit fix) — keyed routing is deterministic per (dek,bucket)
    /// and differs across buckets/users, denying the known-path confirmation
    /// oracle an external observer would have with unkeyed routing.
    #[test]
    fn dir_index_v8_keyed_routing_is_deterministic_and_per_bucket_d5() {
        let dek = DekKey::generate();
        let rk_a = derive_dir_index_route_key(&dek, "bucket-A");
        let rk_a2 = derive_dir_index_route_key(&dek, "bucket-A");
        assert_eq!(rk_a, rk_a2, "route key must be deterministic per (dek,bucket)");
        let rk_b = derive_dir_index_route_key(&dek, "bucket-B");
        assert_ne!(rk_a, rk_b, "different buckets must derive different route keys");

        for p in &["/a", "/a/b", "/photos/2024/jan", "/x/y/z"] {
            assert_eq!(shard_index_for_path(p, &rk_a), shard_index_for_path(p, &rk_a));
            assert!(shard_index_for_path(p, &rk_a) < DIR_INDEX_V8_NUM_SHARDS);
        }
        // Across enough paths, the two buckets' routings are not identical
        // (so an attacker can't precompute a path's shard without the dek).
        let differs = (0..256)
            .map(|i| format!("/dir{:04}", i))
            .any(|p| shard_index_for_path(&p, &rk_a) != shard_index_for_path(&p, &rk_b));
        assert!(differs, "keyed routing must differ across buckets for some paths");
    }

    /// plan-D5 — keyed routing distributes ~uniformly across the 16 shards,
    /// so the per-shard cliff headroom is real (not concentrated in one).
    #[test]
    fn dir_index_v8_routing_distribution_is_balanced_d5() {
        let dek = DekKey::generate();
        let rk = derive_dir_index_route_key(&dek, "bucket-dist");
        let mut counts = [0u32; DIR_INDEX_V8_NUM_SHARDS as usize];
        for i in 0..16_000 {
            let idx = shard_index_for_path(&format!("/sec{}/dir{:06}", i % 50, i), &rk);
            counts[idx as usize] += 1;
        }
        // Expected ~1000/shard; allow ±50% to avoid flakiness while still
        // catching a badly-skewed routing function.
        for (i, c) in counts.iter().enumerate() {
            assert!(
                *c > 500 && *c < 1500,
                "shard {} got {} of 16000 entries; routing too skewed",
                i, c
            );
        }
    }

    /// plan-D5 — `split` returns only non-empty shards, routes every entry
    /// to its keyed shard, and partitions the index without loss.
    #[test]
    fn dir_index_v8_split_routes_entries_correctly_d5() {
        let dek = DekKey::generate();
        let bucket = "bucket-split";
        let route_key = derive_dir_index_route_key(&dek, bucket);
        let mut index = DirectoryIndex::new();
        for i in 0..200 {
            index.ensure_dir(&format!("/d{:03}", i));
        }
        let shards = split_directory_index_into_shards(&index, &route_key);
        for (idx, sub) in &shards {
            assert!(!sub.entries.is_empty(), "shard {} must be non-empty in the map", idx);
            for path in sub.entries.keys() {
                assert_eq!(shard_index_for_path(path, &route_key), *idx);
            }
        }
        let total: usize = shards.values().map(|s| s.entries.len()).sum();
        assert_eq!(total, index.entries.len(), "split must not lose entries");
    }

    /// plan-D5 — the per-shard size guard fails LOUDLY rather than emitting
    /// an over-1-MiB object. 16 shards RAISE the cliff ~16×, they don't
    /// remove it: a single pathologically-large shard must error.
    #[test]
    fn dir_index_v8_oversize_shard_fails_loudly_d5() {
        let dek = DekKey::generate();
        // One directory with a huge subdirs set pushes a single shard's
        // serialized sub-index past the per-shard plaintext cap.
        let mut sub = DirectoryIndex::new();
        let mut big = DirEntry::default();
        for i in 0..60_000 {
            big.subdirs.insert(format!("child-directory-with-a-longish-name-{:08}", i));
        }
        sub.entries.insert("/huge".to_string(), big);
        let json_len = serde_json::to_vec(&sub).unwrap().len();
        assert!(
            json_len >= DIR_INDEX_SHARD_MAX_PLAINTEXT,
            "test setup: sub-index must exceed the per-shard cap; got {} bytes",
            json_len
        );

        let err = EncryptedDirectoryIndexShard::encrypt(&sub, &dek, "bucket-big", 0, 1)
            .expect_err("oversize shard must fail loudly");
        let msg = format!("{}", err);
        assert!(
            msg.contains("exceeds the per-shard cap"),
            "expected the loud per-shard-cap error, got: {}",
            msg
        );
    }

    /// plan-D5 — an empty directory index produces zero shards (no objects,
    /// no `DirIndexShardRef`s), and decrypt+merge of nothing yields an empty
    /// index. Confirms the degenerate "bucket with no directories" case.
    #[test]
    fn dir_index_v8_empty_index_produces_no_shards_d5() {
        let dek = DekKey::generate();
        let bucket = "bucket-empty";
        let route_key = derive_dir_index_route_key(&dek, bucket);
        // A TRULY-empty index (zero entries). `DirectoryIndex::new()` would
        // pre-seed a root "/" entry, which routes to exactly one shard.
        let empty = DirectoryIndex {
            version: 1,
            entries: std::collections::HashMap::new(),
        };
        assert!(
            split_directory_index_into_shards(&empty, &route_key).is_empty(),
            "empty index must produce zero shards"
        );
        let envs = encrypt_all_dir_index_shards(&empty, &dek, bucket, 1);
        assert!(envs.is_empty());
        let merged = decrypt_merge_dir_index_shards(&envs, &dek, bucket, 1).expect("merge empty");
        assert!(merged.entries.is_empty());
    }

    /// plan-D5 — validates the [`DIR_INDEX_SHARD_MAX_PLAINTEXT`] base64
    /// headroom claim end-to-end: a near-cap shard's SERIALIZED envelope (not
    /// just its plaintext) stays under the 1 MiB IPFS block cap, and still
    /// round-trips. This is the assertion that proves the per-shard plaintext
    /// cap actually keeps the on-wire object under the block limit.
    #[test]
    fn dir_index_v8_envelope_stays_under_block_cap_d5() {
        let dek = DekKey::generate();
        let bucket = "bucket-cap";
        // A single-entry sub-index (no root) whose one directory has a large
        // subdirs set, sized to land just UNDER the per-shard plaintext cap so
        // `encrypt` accepts it. The shard is encrypted under the entry's OWN
        // routed shard_idx so the decrypt re-route check passes.
        let path = "/near-cap";
        let route_key = derive_dir_index_route_key(&dek, bucket);
        let shard_idx = shard_index_for_path(path, &route_key);
        let mut sub = DirectoryIndex {
            version: 1,
            entries: std::collections::HashMap::new(),
        };
        let mut big = DirEntry::default();
        for i in 0..16_000 {
            big.subdirs.insert(format!("child-directory-with-name-{:010}", i));
        }
        sub.entries.insert(path.to_string(), big);
        let plaintext_len = serde_json::to_vec(&sub).unwrap().len();
        assert!(
            plaintext_len < DIR_INDEX_SHARD_MAX_PLAINTEXT,
            "test setup: plaintext {} must be under the cap {}",
            plaintext_len, DIR_INDEX_SHARD_MAX_PLAINTEXT
        );
        assert!(
            plaintext_len > 400 * 1024,
            "test setup: want a near-cap plaintext to exercise the headroom, got {}",
            plaintext_len
        );

        let env = EncryptedDirectoryIndexShard::encrypt(&sub, &dek, bucket, shard_idx, 1)
            .expect("near-cap shard must encrypt");
        let envelope_len = env.to_bytes().expect("to_bytes").len();
        assert!(
            envelope_len < MAX_MANIFEST_BLOCK_SIZE,
            "serialized shard envelope {} must stay under the 1 MiB block cap {} \
             (validates the per-shard plaintext cap's base64 headroom)",
            envelope_len, MAX_MANIFEST_BLOCK_SIZE
        );
        let (decoded, _) = env.decrypt(&dek, bucket).expect("near-cap round-trip");
        assert_eq!(decoded.entries, sub.entries);
    }

    /// plan-D5 — the length-prefixed AAD (advisor fix) is injective: buckets
    /// containing `:` round-trip, and a shard for `"a:1"` does NOT decrypt as
    /// bucket `"a"` (which a naive `:`-delimited AAD could alias).
    #[test]
    fn dir_index_v8_bucket_with_colon_does_not_alias_d5() {
        let dek = DekKey::generate();
        let mut index = DirectoryIndex::new();
        index.ensure_dir("/a");

        for bucket in &["a:1", "weird::name", "trailing:"] {
            let shards = encrypt_all_dir_index_shards(&index, &dek, bucket, 1);
            let merged = decrypt_merge_dir_index_shards(&shards, &dek, bucket, 1)
                .expect("colon-bucket round-trip");
            assert_eq!(merged.entries, index.entries);
        }

        // A shard sealed for "a:1" must not decrypt as "a" (length-prefix
        // makes the two AADs distinct even though a delimiter form could
        // produce overlapping bytes).
        let s = encrypt_all_dir_index_shards(&index, &dek, "a:1", 1);
        let (_, env) = s.iter().next().expect("one shard");
        assert!(
            env.decrypt(&dek, "a").is_err(),
            "length-prefixed AAD must prevent 'a:1' aliasing 'a'"
        );
    }

    /// plan-D5 (v8) — `insert_file` into a NON-existent deep path must report
    /// EVERY touched entry key (root + every created ancestor) so the forest's
    /// per-shard dirty tracking marks all affected shards. A miss here would be
    /// a silently-stale shard on read (the load-bearing no-under-marking
    /// property the advisors flagged).
    #[test]
    fn dir_index_v8_insert_deep_path_returns_all_touched_keys_d5() {
        let mut index = DirectoryIndex { version: 1, entries: HashMap::new() };
        let changed = index.insert_file("/a/b/c/file.txt");
        let set: std::collections::HashSet<&str> = changed.iter().map(|s| s.as_str()).collect();
        for k in ["/", "/a", "/a/b", "/a/b/c"] {
            assert!(
                set.contains(k),
                "insert_file deep path must report touched key {}; got {:?}",
                k, changed
            );
        }
        // A second file into the now-existing dir changes only the parent's
        // file_count → exactly the parent key (no over-reporting).
        let again = index.insert_file("/a/b/c/file2.txt");
        assert_eq!(
            again,
            vec!["/a/b/c".to_string()],
            "a second file into an existing dir must report only the parent key"
        );
    }

    /// plan-D5 (v8) — `ensure_dir` on an already-existing path is a no-op and
    /// reports NO changed keys (so an idempotent mkdir marks no shard dirty).
    #[test]
    fn dir_index_v8_ensure_existing_dir_reports_no_change_d5() {
        let mut index = DirectoryIndex { version: 1, entries: HashMap::new() };
        let _ = index.ensure_dir("/x/y");
        let again = index.ensure_dir("/x/y");
        assert!(again.is_empty(), "re-ensuring an existing dir must report no change; got {:?}", again);
    }

    /// plan-D5 — a shard ciphertext cannot be moved into another shard's
    /// slot: AAD binds `shard_idx`, so decrypting shard B's bytes while
    /// claiming `shard_idx = A` fails AEAD.
    #[test]
    fn dir_index_v8_cross_shard_swap_rejected_d5() {
        let dek = DekKey::generate();
        let bucket = "bucket-d5-swap";
        let index = build_d5_cliff_index();
        let shards = encrypt_all_dir_index_shards(&index, &dek, bucket, 1);
        let ids: Vec<u8> = shards.keys().copied().collect();
        assert!(ids.len() >= 2, "need >=2 non-empty shards for a swap test");
        let (a, b) = (ids[0], ids[1]);
        // Forge a shard claiming idx=a but carrying b's ciphertext/nonce/seq.
        let mut forged = shards[&b].clone();
        forged.shard_idx = a;
        let err = forged
            .decrypt(&dek, bucket)
            .expect_err("cross-shard swap must fail (AAD binds shard_idx)");
        let msg = format!("{}", err).to_lowercase();
        assert!(
            msg.contains("decrypt")
                || msg.contains("aead")
                || msg.contains("aes")
                || msg.contains("invalid")
                || msg.contains("tag"),
            "expected an AEAD-grade rejection, got: {}",
            msg
        );
    }

    /// plan-D5 — cross-bucket replay is rejected: the bucket name is in
    /// the AAD, so a shard for bucket A cannot decrypt as bucket B.
    #[test]
    fn dir_index_v8_cross_bucket_aad_rejected_d5() {
        let dek = DekKey::generate();
        let mut index = DirectoryIndex::new();
        index.ensure_dir("/some/path");
        let shards = encrypt_all_dir_index_shards(&index, &dek, "bucket-A", 1);
        let (_, env) = shards.iter().next().expect("one shard");
        let err = env
            .decrypt(&dek, "bucket-B")
            .expect_err("cross-bucket decrypt must fail");
        let msg = format!("{}", err).to_lowercase();
        assert!(
            msg.contains("decrypt")
                || msg.contains("aead")
                || msg.contains("aes")
                || msg.contains("invalid")
                || msg.contains("tag"),
            "expected AEAD rejection on cross-bucket attempt, got: {}",
            msg
        );
    }

    /// plan-D5 — seq is bound into the shard AAD: claiming a different seq
    /// than the one the ciphertext was sealed with fails AEAD.
    #[test]
    fn dir_index_v8_sequence_replay_rejected_d5() {
        let dek = DekKey::generate();
        let bucket = "bucket-d5-seq";
        let mut index = DirectoryIndex::new();
        index.ensure_dir("/x");
        let shards = encrypt_all_dir_index_shards(&index, &dek, bucket, 42);
        let (_, env) = shards.iter().next().expect("one shard");
        let mut tampered = env.clone();
        tampered.seq = 100; // AAD was sealed with seq=42
        let err = tampered
            .decrypt(&dek, bucket)
            .expect_err("seq-replay decrypt must fail");
        let msg = format!("{}", err).to_lowercase();
        assert!(
            msg.contains("decrypt")
                || msg.contains("aead")
                || msg.contains("aes")
                || msg.contains("invalid")
                || msg.contains("tag"),
            "expected AEAD rejection on seq replay, got: {}",
            msg
        );
    }

    /// plan-D5 — splice defense the reader relies on: an OLD shard (lower
    /// seq) served under a root pinning a NEWER seq is rejectable. The
    /// old blob is still AEAD-valid (it was a real generation), but
    /// `decrypt` surfaces its true (lower) seq so the caller's seq-floor
    /// check (mirroring `load_manifest_pages`) rejects it.
    #[test]
    fn dir_index_v8_old_shard_seq_below_floor_is_detectable_d5() {
        let dek = DekKey::generate();
        let bucket = "bucket-d5-splice";
        let mut index = DirectoryIndex::new();
        index.ensure_dir("/a");
        // Generation 1 at seq=5; the current root has since advanced to seq=6.
        let gen1 = encrypt_all_dir_index_shards(&index, &dek, bucket, 5);
        let (idx, old_env) = gen1.iter().next().expect("one shard");
        let (_, served_seq) = old_env
            .decrypt(&dek, bucket)
            .expect("an old generation's blob is still AEAD-valid");
        assert_eq!(served_seq, 5, "decrypt surfaces the real shard seq");
        assert!(
            served_seq < 6,
            "caller's seq-floor (root pins 6) must reject stale shard {}",
            idx
        );
    }

    /// plan-D5 — the v8 shard decoder rejects a non-v8 version byte.
    #[test]
    fn dir_index_v8_decoder_rejects_wrong_version_d5() {
        let dek = DekKey::generate();
        let bucket = "bucket-ver";
        let mut index = DirectoryIndex::new();
        index.ensure_dir("/a");
        let shards = encrypt_all_dir_index_shards(&index, &dek, bucket, 1);
        let (_, env) = shards.iter().next().expect("one shard");
        let mut wrong = env.clone();
        wrong.version = 7;
        let err = wrong
            .decrypt(&dek, bucket)
            .expect_err("v8 decoder must reject version=7");
        let msg = format!("{}", err);
        assert!(
            msg.contains("version 8"),
            "expected version-mismatch error, got: {}",
            msg
        );
    }

    /// plan-D5 — a v7 single-blob envelope and a v8 shard envelope are not
    /// interchangeable: v7 bytes don't decode/decrypt as a v8 shard.
    #[test]
    fn dir_index_v8_decoder_rejects_v7_envelope_d5() {
        let dek = DekKey::generate();
        let bucket = "bucket-x";
        let mut index = DirectoryIndex::new();
        index.ensure_dir("/a");
        let v7 = EncryptedDirectoryIndex::encrypt(&index, &dek, bucket, 1).expect("v7 encrypt");
        let v7_bytes = v7.to_bytes().expect("v7 to_bytes");
        // v7 JSON lacks the required v8 `shard_idx`/`seq` fields, so
        // `from_bytes` rejects it at decode; if a future shape change ever
        // let it decode, decrypt must still fail.
        match EncryptedDirectoryIndexShard::from_bytes(&v7_bytes) {
            Err(_) => {}
            Ok(env) => assert!(
                env.decrypt(&dek, bucket).is_err(),
                "a v7 blob decoded as a v8 shard must fail decrypt"
            ),
        }
    }

    /// plan-D5 — a v7 envelope still encrypts/decrypts correctly after
    /// the v8 envelope was added. Guards against accidental regression
    /// in the v7 path.
    #[test]
    fn dir_index_v7_round_trip_unaffected_by_v8_d5() {
        let dek = DekKey::generate();
        let bucket = "bucket-d5-v7";
        let mut index = DirectoryIndex::new();
        index.ensure_dir("/photos/2024");
        index.ensure_dir("/photos/2025");
        index.insert_file("/photos/2024/cat.jpg");

        let envelope = EncryptedDirectoryIndex::encrypt(&index, &dek, bucket, 9)
            .expect("v7 encrypt small input");
        let (decoded, seq) = envelope.decrypt(&dek, bucket).expect("v7 decrypt");
        assert_eq!(seq, 9);
        assert_eq!(decoded, index);
    }

    #[test]
    fn extract_subtree_dir_ancestor_branch_does_not_overmatch_sibling_84_v1() {
        let dek = DekKey::generate();
        let mut forest = PrivateForest::new();

        // Plant siblings with distinct directory entries.
        for path in &["/foo/inside.txt", "/foobar/sibling.txt"] {
            let metadata = PrivateMetadata::new(*path, 100);
            let storage_key = forest.generate_key(path, &dek);
            let entry = ForestFileEntry::from_metadata(&metadata, storage_key);
            forest.upsert_file(entry);
        }
        forest.directories.insert(
            "/foo".to_string(),
            ForestDirectoryEntry {
                path: "/foo".to_string(),
                files: Vec::new(),
                subdirs: Vec::new(),
                metadata: None,
                subtree_dek: None,
            },
        );
        forest.directories.insert(
            "/foobar".to_string(),
            ForestDirectoryEntry {
                path: "/foobar".to_string(),
                files: Vec::new(),
                subdirs: Vec::new(),
                metadata: None,
                subtree_dek: None,
            },
        );

        let subtree = forest.extract_subtree("/foo");

        assert!(
            subtree.get_file("/foo/inside.txt").is_some(),
            "v1 extract_subtree('/foo') must include /foo/inside.txt"
        );
        assert!(
            subtree.get_file("/foobar/sibling.txt").is_none(),
            "v1 extract_subtree('/foo') must NOT include /foobar/sibling.txt"
        );
        assert!(
            !subtree.directories.contains_key("/foobar"),
            "v1 extract_subtree('/foo')'s directories map must NOT include /foobar \
             (sibling-prefix ancestor overmatch). got keys {:?}",
            subtree.directories.keys().collect::<Vec<_>>()
        );
    }
}
