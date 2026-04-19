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
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Forest format version
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ForestFormat {
    /// Original flat HashMap (version 1)
    FlatMapV1,
    /// HAMT-backed index (version 2) for large forests
    HamtV2,
    /// Sharded index (version 3) — manifest + per-shard encrypted S3 objects
    ShardedV3,
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
        
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

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
            ForestFormat::ShardedV3 => unreachable!("ShardedV3 uses ShardedPrivateForest, not PrivateForest"),
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
        self.modified_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
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
            ForestFormat::ShardedV3 => unreachable!("ShardedV3 uses ShardedPrivateForest, not PrivateForest"),
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
            ForestFormat::ShardedV3 => unreachable!("ShardedV3 uses ShardedPrivateForest, not PrivateForest"),
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
            ForestFormat::ShardedV3 => unreachable!("ShardedV3 uses ShardedPrivateForest, not PrivateForest"),
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
            ForestFormat::ShardedV3 => unreachable!("ShardedV3 uses ShardedPrivateForest, not PrivateForest"),
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
        let normalized = if prefix.is_empty() {
            "/".to_string()
        } else if prefix.starts_with('/') {
            prefix.to_string()
        } else {
            format!("/{}", prefix)
        };

        // For both formats, filter all files by prefix
        // This is still efficient as list_all_files uses the right storage
        self.list_all_files()
            .into_iter()
            .filter(|f| f.path.starts_with(&normalized))
            .collect()
    }

    /// Get total file count
    pub fn file_count(&self) -> usize {
        match self.format {
            ForestFormat::FlatMapV1 => self.files.len(),
            ForestFormat::HamtV2 => self.files_hamt.as_ref().map(|h| h.len()).unwrap_or(0),
            ForestFormat::ShardedV3 => unreachable!("ShardedV3 uses ShardedPrivateForest, not PrivateForest"),
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
        
        // Copy matching files using format-aware iteration
        for entry in self.list_recursive(prefix) {
            subtree.files.insert(entry.path.clone(), entry.clone());
        }
        
        // Copy matching directories
        for (path, dir) in &self.directories {
            if path.starts_with(prefix) || prefix.starts_with(path) {
                subtree.directories.insert(path.clone(), dir.clone());
            }
        }
        
        subtree
    }
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
    /// Prefer [`EncryptedForest::encrypt_v4`] for new writes — it binds the
    /// ciphertext to the bucket and a monotonic sequence counter for replay
    /// protection. This legacy constructor is preserved so existing tests and
    /// pre-v4 call sites compile, but new code paths go through v4.
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
    pub fn decrypt(&self, dek: &DekKey) -> Result<PrivateForest> {
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
// Sharded Forest (ForestFormat::ShardedV3)
// ============================================================================

/// Threshold for automatic migration from monolithic to sharded format
#[deprecated(note = "Migration now triggers on first v1/v2 load via observed_seq.is_none(); see fula-client/src/encryption.rs (load_forest). This constant is no longer consulted by any live call site.")]
pub const SHARDED_MIGRATION_THRESHOLD: usize = 5_000;

/// Per-shard entry limit before resharding (doubling shard count)
pub const RESHARD_THRESHOLD: usize = 10_000;

/// Maximum number of shards
pub const MAX_SHARDS: usize = 256;

/// Domain for shard key derivation
const SHARD_KEY_DOMAIN: &str = "fula/private-forest/shard/v1";

/// Domain for shard assignment
const SHARD_ASSIGN_DOMAIN: &str = "fula/private-forest/shard-assign/v1";

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

/// Determine which shard a file path belongs to (legacy v3/v5 routing)
///
/// Uses DEK + shard_salt in the hash so an observer who knows a filename
/// cannot guess which shard it's in without the secret key. Hashes the full
/// path, so every file may land in a different shard regardless of directory.
pub fn shard_for_path(path: &str, dek: &DekKey, shard_salt: &[u8], num_shards: usize) -> usize {
    let mut hasher = blake3::Hasher::new_derive_key(SHARD_ASSIGN_DOMAIN);
    hasher.update(dek.as_bytes());
    hasher.update(path.as_bytes());
    hasher.update(shard_salt);
    let hash = hasher.finalize();
    (hash.as_bytes()[0] as usize) % num_shards
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
/// Uses two bytes of hash output so that scaling beyond 256 shards is clean
/// once callers are ready to lift that cap.
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

/// Version-aware shard routing.
///
/// Dispatches to [`shard_for_path`] (legacy v3/v5 full-path hash) or
/// [`shard_for_path_v6`] (v6 parent-directory hash) based on the manifest
/// version. Callers that already have a `ShardedPrivateForest` should use
/// `ShardedPrivateForest::shard_for`, which wraps this helper.
pub fn shard_for_path_versioned(
    manifest_version: u8,
    path: &str,
    dek: &DekKey,
    shard_salt: &[u8],
    num_shards: usize,
) -> usize {
    match manifest_version {
        6 => shard_for_path_v6(path, dek, shard_salt, num_shards),
        _ => shard_for_path(path, dek, shard_salt, num_shards),
    }
}

/// Compute the initial shard count for migration based on file count
///
/// `max(16, next_power_of_two(file_count / 5000))`
pub fn compute_initial_shard_count(file_count: usize) -> usize {
    let target = file_count / 5000;
    let pow2 = target.next_power_of_two().max(1);
    pow2.max(16).min(MAX_SHARDS)
}

/// Events emitted during migration/reshard for app-level notifications
#[derive(Clone, Debug)]
pub enum ForestEvent {
    /// Auto-migration from monolithic to sharded has started
    MigrationStarted {
        bucket: String,
        file_count: usize,
        num_shards: usize,
    },
    /// Migration completed
    MigrationCompleted {
        bucket: String,
        duration_ms: u64,
    },
    /// Resharding (doubling shard count) has started
    ReshardStarted {
        bucket: String,
        old_shards: usize,
        new_shards: usize,
    },
    /// Resharding completed
    ReshardCompleted {
        bucket: String,
        duration_ms: u64,
    },
}

/// Shard manifest — stored encrypted at the index_key (version 3, 5, or 6)
///
/// Constant-size-ish regardless of file count (grows only with num_shards).
/// All variable-size per-file data lives in individual shards.
///
/// For v5+ (AAD-bound) manifests, `shard_sequences` carries the expected
/// sequence for each shard, vouched for by the manifest's own AEAD tag.
/// This closes the cold-start shard-replay hole: on first load, the client
/// learns each shard's expected sequence from the manifest and rejects any
/// shard whose embedded sequence does not match.
///
/// Version semantics:
/// - v3: legacy, no AAD. Routing hashes full path.
/// - v5: AAD-bound manifest + shards. Routing hashes full path (legacy).
/// - v6: AAD-bound manifest + shards. Routing hashes parent directory,
///   giving directory-locality for upsert/list_directory.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShardManifest {
    /// Version of the manifest format (3 = legacy, 5 = AAD-bound, 6 = directory-aware)
    pub version: u8,
    /// Format identifier
    pub format: String,
    /// Number of shards (power of 2, default 16, can grow)
    pub num_shards: usize,
    /// Random salt for shard key derivation and shard assignment (32 bytes)
    #[serde(with = "hex_serde")]
    pub shard_salt: Vec<u8>,
    /// Root directory path (usually "/")
    pub root: String,
    /// Creation timestamp (Unix seconds)
    pub created_at: i64,
    /// Last modified timestamp (Unix seconds)
    pub modified_at: i64,
    /// Expected sequence per shard (v5+).
    ///
    /// Length equals `num_shards` after a v5 write. Absent (empty) on v3
    /// manifests for backward compatibility; len-mismatch is tolerated as
    /// "no per-shard replay check available" for legacy data.
    #[serde(default)]
    pub shard_sequences: Vec<u64>,
}

impl ShardManifest {
    /// Create a new shard manifest (legacy v3 shape, zeroed shard_sequences).
    ///
    /// Callers flushing new data should bump to v5 via [`ShardManifest::into_v5`]
    /// once they know the expected sequences for each shard.
    pub fn new(num_shards: usize) -> Self {
        use rand::RngCore;
        let num_shards = num_shards.next_power_of_two().max(16).min(MAX_SHARDS);
        let mut shard_salt = vec![0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut shard_salt);

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        Self {
            version: 3,
            format: "sharded-v3".to_string(),
            num_shards,
            shard_salt,
            root: "/".to_string(),
            created_at: now,
            modified_at: now,
            shard_sequences: Vec::new(),
        }
    }

    /// Update the modified timestamp
    pub fn touch(&mut self) {
        self.modified_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
    }

    /// Promote a manifest to v5 shape (AAD-bound, legacy routing) with the given per-shard sequences.
    ///
    /// `sequences.len()` must equal `self.num_shards`. Caller is responsible for
    /// incrementing each sequence on every shard write.
    pub fn into_v5(mut self, sequences: Vec<u64>) -> Self {
        self.version = 5;
        self.format = "sharded-v5".to_string();
        self.shard_sequences = sequences;
        self
    }

    /// Promote a manifest to v6 shape (AAD-bound, directory-aware routing)
    /// with the given per-shard sequences.
    ///
    /// `sequences.len()` must equal `self.num_shards`. Callers MUST ensure the
    /// shard contents are already distributed using v6 routing (either freshly
    /// built, or redistributed via `ShardedPrivateForest::reshard_to_v6`)
    /// before flipping the manifest version — otherwise reads after this
    /// commit will route to the wrong shard.
    pub fn into_v6(mut self, sequences: Vec<u64>) -> Self {
        self.version = 6;
        self.format = "sharded-v6".to_string();
        self.shard_sequences = sequences;
        self
    }
}

/// A single shard containing file entries
///
/// Encrypted separately and stored as its own S3 object.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ForestShard {
    /// Which shard index this is
    pub shard_index: usize,
    /// Files in this shard, keyed by original path
    pub files: HashMap<String, ForestFileEntry>,
}

impl ForestShard {
    /// Create a new empty shard
    pub fn new(shard_index: usize) -> Self {
        Self {
            shard_index,
            files: HashMap::new(),
        }
    }

    /// Number of files in this shard
    pub fn len(&self) -> usize {
        self.files.len()
    }

    /// Whether this shard is empty
    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }
}

/// Compute the AAD for a v5 shard manifest.
pub fn manifest_v5_aad(bucket: &str, sequence: u64) -> Vec<u8> {
    format!("fula:manifest:v5:{}:{}", bucket, sequence).into_bytes()
}

/// Compute the AAD for a v6 shard manifest (directory-aware routing).
///
/// Distinct prefix from v5 so a v5 ciphertext cannot be served in place of
/// a v6 one (routing-version downgrade is detected at AEAD verification
/// time rather than relying on the plaintext version field).
pub fn manifest_v6_aad(bucket: &str, sequence: u64) -> Vec<u8> {
    format!("fula:manifest:v6:{}:{}", bucket, sequence).into_bytes()
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
/// The per-bucket salt (from [`ShardManifestV7::shard_salt`]) prevents an
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
}

impl ShardV7 {
    /// Fresh, empty shard — no HAMT nodes written, sequence 0.
    pub fn new() -> Self {
        Self {
            root: None,
            seq: 0,
            etag: None,
            entry_count: 0,
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

/// v7 sharded-HAMT manifest.
///
/// Shape mirrors [`ShardManifest`] but replaces the per-shard flat HashMap
/// with a HAMT root reference. The manifest stays small (O(num_shards))
/// regardless of total entry count.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShardManifestV7 {
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
    /// Per-shard metadata. `shards.len() == num_shards` after construction.
    pub shards: Vec<ShardV7>,
}

impl ShardManifestV7 {
    /// Fresh v7 manifest with `num_shards` empty shards.
    ///
    /// `num_shards` is rounded up to the next power of two and clamped to
    /// `[16, MAX_SHARDS]`, matching [`ShardManifest::new`].
    pub fn new(num_shards: usize) -> Self {
        use rand::RngCore;
        let num_shards = num_shards.next_power_of_two().max(16).min(MAX_SHARDS);
        let mut shard_salt = vec![0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut shard_salt);

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        Self {
            version: 7,
            format: "sharded-hamt-v7".to_string(),
            num_shards,
            shard_salt,
            root: "/".to_string(),
            created_at: now,
            modified_at: now,
            shards: (0..num_shards).map(|_| ShardV7::new()).collect(),
        }
    }

    /// Refresh the modified timestamp.
    pub fn touch(&mut self) {
        self.modified_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
    }

    /// Total entries across all shards (O(num_shards), not O(N)).
    pub fn entry_count(&self) -> u64 {
        self.shards.iter().map(|s| s.entry_count as u64).sum()
    }
}

/// Compute the AAD for a v7 shard manifest wrapper.
///
/// Distinct prefix from v5/v6 so a ciphertext of another format cannot be
/// accepted in a v7 slot — format-downgrade is detected at AEAD verification
/// rather than relying on the plaintext version field.
pub fn manifest_v7_aad(bucket: &str, sequence: u64) -> Vec<u8> {
    format!("fula:manifest:v7:{}:{}", bucket, sequence).into_bytes()
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
/// lives at the manifest layer (`manifest.shards[i].seq` + ETag), and
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

/// Encrypted shard manifest (what gets stored at the index_key)
///
/// Version semantics:
/// - v3: legacy sharded manifest, no AAD, no replay protection.
/// - v5: sharded manifest with AAD bound to `fula:manifest:v5:<bucket>:<sequence>`
///   and an outer `sequence` counter. Legacy full-path shard routing.
///   Plaintext carries `shard_sequences` to vouch for per-shard replay protection.
/// - v6: same wrapper shape as v5 but with distinct AAD prefix and directory-
///   aware shard routing (see [`shard_for_path_v6`]). AAD prefix differs from v5
///   so a v5 ciphertext cannot be accepted in a v6 slot.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedShardManifest {
    /// Version of the encryption format (3 = legacy, 5 = AAD-bound, 6 = AAD + v6 routing)
    pub version: u8,
    /// Encrypted manifest data
    #[serde(with = "base64_serde")]
    pub ciphertext: Vec<u8>,
    /// Nonce used for encryption
    #[serde(with = "base64_serde")]
    pub nonce: Vec<u8>,
    /// Monotonic sequence counter (v5+). Bound into AAD to prevent replay.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub sequence: Option<u64>,
}

impl EncryptedShardManifest {
    /// Encrypt a shard manifest with a DEK (legacy v3, no AAD).
    pub fn encrypt(manifest: &ShardManifest, dek: &DekKey) -> Result<Self> {
        let json = serde_json::to_vec(manifest)
            .map_err(|e| CryptoError::Serialization(e.to_string()))?;

        let nonce = Nonce::generate();
        let aead = Aead::new_default(dek);
        let ciphertext = aead.encrypt(&nonce, &json)?;

        Ok(Self {
            version: 3,
            ciphertext,
            nonce: nonce.as_bytes().to_vec(),
            sequence: None,
        })
    }

    /// Encrypt a shard manifest with a DEK and AAD binding (v5).
    pub fn encrypt_v5(
        manifest: &ShardManifest,
        dek: &DekKey,
        bucket: &str,
        sequence: u64,
    ) -> Result<Self> {
        let json = serde_json::to_vec(manifest)
            .map_err(|e| CryptoError::Serialization(e.to_string()))?;

        let nonce = Nonce::generate();
        let aead = Aead::new_default(dek);
        let aad = manifest_v5_aad(bucket, sequence);
        let ciphertext = aead.encrypt_with_aad(&nonce, &json, &aad)?;

        Ok(Self {
            version: 5,
            ciphertext,
            nonce: nonce.as_bytes().to_vec(),
            sequence: Some(sequence),
        })
    }

    /// Decrypt a shard manifest with a DEK (legacy v3, no AAD).
    pub fn decrypt(&self, dek: &DekKey) -> Result<ShardManifest> {
        let nonce = Nonce::from_bytes(&self.nonce)?;
        let aead = Aead::new_default(dek);
        let plaintext = aead.decrypt(&nonce, &self.ciphertext)?;

        serde_json::from_slice(&plaintext)
            .map_err(|e| CryptoError::Serialization(e.to_string()))
    }

    /// Decrypt a v5 shard manifest with a DEK, verifying bucket binding via AAD.
    ///
    /// Returns the manifest plus the bound sequence. Callers should compare
    /// against their cached last-seen sequence to detect replay.
    pub fn decrypt_v5(&self, dek: &DekKey, bucket: &str) -> Result<(ShardManifest, u64)> {
        if self.version != 5 {
            return Err(CryptoError::Decryption(format!(
                "expected EncryptedShardManifest version 5, got {}",
                self.version
            )));
        }
        let sequence = self.sequence.ok_or_else(|| {
            CryptoError::Decryption("v5 EncryptedShardManifest missing sequence field".to_string())
        })?;
        let nonce = Nonce::from_bytes(&self.nonce)?;
        let aead = Aead::new_default(dek);
        let aad = manifest_v5_aad(bucket, sequence);
        let plaintext = aead.decrypt_with_aad(&nonce, &self.ciphertext, &aad)?;
        let manifest: ShardManifest = serde_json::from_slice(&plaintext)
            .map_err(|e| CryptoError::Serialization(e.to_string()))?;
        Ok((manifest, sequence))
    }

    /// Encrypt a shard manifest with a DEK and AAD binding (v6, directory-aware).
    ///
    /// Same wrapper shape as v5 but with a distinct AAD prefix
    /// (`fula:manifest:v6:<bucket>:<sequence>`) so that a v5 ciphertext cannot
    /// be accepted in place of a v6 one.
    pub fn encrypt_v6(
        manifest: &ShardManifest,
        dek: &DekKey,
        bucket: &str,
        sequence: u64,
    ) -> Result<Self> {
        let json = serde_json::to_vec(manifest)
            .map_err(|e| CryptoError::Serialization(e.to_string()))?;

        let nonce = Nonce::generate();
        let aead = Aead::new_default(dek);
        let aad = manifest_v6_aad(bucket, sequence);
        let ciphertext = aead.encrypt_with_aad(&nonce, &json, &aad)?;

        Ok(Self {
            version: 6,
            ciphertext,
            nonce: nonce.as_bytes().to_vec(),
            sequence: Some(sequence),
        })
    }

    /// Decrypt a v6 shard manifest, verifying bucket + sequence via AAD.
    ///
    /// Rejects any non-v6 wrapper so that a downgraded v3/v5 ciphertext cannot
    /// pass the version check silently.
    pub fn decrypt_v6(&self, dek: &DekKey, bucket: &str) -> Result<(ShardManifest, u64)> {
        if self.version != 6 {
            return Err(CryptoError::Decryption(format!(
                "expected EncryptedShardManifest version 6, got {}",
                self.version
            )));
        }
        let sequence = self.sequence.ok_or_else(|| {
            CryptoError::Decryption("v6 EncryptedShardManifest missing sequence field".to_string())
        })?;
        let nonce = Nonce::from_bytes(&self.nonce)?;
        let aead = Aead::new_default(dek);
        let aad = manifest_v6_aad(bucket, sequence);
        let plaintext = aead.decrypt_with_aad(&nonce, &self.ciphertext, &aad)?;
        let manifest: ShardManifest = serde_json::from_slice(&plaintext)
            .map_err(|e| CryptoError::Serialization(e.to_string()))?;
        Ok((manifest, sequence))
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

/// Encrypted v7 sharded-HAMT manifest (what gets stored at the index_key).
///
/// Parallel to [`EncryptedShardManifest`] but carries a [`ShardManifestV7`]
/// plaintext. Version 7 is always AAD-bound; there is no legacy variant.
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
    /// Encrypt a v7 manifest with a DEK and AAD binding.
    pub fn encrypt_v7(
        manifest: &ShardManifestV7,
        dek: &DekKey,
        bucket: &str,
        sequence: u64,
    ) -> Result<Self> {
        let json = serde_json::to_vec(manifest)
            .map_err(|e| CryptoError::Serialization(e.to_string()))?;

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

    /// Decrypt a v7 manifest, verifying bucket + sequence via AAD.
    ///
    /// Rejects any non-v7 wrapper so that a downgraded v3/v5/v6 ciphertext
    /// cannot pass the version check silently.
    pub fn decrypt_v7(&self, dek: &DekKey, bucket: &str) -> Result<(ShardManifestV7, u64)> {
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
        let manifest: ShardManifestV7 = serde_json::from_slice(&plaintext)
            .map_err(|e| CryptoError::Serialization(e.to_string()))?;
        Ok((manifest, self.sequence))
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

/// Compute the AAD for a v2 forest shard.
pub fn shard_v2_aad(bucket: &str, shard_index: usize, sequence: u64) -> Vec<u8> {
    format!("fula:shard:v2:{}:{}:{}", bucket, shard_index, sequence).into_bytes()
}

/// Encrypted forest shard (what gets stored per-shard in S3)
///
/// Version semantics:
/// - v1: legacy shard, no AAD, no replay protection.
/// - v2: AAD bound to `fula:shard:v2:<bucket>:<shard_index>:<sequence>`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedForestShard {
    /// Version of the encryption format
    pub version: u8,
    /// Encrypted shard data
    #[serde(with = "base64_serde")]
    pub ciphertext: Vec<u8>,
    /// Nonce used for encryption
    #[serde(with = "base64_serde")]
    pub nonce: Vec<u8>,
    /// Monotonic sequence counter (v2+). Bound into AAD to prevent replay.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub sequence: Option<u64>,
}

impl EncryptedForestShard {
    /// Encrypt a forest shard with a DEK (legacy v1, no AAD).
    pub fn encrypt(shard: &ForestShard, dek: &DekKey) -> Result<Self> {
        let json = serde_json::to_vec(shard)
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

    /// Encrypt a forest shard with a DEK and AAD binding (v2).
    ///
    /// Binds to bucket + shard_index + sequence. The shard index is included
    /// so that a malicious server cannot serve shard `j`'s ciphertext in
    /// response to a request for shard `i`.
    pub fn encrypt_v2(
        shard: &ForestShard,
        dek: &DekKey,
        bucket: &str,
        sequence: u64,
    ) -> Result<Self> {
        let json = serde_json::to_vec(shard)
            .map_err(|e| CryptoError::Serialization(e.to_string()))?;

        let nonce = Nonce::generate();
        let aead = Aead::new_default(dek);
        let aad = shard_v2_aad(bucket, shard.shard_index, sequence);
        let ciphertext = aead.encrypt_with_aad(&nonce, &json, &aad)?;

        Ok(Self {
            version: 2,
            ciphertext,
            nonce: nonce.as_bytes().to_vec(),
            sequence: Some(sequence),
        })
    }

    /// Decrypt a forest shard with a DEK (legacy v1, no AAD).
    pub fn decrypt(&self, dek: &DekKey) -> Result<ForestShard> {
        let nonce = Nonce::from_bytes(&self.nonce)?;
        let aead = Aead::new_default(dek);
        let plaintext = aead.decrypt(&nonce, &self.ciphertext)?;

        serde_json::from_slice(&plaintext)
            .map_err(|e| CryptoError::Serialization(e.to_string()))
    }

    /// Decrypt a v2 forest shard, verifying bucket + shard_index + sequence via AAD.
    ///
    /// Caller must pass the `shard_index` it requested. Returns the shard and
    /// the bound sequence. Callers should compare the sequence against the
    /// manifest's `shard_sequences[shard_index]` entry (populated by the AAD-
    /// protected v5 manifest) to detect shard-level replay.
    pub fn decrypt_v2(
        &self,
        dek: &DekKey,
        bucket: &str,
        shard_index: usize,
    ) -> Result<(ForestShard, u64)> {
        if self.version != 2 {
            return Err(CryptoError::Decryption(format!(
                "expected EncryptedForestShard version 2, got {}",
                self.version
            )));
        }
        let sequence = self.sequence.ok_or_else(|| {
            CryptoError::Decryption("v2 EncryptedForestShard missing sequence field".to_string())
        })?;
        let nonce = Nonce::from_bytes(&self.nonce)?;
        let aead = Aead::new_default(dek);
        let aad = shard_v2_aad(bucket, shard_index, sequence);
        let plaintext = aead.decrypt_with_aad(&nonce, &self.ciphertext, &aad)?;
        let shard: ForestShard = serde_json::from_slice(&plaintext)
            .map_err(|e| CryptoError::Serialization(e.to_string()))?;
        Ok((shard, sequence))
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

/// Result of detecting the format at the index_key
pub enum ForestOrManifest {
    /// Monolithic forest (version 1, 2, or 4).
    Monolithic(EncryptedForest),
    /// Sharded flat-HashMap manifest (version 3, 5, or 6).
    Manifest(EncryptedShardManifest),
    /// Sharded-HAMT manifest (version 7).
    ManifestV7(EncryptedShardManifestV7),
}

/// Detect whether bytes at the index_key are a monolithic forest or shard manifest
///
/// Reads the outer `version` field to determine the format without decrypting.
///
/// Version mapping:
/// - 1, 2, 4    → monolithic `EncryptedForest` (v4 carries AAD+sequence).
/// - 3, 5, 6    → sharded `EncryptedShardManifest`. v5 carries AAD+sequence
///                with legacy full-path routing; v6 adds directory-aware
///                routing with a distinct AAD prefix.
/// - 7          → sharded-HAMT `EncryptedShardManifestV7`; each shard stores
///                a content-addressed HAMT root rather than a flat HashMap.
pub fn detect_forest_format(bytes: &[u8]) -> Result<ForestOrManifest> {
    let parsed: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|e| CryptoError::Serialization(e.to_string()))?;

    match parsed.get("version").and_then(|v| v.as_u64()) {
        Some(1) | Some(2) | Some(4) => {
            Ok(ForestOrManifest::Monolithic(EncryptedForest::from_bytes(bytes)?))
        }
        Some(3) | Some(5) | Some(6) => {
            Ok(ForestOrManifest::Manifest(EncryptedShardManifest::from_bytes(bytes)?))
        }
        Some(7) => {
            Ok(ForestOrManifest::ManifestV7(EncryptedShardManifestV7::from_bytes(bytes)?))
        }
        Some(v) => Err(CryptoError::Encryption(format!("unsupported forest version: {}", v))),
        None => Err(CryptoError::Serialization("missing version field in forest data".to_string())),
    }
}

/// Sharded private forest — the main in-memory representation for sharded mode
///
/// Wraps the manifest + lazily-loaded shards + dirty tracking.
/// This is NOT persisted — it's reconstructable from S3 at any time.
pub struct ShardedPrivateForest {
    /// The decrypted manifest
    pub manifest: ShardManifest,
    /// Loaded shards (None = not yet loaded from S3)
    pub shards: Vec<Option<ForestShard>>,
    /// Which shards have been modified locally but not yet flushed
    pub dirty_shards: std::collections::HashSet<usize>,
    /// Whether the manifest itself needs to be re-uploaded
    pub manifest_dirty: bool,
}

impl ShardedPrivateForest {
    /// Create a new empty sharded forest
    pub fn new(num_shards: usize) -> Self {
        let manifest = ShardManifest::new(num_shards);
        let shards = (0..manifest.num_shards).map(|i| Some(ForestShard::new(i))).collect();
        Self {
            manifest,
            shards,
            dirty_shards: std::collections::HashSet::new(),
            manifest_dirty: true,
        }
    }

    /// Create from a manifest (shards loaded lazily)
    pub fn from_manifest(manifest: ShardManifest) -> Self {
        let num_shards = manifest.num_shards;
        Self {
            manifest,
            shards: (0..num_shards).map(|_| None).collect(),
            dirty_shards: std::collections::HashSet::new(),
            manifest_dirty: false,
        }
    }

    /// Migrate a monolithic forest into a sharded forest (v6, directory-aware)
    ///
    /// New migrations always target v6 routing. The manifest is created in its
    /// base v3 shape (with `version = 3`, routing via full path) but is then
    /// flipped to v6 so that `shard_for` uses parent-directory routing for the
    /// distribution loop below. The client is still responsible for calling
    /// `into_v6(shard_sequences)` when it writes the manifest to disk.
    pub fn from_migration(forest: PrivateForest, dek: &DekKey, num_shards: usize) -> Self {
        let mut sharded = Self::new(num_shards);
        // Preserve timestamps
        sharded.manifest.created_at = forest.created_at;
        // Flip to v6 routing so the distribution loop and all subsequent
        // upserts land files by parent directory.
        sharded.manifest.version = 6;
        sharded.manifest.format = "sharded-v6".to_string();

        for entry in forest.list_all_files() {
            let shard_idx = shard_for_path_v6(
                &entry.path,
                dek,
                &sharded.manifest.shard_salt,
                sharded.manifest.num_shards,
            );
            if let Some(Some(shard)) = sharded.shards.get_mut(shard_idx) {
                shard.files.insert(entry.path.clone(), entry.clone());
            }
        }

        // Mark all shards dirty (they all need uploading after migration)
        for i in 0..sharded.manifest.num_shards {
            sharded.dirty_shards.insert(i);
        }
        sharded.manifest_dirty = true;

        sharded
    }

    /// Reshard in place from v3/v5 (legacy full-path routing) to v6 (parent-
    /// directory routing).
    ///
    /// Requires all shards to be loaded. Keeps `num_shards` unchanged,
    /// generates a fresh salt, and redistributes every file using v6 routing.
    /// Marks every shard dirty so the next flush rewrites the full index.
    pub fn reshard_to_v6(&mut self, dek: &DekKey) -> Result<()> {
        if !self.all_shards_loaded() {
            return Err(CryptoError::Encryption(
                "all shards must be loaded before resharding to v6".to_string(),
            ));
        }
        if self.manifest.version == 6 {
            return Ok(());
        }

        let all_files: Vec<ForestFileEntry> = self
            .shards
            .iter()
            .filter_map(|s| s.as_ref())
            .flat_map(|shard| shard.files.values().cloned())
            .collect();

        use rand::RngCore;
        let mut new_salt = vec![0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut new_salt);

        let num_shards = self.manifest.num_shards;
        let mut new_shards: Vec<Option<ForestShard>> =
            (0..num_shards).map(|i| Some(ForestShard::new(i))).collect();

        for entry in all_files {
            let shard_idx = shard_for_path_v6(&entry.path, dek, &new_salt, num_shards);
            if let Some(Some(shard)) = new_shards.get_mut(shard_idx) {
                shard.files.insert(entry.path.clone(), entry);
            }
        }

        self.manifest.version = 6;
        self.manifest.format = "sharded-v6".to_string();
        self.manifest.shard_salt = new_salt;
        self.manifest.touch();

        self.shards = new_shards;
        self.dirty_shards = (0..num_shards).collect();
        self.manifest_dirty = true;

        Ok(())
    }

    /// Get the number of shards
    pub fn num_shards(&self) -> usize {
        self.manifest.num_shards
    }

    /// Generate a storage key for a file using the forest's salt
    pub fn generate_key(&self, original_path: &str, dek: &DekKey) -> String {
        // Use the manifest's shard_salt as the forest salt for key generation
        generate_flat_key(original_path, dek, &self.manifest.shard_salt)
    }

    /// Determine which shard a path belongs to
    ///
    /// Dispatches on manifest version:
    /// - v6 uses [`shard_for_path_v6`] (parent-directory routing).
    /// - v3/v5 use [`shard_for_path`] (legacy full-path routing).
    pub fn shard_for(&self, path: &str, dek: &DekKey) -> usize {
        shard_for_path_versioned(
            self.manifest.version,
            path,
            dek,
            &self.manifest.shard_salt,
            self.manifest.num_shards,
        )
    }

    /// Returns true if this forest uses v6 directory-aware routing.
    ///
    /// v6 is the only routing where `list_directory(dir)` can be answered by
    /// loading a single shard — callers should check this before skipping
    /// `load_all_shards`.
    pub fn uses_v6_routing(&self) -> bool {
        self.manifest.version == 6
    }

    /// Shard containing all files directly under `dir` (v6 routing only).
    ///
    /// Returns `None` for non-v6 forests — legacy routing hashes each file's
    /// full path, so files in a single directory may land in any shard.
    /// Accepts `dir` with or without a trailing slash; normalizes internally.
    pub fn shard_for_dir(&self, dir: &str, dek: &DekKey) -> Option<usize> {
        if !self.uses_v6_routing() {
            return None;
        }
        let normalized = if dir.is_empty() || dir == "/" {
            "/".to_string()
        } else if dir.ends_with('/') {
            dir.to_string()
        } else {
            format!("{}/", dir)
        };
        Some(shard_for_path_v6(
            &normalized,
            dek,
            &self.manifest.shard_salt,
            self.manifest.num_shards,
        ))
    }

    /// Add or update a file entry
    ///
    /// Only marks the affected shard as dirty.
    pub fn upsert_file(&mut self, entry: ForestFileEntry, dek: &DekKey) {
        let shard_idx = self.shard_for(&entry.path, dek);

        // Ensure shard is initialized
        if self.shards[shard_idx].is_none() {
            self.shards[shard_idx] = Some(ForestShard::new(shard_idx));
        }

        if let Some(Some(shard)) = self.shards.get_mut(shard_idx) {
            shard.files.insert(entry.path.clone(), entry);
            self.dirty_shards.insert(shard_idx);
        }

        self.manifest.touch();
        self.manifest_dirty = true;
    }

    /// Remove a file from the forest
    pub fn remove_file(&mut self, path: &str, dek: &DekKey) -> Option<ForestFileEntry> {
        let shard_idx = self.shard_for(path, dek);

        let removed = if let Some(Some(shard)) = self.shards.get_mut(shard_idx) {
            let entry = shard.files.remove(path);
            if entry.is_some() {
                self.dirty_shards.insert(shard_idx);
                self.manifest.touch();
                self.manifest_dirty = true;
            }
            entry
        } else {
            None
        };

        removed
    }

    /// Get a file entry by path
    ///
    /// Returns None if the shard hasn't been loaded yet (caller must load it first).
    pub fn get_file(&self, path: &str, dek: &DekKey) -> Option<&ForestFileEntry> {
        let shard_idx = self.shard_for(path, dek);
        self.shards.get(shard_idx)
            .and_then(|s| s.as_ref())
            .and_then(|shard| shard.files.get(path))
    }

    /// Get storage key for a path
    pub fn get_storage_key(&self, path: &str, dek: &DekKey) -> Option<&str> {
        self.get_file(path, dek).map(|f| f.storage_key.as_str())
    }

    /// Set a loaded shard into the cache
    pub fn set_shard(&mut self, shard: ForestShard) {
        let idx = shard.shard_index;
        if idx < self.shards.len() {
            self.shards[idx] = Some(shard);
        }
    }

    /// Check if a specific shard is loaded
    pub fn is_shard_loaded(&self, index: usize) -> bool {
        self.shards.get(index).map(|s| s.is_some()).unwrap_or(false)
    }

    /// Check if all shards are loaded
    pub fn all_shards_loaded(&self) -> bool {
        self.shards.iter().all(|s| s.is_some())
    }

    /// List all files across all loaded shards
    ///
    /// Only includes files from shards that have been loaded.
    /// Call after `load_all_shards_parallel` to get complete results.
    pub fn list_all_files(&self) -> Vec<&ForestFileEntry> {
        self.shards.iter()
            .filter_map(|s| s.as_ref())
            .flat_map(|shard| shard.files.values())
            .collect()
    }

    /// Total file count across all loaded shards
    pub fn file_count(&self) -> usize {
        self.shards.iter()
            .filter_map(|s| s.as_ref())
            .map(|shard| shard.files.len())
            .sum()
    }

    /// Total size of all files across all loaded shards
    pub fn total_size(&self) -> u64 {
        self.list_all_files().iter().map(|f| f.size).sum()
    }

    /// Find file by storage key (reverse lookup, needs all shards loaded)
    pub fn find_by_storage_key(&self, storage_key: &str) -> Option<&ForestFileEntry> {
        self.list_all_files().into_iter().find(|f| f.storage_key == storage_key)
    }

    /// Reconstruct directory tree from file paths in loaded shards
    ///
    /// Directories are NOT stored — they're computed from file paths.
    pub fn reconstruct_directories(&self) -> HashMap<String, Vec<String>> {
        let mut dirs: HashMap<String, Vec<String>> = HashMap::new();
        // Ensure root exists
        dirs.insert("/".to_string(), Vec::new());

        for entry in self.list_all_files() {
            // Add file to its parent directory
            let parent = entry.parent_dir().to_string();
            let parent = if parent.is_empty() { "/".to_string() } else { parent };
            dirs.entry(parent.clone()).or_default().push(entry.path.clone());

            // Ensure all ancestor directories exist
            let mut current = parent;
            while current != "/" && !current.is_empty() {
                if let Some(idx) = current.rfind('/') {
                    let ancestor = if idx == 0 {
                        "/".to_string()
                    } else {
                        current[..idx].to_string()
                    };
                    dirs.entry(ancestor.clone()).or_default();
                    // Add current as subdir of ancestor (only the dir itself, not files)
                    let subdirs = dirs.entry(ancestor.clone()).or_default();
                    if !subdirs.contains(&current) {
                        subdirs.push(current.clone());
                    }
                    current = ancestor;
                } else {
                    break;
                }
            }
        }

        dirs
    }

    /// List files in a specific directory (non-recursive)
    ///
    /// Requires all shards to be loaded for complete results.
    pub fn list_directory(&self, dir_path: &str) -> Vec<&ForestFileEntry> {
        let normalized = if dir_path.is_empty() || dir_path == "/" {
            "/"
        } else {
            dir_path
        };

        self.list_all_files()
            .into_iter()
            .filter(|f| {
                let parent = f.parent_dir();
                let parent = if parent.is_empty() { "/" } else { parent };
                parent == normalized
            })
            .collect()
    }

    /// List subdirectories of a directory
    ///
    /// Requires all shards to be loaded.
    pub fn list_subdirs(&self, dir_path: &str) -> Vec<String> {
        let normalized = if dir_path.is_empty() || dir_path == "/" {
            "/".to_string()
        } else {
            dir_path.to_string()
        };

        let dirs = self.reconstruct_directories();
        dirs.get(&normalized)
            .map(|children| {
                children.iter()
                    .filter(|c| {
                        // Only include subdirectories, not files
                        // A subdir path starts with / and doesn't contain a file extension indicator
                        // Better heuristic: check if the child is a known directory key
                        dirs.contains_key(c.as_str())
                    })
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// List files recursively under a path
    pub fn list_recursive(&self, prefix: &str) -> Vec<&ForestFileEntry> {
        let normalized = if prefix.is_empty() {
            "/".to_string()
        } else if prefix.starts_with('/') {
            prefix.to_string()
        } else {
            format!("/{}", prefix)
        };

        self.list_all_files()
            .into_iter()
            .filter(|f| f.path.starts_with(&normalized))
            .collect()
    }

    /// Check if resharding is needed
    pub fn should_reshard(&self) -> bool {
        if self.manifest.num_shards >= MAX_SHARDS {
            return false;
        }
        self.shards.iter()
            .filter_map(|s| s.as_ref())
            .any(|shard| shard.files.len() > RESHARD_THRESHOLD)
    }

    /// Get the maximum shard size (number of entries)
    pub fn max_shard_size(&self) -> usize {
        self.shards.iter()
            .filter_map(|s| s.as_ref())
            .map(|shard| shard.files.len())
            .max()
            .unwrap_or(0)
    }

    /// Reshard to a new shard count (doubling)
    ///
    /// Generates a new shard_salt and redistributes all files.
    /// All shards must be loaded before calling this.
    /// After resharding, all shards are marked dirty.
    pub fn reshard(&mut self, dek: &DekKey) -> Result<()> {
        if !self.all_shards_loaded() {
            return Err(CryptoError::Encryption("all shards must be loaded before resharding".to_string()));
        }

        let new_num_shards = (self.manifest.num_shards * 2).min(MAX_SHARDS);
        if new_num_shards == self.manifest.num_shards {
            return Err(CryptoError::Encryption("already at maximum shard count".to_string()));
        }

        // Collect all files
        let all_files: Vec<ForestFileEntry> = self.shards.iter()
            .filter_map(|s| s.as_ref())
            .flat_map(|shard| shard.files.values().cloned())
            .collect();

        // Generate new salt
        use rand::RngCore;
        let mut new_salt = vec![0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut new_salt);

        // Create new shards
        let mut new_shards: Vec<Option<ForestShard>> = (0..new_num_shards)
            .map(|i| Some(ForestShard::new(i)))
            .collect();

        // Redistribute files using the manifest's current routing version.
        // v6 forests keep v6 routing on reshard; v3/v5 forests keep legacy
        // routing. Callers that want to upgrade routing should use
        // `reshard_to_v6` instead.
        let routing_version = self.manifest.version;
        for entry in all_files {
            let shard_idx = shard_for_path_versioned(
                routing_version,
                &entry.path,
                dek,
                &new_salt,
                new_num_shards,
            );
            if let Some(Some(shard)) = new_shards.get_mut(shard_idx) {
                shard.files.insert(entry.path.clone(), entry);
            }
        }

        // Update manifest
        self.manifest.num_shards = new_num_shards;
        self.manifest.shard_salt = new_salt;
        self.manifest.touch();

        // Replace shards and mark everything dirty
        self.shards = new_shards;
        self.dirty_shards = (0..new_num_shards).collect();
        self.manifest_dirty = true;

        Ok(())
    }

    /// Convert back to a monolithic PrivateForest (for rollback)
    ///
    /// All shards must be loaded.
    pub fn to_monolithic(&self) -> Result<PrivateForest> {
        if !self.all_shards_loaded() {
            return Err(CryptoError::Encryption("all shards must be loaded for monolithic conversion".to_string()));
        }

        let mut forest = PrivateForest::new();
        forest.salt = self.manifest.shard_salt.clone();
        forest.created_at = self.manifest.created_at;
        forest.modified_at = self.manifest.modified_at;

        for entry in self.list_all_files() {
            forest.upsert_file(entry.clone());
        }

        Ok(forest)
    }

    /// Extract a subtree for sharing (requires all shards loaded)
    pub fn extract_subtree(&self, prefix: &str, dek: &DekKey) -> ShardedPrivateForest {
        let files: Vec<ForestFileEntry> = self.list_recursive(prefix)
            .into_iter()
            .cloned()
            .collect();

        let mut subtree = ShardedPrivateForest::new(self.manifest.num_shards);
        subtree.manifest.shard_salt = self.manifest.shard_salt.clone();
        // Preserve the routing version so `upsert_file` uses the same routing
        // as the source forest — otherwise a v6 source would route its files
        // differently into a v3-default subtree.
        subtree.manifest.version = self.manifest.version;
        subtree.manifest.format = self.manifest.format.clone();

        for entry in files {
            subtree.upsert_file(entry, dek);
        }

        subtree
    }
}

#[cfg(test)]
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
    fn test_shard_assignment_determinism() {
        let dek = DekKey::generate();
        let salt = vec![7u8; 32];

        let idx1 = shard_for_path("/photos/beach.jpg", &dek, &salt, 16);
        let idx2 = shard_for_path("/photos/beach.jpg", &dek, &salt, 16);
        assert_eq!(idx1, idx2, "same path must map to same shard");

        // Different DEK = different shard (prevents observer from guessing)
        let dek2 = DekKey::generate();
        let idx3 = shard_for_path("/photos/beach.jpg", &dek2, &salt, 16);
        // Statistically very likely to differ (1/16 chance of collision)
        // We check 10 different paths to be sure
        let mut differ = false;
        for i in 0..10 {
            let path = format!("/test/file_{}.txt", i);
            let a = shard_for_path(&path, &dek, &salt, 16);
            let b = shard_for_path(&path, &dek2, &salt, 16);
            if a != b { differ = true; break; }
        }
        assert!(differ, "different DEKs must produce different shard assignments");
        let _ = idx3;
    }

    #[test]
    fn test_shard_assignment_uniformity() {
        let dek = DekKey::generate();
        let salt = vec![99u8; 32];
        let num_shards = 16;

        let mut counts = vec![0usize; num_shards];
        for i in 0..10_000 {
            let path = format!("/test/file_{}.dat", i);
            let idx = shard_for_path(&path, &dek, &salt, num_shards);
            assert!(idx < num_shards);
            counts[idx] += 1;
        }

        let avg = 10_000.0 / num_shards as f64;
        for (i, &count) in counts.iter().enumerate() {
            // No shard should have more than 2x average
            assert!(
                (count as f64) < avg * 2.0,
                "shard {} has {} entries (avg {}), distribution is too uneven",
                i, count, avg
            );
            // No shard should be empty
            assert!(count > 0, "shard {} is empty", i);
        }
    }

    #[test]
    fn test_compute_initial_shard_count() {
        assert_eq!(compute_initial_shard_count(0), 16);
        assert_eq!(compute_initial_shard_count(100), 16);
        assert_eq!(compute_initial_shard_count(5_000), 16);
        assert_eq!(compute_initial_shard_count(10_000), 16);
        assert_eq!(compute_initial_shard_count(50_000), 16);
        // Stays at 16 for most users (handles up to ~160K files per shard at threshold)
    }

    #[test]
    fn test_sharded_forest_new() {
        let forest = ShardedPrivateForest::new(16);
        assert_eq!(forest.manifest.num_shards, 16);
        assert_eq!(forest.manifest.version, 3);
        assert_eq!(forest.manifest.shard_salt.len(), 32);
        assert_eq!(forest.shards.len(), 16);
        assert_eq!(forest.file_count(), 0);
        // new() marks manifest dirty since it needs initial persistence
        assert!(forest.manifest_dirty);
    }

    #[test]
    fn test_manifest_encrypt_decrypt_roundtrip() {
        let dek = DekKey::generate();
        let forest = ShardedPrivateForest::new(16);

        let encrypted = EncryptedShardManifest::encrypt(&forest.manifest, &dek).unwrap();
        assert_eq!(encrypted.version, 3);
        assert!(!encrypted.ciphertext.is_empty());

        let decrypted = encrypted.decrypt(&dek).unwrap();
        assert_eq!(decrypted.num_shards, 16);
        assert_eq!(decrypted.shard_salt, forest.manifest.shard_salt);
    }

    #[test]
    fn test_shard_encrypt_decrypt_roundtrip() {
        let dek = DekKey::generate();
        let mut shard = ForestShard::new(5);
        shard.files.insert("/test.txt".to_string(), ForestFileEntry {
            path: "/test.txt".to_string(),
            storage_key: "QmTEST".to_string(),
            size: 1024,
            content_type: Some("text/plain".to_string()),
            created_at: 1000,
            modified_at: 2000,
            user_metadata: HashMap::new(),
            content_hash: None,
            encrypted: false,
            min_version: 0,
        });

        let encrypted = EncryptedForestShard::encrypt(&shard, &dek).unwrap();
        let decrypted = encrypted.decrypt(&dek).unwrap();

        assert_eq!(decrypted.shard_index, 5);
        assert_eq!(decrypted.files.len(), 1);
        assert_eq!(decrypted.files["/test.txt"].storage_key, "QmTEST");
    }

    #[test]
    fn test_manifest_wrong_key_fails() {
        let dek1 = DekKey::generate();
        let dek2 = DekKey::generate();
        let forest = ShardedPrivateForest::new(16);

        let encrypted = EncryptedShardManifest::encrypt(&forest.manifest, &dek1).unwrap();
        assert!(encrypted.decrypt(&dek2).is_err());
    }

    #[test]
    fn test_shard_wrong_key_fails() {
        let dek1 = DekKey::generate();
        let dek2 = DekKey::generate();
        let shard = ForestShard::new(0);

        let encrypted = EncryptedForestShard::encrypt(&shard, &dek1).unwrap();
        assert!(encrypted.decrypt(&dek2).is_err());
    }

    #[test]
    fn test_detect_forest_format_monolithic() {
        let dek = DekKey::generate();
        let forest = PrivateForest::new();
        let encrypted = EncryptedForest::encrypt(&forest, &dek).unwrap();
        let bytes = encrypted.to_bytes().unwrap();

        match detect_forest_format(&bytes).unwrap() {
            ForestOrManifest::Monolithic(_) => {} // expected
            ForestOrManifest::Manifest(_) => panic!("expected monolithic"),
            ForestOrManifest::ManifestV7(_) => panic!("expected monolithic"),
        }
    }

    #[test]
    fn test_detect_forest_format_sharded() {
        let dek = DekKey::generate();
        let forest = ShardedPrivateForest::new(16);
        let encrypted = EncryptedShardManifest::encrypt(&forest.manifest, &dek).unwrap();
        let bytes = encrypted.to_bytes().unwrap();

        match detect_forest_format(&bytes).unwrap() {
            ForestOrManifest::Manifest(_) => {} // expected
            ForestOrManifest::Monolithic(_) => panic!("expected manifest"),
            ForestOrManifest::ManifestV7(_) => panic!("expected manifest"),
        }
    }

    #[test]
    fn test_sharded_upsert_and_get() {
        let dek = DekKey::generate();
        let mut forest = ShardedPrivateForest::new(16);

        // Ensure all shards exist
        for i in 0..16 {
            forest.set_shard(ForestShard::new(i));
        }

        let entry = ForestFileEntry {
            path: "/docs/report.pdf".to_string(),
            storage_key: "QmREPORT".to_string(),
            size: 50_000,
            content_type: Some("application/pdf".to_string()),
            created_at: 1000,
            modified_at: 1000,
            user_metadata: HashMap::new(),
            content_hash: None,
            encrypted: false,
            min_version: 0,
        };

        forest.upsert_file(entry.clone(), &dek);
        assert_eq!(forest.file_count(), 1);
        assert_eq!(forest.get_storage_key("/docs/report.pdf", &dek), Some("QmREPORT"));
        assert!(!forest.dirty_shards.is_empty());
    }

    #[test]
    fn test_sharded_remove() {
        let dek = DekKey::generate();
        let mut forest = ShardedPrivateForest::new(16);
        for i in 0..16 { forest.set_shard(ForestShard::new(i)); }

        let entry = ForestFileEntry {
            path: "/temp.txt".to_string(),
            storage_key: "QmTEMP".to_string(),
            size: 100,
            content_type: None,
            created_at: 1000,
            modified_at: 1000,
            user_metadata: HashMap::new(),
            content_hash: None,
            encrypted: false,
            min_version: 0,
        };

        forest.upsert_file(entry, &dek);
        assert_eq!(forest.file_count(), 1);

        let removed = forest.remove_file("/temp.txt", &dek);
        assert!(removed.is_some());
        assert_eq!(forest.file_count(), 0);
        assert_eq!(forest.get_storage_key("/temp.txt", &dek), None);
    }

    #[test]
    fn test_migration_monolithic_to_sharded() {
        let dek = DekKey::generate();
        let mut forest = PrivateForest::new();

        // Add 100 files
        for i in 0..100 {
            forest.upsert_file(ForestFileEntry {
                path: format!("/files/doc_{}.txt", i),
                storage_key: format!("QmDOC{}", i),
                size: 1000 + i as u64,
                content_type: Some("text/plain".to_string()),
                created_at: 1000,
                modified_at: 2000,
                user_metadata: HashMap::new(),
                content_hash: None,
                encrypted: false,
                min_version: 0,
            });
        }

        let sharded = ShardedPrivateForest::from_migration(forest, &dek, 16);

        // All files accessible
        assert_eq!(sharded.file_count(), 100);
        for i in 0..100 {
            let path = format!("/files/doc_{}.txt", i);
            let key = sharded.get_storage_key(&path, &dek);
            assert_eq!(key, Some(format!("QmDOC{}", i).as_str()), "missing {}", path);
        }

        // All shards are dirty
        assert_eq!(sharded.dirty_shards.len(), 16);
        assert!(sharded.manifest_dirty);
    }

    #[test]
    fn test_migration_sharded_to_monolithic_rollback() {
        let dek = DekKey::generate();
        let mut forest = ShardedPrivateForest::new(16);
        for i in 0..16 { forest.set_shard(ForestShard::new(i)); }

        for i in 0..50 {
            forest.upsert_file(ForestFileEntry {
                path: format!("/data/item_{}.bin", i),
                storage_key: format!("QmITEM{}", i),
                size: 500,
                content_type: None,
                created_at: 1000,
                modified_at: 1000,
                user_metadata: HashMap::new(),
                content_hash: None,
                encrypted: false,
                min_version: 0,
            }, &dek);
        }

        let mono = forest.to_monolithic().unwrap();
        assert_eq!(mono.file_count(), 50);
        for i in 0..50 {
            assert!(mono.get_file(&format!("/data/item_{}.bin", i)).is_some());
        }
    }

    #[test]
    fn test_reshard_preserves_all_files() {
        let dek = DekKey::generate();
        let mut forest = ShardedPrivateForest::new(16);
        for i in 0..16 { forest.set_shard(ForestShard::new(i)); }

        // Add enough files
        for i in 0..200 {
            forest.upsert_file(ForestFileEntry {
                path: format!("/data/file_{}.dat", i),
                storage_key: format!("QmFILE{}", i),
                size: 1024,
                content_type: None,
                created_at: 1000,
                modified_at: 1000,
                user_metadata: HashMap::new(),
                content_hash: None,
                encrypted: false,
                min_version: 0,
            }, &dek);
        }

        let old_count = forest.file_count();
        forest.reshard(&dek).unwrap();

        // All files still accessible
        assert_eq!(forest.file_count(), old_count);
        assert_eq!(forest.manifest.num_shards, 32); // doubled
        for i in 0..200 {
            let path = format!("/data/file_{}.dat", i);
            assert!(forest.get_storage_key(&path, &dek).is_some(), "missing {}", path);
        }

        // All shards marked dirty
        assert_eq!(forest.dirty_shards.len(), 32);
        assert!(forest.manifest_dirty);
    }

    #[test]
    fn test_reshard_changes_shard_keys() {
        let dek = DekKey::generate();
        let forest = ShardedPrivateForest::new(16);

        let old_key = derive_shard_key(&dek, "bucket", &forest.manifest.shard_salt, 0);

        let mut resharded = ShardedPrivateForest::new(16);
        for i in 0..16 { resharded.set_shard(ForestShard::new(i)); }
        resharded.reshard(&dek).unwrap();

        let new_key = derive_shard_key(&dek, "bucket", &resharded.manifest.shard_salt, 0);
        assert_ne!(old_key, new_key, "new salt must produce different shard keys");
    }

    #[test]
    fn test_should_reshard_triggers_correctly() {
        let dek = DekKey::generate();
        let mut forest = ShardedPrivateForest::new(16);
        for i in 0..16 { forest.set_shard(ForestShard::new(i)); }

        assert!(!forest.should_reshard());

        // Fill one shard past the threshold by inserting files that all hash to shard 0
        // We use brute force: insert many files and count per-shard
        for i in 0..200_000 {
            let path = format!("/bulk/f_{}", i);
            let shard_idx = forest.shard_for(&path, &dek);
            if shard_idx == 0 {
                forest.upsert_file(ForestFileEntry {
                    path,
                    storage_key: format!("Qm{}", i),
                    size: 100,
                    content_type: None,
                    created_at: 1000,
                    modified_at: 1000,
                    user_metadata: HashMap::new(),
                    content_hash: None,
                    encrypted: false,
                    min_version: 0,
                }, &dek);
                if forest.max_shard_size() > RESHARD_THRESHOLD {
                    break;
                }
            }
        }

        assert!(forest.should_reshard(), "should trigger reshard after exceeding threshold");
    }

    #[test]
    fn test_shard_keys_are_opaque() {
        let dek = DekKey::generate();
        let salt = vec![1u8; 32];

        for i in 0..16 {
            let key = derive_shard_key(&dek, "my-bucket", &salt, i);
            assert!(key.starts_with("Qm"), "shard key must look like a CID");
            assert!(!key.contains("shard"), "key must not contain 'shard'");
            assert!(!key.contains("bucket"), "key must not contain bucket name");
        }
    }

    #[test]
    fn test_sharded_list_all_files() {
        let dek = DekKey::generate();
        let mut forest = ShardedPrivateForest::new(16);
        for i in 0..16 { forest.set_shard(ForestShard::new(i)); }

        for i in 0..30 {
            forest.upsert_file(ForestFileEntry {
                path: format!("/dir/file_{}.txt", i),
                storage_key: format!("Qm{}", i),
                size: 100,
                content_type: None,
                created_at: 1000,
                modified_at: 1000,
                user_metadata: HashMap::new(),
                content_hash: None,
                encrypted: false,
                min_version: 0,
            }, &dek);
        }

        let all = forest.list_all_files();
        assert_eq!(all.len(), 30);
    }

    #[test]
    fn test_sharded_list_recursive() {
        let dek = DekKey::generate();
        let mut forest = ShardedPrivateForest::new(16);
        for i in 0..16 { forest.set_shard(ForestShard::new(i)); }

        // Add files in different directories
        for i in 0..10 {
            forest.upsert_file(ForestFileEntry {
                path: format!("/photos/trip/img_{}.jpg", i),
                storage_key: format!("QmPHOTO{}", i),
                size: 5000,
                content_type: Some("image/jpeg".to_string()),
                created_at: 1000,
                modified_at: 1000,
                user_metadata: HashMap::new(),
                content_hash: None,
                encrypted: false,
                min_version: 0,
            }, &dek);
        }
        for i in 0..5 {
            forest.upsert_file(ForestFileEntry {
                path: format!("/docs/doc_{}.pdf", i),
                storage_key: format!("QmDOC{}", i),
                size: 2000,
                content_type: Some("application/pdf".to_string()),
                created_at: 1000,
                modified_at: 1000,
                user_metadata: HashMap::new(),
                content_hash: None,
                encrypted: false,
                min_version: 0,
            }, &dek);
        }

        let photos = forest.list_recursive("/photos");
        assert_eq!(photos.len(), 10);

        let docs = forest.list_recursive("/docs");
        assert_eq!(docs.len(), 5);

        let all = forest.list_recursive("/");
        assert_eq!(all.len(), 15);
    }

    #[test]
    fn test_sharded_generate_key() {
        let dek = DekKey::generate();
        let forest = ShardedPrivateForest::new(16);

        let key1 = forest.generate_key("/test.txt", &dek);
        let key2 = forest.generate_key("/test.txt", &dek);
        assert_eq!(key1, key2, "must be deterministic");
        assert!(key1.starts_with("Qm"), "must look like CID");

        let key3 = forest.generate_key("/other.txt", &dek);
        assert_ne!(key1, key3, "different paths must differ");
    }

    #[test]
    fn test_max_shards_limit() {
        let dek = DekKey::generate();
        let mut forest = ShardedPrivateForest::new(MAX_SHARDS);
        for i in 0..MAX_SHARDS { forest.set_shard(ForestShard::new(i)); }

        assert!(!forest.should_reshard(), "cannot reshard at max");
        assert!(forest.reshard(&dek).is_err(), "reshard must fail at max");
    }

    #[test]
    fn test_sharded_extract_subtree() {
        let dek = DekKey::generate();
        let mut forest = ShardedPrivateForest::new(16);
        for i in 0..16 { forest.set_shard(ForestShard::new(i)); }

        for i in 0..10 {
            forest.upsert_file(ForestFileEntry {
                path: format!("/shared/doc_{}.txt", i),
                storage_key: format!("QmSHARE{}", i),
                size: 500,
                content_type: None,
                created_at: 1000,
                modified_at: 1000,
                user_metadata: HashMap::new(),
                content_hash: None,
                encrypted: false,
                min_version: 0,
            }, &dek);
        }
        for i in 0..5 {
            forest.upsert_file(ForestFileEntry {
                path: format!("/private/secret_{}.txt", i),
                storage_key: format!("QmPRIV{}", i),
                size: 200,
                content_type: None,
                created_at: 1000,
                modified_at: 1000,
                user_metadata: HashMap::new(),
                content_hash: None,
                encrypted: false,
                min_version: 0,
            }, &dek);
        }

        let subtree = forest.extract_subtree("/shared", &dek);
        assert_eq!(subtree.file_count(), 10);
        // Private files not included
        let all = subtree.list_all_files();
        assert!(all.iter().all(|f| f.path.starts_with("/shared")));
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
    fn test_manifest_v5_roundtrip_and_shard_sequences() {
        let dek = DekKey::generate();
        let manifest = ShardManifest::new(16).into_v5(vec![0u64; 16]);
        let enc = EncryptedShardManifest::encrypt_v5(&manifest, &dek, "b", 3).unwrap();
        assert_eq!(enc.version, 5);
        assert_eq!(enc.sequence, Some(3));

        let (dec, seq) = enc.decrypt_v5(&dek, "b").unwrap();
        assert_eq!(seq, 3);
        assert_eq!(dec.version, 5);
        assert_eq!(dec.shard_sequences.len(), 16);
    }

    #[test]
    fn test_manifest_v3_legacy_still_decrypts() {
        let dek = DekKey::generate();
        let manifest = ShardManifest::new(16);
        let enc = EncryptedShardManifest::encrypt(&manifest, &dek).unwrap();
        assert_eq!(enc.version, 3);
        let _ = enc.decrypt(&dek).unwrap();
    }

    #[test]
    fn test_shard_v2_roundtrip() {
        let dek = DekKey::generate();
        let mut shard = ForestShard::new(4);
        shard.files.insert(
            "/x".to_string(),
            ForestFileEntry {
                path: "/x".to_string(),
                storage_key: "QmX".to_string(),
                size: 1,
                content_type: None,
                created_at: 0,
                modified_at: 0,
                user_metadata: HashMap::new(),
                content_hash: None,
                encrypted: false,
                min_version: 0,
            },
        );
        let enc = EncryptedForestShard::encrypt_v2(&shard, &dek, "b", 11).unwrap();
        assert_eq!(enc.version, 2);
        assert_eq!(enc.sequence, Some(11));

        let (dec, seq) = enc.decrypt_v2(&dek, "b", 4).unwrap();
        assert_eq!(seq, 11);
        assert_eq!(dec.shard_index, 4);
        assert_eq!(dec.files.len(), 1);
    }

    #[test]
    fn test_shard_v2_wrong_shard_index_fails() {
        // If the server swaps shard j's ciphertext into a request for shard i,
        // the AAD check (which binds the index) must detect it.
        let dek = DekKey::generate();
        let shard = ForestShard::new(4);
        let enc = EncryptedForestShard::encrypt_v2(&shard, &dek, "b", 1).unwrap();
        let err = enc.decrypt_v2(&dek, "b", 5);
        assert!(err.is_err(), "decrypt with wrong shard_index must fail");
    }

    #[test]
    fn test_detect_forest_format_v4_and_v5() {
        let dek = DekKey::generate();

        // v4 monolithic
        let forest = PrivateForest::new();
        let ef4 = EncryptedForest::encrypt_v4(&forest, &dek, "b", 1).unwrap();
        let bytes4 = ef4.to_bytes().unwrap();
        match detect_forest_format(&bytes4).unwrap() {
            ForestOrManifest::Monolithic(_) => {}
            _ => panic!("expected Monolithic for v4"),
        }

        // v5 manifest
        let manifest = ShardManifest::new(16).into_v5(vec![0u64; 16]);
        let em5 = EncryptedShardManifest::encrypt_v5(&manifest, &dek, "b", 1).unwrap();
        let bytes5 = em5.to_bytes().unwrap();
        match detect_forest_format(&bytes5).unwrap() {
            ForestOrManifest::Manifest(_) => {}
            _ => panic!("expected Manifest for v5"),
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
    fn test_manifest_v6_roundtrip_and_bucket_binding() {
        let dek = DekKey::generate();
        let manifest = ShardManifest::new(16).into_v6(vec![1u64; 16]);
        assert_eq!(manifest.version, 6);
        assert_eq!(manifest.format, "sharded-v6");

        let em = EncryptedShardManifest::encrypt_v6(&manifest, &dek, "bucket", 1).unwrap();
        assert_eq!(em.version, 6);
        assert_eq!(em.sequence, Some(1));

        let (decoded, seq) = em.decrypt_v6(&dek, "bucket").unwrap();
        assert_eq!(decoded.version, 6);
        assert_eq!(decoded.format, "sharded-v6");
        assert_eq!(decoded.shard_sequences, vec![1u64; 16]);
        assert_eq!(seq, 1);

        // Wrong bucket binding fails.
        assert!(em.decrypt_v6(&dek, "other-bucket").is_err());
        // v5 decrypt refuses a v6 ciphertext (distinct AAD prefix).
        assert!(em.decrypt_v5(&dek, "bucket").is_err());
    }

    #[test]
    fn test_detect_forest_format_v6() {
        let dek = DekKey::generate();
        let manifest = ShardManifest::new(16).into_v6(vec![0u64; 16]);
        let em = EncryptedShardManifest::encrypt_v6(&manifest, &dek, "b", 1).unwrap();
        let bytes = em.to_bytes().unwrap();
        match detect_forest_format(&bytes).unwrap() {
            ForestOrManifest::Manifest(_) => {}
            _ => panic!("expected Manifest for v6"),
        }
    }

    #[test]
    fn test_shard_manifest_v7_shape() {
        let m = ShardManifestV7::new(16);
        assert_eq!(m.version, 7);
        assert_eq!(m.format, "sharded-hamt-v7");
        assert_eq!(m.num_shards, 16);
        assert_eq!(m.shard_salt.len(), 32);
        assert_eq!(m.shards.len(), 16);
        assert!(m.shards.iter().all(|s| s.is_empty()));
        assert_eq!(m.entry_count(), 0);

        // num_shards is rounded up to the next power of two and floored at 16.
        let big = ShardManifestV7::new(100);
        assert_eq!(big.num_shards, 128);
        assert_eq!(big.shards.len(), 128);
        let tiny = ShardManifestV7::new(1);
        assert_eq!(tiny.num_shards, 16);
    }

    #[test]
    fn test_shard_manifest_v7_encrypt_decrypt_roundtrip() {
        let dek = DekKey::generate();
        let mut manifest = ShardManifestV7::new(16);
        manifest.shards[3].root = Some([0xAB; V7_STORAGE_KEY_LEN]);
        manifest.shards[3].seq = 42;
        manifest.shards[3].entry_count = 17;
        manifest.shards[3].etag = Some("\"abc123\"".to_string());

        let em = EncryptedShardManifestV7::encrypt_v7(&manifest, &dek, "bucket-x", 1).unwrap();
        assert_eq!(em.version, 7);
        assert_eq!(em.sequence, 1);

        let (decoded, seq) = em.decrypt_v7(&dek, "bucket-x").unwrap();
        assert_eq!(seq, 1);
        assert_eq!(decoded.version, 7);
        assert_eq!(decoded.shards[3].root, Some([0xAB; V7_STORAGE_KEY_LEN]));
        assert_eq!(decoded.shards[3].seq, 42);
        assert_eq!(decoded.shards[3].entry_count, 17);
        assert_eq!(decoded.shards[3].etag.as_deref(), Some("\"abc123\""));

        // Wrong bucket binding fails (AAD mismatch).
        assert!(em.decrypt_v7(&dek, "different-bucket").is_err());

        // v6 ciphertext cannot be decrypted as v7 (and vice versa).
        let v6_manifest = ShardManifest::new(16).into_v6(vec![0u64; 16]);
        let em6 = EncryptedShardManifest::encrypt_v6(&v6_manifest, &dek, "bucket-x", 1).unwrap();
        let em6_bytes = em6.to_bytes().unwrap();
        let coerced_v7 = EncryptedShardManifestV7::from_bytes(&em6_bytes);
        if let Ok(parsed) = coerced_v7 {
            // If JSON parses, version must fail the version==7 check at decrypt time.
            assert!(parsed.decrypt_v7(&dek, "bucket-x").is_err());
        }
    }

    #[test]
    fn test_detect_forest_format_v7() {
        let dek = DekKey::generate();
        let manifest = ShardManifestV7::new(16);
        let em = EncryptedShardManifestV7::encrypt_v7(&manifest, &dek, "b", 1).unwrap();
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

    #[test]
    fn test_from_migration_targets_v6() {
        let dek = DekKey::generate();
        let mut mono = PrivateForest::new();
        for path in &["/a/x.txt", "/a/y.txt", "/b/x.txt"] {
            let meta = PrivateMetadata::new(*path, 10);
            let sk = mono.generate_key(path, &dek);
            mono.upsert_file(ForestFileEntry::from_metadata(&meta, sk));
        }

        let sharded = ShardedPrivateForest::from_migration(mono, &dek, 16);
        assert_eq!(sharded.manifest.version, 6);
        assert_eq!(sharded.manifest.format, "sharded-v6");
        assert!(sharded.uses_v6_routing());

        // /a/x.txt and /a/y.txt must share a shard.
        let sx = sharded.shard_for("/a/x.txt", &dek);
        let sy = sharded.shard_for("/a/y.txt", &dek);
        assert_eq!(sx, sy);
    }

    #[test]
    fn test_reshard_to_v6_from_v3_preserves_files() {
        let dek = DekKey::generate();
        let mut sharded = ShardedPrivateForest::new(16);
        assert_eq!(sharded.manifest.version, 3);
        // Ensure all shards loaded for reshard.
        for i in 0..16 {
            sharded.set_shard(ForestShard::new(i));
        }

        for i in 0..20 {
            let path = format!("/dir{}/file{}.txt", i % 4, i);
            let meta = PrivateMetadata::new(&path, 10);
            let sk = sharded.generate_key(&path, &dek);
            sharded.upsert_file(ForestFileEntry::from_metadata(&meta, sk), &dek);
        }

        sharded.reshard_to_v6(&dek).unwrap();
        assert_eq!(sharded.manifest.version, 6);
        assert_eq!(sharded.file_count(), 20);

        // After reshard, same-directory files share a shard.
        let s1 = sharded.shard_for("/dir1/file1.txt", &dek);
        let s2 = sharded.shard_for("/dir1/file5.txt", &dek);
        assert_eq!(s1, s2);
    }

    #[test]
    fn test_shard_for_dir_only_for_v6() {
        let dek = DekKey::generate();
        let sharded_v3 = ShardedPrivateForest::new(16);
        assert!(sharded_v3.shard_for_dir("/a/b/", &dek).is_none());

        let mut sharded_v6 = ShardedPrivateForest::new(16);
        sharded_v6.manifest.version = 6;
        let s = sharded_v6.shard_for_dir("/a/b/", &dek).unwrap();
        // shard_for on any file under /a/b/ must match shard_for_dir.
        assert_eq!(s, sharded_v6.shard_for("/a/b/file.txt", &dek));
        // Trailing-slash normalization: both forms agree.
        assert_eq!(
            sharded_v6.shard_for_dir("/a/b", &dek),
            sharded_v6.shard_for_dir("/a/b/", &dek),
        );
    }
}
