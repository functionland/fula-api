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
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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
}

impl ForestFileEntry {
    /// Create from private metadata and storage key
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
}

/// The private forest - an encrypted index of the entire file system
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivateForest {
    /// Version of the forest format
    pub version: u8,
    /// Salt used for key derivation (random per forest)
    #[serde(with = "hex_serde")]
    pub salt: Vec<u8>,
    /// All files indexed by their original path
    pub files: HashMap<String, ForestFileEntry>,
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

impl PrivateForest {
    /// Create a new empty private forest
    pub fn new() -> Self {
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
        });

        Self {
            version: 1,
            salt,
            files: HashMap::new(),
            directories,
            root: "/".to_string(),
            created_at: now,
            modified_at: now,
        }
    }

    /// Generate a storage key for a new file
    pub fn generate_key(&self, original_path: &str, dek: &DekKey) -> String {
        generate_flat_key(original_path, dek, &self.salt)
    }

    /// Add or update a file in the forest
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
        
        // Update timestamps
        self.modified_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        
        self.files.insert(path, entry);
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
    pub fn remove_file(&mut self, path: &str) -> Option<ForestFileEntry> {
        if let Some(entry) = self.files.remove(path) {
            let parent = entry.parent_dir().to_string();
            if let Some(dir) = self.directories.get_mut(&parent) {
                dir.files.retain(|f| f != path);
            }
            Some(entry)
        } else {
            None
        }
    }

    /// Get a file by path
    pub fn get_file(&self, path: &str) -> Option<&ForestFileEntry> {
        self.files.get(path)
    }

    /// Get storage key for a path
    pub fn get_storage_key(&self, path: &str) -> Option<&str> {
        self.files.get(path).map(|f| f.storage_key.as_str())
    }

    /// List all files
    pub fn list_all_files(&self) -> impl Iterator<Item = &ForestFileEntry> {
        self.files.values()
    }

    /// List files in a directory (non-recursive)
    pub fn list_directory(&self, dir_path: &str) -> Vec<&ForestFileEntry> {
        let normalized = if dir_path.is_empty() || dir_path == "/" {
            "/".to_string()
        } else if dir_path.starts_with('/') {
            dir_path.to_string()
        } else {
            format!("/{}", dir_path)
        };

        if let Some(dir) = self.directories.get(&normalized) {
            dir.files.iter()
                .filter_map(|path| self.files.get(path))
                .collect()
        } else {
            Vec::new()
        }
    }

    /// List subdirectories of a directory
    pub fn list_subdirs(&self, dir_path: &str) -> Vec<&str> {
        let normalized = if dir_path.is_empty() || dir_path == "/" {
            "/".to_string()
        } else if dir_path.starts_with('/') {
            dir_path.to_string()
        } else {
            format!("/{}", dir_path)
        };

        if let Some(dir) = self.directories.get(&normalized) {
            dir.subdirs.iter().map(|s| s.as_str()).collect()
        } else {
            Vec::new()
        }
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

        self.files.values()
            .filter(|f| f.path.starts_with(&normalized))
            .collect()
    }

    /// Get total file count
    pub fn file_count(&self) -> usize {
        self.files.len()
    }

    /// Get total size of all files
    pub fn total_size(&self) -> u64 {
        self.files.values().map(|f| f.size).sum()
    }

    /// Find file by storage key (reverse lookup)
    pub fn find_by_storage_key(&self, storage_key: &str) -> Option<&ForestFileEntry> {
        self.files.values().find(|f| f.storage_key == storage_key)
    }

    /// Extract a subtree for sharing
    pub fn extract_subtree(&self, prefix: &str) -> PrivateForest {
        let mut subtree = PrivateForest::new();
        subtree.salt = self.salt.clone();
        subtree.root = prefix.to_string();
        
        // Copy matching files
        for (path, entry) in &self.files {
            if path.starts_with(prefix) {
                subtree.files.insert(path.clone(), entry.clone());
            }
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

impl EncryptedForest {
    /// Encrypt a private forest with a DEK
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
        })
    }

    /// Decrypt a private forest with a DEK
    pub fn decrypt(&self, dek: &DekKey) -> Result<PrivateForest> {
        let nonce = Nonce::from_bytes(&self.nonce)?;
        let aead = Aead::new_default(dek);
        let plaintext = aead.decrypt(&nonce, &self.ciphertext)?;
        
        serde_json::from_slice(&plaintext)
            .map_err(|e| CryptoError::Serialization(e.to_string()))
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
}
