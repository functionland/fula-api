//! Private metadata encryption for hiding file names, sizes, and timestamps
//!
//! This module implements metadata privacy by encrypting sensitive information
//! that would otherwise be visible to storage nodes:
//! - Original file name/path
//! - Actual file size
//! - Timestamps
//! - Content type
//! - Any other user-defined metadata
//!
//! The encrypted metadata is stored alongside the encrypted content, and the
//! visible storage key is obfuscated so servers cannot determine file names.

use crate::{
    CryptoError, Result,
    keys::DekKey,
    symmetric::{Aead, Nonce},
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Private (sensitive) metadata that gets encrypted
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivateMetadata {
    /// Original file name/path (the real key)
    pub original_key: String,
    /// Actual file size in bytes
    pub actual_size: u64,
    /// Original content type (MIME type)
    pub content_type: Option<String>,
    /// Original creation timestamp (Unix seconds)
    pub created_at: i64,
    /// Original last modified timestamp (Unix seconds)
    pub modified_at: i64,
    /// User-defined metadata (x-amz-meta-* headers)
    #[serde(default)]
    pub user_metadata: HashMap<String, String>,
    /// Content hash before encryption
    pub content_hash: Option<String>,
    /// Any additional custom fields
    #[serde(default)]
    pub custom: HashMap<String, String>,
}

impl PrivateMetadata {
    /// Create new private metadata
    pub fn new(original_key: impl Into<String>, actual_size: u64) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        
        Self {
            original_key: original_key.into(),
            actual_size,
            content_type: None,
            created_at: now,
            modified_at: now,
            user_metadata: HashMap::new(),
            content_hash: None,
            custom: HashMap::new(),
        }
    }

    /// Set content type
    pub fn with_content_type(mut self, content_type: impl Into<String>) -> Self {
        self.content_type = Some(content_type.into());
        self
    }

    /// Set timestamps
    pub fn with_timestamps(mut self, created: i64, modified: i64) -> Self {
        self.created_at = created;
        self.modified_at = modified;
        self
    }

    /// Add user metadata
    pub fn with_user_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.user_metadata.insert(key.into(), value.into());
        self
    }

    /// Set content hash
    pub fn with_content_hash(mut self, hash: impl Into<String>) -> Self {
        self.content_hash = Some(hash.into());
        self
    }

    /// Add custom field
    pub fn with_custom(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.custom.insert(key.into(), value.into());
        self
    }
}

/// Encrypted private metadata bundle
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedPrivateMetadata {
    /// Version of the encryption format
    pub version: u8,
    /// Encrypted metadata blob (JSON serialized, then AES-GCM encrypted)
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

impl EncryptedPrivateMetadata {
    /// Encrypt private metadata with a DEK
    pub fn encrypt(metadata: &PrivateMetadata, dek: &DekKey) -> Result<Self> {
        // Serialize to JSON
        let json = serde_json::to_vec(metadata)
            .map_err(|e| CryptoError::Serialization(e.to_string()))?;

        // Encrypt with AES-GCM
        let nonce = Nonce::generate();
        let aead = Aead::new_default(dek);
        let ciphertext = aead.encrypt(&nonce, &json)?;

        Ok(Self {
            version: 1,
            ciphertext,
            nonce: nonce.as_bytes().to_vec(),
        })
    }

    /// Decrypt private metadata with a DEK
    pub fn decrypt(&self, dek: &DekKey) -> Result<PrivateMetadata> {
        let nonce = Nonce::from_bytes(&self.nonce)?;
        let aead = Aead::new_default(dek);
        let plaintext = aead.decrypt(&nonce, &self.ciphertext)?;

        serde_json::from_slice(&plaintext)
            .map_err(|e| CryptoError::Serialization(e.to_string()))
    }

    /// Serialize to JSON string for storage
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string(self)
            .map_err(|e| CryptoError::Serialization(e.to_string()))
    }

    /// Deserialize from JSON string
    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_str(json)
            .map_err(|e| CryptoError::Serialization(e.to_string()))
    }
}

/// Options for key obfuscation
#[derive(Clone, Debug)]
pub enum KeyObfuscation {
    /// Hash the key with a secret prefix (deterministic - same key = same hash)
    /// Allows server-side deduplication but reveals if same file uploaded twice
    DeterministicHash,
    /// Random UUID for each upload (non-deterministic)
    /// Maximum privacy but no dedup
    RandomUuid,
    /// Preserve path structure but hash filenames
    /// e.g., "/photos/vacation/" + hash(filename)
    /// Allows folder-like organization while hiding filenames
    PreserveStructure,
}

/// Generate an obfuscated storage key
pub fn obfuscate_key(original_key: &str, dek: &DekKey, mode: KeyObfuscation) -> String {
    match mode {
        KeyObfuscation::DeterministicHash => {
            // Hash key with DEK as context for determinism within a user's scope
            let mut hasher = blake3::Hasher::new();
            hasher.update(dek.as_bytes());
            hasher.update(original_key.as_bytes());
            let hash = hasher.finalize();
            format!("e/{}", hex::encode(&hash.as_bytes()[..16]))
        }
        KeyObfuscation::RandomUuid => {
            // Generate random path
            let uuid = generate_random_id();
            format!("e/{}", uuid)
        }
        KeyObfuscation::PreserveStructure => {
            // Keep directory structure, hash only the filename
            if let Some(last_slash) = original_key.rfind('/') {
                let dir = &original_key[..=last_slash];
                let filename = &original_key[last_slash + 1..];
                
                let mut hasher = blake3::Hasher::new();
                hasher.update(dek.as_bytes());
                hasher.update(filename.as_bytes());
                let hash = hasher.finalize();
                
                format!("{}e_{}", dir, hex::encode(&hash.as_bytes()[..12]))
            } else {
                // No directory, just hash the whole thing
                let mut hasher = blake3::Hasher::new();
                hasher.update(dek.as_bytes());
                hasher.update(original_key.as_bytes());
                let hash = hasher.finalize();
                format!("e_{}", hex::encode(&hash.as_bytes()[..12]))
            }
        }
    }
}

/// Generate a random identifier
fn generate_random_id() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Reverse lookup: find obfuscated key from original
/// Only works with DeterministicHash mode
pub fn find_obfuscated_key(original_key: &str, dek: &DekKey) -> String {
    obfuscate_key(original_key, dek, KeyObfuscation::DeterministicHash)
}

/// Visible (public) metadata - what the server sees
/// These values are intentionally dummy/randomized
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicMetadata {
    /// Obfuscated storage key
    pub storage_key: String,
    /// Dummy size (can be randomized or set to ciphertext size)
    pub visible_size: u64,
    /// Encrypted private metadata (JSON string)
    pub encrypted_metadata: String,
    /// The obfuscation mode used (for decryption)
    pub obfuscation_mode: String,
}

impl PublicMetadata {
    /// Create public metadata from private metadata
    pub fn from_private(
        private: &PrivateMetadata,
        dek: &DekKey,
        ciphertext_size: u64,
        mode: KeyObfuscation,
    ) -> Result<Self> {
        let storage_key = obfuscate_key(&private.original_key, dek, mode.clone());
        let encrypted = EncryptedPrivateMetadata::encrypt(private, dek)?;
        
        let mode_str = match mode {
            KeyObfuscation::DeterministicHash => "hash",
            KeyObfuscation::RandomUuid => "uuid",
            KeyObfuscation::PreserveStructure => "structure",
        };

        Ok(Self {
            storage_key,
            visible_size: ciphertext_size, // Server sees ciphertext size, not original
            encrypted_metadata: encrypted.to_json()?,
            obfuscation_mode: mode_str.to_string(),
        })
    }

    /// Recover private metadata
    pub fn decrypt_private(&self, dek: &DekKey) -> Result<PrivateMetadata> {
        let encrypted = EncryptedPrivateMetadata::from_json(&self.encrypted_metadata)?;
        encrypted.decrypt(dek)
    }
}

/// A mapping entry for the client's local index
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MetadataMapping {
    /// Original key (plaintext, stored locally)
    pub original_key: String,
    /// Obfuscated storage key (for server requests)
    pub storage_key: String,
    /// The DEK used (wrapped, for storage)
    pub wrapped_dek: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_private_metadata_roundtrip() {
        let dek = DekKey::generate();
        
        let private = PrivateMetadata::new("/photos/vacation/beach.jpg", 1024 * 1024)
            .with_content_type("image/jpeg")
            .with_user_metadata("camera", "iPhone 15")
            .with_content_hash("abc123def456");

        let encrypted = EncryptedPrivateMetadata::encrypt(&private, &dek).unwrap();
        let decrypted = encrypted.decrypt(&dek).unwrap();

        assert_eq!(decrypted.original_key, "/photos/vacation/beach.jpg");
        assert_eq!(decrypted.actual_size, 1024 * 1024);
        assert_eq!(decrypted.content_type, Some("image/jpeg".to_string()));
        assert_eq!(decrypted.user_metadata.get("camera"), Some(&"iPhone 15".to_string()));
    }

    #[test]
    fn test_wrong_key_fails() {
        let dek1 = DekKey::generate();
        let dek2 = DekKey::generate();

        let private = PrivateMetadata::new("secret.txt", 100);
        let encrypted = EncryptedPrivateMetadata::encrypt(&private, &dek1).unwrap();

        assert!(encrypted.decrypt(&dek2).is_err());
    }

    #[test]
    fn test_obfuscation_deterministic() {
        let dek = DekKey::generate();
        let key = "/documents/report.pdf";

        let obf1 = obfuscate_key(key, &dek, KeyObfuscation::DeterministicHash);
        let obf2 = obfuscate_key(key, &dek, KeyObfuscation::DeterministicHash);

        assert_eq!(obf1, obf2, "Deterministic hash should be consistent");
        assert!(obf1.starts_with("e/"), "Should have encrypted prefix");
        assert!(!obf1.contains("report"), "Should not contain original filename");
    }

    #[test]
    fn test_obfuscation_random() {
        let dek = DekKey::generate();
        let key = "/documents/report.pdf";

        let obf1 = obfuscate_key(key, &dek, KeyObfuscation::RandomUuid);
        let obf2 = obfuscate_key(key, &dek, KeyObfuscation::RandomUuid);

        assert_ne!(obf1, obf2, "Random UUIDs should be different");
    }

    #[test]
    fn test_obfuscation_preserve_structure() {
        let dek = DekKey::generate();
        let key = "/photos/2024/vacation/beach.jpg";

        let obf = obfuscate_key(key, &dek, KeyObfuscation::PreserveStructure);

        assert!(obf.starts_with("/photos/2024/vacation/"), "Should preserve directory");
        assert!(obf.contains("e_"), "Should have encrypted filename");
        assert!(!obf.contains("beach"), "Should not contain original filename");
    }

    #[test]
    fn test_public_metadata_creation() {
        let dek = DekKey::generate();
        let private = PrivateMetadata::new("/secret/file.txt", 500);

        let public = PublicMetadata::from_private(
            &private,
            &dek,
            550, // ciphertext is larger
            KeyObfuscation::DeterministicHash,
        ).unwrap();

        assert!(public.storage_key.starts_with("e/"));
        assert_eq!(public.visible_size, 550);
        assert_eq!(public.obfuscation_mode, "hash");

        // Should be able to recover private metadata
        let recovered = public.decrypt_private(&dek).unwrap();
        assert_eq!(recovered.original_key, "/secret/file.txt");
        assert_eq!(recovered.actual_size, 500);
    }

    #[test]
    fn test_different_files_different_hashes() {
        let dek = DekKey::generate();

        let obf1 = obfuscate_key("/file1.txt", &dek, KeyObfuscation::DeterministicHash);
        let obf2 = obfuscate_key("/file2.txt", &dek, KeyObfuscation::DeterministicHash);

        assert_ne!(obf1, obf2, "Different files should have different hashes");
    }

    #[test]
    fn test_same_file_different_users() {
        let dek1 = DekKey::generate();
        let dek2 = DekKey::generate();

        let obf1 = obfuscate_key("/file.txt", &dek1, KeyObfuscation::DeterministicHash);
        let obf2 = obfuscate_key("/file.txt", &dek2, KeyObfuscation::DeterministicHash);

        assert_ne!(obf1, obf2, "Same file with different DEKs should have different hashes");
    }

    #[test]
    fn test_serialization() {
        let dek = DekKey::generate();
        let private = PrivateMetadata::new("test.txt", 100);

        let encrypted = EncryptedPrivateMetadata::encrypt(&private, &dek).unwrap();
        let json = encrypted.to_json().unwrap();
        let recovered = EncryptedPrivateMetadata::from_json(&json).unwrap();

        let decrypted = recovered.decrypt(&dek).unwrap();
        assert_eq!(decrypted.original_key, "test.txt");
    }
}
