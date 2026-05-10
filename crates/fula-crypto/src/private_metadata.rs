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
    time::now_timestamp,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Private (sensitive) metadata that gets encrypted
///
/// All plaintext-sensitive fields (filename, MIME type, content hash,
/// user-supplied metadata) are kept inside the AEAD-protected envelope.
/// `Debug` is hand-rolled to redact every sensitive field so a stray
/// `{:?}` log line cannot leak the same plaintext the AEAD layer is
/// protecting on the wire.
#[derive(Clone, Serialize, Deserialize)]
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

impl std::fmt::Debug for PrivateMetadata {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrivateMetadata")
            .field("original_key", &"<redacted>")
            .field("actual_size", &self.actual_size)
            .field("content_type", &self.content_type.as_ref().map(|_| "<redacted>"))
            .field("created_at", &self.created_at)
            .field("modified_at", &self.modified_at)
            .field(
                "user_metadata",
                &format_args!("[{} entries redacted]", self.user_metadata.len()),
            )
            .field("content_hash", &self.content_hash.as_ref().map(|_| "<redacted>"))
            .field(
                "custom",
                &format_args!("[{} entries redacted]", self.custom.len()),
            )
            .finish()
    }
}

impl PrivateMetadata {
    /// Create new private metadata
    pub fn new(original_key: impl Into<String>, actual_size: u64) -> Self {
        let now = now_timestamp();

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
///
/// Wire-format versions
/// --------------------
/// - **v1** (legacy, no AAD): the AEAD ciphertext was produced with an empty
///   AAD. A storage server with read access to multiple metadata blobs
///   encrypted under the same DEK can swap them without detection. v1 is
///   readable by every SDK version for backward compatibility but new writes
///   should not be produced in v1; use [`EncryptedPrivateMetadata::encrypt_v2`].
/// - **v2** (default for new writes): AEAD-bound to the obfuscated storage
///   key. The caller passes the storage_key as the AAD on both encrypt and
///   decrypt; AEAD verification fails if the metadata blob is moved to a
///   different storage path. See [`EncryptedPrivateMetadata::aad_v2`] for
///   the canonical AAD construction.
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
    /// Wire-format constant: current v2 version byte.
    pub const WIRE_VERSION_V2: u8 = 2;

    /// Build the canonical v2 AAD for a given obfuscated storage key.
    ///
    /// The AAD is `"fula:private-metadata:v2:" || storage_key`. Domain
    /// separation prefix prevents cross-purpose ciphertext reuse with any
    /// other AEAD callsite, and including the storage key in the AAD ensures
    /// the metadata blob cannot be moved to a different path without breaking
    /// the AEAD tag. The caller MUST pass the same `storage_key` on encrypt
    /// and decrypt; mismatched values fail closed.
    pub fn aad_v2(storage_key: &str) -> Vec<u8> {
        let mut aad = Vec::with_capacity(b"fula:private-metadata:v2:".len() + storage_key.len());
        aad.extend_from_slice(b"fula:private-metadata:v2:");
        aad.extend_from_slice(storage_key.as_bytes());
        aad
    }

    /// **DEPRECATED — use [`EncryptedPrivateMetadata::encrypt_v2`].**
    ///
    /// Produces a v1 (no-AAD) blob. Kept callable so existing data and
    /// callers continue to work, but new writes from production code must
    /// route through `encrypt_v2` to gain cross-path replay protection.
    /// Tests that legitimately need a v1 blob (round-trip + back-compat
    /// fixtures) annotate the call with `#[allow(deprecated)]`.
    #[deprecated(
        since = "0.7.0",
        note = "use encrypt_v2(metadata, dek, &aad_v2(storage_key)) — v1 is no-AAD and master can swap blobs across paths"
    )]
    pub fn encrypt(metadata: &PrivateMetadata, dek: &DekKey) -> Result<Self> {
        // Serialize to JSON
        let json = serde_json::to_vec(metadata)
            .map_err(|e| CryptoError::Serialization(e.to_string()))?;

        // Encrypt with AES-GCM, no AAD (legacy v1).
        let nonce = Nonce::generate();
        let aead = Aead::new_default(dek);
        let ciphertext = aead.encrypt(&nonce, &json)?;

        Ok(Self {
            version: 1,
            ciphertext,
            nonce: nonce.as_bytes().to_vec(),
        })
    }

    /// Encrypt private metadata with a DEK and an AAD bound to the storage
    /// path (v2 wire format).
    ///
    /// The AAD MUST be the canonical [`EncryptedPrivateMetadata::aad_v2`]
    /// construction over the same `storage_key` that callers will use to
    /// fetch this blob. Decrypt then re-builds the same AAD from the
    /// fetched-from path; if a server moved the blob to a different path,
    /// the AEAD tag check fails closed.
    pub fn encrypt_v2(
        metadata: &PrivateMetadata,
        dek: &DekKey,
        aad: &[u8],
    ) -> Result<Self> {
        let json = serde_json::to_vec(metadata)
            .map_err(|e| CryptoError::Serialization(e.to_string()))?;

        let nonce = Nonce::generate();
        let aead = Aead::new_default(dek);
        let ciphertext = aead.encrypt_with_aad(&nonce, &json, aad)?;

        Ok(Self {
            version: Self::WIRE_VERSION_V2,
            ciphertext,
            nonce: nonce.as_bytes().to_vec(),
        })
    }

    /// Decrypt a v1 metadata blob (no AAD).
    ///
    /// Returns a clear error if `self.version >= 2` — those formats require
    /// the AAD-bound [`EncryptedPrivateMetadata::decrypt_v2`] path. This
    /// preserves backward compatibility for already-stored v1 data while
    /// preventing v2 callers from accidentally bypassing the AAD check.
    pub fn decrypt(&self, dek: &DekKey) -> Result<PrivateMetadata> {
        if self.version >= Self::WIRE_VERSION_V2 {
            return Err(CryptoError::Decryption(format!(
                "EncryptedPrivateMetadata version {} requires decrypt_v2(dek, aad) — \
                 v1 legacy decrypt is for version 1 only",
                self.version
            )));
        }
        let nonce = Nonce::from_bytes(&self.nonce)?;
        let aead = Aead::new_default(dek);
        let plaintext = aead.decrypt(&nonce, &self.ciphertext)?;

        serde_json::from_slice(&plaintext)
            .map_err(|e| CryptoError::Serialization(e.to_string()))
    }

    /// Decrypt a v2 metadata blob with AAD verification.
    ///
    /// `aad` MUST equal the bytes the producer passed to
    /// [`EncryptedPrivateMetadata::encrypt_v2`]; in production this is
    /// `aad_v2(storage_key)` for the path the blob was fetched from.
    /// AEAD failure on AAD mismatch surfaces as
    /// [`CryptoError::Decryption`] (the underlying AEAD layer's failure).
    ///
    /// Errors if `self.version != 2` to prevent silent v1-as-v2 confusion.
    pub fn decrypt_v2(&self, dek: &DekKey, aad: &[u8]) -> Result<PrivateMetadata> {
        if self.version != Self::WIRE_VERSION_V2 {
            return Err(CryptoError::Decryption(format!(
                "decrypt_v2 requires EncryptedPrivateMetadata version {}, got {}",
                Self::WIRE_VERSION_V2,
                self.version
            )));
        }
        let nonce = Nonce::from_bytes(&self.nonce)?;
        let aead = Aead::new_default(dek);
        let plaintext = aead.decrypt_with_aad(&nonce, &self.ciphertext, aad)?;

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
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyObfuscation {
    /// Hash the key with a secret prefix (deterministic - same key = same hash)
    /// Allows server-side deduplication but reveals if same file uploaded twice
    /// Server sees: `e/a7c3f9b2e8d14a6f` (reveals "e/" prefix)
    #[deprecated(since = "0.7.0", note = "use FlatNamespace; DeterministicHash lacks domain separation and is not used in production")]
    DeterministicHash,
    /// Random UUID for each upload (non-deterministic)
    /// Maximum privacy but no dedup
    /// Server sees: `e/random-uuid-here`
    RandomUuid,
    /// Preserve path structure but hash filenames
    /// e.g., "/photos/vacation/" + hash(filename)
    /// Allows folder-like organization while hiding filenames
    /// Server sees: `/photos/vacation/e_a7c3f9b2`
    PreserveStructure,
    /// Flat namespace - complete structure hiding (RECOMMENDED)
    /// 
    /// Inspired by WNFS and Peergos:
    /// - All keys look like random CID-style hashes
    /// - No prefixes or structure hints
    /// - File tree stored in encrypted index (PrivateForest)
    /// - Server cannot determine folder structure, parent/child relationships
    /// 
    /// Server sees: `QmX7a8f3e2d1c9b4a5e6f7d8c9a0b1e2f3a4b5c6d7e8f9`
    FlatNamespace,
}

/// Generate an obfuscated storage key
#[allow(deprecated)]
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
        KeyObfuscation::FlatNamespace => {
            // Completely flat - no prefixes, looks like a CID
            // Uses PrivateForest module for key generation
            //
            // Security audit M-001: The empty salt is intentional.
            // obfuscate_key() with FlatNamespace provides deterministic key LOOKUP
            // without a forest context. Forest-backed storage uses
            // PrivateForest::generate_key() which supplies the forest's random
            // 32-byte salt. Cross-bucket correlation is not possible because
            // each user has a unique DEK derived from their secret key.
            crate::private_forest::generate_flat_key(original_key, dek, &[])
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
#[allow(deprecated)]
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
    /// Create public metadata from private metadata.
    ///
    /// New writes use [`EncryptedPrivateMetadata::encrypt_v2`] with AAD
    /// bound to the obfuscated storage key — this prevents a storage server
    /// from swapping metadata blobs across paths.
    pub fn from_private(
        private: &PrivateMetadata,
        dek: &DekKey,
        ciphertext_size: u64,
        mode: KeyObfuscation,
    ) -> Result<Self> {
        let storage_key = obfuscate_key(&private.original_key, dek, mode.clone());
        let aad = EncryptedPrivateMetadata::aad_v2(&storage_key);
        let encrypted = EncryptedPrivateMetadata::encrypt_v2(private, dek, &aad)?;

        #[allow(deprecated)]
        let mode_str = match mode {
            KeyObfuscation::DeterministicHash => "hash",
            KeyObfuscation::RandomUuid => "uuid",
            KeyObfuscation::PreserveStructure => "structure",
            KeyObfuscation::FlatNamespace => "flat",
        };

        Ok(Self {
            storage_key,
            visible_size: ciphertext_size, // Server sees ciphertext size, not original
            encrypted_metadata: encrypted.to_json()?,
            obfuscation_mode: mode_str.to_string(),
        })
    }

    /// Recover private metadata.
    ///
    /// Dispatches on the encrypted blob's wire-format version: v1 (legacy,
    /// no AAD) reads with the no-AAD path; v2 (current) reads with AAD bound
    /// to `self.storage_key`. Unknown versions (e.g., a future v3 produced
    /// by a newer SDK) error cleanly so a downgrade attack cannot pick the
    /// wrong dispatch arm.
    pub fn decrypt_private(&self, dek: &DekKey) -> Result<PrivateMetadata> {
        let encrypted = EncryptedPrivateMetadata::from_json(&self.encrypted_metadata)?;
        match encrypted.version {
            1 => {
                #[allow(deprecated)]
                encrypted.decrypt(dek)
            }
            2 => {
                let aad = EncryptedPrivateMetadata::aad_v2(&self.storage_key);
                encrypted.decrypt_v2(dek, &aad)
            }
            v => Err(CryptoError::Decryption(format!(
                "unsupported EncryptedPrivateMetadata wire version {} — \
                 this SDK reads v1 and v2",
                v
            ))),
        }
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
#[allow(deprecated)]
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

    // ─────────────────────────────────────────────────────────────────────
    // F2 (audit): wire-format v2 round-trip + back-compat regression tests.
    // These guard the load-bearing invariant that already-uploaded data
    // (v1, no AAD) must remain readable after the SDK starts producing v2.
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn test_v2_round_trip() {
        let dek = DekKey::generate();
        let private = PrivateMetadata::new("/photos/beach.jpg", 1024)
            .with_content_type("image/jpeg");
        let storage_key = "QmFakeStorageKey1234567890abcdef";
        let aad = EncryptedPrivateMetadata::aad_v2(storage_key);

        let encrypted = EncryptedPrivateMetadata::encrypt_v2(&private, &dek, &aad).unwrap();
        assert_eq!(encrypted.version, EncryptedPrivateMetadata::WIRE_VERSION_V2);

        let decrypted = encrypted.decrypt_v2(&dek, &aad).unwrap();
        assert_eq!(decrypted.original_key, "/photos/beach.jpg");
        assert_eq!(decrypted.actual_size, 1024);
    }

    #[test]
    fn test_v2_wrong_aad_rejects() {
        let dek = DekKey::generate();
        let private = PrivateMetadata::new("/secret.txt", 100);
        let aad_correct = EncryptedPrivateMetadata::aad_v2("QmCorrect");
        let aad_wrong = EncryptedPrivateMetadata::aad_v2("QmWrongPath");

        let encrypted = EncryptedPrivateMetadata::encrypt_v2(&private, &dek, &aad_correct).unwrap();
        assert!(
            encrypted.decrypt_v2(&dek, &aad_wrong).is_err(),
            "AEAD must reject mismatched AAD — server cannot swap blob across paths"
        );
        // And the correct AAD still works.
        assert!(encrypted.decrypt_v2(&dek, &aad_correct).is_ok());
    }

    #[test]
    fn test_v1_legacy_data_still_readable_by_v2_sdk() {
        // Backward compat invariant: an SDK that has been upgraded to
        // produce v2 blobs must still successfully decrypt every
        // previously-stored v1 blob. We synthesize a v1 blob with the
        // deprecated `encrypt` and read it through `PublicMetadata`'s
        // dispatch (which an upgraded SDK uses).
        let dek = DekKey::generate();
        let private = PrivateMetadata::new("/legacy.txt", 42);
        let v1_blob = EncryptedPrivateMetadata::encrypt(&private, &dek).unwrap();
        assert_eq!(v1_blob.version, 1);

        // Legacy decrypt path on v1 blob — must succeed.
        let decrypted = v1_blob.decrypt(&dek).unwrap();
        assert_eq!(decrypted.original_key, "/legacy.txt");
    }

    #[test]
    fn test_v2_blob_rejected_by_legacy_decrypt() {
        // A v2 blob fed through the legacy `decrypt` (no-AAD) must fail
        // closed with a clear error directing the caller to `decrypt_v2`,
        // rather than silently bypassing the AAD check.
        let dek = DekKey::generate();
        let private = PrivateMetadata::new("/file.txt", 10);
        let aad = EncryptedPrivateMetadata::aad_v2("QmStorageKey");
        let v2_blob = EncryptedPrivateMetadata::encrypt_v2(&private, &dek, &aad).unwrap();

        let err = v2_blob.decrypt(&dek).unwrap_err().to_string();
        assert!(
            err.contains("decrypt_v2"),
            "legacy decrypt() on v2 blob must surface a `use decrypt_v2` error; got: {}",
            err
        );
    }

    #[test]
    fn test_v1_blob_rejected_by_v2_decrypt() {
        // Symmetrically: a v1 blob fed through `decrypt_v2` must fail
        // closed (the AEAD layer would fail anyway, but we want a clear
        // version-mismatch error before the AEAD attempt).
        let dek = DekKey::generate();
        let private = PrivateMetadata::new("/file.txt", 10);
        let v1_blob = EncryptedPrivateMetadata::encrypt(&private, &dek).unwrap();
        let aad = EncryptedPrivateMetadata::aad_v2("Qm");

        assert!(v1_blob.decrypt_v2(&dek, &aad).is_err());
    }

    #[test]
    fn test_public_metadata_dispatches_on_version() {
        // PublicMetadata::decrypt_private dispatches v1/v2 based on the
        // blob's wire version — covers both directions of the migration
        // matrix in a single integration-shaped test.
        let dek = DekKey::generate();
        let private = PrivateMetadata::new("/file.txt", 100);

        let public_v2 = PublicMetadata::from_private(
            &private,
            &dek,
            100,
            KeyObfuscation::FlatNamespace,
        )
        .unwrap();
        // New writes must produce v2 by default (F2 audit fix).
        let inner = EncryptedPrivateMetadata::from_json(&public_v2.encrypted_metadata).unwrap();
        assert_eq!(inner.version, 2, "new writes must be v2");

        // Round-trip via PublicMetadata.
        let recovered = public_v2.decrypt_private(&dek).unwrap();
        assert_eq!(recovered.original_key, "/file.txt");

        // Synthesize a legacy v1 PublicMetadata (as if produced by a pre-0.7
        // SDK): v1 inner blob, otherwise valid PublicMetadata. The dispatch
        // must read this back successfully.
        let storage_key = obfuscate_key(
            "/file.txt",
            &dek,
            KeyObfuscation::FlatNamespace,
        );
        let v1_inner = EncryptedPrivateMetadata::encrypt(&private, &dek).unwrap();
        let public_v1 = PublicMetadata {
            storage_key,
            visible_size: 100,
            encrypted_metadata: v1_inner.to_json().unwrap(),
            obfuscation_mode: "flat".to_string(),
        };
        let recovered_legacy = public_v1.decrypt_private(&dek).unwrap();
        assert_eq!(recovered_legacy.original_key, "/file.txt");
    }
}
