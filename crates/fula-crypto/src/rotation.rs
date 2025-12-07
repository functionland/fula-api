//! Key rotation for the file system
//!
//! This module implements full key rotation capabilities:
//! - Rotate KEK (Key Encryption Key) without re-encrypting data
//! - Re-wrap all DEKs with the new KEK
//! - Track key versions for migration
//! - Support incremental rotation (batch processing)

use crate::{
    CryptoError, Result,
    hpke::{Encryptor, Decryptor, EncryptedData},
    keys::{DekKey, KekKeyPair, PublicKey},
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Metadata about an encrypted object's key
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct WrappedKeyInfo {
    /// The wrapped DEK
    pub wrapped_dek: EncryptedData,
    /// Version of the KEK used to wrap this DEK
    pub kek_version: u32,
    /// Object path/identifier
    pub object_path: String,
}

/// Result of a key rotation operation
#[derive(Debug)]
pub struct RotationResult {
    /// Number of keys successfully rotated
    pub rotated_count: usize,
    /// Number of keys that failed to rotate
    pub failed_count: usize,
    /// Paths that failed with error messages
    pub failures: Vec<(String, String)>,
    /// New KEK version
    pub new_kek_version: u32,
}

/// Key rotation manager
pub struct KeyRotationManager {
    /// Current KEK
    current_keypair: KekKeyPair,
    /// Current KEK version
    current_version: u32,
    /// Previous KEK (for decrypting old wrapped keys)
    previous_keypair: Option<KekKeyPair>,
    /// Previous KEK version
    previous_version: Option<u32>,
}

impl KeyRotationManager {
    /// Create a new rotation manager with initial keypair
    pub fn new(keypair: KekKeyPair) -> Self {
        Self {
            current_keypair: keypair,
            current_version: 1,
            previous_keypair: None,
            previous_version: None,
        }
    }

    /// Create from existing state
    pub fn from_state(
        current_keypair: KekKeyPair,
        current_version: u32,
        previous_keypair: Option<KekKeyPair>,
        previous_version: Option<u32>,
    ) -> Self {
        Self {
            current_keypair,
            current_version,
            previous_keypair,
            previous_version,
        }
    }

    /// Get the current public key
    pub fn current_public_key(&self) -> &PublicKey {
        self.current_keypair.public_key()
    }

    /// Get the current KEK version
    pub fn current_version(&self) -> u32 {
        self.current_version
    }

    /// Rotate to a new KEK
    /// Returns the new public key
    pub fn rotate_kek(&mut self) -> &PublicKey {
        // Move current to previous
        let old_keypair = std::mem::replace(
            &mut self.current_keypair,
            KekKeyPair::generate(),
        );
        
        self.previous_keypair = Some(old_keypair);
        self.previous_version = Some(self.current_version);
        self.current_version += 1;

        self.current_keypair.public_key()
    }

    /// Re-wrap a single DEK from old KEK to new KEK
    pub fn rewrap_dek(&self, wrapped_info: &WrappedKeyInfo) -> Result<WrappedKeyInfo> {
        // Determine which keypair to use for decryption
        let decrypt_keypair = if wrapped_info.kek_version == self.current_version {
            // Already using current key
            return Ok(wrapped_info.clone());
        } else if Some(wrapped_info.kek_version) == self.previous_version {
            self.previous_keypair.as_ref()
                .ok_or_else(|| CryptoError::InvalidKey("Previous keypair not available".into()))?
        } else {
            return Err(CryptoError::InvalidKey(format!(
                "Unknown KEK version: {}. Current: {}, Previous: {:?}",
                wrapped_info.kek_version, self.current_version, self.previous_version
            )));
        };

        // Decrypt with old KEK
        let decryptor = Decryptor::new(decrypt_keypair);
        let dek = decryptor.decrypt_dek(&wrapped_info.wrapped_dek)?;

        // Re-encrypt with new KEK
        let encryptor = Encryptor::new(self.current_keypair.public_key());
        let new_wrapped = encryptor.encrypt_dek(&dek)?;

        Ok(WrappedKeyInfo {
            wrapped_dek: new_wrapped,
            kek_version: self.current_version,
            object_path: wrapped_info.object_path.clone(),
        })
    }

    /// Re-wrap multiple DEKs (batch operation)
    pub fn rewrap_batch(&self, wrapped_keys: &[WrappedKeyInfo]) -> RotationResult {
        let mut rotated_count = 0;
        let mut failed_count = 0;
        let mut failures = Vec::new();

        for wrapped in wrapped_keys {
            match self.rewrap_dek(wrapped) {
                Ok(_) => rotated_count += 1,
                Err(e) => {
                    failed_count += 1;
                    failures.push((wrapped.object_path.clone(), e.to_string()));
                }
            }
        }

        RotationResult {
            rotated_count,
            failed_count,
            failures,
            new_kek_version: self.current_version,
        }
    }

    /// Wrap a new DEK with the current KEK
    pub fn wrap_dek(&self, dek: &DekKey, object_path: &str) -> Result<WrappedKeyInfo> {
        let encryptor = Encryptor::new(self.current_keypair.public_key());
        let wrapped = encryptor.encrypt_dek(dek)?;

        Ok(WrappedKeyInfo {
            wrapped_dek: wrapped,
            kek_version: self.current_version,
            object_path: object_path.to_string(),
        })
    }

    /// Unwrap a DEK (handles both current and previous versions)
    pub fn unwrap_dek(&self, wrapped: &WrappedKeyInfo) -> Result<DekKey> {
        let keypair = if wrapped.kek_version == self.current_version {
            &self.current_keypair
        } else if Some(wrapped.kek_version) == self.previous_version {
            self.previous_keypair.as_ref()
                .ok_or_else(|| CryptoError::InvalidKey("Previous keypair not available".into()))?
        } else {
            return Err(CryptoError::InvalidKey(format!(
                "Cannot unwrap DEK: unknown KEK version {}",
                wrapped.kek_version
            )));
        };

        let decryptor = Decryptor::new(keypair);
        decryptor.decrypt_dek(&wrapped.wrapped_dek)
    }

    /// Clear the previous keypair (after all DEKs have been rotated)
    pub fn clear_previous(&mut self) {
        self.previous_keypair = None;
        self.previous_version = None;
    }

    /// Check if there are keys pending rotation
    pub fn has_pending_rotation(&self) -> bool {
        self.previous_keypair.is_some()
    }

    /// Export current public key for backup
    pub fn export_public_key(&self) -> String {
        self.current_keypair.public_key().to_base64()
    }
}

/// Full file system key rotation coordinator
pub struct FileSystemRotation {
    /// The rotation manager
    rotation_manager: KeyRotationManager,
    /// Index of all wrapped keys (path -> WrappedKeyInfo)
    wrapped_keys: HashMap<String, WrappedKeyInfo>,
    /// Batch size for incremental rotation
    batch_size: usize,
}

impl FileSystemRotation {
    pub fn new(keypair: KekKeyPair) -> Self {
        Self {
            rotation_manager: KeyRotationManager::new(keypair),
            wrapped_keys: HashMap::new(),
            batch_size: 100,
        }
    }

    /// Set batch size for incremental rotation
    pub fn with_batch_size(mut self, size: usize) -> Self {
        self.batch_size = size;
        self
    }

    /// Register a file's wrapped DEK
    pub fn register_file(&mut self, path: &str, wrapped: WrappedKeyInfo) {
        self.wrapped_keys.insert(path.to_string(), wrapped);
    }

    /// Get the wrapped DEK for a file
    pub fn get_wrapped_key(&self, path: &str) -> Option<&WrappedKeyInfo> {
        self.wrapped_keys.get(path)
    }

    /// Wrap a new DEK for a file
    pub fn wrap_new_file(&mut self, path: &str, dek: &DekKey) -> Result<WrappedKeyInfo> {
        let wrapped = self.rotation_manager.wrap_dek(dek, path)?;
        self.wrapped_keys.insert(path.to_string(), wrapped.clone());
        Ok(wrapped)
    }

    /// Unwrap a file's DEK
    pub fn unwrap_file(&self, path: &str) -> Result<DekKey> {
        let wrapped = self.wrapped_keys.get(path)
            .ok_or_else(|| CryptoError::InvalidKey(format!("File not found: {}", path)))?;
        self.rotation_manager.unwrap_dek(wrapped)
    }

    /// Initiate a key rotation
    /// Returns the new public key
    pub fn rotate(&mut self) -> &PublicKey {
        self.rotation_manager.rotate_kek()
    }

    /// Get keys that need rotation
    pub fn get_keys_needing_rotation(&self) -> Vec<&WrappedKeyInfo> {
        let current_version = self.rotation_manager.current_version();
        self.wrapped_keys.values()
            .filter(|w| w.kek_version < current_version)
            .collect()
    }

    /// Rotate a batch of keys
    /// Returns the number rotated and any failures
    pub fn rotate_batch(&mut self) -> RotationResult {
        let current_version = self.rotation_manager.current_version();
        
        // Find keys needing rotation
        let to_rotate: Vec<_> = self.wrapped_keys.iter()
            .filter(|(_, w)| w.kek_version < current_version)
            .take(self.batch_size)
            .map(|(path, wrapped)| (path.clone(), wrapped.clone()))
            .collect();

        let mut rotated = 0;
        let mut failed = 0;
        let mut failures = Vec::new();

        for (path, wrapped) in to_rotate {
            match self.rotation_manager.rewrap_dek(&wrapped) {
                Ok(new_wrapped) => {
                    self.wrapped_keys.insert(path, new_wrapped);
                    rotated += 1;
                }
                Err(e) => {
                    failed += 1;
                    failures.push((path, e.to_string()));
                }
            }
        }

        RotationResult {
            rotated_count: rotated,
            failed_count: failed,
            failures,
            new_kek_version: current_version,
        }
    }

    /// Rotate all keys (may be slow for large systems)
    pub fn rotate_all(&mut self) -> RotationResult {
        let mut total_rotated = 0;
        let mut total_failed = 0;
        let mut all_failures = Vec::new();

        loop {
            let result = self.rotate_batch();
            total_rotated += result.rotated_count;
            total_failed += result.failed_count;
            all_failures.extend(result.failures);

            if result.rotated_count == 0 {
                break;
            }
        }

        // Clear previous key after all rotation is complete
        if total_failed == 0 && !self.rotation_manager.has_pending_rotation() {
            self.rotation_manager.clear_previous();
        }

        RotationResult {
            rotated_count: total_rotated,
            failed_count: total_failed,
            failures: all_failures,
            new_kek_version: self.rotation_manager.current_version(),
        }
    }

    /// Check if all keys have been rotated to current version
    pub fn is_rotation_complete(&self) -> bool {
        self.get_keys_needing_rotation().is_empty()
    }

    /// Get rotation progress
    pub fn rotation_progress(&self) -> (usize, usize) {
        let current_version = self.rotation_manager.current_version();
        let total = self.wrapped_keys.len();
        let rotated = self.wrapped_keys.values()
            .filter(|w| w.kek_version == current_version)
            .count();
        (rotated, total)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::symmetric::{encrypt, decrypt};

    #[test]
    fn test_key_rotation_basic() {
        let keypair = KekKeyPair::generate();
        let mut manager = KeyRotationManager::new(keypair);

        assert_eq!(manager.current_version(), 1);

        // Create some wrapped DEKs
        let dek1 = DekKey::generate();
        let wrapped1 = manager.wrap_dek(&dek1, "/file1.txt").unwrap();

        // Rotate keys
        manager.rotate_kek();
        assert_eq!(manager.current_version(), 2);

        // Old wrapped key should still be decryptable
        let unwrapped = manager.unwrap_dek(&wrapped1).unwrap();
        assert_eq!(dek1.as_bytes(), unwrapped.as_bytes());

        // Re-wrap to new version
        let rewrapped = manager.rewrap_dek(&wrapped1).unwrap();
        assert_eq!(rewrapped.kek_version, 2);

        // Verify re-wrapped key still decrypts to same DEK
        let unwrapped2 = manager.unwrap_dek(&rewrapped).unwrap();
        assert_eq!(dek1.as_bytes(), unwrapped2.as_bytes());
    }

    #[test]
    fn test_full_filesystem_rotation() {
        let keypair = KekKeyPair::generate();
        let mut fs = FileSystemRotation::new(keypair)
            .with_batch_size(10);

        // Create 25 files
        for i in 0..25 {
            let dek = DekKey::generate();
            fs.wrap_new_file(&format!("/file{}.txt", i), &dek).unwrap();
        }

        // Verify all at version 1
        assert_eq!(fs.rotation_progress(), (25, 25));

        // Initiate rotation
        fs.rotate();

        // Now need to rotate all
        assert_eq!(fs.get_keys_needing_rotation().len(), 25);

        // Rotate first batch (10)
        let result = fs.rotate_batch();
        assert_eq!(result.rotated_count, 10);
        assert_eq!(fs.rotation_progress(), (10, 25));

        // Rotate all remaining
        let result = fs.rotate_all();
        assert_eq!(result.rotated_count, 15);
        assert!(fs.is_rotation_complete());
        assert_eq!(fs.rotation_progress(), (25, 25));
    }

    #[test]
    fn test_data_accessible_after_rotation() {
        let keypair = KekKeyPair::generate();
        let mut fs = FileSystemRotation::new(keypair);

        // Encrypt some data
        let original_data = b"Important file content";
        let dek = DekKey::generate();
        let (nonce, ciphertext) = encrypt(&dek, original_data).unwrap();

        // Register the file
        fs.wrap_new_file("/important.txt", &dek).unwrap();

        // Rotate keys
        fs.rotate();
        fs.rotate_all();

        // Data should still be accessible
        let unwrapped_dek = fs.unwrap_file("/important.txt").unwrap();
        let decrypted = decrypt(&unwrapped_dek, &nonce, &ciphertext).unwrap();

        assert_eq!(original_data.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_multiple_rotations() {
        let keypair = KekKeyPair::generate();
        let mut manager = KeyRotationManager::new(keypair);

        // Create a DEK
        let dek = DekKey::generate();
        let mut wrapped = manager.wrap_dek(&dek, "/test.txt").unwrap();
        assert_eq!(wrapped.kek_version, 1);

        // Rotate 3 times, re-wrapping each time
        for expected_version in 2..=4 {
            manager.rotate_kek();
            wrapped = manager.rewrap_dek(&wrapped).unwrap();
            assert_eq!(wrapped.kek_version, expected_version);

            // Verify DEK still accessible
            let unwrapped = manager.unwrap_dek(&wrapped).unwrap();
            assert_eq!(dek.as_bytes(), unwrapped.as_bytes());
        }
    }

    #[test]
    fn test_cannot_decrypt_after_clear_previous() {
        let keypair = KekKeyPair::generate();
        let mut manager = KeyRotationManager::new(keypair);

        // Create and wrap a DEK
        let dek = DekKey::generate();
        let wrapped_v1 = manager.wrap_dek(&dek, "/test.txt").unwrap();

        // Rotate
        manager.rotate_kek();

        // Re-wrap to v2
        let wrapped_v2 = manager.rewrap_dek(&wrapped_v1).unwrap();

        // Clear previous key
        manager.clear_previous();

        // V2 should still work
        assert!(manager.unwrap_dek(&wrapped_v2).is_ok());

        // V1 should fail (previous key cleared)
        assert!(manager.unwrap_dek(&wrapped_v1).is_err());
    }
}
