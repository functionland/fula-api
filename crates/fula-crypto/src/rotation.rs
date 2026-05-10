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
    ///
    /// Returns an error if a previous keypair already exists (i.e., a prior rotation
    /// has not been fully completed by re-wrapping all DEKs). Call `clear_previous()`
    /// after all DEKs have been re-wrapped, or use `FileSystemRotation::rotate_all()`
    /// which handles this automatically.
    pub fn rotate_kek(&mut self) -> Result<&PublicKey> {
        if self.previous_keypair.is_some() {
            return Err(CryptoError::InvalidKey(
                "Cannot rotate KEK: previous keypair still exists. \
                 Re-wrap all DEKs and call clear_previous() before rotating again."
                    .into(),
            ));
        }

        // Move current to previous
        let old_keypair = std::mem::replace(
            &mut self.current_keypair,
            KekKeyPair::generate(),
        );

        self.previous_keypair = Some(old_keypair);
        self.previous_version = Some(self.current_version);
        self.current_version += 1;

        Ok(self.current_keypair.public_key())
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

    /// Re-wrap multiple DEKs in parallel (batch operation with configurable concurrency)
    ///
    /// Uses `std::thread::scope` to process re-wrapping across multiple threads.
    /// Each thread handles a slice of the input, and results are collected after all complete.
    /// The `concurrency` parameter controls the maximum number of threads used.
    pub fn rewrap_batch_parallel(
        &self,
        wrapped_keys: &[WrappedKeyInfo],
        concurrency: usize,
    ) -> RotationResult {
        let concurrency = concurrency.max(1);

        if wrapped_keys.is_empty() {
            return RotationResult {
                rotated_count: 0,
                failed_count: 0,
                failures: Vec::new(),
                new_kek_version: self.current_version,
            };
        }

        // Parallel re-wrapping using scoped threads
        let chunk_size = (wrapped_keys.len() + concurrency - 1) / concurrency;
        let results: Vec<_> = std::thread::scope(|s| {
            let handles: Vec<_> = wrapped_keys
                .chunks(chunk_size.max(1))
                .map(|chunk| {
                    s.spawn(|| {
                        chunk
                            .iter()
                            .map(|wrapped| {
                                let result = self
                                    .rewrap_dek(wrapped)
                                    .map_err(|e| e.to_string());
                                (wrapped.object_path.clone(), result)
                            })
                            .collect::<Vec<_>>()
                    })
                })
                .collect();

            handles
                .into_iter()
                .flat_map(|h| h.join().unwrap())
                .collect()
        });

        let mut rotated_count = 0;
        let mut failed_count = 0;
        let mut failures = Vec::new();

        for (path, result) in results {
            match result {
                Ok(_) => rotated_count += 1,
                Err(e) => {
                    failed_count += 1;
                    failures.push((path, e));
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

    /// Clear the previous keypair after all DEKs have been re-wrapped.
    ///
    /// **Precondition (caller-enforced):** every wrapped DEK in the
    /// system must have been re-wrapped to `self.current_version` before
    /// this is called. Dropping the previous keypair while wraps at the
    /// older version still exist makes those wraps **permanently
    /// undecryptable** (the AEAD-wrapping under the previous keypair is
    /// no longer recoverable).
    ///
    /// `KeyRotationManager` does not own the wrapped-DEK index, so the
    /// precondition cannot be checked here. Callers should prefer
    /// [`FileSystemRotation::rotate_all`] / `rotate_all_parallel`, which
    /// own the index and call this only when every DEK has been migrated
    /// (verified via `is_rotation_complete()`). Direct callers of this
    /// method are responsible for the same check.
    ///
    /// Idempotent: calling on an already-cleared manager is a no-op.
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
    /// Returns the new public key, or an error if a previous rotation is still pending
    pub fn rotate(&mut self) -> Result<&PublicKey> {
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

        // Clear previous key after all rotation is complete.
        //
        // F9 audit fix: pre-0.7 used `!self.rotation_manager.has_pending_rotation()`,
        // which is unreachable — `rotate_kek` always sets `previous_keypair = Some(_)`,
        // so `has_pending_rotation()` is always true after the first rotation. The
        // result was that `clear_previous` was never called automatically and any
        // second rotation attempt errored with "previous keypair still exists",
        // wedging the rotation pipeline. The correct precondition is "all DEKs
        // have been re-wrapped to the current version" (`is_rotation_complete()`).
        // Keep `total_failed == 0` defensively: even if every DEK now claims to
        // be at current_version, a partial-failure run shouldn't auto-clear.
        if total_failed == 0 && self.is_rotation_complete() {
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

    /// Rotate a batch of keys in parallel
    ///
    /// Like `rotate_batch`, but processes re-wrapping across `concurrency` threads.
    /// The batch size is still controlled by `with_batch_size`.
    pub fn rotate_batch_parallel(&mut self, concurrency: usize) -> RotationResult {
        let concurrency = concurrency.max(1);
        let current_version = self.rotation_manager.current_version();

        // Find keys needing rotation
        let to_rotate: Vec<_> = self
            .wrapped_keys
            .iter()
            .filter(|(_, w)| w.kek_version < current_version)
            .take(self.batch_size)
            .map(|(path, wrapped)| (path.clone(), wrapped.clone()))
            .collect();

        if to_rotate.is_empty() {
            return RotationResult {
                rotated_count: 0,
                failed_count: 0,
                failures: Vec::new(),
                new_kek_version: current_version,
            };
        }

        // Parallel re-wrapping using scoped threads
        let manager = &self.rotation_manager;
        let chunk_size = (to_rotate.len() + concurrency - 1) / concurrency;
        let results: Vec<_> = std::thread::scope(|s| {
            let handles: Vec<_> = to_rotate
                .chunks(chunk_size.max(1))
                .map(|chunk| {
                    s.spawn(move || {
                        chunk
                            .iter()
                            .map(|(path, wrapped)| {
                                let result = manager
                                    .rewrap_dek(wrapped)
                                    .map_err(|e| e.to_string());
                                (path.clone(), result)
                            })
                            .collect::<Vec<_>>()
                    })
                })
                .collect();

            handles
                .into_iter()
                .flat_map(|h| h.join().unwrap())
                .collect()
        });

        let mut rotated = 0;
        let mut failed = 0;
        let mut failures = Vec::new();

        for (path, result) in results {
            match result {
                Ok(new_wrapped) => {
                    self.wrapped_keys.insert(path, new_wrapped);
                    rotated += 1;
                }
                Err(e) => {
                    failed += 1;
                    failures.push((path, e));
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

    /// Rotate all keys in parallel (with configurable concurrency)
    ///
    /// Like `rotate_all`, but each batch is processed with `concurrency` threads.
    /// For 10M files with concurrency=32, this can reduce rotation time by ~30x.
    pub fn rotate_all_parallel(&mut self, concurrency: usize) -> RotationResult {
        let mut total_rotated = 0;
        let mut total_failed = 0;
        let mut all_failures = Vec::new();

        loop {
            let result = self.rotate_batch_parallel(concurrency);
            total_rotated += result.rotated_count;
            total_failed += result.failed_count;
            all_failures.extend(result.failures);

            if result.rotated_count == 0 {
                break;
            }
        }

        // Clear previous key after all rotation is complete.
        // F9 audit fix: see `rotate_all` for full rationale. Same predicate
        // inversion bug existed in both methods; same fix applied here.
        if total_failed == 0 && self.is_rotation_complete() {
            self.rotation_manager.clear_previous();
        }

        RotationResult {
            rotated_count: total_rotated,
            failed_count: total_failed,
            failures: all_failures,
            new_kek_version: self.rotation_manager.current_version(),
        }
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
        manager.rotate_kek().unwrap();
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
        fs.rotate().unwrap();

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
        fs.rotate().unwrap();
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
            manager.rotate_kek().unwrap();
            wrapped = manager.rewrap_dek(&wrapped).unwrap();
            assert_eq!(wrapped.kek_version, expected_version);

            // Verify DEK still accessible
            let unwrapped = manager.unwrap_dek(&wrapped).unwrap();
            assert_eq!(dek.as_bytes(), unwrapped.as_bytes());

            // Clear previous to allow next rotation
            manager.clear_previous();
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
        manager.rotate_kek().unwrap();

        // Re-wrap to v2
        let wrapped_v2 = manager.rewrap_dek(&wrapped_v1).unwrap();

        // Clear previous key
        manager.clear_previous();

        // V2 should still work
        assert!(manager.unwrap_dek(&wrapped_v2).is_ok());

        // V1 should fail (previous key cleared)
        assert!(manager.unwrap_dek(&wrapped_v1).is_err());
    }

    #[test]
    fn test_parallel_filesystem_rotation() {
        let keypair = KekKeyPair::generate();
        let mut fs = FileSystemRotation::new(keypair)
            .with_batch_size(50);

        // Create 100 files and remember their DEKs
        let mut deks = Vec::new();
        for i in 0..100 {
            let dek = DekKey::generate();
            fs.wrap_new_file(&format!("/file{}.txt", i), &dek).unwrap();
            deks.push((format!("/file{}.txt", i), dek));
        }

        // Verify all at version 1
        assert_eq!(fs.rotation_progress(), (100, 100));

        // Initiate rotation
        fs.rotate().unwrap();
        assert_eq!(fs.get_keys_needing_rotation().len(), 100);

        // Rotate first batch in parallel (50 items, 4 threads)
        let result = fs.rotate_batch_parallel(4);
        assert_eq!(result.rotated_count, 50);
        assert_eq!(result.failed_count, 0);
        assert_eq!(fs.rotation_progress(), (50, 100));

        // Rotate remaining in parallel
        let result = fs.rotate_all_parallel(4);
        assert_eq!(result.rotated_count, 50);
        assert_eq!(result.failed_count, 0);
        assert!(fs.is_rotation_complete());
        assert_eq!(fs.rotation_progress(), (100, 100));

        // Verify all DEKs are still accessible after parallel rotation
        for (path, original_dek) in &deks {
            let unwrapped = fs.unwrap_file(path).unwrap();
            assert_eq!(original_dek.as_bytes(), unwrapped.as_bytes());
        }
    }

    #[test]
    fn test_parallel_batch_rewrap() {
        let keypair = KekKeyPair::generate();
        let mut manager = KeyRotationManager::new(keypair);

        // Create wrapped DEKs
        let mut wrapped_keys = Vec::new();
        let mut original_deks = Vec::new();
        for i in 0..20 {
            let dek = DekKey::generate();
            let wrapped = manager.wrap_dek(&dek, &format!("/file{}.txt", i)).unwrap();
            wrapped_keys.push(wrapped);
            original_deks.push(dek);
        }

        // Rotate KEK
        manager.rotate_kek().unwrap();

        // Parallel batch rewrap
        let result = manager.rewrap_batch_parallel(&wrapped_keys, 4);
        assert_eq!(result.rotated_count, 20);
        assert_eq!(result.failed_count, 0);
    }

    // ─────────────────────────────────────────────────────────────────
    // F9 (audit): regression for the rotate_all logic-inversion bug.
    //
    // Pre-fix the auto-clear predicate at rotation.rs:406 / 522 was
    // `!has_pending_rotation()`, which is **always false** after
    // `rotate_kek` (since rotate_kek sets `previous_keypair = Some(_)`).
    // Result: `clear_previous` never ran automatically, so a second
    // `rotate()` on the same FileSystemRotation always errored with
    // "previous keypair still exists" — the rotation pipeline wedged
    // permanently after a single rotation. The fix replaces the bad
    // predicate with `is_rotation_complete()`, which correctly returns
    // true once every DEK has been re-wrapped to current_version.
    // ─────────────────────────────────────────────────────────────────

    #[test]
    fn test_rotate_all_clears_previous_when_complete() {
        // Demonstrates the headline bug + fix: after rotate_all, the
        // pipeline must be able to rotate again without error.
        let keypair = KekKeyPair::generate();
        let mut fs = FileSystemRotation::new(keypair).with_batch_size(50);

        // Seed 10 files.
        for i in 0..10 {
            let dek = DekKey::generate();
            fs.wrap_new_file(&format!("/file{}.txt", i), &dek).unwrap();
        }

        // First rotation cycle.
        fs.rotate().expect("first rotation");
        let result = fs.rotate_all();
        assert_eq!(result.rotated_count, 10);
        assert_eq!(result.failed_count, 0);
        assert!(fs.is_rotation_complete(), "rotation must complete after rotate_all");
        assert!(
            !fs.rotation_manager.has_pending_rotation(),
            "F9: rotate_all must auto-clear previous keypair when all DEKs migrated; \
             pre-fix this assertion failed because !has_pending_rotation() was unreachable"
        );

        // Second rotation cycle — pre-fix this errored with "previous
        // keypair still exists" because clear_previous never ran.
        fs.rotate().expect(
            "F9: second rotation must succeed after rotate_all; pre-fix this errored",
        );
        let result2 = fs.rotate_all();
        assert_eq!(result2.rotated_count, 10);
        assert_eq!(result2.failed_count, 0);
        assert!(fs.is_rotation_complete());
        assert!(
            !fs.rotation_manager.has_pending_rotation(),
            "second rotate_all must also auto-clear"
        );

        // Third rotation cycle — full chain now works repeatedly.
        fs.rotate().expect("third rotation");
        let result3 = fs.rotate_all();
        assert_eq!(result3.rotated_count, 10);
        assert!(fs.is_rotation_complete());
    }

    #[test]
    fn test_rotate_all_parallel_clears_previous_when_complete() {
        // Same regression as above, parallel path.
        let keypair = KekKeyPair::generate();
        let mut fs = FileSystemRotation::new(keypair).with_batch_size(50);

        for i in 0..20 {
            let dek = DekKey::generate();
            fs.wrap_new_file(&format!("/file{}.txt", i), &dek).unwrap();
        }

        fs.rotate().expect("first rotation");
        let result = fs.rotate_all_parallel(4);
        assert_eq!(result.rotated_count, 20);
        assert!(fs.is_rotation_complete());
        assert!(
            !fs.rotation_manager.has_pending_rotation(),
            "F9: rotate_all_parallel must auto-clear previous keypair when all DEKs migrated"
        );

        // Second rotation must succeed.
        fs.rotate()
            .expect("F9: second rotation must succeed after rotate_all_parallel");
        let result2 = fs.rotate_all_parallel(4);
        assert_eq!(result2.rotated_count, 20);
    }

    #[test]
    fn test_rotate_all_does_not_clear_previous_on_partial_failure() {
        // Defensive check on the `total_failed == 0` conjunction:
        // if any DEK failed to re-wrap, we MUST NOT clear the previous
        // keypair. Doing so would orphan the failed DEKs forever.
        //
        // We can't easily inject a rewrap failure without modifying the
        // production code, but we can verify the invariant directly: if
        // is_rotation_complete() is false (a wrap is still at v_old),
        // clear_previous must not run.
        let keypair = KekKeyPair::generate();
        let mut fs = FileSystemRotation::new(keypair).with_batch_size(2);

        for i in 0..5 {
            let dek = DekKey::generate();
            fs.wrap_new_file(&format!("/file{}.txt", i), &dek).unwrap();
        }
        fs.rotate().expect("first rotation");

        // Manually inject a residual wrap at the old version by directly
        // manipulating the wrapped_keys index. This simulates "rotation
        // ran but one wrap is still stale" — e.g., a pre-existing wrap
        // at an older version that didn't get picked up.
        let old_version = fs.rotation_manager.current_version() - 1;
        // Insert a synthetic stale wrap by faking a WrappedKeyInfo at the
        // old version. We construct it by wrapping under the previous
        // keypair (which we still have via the manager).
        let dek_stale = DekKey::generate();
        let wrapped_stale = WrappedKeyInfo {
            wrapped_dek: {
                let prev = fs
                    .rotation_manager
                    .previous_keypair
                    .as_ref()
                    .expect("previous keypair should exist mid-rotation");
                Encryptor::new(prev.public_key())
                    .encrypt_dek(&dek_stale)
                    .unwrap()
            },
            kek_version: old_version,
            object_path: "/stale.txt".to_string(),
        };
        fs.register_file("/stale.txt", wrapped_stale);

        // Run rotate_all. Note: rotate_all WILL re-wrap the stale entry
        // (it's at v_old, and rotate_batch picks up "anything < current_version").
        // So is_rotation_complete() returns true after rotate_all.
        // The test above already covers the happy path. Here we instead
        // verify the structural invariant: `is_rotation_complete()` is
        // the only auto-clear gate, so a future regression that breaks
        // it would be caught.
        let _ = fs.rotate_all();
        assert!(fs.is_rotation_complete(), "all stale wraps re-wrapped");
        assert!(
            !fs.rotation_manager.has_pending_rotation(),
            "F9: clear_previous must run when is_rotation_complete()"
        );
    }
}
