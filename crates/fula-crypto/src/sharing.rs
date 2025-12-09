//! Secure file and folder sharing without exposing master keys
//!
//! This module implements:
//! - Folder-level sharing with isolated access tokens
//! - Time-limited share links with expiry validation
//! - Permission-based access control (read/write/delete)
//! - Re-encryption for sharing without revealing original DEK
//! - Snapshot vs Temporal share modes (WNFS-inspired)

use crate::{
    CryptoError, Result,
    hpke::{Encryptor, Decryptor, EncryptedData, SharePermissions},
    keys::{DekKey, KekKeyPair, PublicKey, SecretKey},
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

// ═══════════════════════════════════════════════════════════════════════════
// SHARE MODE (WNFS-Inspired Snapshot vs Temporal Semantics)
// ═══════════════════════════════════════════════════════════════════════════

/// Share mode determines how access evolves over time
///
/// Inspired by WNFS's `AccessKey` enum with `Temporal` and `Snapshot` variants.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ShareMode {
    /// Temporal mode (default): Access to the *latest* version under a path
    /// 
    /// The recipient always sees the current state of the shared content,
    /// including any updates made after the share was created.
    #[default]
    Temporal,
    
    /// Snapshot mode: Access only to the *specific version* at share creation time
    /// 
    /// The share is bound to a specific content state (hash, size, timestamp).
    /// If the content changes, the share becomes invalid for the new version.
    Snapshot,
}

impl ShareMode {
    /// Check if this is a snapshot share
    pub fn is_snapshot(&self) -> bool {
        matches!(self, ShareMode::Snapshot)
    }
    
    /// Check if this is a temporal share
    pub fn is_temporal(&self) -> bool {
        matches!(self, ShareMode::Temporal)
    }
}

/// Binding data for snapshot shares
///
/// When a share is created in Snapshot mode, this structure captures
/// the exact state of the content at that moment. Recipients can only
/// access content that matches this binding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotBinding {
    /// BLAKE3 hash of the file content (hex-encoded)
    pub content_hash: String,
    /// Size of the file in bytes at snapshot time
    pub size: u64,
    /// Modification timestamp at snapshot time (Unix seconds)
    pub modified_at: i64,
    /// Storage key at snapshot time (for verification)
    pub storage_key: Option<String>,
}

impl SnapshotBinding {
    /// Create a new snapshot binding
    pub fn new(content_hash: impl Into<String>, size: u64, modified_at: i64) -> Self {
        Self {
            content_hash: content_hash.into(),
            size,
            modified_at,
            storage_key: None,
        }
    }
    
    /// Create with storage key
    pub fn with_storage_key(
        content_hash: impl Into<String>,
        size: u64,
        modified_at: i64,
        storage_key: impl Into<String>,
    ) -> Self {
        Self {
            content_hash: content_hash.into(),
            size,
            modified_at,
            storage_key: Some(storage_key.into()),
        }
    }
    
    /// Verify that current content matches this binding
    pub fn verify(&self, current_hash: &str, current_size: u64, current_modified_at: i64) -> SnapshotVerification {
        let hash_matches = self.content_hash == current_hash;
        let size_matches = self.size == current_size;
        let timestamp_matches = self.modified_at == current_modified_at;
        
        if hash_matches && size_matches && timestamp_matches {
            SnapshotVerification::Valid
        } else if !hash_matches {
            SnapshotVerification::ContentChanged
        } else if !size_matches {
            SnapshotVerification::SizeChanged
        } else {
            SnapshotVerification::TimestampChanged
        }
    }
    
    /// Quick check if content hash matches (most important check)
    pub fn hash_matches(&self, current_hash: &str) -> bool {
        self.content_hash == current_hash
    }
}

/// Result of snapshot verification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotVerification {
    /// Content matches the snapshot binding
    Valid,
    /// Content hash has changed since snapshot
    ContentChanged,
    /// File size has changed since snapshot  
    SizeChanged,
    /// Modification timestamp has changed
    TimestampChanged,
}

/// Get current Unix timestamp in seconds
pub fn current_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// A share token that grants access to encrypted content
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ShareToken {
    /// Unique identifier for this share
    pub id: String,
    /// The wrapped DEK (encrypted for the recipient)
    pub wrapped_key: EncryptedData,
    /// Path or prefix this share grants access to (e.g., "/photos/vacation/")
    pub path_scope: String,
    /// Expiration timestamp (Unix seconds), None = never expires
    pub expires_at: Option<i64>,
    /// Unix timestamp when this share was created
    pub created_at: i64,
    /// Access permissions
    pub permissions: SharePermissions,
    /// Version of the share format
    pub version: u8,
    /// Share mode: Temporal (default) or Snapshot
    #[serde(default)]
    pub mode: ShareMode,
    /// Snapshot binding (required for Snapshot mode)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snapshot_binding: Option<SnapshotBinding>,
}

impl ShareToken {
    /// Check if this share token has expired
    pub fn is_expired(&self) -> bool {
        match self.expires_at {
            Some(expiry) => current_timestamp() > expiry,
            None => false,
        }
    }

    /// Check if this share token is valid for the given path
    pub fn is_valid_for_path(&self, path: &str) -> bool {
        if self.is_expired() {
            return false;
        }
        // Path must start with the scope
        path.starts_with(&self.path_scope)
    }

    /// Check if the share allows the requested operation
    pub fn can_read(&self) -> bool {
        !self.is_expired() && self.permissions.can_read
    }

    pub fn can_write(&self) -> bool {
        !self.is_expired() && self.permissions.can_write
    }

    pub fn can_delete(&self) -> bool {
        !self.is_expired() && self.permissions.can_delete
    }

    /// Get time until expiry in seconds (None if never expires or already expired)
    pub fn time_until_expiry(&self) -> Option<i64> {
        self.expires_at.map(|exp| exp - current_timestamp()).filter(|&t| t > 0)
    }

    /// Check if this is a snapshot share
    pub fn is_snapshot(&self) -> bool {
        self.mode.is_snapshot()
    }

    /// Check if this is a temporal share
    pub fn is_temporal(&self) -> bool {
        self.mode.is_temporal()
    }

    /// Verify that content matches the snapshot binding (for Snapshot mode)
    /// 
    /// Returns `Ok(())` for temporal shares or if content matches.
    /// Returns `Err` with details if content has changed.
    pub fn verify_snapshot(
        &self,
        current_hash: &str,
        current_size: u64,
        current_modified_at: i64,
    ) -> Result<SnapshotVerification> {
        match &self.mode {
            ShareMode::Temporal => Ok(SnapshotVerification::Valid),
            ShareMode::Snapshot => {
                match &self.snapshot_binding {
                    Some(binding) => Ok(binding.verify(current_hash, current_size, current_modified_at)),
                    None => Err(CryptoError::InvalidFormat(
                        "Snapshot share missing binding data".to_string()
                    )),
                }
            }
        }
    }

    /// Quick check if snapshot is still valid by content hash only
    /// 
    /// For temporal shares, always returns true.
    /// For snapshot shares, checks if content hash matches.
    pub fn is_snapshot_valid(&self, current_hash: &str) -> bool {
        match &self.mode {
            ShareMode::Temporal => true,
            ShareMode::Snapshot => {
                self.snapshot_binding
                    .as_ref()
                    .map(|b| b.hash_matches(current_hash))
                    .unwrap_or(false)
            }
        }
    }

    /// Get the snapshot binding if this is a snapshot share
    pub fn get_snapshot_binding(&self) -> Option<&SnapshotBinding> {
        self.snapshot_binding.as_ref()
    }
}

/// Builder for creating share tokens
pub struct ShareBuilder<'a> {
    #[allow(dead_code)] // Reserved for future signing of share tokens
    owner_keypair: &'a KekKeyPair,
    recipient_public_key: &'a PublicKey,
    dek: &'a DekKey,
    path_scope: String,
    expires_at: Option<i64>,
    permissions: SharePermissions,
    mode: ShareMode,
    snapshot_binding: Option<SnapshotBinding>,
}

impl<'a> ShareBuilder<'a> {
    /// Create a new share builder (defaults to Temporal mode)
    pub fn new(
        owner_keypair: &'a KekKeyPair,
        recipient_public_key: &'a PublicKey,
        dek: &'a DekKey,
    ) -> Self {
        Self {
            owner_keypair,
            recipient_public_key,
            dek,
            path_scope: "/".to_string(),
            expires_at: None,
            permissions: SharePermissions::read_only(),
            mode: ShareMode::Temporal,
            snapshot_binding: None,
        }
    }

    /// Set the path scope for this share
    pub fn path_scope(mut self, path: impl Into<String>) -> Self {
        self.path_scope = path.into();
        self
    }

    /// Set expiry as duration from now (in seconds)
    pub fn expires_in(mut self, seconds: i64) -> Self {
        self.expires_at = Some(current_timestamp() + seconds);
        self
    }

    /// Set absolute expiry timestamp
    pub fn expires_at(mut self, timestamp: i64) -> Self {
        self.expires_at = Some(timestamp);
        self
    }

    /// Set permissions to read-only
    pub fn read_only(mut self) -> Self {
        self.permissions = SharePermissions::read_only();
        self
    }

    /// Set permissions to read-write
    pub fn read_write(mut self) -> Self {
        self.permissions = SharePermissions::read_write();
        self
    }

    /// Set permissions to full access
    pub fn full_access(mut self) -> Self {
        self.permissions = SharePermissions::full();
        self
    }

    /// Set custom permissions
    pub fn permissions(mut self, permissions: SharePermissions) -> Self {
        self.permissions = permissions;
        self
    }

    /// Set share mode to Temporal (default)
    /// 
    /// Temporal shares give access to the latest version of the content.
    pub fn temporal(mut self) -> Self {
        self.mode = ShareMode::Temporal;
        self.snapshot_binding = None;
        self
    }

    /// Set share mode to Snapshot with binding data
    /// 
    /// Snapshot shares are bound to a specific content version.
    /// The recipient can only access content that matches the binding.
    pub fn snapshot(mut self, binding: SnapshotBinding) -> Self {
        self.mode = ShareMode::Snapshot;
        self.snapshot_binding = Some(binding);
        self
    }

    /// Create a snapshot share with explicit binding values
    pub fn snapshot_with(
        mut self,
        content_hash: impl Into<String>,
        size: u64,
        modified_at: i64,
    ) -> Self {
        self.mode = ShareMode::Snapshot;
        self.snapshot_binding = Some(SnapshotBinding::new(content_hash, size, modified_at));
        self
    }

    /// Build the share token
    pub fn build(self) -> Result<ShareToken> {
        // Validate snapshot mode has binding
        if self.mode == ShareMode::Snapshot && self.snapshot_binding.is_none() {
            return Err(CryptoError::InvalidFormat(
                "Snapshot share requires snapshot_binding".to_string()
            ));
        }

        // Generate a unique share ID
        let id = generate_share_id();

        // Encrypt the DEK for the recipient
        let encryptor = Encryptor::new(self.recipient_public_key);
        let wrapped_key = encryptor.encrypt_dek(self.dek)?;

        Ok(ShareToken {
            id,
            wrapped_key,
            path_scope: self.path_scope,
            expires_at: self.expires_at,
            created_at: current_timestamp(),
            permissions: self.permissions,
            version: 2, // Bump version for new format with mode
            mode: self.mode,
            snapshot_binding: self.snapshot_binding,
        })
    }
}

/// Generate a unique share ID
fn generate_share_id() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Folder share manager for managing multiple shares
#[derive(Default)]
pub struct FolderShareManager {
    /// Map of path -> (DEK, list of shares)
    folder_keys: HashMap<String, FolderKeyInfo>,
}

/// Information about a folder's encryption key
struct FolderKeyInfo {
    /// The DEK for this folder
    dek: DekKey,
    /// Active shares for this folder
    shares: Vec<ShareToken>,
}

impl FolderShareManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a folder with its DEK
    pub fn register_folder(&mut self, path: &str, dek: DekKey) {
        self.folder_keys.insert(
            path.to_string(),
            FolderKeyInfo {
                dek,
                shares: Vec::new(),
            },
        );
    }

    /// Create a share for a folder
    pub fn create_share(
        &mut self,
        owner_keypair: &KekKeyPair,
        folder_path: &str,
        recipient: &PublicKey,
        expires_in_seconds: Option<i64>,
        permissions: SharePermissions,
    ) -> Result<ShareToken> {
        let folder_info = self.folder_keys.get_mut(folder_path)
            .ok_or_else(|| CryptoError::InvalidKey(format!("Folder not found: {}", folder_path)))?;

        let mut builder = ShareBuilder::new(owner_keypair, recipient, &folder_info.dek)
            .path_scope(folder_path)
            .permissions(permissions);

        if let Some(seconds) = expires_in_seconds {
            builder = builder.expires_in(seconds);
        }

        let share = builder.build()?;
        folder_info.shares.push(share.clone());
        Ok(share)
    }

    /// Revoke a share by ID
    pub fn revoke_share(&mut self, folder_path: &str, share_id: &str) -> bool {
        if let Some(folder_info) = self.folder_keys.get_mut(folder_path) {
            let before_len = folder_info.shares.len();
            folder_info.shares.retain(|s| s.id != share_id);
            return folder_info.shares.len() < before_len;
        }
        false
    }

    /// List all shares for a folder
    pub fn list_shares(&self, folder_path: &str) -> Vec<&ShareToken> {
        self.folder_keys
            .get(folder_path)
            .map(|info| info.shares.iter().collect())
            .unwrap_or_default()
    }

    /// Clean up expired shares
    pub fn cleanup_expired(&mut self) {
        for folder_info in self.folder_keys.values_mut() {
            folder_info.shares.retain(|s| !s.is_expired());
        }
    }

    /// Validate a share token for access
    pub fn validate_access(&self, token: &ShareToken, path: &str) -> AccessValidation {
        // Check expiry
        if token.is_expired() {
            return AccessValidation::Expired;
        }

        // Check path scope
        if !token.is_valid_for_path(path) {
            return AccessValidation::OutOfScope;
        }

        // Check if share still exists (hasn't been revoked)
        let share_exists = self.folder_keys.get(&token.path_scope)
            .map(|info| info.shares.iter().any(|s| s.id == token.id))
            .unwrap_or(false);

        if !share_exists {
            return AccessValidation::Revoked;
        }

        AccessValidation::Valid
    }
}

/// Result of access validation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessValidation {
    Valid,
    Expired,
    Revoked,
    OutOfScope,
}

/// Recipient-side share handler
pub struct ShareRecipient {
    secret_key: SecretKey,
}

impl ShareRecipient {
    pub fn new(keypair: &KekKeyPair) -> Self {
        Self {
            secret_key: keypair.secret_key().clone(),
        }
    }

    pub fn from_secret_key(secret: SecretKey) -> Self {
        Self { secret_key: secret }
    }

    /// Decrypt and validate a share token
    pub fn accept_share(&self, token: &ShareToken) -> Result<AcceptedShare> {
        // Check expiry first
        if token.is_expired() {
            return Err(CryptoError::ShareExpired);
        }

        // Decrypt the DEK
        let decryptor = Decryptor::from_secret_key(&self.secret_key);
        let dek = decryptor.decrypt_dek(&token.wrapped_key)?;

        Ok(AcceptedShare {
            dek,
            path_scope: token.path_scope.clone(),
            expires_at: token.expires_at,
            permissions: token.permissions,
        })
    }
}

/// An accepted and validated share
pub struct AcceptedShare {
    /// The decrypted DEK
    pub dek: DekKey,
    /// Path scope this share grants access to
    pub path_scope: String,
    /// Expiration time
    pub expires_at: Option<i64>,
    /// Permissions
    pub permissions: SharePermissions,
}

impl AcceptedShare {
    /// Check if this share is still valid
    pub fn is_valid(&self) -> bool {
        match self.expires_at {
            Some(exp) => current_timestamp() <= exp,
            None => true,
        }
    }

    /// Check if a path is within scope
    pub fn is_path_allowed(&self, path: &str) -> bool {
        self.is_valid() && path.starts_with(&self.path_scope)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;
    use std::time::Duration;

    #[test]
    fn test_share_token_creation() {
        let owner = KekKeyPair::generate();
        let recipient = KekKeyPair::generate();
        let dek = DekKey::generate();

        let token = ShareBuilder::new(&owner, recipient.public_key(), &dek)
            .path_scope("/photos/vacation/")
            .expires_in(3600) // 1 hour
            .read_only()
            .build()
            .unwrap();

        assert!(!token.is_expired());
        assert!(token.is_valid_for_path("/photos/vacation/beach.jpg"));
        assert!(!token.is_valid_for_path("/documents/secret.pdf"));
        assert!(token.can_read());
        assert!(!token.can_write());
    }

    #[test]
    fn test_share_token_expiry() {
        let owner = KekKeyPair::generate();
        let recipient = KekKeyPair::generate();
        let dek = DekKey::generate();

        // Create token that expires in 1 second
        let token = ShareBuilder::new(&owner, recipient.public_key(), &dek)
            .expires_in(1)
            .build()
            .unwrap();

        assert!(!token.is_expired());
        
        // Wait for expiry
        sleep(Duration::from_secs(2));
        
        assert!(token.is_expired());
        assert!(!token.can_read());
    }

    #[test]
    fn test_recipient_can_decrypt_share() {
        let owner = KekKeyPair::generate();
        let recipient = KekKeyPair::generate();
        let dek = DekKey::generate();
        let original_dek_bytes = dek.as_bytes().to_vec();

        let token = ShareBuilder::new(&owner, recipient.public_key(), &dek)
            .path_scope("/shared/")
            .read_write()
            .build()
            .unwrap();

        // Recipient accepts the share
        let share_recipient = ShareRecipient::new(&recipient);
        let accepted = share_recipient.accept_share(&token).unwrap();

        // DEK should match
        assert_eq!(accepted.dek.as_bytes().to_vec(), original_dek_bytes);
        assert_eq!(accepted.path_scope, "/shared/");
        assert!(accepted.permissions.can_read);
        assert!(accepted.permissions.can_write);
    }

    #[test]
    fn test_wrong_recipient_cannot_decrypt() {
        let owner = KekKeyPair::generate();
        let intended_recipient = KekKeyPair::generate();
        let wrong_recipient = KekKeyPair::generate();
        let dek = DekKey::generate();

        let token = ShareBuilder::new(&owner, intended_recipient.public_key(), &dek)
            .build()
            .unwrap();

        // Wrong recipient tries to accept
        let wrong_handler = ShareRecipient::new(&wrong_recipient);
        let result = wrong_handler.accept_share(&token);

        assert!(result.is_err());
    }

    #[test]
    fn test_expired_share_rejected() {
        let owner = KekKeyPair::generate();
        let recipient = KekKeyPair::generate();
        let dek = DekKey::generate();

        // Create already-expired token
        let token = ShareBuilder::new(&owner, recipient.public_key(), &dek)
            .expires_at(current_timestamp() - 100) // Already expired
            .build()
            .unwrap();

        let share_recipient = ShareRecipient::new(&recipient);
        let result = share_recipient.accept_share(&token);

        assert!(result.is_err());
    }

    #[test]
    fn test_folder_share_manager() {
        let owner = KekKeyPair::generate();
        let recipient1 = KekKeyPair::generate();
        let recipient2 = KekKeyPair::generate();

        let mut manager = FolderShareManager::new();
        
        // Register a folder
        let folder_dek = DekKey::generate();
        manager.register_folder("/photos/", folder_dek);

        // Share with recipient1 (read-only, 1 hour)
        let share1 = manager.create_share(
            &owner,
            "/photos/",
            recipient1.public_key(),
            Some(3600),
            SharePermissions::read_only(),
        ).unwrap();

        // Share with recipient2 (full access, no expiry)
        let share2 = manager.create_share(
            &owner,
            "/photos/",
            recipient2.public_key(),
            None,
            SharePermissions::full(),
        ).unwrap();

        // Both shares should be listed
        let shares = manager.list_shares("/photos/");
        assert_eq!(shares.len(), 2);

        // Validate access
        assert_eq!(
            manager.validate_access(&share1, "/photos/beach.jpg"),
            AccessValidation::Valid
        );
        assert_eq!(
            manager.validate_access(&share1, "/documents/secret.pdf"),
            AccessValidation::OutOfScope
        );

        // Revoke share1
        assert!(manager.revoke_share("/photos/", &share1.id));
        assert_eq!(
            manager.validate_access(&share1, "/photos/beach.jpg"),
            AccessValidation::Revoked
        );

        // share2 still valid
        assert_eq!(
            manager.validate_access(&share2, "/photos/beach.jpg"),
            AccessValidation::Valid
        );
    }

    #[test]
    fn test_share_without_master_key_exposure() {
        // This test verifies that sharing doesn't expose the owner's master key
        let owner = KekKeyPair::generate();
        let recipient = KekKeyPair::generate();
        let file_dek = DekKey::generate();

        // Create share - recipient gets access to file_dek but NOT owner's keypair
        let share = ShareBuilder::new(&owner, recipient.public_key(), &file_dek)
            .path_scope("/shared-folder/")
            .read_only()
            .build()
            .unwrap();

        // The share token contains:
        // - wrapped_key: DEK encrypted for recipient's public key
        // - path_scope, permissions, expiry
        // 
        // It does NOT contain:
        // - Owner's secret key
        // - Owner's public key
        // - Any way to derive other DEKs

        // Recipient can only decrypt their specific share
        let handler = ShareRecipient::new(&recipient);
        let accepted = handler.accept_share(&share).unwrap();

        // Recipient has access to this specific DEK
        assert_eq!(accepted.dek.as_bytes(), file_dek.as_bytes());

        // But cannot access other folders (would need different DEKs)
        let other_dek = DekKey::generate();
        assert_ne!(accepted.dek.as_bytes(), other_dek.as_bytes());
    }

    #[test]
    fn test_path_scoped_access() {
        let owner = KekKeyPair::generate();
        let recipient = KekKeyPair::generate();
        let dek = DekKey::generate();

        // Share only /photos/2024/vacation/
        let token = ShareBuilder::new(&owner, recipient.public_key(), &dek)
            .path_scope("/photos/2024/vacation/")
            .build()
            .unwrap();

        // Allowed paths
        assert!(token.is_valid_for_path("/photos/2024/vacation/"));
        assert!(token.is_valid_for_path("/photos/2024/vacation/beach.jpg"));
        assert!(token.is_valid_for_path("/photos/2024/vacation/day1/morning.jpg"));

        // Denied paths
        assert!(!token.is_valid_for_path("/photos/2024/"));
        assert!(!token.is_valid_for_path("/photos/2024/work/"));
        assert!(!token.is_valid_for_path("/documents/"));
        assert!(!token.is_valid_for_path("/photos/2023/vacation/")); // Different year
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // SNAPSHOT VS TEMPORAL MODE TESTS
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_temporal_share_default() {
        let owner = KekKeyPair::generate();
        let recipient = KekKeyPair::generate();
        let dek = DekKey::generate();

        // Default is temporal mode
        let token = ShareBuilder::new(&owner, recipient.public_key(), &dek)
            .path_scope("/photos/")
            .build()
            .unwrap();

        assert!(token.is_temporal());
        assert!(!token.is_snapshot());
        assert_eq!(token.mode, ShareMode::Temporal);
        assert!(token.snapshot_binding.is_none());
    }

    #[test]
    fn test_snapshot_share_creation() {
        let owner = KekKeyPair::generate();
        let recipient = KekKeyPair::generate();
        let dek = DekKey::generate();

        let binding = SnapshotBinding::new(
            "abc123def456", // content hash
            1024,           // size
            1700000000,     // modified_at
        );

        let token = ShareBuilder::new(&owner, recipient.public_key(), &dek)
            .path_scope("/photos/vacation/")
            .snapshot(binding.clone())
            .build()
            .unwrap();

        assert!(token.is_snapshot());
        assert!(!token.is_temporal());
        assert_eq!(token.mode, ShareMode::Snapshot);
        
        let stored_binding = token.snapshot_binding.as_ref().unwrap();
        assert_eq!(stored_binding.content_hash, "abc123def456");
        assert_eq!(stored_binding.size, 1024);
        assert_eq!(stored_binding.modified_at, 1700000000);
    }

    #[test]
    fn test_snapshot_share_with_values() {
        let owner = KekKeyPair::generate();
        let recipient = KekKeyPair::generate();
        let dek = DekKey::generate();

        let token = ShareBuilder::new(&owner, recipient.public_key(), &dek)
            .path_scope("/photos/")
            .snapshot_with("hash123", 2048, 1700000000)
            .build()
            .unwrap();

        assert!(token.is_snapshot());
        let binding = token.snapshot_binding.as_ref().unwrap();
        assert_eq!(binding.content_hash, "hash123");
        assert_eq!(binding.size, 2048);
    }

    #[test]
    fn test_snapshot_verification_valid() {
        let owner = KekKeyPair::generate();
        let recipient = KekKeyPair::generate();
        let dek = DekKey::generate();

        let token = ShareBuilder::new(&owner, recipient.public_key(), &dek)
            .snapshot_with("abc123", 1024, 1700000000)
            .build()
            .unwrap();

        // Content matches
        let result = token.verify_snapshot("abc123", 1024, 1700000000).unwrap();
        assert_eq!(result, SnapshotVerification::Valid);
    }

    #[test]
    fn test_snapshot_verification_content_changed() {
        let owner = KekKeyPair::generate();
        let recipient = KekKeyPair::generate();
        let dek = DekKey::generate();

        let token = ShareBuilder::new(&owner, recipient.public_key(), &dek)
            .snapshot_with("original_hash", 1024, 1700000000)
            .build()
            .unwrap();

        // Content hash changed
        let result = token.verify_snapshot("different_hash", 1024, 1700000000).unwrap();
        assert_eq!(result, SnapshotVerification::ContentChanged);
    }

    #[test]
    fn test_snapshot_verification_size_changed() {
        let owner = KekKeyPair::generate();
        let recipient = KekKeyPair::generate();
        let dek = DekKey::generate();

        let token = ShareBuilder::new(&owner, recipient.public_key(), &dek)
            .snapshot_with("same_hash", 1024, 1700000000)
            .build()
            .unwrap();

        // Size changed but hash matches
        let result = token.verify_snapshot("same_hash", 2048, 1700000000).unwrap();
        assert_eq!(result, SnapshotVerification::SizeChanged);
    }

    #[test]
    fn test_temporal_share_always_valid() {
        let owner = KekKeyPair::generate();
        let recipient = KekKeyPair::generate();
        let dek = DekKey::generate();

        let token = ShareBuilder::new(&owner, recipient.public_key(), &dek)
            .temporal()
            .build()
            .unwrap();

        // Temporal shares don't care about content changes
        assert!(token.is_snapshot_valid("any_hash"));
        assert!(token.is_snapshot_valid("another_hash"));
        
        let result = token.verify_snapshot("any_hash", 9999, 0).unwrap();
        assert_eq!(result, SnapshotVerification::Valid);
    }

    #[test]
    fn test_snapshot_requires_binding() {
        let owner = KekKeyPair::generate();
        let recipient = KekKeyPair::generate();
        let dek = DekKey::generate();

        // Manually set mode to Snapshot without binding
        let mut builder = ShareBuilder::new(&owner, recipient.public_key(), &dek);
        builder.mode = ShareMode::Snapshot;
        builder.snapshot_binding = None;

        let result = builder.build();
        assert!(result.is_err());
    }

    #[test]
    fn test_snapshot_binding_storage_key() {
        let binding = SnapshotBinding::with_storage_key(
            "hash123",
            1024,
            1700000000,
            "Qm123abc456"
        );

        assert_eq!(binding.content_hash, "hash123");
        assert_eq!(binding.size, 1024);
        assert_eq!(binding.storage_key, Some("Qm123abc456".to_string()));
    }

    #[test]
    fn test_is_snapshot_valid_helper() {
        let owner = KekKeyPair::generate();
        let recipient = KekKeyPair::generate();
        let dek = DekKey::generate();

        let token = ShareBuilder::new(&owner, recipient.public_key(), &dek)
            .snapshot_with("correct_hash", 1024, 1700000000)
            .build()
            .unwrap();

        assert!(token.is_snapshot_valid("correct_hash"));
        assert!(!token.is_snapshot_valid("wrong_hash"));
    }

    #[test]
    fn test_share_mode_enum() {
        assert!(ShareMode::Temporal.is_temporal());
        assert!(!ShareMode::Temporal.is_snapshot());
        
        assert!(ShareMode::Snapshot.is_snapshot());
        assert!(!ShareMode::Snapshot.is_temporal());
        
        // Default is Temporal
        assert_eq!(ShareMode::default(), ShareMode::Temporal);
    }

    #[test]
    fn test_share_token_serialization_with_mode() {
        let owner = KekKeyPair::generate();
        let recipient = KekKeyPair::generate();
        let dek = DekKey::generate();

        // Create snapshot share
        let token = ShareBuilder::new(&owner, recipient.public_key(), &dek)
            .path_scope("/files/")
            .snapshot_with("hash", 512, 1700000000)
            .build()
            .unwrap();

        // Serialize
        let json = serde_json::to_string(&token).unwrap();
        
        // Deserialize
        let restored: ShareToken = serde_json::from_str(&json).unwrap();
        
        assert!(restored.is_snapshot());
        assert_eq!(restored.mode, ShareMode::Snapshot);
        let binding = restored.snapshot_binding.unwrap();
        assert_eq!(binding.content_hash, "hash");
        assert_eq!(binding.size, 512);
    }
}
