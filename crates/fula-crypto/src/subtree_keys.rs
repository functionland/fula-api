//! Shallow Cryptree-Style Subtree Keys for Better Revocation
//!
//! Inspired by Peergos's Cryptree design, this module implements a **shallow**
//! key hierarchy where major subtrees (folders) have their own DEKs.
//!
//! # Design Goals
//!
//! 1. **Improved Revocation**: Re-key just one subtree instead of the entire bucket
//! 2. **Least Privilege**: A subtree share cannot access unrelated data
//! 3. **Low Overhead**: Still use a single `PrivateForest` object
//!
//! # Architecture
//!
//! ```text
//! Master DEK (bucket-level)
//!     │
//!     ├── /photos/ ─── Subtree DEK A ─── [beach.jpg, sunset.jpg, ...]
//!     │
//!     ├── /documents/ ─── Subtree DEK B ─── [report.pdf, notes.txt, ...]
//!     │
//!     └── /apps/myapp/ ─── Subtree DEK C ─── [config.json, data.bin, ...]
//!
//! Sharing /photos/ only exposes Subtree DEK A.
//! Revoking that share only requires re-keying /photos/, not the whole bucket.
//! ```
//!
//! # Reference
//!
//! - Peergos Cryptree: `book.peergos.org/security/cryptree.html`
//! - Peergos source: `src/peergos/shared/user/fs/cryptree/CryptreeNode.java`

use crate::{
    CryptoError, Result,
    keys::DekKey,
    hpke::{EncryptedData, Encryptor, Decryptor, SharePermissions},
    keys::{KekKeyPair, PublicKey, SecretKey},
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Get current Unix timestamp in seconds
fn current_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

// ═══════════════════════════════════════════════════════════════════════════
// SUBTREE DEK - Encrypted subtree key stored in directory entries
// ═══════════════════════════════════════════════════════════════════════════

/// An encrypted subtree DEK, stored in directory entries
/// 
/// The subtree DEK is encrypted with the parent's DEK (or master DEK for top-level).
/// This creates a chain of keys where having access to a parent gives access to children.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedSubtreeDek {
    /// The encrypted DEK bytes
    pub ciphertext: Vec<u8>,
    /// Nonce used for encryption
    pub nonce: Vec<u8>,
    /// Version of the subtree key (for rotation tracking)
    pub version: u32,
    /// Creation timestamp
    pub created_at: i64,
}

impl EncryptedSubtreeDek {
    /// Encrypt a subtree DEK with a parent DEK
    pub fn encrypt(subtree_dek: &DekKey, parent_dek: &DekKey, version: u32) -> Result<Self> {
        use crate::symmetric::{Aead, Nonce};
        
        let nonce = Nonce::generate();
        let aead = Aead::new_default(parent_dek);
        let ciphertext = aead.encrypt(&nonce, subtree_dek.as_bytes())?;
        
        Ok(Self {
            ciphertext,
            nonce: nonce.as_bytes().to_vec(),
            version,
            created_at: current_timestamp(),
        })
    }
    
    /// Decrypt to get the subtree DEK
    pub fn decrypt(&self, parent_dek: &DekKey) -> Result<DekKey> {
        use crate::symmetric::{Aead, Nonce};
        
        let nonce = Nonce::from_bytes(&self.nonce)?;
        let aead = Aead::new_default(parent_dek);
        let plaintext = aead.decrypt(&nonce, &self.ciphertext)?;
        
        DekKey::from_bytes(&plaintext)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// SUBTREE KEY INFO - Runtime information about a subtree's key
// ═══════════════════════════════════════════════════════════════════════════

/// Information about a subtree's key
#[derive(Clone)]
pub struct SubtreeKeyInfo {
    /// The path prefix this key applies to
    pub path_prefix: String,
    /// The decrypted DEK (only in memory)
    pub dek: DekKey,
    /// Version of this key
    pub version: u32,
    /// When this key was created
    pub created_at: i64,
}

impl std::fmt::Debug for SubtreeKeyInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SubtreeKeyInfo")
            .field("path_prefix", &self.path_prefix)
            .field("dek", &"[REDACTED]")
            .field("version", &self.version)
            .field("created_at", &self.created_at)
            .finish()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// SUBTREE KEY MANAGER - Manages the key hierarchy
// ═══════════════════════════════════════════════════════════════════════════

/// Manager for subtree keys (Cryptree-inspired key hierarchy)
/// 
/// This provides a shallow key hierarchy where top-level folders can have
/// their own DEKs, enabling granular sharing and efficient revocation.
#[derive(Clone, Default)]
pub struct SubtreeKeyManager {
    /// Map of path prefix → subtree key info
    subtree_keys: HashMap<String, SubtreeKeyInfo>,
    /// The master DEK for paths without a subtree key
    master_dek: Option<DekKey>,
}

impl std::fmt::Debug for SubtreeKeyManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SubtreeKeyManager")
            .field("subtree_keys", &self.subtree_keys)
            .field("master_dek", &self.master_dek.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

impl SubtreeKeyManager {
    /// Create a new subtree key manager
    pub fn new() -> Self {
        Self::default()
    }
    
    /// Create with a master DEK
    pub fn with_master_dek(master_dek: DekKey) -> Self {
        Self {
            subtree_keys: HashMap::new(),
            master_dek: Some(master_dek),
        }
    }
    
    /// Set the master DEK
    pub fn set_master_dek(&mut self, dek: DekKey) {
        self.master_dek = Some(dek);
    }
    
    /// Get the master DEK
    pub fn master_dek(&self) -> Option<&DekKey> {
        self.master_dek.as_ref()
    }
    
    /// Create a new subtree with its own DEK
    /// 
    /// Returns the encrypted subtree DEK for storage in the directory entry.
    pub fn create_subtree(&mut self, path_prefix: &str) -> Result<(DekKey, EncryptedSubtreeDek)> {
        let master = self.master_dek.as_ref()
            .ok_or_else(|| CryptoError::InvalidKey("Master DEK not set".into()))?;
        
        // Normalize path
        let normalized = Self::normalize_path(path_prefix);
        
        // Generate new subtree DEK
        let subtree_dek = DekKey::generate();
        let version = 1u32;
        
        // Encrypt with master DEK
        let encrypted = EncryptedSubtreeDek::encrypt(&subtree_dek, master, version)?;
        
        // Store in memory
        self.subtree_keys.insert(normalized.clone(), SubtreeKeyInfo {
            path_prefix: normalized,
            dek: subtree_dek.clone(),
            version,
            created_at: current_timestamp(),
        });
        
        Ok((subtree_dek, encrypted))
    }
    
    /// Load an existing subtree key from encrypted storage
    pub fn load_subtree(&mut self, path_prefix: &str, encrypted: &EncryptedSubtreeDek) -> Result<DekKey> {
        let master = self.master_dek.as_ref()
            .ok_or_else(|| CryptoError::InvalidKey("Master DEK not set".into()))?;
        
        let normalized = Self::normalize_path(path_prefix);
        let subtree_dek = encrypted.decrypt(master)?;
        
        self.subtree_keys.insert(normalized.clone(), SubtreeKeyInfo {
            path_prefix: normalized,
            dek: subtree_dek.clone(),
            version: encrypted.version,
            created_at: encrypted.created_at,
        });
        
        Ok(subtree_dek)
    }
    
    /// Get the DEK for a given path
    /// 
    /// Resolution order:
    /// 1. Check if path matches a subtree prefix → use subtree DEK
    /// 2. Fall back to master DEK
    pub fn resolve_dek(&self, path: &str) -> Option<&DekKey> {
        let normalized = Self::normalize_path(path);
        
        // Find the most specific matching subtree
        let mut best_match: Option<&SubtreeKeyInfo> = None;
        let mut best_len = 0;
        
        for (prefix, info) in &self.subtree_keys {
            if normalized.starts_with(prefix) && prefix.len() > best_len {
                best_match = Some(info);
                best_len = prefix.len();
            }
        }
        
        if let Some(info) = best_match {
            Some(&info.dek)
        } else {
            self.master_dek.as_ref()
        }
    }
    
    /// Get the subtree key info for a path (if it has a specific subtree key)
    pub fn get_subtree_key(&self, path_prefix: &str) -> Option<&SubtreeKeyInfo> {
        let normalized = Self::normalize_path(path_prefix);
        self.subtree_keys.get(&normalized)
    }
    
    /// Check if a path has its own subtree key
    pub fn has_subtree_key(&self, path_prefix: &str) -> bool {
        let normalized = Self::normalize_path(path_prefix);
        self.subtree_keys.contains_key(&normalized)
    }
    
    /// List all subtree prefixes
    pub fn list_subtrees(&self) -> Vec<&str> {
        self.subtree_keys.keys().map(|s| s.as_str()).collect()
    }
    
    /// Rotate a subtree's key
    /// 
    /// Generates a new DEK for the subtree. Returns:
    /// - The new DEK
    /// - The new encrypted DEK for storage
    /// - List of paths that need re-encryption
    pub fn rotate_subtree(&mut self, path_prefix: &str) -> Result<SubtreeRotationResult> {
        let master = self.master_dek.as_ref()
            .ok_or_else(|| CryptoError::InvalidKey("Master DEK not set".into()))?;
        
        let normalized = Self::normalize_path(path_prefix);
        
        // Get current version
        let current_version = self.subtree_keys
            .get(&normalized)
            .map(|info| info.version)
            .unwrap_or(0);
        
        // Generate new key
        let new_dek = DekKey::generate();
        let new_version = current_version + 1;
        let encrypted = EncryptedSubtreeDek::encrypt(&new_dek, master, new_version)?;
        
        // Update in memory
        self.subtree_keys.insert(normalized.clone(), SubtreeKeyInfo {
            path_prefix: normalized.clone(),
            dek: new_dek.clone(),
            version: new_version,
            created_at: current_timestamp(),
        });
        
        Ok(SubtreeRotationResult {
            path_prefix: normalized,
            new_dek,
            encrypted_dek: encrypted,
            old_version: current_version,
            new_version,
        })
    }
    
    /// Remove a subtree key (files will use master DEK)
    pub fn remove_subtree(&mut self, path_prefix: &str) -> bool {
        let normalized = Self::normalize_path(path_prefix);
        self.subtree_keys.remove(&normalized).is_some()
    }
    
    /// Normalize a path prefix
    fn normalize_path(path: &str) -> String {
        let mut normalized = if path.starts_with('/') {
            path.to_string()
        } else {
            format!("/{}", path)
        };
        
        // Ensure trailing slash for directories
        if !normalized.ends_with('/') {
            normalized.push('/');
        }
        
        normalized
    }
}

/// Result of rotating a subtree's key
#[derive(Clone)]
pub struct SubtreeRotationResult {
    /// The path prefix that was rotated
    pub path_prefix: String,
    /// The new DEK
    pub new_dek: DekKey,
    /// The encrypted DEK for storage
    pub encrypted_dek: EncryptedSubtreeDek,
    /// Previous version number
    pub old_version: u32,
    /// New version number
    pub new_version: u32,
}

impl std::fmt::Debug for SubtreeRotationResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SubtreeRotationResult")
            .field("path_prefix", &self.path_prefix)
            .field("new_dek", &"[REDACTED]")
            .field("encrypted_dek", &self.encrypted_dek)
            .field("old_version", &self.old_version)
            .field("new_version", &self.new_version)
            .finish()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// SUBTREE SHARE TOKEN - Share a subtree with its key
// ═══════════════════════════════════════════════════════════════════════════

/// A share token specifically for subtree access
/// 
/// Unlike per-file shares, this grants access to an entire subtree.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubtreeShareToken {
    /// Unique identifier
    pub id: String,
    /// The path prefix this share grants access to
    pub path_prefix: String,
    /// The wrapped subtree DEK (encrypted for recipient)
    pub wrapped_dek: EncryptedData,
    /// Expiration timestamp (Unix seconds), None = never expires
    pub expires_at: Option<i64>,
    /// Unix timestamp when this share was created
    pub created_at: i64,
    /// Access permissions
    pub permissions: SharePermissions,
    /// Version of the subtree key
    pub subtree_version: u32,
}

impl SubtreeShareToken {
    /// Check if this share has expired
    pub fn is_expired(&self) -> bool {
        match self.expires_at {
            Some(expiry) => current_timestamp() > expiry,
            None => false,
        }
    }
    
    /// Check if a path is within this share's scope
    pub fn is_valid_for_path(&self, path: &str) -> bool {
        let normalized = if path.starts_with('/') {
            path.to_string()
        } else {
            format!("/{}", path)
        };
        normalized.starts_with(&self.path_prefix)
    }
    
    /// Check if read access is granted
    pub fn can_read(&self) -> bool {
        !self.is_expired() && self.permissions.can_read
    }
    
    /// Check if write access is granted
    pub fn can_write(&self) -> bool {
        !self.is_expired() && self.permissions.can_write
    }
}

/// Builder for subtree share tokens
pub struct SubtreeShareBuilder<'a> {
    #[allow(dead_code)] // Reserved for future signing
    owner_keypair: &'a KekKeyPair,
    recipient_public_key: &'a PublicKey,
    subtree_dek: &'a DekKey,
    path_prefix: String,
    subtree_version: u32,
    expires_at: Option<i64>,
    permissions: SharePermissions,
}

impl<'a> SubtreeShareBuilder<'a> {
    /// Create a new subtree share builder
    pub fn new(
        owner_keypair: &'a KekKeyPair,
        recipient_public_key: &'a PublicKey,
        subtree_dek: &'a DekKey,
        path_prefix: impl Into<String>,
        subtree_version: u32,
    ) -> Self {
        Self {
            owner_keypair,
            recipient_public_key,
            subtree_dek,
            path_prefix: path_prefix.into(),
            subtree_version,
            expires_at: None,
            permissions: SharePermissions::read_only(),
        }
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
    
    /// Set custom permissions
    pub fn permissions(mut self, permissions: SharePermissions) -> Self {
        self.permissions = permissions;
        self
    }
    
    /// Build the subtree share token
    pub fn build(self) -> Result<SubtreeShareToken> {
        // Generate unique ID
        use rand::RngCore;
        let mut id_bytes = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut id_bytes);
        let id = hex::encode(id_bytes);
        
        // Encrypt the subtree DEK for the recipient
        let encryptor = Encryptor::new(self.recipient_public_key);
        let wrapped_dek = encryptor.encrypt_dek(self.subtree_dek)?;
        
        // Normalize path prefix
        let path_prefix = if self.path_prefix.starts_with('/') {
            self.path_prefix
        } else {
            format!("/{}", self.path_prefix)
        };
        let path_prefix = if path_prefix.ends_with('/') {
            path_prefix
        } else {
            format!("{}/", path_prefix)
        };
        
        Ok(SubtreeShareToken {
            id,
            path_prefix,
            wrapped_dek,
            expires_at: self.expires_at,
            created_at: current_timestamp(),
            permissions: self.permissions,
            subtree_version: self.subtree_version,
        })
    }
}

/// Recipient handler for subtree shares
pub struct SubtreeShareRecipient {
    secret_key: SecretKey,
}

impl SubtreeShareRecipient {
    pub fn new(keypair: &KekKeyPair) -> Self {
        Self {
            secret_key: keypair.secret_key().clone(),
        }
    }
    
    /// Accept a subtree share and extract the DEK
    pub fn accept_share(&self, token: &SubtreeShareToken) -> Result<AcceptedSubtreeShare> {
        if token.is_expired() {
            return Err(CryptoError::ShareExpired);
        }
        
        let decryptor = Decryptor::from_secret_key(&self.secret_key);
        let dek = decryptor.decrypt_dek(&token.wrapped_dek)?;
        
        Ok(AcceptedSubtreeShare {
            path_prefix: token.path_prefix.clone(),
            dek,
            expires_at: token.expires_at,
            permissions: token.permissions,
            subtree_version: token.subtree_version,
        })
    }
}

/// An accepted subtree share with decrypted DEK
#[derive(Clone)]
pub struct AcceptedSubtreeShare {
    /// The path prefix this share grants access to
    pub path_prefix: String,
    /// The decrypted subtree DEK
    pub dek: DekKey,
    /// Expiration timestamp
    pub expires_at: Option<i64>,
    /// Access permissions
    pub permissions: SharePermissions,
    /// Version of the subtree key
    pub subtree_version: u32,
}

impl std::fmt::Debug for AcceptedSubtreeShare {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AcceptedSubtreeShare")
            .field("path_prefix", &self.path_prefix)
            .field("dek", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .field("permissions", &self.permissions)
            .field("subtree_version", &self.subtree_version)
            .finish()
    }
}

impl AcceptedSubtreeShare {
    /// Check if a path is within this share's scope
    pub fn is_valid_for_path(&self, path: &str) -> bool {
        let normalized = if path.starts_with('/') {
            path.to_string()
        } else {
            format!("/{}", path)
        };
        normalized.starts_with(&self.path_prefix)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypted_subtree_dek_roundtrip() {
        let master_dek = DekKey::generate();
        let subtree_dek = DekKey::generate();
        
        let encrypted = EncryptedSubtreeDek::encrypt(&subtree_dek, &master_dek, 1).unwrap();
        let decrypted = encrypted.decrypt(&master_dek).unwrap();
        
        assert_eq!(subtree_dek.as_bytes(), decrypted.as_bytes());
        assert_eq!(encrypted.version, 1);
    }
    
    #[test]
    fn test_subtree_key_manager_create() {
        let master_dek = DekKey::generate();
        let mut manager = SubtreeKeyManager::with_master_dek(master_dek);
        
        let (subtree_dek, encrypted) = manager.create_subtree("/photos/").unwrap();
        
        assert!(manager.has_subtree_key("/photos/"));
        assert_eq!(encrypted.version, 1);
        
        // Verify the stored key matches
        let info = manager.get_subtree_key("/photos/").unwrap();
        assert_eq!(info.dek.as_bytes(), subtree_dek.as_bytes());
    }
    
    #[test]
    fn test_subtree_key_manager_resolve() {
        let master_dek = DekKey::generate();
        let mut manager = SubtreeKeyManager::with_master_dek(master_dek.clone());
        
        let (photos_dek, _) = manager.create_subtree("/photos/").unwrap();
        let (docs_dek, _) = manager.create_subtree("/documents/").unwrap();
        
        // Files under /photos/ should use photos DEK
        let resolved = manager.resolve_dek("/photos/beach.jpg").unwrap();
        assert_eq!(resolved.as_bytes(), photos_dek.as_bytes());
        
        // Files under /documents/ should use docs DEK
        let resolved = manager.resolve_dek("/documents/report.pdf").unwrap();
        assert_eq!(resolved.as_bytes(), docs_dek.as_bytes());
        
        // Files at root should use master DEK
        let resolved = manager.resolve_dek("/readme.txt").unwrap();
        assert_eq!(resolved.as_bytes(), master_dek.as_bytes());
    }
    
    #[test]
    fn test_subtree_key_manager_nested_resolution() {
        let master_dek = DekKey::generate();
        let mut manager = SubtreeKeyManager::with_master_dek(master_dek);
        
        let (photos_dek, _) = manager.create_subtree("/photos/").unwrap();
        let (vacation_dek, _) = manager.create_subtree("/photos/vacation/").unwrap();
        
        // /photos/portrait.jpg uses /photos/ DEK
        let resolved = manager.resolve_dek("/photos/portrait.jpg").unwrap();
        assert_eq!(resolved.as_bytes(), photos_dek.as_bytes());
        
        // /photos/vacation/beach.jpg uses more specific /photos/vacation/ DEK
        let resolved = manager.resolve_dek("/photos/vacation/beach.jpg").unwrap();
        assert_eq!(resolved.as_bytes(), vacation_dek.as_bytes());
    }
    
    #[test]
    fn test_subtree_key_rotation() {
        let master_dek = DekKey::generate();
        let mut manager = SubtreeKeyManager::with_master_dek(master_dek);
        
        let (original_dek, _) = manager.create_subtree("/photos/").unwrap();
        
        // Rotate the key
        let result = manager.rotate_subtree("/photos/").unwrap();
        
        assert_eq!(result.old_version, 1);
        assert_eq!(result.new_version, 2);
        assert_ne!(result.new_dek.as_bytes(), original_dek.as_bytes());
        
        // Verify the new key is now used
        let resolved = manager.resolve_dek("/photos/beach.jpg").unwrap();
        assert_eq!(resolved.as_bytes(), result.new_dek.as_bytes());
    }
    
    #[test]
    fn test_subtree_key_load() {
        let master_dek = DekKey::generate();
        let mut manager1 = SubtreeKeyManager::with_master_dek(master_dek.clone());
        
        // Create subtree in manager1
        let (subtree_dek, encrypted) = manager1.create_subtree("/photos/").unwrap();
        
        // Load in a new manager (simulating restart)
        let mut manager2 = SubtreeKeyManager::with_master_dek(master_dek);
        let loaded_dek = manager2.load_subtree("/photos/", &encrypted).unwrap();
        
        assert_eq!(loaded_dek.as_bytes(), subtree_dek.as_bytes());
        assert!(manager2.has_subtree_key("/photos/"));
    }
    
    #[test]
    fn test_subtree_share_token_creation() {
        let owner = KekKeyPair::generate();
        let recipient = KekKeyPair::generate();
        let subtree_dek = DekKey::generate();
        
        let token = SubtreeShareBuilder::new(
            &owner,
            recipient.public_key(),
            &subtree_dek,
            "/photos/",
            1,
        )
            .expires_in(3600)
            .read_only()
            .build()
            .unwrap();
        
        assert!(!token.is_expired());
        assert!(token.is_valid_for_path("/photos/beach.jpg"));
        assert!(token.is_valid_for_path("/photos/vacation/sunset.jpg"));
        assert!(!token.is_valid_for_path("/documents/report.pdf"));
        assert!(token.can_read());
        assert!(!token.can_write());
    }
    
    #[test]
    fn test_subtree_share_accept() {
        let owner = KekKeyPair::generate();
        let recipient = KekKeyPair::generate();
        let subtree_dek = DekKey::generate();
        
        let token = SubtreeShareBuilder::new(
            &owner,
            recipient.public_key(),
            &subtree_dek,
            "/photos/",
            1,
        )
            .read_write()
            .build()
            .unwrap();
        
        // Recipient accepts the share
        let handler = SubtreeShareRecipient::new(&recipient);
        let accepted = handler.accept_share(&token).unwrap();
        
        assert_eq!(accepted.dek.as_bytes(), subtree_dek.as_bytes());
        assert_eq!(accepted.path_prefix, "/photos/");
        assert!(accepted.permissions.can_read);
        assert!(accepted.permissions.can_write);
    }
    
    #[test]
    fn test_wrong_recipient_cannot_accept() {
        let owner = KekKeyPair::generate();
        let intended = KekKeyPair::generate();
        let wrong = KekKeyPair::generate();
        let subtree_dek = DekKey::generate();
        
        let token = SubtreeShareBuilder::new(
            &owner,
            intended.public_key(),
            &subtree_dek,
            "/photos/",
            1,
        )
            .build()
            .unwrap();
        
        let handler = SubtreeShareRecipient::new(&wrong);
        let result = handler.accept_share(&token);
        
        assert!(result.is_err());
    }
    
    #[test]
    fn test_path_normalization() {
        let master_dek = DekKey::generate();
        let mut manager = SubtreeKeyManager::with_master_dek(master_dek);
        
        // Create with various path formats
        let (dek1, _) = manager.create_subtree("photos").unwrap();
        
        // All these should resolve to the same subtree
        assert!(manager.has_subtree_key("/photos/"));
        assert!(manager.has_subtree_key("photos"));
        assert!(manager.has_subtree_key("photos/"));
        
        let resolved = manager.resolve_dek("photos/beach.jpg").unwrap();
        assert_eq!(resolved.as_bytes(), dek1.as_bytes());
    }
    
    #[test]
    fn test_list_subtrees() {
        let master_dek = DekKey::generate();
        let mut manager = SubtreeKeyManager::with_master_dek(master_dek);
        
        manager.create_subtree("/photos/").unwrap();
        manager.create_subtree("/documents/").unwrap();
        manager.create_subtree("/apps/myapp/").unwrap();
        
        let subtrees = manager.list_subtrees();
        assert_eq!(subtrees.len(), 3);
        assert!(subtrees.contains(&"/photos/"));
        assert!(subtrees.contains(&"/documents/"));
        assert!(subtrees.contains(&"/apps/myapp/"));
    }
    
    #[test]
    fn test_remove_subtree() {
        let master_dek = DekKey::generate();
        let mut manager = SubtreeKeyManager::with_master_dek(master_dek.clone());
        
        manager.create_subtree("/photos/").unwrap();
        assert!(manager.has_subtree_key("/photos/"));
        
        // Remove
        let removed = manager.remove_subtree("/photos/");
        assert!(removed);
        assert!(!manager.has_subtree_key("/photos/"));
        
        // Files should now use master DEK
        let resolved = manager.resolve_dek("/photos/beach.jpg").unwrap();
        assert_eq!(resolved.as_bytes(), master_dek.as_bytes());
    }
    
    #[test]
    fn test_subtree_share_serialization() {
        let owner = KekKeyPair::generate();
        let recipient = KekKeyPair::generate();
        let subtree_dek = DekKey::generate();
        
        let token = SubtreeShareBuilder::new(
            &owner,
            recipient.public_key(),
            &subtree_dek,
            "/photos/",
            1,
        )
            .build()
            .unwrap();
        
        // Serialize
        let json = serde_json::to_string(&token).unwrap();
        
        // Deserialize
        let restored: SubtreeShareToken = serde_json::from_str(&json).unwrap();
        
        assert_eq!(restored.id, token.id);
        assert_eq!(restored.path_prefix, token.path_prefix);
        assert_eq!(restored.subtree_version, token.subtree_version);
    }
}
