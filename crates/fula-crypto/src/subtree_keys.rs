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
    time::now_timestamp,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Get current Unix timestamp in seconds (WASM-compatible)
fn current_timestamp() -> i64 {
    now_timestamp()
}

// ═══════════════════════════════════════════════════════════════════════════
// SUBTREE DEK - Encrypted subtree key stored in directory entries
// ═══════════════════════════════════════════════════════════════════════════

/// An encrypted subtree DEK, stored in directory entries
///
/// The subtree DEK is encrypted with the parent's DEK (or master DEK for
/// top-level). This creates a chain of keys where having access to a parent
/// gives access to children.
///
/// Wire-format dispatch
/// --------------------
/// The serialized form carries two distinct version fields:
///
/// - `version: u32` — **rotation version** (advances on each subtree key
///   rotation; not an AEAD-format version).
/// - `aad_format_version: u8` (added in 0.7.0) — **AEAD wire-format version**.
///   `0` (legacy, default for blobs serialized before 0.7.0) means the
///   ciphertext was produced with no AAD; a storage server can swap such
///   blobs across paths without detection. `2` means the AEAD is bound to
///   `(path_prefix, version)` via [`EncryptedSubtreeDek::aad_v2`].
///
/// `#[serde(default)]` on the new field makes pre-0.7 blobs deserialize
/// cleanly with `aad_format_version = 0`, preserving read access to all
/// already-stored data.
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
    /// AEAD wire-format version. `0` = legacy no-AAD; `2` = AAD bound to
    /// `(path_prefix, version)`. `#[serde(default)]` keeps pre-0.7 blobs
    /// readable.
    #[serde(default)]
    pub aad_format_version: u8,
}

impl EncryptedSubtreeDek {
    /// Wire-format constant: current AAD-bound v2 version byte.
    pub const AAD_FORMAT_V2: u8 = 2;

    /// Build the canonical v2 AAD for a given subtree path prefix and
    /// rotation version.
    ///
    /// `aad = "fula:subtree-dek:v2:" || path_prefix || ":" || version_be4`.
    /// Including `version` in the AAD prevents a server from rolling back to
    /// an older wrapped DEK at the same path; including the path prevents
    /// cross-subtree swaps.
    pub fn aad_v2(path_prefix: &str, version: u32) -> Vec<u8> {
        let mut aad = Vec::with_capacity(
            b"fula:subtree-dek:v2:".len() + path_prefix.len() + 1 + 4,
        );
        aad.extend_from_slice(b"fula:subtree-dek:v2:");
        aad.extend_from_slice(path_prefix.as_bytes());
        aad.push(b':');
        aad.extend_from_slice(&version.to_be_bytes());
        aad
    }

    /// **DEPRECATED — use [`EncryptedSubtreeDek::encrypt_v2`].**
    ///
    /// Produces a legacy `aad_format_version = 0` blob (no AAD). Kept
    /// callable for legacy round-trip / fixtures; production callers should
    /// route to `encrypt_v2` to gain cross-path / rotation-rollback
    /// resistance.
    #[deprecated(
        since = "0.7.0",
        note = "use encrypt_v2(subtree_dek, parent_dek, path_prefix, version) — legacy encrypt is no-AAD and master can swap blobs across paths or roll back rotations"
    )]
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
            aad_format_version: 0,
        })
    }

    /// Encrypt a subtree DEK with a parent DEK and AAD bound to the
    /// subtree path + rotation version.
    ///
    /// `path_prefix` MUST be the canonical subtree-prefix string (see
    /// `SubtreeKeyManager::normalize_path`). `version` is the same rotation
    /// version that gets stored in [`EncryptedSubtreeDek::version`]. The
    /// caller must pass the same `(path_prefix, version)` to `decrypt_v2`;
    /// AEAD verification fails if the wrap is moved to a different path or
    /// downgraded to an older rotation.
    pub fn encrypt_v2(
        subtree_dek: &DekKey,
        parent_dek: &DekKey,
        path_prefix: &str,
        version: u32,
    ) -> Result<Self> {
        use crate::symmetric::{Aead, Nonce};

        let aad = Self::aad_v2(path_prefix, version);
        let nonce = Nonce::generate();
        let aead = Aead::new_default(parent_dek);
        let ciphertext = aead.encrypt_with_aad(&nonce, subtree_dek.as_bytes(), &aad)?;

        Ok(Self {
            ciphertext,
            nonce: nonce.as_bytes().to_vec(),
            version,
            created_at: current_timestamp(),
            aad_format_version: Self::AAD_FORMAT_V2,
        })
    }

    /// Decrypt a legacy (`aad_format_version == 0`) subtree DEK wrap.
    ///
    /// Errors when `aad_format_version != 0` to prevent a v2 blob from
    /// being silently decrypted without its AAD. v2 blobs go through
    /// [`EncryptedSubtreeDek::decrypt_v2`].
    pub fn decrypt(&self, parent_dek: &DekKey) -> Result<DekKey> {
        use crate::symmetric::{Aead, Nonce};

        if self.aad_format_version != 0 {
            return Err(CryptoError::Decryption(format!(
                "EncryptedSubtreeDek aad_format_version {} requires decrypt_v2(parent_dek, path_prefix) — \
                 legacy decrypt is for aad_format_version 0 only",
                self.aad_format_version
            )));
        }
        let nonce = Nonce::from_bytes(&self.nonce)?;
        let aead = Aead::new_default(parent_dek);
        let plaintext = aead.decrypt(&nonce, &self.ciphertext)?;

        DekKey::from_bytes(&plaintext)
    }

    /// Decrypt a v2 subtree DEK wrap with AAD verification.
    ///
    /// Caller passes the path prefix the wrap was issued for; AAD is
    /// reconstructed via `aad_v2(path_prefix, self.version)` and checked
    /// against the AEAD tag. Mismatched paths or rolled-back rotation
    /// versions surface as `CryptoError::Decryption`.
    pub fn decrypt_v2(&self, parent_dek: &DekKey, path_prefix: &str) -> Result<DekKey> {
        use crate::symmetric::{Aead, Nonce};

        if self.aad_format_version != Self::AAD_FORMAT_V2 {
            return Err(CryptoError::Decryption(format!(
                "decrypt_v2 requires EncryptedSubtreeDek aad_format_version {}, got {}",
                Self::AAD_FORMAT_V2,
                self.aad_format_version
            )));
        }
        let aad = Self::aad_v2(path_prefix, self.version);
        let nonce = Nonce::from_bytes(&self.nonce)?;
        let aead = Aead::new_default(parent_dek);
        let plaintext = aead.decrypt_with_aad(&nonce, &self.ciphertext, &aad)?;

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
    /// Encrypts via [`EncryptedSubtreeDek::encrypt_v2`] (AAD bound to the
    /// canonical path prefix and rotation version) so a server cannot move
    /// the wrap to a different subtree path or roll back the rotation.
    pub fn create_subtree(&mut self, path_prefix: &str) -> Result<(DekKey, EncryptedSubtreeDek)> {
        let master = self.master_dek.as_ref()
            .ok_or_else(|| CryptoError::InvalidKey("Master DEK not set".into()))?;

        // Normalize path
        let normalized = Self::normalize_path(path_prefix);

        // Generate new subtree DEK
        let subtree_dek = DekKey::generate();
        let version = 1u32;

        // Encrypt with master DEK and AAD-bound to (path_prefix, version).
        let encrypted = EncryptedSubtreeDek::encrypt_v2(
            &subtree_dek,
            master,
            &normalized,
            version,
        )?;

        // Store in memory
        self.subtree_keys.insert(normalized.clone(), SubtreeKeyInfo {
            path_prefix: normalized,
            dek: subtree_dek.clone(),
            version,
            created_at: current_timestamp(),
        });

        Ok((subtree_dek, encrypted))
    }

    /// Load an existing subtree key from encrypted storage.
    ///
    /// Dispatches on the wrap's `aad_format_version`: legacy (`0`) blobs
    /// (from pre-0.7 SDKs) read with the no-AAD path; v2 blobs (`2`) read
    /// with AAD bound to the canonical path prefix and stored rotation
    /// version. Mixed deployments — some subtrees v1, others v2 — work
    /// because each blob carries its own version on the wire.
    pub fn load_subtree(&mut self, path_prefix: &str, encrypted: &EncryptedSubtreeDek) -> Result<DekKey> {
        let master = self.master_dek.as_ref()
            .ok_or_else(|| CryptoError::InvalidKey("Master DEK not set".into()))?;

        let normalized = Self::normalize_path(path_prefix);
        let subtree_dek = match encrypted.aad_format_version {
            0 => encrypted.decrypt(master)?, // legacy v1 wrap (no AAD)
            EncryptedSubtreeDek::AAD_FORMAT_V2 => {
                encrypted.decrypt_v2(master, &normalized)?
            }
            v => {
                return Err(CryptoError::Decryption(format!(
                    "unsupported EncryptedSubtreeDek aad_format_version {} — \
                     this SDK reads 0 (legacy) and 2",
                    v
                )));
            }
        };

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
        
        // Generate new key. v2 wrap binds the new (path_prefix, new_version)
        // tuple into AAD so an old wrap cannot be replayed at this path.
        let new_dek = DekKey::generate();
        let new_version = current_version + 1;
        let encrypted = EncryptedSubtreeDek::encrypt_v2(
            &new_dek,
            master,
            &normalized,
            new_version,
        )?;
        
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

/// Subtree-share-token AAD version 5 sentinel. Tokens with
/// `version >= SUBTREE_SHARE_TOKEN_AAD_V5` bind every non-`wrapped_dek`
/// field AND the recipient public key into the DEK-wrap AAD. Tokens with
/// `version < 5` are rejected — there is no legacy fallback path.
pub(crate) const SUBTREE_SHARE_TOKEN_AAD_V5: u8 = 5;

/// Build the canonical AAD bytes that bind subtree-share-token metadata to
/// the wrapped DEK. Analogous to `sharing::build_share_token_aad` but with a
/// distinct domain prefix so tokens from one flow cannot be substituted into
/// the other.
///
/// Layout (all integers big-endian):
/// - domain: `b"fula:v5:subtree-share-token|"`
/// - id: `<u32 len><bytes>`
/// - path_prefix: `<u32 len><bytes>`
/// - expires_at: `<u8 tag>` then `<i64>` if Some
/// - created_at: `<i64>`
/// - permissions: `[can_read, can_write, can_delete]` each as `u8` 0/1
/// - subtree_version: `<u32>`
/// - version: `<u8>`
/// - recipient_pk: `<u32 len=32><bytes>` (M-5: binds the intended recipient's
///   X25519 public key so tokens cannot be mis-routed between recipients)
pub(crate) fn build_subtree_share_token_aad(
    id: &str,
    path_prefix: &str,
    expires_at: Option<i64>,
    created_at: i64,
    permissions: &SharePermissions,
    subtree_version: u32,
    version: u8,
    recipient_pk: &[u8; 32],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(128);
    out.extend_from_slice(b"fula:v5:subtree-share-token|");

    fn push_bytes(out: &mut Vec<u8>, b: &[u8]) {
        debug_assert!(
            b.len() <= u32::MAX as usize,
            "subtree share token AAD field exceeds u32 length prefix"
        );
        out.extend_from_slice(&(b.len() as u32).to_be_bytes());
        out.extend_from_slice(b);
    }

    push_bytes(&mut out, id.as_bytes());
    push_bytes(&mut out, path_prefix.as_bytes());

    match expires_at {
        None => out.push(0u8),
        Some(ts) => {
            out.push(1u8);
            out.extend_from_slice(&ts.to_be_bytes());
        }
    }
    out.extend_from_slice(&created_at.to_be_bytes());
    out.push(permissions.can_read as u8);
    out.push(permissions.can_write as u8);
    out.push(permissions.can_delete as u8);
    out.extend_from_slice(&subtree_version.to_be_bytes());
    out.push(version);
    push_bytes(&mut out, recipient_pk);
    out
}

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
    /// Share-token format version. `>= 4` means metadata is bound into the
    /// wrap-AAD. Older tokens lacked this field; `#[serde(default)]` maps them
    /// to `0` so the legacy unauthenticated decrypt path is used.
    #[serde(default)]
    pub version: u8,
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
    ///
    /// Produces a `version = 5` token whose wrapped subtree DEK binds every
    /// metadata field (id, path_prefix, expiry, created_at, permissions,
    /// subtree_version, version) AND the recipient public key into AAD. Any
    /// post-build mutation, or use of the wrong recipient secret, causes
    /// `accept_share` to fail with a generic auth error.
    pub fn build(self) -> Result<SubtreeShareToken> {
        // Generate unique ID
        use rand::RngCore;
        let mut id_bytes = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut id_bytes);
        let id = hex::encode(id_bytes);

        // Normalize path prefix BEFORE binding so the AAD covers the
        // canonical form the recipient will see.
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

        let created_at = current_timestamp();
        let version = SUBTREE_SHARE_TOKEN_AAD_V5;

        let recipient_pk_bytes = self.recipient_public_key.as_bytes();
        let aad = build_subtree_share_token_aad(
            &id,
            &path_prefix,
            self.expires_at,
            created_at,
            &self.permissions,
            self.subtree_version,
            version,
            recipient_pk_bytes,
        );

        // Encrypt the subtree DEK for the recipient, binding the AAD.
        let encryptor = Encryptor::new(self.recipient_public_key);
        let wrapped_dek = encryptor.encrypt_dek_with_context(self.subtree_dek, &aad)?;

        Ok(SubtreeShareToken {
            id,
            path_prefix,
            wrapped_dek,
            expires_at: self.expires_at,
            created_at,
            permissions: self.permissions,
            subtree_version: self.subtree_version,
            version,
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
    ///
    /// Strict version gate: only `version >= SUBTREE_SHARE_TOKEN_AAD_V5`
    /// tokens are accepted, and they MUST unwrap through the AAD-bound path
    /// which also binds the recipient public key derived from `self.secret_key`.
    /// Pre-v5 tokens are rejected — the legacy non-AAD path has been removed
    /// to close the downgrade-oracle surface.
    pub fn accept_share(&self, token: &SubtreeShareToken) -> Result<AcceptedSubtreeShare> {
        if token.is_expired() {
            return Err(CryptoError::ShareExpired);
        }

        // Strict version gate: pre-v5 tokens have no recipient-pk binding.
        if token.version < SUBTREE_SHARE_TOKEN_AAD_V5 {
            return Err(CryptoError::Decryption(
                "subtree share token rejected: version predates recipient-pk AAD binding".to_string(),
            ));
        }

        let decryptor = Decryptor::from_secret_key(&self.secret_key);
        let recipient_pk = self.secret_key.public_key();
        let recipient_pk_bytes = recipient_pk.as_bytes();
        let aad = build_subtree_share_token_aad(
            &token.id,
            &token.path_prefix,
            token.expires_at,
            token.created_at,
            &token.permissions,
            token.subtree_version,
            token.version,
            recipient_pk_bytes,
        );
        let dek = decryptor.decrypt_dek_with_context(&token.wrapped_dek, &aad)?;

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
#[allow(deprecated)] // F2: tests legitimately exercise the legacy v1 (no-AAD) encrypt path; deprecation targets production callers only
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

    // ─────────────────────────────────────────────────────────────────────
    // F2 (audit): EncryptedSubtreeDek wire-format v2 AAD binding +
    // back-compat regression tests. Loads-bearing for the invariant that
    // pre-0.7 (legacy v1 / aad_format_version=0) wraps remain readable.
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn test_subtree_dek_v2_round_trip() {
        let parent_dek = DekKey::generate();
        let subtree_dek = DekKey::generate();

        let encrypted = EncryptedSubtreeDek::encrypt_v2(
            &subtree_dek,
            &parent_dek,
            "/photos/",
            1,
        )
        .unwrap();
        assert_eq!(encrypted.aad_format_version, EncryptedSubtreeDek::AAD_FORMAT_V2);
        assert_eq!(encrypted.version, 1);

        let decrypted = encrypted.decrypt_v2(&parent_dek, "/photos/").unwrap();
        assert_eq!(subtree_dek.as_bytes(), decrypted.as_bytes());
    }

    #[test]
    fn test_subtree_dek_v2_wrong_path_rejects() {
        let parent_dek = DekKey::generate();
        let subtree_dek = DekKey::generate();

        let encrypted = EncryptedSubtreeDek::encrypt_v2(
            &subtree_dek,
            &parent_dek,
            "/photos/",
            1,
        )
        .unwrap();
        assert!(
            encrypted.decrypt_v2(&parent_dek, "/documents/").is_err(),
            "AEAD must reject mismatched path — server cannot move wrap to a different subtree"
        );
    }

    #[test]
    fn test_subtree_dek_v2_wrong_version_rejects() {
        let parent_dek = DekKey::generate();
        let subtree_dek = DekKey::generate();

        // Encrypt with version 5 (rotation version).
        let mut encrypted = EncryptedSubtreeDek::encrypt_v2(
            &subtree_dek,
            &parent_dek,
            "/photos/",
            5,
        )
        .unwrap();
        // Tamper with the version field — server attempts a rotation rollback.
        encrypted.version = 4;
        assert!(
            encrypted.decrypt_v2(&parent_dek, "/photos/").is_err(),
            "AEAD must reject mutated rotation version — server cannot roll back rotations"
        );
    }

    #[test]
    fn test_subtree_dek_v1_legacy_data_still_readable() {
        // An SDK upgraded to produce v2 wraps must still read every
        // pre-0.7 (aad_format_version=0) wrap successfully.
        let parent_dek = DekKey::generate();
        let subtree_dek = DekKey::generate();

        let v1_blob = EncryptedSubtreeDek::encrypt(&subtree_dek, &parent_dek, 1).unwrap();
        assert_eq!(v1_blob.aad_format_version, 0);

        let decrypted = v1_blob.decrypt(&parent_dek).unwrap();
        assert_eq!(subtree_dek.as_bytes(), decrypted.as_bytes());
    }

    #[test]
    fn test_subtree_dek_v1_blob_serde_default() {
        // Backward-compat: a serialized v1 blob (produced by a pre-0.7 SDK
        // that didn't know about the `aad_format_version` field) MUST
        // deserialize cleanly with `aad_format_version` defaulting to 0.
        // Without `#[serde(default)]` on that field, every legacy wrap
        // would fail to load.
        let parent_dek = DekKey::generate();
        let subtree_dek = DekKey::generate();
        let v1_blob = EncryptedSubtreeDek::encrypt(&subtree_dek, &parent_dek, 1).unwrap();

        // Simulate a pre-0.7 wire form by serializing without the field.
        let json_with_field = serde_json::to_string(&v1_blob).unwrap();
        // Strip the field to simulate older serde output:
        let json_without = json_with_field
            .replace(",\"aad_format_version\":0", "")
            .replace("\"aad_format_version\":0,", "");

        let deserialized: EncryptedSubtreeDek = serde_json::from_str(&json_without).unwrap();
        assert_eq!(deserialized.aad_format_version, 0, "missing field must default to 0");
        let decrypted = deserialized.decrypt(&parent_dek).unwrap();
        assert_eq!(subtree_dek.as_bytes(), decrypted.as_bytes());
    }

    #[test]
    fn test_subtree_dek_v2_rejected_by_legacy_decrypt() {
        // A v2 wrap fed through legacy decrypt() must fail closed — it would
        // otherwise silently bypass the AAD check.
        let parent_dek = DekKey::generate();
        let subtree_dek = DekKey::generate();
        let v2_blob = EncryptedSubtreeDek::encrypt_v2(&subtree_dek, &parent_dek, "/p/", 1).unwrap();

        // DekKey doesn't implement Debug (key material), so use match instead
        // of .unwrap_err() which would require Debug on the Ok variant.
        match v2_blob.decrypt(&parent_dek) {
            Ok(_) => panic!("legacy decrypt() must reject v2 wrap"),
            Err(e) => {
                let msg = e.to_string();
                assert!(
                    msg.contains("decrypt_v2"),
                    "error must direct caller to decrypt_v2; got: {}",
                    msg
                );
            }
        }
    }

    #[test]
    fn test_subtree_dek_v1_rejected_by_v2_decrypt() {
        // Symmetrically: v1 wrap fed through decrypt_v2 must fail closed
        // before the AEAD layer even gets called.
        let parent_dek = DekKey::generate();
        let subtree_dek = DekKey::generate();
        let v1_blob = EncryptedSubtreeDek::encrypt(&subtree_dek, &parent_dek, 1).unwrap();

        assert!(v1_blob.decrypt_v2(&parent_dek, "/p/").is_err());
    }

    #[test]
    fn test_subtree_key_manager_create_subtree_emits_v2() {
        // create_subtree (production write path) must emit v2 wraps so the
        // F2 caller migration is verified end-to-end, not just at unit-test
        // level.
        let master_dek = DekKey::generate();
        let mut manager = SubtreeKeyManager::with_master_dek(master_dek);

        let (_dek, encrypted) = manager.create_subtree("/photos/").unwrap();
        assert_eq!(
            encrypted.aad_format_version,
            EncryptedSubtreeDek::AAD_FORMAT_V2,
            "production create_subtree must emit v2 wraps"
        );
    }

    #[test]
    fn test_subtree_key_manager_load_subtree_dispatches_on_version() {
        // Mixed deployment scenario: a master holds both v1 (legacy) and
        // v2 (new) wraps. load_subtree must read both.
        let master_dek = DekKey::generate();

        // Legacy v1 wrap simulates pre-0.7 stored data.
        let legacy_subtree = DekKey::generate();
        let v1_wrap = EncryptedSubtreeDek::encrypt(&legacy_subtree, &master_dek, 1).unwrap();

        let mut manager = SubtreeKeyManager::with_master_dek(master_dek);
        let loaded_legacy = manager.load_subtree("/legacy/", &v1_wrap).unwrap();
        assert_eq!(legacy_subtree.as_bytes(), loaded_legacy.as_bytes());

        // New v2 subtree created in the same manager.
        let (new_subtree, _) = manager.create_subtree("/new/").unwrap();
        assert!(manager.has_subtree_key("/new/"));
        let resolved = manager.resolve_dek("/new/file.txt").unwrap();
        assert_eq!(resolved.as_bytes(), new_subtree.as_bytes());
    }

    // ═══════════════════════════════════════════════════════════════════════
    // F2: Subtree-Share-Token Metadata AAD Binding
    // ═══════════════════════════════════════════════════════════════════════
    mod f2_subtree_share_token_aad_binding {
        use super::*;

        fn build_v5_token() -> (KekKeyPair, KekKeyPair, DekKey, SubtreeShareToken) {
            let owner = KekKeyPair::generate();
            let recipient = KekKeyPair::generate();
            let dek = DekKey::generate();
            let token = SubtreeShareBuilder::new(
                &owner,
                recipient.public_key(),
                &dek,
                "/photos/",
                7,
            )
                .expires_in(3600)
                .read_only()
                .build()
                .unwrap();
            (owner, recipient, dek, token)
        }

        #[test]
        fn round_trip_v5_succeeds() {
            let (_owner, recipient, dek, token) = build_v5_token();
            assert_eq!(token.version, SUBTREE_SHARE_TOKEN_AAD_V5);
            let accepted = SubtreeShareRecipient::new(&recipient)
                .accept_share(&token)
                .unwrap();
            assert_eq!(accepted.dek.as_bytes(), dek.as_bytes());
            assert_eq!(accepted.path_prefix, "/photos/");
        }

        #[test]
        fn mutated_path_prefix_rejected() {
            let (_owner, recipient, _dek, mut token) = build_v5_token();
            token.path_prefix = "/".to_string();
            let err = SubtreeShareRecipient::new(&recipient)
                .accept_share(&token)
                .unwrap_err();
            assert!(matches!(err, CryptoError::Decryption(_)), "got: {:?}", err);
        }

        #[test]
        fn mutated_expiry_rejected() {
            let (_owner, recipient, _dek, mut token) = build_v5_token();
            token.expires_at = Some(current_timestamp() + 86400 * 365);
            let err = SubtreeShareRecipient::new(&recipient)
                .accept_share(&token)
                .unwrap_err();
            assert!(matches!(err, CryptoError::Decryption(_)), "got: {:?}", err);
        }

        #[test]
        fn mutated_permissions_rejected() {
            let (_owner, recipient, _dek, mut token) = build_v5_token();
            token.permissions = SharePermissions::full();
            let err = SubtreeShareRecipient::new(&recipient)
                .accept_share(&token)
                .unwrap_err();
            assert!(matches!(err, CryptoError::Decryption(_)), "got: {:?}", err);
        }

        #[test]
        fn mutated_subtree_version_rejected() {
            let (_owner, recipient, _dek, mut token) = build_v5_token();
            token.subtree_version = 99;
            let err = SubtreeShareRecipient::new(&recipient)
                .accept_share(&token)
                .unwrap_err();
            assert!(matches!(err, CryptoError::Decryption(_)), "got: {:?}", err);
        }

        #[test]
        fn mutated_id_rejected() {
            let (_owner, recipient, _dek, mut token) = build_v5_token();
            token.id = "deadbeef".to_string();
            let err = SubtreeShareRecipient::new(&recipient)
                .accept_share(&token)
                .unwrap_err();
            assert!(matches!(err, CryptoError::Decryption(_)), "got: {:?}", err);
        }

        #[test]
        fn downgraded_version_rejected() {
            let (_owner, recipient, _dek, mut token) = build_v5_token();
            token.version = 0; // Force the strict gate to reject
            let err = SubtreeShareRecipient::new(&recipient)
                .accept_share(&token)
                .unwrap_err();
            assert!(matches!(err, CryptoError::Decryption(_)), "got: {:?}", err);
        }

        #[test]
        fn v4_subtree_token_rejected() {
            // M-5: pre-v5 subtree tokens carry no recipient-pk binding and
            // must be refused outright. No legacy fallback path exists.
            let (_owner, recipient, _dek, mut token) = build_v5_token();
            token.version = 4;
            let err = SubtreeShareRecipient::new(&recipient)
                .accept_share(&token)
                .unwrap_err();
            assert!(matches!(err, CryptoError::Decryption(_)), "got: {:?}", err);
        }

        #[test]
        fn wrong_recipient_key_rejected() {
            // M-5: deriving a different recipient_pk from a wrong secret
            // yields a different AAD → generic auth failure.
            let owner = KekKeyPair::generate();
            let recipient = KekKeyPair::generate();
            let wrong_recipient = KekKeyPair::generate();
            let dek = DekKey::generate();
            let token = SubtreeShareBuilder::new(
                &owner, recipient.public_key(), &dek, "/photos/", 1,
            ).build().unwrap();
            let err = SubtreeShareRecipient::new(&wrong_recipient)
                .accept_share(&token)
                .unwrap_err();
            assert!(matches!(err, CryptoError::Decryption(_)), "got: {:?}", err);
        }

        #[test]
        fn cross_token_wrapped_dek_substitution_rejected() {
            let owner = KekKeyPair::generate();
            let recipient = KekKeyPair::generate();
            let dek_a = DekKey::generate();
            let dek_b = DekKey::generate();
            let token_a = SubtreeShareBuilder::new(
                &owner, recipient.public_key(), &dek_a, "/a/", 1,
            ).build().unwrap();
            let token_b = SubtreeShareBuilder::new(
                &owner, recipient.public_key(), &dek_b, "/b/", 1,
            ).build().unwrap();
            let mut franken = token_a.clone();
            franken.wrapped_dek = token_b.wrapped_dek.clone();
            let err = SubtreeShareRecipient::new(&recipient)
                .accept_share(&franken)
                .unwrap_err();
            assert!(matches!(err, CryptoError::Decryption(_)), "got: {:?}", err);
        }

        #[test]
        fn share_token_and_subtree_aad_differ() {
            // Domain prefixes must differ so a share-token wrap cannot be
            // substituted for a subtree-token wrap (or vice versa).
            let pk = [0u8; 32];
            let subtree_aad = build_subtree_share_token_aad(
                "id", "/", None, 0, &SharePermissions::read_only(), 1, 5, &pk,
            );
            assert!(subtree_aad.starts_with(b"fula:v5:subtree-share-token|"));
            // share-token prefix is different — test at that module's level
            // (sharing.rs:aad_domain_prefix_prevents_cross_context_substitution)
        }
    }
}
