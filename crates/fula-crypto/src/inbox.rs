//! Async/Offline Sharing via Inbox (WNFS-Inspired)
//!
//! This module implements asynchronous, store-and-forward sharing where a sharer
//! writes encrypted share descriptors into a recipient's "inbox" in storage.
//! The recipient can later discover and accept these shares without the sharer
//! or gateway being online at the same time.
//!
//! # Design Goals
//!
//! 1. **Offline sharing**: Recipients can pick up shares later
//! 2. **Privacy**: Inbox entries are encrypted to recipient's public key
//! 3. **Low overhead**: Small metadata objects, preserves normal read/write performance
//!
//! # Architecture
//!
//! ```text
//! Sharer                          Storage                         Recipient
//!   │                                │                                │
//!   │ 1. Create ShareToken           │                                │
//!   │    + ShareEnvelope             │                                │
//!   │                                │                                │
//!   │ 2. Encrypt for recipient ──────│───────────────────────────────►│
//!   │                                │                                │
//!   │ 3. Store in inbox ─────────────│►[InboxEntry stored]            │
//!   │                                │                                │
//!   │                                │                                │
//!   │                                │  [Later, recipient online]     │
//!   │                                │                                │
//!   │                                │◄──4. List inbox entries ───────│
//!   │                                │                                │
//!   │                                │◄──5. Decrypt & accept ─────────│
//!   │                                │                                │
//!   │                                │  6. Use ShareToken to access   │
//!   │                                │     shared content             │
//! ```
//!
//! # Reference
//!
//! - WNFS: `wnfs/src/private/share.rs` - sharer/recipient share workflow

use crate::{
    CryptoError, Result,
    hpke::{EncryptedData, Encryptor, Decryptor, SharePermissions},
    keys::{DekKey, KekKeyPair, PublicKey, SecretKey},
    sharing::{ShareToken, ShareMode, SnapshotBinding},
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

/// Generate a unique inbox entry ID
fn generate_entry_id() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

// ═══════════════════════════════════════════════════════════════════════════
// SHARE ENVELOPE - Container for ShareToken + metadata
// ═══════════════════════════════════════════════════════════════════════════

/// A share envelope containing the ShareToken and metadata about the share
///
/// This is what gets encrypted and stored in the recipient's inbox.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShareEnvelope {
    /// The actual share token with wrapped DEK and permissions
    pub token: ShareToken,
    /// Optional human-readable label for this share
    pub label: Option<String>,
    /// Optional message from the sharer
    pub message: Option<String>,
    /// Optional sharer identity (could be DID, public key fingerprint, etc.)
    pub sharer_id: Option<String>,
    /// Optional sharer display name
    pub sharer_name: Option<String>,
    /// Timestamp when this envelope was created
    pub created_at: i64,
    /// Optional custom metadata
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

impl ShareEnvelope {
    /// Create a new share envelope
    pub fn new(token: ShareToken) -> Self {
        Self {
            token,
            label: None,
            message: None,
            sharer_id: None,
            sharer_name: None,
            created_at: current_timestamp(),
            metadata: HashMap::new(),
        }
    }
    
    /// Set the label
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }
    
    /// Set a message
    pub fn with_message(mut self, message: impl Into<String>) -> Self {
        self.message = Some(message.into());
        self
    }
    
    /// Set sharer identity
    pub fn with_sharer_id(mut self, id: impl Into<String>) -> Self {
        self.sharer_id = Some(id.into());
        self
    }
    
    /// Set sharer display name
    pub fn with_sharer_name(mut self, name: impl Into<String>) -> Self {
        self.sharer_name = Some(name.into());
        self
    }
    
    /// Add custom metadata
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }
    
    /// Get the path scope from the underlying token
    pub fn path_scope(&self) -> &str {
        &self.token.path_scope
    }
    
    /// Check if the underlying token has expired
    pub fn is_expired(&self) -> bool {
        self.token.is_expired()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// INBOX ENTRY - Encrypted envelope stored in recipient's inbox
// ═══════════════════════════════════════════════════════════════════════════

/// An encrypted inbox entry stored in the recipient's inbox
///
/// The envelope is encrypted using HPKE to the recipient's public key.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InboxEntry {
    /// Unique ID for this entry
    pub id: String,
    /// The encrypted share envelope
    pub encrypted_envelope: EncryptedData,
    /// Timestamp when this entry was created
    pub created_at: i64,
    /// Status of this entry
    pub status: InboxEntryStatus,
    /// Hash of recipient's public key (for verification)
    pub recipient_key_hash: String,
}

/// Status of an inbox entry
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum InboxEntryStatus {
    /// Entry is new and unread
    #[default]
    Pending,
    /// Entry has been read but not yet accepted
    Read,
    /// Entry has been accepted
    Accepted,
    /// Entry was dismissed/rejected
    Dismissed,
    /// Entry has expired
    Expired,
}

impl InboxEntry {
    /// Create a new inbox entry by encrypting an envelope for a recipient
    pub fn create(
        envelope: &ShareEnvelope,
        recipient_public_key: &PublicKey,
    ) -> Result<Self> {
        // Serialize the envelope
        let envelope_bytes = serde_json::to_vec(envelope)
            .map_err(|e| CryptoError::Encryption(e.to_string()))?;
        
        // Encrypt to recipient using HPKE
        let encryptor = Encryptor::new(recipient_public_key);
        let encrypted = encryptor.encrypt(&envelope_bytes)?;
        
        // Hash recipient's public key for verification
        let recipient_key_hash = {
            let hash = blake3::hash(recipient_public_key.as_bytes());
            hex::encode(&hash.as_bytes()[..16])
        };
        
        Ok(Self {
            id: generate_entry_id(),
            encrypted_envelope: encrypted,
            created_at: current_timestamp(),
            status: InboxEntryStatus::Pending,
            recipient_key_hash,
        })
    }
    
    /// Decrypt the envelope using the recipient's secret key
    pub fn decrypt(&self, recipient_secret: &SecretKey) -> Result<ShareEnvelope> {
        let decryptor = Decryptor::from_secret_key(recipient_secret);
        let envelope_bytes = decryptor.decrypt(&self.encrypted_envelope)?;
        
        serde_json::from_slice(&envelope_bytes)
            .map_err(|e| CryptoError::Decryption(e.to_string()))
    }
    
    /// Check if this entry is for the given recipient
    pub fn is_for_recipient(&self, recipient_public_key: &PublicKey) -> bool {
        let hash = blake3::hash(recipient_public_key.as_bytes());
        let expected = hex::encode(&hash.as_bytes()[..16]);
        self.recipient_key_hash == expected
    }
    
    /// Check if this entry is expired (based on creation time + default TTL)
    pub fn is_stale(&self, max_age_seconds: i64) -> bool {
        current_timestamp() - self.created_at > max_age_seconds
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// SHARE INBOX - Manager for inbox operations
// ═══════════════════════════════════════════════════════════════════════════

/// Default inbox entry time-to-live (30 days)
pub const DEFAULT_INBOX_TTL_SECONDS: i64 = 30 * 24 * 60 * 60;

/// Inbox prefix for storage
pub const INBOX_PREFIX: &str = "/.fula/inbox/";

/// Manager for async/offline share inbox operations
///
/// This manages the sharer and recipient flows for store-and-forward sharing.
#[derive(Clone, Debug, Default)]
pub struct ShareInbox {
    /// Inbox entries (in memory, would be persisted via PrivateForest)
    entries: HashMap<String, InboxEntry>,
    /// TTL for inbox entries
    ttl_seconds: i64,
}

impl ShareInbox {
    /// Create a new share inbox
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            ttl_seconds: DEFAULT_INBOX_TTL_SECONDS,
        }
    }
    
    /// Create with custom TTL
    pub fn with_ttl(ttl_seconds: i64) -> Self {
        Self {
            entries: HashMap::new(),
            ttl_seconds,
        }
    }
    
    /// Set the TTL for inbox entries
    pub fn set_ttl(&mut self, seconds: i64) {
        self.ttl_seconds = seconds;
    }
    
    // ─────────────────────────────────────────────────────────────────────────
    // SHARER FLOW
    // ─────────────────────────────────────────────────────────────────────────
    
    /// Enqueue a share for a recipient (sharer flow)
    ///
    /// This creates an encrypted inbox entry that can be stored in the
    /// recipient's inbox location.
    pub fn enqueue_share(
        &mut self,
        envelope: &ShareEnvelope,
        recipient_public_key: &PublicKey,
    ) -> Result<InboxEntry> {
        let entry = InboxEntry::create(envelope, recipient_public_key)?;
        self.entries.insert(entry.id.clone(), entry.clone());
        Ok(entry)
    }
    
    /// Get the inbox path for a recipient
    pub fn inbox_path_for_recipient(recipient_public_key: &PublicKey) -> String {
        let hash = blake3::hash(recipient_public_key.as_bytes());
        let recipient_id = hex::encode(&hash.as_bytes()[..16]);
        format!("{}{}/", INBOX_PREFIX, recipient_id)
    }
    
    /// Get the full storage path for an inbox entry
    pub fn entry_storage_path(recipient_public_key: &PublicKey, entry_id: &str) -> String {
        format!("{}{}.share", Self::inbox_path_for_recipient(recipient_public_key), entry_id)
    }
    
    // ─────────────────────────────────────────────────────────────────────────
    // RECIPIENT FLOW
    // ─────────────────────────────────────────────────────────────────────────
    
    /// Load an inbox entry from serialized data
    pub fn load_entry(data: &[u8]) -> Result<InboxEntry> {
        serde_json::from_slice(data)
            .map_err(|e| CryptoError::InvalidFormat(e.to_string()))
    }
    
    /// Add an entry to the inbox (after loading from storage)
    pub fn add_entry(&mut self, entry: InboxEntry) {
        self.entries.insert(entry.id.clone(), entry);
    }
    
    /// List all pending inbox entries for a recipient
    pub fn list_pending(&self, recipient_keypair: &KekKeyPair) -> Vec<&InboxEntry> {
        self.entries.values()
            .filter(|e| {
                e.status == InboxEntryStatus::Pending &&
                e.is_for_recipient(recipient_keypair.public_key()) &&
                !e.is_stale(self.ttl_seconds)
            })
            .collect()
    }
    
    /// List all entries (any status)
    pub fn list_all(&self) -> Vec<&InboxEntry> {
        self.entries.values().collect()
    }
    
    /// Get an entry by ID
    pub fn get_entry(&self, id: &str) -> Option<&InboxEntry> {
        self.entries.get(id)
    }
    
    /// Get a mutable entry by ID
    pub fn get_entry_mut(&mut self, id: &str) -> Option<&mut InboxEntry> {
        self.entries.get_mut(id)
    }
    
    /// Accept an inbox entry and return the decrypted envelope
    pub fn accept_entry(
        &mut self,
        entry_id: &str,
        recipient_keypair: &KekKeyPair,
    ) -> Result<ShareEnvelope> {
        let entry = self.entries.get_mut(entry_id)
            .ok_or_else(|| CryptoError::InvalidKey(format!("Entry not found: {}", entry_id)))?;
        
        // Verify this entry is for the recipient
        if !entry.is_for_recipient(recipient_keypair.public_key()) {
            return Err(CryptoError::InvalidKey("Entry is not for this recipient".into()));
        }
        
        // Decrypt the envelope
        let envelope = entry.decrypt(recipient_keypair.secret_key())?;
        
        // Update status
        entry.status = InboxEntryStatus::Accepted;
        
        Ok(envelope)
    }
    
    /// Mark an entry as read (without accepting)
    pub fn mark_read(&mut self, entry_id: &str) -> bool {
        if let Some(entry) = self.entries.get_mut(entry_id) {
            if entry.status == InboxEntryStatus::Pending {
                entry.status = InboxEntryStatus::Read;
                return true;
            }
        }
        false
    }
    
    /// Dismiss/reject an entry
    pub fn dismiss_entry(&mut self, entry_id: &str) -> bool {
        if let Some(entry) = self.entries.get_mut(entry_id) {
            entry.status = InboxEntryStatus::Dismissed;
            return true;
        }
        false
    }
    
    /// Remove an entry from the inbox
    pub fn remove_entry(&mut self, entry_id: &str) -> Option<InboxEntry> {
        self.entries.remove(entry_id)
    }
    
    /// Clean up stale and expired entries
    pub fn cleanup(&mut self) -> usize {
        let before = self.entries.len();
        self.entries.retain(|_, entry| {
            !entry.is_stale(self.ttl_seconds) && 
            entry.status != InboxEntryStatus::Dismissed &&
            entry.status != InboxEntryStatus::Expired
        });
        before - self.entries.len()
    }
    
    /// Get count of pending entries
    pub fn pending_count(&self, recipient_keypair: &KekKeyPair) -> usize {
        self.list_pending(recipient_keypair).len()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// SHARE ENVELOPE BUILDER - Fluent API for creating envelopes
// ═══════════════════════════════════════════════════════════════════════════

/// Builder for creating share envelopes
pub struct ShareEnvelopeBuilder<'a> {
    owner_keypair: &'a KekKeyPair,
    recipient_public_key: &'a PublicKey,
    dek: &'a DekKey,
    path_scope: String,
    expires_at: Option<i64>,
    permissions: SharePermissions,
    mode: ShareMode,
    snapshot_binding: Option<SnapshotBinding>,
    label: Option<String>,
    message: Option<String>,
    sharer_id: Option<String>,
    sharer_name: Option<String>,
    metadata: HashMap<String, String>,
}

impl<'a> ShareEnvelopeBuilder<'a> {
    /// Create a new envelope builder
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
            label: None,
            message: None,
            sharer_id: None,
            sharer_name: None,
            metadata: HashMap::new(),
        }
    }
    
    /// Set the path scope
    pub fn path_scope(mut self, path: impl Into<String>) -> Self {
        self.path_scope = path.into();
        self
    }
    
    /// Set expiry as duration from now
    pub fn expires_in(mut self, seconds: i64) -> Self {
        self.expires_at = Some(current_timestamp() + seconds);
        self
    }
    
    /// Set absolute expiry timestamp
    pub fn expires_at(mut self, timestamp: i64) -> Self {
        self.expires_at = Some(timestamp);
        self
    }
    
    /// Set read-only permissions
    pub fn read_only(mut self) -> Self {
        self.permissions = SharePermissions::read_only();
        self
    }
    
    /// Set read-write permissions
    pub fn read_write(mut self) -> Self {
        self.permissions = SharePermissions::read_write();
        self
    }
    
    /// Set custom permissions
    pub fn permissions(mut self, permissions: SharePermissions) -> Self {
        self.permissions = permissions;
        self
    }
    
    /// Set share mode to temporal
    pub fn temporal(mut self) -> Self {
        self.mode = ShareMode::Temporal;
        self.snapshot_binding = None;
        self
    }
    
    /// Set share mode to snapshot
    pub fn snapshot(mut self, binding: SnapshotBinding) -> Self {
        self.mode = ShareMode::Snapshot;
        self.snapshot_binding = Some(binding);
        self
    }
    
    /// Set a label for this share
    pub fn label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }
    
    /// Set a message for the recipient
    pub fn message(mut self, message: impl Into<String>) -> Self {
        self.message = Some(message.into());
        self
    }
    
    /// Set sharer identity
    pub fn sharer_id(mut self, id: impl Into<String>) -> Self {
        self.sharer_id = Some(id.into());
        self
    }
    
    /// Set sharer display name
    pub fn sharer_name(mut self, name: impl Into<String>) -> Self {
        self.sharer_name = Some(name.into());
        self
    }
    
    /// Add custom metadata
    pub fn metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }
    
    /// Build the share envelope and encrypted inbox entry
    pub fn build(self) -> Result<(ShareEnvelope, InboxEntry)> {
        use crate::sharing::ShareBuilder;
        
        // Build the underlying ShareToken
        let mut token_builder = ShareBuilder::new(
            self.owner_keypair,
            self.recipient_public_key,
            self.dek,
        )
            .path_scope(&self.path_scope)
            .permissions(self.permissions);
        
        if let Some(exp) = self.expires_at {
            token_builder = token_builder.expires_at(exp);
        }
        
        if self.mode == ShareMode::Snapshot {
            if let Some(binding) = self.snapshot_binding {
                token_builder = token_builder.snapshot(binding);
            }
        }
        
        let token = token_builder.build()?;
        
        // Build the envelope
        let mut envelope = ShareEnvelope::new(token);
        
        if let Some(label) = self.label {
            envelope = envelope.with_label(label);
        }
        if let Some(message) = self.message {
            envelope = envelope.with_message(message);
        }
        if let Some(id) = self.sharer_id {
            envelope = envelope.with_sharer_id(id);
        }
        if let Some(name) = self.sharer_name {
            envelope = envelope.with_sharer_name(name);
        }
        for (k, v) in self.metadata {
            envelope = envelope.with_metadata(k, v);
        }
        
        // Create the encrypted inbox entry
        let entry = InboxEntry::create(&envelope, self.recipient_public_key)?;
        
        Ok((envelope, entry))
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sharing::ShareBuilder;

    #[test]
    fn test_share_envelope_creation() {
        let owner = KekKeyPair::generate();
        let recipient = KekKeyPair::generate();
        let dek = DekKey::generate();
        
        let token = ShareBuilder::new(&owner, recipient.public_key(), &dek)
            .path_scope("/photos/")
            .build()
            .unwrap();
        
        let envelope = ShareEnvelope::new(token)
            .with_label("Vacation Photos")
            .with_message("Check out my vacation pics!")
            .with_sharer_name("Alice");
        
        assert_eq!(envelope.label, Some("Vacation Photos".to_string()));
        assert_eq!(envelope.message, Some("Check out my vacation pics!".to_string()));
        assert_eq!(envelope.sharer_name, Some("Alice".to_string()));
        assert_eq!(envelope.path_scope(), "/photos/");
    }
    
    #[test]
    fn test_inbox_entry_encrypt_decrypt() {
        let owner = KekKeyPair::generate();
        let recipient = KekKeyPair::generate();
        let dek = DekKey::generate();
        
        let token = ShareBuilder::new(&owner, recipient.public_key(), &dek)
            .path_scope("/shared/")
            .build()
            .unwrap();
        
        let envelope = ShareEnvelope::new(token)
            .with_label("Test Share");
        
        // Create encrypted entry
        let entry = InboxEntry::create(&envelope, recipient.public_key()).unwrap();
        
        assert!(entry.is_for_recipient(recipient.public_key()));
        assert!(!entry.is_for_recipient(owner.public_key()));
        assert_eq!(entry.status, InboxEntryStatus::Pending);
        
        // Decrypt
        let decrypted = entry.decrypt(recipient.secret_key()).unwrap();
        
        assert_eq!(decrypted.label, Some("Test Share".to_string()));
        assert_eq!(decrypted.path_scope(), "/shared/");
    }
    
    #[test]
    fn test_wrong_recipient_cannot_decrypt() {
        let owner = KekKeyPair::generate();
        let intended = KekKeyPair::generate();
        let wrong = KekKeyPair::generate();
        let dek = DekKey::generate();
        
        let token = ShareBuilder::new(&owner, intended.public_key(), &dek)
            .build()
            .unwrap();
        
        let envelope = ShareEnvelope::new(token);
        let entry = InboxEntry::create(&envelope, intended.public_key()).unwrap();
        
        // Wrong recipient cannot decrypt
        let result = entry.decrypt(wrong.secret_key());
        assert!(result.is_err());
    }
    
    #[test]
    fn test_share_inbox_workflow() {
        let owner = KekKeyPair::generate();
        let recipient = KekKeyPair::generate();
        let dek = DekKey::generate();
        
        let mut inbox = ShareInbox::new();
        
        // Sharer creates and enqueues share
        let token = ShareBuilder::new(&owner, recipient.public_key(), &dek)
            .path_scope("/photos/vacation/")
            .expires_in(3600)
            .build()
            .unwrap();
        
        let envelope = ShareEnvelope::new(token)
            .with_label("Vacation 2024")
            .with_sharer_name("Alice");
        
        let entry = inbox.enqueue_share(&envelope, recipient.public_key()).unwrap();
        let entry_id = entry.id.clone();
        
        // Recipient lists pending shares
        let pending = inbox.list_pending(&recipient);
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].id, entry_id);
        
        // Recipient accepts share
        let accepted = inbox.accept_entry(&entry_id, &recipient).unwrap();
        
        assert_eq!(accepted.label, Some("Vacation 2024".to_string()));
        assert_eq!(accepted.sharer_name, Some("Alice".to_string()));
        assert_eq!(accepted.path_scope(), "/photos/vacation/");
        
        // Entry is now accepted
        let entry = inbox.get_entry(&entry_id).unwrap();
        assert_eq!(entry.status, InboxEntryStatus::Accepted);
        
        // No more pending
        let pending = inbox.list_pending(&recipient);
        assert_eq!(pending.len(), 0);
    }
    
    #[test]
    fn test_inbox_dismiss() {
        let owner = KekKeyPair::generate();
        let recipient = KekKeyPair::generate();
        let dek = DekKey::generate();
        
        let mut inbox = ShareInbox::new();
        
        let token = ShareBuilder::new(&owner, recipient.public_key(), &dek)
            .build()
            .unwrap();
        
        let envelope = ShareEnvelope::new(token);
        let entry = inbox.enqueue_share(&envelope, recipient.public_key()).unwrap();
        let entry_id = entry.id.clone();
        
        // Dismiss
        assert!(inbox.dismiss_entry(&entry_id));
        
        let entry = inbox.get_entry(&entry_id).unwrap();
        assert_eq!(entry.status, InboxEntryStatus::Dismissed);
        
        // Dismissed entries not in pending
        let pending = inbox.list_pending(&recipient);
        assert_eq!(pending.len(), 0);
    }
    
    #[test]
    fn test_inbox_cleanup() {
        let owner = KekKeyPair::generate();
        let recipient = KekKeyPair::generate();
        let dek = DekKey::generate();
        
        let mut inbox = ShareInbox::with_ttl(1); // 1 second TTL
        
        let token = ShareBuilder::new(&owner, recipient.public_key(), &dek)
            .build()
            .unwrap();
        
        let envelope = ShareEnvelope::new(token);
        inbox.enqueue_share(&envelope, recipient.public_key()).unwrap();
        
        assert_eq!(inbox.list_all().len(), 1);
        
        // Wait for TTL to expire
        std::thread::sleep(std::time::Duration::from_secs(2));
        
        // Cleanup removes stale entries
        let removed = inbox.cleanup();
        assert_eq!(removed, 1);
        assert_eq!(inbox.list_all().len(), 0);
    }
    
    #[test]
    fn test_inbox_path_generation() {
        let recipient = KekKeyPair::generate();
        
        let path = ShareInbox::inbox_path_for_recipient(recipient.public_key());
        assert!(path.starts_with("/.fula/inbox/"));
        assert!(path.ends_with("/"));
        
        let entry_path = ShareInbox::entry_storage_path(recipient.public_key(), "abc123");
        assert!(entry_path.starts_with("/.fula/inbox/"));
        assert!(entry_path.ends_with("/abc123.share"));
    }
    
    #[test]
    fn test_share_envelope_builder() {
        let owner = KekKeyPair::generate();
        let recipient = KekKeyPair::generate();
        let dek = DekKey::generate();
        
        let (envelope, entry) = ShareEnvelopeBuilder::new(&owner, recipient.public_key(), &dek)
            .path_scope("/docs/")
            .expires_in(7200)
            .read_write()
            .label("Important Documents")
            .message("Please review these docs")
            .sharer_name("Bob")
            .metadata("project", "alpha")
            .build()
            .unwrap();
        
        assert_eq!(envelope.label, Some("Important Documents".to_string()));
        assert_eq!(envelope.message, Some("Please review these docs".to_string()));
        assert_eq!(envelope.sharer_name, Some("Bob".to_string()));
        assert_eq!(envelope.metadata.get("project"), Some(&"alpha".to_string()));
        assert_eq!(envelope.path_scope(), "/docs/");
        assert!(envelope.token.permissions.can_read);
        assert!(envelope.token.permissions.can_write);
        
        // Entry can be decrypted by recipient
        let decrypted = entry.decrypt(recipient.secret_key()).unwrap();
        assert_eq!(decrypted.label, envelope.label);
    }
    
    #[test]
    fn test_multiple_shares_same_recipient() {
        let owner1 = KekKeyPair::generate();
        let owner2 = KekKeyPair::generate();
        let recipient = KekKeyPair::generate();
        let dek1 = DekKey::generate();
        let dek2 = DekKey::generate();
        
        let mut inbox = ShareInbox::new();
        
        // First share from owner1
        let token1 = ShareBuilder::new(&owner1, recipient.public_key(), &dek1)
            .path_scope("/photos/")
            .build()
            .unwrap();
        let envelope1 = ShareEnvelope::new(token1).with_label("Photos from Alice");
        inbox.enqueue_share(&envelope1, recipient.public_key()).unwrap();
        
        // Second share from owner2
        let token2 = ShareBuilder::new(&owner2, recipient.public_key(), &dek2)
            .path_scope("/music/")
            .build()
            .unwrap();
        let envelope2 = ShareEnvelope::new(token2).with_label("Music from Bob");
        inbox.enqueue_share(&envelope2, recipient.public_key()).unwrap();
        
        // Recipient sees both
        let pending = inbox.list_pending(&recipient);
        assert_eq!(pending.len(), 2);
    }
    
    #[test]
    fn test_inbox_entry_serialization() {
        let owner = KekKeyPair::generate();
        let recipient = KekKeyPair::generate();
        let dek = DekKey::generate();
        
        let token = ShareBuilder::new(&owner, recipient.public_key(), &dek)
            .path_scope("/test/")
            .build()
            .unwrap();
        
        let envelope = ShareEnvelope::new(token).with_label("Test");
        let entry = InboxEntry::create(&envelope, recipient.public_key()).unwrap();
        
        // Serialize
        let json = serde_json::to_string(&entry).unwrap();
        
        // Deserialize
        let loaded = ShareInbox::load_entry(json.as_bytes()).unwrap();
        
        assert_eq!(loaded.id, entry.id);
        assert_eq!(loaded.status, entry.status);
        
        // Can still decrypt
        let decrypted = loaded.decrypt(recipient.secret_key()).unwrap();
        assert_eq!(decrypted.label, Some("Test".to_string()));
    }
}
