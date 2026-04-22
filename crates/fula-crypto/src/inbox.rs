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
    time::now_timestamp,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Get current Unix timestamp in seconds (WASM-compatible)
fn current_timestamp() -> i64 {
    now_timestamp()
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
/// The envelope is encrypted using HPKE **Auth mode** to the recipient's
/// public key, binding the sender's long-term KEK keypair into the HPKE
/// context (RFC 9180 §5, mode `auth`). The claimed sender public key lives
/// outside the ciphertext (`sender_public_key`) so the recipient can
/// bootstrap verification; tampering with that field causes the HPKE auth
/// check to fail with a generic authentication error.
///
/// M-6: with Auth mode the recipient can prove that whoever produced this
/// entry held the secret for `sender_public_key`, turning `sharer_id` /
/// `sharer_name` from free-form claims into strings anchored to a verified
/// key. Pinning a `sender_public_key` to a human identity remains a UI-layer
/// concern (out-of-band fingerprint exchange).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InboxEntry {
    /// Unique ID for this entry
    pub id: String,
    /// The encrypted share envelope (HPKE Auth mode)
    pub encrypted_envelope: EncryptedData,
    /// Timestamp when this entry was created
    pub created_at: i64,
    /// Status of this entry
    pub status: InboxEntryStatus,
    /// Hash of recipient's public key (for verification)
    pub recipient_key_hash: String,
    /// Sender's long-term KEK public key (X25519, 32 bytes).
    ///
    /// Required — no Base-mode legacy envelopes survive the v5 cutover.
    /// Under HPKE Auth mode this field is consulted by the recipient when
    /// opening the envelope; any mismatch between this claimed value and
    /// the keypair actually used at encrypt time fails the HPKE auth check.
    pub sender_public_key: [u8; 32],
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

/// Domain separator for the Auth-mode envelope AAD (M-6). The recipient pk
/// hash is appended so a ciphertext captured in flight cannot be replayed
/// to a different recipient of the same sender — the recipient reconstructs
/// the AAD from its own pk, mismatches collapse to a generic HPKE failure.
const ENVELOPE_AAD_PREFIX_V5: &[u8] = b"fula:v5:envelope|";

/// Build the envelope AAD used by both encrypt and decrypt. Length-prefixed
/// `recipient_pk_hash` (16 bytes) binds the recipient of the ciphertext.
fn build_envelope_aad(recipient_pk_hash: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(ENVELOPE_AAD_PREFIX_V5.len() + 4 + recipient_pk_hash.len());
    aad.extend_from_slice(ENVELOPE_AAD_PREFIX_V5);
    aad.extend_from_slice(&(recipient_pk_hash.len() as u32).to_be_bytes());
    aad.extend_from_slice(recipient_pk_hash);
    aad
}

fn recipient_pk_hash_bytes(recipient_public_key: &PublicKey) -> [u8; 16] {
    let hash = blake3::hash(recipient_public_key.as_bytes());
    let mut out = [0u8; 16];
    out.copy_from_slice(&hash.as_bytes()[..16]);
    out
}

impl InboxEntry {
    /// Create a new inbox entry by encrypting an envelope for a recipient
    /// under HPKE Auth mode (M-6). The `sender_keypair` authenticates the
    /// producer — recipients can verify that whoever built this entry held
    /// the matching secret key.
    pub fn create(
        envelope: &ShareEnvelope,
        recipient_public_key: &PublicKey,
        sender_keypair: &KekKeyPair,
    ) -> Result<Self> {
        // Serialize the envelope
        let envelope_bytes = serde_json::to_vec(envelope)
            .map_err(|e| CryptoError::Encryption(e.to_string()))?;

        // Bind recipient pk hash into AAD so captures aren't replayable.
        let recipient_pk_hash_raw = recipient_pk_hash_bytes(recipient_public_key);
        let aad = build_envelope_aad(&recipient_pk_hash_raw);

        // Encrypt to recipient using HPKE Auth mode, binding the sender keypair.
        let encryptor = Encryptor::new(recipient_public_key);
        let encrypted =
            encryptor.encrypt_for_recipient_auth(sender_keypair, &envelope_bytes, &aad)?;

        let mut sender_pk_bytes = [0u8; 32];
        sender_pk_bytes.copy_from_slice(sender_keypair.public_key().as_bytes());

        Ok(Self {
            id: generate_entry_id(),
            encrypted_envelope: encrypted,
            created_at: current_timestamp(),
            status: InboxEntryStatus::Pending,
            recipient_key_hash: hex::encode(recipient_pk_hash_raw),
            sender_public_key: sender_pk_bytes,
        })
    }

    /// Decrypt the envelope using the recipient's secret key, verifying the
    /// sender via HPKE Auth mode. Also enforces the M-5 token-version gate
    /// post-decrypt: envelopes whose inner `ShareToken` predates the v5
    /// recipient-pk AAD binding are rejected even if HPKE accepts them.
    pub fn decrypt(&self, recipient_secret: &SecretKey) -> Result<ShareEnvelope> {
        // Derive recipient pk from the supplied secret key and rebuild AAD —
        // must be done locally so a tampered `recipient_key_hash` cannot
        // steer the AAD construction.
        let derived_pk = recipient_secret.public_key();
        let recipient_pk_hash_raw = recipient_pk_hash_bytes(&derived_pk);
        let aad = build_envelope_aad(&recipient_pk_hash_raw);

        let sender_pk = PublicKey::from_bytes(&self.sender_public_key)
            .map_err(|_| CryptoError::Decryption("authentication failed".to_string()))?;
        let decryptor = Decryptor::from_secret_key(recipient_secret);
        let envelope_bytes =
            decryptor.decrypt_for_recipient_auth(&sender_pk, &self.encrypted_envelope, &aad)?;

        let envelope: ShareEnvelope = serde_json::from_slice(&envelope_bytes)
            .map_err(|e| CryptoError::Decryption(e.to_string()))?;

        // M-5 alignment: reject envelopes whose token lacks the recipient-pk
        // AAD binding. Paired with the enqueue-time gate in Inbox::enqueue_share.
        if envelope.token.version < crate::sharing::SHARE_TOKEN_AAD_V5 {
            return Err(CryptoError::Decryption(
                "inbox envelope rejected: share token predates recipient-pk AAD binding".to_string(),
            ));
        }

        Ok(envelope)
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
    ///
    /// M-5: Rejects envelopes whose inner `ShareToken` predates the v5 AAD
    /// binding. A pre-v5 token has no recipient-pk commitment, so enqueueing
    /// one into a different recipient's inbox would produce an unopenable
    /// entry (DoS / inbox-spam vector). The version gate is a cheap format
    /// check that fails fast with a clear error, long before the envelope
    /// ciphertext is stored.
    pub fn enqueue_share(
        &mut self,
        envelope: &ShareEnvelope,
        recipient_public_key: &PublicKey,
        sender_keypair: &KekKeyPair,
    ) -> Result<InboxEntry> {
        use crate::sharing::SHARE_TOKEN_AAD_V5;
        if envelope.token.version < SHARE_TOKEN_AAD_V5 {
            return Err(CryptoError::InvalidFormat(
                "inbox envelope rejected: share token predates recipient-pk AAD binding \
                 (token version < 5)".to_string(),
            ));
        }
        let entry = InboxEntry::create(envelope, recipient_public_key, sender_keypair)?;
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
    ///
    /// # Deprecated
    /// Use `list_pending()` with recipient key for user-scoped access.
    /// This method returns all entries without recipient verification.
    #[deprecated(note = "Use list_pending() with recipient key for user-scoped access")]
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
    ///
    /// Security: Verifies the entry belongs to the recipient before modifying.
    pub fn mark_read(&mut self, entry_id: &str, recipient: &PublicKey) -> Result<bool> {
        if let Some(entry) = self.entries.get_mut(entry_id) {
            // Verify recipient owns this entry
            if !entry.is_for_recipient(recipient) {
                return Err(CryptoError::InvalidKey("Entry is not for this recipient".into()));
            }
            if entry.status == InboxEntryStatus::Pending {
                entry.status = InboxEntryStatus::Read;
                return Ok(true);
            }
            Ok(false)
        } else {
            Ok(false)
        }
    }

    /// Dismiss/reject an entry
    ///
    /// Security: Verifies the entry belongs to the recipient before modifying.
    pub fn dismiss_entry(&mut self, entry_id: &str, recipient: &PublicKey) -> Result<bool> {
        if let Some(entry) = self.entries.get_mut(entry_id) {
            // Verify recipient owns this entry
            if !entry.is_for_recipient(recipient) {
                return Err(CryptoError::InvalidKey("Entry is not for this recipient".into()));
            }
            entry.status = InboxEntryStatus::Dismissed;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Remove an entry from the inbox
    ///
    /// Security: Verifies the entry belongs to the recipient before removing.
    pub fn remove_entry(&mut self, entry_id: &str, recipient: &PublicKey) -> Result<Option<InboxEntry>> {
        // First verify ownership
        if let Some(entry) = self.entries.get(entry_id) {
            if !entry.is_for_recipient(recipient) {
                return Err(CryptoError::InvalidKey("Entry is not for this recipient".into()));
            }
        }
        Ok(self.entries.remove(entry_id))
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
        
        // Create the encrypted inbox entry. Auth mode (M-6) binds the
        // sender's long-term keypair into the HPKE context so the recipient
        // can verify that `sender_public_key` actually produced the envelope.
        let entry =
            InboxEntry::create(&envelope, self.recipient_public_key, self.owner_keypair)?;

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
        let entry = InboxEntry::create(&envelope, recipient.public_key(), &owner).unwrap();
        
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
        let entry = InboxEntry::create(&envelope, intended.public_key(), &owner).unwrap();
        
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

        let entry = inbox.enqueue_share(&envelope, recipient.public_key(), &owner).unwrap();
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
        let entry = inbox.enqueue_share(&envelope, recipient.public_key(), &owner).unwrap();
        let entry_id = entry.id.clone();

        // Dismiss with correct recipient
        assert!(inbox.dismiss_entry(&entry_id, recipient.public_key()).unwrap());

        let entry = inbox.get_entry(&entry_id).unwrap();
        assert_eq!(entry.status, InboxEntryStatus::Dismissed);

        // Dismissed entries not in pending
        let pending = inbox.list_pending(&recipient);
        assert_eq!(pending.len(), 0);
    }

    #[test]
    fn test_inbox_dismiss_wrong_recipient() {
        let owner = KekKeyPair::generate();
        let recipient = KekKeyPair::generate();
        let wrong_recipient = KekKeyPair::generate();
        let dek = DekKey::generate();

        let mut inbox = ShareInbox::new();

        let token = ShareBuilder::new(&owner, recipient.public_key(), &dek)
            .build()
            .unwrap();

        let envelope = ShareEnvelope::new(token);
        let entry = inbox.enqueue_share(&envelope, recipient.public_key(), &owner).unwrap();
        let entry_id = entry.id.clone();

        // Wrong recipient cannot dismiss
        let result = inbox.dismiss_entry(&entry_id, wrong_recipient.public_key());
        assert!(result.is_err());

        // Entry should still be pending
        let entry = inbox.get_entry(&entry_id).unwrap();
        assert_eq!(entry.status, InboxEntryStatus::Pending);
    }
    
    #[test]
    #[allow(deprecated)]
    fn test_inbox_cleanup() {
        let owner = KekKeyPair::generate();
        let recipient = KekKeyPair::generate();
        let dek = DekKey::generate();

        let mut inbox = ShareInbox::with_ttl(1); // 1 second TTL

        let token = ShareBuilder::new(&owner, recipient.public_key(), &dek)
            .build()
            .unwrap();

        let envelope = ShareEnvelope::new(token);
        inbox.enqueue_share(&envelope, recipient.public_key(), &owner).unwrap();

        // Using deprecated list_all() for test purposes
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
        inbox.enqueue_share(&envelope1, recipient.public_key(), &owner1).unwrap();
        
        // Second share from owner2
        let token2 = ShareBuilder::new(&owner2, recipient.public_key(), &dek2)
            .path_scope("/music/")
            .build()
            .unwrap();
        let envelope2 = ShareEnvelope::new(token2).with_label("Music from Bob");
        inbox.enqueue_share(&envelope2, recipient.public_key(), &owner2).unwrap();
        
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
        let entry = InboxEntry::create(&envelope, recipient.public_key(), &owner).unwrap();
        
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

    // ═══════════════════════════════════════════════════════════════════════════
    // ISOLATION / LEAKAGE TESTS
    // These tests verify that no cross-user data leakage can occur
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_isolation_list_pending_only_shows_own_entries() {
        // Scenario: Multiple users have entries in same ShareInbox
        // Verify: Each user only sees their own entries via list_pending()
        let owner = KekKeyPair::generate();
        let user_a = KekKeyPair::generate();
        let user_b = KekKeyPair::generate();
        let user_c = KekKeyPair::generate();
        let dek = DekKey::generate();

        let mut inbox = ShareInbox::new();

        // Create entries for different users
        let token_a = ShareBuilder::new(&owner, user_a.public_key(), &dek)
            .path_scope("/for-a/")
            .build()
            .unwrap();
        let envelope_a = ShareEnvelope::new(token_a).with_label("For User A");
        inbox.enqueue_share(&envelope_a, user_a.public_key(), &owner).unwrap();

        let token_b1 = ShareBuilder::new(&owner, user_b.public_key(), &dek)
            .path_scope("/for-b-1/")
            .build()
            .unwrap();
        let envelope_b1 = ShareEnvelope::new(token_b1).with_label("For User B - 1");
        inbox.enqueue_share(&envelope_b1, user_b.public_key(), &owner).unwrap();

        let token_b2 = ShareBuilder::new(&owner, user_b.public_key(), &dek)
            .path_scope("/for-b-2/")
            .build()
            .unwrap();
        let envelope_b2 = ShareEnvelope::new(token_b2).with_label("For User B - 2");
        inbox.enqueue_share(&envelope_b2, user_b.public_key(), &owner).unwrap();

        // User A should only see 1 entry
        let pending_a = inbox.list_pending(&user_a);
        assert_eq!(pending_a.len(), 1, "User A should see exactly 1 entry");
        assert!(pending_a[0].is_for_recipient(user_a.public_key()));

        // User B should see 2 entries
        let pending_b = inbox.list_pending(&user_b);
        assert_eq!(pending_b.len(), 2, "User B should see exactly 2 entries");
        for entry in &pending_b {
            assert!(entry.is_for_recipient(user_b.public_key()));
        }

        // User C should see 0 entries (no shares for them)
        let pending_c = inbox.list_pending(&user_c);
        assert_eq!(pending_c.len(), 0, "User C should see no entries");
    }

    #[test]
    fn test_isolation_wrong_recipient_cannot_mark_read() {
        let owner = KekKeyPair::generate();
        let intended_recipient = KekKeyPair::generate();
        let attacker = KekKeyPair::generate();
        let dek = DekKey::generate();

        let mut inbox = ShareInbox::new();

        let token = ShareBuilder::new(&owner, intended_recipient.public_key(), &dek)
            .build()
            .unwrap();
        let envelope = ShareEnvelope::new(token);
        let entry = inbox.enqueue_share(&envelope, intended_recipient.public_key(), &owner).unwrap();
        let entry_id = entry.id.clone();

        // Attacker tries to mark_read - should fail
        let result = inbox.mark_read(&entry_id, attacker.public_key());
        assert!(result.is_err(), "Attacker should not be able to mark_read");

        // Entry should still be Pending
        let entry = inbox.get_entry(&entry_id).unwrap();
        assert_eq!(entry.status, InboxEntryStatus::Pending, "Status should remain Pending");

        // Intended recipient can mark_read
        let result = inbox.mark_read(&entry_id, intended_recipient.public_key());
        assert!(result.is_ok(), "Intended recipient should be able to mark_read");
        assert!(result.unwrap(), "mark_read should return true");
    }

    #[test]
    fn test_isolation_wrong_recipient_cannot_remove() {
        let owner = KekKeyPair::generate();
        let intended_recipient = KekKeyPair::generate();
        let attacker = KekKeyPair::generate();
        let dek = DekKey::generate();

        let mut inbox = ShareInbox::new();

        let token = ShareBuilder::new(&owner, intended_recipient.public_key(), &dek)
            .build()
            .unwrap();
        let envelope = ShareEnvelope::new(token);
        let entry = inbox.enqueue_share(&envelope, intended_recipient.public_key(), &owner).unwrap();
        let entry_id = entry.id.clone();

        // Attacker tries to remove - should fail
        let result = inbox.remove_entry(&entry_id, attacker.public_key());
        assert!(result.is_err(), "Attacker should not be able to remove entry");

        // Entry should still exist
        assert!(inbox.get_entry(&entry_id).is_some(), "Entry should still exist");

        // Intended recipient can remove
        let result = inbox.remove_entry(&entry_id, intended_recipient.public_key());
        assert!(result.is_ok(), "Intended recipient should be able to remove");
        assert!(result.unwrap().is_some(), "remove_entry should return the entry");

        // Entry should be gone
        assert!(inbox.get_entry(&entry_id).is_none(), "Entry should be removed");
    }

    #[test]
    fn test_isolation_wrong_recipient_cannot_accept() {
        let owner = KekKeyPair::generate();
        let intended_recipient = KekKeyPair::generate();
        let attacker = KekKeyPair::generate();
        let dek = DekKey::generate();

        let mut inbox = ShareInbox::new();

        let token = ShareBuilder::new(&owner, intended_recipient.public_key(), &dek)
            .path_scope("/secret/")
            .build()
            .unwrap();
        let envelope = ShareEnvelope::new(token).with_label("Secret Data");
        let entry = inbox.enqueue_share(&envelope, intended_recipient.public_key(), &owner).unwrap();
        let entry_id = entry.id.clone();

        // Attacker tries to accept - should fail
        let result = inbox.accept_entry(&entry_id, &attacker);
        assert!(result.is_err(), "Attacker should not be able to accept entry");

        // Entry should still be Pending (not Accepted)
        let entry = inbox.get_entry(&entry_id).unwrap();
        assert_eq!(entry.status, InboxEntryStatus::Pending, "Status should remain Pending");

        // Intended recipient can accept
        let result = inbox.accept_entry(&entry_id, &intended_recipient);
        assert!(result.is_ok(), "Intended recipient should be able to accept");
        let envelope = result.unwrap();
        assert_eq!(envelope.label, Some("Secret Data".to_string()));
    }

    #[test]
    fn test_isolation_entry_content_encrypted_per_recipient() {
        // Scenario: Even if attacker gets the InboxEntry, they cannot decrypt
        let owner = KekKeyPair::generate();
        let intended_recipient = KekKeyPair::generate();
        let attacker = KekKeyPair::generate();
        let dek = DekKey::generate();

        let token = ShareBuilder::new(&owner, intended_recipient.public_key(), &dek)
            .path_scope("/confidential/")
            .build()
            .unwrap();
        let envelope = ShareEnvelope::new(token).with_label("Confidential");
        let entry = InboxEntry::create(&envelope, intended_recipient.public_key(), &owner).unwrap();

        // Attacker cannot decrypt even with direct access to the entry
        let decrypt_result = entry.decrypt(attacker.secret_key());
        assert!(decrypt_result.is_err(), "Attacker should not be able to decrypt");

        // Intended recipient can decrypt
        let decrypt_result = entry.decrypt(intended_recipient.secret_key());
        assert!(decrypt_result.is_ok(), "Intended recipient should be able to decrypt");
        let decrypted = decrypt_result.unwrap();
        assert_eq!(decrypted.label, Some("Confidential".to_string()));
    }

    #[test]
    fn test_isolation_recipient_hash_prevents_enumeration() {
        // Verify that recipient_key_hash correctly identifies ownership
        let user_a = KekKeyPair::generate();
        let user_b = KekKeyPair::generate();

        // Different users should have different inbox paths
        let path_a = ShareInbox::inbox_path_for_recipient(user_a.public_key());
        let path_b = ShareInbox::inbox_path_for_recipient(user_b.public_key());

        assert_ne!(path_a, path_b, "Different users should have different inbox paths");

        // Same user should always get same path (deterministic)
        let path_a2 = ShareInbox::inbox_path_for_recipient(user_a.public_key());
        assert_eq!(path_a, path_a2, "Same user should get same inbox path");
    }

    #[test]
    fn test_isolation_multi_user_inbox_no_cross_contamination() {
        // Comprehensive test: multiple users, multiple shares, verify complete isolation
        let owner = KekKeyPair::generate();
        let alice = KekKeyPair::generate();
        let bob = KekKeyPair::generate();
        let charlie = KekKeyPair::generate();
        let dek = DekKey::generate();

        let mut inbox = ShareInbox::new();

        // Create shares for Alice
        let token_alice = ShareBuilder::new(&owner, alice.public_key(), &dek)
            .path_scope("/alice-secret/")
            .build()
            .unwrap();
        let envelope_alice = ShareEnvelope::new(token_alice).with_label("Alice's Secret");
        let entry_alice = inbox.enqueue_share(&envelope_alice, alice.public_key(), &owner).unwrap();

        // Create shares for Bob
        let token_bob = ShareBuilder::new(&owner, bob.public_key(), &dek)
            .path_scope("/bob-secret/")
            .build()
            .unwrap();
        let envelope_bob = ShareEnvelope::new(token_bob).with_label("Bob's Secret");
        let entry_bob = inbox.enqueue_share(&envelope_bob, bob.public_key(), &owner).unwrap();

        // === VERIFICATION: Alice's operations ===

        // Alice can see only her entry
        let alice_pending = inbox.list_pending(&alice);
        assert_eq!(alice_pending.len(), 1);
        assert_eq!(alice_pending[0].id, entry_alice.id);

        // Alice cannot operate on Bob's entry
        assert!(inbox.mark_read(&entry_bob.id, alice.public_key()).is_err());
        assert!(inbox.dismiss_entry(&entry_bob.id, alice.public_key()).is_err());
        assert!(inbox.remove_entry(&entry_bob.id, alice.public_key()).is_err());
        assert!(inbox.accept_entry(&entry_bob.id, &alice).is_err());

        // Alice can operate on her own entry
        assert!(inbox.accept_entry(&entry_alice.id, &alice).is_ok());

        // === VERIFICATION: Bob's operations ===

        // Bob can see only his entry
        let bob_pending = inbox.list_pending(&bob);
        assert_eq!(bob_pending.len(), 1);
        assert_eq!(bob_pending[0].id, entry_bob.id);

        // Bob cannot operate on Alice's entry (even though Alice already accepted it)
        assert!(inbox.mark_read(&entry_alice.id, bob.public_key()).is_err());
        assert!(inbox.dismiss_entry(&entry_alice.id, bob.public_key()).is_err());
        assert!(inbox.remove_entry(&entry_alice.id, bob.public_key()).is_err());

        // === VERIFICATION: Charlie (no shares) ===

        // Charlie sees nothing
        let charlie_pending = inbox.list_pending(&charlie);
        assert_eq!(charlie_pending.len(), 0);

        // Charlie cannot operate on anyone's entries
        assert!(inbox.mark_read(&entry_alice.id, charlie.public_key()).is_err());
        assert!(inbox.mark_read(&entry_bob.id, charlie.public_key()).is_err());
        assert!(inbox.accept_entry(&entry_bob.id, &charlie).is_err());
    }

    #[test]
    fn test_isolation_nonexistent_entry_returns_ok_false() {
        // Verify that operations on non-existent entries don't leak information
        // (should return Ok(false) or Ok(None), not Err)
        let user = KekKeyPair::generate();
        let mut inbox = ShareInbox::new();

        let fake_entry_id = "nonexistent-entry-id-12345";

        // These should all return Ok with false/None, not error
        // (to prevent timing attacks or enumeration)
        let mark_result = inbox.mark_read(fake_entry_id, user.public_key());
        assert!(mark_result.is_ok(), "Non-existent entry should return Ok");
        assert!(!mark_result.unwrap(), "Should return false for non-existent");

        let dismiss_result = inbox.dismiss_entry(fake_entry_id, user.public_key());
        assert!(dismiss_result.is_ok(), "Non-existent entry should return Ok");
        assert!(!dismiss_result.unwrap(), "Should return false for non-existent");

        let remove_result = inbox.remove_entry(fake_entry_id, user.public_key());
        assert!(remove_result.is_ok(), "Non-existent entry should return Ok");
        assert!(remove_result.unwrap().is_none(), "Should return None for non-existent");
    }

    #[test]
    #[allow(deprecated)]
    fn test_isolation_list_all_deprecation_warning() {
        // This test exists to document that list_all() is deprecated
        // and to verify it still works (for migration purposes)
        let owner = KekKeyPair::generate();
        let user = KekKeyPair::generate();
        let dek = DekKey::generate();

        let mut inbox = ShareInbox::new();

        let token = ShareBuilder::new(&owner, user.public_key(), &dek)
            .build()
            .unwrap();
        let envelope = ShareEnvelope::new(token);
        inbox.enqueue_share(&envelope, user.public_key(), &owner).unwrap();

        // list_all() still works but is deprecated
        // Prefer list_pending() with recipient key
        let all = inbox.list_all();
        assert_eq!(all.len(), 1);

        // Recommended alternative:
        let pending = inbox.list_pending(&user);
        assert_eq!(pending.len(), 1);
    }
}
