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
    chunked::{ChunkedDecoder, ChunkedFileMetadata},
    hpke::{Encryptor, Decryptor, EncryptedData, SharePermissions},
    keys::{DekKey, KekKeyPair, PublicKey, SecretKey},
    symmetric::{Aead, Nonce},
    time::now_timestamp,
};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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

/// Get current Unix timestamp in seconds (WASM-compatible)
///
/// This function works in both native and WASM environments.
pub fn current_timestamp() -> i64 {
    now_timestamp()
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
    /// Encryption nonce (base64 encoded) - included so recipient can decrypt
    /// without needing to fetch metadata headers from S3
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    /// Chunked file metadata (JSON) - for files > 768KB that use per-chunk nonces
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chunked_metadata: Option<String>,
    /// Content encryption version (e.g., 4 = AAD-bound).
    /// None means legacy (version 2, no AAD).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encryption_version: Option<u8>,
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

/// Share-token AAD version 5 sentinel. Tokens with `version >= SHARE_TOKEN_AAD_V5`
/// bind every non-`wrapped_key` field AND the recipient public key into the
/// DEK-wrap AAD. Tokens with `version < 5` are rejected — there is no legacy
/// fallback path (would be a downgrade oracle).
pub(crate) const SHARE_TOKEN_AAD_V5: u8 = 5;

/// Build the canonical AAD bytes that bind share-token metadata to the wrapped DEK.
///
/// The encoding is a fixed, length-prefixed binary form (NOT serde_json), because
/// JSON is non-canonical across language/version boundaries. Every non-wrapped_key
/// field of `ShareToken` plus the intended recipient public key is covered; any
/// mutation collapses AEAD authenticity and yields a generic "authentication
/// failed" on unwrap.
///
/// Layout (all integers big-endian):
/// - domain: `b"fula:v5:share-token|"` (constant, outside the caller-controlled region)
/// - id: `<u32 len><bytes>`
/// - path_scope: `<u32 len><bytes>`
/// - expires_at: `<u8 tag>` then `<i64>` if Some
/// - created_at: `<i64>`
/// - permissions: `[can_read, can_write, can_delete]` each as `u8` 0/1
/// - version: `<u8>`
/// - mode: `<u8>` (0=Temporal, 1=Snapshot)
/// - snapshot_binding: `<u8 tag>` then for Some:
///     `<u32 len><content_hash bytes>`
///     `<u64 size>` `<i64 modified_at>`
///     `<u8 tag>` then `<u32 len><storage_key bytes>` if Some
/// - nonce: `<u8 tag>` then `<u32 len><bytes>` if Some
/// - chunked_metadata: `<u8 tag>` then `<u32 len><bytes>` if Some
/// - encryption_version: `<u8 tag>` then `<u8>` if Some
/// - recipient_pk: `<u32 len=32><bytes>` (M-5: binds the intended recipient's
///   X25519 public key; applies to both addressed shares and anonymous bearer
///   links — in the latter case the pk is the ephemeral key whose secret half
///   is conveyed out-of-band in the URL fragment)
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_share_token_aad(
    id: &str,
    path_scope: &str,
    expires_at: Option<i64>,
    created_at: i64,
    permissions: &SharePermissions,
    version: u8,
    mode: ShareMode,
    snapshot_binding: Option<&SnapshotBinding>,
    nonce: Option<&[u8]>,
    chunked_metadata: Option<&[u8]>,
    encryption_version: Option<u8>,
    recipient_pk: &[u8; 32],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    out.extend_from_slice(b"fula:v5:share-token|");

    fn push_bytes(out: &mut Vec<u8>, b: &[u8]) {
        debug_assert!(
            b.len() <= u32::MAX as usize,
            "share token AAD field exceeds u32 length prefix"
        );
        out.extend_from_slice(&(b.len() as u32).to_be_bytes());
        out.extend_from_slice(b);
    }
    fn push_opt_bytes(out: &mut Vec<u8>, b: Option<&[u8]>) {
        match b {
            None => out.push(0u8),
            Some(bytes) => {
                out.push(1u8);
                push_bytes(out, bytes);
            }
        }
    }

    push_bytes(&mut out, id.as_bytes());
    push_bytes(&mut out, path_scope.as_bytes());

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
    out.push(version);
    out.push(match mode {
        ShareMode::Temporal => 0u8,
        ShareMode::Snapshot => 1u8,
    });

    match snapshot_binding {
        None => out.push(0u8),
        Some(b) => {
            out.push(1u8);
            push_bytes(&mut out, b.content_hash.as_bytes());
            out.extend_from_slice(&b.size.to_be_bytes());
            out.extend_from_slice(&b.modified_at.to_be_bytes());
            push_opt_bytes(&mut out, b.storage_key.as_deref().map(|s| s.as_bytes()));
        }
    }

    push_opt_bytes(&mut out, nonce);
    push_opt_bytes(&mut out, chunked_metadata);
    match encryption_version {
        None => out.push(0u8),
        Some(v) => {
            out.push(1u8);
            out.push(v);
        }
    }
    push_bytes(&mut out, recipient_pk);
    out
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
    /// Encryption nonce (base64) for single-block files
    nonce: Option<String>,
    /// Chunked file metadata (JSON) for files > 768KB
    chunked_metadata: Option<String>,
    /// Content encryption version (e.g., 4 = AAD-bound)
    encryption_version: Option<u8>,
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
            nonce: None,
            chunked_metadata: None,
            encryption_version: None,
        }
    }

    /// Set the content encryption version (e.g., 4 for AAD-bound encryption)
    pub fn encryption_version(mut self, version: u8) -> Self {
        self.encryption_version = Some(version);
        self
    }

    /// Set the encryption nonce (base64 encoded) for single-block files
    /// This allows recipients to decrypt without needing S3 metadata headers
    pub fn nonce(mut self, nonce_b64: impl Into<String>) -> Self {
        self.nonce = Some(nonce_b64.into());
        self
    }

    /// Set chunked file metadata (JSON) for files > 768KB
    /// This allows recipients to decrypt chunked files without needing S3 metadata headers
    pub fn chunked_metadata(mut self, metadata_json: impl Into<String>) -> Self {
        self.chunked_metadata = Some(metadata_json.into());
        self
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
    ///
    /// Produces a `version = 5` token whose wrapped DEK binds every metadata
    /// field (path_scope, expiry, permissions, mode, snapshot_binding, nonce,
    /// chunked_metadata, encryption_version, id, created_at) AND the intended
    /// recipient's public key into AAD. Any post-build mutation of those
    /// fields, or an attempt to unwrap with a secret key that does not derive
    /// the bound recipient pk, causes `accept_share` to fail with a generic
    /// authentication error.
    pub fn build(self) -> Result<ShareToken> {
        // Validate snapshot mode has binding
        if self.mode == ShareMode::Snapshot && self.snapshot_binding.is_none() {
            return Err(CryptoError::InvalidFormat(
                "Snapshot share requires snapshot_binding".to_string()
            ));
        }

        // Generate a unique share ID
        let id = generate_share_id();
        let created_at = current_timestamp();
        let version = SHARE_TOKEN_AAD_V5;

        // Build the AAD over every field we will store in the token plus the
        // recipient's public key. The wrapped_key itself is excluded (it IS
        // the ciphertext).
        let recipient_pk_bytes = self.recipient_public_key.as_bytes();
        let aad = build_share_token_aad(
            &id,
            &self.path_scope,
            self.expires_at,
            created_at,
            &self.permissions,
            version,
            self.mode,
            self.snapshot_binding.as_ref(),
            self.nonce.as_deref().map(|s| s.as_bytes()),
            self.chunked_metadata.as_deref().map(|s| s.as_bytes()),
            self.encryption_version,
            recipient_pk_bytes,
        );

        // Encrypt the DEK for the recipient, binding the AAD.
        let encryptor = Encryptor::new(self.recipient_public_key);
        let wrapped_key = encryptor.encrypt_dek_with_context(self.dek, &aad)?;

        Ok(ShareToken {
            id,
            wrapped_key,
            path_scope: self.path_scope,
            expires_at: self.expires_at,
            created_at,
            permissions: self.permissions,
            version,
            mode: self.mode,
            snapshot_binding: self.snapshot_binding,
            nonce: self.nonce,
            chunked_metadata: self.chunked_metadata,
            encryption_version: self.encryption_version,
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

/// Wrap an ARBITRARY 32-byte `secret` for a recipient X25519 public key,
/// producing a `version = 5` [`ShareToken`] whose wrapped "DEK" *is* the secret.
///
/// This is the producer side of the MCP "Method-2" link-secret pairing: the
/// recipient recovers the exact 32 secret bytes via
/// [`ShareRecipient::accept_share`] (or the local MCP's
/// `McpIdentity::accept_link_secret`, which is `accept_share` followed by
/// `*AcceptedShare.dek.as_bytes()`).
///
/// It is a THIN composition of the already-tested [`ShareBuilder`] primitive —
/// it introduces no new crypto. The only specialization is that the 32-byte
/// secret is carried in the [`DekKey`] slot (exactly as the merged
/// `McpIdentity::accept_link_secret` test does), so the recipient gets the
/// secret back verbatim.
///
/// ## Ephemeral sender
///
/// The sender/owner keypair is generated FRESH inside this function and then
/// dropped. The v5 share-token AAD binds the **recipient** public key
/// (verified in [`ShareRecipient::accept_share`]), *not* the sender, so a
/// stable owner identity is neither required nor leaked — `accept_share` never
/// inspects the sender. This lets a caller (FxFiles' fail-closed
/// `CollabLinkSecretWrapper`, or the Cloudflare Worker) wrap a secret for an
/// AI/MCP recipient without holding any long-lived key of its own.
///
/// ## Security properties the caller MUST uphold
///
/// - **No sender authentication.** Because the sender is ephemeral and unbound,
///   the token proves to the recipient only "this was wrapped *for my* public
///   key" — NOT *who* wrapped it. Anyone who knows the recipient's (published)
///   public key can mint a structurally valid token. The recovered secret is
///   therefore a **bearer / possession** capability: the consumer (the MCP) must
///   authorize a session on POSSESSION of the recovered secret, not on the
///   wrap's origin. If owner attribution is ever required, the (currently
///   unused) `owner_keypair` signing slot in [`ShareBuilder`] is where it would
///   be added — it is intentionally not relied upon here.
/// - **Authenticate the recipient public key out-of-band.** This function wraps
///   for whatever public key you pass. If the caller obtained that key over an
///   unauthenticated channel, a man-in-the-middle can substitute their own key
///   and the wrap still "succeeds" — for the attacker. Callers MUST pin / verify
///   the recipient's `FULA-` identity (TOFU-with-persistence, or signed by a
///   stable owner key) before wrapping. This is the standard HPKE trust
///   assumption, not a defect of this function.
/// - **Recipient key validation.** Any 32 bytes are accepted as the recipient
///   public key (matching `create_share_token`). The all-zero key and X25519
///   low-order points are closed by RFC 9180 DHKEM, which aborts on an all-zero
///   Diffie-Hellman shared secret, so `build()` returns `Err` rather than
///   producing a trivially-decryptable token.
/// - **Expiry semantics.** `expires_in_seconds` is a duration ADDED to "now":
///   the token expires at `now + expires_in_seconds`. A negative value yields a
///   born-expired token that `accept_share` rejects (fail-closed); `None` never
///   expires.
///
/// ## Fail-closed input validation
///
/// Both `secret` and `recipient_public_key` MUST be exactly 32 bytes; any other
/// length returns [`CryptoError::InvalidKey`] WITHOUT building a token.
///
/// # Arguments
/// * `secret` - the 32 raw secret bytes to wrap (e.g. a collaboration link
///   secret). Carried in the wrapped-DEK slot; recovered verbatim by the recipient.
/// * `recipient_public_key` - the recipient's 32-byte X25519 public key.
/// * `path_scope` - optional path/scope string bound into the token AAD
///   (defaults to `"/"` when `None`; round-trips to the recipient unchanged).
/// * `expires_in_seconds` - optional expiry as a duration from now, in seconds
///   (`None` = never expires).
///
/// # Errors
/// * [`CryptoError::InvalidKey`] if `secret` or `recipient_public_key` is not 32 bytes.
/// * any error surfaced by the underlying HPKE DEK wrap.
pub fn wrap_secret_for_recipient(
    secret: &[u8],
    recipient_public_key: &[u8],
    path_scope: Option<&str>,
    expires_in_seconds: Option<i64>,
) -> Result<ShareToken> {
    // Fail closed on bad lengths. `DekKey::from_bytes` / `PublicKey::from_bytes`
    // also enforce 32, but check explicitly so the error names the bad field
    // (and so no `KekKeyPair` is generated for an already-doomed call).
    if secret.len() != 32 {
        return Err(CryptoError::InvalidKey(format!(
            "secret must be exactly 32 bytes, got {}",
            secret.len()
        )));
    }
    if recipient_public_key.len() != 32 {
        return Err(CryptoError::InvalidKey(format!(
            "recipient public key must be exactly 32 bytes, got {}",
            recipient_public_key.len()
        )));
    }

    // The 32-byte secret rides in the DEK slot; the recipient recovers it
    // verbatim from `AcceptedShare.dek`.
    let dek = DekKey::from_bytes(secret)?;
    let recipient_pk = PublicKey::from_bytes(recipient_public_key)?;

    // Ephemeral sender — see the "Ephemeral sender" doc section above. `build()`
    // does not read `owner_keypair`; the recipient-pk binding lives in the AAD.
    let ephemeral_sender = KekKeyPair::generate();

    let mut builder = ShareBuilder::new(&ephemeral_sender, &recipient_pk, &dek);
    if let Some(scope) = path_scope {
        builder = builder.path_scope(scope);
    }
    if let Some(seconds) = expires_in_seconds {
        builder = builder.expires_in(seconds);
    }

    builder.build()
}

// ═══════════════════════════════════════════════════════════════════════════
// METHOD-2 RECIPIENT CONSUMER: link-secret unwrap + owner-file decrypt
// ═══════════════════════════════════════════════════════════════════════════
//
// These are the RECIPIENT-side counterparts to `wrap_secret_for_recipient`,
// exposed (via the `fula-js` wasm bindings) so the hosted Cloudflare Worker can
// consume a Method-2 collaboration share WITHOUT re-implementing any `fula:v4`
// crypto in TypeScript. They are THIN compositions of already-tested primitives
// (`ShareRecipient::accept_share`, `Aead`, `Nonce`, `ChunkedDecoder`) — they add
// NO new crypto.
//
// The owner-file decrypt logic ([`decrypt_accepted_single_block`] /
// [`assemble_accepted_chunked`]) is a byte-for-byte mirror of the native MCP read
// path (`crates/fula-mcp/src/read.rs` `decrypt_single_block` / `assemble_chunked`).
// A `#[cfg(test)]` cross-check in that file asserts the two stay byte-identical,
// so the Worker (wasm) and the native MCP cannot silently drift.

/// Accept a strict-v5 share token with raw recipient X25519 secret-key bytes.
///
/// Centralizes the fail-closed 32-byte length check + [`ShareRecipient::accept_share`]
/// so the unwrap / describe / decrypt entry points share ONE accept path.
/// `accept_share` itself enforces the strict-v5 gate, the expiry check, and the
/// recipient-public-key AAD binding (a wrong key, an expired token, or any
/// tampered field ⇒ a generic authentication failure).
fn accept_token(recipient_secret_key: &[u8], token: &ShareToken) -> Result<AcceptedShare> {
    if recipient_secret_key.len() != 32 {
        return Err(CryptoError::InvalidKey(format!(
            "recipient secret key must be exactly 32 bytes, got {}",
            recipient_secret_key.len()
        )));
    }
    let secret = SecretKey::from_bytes(recipient_secret_key)?;
    ShareRecipient::from_secret_key(secret).accept_share(token)
}

/// Recipient counterpart to [`wrap_secret_for_recipient`]: recover the EXACT
/// 32-byte secret a producer wrapped for this recipient's X25519 public key.
///
/// For the Method-2 collaboration pairing the recovered "DEK" *is* the group
/// link secret (the recipient then derives the manifest / collab-file keys from
/// it). Fail-closed: a non-32-byte key, a pre-v5 / expired / tampered token, or a
/// token addressed to a different key all return `Err`.
///
/// This is the shared core that the `fula-js` `unwrapSecretForRecipient` binding
/// and the cross-impl KAT both call.
pub fn unwrap_secret_for_recipient(
    recipient_secret_key: &[u8],
    token: &ShareToken,
) -> Result<[u8; 32]> {
    let accepted = accept_token(recipient_secret_key, token)?;
    Ok(*accepted.dek.as_bytes())
}

/// Non-secret framing of an owner (`encType:"fula"`) share: whether the file is
/// chunked and, if so, how many chunks. Lets a recipient that fetches ciphertext
/// itself (the Worker) learn how many chunk objects to fetch BEFORE fetching —
/// `num_chunks` lives INSIDE the encrypted share, so it is otherwise unknowable.
///
/// Deliberately carries NO key material (no DEK, no nonce, no metadata plaintext);
/// only the framing the caller needs to drive its fetch loop.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SharedFileFraming {
    /// True when the file is stored as multiple per-chunk objects.
    pub chunked: bool,
    /// Number of chunk objects to fetch (`1` for a single-block file).
    pub num_chunks: u32,
    /// The content encryption version recorded in the share (`None` = legacy v2).
    pub encryption_version: Option<u8>,
}

/// Accept a share and report its [`SharedFileFraming`] (chunked? how many
/// chunks?) WITHOUT exposing any key material. The DEK is decrypted only to
/// authenticate the share, then dropped.
pub fn describe_shared_file(
    recipient_secret_key: &[u8],
    token: &ShareToken,
) -> Result<SharedFileFraming> {
    let accepted = accept_token(recipient_secret_key, token)?;
    let (chunked, num_chunks) = match accepted.chunked_metadata.as_deref() {
        Some(meta_json) => (true, parse_chunked_metadata(meta_json)?.num_chunks),
        None => (false, 1),
    };
    Ok(SharedFileFraming {
        chunked,
        num_chunks,
        encryption_version: accepted.encryption_version,
    })
}

/// Decrypt a SINGLE-BLOCK owner file: accept the share, then decrypt the
/// already-fetched whole ciphertext. Errors if the share is actually chunked
/// (the caller must use [`decrypt_shared_file_chunked`]).
///
/// Mirrors `read.rs::decrypt_single_block` exactly: the nonce is the
/// base64-STANDARD decode of the share `nonce`; the AAD is
/// `fula:v4:content:{storage_key}`; the version gate is `Some(>=4)` ⇒ AAD,
/// `Some(<4)` ⇒ no AAD, `None` ⇒ try-AAD-then-plaintext.
pub fn decrypt_shared_file_single_block(
    recipient_secret_key: &[u8],
    token: &ShareToken,
    storage_key: &str,
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let accepted = accept_token(recipient_secret_key, token)?;
    if accepted.chunked_metadata.is_some() {
        return Err(CryptoError::InvalidFormat(
            "share is for a chunked file; use decrypt_shared_file_chunked".to_string(),
        ));
    }
    decrypt_accepted_single_block(&accepted, ciphertext, storage_key)
}

/// Decrypt a CHUNKED owner file: accept the share, then assemble the
/// already-fetched per-chunk ciphertexts. `chunks` MUST be in ascending chunk
/// order (`chunks[i]` is chunk index `i`, fetched from `{storage_key}.chunks/{i:08}`).
/// Errors if the share is single-block, or if `chunks.len()` does not match the
/// share's `num_chunks` (checked BEFORE any per-chunk AEAD open).
///
/// Mirrors `read.rs::assemble_chunked` exactly: `format == "streaming-v2"` ⇒
/// `ChunkedDecoder::with_aad(dek, meta, "fula:v4:chunk:{storage_key}")` (the
/// decoder appends `:{index}` to the AAD per chunk), otherwise the legacy no-AAD
/// decoder.
pub fn decrypt_shared_file_chunked(
    recipient_secret_key: &[u8],
    token: &ShareToken,
    storage_key: &str,
    chunks: Vec<Vec<u8>>,
) -> Result<Vec<u8>> {
    let accepted = accept_token(recipient_secret_key, token)?;
    let meta_json = accepted.chunked_metadata.as_deref().ok_or_else(|| {
        CryptoError::InvalidFormat(
            "share is for a single-block file; use decrypt_shared_file_single_block".to_string(),
        )
    })?;
    let meta = parse_chunked_metadata(meta_json)?;
    if chunks.len() != meta.num_chunks as usize {
        return Err(CryptoError::InvalidFormat(format!(
            "chunk count mismatch: share declares {} chunk(s), got {}",
            meta.num_chunks,
            chunks.len()
        )));
    }
    let indexed: Vec<(u32, Vec<u8>)> = chunks
        .into_iter()
        .enumerate()
        .map(|(i, c)| (i as u32, c))
        .collect();
    assemble_accepted_chunked(accepted.dek, meta, &indexed, storage_key)
}

/// Parse a share's `chunked_metadata` JSON into [`ChunkedFileMetadata`].
fn parse_chunked_metadata(meta_json: &str) -> Result<ChunkedFileMetadata> {
    serde_json::from_str(meta_json)
        .map_err(|e| CryptoError::InvalidFormat(format!("chunked metadata parse failed: {e}")))
}

/// Decrypt a single-block owner object from an ALREADY-accepted share. PURE (no
/// I/O). Byte-for-byte mirror of `read.rs::decrypt_single_block` — the native MCP
/// and the wasm binding share this exact logic (enforced by a cross-check test in
/// `read.rs`).
pub fn decrypt_accepted_single_block(
    accepted: &AcceptedShare,
    ciphertext: &[u8],
    storage_key: &str,
) -> Result<Vec<u8>> {
    let nonce_b64 = accepted.nonce.as_deref().ok_or_else(|| {
        CryptoError::InvalidFormat("single-block fula file has no nonce".to_string())
    })?;
    let nonce_bytes = base64::engine::general_purpose::STANDARD
        .decode(nonce_b64)
        .map_err(|e| CryptoError::InvalidFormat(format!("nonce base64: {e}")))?;
    let nonce = Nonce::from_bytes(&nonce_bytes)?;

    let aead = Aead::new_default(&accepted.dek);
    let aad = format!("fula:v4:content:{storage_key}");

    // Version gate — identical to fula-client's `get_object_with_share`.
    let plaintext = match accepted.encryption_version {
        Some(v) if v >= 4 => aead.decrypt_with_aad(&nonce, ciphertext, aad.as_bytes())?,
        Some(_) => aead.decrypt(&nonce, ciphertext)?,
        None => match aead.decrypt_with_aad(&nonce, ciphertext, aad.as_bytes()) {
            Ok(p) => p,
            Err(_) => aead.decrypt(&nonce, ciphertext)?,
        },
    };
    Ok(plaintext)
}

/// Assemble a chunked owner object from already-fetched per-chunk ciphertexts and
/// an already-accepted share's DEK + metadata. PURE (no I/O). Byte-for-byte mirror
/// of `read.rs::assemble_chunked` (enforced by a cross-check test in `read.rs`).
pub fn assemble_accepted_chunked(
    dek: DekKey,
    meta: ChunkedFileMetadata,
    chunks: &[(u32, Vec<u8>)],
    storage_key: &str,
) -> Result<Vec<u8>> {
    let mut decoder = if meta.format == "streaming-v2" {
        ChunkedDecoder::with_aad(dek, meta, format!("fula:v4:chunk:{storage_key}"))
    } else {
        ChunkedDecoder::new(dek, meta)
    };
    for (i, ct) in chunks {
        decoder.decrypt_chunk(*i, ct)?;
    }
    decoder.finalize().map(|b| b.to_vec())
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
    ///
    /// Strictly requires `version >= SHARE_TOKEN_AAD_V5` (currently 5). Every
    /// non-`wrapped_key` field — `id`, `path_scope`, `expires_at`, `created_at`,
    /// `permissions`, `mode`, `snapshot_binding`, `nonce`, `chunked_metadata`,
    /// `encryption_version`, `version` — plus the recipient public key derived
    /// from `self.secret_key` is rebuilt into the AAD. Any post-issue mutation
    /// of those fields or use of the wrong recipient key yields a generic
    /// authentication failure.
    ///
    /// There is no legacy path and no fallback-on-failure: pre-v5 tokens are
    /// rejected outright. A fallback would create a downgrade oracle that
    /// strips AAD binding.
    pub fn accept_share(&self, token: &ShareToken) -> Result<AcceptedShare> {
        // Check expiry first
        if token.is_expired() {
            return Err(CryptoError::ShareExpired);
        }

        // Strict version gate: pre-v5 tokens have no recipient-pk binding and
        // are rejected to prevent downgrade-oracle exploitation.
        if token.version < SHARE_TOKEN_AAD_V5 {
            return Err(CryptoError::Decryption(
                "share token rejected: version predates recipient-pk AAD binding".to_string(),
            ));
        }

        let decryptor = Decryptor::from_secret_key(&self.secret_key);
        // Derive our public key from the secret we hold and bind it into the
        // AAD reconstruction. If the token was issued to a different pk, the
        // derived AAD differs from the producer's → generic auth failure.
        let recipient_pk = self.secret_key.public_key();
        let recipient_pk_bytes = recipient_pk.as_bytes();
        let aad = build_share_token_aad(
            &token.id,
            &token.path_scope,
            token.expires_at,
            token.created_at,
            &token.permissions,
            token.version,
            token.mode,
            token.snapshot_binding.as_ref(),
            token.nonce.as_deref().map(|s| s.as_bytes()),
            token.chunked_metadata.as_deref().map(|s| s.as_bytes()),
            token.encryption_version,
            recipient_pk_bytes,
        );
        let dek = decryptor.decrypt_dek_with_context(&token.wrapped_key, &aad)?;

        Ok(AcceptedShare {
            dek,
            path_scope: token.path_scope.clone(),
            expires_at: token.expires_at,
            permissions: token.permissions,
            nonce: token.nonce.clone(),
            chunked_metadata: token.chunked_metadata.clone(),
            encryption_version: token.encryption_version,
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
    /// Encryption nonce (base64 encoded) - for single-block files
    pub nonce: Option<String>,
    /// Chunked file metadata (JSON) - for files > 768KB
    pub chunked_metadata: Option<String>,
    /// Content encryption version (None = legacy v2, Some(4) = AAD-bound)
    pub encryption_version: Option<u8>,
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
    fn test_wrap_secret_for_recipient_round_trips() {
        // The producer side of the MCP Method-2 pairing: wrap an arbitrary
        // 32-byte secret for a recipient and recover it verbatim.
        let recipient = KekKeyPair::generate();
        let secret: [u8; 32] = std::array::from_fn(|i| i as u8); // 0x00..0x1f

        let token = wrap_secret_for_recipient(
            &secret,
            recipient.public_key().as_bytes(),
            Some("/collab/group-xyz"),
            Some(3600),
        )
        .unwrap();

        // It is a strict v5 token (the only kind accept_share will take).
        assert_eq!(token.version, SHARE_TOKEN_AAD_V5);
        assert_eq!(token.path_scope, "/collab/group-xyz");
        assert!(token.expires_at.is_some());

        // Survives a JSON round-trip (the wire form the bindings return) and
        // the recipient recovers the EXACT secret bytes.
        let json = serde_json::to_string(&token).unwrap();
        let back: ShareToken = serde_json::from_str(&json).unwrap();
        let accepted = ShareRecipient::new(&recipient).accept_share(&back).unwrap();
        assert_eq!(accepted.dek.as_bytes(), &secret);

        // A DIFFERENT recipient cannot recover it (recipient-pk AAD binding).
        let stranger = KekKeyPair::generate();
        assert!(ShareRecipient::new(&stranger).accept_share(&back).is_err());
    }

    #[test]
    fn test_wrap_secret_for_recipient_rejects_bad_lengths() {
        let recipient = KekKeyPair::generate();
        let pk = recipient.public_key().as_bytes();

        // Secret must be exactly 32 bytes.
        assert!(wrap_secret_for_recipient(&[0u8; 31], pk, None, None).is_err());
        assert!(wrap_secret_for_recipient(&[0u8; 33], pk, None, None).is_err());
        // Recipient public key must be exactly 32 bytes.
        assert!(wrap_secret_for_recipient(&[7u8; 32], &[0u8; 31], None, None).is_err());
        assert!(wrap_secret_for_recipient(&[7u8; 32], &[0u8; 33], None, None).is_err());
        // The all-valid case still succeeds (guards against a wholesale-reject bug).
        assert!(wrap_secret_for_recipient(&[7u8; 32], pk, None, None).is_ok());
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

    /// Test that simulates the exact FxFiles → Web UI share flow:
    /// 1. Generate random bytes (like Dart's X25519().newKeyPair().extractPrivateKeyBytes())
    /// 2. Create public key from those bytes (Rust derives public key)
    /// 3. Create share token with that public key
    /// 4. Serialize to JSON, transmit, deserialize (simulating URL transmission)
    /// 5. Accept share using SecretKey from same bytes
    /// 6. Verify DEK matches
    /// 7. Use DEK to decrypt test content
    #[test]
    fn test_fxfiles_to_webui_share_flow() {
        use crate::symmetric::{Aead, Nonce};

        // === STEP 1: FxFiles side - generate disposable keypair ===
        // This simulates: final x25519 = X25519(); final keyPair = await x25519.newKeyPair();
        let mut disposable_secret_bytes = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut disposable_secret_bytes);

        // === STEP 2: Create SecretKey and derive PublicKey ===
        // This simulates: final publicKeyBytes = Uint8List.fromList(publicKeyData.bytes);
        let disposable_secret = SecretKey::from_bytes(&disposable_secret_bytes).unwrap();
        let disposable_public = disposable_secret.public_key();

        println!("Disposable secret key: {:?}", hex::encode(&disposable_secret_bytes));
        println!("Derived public key: {:?}", hex::encode(disposable_public.as_bytes()));

        // === STEP 3: Owner creates share token ===
        // Original file was encrypted with this DEK
        let owner_keypair = KekKeyPair::generate();
        let original_dek = DekKey::generate();

        // Encrypt some test content
        let plaintext = b"This is a test JPEG file. Should start with FF D8 FF in real case.";
        let nonce = Nonce::generate();
        let aead = Aead::new_default(&original_dek);
        let ciphertext = aead.encrypt(&nonce, plaintext).unwrap();

        // Create share token with disposable public key
        let token = ShareBuilder::new(&owner_keypair, &disposable_public, &original_dek)
            .path_scope("/test/file.jpg")
            .build()
            .unwrap();

        // === STEP 4: Serialize token for transmission ===
        // This simulates: base64Encode(jsonEncode(token))
        let token_json = serde_json::to_string(&token).unwrap();
        println!("Share token JSON length: {}", token_json.len());

        // === STEP 5: Web UI side - deserialize token ===
        // This simulates: jsonDecode(base64Decode(payload.t))
        let received_token: ShareToken = serde_json::from_str(&token_json).unwrap();

        // === STEP 6: Web UI creates SecretKey from URL's sk bytes ===
        // This simulates: createEncryptedClient({ secretKey: base64Decode(payload.sk) })
        let web_secret = SecretKey::from_bytes(&disposable_secret_bytes).unwrap();
        let web_derived_public = web_secret.public_key();

        println!("Web derived public key: {:?}", hex::encode(web_derived_public.as_bytes()));

        // CRITICAL CHECK: The derived public key must match!
        assert_eq!(
            disposable_public.as_bytes(),
            web_derived_public.as_bytes(),
            "Public key derived on web side must match the one used for token creation"
        );

        // === STEP 7: Accept the share ===
        let recipient = ShareRecipient::from_secret_key(web_secret);
        let accepted = recipient.accept_share(&received_token).unwrap();

        println!("Original DEK first 4 bytes: {:02x}{:02x}{:02x}{:02x}",
            original_dek.as_bytes()[0], original_dek.as_bytes()[1],
            original_dek.as_bytes()[2], original_dek.as_bytes()[3]);
        println!("Accepted DEK first 4 bytes: {:02x}{:02x}{:02x}{:02x}",
            accepted.dek.as_bytes()[0], accepted.dek.as_bytes()[1],
            accepted.dek.as_bytes()[2], accepted.dek.as_bytes()[3]);

        // CRITICAL CHECK: DEK must match!
        assert_eq!(
            original_dek.as_bytes(),
            accepted.dek.as_bytes(),
            "Decrypted DEK must match the original DEK"
        );

        // === STEP 8: Decrypt the content ===
        let recipient_aead = Aead::new_default(&accepted.dek);
        let decrypted = recipient_aead.decrypt(&nonce, &ciphertext).unwrap();

        assert_eq!(
            plaintext.as_slice(),
            decrypted.as_slice(),
            "Decrypted content must match original plaintext"
        );

        println!("SUCCESS: Full share flow works correctly!");
    }

    /// Test share with SecretKey bytes that look like what Dart might produce
    /// (testing various edge cases in key format)
    #[test]
    fn test_share_with_various_key_formats() {
        // Test with bytes that have various patterns
        let test_cases: Vec<[u8; 32]> = vec![
            // All zeros (will be clamped)
            [0u8; 32],
            // All ones (will be clamped)
            [0xFFu8; 32],
            // Sequential bytes
            {
                let mut arr = [0u8; 32];
                for (i, b) in arr.iter_mut().enumerate() {
                    *b = i as u8;
                }
                arr
            },
            // Random bytes (typical case)
            {
                let mut arr = [0u8; 32];
                rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut arr);
                arr
            },
        ];

        for (i, secret_bytes) in test_cases.iter().enumerate() {
            println!("\n=== Test case {} ===", i);

            let owner = KekKeyPair::generate();
            let dek = DekKey::generate();

            // Create disposable keypair from raw bytes
            let disposable_secret = SecretKey::from_bytes(secret_bytes).unwrap();
            let disposable_public = disposable_secret.public_key();

            // Create share token
            let token = ShareBuilder::new(&owner, &disposable_public, &dek)
                .path_scope("/test")
                .build()
                .unwrap();

            // Serialize and deserialize (round-trip)
            let json = serde_json::to_string(&token).unwrap();
            let restored_token: ShareToken = serde_json::from_str(&json).unwrap();

            // Accept share using same secret bytes
            let recipient_secret = SecretKey::from_bytes(secret_bytes).unwrap();
            let recipient = ShareRecipient::from_secret_key(recipient_secret);
            let accepted = recipient.accept_share(&restored_token).unwrap();

            // DEK must match
            assert_eq!(
                dek.as_bytes(),
                accepted.dek.as_bytes(),
                "Test case {}: DEK mismatch", i
            );

            println!("Test case {}: PASSED", i);
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // F2: Share-Token Metadata AAD Binding
    // ═══════════════════════════════════════════════════════════════════════
    //
    // Every non-`wrapped_key` field on a `version >= 4` ShareToken is bound
    // into the wrap-AAD. Any mutation of those fields must cause `accept_share`
    // to fail with a generic authentication error, proving a recipient cannot
    // silently widen scope / strip expiry / elevate permissions by rewriting
    // the outer struct.
    mod f2_share_token_aad_binding {
        use super::*;

        /// `AcceptedShare` does not derive `Debug`, so `Result::unwrap_err` is
        /// unusable. This helper asserts a generic decryption failure.
        fn assert_auth_failure(result: Result<AcceptedShare>) {
            match result {
                Ok(_) => panic!("expected auth failure, got Ok"),
                Err(CryptoError::Decryption(_)) => {}
                Err(other) => panic!("expected Decryption error, got {:?}", other),
            }
        }

        fn build_v5_token() -> (KekKeyPair, KekKeyPair, DekKey, ShareToken) {
            let owner = KekKeyPair::generate();
            let recipient = KekKeyPair::generate();
            let dek = DekKey::generate();
            let token = ShareBuilder::new(&owner, recipient.public_key(), &dek)
                .path_scope("/photos/vacation/")
                .expires_in(3600)
                .read_only()
                .nonce("nonce-b64-abc")
                .chunked_metadata(r#"{"chunks":1}"#)
                .encryption_version(4)
                .build()
                .unwrap();
            (owner, recipient, dek, token)
        }

        #[test]
        fn round_trip_v5_succeeds() {
            let (_owner, recipient, dek, token) = build_v5_token();
            assert_eq!(token.version, SHARE_TOKEN_AAD_V5);
            let accepted = ShareRecipient::new(&recipient).accept_share(&token).unwrap();
            assert_eq!(accepted.dek.as_bytes(), dek.as_bytes());
            assert_eq!(accepted.path_scope, "/photos/vacation/");
        }

        #[test]
        fn mutated_path_scope_rejected() {
            let (_owner, recipient, _dek, mut token) = build_v5_token();
            token.path_scope = "/".to_string();
            assert_auth_failure(ShareRecipient::new(&recipient).accept_share(&token));
        }

        #[test]
        fn mutated_expires_at_rejected() {
            let (_owner, recipient, _dek, mut token) = build_v5_token();
            token.expires_at = Some(current_timestamp() + 86400 * 365);
            assert_auth_failure(ShareRecipient::new(&recipient).accept_share(&token));
        }

        #[test]
        fn removed_expiry_rejected() {
            let (_owner, recipient, _dek, mut token) = build_v5_token();
            token.expires_at = None;
            assert_auth_failure(ShareRecipient::new(&recipient).accept_share(&token));
        }

        #[test]
        fn mutated_created_at_rejected() {
            let (_owner, recipient, _dek, mut token) = build_v5_token();
            token.created_at = 1;
            assert_auth_failure(ShareRecipient::new(&recipient).accept_share(&token));
        }

        #[test]
        fn mutated_permissions_rejected() {
            let (_owner, recipient, _dek, mut token) = build_v5_token();
            token.permissions = SharePermissions::full();
            assert_auth_failure(ShareRecipient::new(&recipient).accept_share(&token));
        }

        #[test]
        fn mutated_mode_rejected() {
            let (_owner, recipient, _dek, mut token) = build_v5_token();
            token.mode = ShareMode::Snapshot;
            token.snapshot_binding = Some(SnapshotBinding::new("h", 0, 0));
            assert_auth_failure(ShareRecipient::new(&recipient).accept_share(&token));
        }

        #[test]
        fn mutated_snapshot_binding_rejected() {
            let owner = KekKeyPair::generate();
            let recipient = KekKeyPair::generate();
            let dek = DekKey::generate();
            let mut token = ShareBuilder::new(&owner, recipient.public_key(), &dek)
                .path_scope("/snap/")
                .snapshot(SnapshotBinding::new("hash-a", 100, 1000))
                .build()
                .unwrap();
            // Swap the binding to a different content-hash
            token.snapshot_binding = Some(SnapshotBinding::new("hash-b", 100, 1000));
            assert_auth_failure(ShareRecipient::new(&recipient).accept_share(&token));
        }

        #[test]
        fn mutated_nonce_rejected() {
            let (_owner, recipient, _dek, mut token) = build_v5_token();
            token.nonce = Some("different-nonce".to_string());
            assert_auth_failure(ShareRecipient::new(&recipient).accept_share(&token));
        }

        #[test]
        fn removed_nonce_rejected() {
            let (_owner, recipient, _dek, mut token) = build_v5_token();
            token.nonce = None;
            assert_auth_failure(ShareRecipient::new(&recipient).accept_share(&token));
        }

        #[test]
        fn added_nonce_rejected() {
            let owner = KekKeyPair::generate();
            let recipient = KekKeyPair::generate();
            let dek = DekKey::generate();
            // Build a token WITHOUT nonce
            let mut token = ShareBuilder::new(&owner, recipient.public_key(), &dek)
                .build()
                .unwrap();
            assert!(token.nonce.is_none());
            // Attempt to inject a nonce the producer never signed
            token.nonce = Some("injected".to_string());
            assert_auth_failure(ShareRecipient::new(&recipient).accept_share(&token));
        }

        #[test]
        fn mutated_chunked_metadata_rejected() {
            let (_owner, recipient, _dek, mut token) = build_v5_token();
            token.chunked_metadata = Some(r#"{"chunks":2}"#.to_string());
            assert_auth_failure(ShareRecipient::new(&recipient).accept_share(&token));
        }

        #[test]
        fn mutated_encryption_version_rejected() {
            let (_owner, recipient, _dek, mut token) = build_v5_token();
            token.encryption_version = Some(2);
            assert_auth_failure(ShareRecipient::new(&recipient).accept_share(&token));
        }

        #[test]
        fn mutated_id_rejected() {
            let (_owner, recipient, _dek, mut token) = build_v5_token();
            token.id = "deadbeef".to_string();
            assert_auth_failure(ShareRecipient::new(&recipient).accept_share(&token));
        }

        #[test]
        fn downgraded_version_rejected() {
            // An attacker rewrites version back to 3 so a downstream reader
            // takes a legacy (unauthenticated) path. The strict gate at
            // accept_share refuses any version < 5 outright — generic auth
            // failure, no downgrade oracle.
            let (_owner, recipient, _dek, mut token) = build_v5_token();
            token.version = 3;
            assert_auth_failure(ShareRecipient::new(&recipient).accept_share(&token));
        }

        #[test]
        fn v4_token_rejected() {
            // M-5: pre-v5 tokens carry no recipient-pk binding. They must be
            // rejected wholesale — there is no legacy fallback path.
            let (_owner, recipient, _dek, mut token) = build_v5_token();
            token.version = 4;
            assert_auth_failure(ShareRecipient::new(&recipient).accept_share(&token));
        }

        #[test]
        fn wrong_recipient_key_rejected_at_aad_layer() {
            // M-5: even if the wrapped_key somehow decrypted under a different
            // secret (impossible in HPKE base mode, but defense-in-depth), the
            // derived recipient_pk in the AAD reconstruction would differ →
            // generic auth failure.
            let owner = KekKeyPair::generate();
            let recipient = KekKeyPair::generate();
            let wrong_recipient = KekKeyPair::generate();
            let dek = DekKey::generate();
            let token = ShareBuilder::new(&owner, recipient.public_key(), &dek)
                .path_scope("/photos/")
                .build()
                .unwrap();
            assert_auth_failure(ShareRecipient::new(&wrong_recipient).accept_share(&token));
        }

        #[test]
        fn cross_token_wrapped_key_substitution_rejected() {
            // Attacker takes wrapped_key from token B and pastes it onto
            // token A's metadata. Both were built v5, but the AADs differ by
            // at least the `id` → token A no longer unwraps.
            let owner = KekKeyPair::generate();
            let recipient = KekKeyPair::generate();
            let dek_a = DekKey::generate();
            let dek_b = DekKey::generate();
            let token_a = ShareBuilder::new(&owner, recipient.public_key(), &dek_a)
                .path_scope("/a/")
                .build()
                .unwrap();
            let token_b = ShareBuilder::new(&owner, recipient.public_key(), &dek_b)
                .path_scope("/b/")
                .build()
                .unwrap();
            let mut franken = token_a.clone();
            franken.wrapped_key = token_b.wrapped_key.clone();
            assert_auth_failure(ShareRecipient::new(&recipient).accept_share(&franken));
        }

        #[test]
        fn aad_encoding_is_canonical_for_identical_inputs() {
            // Two AADs built from the same inputs must be byte-identical.
            let perms = SharePermissions::read_write();
            let pk = [0xABu8; 32];
            let aad1 = build_share_token_aad(
                "id-x", "/p/", Some(123), 456, &perms, 5, ShareMode::Temporal,
                None, Some(b"n"), Some(b"m"), Some(4), &pk,
            );
            let aad2 = build_share_token_aad(
                "id-x", "/p/", Some(123), 456, &perms, 5, ShareMode::Temporal,
                None, Some(b"n"), Some(b"m"), Some(4), &pk,
            );
            assert_eq!(aad1, aad2);
            // Any single-bit change in input yields a different AAD
            let aad3 = build_share_token_aad(
                "id-x", "/p/", Some(124), 456, &perms, 5, ShareMode::Temporal,
                None, Some(b"n"), Some(b"m"), Some(4), &pk,
            );
            assert_ne!(aad1, aad3);
            // A different recipient pk also yields a different AAD
            let pk2 = [0xCDu8; 32];
            let aad4 = build_share_token_aad(
                "id-x", "/p/", Some(123), 456, &perms, 5, ShareMode::Temporal,
                None, Some(b"n"), Some(b"m"), Some(4), &pk2,
            );
            assert_ne!(aad1, aad4);
        }

        #[test]
        fn aad_domain_prefix_prevents_cross_context_substitution() {
            // The share-token AAD prefix must differ from the subtree prefix.
            // Otherwise a subtree token's wrapped DEK could be pasted into
            // a share-token envelope.
            let pk = [0u8; 32];
            let aad = build_share_token_aad(
                "id", "/", None, 0, &SharePermissions::read_only(), 5,
                ShareMode::Temporal, None, None, None, None, &pk,
            );
            assert!(aad.starts_with(b"fula:v5:share-token|"));
        }
    }
}
