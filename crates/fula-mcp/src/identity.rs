//! # MCP collaboration identity (Method-2 keypair)
//!
//! The collaboration partner (the MCP server) needs a STABLE X25519 identity so
//! an owner can address `owner -> MCP` collaboration grants to it. This module
//! wraps [`fula_crypto::KekKeyPair`] with the persistence + identity-string
//! helpers the collaboration flow needs, and reuses [`fula_crypto::sharing`] to
//! recover a wrapped link secret — it does NOT reimplement any HPKE / wrapping.
//!
//! ## The "FULA-" identity string
//!
//! A user/agent's share identity is its X25519 **public** key, base64url-encoded
//! with padding stripped, prefixed `"FULA-"` (mirrors the Dart
//! `encodeFulaShareId`). This is the string an owner pastes to address a grant.
//!
//! ## Key custody
//!
//! The X25519 **private** key MUST NEVER be transmitted — only the public key /
//! `FULA-` id are shared. [`McpIdentity::load_or_generate`] persists the raw
//! 32-byte secret to a LOCAL file (with `0600`-equivalent permissions on Unix;
//! on Windows it relies on the user-profile directory ACL, as Windows has no
//! Unix mode bits).

use std::path::Path;

use base64::Engine as _;
use fula_crypto::{
    KekKeyPair, PublicKey, SecretKey,
    sharing::{ShareRecipient, ShareToken},
};
use zeroize::Zeroize;

/// The mandatory prefix on a FULA share identity string.
const FULA_PREFIX: &str = "FULA-";

/// Errors surfaced by the MCP identity layer.
#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    /// Reading or writing the on-disk secret-key file failed.
    #[error("identity key file I/O error: {0}")]
    Io(String),

    /// The persisted bytes did not form a valid 32-byte X25519 secret key.
    #[error("invalid persisted key material: {0}")]
    Key(String),

    /// A `FULA-` id (or bare base64 key) did not base64-decode.
    #[error("base64 decode failed: {0}")]
    Base64(String),

    /// Accepting the `owner -> MCP` share token failed (not addressed to this
    /// keypair, expired, pre-v5, or tampered).
    #[error("share acceptance failed: {0}")]
    Share(String),
}

/// The MCP's persistent collaboration identity — an X25519 keypair plus the
/// FULA id / base64 helpers and the link-secret acceptance path.
pub struct McpIdentity {
    keypair: KekKeyPair,
}

impl McpIdentity {
    /// Generate a fresh random X25519 keypair.
    pub fn generate() -> Self {
        Self {
            keypair: KekKeyPair::generate(),
        }
    }

    /// Build an identity from raw 32-byte X25519 secret-key bytes.
    ///
    /// # Errors
    /// [`IdentityError::Key`] if `bytes` is not a valid 32-byte secret key.
    pub fn from_secret_bytes(bytes: &[u8]) -> std::result::Result<Self, IdentityError> {
        let secret = SecretKey::from_bytes(bytes).map_err(|e| IdentityError::Key(e.to_string()))?;
        Ok(Self {
            keypair: KekKeyPair::from_secret_key(secret),
        })
    }

    /// Load the identity from `path` if it exists, otherwise generate a fresh one
    /// and persist it.
    ///
    /// The file stores the raw 32 secret-key bytes. On Unix it is created with
    /// `0600` permissions; on Windows the file inherits the directory ACL (no
    /// Unix mode bits exist). The private key is NEVER transmitted — only
    /// persisted locally.
    ///
    /// # Errors
    /// - [`IdentityError::Io`] on a filesystem error.
    /// - [`IdentityError::Key`] if an existing file holds invalid key material.
    pub fn load_or_generate(path: impl AsRef<Path>) -> std::result::Result<Self, IdentityError> {
        let path = path.as_ref();
        if path.exists() {
            let mut raw = std::fs::read(path).map_err(|e| IdentityError::Io(e.to_string()))?;
            let result = Self::from_secret_bytes(&raw);
            raw.zeroize(); // wipe the secret bytes read off disk
            result
        } else {
            let identity = Self::generate();
            identity.persist_secret(path)?;
            Ok(identity)
        }
    }

    /// Persist the raw 32-byte secret key to `path` (creating parent dirs).
    fn persist_secret(&self, path: &Path) -> std::result::Result<(), IdentityError> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|e| IdentityError::Io(e.to_string()))?;
            }
        }
        let secret = self.keypair.secret_key().as_bytes();
        write_secret_file(path, secret).map_err(|e| IdentityError::Io(e.to_string()))
    }

    /// This identity's `"FULA-..."` share id (the public key, base64url, padding
    /// stripped). Mirrors Dart `encodeFulaShareId`.
    pub fn fula_id(&self) -> String {
        encode_fula_id(self.keypair.public_key().as_bytes())
    }

    /// This identity's X25519 public key as standard base64 (32 bytes).
    pub fn public_key_b64(&self) -> String {
        self.keypair.public_key().to_base64()
    }

    /// Borrow the X25519 public key.
    pub fn public_key(&self) -> &PublicKey {
        self.keypair.public_key()
    }

    /// Borrow the underlying keypair (e.g. to mint `MCP -> owner` shares).
    pub fn keypair(&self) -> &KekKeyPair {
        &self.keypair
    }

    /// Recover the wrapped 32-byte **link secret** from an `owner -> MCP` share
    /// token.
    ///
    /// The owner wraps the collaboration link secret (as a `DekKey`) for THIS
    /// identity's public key via `fula_crypto::sharing::ShareBuilder`; this
    /// accepts it with the identity's own keypair and returns the recovered link
    /// secret bytes. The strict v5 [`ShareRecipient::accept_share`] rejects any
    /// token not addressed to this keypair (and any pre-v5 token).
    ///
    /// # Errors
    /// [`IdentityError::Share`] if the token is not addressed to this identity,
    /// is expired, is pre-v5, or has been tampered with.
    pub fn accept_link_secret(
        &self,
        share_token: &ShareToken,
    ) -> std::result::Result<[u8; 32], IdentityError> {
        let accepted = ShareRecipient::new(&self.keypair)
            .accept_share(share_token)
            .map_err(|e| IdentityError::Share(e.to_string()))?;
        // The recovered DEK *is* the link secret (always exactly 32 bytes).
        Ok(*accepted.dek.as_bytes())
    }
}

/// Encode a 32-byte X25519 public key as a `"FULA-..."` share id (base64url,
/// padding stripped). Mirrors Dart `encodeFulaShareId`.
pub fn encode_fula_id(public_key: &[u8]) -> String {
    let body = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(public_key);
    format!("{FULA_PREFIX}{body}")
}

/// Decode a `"FULA-..."` share id (or a bare base64 / base64url key) back to the
/// public-key bytes. Mirrors Dart `decodeFulaShareId`: strips the optional
/// (case-insensitive) `FULA-` prefix, re-pads, and base64url-decodes, tolerating
/// the standard alphabet as a fallback.
///
/// # Errors
/// [`IdentityError::Base64`] if the input is not decodable base64.
pub fn decode_fula_id(input: &str) -> std::result::Result<Vec<u8>, IdentityError> {
    let trimmed = input.trim();
    let body = if trimmed.len() >= FULA_PREFIX.len()
        && trimmed[..FULA_PREFIX.len()].eq_ignore_ascii_case(FULA_PREFIX)
    {
        &trimmed[FULA_PREFIX.len()..]
    } else {
        trimmed
    };
    // Strip any padding, then decode url-safe (no-pad), falling back to the
    // standard alphabet for a bare standard-base64 key.
    let body = body.trim_end_matches('=');
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(body)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(body))
        .map_err(|e| IdentityError::Base64(e.to_string()))
}

/// Write `bytes` to `path`, restricting permissions to the owner where the
/// platform supports it.
fn write_secret_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600); // create owner-only from the start
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use fula_crypto::{DekKey, sharing::ShareBuilder};

    #[test]
    fn fula_id_encode_decode_round_trip_and_known_answer() {
        let pk: Vec<u8> = (0u8..32).collect();
        let id = encode_fula_id(&pk);
        // Known answer captured from the Dart `encodeFulaShareId` over 0x00..0x1f.
        assert_eq!(id, "FULA-AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8");
        assert_eq!(decode_fula_id(&id).unwrap(), pk);
        // Decode also tolerates a bare (prefix-less) key and a lowercase prefix.
        assert_eq!(
            decode_fula_id("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8").unwrap(),
            pk
        );
        assert_eq!(
            decode_fula_id("fula-AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8").unwrap(),
            pk
        );
    }

    #[test]
    fn fula_id_matches_public_key_and_b64_round_trips() {
        let identity = McpIdentity::generate();
        assert_eq!(
            identity.fula_id(),
            encode_fula_id(identity.public_key().as_bytes())
        );
        let pk = base64::engine::general_purpose::STANDARD
            .decode(identity.public_key_b64())
            .unwrap();
        assert_eq!(pk.len(), 32);
        assert_eq!(pk.as_slice(), identity.public_key().as_bytes().as_slice());
        // The FULA id decodes back to the same public key.
        assert_eq!(
            decode_fula_id(&identity.fula_id()).unwrap().as_slice(),
            identity.public_key().as_bytes().as_slice()
        );
    }

    #[test]
    fn accept_link_secret_recovers_exact_wrapped_secret() {
        let owner = KekKeyPair::generate();
        let mcp = McpIdentity::generate();

        // The owner wraps a 32-byte link secret (as a DekKey) for the MCP pubkey.
        let link_secret = [0x42u8; 32];
        let dek = DekKey::from_bytes(&link_secret).unwrap();
        let token = ShareBuilder::new(&owner, mcp.public_key(), &dek)
            .path_scope("/collab/group-123")
            .build()
            .unwrap();

        // The MCP recovers the EXACT link secret.
        assert_eq!(mcp.accept_link_secret(&token).unwrap(), link_secret);

        // The token can be carried as a string in a capability bundle (serde) and
        // still recovers after a serialize -> deserialize round-trip.
        let token_str = serde_json::to_string(&token).unwrap();
        let token_back: ShareToken = serde_json::from_str(&token_str).unwrap();
        assert_eq!(mcp.accept_link_secret(&token_back).unwrap(), link_secret);

        // A DIFFERENT identity must NOT be able to recover it.
        let stranger = McpIdentity::generate();
        assert!(stranger.accept_link_secret(&token).is_err());
    }

    #[test]
    fn load_or_generate_persists_and_reloads_same_identity() {
        let dir = std::env::temp_dir().join(format!(
            "fula_mcp_identity_test_{}_{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("mcp_identity.key");
        let _ = std::fs::remove_file(&path);

        // First call generates + persists; second call reloads the SAME key.
        let first = McpIdentity::load_or_generate(&path).unwrap();
        assert!(path.exists());
        let reloaded = McpIdentity::load_or_generate(&path).unwrap();

        assert_eq!(first.public_key_b64(), reloaded.public_key_b64());
        assert_eq!(first.fula_id(), reloaded.fula_id());
        assert_eq!(
            first.keypair().secret_key().as_bytes(),
            reloaded.keypair().secret_key().as_bytes()
        );

        // The persisted file is exactly the 32 secret-key bytes.
        let on_disk = std::fs::read(&path).unwrap();
        assert_eq!(on_disk.len(), 32);

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }
}
