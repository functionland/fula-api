//! Key management for the Fula storage system
//!
//! Implements the KEK/DEK (Key Encryption Key / Data Encryption Key) architecture:
//! - DEK: Random symmetric keys for encrypting file content
//! - KEK: Asymmetric keys for encrypting DEKs and enabling sharing

use crate::{CryptoError, Result};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Size of a symmetric key in bytes (256 bits)
pub const KEY_SIZE: usize = 32;

/// Size of a nonce in bytes (96 bits for AES-GCM/ChaCha20-Poly1305)
pub const NONCE_SIZE: usize = 12;

/// A Data Encryption Key (DEK) for symmetric encryption
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct DekKey {
    key: [u8; KEY_SIZE],
}

impl DekKey {
    /// Generate a new random DEK
    ///
    /// # Panics
    /// Panics if the OS random number generator is unavailable.
    pub fn generate() -> Self {
        let mut key = [0u8; KEY_SIZE];
        rand::RngCore::fill_bytes(&mut OsRng, &mut key);
        Self { key }
    }

    /// Generate a new random DEK, returning an error if OS entropy is unavailable.
    pub fn try_generate() -> Result<Self> {
        let mut key = [0u8; KEY_SIZE];
        getrandom::getrandom(&mut key)
            .map_err(|e| CryptoError::KeyGeneration(format!("getrandom failed: {}", e)))?;
        Ok(Self { key })
    }

    /// Create a DEK from raw bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != KEY_SIZE {
            return Err(CryptoError::InvalidKey(format!(
                "DEK must be {} bytes, got {}",
                KEY_SIZE,
                bytes.len()
            )));
        }
        let mut key = [0u8; KEY_SIZE];
        key.copy_from_slice(bytes);
        Ok(Self { key })
    }

    /// Get the key bytes
    pub fn as_bytes(&self) -> &[u8; KEY_SIZE] {
        &self.key
    }
}

/// A public key for asymmetric encryption (X25519)
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKey {
    bytes: [u8; 32],
}

impl PublicKey {
    /// Create from raw bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 32 {
            return Err(CryptoError::InvalidKey(format!(
                "public key must be 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        Ok(Self { bytes: arr })
    }

    /// Get the key bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// Encode as base64
    pub fn to_base64(&self) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(self.bytes)
    }

    /// Decode from base64
    pub fn from_base64(s: &str) -> Result<Self> {
        use base64::Engine;
        let bytes = base64::engine::general_purpose::STANDARD.decode(s)?;
        Self::from_bytes(&bytes)
    }
}

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PublicKey({})", self.to_base64())
    }
}

/// A secret key for asymmetric encryption (X25519)
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey {
    bytes: [u8; 32],
}

impl SecretKey {
    /// Generate a new random secret key
    ///
    /// # Panics
    /// Panics if the OS random number generator is unavailable.
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        rand::RngCore::fill_bytes(&mut OsRng, &mut bytes);
        Self { bytes }
    }

    /// Generate a new random secret key, returning an error if OS entropy is unavailable.
    pub fn try_generate() -> Result<Self> {
        let mut bytes = [0u8; 32];
        getrandom::getrandom(&mut bytes)
            .map_err(|e| CryptoError::KeyGeneration(format!("getrandom failed: {}", e)))?;
        Ok(Self { bytes })
    }

    /// Create from raw bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 32 {
            return Err(CryptoError::InvalidKey(format!(
                "secret key must be 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        Ok(Self { bytes: arr })
    }

    /// Get the key bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// Derive the public key from this secret key
    pub fn public_key(&self) -> PublicKey {
        use x25519_dalek::{PublicKey as X25519Public, StaticSecret};
        let secret = StaticSecret::from(self.bytes);
        let public = X25519Public::from(&secret);
        PublicKey {
            bytes: *public.as_bytes(),
        }
    }

    /// Encode as base64
    pub fn to_base64(&self) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(self.bytes)
    }

    /// Decode from base64
    pub fn from_base64(s: &str) -> Result<Self> {
        use base64::Engine;
        let bytes = base64::engine::general_purpose::STANDARD.decode(s)?;
        Self::from_bytes(&bytes)
    }
}

/// A key pair for asymmetric encryption
#[derive(Clone)]
pub struct KekKeyPair {
    secret: SecretKey,
    public: PublicKey,
}

impl KekKeyPair {
    /// Generate a new random key pair
    pub fn generate() -> Self {
        let secret = SecretKey::generate();
        let public = secret.public_key();
        Self { secret, public }
    }

    /// Create from an existing secret key
    pub fn from_secret_key(secret: SecretKey) -> Self {
        let public = secret.public_key();
        Self { secret, public }
    }

    /// Get the secret key
    pub fn secret_key(&self) -> &SecretKey {
        &self.secret
    }

    /// Get the public key
    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }
}

/// Key manager for handling key derivation and rotation
pub struct KeyManager {
    /// The root key pair for this user
    root_keypair: KekKeyPair,
    /// Current key version for rotation tracking
    version: u32,
}

impl KeyManager {
    /// Create a new key manager with a fresh **random** key pair.
    ///
    /// **DEPRECATED: production code must use [`KeyManager::from_secret_key`]
    /// with a stable, OAuth-derived secret.** Calling `new()` produces a
    /// throwaway random keypair: every session derives a different identity,
    /// so any data encrypted under it becomes permanently unreadable on the
    /// next process start. Tests / examples that legitimately need ephemeral
    /// keys should annotate the call with `#[allow(deprecated)]`.
    ///
    /// Memory `feedback_cross_platform_alignment` requires every cross-platform
    /// SDK entry point to derive its key from `from_secret_key`; this
    /// deprecation surfaces accidental random-init paths at compile time.
    #[deprecated(
        since = "0.7.0",
        note = "use KeyManager::from_secret_key — random keypair locks users out of all writes on next session restart"
    )]
    pub fn new() -> Self {
        Self {
            root_keypair: KekKeyPair::generate(),
            version: 1,
        }
    }

    /// Create a key manager from an existing secret key
    pub fn from_secret_key(secret: SecretKey) -> Self {
        Self {
            root_keypair: KekKeyPair::from_secret_key(secret),
            version: 1,
        }
    }

    /// Get the current public key
    pub fn public_key(&self) -> &PublicKey {
        self.root_keypair.public_key()
    }

    /// Get the current key pair
    pub fn keypair(&self) -> &KekKeyPair {
        &self.root_keypair
    }

    /// Get the current key version
    pub fn version(&self) -> u32 {
        self.version
    }

    /// Generate a new DEK for file encryption
    pub fn generate_dek(&self) -> DekKey {
        DekKey::generate()
    }

    /// Derive a path-specific key for hierarchical encryption.
    ///
    /// # Security Note
    ///
    /// The KDF input concatenates `secret_key || path` without length encoding.
    /// This is safe because the secret key is always exactly 32 bytes (X25519),
    /// so there is no ambiguity in parsing: bytes `[0..32]` are always the key
    /// and bytes `[32..]` are always the path. A variable-length first component
    /// could allow `(key="AB", path="CD")` to collide with `(key="ABC", path="D")`,
    /// but the fixed 32-byte key size prevents this.
    ///
    /// # Caller Contract — Path Canonicalization (D3 audit)
    ///
    /// **The path bytes are hashed VERBATIM.** Callers are responsible for
    /// passing a cross-platform-stable canonical form, otherwise the same
    /// logical path can derive different DEKs on different operating systems
    /// and the user's data becomes unreadable on the second device.
    ///
    /// Two specific failure modes:
    ///
    /// 1. **Path separator drift.** Windows callers might pass
    ///    `"photos\\cat.jpg"` while macOS/Linux callers pass `"photos/cat.jpg"`.
    ///    These are different byte sequences and produce different keys.
    ///
    /// 2. **Unicode normalization drift.** Filenames read from a macOS HFS+
    ///    file system arrive in NFD form (`"caf\u{65}\u{0301}"`); the same
    ///    filename typed into an iOS keyboard arrives in NFC form
    ///    (`"caf\u{e9}"`). These look identical to a user but hash differently.
    ///
    /// Callers who own the path string before this function is reached SHOULD
    /// canonicalize via [`canonicalize_path`] (which handles separator drift)
    /// and SHOULD additionally NFC-normalize Unicode if any path component
    /// might come from an OS file-system enumeration (use the
    /// `unicode-normalization` crate; not pulled in here to keep
    /// fula-crypto's dependency footprint minimal).
    ///
    /// **No runtime canonicalization is applied here** — adding it would
    /// retroactively change the DEK derivation for every existing path
    /// stored under the pre-canonical form, breaking already-uploaded data.
    /// Callers that want canonicalization must opt in at their own boundary
    /// and apply it consistently for every read and write of the same logical
    /// path.
    pub fn derive_path_key(&self, path: &str) -> DekKey {
        use crate::hashing::derive_key;
        let derived = derive_key(
            "fula-path-key-v1",
            &[self.root_keypair.secret.as_bytes(), path.as_bytes()].concat(),
        );
        DekKey {
            key: *derived.as_bytes(),
        }
    }

    /// Rotate to a new key pair (for key compromise scenarios)
    pub fn rotate(&mut self) -> KekKeyPair {
        let new_keypair = KekKeyPair::generate();
        let old_keypair = std::mem::replace(&mut self.root_keypair, new_keypair);
        self.version += 1;
        old_keypair
    }
}

/// **DEPRECATED — see [`KeyManager::new`] for migration.**
///
/// Kept callable so existing source compiles, but every invocation produces a
/// random throwaway keypair. Production must construct via
/// `KeyManager::from_secret_key`. Rust does not permit `#[deprecated]` on trait
/// method impls; the deprecation warning fires through the inner `Self::new()`
/// call and through the doc note here.
impl Default for KeyManager {
    fn default() -> Self {
        #[allow(deprecated)]
        Self::new()
    }
}

/// **D3 audit fix** — canonicalize a logical path string for use as the
/// input to [`KeyManager::derive_path_key`] (and the SDK's path-keyed
/// forest lookup).
///
/// Behaviour:
///
/// 1. Replaces every `\` (backslash) with `/` (forward slash). This
///    handles the most common cross-OS divergence: a Windows caller
///    passing `"photos\\cat.jpg"` and a Mac caller passing
///    `"photos/cat.jpg"` should be treated as the same logical path.
///    S3-style storage paths are forward-slash by convention; this
///    coerces caller input to that form.
///
/// 2. Trims a single trailing `/` if present (other than the bare
///    `"/"` root). `"photos/"` and `"photos"` should be the same key.
///
/// **What this function does NOT do** — Unicode NFC normalization.
/// fula-crypto deliberately doesn't depend on `unicode-normalization`
/// to keep the wasm32 footprint small. Callers whose paths might come
/// from OS file-system enumerations (where macOS HFS+ produces NFD
/// while iOS produces NFC) MUST normalize themselves before reaching
/// this helper. A path that is byte-identical on both sides is safe;
/// a path that differs in normalization is not.
///
/// # Example
/// ```
/// # use fula_crypto::keys::canonicalize_path;
/// assert_eq!(canonicalize_path("photos\\cat.jpg"), "photos/cat.jpg");
/// assert_eq!(canonicalize_path("photos/"), "photos");
/// assert_eq!(canonicalize_path("/"), "/");
/// ```
pub fn canonicalize_path(s: &str) -> String {
    let mut out: String = s.replace('\\', "/");
    // Preserve the bare-root `/`; only strip trailing `/` from longer paths.
    if out.len() > 1 && out.ends_with('/') {
        out.pop();
    }
    out
}

/// Metadata about an encrypted file's keys
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct EncryptionKeyInfo {
    /// Version of the encryption format
    pub version: u8,
    /// Key version used for encryption
    pub key_version: u32,
    /// Encapsulated key (from HPKE)
    #[serde(with = "base64_serde")]
    pub encapsulated_key: Vec<u8>,
    /// Algorithm identifier
    pub algorithm: String,
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

#[cfg(test)]
#[allow(deprecated)] // tests legitimately exercise KeyManager::new() (random keypair); deprecation targets production callers only
mod tests {
    use super::*;

    #[test]
    fn test_canonicalize_path_backslash_to_forward_slash() {
        assert_eq!(canonicalize_path("photos\\cat.jpg"), "photos/cat.jpg");
        assert_eq!(
            canonicalize_path("photos\\2024\\beach\\sunset.jpg"),
            "photos/2024/beach/sunset.jpg"
        );
    }

    #[test]
    fn test_canonicalize_path_trailing_slash_trimmed() {
        assert_eq!(canonicalize_path("photos/"), "photos");
        assert_eq!(canonicalize_path("photos/2024/"), "photos/2024");
    }

    #[test]
    fn test_canonicalize_path_root_preserved() {
        // Bare "/" represents root; do not collapse to empty string.
        assert_eq!(canonicalize_path("/"), "/");
        // Same for backslash-spelled root.
        assert_eq!(canonicalize_path("\\"), "/");
    }

    #[test]
    fn test_canonicalize_path_idempotent() {
        let canonical = "photos/cat.jpg";
        assert_eq!(canonicalize_path(canonical), canonical);
        // Double-application is a no-op.
        assert_eq!(canonicalize_path(&canonicalize_path(canonical)), canonical);
    }

    #[test]
    fn test_canonicalize_path_non_ascii_passthrough() {
        // The helper does NOT NFC-normalize. A pre-normalized non-ASCII
        // path passes through verbatim. The contract is documented on
        // `derive_path_key`: callers requiring NFC must normalize first.
        let nfc_cafe = "caf\u{e9}/photo.jpg"; // single codepoint U+00E9
        let nfd_cafe = "cafe\u{0301}/photo.jpg"; // two-codepoint composed form
        assert_eq!(canonicalize_path(nfc_cafe), nfc_cafe);
        assert_eq!(canonicalize_path(nfd_cafe), nfd_cafe);
        // The two are different byte sequences — caller's responsibility.
        assert_ne!(canonicalize_path(nfc_cafe), canonicalize_path(nfd_cafe));
    }

    #[test]
    fn test_dek_generation() {
        let dek1 = DekKey::generate();
        let dek2 = DekKey::generate();
        assert_ne!(dek1.as_bytes(), dek2.as_bytes());
    }

    #[test]
    fn test_keypair_generation() {
        let kp1 = KekKeyPair::generate();
        let kp2 = KekKeyPair::generate();
        assert_ne!(kp1.public_key(), kp2.public_key());
    }

    #[test]
    fn test_public_key_derivation() {
        let kp = KekKeyPair::generate();
        let derived_public = kp.secret_key().public_key();
        assert_eq!(kp.public_key(), &derived_public);
    }

    #[test]
    fn test_base64_roundtrip() {
        let kp = KekKeyPair::generate();
        let encoded = kp.public_key().to_base64();
        let decoded = PublicKey::from_base64(&encoded).unwrap();
        assert_eq!(kp.public_key(), &decoded);
    }

    #[test]
    fn test_key_manager_rotation() {
        let mut km = KeyManager::new();
        let v1 = km.version();
        let old_public = km.public_key().clone();
        
        km.rotate();
        
        assert_eq!(km.version(), v1 + 1);
        assert_ne!(km.public_key(), &old_public);
    }

    #[test]
    fn test_path_key_derivation() {
        let km = KeyManager::new();
        let key1 = km.derive_path_key("/bucket/file1.txt");
        let key2 = km.derive_path_key("/bucket/file2.txt");
        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }
}
