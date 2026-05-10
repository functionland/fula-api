//! Hybrid Public Key Encryption (HPKE) implementation
//!
//! Implements RFC 9180 for secure file sharing:
//! - Encrypt files for recipients without prior key exchange
//! - Enable the "Inbox Pattern" for decentralized file drops
//! - Support key encapsulation for DEK wrapping
//!
//! This module uses the standard RFC 9180 HPKE implementation with:
//! - KEM: X25519-HKDF-SHA256 (DHKEM)
//! - KDF: HKDF-SHA256
//! - AEAD: ChaCha20Poly1305 (default) or AES-256-GCM

use crate::{
    CryptoError, Result,
    keys::{DekKey, KekKeyPair, PublicKey, SecretKey},
    symmetric::AeadCipher,
};
use zeroize::Zeroizing;
use hpke::{
    Deserializable, Kem, Serializable,
    aead::ChaCha20Poly1305,
    kdf::HkdfSha256,
    kem::X25519HkdfSha256,
    OpModeR, OpModeS,
    rand_core::{CryptoRng, RngCore},
};
use serde::{Deserialize as SerdeDeserialize, Serialize};

/// Adapter to bridge getrandom to hpke's rand_core 0.9
///
/// # Panics
///
/// All methods on this adapter call `getrandom::getrandom()` and panic if the
/// OS entropy source is unavailable. This can happen in degraded environments
/// (early boot, certain sandboxed WASM runtimes without Web Crypto API).
///
/// The `hpke` crate's `RngCore` trait requires infallible `fill_bytes`, so
/// errors cannot be propagated through this adapter. Callers that need
/// fallible HPKE operations should call [`check_entropy`] before invoking
/// [`Encryptor`] or [`Decryptor`] methods.
struct HpkeRng;

impl RngCore for HpkeRng {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        getrandom::getrandom(&mut buf).expect("getrandom failed: OS entropy source unavailable");
        u32::from_le_bytes(buf)
    }

    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        getrandom::getrandom(&mut buf).expect("getrandom failed: OS entropy source unavailable");
        u64::from_le_bytes(buf)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        getrandom::getrandom(dest).expect("getrandom failed: OS entropy source unavailable");
    }
}

impl CryptoRng for HpkeRng {}

/// Check whether the OS entropy source is available.
///
/// Returns `Ok(())` if `getrandom` succeeds, or an error describing the
/// failure. Call this before HPKE operations in contexts where entropy may
/// be unavailable (early boot, sandboxed WASM) to get a recoverable error
/// instead of a panic from [`HpkeRng`].
pub fn check_entropy() -> crate::Result<()> {
    let mut buf = [0u8; 1];
    getrandom::getrandom(&mut buf)
        .map_err(|e| crate::CryptoError::KeyGeneration(format!("entropy unavailable: {}", e)))
}

/// Size of encapsulated key
pub const ENCAPSULATED_KEY_SIZE: usize = 32;

/// HPKE configuration
///
/// # Fixed cipher suite
///
/// The HPKE implementation is hardcoded to the RFC 9180 suite
/// `X25519HkdfSha256 + HkdfSha256 + ChaCha20Poly1305`. The [`HpkeConfig::aead`]
/// field is **ignored** by `HpkeEncryption` and is retained only for
/// forward-compatibility and diagnostics. Setting it to anything other than
/// [`AeadCipher::ChaCha20Poly1305`] does not change behavior.
#[derive(Clone, Debug, Serialize, SerdeDeserialize)]
pub struct HpkeConfig {
    /// Nominal AEAD cipher — **ignored by the current implementation**.
    ///
    /// The RFC 9180 suite is fixed to ChaCha20Poly1305. This field exists so
    /// that future cipher-suite negotiation can be wired in without a schema
    /// break. Use [`AeadCipher::ChaCha20Poly1305`] for any config that is
    /// serialized and later inspected, to avoid misleading readers.
    #[deprecated(
        note = "ignored; the RFC 9180 suite is fixed to ChaCha20Poly1305 — kept for forward-compat only"
    )]
    pub aead: AeadCipher,
    /// Key derivation context
    pub context: String,
}

impl Default for HpkeConfig {
    #[allow(deprecated)]
    fn default() -> Self {
        Self {
            aead: AeadCipher::ChaCha20Poly1305,
            context: "fula-hpke-v1".to_string(),
        }
    }
}

/// Encapsulated key from RFC 9180 HPKE encryption
#[derive(Clone, Serialize, SerdeDeserialize)]
pub struct EncapsulatedKey {
    /// The encapsulated key bytes (from RFC 9180 KEM)
    #[serde(with = "base64_array_serde")]
    pub ephemeral_public: [u8; 32],
}

mod base64_array_serde {
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&base64::engine::general_purpose::STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        let vec = base64::engine::general_purpose::STANDARD
            .decode(&s)
            .map_err(serde::de::Error::custom)?;
        if vec.len() != 32 {
            return Err(serde::de::Error::custom(format!(
                "expected 32 bytes, got {}",
                vec.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&vec);
        Ok(arr)
    }
}

mod base64_vec_serde {
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

impl EncapsulatedKey {
    /// Create from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 32 {
            return Err(CryptoError::InvalidKey(format!(
                "encapsulated key must be 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        Ok(Self { ephemeral_public: arr })
    }

    /// Get as bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.ephemeral_public
    }

    /// Encode as base64
    pub fn to_base64(&self) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(self.ephemeral_public)
    }

    /// Decode from base64
    pub fn from_base64(s: &str) -> Result<Self> {
        use base64::Engine;
        let bytes = base64::engine::general_purpose::STANDARD.decode(s)?;
        Self::from_bytes(&bytes)
    }
}

impl std::fmt::Debug for EncapsulatedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "EncapsulatedKey({})", self.to_base64())
    }
}

/// Encrypted data with all metadata needed for decryption (RFC 9180 HPKE format)
///
/// `Debug` is hand-rolled to redact `ciphertext`. While the bytes are
/// AEAD-encrypted (not plaintext), exposing them in logs aids any later
/// offline attempt to brute-force or correlate wrapped material if the
/// recipient secret is ever leaked. Length is preserved for diagnostics.
#[derive(Clone, Serialize, SerdeDeserialize)]
pub struct EncryptedData {
    /// Version of the encryption format (2 = RFC 9180 HPKE)
    pub version: u8,
    /// The encapsulated key from HPKE KEM
    pub encapsulated_key: EncapsulatedKey,
    /// The AEAD cipher used (for display/logging only, RFC 9180 uses fixed suite)
    pub cipher: AeadCipher,
    /// The encrypted ciphertext (includes AEAD auth tag)
    #[serde(with = "base64_vec_serde")]
    pub ciphertext: Vec<u8>,
}

impl std::fmt::Debug for EncryptedData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptedData")
            .field("version", &self.version)
            .field("encapsulated_key", &self.encapsulated_key)
            .field("cipher", &self.cipher)
            .field(
                "ciphertext",
                &format_args!("[{} bytes redacted]", self.ciphertext.len()),
            )
            .finish()
    }
}

impl EncryptedData {
    /// Get the size of the encrypted data
    pub fn ciphertext_len(&self) -> usize {
        self.ciphertext.len()
    }
}

/// Domain separation info for HPKE context binding (RFC 9180 info parameter)
const HPKE_INFO: &[u8] = b"fula-storage-v2";

/// Encryptor for RFC 9180 HPKE-based encryption
pub struct Encryptor {
    recipient_public: PublicKey,
    #[allow(dead_code)]
    config: HpkeConfig,  // Reserved for future cipher suite options
}

impl Encryptor {
    /// Create a new encryptor for the given recipient
    pub fn new(recipient_public: &PublicKey) -> Self {
        Self {
            recipient_public: recipient_public.clone(),
            config: HpkeConfig::default(),
        }
    }

    /// Create with custom configuration
    pub fn with_config(recipient_public: &PublicKey, config: HpkeConfig) -> Self {
        Self {
            recipient_public: recipient_public.clone(),
            config,
        }
    }

    /// Encrypt data for the recipient using RFC 9180 HPKE
    /// Uses default AAD context "fula:v2:default"
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<EncryptedData> {
        self.encrypt_with_aad(plaintext, b"fula:v2:default")
    }

    /// Encrypt data with custom AAD (Additional Authenticated Data)
    /// Security audit fix #5: AAD binds ciphertext to context, preventing swapping attacks
    pub fn encrypt_with_aad(&self, plaintext: &[u8], aad: &[u8]) -> Result<EncryptedData> {
        // Parse recipient's public key into HPKE format
        let pk_recip = <X25519HkdfSha256 as Kem>::PublicKey::from_bytes(
            self.recipient_public.as_bytes()
        ).map_err(|e| CryptoError::Encryption(format!("Invalid recipient public key: {:?}", e)))?;

        // Use RFC 9180 single-shot seal (Base mode - no sender authentication)
        let mut csprng = HpkeRng;
        let (encapped_key, ciphertext) = hpke::single_shot_seal::<
            ChaCha20Poly1305,
            HkdfSha256,
            X25519HkdfSha256,
            _
        >(
            &OpModeS::Base,
            &pk_recip,
            HPKE_INFO,
            plaintext,
            aad,  // Security audit fix #5: AAD binding
            &mut csprng,
        ).map_err(|e| CryptoError::Encryption(format!("HPKE encryption failed: {:?}", e)))?;

        // Serialize encapsulated key
        let enc_bytes = encapped_key.to_bytes();
        let mut enc_array = [0u8; 32];
        enc_array.copy_from_slice(&enc_bytes);

        Ok(EncryptedData {
            version: 2,  // Version 2 = RFC 9180 HPKE
            encapsulated_key: EncapsulatedKey {
                ephemeral_public: enc_array,
            },
            cipher: AeadCipher::ChaCha20Poly1305,
            ciphertext,
        })
    }

    /// Encrypt a DEK for the recipient (for key wrapping)
    /// Uses AAD context "fula:v2:dek-wrap" to bind DEK to its purpose
    pub fn encrypt_dek(&self, dek: &DekKey) -> Result<EncryptedData> {
        self.encrypt_with_aad(dek.as_bytes(), b"fula:v2:dek-wrap")
    }

    /// Encrypt a DEK, binding additional `context` bytes into the AAD.
    ///
    /// The full AAD is `b"fula:v2:dek-wrap|" ++ context`. `context` is expected
    /// to be a canonical, length-prefixed encoding of the surrounding metadata
    /// (e.g. share-token fields) so any post-wrap mutation of that metadata
    /// breaks unwrap authenticity. Callers own domain separation inside
    /// `context` (e.g. `b"fula:v4:share-token|..."`).
    pub fn encrypt_dek_with_context(
        &self,
        dek: &DekKey,
        context: &[u8],
    ) -> Result<EncryptedData> {
        let mut aad = Vec::with_capacity(b"fula:v2:dek-wrap|".len() + context.len());
        aad.extend_from_slice(b"fula:v2:dek-wrap|");
        aad.extend_from_slice(context);
        self.encrypt_with_aad(dek.as_bytes(), &aad)
    }

    /// Encrypt for the recipient with HPKE Auth mode, binding the sender's
    /// long-term X25519 keypair into the HPKE key schedule (RFC 9180 §5 mode
    /// `auth`). Unlike Base mode, this authenticates that `sender` possessed
    /// their secret key at encrypt time — an attacker who knows the recipient
    /// pk (public) cannot forge an Auth-mode ciphertext claiming a given
    /// sender pk without the matching secret.
    ///
    /// `aad` is authenticated but not encrypted. Callers should bind the
    /// recipient pk (or its hash) into `aad` so captures cannot be replayed
    /// to a different recipient of the same sender.
    ///
    /// Returns `EncryptedData` with `version = 2` (same envelope format as
    /// Base mode — the Auth binding lives inside the HPKE context, not the
    /// on-wire header).
    pub fn encrypt_for_recipient_auth(
        &self,
        sender: &KekKeyPair,
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<EncryptedData> {
        let pk_recip = <X25519HkdfSha256 as Kem>::PublicKey::from_bytes(
            self.recipient_public.as_bytes(),
        )
        .map_err(|e| CryptoError::Encryption(format!("Invalid recipient public key: {:?}", e)))?;

        let sk_sender = <X25519HkdfSha256 as Kem>::PrivateKey::from_bytes(
            sender.secret_key().as_bytes(),
        )
        .map_err(|e| CryptoError::Encryption(format!("Invalid sender secret key: {:?}", e)))?;
        let pk_sender = <X25519HkdfSha256 as Kem>::PublicKey::from_bytes(
            sender.public_key().as_bytes(),
        )
        .map_err(|e| CryptoError::Encryption(format!("Invalid sender public key: {:?}", e)))?;

        let mut csprng = HpkeRng;
        let (encapped_key, ciphertext) = hpke::single_shot_seal::<
            ChaCha20Poly1305,
            HkdfSha256,
            X25519HkdfSha256,
            _,
        >(
            &OpModeS::Auth((sk_sender, pk_sender)),
            &pk_recip,
            HPKE_INFO,
            plaintext,
            aad,
            &mut csprng,
        )
        .map_err(|e| CryptoError::Encryption(format!("HPKE auth encryption failed: {:?}", e)))?;

        let enc_bytes = encapped_key.to_bytes();
        let mut enc_array = [0u8; 32];
        enc_array.copy_from_slice(&enc_bytes);

        Ok(EncryptedData {
            version: 2,
            encapsulated_key: EncapsulatedKey {
                ephemeral_public: enc_array,
            },
            cipher: AeadCipher::ChaCha20Poly1305,
            ciphertext,
        })
    }
}

/// Decryptor for RFC 9180 HPKE-based decryption
pub struct Decryptor {
    secret: SecretKey,
    #[allow(dead_code)]
    config: HpkeConfig,  // Reserved for future cipher suite options
}

impl Decryptor {
    /// Create a new decryptor with the recipient's key pair
    pub fn new(keypair: &KekKeyPair) -> Self {
        Self {
            secret: keypair.secret_key().clone(),
            config: HpkeConfig::default(),
        }
    }

    /// Create with the secret key directly
    pub fn from_secret_key(secret: &SecretKey) -> Self {
        Self {
            secret: secret.clone(),
            config: HpkeConfig::default(),
        }
    }

    /// Create with custom configuration
    pub fn with_config(keypair: &KekKeyPair, config: HpkeConfig) -> Self {
        Self {
            secret: keypair.secret_key().clone(),
            config,
        }
    }

    /// Decrypt data using RFC 9180 HPKE
    /// Uses default AAD context "fula:v2:default" (must match encryption)
    pub fn decrypt(&self, encrypted: &EncryptedData) -> Result<Vec<u8>> {
        self.decrypt_with_aad(encrypted, b"fula:v2:default")
    }

    /// Decrypt data with custom AAD (must match the AAD used during encryption)
    /// Security audit fix #5: AAD binding verification
    ///
    /// Attacker-controllable failure modes (malformed encapsulated key, tag
    /// mismatch, AAD mismatch) collapse to a single generic error so an
    /// attacker with a decryption oracle can't distinguish reasons.
    pub fn decrypt_with_aad(&self, encrypted: &EncryptedData, aad: &[u8]) -> Result<Vec<u8>> {
        // Parse secret key into HPKE format.
        // This failure is NOT attacker-controllable — it reflects a corrupted
        // local keystore, so keep the specific error to aid operators.
        let sk_recip = <X25519HkdfSha256 as Kem>::PrivateKey::from_bytes(
            self.secret.as_bytes()
        ).map_err(|e| CryptoError::Decryption(format!("Invalid secret key: {:?}", e)))?;

        // Parse encapsulated key. This IS attacker-controllable (comes from the
        // ciphertext envelope), so map to the generic failure below.
        let enc_key = <X25519HkdfSha256 as Kem>::EncappedKey::from_bytes(
            encrypted.encapsulated_key.as_bytes()
        ).map_err(|_| CryptoError::Decryption("authentication failed".to_string()))?;

        // Use RFC 9180 single-shot open (Base mode). Tag/AAD failure is also
        // attacker-controllable and must share the same error string.
        let plaintext = hpke::single_shot_open::<
            ChaCha20Poly1305,
            HkdfSha256,
            X25519HkdfSha256,
        >(
            &OpModeR::Base,
            &sk_recip,
            &enc_key,
            HPKE_INFO,
            &encrypted.ciphertext,
            aad,  // Security audit fix #5: AAD binding verification
        ).map_err(|_| CryptoError::Decryption("authentication failed".to_string()))?;

        Ok(plaintext)
    }

    /// Decrypt a wrapped DEK
    /// Uses AAD context "fula:v2:dek-wrap" (must match encryption)
    pub fn decrypt_dek(&self, encrypted: &EncryptedData) -> Result<DekKey> {
        let bytes = Zeroizing::new(self.decrypt_with_aad(encrypted, b"fula:v2:dek-wrap")?);
        DekKey::from_bytes(&bytes)
    }

    /// Decrypt a wrapped DEK whose AAD binds additional `context` bytes.
    ///
    /// Mirror of [`Encryptor::encrypt_dek_with_context`]. The AAD is
    /// `b"fula:v2:dek-wrap|" ++ context` and `context` must byte-for-byte match
    /// what the producer bound. Any mutation of the caller-bound metadata
    /// collapses to the generic `authentication failed` error.
    pub fn decrypt_dek_with_context(
        &self,
        encrypted: &EncryptedData,
        context: &[u8],
    ) -> Result<DekKey> {
        let mut aad = Vec::with_capacity(b"fula:v2:dek-wrap|".len() + context.len());
        aad.extend_from_slice(b"fula:v2:dek-wrap|");
        aad.extend_from_slice(context);
        let bytes = Zeroizing::new(self.decrypt_with_aad(encrypted, &aad)?);
        DekKey::from_bytes(&bytes)
    }

    /// Decrypt a ciphertext produced by [`Encryptor::encrypt_for_recipient_auth`].
    ///
    /// Verifies that the sender possessed the secret key matching
    /// `sender_public_key` at encrypt time. A mismatch (tampered claim,
    /// forged ciphertext, or a captured Base-mode envelope replayed with a
    /// fabricated sender pk) surfaces as a generic `authentication failed`
    /// error — mode-ID, KEM, and AEAD checks are indistinguishable from the
    /// caller's perspective.
    pub fn decrypt_for_recipient_auth(
        &self,
        sender_public_key: &PublicKey,
        encrypted: &EncryptedData,
        aad: &[u8],
    ) -> Result<Vec<u8>> {
        let sk_recip = <X25519HkdfSha256 as Kem>::PrivateKey::from_bytes(
            self.secret.as_bytes(),
        )
        .map_err(|e| CryptoError::Decryption(format!("Invalid secret key: {:?}", e)))?;

        let pk_sender = <X25519HkdfSha256 as Kem>::PublicKey::from_bytes(
            sender_public_key.as_bytes(),
        )
        .map_err(|_| CryptoError::Decryption("authentication failed".to_string()))?;

        let enc_key = <X25519HkdfSha256 as Kem>::EncappedKey::from_bytes(
            encrypted.encapsulated_key.as_bytes(),
        )
        .map_err(|_| CryptoError::Decryption("authentication failed".to_string()))?;

        let plaintext = hpke::single_shot_open::<
            ChaCha20Poly1305,
            HkdfSha256,
            X25519HkdfSha256,
        >(
            &OpModeR::Auth(pk_sender),
            &sk_recip,
            &enc_key,
            HPKE_INFO,
            &encrypted.ciphertext,
            aad,
        )
        .map_err(|_| CryptoError::Decryption("authentication failed".to_string()))?;

        Ok(plaintext)
    }
}

/// Generate a random DEK and wrap it for multiple recipients.
///
/// Returns the plaintext DEK (for content encryption) and one HPKE-wrapped
/// copy per recipient. Each recipient can unwrap the DEK independently using
/// their own secret key.
pub fn wrap_dek_for_multiple(
    recipients: &[PublicKey],
) -> Result<(DekKey, Vec<EncryptedData>)> {
    let dek = DekKey::generate();

    let mut wrapped_keys = Vec::with_capacity(recipients.len());
    for recipient in recipients {
        let encryptor = Encryptor::new(recipient);
        let wrapped = encryptor.encrypt_dek(&dek)?;
        wrapped_keys.push(wrapped);
    }

    Ok((dek, wrapped_keys))
}

/// Deprecated alias for [`wrap_dek_for_multiple`].
#[deprecated(since = "0.6.0", note = "renamed to wrap_dek_for_multiple; the _plaintext parameter was unused")]
pub fn encrypt_for_multiple(
    _plaintext: &[u8],
    recipients: &[PublicKey],
) -> Result<(DekKey, Vec<EncryptedData>)> {
    wrap_dek_for_multiple(recipients)
}

/// Create a time-limited sharing link
#[derive(Clone, Serialize, SerdeDeserialize, Debug)]
pub struct ShareLink {
    /// The wrapped DEK
    pub wrapped_key: EncryptedData,
    /// Expiration timestamp (Unix seconds)
    pub expires_at: Option<i64>,
    /// Optional access permissions
    pub permissions: SharePermissions,
}

/// Permissions for a share link
#[derive(Clone, Copy, Serialize, SerdeDeserialize, Debug, Default)]
pub struct SharePermissions {
    pub can_read: bool,
    pub can_write: bool,
    pub can_delete: bool,
}

impl SharePermissions {
    pub fn read_only() -> Self {
        Self {
            can_read: true,
            can_write: false,
            can_delete: false,
        }
    }

    pub fn read_write() -> Self {
        Self {
            can_read: true,
            can_write: true,
            can_delete: false,
        }
    }

    pub fn full() -> Self {
        Self {
            can_read: true,
            can_write: true,
            can_delete: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hpke_roundtrip() {
        let keypair = KekKeyPair::generate();
        let plaintext = b"Hello, World!";

        let encryptor = Encryptor::new(keypair.public_key());
        let encrypted = encryptor.encrypt(plaintext).unwrap();

        let decryptor = Decryptor::new(&keypair);
        let decrypted = decryptor.decrypt(&encrypted).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_dek_wrapping() {
        let keypair = KekKeyPair::generate();
        let dek = DekKey::generate();

        let encryptor = Encryptor::new(keypair.public_key());
        let wrapped = encryptor.encrypt_dek(&dek).unwrap();

        let decryptor = Decryptor::new(&keypair);
        let unwrapped = decryptor.decrypt_dek(&wrapped).unwrap();

        assert_eq!(dek.as_bytes(), unwrapped.as_bytes());
    }

    #[test]
    fn test_wrong_key_fails() {
        let keypair1 = KekKeyPair::generate();
        let keypair2 = KekKeyPair::generate();
        let plaintext = b"secret data";

        let encryptor = Encryptor::new(keypair1.public_key());
        let encrypted = encryptor.encrypt(plaintext).unwrap();

        let decryptor = Decryptor::new(&keypair2);
        let result = decryptor.decrypt(&encrypted);

        assert!(result.is_err());
    }

    #[test]
    fn test_wrap_dek_for_multiple() {
        let recipients: Vec<_> = (0..3).map(|_| KekKeyPair::generate()).collect();
        let public_keys: Vec<_> = recipients.iter().map(|kp| kp.public_key().clone()).collect();

        let (dek, wrapped_keys) = wrap_dek_for_multiple(&public_keys).unwrap();

        // Each recipient should be able to decrypt their wrapped key
        for (i, wrapped) in wrapped_keys.iter().enumerate() {
            let decryptor = Decryptor::new(&recipients[i]);
            let unwrapped = decryptor.decrypt_dek(wrapped).unwrap();
            assert_eq!(dek.as_bytes(), unwrapped.as_bytes());
        }
    }

    #[test]
    fn test_encapsulated_key_serialization() {
        let keypair = KekKeyPair::generate();
        let encryptor = Encryptor::new(keypair.public_key());
        let encrypted = encryptor.encrypt(b"test").unwrap();

        let json = serde_json::to_string(&encrypted).unwrap();
        let deserialized: EncryptedData = serde_json::from_str(&json).unwrap();

        assert_eq!(
            encrypted.encapsulated_key.as_bytes(),
            deserialized.encapsulated_key.as_bytes()
        );
    }

    // ==================== Security Tests ====================

    /// Test that tampering with ciphertext is detected
    #[test]
    fn test_ciphertext_tampering_detected() {
        let keypair = KekKeyPair::generate();
        let plaintext = b"Authenticated message";

        let encryptor = Encryptor::new(keypair.public_key());
        let mut encrypted = encryptor.encrypt(plaintext).unwrap();

        // Tamper with ciphertext
        if !encrypted.ciphertext.is_empty() {
            encrypted.ciphertext[0] ^= 0xFF;
        }

        let decryptor = Decryptor::new(&keypair);
        assert!(decryptor.decrypt(&encrypted).is_err(), "Tampered ciphertext should fail");
    }

    // Note: RFC 9180 HPKE handles nonce internally, so no separate nonce tampering test needed
    // The nonce is derived from the key schedule and ciphertext sequence number

    /// Test that tampering with encapsulated key is detected
    #[test]
    fn test_encapsulated_key_tampering_detected() {
        let keypair = KekKeyPair::generate();
        let plaintext = b"Message with key integrity";

        let encryptor = Encryptor::new(keypair.public_key());
        let mut encrypted = encryptor.encrypt(plaintext).unwrap();

        // Tamper with encapsulated key
        encrypted.encapsulated_key.ephemeral_public[0] ^= 0x01;

        let decryptor = Decryptor::new(&keypair);
        assert!(decryptor.decrypt(&encrypted).is_err(), "Tampered encapsulated key should fail");
    }

    /// Test that same plaintext produces different ciphertexts (semantic security)
    #[test]
    fn test_semantic_security() {
        let keypair = KekKeyPair::generate();
        let plaintext = b"Same message encrypted multiple times";

        let encryptor = Encryptor::new(keypair.public_key());

        let encrypted1 = encryptor.encrypt(plaintext).unwrap();
        let encrypted2 = encryptor.encrypt(plaintext).unwrap();
        let encrypted3 = encryptor.encrypt(plaintext).unwrap();

        // All ciphertexts should be different (RFC 9180 uses ephemeral keys)
        assert_ne!(encrypted1.ciphertext, encrypted2.ciphertext);
        assert_ne!(encrypted2.ciphertext, encrypted3.ciphertext);
        assert_ne!(encrypted1.ciphertext, encrypted3.ciphertext);

        // All encapsulated keys should be different (ephemeral keys from KEM)
        assert_ne!(
            encrypted1.encapsulated_key.as_bytes(),
            encrypted2.encapsulated_key.as_bytes()
        );
        assert_ne!(
            encrypted2.encapsulated_key.as_bytes(),
            encrypted3.encapsulated_key.as_bytes()
        );
    }

    /// Test that ciphertext doesn't contain plaintext patterns
    #[test]
    fn test_no_plaintext_leakage() {
        let keypair = KekKeyPair::generate();
        let plaintext = b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";  // Repeated pattern

        let encryptor = Encryptor::new(keypair.public_key());
        let encrypted = encryptor.encrypt(plaintext).unwrap();

        // Ciphertext should not contain long runs of the same byte
        let max_run = encrypted.ciphertext.windows(4)
            .filter(|w| w.iter().all(|&b| b == w[0]))
            .count();
        
        assert!(max_run < 3, "Ciphertext may leak plaintext patterns");
    }

    /// Test key isolation - one keypair cannot decrypt another's data
    #[test]
    fn test_key_isolation() {
        let keypair1 = KekKeyPair::generate();
        let keypair2 = KekKeyPair::generate();
        let keypair3 = KekKeyPair::generate();

        let encryptor1 = Encryptor::new(keypair1.public_key());
        let encrypted = encryptor1.encrypt(b"secret for keypair1").unwrap();

        // Only keypair1 can decrypt
        let decryptor1 = Decryptor::new(&keypair1);
        assert!(decryptor1.decrypt(&encrypted).is_ok());

        // keypair2 and keypair3 cannot decrypt
        let decryptor2 = Decryptor::new(&keypair2);
        let decryptor3 = Decryptor::new(&keypair3);
        assert!(decryptor2.decrypt(&encrypted).is_err());
        assert!(decryptor3.decrypt(&encrypted).is_err());
    }

    /// Test empty plaintext handling
    #[test]
    fn test_empty_plaintext() {
        let keypair = KekKeyPair::generate();
        let plaintext = b"";

        let encryptor = Encryptor::new(keypair.public_key());
        let encrypted = encryptor.encrypt(plaintext).unwrap();

        let decryptor = Decryptor::new(&keypair);
        let decrypted = decryptor.decrypt(&encrypted).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    /// Test large message handling
    #[test]
    fn test_large_message() {
        let keypair = KekKeyPair::generate();
        let plaintext = vec![0x42u8; 1024 * 1024];  // 1 MB

        let encryptor = Encryptor::new(keypair.public_key());
        let encrypted = encryptor.encrypt(&plaintext).unwrap();

        let decryptor = Decryptor::new(&keypair);
        let decrypted = decryptor.decrypt(&encrypted).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    /// Test binary data with all byte values
    #[test]
    fn test_binary_data() {
        let keypair = KekKeyPair::generate();
        let plaintext: Vec<u8> = (0..=255).collect();

        let encryptor = Encryptor::new(keypair.public_key());
        let encrypted = encryptor.encrypt(&plaintext).unwrap();

        let decryptor = Decryptor::new(&keypair);
        let decrypted = decryptor.decrypt(&encrypted).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    /// Test that version field is correctly set
    #[test]
    fn test_version_field() {
        let keypair = KekKeyPair::generate();
        let encryptor = Encryptor::new(keypair.public_key());
        let encrypted = encryptor.encrypt(b"test").unwrap();

        assert_eq!(encrypted.version, crate::CRYPTO_VERSION);
    }

    /// Test decryption from secret key directly
    #[test]
    fn test_decrypt_from_secret_key() {
        let keypair = KekKeyPair::generate();
        let plaintext = b"Decrypt using secret key directly";

        let encryptor = Encryptor::new(keypair.public_key());
        let encrypted = encryptor.encrypt(plaintext).unwrap();

        // Decrypt using secret key directly
        let decryptor = Decryptor::from_secret_key(keypair.secret_key());
        let decrypted = decryptor.decrypt(&encrypted).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    /// Test that truncated ciphertext fails
    #[test]
    fn test_truncated_ciphertext_fails() {
        let keypair = KekKeyPair::generate();
        let plaintext = b"Message that will be truncated";

        let encryptor = Encryptor::new(keypair.public_key());
        let mut encrypted = encryptor.encrypt(plaintext).unwrap();

        // Truncate ciphertext
        if encrypted.ciphertext.len() > 10 {
            encrypted.ciphertext.truncate(encrypted.ciphertext.len() - 10);
        }

        let decryptor = Decryptor::new(&keypair);
        assert!(decryptor.decrypt(&encrypted).is_err(), "Truncated ciphertext should fail");
    }

    /// Test that appended data fails
    #[test]
    fn test_appended_data_fails() {
        let keypair = KekKeyPair::generate();
        let plaintext = b"Original message";

        let encryptor = Encryptor::new(keypair.public_key());
        let mut encrypted = encryptor.encrypt(plaintext).unwrap();

        // Append extra data
        encrypted.ciphertext.extend_from_slice(b"extra garbage");

        let decryptor = Decryptor::new(&keypair);
        assert!(decryptor.decrypt(&encrypted).is_err(), "Appended data should fail");
    }

    // ==================== AAD Binding Tests (Security Audit Fix #5) ====================

    /// Test that AAD binding works correctly
    #[test]
    fn test_aad_binding_roundtrip() {
        let keypair = KekKeyPair::generate();
        let plaintext = b"Data with AAD binding";
        let aad = b"fula:v2:bucket:my-bucket:key:my-file.txt";

        let encryptor = Encryptor::new(keypair.public_key());
        let encrypted = encryptor.encrypt_with_aad(plaintext, aad).unwrap();

        let decryptor = Decryptor::new(&keypair);
        let decrypted = decryptor.decrypt_with_aad(&encrypted, aad).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    /// Test that wrong AAD fails decryption
    #[test]
    fn test_wrong_aad_fails() {
        let keypair = KekKeyPair::generate();
        let plaintext = b"Data with AAD binding";
        let correct_aad = b"fula:v2:bucket:my-bucket:key:my-file.txt";
        let wrong_aad = b"fula:v2:bucket:other-bucket:key:other-file.txt";

        let encryptor = Encryptor::new(keypair.public_key());
        let encrypted = encryptor.encrypt_with_aad(plaintext, correct_aad).unwrap();

        let decryptor = Decryptor::new(&keypair);
        
        // Correct AAD should work
        assert!(decryptor.decrypt_with_aad(&encrypted, correct_aad).is_ok());
        
        // Wrong AAD should fail
        let result = decryptor.decrypt_with_aad(&encrypted, wrong_aad);
        assert!(result.is_err(), "Wrong AAD should fail decryption");
    }

    /// Test that empty AAD differs from non-empty AAD
    #[test]
    fn test_empty_vs_nonempty_aad() {
        let keypair = KekKeyPair::generate();
        let plaintext = b"Test data";

        let encryptor = Encryptor::new(keypair.public_key());
        let encrypted = encryptor.encrypt_with_aad(plaintext, b"some-context").unwrap();

        let decryptor = Decryptor::new(&keypair);
        
        // Empty AAD should fail
        let result = decryptor.decrypt_with_aad(&encrypted, b"");
        assert!(result.is_err(), "Empty AAD should fail when non-empty was used");
    }

    /// Test DEK wrapping uses correct AAD
    #[test]
    fn test_dek_wrap_aad() {
        let keypair = KekKeyPair::generate();
        let dek = DekKey::generate();

        let encryptor = Encryptor::new(keypair.public_key());
        let wrapped = encryptor.encrypt_dek(&dek).unwrap();

        let decryptor = Decryptor::new(&keypair);
        let unwrapped = decryptor.decrypt_dek(&wrapped).unwrap();

        assert_eq!(dek.as_bytes(), unwrapped.as_bytes());
    }
}
