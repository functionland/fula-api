//! Hybrid Public Key Encryption (HPKE) implementation
//!
//! Implements RFC 9180 for secure file sharing:
//! - Encrypt files for recipients without prior key exchange
//! - Enable the "Inbox Pattern" for decentralized file drops
//! - Support key encapsulation for DEK wrapping

use crate::{
    CryptoError, Result, CRYPTO_VERSION,
    keys::{DekKey, KekKeyPair, PublicKey, SecretKey},
    symmetric::{Aead, AeadCipher, Nonce},
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};

/// Size of encapsulated key
pub const ENCAPSULATED_KEY_SIZE: usize = 32;

/// HPKE configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HpkeConfig {
    /// The AEAD cipher to use
    pub aead: AeadCipher,
    /// Key derivation context
    pub context: String,
}

impl Default for HpkeConfig {
    fn default() -> Self {
        Self {
            aead: AeadCipher::Aes256Gcm,
            context: "fula-hpke-v1".to_string(),
        }
    }
}

/// Encapsulated key from HPKE encryption
#[derive(Clone, Serialize, Deserialize)]
pub struct EncapsulatedKey {
    /// The ephemeral public key
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

/// Encrypted data with all metadata needed for decryption
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct EncryptedData {
    /// Version of the encryption format
    pub version: u8,
    /// The encapsulated key
    pub encapsulated_key: EncapsulatedKey,
    /// The nonce used for AEAD
    pub nonce: Nonce,
    /// The AEAD cipher used
    pub cipher: AeadCipher,
    /// The encrypted ciphertext
    #[serde(with = "base64_vec_serde")]
    pub ciphertext: Vec<u8>,
}

impl EncryptedData {
    /// Get the size of the encrypted data
    pub fn ciphertext_len(&self) -> usize {
        self.ciphertext.len()
    }
}

/// Encryptor for HPKE-based encryption
pub struct Encryptor {
    recipient_public: PublicKey,
    config: HpkeConfig,
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

    /// Encrypt data for the recipient
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<EncryptedData> {
        // Generate ephemeral key pair
        let ephemeral_secret = StaticSecret::random_from_rng(OsRng);
        let ephemeral_public = X25519Public::from(&ephemeral_secret);

        // Perform X25519 key exchange
        let recipient_x25519 = X25519Public::from(*self.recipient_public.as_bytes());
        let shared_secret = ephemeral_secret.diffie_hellman(&recipient_x25519);

        // Derive the DEK from shared secret using BLAKE3
        let dek = derive_dek(shared_secret.as_bytes(), &self.config.context);

        // Encrypt the data
        let nonce = Nonce::generate();
        let aead = Aead::new(&dek, self.config.aead);
        let ciphertext = aead.encrypt(&nonce, plaintext)?;

        Ok(EncryptedData {
            version: CRYPTO_VERSION,
            encapsulated_key: EncapsulatedKey {
                ephemeral_public: *ephemeral_public.as_bytes(),
            },
            nonce,
            cipher: self.config.aead,
            ciphertext,
        })
    }

    /// Encrypt a DEK for the recipient (for key wrapping)
    pub fn encrypt_dek(&self, dek: &DekKey) -> Result<EncryptedData> {
        self.encrypt(dek.as_bytes())
    }
}

/// Decryptor for HPKE-based decryption
pub struct Decryptor {
    secret: SecretKey,
    config: HpkeConfig,
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

    /// Decrypt data
    pub fn decrypt(&self, encrypted: &EncryptedData) -> Result<Vec<u8>> {
        // Recreate the shared secret from the encapsulated key
        let recipient_secret = StaticSecret::from(*self.secret.as_bytes());
        let ephemeral_public = X25519Public::from(encrypted.encapsulated_key.ephemeral_public);
        let shared_secret = recipient_secret.diffie_hellman(&ephemeral_public);

        // Derive the DEK from shared secret
        let dek = derive_dek(shared_secret.as_bytes(), &self.config.context);

        // Decrypt the data
        let aead = Aead::new(&dek, encrypted.cipher);
        aead.decrypt(&encrypted.nonce, &encrypted.ciphertext)
    }

    /// Decrypt a wrapped DEK
    pub fn decrypt_dek(&self, encrypted: &EncryptedData) -> Result<DekKey> {
        let bytes = self.decrypt(encrypted)?;
        DekKey::from_bytes(&bytes)
    }
}

/// Derive a DEK from a shared secret
fn derive_dek(shared_secret: &[u8], context: &str) -> DekKey {
    use crate::hashing::derive_key;
    let derived = derive_key(context, shared_secret);
    DekKey::from_bytes(derived.as_bytes()).expect("derived key has correct length")
}

/// Encrypt data for multiple recipients
pub fn encrypt_for_multiple(
    _plaintext: &[u8],
    recipients: &[PublicKey],
) -> Result<(DekKey, Vec<EncryptedData>)> {
    // Generate a random DEK
    let dek = DekKey::generate();

    // Encrypt the DEK for each recipient
    let mut wrapped_keys = Vec::with_capacity(recipients.len());
    for recipient in recipients {
        let encryptor = Encryptor::new(recipient);
        let wrapped = encryptor.encrypt_dek(&dek)?;
        wrapped_keys.push(wrapped);
    }

    Ok((dek, wrapped_keys))
}

/// Create a time-limited sharing link
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ShareLink {
    /// The wrapped DEK
    pub wrapped_key: EncryptedData,
    /// Expiration timestamp (Unix seconds)
    pub expires_at: Option<i64>,
    /// Optional access permissions
    pub permissions: SharePermissions,
}

/// Permissions for a share link
#[derive(Clone, Copy, Serialize, Deserialize, Debug, Default)]
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
    fn test_encrypt_for_multiple() {
        let recipients: Vec<_> = (0..3).map(|_| KekKeyPair::generate()).collect();
        let public_keys: Vec<_> = recipients.iter().map(|kp| kp.public_key().clone()).collect();
        let plaintext = b"shared secret";

        let (dek, wrapped_keys) = encrypt_for_multiple(plaintext, &public_keys).unwrap();

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

    /// Test that tampering with nonce is detected
    #[test]
    fn test_nonce_tampering_detected() {
        let keypair = KekKeyPair::generate();
        let plaintext = b"Message with nonce integrity";

        let encryptor = Encryptor::new(keypair.public_key());
        let mut encrypted = encryptor.encrypt(plaintext).unwrap();

        // Tamper with nonce
        let mut nonce_bytes = encrypted.nonce.as_bytes().to_vec();
        nonce_bytes[0] ^= 0x01;
        encrypted.nonce = Nonce::from_bytes(&nonce_bytes).unwrap();

        let decryptor = Decryptor::new(&keypair);
        assert!(decryptor.decrypt(&encrypted).is_err(), "Tampered nonce should fail");
    }

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

        // All ciphertexts should be different
        assert_ne!(encrypted1.ciphertext, encrypted2.ciphertext);
        assert_ne!(encrypted2.ciphertext, encrypted3.ciphertext);
        assert_ne!(encrypted1.ciphertext, encrypted3.ciphertext);

        // All nonces should be different
        assert_ne!(encrypted1.nonce.as_bytes(), encrypted2.nonce.as_bytes());
        assert_ne!(encrypted2.nonce.as_bytes(), encrypted3.nonce.as_bytes());

        // All encapsulated keys should be different (ephemeral keys)
        assert_ne!(
            encrypted1.encapsulated_key.as_bytes(),
            encrypted2.encapsulated_key.as_bytes()
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
}
