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
    pub fn generate() -> Self {
        let mut key = [0u8; KEY_SIZE];
        rand::RngCore::fill_bytes(&mut OsRng, &mut key);
        Self { key }
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
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        rand::RngCore::fill_bytes(&mut OsRng, &mut bytes);
        Self { bytes }
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
    /// Create a new key manager with a fresh key pair
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

    /// Derive a path-specific key for hierarchical encryption
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

impl Default for KeyManager {
    fn default() -> Self {
        Self::new()
    }
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
mod tests {
    use super::*;

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
