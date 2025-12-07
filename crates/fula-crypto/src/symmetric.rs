//! Symmetric encryption using AES-GCM and ChaCha20-Poly1305
//!
//! This module provides authenticated encryption for file content using
//! Data Encryption Keys (DEKs).

use crate::{CryptoError, Result, keys::{DekKey, KEY_SIZE, NONCE_SIZE}};
use aes_gcm::{
    Aes256Gcm, KeyInit,
    aead::Aead as AeadTrait,
};
use chacha20poly1305::ChaCha20Poly1305;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

/// A nonce for AEAD encryption
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Nonce {
    bytes: [u8; NONCE_SIZE],
}

impl Nonce {
    /// Generate a random nonce
    pub fn generate() -> Self {
        let mut bytes = [0u8; NONCE_SIZE];
        rand::RngCore::fill_bytes(&mut OsRng, &mut bytes);
        Self { bytes }
    }

    /// Create from raw bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != NONCE_SIZE {
            return Err(CryptoError::InvalidNonce(format!(
                "nonce must be {} bytes, got {}",
                NONCE_SIZE,
                bytes.len()
            )));
        }
        let mut arr = [0u8; NONCE_SIZE];
        arr.copy_from_slice(bytes);
        Ok(Self { bytes: arr })
    }

    /// Get the nonce bytes
    pub fn as_bytes(&self) -> &[u8; NONCE_SIZE] {
        &self.bytes
    }

    /// Increment the nonce (for streaming encryption)
    pub fn increment(&mut self) {
        for byte in self.bytes.iter_mut().rev() {
            if *byte == 255 {
                *byte = 0;
            } else {
                *byte += 1;
                break;
            }
        }
    }
}

/// Supported AEAD ciphers
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AeadCipher {
    /// AES-256-GCM
    Aes256Gcm,
    /// ChaCha20-Poly1305
    ChaCha20Poly1305,
}

impl Default for AeadCipher {
    fn default() -> Self {
        Self::Aes256Gcm
    }
}

impl AeadCipher {
    /// Get the algorithm identifier string
    pub fn algorithm_id(&self) -> &'static str {
        match self {
            Self::Aes256Gcm => "AES-256-GCM",
            Self::ChaCha20Poly1305 => "ChaCha20-Poly1305",
        }
    }

    /// Get the authentication tag size
    pub fn tag_size(&self) -> usize {
        16 // Both use 128-bit tags
    }
}

/// AEAD encryption/decryption interface
pub struct Aead {
    cipher: AeadCipher,
    key: [u8; KEY_SIZE],
}

impl Aead {
    /// Create a new AEAD instance with the given key and cipher
    pub fn new(key: &DekKey, cipher: AeadCipher) -> Self {
        Self {
            cipher,
            key: *key.as_bytes(),
        }
    }

    /// Create with the default cipher (AES-256-GCM)
    pub fn new_default(key: &DekKey) -> Self {
        Self::new(key, AeadCipher::default())
    }

    /// Encrypt data with the given nonce
    pub fn encrypt(&self, nonce: &Nonce, plaintext: &[u8]) -> Result<Vec<u8>> {
        let nonce_arr = aes_gcm::Nonce::from_slice(nonce.as_bytes());
        
        match self.cipher {
            AeadCipher::Aes256Gcm => {
                let cipher = Aes256Gcm::new_from_slice(&self.key)
                    .map_err(|e| CryptoError::Encryption(e.to_string()))?;
                cipher
                    .encrypt(nonce_arr, plaintext)
                    .map_err(|e| CryptoError::Encryption(e.to_string()))
            }
            AeadCipher::ChaCha20Poly1305 => {
                let nonce_arr = chacha20poly1305::Nonce::from_slice(nonce.as_bytes());
                let cipher = ChaCha20Poly1305::new_from_slice(&self.key)
                    .map_err(|e| CryptoError::Encryption(e.to_string()))?;
                cipher
                    .encrypt(nonce_arr, plaintext)
                    .map_err(|e| CryptoError::Encryption(e.to_string()))
            }
        }
    }

    /// Encrypt data with the given nonce and associated data
    pub fn encrypt_with_aad(&self, nonce: &Nonce, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let nonce_arr = aes_gcm::Nonce::from_slice(nonce.as_bytes());
        let payload = aes_gcm::aead::Payload { msg: plaintext, aad };
        
        match self.cipher {
            AeadCipher::Aes256Gcm => {
                let cipher = Aes256Gcm::new_from_slice(&self.key)
                    .map_err(|e| CryptoError::Encryption(e.to_string()))?;
                cipher
                    .encrypt(nonce_arr, payload)
                    .map_err(|e| CryptoError::Encryption(e.to_string()))
            }
            AeadCipher::ChaCha20Poly1305 => {
                let nonce_arr = chacha20poly1305::Nonce::from_slice(nonce.as_bytes());
                let payload = chacha20poly1305::aead::Payload { msg: plaintext, aad };
                let cipher = ChaCha20Poly1305::new_from_slice(&self.key)
                    .map_err(|e| CryptoError::Encryption(e.to_string()))?;
                cipher
                    .encrypt(nonce_arr, payload)
                    .map_err(|e| CryptoError::Encryption(e.to_string()))
            }
        }
    }

    /// Decrypt data with the given nonce
    pub fn decrypt(&self, nonce: &Nonce, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let nonce_arr = aes_gcm::Nonce::from_slice(nonce.as_bytes());
        
        match self.cipher {
            AeadCipher::Aes256Gcm => {
                let cipher = Aes256Gcm::new_from_slice(&self.key)
                    .map_err(|e| CryptoError::Decryption(e.to_string()))?;
                cipher
                    .decrypt(nonce_arr, ciphertext)
                    .map_err(|e| CryptoError::Decryption(e.to_string()))
            }
            AeadCipher::ChaCha20Poly1305 => {
                let nonce_arr = chacha20poly1305::Nonce::from_slice(nonce.as_bytes());
                let cipher = ChaCha20Poly1305::new_from_slice(&self.key)
                    .map_err(|e| CryptoError::Decryption(e.to_string()))?;
                cipher
                    .decrypt(nonce_arr, ciphertext)
                    .map_err(|e| CryptoError::Decryption(e.to_string()))
            }
        }
    }

    /// Decrypt data with the given nonce and associated data
    pub fn decrypt_with_aad(&self, nonce: &Nonce, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let nonce_arr = aes_gcm::Nonce::from_slice(nonce.as_bytes());
        let payload = aes_gcm::aead::Payload { msg: ciphertext, aad };
        
        match self.cipher {
            AeadCipher::Aes256Gcm => {
                let cipher = Aes256Gcm::new_from_slice(&self.key)
                    .map_err(|e| CryptoError::Decryption(e.to_string()))?;
                cipher
                    .decrypt(nonce_arr, payload)
                    .map_err(|e| CryptoError::Decryption(e.to_string()))
            }
            AeadCipher::ChaCha20Poly1305 => {
                let nonce_arr = chacha20poly1305::Nonce::from_slice(nonce.as_bytes());
                let payload = chacha20poly1305::aead::Payload { msg: ciphertext, aad };
                let cipher = ChaCha20Poly1305::new_from_slice(&self.key)
                    .map_err(|e| CryptoError::Decryption(e.to_string()))?;
                cipher
                    .decrypt(nonce_arr, payload)
                    .map_err(|e| CryptoError::Decryption(e.to_string()))
            }
        }
    }

    /// Get the cipher type
    pub fn cipher(&self) -> AeadCipher {
        self.cipher
    }
}

/// Encrypt data with a generated nonce (convenience function)
pub fn encrypt(key: &DekKey, plaintext: &[u8]) -> Result<(Nonce, Vec<u8>)> {
    let nonce = Nonce::generate();
    let aead = Aead::new_default(key);
    let ciphertext = aead.encrypt(&nonce, plaintext)?;
    Ok((nonce, ciphertext))
}

/// Decrypt data (convenience function)
pub fn decrypt(key: &DekKey, nonce: &Nonce, ciphertext: &[u8]) -> Result<Vec<u8>> {
    let aead = Aead::new_default(key);
    aead.decrypt(nonce, ciphertext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_gcm_roundtrip() {
        let key = DekKey::generate();
        let plaintext = b"Hello, World!";
        
        let (nonce, ciphertext) = encrypt(&key, plaintext).unwrap();
        let decrypted = decrypt(&key, &nonce, &ciphertext).unwrap();
        
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_chacha20_poly1305_roundtrip() {
        let key = DekKey::generate();
        let plaintext = b"Hello, World!";
        let nonce = Nonce::generate();
        
        let aead = Aead::new(&key, AeadCipher::ChaCha20Poly1305);
        let ciphertext = aead.encrypt(&nonce, plaintext).unwrap();
        let decrypted = aead.decrypt(&nonce, &ciphertext).unwrap();
        
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_aead_with_aad() {
        let key = DekKey::generate();
        let plaintext = b"secret data";
        let aad = b"associated data";
        let nonce = Nonce::generate();
        
        let aead = Aead::new_default(&key);
        let ciphertext = aead.encrypt_with_aad(&nonce, plaintext, aad).unwrap();
        let decrypted = aead.decrypt_with_aad(&nonce, &ciphertext, aad).unwrap();
        
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_wrong_aad_fails() {
        let key = DekKey::generate();
        let plaintext = b"secret data";
        let nonce = Nonce::generate();
        
        let aead = Aead::new_default(&key);
        let ciphertext = aead.encrypt_with_aad(&nonce, plaintext, b"correct aad").unwrap();
        let result = aead.decrypt_with_aad(&nonce, &ciphertext, b"wrong aad");
        
        assert!(result.is_err());
    }

    #[test]
    fn test_nonce_increment() {
        let mut nonce = Nonce::from_bytes(&[0u8; NONCE_SIZE]).unwrap();
        nonce.increment();
        assert_eq!(nonce.as_bytes()[NONCE_SIZE - 1], 1);
        
        let mut nonce = Nonce::from_bytes(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255]).unwrap();
        nonce.increment();
        assert_eq!(nonce.as_bytes()[NONCE_SIZE - 1], 0);
        assert_eq!(nonce.as_bytes()[NONCE_SIZE - 2], 1);
    }
}
