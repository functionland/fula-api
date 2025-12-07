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

    // ==================== Security Tests ====================

    /// Test that wrong key fails to decrypt
    #[test]
    fn test_wrong_key_fails() {
        let key1 = DekKey::generate();
        let key2 = DekKey::generate();
        let plaintext = b"Secret message";
        
        let (nonce, ciphertext) = encrypt(&key1, plaintext).unwrap();
        let result = decrypt(&key2, &nonce, &ciphertext);
        
        assert!(result.is_err(), "Wrong key should fail to decrypt");
    }

    /// Test that tampered ciphertext fails authentication
    #[test]
    fn test_ciphertext_tampering_detected() {
        let key = DekKey::generate();
        let plaintext = b"Authenticated message";
        
        let (nonce, mut ciphertext) = encrypt(&key, plaintext).unwrap();
        
        // Tamper with ciphertext
        if !ciphertext.is_empty() {
            ciphertext[0] ^= 0xFF;
        }
        
        let result = decrypt(&key, &nonce, &ciphertext);
        assert!(result.is_err(), "Tampered ciphertext should fail");
    }

    /// Test that tampered authentication tag fails
    #[test]
    fn test_tag_tampering_detected() {
        let key = DekKey::generate();
        let plaintext = b"Message with tag";
        
        let (nonce, mut ciphertext) = encrypt(&key, plaintext).unwrap();
        
        // Tamper with the last byte (part of the auth tag)
        if !ciphertext.is_empty() {
            let last = ciphertext.len() - 1;
            ciphertext[last] ^= 0x01;
        }
        
        let result = decrypt(&key, &nonce, &ciphertext);
        assert!(result.is_err(), "Tampered tag should fail");
    }

    /// Test that wrong nonce fails to decrypt correctly
    #[test]
    fn test_wrong_nonce_fails() {
        let key = DekKey::generate();
        let plaintext = b"Nonce-protected message";
        
        let (nonce1, ciphertext) = encrypt(&key, plaintext).unwrap();
        let nonce2 = Nonce::generate();
        
        // Different nonce should fail
        assert_ne!(nonce1.as_bytes(), nonce2.as_bytes());
        let result = decrypt(&key, &nonce2, &ciphertext);
        assert!(result.is_err(), "Wrong nonce should fail to decrypt");
    }

    /// Test that truncated ciphertext fails
    #[test]
    fn test_truncated_ciphertext_fails() {
        let key = DekKey::generate();
        let plaintext = b"Message to truncate";
        
        let (nonce, mut ciphertext) = encrypt(&key, plaintext).unwrap();
        
        // Truncate the ciphertext
        ciphertext.truncate(ciphertext.len() / 2);
        
        let result = decrypt(&key, &nonce, &ciphertext);
        assert!(result.is_err(), "Truncated ciphertext should fail");
    }

    /// Test that appended data fails
    #[test]
    fn test_appended_data_fails() {
        let key = DekKey::generate();
        let plaintext = b"Original message";
        
        let (nonce, mut ciphertext) = encrypt(&key, plaintext).unwrap();
        
        // Append extra data
        ciphertext.extend_from_slice(b"extra");
        
        let result = decrypt(&key, &nonce, &ciphertext);
        assert!(result.is_err(), "Appended data should fail");
    }

    /// Test nonce uniqueness
    #[test]
    fn test_nonce_uniqueness() {
        let mut nonces = std::collections::HashSet::new();
        
        for _ in 0..1000 {
            let nonce = Nonce::generate();
            let nonce_bytes = nonce.as_bytes().to_vec();
            assert!(nonces.insert(nonce_bytes), "Nonce collision detected!");
        }
    }

    /// Test same plaintext produces different ciphertexts (due to random nonce)
    #[test]
    fn test_ciphertext_randomness() {
        let key = DekKey::generate();
        let plaintext = b"Same message";
        
        let (_, ct1) = encrypt(&key, plaintext).unwrap();
        let (_, ct2) = encrypt(&key, plaintext).unwrap();
        let (_, ct3) = encrypt(&key, plaintext).unwrap();
        
        assert_ne!(ct1, ct2, "Ciphertexts should be different");
        assert_ne!(ct2, ct3, "Ciphertexts should be different");
        assert_ne!(ct1, ct3, "Ciphertexts should be different");
    }

    /// Test empty plaintext handling
    #[test]
    fn test_empty_plaintext() {
        let key = DekKey::generate();
        let plaintext = b"";
        
        let (nonce, ciphertext) = encrypt(&key, plaintext).unwrap();
        let decrypted = decrypt(&key, &nonce, &ciphertext).unwrap();
        
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
        // Empty plaintext still has auth tag
        assert!(!ciphertext.is_empty());
    }

    /// Test large message encryption
    #[test]
    fn test_large_message() {
        let key = DekKey::generate();
        let plaintext = vec![0x42u8; 1024 * 1024]; // 1 MB
        
        let (nonce, ciphertext) = encrypt(&key, &plaintext).unwrap();
        let decrypted = decrypt(&key, &nonce, &ciphertext).unwrap();
        
        assert_eq!(plaintext, decrypted);
    }

    /// Test binary data with all byte values
    #[test]
    fn test_all_byte_values() {
        let key = DekKey::generate();
        let plaintext: Vec<u8> = (0..=255).collect();
        
        let (nonce, ciphertext) = encrypt(&key, &plaintext).unwrap();
        let decrypted = decrypt(&key, &nonce, &ciphertext).unwrap();
        
        assert_eq!(plaintext, decrypted);
    }

    /// Test ciphertext expansion (plaintext + tag)
    #[test]
    fn test_ciphertext_expansion() {
        let key = DekKey::generate();
        let plaintext = b"Test message";
        
        let (_, ciphertext) = encrypt(&key, plaintext).unwrap();
        
        // AES-GCM adds 16-byte auth tag
        assert_eq!(ciphertext.len(), plaintext.len() + 16);
    }

    /// Test that both cipher algorithms work correctly
    #[test]
    fn test_both_ciphers() {
        let key = DekKey::generate();
        let plaintext = b"Test both ciphers";
        let nonce = Nonce::generate();
        
        // AES-256-GCM
        let aead_aes = Aead::new(&key, AeadCipher::Aes256Gcm);
        let ct_aes = aead_aes.encrypt(&nonce, plaintext).unwrap();
        let pt_aes = aead_aes.decrypt(&nonce, &ct_aes).unwrap();
        assert_eq!(plaintext.as_slice(), pt_aes.as_slice());
        
        // ChaCha20-Poly1305
        let aead_chacha = Aead::new(&key, AeadCipher::ChaCha20Poly1305);
        let ct_chacha = aead_chacha.encrypt(&nonce, plaintext).unwrap();
        let pt_chacha = aead_chacha.decrypt(&nonce, &ct_chacha).unwrap();
        assert_eq!(plaintext.as_slice(), pt_chacha.as_slice());
        
        // Ciphertexts should be different between algorithms
        assert_ne!(ct_aes, ct_chacha);
    }

    /// Test cross-cipher decryption fails
    #[test]
    fn test_cross_cipher_fails() {
        let key = DekKey::generate();
        let plaintext = b"Cipher-specific message";
        let nonce = Nonce::generate();
        
        // Encrypt with AES
        let aead_aes = Aead::new(&key, AeadCipher::Aes256Gcm);
        let ciphertext = aead_aes.encrypt(&nonce, plaintext).unwrap();
        
        // Try to decrypt with ChaCha20
        let aead_chacha = Aead::new(&key, AeadCipher::ChaCha20Poly1305);
        let result = aead_chacha.decrypt(&nonce, &ciphertext);
        
        assert!(result.is_err(), "Cross-cipher decryption should fail");
    }

    /// Test AAD provides additional binding
    #[test]
    fn test_aad_binding() {
        let key = DekKey::generate();
        let plaintext = b"Bound to context";
        let nonce = Nonce::generate();
        let aad = b"file:/path/to/file.txt";
        
        let aead = Aead::new_default(&key);
        let ciphertext = aead.encrypt_with_aad(&nonce, plaintext, aad).unwrap();
        
        // Decryption with correct AAD succeeds
        let decrypted = aead.decrypt_with_aad(&nonce, &ciphertext, aad).unwrap();
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
        
        // Decryption without AAD fails
        let result = aead.decrypt(&nonce, &ciphertext);
        assert!(result.is_err(), "Missing AAD should fail");
        
        // Decryption with different AAD fails
        let result = aead.decrypt_with_aad(&nonce, &ciphertext, b"different-context");
        assert!(result.is_err(), "Wrong AAD should fail");
        
        // Decryption with empty AAD fails
        let result = aead.decrypt_with_aad(&nonce, &ciphertext, b"");
        assert!(result.is_err(), "Empty AAD should fail");
    }
}
