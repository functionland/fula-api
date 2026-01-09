//! Hybrid Post-Quantum Key Encapsulation Mechanism
//!
//! This module implements a hybrid KEM combining:
//! - **X25519** (classical ECDH) - Fast, well-tested, 128-bit classical security
//! - **ML-KEM-768 (Kyber768)** - NIST-standardized, 192-bit post-quantum security
//!
//! # Security Rationale
//!
//! The hybrid approach provides defense-in-depth:
//! - If classical crypto is broken (quantum computers), ML-KEM protects
//! - If ML-KEM has unforeseen weaknesses, X25519 still provides security
//! - Combined shared secret uses HKDF-SHA256 for proper key derivation
//!
//! # Wire Format
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │                    Hybrid Encapsulated Key                          │
//! ├───────────────────────────────┬─────────────────────────────────────┤
//! │  X25519 ephemeral (32 bytes)  │  ML-KEM-768 ciphertext (1088 bytes) │
//! └───────────────────────────────┴─────────────────────────────────────┘
//! Total: 1120 bytes
//!
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │                    Hybrid Public Key                                │
//! ├───────────────────────────────┬─────────────────────────────────────┤
//! │  X25519 public (32 bytes)     │  ML-KEM-768 public (1184 bytes)     │
//! └───────────────────────────────┴─────────────────────────────────────┘
//! Total: 1216 bytes
//! ```
//!
//! # NIST Compliance
//!
//! ML-KEM-768 corresponds to NIST's FIPS 203 standard (formerly Kyber768).
//! It provides NIST Security Level 3 (equivalent to AES-192).

use crate::{CryptoError, Result};
use hkdf::Hkdf;
use libcrux_ml_kem::mlkem768::{
    generate_key_pair as mlkem_generate_key_pair,
    encapsulate as mlkem_encapsulate,
    decapsulate as mlkem_decapsulate,
    MlKem768PublicKey,
    MlKem768PrivateKey,
    MlKem768Ciphertext,
};
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Size of the X25519 public key
pub const X25519_PUBLIC_KEY_SIZE: usize = 32;

/// Size of the X25519 secret key
pub const X25519_SECRET_KEY_SIZE: usize = 32;

/// Size of the ML-KEM-768 public key (FIPS 203)
pub const MLKEM_PUBLIC_KEY_SIZE: usize = 1184;

/// Size of the ML-KEM-768 secret key (FIPS 203)
pub const MLKEM_SECRET_KEY_SIZE: usize = 2400;

/// Size of the ML-KEM-768 ciphertext (FIPS 203)
pub const MLKEM_CIPHERTEXT_SIZE: usize = 1088;

/// Size of the hybrid public key (X25519 + ML-KEM-768)
pub const HYBRID_PUBLIC_KEY_SIZE: usize = X25519_PUBLIC_KEY_SIZE + MLKEM_PUBLIC_KEY_SIZE;

/// Size of the hybrid secret key (X25519 + ML-KEM-768)
pub const HYBRID_SECRET_KEY_SIZE: usize = X25519_SECRET_KEY_SIZE + MLKEM_SECRET_KEY_SIZE;

/// Size of the hybrid encapsulated key (X25519 ephemeral + ML-KEM ciphertext)
pub const HYBRID_ENCAPSULATED_KEY_SIZE: usize = X25519_PUBLIC_KEY_SIZE + MLKEM_CIPHERTEXT_SIZE;

/// Size of the derived shared secret
pub const SHARED_SECRET_SIZE: usize = 32;

/// Domain separation for HKDF key derivation
const HKDF_INFO: &[u8] = b"fula-hybrid-kem-v1";

/// A hybrid public key combining X25519 and ML-KEM-768
#[derive(Clone)]
pub struct HybridPublicKey {
    /// Classical X25519 public key
    x25519: [u8; X25519_PUBLIC_KEY_SIZE],
    /// Post-quantum ML-KEM-768 public key
    mlkem: [u8; MLKEM_PUBLIC_KEY_SIZE],
}

impl HybridPublicKey {
    /// Create from raw bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != HYBRID_PUBLIC_KEY_SIZE {
            return Err(CryptoError::InvalidKey(format!(
                "hybrid public key must be {} bytes, got {}",
                HYBRID_PUBLIC_KEY_SIZE,
                bytes.len()
            )));
        }
        
        let mut x25519 = [0u8; X25519_PUBLIC_KEY_SIZE];
        let mut mlkem = [0u8; MLKEM_PUBLIC_KEY_SIZE];
        
        x25519.copy_from_slice(&bytes[..X25519_PUBLIC_KEY_SIZE]);
        mlkem.copy_from_slice(&bytes[X25519_PUBLIC_KEY_SIZE..]);
        
        Ok(Self { x25519, mlkem })
    }
    
    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(HYBRID_PUBLIC_KEY_SIZE);
        bytes.extend_from_slice(&self.x25519);
        bytes.extend_from_slice(&self.mlkem);
        bytes
    }
    
    /// Get the X25519 component
    pub fn x25519_bytes(&self) -> &[u8; X25519_PUBLIC_KEY_SIZE] {
        &self.x25519
    }
    
    /// Get the ML-KEM component
    pub fn mlkem_bytes(&self) -> &[u8; MLKEM_PUBLIC_KEY_SIZE] {
        &self.mlkem
    }
    
    /// Encode as base64
    pub fn to_base64(&self) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(self.to_bytes())
    }
    
    /// Decode from base64
    pub fn from_base64(s: &str) -> Result<Self> {
        use base64::Engine;
        let bytes = base64::engine::general_purpose::STANDARD.decode(s)?;
        Self::from_bytes(&bytes)
    }
}

impl std::fmt::Debug for HybridPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HybridPublicKey(x25519+mlkem768, {} bytes)", HYBRID_PUBLIC_KEY_SIZE)
    }
}

/// A hybrid secret key combining X25519 and ML-KEM-768
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct HybridSecretKey {
    /// Classical X25519 secret key
    x25519: [u8; X25519_SECRET_KEY_SIZE],
    /// Post-quantum ML-KEM-768 secret key
    mlkem: [u8; MLKEM_SECRET_KEY_SIZE],
}

impl HybridSecretKey {
    /// Generate a new random hybrid key pair
    pub fn generate() -> (Self, HybridPublicKey) {
        // Generate X25519 keypair using getrandom (WASM compatible)
        let mut x25519_bytes = [0u8; 32];
        getrandom::getrandom(&mut x25519_bytes).expect("getrandom failed");
        let x25519_secret = StaticSecret::from(x25519_bytes);
        let x25519_public = X25519Public::from(&x25519_secret);

        // Generate ML-KEM-768 keypair using libcrux (FIPS 203)
        // libcrux uses explicit 64-byte randomness instead of callback RNG
        let mut keygen_randomness = [0u8; 64];
        getrandom::getrandom(&mut keygen_randomness).expect("getrandom failed");
        let mlkem_keypair = mlkem_generate_key_pair(keygen_randomness);

        // Extract raw bytes from libcrux types
        let mut mlkem_pk = [0u8; MLKEM_PUBLIC_KEY_SIZE];
        let mut mlkem_sk = [0u8; MLKEM_SECRET_KEY_SIZE];
        mlkem_pk.copy_from_slice(mlkem_keypair.public_key().as_ref());
        mlkem_sk.copy_from_slice(mlkem_keypair.private_key().as_ref());

        let secret = Self {
            x25519: x25519_secret.to_bytes(),
            mlkem: mlkem_sk,
        };

        let public = HybridPublicKey {
            x25519: *x25519_public.as_bytes(),
            mlkem: mlkem_pk,
        };

        (secret, public)
    }
    
    /// Create from raw bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != HYBRID_SECRET_KEY_SIZE {
            return Err(CryptoError::InvalidKey(format!(
                "hybrid secret key must be {} bytes, got {}",
                HYBRID_SECRET_KEY_SIZE,
                bytes.len()
            )));
        }
        
        let mut x25519 = [0u8; X25519_SECRET_KEY_SIZE];
        let mut mlkem = [0u8; MLKEM_SECRET_KEY_SIZE];
        
        x25519.copy_from_slice(&bytes[..X25519_SECRET_KEY_SIZE]);
        mlkem.copy_from_slice(&bytes[X25519_SECRET_KEY_SIZE..]);
        
        Ok(Self { x25519, mlkem })
    }
    
    /// Serialize to bytes (handle with care - contains secret material)
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(HYBRID_SECRET_KEY_SIZE);
        bytes.extend_from_slice(&self.x25519);
        bytes.extend_from_slice(&self.mlkem);
        bytes
    }
    
    /// Derive the public key from this secret key
    pub fn public_key(&self) -> HybridPublicKey {
        // Derive X25519 public
        let x25519_secret = StaticSecret::from(self.x25519);
        let x25519_public = X25519Public::from(&x25519_secret);
        
        // For ML-KEM, we need to store the public key separately or regenerate
        // The pqc_kyber crate includes the public key in the secret key bytes
        // Extract it from the last 1184 bytes of the secret key
        let mut mlkem_public = [0u8; MLKEM_PUBLIC_KEY_SIZE];
        let pk_start = MLKEM_SECRET_KEY_SIZE - MLKEM_PUBLIC_KEY_SIZE;
        mlkem_public.copy_from_slice(&self.mlkem[pk_start..]);
        
        HybridPublicKey {
            x25519: *x25519_public.as_bytes(),
            mlkem: mlkem_public,
        }
    }
    
    /// Encode as base64
    pub fn to_base64(&self) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(self.to_bytes())
    }
    
    /// Decode from base64
    pub fn from_base64(s: &str) -> Result<Self> {
        use base64::Engine;
        let bytes = base64::engine::general_purpose::STANDARD.decode(s)?;
        Self::from_bytes(&bytes)
    }
}

impl std::fmt::Debug for HybridSecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HybridSecretKey(x25519+mlkem768, [REDACTED])")
    }
}

/// A hybrid key pair for post-quantum encryption
#[derive(Clone)]
pub struct HybridKeyPair {
    secret: HybridSecretKey,
    public: HybridPublicKey,
}

impl HybridKeyPair {
    /// Generate a new random hybrid key pair
    pub fn generate() -> Self {
        let (secret, public) = HybridSecretKey::generate();
        Self { secret, public }
    }
    
    /// Create from an existing secret key
    pub fn from_secret_key(secret: HybridSecretKey) -> Self {
        let public = secret.public_key();
        Self { secret, public }
    }
    
    /// Get the secret key
    pub fn secret_key(&self) -> &HybridSecretKey {
        &self.secret
    }
    
    /// Get the public key
    pub fn public_key(&self) -> &HybridPublicKey {
        &self.public
    }
}

/// Encapsulated key from hybrid KEM
#[derive(Clone)]
pub struct HybridEncapsulatedKey {
    /// X25519 ephemeral public key
    x25519_ephemeral: [u8; X25519_PUBLIC_KEY_SIZE],
    /// ML-KEM ciphertext
    mlkem_ciphertext: [u8; MLKEM_CIPHERTEXT_SIZE],
}

impl HybridEncapsulatedKey {
    /// Create from raw bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != HYBRID_ENCAPSULATED_KEY_SIZE {
            return Err(CryptoError::InvalidKey(format!(
                "hybrid encapsulated key must be {} bytes, got {}",
                HYBRID_ENCAPSULATED_KEY_SIZE,
                bytes.len()
            )));
        }
        
        let mut x25519_ephemeral = [0u8; X25519_PUBLIC_KEY_SIZE];
        let mut mlkem_ciphertext = [0u8; MLKEM_CIPHERTEXT_SIZE];
        
        x25519_ephemeral.copy_from_slice(&bytes[..X25519_PUBLIC_KEY_SIZE]);
        mlkem_ciphertext.copy_from_slice(&bytes[X25519_PUBLIC_KEY_SIZE..]);
        
        Ok(Self { x25519_ephemeral, mlkem_ciphertext })
    }
    
    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(HYBRID_ENCAPSULATED_KEY_SIZE);
        bytes.extend_from_slice(&self.x25519_ephemeral);
        bytes.extend_from_slice(&self.mlkem_ciphertext);
        bytes
    }
    
    /// Encode as base64
    pub fn to_base64(&self) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(self.to_bytes())
    }
    
    /// Decode from base64
    pub fn from_base64(s: &str) -> Result<Self> {
        use base64::Engine;
        let bytes = base64::engine::general_purpose::STANDARD.decode(s)?;
        Self::from_bytes(&bytes)
    }
}

impl std::fmt::Debug for HybridEncapsulatedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HybridEncapsulatedKey({} bytes)", HYBRID_ENCAPSULATED_KEY_SIZE)
    }
}

/// Encapsulate a shared secret for a recipient (sender side)
///
/// This generates an ephemeral key pair and combines:
/// 1. X25519 ECDH with recipient's X25519 public key
/// 2. ML-KEM-768 encapsulation with recipient's ML-KEM public key
/// 3. HKDF-SHA256 to derive the final shared secret
///
/// Returns the encapsulated key (to send to recipient) and the shared secret
pub fn encapsulate(recipient_public: &HybridPublicKey) -> Result<(HybridEncapsulatedKey, [u8; SHARED_SECRET_SIZE])> {
    // X25519: Generate ephemeral keypair using getrandom (WASM compatible)
    let mut ephemeral_bytes = [0u8; 32];
    getrandom::getrandom(&mut ephemeral_bytes).expect("getrandom failed");
    let x25519_ephemeral_secret = StaticSecret::from(ephemeral_bytes);
    let x25519_ephemeral_public = X25519Public::from(&x25519_ephemeral_secret);
    let x25519_recipient_public = X25519Public::from(recipient_public.x25519);
    let x25519_shared = x25519_ephemeral_secret.diffie_hellman(&x25519_recipient_public);

    // ML-KEM-768: Encapsulate using libcrux (FIPS 203)
    // libcrux uses explicit 32-byte randomness instead of callback RNG
    let mut encaps_randomness = [0u8; 32];
    getrandom::getrandom(&mut encaps_randomness).expect("getrandom failed");

    let mlkem_pk = MlKem768PublicKey::from(recipient_public.mlkem);
    let (ct, mlkem_shared_secret) = mlkem_encapsulate(&mlkem_pk, encaps_randomness);

    // Extract raw bytes from libcrux types
    let mut mlkem_ciphertext = [0u8; MLKEM_CIPHERTEXT_SIZE];
    mlkem_ciphertext.copy_from_slice(ct.as_ref());

    // Combine shared secrets using HKDF-SHA256
    // IKM = X25519_shared || ML-KEM_shared
    let mut ikm = Vec::with_capacity(32 + SHARED_SECRET_SIZE);
    ikm.extend_from_slice(x25519_shared.as_bytes());
    ikm.extend_from_slice(&mlkem_shared_secret);

    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut shared_secret = [0u8; SHARED_SECRET_SIZE];
    hk.expand(HKDF_INFO, &mut shared_secret)
        .map_err(|e| CryptoError::Encryption(format!("HKDF expansion failed: {:?}", e)))?;

    // Zero out intermediate secrets
    ikm.zeroize();

    let encapsulated = HybridEncapsulatedKey {
        x25519_ephemeral: *x25519_ephemeral_public.as_bytes(),
        mlkem_ciphertext,
    };
    
    Ok((encapsulated, shared_secret))
}

/// Decapsulate a shared secret (recipient side)
///
/// This uses the recipient's secret key to recover:
/// 1. X25519 ECDH with the ephemeral public key
/// 2. ML-KEM-768 decapsulation
/// 3. HKDF-SHA256 to derive the same shared secret
pub fn decapsulate(
    encapsulated: &HybridEncapsulatedKey,
    recipient_secret: &HybridSecretKey,
) -> Result<[u8; SHARED_SECRET_SIZE]> {
    // X25519: Perform ECDH with ephemeral public key
    let x25519_secret = StaticSecret::from(recipient_secret.x25519);
    let x25519_ephemeral_public = X25519Public::from(encapsulated.x25519_ephemeral);
    let x25519_shared = x25519_secret.diffie_hellman(&x25519_ephemeral_public);

    // ML-KEM-768: Decapsulate using libcrux (FIPS 203)
    // Note: libcrux argument order is (private_key, ciphertext) - swapped from pqc_kyber
    let mlkem_sk = MlKem768PrivateKey::from(recipient_secret.mlkem);
    let mlkem_ct = MlKem768Ciphertext::from(encapsulated.mlkem_ciphertext);
    let mlkem_shared_secret = mlkem_decapsulate(&mlkem_sk, &mlkem_ct);

    // Combine shared secrets using HKDF-SHA256 (same as encapsulation)
    let mut ikm = Vec::with_capacity(32 + SHARED_SECRET_SIZE);
    ikm.extend_from_slice(x25519_shared.as_bytes());
    ikm.extend_from_slice(&mlkem_shared_secret);

    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut shared_secret = [0u8; SHARED_SECRET_SIZE];
    hk.expand(HKDF_INFO, &mut shared_secret)
        .map_err(|e| CryptoError::Decryption(format!("HKDF expansion failed: {:?}", e)))?;

    // Zero out intermediate secrets
    ikm.zeroize();

    Ok(shared_secret)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_hybrid_keypair_generation() {
        let keypair = HybridKeyPair::generate();
        
        // Verify sizes
        assert_eq!(keypair.public_key().to_bytes().len(), HYBRID_PUBLIC_KEY_SIZE);
        assert_eq!(keypair.secret_key().to_bytes().len(), HYBRID_SECRET_KEY_SIZE);
    }
    
    #[test]
    fn test_hybrid_encapsulation_decapsulation() {
        // Generate recipient keypair
        let recipient = HybridKeyPair::generate();
        
        // Sender encapsulates
        let (encapsulated, sender_shared) = encapsulate(recipient.public_key()).unwrap();
        
        // Recipient decapsulates
        let recipient_shared = decapsulate(&encapsulated, recipient.secret_key()).unwrap();
        
        // Shared secrets must match
        assert_eq!(sender_shared, recipient_shared);
    }
    
    #[test]
    fn test_encapsulated_key_size() {
        let recipient = HybridKeyPair::generate();
        let (encapsulated, _) = encapsulate(recipient.public_key()).unwrap();
        
        assert_eq!(encapsulated.to_bytes().len(), HYBRID_ENCAPSULATED_KEY_SIZE);
        // 32 (X25519) + 1088 (ML-KEM-768) = 1120 bytes
        assert_eq!(HYBRID_ENCAPSULATED_KEY_SIZE, 32 + 1088);
    }
    
    #[test]
    fn test_public_key_serialization() {
        let keypair = HybridKeyPair::generate();
        let bytes = keypair.public_key().to_bytes();
        let restored = HybridPublicKey::from_bytes(&bytes).unwrap();
        
        assert_eq!(keypair.public_key().x25519, restored.x25519);
        assert_eq!(keypair.public_key().mlkem, restored.mlkem);
    }
    
    #[test]
    fn test_secret_key_serialization() {
        let keypair = HybridKeyPair::generate();
        let bytes = keypair.secret_key().to_bytes();
        let restored = HybridSecretKey::from_bytes(&bytes).unwrap();
        
        // Verify by checking derived public keys match
        let original_public = keypair.public_key();
        let restored_public = restored.public_key();
        
        assert_eq!(original_public.x25519, restored_public.x25519);
    }
    
    #[test]
    fn test_base64_roundtrip() {
        let keypair = HybridKeyPair::generate();
        
        // Public key
        let b64 = keypair.public_key().to_base64();
        let restored = HybridPublicKey::from_base64(&b64).unwrap();
        assert_eq!(keypair.public_key().to_bytes(), restored.to_bytes());
        
        // Encapsulated key
        let (enc, _) = encapsulate(keypair.public_key()).unwrap();
        let enc_b64 = enc.to_base64();
        let enc_restored = HybridEncapsulatedKey::from_base64(&enc_b64).unwrap();
        assert_eq!(enc.to_bytes(), enc_restored.to_bytes());
    }
    
    #[test]
    fn test_wrong_key_fails() {
        let recipient1 = HybridKeyPair::generate();
        let recipient2 = HybridKeyPair::generate();
        
        // Encapsulate for recipient1
        let (encapsulated, sender_shared) = encapsulate(recipient1.public_key()).unwrap();
        
        // Decapsulate with recipient2's key - should produce different shared secret
        // (ML-KEM will fail or produce wrong result)
        let result = decapsulate(&encapsulated, recipient2.secret_key());
        
        // Either it fails or produces a different secret
        match result {
            Ok(wrong_shared) => assert_ne!(sender_shared, wrong_shared),
            Err(_) => {} // Expected for ML-KEM mismatch
        }
    }
    
    #[test]
    fn test_multiple_encapsulations_different() {
        let recipient = HybridKeyPair::generate();
        
        // Two encapsulations should produce different encapsulated keys and secrets
        let (enc1, shared1) = encapsulate(recipient.public_key()).unwrap();
        let (enc2, shared2) = encapsulate(recipient.public_key()).unwrap();
        
        // Encapsulated keys should differ (ephemeral randomness)
        assert_ne!(enc1.to_bytes(), enc2.to_bytes());
        
        // Shared secrets should differ
        assert_ne!(shared1, shared2);
        
        // But both should decapsulate correctly
        let dec1 = decapsulate(&enc1, recipient.secret_key()).unwrap();
        let dec2 = decapsulate(&enc2, recipient.secret_key()).unwrap();
        
        assert_eq!(shared1, dec1);
        assert_eq!(shared2, dec2);
    }
}
