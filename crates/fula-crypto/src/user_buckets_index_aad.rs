//! Encrypted bucketsIndex envelope — AEAD key derivation + AAD builder.
//!
//! The per-user `UserBucketsIndex` CBOR is encrypted as an envelope:
//!
//! ```text
//! { v: 3, nonce: bytes(12), ciphertext: AES-256-GCM(plaintext, K_index, AAD) }
//! ```
//!
//! where `K_index` is derived from the user's `KEK_seed` and `AAD` is
//! built by [`build_aad`] below.
//!
//! AAD construction:
//! ```text
//! AAD = "fula:user-buckets-index:v1"
//!    || user_key_hex_bytes         (32 ASCII bytes — caller's hashed user identity)
//!    || sequence_u64_be            (matches the signed-entry sequence)
//!    || envelope_v_u32_be          (envelope format version; currently 3)
//! ```
//!
//! Properties this AAD construction defends against:
//!
//! 1. **Cross-user blob substitution**. Master cannot take Alice's
//!    encrypted body and slot it under Bob's `users_enc[user_key]`
//!    entry: the AAD includes `user_key_hex_bytes`, so Bob's client
//!    decrypts with Bob's user_key, the AAD mismatch fails AEAD
//!    verification, and the bytes are rejected.
//!
//! 2. **Stale replay**. Master cannot serve an old encrypted body
//!    paired with a current sequence: the AAD's `sequence` is fixed
//!    by the producer and bound to the published entry; mismatch ⇒
//!    decryption fails.
//!
//! 3. **Format-version confusion**. Future envelope versions are
//!    domain-separated; a v3 reader cannot accidentally accept a v4
//!    body or vice versa.
//!
//! The lengths of `user_key_hex_bytes`, `sequence_u64_be`, and
//! `envelope_v_u32_be` are fixed (32, 8, and 4 bytes respectively),
//! so the AAD has unambiguous structure without explicit length
//! prefixes.

/// BLAKE3-derive context for the bucketsIndex AEAD key.
const DOMAIN_INDEX_KEY: &str = "fula:user-buckets-index:v1";

/// AAD tag prefix bound into every AEAD operation on the envelope.
/// Bumping the version tag forces all clients to re-encrypt and is
/// only used if the encryption format itself changes.
pub const AAD_TAG: &[u8] = b"fula:user-buckets-index:v1";

/// Length of the AEAD key in bytes (AES-256-GCM).
pub const INDEX_KEY_LEN: usize = 32;

/// Current encrypted-envelope format version. The plaintext payload
/// inside the envelope is independently versioned ([`PAYLOAD_VERSION`]).
pub const ENVELOPE_VERSION: u32 = 3;

/// Current plaintext-payload format version (the CBOR inside the
/// ciphertext). Versioned separately from the envelope so the
/// encryption parameters and the schema of what's encrypted can
/// evolve independently.
pub const PAYLOAD_VERSION: u32 = 1;

/// AEAD nonce length (96-bit, AES-GCM standard).
pub const NONCE_LEN: usize = 12;

/// Expected length of `user_key_hex` (the canonical 16-byte
/// `hashed_user_id` rendered as 32 lowercase hex characters).
pub const USER_KEY_HEX_LEN: usize = 32;

/// Derive the 32-byte AEAD key `K_index` from the user's `KEK_seed`.
///
/// Domain-separated from the entry-signing key derivation in
/// [`crate::user_entry`]. Same `kek_seed` → same `K_index`,
/// deterministically — clients on a fresh device re-derive identical
/// keys from the user's seed without needing any persisted state.
pub fn derive_index_key(kek_seed: &[u8; 32]) -> [u8; INDEX_KEY_LEN] {
    let mut hasher = blake3::Hasher::new_derive_key(DOMAIN_INDEX_KEY);
    hasher.update(kek_seed);
    let h = hasher.finalize();
    let mut out = [0u8; INDEX_KEY_LEN];
    out.copy_from_slice(h.as_bytes());
    out
}

/// Build the AAD bytes that bind a ciphertext to its (user_key,
/// sequence, envelope_version) triple.
///
/// `user_key_hex` MUST be exactly [`USER_KEY_HEX_LEN`] characters of
/// lowercase ASCII hex. Caller validates upstream; this function does
/// not panic on misuse but produces an AAD that legitimate readers
/// will fail to match (defense against accidental misuse).
pub fn build_aad(user_key_hex: &str, sequence: u64, envelope_version: u32) -> Vec<u8> {
    let mut buf = Vec::with_capacity(AAD_TAG.len() + user_key_hex.len() + 8 + 4);
    buf.extend_from_slice(AAD_TAG);
    buf.extend_from_slice(user_key_hex.as_bytes());
    buf.extend_from_slice(&sequence.to_be_bytes());
    buf.extend_from_slice(&envelope_version.to_be_bytes());
    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::symmetric::{Aead, AeadCipher, Nonce};

    const KEK_A: [u8; 32] = [0xA5; 32];
    const KEK_B: [u8; 32] = [0xB7; 32];
    const USER_KEY_A: &str = "0123456789abcdef0123456789abcdef";
    const USER_KEY_B: &str = "fedcba9876543210fedcba9876543210";

    #[test]
    fn index_key_deterministic() {
        let a = derive_index_key(&KEK_A);
        let b = derive_index_key(&KEK_A);
        assert_eq!(a, b);
    }

    #[test]
    fn index_key_distinct_keks_distinct_keys() {
        let a = derive_index_key(&KEK_A);
        let b = derive_index_key(&KEK_B);
        assert_ne!(a, b);
    }

    #[test]
    fn index_key_domain_separated_from_kek() {
        let k = derive_index_key(&KEK_A);
        assert_ne!(k, KEK_A);
    }

    #[test]
    fn aad_includes_user_key() {
        let a = build_aad(USER_KEY_A, 42, ENVELOPE_VERSION);
        let b = build_aad(USER_KEY_B, 42, ENVELOPE_VERSION);
        assert_ne!(a, b);
    }

    #[test]
    fn aad_includes_sequence() {
        let a = build_aad(USER_KEY_A, 42, ENVELOPE_VERSION);
        let b = build_aad(USER_KEY_A, 43, ENVELOPE_VERSION);
        assert_ne!(a, b);
    }

    #[test]
    fn aad_includes_envelope_version() {
        let a = build_aad(USER_KEY_A, 42, 3);
        let b = build_aad(USER_KEY_A, 42, 4);
        assert_ne!(a, b);
    }

    #[test]
    fn aad_starts_with_tag() {
        let aad = build_aad(USER_KEY_A, 42, ENVELOPE_VERSION);
        assert!(aad.starts_with(AAD_TAG));
    }

    #[test]
    fn aad_length_is_predictable() {
        let aad = build_aad(USER_KEY_A, 42, ENVELOPE_VERSION);
        // Tag (26 ASCII bytes) + 32 hex user_key + 8 seq + 4 envelope_v = 70
        assert_eq!(aad.len(), AAD_TAG.len() + USER_KEY_HEX_LEN + 8 + 4);
    }

    /// End-to-end: derive K_index, AEAD-encrypt a payload with our AAD,
    /// decrypt, recover. This is the path the client SDK and (mirror)
    /// the server's verifier will exercise.
    #[test]
    fn aead_round_trip_with_derived_key() {
        let k = derive_index_key(&KEK_A);
        let aead = Aead::new(&crate::keys::DekKey::from_bytes(&k).unwrap(), AeadCipher::Aes256Gcm);
        let nonce = Nonce::generate();
        let aad = build_aad(USER_KEY_A, 7, ENVELOPE_VERSION);
        let plaintext = b"plaintext bucketsIndex CBOR bytes go here";
        let ct = aead.encrypt_with_aad(&nonce, plaintext, &aad).unwrap();
        let pt = aead.decrypt_with_aad(&nonce, &ct, &aad).unwrap();
        assert_eq!(&pt, plaintext);
    }

    /// AAD-binding load-bearing test: cross-user substitution must fail.
    #[test]
    fn aead_rejects_mismatched_user_key() {
        let k = derive_index_key(&KEK_A);
        let aead = Aead::new(&crate::keys::DekKey::from_bytes(&k).unwrap(), AeadCipher::Aes256Gcm);
        let nonce = Nonce::generate();
        let aad_alice = build_aad(USER_KEY_A, 7, ENVELOPE_VERSION);
        let aad_bob = build_aad(USER_KEY_B, 7, ENVELOPE_VERSION);
        let ct = aead.encrypt_with_aad(&nonce, b"alice's secret", &aad_alice).unwrap();
        // Try to "decrypt" as if this were Bob's blob — must fail.
        assert!(aead.decrypt_with_aad(&nonce, &ct, &aad_bob).is_err());
    }

    #[test]
    fn aead_rejects_mismatched_sequence() {
        let k = derive_index_key(&KEK_A);
        let aead = Aead::new(&crate::keys::DekKey::from_bytes(&k).unwrap(), AeadCipher::Aes256Gcm);
        let nonce = Nonce::generate();
        let aad_seq7 = build_aad(USER_KEY_A, 7, ENVELOPE_VERSION);
        let aad_seq8 = build_aad(USER_KEY_A, 8, ENVELOPE_VERSION);
        let ct = aead.encrypt_with_aad(&nonce, b"seq 7 payload", &aad_seq7).unwrap();
        assert!(aead.decrypt_with_aad(&nonce, &ct, &aad_seq8).is_err());
    }

    #[test]
    fn aead_rejects_mismatched_envelope_version() {
        let k = derive_index_key(&KEK_A);
        let aead = Aead::new(&crate::keys::DekKey::from_bytes(&k).unwrap(), AeadCipher::Aes256Gcm);
        let nonce = Nonce::generate();
        let aad_v3 = build_aad(USER_KEY_A, 7, 3);
        let aad_v4 = build_aad(USER_KEY_A, 7, 4);
        let ct = aead.encrypt_with_aad(&nonce, b"payload", &aad_v3).unwrap();
        assert!(aead.decrypt_with_aad(&nonce, &ct, &aad_v4).is_err());
    }

    #[test]
    fn aead_rejects_wrong_kek() {
        // Defense in depth: even if AAD matches, a different KEK
        // produces a different K_index and decryption fails.
        let k_a = derive_index_key(&KEK_A);
        let k_b = derive_index_key(&KEK_B);
        let aead_a = Aead::new(&crate::keys::DekKey::from_bytes(&k_a).unwrap(), AeadCipher::Aes256Gcm);
        let aead_b = Aead::new(&crate::keys::DekKey::from_bytes(&k_b).unwrap(), AeadCipher::Aes256Gcm);
        let nonce = Nonce::generate();
        let aad = build_aad(USER_KEY_A, 7, ENVELOPE_VERSION);
        let ct = aead_a.encrypt_with_aad(&nonce, b"alice's secret", &aad).unwrap();
        assert!(aead_b.decrypt_with_aad(&nonce, &ct, &aad).is_err());
    }

    /// Recovery: clear app data, re-derive from seed (= KEK_A), the
    /// same K_index decrypts the published envelope. This is the
    /// load-bearing recovery property — losing local state never
    /// locks the user out as long as they remember their seed.
    #[test]
    fn aead_recovers_on_fresh_device_from_same_kek() {
        let k_original = derive_index_key(&KEK_A);
        let aead_original = Aead::new(&crate::keys::DekKey::from_bytes(&k_original).unwrap(), AeadCipher::Aes256Gcm);
        let nonce = Nonce::generate();
        let aad = build_aad(USER_KEY_A, 100, ENVELOPE_VERSION);
        let ct = aead_original.encrypt_with_aad(&nonce, b"existing data", &aad).unwrap();

        // Fresh device: only has KEK_A (re-derived from the user's
        // seed) and the published nonce/ciphertext/AAD. Re-derives
        // K_index identically.
        let k_recovered = derive_index_key(&KEK_A);
        let aead_recovered = Aead::new(&crate::keys::DekKey::from_bytes(&k_recovered).unwrap(), AeadCipher::Aes256Gcm);
        let pt = aead_recovered.decrypt_with_aad(&nonce, &ct, &aad).unwrap();
        assert_eq!(&pt, b"existing data");
    }
}
