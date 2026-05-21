//! User-entry signing — `K_entry_seed` derivation + Ed25519 signatures for
//! the global users-index CBOR entries.
//!
//! Architecture context: master publishes a global users-index CBOR
//! (anchored to IPNS + on-chain) that maps user keys to per-user
//! bucketsIndex CIDs. For Mode B/C users this is upgraded to map to
//! `(cid, sequence, signature)` triples so master cannot forge a
//! user's entry — only the user's seed-derived Ed25519 key can produce
//! a verifying signature.
//!
//! Key derivation:
//! ```text
//! KEK_seed (32 bytes, existing — Argon2id over user's seed)
//!   └─ K_entry_seed = BLAKE3-derive("fula:user-entry-signing:v1", KEK_seed) (32 bytes)
//!         └─ Ed25519 keypair via `ed25519_dalek::SigningKey::from_bytes`
//! ```
//!
//! Domain-separated from `K_index` (the AEAD key for the bucketsIndex
//! body — see [`crate::user_buckets_index_aad`]) and from
//! `effective_user_id` / `signing_seed_from_seed`
//! (the issuer-challenge-response key in [`crate::effective_user_id`]).
//! These three derivation contexts are independent: leaking one does
//! not weaken the others.
//!
//! Signature payload:
//! ```text
//! payload = "fula:user-entry-sig:v1"
//!        || user_key_hex_bytes      (32 ASCII bytes — caller's hashed user identity)
//!        || cid_bytes               (the encrypted bucketsIndex CID as UTF-8 bytes)
//!        || sequence_u64_be         (monotonic per user)
//!        || envelope_v_u32_be       (encrypted-envelope version, currently 3)
//! ```
//!
//! Length-prefixing is intentionally NOT applied here because each
//! field has a fixed length or is uniquely terminable: the tag and
//! `user_key_hex_bytes` are constant-length, the `cid_bytes` is
//! followed by fixed-width `sequence_u64_be || envelope_v_u32_be`
//! which makes ambiguous parsing impossible (any forged splitting of
//! the buffer that re-interprets cid bytes as part of the trailing
//! ints would change the final 12 bytes and fail Ed25519 verification
//! anyway). Domain separation is via the leading ASCII tag.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

/// BLAKE3-derive context for the entry-signing seed. Bumping the
/// version tag forces all clients onto fresh keys — only do this
/// alongside a forced re-registration of every user's TOFU binding.
const DOMAIN_ENTRY_SIGNING: &str = "fula:user-entry-signing:v1";

/// Domain tag prefix for the signature payload. Bound into every
/// signed entry so a signature produced by these primitives cannot be
/// repurposed as a signature for a different protocol that happens to
/// reuse the same Ed25519 key.
pub const ENTRY_SIGNATURE_TAG: &[u8] = b"fula:user-entry-sig:v1";

/// Length of the entry-signing seed in bytes (Ed25519 seed = 32).
pub const ENTRY_SIGNING_SEED_LEN: usize = 32;

/// Length of an Ed25519 public key in bytes.
pub const ENTRY_PUBKEY_LEN: usize = 32;

/// Length of an Ed25519 detached signature in bytes.
pub const ENTRY_SIGNATURE_LEN: usize = 64;

/// Derive the 32-byte entry-signing seed from the user's `KEK_seed`.
///
/// `KEK_seed` is the existing per-user master KEK produced by the
/// Argon2id derivation in the Mode B/C sign-in flow (see
/// `auth_service.dart` in the FxFiles client). Domain-separated from
/// other sub-keys derived from the same `KEK_seed` (notably `K_index`
/// in [`crate::user_buckets_index_aad`]).
///
/// Deterministic: the same `kek_seed` always produces the same
/// signing seed, so a client re-deriving from the user's master seed
/// on a fresh device gets the same Ed25519 keypair without any
/// persisted state.
pub fn derive_entry_signing_seed(kek_seed: &[u8; 32]) -> [u8; ENTRY_SIGNING_SEED_LEN] {
    let mut hasher = blake3::Hasher::new_derive_key(DOMAIN_ENTRY_SIGNING);
    hasher.update(kek_seed);
    let h = hasher.finalize();
    let mut out = [0u8; ENTRY_SIGNING_SEED_LEN];
    out.copy_from_slice(h.as_bytes());
    out
}

/// Compute the Ed25519 public verifying key from a `KEK_seed`.
///
/// Convenience wrapper combining [`derive_entry_signing_seed`] and
/// `ed25519_dalek::SigningKey::verifying_key`. The returned 32-byte
/// pubkey is what master records under TOFU binding on first publish.
pub fn entry_pubkey_from_kek(kek_seed: &[u8; 32]) -> [u8; ENTRY_PUBKEY_LEN] {
    let signing_seed = derive_entry_signing_seed(kek_seed);
    let sk = SigningKey::from_bytes(&signing_seed);
    sk.verifying_key().to_bytes()
}

/// Build the byte buffer that is fed to Ed25519 sign/verify for a
/// users-index entry.
///
/// `user_key_hex` is the 32-character ASCII hex form of the caller's
/// `hashed_user_id` (the BLAKE3-derived user key the gateway uses for
/// namespace routing). Callers MUST pass it lowercase (canonical).
///
/// `cid` is the dag-cbor base32 string of the encrypted bucketsIndex
/// envelope this entry points at (e.g. `"bafyrei..."`).
///
/// `sequence` is the user's monotonic per-entry counter.
///
/// `envelope_version` is the encrypted-envelope format version
/// (currently `3`; see [`crate::user_buckets_index_aad`]).
pub fn entry_signature_payload(
    user_key_hex: &str,
    cid: &str,
    sequence: u64,
    envelope_version: u32,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(
        ENTRY_SIGNATURE_TAG.len() + user_key_hex.len() + cid.len() + 8 + 4,
    );
    buf.extend_from_slice(ENTRY_SIGNATURE_TAG);
    buf.extend_from_slice(user_key_hex.as_bytes());
    buf.extend_from_slice(cid.as_bytes());
    buf.extend_from_slice(&sequence.to_be_bytes());
    buf.extend_from_slice(&envelope_version.to_be_bytes());
    buf
}

/// Sign an entry. Returns a 64-byte detached Ed25519 signature.
///
/// `kek_seed` is the user's master KEK — used here ONLY to derive
/// the entry-signing key; not transmitted anywhere.
pub fn sign_entry(
    kek_seed: &[u8; 32],
    user_key_hex: &str,
    cid: &str,
    sequence: u64,
    envelope_version: u32,
) -> [u8; ENTRY_SIGNATURE_LEN] {
    let signing_seed = derive_entry_signing_seed(kek_seed);
    let sk = SigningKey::from_bytes(&signing_seed);
    let payload =
        entry_signature_payload(user_key_hex, cid, sequence, envelope_version);
    sk.sign(&payload).to_bytes()
}

/// Verify an entry signature against a published 32-byte pubkey.
///
/// Returns `true` if the signature is valid for the given fields under
/// the supplied pubkey. Used both client-side on cold-start
/// (verifying the user's own entry against the re-derived pubkey) and
/// server-side at submit/publish time (defense in depth — the
/// per-user TOFU-bound pubkey must match the signing key).
pub fn verify_entry_signature(
    pubkey: &[u8; ENTRY_PUBKEY_LEN],
    user_key_hex: &str,
    cid: &str,
    sequence: u64,
    envelope_version: u32,
    signature: &[u8; ENTRY_SIGNATURE_LEN],
) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(pubkey) else {
        return false;
    };
    let Ok(sig) = Signature::from_slice(signature) else {
        return false;
    };
    let payload =
        entry_signature_payload(user_key_hex, cid, sequence, envelope_version);
    vk.verify(&payload, &sig).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEK_A: [u8; 32] = [0xA5; 32];
    const KEK_B: [u8; 32] = [0xB7; 32];

    #[test]
    fn entry_signing_seed_deterministic() {
        let a = derive_entry_signing_seed(&KEK_A);
        let b = derive_entry_signing_seed(&KEK_A);
        assert_eq!(a, b, "same KEK must produce the same signing seed");
    }

    #[test]
    fn entry_signing_seed_distinct_keks_distinct_seeds() {
        let a = derive_entry_signing_seed(&KEK_A);
        let b = derive_entry_signing_seed(&KEK_B);
        assert_ne!(a, b);
    }

    #[test]
    fn entry_signing_domain_separated_from_kek() {
        // The signing seed must not equal the input KEK_seed — it should
        // be a one-way derivation. If they were equal, leaking the
        // signing seed (e.g. via secure-enclave bypass) would reveal the
        // master KEK and vice versa.
        let signing_seed = derive_entry_signing_seed(&KEK_A);
        assert_ne!(signing_seed, KEK_A);
    }

    #[test]
    fn entry_signing_domain_separated_from_index_key() {
        // K_entry_seed and K_index both derive from KEK_seed under
        // different domain tags — they must be independent values.
        use crate::user_buckets_index_aad::derive_index_key;
        let signing = derive_entry_signing_seed(&KEK_A);
        let index = derive_index_key(&KEK_A);
        assert_ne!(signing, index);
    }

    #[test]
    fn entry_pubkey_deterministic() {
        let a = entry_pubkey_from_kek(&KEK_A);
        let b = entry_pubkey_from_kek(&KEK_A);
        assert_eq!(a, b);
    }

    #[test]
    fn entry_pubkey_distinct_keks_distinct_pubkeys() {
        let a = entry_pubkey_from_kek(&KEK_A);
        let b = entry_pubkey_from_kek(&KEK_B);
        assert_ne!(a, b);
    }

    #[test]
    fn signature_round_trip() {
        let pubkey = entry_pubkey_from_kek(&KEK_A);
        let sig = sign_entry(
            &KEK_A,
            "0123456789abcdef0123456789abcdef",
            "bafyreidaxrfgo636gfjsykzuok3gh5b633fgilz3nb2g6xucl4eugtdsoa",
            42,
            3,
        );
        assert!(verify_entry_signature(
            &pubkey,
            "0123456789abcdef0123456789abcdef",
            "bafyreidaxrfgo636gfjsykzuok3gh5b633fgilz3nb2g6xucl4eugtdsoa",
            42,
            3,
            &sig,
        ));
    }

    #[test]
    fn signature_recovers_from_seed_on_fresh_device() {
        // The recovery guarantee: clear app state, re-derive from seed
        // (KEK_A here), the same entry signature verifies — proving
        // continuity of identity across reinstalls.
        let sig = sign_entry(
            &KEK_A,
            "0123456789abcdef0123456789abcdef",
            "bafyreidonv3avlfjknoqnsufrjzvkgc3r6zvrmrsuj2f5w3fojbxoycypq",
            7,
            3,
        );
        // Simulate a fresh device that has only KEK_A (re-derived from
        // the user's seed) and the published entry. The pubkey is
        // re-derivable; the signature verifies.
        let recovered_pubkey = entry_pubkey_from_kek(&KEK_A);
        assert!(verify_entry_signature(
            &recovered_pubkey,
            "0123456789abcdef0123456789abcdef",
            "bafyreidonv3avlfjknoqnsufrjzvkgc3r6zvrmrsuj2f5w3fojbxoycypq",
            7,
            3,
            &sig,
        ));
    }

    #[test]
    fn signature_rejects_tampered_cid() {
        let pubkey = entry_pubkey_from_kek(&KEK_A);
        let sig = sign_entry(
            &KEK_A,
            "0123456789abcdef0123456789abcdef",
            "bafyreidaxrfgo636gfjsykzuok3gh5b633fgilz3nb2g6xucl4eugtdsoa",
            42,
            3,
        );
        // Master tries to substitute Alice's CID with Eve's CID under
        // Alice's user_key + signature — signature verification must
        // fail.
        assert!(!verify_entry_signature(
            &pubkey,
            "0123456789abcdef0123456789abcdef",
            "bafyreif2j2alicedoesnothaveaccesstothiscidwhichshouldfailaa",
            42,
            3,
            &sig,
        ));
    }

    #[test]
    fn signature_rejects_tampered_user_key() {
        let pubkey = entry_pubkey_from_kek(&KEK_A);
        let sig = sign_entry(
            &KEK_A,
            "0123456789abcdef0123456789abcdef",
            "bafyreidaxrfgo636gfjsykzuok3gh5b633fgilz3nb2g6xucl4eugtdsoa",
            42,
            3,
        );
        // Master tries to move Alice's signature under Bob's user_key
        // slot in the global CBOR — must fail.
        assert!(!verify_entry_signature(
            &pubkey,
            "fedcba9876543210fedcba9876543210",
            "bafyreidaxrfgo636gfjsykzuok3gh5b633fgilz3nb2g6xucl4eugtdsoa",
            42,
            3,
            &sig,
        ));
    }

    #[test]
    fn signature_rejects_tampered_sequence() {
        let pubkey = entry_pubkey_from_kek(&KEK_A);
        let sig = sign_entry(
            &KEK_A,
            "0123456789abcdef0123456789abcdef",
            "bafyreidaxrfgo636gfjsykzuok3gh5b633fgilz3nb2g6xucl4eugtdsoa",
            42,
            3,
        );
        // Replay-with-modified-sequence — defense against an attacker
        // who recorded a valid signed entry and wants to re-present it
        // at a different sequence (e.g. inflate to win a race).
        assert!(!verify_entry_signature(
            &pubkey,
            "0123456789abcdef0123456789abcdef",
            "bafyreidaxrfgo636gfjsykzuok3gh5b633fgilz3nb2g6xucl4eugtdsoa",
            43,
            3,
            &sig,
        ));
    }

    #[test]
    fn signature_rejects_tampered_envelope_version() {
        let pubkey = entry_pubkey_from_kek(&KEK_A);
        let sig = sign_entry(
            &KEK_A,
            "0123456789abcdef0123456789abcdef",
            "bafyreidaxrfgo636gfjsykzuok3gh5b633fgilz3nb2g6xucl4eugtdsoa",
            42,
            3,
        );
        assert!(!verify_entry_signature(
            &pubkey,
            "0123456789abcdef0123456789abcdef",
            "bafyreidaxrfgo636gfjsykzuok3gh5b633fgilz3nb2g6xucl4eugtdsoa",
            42,
            4,
            &sig,
        ));
    }

    #[test]
    fn signature_rejects_wrong_pubkey() {
        let sig = sign_entry(
            &KEK_A,
            "0123456789abcdef0123456789abcdef",
            "bafyreidaxrfgo636gfjsykzuok3gh5b633fgilz3nb2g6xucl4eugtdsoa",
            42,
            3,
        );
        // Different user (KEK_B) cannot impersonate KEK_A. This is the
        // TOFU-binding's load-bearing property: master records KEK_A's
        // pubkey on first publish; signatures from KEK_B's keypair fail
        // verification against KEK_A's stored pubkey.
        let other_pubkey = entry_pubkey_from_kek(&KEK_B);
        assert!(!verify_entry_signature(
            &other_pubkey,
            "0123456789abcdef0123456789abcdef",
            "bafyreidaxrfgo636gfjsykzuok3gh5b633fgilz3nb2g6xucl4eugtdsoa",
            42,
            3,
            &sig,
        ));
    }

    #[test]
    fn signature_rejects_malformed_pubkey() {
        let sig = [0u8; ENTRY_SIGNATURE_LEN];
        // Non-curve point pubkey must be rejected by the underlying
        // library and surface as verification failure, not a panic.
        let mut malformed = [0u8; ENTRY_PUBKEY_LEN];
        malformed[0] = 0xFF;
        // Many random 32-byte arrays land off-curve; if this one happens
        // to be on-curve, verify_entry_signature still safely returns
        // false because the signature is all-zeros.
        let result = verify_entry_signature(
            &malformed,
            "0123456789abcdef0123456789abcdef",
            "bafyrei…",
            0,
            3,
            &sig,
        );
        assert!(!result);
    }

    #[test]
    fn payload_is_tag_prefixed() {
        let payload = entry_signature_payload(
            "0123456789abcdef0123456789abcdef",
            "bafyrei…cid",
            1,
            3,
        );
        assert!(payload.starts_with(ENTRY_SIGNATURE_TAG));
    }

    #[test]
    fn payload_ends_with_be_encoded_ints() {
        let seq: u64 = 0x0102030405060708;
        let env_v: u32 = 0x0A0B0C0D;
        let payload = entry_signature_payload("uk", "cid", seq, env_v);
        let len = payload.len();
        // Last 4 bytes = envelope version big-endian.
        assert_eq!(&payload[len - 4..], &env_v.to_be_bytes());
        // Bytes 12..4 from the end = sequence big-endian.
        assert_eq!(&payload[len - 12..len - 4], &seq.to_be_bytes());
    }
}
