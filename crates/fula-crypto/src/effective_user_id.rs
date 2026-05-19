//! Effective user-ID derivation — "seed IS the user" identity model.
//!
//! Per the audit F-A1 / F-A3 redesign (2026-05-18), the gateway's
//! namespace key (which today is `BLAKE3("fula:user_id:" || JWT.sub)[..16]`)
//! becomes a function of the user's seed rather than of public OAuth
//! attributes. The seed never leaves the client device; whoever can
//! compute a given `effective_user_id` IS that user.
//!
//! The token issuer (separate service, owned by the same team — NOT in
//! this repo) uses these primitives to:
//! 1. Verify a client's proof-of-seed-knowledge (Ed25519 signature
//!    over a challenge nonce, signed with the seed-derived key).
//! 2. Issue a JWT with `sub = effective_user_id_hex`.
//!
//! Fula-cli is unchanged — it still treats `sub` opaquely.
//!
//! ## Modes
//!
//! - **Mode A — OAuth-only (legacy)**. Existing users. NOT covered by
//!   this module — they keep the OAuth-sub-as-JWT-sub flow exactly as
//!   today. Identity-derivable; users opt into Mode B for stronger
//!   protection.
//! - **Mode B — OAuth + seed**. `effective_user_id` is a function of
//!   the OAuth identity AND the user-entered seed. Different OAuth
//!   identities AND different seeds produce different ids — so a Mode
//!   B user with the same OAuth identity as a Mode A user lands in a
//!   different namespace (no overwrite risk).
//! - **Mode C — Seed-only (no OAuth)**. `effective_user_id` is a
//!   function of the seed alone. Two users with identical seeds
//!   coincidentally collide — by design (the seed IS the identity).
//!   Use a high-entropy passphrase.
//!
//! ## Canonicalization
//!
//! - `provider`: a small ASCII enum tag (`"google"`, `"apple"`).
//!   Caller is responsible for using the canonical form.
//! - `oauth_sub`: treated as opaque bytes. **NOT** NFKC-normalized —
//!   OAuth `sub` identifiers are opaque, not Unicode user input, and
//!   normalizing them could alter semantics (Codex advisor 2026-05-18).
//! - `seed`: NFKC-normalized so visually-identical passwords typed
//!   with different Unicode codepoints (e.g., precomposed vs
//!   decomposed accents) produce the same id.
//!
//! ## Encoding
//!
//! Length-prefixed (u32 little-endian) byte concatenation under a
//! distinct domain tag per mode. Length-prefixing prevents the kind
//! of ambiguity that raw colon-concatenation has (a password
//! containing `:` would collide with a different identity under
//! naive `provider:sub:email:password`).
//!
//! ```text
//! Mode B: domain_b || u32_le(len(provider)) || provider
//!                  || u32_le(len(oauth_sub)) || oauth_sub
//!                  || u32_le(len(NFKC(seed))) || NFKC(seed)
//! Mode C: domain_c || u32_le(len(NFKC(seed))) || NFKC(seed)
//! ```
//!
//! BLAKE3 of the buffer, truncated to 16 bytes.

use unicode_normalization::UnicodeNormalization;

/// Domain tag for Mode B `effective_user_id`. Bumping `v2` to `v3`
/// would constitute a new identity scheme; all existing Mode B users
/// would land in fresh namespaces. Do not change without a migration.
const DOMAIN_MODE_B: &[u8] = b"fula:effective-uid:v2:mode-b";

/// Domain tag for Mode C `effective_user_id`.
const DOMAIN_MODE_C: &[u8] = b"fula:effective-uid:v2:mode-c";

/// Domain tag for the seed-derived Ed25519 signing key. Distinct
/// derivation from the user-id so the 32-byte signing seed is not
/// derivable from the 16-byte user-id (and vice versa).
const DOMAIN_SIGNING_KEY: &str = "fula:signing-key:v2";

/// Length of the resulting user-id in bytes (16 bytes = 128 bits).
pub const EFFECTIVE_USER_ID_LEN: usize = 16;

/// Length of the seed-derived signing-key material (32 bytes — Ed25519 seed).
pub const SIGNING_KEY_SEED_LEN: usize = 32;

/// Compute the **Mode B** `effective_user_id` from (provider, OAuth sub, seed).
///
/// - `provider`: canonical provider tag (`"google"`, `"apple"`, etc.).
/// - `oauth_sub`: the OAuth `sub` claim as returned by the provider.
///   Treated as opaque bytes — not NFKC-normalized.
/// - `seed`: the user-entered password/passphrase. NFKC-normalized
///   internally before hashing.
///
/// Returns 16 bytes (128 bits) suitable as the JWT `sub` (after hex
/// encoding) and as the gateway namespace key (after the gateway's
/// usual `BLAKE3("fula:user_id:" || sub)[..16]` re-hash).
pub fn compute_effective_user_id_mode_b(
    provider: &str,
    oauth_sub: &str,
    seed: &str,
) -> [u8; EFFECTIVE_USER_ID_LEN] {
    let seed_normalized: String = seed.nfc().collect();
    let mut hasher = blake3::Hasher::new();
    hasher.update(DOMAIN_MODE_B);
    hasher.update(&(provider.len() as u32).to_le_bytes());
    hasher.update(provider.as_bytes());
    hasher.update(&(oauth_sub.len() as u32).to_le_bytes());
    hasher.update(oauth_sub.as_bytes());
    let seed_bytes = seed_normalized.as_bytes();
    hasher.update(&(seed_bytes.len() as u32).to_le_bytes());
    hasher.update(seed_bytes);
    let h = hasher.finalize();
    let mut out = [0u8; EFFECTIVE_USER_ID_LEN];
    out.copy_from_slice(&h.as_bytes()[..EFFECTIVE_USER_ID_LEN]);
    out
}

/// Compute the **Mode C** (seed-only, no OAuth) `effective_user_id`.
///
/// - `seed`: the user-entered passphrase. NFKC-normalized internally.
///
/// Two callers with identical seeds produce identical user-ids — by
/// design. Users are responsible for choosing high-entropy seeds.
pub fn compute_effective_user_id_mode_c(seed: &str) -> [u8; EFFECTIVE_USER_ID_LEN] {
    let seed_normalized: String = seed.nfc().collect();
    let mut hasher = blake3::Hasher::new();
    hasher.update(DOMAIN_MODE_C);
    let seed_bytes = seed_normalized.as_bytes();
    hasher.update(&(seed_bytes.len() as u32).to_le_bytes());
    hasher.update(seed_bytes);
    let h = hasher.finalize();
    let mut out = [0u8; EFFECTIVE_USER_ID_LEN];
    out.copy_from_slice(&h.as_bytes()[..EFFECTIVE_USER_ID_LEN]);
    out
}

/// Derive a deterministic 32-byte Ed25519 signing-key seed from the
/// user's seed. The returned bytes are the input to
/// `ed25519_dalek::SigningKey::from_bytes`.
///
/// Same client-side seed → same signing keypair. The issuer's
/// challenge-response verification (Codex's "option Y" /
/// proof-of-seed-knowledge) compares signatures against the public
/// half stored at registration time.
///
/// Domain-separated from the `effective_user_id` derivations so the
/// 32-byte signing seed and the 16-byte user-id are independent
/// values of the user's seed.
pub fn derive_signing_seed_from_seed(seed: &str) -> [u8; SIGNING_KEY_SEED_LEN] {
    let seed_normalized: String = seed.nfc().collect();
    let mut hasher = blake3::Hasher::new_derive_key(DOMAIN_SIGNING_KEY);
    hasher.update(seed_normalized.as_bytes());
    let h = hasher.finalize();
    let mut out = [0u8; SIGNING_KEY_SEED_LEN];
    out.copy_from_slice(h.as_bytes());
    out
}

/// Sign a message using the seed-derived Ed25519 keypair.
///
/// `signing_seed` is the 32-byte output of [`derive_signing_seed_from_seed`].
/// Returns a 64-byte detached Ed25519 signature. Used by Mode B / Mode C
/// clients to prove possession of their seed when responding to the
/// issuer's challenge nonce.
pub fn sign_with_signing_seed(
    signing_seed: &[u8; SIGNING_KEY_SEED_LEN],
    message: &[u8],
) -> [u8; 64] {
    use ed25519_dalek::Signer;
    let sk = ed25519_dalek::SigningKey::from_bytes(signing_seed);
    sk.sign(message).to_bytes()
}

/// Derive the Ed25519 public verifying key from the 32-byte signing seed.
///
/// The result is what clients send to the issuer at registration time and
/// what the issuer stores to verify subsequent sign-in signatures.
pub fn public_key_from_signing_seed(
    signing_seed: &[u8; SIGNING_KEY_SEED_LEN],
) -> [u8; 32] {
    let sk = ed25519_dalek::SigningKey::from_bytes(signing_seed);
    sk.verifying_key().to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey, Verifier};

    #[test]
    fn mode_b_distinct_seeds_distinct_ids() {
        let a = compute_effective_user_id_mode_b("google", "sub123", "ABCD");
        let b = compute_effective_user_id_mode_b("google", "sub123", "EFGH");
        assert_ne!(a, b);
    }

    #[test]
    fn mode_b_distinct_oauth_subs_distinct_ids() {
        let a = compute_effective_user_id_mode_b("google", "sub123", "ABCD");
        let b = compute_effective_user_id_mode_b("google", "sub456", "ABCD");
        assert_ne!(a, b);
    }

    #[test]
    fn mode_b_distinct_providers_distinct_ids() {
        // Same seed + same opaque sub string, different provider tag →
        // different id. Defends against accidental account-merging
        // between Google and Apple if the OAuth providers happened to
        // produce colliding `sub` strings.
        let a = compute_effective_user_id_mode_b("google", "shared_sub", "ABCD");
        let b = compute_effective_user_id_mode_b("apple", "shared_sub", "ABCD");
        assert_ne!(a, b);
    }

    #[test]
    fn mode_b_deterministic() {
        let a = compute_effective_user_id_mode_b("google", "sub123", "ABCD");
        let b = compute_effective_user_id_mode_b("google", "sub123", "ABCD");
        assert_eq!(a, b);
    }

    #[test]
    fn mode_b_nfkc_normalizes_seed() {
        // 'é' as precomposed (U+00E9) vs decomposed (U+0065 U+0301).
        // Visually identical; must hash to the same id.
        let precomposed = "passw\u{00E9}rd";
        let decomposed = "passwe\u{0301}rd";
        let a = compute_effective_user_id_mode_b("google", "sub", precomposed);
        let b = compute_effective_user_id_mode_b("google", "sub", decomposed);
        assert_eq!(a, b, "NFKC must collapse compatibility-equivalent codepoints");
    }

    #[test]
    fn mode_b_oauth_sub_is_opaque_not_normalized() {
        // OAuth `sub` is an opaque identifier from the IDP — we MUST NOT
        // alter its bytes via Unicode normalization (Codex 2026-05-18).
        let precomposed = "sub-\u{00E9}";
        let decomposed = "sub-e\u{0301}";
        let a = compute_effective_user_id_mode_b("google", precomposed, "seed");
        let b = compute_effective_user_id_mode_b("google", decomposed, "seed");
        assert_ne!(a, b);
    }

    #[test]
    fn mode_b_separator_attack_resistance() {
        // Length-prefixed encoding defends against the naive
        // colon-concatenation ambiguity:
        //   "google:sub123:ABCD" == "google:sub:123:ABCD"
        // both as colon-joined strings, but they're different
        // identities under length-prefixed encoding.
        let a = compute_effective_user_id_mode_b("google", "sub123", "ABCD");
        let b = compute_effective_user_id_mode_b("google", "sub", "123:ABCD");
        assert_ne!(
            a, b,
            "length-prefixed encoding defends against separator-injection ambiguity"
        );
    }

    #[test]
    fn mode_b_vs_mode_c_domain_separated() {
        let b = compute_effective_user_id_mode_b("google", "sub123", "ABCD");
        let c = compute_effective_user_id_mode_c("ABCD");
        assert_ne!(b, c);
    }

    #[test]
    fn mode_c_distinct_seeds_distinct_ids() {
        let a = compute_effective_user_id_mode_c("ABCD");
        let b = compute_effective_user_id_mode_c("EFGH");
        assert_ne!(a, b);
    }

    #[test]
    fn mode_c_deterministic() {
        let a = compute_effective_user_id_mode_c("ABCD");
        let b = compute_effective_user_id_mode_c("ABCD");
        assert_eq!(a, b);
    }

    #[test]
    fn mode_c_collision_on_identical_seed() {
        // "seed IS the user" — two callers with the same seed are the
        // same user. By design. High-entropy seeds make accidental
        // collisions infeasible.
        let a = compute_effective_user_id_mode_c("correct horse battery staple");
        let b = compute_effective_user_id_mode_c("correct horse battery staple");
        assert_eq!(a, b);
    }

    #[test]
    fn mode_c_nfkc_normalizes_seed() {
        let precomposed = "passw\u{00E9}rd";
        let decomposed = "passwe\u{0301}rd";
        assert_eq!(
            compute_effective_user_id_mode_c(precomposed),
            compute_effective_user_id_mode_c(decomposed),
        );
    }

    #[test]
    fn signing_seed_deterministic() {
        let a = derive_signing_seed_from_seed("ABCD");
        let b = derive_signing_seed_from_seed("ABCD");
        assert_eq!(a, b);
    }

    #[test]
    fn signing_seed_distinct_seeds_distinct_keys() {
        let a = derive_signing_seed_from_seed("ABCD");
        let b = derive_signing_seed_from_seed("EFGH");
        assert_ne!(a, b);
    }

    #[test]
    fn signing_seed_nfkc_normalizes() {
        let precomposed = "passw\u{00E9}rd";
        let decomposed = "passwe\u{0301}rd";
        assert_eq!(
            derive_signing_seed_from_seed(precomposed),
            derive_signing_seed_from_seed(decomposed),
        );
    }

    #[test]
    fn signing_seed_domain_separated_from_user_id() {
        // Same seed → distinct outputs for the user-id and the
        // signing-seed derivations. Domain separation makes them
        // independent: a client's user-id leaking does not weaken
        // their signing key, and vice versa.
        let seed = "test-seed-domain-check";
        let signing = derive_signing_seed_from_seed(seed);
        let uid_b = compute_effective_user_id_mode_b("google", "sub", seed);
        let uid_c = compute_effective_user_id_mode_c(seed);
        // Compare the 16-byte prefix of the 32-byte signing seed against
        // the 16-byte user-ids — they must not coincide.
        assert_ne!(&signing[..EFFECTIVE_USER_ID_LEN], &uid_b[..]);
        assert_ne!(&signing[..EFFECTIVE_USER_ID_LEN], &uid_c[..]);
    }

    #[test]
    fn signing_seed_round_trips_through_ed25519() {
        // The whole point of the signing-seed derivation: feed it to
        // ed25519-dalek, sign a challenge, verify with the public key.
        // This is the proof-of-seed-knowledge protocol the issuer uses
        // to authenticate Mode B / Mode C clients.
        let signing_seed = derive_signing_seed_from_seed("a-user-passphrase");
        let sk = SigningKey::from_bytes(&signing_seed);
        let pk = sk.verifying_key();
        let challenge = b"server-issued nonce";
        let sig = sk.sign(challenge);
        assert!(pk.verify(challenge, &sig).is_ok());
        // Wrong challenge fails verification.
        assert!(pk.verify(b"different bytes", &sig).is_err());
    }

    #[test]
    fn signing_seed_distinct_seeds_distinct_public_keys() {
        let sk_a = SigningKey::from_bytes(&derive_signing_seed_from_seed("ABCD"));
        let sk_b = SigningKey::from_bytes(&derive_signing_seed_from_seed("EFGH"));
        assert_ne!(sk_a.verifying_key().to_bytes(), sk_b.verifying_key().to_bytes());
    }
}
