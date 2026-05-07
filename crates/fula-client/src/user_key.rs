//! Phase 3.3 — userKey derivation, available on every target.
//!
//! Two functions live here, and choosing the right one matters — getting
//! it wrong produces a silent cold-start failure (master publishes under
//! userKey A, SDK looks up userKey B, lookup misses, "user has not
//! written yet" error even though they have).
//!
//! ### `derive_user_key_from_jwt_sub` (PREFERRED — matches master exactly)
//!
//! Master's `crates/fula-cli/src/state.rs::hash_user_id` does:
//! ```text
//! BLAKE3.derive_key("fula:user_id:", claims.sub.as_bytes())[..16].hex()
//! ```
//! `claims.sub` is fed in as-is, no transformation. Whatever string the
//! JWT carries as `sub` IS the hash input. This function mirrors that
//! exactly. Apps that have access to the JWT sub at sign-in (which is
//! always — they just received the token) should call THIS one.
//!
//! For pre-migration-011 users, `claims.sub` is plaintext email.
//! For post-migration users, `claims.sub` is `sha256(email).hex()`.
//! Either way, hashing the sub directly matches master.
//!
//! ### `derive_user_key_from_email` (LEGACY — breaks for pre-migration users)
//!
//! Originally written assuming all users would be post-migration-011
//! (where `claims.sub == sha256(email).hex()`). That assumption is
//! WRONG for pre-migration users — their JWTs still carry plaintext
//! email as `sub`, and master's `hash_user_id(claims.sub)` therefore
//! produces a different value than the one this function returns.
//! Result: pre-migration users' cold-start lookups always miss.
//!
//! Kept for backward compatibility with apps that have already shipped
//! using it. Apps SHOULD migrate to `derive_user_key_from_jwt_sub`.
//!
//! **Algorithm (legacy, post-migration-only):**
//! ```text
//! email_lower = email.to_lowercase()
//! user_id_digest = sha256(email_lower.as_bytes())
//! user_id_hex = hex(user_id_digest)
//! user_key = hex( BLAKE3.derive_key("fula:user_id:", user_id_hex.as_bytes())[..16] )
//! ```
//!
//! Both functions are pure (sha2 + blake3 + hex), build cleanly on
//! wasm32, and are exposed through FRB and wasm-bindgen. Master and
//! SDK produce the same userKey when each side uses its correct input.

use sha2::{Digest, Sha256};

/// Compute the canonical fula `userKey` directly from a JWT `sub` claim.
///
/// **Use this for cold-start config whenever the app has access to the
/// JWT sub** — which it does at sign-in (the issued token carries it).
///
/// Mirrors master's `crates/fula-cli/src/state.rs::hash_user_id` byte-for-byte:
/// the input bytes go straight into `BLAKE3.derive_key` with no
/// transformation. Returns 32 hex chars (first 16 bytes of the digest).
///
/// Works correctly for BOTH pre-migration users (whose `sub` is plaintext
/// email) AND post-migration users (whose `sub` is `sha256(email).hex()`).
/// The caller passes the JWT sub through unchanged; this function does
/// not normalize, lowercase, or pre-hash.
///
/// Apps should cache the JWT sub at sign-in and pass it to this function
/// when (re-)configuring `Config::users_index_user_key`. The SDK never
/// persists or transmits the raw sub.
pub fn derive_user_key_from_jwt_sub(jwt_sub: &str) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"fula:user_id:");
    hasher.update(jwt_sub.as_bytes());
    hex::encode(&hasher.finalize().as_bytes()[..16])
}

/// **DEPRECATED — breaks for pre-migration-011 users.** Use
/// [`derive_user_key_from_jwt_sub`] instead and pass the JWT `sub` claim.
///
/// Computes the userKey from a plaintext email by first applying
/// `sha256(email.lowercase()).hex()` and then hashing that hex string
/// via `BLAKE3.derive_key("fula:user_id:", ...)`. Returns 32 hex chars.
///
/// This produces the correct userKey for users whose JWT `sub` is
/// `sha256(email).hex()` (post-migration-011) by accident — the SDK's
/// extra `sha256` step happens to match what master's auth chain
/// already did upstream. For users whose JWT `sub` is plaintext email
/// (pre-migration-011), the SDK applies `sha256` but master does not,
/// and the two derivations diverge.
///
/// Kept for source compatibility with apps that have already shipped
/// using it. Cold-start may fail for pre-migration users; switch to
/// [`derive_user_key_from_jwt_sub`] to fix.
pub fn derive_user_key_from_email(email: &str) -> String {
    let user_id_digest = Sha256::digest(email.to_lowercase().as_bytes());
    let user_id_hex = hex::encode(user_id_digest);
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"fula:user_id:");
    hasher.update(user_id_hex.as_bytes());
    hex::encode(&hasher.finalize().as_bytes()[..16])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pinned test vector reproducing the bug observed in production
    /// for pre-migration-011 user `ehsan@fx.land`. Master stored
    /// `4da2c0616b1d39660f9f94e145fbce4f` (BLAKE3 over the plaintext
    /// email), but the SDK was computing
    /// `d2df90894e237aa4ef50618e514e0e37` (BLAKE3 over sha256(email)).
    /// Cold-start lookup missed because of this mismatch.
    ///
    /// `derive_user_key_from_jwt_sub` with the plaintext email as the
    /// argument MUST produce the master-stored value.
    #[test]
    fn derive_user_key_from_jwt_sub_matches_master_for_plaintext_email_sub() {
        let key = derive_user_key_from_jwt_sub("ehsan@fx.land");
        assert_eq!(key, "4da2c0616b1d39660f9f94e145fbce4f");
    }

    /// For post-migration-011 users the JWT sub is `sha256(email).hex()`.
    /// Calling `derive_user_key_from_jwt_sub` with that sub must produce
    /// the SAME value as the legacy `derive_user_key_from_email(email)`,
    /// because `derive_user_key_from_email` does `sha256(email).hex()`
    /// internally before hashing — same input bytes flowing into the
    /// same `BLAKE3.derive_key("fula:user_id:", ...)` call.
    #[test]
    fn derive_user_key_from_jwt_sub_matches_legacy_for_sha256_email_sub() {
        let email = "ehsan@fx.land";
        let sha256_hex = hex::encode(Sha256::digest(email.to_lowercase().as_bytes()));
        let from_sub = derive_user_key_from_jwt_sub(&sha256_hex);
        let from_email_legacy = derive_user_key_from_email(email);
        assert_eq!(from_sub, from_email_legacy);
    }

    /// Pinned reference for the legacy function. Documents the value
    /// it returns for `ehsan@fx.land` so future refactors can't
    /// silently change the algorithm.
    #[test]
    fn derive_user_key_from_email_pinned_value() {
        assert_eq!(
            derive_user_key_from_email("ehsan@fx.land"),
            "d2df90894e237aa4ef50618e514e0e37"
        );
    }

    /// Empty input must not panic (defense-in-depth — the input
    /// shouldn't ever be empty in practice, but BLAKE3 must not be
    /// called in a way that aborts on edge inputs).
    #[test]
    fn derive_user_key_from_jwt_sub_empty_does_not_panic() {
        let key = derive_user_key_from_jwt_sub("");
        assert_eq!(key.len(), 32);  // still 32 hex chars (16 bytes)
    }
}
