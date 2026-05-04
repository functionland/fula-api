//! Phase 3.3 — userKey derivation, available on every target.
//!
//! `derive_user_key_from_email` was originally inlined in
//! `registry_resolver.rs`, but that module is gated to native via
//! `#![cfg(not(target_arch = "wasm32"))]` because it depends on
//! `reqwest`, `parking_lot`, and other crates that don't compile on
//! wasm. The userKey computation itself is pure: just `sha2` +
//! `blake3` + `hex` — all of which build cleanly on wasm32 (these
//! are already transitive deps of the wasm SDK build).
//!
//! Extracting the helper here lets the FRB and wasm-bindgen
//! bindings expose `derive_user_key_from_email` without having to
//! re-implement the algorithm. Master and SDK both produce the
//! same `userKey` for the same email, regardless of which target
//! the SDK was built for.
//!
//! **Algorithm (must stay in lockstep with master's `state.rs::hash_user_id`):**
//!
//! ```text
//! email_lower = email.to_lowercase()
//! user_id_digest = sha256(email_lower.as_bytes())
//! user_id_hex = hex(user_id_digest)
//! domain_separated = "fula:user_id:" || user_id_hex
//! user_key = hex( blake3(domain_separated)[..16] )
//! ```
//!
//! Drift here vs. master = silent cold-start failure (master
//! publishes under userKey A, SDK looks up userKey B). The
//! `derive_user_key_matches_master_state_rs_algorithm` test in
//! `registry_resolver.rs` reproduces master's algorithm step-by-step
//! and asserts equality.

use sha2::{Digest, Sha256};

/// Compute the canonical fula `userKey` for cold-start config from a
/// plaintext email. Returns 32 hex chars (16-byte BLAKE3 truncated digest).
///
/// Apps call this at sign-in time (the OAuth flow has plaintext email)
/// and pass the returned string into `Config::users_index_user_key`.
/// The SDK never persists or transmits the raw email.
pub fn derive_user_key_from_email(email: &str) -> String {
    let user_id_digest = Sha256::digest(email.to_lowercase().as_bytes());
    let user_id_hex = hex::encode(user_id_digest);
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"fula:user_id:");
    hasher.update(user_id_hex.as_bytes());
    hex::encode(&hasher.finalize().as_bytes()[..16])
}
