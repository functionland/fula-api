//! # fula-mcp
//!
//! MCP (Model Context Protocol) server crate for the Fula decentralized
//! storage system.
//!
//! ## Phase 1 status: round-trip spike (NO MCP protocol yet)
//!
//! This crate is greenfield. Phase 1's only job is to **prove** that the
//! existing [`fula_crypto`] and [`fula_client`] crates can be reused to do a
//! full **encrypt → chunked-upload → download → decrypt** round-trip, writing
//! to the gateway in the same on-the-wire format the FxFiles app uses and
//! reading it back byte-identically with the app-derived Mode A secret. There
//! is no MCP transport, no tool dispatch, and no server loop in this phase —
//! only this thin library plus the round-trip tests under `tests/`.
//!
//! Scope note: the tests here are *same-client* round-trips (this code both
//! writes and reads). They validate the reuse and the live-gateway format path;
//! they do not re-assert cross-compatibility with the Flutter client, which the
//! workspace already covers in `tests/cross_platform_encryption_test.rs`.
//!
//! What lives here so far:
//! - [`derive_mode_a_secret`]: the Mode A (OAuth-derived) key-derivation
//!   helper, byte-for-byte what FxFiles' `auth_service.dart` does. Every later
//!   phase that needs to act as a user re-derives the same secret, so it lives
//!   in the library rather than being duplicated per test.
//! - [`primitives`]: a curated re-export of the `fula_crypto` / `fula_client`
//!   types the round-trip exercises (and that subsequent phases build on), so
//!   downstream code has one import surface.
//!
//! Subsequent phases will add the MCP protocol layer and forest-write
//! operations on top of this foundation.

use thiserror::Error;

pub mod capability;

/// File categorization + native-bucket routing, a faithful port of FxFiles'
/// `ShelfClassifier` + the content-bucket map (P4).
pub mod category;

/// The AI's scoped, encrypted WRITE operation: `store_file` (P5). Writes a file
/// into the AI's own encrypted workspace and mints an owner-readable share
/// token for it. See [`store::store_file`].
pub mod store;

/// The AI's scoped, decrypting READ operation: `read_file` (P6). The home of the
/// default-deny read guarantee — reads ONLY the AI's own workspace files (`ai/`
/// scope) or files the owner explicitly granted via a share token, rejecting
/// anything else before any network I/O. See [`read::read_file`].
pub mod read;

/// The AI's scoped ENUMERATION operations: `list_files` + `search` (P7).
/// Enumerates ONLY the AI's own `ai/` workspace forest — confined by the P3
/// segment-boundary geometry so the user's real buckets can never leak — with
/// optional category / sub-prefix narrowing and filename search. See
/// [`list::list_files`] and [`list::search`].
pub mod list;

/// The AI's TAG operations: `tag_file` + `list_tags` (P8). Writes the AI's tags
/// into its OWN workspace as a [`TagCloudMetadata`](tags::TagCloudMetadata)
/// document whose JSON byte-shape is identical to FxFiles' native tag format, so
/// FxFiles can adopt them with a straight additive-by-id merge. The document is
/// NOT the user's master-key-encrypted `tag-metadata-v8` doc — it lives under the
/// `ai/` scope in the workspace bucket (encrypted with the workspace secret). See
/// [`tags::tag_file`] and [`tags::list_tags`].
pub mod tags;

/// Re-exports of the underlying crypto + client types this crate builds on.
///
/// Phase 1 deliberately reuses these verbatim instead of wrapping them — the
/// spike is about proving compatibility, not introducing a new abstraction.
pub mod primitives {
    pub use fula_client::{
        Config, DecryptedObjectInfo, EncryptedClient, EncryptionConfig, PutObjectResult,
    };
    pub use fula_crypto::{
        ChunkedDecoder, ChunkedEncoder, ChunkedFileMetadata, DekKey, EncryptedChunk, SecretKey,
        should_use_chunked, CHUNKED_THRESHOLD,
    };
}

/// Errors surfaced by the `fula-mcp` helpers.
#[derive(Debug, Error)]
pub enum McpError {
    /// The derived 32-byte secret could not be turned into a [`SecretKey`].
    ///
    /// In practice this is unreachable for Mode A (the derivation always
    /// yields exactly 32 bytes), but we surface it instead of panicking so
    /// callers stay in control.
    #[error("failed to construct secret key from derived bytes: {0}")]
    KeyConstruction(String),
}

/// The fixed Argon2id domain-separation context for FxFiles file-encryption
/// key derivation.
///
/// This is the `context`/salt string passed to
/// [`fula_crypto::hashing::derive_key_argon2id`]. It is `auth_service.dart`'s
/// `"fula-files-v1"` literal byte-for-byte; changing it derives a different
/// key and breaks compatibility with already-stored files.
pub const MODE_A_DERIVATION_CONTEXT: &str = "fula-files-v1";

/// Derive the Mode A (OAuth) file-encryption secret for a user.
///
/// Mode A is the OAuth-identity flow: the user's master secret is
/// `Argon2id(context = "fula-files-v1", input = "{provider}:{oauth_sub}:{email}")`.
/// This is byte-for-byte what FxFiles' `auth_service.dart` computes, so the
/// resulting [`SecretKey`] unwraps the same per-file DEKs that the app wrote.
///
/// The `input` is the three identity fields joined with `':'` in
/// `provider:oauth_sub:email` order — no trailing separator, no normalization
/// beyond what the caller passes (the values are taken verbatim, matching the
/// app).
///
/// # Errors
/// Returns [`McpError::KeyConstruction`] only if the derived bytes can't form a
/// [`SecretKey`]; for Mode A this does not happen (the KDF returns 32 bytes).
pub fn derive_mode_a_secret(
    provider: &str,
    oauth_sub: &str,
    email: &str,
) -> Result<primitives::SecretKey, McpError> {
    let input = format!("{provider}:{oauth_sub}:{email}");
    let key_bytes = fula_crypto::hashing::derive_key_argon2id(MODE_A_DERIVATION_CONTEXT, input.as_bytes());
    primitives::SecretKey::from_bytes(&key_bytes)
        .map_err(|e| McpError::KeyConstruction(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_a_derivation_is_deterministic_and_32_bytes() {
        // The derivation must be a pure function of the identity triple:
        // identical inputs → identical secret (this is what lets a later
        // session re-derive the key and read prior files).
        let a = derive_mode_a_secret("google", "123456789", "test@example.com").unwrap();
        let b = derive_mode_a_secret("google", "123456789", "test@example.com").unwrap();
        assert_eq!(a.as_bytes(), b.as_bytes(), "derivation must be deterministic");

        // A different identity must derive a different secret.
        let c = derive_mode_a_secret("google", "999999999", "other@example.com").unwrap();
        assert_ne!(
            a.as_bytes(),
            c.as_bytes(),
            "different identity must derive a different secret"
        );

        // SecretKey is fixed-size 32 bytes (KEY_SIZE).
        assert_eq!(a.as_bytes().len(), 32);
    }

    #[test]
    fn derivation_context_matches_fxfiles_literal() {
        // Guardrail: if anyone changes this constant, compatibility with
        // already-stored files breaks. Pin it explicitly.
        assert_eq!(MODE_A_DERIVATION_CONTEXT, "fula-files-v1");
    }
}
