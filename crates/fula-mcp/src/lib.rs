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

/// The MCP's per-session collaboration authority bundle — the per-group link
/// secret (recovered once from the wrapped share token via the local
/// [`identity`]), the optional write token, and the shared HTTP client — parsed
/// from `FULA_MCP_CAPABILITY`. Replaces the old workspace/grant bundle.
pub mod capability;

/// The collaboration HTTP client for the `/api/collab/{group_id}/*` endpoints:
/// manifest-sync (GET/PUT), collab-file get + upload, and owner-file `fula-fetch`.
/// All crypto is delegated to [`manifest`] / `fula-crypto`.
pub mod collab;

/// Pure path / tree helpers over the manifest (logical paths, folder
/// normalization, directory markers, tombstone filtering) shared by the read /
/// list / store ops.
pub mod tree;

/// Collaboration manifest + collab-file crypto — a byte-exact Rust port of the
/// Dart `share_link_builder.dart` / `CollaborationService` (and TS
/// `sharingService.ts`) routines the FxFiles app and web portal use in
/// production. HKDF-SHA256 (empty salt) key derivation + AES-256-GCM
/// (`nonce||ct||tag`) for the `"ENC1:"` manifest envelope and raw collab files,
/// plus the [`manifest::CollaborationGroup`] / [`manifest::CollaborationFile`]
/// model (with the CRDT [`merge_with`](manifest::CollaborationGroup::merge_with)).
/// Correctness is gated by decrypting REAL Dart-produced vectors in
/// `tests/collab_crypto_vectors.rs`.
pub mod manifest;

/// The MCP's persistent collaboration identity (Method-2 X25519 keypair). Wraps
/// [`fula_crypto::KekKeyPair`] with the `"FULA-..."` share-id helpers, local
/// secret persistence, and [`accept_link_secret`](identity::McpIdentity::accept_link_secret)
/// which recovers an owner-wrapped link secret via `fula_crypto::sharing`
/// (no HPKE reimplementation).
pub mod identity;

/// File categorization + native-bucket routing, a faithful port of FxFiles'
/// `ShelfClassifier` + the content-bucket map (P4).
pub mod category;

/// The AI's collaboration WRITE ops: `store_file` / `create_folder` /
/// `remove_file`. Each encrypts (for `store_file`) + uploads a per-file blob and
/// commits an additive change to the group manifest via GET-latest →
/// `remote.merge_with(&local)` → PUT (merge-on-write, so concurrent human edits
/// survive). Removal is a manifest TOMBSTONE, never a server delete. See
/// [`store::store_file`].
pub mod store;

/// The AI's collaboration READ op: `read_file` (by file id or logical path).
/// Resolves the entry in the group manifest and decrypts it — `collab` blobs with
/// the per-file collab key, `fula` (owner) files by accepting the share token with
/// the group link keypair and mirroring `fula-client`'s single-block / chunked
/// decrypt. See [`read::read_file`].
pub mod read;

/// The AI's collaboration ENUMERATION ops: `list_files` + `search` over the group
/// manifest, with an optional folder-prefix / category filter and directory-marker
/// awareness so a folder tree can be derived. See [`list::list_files`] and
/// [`list::search`].
pub mod list;

/// The AI's TAG operations — DEFERRED in collaboration mode. The manifest is
/// byte-exact with the Dart/TS producers, so embedding tags would lose them
/// cross-client; the tools return an explicit "unsupported (deferred)" outcome
/// rather than silently succeeding. See [`tags`] for the rationale + TODO.
pub mod tags;

/// Fail-fast credit/quota pre-check + a per-session WRITE rate limiter (P10).
/// The quota check calls the SAME credit endpoint the gateway uses and FAILS
/// OPEN on any error (the gateway re-enforces quota on the real PUT, so a check
/// outage degrades to "the PUT may fail later," not "all writes blocked"); the
/// token-bucket limiter throttles a runaway AI's writes per session. Both run
/// after input validation, before the heavy encrypt+upload. See [`quota`].
pub mod quota;

/// Silent token auto-refresh. POSTs `{refresh_token}` to `refresh_url` and parses
/// the fresh `{token}` (the `POST /api/mcp/tokens/refresh-connection` contract); a
/// refresh that itself 401/403s means REVOKED (terminal). Reused by [`retry`] to
/// re-mint the `collab_write_token` on a write 401/403. Backward-compatible: with
/// no `refresh_token`/`refresh_url`, no refresh is attempted. See
/// [`refresh::refresh_connection_jwt`].
pub mod refresh;

/// The collab write-token refresh-on-auth retry wrapper. Wraps a single
/// collaboration WRITE call so a 401/403 re-mints the `collab_write_token` (via
/// [`refresh::refresh_connection_jwt`]'s `{refresh_token} → {token}` shape) and
/// retries exactly once. See [`retry::with_collab_write_retry`].
pub mod retry;

/// The stdio MCP server that exposes the collaboration ops (read / list / search /
/// store / create_folder / remove_file; tag tools deferred) as Model Context
/// Protocol tools. Loads the [`capability::CapabilityBundle`] from the environment
/// once at startup (in memory only) and runs over stdio via the `rmcp` SDK. See
/// [`server::run`] (env-driven entrypoint) and [`server::FulaMcpServer`].
pub mod server;

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
