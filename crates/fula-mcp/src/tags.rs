//! # Tags — DEFERRED in collaboration mode
//!
//! Tags are intentionally NOT persisted in the collaboration rework, and the tag
//! tools return a clear "unsupported (deferred)" outcome rather than silently
//! succeeding. The reasons are concrete:
//!
//! - The collaboration manifest model ([`crate::manifest::CollaborationGroup`]) is
//!   **byte-exact** with the Dart app and the TS web portal (gated by
//!   `tests/collab_crypto_vectors.rs`). Adding a `tags` field to it would be
//!   silently **dropped** by those clients on their next manifest write — they
//!   `fromJson`/`toJson` only the fields they know — so AI-written tags would be
//!   lost the moment a human edited the group.
//! - The previous per-document tag store lived in the AI **workspace** path, which
//!   the rework removes — and must not resurrect.
//!
//! So neither "embed in the manifest" nor "separate workspace doc" is a safe,
//! minimal option today. Deferring (loudly) is the honest choice.
//!
//! TODO(collab-tags): persist tags once EITHER (a) the Dart/TS manifest model
//! gains a shared `tags`/`fileTags` section that all three implementations
//! round-trip, OR (b) a dedicated group-scoped `/api/collab/{group}/tags`
//! endpoint exists. Until then, writing tags anywhere would lose them
//! cross-client, so the tools fail closed with [`TagError::Deferred`].

use crate::capability::CapabilityBundle;

/// Errors surfaced by the (currently deferred) tag ops.
#[derive(Debug, thiserror::Error)]
pub enum TagError {
    /// Tags are not yet supported for collaboration groups (see the module docs).
    #[error("tags are not yet supported in collaboration mode (deferred — see fula-mcp::tags)")]
    Deferred,
}

/// DEFERRED — always returns [`TagError::Deferred`]. Kept as a stable entry point
/// so the MCP tool surface is unchanged; it never silently reports success.
pub fn tag_file(
    _cap: &CapabilityBundle,
    _file_id: &str,
    _tags: &[String],
) -> Result<(), TagError> {
    Err(TagError::Deferred)
}

/// DEFERRED — always returns [`TagError::Deferred`].
pub fn list_tags(_cap: &CapabilityBundle) -> Result<(), TagError> {
    Err(TagError::Deferred)
}
