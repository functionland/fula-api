//! Scoped MCP-S3 authorization (P12 — gateway scope enforcement).
//!
//! A *scoped MCP token* is an HS256 JWT minted by the pinning-webui for a
//! paired AI agent (issuer contract: `pinning-webui/server/mcpTokens.ts`). It
//! carries `token_use == "mcp_s3"` and an `mcp` claim naming exactly one
//! `(bucket, prefix, perms)` scope. Unlike the long-lived storage JWTs (which
//! grant the broad `storage:*` scope), an MCP token may touch ONLY its declared
//! bucket, ONLY keys under its declared prefix (`ai/`), and ONLY the actions its
//! `perms` grant.
//!
//! This module turns the raw [`crate::auth::McpScopeClaim`] into a validated
//! [`McpScope`] ([`McpScope::from_claim`]) and answers per-request
//! authorization questions ([`McpScope::assert`]). Cross-USER isolation is NOT
//! this module's job — the gateway already opens buckets per
//! `(hashed_user_id, bucket)` and the JWT `sub` pins the user. This module adds
//! the intra-user bucket/prefix/perm fence on top.
//!
//! ## Fail-closed contract
//! - [`McpScope::from_claim`] REJECTS a claim whose major version is not 1, that
//!   does not carry exactly one scope, whose bucket is empty, or whose prefix is
//!   not the constant `ai/`. The middleware turns any such rejection into a
//!   refused token (a malformed MCP token must NOT fall through to broad
//!   access).
//! - Unknown permission strings are IGNORED (forward-compat): a v1 gateway never
//!   treats an unrecognised perm as a grant, but also never rejects the token
//!   for carrying one (the issuer may add additive perms in a v1 minor).

use crate::auth::McpScopeClaim;

/// The constant key-namespace prefix an MCP token is scoped to. Keys the MCP
/// writes are `ai/<category>/...` in `fula-ai-workspace`; the gateway stores
/// keys verbatim, so this is the literal prefix the token's `prefix` claim must
/// equal. (Cross-user isolation does NOT come from this prefix.)
pub const MCP_WORKSPACE_PREFIX: &str = "ai/";

/// The only `mcp.v` major version this gateway understands. A token declaring a
/// different major version is rejected (fail-closed) — never silently treated
/// as an unconstrained token.
pub const MCP_SCOPE_VERSION: u32 = 1;

/// An S3 action, mapped to the MCP permission it requires.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpAction {
    /// GetObject / HeadObject / ListParts / GetObjectTagging / copy-source read.
    Read,
    /// PutObject / multipart / DeleteObject(s) / copy-dest write / tagging write
    /// / CreateBucket / DeleteBucket.
    Write,
    /// ListObjects(V2) / ListMultipartUploads.
    List,
}

/// A recognised MCP permission. Unknown perm strings on the wire are dropped at
/// parse time, so this enum is exhaustive for what the gateway will honor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpPerm {
    Read,
    Write,
    List,
}

impl McpPerm {
    /// Parse a single perm string; `None` for an unrecognised string (which the
    /// caller drops — never a grant).
    fn parse(s: &str) -> Option<Self> {
        match s {
            "read" => Some(Self::Read),
            "write" => Some(Self::Write),
            "list" => Some(Self::List),
            _ => None,
        }
    }

    /// The perm an action requires.
    fn for_action(action: McpAction) -> Self {
        match action {
            McpAction::Read => Self::Read,
            McpAction::Write => Self::Write,
            McpAction::List => Self::List,
        }
    }
}

/// Why a scope claim was rejected / an access denied. The middleware/handlers
/// map every variant onto the same opaque `AccessDenied` (or token-refused) S3
/// error — the distinction exists for tests + tracing, never to leak which rule
/// tripped to the client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeError {
    /// `mcp.v` was not the supported major version.
    UnsupportedVersion(u32),
    /// v1 requires exactly one scope entry; the claim had a different count.
    WrongScopeCount(usize),
    /// The scope's `bucket` was empty.
    EmptyBucket,
    /// The scope's `prefix` was not the constant `ai/`.
    BadPrefix,
    /// The requested bucket did not match the token's scoped bucket.
    BucketMismatch,
    /// An object key fell outside the scoped prefix.
    PrefixViolation,
    /// The action's required permission was not granted by the token.
    MissingPerm(McpAction),
}

impl std::fmt::Display for ScopeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedVersion(v) => write!(f, "unsupported mcp.v: {v}"),
            Self::WrongScopeCount(n) => write!(f, "v1 requires exactly one scope, got {n}"),
            Self::EmptyBucket => write!(f, "scope bucket is empty"),
            Self::BadPrefix => write!(f, "scope prefix must be the ai/ workspace namespace"),
            Self::BucketMismatch => write!(f, "request bucket is outside the token's scope"),
            Self::PrefixViolation => write!(f, "object key is outside the token's prefix"),
            Self::MissingPerm(a) => write!(f, "token lacks the permission for {a:?}"),
        }
    }
}

impl std::error::Error for ScopeError {}

/// A validated, enforce-ready MCP scope. Built once per request (at the
/// middleware) from the token's claim and then consulted by handlers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpScope {
    bucket: String,
    prefix: String,
    perms: Vec<McpPerm>,
}

impl McpScope {
    /// Validate a raw `mcp` claim into an enforce-ready scope. Fail-closed: any
    /// structural violation (wrong version, not exactly one scope, empty bucket,
    /// non-`ai/` prefix) is an `Err`. Unknown perm strings are dropped, NOT
    /// rejected (forward-compat — never treated as a grant).
    pub fn from_claim(claim: &McpScopeClaim) -> Result<Self, ScopeError> {
        if claim.v != MCP_SCOPE_VERSION {
            return Err(ScopeError::UnsupportedVersion(claim.v));
        }
        if claim.scopes.len() != 1 {
            return Err(ScopeError::WrongScopeCount(claim.scopes.len()));
        }
        let entry = &claim.scopes[0];
        if entry.bucket.is_empty() {
            return Err(ScopeError::EmptyBucket);
        }
        if entry.prefix != MCP_WORKSPACE_PREFIX {
            return Err(ScopeError::BadPrefix);
        }
        // Drop unrecognised perm strings (forward-compat); dedup is unnecessary
        // for correctness (membership test below tolerates duplicates).
        let perms: Vec<McpPerm> = entry.perms.iter().filter_map(|p| McpPerm::parse(p)).collect();
        Ok(Self {
            bucket: entry.bucket.clone(),
            prefix: entry.prefix.clone(),
            perms,
        })
    }

    /// The scoped bucket (read-only accessor; handlers don't need it but tests +
    /// tracing might).
    pub fn bucket(&self) -> &str {
        &self.bucket
    }

    fn has_perm(&self, perm: McpPerm) -> bool {
        self.perms.contains(&perm)
    }

    /// Coarse READ capability for the capability gate (`UserSession::can_read`).
    /// An MCP token mints NO storage `scope`, so the per-handler `can_read`
    /// gate (which tests `storage:read`) would otherwise reject every MCP op
    /// BEFORE [`Self::assert`] runs. Capability is derived from perms instead:
    /// `read` OR `list` ⇒ can_read, because the list handlers gate on
    /// `can_read` and then narrow via `assert(List)`. This is intentionally
    /// COARSE — [`Self::assert`] remains the authoritative per-op fence, so a
    /// list-only token passing `can_read` is still denied an actual object GET.
    pub fn has_read_capability(&self) -> bool {
        self.has_perm(McpPerm::Read) || self.has_perm(McpPerm::List)
    }

    /// Coarse WRITE capability for the capability gate
    /// (`UserSession::can_write`): the `write` perm. As with
    /// [`Self::has_read_capability`], [`Self::assert`] is still the
    /// authoritative per-op fence.
    pub fn has_write_capability(&self) -> bool {
        self.has_perm(McpPerm::Write)
    }

    /// Is `key` within the scoped prefix? Because the prefix is `ai/` (ends in
    /// `/`), a plain `starts_with` already enforces the segment boundary:
    /// `ai/foo` is in-scope, `aimage/foo` is NOT (it does not start with
    /// `ai/`). The exact key `ai/` (the bare prefix) is also in-scope.
    fn key_in_prefix(&self, key: &str) -> bool {
        key.starts_with(&self.prefix)
    }

    /// Authorize a single request against this scope. Fail-closed everywhere:
    /// - the requested `bucket` MUST equal the scoped bucket;
    /// - for object ops (`key = Some`) the key MUST be within the scoped prefix
    ///   (`ai/`, segment-bounded);
    /// - the `action`'s required permission MUST be granted.
    ///
    /// Bucket-level ops pass `key = None` (CreateBucket/DeleteBucket = `Write`,
    /// ListObjects = `List`); the prefix check is skipped but the bucket + perm
    /// checks still apply. The perm requirement is driven by the ACTION
    /// (`List ⇒ list`, `Read ⇒ read`, `Write ⇒ write`), so a read+list-only
    /// token can list a bucket but cannot create one.
    pub fn assert(
        &self,
        bucket: &str,
        key: Option<&str>,
        action: McpAction,
    ) -> Result<(), ScopeError> {
        if bucket != self.bucket {
            return Err(ScopeError::BucketMismatch);
        }
        if let Some(k) = key {
            if !self.key_in_prefix(k) {
                return Err(ScopeError::PrefixViolation);
            }
        }
        if !self.has_perm(McpPerm::for_action(action)) {
            return Err(ScopeError::MissingPerm(action));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{McpScopeClaim, McpScopeEntry};

    /// Build a claim with the given version / bucket / prefix / perms.
    fn claim(v: u32, bucket: &str, prefix: &str, perms: &[&str]) -> McpScopeClaim {
        McpScopeClaim {
            v,
            scopes: vec![McpScopeEntry {
                bucket: bucket.to_string(),
                prefix: prefix.to_string(),
                perms: perms.iter().map(|s| s.to_string()).collect(),
            }],
        }
    }

    /// The canonical full-access scope used across the in-scope tests.
    fn full_scope() -> McpScope {
        McpScope::from_claim(&claim(1, "fula-ai-workspace", "ai/", &["read", "write", "list"]))
            .expect("canonical claim parses")
    }

    #[test]
    fn in_scope_ops_are_allowed() {
        let s = full_scope();
        // Object read/write within bucket + prefix.
        assert!(s.assert("fula-ai-workspace", Some("ai/notes/a.txt"), McpAction::Read).is_ok());
        assert!(s.assert("fula-ai-workspace", Some("ai/notes/a.txt"), McpAction::Write).is_ok());
        // The bare prefix key is in-scope.
        assert!(s.assert("fula-ai-workspace", Some("ai/"), McpAction::Read).is_ok());
        // Bucket-level list + create (write present).
        assert!(s.assert("fula-ai-workspace", None, McpAction::List).is_ok());
        assert!(s.assert("fula-ai-workspace", None, McpAction::Write).is_ok());
    }

    #[test]
    fn deny_other_bucket() {
        let s = full_scope();
        assert_eq!(
            s.assert("some-other-bucket", Some("ai/x"), McpAction::Read),
            Err(ScopeError::BucketMismatch)
        );
        // Bucket-level op on the wrong bucket is denied too.
        assert_eq!(
            s.assert("some-other-bucket", None, McpAction::List),
            Err(ScopeError::BucketMismatch)
        );
    }

    #[test]
    fn deny_prefix_boundary_aimage() {
        // The segment-boundary case: `aimage/...` must NOT be treated as inside
        // the `ai/` prefix (the bug this guards against).
        let s = full_scope();
        assert_eq!(
            s.assert("fula-ai-workspace", Some("aimage/secret"), McpAction::Read),
            Err(ScopeError::PrefixViolation)
        );
        assert_eq!(
            s.assert("fula-ai-workspace", Some("other/key"), McpAction::Write),
            Err(ScopeError::PrefixViolation)
        );
    }

    #[test]
    fn deny_missing_perm_write_with_read_only() {
        // A read-only token may read but not write, even in-bucket/in-prefix.
        let s = McpScope::from_claim(&claim(1, "fula-ai-workspace", "ai/", &["read"])).unwrap();
        assert!(s.assert("fula-ai-workspace", Some("ai/x"), McpAction::Read).is_ok());
        assert_eq!(
            s.assert("fula-ai-workspace", Some("ai/x"), McpAction::Write),
            Err(ScopeError::MissingPerm(McpAction::Write))
        );
        // ...and cannot list (no list perm).
        assert_eq!(
            s.assert("fula-ai-workspace", None, McpAction::List),
            Err(ScopeError::MissingPerm(McpAction::List))
        );
    }

    #[test]
    fn read_list_token_can_list_but_not_create_bucket() {
        // Confirms the perm requirement is driven by the ACTION, not hardcoded
        // to `write` for every key=None op.
        let s = McpScope::from_claim(&claim(1, "fula-ai-workspace", "ai/", &["read", "list"])).unwrap();
        assert!(s.assert("fula-ai-workspace", None, McpAction::List).is_ok());
        assert_eq!(
            s.assert("fula-ai-workspace", None, McpAction::Write),
            Err(ScopeError::MissingPerm(McpAction::Write))
        );
    }

    #[test]
    fn version_not_one_is_rejected_at_from_claim() {
        assert_eq!(
            McpScope::from_claim(&claim(2, "fula-ai-workspace", "ai/", &["read"])),
            Err(ScopeError::UnsupportedVersion(2))
        );
        assert_eq!(
            McpScope::from_claim(&claim(0, "fula-ai-workspace", "ai/", &["read"])),
            Err(ScopeError::UnsupportedVersion(0))
        );
    }

    #[test]
    fn wrong_scope_count_is_rejected() {
        // Zero scopes.
        let zero = McpScopeClaim { v: 1, scopes: vec![] };
        assert_eq!(McpScope::from_claim(&zero), Err(ScopeError::WrongScopeCount(0)));
        // Two scopes (reserved for a future version; a v1 gateway rejects).
        let two = McpScopeClaim {
            v: 1,
            scopes: vec![
                McpScopeEntry { bucket: "a".into(), prefix: "ai/".into(), perms: vec!["read".into()] },
                McpScopeEntry { bucket: "b".into(), prefix: "ai/".into(), perms: vec!["read".into()] },
            ],
        };
        assert_eq!(McpScope::from_claim(&two), Err(ScopeError::WrongScopeCount(2)));
    }

    #[test]
    fn empty_bucket_and_bad_prefix_rejected() {
        assert_eq!(
            McpScope::from_claim(&claim(1, "", "ai/", &["read"])),
            Err(ScopeError::EmptyBucket)
        );
        assert_eq!(
            McpScope::from_claim(&claim(1, "fula-ai-workspace", "other/", &["read"])),
            Err(ScopeError::BadPrefix)
        );
        // A prefix that merely contains `ai/` but isn't exactly it is rejected.
        assert_eq!(
            McpScope::from_claim(&claim(1, "fula-ai-workspace", "ai", &["read"])),
            Err(ScopeError::BadPrefix)
        );
    }

    #[test]
    fn unknown_perm_is_ignored_not_rejected() {
        // The token parses (not rejected) but the unknown perm grants nothing.
        let s = McpScope::from_claim(&claim(
            1,
            "fula-ai-workspace",
            "ai/",
            &["read", "future_admin", "write"],
        ))
        .expect("unknown perm must not reject the token");
        // Known perms still work.
        assert!(s.assert("fula-ai-workspace", Some("ai/x"), McpAction::Read).is_ok());
        assert!(s.assert("fula-ai-workspace", Some("ai/x"), McpAction::Write).is_ok());
        // The unknown perm did NOT grant list.
        assert_eq!(
            s.assert("fula-ai-workspace", None, McpAction::List),
            Err(ScopeError::MissingPerm(McpAction::List))
        );

        // A token whose ONLY perm is unknown grants nothing at all.
        let none_known =
            McpScope::from_claim(&claim(1, "fula-ai-workspace", "ai/", &["future_only"])).unwrap();
        assert_eq!(
            none_known.assert("fula-ai-workspace", Some("ai/x"), McpAction::Read),
            Err(ScopeError::MissingPerm(McpAction::Read))
        );
    }
}
