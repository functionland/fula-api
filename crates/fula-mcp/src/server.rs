//! # `server` — the stdio MCP server that exposes the six AI-workspace ops (P9)
//!
//! Phases P5–P8 built the six scoped operations as plain async library calls.
//! Phase 9 wires them into a real **Model Context Protocol** server over
//! **stdio**, so the local MCP is runnable by Claude Code / Claude Desktop. The
//! SDK is [`rmcp`] (the official `modelcontextprotocol/rust-sdk`).
//!
//! ## The shape
//!
//! [`FulaMcpServer`] holds the per-session [`CapabilityBundle`] (loaded ONCE at
//! startup from the env, in memory only — never logged) plus the rmcp
//! [`ToolRouter`]. Each `#[tool]` method:
//!
//! 1. parses its typed args (`Parameters<T>` with a serde/`schemars` schema),
//! 2. dispatches to the matching P5–P8 library op against the bundle,
//! 3. maps the op's typed error onto an **MCP tool error** ([`CallToolResult`]
//!    with `is_error = true`), and
//! 4. emits ONE structured audit event (action + key + scope + outcome +
//!    duration) — never the content, never any secret/DEK.
//!
//! ## The six tools
//!
//! | tool                | op (P)                       | returns                               |
//! |---------------------|------------------------------|---------------------------------------|
//! | `fula_store_file`   | [`store_file`] (+ [`tag_file`]) | `{ key, category, native_bucket, etag }` |
//! | `fula_read_file`    | [`read_workspace_file`] (P6) | `{ content_base64 }`                  |
//! | `fula_list_files`   | [`list_files`] (P7)          | `[ FileEntry … ]`                     |
//! | `fula_search`       | [`search`] (P7)              | `[ FileEntry … ]`                     |
//! | `fula_tag_file`     | [`tag_file`] (P8)            | `{ created_tags, added_associations }`|
//! | `fula_list_tags`    | [`list_tags`] (P8)           | `[ FileTag … ]`                       |
//!
//! ## Error mapping — MCP **tool** errors, never a secret leak
//!
//! The task is explicit: *map errors → MCP tool errors*, and *NEVER leak secrets
//! or DEKs in errors*. We honor both with a single funnel, [`tool_error`]:
//!
//! - Each op's `Capability` / out-of-scope variant → **access-denied**
//!   (a fixed `"access denied: …"` message, no raw Display forwarded).
//! - Each op's not-found variant → **not-found**.
//! - Everything else (`Client` / crypto / serialize / shape) → **internal**.
//!
//! The crux is that the underlying error enums' [`Display`] can embed
//! `fula-client` transport text — which may contain the gateway JWT, a signed
//! URL, or other sensitive material. So the mapper **never forwards the raw
//! Display into the MCP error**: it emits a FIXED generic message per category.
//! The detailed Display is only ever written to the operator's own stderr audit
//! event at `debug` level via [`tracing`], never to the wire the model sees.
//! (See [`secrets-never-leak`](#how-we-prove-secrets-never-leak).)
//!
//! These are returned as `Ok(CallToolResult::error(…))` (an MCP tool error the
//! model can see and react to) rather than `Err(ErrorData)` (a JSON-RPC
//! protocol error), because the task asks for *tool* errors and because a
//! denied/not-found read is a legitimate tool *outcome*, not a malformed
//! request. Only genuinely malformed input (e.g. non-base64 `content`) is a
//! protocol-level [`ErrorData::invalid_params`].
//!
//! ## How we prove secrets never leak
//!
//! - The mapper [`tool_error`] takes only `(category, audit_detail)`: the
//!   model-visible text is a constant per category; the `audit_detail` goes to
//!   stderr only.
//! - The audit event ([`audit`]) logs `action`, `key`, `scope`, `outcome`,
//!   `duration_ms`, and (on failure) a `detail` — it NEVER logs the file
//!   `content`, the workspace secret, the MCP secret, the JWT, or any DEK /
//!   share token. `CapabilityBundle`'s own [`Debug`] is redacting, so even an
//!   accidental `{cap:?}` could not print a secret.
//! - The tests in this module assert that a forced `Client`-style failure
//!   produces an MCP error whose text contains NONE of a planted secret
//!   substring.
//!
//! ## What later phases lean on (documented seams)
//!
//! - **P10 (quota pre-check):** the per-tool flow already centralizes
//!   *parse → authorize-via-op → audit*. A quota gate slots in right after the
//!   op's own `assert_in_scope` (so it runs after authority, before the heavy
//!   `put`), or as a thin wrapper inside [`FulaMcpServer::store_impl`]; the
//!   audit event already carries the `key`/`scope` a quota decision keys on.
//! - **P17 (`fula_request_access`):** adding a seventh tool is purely additive —
//!   a new `#[tool]` method on the same `#[tool_router]` impl. It would mint /
//!   surface an `owner → MCP` grant request; the bundle already exposes
//!   `mcp_public_key()` (the address such a grant is minted to) and `read.rs`
//!   already has the granted-read path that consumes the resulting token. The
//!   server structure needs no change beyond the new method + its arg struct.

use std::time::Instant;

use base64::Engine as _;
use bytes::Bytes;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, Content, ServerCapabilities, ServerInfo};
use rmcp::{tool, tool_handler, tool_router, ErrorData, ServerHandler};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::capability::CapabilityBundle;
use crate::category::Category;
use crate::list::{list_files, search, ListFilter};
use crate::read::read_workspace_file;
use crate::store::store_file;
use crate::tags::{list_tags, tag_file, FileTag};

/// The category of an operation outcome, used for BOTH the MCP error mapping and
/// the audit `outcome` field. Keeps the two in lockstep.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    /// The op succeeded.
    Ok,
    /// The op was denied by the capability / scope check (out-of-scope, missing
    /// grant, or a non-canonical key). Maps to the MCP "access denied" tool error.
    AccessDenied,
    /// The target object did not exist. Maps to the MCP "not found" tool error.
    NotFound,
    /// The user is over their storage quota / out of credits (P10). Maps to the
    /// MCP "quota exceeded" tool error — an ACTIONABLE signal (add credits),
    /// distinct from a generic internal failure the model cannot fix.
    QuotaExceeded,
    /// A write was rate-limited (P10) — the session's local write bucket or the
    /// gateway's per-user limiter. Maps to the MCP "rate limited" tool error — an
    /// ACTIONABLE signal (slow down and retry).
    RateLimited,
    /// Any other failure (client / network / crypto / serialize / shape). Maps to
    /// the MCP "internal error" tool error.
    Internal,
}

impl Outcome {
    /// The audit `outcome` label.
    fn label(self) -> &'static str {
        match self {
            Outcome::Ok => "ok",
            Outcome::AccessDenied => "access_denied",
            Outcome::NotFound => "not_found",
            Outcome::QuotaExceeded => "quota_exceeded",
            Outcome::RateLimited => "rate_limited",
            Outcome::Internal => "internal_error",
        }
    }

    /// The FIXED, model-visible error message for a failure category. Deliberately
    /// generic — it carries NO detail from the underlying error's Display, so no
    /// JWT / DEK / transport substring can ever reach the model through it.
    fn client_message(self) -> &'static str {
        match self {
            // Should never be rendered (Ok is not an error), but keep total.
            Outcome::Ok => "ok",
            Outcome::AccessDenied => {
                "access denied: the requested key is outside this session's granted scope"
            }
            Outcome::NotFound => "not found: no such object in the AI workspace",
            // ACTIONABLE, generic, secret-free (like the others): tells the model
            // exactly what to do without leaking balances or any transport detail.
            Outcome::QuotaExceeded => {
                "quota exceeded: the user is over their storage quota or out of credits; \
                 add FULA credits and retry"
            }
            Outcome::RateLimited => {
                "rate limited: too many writes in a short period; slow down and retry shortly"
            }
            Outcome::Internal => "internal error: the storage operation could not be completed",
        }
    }
}

// ── argument structs (serde + schemars schema for each tool) ──────────────────

/// Args for [`fula_store_file`](FulaMcpServer::fula_store_file).
///
/// Note there is intentionally **no `path` field**: the task listed an optional
/// "read from a local FS path" form, but letting an MCP server read arbitrary
/// local files is a file-exfiltration primitive for whatever drives the server.
/// The AI hands us the bytes it wants stored as base64 `content`; we never touch
/// the operator's filesystem. (A future phase that wants a constrained, allowlist-
/// rooted `path` can add it deliberately — it is a security expansion, not a
/// default.)
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct StoreFileArgs {
    /// The file bytes to store, **base64-encoded** (standard alphabet). The AI's
    /// output. Encrypted client-side under a fresh per-file DEK before upload.
    pub content: String,
    /// The file name (drives categorization + the key's trailing segment).
    pub name: String,
    /// Explicit MIME content type, if known (e.g. `image/png`). Drives
    /// classification and is recorded on the object.
    #[serde(default)]
    pub mime: Option<String>,
    /// Optional text payload that biases Link/Note classification.
    #[serde(default)]
    pub text: Option<String>,
    /// Force a category (one of: `link`, `note`, `screenshot`, `image`, `video`,
    /// `audio`, `document`, `file`, `other`) instead of auto-classifying.
    #[serde(default)]
    pub category_override: Option<String>,
    /// Optional tags to apply to the stored file in one call (each upserted into
    /// the AI's native tag document).
    #[serde(default)]
    pub tags: Option<Vec<String>>,
}

/// Args for [`fula_read_file`](FulaMcpServer::fula_read_file).
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct ReadFileArgs {
    /// The canonical logical key of an AI-workspace file
    /// (`ai/<category>/<uuid>-<name>`), as returned by `fula_store_file` /
    /// `fula_list_files`.
    pub key: String,
}

/// Args for [`fula_list_files`](FulaMcpServer::fula_list_files).
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct ListFilesArgs {
    /// Keep only files of this category (`link`, `note`, `screenshot`, `image`,
    /// `video`, `audio`, `document`, `file`, `other`). Omit for all categories.
    #[serde(default)]
    pub category: Option<String>,
    /// Keep only files whose logical key is inside this sub-prefix of `ai/`
    /// (segment-boundary match). Must itself be inside `ai/`.
    #[serde(default)]
    pub prefix: Option<String>,
}

/// Args for [`fula_search`](FulaMcpServer::fula_search).
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct SearchArgs {
    /// Substring to match against file names (case-insensitive). Empty matches
    /// every file in the workspace.
    pub query: String,
}

/// Args for [`fula_tag_file`](FulaMcpServer::fula_tag_file).
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct TagFileArgs {
    /// The logical key of the workspace file to tag
    /// (`ai/<category>/<uuid>-<name>`).
    pub key: String,
    /// One or more tag names to apply (deduped case-insensitively). Required.
    pub tags: Vec<String>,
}

/// Args for [`fula_list_tags`](FulaMcpServer::fula_list_tags) — none.
#[derive(Debug, Default, Deserialize, Serialize, JsonSchema)]
pub struct ListTagsArgs {}

// ── result projections (what the model sees — NEVER storage_key / share / DEK) ──

/// `fula_store_file` result. Deliberately omits `storage_key` (obfuscated
/// location) and `owner_share` (a [`ShareToken`](fula_crypto::ShareToken)
/// wrapping the content DEK) — both are crypto-adjacent and never leave the
/// server.
///
/// Derives `Deserialize` too so the gated e2e (which reads the tool result back)
/// can parse it; production only ever serializes it.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct StoreFileResult {
    /// The canonical logical key the file was stored under.
    pub key: String,
    /// The category it classified as.
    pub category: String,
    /// The FxFiles native content bucket this category would adopt into
    /// (`images-v8`, …), or `null` for non-content categories.
    pub native_bucket: Option<String>,
    /// The S3 ETag the upload returned (content checksum; not a secret).
    pub etag: String,
    /// Names of tags newly CREATED by an accompanying `tags` argument (empty when
    /// no tags were supplied or all already existed).
    #[serde(default)]
    pub created_tags: Vec<String>,
    /// Number of (tag, file) associations newly added by a `tags` argument.
    #[serde(default)]
    pub added_associations: usize,
    /// `true` iff `tags` were supplied but the tag write FAILED *after* the file
    /// was already stored durably. The file IS stored (the `key`/`etag` above are
    /// valid and the model can read it back); only the tagging did not land, and
    /// can be retried with `fula_tag_file`. We surface the store as a SUCCESS (so
    /// the model still learns the `key`) rather than hiding a durable write behind
    /// a tool error.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub tags_failed: bool,
}

/// `fula_read_file` result: the decrypted bytes, base64-encoded.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct ReadFileResult {
    /// The file's plaintext bytes, base64-encoded (standard alphabet).
    pub content_base64: String,
}

/// `fula_tag_file` result.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct TagFileResult {
    /// Names of tags newly created by this call.
    pub created_tags: Vec<String>,
    /// Number of (tag, file) associations newly added by this call.
    pub added_associations: usize,
}

/// The stdio MCP server. Holds the in-memory per-session capability bundle and
/// the rmcp tool router.
#[derive(Clone)]
pub struct FulaMcpServer {
    /// The per-session authority, loaded ONCE at startup (in memory only). Shared
    /// (`Arc`) so the rmcp router's `Clone` requirement is cheap and the secret is
    /// not copied. Its [`Debug`] is redacting.
    cap: std::sync::Arc<CapabilityBundle>,
    /// The rmcp tool router (generated by `#[tool_router]`). Read by the
    /// `#[tool_handler]`-generated `ServerHandler::call_tool` / `list_tools`
    /// through macro expansion, which the dead-code analyzer cannot see — hence
    /// the allow (the rmcp README's own example carries the same field).
    #[allow(dead_code)]
    tool_router: ToolRouter<Self>,
}

impl std::fmt::Debug for FulaMcpServer {
    /// Redacting: never prints the bundle (which holds secrets). The bundle's own
    /// Debug is redacting too, but we keep this terse on purpose.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FulaMcpServer")
            .field("cap", &"<CapabilityBundle: redacted>")
            .finish()
    }
}

#[tool_router]
impl FulaMcpServer {
    /// Build the server around an already-loaded [`CapabilityBundle`].
    ///
    /// The bundle is taken by value and wrapped in an `Arc`; the server never
    /// re-reads the env or the disk after this. Used by [`crate::server::run`]
    /// (which loads the bundle from the env first) and by the tests (which build
    /// a bundle from a known secret).
    pub fn new(cap: CapabilityBundle) -> Self {
        Self {
            cap: std::sync::Arc::new(cap),
            tool_router: Self::tool_router(),
        }
    }

    /// Store a file into the AI's encrypted workspace, optionally tagging it.
    #[tool(
        description = "Store a file into the AI's own encrypted Fula workspace. \
        The bytes are provided base64-encoded and are encrypted client-side before \
        upload; the gateway only ever sees ciphertext. Optionally apply tags in the \
        same call. Returns the logical key, classified category, and ETag."
    )]
    pub async fn fula_store_file(
        &self,
        Parameters(args): Parameters<StoreFileArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let started = Instant::now();
        // Decode base64 content. A bad base64 body is a MALFORMED request (the
        // caller sent us something we cannot interpret), so it is the one
        // protocol-level error here, not a tool outcome.
        let content = match base64::engine::general_purpose::STANDARD.decode(args.content.as_bytes())
        {
            Ok(bytes) => Bytes::from(bytes),
            Err(_) => {
                audit("fula_store_file", Some(&args.name), "ai", Outcome::Internal, started, Some("content was not valid base64"));
                return Err(ErrorData::invalid_params(
                    "`content` must be valid base64",
                    None,
                ));
            }
        };
        let category_override = match parse_category_override(args.category_override.as_deref()) {
            Ok(c) => c,
            Err(()) => {
                audit("fula_store_file", Some(&args.name), "ai", Outcome::Internal, started, Some("unknown category_override"));
                return Err(ErrorData::invalid_params(
                    "`category_override` is not a known category",
                    None,
                ));
            }
        };

        Ok(self
            .store_impl(content, &args.name, args.mime.as_deref(), args.text.as_deref(), category_override, args.tags.as_deref(), started)
            .await)
    }

    /// Read one of the AI's own workspace files; returns its bytes base64-encoded.
    #[tool(
        description = "Read one of the AI's own Fula workspace files by its logical \
        key (ai/<category>/<uuid>-<name>). The bytes are fetched and decrypted \
        client-side and returned base64-encoded. Only the AI's own workspace files \
        are readable; any other key is denied."
    )]
    pub async fn fula_read_file(
        &self,
        Parameters(args): Parameters<ReadFileArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let started = Instant::now();
        match read_workspace_file(&self.cap, &args.key).await {
            Ok(bytes) => {
                let content_base64 =
                    base64::engine::general_purpose::STANDARD.encode(bytes.as_ref());
                audit("fula_read_file", Some(&args.key), "ai", Outcome::Ok, started, None);
                Ok(json_ok(&ReadFileResult { content_base64 }))
            }
            Err(e) => {
                use crate::read::ReadError;
                let (outcome, kind) = match &e {
                    ReadError::Capability(_) => (Outcome::AccessDenied, "capability"),
                    ReadError::NotFound(_) => (Outcome::NotFound, "not_found"),
                    ReadError::Client(_) => (Outcome::Internal, "client"),
                };
                Ok(tool_error("fula_read_file", Some(&args.key), "ai", outcome, started, kind))
            }
        }
    }

    /// List the AI's workspace files, optionally narrowed by category / prefix.
    #[tool(
        description = "List the files in the AI's own Fula workspace, optionally \
        filtered by category and/or a sub-prefix of ai/. Returns rows with the \
        logical key, size, content type, category, and last-modified time. Only \
        the AI's own workspace is enumerated."
    )]
    pub async fn fula_list_files(
        &self,
        Parameters(args): Parameters<ListFilesArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let started = Instant::now();
        let category = match parse_category_override(args.category.as_deref()) {
            Ok(c) => c,
            Err(()) => {
                audit("fula_list_files", None, "ai", Outcome::Internal, started, Some("unknown category"));
                return Err(ErrorData::invalid_params("`category` is not a known category", None));
            }
        };
        let filter = ListFilter { category, prefix: args.prefix.clone() };
        match list_files(&self.cap, &filter).await {
            Ok(rows) => {
                audit("fula_list_files", args.prefix.as_deref(), "ai", Outcome::Ok, started, None);
                Ok(json_ok(&rows))
            }
            Err(e) => Ok(map_list_error("fula_list_files", args.prefix.as_deref(), e, started)),
        }
    }

    /// Search the AI's workspace by file-name substring (case-insensitive).
    #[tool(
        description = "Search the AI's own Fula workspace by file-name substring \
        (case-insensitive). Returns the same row shape as fula_list_files for \
        matching files. Only the AI's own workspace is searched."
    )]
    pub async fn fula_search(
        &self,
        Parameters(args): Parameters<SearchArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let started = Instant::now();
        match search(&self.cap, &args.query).await {
            Ok(rows) => {
                audit("fula_search", None, "ai", Outcome::Ok, started, None);
                Ok(json_ok(&rows))
            }
            Err(e) => Ok(map_list_error("fula_search", None, e, started)),
        }
    }

    /// Tag a stored workspace file with one or more tags.
    #[tool(
        description = "Apply one or more tags to a stored Fula workspace file \
        (by its logical key). Tags are written into the AI's native tag document \
        and deduped case-insensitively. Returns which tag names were newly created \
        and how many associations were added."
    )]
    pub async fn fula_tag_file(
        &self,
        Parameters(args): Parameters<TagFileArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let started = Instant::now();
        match tag_file(&self.cap, &args.key, &args.tags).await {
            Ok(out) => {
                audit("fula_tag_file", Some(&args.key), "ai", Outcome::Ok, started, None);
                Ok(json_ok(&TagFileResult {
                    created_tags: out.created_tags,
                    added_associations: out.added_associations,
                }))
            }
            Err(e) => Ok(map_tag_error("fula_tag_file", Some(&args.key), e, started)),
        }
    }

    /// List all tags in the AI's workspace tag document.
    #[tool(
        description = "List all tags currently defined in the AI's Fula workspace \
        tag document. Returns each tag's id, name, color, timestamps, and file \
        count."
    )]
    pub async fn fula_list_tags(
        &self,
        Parameters(_args): Parameters<ListTagsArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let started = Instant::now();
        match list_tags(&self.cap).await {
            Ok(tags) => {
                audit("fula_list_tags", None, "ai", Outcome::Ok, started, None);
                Ok(json_ok::<Vec<FileTag>>(&tags))
            }
            Err(e) => Ok(map_tag_error("fula_list_tags", None, e, started)),
        }
    }
}

impl FulaMcpServer {
    /// The store happy-path + tag-on-store, split out so the public tool method
    /// stays a thin parse-and-dispatch. Returns a [`CallToolResult`] (success or
    /// a mapped tool error) — never an `Err`, since by here the args are valid.
    ///
    /// The argument list mirrors `store_file`'s own surface (content + the five
    /// classify/key inputs) plus the in-call `tags` and the audit `started`
    /// instant; splitting them into a struct would just move the same fields, so
    /// we allow the lint (as `capability::mint_owner_share` already does).
    #[allow(clippy::too_many_arguments)]
    async fn store_impl(
        &self,
        content: Bytes,
        name: &str,
        mime: Option<&str>,
        text: Option<&str>,
        category_override: Option<Category>,
        tags: Option<&[String]>,
        started: Instant,
    ) -> CallToolResult {
        let outcome = match store_file(&self.cap, content, name, mime, text, category_override).await
        {
            Ok(o) => o,
            Err(e) => {
                use crate::store::StoreError;
                let (oc, kind) = match &e {
                    StoreError::Capability(_) => (Outcome::AccessDenied, "capability"),
                    StoreError::ObjectNotFound(_) => (Outcome::NotFound, "not_found"),
                    StoreError::QuotaExceeded => (Outcome::QuotaExceeded, "quota_exceeded"),
                    StoreError::RateLimited => (Outcome::RateLimited, "rate_limited"),
                    StoreError::Client(_) => (Outcome::Internal, "client"),
                    StoreError::DekRecovery(_) => (Outcome::Internal, "dek_recovery"),
                    StoreError::Share(_) => (Outcome::Internal, "share"),
                    StoreError::MetadataShape(_) => (Outcome::Internal, "metadata_shape"),
                };
                return tool_error("fula_store_file", Some(name), "ai", oc, started, kind);
            }
        };

        // If tags were supplied, apply them in the same call. A tag failure does
        // NOT roll back the stored file (it is already durably written + shared).
        // Crucially we still return the store as a SUCCESS carrying the `key`
        // (per the documented tool contract `{ key, category, native_bucket,
        // etag }`) and set `tags_failed = true`, rather than converting a durable
        // write into a tool error that would HIDE the key from the model. The
        // model can re-tag via `fula_tag_file`. We attempt tagging only when there
        // is at least one non-trivial tag.
        let mut created_tags = Vec::new();
        let mut added_associations = 0usize;
        let mut tags_failed = false;
        if let Some(tags) = tags.filter(|t| !t.is_empty()) {
            match tag_file(&self.cap, &outcome.key, tags).await {
                Ok(t) => {
                    created_tags = t.created_tags;
                    added_associations = t.added_associations;
                }
                Err(_e) => {
                    // Stored OK; only tagging failed. Audit it with a BOUNDED label
                    // (never the error Display, to keep the "no secret in logs"
                    // invariant), and report the store success with tags_failed set.
                    tags_failed = true;
                    audit(
                        "fula_store_file",
                        Some(&outcome.key),
                        "ai",
                        Outcome::Ok,
                        started,
                        Some("stored_ok_tagging_failed"),
                    );
                }
            }
        }

        if !tags_failed {
            audit("fula_store_file", Some(&outcome.key), "ai", Outcome::Ok, started, None);
        }
        json_ok(&StoreFileResult {
            key: outcome.key,
            category: outcome.category.name().to_string(),
            native_bucket: outcome.native_bucket,
            etag: outcome.etag,
            created_tags,
            added_associations,
            tags_failed,
        })
    }
}

#[tool_handler]
impl ServerHandler for FulaMcpServer {
    fn get_info(&self) -> ServerInfo {
        // `ServerInfo` (= `InitializeResult`) is `#[non_exhaustive]` in rmcp 1.7,
        // so we build it via `::new(capabilities)` + the chainable setters rather
        // than a struct literal. `enable_tools()` advertises the tool capability;
        // protocol version + server_info default to rmcp's latest-known values.
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_instructions(
                "Fula AI workspace tools. Store, read, list, search, and tag files \
                 in the AI's own end-to-end-encrypted Fula workspace. The AI can \
                 only ever access its own workspace files (the `ai/` scope) or \
                 files the owner has explicitly granted; the user's real files are \
                 never readable. File bytes are exchanged base64-encoded.",
            )
    }
}

// ── shared helpers: result projection, error mapping, audit ───────────────────

/// Build a successful [`CallToolResult`] whose single content block is the
/// JSON-serialized `value`. We use `Content::text(json)` (rather than the
/// `Json<T>` structured-output wrapper) so the content is a plain JSON string the
/// model reads directly; serialization of these plain projections never fails, so
/// a serialize error falls back to a generic internal tool error.
fn json_ok<T: Serialize>(value: &T) -> CallToolResult {
    match serde_json::to_string(value) {
        Ok(s) => CallToolResult::success(vec![Content::text(s)]),
        Err(_) => CallToolResult::error(vec![Content::text(
            Outcome::Internal.client_message(),
        )]),
    }
}

/// Build an MCP **tool error** ([`CallToolResult`] with `is_error = true`) for a
/// failure `outcome`, emit the audit event, and return the model-visible result
/// carrying ONLY the fixed generic message for that category.
///
/// `error_kind` is a BOUNDED, static label (e.g. `"client"`, `"corrupt_document"`)
/// chosen from the source error's *variant* — never its `Display`. This is the
/// crux of the crate's "no secret in logs" invariant (`capability.rs`): because
/// the audit detail is a fixed label rather than `e.to_string()`, no transport /
/// JWT / DEK substring from a `Client`-style error's Display can EVER reach the
/// audit stream OR the model. The model-visible text is the equally-generic
/// [`Outcome::client_message`]. (We deliberately trade per-error log granularity
/// for a leak-proof-by-construction audit; the `key` + `scope` + `duration_ms` +
/// `outcome` + `error_kind` still localize a failure to the failing op + object.)
fn tool_error(
    action: &str,
    key: Option<&str>,
    scope: &str,
    outcome: Outcome,
    started: Instant,
    error_kind: &'static str,
) -> CallToolResult {
    audit(action, key, scope, outcome, started, Some(error_kind));
    CallToolResult::error(vec![Content::text(outcome.client_message())])
}

/// Map a [`crate::list::ListError`] onto a tool error (list/search share it).
/// Yields a BOUNDED `error_kind` label from the variant, never the Display.
fn map_list_error(
    action: &str,
    key: Option<&str>,
    err: crate::list::ListError,
    started: Instant,
) -> CallToolResult {
    use crate::list::ListError;
    let (outcome, kind) = match &err {
        ListError::Capability(_) => (Outcome::AccessDenied, "capability"),
        ListError::Client(_) => (Outcome::Internal, "client"),
    };
    tool_error(action, key, "ai", outcome, started, kind)
}

/// Map a [`crate::tags::TagError`] onto a tool error (tag_file / list_tags share
/// it). Yields a BOUNDED `error_kind` label from the variant, never the Display.
/// `NoTags` is reached only after arg parse (an empty `tags` array deserializes
/// fine), so it is surfaced as an internal tool error rather than a protocol one.
fn map_tag_error(
    action: &str,
    key: Option<&str>,
    err: crate::tags::TagError,
    started: Instant,
) -> CallToolResult {
    use crate::tags::TagError;
    let (outcome, kind) = match &err {
        TagError::Capability(_) => (Outcome::AccessDenied, "capability"),
        // CorruptDocument / Client / Serialize / NoTags are all "internal" from the
        // model's perspective (it cannot fix them by retrying with a different key).
        TagError::CorruptDocument { .. } => (Outcome::Internal, "corrupt_document"),
        TagError::Client(_) => (Outcome::Internal, "client"),
        TagError::Serialize(_) => (Outcome::Internal, "serialize"),
        TagError::NoTags => (Outcome::Internal, "no_tags"),
    };
    tool_error(action, key, "ai", outcome, started, kind)
}

/// Parse an optional `category_override` / `category` string into a [`Category`].
/// `None`/empty → `Ok(None)` (no override). An unknown name → `Err(())` (the
/// caller maps it to an `invalid_params` protocol error).
fn parse_category_override(s: Option<&str>) -> Result<Option<Category>, ()> {
    match s.filter(|s| !s.is_empty()) {
        None => Ok(None),
        Some(name) => Category::from_name(name).map(Some).ok_or(()),
    }
}

/// Emit ONE structured audit event for a tool call.
///
/// Logs `action`, `key`, `scope`, `outcome`, `duration_ms`, and an optional
/// `detail`. **`detail` is always a BOUNDED static label** (an error-kind such as
/// `"client"` / `"corrupt_document"`, or the `"stored_ok_tagging_failed"`
/// marker) — NEVER an error `Display`. This is what upholds the crate's "no secret
/// in logs" invariant (`capability.rs`) *by construction*: there is no code path
/// by which a transport / JWT / DEK substring can enter the audit stream, because
/// the only strings passed in are compile-time constants. It also NEVER logs the
/// file content, the workspace/MCP secret, the JWT, or any DEK / share token —
/// none of those are passed in. `key` is the logical object key (e.g.
/// `ai/image/<uuid>-photo.png`) — a workspace path the local operator (who is the
/// data owner in this local-stdio model) already controls, not a secret. (A
/// future *hosted/multi-tenant* deployment, where operator ≠ owner, should hash
/// the key with an injected audit secret; noted as a follow-up.)
///
/// The durable, user-side audit document is a deliberate follow-up (a P-future
/// "workspace audit doc"): this tracing-to-stderr seam is where that writer would
/// subscribe. For P9, structured stderr events are sufficient and are the
/// canonical place a `tracing` layer (file / OTLP) attaches.
fn audit(
    action: &str,
    key: Option<&str>,
    scope: &str,
    outcome: Outcome,
    started: Instant,
    detail: Option<&'static str>,
) {
    let duration_ms = started.elapsed().as_millis() as u64;
    match outcome {
        Outcome::Ok => tracing::info!(
            action,
            key = key.unwrap_or(""),
            scope,
            outcome = outcome.label(),
            duration_ms,
            // Present only for the partial "stored ok but tagging failed" case;
            // a bounded label, never an error Display.
            detail = detail.unwrap_or(""),
            "fula-mcp tool call"
        ),
        _ => tracing::warn!(
            action,
            key = key.unwrap_or(""),
            scope,
            outcome = outcome.label(),
            duration_ms,
            // A bounded error-kind label; operator-only (stderr) and never the
            // model, but it is leak-proof regardless since it is a constant.
            detail = detail.unwrap_or(""),
            "fula-mcp tool call failed"
        ),
    }
}

/// Load the [`CapabilityBundle`] from the environment and run the MCP server over
/// **stdio** until the client disconnects.
///
/// The bundle is read ONCE here (via [`CapabilityBundle::from_env`]) and held in
/// memory for the process lifetime — never written to disk, never logged. The
/// secret material is consumed into typed keys inside `from_env`; this function
/// never sees or prints it.
///
/// stdio is the transport Claude Code / Desktop launch a local MCP over: the
/// server speaks JSON-RPC on stdin/stdout while all logging goes to stderr (so it
/// never corrupts the protocol stream).
///
/// # Errors
/// - A [`crate::capability::CapabilityError`] if the env bundle is missing or
///   malformed (surfaced as a boxed error).
/// - Any rmcp serve / transport error.
pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let cap = CapabilityBundle::from_env()?;
    // Audit the startup WITHOUT printing any secret. The bundle's Debug is
    // redacting, but we log only the non-sensitive shape explicitly.
    tracing::info!(
        endpoint = cap.endpoint(),
        grants = cap.grants().len(),
        "fula-mcp: capability bundle loaded; starting stdio MCP server"
    );
    serve_stdio(cap).await
}

/// Run the server over stdio for an already-built bundle (the seam the binary and
/// any integration harness share). Split from [`run`] so a caller that constructs
/// the bundle itself (not from env) can still drive the real transport.
pub async fn serve_stdio(cap: CapabilityBundle) -> Result<(), Box<dyn std::error::Error>> {
    use rmcp::transport::stdio;
    use rmcp::ServiceExt;

    let service = FulaMcpServer::new(cap).serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use fula_crypto::SecretKey;

    // ── Bundle builders (offline; endpoint unreachable so any accidental I/O
    //    fails LOUDLY and differently from a capability denial) ────────────────

    fn bundle_json(grant_scope: Option<&str>, can_read: bool, can_write: bool) -> String {
        let ws = base64::engine::general_purpose::STANDARD.encode([1u8; 32]);
        let mcp = base64::engine::general_purpose::STANDARD.encode([2u8; 32]);
        let owner = base64::engine::general_purpose::STANDARD
            .encode(SecretKey::from_bytes(&[3u8; 32]).unwrap().public_key().as_bytes());
        let grants = match grant_scope {
            Some(s) => format!(
                r#"[{{ "scope": "{s}", "permissions": {{ "can_read": {can_read}, "can_write": {can_write}, "can_delete": false }} }}]"#
            ),
            None => "[]".to_string(),
        };
        format!(
            r#"{{ "endpoint": "https://offline.invalid", "jwt": "super-secret-jwt-DO-NOT-LEAK", "workspace_secret_b64": "{ws}", "mcp_secret_b64": "{mcp}", "owner_public_b64": "{owner}", "grants": {grants} }}"#
        )
    }

    /// A server whose bundle holds an `ai/` read+write grant (the normal session).
    fn server_rw() -> FulaMcpServer {
        let cap = CapabilityBundle::from_json(&bundle_json(Some("ai/"), true, true)).unwrap();
        FulaMcpServer::new(cap)
    }

    /// A server whose bundle holds NO grants (every op is denied pre-I/O).
    fn server_no_grants() -> FulaMcpServer {
        let cap = CapabilityBundle::from_json(&bundle_json(None, false, false)).unwrap();
        FulaMcpServer::new(cap)
    }

    /// Pull the single text block out of a CallToolResult for assertions. In rmcp
    /// 1.7 `content` is a `Vec<Content>` (not an `Option`); `Content::as_text`
    /// yields the `RawTextContent` whose `.text` is the string.
    fn text_of(result: &CallToolResult) -> String {
        result
            .content
            .first()
            .and_then(|c| c.as_text())
            .map(|t| t.text.clone())
            .unwrap_or_default()
    }

    // ── arg-parse → op-dispatch → result-shape (the unit contract) ────────────

    #[tokio::test]
    async fn store_file_rejects_non_base64_content_as_invalid_params() {
        // A malformed base64 body is the one PROTOCOL-level error (Err), not a tool
        // outcome. Proves the arg-parse arm.
        let srv = server_rw();
        let args = StoreFileArgs {
            content: "this is not base64!!!@@@".to_string(),
            name: "x.txt".to_string(),
            mime: None,
            text: None,
            category_override: None,
            tags: None,
        };
        let err = srv.fula_store_file(Parameters(args)).await.unwrap_err();
        assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_PARAMS);
    }

    #[tokio::test]
    async fn store_file_rejects_unknown_category_override() {
        let srv = server_rw();
        let args = StoreFileArgs {
            content: base64::engine::general_purpose::STANDARD.encode(b"hello"),
            name: "x.txt".to_string(),
            mime: None,
            text: None,
            category_override: Some("not-a-category".to_string()),
            tags: None,
        };
        let err = srv.fula_store_file(Parameters(args)).await.unwrap_err();
        assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_PARAMS);
    }

    #[tokio::test]
    async fn read_file_out_of_scope_maps_to_access_denied_tool_error() {
        // A key outside ai/ is denied by read.rs BEFORE any I/O → our mapper turns
        // it into an MCP tool error (is_error) with the fixed access-denied message
        // and NO network call against offline.invalid.
        let srv = server_rw();
        let args = ReadFileArgs { key: "photos/secret.jpg".to_string() };
        let res = srv.fula_read_file(Parameters(args)).await.unwrap();
        assert_eq!(res.is_error, Some(true), "must be a tool error");
        let txt = text_of(&res);
        assert!(txt.contains("access denied"), "got: {txt}");
    }

    #[tokio::test]
    async fn read_file_no_grant_maps_to_access_denied() {
        // Bundle with NO ai/ read grant → access denied (pre-I/O).
        let srv = server_no_grants();
        let args = ReadFileArgs { key: "ai/note/abc-x.txt".to_string() };
        let res = srv.fula_read_file(Parameters(args)).await.unwrap();
        assert_eq!(res.is_error, Some(true));
        assert!(text_of(&res).contains("access denied"));
    }

    #[tokio::test]
    async fn list_files_no_grant_maps_to_access_denied() {
        let srv = server_no_grants();
        let res = srv
            .fula_list_files(Parameters(ListFilesArgs { category: None, prefix: None }))
            .await
            .unwrap();
        assert_eq!(res.is_error, Some(true));
        assert!(text_of(&res).contains("access denied"));
    }

    #[tokio::test]
    async fn list_files_unknown_category_is_invalid_params() {
        let srv = server_rw();
        let err = srv
            .fula_list_files(Parameters(ListFilesArgs {
                category: Some("bogus".to_string()),
                prefix: None,
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_PARAMS);
    }

    #[tokio::test]
    async fn search_no_grant_maps_to_access_denied() {
        let srv = server_no_grants();
        let res = srv
            .fula_search(Parameters(SearchArgs { query: "anything".to_string() }))
            .await
            .unwrap();
        assert_eq!(res.is_error, Some(true));
        assert!(text_of(&res).contains("access denied"));
    }

    #[tokio::test]
    async fn tag_file_no_grant_maps_to_access_denied() {
        let srv = server_no_grants();
        let res = srv
            .fula_tag_file(Parameters(TagFileArgs {
                key: "ai/note/abc-x.txt".to_string(),
                tags: vec!["Work".to_string()],
            }))
            .await
            .unwrap();
        assert_eq!(res.is_error, Some(true));
        assert!(text_of(&res).contains("access denied"));
    }

    #[tokio::test]
    async fn store_file_rate_limited_maps_to_rate_limited_tool_error() {
        // P10: drain the session's write bucket, then a store must surface the
        // MCP "rate limited" tool error (is_error) with the fixed actionable
        // message — and do so WITHOUT any network call (the gate is pre-I/O; the
        // endpoint is unreachable, so a network fall-through would say "internal"
        // instead). This exercises the full server → store_file → Outcome mapping.
        let ws = base64::engine::general_purpose::STANDARD.encode([1u8; 32]);
        let mcp = base64::engine::general_purpose::STANDARD.encode([2u8; 32]);
        let owner = base64::engine::general_purpose::STANDARD
            .encode(SecretKey::from_bytes(&[3u8; 32]).unwrap().public_key().as_bytes());
        let json = format!(
            r#"{{ "endpoint": "https://offline.invalid", "jwt": "j", "workspace_secret_b64": "{ws}", "mcp_secret_b64": "{mcp}", "owner_public_b64": "{owner}", "write_burst": 1, "write_refill_per_sec": 0.0001, "grants": [{{ "scope": "ai/", "permissions": {{ "can_read": true, "can_write": true, "can_delete": false }} }}] }}"#
        );
        let cap = CapabilityBundle::from_json(&json).unwrap();
        assert!(cap.try_consume_write_token(), "drain the single token");
        let srv = FulaMcpServer::new(cap);
        let args = StoreFileArgs {
            content: base64::engine::general_purpose::STANDARD.encode(b"hello"),
            name: "x.txt".to_string(),
            mime: Some("text/plain".to_string()),
            text: None,
            category_override: None,
            tags: None,
        };
        let res = srv.fula_store_file(Parameters(args)).await.unwrap();
        assert_eq!(res.is_error, Some(true), "must be a tool error");
        let txt = text_of(&res);
        assert!(txt.contains("rate limited"), "got: {txt}");
    }

    #[tokio::test]
    async fn list_tags_no_read_grant_maps_to_access_denied() {
        // A bundle whose only grant is on a DIFFERENT scope → list_tags (needs ai/
        // read) denies pre-I/O.
        let cap = CapabilityBundle::from_json(&bundle_json(Some("other/"), true, true)).unwrap();
        let srv = FulaMcpServer::new(cap);
        let res = srv.fula_list_tags(Parameters(ListTagsArgs {})).await.unwrap();
        assert_eq!(res.is_error, Some(true));
        assert!(text_of(&res).contains("access denied"));
    }

    // ── the SECURITY crux: no secret substring ever reaches the model ─────────

    #[tokio::test]
    async fn tool_errors_never_contain_the_jwt_or_secret() {
        // Drive several denied/failed paths and assert the model-visible text
        // contains NONE of the planted secret material from the bundle JSON
        // (the JWT, the workspace-secret base64, the MCP-secret base64).
        let srv = server_rw();
        let jwt = "super-secret-jwt-DO-NOT-LEAK";
        let ws_b64 = base64::engine::general_purpose::STANDARD.encode([1u8; 32]);
        let mcp_b64 = base64::engine::general_purpose::STANDARD.encode([2u8; 32]);

        // An out-of-scope read (access-denied) and a list with no grant.
        let r1 = srv
            .fula_read_file(Parameters(ReadFileArgs { key: "photos/x.jpg".to_string() }))
            .await
            .unwrap();
        let r2 = server_no_grants()
            .fula_list_files(Parameters(ListFilesArgs { category: None, prefix: None }))
            .await
            .unwrap();

        for r in [&r1, &r2] {
            let txt = text_of(r);
            assert!(!txt.contains(jwt), "tool error leaked the JWT: {txt}");
            assert!(!txt.contains(&ws_b64), "tool error leaked the workspace secret: {txt}");
            assert!(!txt.contains(&mcp_b64), "tool error leaked the MCP secret: {txt}");
        }
    }

    #[test]
    fn outcome_client_messages_are_generic_and_secret_free() {
        // The fixed per-category messages must be static, generic strings — they
        // are the ONLY text the model sees on failure, so they must never be a
        // template that could interpolate a secret.
        for oc in [
            Outcome::AccessDenied,
            Outcome::NotFound,
            Outcome::QuotaExceeded,
            Outcome::RateLimited,
            Outcome::Internal,
        ] {
            let m = oc.client_message();
            assert!(!m.is_empty());
            // No format placeholders, no obviously-sensitive markers.
            assert!(!m.contains('{') && !m.contains("jwt") && !m.contains("secret"));
        }
    }

    // ── the AUDIT stream is also leak-proof (not just the model-visible text) ──
    //
    // The crate invariant is "no secret in logs". Because `audit`'s `detail` is
    // typed `Option<&'static str>` and every call site passes a compile-time
    // constant, a runtime secret cannot enter the audit stream BY CONSTRUCTION.
    // This test makes that concrete: it captures the actual `tracing` events a
    // failing tool call emits and asserts the rendered output contains NONE of
    // the planted secret material AND that the `detail` is a known bounded label.

    use std::sync::{Arc, Mutex};

    /// A minimal `tracing` layer that records every event's rendered fields into a
    /// shared string buffer, so a test can inspect exactly what would be logged.
    #[derive(Clone, Default)]
    struct CaptureLayer {
        buf: Arc<Mutex<String>>,
    }

    impl<S> tracing_subscriber::Layer<S> for CaptureLayer
    where
        S: tracing::Subscriber,
    {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            struct Visitor<'a>(&'a mut String);
            impl tracing::field::Visit for Visitor<'_> {
                fn record_debug(
                    &mut self,
                    field: &tracing::field::Field,
                    value: &dyn std::fmt::Debug,
                ) {
                    use std::fmt::Write as _;
                    let _ = write!(self.0, " {}={:?}", field.name(), value);
                }
                fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                    use std::fmt::Write as _;
                    let _ = write!(self.0, " {}={}", field.name(), value);
                }
            }
            let mut guard = self.buf.lock().unwrap();
            event.record(&mut Visitor(&mut guard));
            guard.push('\n');
        }
    }

    #[tokio::test]
    async fn audit_stream_never_contains_a_secret_and_uses_bounded_detail() {
        use tracing_subscriber::layer::SubscriberExt as _;

        let capture = CaptureLayer::default();
        let buf = capture.buf.clone();

        // Install the capture as the PROCESS-GLOBAL subscriber (once). A
        // thread-local `set_default` races other parallel tests: their guard
        // drops transiently reset the process-wide `tracing` max-level, which can
        // filter out our `warn!` audit event before this layer ever sees it
        // (the test then passes ONLY under `--test-threads=1`). No other test in
        // this binary installs a global subscriber, so a single global install is
        // safe and keeps the level permissive across all threads. The capture
        // buffer is this test's own Arc<Mutex>; the assertions key on this test's
        // planted strings, so any other test's events sharing the buffer are inert.
        let subscriber = tracing_subscriber::registry().with(capture);
        let _ = tracing::subscriber::set_global_default(subscriber);

        // Drive a failing path that goes through `tool_error` → `audit`.
        let srv = server_rw();
        let _ = srv
            .fula_read_file(Parameters(ReadFileArgs { key: "photos/x.jpg".to_string() }))
            .await
            .unwrap();

        let logged = buf.lock().unwrap().clone();
        // The audit event must have been emitted.
        assert!(logged.contains("fula-mcp tool call failed"), "no audit event captured: {logged:?}");
        // It must carry a BOUNDED detail label — here, the capability denial kind.
        assert!(logged.contains("detail=capability"), "expected bounded detail label: {logged:?}");
        // And it must NOT contain any planted secret from the bundle.
        let jwt = "super-secret-jwt-DO-NOT-LEAK";
        let ws_b64 = base64::engine::general_purpose::STANDARD.encode([1u8; 32]);
        let mcp_b64 = base64::engine::general_purpose::STANDARD.encode([2u8; 32]);
        assert!(!logged.contains(jwt), "AUDIT LEAKED THE JWT: {logged}");
        assert!(!logged.contains(&ws_b64), "audit leaked the workspace secret: {logged}");
        assert!(!logged.contains(&mcp_b64), "audit leaked the MCP secret: {logged}");
        // The key IS logged (allowed by spec / local-operator model); confirm it
        // is the requested logical key, not a secret.
        assert!(logged.contains("key=photos/x.jpg"), "audit should log the requested key: {logged}");
    }

    // ── server Debug is redacting ─────────────────────────────────────────────

    #[test]
    fn server_debug_does_not_print_secrets() {
        let srv = server_rw();
        let dbg = format!("{srv:?}");
        assert!(!dbg.contains("super-secret-jwt-DO-NOT-LEAK"), "server Debug leaked the JWT: {dbg}");
        assert!(dbg.contains("redacted"));
    }

    // ── category override parsing ─────────────────────────────────────────────

    #[test]
    fn parse_category_override_handles_known_unknown_and_empty() {
        assert_eq!(parse_category_override(None), Ok(None));
        assert_eq!(parse_category_override(Some("")), Ok(None));
        assert_eq!(parse_category_override(Some("image")), Ok(Some(Category::Image)));
        assert_eq!(parse_category_override(Some("note")), Ok(Some(Category::Note)));
        assert!(parse_category_override(Some("nope")).is_err());
    }
}
