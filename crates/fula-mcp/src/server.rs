//! # `server` — the stdio MCP server exposing the collaboration ops
//!
//! Wires the collaboration library ops into a **Model Context Protocol** server
//! over **stdio** (the transport Claude Code / Desktop launch a local MCP over).
//! The SDK is [`rmcp`].
//!
//! [`FulaMcpServer`] holds the per-session [`CapabilityBundle`] (loaded ONCE at
//! startup, in memory only — never logged) plus the rmcp [`ToolRouter`]. Each
//! `#[tool]` method parses its typed args, dispatches to the matching library op
//! against the group, maps the op's typed error onto an **MCP tool error**
//! ([`CallToolResult`] with `is_error = true`), and emits ONE structured audit
//! event (action + key + group + outcome + duration) — never content, never a
//! secret.
//!
//! ## The tools
//!
//! | tool                 | op                          | returns                          |
//! |----------------------|-----------------------------|----------------------------------|
//! | `fula_read_file`     | [`read_file`]               | `{ file_id, path, …, content_base64 }` |
//! | `fula_list_files`    | [`list_files`]              | `[ FileEntry … ]`                |
//! | `fula_search`        | [`search`]                  | `[ FileEntry … ]`                |
//! | `fula_store_file`    | [`store_file`]              | `{ file_id, path, category, … }` |
//! | `fula_create_folder` | [`create_folder`]           | `{ manifest_version, path }`     |
//! | `fula_remove_file`   | [`remove_file`]             | `{ manifest_version, path }`     |
//! | `fula_tag_file`      | [`tag_file`] (DEFERRED)      | unsupported tool error           |
//! | `fula_list_tags`     | [`list_tags`] (DEFERRED)     | unsupported tool error           |
//!
//! ## Error mapping — MCP tool errors, never a secret leak
//!
//! The model-visible error text is a FIXED generic message per [`Outcome`]
//! category ([`Outcome::client_message`]); a bounded error-kind *label* (never the
//! error `Display`) goes only to the stderr audit event. So no transport / token /
//! DEK substring can ever reach the model or the audit stream. Genuinely malformed
//! input (bad base64, unknown category, missing id+path) is a protocol-level
//! [`ErrorData::invalid_params`]; everything else is a tool outcome.

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
use crate::list::{list_files, search, FileEntry, ListFilter};
use crate::read::{read_file, ReadBy};
use crate::store::{create_folder, remove_file, store_file};
use crate::tags::{list_tags, tag_file};

/// The category of an operation outcome — drives BOTH the MCP error mapping and
/// the audit `outcome` field, keeping the two in lockstep.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    /// The op succeeded.
    Ok,
    /// The session is not authorized for the action (read-only session attempting
    /// a write, or a rejected write token).
    AccessDenied,
    /// The target object / manifest did not exist.
    NotFound,
    /// The user is over their storage quota / out of credits.
    QuotaExceeded,
    /// A write was rate-limited (the session's local write bucket).
    RateLimited,
    /// The operation is not supported yet in collaboration mode (e.g. tags).
    Unsupported,
    /// Any other failure (HTTP / crypto / serialize).
    Internal,
}

impl Outcome {
    fn label(self) -> &'static str {
        match self {
            Outcome::Ok => "ok",
            Outcome::AccessDenied => "access_denied",
            Outcome::NotFound => "not_found",
            Outcome::QuotaExceeded => "quota_exceeded",
            Outcome::RateLimited => "rate_limited",
            Outcome::Unsupported => "unsupported",
            Outcome::Internal => "internal_error",
        }
    }

    /// The FIXED, model-visible error message — carries NO detail from any
    /// underlying error's Display, so no token / DEK / transport substring leaks.
    fn client_message(self) -> &'static str {
        match self {
            Outcome::Ok => "ok",
            Outcome::AccessDenied => {
                "access denied: this session is read-only or its write authorization was rejected"
            }
            Outcome::NotFound => "not found: no such file in this collaboration group",
            Outcome::QuotaExceeded => {
                "quota exceeded: the user is over their storage quota or out of credits; \
                 add FULA credits and retry"
            }
            Outcome::RateLimited => {
                "rate limited: too many writes in a short period; slow down and retry shortly"
            }
            Outcome::Unsupported => {
                "unsupported: this operation is not yet available in collaboration mode (deferred)"
            }
            Outcome::Internal => "internal error: the storage operation could not be completed",
        }
    }
}

// ── argument structs ──────────────────────────────────────────────────────────

/// Args for [`fula_read_file`](FulaMcpServer::fula_read_file). Provide `file_id`
/// (preferred, unambiguous) OR `path`.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct ReadFileArgs {
    /// The file's UUID (as returned by `fula_store_file` / `fula_list_files`).
    #[serde(default)]
    pub file_id: Option<String>,
    /// A logical path (e.g. `/notes/memo.txt`). Used only if `file_id` is absent.
    #[serde(default)]
    pub path: Option<String>,
}

/// Args for [`fula_list_files`](FulaMcpServer::fula_list_files).
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct ListFilesArgs {
    /// Keep only entries strictly under this folder (e.g. `/notes`). Omit for the
    /// whole group.
    #[serde(default)]
    pub folder: Option<String>,
    /// Keep only files of this category (`link`, `note`, `screenshot`, `image`,
    /// `video`, `audio`, `document`, `file`, `other`).
    #[serde(default)]
    pub category: Option<String>,
    /// Include folder markers in the result (default `true`, so a tree can be
    /// built).
    #[serde(default)]
    pub include_directories: Option<bool>,
}

/// Args for [`fula_search`](FulaMcpServer::fula_search).
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct SearchArgs {
    /// Substring to match against file names + paths (case-insensitive).
    pub query: String,
}

/// Args for [`fula_store_file`](FulaMcpServer::fula_store_file).
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct StoreFileArgs {
    /// The file bytes to store, **base64-encoded** (standard alphabet). Encrypted
    /// client-side under a fresh per-file key before upload.
    pub content: String,
    /// The file name (drives categorization + the display name).
    pub name: String,
    /// Explicit MIME content type, if known (e.g. `image/png`).
    #[serde(default)]
    pub mime: Option<String>,
    /// Optional text payload that biases Link/Note classification.
    #[serde(default)]
    pub text: Option<String>,
    /// Optional folder to place the file in (e.g. `/notes`). Omit for the group
    /// root.
    #[serde(default)]
    pub subfolder_path: Option<String>,
    /// Force a category instead of auto-classifying.
    #[serde(default)]
    pub category_override: Option<String>,
}

/// Args for [`fula_create_folder`](FulaMcpServer::fula_create_folder).
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct CreateFolderArgs {
    /// The folder path to create (e.g. `/projects/alpha`).
    pub path: String,
}

/// Args for [`fula_remove_file`](FulaMcpServer::fula_remove_file).
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct RemoveFileArgs {
    /// The UUID of the file to remove (tombstoned in the manifest; never deleted
    /// from storage).
    pub file_id: String,
}

/// Args for [`fula_tag_file`](FulaMcpServer::fula_tag_file).
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct TagFileArgs {
    /// The UUID of the file to tag.
    pub file_id: String,
    /// One or more tag names.
    pub tags: Vec<String>,
}

/// Args for [`fula_list_tags`](FulaMcpServer::fula_list_tags) — none.
#[derive(Debug, Default, Deserialize, Serialize, JsonSchema)]
pub struct ListTagsArgs {}

// ── result projections (what the model sees) ──────────────────────────────────

/// `fula_read_file` result.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct ReadFileResult {
    /// The file's UUID.
    pub file_id: String,
    /// The display filename.
    pub file_name: String,
    /// The derived logical path.
    pub path: String,
    /// The recorded MIME type, if any.
    pub content_type: Option<String>,
    /// The on-wire encoding (`collab` / `fula`).
    pub enc_type: String,
    /// The file's plaintext bytes, base64-encoded (standard alphabet).
    pub content_base64: String,
}

/// One row in `fula_list_files` / `fula_search`.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct FileEntryDto {
    /// The entry's UUID.
    pub file_id: String,
    /// The display filename (or folder leaf).
    pub file_name: String,
    /// The derived logical path.
    pub path: String,
    /// Whether this entry is a folder.
    pub is_directory: bool,
    /// The (re-derived, best-effort) category name.
    pub category: String,
    /// The recorded MIME type, if any.
    pub content_type: Option<String>,
    /// The on-wire encoding (`collab` / `fula`).
    pub enc_type: String,
    /// The recorded size in bytes.
    pub size: i64,
    /// Base64 public key of whoever added the entry.
    pub added_by_public_key: String,
    /// The raw ISO-8601 `addedAt` string.
    pub added_at: String,
    /// `added_at` as Unix seconds, best-effort.
    pub modified_at: Option<i64>,
}

impl From<&FileEntry> for FileEntryDto {
    fn from(e: &FileEntry) -> Self {
        Self {
            file_id: e.file_id.clone(),
            file_name: e.file_name.clone(),
            path: e.path.clone(),
            is_directory: e.is_directory,
            category: e.category.name().to_string(),
            content_type: e.content_type.clone(),
            enc_type: e.enc_type.clone(),
            size: e.size,
            added_by_public_key: e.added_by_public_key.clone(),
            added_at: e.added_at.clone(),
            modified_at: e.modified_at,
        }
    }
}

/// `fula_store_file` result. Omits the internal `bucket`/`storage_key` (collab
/// reads address the file by id).
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct StoreFileResult {
    /// The new file's UUID (its handle for read/remove).
    pub file_id: String,
    /// The stored display filename.
    pub file_name: String,
    /// The file's logical path.
    pub path: String,
    /// The classified category name.
    pub category: String,
    /// The recorded MIME type, if any.
    pub content_type: Option<String>,
    /// The plaintext size in bytes.
    pub size: i64,
    /// The manifest version after the commit.
    pub manifest_version: i64,
}

/// `fula_create_folder` / `fula_remove_file` result.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct ManifestMutationResult {
    /// The manifest version after the commit.
    pub manifest_version: i64,
    /// The logical path affected, if known.
    pub path: Option<String>,
}

/// The stdio MCP server. Holds the in-memory per-session capability bundle and the
/// rmcp tool router.
#[derive(Clone)]
pub struct FulaMcpServer {
    cap: std::sync::Arc<CapabilityBundle>,
    #[allow(dead_code)]
    tool_router: ToolRouter<Self>,
}

impl std::fmt::Debug for FulaMcpServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FulaMcpServer")
            .field("cap", &"<CapabilityBundle: redacted>")
            .finish()
    }
}

#[tool_router]
impl FulaMcpServer {
    /// Build the server around an already-loaded [`CapabilityBundle`].
    pub fn new(cap: CapabilityBundle) -> Self {
        Self {
            cap: std::sync::Arc::new(cap),
            tool_router: Self::tool_router(),
        }
    }

    /// Read a file from the collaboration group, by `file_id` or `path`.
    #[tool(
        description = "Read a file from the collaboration group by its file_id \
        (preferred) or logical path. The bytes are fetched and decrypted \
        client-side and returned base64-encoded."
    )]
    pub async fn fula_read_file(
        &self,
        Parameters(args): Parameters<ReadFileArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let started = Instant::now();
        let by = match (
            args.file_id.as_deref().filter(|s| !s.trim().is_empty()),
            args.path.as_deref().filter(|s| !s.trim().is_empty()),
        ) {
            (Some(id), _) => ReadBy::FileId(id.to_string()),
            (None, Some(p)) => ReadBy::Path(p.to_string()),
            (None, None) => {
                return Err(ErrorData::invalid_params(
                    "provide `file_id` or `path`",
                    None,
                ))
            }
        };
        let audit_key = match &by {
            ReadBy::FileId(id) => id.clone(),
            ReadBy::Path(p) => p.clone(),
        };

        match read_file(&self.cap, &by).await {
            Ok(out) => {
                let content_base64 =
                    base64::engine::general_purpose::STANDARD.encode(out.bytes.as_ref());
                self.audit_ok("fula_read_file", Some(&audit_key), started);
                Ok(json_ok(&ReadFileResult {
                    file_id: out.file_id,
                    file_name: out.file_name,
                    path: out.path,
                    content_type: out.content_type,
                    enc_type: out.enc_type,
                    content_base64,
                }))
            }
            Err(e) => {
                use crate::read::ReadError;
                let (oc, kind) = match &e {
                    ReadError::NotFound(_) => (Outcome::NotFound, "not_found"),
                    ReadError::Collab(c) if is_collab_not_found(c) => (Outcome::NotFound, "not_found"),
                    ReadError::InvalidInput(_) => (Outcome::NotFound, "invalid_input"),
                    ReadError::Collab(_) => (Outcome::Internal, "collab"),
                    ReadError::Capability(_) => (Outcome::Internal, "capability"),
                    ReadError::Share(_) => (Outcome::Internal, "share"),
                    ReadError::Crypto(_) => (Outcome::Internal, "crypto"),
                };
                Ok(self.tool_error("fula_read_file", Some(&audit_key), oc, started, kind))
            }
        }
    }

    /// List the group's files (and folders), optionally filtered.
    #[tool(
        description = "List the files and folders in the collaboration group, \
        optionally filtered by a folder prefix and/or a category. Folder markers are \
        returned with is_directory=true so a tree can be built."
    )]
    pub async fn fula_list_files(
        &self,
        Parameters(args): Parameters<ListFilesArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let started = Instant::now();
        let category = match parse_category(args.category.as_deref()) {
            Ok(c) => c,
            Err(()) => {
                return Err(ErrorData::invalid_params(
                    "`category` is not a known category",
                    None,
                ))
            }
        };
        let filter = ListFilter {
            folder: args.folder.clone(),
            category,
            include_directories: args.include_directories.unwrap_or(true),
        };
        match list_files(&self.cap, &filter).await {
            Ok(rows) => {
                self.audit_ok("fula_list_files", args.folder.as_deref(), started);
                let dtos: Vec<FileEntryDto> = rows.iter().map(FileEntryDto::from).collect();
                Ok(json_ok(&dtos))
            }
            Err(e) => Ok(self.map_list_error("fula_list_files", args.folder.as_deref(), e, started)),
        }
    }

    /// Search the group's files by name / path substring.
    #[tool(
        description = "Search the collaboration group's files by filename or path \
        substring (case-insensitive). Returns the same row shape as fula_list_files."
    )]
    pub async fn fula_search(
        &self,
        Parameters(args): Parameters<SearchArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let started = Instant::now();
        match search(&self.cap, &args.query).await {
            Ok(rows) => {
                self.audit_ok("fula_search", None, started);
                let dtos: Vec<FileEntryDto> = rows.iter().map(FileEntryDto::from).collect();
                Ok(json_ok(&dtos))
            }
            Err(e) => Ok(self.map_list_error("fula_search", None, e, started)),
        }
    }

    /// Store a file into the collaboration group.
    #[tool(
        description = "Store a file into the collaboration group. The bytes are \
        provided base64-encoded and encrypted client-side before upload. Optionally \
        place it in a subfolder. Returns the new file_id, path, and category."
    )]
    pub async fn fula_store_file(
        &self,
        Parameters(args): Parameters<StoreFileArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let started = Instant::now();
        let content = match base64::engine::general_purpose::STANDARD.decode(args.content.as_bytes())
        {
            Ok(bytes) => Bytes::from(bytes),
            Err(_) => {
                return Err(ErrorData::invalid_params("`content` must be valid base64", None))
            }
        };
        let category_override = match parse_category(args.category_override.as_deref()) {
            Ok(c) => c,
            Err(()) => {
                return Err(ErrorData::invalid_params(
                    "`category_override` is not a known category",
                    None,
                ))
            }
        };

        match store_file(
            &self.cap,
            content,
            &args.name,
            args.mime.as_deref(),
            args.text.as_deref(),
            args.subfolder_path.as_deref(),
            category_override,
        )
        .await
        {
            Ok(o) => {
                self.audit_ok("fula_store_file", Some(&o.path), started);
                Ok(json_ok(&StoreFileResult {
                    file_id: o.file_id,
                    file_name: o.file_name,
                    path: o.path,
                    category: o.category.name().to_string(),
                    content_type: o.content_type,
                    size: o.size,
                    manifest_version: o.manifest_version,
                }))
            }
            Err(e) => self.map_store_error("fula_store_file", Some(&args.name), e, started),
        }
    }

    /// Create a folder in the collaboration group.
    #[tool(
        description = "Create a folder (directory marker) in the collaboration \
        group, e.g. /projects/alpha. Folders organize files in the derived tree."
    )]
    pub async fn fula_create_folder(
        &self,
        Parameters(args): Parameters<CreateFolderArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let started = Instant::now();
        match create_folder(&self.cap, &args.path).await {
            Ok(m) => {
                self.audit_ok("fula_create_folder", Some(&args.path), started);
                Ok(json_ok(&ManifestMutationResult {
                    manifest_version: m.manifest_version,
                    path: m.path,
                }))
            }
            Err(e) => self.map_store_error("fula_create_folder", Some(&args.path), e, started),
        }
    }

    /// Remove a file from the collaboration group (tombstone only).
    #[tool(
        description = "Remove a file from the collaboration group by its file_id. \
        The file is tombstoned in the manifest (it stops appearing in listings); the \
        stored bytes are never deleted, so other group members are unaffected."
    )]
    pub async fn fula_remove_file(
        &self,
        Parameters(args): Parameters<RemoveFileArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let started = Instant::now();
        match remove_file(&self.cap, &args.file_id).await {
            Ok(m) => {
                self.audit_ok("fula_remove_file", Some(&args.file_id), started);
                Ok(json_ok(&ManifestMutationResult {
                    manifest_version: m.manifest_version,
                    path: m.path,
                }))
            }
            Err(e) => self.map_store_error("fula_remove_file", Some(&args.file_id), e, started),
        }
    }

    /// Tag a file — DEFERRED in collaboration mode.
    #[tool(
        description = "Apply tags to a file. NOTE: tagging is not yet supported in \
        collaboration mode (deferred) and currently returns an unsupported error."
    )]
    pub async fn fula_tag_file(
        &self,
        Parameters(args): Parameters<TagFileArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let started = Instant::now();
        match tag_file(&self.cap, &args.file_id, &args.tags) {
            Ok(()) => Ok(json_ok(&serde_json::json!({ "ok": true }))),
            Err(_) => Ok(self.tool_error(
                "fula_tag_file",
                Some(&args.file_id),
                Outcome::Unsupported,
                started,
                "deferred",
            )),
        }
    }

    /// List tags — DEFERRED in collaboration mode.
    #[tool(
        description = "List tags. NOTE: tagging is not yet supported in \
        collaboration mode (deferred) and currently returns an unsupported error."
    )]
    pub async fn fula_list_tags(
        &self,
        Parameters(_args): Parameters<ListTagsArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let started = Instant::now();
        match list_tags(&self.cap) {
            Ok(()) => Ok(json_ok(&serde_json::json!([]))),
            Err(_) => {
                Ok(self.tool_error("fula_list_tags", None, Outcome::Unsupported, started, "deferred"))
            }
        }
    }
}

impl FulaMcpServer {
    /// Emit a success audit event.
    fn audit_ok(&self, action: &str, key: Option<&str>, started: Instant) {
        audit(action, key, self.cap.group_id(), Outcome::Ok, started, None);
    }

    /// Build an MCP tool error + emit the failure audit event (group as scope).
    fn tool_error(
        &self,
        action: &str,
        key: Option<&str>,
        outcome: Outcome,
        started: Instant,
        error_kind: &'static str,
    ) -> CallToolResult {
        audit(action, key, self.cap.group_id(), outcome, started, Some(error_kind));
        CallToolResult::error(vec![Content::text(outcome.client_message())])
    }

    /// Map a [`crate::list::ListError`] onto a tool error.
    fn map_list_error(
        &self,
        action: &str,
        key: Option<&str>,
        err: crate::list::ListError,
        started: Instant,
    ) -> CallToolResult {
        use crate::list::ListError;
        let (oc, kind) = match &err {
            ListError::Collab(c) if is_collab_not_found(c) => (Outcome::NotFound, "not_found"),
            ListError::Collab(_) => (Outcome::Internal, "collab"),
        };
        self.tool_error(action, key, oc, started, kind)
    }

    /// Map a [`crate::store::StoreError`] onto a tool error (or an `invalid_params`
    /// protocol error for a genuinely malformed input).
    fn map_store_error(
        &self,
        action: &str,
        key: Option<&str>,
        err: crate::store::StoreError,
        started: Instant,
    ) -> Result<CallToolResult, ErrorData> {
        use crate::collab::CollabError;
        use crate::store::StoreError;
        let (oc, kind) = match &err {
            // A bad filename / subfolder path is a malformed request — surface its
            // (secret-free) message as a protocol error.
            StoreError::InvalidInput(msg) => {
                audit(action, key, self.cap.group_id(), Outcome::Internal, started, Some("invalid_input"));
                return Err(ErrorData::invalid_params(msg.clone(), None));
            }
            StoreError::ManifestMissing => (Outcome::NotFound, "manifest_missing"),
            StoreError::RateLimited => (Outcome::RateLimited, "rate_limited"),
            StoreError::QuotaExceeded => (Outcome::QuotaExceeded, "quota_exceeded"),
            StoreError::Serialize(_) => (Outcome::Internal, "serialize"),
            StoreError::Collab(CollabError::WriteNotConfigured) => {
                (Outcome::AccessDenied, "write_not_configured")
            }
            StoreError::Collab(CollabError::Auth { .. }) => (Outcome::AccessDenied, "auth"),
            StoreError::Collab(c) if is_collab_not_found(c) => (Outcome::NotFound, "not_found"),
            StoreError::Collab(_) => (Outcome::Internal, "collab"),
        };
        Ok(self.tool_error(action, key, oc, started, kind))
    }
}

#[tool_handler]
impl ServerHandler for FulaMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_instructions(
                "Fula collaboration-group tools. Read, list, search, store, and \
                 organize (create_folder / remove_file) files in a shared, \
                 end-to-end-encrypted collaboration group. Files are addressed by a \
                 file_id (or logical path); file bytes are exchanged base64-encoded. \
                 Removing a file tombstones it in the group manifest — it is never \
                 deleted from storage. Tagging is deferred (not yet supported).",
            )
    }
}

// ── shared helpers ────────────────────────────────────────────────────────────

/// Is this collab error a not-found?
fn is_collab_not_found(err: &crate::collab::CollabError) -> bool {
    matches!(err, crate::collab::CollabError::NotFound(_))
}

/// Build a successful [`CallToolResult`] whose single content block is the
/// JSON-serialized `value`.
fn json_ok<T: Serialize>(value: &T) -> CallToolResult {
    match serde_json::to_string(value) {
        Ok(s) => CallToolResult::success(vec![Content::text(s)]),
        Err(_) => CallToolResult::error(vec![Content::text(Outcome::Internal.client_message())]),
    }
}

/// Parse an optional category name into a [`Category`]. `None`/empty → `Ok(None)`;
/// an unknown name → `Err(())`.
fn parse_category(s: Option<&str>) -> Result<Option<Category>, ()> {
    match s.filter(|s| !s.is_empty()) {
        None => Ok(None),
        Some(name) => Category::from_name(name).map(Some).ok_or(()),
    }
}

/// Emit ONE structured audit event. `detail` is always a BOUNDED static label
/// (never an error Display), so no secret can enter the audit stream. Never logs
/// content, the link secret, the write token, or any DEK.
fn audit(
    action: &str,
    key: Option<&str>,
    group: &str,
    outcome: Outcome,
    started: Instant,
    detail: Option<&'static str>,
) {
    let duration_ms = started.elapsed().as_millis() as u64;
    match outcome {
        Outcome::Ok => tracing::info!(
            action,
            key = key.unwrap_or(""),
            group,
            outcome = outcome.label(),
            duration_ms,
            detail = detail.unwrap_or(""),
            "fula-mcp tool call"
        ),
        _ => tracing::warn!(
            action,
            key = key.unwrap_or(""),
            group,
            outcome = outcome.label(),
            duration_ms,
            detail = detail.unwrap_or(""),
            "fula-mcp tool call failed"
        ),
    }
}

/// Load the [`CapabilityBundle`] from the environment and run the MCP server over
/// **stdio** until the client disconnects. The bundle is read ONCE and held in
/// memory — never written to disk, never logged.
pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let cap = CapabilityBundle::from_env()?;
    tracing::info!(
        webui_base = cap.webui_base(),
        group = cap.group_id(),
        mcp_id = cap.mcp_fula_id(),
        "fula-mcp: collaboration bundle loaded; starting stdio MCP server"
    );
    serve_stdio(cap).await
}

/// Run the server over stdio for an already-built bundle.
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
    use crate::identity::McpIdentity;
    use fula_crypto::{sharing::ShareBuilder, DekKey, KekKeyPair};

    fn temp_identity_path(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "fula_mcp_server_test_{}_{}_{:?}",
            tag,
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("mcp_identity.key")
    }

    /// Build a server whose bundle targets an UNREACHABLE endpoint (so any
    /// accidental network I/O fails loudly, distinct from a no-I/O denial), with an
    /// optional write token. Plants a recognizable secret write token for the
    /// leak test.
    fn server_with(tag: &str, write_token: Option<&str>) -> FulaMcpServer {
        let id_path = temp_identity_path(tag);
        let _ = std::fs::remove_file(&id_path);
        let identity = McpIdentity::load_or_generate(&id_path).unwrap();
        let owner = KekKeyPair::generate();
        let dek = DekKey::from_bytes(&[5u8; 32]).unwrap();
        let token = ShareBuilder::new(&owner, identity.public_key(), &dek)
            .path_scope("/collab/g")
            .build()
            .unwrap();
        let wrapped = serde_json::to_string(&token).unwrap();
        let wt = match write_token {
            Some(t) => format!(r#","collab_write_token":"{t}""#),
            None => String::new(),
        };
        let json = format!(
            r#"{{"webui_base":"https://offline.invalid","group_id":"group-xyz","manifest_bucket":"fula-metadata","manifest_key":"m/group-xyz.json","wrapped_link_secret":{wrapped:?},"identity_path":{id:?}{wt}}}"#,
            id = id_path.to_str().unwrap(),
        );
        FulaMcpServer::new(CapabilityBundle::from_json(&json).unwrap())
    }

    fn text_of(result: &CallToolResult) -> String {
        result
            .content
            .first()
            .and_then(|c| c.as_text())
            .map(|t| t.text.clone())
            .unwrap_or_default()
    }

    /// An error result carries exactly the fixed [`Outcome`] message; a success
    /// result carries JSON. Comparing the text to the expected message is therefore
    /// sufficient to prove the error path without depending on the rmcp
    /// `is_error` field shape.
    fn assert_error_msg(result: &CallToolResult, expected: &str) {
        assert_eq!(text_of(result), expected);
    }

    #[tokio::test]
    async fn store_without_write_token_is_access_denied_no_io() {
        // A read-only bundle: store must fail at the write-token gate BEFORE any I/O
        // (the endpoint is unreachable, so an I/O attempt would error differently).
        let srv = server_with("ro_store", None);
        let content = base64::engine::general_purpose::STANDARD.encode(b"hello");
        let res = srv
            .fula_store_file(Parameters(StoreFileArgs {
                content,
                name: "a.txt".into(),
                mime: None,
                text: None,
                subfolder_path: None,
                category_override: None,
            }))
            .await
            .unwrap();
        assert_error_msg(&res, Outcome::AccessDenied.client_message());
    }

    #[tokio::test]
    async fn create_folder_and_remove_without_write_token_denied_no_io() {
        let srv = server_with("ro_folder", None);
        let res = srv
            .fula_create_folder(Parameters(CreateFolderArgs { path: "/x".into() }))
            .await
            .unwrap();
        assert_error_msg(&res, Outcome::AccessDenied.client_message());

        let res2 = srv
            .fula_remove_file(Parameters(RemoveFileArgs {
                file_id: "id-1".into(),
            }))
            .await
            .unwrap();
        assert_error_msg(&res2, Outcome::AccessDenied.client_message());
    }

    #[tokio::test]
    async fn store_bad_base64_is_invalid_params() {
        let srv = server_with("badb64", Some("wt"));
        let err = srv
            .fula_store_file(Parameters(StoreFileArgs {
                content: "!!!not base64!!!".into(),
                name: "a.txt".into(),
                mime: None,
                text: None,
                subfolder_path: None,
                category_override: None,
            }))
            .await
            .unwrap_err();
        assert!(err.message.contains("base64"));
    }

    #[tokio::test]
    async fn unknown_category_override_is_invalid_params() {
        let srv = server_with("badcat", Some("wt"));
        let content = base64::engine::general_purpose::STANDARD.encode(b"x");
        let err = srv
            .fula_store_file(Parameters(StoreFileArgs {
                content,
                name: "a.txt".into(),
                mime: None,
                text: None,
                subfolder_path: None,
                category_override: Some("not-a-category".into()),
            }))
            .await
            .unwrap_err();
        assert!(err.message.contains("category"));
    }

    #[tokio::test]
    async fn read_without_id_or_path_is_invalid_params() {
        let srv = server_with("noidpath", None);
        let err = srv
            .fula_read_file(Parameters(ReadFileArgs {
                file_id: None,
                path: None,
            }))
            .await
            .unwrap_err();
        assert!(err.message.contains("file_id") || err.message.contains("path"));
    }

    #[tokio::test]
    async fn tag_tools_report_unsupported() {
        let srv = server_with("tags", Some("wt"));
        let res = srv
            .fula_tag_file(Parameters(TagFileArgs {
                file_id: "id".into(),
                tags: vec!["a".into()],
            }))
            .await
            .unwrap();
        assert_error_msg(&res, Outcome::Unsupported.client_message());

        let res2 = srv
            .fula_list_tags(Parameters(ListTagsArgs {}))
            .await
            .unwrap();
        assert_error_msg(&res2, Outcome::Unsupported.client_message());
    }

    #[tokio::test]
    async fn store_failure_message_never_leaks_the_write_token() {
        // With a write token, store passes the gate and attempts a fetch to the
        // unreachable endpoint → an Internal tool error. The model-visible text is
        // the fixed generic message and must contain NONE of the secret token.
        let secret = "SUPER-SECRET-WRITE-TOKEN-DO-NOT-LEAK";
        let srv = server_with("leak", Some(secret));
        let content = base64::engine::general_purpose::STANDARD.encode(b"hello");
        let res = srv
            .fula_store_file(Parameters(StoreFileArgs {
                content,
                name: "a.txt".into(),
                mime: None,
                text: None,
                subfolder_path: None,
                category_override: None,
            }))
            .await
            .unwrap();
        let text = text_of(&res);
        assert!(!text.contains(secret), "the write token must never reach the model");
        assert_eq!(text, Outcome::Internal.client_message());
    }

    #[test]
    fn get_info_advertises_tools_and_instructions() {
        let srv = server_with("info", None);
        let info = srv.get_info();
        assert!(info.capabilities.tools.is_some());
        assert!(info.instructions.unwrap().contains("collaboration"));
    }
}
