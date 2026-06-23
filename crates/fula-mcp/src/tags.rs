//! # `tag_file` + `list_tags` — the AI's tag writer, in FxFiles' native format (P8)
//!
//! Phase 8 builds the two tag operations as plain async library functions (the
//! MCP-protocol wiring is P9). Their entire value is **format fidelity**: the
//! AI writes a [`TagCloudMetadata`] document whose JSON byte-shape is identical
//! to what FxFiles' `TagStorageService` writes, so FxFiles can adopt the AI's
//! tags with a straight additive-by-id merge — no translation layer.
//!
//! ## The model (locked in by the P2 finding — same as files)
//!
//! The AI **cannot** write the user's master-key-encrypted `tag-metadata-v8`
//! bucket (that bucket is encrypted under the user's master KEK, which the AI
//! never holds). So tags follow the exact model P5 established for files: the AI
//! writes its tags into **its OWN workspace** — the [`WORKSPACE_BUCKET`],
//! encrypted under the dedicated **workspace secret** (which FxFiles also knows;
//! see [`crate::capability`]) — in the EXACT [`TagCloudMetadata`] JSON the app
//! uses. FxFiles later reads that document and adopts the tags.
//!
//! This is NOT the user's real per-user tag document. The app's
//! `restoreFromCloud()` reads `tag-metadata`(-v8) at `.fula/tags/{userId}.json`;
//! the AI's document lives at a DIFFERENT (bucket, key) (see
//! [`tag_metadata_key`]) and is decrypted with the workspace secret. P14
//! (FxFiles adoption) must read THIS location and feed the decoded
//! `TagCloudMetadata` into the same additive-by-id merge — see the
//! [crate-level P14 note](#what-p9-and-p14-need-from-this).
//!
//! ## The workspace tag-metadata location (the convention)
//!
//! - **Bucket:** [`WORKSPACE_BUCKET`] (`fula-ai-workspace`) — the AI's own
//!   bucket, reused from P5 so no new gateway-scoped bucket is introduced.
//! - **Key:** [`TAG_METADATA_KEY`] = `ai/tag-metadata/ai-workspace.json`. It
//!   lives UNDER the `ai/` prefix on purpose: the P3 scope gate
//!   ([`CapabilityBundle::assert_in_scope`]) admits a key only if its first path
//!   segment is `ai`, so the recognizable-but-out-of-scope `.fula/tags/…` form
//!   the app uses would be DENIED here. `ai/tag-metadata/…` is segment-contained
//!   in the `ai/` grant and so reuses the proven P5/P6 `ai/` write+read authority
//!   verbatim.
//!
//! ## `tag_file` — read-modify-write of one JSON document
//!
//! [`tag_file`] loads the document (or starts empty on NotFound), upserts a
//! [`FileTag`] per requested name (case-insensitively deduped; a brand-new tag
//! gets a fresh uuid + the [`DEFAULT_TAG_COLOR`]), adds a [`TaggedFile`]
//! association per (tag, file) keyed by the stored file's logical `key` as
//! `remoteKey`, recomputes each touched tag's `fileCount`, bumps `updatedAt`,
//! and writes the document back. The write is **scope-gated BEFORE any I/O**:
//! `assert_in_scope(TAG_METADATA_KEY, "ai", Write)` — a bundle lacking the `ai/`
//! write grant is rejected with no network call.
//!
//! ### Concurrency (documented limitation, matches the app)
//!
//! `tag_file` is a last-writer-wins read-modify-write of ONE object; there is no
//! compare-and-swap (the SDK exposes no conditional-PUT on this path). Two
//! concurrent `tag_file` calls can drop the losing call's additions. This is the
//! same property FxFiles' own `syncToCloud()` has, and it is benign here: the
//! merge is additive-by-id and the operation is idempotent by tag-name and by
//! (`tagId`, `remoteKey`), so a lost update loses at most some associations,
//! recoverable by re-tagging. P9/P-future may add a CAS if a use-case needs it.
//!
//! ### Re-writing a fixed key is safe in the forest
//!
//! Unlike P5/P6/P7 (which always wrote fresh-uuid keys), `tag_file` overwrites
//! ONE fixed logical key on every call. This is correct: the SDK forest's
//! `upsert_file` is keyed by the LOGICAL path and **replaces** an existing entry
//! (the directory file-list also de-dups), so `list_files_from_forest` /
//! `get_object_flat` always resolve exactly one current entry. (Each write does
//! mint a fresh per-file DEK → a fresh obfuscated `storage_key`, so the PRIOR
//! ciphertext is left orphaned at its old storage key — harmless dead data, the
//! same property P5's bucket already has.)
//!
//! ## Fidelity choices (verified against the Dart `toJson`/`fromJson`)
//!
//! - **camelCase keys**, fields in the SAME order the Dart `toJson` emits.
//! - **Nullable association fields emit explicit `null`** (`Option<String>`
//!   WITHOUT `skip_serializing_if`), exactly as Dart's `jsonEncode` of a map
//!   containing `'localPath': null` emits `"localPath":null`. (Parsing tolerates
//!   either, but byte-fidelity wants the null present.)
//! - **Tolerant deserialize**: `fileCount` and `version` default if absent
//!   (Dart's `fromJson` does `?? 0` / `?? '1.0'`), so a document the app wrote is
//!   read without error. We deliberately do NOT `deny_unknown_fields` (forward
//!   compatibility with app-added fields).
//! - **Timestamps** are RFC3339 / ISO-8601 strings with millisecond precision
//!   and a `Z` suffix (e.g. `2026-06-20T12:34:56.789Z`). The app parses these
//!   with the liberal `DateTime.parse`, so exact byte-parity with Dart's
//!   `toIso8601String()` microsecond/offset quirks is unnecessary — semantic
//!   fidelity suffices.

use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::capability::{CapabilityBundle, CapabilityError, Permission};
use crate::retry::with_refresh_retry;
use crate::store::{WORKSPACE_BUCKET, WORKSPACE_KEY_PREFIX};

/// The logical key the AI's tag-metadata document lives at, inside
/// [`WORKSPACE_BUCKET`].
///
/// It is UNDER the `ai/` prefix so the P3 scope gate admits it (the gate keys on
/// the first path segment being `ai`). This is deliberately NOT the app's
/// `.fula/tags/{userId}.json` — that path's first segment is `.fula`, which the
/// `ai/` grant does not cover, and in any case the AI does not write the user's
/// per-user document. P14 reads THIS key from THIS bucket with the workspace
/// secret.
pub const TAG_METADATA_KEY: &str = "ai/tag-metadata/ai-workspace.json";

/// The default ARGB color assigned to a tag the AI creates.
///
/// `0xFF1E88E5` is the "Blue" entry of FxFiles' `TagColors.presetColors`
/// palette (`file_tag.dart`), so an adopted tag shows a palette-consistent
/// color. The app's own `getRandomColor()` is time-seeded (nondeterministic);
/// we deliberately pick ONE fixed, reproducible palette color instead — the user
/// can recolor in-app afterward. In JSON this serializes as the decimal
/// `0xFF1E88E5` = `4280191205`, exactly as a Dart `int` would.
pub const DEFAULT_TAG_COLOR: i64 = 0xFF1E_88E5;

/// The `userId` recorded inside the document when the bundle does not carry one.
///
/// The AI writes to its OWN workspace, not the user's per-user document, so this
/// field is informational: the app's adoption merges purely by tag/file `id`
/// (its `restoreFromCloud` does `if (box.containsKey(id)) continue;` and never
/// gates on `metadata.userId`). When the bundle DOES carry a `user_id` we use it
/// for full fidelity; otherwise this honest marker makes clear the document
/// originated in the AI workspace.
pub const FALLBACK_USER_ID: &str = "ai-workspace";

/// The document `version`, mirroring the Dart `TagCloudMetadata.version` default.
const TAG_METADATA_VERSION: &str = "1.0";

/// A user-created tag — mirrors FxFiles' `FileTag` (`file_tag.dart`).
///
/// Field names + order match the Dart `toJson` exactly (`id`, `name`,
/// `colorValue`, `createdAt`, `updatedAt`, `fileCount`), all camelCase via
/// `rename_all`. Timestamps are ISO-8601 strings (the app parses them with the
/// liberal `DateTime.parse`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileTag {
    /// Stable unique id (a uuid v4, like the app). The adoption merge keys on it.
    pub id: String,
    /// Display name (the AI's tag text).
    pub name: String,
    /// ARGB color as an int (`Color.value`), e.g. [`DEFAULT_TAG_COLOR`].
    pub color_value: i64,
    /// ISO-8601 creation timestamp.
    pub created_at: String,
    /// ISO-8601 last-update timestamp.
    pub updated_at: String,
    /// Number of files carrying this tag. Defaults to 0 if absent (the Dart
    /// `fromJson` does `?? 0`), so an app-written document missing it still reads.
    #[serde(default)]
    pub file_count: i64,
}

/// A file→tag association — mirrors FxFiles' `TaggedFile` (`file_tag.dart`).
///
/// Field names + order match the Dart `toJson` exactly. The three location
/// fields are `Option<String>` WITHOUT `skip_serializing_if` so an absent value
/// serializes as explicit `null` (byte-faithful to Dart's `jsonEncode`). An
/// AI-tagged workspace file sets only `remoteKey` (= the stored file's logical
/// key); `localPath`/`iosAssetId` are `null`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TaggedFile {
    /// Unique id for THIS association (a uuid v4). Adoption merge keys on it.
    pub id: String,
    /// The [`FileTag::id`] this association points at.
    pub tag_id: String,
    /// Local file path (Android) — `null` for an AI-tagged cloud file.
    pub local_path: Option<String>,
    /// Cloud file key — for an AI-tagged workspace file this is the stored
    /// file's logical key (`ai/<category>/<uuid>-<name>`). NOTE there is no
    /// bucket field: adoption resolves this key against the AI workspace bucket
    /// (see the P14 note), not the user's content buckets.
    pub remote_key: Option<String>,
    /// iOS PhotoKit asset id — `null` for an AI-tagged cloud file.
    pub ios_asset_id: Option<String>,
    /// File name for display.
    pub file_name: String,
    /// ISO-8601 timestamp when the association was made.
    pub tagged_at: String,
}

impl TaggedFile {
    /// The file identifier the app's `fileIdentifier` getter would compute:
    /// `iosAssetId ?? localPath ?? remoteKey ?? ""`. Provided for parity so a
    /// caller can reason about associations the same way the app does.
    pub fn file_identifier(&self) -> &str {
        self.ios_asset_id
            .as_deref()
            .or(self.local_path.as_deref())
            .or(self.remote_key.as_deref())
            .unwrap_or("")
    }
}

/// The cloud tag document — mirrors FxFiles' `TagCloudMetadata`
/// (`file_tag.dart`).
///
/// Top-level keys + order match the Dart `toJson` exactly (`userId`, `tags`,
/// `taggedFiles`, `updatedAt`, `version`). An empty document still emits every
/// key (`tags: []`, `taggedFiles: []`), as the Dart `toJson` does.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TagCloudMetadata {
    /// The user id. Informational in the AI-workspace document (see
    /// [`FALLBACK_USER_ID`]); the app merges by tag/file id, not this field.
    pub user_id: String,
    /// All tags.
    #[serde(default)]
    pub tags: Vec<FileTag>,
    /// All file→tag associations.
    #[serde(default)]
    pub tagged_files: Vec<TaggedFile>,
    /// ISO-8601 timestamp of the last write.
    pub updated_at: String,
    /// Document version; defaults to `"1.0"` if absent (the Dart `fromJson` does
    /// `?? '1.0'`).
    #[serde(default = "default_version")]
    pub version: String,
}

fn default_version() -> String {
    TAG_METADATA_VERSION.to_string()
}

impl TagCloudMetadata {
    /// A fresh, empty document for `user_id` stamped `updated_at = now`.
    fn empty(user_id: &str, now: &str) -> Self {
        TagCloudMetadata {
            user_id: user_id.to_string(),
            tags: Vec::new(),
            tagged_files: Vec::new(),
            updated_at: now.to_string(),
            version: TAG_METADATA_VERSION.to_string(),
        }
    }
}

/// Errors surfaced by [`tag_file`] and [`list_tags`].
///
/// As in [`crate::store::StoreError`] / [`crate::read::ReadError`], an
/// access-DENIED outcome is a DISTINCT variant ([`TagError::Capability`]) so a
/// caller (and a test) can tell a denial apart from a network failure — and so
/// the offline tests can prove the scope gate fires BEFORE any I/O.
#[derive(Debug, Error)]
pub enum TagError {
    /// The scope/authority check failed (the bundle lacks the `ai/` write/read
    /// grant), or the metadata key failed canonicalization. Raised BEFORE any
    /// network I/O.
    #[error("tag capability check failed: {0}")]
    Capability(#[from] CapabilityError),

    /// Building the workspace client or a storage call (get / put) failed.
    #[error("tag storage operation failed: {0}")]
    Client(String),

    /// The existing tag document could not be parsed (it exists but is not valid
    /// `TagCloudMetadata` JSON). We REFUSE to silently overwrite a corrupt or
    /// schema-incompatible document with an empty one — only a genuine
    /// not-found starts fresh.
    #[error("existing tag document at `{key}` is not valid TagCloudMetadata JSON: {reason}")]
    CorruptDocument {
        /// The document key that failed to parse.
        key: String,
        /// The parse error.
        reason: String,
    },

    /// Serializing the updated document to JSON failed (effectively unreachable
    /// for these plain types, surfaced rather than panicking).
    #[error("failed to serialize tag document: {0}")]
    Serialize(String),

    /// No tag names were supplied to [`tag_file`] (nothing to do; refused rather
    /// than performing a no-op round-trip).
    #[error("tag_file called with no tag names")]
    NoTags,
}

/// The outcome of a [`tag_file`] call: the document as written, plus what
/// changed. Carries enough for a caller (and P9 tool output) to report the
/// result without re-reading.
#[derive(Clone, Debug)]
pub struct TagOutcome {
    /// The full tag document AFTER the write (the exact bytes' logical content).
    pub metadata: TagCloudMetadata,
    /// Names of tags newly CREATED by this call (not previously present).
    pub created_tags: Vec<String>,
    /// Number of (tag, file) associations newly ADDED by this call.
    pub added_associations: usize,
}

/// The workspace tag-metadata location: `(bucket, key)`.
///
/// Exposed so P9 / P14 and the e2e can name the exact spot without duplicating
/// the constants. The bucket is [`WORKSPACE_BUCKET`]; the key is
/// [`TAG_METADATA_KEY`].
pub fn tag_metadata_location() -> (&'static str, &'static str) {
    (WORKSPACE_BUCKET, TAG_METADATA_KEY)
}

/// Convenience alias returning just the document key.
pub fn tag_metadata_key() -> &'static str {
    TAG_METADATA_KEY
}

/// An ISO-8601 / RFC3339 timestamp string with millisecond precision and a `Z`
/// suffix, matching the shape FxFiles' `DateTime.toIso8601String()` produces for
/// a UTC instant (e.g. `2026-06-20T12:34:56.789Z`). The app parses with the
/// liberal `DateTime.parse`, so this is accepted verbatim.
fn now_iso8601() -> String {
    // Compute UTC from the system clock without pulling in `chrono`: format the
    // civil date/time from the unix epoch ourselves. Millisecond precision.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    format_unix_millis_utc(now.as_millis())
}

/// Format a count of milliseconds since the Unix epoch as
/// `YYYY-MM-DDТHH:MM:SS.mmmZ` (UTC, proleptic Gregorian). Pure + deterministic so
/// it is unit-testable; used by [`now_iso8601`].
fn format_unix_millis_utc(total_millis: u128) -> String {
    let millis = (total_millis % 1000) as u32;
    let total_secs = (total_millis / 1000) as i64;
    let secs_of_day = total_secs.rem_euclid(86_400);
    let days_since_epoch = total_secs.div_euclid(86_400);

    let hour = secs_of_day / 3600;
    let minute = (secs_of_day % 3600) / 60;
    let second = secs_of_day % 60;

    let (year, month, day) = civil_from_days(days_since_epoch);
    format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z"
    )
}

/// Convert a day count since 1970-01-01 into a `(year, month, day)` civil date
/// (proleptic Gregorian). Howard Hinnant's well-known `civil_from_days`
/// algorithm — exact for the range we care about.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32; // [1, 12]
    let year = if m <= 2 { y + 1 } else { y };
    (year, m, d)
}

/// Derive a display file name from a stored file's logical key: the final
/// `/`-separated path component (e.g. `ai/image/abc-photo.png` → `photo.png`'s
/// uuid-prefixed segment `abc-photo.png`). Falls back to the whole key when
/// there is no separator or the last segment is empty.
fn file_name_from_key(file_key: &str) -> String {
    match file_key.rsplit('/').next() {
        Some(last) if !last.is_empty() => last.to_string(),
        _ => file_key.to_string(),
    }
}

/// Resolve the `userId` to stamp into the document: the bundle's `user_id` if it
/// carries one, else [`FALLBACK_USER_ID`].
fn resolve_user_id(cap: &CapabilityBundle) -> String {
    cap.user_id()
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .unwrap_or_else(|| FALLBACK_USER_ID.to_string())
}

/// Pure read-modify step: apply `tag_names` × `file_key` to `doc` in place,
/// returning what changed. Split out from [`tag_file`] so the upsert/dedup logic
/// is unit-testable with NO network.
///
/// Semantics (mirroring the app's intent):
/// - Tags dedupe **case-insensitively by name**; a new tag preserves the
///   caller's display casing and gets a fresh uuid + [`DEFAULT_TAG_COLOR`].
/// - Associations dedupe by (`tagId`, `remoteKey`); an existing (tag, file) pair
///   is not re-added.
/// - `fileCount` is recomputed for every tag that gained an association, and
///   `updatedAt` is bumped on touched tags + the document — but an existing tag
///   whose association already exists is left untouched (no spurious mutation).
fn apply_tagging(
    doc: &mut TagCloudMetadata,
    file_key: &str,
    file_name: &str,
    tag_names: &[String],
    now: &str,
) -> (Vec<String>, usize) {
    let mut created_tags = Vec::new();
    let mut added_associations = 0usize;
    // Track which tag ids gained an association this call (to recompute counts +
    // bump updatedAt for exactly those).
    let mut touched_tag_ids: Vec<String> = Vec::new();

    for raw_name in tag_names {
        let name = raw_name.trim();
        if name.is_empty() {
            continue; // skip empty/whitespace names (the app trims; an empty name is meaningless)
        }

        // Find an existing tag by case-insensitive name, else create one.
        let tag_id = match doc
            .tags
            .iter()
            .find(|t| t.name.eq_ignore_ascii_case(name))
        {
            Some(t) => t.id.clone(),
            None => {
                let id = Uuid::new_v4().to_string();
                doc.tags.push(FileTag {
                    id: id.clone(),
                    name: name.to_string(),
                    color_value: DEFAULT_TAG_COLOR,
                    created_at: now.to_string(),
                    updated_at: now.to_string(),
                    file_count: 0,
                });
                created_tags.push(name.to_string());
                id
            }
        };

        // Add the association unless an identical (tagId, remoteKey) already exists.
        let already = doc.tagged_files.iter().any(|tf| {
            tf.tag_id == tag_id && tf.remote_key.as_deref() == Some(file_key)
        });
        if !already {
            doc.tagged_files.push(TaggedFile {
                id: Uuid::new_v4().to_string(),
                tag_id: tag_id.clone(),
                local_path: None,
                remote_key: Some(file_key.to_string()),
                ios_asset_id: None,
                file_name: file_name.to_string(),
                tagged_at: now.to_string(),
            });
            added_associations += 1;
            if !touched_tag_ids.contains(&tag_id) {
                touched_tag_ids.push(tag_id.clone());
            }
        }
    }

    // Recompute fileCount + bump updatedAt for exactly the tags that changed.
    for tag_id in &touched_tag_ids {
        let count = doc
            .tagged_files
            .iter()
            .filter(|tf| &tf.tag_id == tag_id)
            .count() as i64;
        if let Some(tag) = doc.tags.iter_mut().find(|t| &t.id == tag_id) {
            tag.file_count = count;
            tag.updated_at = now.to_string();
        }
    }

    (created_tags, added_associations)
}

/// Load the AI's tag document from the workspace, or `None` if it does not exist
/// yet. A genuine not-found returns `Ok(None)` (the caller starts fresh); a
/// document that exists but fails to parse is a [`TagError::CorruptDocument`]
/// (we never silently clobber it).
///
/// Takes `cap` (not a pre-built client) so the GET runs through the L1c
/// refresh-on-auth retry: an expired scoped JWT is refreshed once and the GET
/// retried. The client is (re)built from `cap` inside the wrapper; a no-op
/// without a `refresh_token`. The not-found classification is unchanged — it runs
/// on the wrapper's final error, so a refreshed-then-not-found GET still maps to
/// `Ok(None)`.
async fn load_tag_document(
    cap: &CapabilityBundle,
) -> Result<Option<TagCloudMetadata>, TagError> {
    let client = cap.workspace_client()?;
    let got = with_refresh_retry(cap, client, |c| async move {
        c.get_object_flat(WORKSPACE_BUCKET, TAG_METADATA_KEY).await
    })
    .await;
    match got {
        Ok(bytes) => {
            let parsed: TagCloudMetadata =
                serde_json::from_slice(&bytes).map_err(|e| TagError::CorruptDocument {
                    key: TAG_METADATA_KEY.to_string(),
                    reason: e.to_string(),
                })?;
            Ok(Some(parsed))
        }
        Err(e) => {
            // A not-found means "no document yet" → start fresh. Anything else is
            // a real client/transport error.
            let msg = e.to_string();
            if msg.to_lowercase().contains("not found") {
                Ok(None)
            } else {
                Err(TagError::Client(format!("get tag document: {msg}")))
            }
        }
    }
}

/// Tag a stored workspace file with one or more tags, writing the result into the
/// AI's tag document in FxFiles' native [`TagCloudMetadata`] format.
///
/// Read-modify-write: load the document (or start empty on not-found), upsert the
/// tags + associations via [`apply_tagging`], and write it back. The write is
/// scope-gated BEFORE any I/O.
///
/// # Arguments
/// - `cap`: the in-memory capability bundle. Must hold a `Write` grant whose
///   canonical scope is [`WORKSPACE_KEY_PREFIX`] (`ai`).
/// - `file_key`: the stored file's **logical** key
///   (`ai/<category>/<uuid>-<name>`, i.e. [`crate::store::StoreOutcome::key`]).
///   Recorded as the association's `remoteKey`.
/// - `tag_names`: the tag names to apply (deduped case-insensitively; empty
///   names skipped). Must be non-empty.
///
/// # Errors
/// - [`TagError::NoTags`] if `tag_names` is empty (or all-empty after trimming
///   yields no work — see note: an all-whitespace list still performs the load
///   to stay simple, but produces no changes).
/// - [`TagError::Capability`] if the bundle lacks the `ai/` write grant (raised
///   with NO I/O performed).
/// - [`TagError::CorruptDocument`] if an existing document cannot be parsed.
/// - [`TagError::Client`] if a storage call fails.
/// - [`TagError::Serialize`] if the updated document cannot be serialized.
pub async fn tag_file(
    cap: &CapabilityBundle,
    file_key: &str,
    tag_names: &[String],
) -> Result<TagOutcome, TagError> {
    if tag_names.is_empty() {
        return Err(TagError::NoTags);
    }

    // GATE FIRST — authorize the WRITE of the tag document before any network
    // I/O. The key is fixed (TAG_METADATA_KEY), under the `ai/` scope; a bundle
    // lacking the `ai/` write grant is denied here with no client built.
    cap.assert_in_scope(TAG_METADATA_KEY, WORKSPACE_KEY_PREFIX, Permission::Write)?;

    let now = now_iso8601();
    let user_id = resolve_user_id(cap);

    // Load (or start fresh). A corrupt existing document is an error, NOT an
    // overwrite. `load_tag_document` runs the GET through the L1c refresh-on-auth
    // retry internally, so a JWT that expired before this call is refreshed here.
    let mut doc = load_tag_document(cap)
        .await?
        .unwrap_or_else(|| TagCloudMetadata::empty(&user_id, &now));

    // Apply the tagging in memory.
    let file_name = file_name_from_key(file_key);
    let (created_tags, added_associations) =
        apply_tagging(&mut doc, file_key, &file_name, tag_names, &now);

    // Always bump the document's updatedAt to reflect this call (matches the
    // app's syncToCloud, which stamps a fresh updatedAt on every sync).
    doc.updated_at = now.clone();

    // Serialize + write back. `to_vec` (compact) — the app uses `jsonEncode`
    // (also compact), so the byte shape matches. The PUT is wrapped in the L1c
    // refresh-on-auth retry too (the JWT could expire between the load and this
    // write); the client is (re)built here so it carries any JWT swapped by the
    // load above. `bytes` is non-Copy, so the closure borrows it and clones the
    // (small) tag-doc per attempt to keep the `Fn` bound (the wrapper may call it
    // twice). The closure MUST use its own `c` (the rebuilt, fresh-JWT client).
    let bytes = serde_json::to_vec(&doc).map_err(|e| TagError::Serialize(e.to_string()))?;
    let client = cap.workspace_client()?;
    let bytes_ref = &bytes;
    with_refresh_retry(cap, client, |c| async move {
        c.put_object_flat(
            WORKSPACE_BUCKET,
            TAG_METADATA_KEY,
            bytes_ref.clone(),
            Some("application/json"),
        )
        .await
    })
    .await
    .map_err(|e| TagError::Client(format!("put tag document: {e}")))?;

    Ok(TagOutcome {
        metadata: doc,
        created_tags,
        added_associations,
    })
}

/// List all tags in the AI's tag document.
///
/// Scope-gated (READ) BEFORE any I/O. Returns an empty list if the document does
/// not exist yet.
///
/// # Errors
/// - [`TagError::Capability`] if the bundle lacks the `ai/` read grant (NO I/O).
/// - [`TagError::CorruptDocument`] if the document exists but cannot be parsed.
/// - [`TagError::Client`] if a storage call fails.
pub async fn list_tags(cap: &CapabilityBundle) -> Result<Vec<FileTag>, TagError> {
    // GATE FIRST — authorize the READ of the tag document before any I/O.
    cap.assert_in_scope(TAG_METADATA_KEY, WORKSPACE_KEY_PREFIX, Permission::Read)?;
    // `load_tag_document` builds the client + runs the GET through the L1c
    // refresh-on-auth retry internally.
    match load_tag_document(cap).await? {
        Some(doc) => Ok(doc.tags),
        None => Ok(Vec::new()),
    }
}

/// Return the tags currently applied to a specific file (by its logical
/// `file_key`, i.e. the association `remoteKey`).
///
/// Scope-gated (READ) BEFORE any I/O. Loads the document, finds every
/// association whose `remoteKey == file_key`, and resolves those to their
/// [`FileTag`]s (deduped, in document order). Empty if the document or the file
/// has no tags.
///
/// # Errors
/// Same as [`list_tags`].
pub async fn tags_for_file(
    cap: &CapabilityBundle,
    file_key: &str,
) -> Result<Vec<FileTag>, TagError> {
    cap.assert_in_scope(TAG_METADATA_KEY, WORKSPACE_KEY_PREFIX, Permission::Read)?;
    let doc = match load_tag_document(cap).await? {
        Some(doc) => doc,
        None => return Ok(Vec::new()),
    };
    Ok(tags_for_file_in_doc(&doc, file_key))
}

/// Pure helper: the [`FileTag`]s associated with `file_key` within `doc`
/// (deduped by tag id, in `doc.tags` order). Unit-testable with no network.
fn tags_for_file_in_doc(doc: &TagCloudMetadata, file_key: &str) -> Vec<FileTag> {
    // Collect the tag ids associated with this file.
    let tag_ids: Vec<&str> = doc
        .tagged_files
        .iter()
        .filter(|tf| tf.remote_key.as_deref() == Some(file_key))
        .map(|tf| tf.tag_id.as_str())
        .collect();
    // Resolve to FileTags in document order, deduped.
    doc.tags
        .iter()
        .filter(|t| tag_ids.contains(&t.id.as_str()))
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    use base64::Engine as _;
    use fula_crypto::SecretKey;

    // ── Timestamp formatting (pure) ────────────────────────────────────────

    #[test]
    fn format_unix_millis_matches_known_instants() {
        // The Unix epoch.
        assert_eq!(format_unix_millis_utc(0), "1970-01-01T00:00:00.000Z");
        // A known instant: 2021-01-01T00:00:00.000Z = 1_609_459_200_000 ms.
        assert_eq!(
            format_unix_millis_utc(1_609_459_200_000),
            "2021-01-01T00:00:00.000Z"
        );
        // Millisecond precision is preserved.
        assert_eq!(
            format_unix_millis_utc(1_609_459_200_789),
            "2021-01-01T00:00:00.789Z"
        );
        // A leap-year date (2024-02-29) to exercise civil_from_days.
        // 2024-02-29T12:34:56.000Z = 1_709_209_max? compute: use a fixed value.
        // 2024-02-29T00:00:00Z = 1709164800 s.
        assert_eq!(
            format_unix_millis_utc(1_709_164_800_000),
            "2024-02-29T00:00:00.000Z"
        );
    }

    #[test]
    fn now_iso8601_has_expected_shape() {
        let s = now_iso8601();
        // 2026-06-20T12:34:56.789Z → length 24, ends with Z, has 'T' and a dot.
        assert_eq!(s.len(), 24, "got {s}");
        assert!(s.ends_with('Z'));
        assert!(s.contains('T'));
        assert_eq!(&s[4..5], "-");
        assert_eq!(&s[19..20], ".");
    }

    // ── file_name_from_key (pure) ──────────────────────────────────────────

    #[test]
    fn file_name_from_key_takes_last_segment() {
        assert_eq!(
            file_name_from_key("ai/image/abc123-photo.png"),
            "abc123-photo.png"
        );
        assert_eq!(file_name_from_key("ai/note/xyz"), "xyz");
        // No separator → whole key.
        assert_eq!(file_name_from_key("solo.txt"), "solo.txt");
        // Trailing slash → falls back to whole key (last segment empty).
        assert_eq!(file_name_from_key("ai/dir/"), "ai/dir/");
    }

    // ── Golden JSON: byte-shape fidelity vs the Dart toJson ─────────────────
    //
    // These pin the EXACT serialized shape. A reviewer can diff this against the
    // Dart `toJson` in file_tag.dart: same camelCase keys, same order, nullable
    // association fields present as `null`, empty doc still emits tags/taggedFiles.

    #[test]
    fn golden_empty_metadata_serializes_like_dart() {
        let doc = TagCloudMetadata::empty("u123", "2026-06-20T12:00:00.000Z");
        let json = serde_json::to_string(&doc).unwrap();
        // userId, tags:[], taggedFiles:[], updatedAt, version — in Dart order.
        assert_eq!(
            json,
            r#"{"userId":"u123","tags":[],"taggedFiles":[],"updatedAt":"2026-06-20T12:00:00.000Z","version":"1.0"}"#
        );
    }

    #[test]
    fn golden_file_tag_serializes_like_dart() {
        let tag = FileTag {
            id: "tag-1".to_string(),
            name: "Receipts".to_string(),
            color_value: DEFAULT_TAG_COLOR,
            created_at: "2026-06-20T12:00:00.000Z".to_string(),
            updated_at: "2026-06-20T12:00:00.000Z".to_string(),
            file_count: 3,
        };
        let json = serde_json::to_string(&tag).unwrap();
        // colorValue is the DECIMAL of 0xFF1E88E5 (= 4280191205), as Dart int JSON.
        assert_eq!(
            json,
            r#"{"id":"tag-1","name":"Receipts","colorValue":4280191205,"createdAt":"2026-06-20T12:00:00.000Z","updatedAt":"2026-06-20T12:00:00.000Z","fileCount":3}"#
        );
    }

    #[test]
    fn golden_tagged_file_emits_nulls_like_dart() {
        // An AI-tagged cloud file: only remoteKey set; localPath/iosAssetId NULL.
        let tf = TaggedFile {
            id: "assoc-1".to_string(),
            tag_id: "tag-1".to_string(),
            local_path: None,
            remote_key: Some("ai/image/abc-photo.png".to_string()),
            ios_asset_id: None,
            file_name: "abc-photo.png".to_string(),
            tagged_at: "2026-06-20T12:00:00.000Z".to_string(),
        };
        let json = serde_json::to_string(&tf).unwrap();
        // localPath + iosAssetId are PRESENT as null (byte-faithful to Dart).
        assert_eq!(
            json,
            r#"{"id":"assoc-1","tagId":"tag-1","localPath":null,"remoteKey":"ai/image/abc-photo.png","iosAssetId":null,"fileName":"abc-photo.png","taggedAt":"2026-06-20T12:00:00.000Z"}"#
        );
    }

    // ── Round-trip: a doc shaped like the Dart fromJson reads back identically ─

    #[test]
    fn round_trips_through_serde() {
        let mut doc = TagCloudMetadata::empty("u1", "2026-06-20T00:00:00.000Z");
        apply_tagging(
            &mut doc,
            "ai/image/k-photo.png",
            "k-photo.png",
            &["Travel".to_string(), "2026".to_string()],
            "2026-06-20T00:00:00.000Z",
        );
        let json = serde_json::to_string(&doc).unwrap();
        let back: TagCloudMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(doc, back, "round-trip must be lossless");
    }

    #[test]
    fn deserializes_dart_document_tolerating_missing_filecount_and_version() {
        // Simulate a document the app wrote: a tag with NO fileCount, doc with NO
        // version. The Dart fromJson tolerates both (`?? 0`, `?? '1.0'`); ours must
        // too via #[serde(default)].
        let dart_json = r#"{
            "userId": "abcdef0123456789",
            "tags": [
                {"id":"t1","name":"Work","colorValue":4280191205,
                 "createdAt":"2026-06-20T00:00:00.000Z","updatedAt":"2026-06-20T00:00:00.000Z"}
            ],
            "taggedFiles": [
                {"id":"a1","tagId":"t1","localPath":null,"remoteKey":"ai/document/x.pdf",
                 "iosAssetId":null,"fileName":"x.pdf","taggedAt":"2026-06-20T00:00:00.000Z"}
            ],
            "updatedAt": "2026-06-20T00:00:00.000Z"
        }"#;
        let doc: TagCloudMetadata = serde_json::from_str(dart_json).unwrap();
        assert_eq!(doc.version, "1.0", "missing version defaults to 1.0");
        assert_eq!(doc.tags[0].file_count, 0, "missing fileCount defaults to 0");
        assert_eq!(doc.tags[0].name, "Work");
        assert_eq!(
            doc.tagged_files[0].remote_key.as_deref(),
            Some("ai/document/x.pdf")
        );
    }

    // ── apply_tagging logic (pure, the algorithmic crux) ───────────────────

    const T0: &str = "2026-06-20T00:00:00.000Z";

    #[test]
    fn apply_tagging_creates_tags_and_association() {
        let mut doc = TagCloudMetadata::empty("u", T0);
        let (created, added) = apply_tagging(
            &mut doc,
            "ai/image/k-photo.png",
            "k-photo.png",
            &["Travel".to_string(), "Beach".to_string()],
            T0,
        );
        assert_eq!(created, vec!["Travel".to_string(), "Beach".to_string()]);
        assert_eq!(added, 2);
        assert_eq!(doc.tags.len(), 2);
        assert_eq!(doc.tagged_files.len(), 2);
        // Each new tag's fileCount reflects its one association.
        for t in &doc.tags {
            assert_eq!(t.file_count, 1, "tag {} should have fileCount 1", t.name);
            assert_eq!(t.color_value, DEFAULT_TAG_COLOR);
        }
        // Associations point at the file by remoteKey, with null local/ios.
        for tf in &doc.tagged_files {
            assert_eq!(tf.remote_key.as_deref(), Some("ai/image/k-photo.png"));
            assert!(tf.local_path.is_none());
            assert!(tf.ios_asset_id.is_none());
            assert_eq!(tf.file_name, "k-photo.png");
        }
    }

    #[test]
    fn apply_tagging_dedupes_tag_by_name_case_insensitively() {
        let mut doc = TagCloudMetadata::empty("u", T0);
        apply_tagging(&mut doc, "ai/file/a", "a", &["Work".to_string()], T0);
        // Tag a DIFFERENT file with the same name in a different case → reuses tag.
        let (created, added) =
            apply_tagging(&mut doc, "ai/file/b", "b", &["WORK".to_string()], T0);
        assert!(created.is_empty(), "same-name tag must not be recreated");
        assert_eq!(added, 1, "but the new file gets a new association");
        assert_eq!(doc.tags.len(), 1, "still exactly one tag");
        assert_eq!(doc.tags[0].file_count, 2, "tag now covers two files");
        assert_eq!(doc.tagged_files.len(), 2);
    }

    #[test]
    fn apply_tagging_is_idempotent_for_same_file_and_tag() {
        let mut doc = TagCloudMetadata::empty("u", T0);
        apply_tagging(&mut doc, "ai/file/a", "a", &["Keep".to_string()], T0);
        // Re-tag the SAME file with the SAME tag → no new tag, no new association.
        let (created, added) =
            apply_tagging(&mut doc, "ai/file/a", "a", &["Keep".to_string()], T0);
        assert!(created.is_empty());
        assert_eq!(added, 0, "duplicate (tag, file) must not be re-added");
        assert_eq!(doc.tags.len(), 1);
        assert_eq!(doc.tagged_files.len(), 1);
        assert_eq!(doc.tags[0].file_count, 1);
    }

    #[test]
    fn apply_tagging_skips_empty_names() {
        let mut doc = TagCloudMetadata::empty("u", T0);
        let (created, added) = apply_tagging(
            &mut doc,
            "ai/file/a",
            "a",
            &["".to_string(), "   ".to_string(), "Real".to_string()],
            T0,
        );
        assert_eq!(created, vec!["Real".to_string()]);
        assert_eq!(added, 1);
        assert_eq!(doc.tags.len(), 1);
    }

    #[test]
    fn apply_tagging_trims_name_but_preserves_display_casing() {
        let mut doc = TagCloudMetadata::empty("u", T0);
        apply_tagging(&mut doc, "ai/file/a", "a", &["  Spaced Name  ".to_string()], T0);
        assert_eq!(doc.tags[0].name, "Spaced Name", "name trimmed, casing kept");
    }

    #[test]
    fn tags_for_file_in_doc_returns_only_that_files_tags() {
        let mut doc = TagCloudMetadata::empty("u", T0);
        apply_tagging(&mut doc, "ai/file/a", "a", &["X".to_string(), "Y".to_string()], T0);
        apply_tagging(&mut doc, "ai/file/b", "b", &["Z".to_string()], T0);
        let a_tags = tags_for_file_in_doc(&doc, "ai/file/a");
        let mut names: Vec<&str> = a_tags.iter().map(|t| t.name.as_str()).collect();
        names.sort_unstable();
        assert_eq!(names, vec!["X", "Y"]);
        let b_tags = tags_for_file_in_doc(&doc, "ai/file/b");
        assert_eq!(b_tags.len(), 1);
        assert_eq!(b_tags[0].name, "Z");
        // A file with no tags → empty.
        assert!(tags_for_file_in_doc(&doc, "ai/file/none").is_empty());
    }

    // ── Scope gate is enforced (offline; replicate the EXACT pre-I/O check) ──
    //
    // We cannot run the full async tag_file offline (it needs the gateway), but
    // the security gate is the synchronous assert_in_scope tag_file performs
    // first. We replicate it EXACTLY — same key, same scope, same permission —
    // against bundles with/without the grant.

    fn bundle_json(grant_scope: Option<&str>, can_write: bool, user_id: Option<&str>) -> String {
        let ws = base64::engine::general_purpose::STANDARD.encode([1u8; 32]);
        let mcp = base64::engine::general_purpose::STANDARD.encode([2u8; 32]);
        let owner = base64::engine::general_purpose::STANDARD
            .encode(SecretKey::from_bytes(&[3u8; 32]).unwrap().public_key().as_bytes());
        let grants = match grant_scope {
            Some(s) => format!(
                r#"[{{ "scope": "{s}", "permissions": {{ "can_read": true, "can_write": {can_write}, "can_delete": false }} }}]"#
            ),
            None => "[]".to_string(),
        };
        let uid = match user_id {
            Some(u) => format!(r#", "user_id": "{u}""#),
            None => String::new(),
        };
        format!(
            r#"{{ "endpoint": "https://offline.invalid", "jwt": "j", "workspace_secret_b64": "{ws}", "mcp_secret_b64": "{mcp}", "owner_public_b64": "{owner}"{uid}, "grants": {grants} }}"#
        )
    }

    /// The EXACT write gate tag_file performs.
    fn tag_write_gate(cap: &CapabilityBundle) -> Result<(), TagError> {
        cap.assert_in_scope(TAG_METADATA_KEY, WORKSPACE_KEY_PREFIX, Permission::Write)?;
        Ok(())
    }

    #[test]
    fn tag_gate_allows_write_with_ai_grant() {
        let cap = CapabilityBundle::from_json(&bundle_json(Some("ai/"), true, None)).unwrap();
        assert!(tag_write_gate(&cap).is_ok());
    }

    #[test]
    fn tag_gate_denies_without_grant() {
        let cap = CapabilityBundle::from_json(&bundle_json(None, false, None)).unwrap();
        assert!(matches!(
            tag_write_gate(&cap),
            Err(TagError::Capability(CapabilityError::OutOfScope { .. }))
        ));
    }

    #[test]
    fn tag_gate_denies_read_only_ai_grant() {
        let cap = CapabilityBundle::from_json(&bundle_json(Some("ai/"), false, None)).unwrap();
        assert!(matches!(
            tag_write_gate(&cap),
            Err(TagError::Capability(CapabilityError::OutOfScope { .. }))
        ));
    }

    #[test]
    fn tag_metadata_key_is_under_ai_scope() {
        // Guardrail: the doc key MUST be admitted by the `ai/` gate (its first
        // segment is `ai`). If someone "fixes" it back to `.fula/tags/...` this
        // fails — that path is OUTSIDE the ai/ grant and would deny every call.
        let cap = CapabilityBundle::from_json(&bundle_json(Some("ai/"), true, None)).unwrap();
        assert!(cap
            .assert_in_scope(TAG_METADATA_KEY, WORKSPACE_KEY_PREFIX, Permission::Read)
            .is_ok());
        assert!(cap
            .assert_in_scope(TAG_METADATA_KEY, WORKSPACE_KEY_PREFIX, Permission::Write)
            .is_ok());
        // And the constant really is under ai/.
        assert!(TAG_METADATA_KEY.starts_with("ai/"));
    }

    // ── userId resolution ──────────────────────────────────────────────────

    #[test]
    fn resolve_user_id_prefers_bundle_then_fallback() {
        let with = CapabilityBundle::from_json(&bundle_json(Some("ai/"), true, Some("deadbeef01234567"))).unwrap();
        assert_eq!(resolve_user_id(&with), "deadbeef01234567");
        let without = CapabilityBundle::from_json(&bundle_json(Some("ai/"), true, None)).unwrap();
        assert_eq!(resolve_user_id(&without), FALLBACK_USER_ID);
    }

    // ── tag_file early errors (no I/O) ─────────────────────────────────────

    #[tokio::test]
    async fn tag_file_no_names_is_rejected() {
        let cap = CapabilityBundle::from_json(&bundle_json(Some("ai/"), true, None)).unwrap();
        assert!(matches!(tag_file(&cap, "ai/file/a", &[]).await, Err(TagError::NoTags)));
    }

    #[tokio::test]
    async fn tag_file_denies_out_of_scope_before_any_io() {
        // Bundle with NO grant + an UNREACHABLE endpoint: if the gate did not fire
        // first, the call would hit the network and fail with a Client error.
        // Asserting Capability proves the gate short-circuited pre-I/O.
        let cap = CapabilityBundle::from_json(&bundle_json(None, false, None)).unwrap();
        let err = tag_file(&cap, "ai/file/a", &["X".to_string()]).await.unwrap_err();
        assert!(
            matches!(err, TagError::Capability(CapabilityError::OutOfScope { .. })),
            "out-of-scope tag_file must deny pre-I/O (got {err:?})"
        );
    }

    #[tokio::test]
    async fn list_tags_denies_without_read_grant_before_any_io() {
        // A bundle whose only grant is write-but-not-read on a DIFFERENT scope →
        // list_tags (which needs ai/ read) denies before touching the network.
        let cap = CapabilityBundle::from_json(&bundle_json(Some("other/"), true, None)).unwrap();
        let err = list_tags(&cap).await.unwrap_err();
        assert!(
            matches!(err, TagError::Capability(CapabilityError::OutOfScope { .. })),
            "list_tags without ai/ read grant must deny pre-I/O (got {err:?})"
        );
    }
}
