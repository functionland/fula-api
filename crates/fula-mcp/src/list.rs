//! # `list_files` + `search` — the AI's scoped ENUMERATION operations (P7)
//!
//! The enumeration counterpart to P5's [`crate::store`] (write) and P6's
//! [`crate::read`] (read). This is where the **scope-confined enumeration
//! guarantee** lives: the AI may enumerate ONLY its own `ai/` workspace forest —
//! it can list and search the files it wrote, but it must **never** enumerate the
//! user's real buckets. The MCP-protocol wiring (tool dispatch) comes later (P9);
//! here we build + test the operations as plain async library calls.
//!
//! ## The two operations
//!
//! - [`list_files`] — list the AI's workspace forest, **confined to the `ai/`
//!   scope**, with optional [`ListFilter::category`] and sub-[`ListFilter::prefix`]
//!   narrowing. Returns [`FileEntry`] rows.
//! - [`search`] — [`list_files`] over the whole `ai/` scope, then keep entries
//!   whose **filename** (the last key segment) contains the query
//!   case-insensitively. (Tag-based search/filter is P8 — see the seam note below;
//!   this phase adds NO tag logic.)
//!
//! ## Scope confinement (security-critical) — geometry, not substring
//!
//! Enumeration is the one operation where a forest listing could *surface* keys
//! the AI must not see. We defend it in two layers, both reusing the proven P3
//! [`CapabilityBundle::assert_in_scope`] segment geometry — never a substring
//! match:
//!
//! 1. **Gate before any I/O.** [`list_files`] calls
//!    `assert_in_scope(scope_prefix, WORKSPACE_KEY_PREFIX, Read)` BEFORE building
//!    a client or touching the network (`scope_prefix` is `ai`, or `ai/<category>`
//!    when a category filter is given). This proves the session actually holds the
//!    `ai/` read grant; a bundle that lacks it is denied with
//!    [`ListError::Capability`] and **no network call** — exactly the P6
//!    gate-before-I/O contract. (Note the *category* in `scope_prefix` only tweaks
//!    the geometry of the gate's KEY argument; authority is still the `ai/` grant,
//!    so `assert_in_scope`'s scope argument stays [`WORKSPACE_KEY_PREFIX`].)
//!
//! 2. **Confine every returned entry by the same segment geometry.** Even though
//!    the workspace forest *should* contain only `ai/` keys, we treat the listing
//!    as untrusted: each entry survives iff
//!    `assert_in_scope(entry_key, WORKSPACE_KEY_PREFIX, Read).is_ok()`. This is the
//!    P3 path-**segment** boundary — it drops `ai-evil/…` (first-segment substring
//!    footgun), drops any non-`ai/` key, and drops any non-canonical bookkeeping
//!    entry (the key canon is strict). A non-`ai/` key can therefore never leak
//!    into a [`FileEntry`].
//!
//! Two deliberate choices in (2), confirmed by the P7 design review (built-in
//! advisor + Codex/GPT-5.5): **enumeration requires `Read` by design** —
//! listing/searching filenames *is* read-like metadata disclosure, so a session
//! without the `ai/` read grant legitimately cannot enumerate (it fails the gate
//! in (1), so it never even reaches the per-entry pass — there is no
//! silently-empty result). And the per-entry authority arm is **intentionally
//! redundant** with the gate: the gate already proved the `ai/` read grant, so the
//! per-entry check re-proves it only as cheap defense-in-depth. We reuse the full
//! `assert_in_scope` rather than a hand-rolled geometry helper precisely so the
//! strict key-canon + segment boundary stay single-sourced (a separate helper
//! would risk drifting from the canon the rest of the crate enforces).
//!
//! ## Why confinement reuses the FULL gate, but feature filters do NOT
//!
//! Confinement asks one question — *"is this key inside `ai/` and am I allowed
//! there?"* — which is precisely what `assert_in_scope(key, "ai", Read)` answers,
//! so reusing it is the faithful, single-source-of-truth choice (no second copy of
//! the segment logic to drift). But the *feature* filters (category, sub-prefix)
//! are NOT authority questions and must NOT go through `assert_in_scope`: its
//! authority arm is **equality** against the held grants, and the session only
//! grants `ai/`. Asking `assert_in_scope(key, "ai/image", Read)` would fail the
//! authority arm (no `ai/image` grant exists) and silently empty the result. So
//! the narrowing filters are **pure segment / string comparisons** over the
//! already-confined, already-canonical key. Rule of thumb: *`assert_in_scope`
//! gates entry into `ai/`; feature filters are plain matches.*
//!
//! ## Category derivation (round-trips what `store_file` wrote)
//!
//! [`crate::store::build_workspace_key`] encodes the category as the SECOND key
//! segment (`ai/<category>/<uuid>-<name>`). We recover it by mapping that segment
//! back via [`Category::from_name`] — a faithful round-trip of what the writer
//! encoded. If the segment is not a known category name (a foreign / hand-written
//! key that still lives under `ai/`), we fall back to
//! [`classify`]`(content_type, key, None)`, the same classifier the store path
//! uses. The fallback never re-reads bytes (enumeration is metadata-only).

use thiserror::Error;

use crate::capability::{CapabilityBundle, CapabilityError, Permission};
use crate::category::{classify, Category};
use crate::store::WORKSPACE_KEY_PREFIX;

use fula_client::FileMetadata;

/// One row of a workspace enumeration result.
///
/// A metadata-only projection of a forest entry, confined to the `ai/` scope.
/// Carries everything the MCP enumeration tools (P9) and the tag layer (P8) need
/// without exposing the obfuscated storage key or any crypto material:
///
/// - **P8 (tag writer/reader)** keys its tag store by [`Self::key`] (the logical
///   `ai/<category>/<uuid>-<name>` path) and will add tag-based filtering/search
///   alongside [`ListFilter`] (the predicate seam) — it does NOT need a new list
///   API, only an extra filter arm.
/// - **P9 (MCP tool wiring)** serializes [`FileEntry`] rows straight into tool
///   results; the field set is deliberately the user-meaningful shape (logical
///   key, plaintext size, content type, category, mtime), never `storage_key`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct FileEntry {
    /// The canonical logical key (`ai/<category>/<uuid>-<name>`). This is the
    /// human-meaningful path the AI stored under, and the handle P6
    /// [`crate::read::read_workspace_file`] reads back by.
    pub key: String,
    /// The plaintext (original) size in bytes — NOT the ciphertext size.
    pub size: u64,
    /// The content type recorded at store time, if any.
    pub content_type: Option<String>,
    /// The file's category, recovered from the `ai/<category>/` key segment
    /// (falling back to [`classify`] when the segment is not a known category).
    pub category: Category,
    /// Last-modified timestamp (Unix seconds), if the forest recorded one.
    pub modified_at: Option<i64>,
}

/// Optional narrowing applied to a [`list_files`] enumeration.
///
/// Both fields are pure *feature* filters over the already-`ai/`-confined,
/// already-canonical keys (see the module docs) — they are NOT authority checks.
/// An all-`None` filter lists the whole `ai/` scope.
///
/// This is the seam P8 extends: tag-based filtering adds a `tags` arm here (and a
/// matching predicate in [`confine_filter_map`]), reusing the same list pipeline.
#[derive(Debug, Clone, Default)]
pub struct ListFilter {
    /// Keep only entries whose category equals this (compared on the key's
    /// `<category>` segment, the same value [`FileEntry::category`] derives).
    pub category: Option<Category>,
    /// Keep only entries whose logical key is inside this sub-prefix of `ai/`, by
    /// the P3 path-**segment** boundary (so `ai/image` does not admit
    /// `ai/imagery/…`). The prefix is interpreted relative to the workspace and
    /// must itself be inside `ai/`; a prefix outside `ai/` matches nothing.
    pub prefix: Option<String>,
}

/// Errors surfaced by [`list_files`] and [`search`].
///
/// The shape mirrors [`crate::read::ReadError`]: a denial is a *distinct* variant
/// ([`ListError::Capability`]) so "scope confinement is enforced" lives in the
/// type — a caller (and a test) can tell an access-DENIED outcome apart from a
/// network failure. This is what lets the offline tests prove the scope gate fires
/// BEFORE any I/O: an enumeration with no `ai/` grant against an unreachable
/// endpoint returns `Capability`, not `Client`.
#[derive(Debug, Error)]
pub enum ListError {
    /// The scope/authority gate failed (the session does not hold the `ai/` read
    /// grant, or the gate's scope/key failed canonicalization). This is the
    /// access-DENIED outcome and is raised BEFORE any network I/O.
    #[error("enumeration denied by capability check: {0}")]
    Capability(#[from] CapabilityError),

    /// Building the workspace client or the forest listing failed. (Network /
    /// crypto failure, NOT an authorization outcome.)
    #[error("enumeration storage operation failed: {0}")]
    Client(String),
}

/// List the AI's workspace files, **confined to the `ai/` scope**, with optional
/// category / sub-prefix narrowing.
///
/// Pipeline: gate (BEFORE any I/O) → list the workspace forest →
/// [`confine_filter_map`] (per-entry `ai/` confinement + feature filters + map to
/// [`FileEntry`]). The gate and the confinement both use the P3 segment geometry;
/// the feature filters are pure matches (see the module docs).
///
/// # Arguments
/// - `cap`: the session capability bundle. Must hold a `Read` grant for the
///   `ai/` scope.
/// - `filter`: optional category / sub-prefix narrowing. An empty
///   [`ListFilter`] lists the whole `ai/` scope.
///
/// # Errors
/// - [`ListError::Capability`] if the bundle lacks the `ai/` read grant (raised
///   with NO I/O performed).
/// - [`ListError::Client`] if building the client or the forest listing fails.
pub async fn list_files(
    cap: &CapabilityBundle,
    filter: &ListFilter,
) -> Result<Vec<FileEntry>, ListError> {
    // GATE FIRST — no client, no network until this passes. The scope ARGUMENT is
    // always WORKSPACE_KEY_PREFIX (`ai`) because the held grant is `ai/`; the KEY
    // argument tightens to `ai/<category>` when a category filter is present, so a
    // category enumeration still proves its key is geometrically inside `ai/`.
    // `?` maps CapabilityError -> ListError::Capability (the distinct DENIED type).
    let scope_key = match &filter.category {
        Some(cat) => format!("{}/{}", WORKSPACE_KEY_PREFIX, cat.name()),
        None => WORKSPACE_KEY_PREFIX.to_string(),
    };
    cap.assert_in_scope(&scope_key, WORKSPACE_KEY_PREFIX, Permission::Read)?;

    // Authorized: build the workspace client (own secret) and list ITS OWN forest.
    let client = cap.workspace_client()?;
    let entries = client
        .list_files_from_forest(crate::store::WORKSPACE_BUCKET)
        .await
        .map_err(|e| ListError::Client(format!("list_files_from_forest: {e}")))?;

    // Confine to `ai/`, apply the feature filters, and project to FileEntry. This
    // is the pure step the offline tests drive directly with hand-built entries.
    Ok(confine_filter_map(cap, &entries, filter))
}

/// Search the AI's workspace by **filename** substring, case-insensitively.
///
/// Implemented as [`list_files`] over the whole `ai/` scope (so it inherits the
/// exact scope confinement — a non-`ai/` key can never appear) followed by a pure
/// filter: keep entries whose filename (the last `/`-segment of the key) contains
/// `query`, compared case-insensitively. An empty query matches every confined
/// entry (it is a substring of everything).
///
/// Tag-based search is P8 and is intentionally NOT added here; this is a
/// filename/key search only. The P8 seam is [`ListFilter`] (a `tags` predicate),
/// not this function.
///
/// # Errors
/// Same as [`list_files`]: [`ListError::Capability`] if the `ai/` read grant is
/// absent (no I/O), or [`ListError::Client`] on a listing failure.
pub async fn search(cap: &CapabilityBundle, query: &str) -> Result<Vec<FileEntry>, ListError> {
    let all = list_files(cap, &ListFilter::default()).await?;
    let needle = query.to_lowercase();
    Ok(all
        .into_iter()
        .filter(|e| filename_of(&e.key).to_lowercase().contains(&needle))
        .collect())
}

/// The pure core of [`list_files`]: confine raw forest entries to the `ai/`
/// scope, apply the optional category / sub-prefix filters, and project to
/// [`FileEntry`]. NO network, NO crypto — only `cap`'s synchronous segment checks.
///
/// Split out from [`list_files`] precisely so the scope-confinement behavior is
/// unit-testable with **hand-built** [`FileMetadata`] (the offline tests construct
/// a list mixing `ai/…` and non-`ai/` keys and assert only the `ai/` ones
/// survive) — `list_files_from_forest` itself always hits the wire, so it cannot
/// be fed constructed entries.
///
/// Steps, in order:
/// 1. **Confine** — keep an entry iff `assert_in_scope(key, "ai", Read).is_ok()`
///    (P3 segment geometry + the `ai/` authority the gate already proved). Drops
///    non-`ai/` keys, `ai-evil/…`, and non-canonical entries.
/// 2. **Category filter** — if set, keep iff the key's `<category>` segment maps
///    to that category. Pure segment compare (NOT `assert_in_scope`).
/// 3. **Prefix filter** — if set, keep iff the key is inside that sub-prefix by
///    segment boundary. Pure segment compare.
/// 4. **Map** — build [`FileEntry`], deriving the category from the key segment
///    (falling back to [`classify`]).
fn confine_filter_map(
    cap: &CapabilityBundle,
    entries: &[FileMetadata],
    filter: &ListFilter,
) -> Vec<FileEntry> {
    // Pre-split the optional prefix filter into canonical segments ONCE. A prefix
    // that fails canonicalization (or that is not itself inside `ai/`) can match
    // nothing, so we short-circuit to an empty result rather than ignoring it.
    let prefix_segs: Option<Vec<String>> = match &filter.prefix {
        Some(p) => match canonical_segments(p) {
            Some(segs) if segs.first().map(String::as_str) == Some(WORKSPACE_KEY_PREFIX) => {
                Some(segs)
            }
            // Prefix is malformed or outside `ai/` → matches nothing.
            _ => return Vec::new(),
        },
        None => None,
    };

    entries
        .iter()
        .filter_map(|meta| {
            let key = meta.original_key.as_str();

            // (1) CONFINE: must be inside `ai/` by the P3 segment gate. This is the
            //     security boundary — it reuses the exact geometry assert_in_scope
            //     enforces, so no non-`ai/` (or non-canonical) key survives.
            if cap
                .assert_in_scope(key, WORKSPACE_KEY_PREFIX, Permission::Read)
                .is_err()
            {
                return None;
            }

            // From here the key is canonical AND inside `ai/`, so it splits into
            // at least the `ai` segment; the category is segment[1] when present.
            let segs: Vec<&str> = key.split('/').collect();
            let category_segment = segs.get(1).copied();

            // (2) CATEGORY filter (pure segment compare — never assert_in_scope).
            if let Some(want) = filter.category {
                // The entry's category segment must map to exactly `want`. A key
                // with no category segment (a bare `ai/<file>`, which the store
                // path never writes) cannot match a category filter.
                if category_segment.and_then(Category::from_name) != Some(want) {
                    return None;
                }
            }

            // (3) PREFIX filter (pure segment boundary — never assert_in_scope).
            if let Some(want_segs) = &prefix_segs {
                if !segments_prefix(&segs, want_segs) {
                    return None;
                }
            }

            // (4) MAP: derive the category from the key segment, falling back to
            //     the classifier on the content-type when the segment is foreign.
            let category = category_segment
                .and_then(Category::from_name)
                .unwrap_or_else(|| classify(meta.content_type.as_deref(), key, None));

            Some(FileEntry {
                key: key.to_string(),
                size: meta.original_size,
                content_type: meta.content_type.clone(),
                category,
                modified_at: meta.modified_at,
            })
        })
        .collect()
}

/// The filename (last `/`-segment) of a logical key, or the whole key if it has
/// no separator. Mirrors `FileMetadata::filename` so search keys off the same
/// notion of "filename" the SDK uses.
fn filename_of(key: &str) -> &str {
    key.rsplit('/').next().unwrap_or(key)
}

/// Split a path into non-empty segments, rejecting `.`/`..` traversal — a small,
/// LENIENT canonicalizer for the sub-prefix filter (which never reaches storage,
/// so leading/trailing/doubled slashes are dropped, mirroring the scope canon in
/// P3). Returns `None` for an empty result or a traversal segment.
///
/// We keep this local (rather than exposing P3's private `canonicalize_scope`) so
/// the list module owns its own small, auditable prefix-normalization and does not
/// widen the capability layer's API surface.
fn canonical_segments(path: &str) -> Option<Vec<String>> {
    if path.contains('\0') {
        return None;
    }
    let mut out = Vec::new();
    for seg in path.split('/') {
        if seg.is_empty() {
            continue; // drop leading/trailing/doubled slash (lenient, like a scope)
        }
        if seg == "." || seg == ".." {
            return None; // a prefix has nothing to resolve traversal against
        }
        out.push(seg.to_string());
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

/// Is `key_segs` inside `prefix_segs` by path-segment prefix? True iff `key_segs`
/// starts with `prefix_segs`, element-by-element. Equal lists prefix each other
/// (an exact-key prefix is admitted). This is the same segment-boundary rule P3
/// uses, applied here to the feature sub-prefix filter.
fn segments_prefix(key_segs: &[&str], prefix_segs: &[String]) -> bool {
    if prefix_segs.len() > key_segs.len() {
        return false;
    }
    prefix_segs
        .iter()
        .zip(key_segs.iter())
        .all(|(p, k)| p == k)
}

#[cfg(test)]
mod tests {
    use super::*;

    use base64::Engine as _;
    use fula_crypto::SecretKey;
    use std::collections::HashMap;

    use crate::capability::CapabilityBundle as Bundle;

    // ── Bundle builders (offline; the endpoint is never contacted) ──────────

    /// A bundle JSON with a single configurable grant. `endpoint` is unreachable
    /// so any accidental I/O fails loudly (and DIFFERENTLY from a Capability
    /// denial), which is what the gate-before-I/O proof relies on.
    fn bundle_json(grant_scope: Option<&str>, can_read: bool) -> String {
        let ws = base64::engine::general_purpose::STANDARD.encode([1u8; 32]);
        let mcp = base64::engine::general_purpose::STANDARD.encode([2u8; 32]);
        let owner = base64::engine::general_purpose::STANDARD.encode(
            SecretKey::from_bytes(&[3u8; 32]).unwrap().public_key().as_bytes(),
        );
        let grants = match grant_scope {
            Some(s) => format!(
                r#"[{{ "scope": "{s}", "permissions": {{ "can_read": {can_read}, "can_write": false, "can_delete": false }} }}]"#
            ),
            None => "[]".to_string(),
        };
        format!(
            r#"{{ "endpoint": "https://offline.invalid", "jwt": "j", "workspace_secret_b64": "{ws}", "mcp_secret_b64": "{mcp}", "owner_public_b64": "{owner}", "grants": {grants} }}"#
        )
    }

    /// The normal session bundle: holds an `ai/` READ grant.
    fn ai_read_bundle() -> Bundle {
        Bundle::from_json(&bundle_json(Some("ai/"), true)).unwrap()
    }

    /// Construct a forest entry directly (NO network), the way the SDK would
    /// surface one. Only the fields the enumeration reads are meaningful.
    fn meta(key: &str, size: u64, content_type: Option<&str>, modified_at: Option<i64>) -> FileMetadata {
        FileMetadata {
            storage_key: format!("obfuscated-of-{key}"),
            original_key: key.to_string(),
            original_size: size,
            content_type: content_type.map(|s| s.to_string()),
            created_at: modified_at,
            modified_at,
            user_metadata: HashMap::new(),
            is_encrypted: true,
        }
    }

    /// A representative mixed listing: several genuine `ai/<category>/…` keys PLUS
    /// hostile / out-of-scope keys the confinement MUST drop. Returned in a fixed
    /// order so tests can assert exact membership.
    fn mixed_listing() -> Vec<FileMetadata> {
        vec![
            meta("ai/image/uuid1-photo.png", 1000, Some("image/png"), Some(100)),
            meta("ai/note/uuid2-summary.txt", 50, Some("text/plain"), Some(200)),
            meta("ai/document/uuid3-report.pdf", 4000, Some("application/pdf"), Some(300)),
            // ── must be DROPPED by confinement ──
            meta("photos/2026/vacation.jpg", 9999, Some("image/jpeg"), Some(400)), // user's real bucket key
            meta("ai-evil/secret.txt", 7, Some("text/plain"), Some(500)),          // first-segment substring footgun
            meta("documents/private.pdf", 8888, Some("application/pdf"), Some(600)), // sibling top-level
            meta("ai/../escape.txt", 1, Some("text/plain"), Some(700)),            // non-canonical (traversal)
            meta("ai//doubled.txt", 1, Some("text/plain"), Some(800)),             // non-canonical (doubled slash)
        ]
    }

    fn keys(entries: &[FileEntry]) -> Vec<&str> {
        entries.iter().map(|e| e.key.as_str()).collect()
    }

    // ── (1) SCOPE CONFINEMENT — only ai/ keys survive ──────────────────────

    #[test]
    fn confine_keeps_only_ai_keys_and_drops_everything_else() {
        let cap = ai_read_bundle();
        let out = confine_filter_map(&cap, &mixed_listing(), &ListFilter::default());
        // Exactly the three genuine ai/ keys, in listing order; nothing else.
        assert_eq!(
            keys(&out),
            vec![
                "ai/image/uuid1-photo.png",
                "ai/note/uuid2-summary.txt",
                "ai/document/uuid3-report.pdf",
            ]
        );
        // Explicit: NONE of the hostile keys leaked.
        for leaked in [
            "photos/2026/vacation.jpg",
            "ai-evil/secret.txt",
            "documents/private.pdf",
            "ai/../escape.txt",
            "ai//doubled.txt",
        ] {
            assert!(
                !keys(&out).contains(&leaked),
                "confinement leaked a non-ai/ or non-canonical key: {leaked}"
            );
        }
    }

    #[test]
    fn confine_derives_category_from_key_segment() {
        let cap = ai_read_bundle();
        let out = confine_filter_map(&cap, &mixed_listing(), &ListFilter::default());
        assert_eq!(out[0].category, Category::Image);
        assert_eq!(out[1].category, Category::Note);
        assert_eq!(out[2].category, Category::Document);
        // And the projected metadata is carried straight through.
        assert_eq!(out[0].size, 1000);
        assert_eq!(out[0].content_type.as_deref(), Some("image/png"));
        assert_eq!(out[0].modified_at, Some(100));
    }

    #[test]
    fn confine_category_fallback_when_segment_is_foreign() {
        // A key that IS inside ai/ but whose 2nd segment is not a known category:
        // the category derives from classify(content_type, …) instead of the
        // segment, and the entry is still surfaced (it's a legitimate ai/ key).
        let cap = ai_read_bundle();
        let entries = vec![meta("ai/inbox/uuid-clip.mp4", 5000, Some("video/mp4"), Some(1))];
        let out = confine_filter_map(&cap, &entries, &ListFilter::default());
        assert_eq!(keys(&out), vec!["ai/inbox/uuid-clip.mp4"]);
        // "inbox" is not a category name → fall back to classify → video/mp4 = Video.
        assert_eq!(out[0].category, Category::Video);
    }

    // ── (2) CATEGORY filter narrows correctly ──────────────────────────────

    #[test]
    fn category_filter_narrows_to_one_category() {
        let cap = ai_read_bundle();
        let filter = ListFilter {
            category: Some(Category::Note),
            prefix: None,
        };
        let out = confine_filter_map(&cap, &mixed_listing(), &filter);
        assert_eq!(keys(&out), vec!["ai/note/uuid2-summary.txt"]);
        assert_eq!(out[0].category, Category::Note);
    }

    #[test]
    fn category_filter_for_absent_category_is_empty() {
        // No audio files in the listing → the audio filter yields nothing (and
        // crucially does NOT error or leak).
        let cap = ai_read_bundle();
        let filter = ListFilter {
            category: Some(Category::Audio),
            prefix: None,
        };
        let out = confine_filter_map(&cap, &mixed_listing(), &filter);
        assert!(out.is_empty());
    }

    // ── (3) PREFIX filter (pure segment boundary) ──────────────────────────

    #[test]
    fn prefix_filter_uses_segment_boundary_not_substring() {
        let cap = ai_read_bundle();
        let entries = vec![
            meta("ai/image/a.png", 1, Some("image/png"), None),
            meta("ai/imagery/b.png", 1, Some("image/png"), None), // substring of "ai/image" but NOT a child segment
            meta("ai/note/c.txt", 1, Some("text/plain"), None),
        ];
        let filter = ListFilter {
            category: None,
            prefix: Some("ai/image".to_string()),
        };
        let out = confine_filter_map(&cap, &entries, &filter);
        // Only ai/image/* — ai/imagery/* must NOT match (segment boundary).
        assert_eq!(keys(&out), vec!["ai/image/a.png"]);
    }

    #[test]
    fn prefix_outside_ai_matches_nothing() {
        // A sub-prefix that is not itself inside ai/ can never select an ai/ key,
        // so the result is empty (defensive: we never widen beyond ai/).
        let cap = ai_read_bundle();
        let filter = ListFilter {
            category: None,
            prefix: Some("photos/".to_string()),
        };
        let out = confine_filter_map(&cap, &mixed_listing(), &filter);
        assert!(out.is_empty());
    }

    #[test]
    fn category_and_prefix_filters_compose() {
        let cap = ai_read_bundle();
        let entries = vec![
            meta("ai/image/keep.png", 1, Some("image/png"), None),
            meta("ai/image/also.png", 1, Some("image/png"), None),
            meta("ai/note/skip.txt", 1, Some("text/plain"), None),
        ];
        let filter = ListFilter {
            category: Some(Category::Image),
            prefix: Some("ai/image/keep.png".to_string()), // exact-key prefix
        };
        let out = confine_filter_map(&cap, &entries, &filter);
        assert_eq!(keys(&out), vec!["ai/image/keep.png"]);
    }

    // ── (4) the GATE actually fires BEFORE any I/O (async, offline) ─────────
    //
    // The bundle endpoint is https://offline.invalid. If the gate did NOT fire
    // first, list_files would build a client and hit the network, surfacing a
    // Client error. Asserting a *Capability* error instead is positive proof the
    // synchronous gate short-circuited BEFORE any client construction / I/O. We
    // can't reuse P6's out-of-scope-KEY trick (the scope key `ai`/`ai/<cat>` is
    // always geometrically inside `ai/`), so the lever is the AUTHORITY arm: a
    // bundle lacking the `ai/` read grant is denied pre-I/O.

    #[tokio::test]
    async fn list_files_denies_without_ai_grant_before_any_io() {
        // Bundle with NO grants → no `ai/` read authority → Capability denial,
        // NOT a network error against offline.invalid.
        let cap = Bundle::from_json(&bundle_json(None, false)).unwrap();
        let err = list_files(&cap, &ListFilter::default()).await.unwrap_err();
        assert!(
            matches!(err, ListError::Capability(CapabilityError::OutOfScope { .. })),
            "no-grant enumeration must deny pre-I/O (got {err:?})"
        );
    }

    #[tokio::test]
    async fn list_files_denies_read_only_missing_before_any_io() {
        // An `ai/` grant that is NOT readable (can_read:false) → denied pre-I/O.
        let cap = Bundle::from_json(&bundle_json(Some("ai/"), false)).unwrap();
        let err = list_files(&cap, &ListFilter::default()).await.unwrap_err();
        assert!(
            matches!(err, ListError::Capability(CapabilityError::OutOfScope { .. })),
            "read-missing enumeration must deny pre-I/O (got {err:?})"
        );
    }

    #[tokio::test]
    async fn list_files_with_category_denies_without_grant_before_any_io() {
        // Same proof for the category path (scope_key = ai/<category>): still
        // authorized by the `ai/` grant, so a missing grant denies pre-I/O.
        let cap = Bundle::from_json(&bundle_json(None, false)).unwrap();
        let filter = ListFilter {
            category: Some(Category::Image),
            prefix: None,
        };
        let err = list_files(&cap, &filter).await.unwrap_err();
        assert!(
            matches!(err, ListError::Capability(CapabilityError::OutOfScope { .. })),
            "category enumeration must deny pre-I/O without grant (got {err:?})"
        );
    }

    #[tokio::test]
    async fn search_denies_without_ai_grant_before_any_io() {
        // search delegates to list_files, so it inherits the gate-before-I/O.
        let cap = Bundle::from_json(&bundle_json(None, false)).unwrap();
        let err = search(&cap, "anything").await.unwrap_err();
        assert!(
            matches!(err, ListError::Capability(CapabilityError::OutOfScope { .. })),
            "no-grant search must deny pre-I/O (got {err:?})"
        );
    }

    // ── (5) SEARCH — filename match, case-insensitive, never leaks ─────────
    //
    // search() composes list_files (which hits the wire) so we test its pure
    // filter via a small replica of the exact post-list predicate, fed the
    // confined entries from confine_filter_map. This proves the filename-substring
    // case-insensitivity AND that non-ai/ keys never reach the search result
    // (because the input is already confined).

    /// The exact filter search() applies after listing.
    fn search_filter(entries: Vec<FileEntry>, query: &str) -> Vec<FileEntry> {
        let needle = query.to_lowercase();
        entries
            .into_iter()
            .filter(|e| filename_of(&e.key).to_lowercase().contains(&needle))
            .collect()
    }

    #[test]
    fn search_matches_filename_case_insensitively() {
        let cap = ai_read_bundle();
        let confined = confine_filter_map(&cap, &mixed_listing(), &ListFilter::default());
        // "REPORT" (upper) must match ai/document/uuid3-report.pdf (lower).
        let out = search_filter(confined.clone(), "REPORT");
        assert_eq!(keys(&out), vec!["ai/document/uuid3-report.pdf"]);
        // "photo" matches the image filename.
        let out2 = search_filter(confined.clone(), "photo");
        assert_eq!(keys(&out2), vec!["ai/image/uuid1-photo.png"]);
    }

    #[test]
    fn search_matches_on_filename_not_category_segment() {
        // The crux of "matches the FILENAME": searching the category word "image"
        // must NOT return every ai/image/* file — only files whose FILENAME
        // contains "image". Here the note's filename literally contains "image".
        let cap = ai_read_bundle();
        let entries = vec![
            meta("ai/image/uuid-a.png", 1, Some("image/png"), None), // filename "uuid-a.png" has no "image"
            meta("ai/note/uuid-image-of-cat.txt", 1, Some("text/plain"), None), // filename DOES contain "image"
        ];
        let confined = confine_filter_map(&cap, &entries, &ListFilter::default());
        let out = search_filter(confined, "image");
        assert_eq!(
            keys(&out),
            vec!["ai/note/uuid-image-of-cat.txt"],
            "search must match the filename, not the ai/<category>/ path segment"
        );
    }

    #[test]
    fn search_never_leaks_non_ai_keys() {
        // Even if a hostile filename would textually match the query, confinement
        // runs FIRST (the input to the search filter is already confined), so a
        // non-ai/ key can never be in a search result.
        let cap = ai_read_bundle();
        let entries = vec![
            meta("photos/2026/secret-report.jpg", 1, Some("image/jpeg"), None), // dropped by confinement
            meta("ai/document/uuid-report.pdf", 1, Some("application/pdf"), None),
        ];
        let confined = confine_filter_map(&cap, &entries, &ListFilter::default());
        let out = search_filter(confined, "report");
        // Only the ai/ document — the photos/ key was already dropped.
        assert_eq!(keys(&out), vec!["ai/document/uuid-report.pdf"]);
    }

    #[test]
    fn search_empty_query_returns_all_confined() {
        let cap = ai_read_bundle();
        let confined = confine_filter_map(&cap, &mixed_listing(), &ListFilter::default());
        let out = search_filter(confined.clone(), "");
        assert_eq!(out.len(), confined.len());
        assert_eq!(out.len(), 3, "only the three ai/ keys, all matched by empty query");
    }

    // ── helper-level unit checks ────────────────────────────────────────────

    #[test]
    fn filename_of_takes_last_segment() {
        assert_eq!(filename_of("ai/image/uuid-photo.png"), "uuid-photo.png");
        assert_eq!(filename_of("noslash"), "noslash");
    }

    #[test]
    fn canonical_segments_is_lenient_but_rejects_traversal() {
        assert_eq!(
            canonical_segments("ai/image").unwrap(),
            vec!["ai".to_string(), "image".to_string()]
        );
        // Lenient about slashes (a prefix never reaches storage).
        assert_eq!(canonical_segments("/ai//image/").unwrap(), vec!["ai", "image"]);
        // Rejects traversal / empty / NUL.
        assert!(canonical_segments("ai/../x").is_none());
        assert!(canonical_segments("").is_none());
        assert!(canonical_segments("/").is_none());
        assert!(canonical_segments("ai/\0/x").is_none());
    }

    #[test]
    fn category_from_name_round_trips_name() {
        for cat in [
            Category::Link,
            Category::Note,
            Category::Screenshot,
            Category::Image,
            Category::Video,
            Category::Audio,
            Category::Document,
            Category::File,
            Category::Other,
        ] {
            assert_eq!(Category::from_name(cat.name()), Some(cat));
        }
        assert_eq!(Category::from_name("inbox"), None);
        assert_eq!(Category::from_name("Image"), None, "case-sensitive (name() is lowercase)");
    }
}
