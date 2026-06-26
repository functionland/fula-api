//! # `list_files` + `search` — the AI's collaboration ENUMERATION ops
//!
//! Enumerate the group's manifest. Authorization is membership in the group (the
//! bundle is per-group), so there is no `ai/`-scope confinement — every entry the
//! manifest lists is shared with the group. A folder tree is *derived* from each
//! entry's logical path (see [`crate::tree`]); directory markers are returned as
//! entries with [`FileEntry::is_directory`] set so a client can build the tree.
//!
//! - [`list_files`] — all live entries, optionally narrowed by a `folder` prefix
//!   and/or a `category`, and optionally excluding directory markers.
//! - [`search`] — live FILE entries whose filename or logical path contains the
//!   query (case-insensitive).
//!
//! `category` is **re-derived** from each entry's `content_type` + filename at list
//! time (the manifest does not store a category). For `link`/`note` files — whose
//! category was decided from the body text at store time — the re-derived category
//! may differ, since the body is not present during a listing; this is a known,
//! best-effort convenience, not an authority decision.

use crate::capability::CapabilityBundle;
use crate::category::{classify, Category};
use crate::collab::{self, CollabError};
use crate::manifest::{CollaborationFile, CollaborationGroup};
use crate::tree::{is_directory, live_files, logical_path_of, path_under_folder};

/// Optional narrowing for [`list_files`].
#[derive(Debug, Clone, Default)]
pub struct ListFilter {
    /// Only entries strictly under this folder (segment-boundary). `None` ⇒ the
    /// whole group.
    pub folder: Option<String>,
    /// Only files of this (re-derived) category. Directory markers never match a
    /// category filter.
    pub category: Option<Category>,
    /// Include directory markers in the result (default via [`Default`] is `false`;
    /// callers building a tree should set `true`).
    pub include_directories: bool,
}

/// One enumerated manifest entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileEntry {
    /// The entry's UUID.
    pub file_id: String,
    /// The display filename (or folder leaf).
    pub file_name: String,
    /// The derived logical path.
    pub path: String,
    /// Whether this entry is a folder marker.
    pub is_directory: bool,
    /// The re-derived category (best-effort; see the module note).
    pub category: Category,
    /// The recorded MIME type, if any.
    pub content_type: Option<String>,
    /// The on-wire encoding (`"collab"` / `"fula"`).
    pub enc_type: String,
    /// The recorded size in bytes.
    pub size: i64,
    /// Base64 public key of whoever added the entry.
    pub added_by_public_key: String,
    /// The raw ISO-8601 `addedAt` string from the manifest.
    pub added_at: String,
    /// `added_at` parsed to Unix seconds, best-effort (`None` if unparseable).
    pub modified_at: Option<i64>,
}

/// Errors surfaced by the enumeration ops.
#[derive(Debug, thiserror::Error)]
pub enum ListError {
    /// A collaboration HTTP / manifest failure.
    #[error("collaboration error: {0}")]
    Collab(#[from] CollabError),
}

/// Parse an ISO-8601 timestamp (with or without a `Z` / offset) to Unix seconds,
/// best-effort. Naive (offset-less) strings are interpreted as UTC.
fn parse_ts(s: &str) -> Option<i64> {
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(s) {
        return Some(dt.timestamp());
    }
    let naive = s.strip_suffix('Z').unwrap_or(s);
    for fmt in ["%Y-%m-%dT%H:%M:%S%.f", "%Y-%m-%dT%H:%M:%S"] {
        if let Ok(ndt) = chrono::NaiveDateTime::parse_from_str(naive, fmt) {
            return Some(ndt.and_utc().timestamp());
        }
    }
    None
}

/// Build a [`FileEntry`] for a manifest file (path + directory flag + category
/// already computed by the caller).
fn entry_of(f: &CollaborationFile, path: String, is_dir: bool, category: Category) -> FileEntry {
    FileEntry {
        file_id: f.id.clone(),
        file_name: f.file_name.clone(),
        path,
        is_directory: is_dir,
        category,
        content_type: f.content_type.clone(),
        enc_type: f.enc_type.clone(),
        size: f.file_size,
        added_by_public_key: f.added_by_public_key.clone(),
        added_at: f.added_at.clone(),
        modified_at: parse_ts(&f.added_at),
    }
}

/// Pure enumeration core: apply `filter` over the manifest's live entries.
fn confine(manifest: &CollaborationGroup, filter: &ListFilter) -> Vec<FileEntry> {
    live_files(manifest)
        .into_iter()
        .filter_map(|f| {
            let is_dir = is_directory(f);
            if is_dir && !filter.include_directories {
                return None;
            }
            let path = logical_path_of(f);
            if let Some(folder) = filter.folder.as_deref() {
                if !path_under_folder(&path, folder) {
                    return None;
                }
            }
            let category = classify(f.content_type.as_deref(), &f.file_name, None);
            if let Some(want) = filter.category {
                if is_dir || category != want {
                    return None;
                }
            }
            Some(entry_of(f, path, is_dir, category))
        })
        .collect()
}

/// Pure search core: live FILE entries whose filename or path contains `query`.
fn search_in(manifest: &CollaborationGroup, query: &str) -> Vec<FileEntry> {
    let needle = query.trim().to_lowercase();
    if needle.is_empty() {
        return Vec::new();
    }
    live_files(manifest)
        .into_iter()
        .filter(|f| !is_directory(f))
        .filter_map(|f| {
            let path = logical_path_of(f);
            if f.file_name.to_lowercase().contains(&needle)
                || path.to_lowercase().contains(&needle)
            {
                let category = classify(f.content_type.as_deref(), &f.file_name, None);
                Some(entry_of(f, path, false, category))
            } else {
                None
            }
        })
        .collect()
}

/// List the group's files (and, if requested, folder markers), applying `filter`.
/// A group with no manifest yet yields an empty list.
pub async fn list_files(
    cap: &CapabilityBundle,
    filter: &ListFilter,
) -> Result<Vec<FileEntry>, ListError> {
    match collab::fetch_manifest(cap.http(), cap.webui_base(), cap.group_id(), cap.link_secret())
        .await?
    {
        Some(manifest) => Ok(confine(&manifest, filter)),
        None => Ok(Vec::new()),
    }
}

/// Search the group's files by filename / path substring (case-insensitive).
pub async fn search(cap: &CapabilityBundle, query: &str) -> Result<Vec<FileEntry>, ListError> {
    match collab::fetch_manifest(cap.http(), cap.webui_base(), cap.group_id(), cap.link_secret())
        .await?
    {
        Some(manifest) => Ok(search_in(&manifest, query)),
        None => Ok(Vec::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree::DIRECTORY_CONTENT_TYPE;

    fn group() -> CollaborationGroup {
        serde_json::from_str(
            r#"{"id":"g","name":"n","ownerPublicKey":"o","manifestKey":"k","createdAt":"c","updatedAt":"u","files":[]}"#,
        )
        .unwrap()
    }

    fn file(id: &str, name: &str, scope: Option<&str>, ct: Option<&str>) -> CollaborationFile {
        CollaborationFile {
            id: id.to_string(),
            file_name: name.to_string(),
            content_type: ct.map(str::to_string),
            bucket: "b".to_string(),
            storage_key: format!("sk-{id}"),
            path_scope: scope.map(str::to_string),
            added_by_public_key: "pk".to_string(),
            added_at: "2026-01-02T03:04:05.000Z".to_string(),
            file_size: 10,
            enc_type: "collab".to_string(),
            share_token_json: None,
        }
    }

    fn populated() -> CollaborationGroup {
        let mut g = group();
        g.files.push(file("F1", "memo.txt", Some("/notes"), Some("text/plain")));
        g.files.push(file("F2", "pic.jpg", Some("/notes"), Some("image/jpeg")));
        g.files.push(file("F3", "root.txt", None, Some("text/plain")));
        let mut dir = file("D1", "notes", Some("/notes"), Some(DIRECTORY_CONTENT_TYPE));
        dir.file_size = 0;
        g.files.push(dir);
        // A tombstoned file must never appear.
        g.files.push(file("F4", "gone.txt", None, Some("text/plain")));
        g.removed_file_ids.push("F4".to_string());
        g
    }

    #[test]
    fn list_default_excludes_dirs_and_tombstones() {
        let g = populated();
        let out = confine(&g, &ListFilter::default());
        let ids: Vec<&str> = out.iter().map(|e| e.file_id.as_str()).collect();
        assert_eq!(ids, vec!["F1", "F2", "F3"]); // no D1 (dir), no F4 (tombstone)
    }

    #[test]
    fn list_folder_filter_segment_boundary() {
        let g = populated();
        let f = ListFilter {
            folder: Some("/notes".into()),
            include_directories: true,
            ..Default::default()
        };
        let out = confine(&g, &f);
        let ids: std::collections::HashSet<&str> =
            out.iter().map(|e| e.file_id.as_str()).collect();
        // F1, F2 are under /notes; D1 marker is AT /notes (not "under") so excluded;
        // F3 is at root.
        assert!(ids.contains("F1") && ids.contains("F2"));
        assert!(!ids.contains("F3") && !ids.contains("D1"));
    }

    #[test]
    fn list_category_filter_excludes_dirs() {
        let g = populated();
        let f = ListFilter {
            category: Some(Category::Image),
            include_directories: true,
            ..Default::default()
        };
        let out = confine(&g, &f);
        let ids: Vec<&str> = out.iter().map(|e| e.file_id.as_str()).collect();
        assert_eq!(ids, vec!["F2"]); // only the jpeg; the dir never matches a category
    }

    #[test]
    fn list_include_directories_flag() {
        let g = populated();
        let f = ListFilter {
            include_directories: true,
            ..Default::default()
        };
        let out = confine(&g, &f);
        let dir = out.iter().find(|e| e.file_id == "D1").expect("dir present");
        assert!(dir.is_directory);
        assert_eq!(dir.path, "/notes");
    }

    #[test]
    fn search_matches_name_and_path_skips_dirs() {
        let g = populated();
        let by_name = search_in(&g, "MEMO");
        assert_eq!(by_name.len(), 1);
        assert_eq!(by_name[0].file_id, "F1");
        // Path match.
        let by_path = search_in(&g, "/notes");
        let ids: std::collections::HashSet<&str> =
            by_path.iter().map(|e| e.file_id.as_str()).collect();
        assert!(ids.contains("F1") && ids.contains("F2"));
        assert!(!ids.contains("D1"), "search excludes directory markers");
        // Empty query ⇒ empty.
        assert!(search_in(&g, "   ").is_empty());
    }

    #[test]
    fn entry_parses_timestamp() {
        let g = populated();
        let out = confine(&g, &ListFilter::default());
        assert!(out[0].modified_at.is_some());
    }
}
