//! # Pure path / tree helpers over the collaboration manifest
//!
//! The manifest is a flat list of [`CollaborationFile`]s; a folder tree is
//! *derived* from each file's `path_scope` + `file_name`, with directories
//! represented by marker entries whose `content_type` is
//! [`DIRECTORY_CONTENT_TYPE`]. These helpers are pure (no I/O) and shared by
//! [`crate::read`], [`crate::list`], and [`crate::store`].
//!
//! ## `path_scope` is interpreted leniently
//!
//! Two producers write `path_scope` differently:
//! - the **AI** (this crate) writes the containing FOLDER (e.g. `"/notes"`), per
//!   the collab-rework contract;
//! - the **FxFiles app** sometimes writes the file's FULL path (e.g.
//!   `"/legal/contract.pdf"`), matching the Dart vector.
//!
//! [`logical_path_of`] reconciles both: if `path_scope`'s last segment already
//! equals `file_name` it is treated as a full path; otherwise it is treated as the
//! containing folder and `file_name` is appended. All files are in-group (hence
//! authorized), so a mismatched interpretation is at worst a display/addressing
//! nuance, never an access decision.

use crate::manifest::{CollaborationFile, CollaborationGroup};

/// The `content_type` marking a manifest entry as a folder (not a file).
pub const DIRECTORY_CONTENT_TYPE: &str = "application/x-directory";

/// Is this manifest entry a folder marker?
pub fn is_directory(file: &CollaborationFile) -> bool {
    file.content_type.as_deref() == Some(DIRECTORY_CONTENT_TYPE)
}

/// Normalize a user-supplied folder path to canonical `"/a/b"` form (leading
/// slash, no trailing slash, collapsed inner slashes).
///
/// Returns `Ok(None)` for the group root (empty / `"/"`), `Ok(Some(path))` for a
/// real folder, and `Err` for a path containing a `.`/`..` segment or a NUL.
pub fn normalize_folder(path: &str) -> Result<Option<String>, &'static str> {
    let trimmed = path.trim();
    if trimmed.is_empty() || trimmed == "/" {
        return Ok(None);
    }
    if trimmed.contains('\0') {
        return Err("path must not contain a NUL byte");
    }
    let mut segs: Vec<&str> = Vec::new();
    for seg in trimmed.split('/') {
        if seg.is_empty() {
            continue; // collapse `//`, leading/trailing `/`
        }
        if seg == "." || seg == ".." {
            return Err("path must not contain `.` or `..` segments");
        }
        segs.push(seg);
    }
    if segs.is_empty() {
        return Ok(None);
    }
    Ok(Some(format!("/{}", segs.join("/"))))
}

/// The user-facing logical path of a manifest entry (file or folder marker).
///
/// See the module note: `path_scope` is treated as a full path when its last
/// segment equals `file_name`, otherwise as the containing folder.
pub fn logical_path_of(file: &CollaborationFile) -> String {
    let name = file.file_name.trim_matches('/');
    match file
        .path_scope
        .as_deref()
        .and_then(|s| normalize_folder(s).ok().flatten())
    {
        None => format!("/{name}"),
        Some(dir) => {
            let leaf = dir.rsplit('/').next().unwrap_or("");
            if leaf == name {
                dir // path_scope already IS the full path (Dart style)
            } else {
                format!("{dir}/{name}") // path_scope is the containing folder
            }
        }
    }
}

/// Is `logical_path` strictly UNDER `folder` (segment-boundary)? A root/invalid
/// `folder` imposes no restriction (everything matches). The folder marker for
/// `folder` itself is NOT considered under it (only its contents are).
pub fn path_under_folder(logical_path: &str, folder: &str) -> bool {
    match normalize_folder(folder) {
        Ok(Some(dir)) => logical_path.starts_with(&format!("{dir}/")),
        _ => true,
    }
}

/// Is `id` tombstoned (present in `removed_file_ids`)?
pub fn is_tombstoned(group: &CollaborationGroup, id: &str) -> bool {
    group.removed_file_ids.iter().any(|t| t == id)
}

/// The live (non-tombstoned) entries of a manifest, in manifest order.
pub fn live_files(group: &CollaborationGroup) -> Vec<&CollaborationFile> {
    group
        .files
        .iter()
        .filter(|f| !is_tombstoned(group, &f.id))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(name: &str, scope: Option<&str>, ct: Option<&str>) -> CollaborationFile {
        CollaborationFile {
            id: format!("id-{name}"),
            file_name: name.to_string(),
            content_type: ct.map(str::to_string),
            bucket: "b".to_string(),
            storage_key: "sk".to_string(),
            path_scope: scope.map(str::to_string),
            added_by_public_key: "pk".to_string(),
            added_at: "2026-01-01T00:00:00.000Z".to_string(),
            file_size: 1,
            enc_type: "collab".to_string(),
            share_token_json: None,
        }
    }

    #[test]
    fn normalize_folder_cases() {
        assert_eq!(normalize_folder("").unwrap(), None);
        assert_eq!(normalize_folder("/").unwrap(), None);
        assert_eq!(normalize_folder("/notes").unwrap(), Some("/notes".into()));
        assert_eq!(normalize_folder("notes/").unwrap(), Some("/notes".into()));
        assert_eq!(normalize_folder("//a///b//").unwrap(), Some("/a/b".into()));
        assert!(normalize_folder("/a/../b").is_err());
        assert!(normalize_folder("/a/./b").is_err());
    }

    #[test]
    fn logical_path_folder_style_vs_full_path_style() {
        // AI style: path_scope is the folder.
        assert_eq!(
            logical_path_of(&file("memo.txt", Some("/notes"), None)),
            "/notes/memo.txt"
        );
        // Dart style: path_scope is already the full path.
        assert_eq!(
            logical_path_of(&file("contract.pdf", Some("/legal/contract.pdf"), None)),
            "/legal/contract.pdf"
        );
        // Root file.
        assert_eq!(logical_path_of(&file("a.txt", None, None)), "/a.txt");
        // Folder marker.
        let folder = file("alpha", Some("/projects/alpha"), Some(DIRECTORY_CONTENT_TYPE));
        assert!(is_directory(&folder));
        assert_eq!(logical_path_of(&folder), "/projects/alpha");
    }

    #[test]
    fn path_under_folder_segment_boundary() {
        assert!(path_under_folder("/notes/memo.txt", "/notes"));
        assert!(!path_under_folder("/notebook/x.txt", "/notes")); // segment boundary
        assert!(!path_under_folder("/notes", "/notes")); // the marker itself is not "under"
        assert!(path_under_folder("/anything", "/")); // root: no restriction
    }

    #[test]
    fn live_files_excludes_tombstones() {
        let mut g: CollaborationGroup = serde_json::from_str(
            r#"{"id":"g","name":"n","ownerPublicKey":"o","manifestKey":"k","createdAt":"c","updatedAt":"u","files":[]}"#,
        )
        .unwrap();
        g.files.push(file("a.txt", None, None));
        g.files.push(file("b.txt", None, None));
        g.removed_file_ids.push("id-b.txt".to_string());
        let live = live_files(&g);
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].file_name, "a.txt");
    }
}
