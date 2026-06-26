//! # `store` — the AI's collaboration WRITE ops (store / create_folder / remove)
//!
//! Every write operates on the group's encrypted **manifest** plus (for
//! `store_file`) a per-file encrypted blob. There is no workspace forest and no
//! `ai/` scope: the bundle is per-group, so authorization is simply "this is the
//! group the MCP was handed".
//!
//! ## The commit protocol (optimistic, merge-on-write)
//!
//! The manifest-sync `PUT` is **last-writer-wins** (no compare-and-swap), so a
//! naive overwrite would clobber a concurrent human edit. Each write therefore:
//!
//! 1. fetches the current manifest (the operation **base**);
//! 2. clones it and applies its purely-ADDITIVE change (append a file / append a
//!    folder marker / add a tombstone id) → `local`;
//! 3. fetches the manifest AGAIN, fresh, just before the PUT → `remote`;
//! 4. computes `remote.merge_with(&local)` — note the ordering: the FRESH `remote`
//!    is `self`, so it WINS on any existing-id conflict (a concurrent human rename
//!    / move of an existing file survives), while the AI's brand-new entry (a
//!    fresh UUID present only in `local`) is still unioned in. Tombstones union
//!    symmetrically. Because every AI op is additive, this never loses the human's
//!    edit nor the AI's change *in the merge*;
//! 5. re-encrypts (`ENC1:`) and PUTs, with one write-token refresh-and-retry.
//!
//! ### Residual lost-update window (documented; not closed here)
//!
//! Re-fetch-then-merge NARROWS but does not CLOSE the lost-update window: a human
//! `PUT` that lands between step 3 and step 5 is still clobbered by ours (and vice
//! versa) because the server offers no conditional write. Closing it requires a
//! server-side `If-Match: <version>` conditional PUT — a deliberate follow-up. For
//! the current model (a single AI partner + occasional human edits) the merge
//! makes the common cases safe; the rare overlap is the documented risk.
//!
//! ### Orphan blobs on a failed manifest PUT
//!
//! `store_file` uploads the blob BEFORE committing the manifest. If the manifest
//! PUT ultimately fails, the uploaded blob is unreferenced (orphaned) — we do NOT
//! issue a server `DELETE` (it is global/irreversible and could affect other
//! members; see `collab.rs`). Orphans are harmless (nothing points at them) and a
//! retry uses a fresh file id; a server-side GC of unreferenced collab files is a
//! follow-up.

use bytes::Bytes;
use uuid::Uuid;

use crate::capability::CapabilityBundle;
use crate::category::{classify, Category};
use crate::collab::{self, CollabError};
use crate::manifest::{collab_file_encrypt, enc1_encrypt, CollaborationFile, CollaborationGroup};
use crate::quota::QuotaDecision;
use crate::retry::with_collab_write_retry;
use crate::tree::{logical_path_of, normalize_folder, DIRECTORY_CONTENT_TYPE};

/// Errors surfaced by the write ops.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// A collaboration HTTP / manifest failure (includes
    /// [`CollabError::WriteNotConfigured`] when the session is read-only).
    #[error("collaboration error: {0}")]
    Collab(#[from] CollabError),

    /// The caller supplied an invalid filename or subfolder path.
    #[error("invalid input: {0}")]
    InvalidInput(String),

    /// The group has no manifest yet — it must be initialized (by a human client)
    /// before the AI can write into it. We never synthesize one (the bundle lacks
    /// the group name / owner key / created-at).
    #[error("the group manifest is not initialized; cannot write")]
    ManifestMissing,

    /// The per-session write rate limit was exceeded.
    #[error("write rate limit exceeded for this session")]
    RateLimited,

    /// The credit pre-check denied the write (gateway re-checks on the real PUT).
    #[error("storage quota exceeded")]
    QuotaExceeded,

    /// Re-serializing the merged manifest to JSON failed (unreachable in practice).
    #[error("manifest serialization failed: {0}")]
    Serialize(String),
}

/// The result of a successful [`store_file`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreOutcome {
    /// The new file's UUID (its stable handle for `read`/`remove`).
    pub file_id: String,
    /// The stored display filename.
    pub file_name: String,
    /// The file's derived logical path within the group (e.g. `/notes/memo.txt`).
    pub path: String,
    /// The classified category (derived; not stored in the manifest).
    pub category: Category,
    /// The MIME type recorded for the file, if any.
    pub content_type: Option<String>,
    /// The bucket the blob was stored in.
    pub bucket: String,
    /// The storage key of the blob.
    pub storage_key: String,
    /// The plaintext size in bytes.
    pub size: i64,
    /// The manifest version after the commit.
    pub manifest_version: i64,
}

/// The result of a [`create_folder`] / [`remove_file`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestMutation {
    /// The manifest version after the commit.
    pub manifest_version: i64,
    /// The logical path affected (the new folder, or the removed file's path if it
    /// was present in the base manifest).
    pub path: Option<String>,
}

/// Current UTC time as the ISO-8601 string shape the manifest uses
/// (`YYYY-MM-DDTHH:MM:SS.mmmZ`), matching the Dart `DateTime.toIso8601String()`
/// form that `manifest.rs`'s naive parser understands.
fn now_iso8601() -> String {
    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

/// Sanitize a display filename: trim, strip any path separators / NUL, and reject
/// an empty result. The manifest's `file_name` feeds [`logical_path_of`], so it
/// must be a single safe segment.
fn sanitize_file_name(raw: &str) -> Result<String, StoreError> {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.trim().chars() {
        match ch {
            '/' | '\\' | '\0' => continue,
            c => out.push(c),
        }
    }
    let out = out.trim().to_string();
    if out.is_empty() {
        return Err(StoreError::InvalidInput("filename is empty".into()));
    }
    Ok(out)
}

/// Fetch the group's current manifest, erroring if it does not exist yet.
async fn fetch_base(cap: &CapabilityBundle) -> Result<CollaborationGroup, StoreError> {
    collab::fetch_manifest(cap.http(), cap.webui_base(), cap.group_id(), cap.link_secret())
        .await?
        .ok_or(StoreError::ManifestMissing)
}

/// Apply an additive `mutate` to a clone of `base`, then GET-latest + merge + PUT.
///
/// Implements steps 3–5 of the commit protocol (see the module docs): the fresh
/// `remote` is the merge `self` so concurrent human edits to existing entries win,
/// while the additive change carried only by `local` is unioned in. Returns the
/// merged manifest (so callers can read back the new version).
async fn commit_manifest_change<F>(
    cap: &CapabilityBundle,
    base: &CollaborationGroup,
    mutate: F,
) -> Result<CollaborationGroup, StoreError>
where
    F: FnOnce(&mut CollaborationGroup),
{
    let mut local = base.clone();
    mutate(&mut local);

    // GET-latest, fresh, just before the PUT. If it 404s now (deleted mid-flight),
    // fall back to the base we started from.
    let remote =
        collab::fetch_manifest(cap.http(), cap.webui_base(), cap.group_id(), cap.link_secret())
            .await?
            .unwrap_or_else(|| base.clone());

    // remote == self ⇒ wins on existing-id conflict; local's additive entry is
    // unioned in via putIfAbsent. See the module docs for why this ordering.
    let merged = remote.merge_with(&local, &now_iso8601());

    let json = serde_json::to_vec(&merged).map_err(|e| StoreError::Serialize(e.to_string()))?;
    let enc1 = enc1_encrypt(&json, cap.link_secret(), cap.group_id());

    with_collab_write_retry(cap, |tok| {
        let enc1 = enc1.clone();
        async move {
            collab::put_manifest(cap.http(), cap.webui_base(), cap.group_id(), &tok, &enc1).await
        }
    })
    .await?;

    Ok(merged)
}

/// Store a file into the collaboration group: classify it, encrypt it under the
/// group link secret, upload the blob, and append a `collab` entry to the manifest
/// (merge-committed).
///
/// `subfolder_path` (e.g. `"/notes"`) places the file in a folder; `None` ⇒ the
/// group root. `category_override` forces a category; otherwise it is classified
/// from `mime`/`filename`/`text`.
#[allow(clippy::too_many_arguments)]
pub async fn store_file(
    cap: &CapabilityBundle,
    content: Bytes,
    filename: &str,
    mime: Option<&str>,
    text: Option<&str>,
    subfolder_path: Option<&str>,
    category_override: Option<Category>,
) -> Result<StoreOutcome, StoreError> {
    let file_name = sanitize_file_name(filename)?;
    let path_scope = match subfolder_path {
        Some(p) => normalize_folder(p).map_err(|e| StoreError::InvalidInput(e.to_string()))?,
        None => None,
    };
    let category = category_override.unwrap_or_else(|| classify(mime, &file_name, text));

    // Cheap gates BEFORE any encrypt/upload. Require a write token, then take a
    // rate-limit token, then the fail-open quota pre-check.
    if cap.collab_write_token().is_none() {
        return Err(StoreError::Collab(CollabError::WriteNotConfigured));
    }
    if !cap.try_consume_write_token() {
        return Err(StoreError::RateLimited);
    }
    if let QuotaDecision::Denied = cap.check_quota().await {
        return Err(StoreError::QuotaExceeded);
    }

    // The group must already exist (we cannot synthesize a manifest). Fetch the
    // base BEFORE uploading so a missing group fails without orphaning a blob.
    let base = fetch_base(cap).await?;

    let file_id = Uuid::new_v4().to_string();
    let size = content.len() as i64;

    // Encrypt under the per-file collab key (HKDF of the link secret + file id).
    let blob = collab_file_encrypt(content.as_ref(), cap.link_secret(), &file_id);

    // Upload the blob (write-token refresh-and-retry on a 401/403).
    let resp = with_collab_write_retry(cap, |tok| {
        let blob = blob.clone();
        let file_id = file_id.clone();
        async move {
            collab::upload_collab_file(
                cap.http(),
                cap.webui_base(),
                cap.group_id(),
                &tok,
                &file_id,
                blob,
            )
            .await
        }
    })
    .await?;

    // Prefer the server's authoritative storage location; fall back to the
    // documented default (collab reads address the file by id, so this is
    // informational).
    let bucket = resp
        .bucket
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| cap.manifest_bucket().to_string());
    let storage_key = resp
        .storage_key
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!(".fula/collab/{}/files/{}", cap.group_id(), file_id));

    let entry = CollaborationFile {
        id: file_id.clone(),
        file_name: file_name.clone(),
        content_type: mime.map(str::to_string),
        bucket: bucket.clone(),
        storage_key: storage_key.clone(),
        path_scope: path_scope.clone(),
        added_by_public_key: cap.mcp_public_b64().to_string(),
        added_at: now_iso8601(),
        file_size: size,
        enc_type: "collab".to_string(),
        share_token_json: None,
    };
    let path = logical_path_of(&entry);

    let merged = commit_manifest_change(cap, &base, move |m| m.files.push(entry)).await?;

    Ok(StoreOutcome {
        file_id,
        file_name,
        path,
        category,
        content_type: mime.map(str::to_string),
        bucket,
        storage_key,
        size,
        manifest_version: merged.version,
    })
}

/// Append a directory marker (`content_type == "application/x-directory"`) for
/// `path` to the manifest. The folder's full path lives in `path_scope`.
pub async fn create_folder(
    cap: &CapabilityBundle,
    path: &str,
) -> Result<ManifestMutation, StoreError> {
    if cap.collab_write_token().is_none() {
        return Err(StoreError::Collab(CollabError::WriteNotConfigured));
    }
    let folder = normalize_folder(path)
        .map_err(|e| StoreError::InvalidInput(e.to_string()))?
        .ok_or_else(|| StoreError::InvalidInput("cannot create the group root as a folder".into()))?;
    let leaf = folder.rsplit('/').next().unwrap_or("").to_string();

    if !cap.try_consume_write_token() {
        return Err(StoreError::RateLimited);
    }

    let base = fetch_base(cap).await?;

    let marker = CollaborationFile {
        id: Uuid::new_v4().to_string(),
        file_name: leaf,
        content_type: Some(DIRECTORY_CONTENT_TYPE.to_string()),
        bucket: cap.manifest_bucket().to_string(),
        storage_key: String::new(),
        path_scope: Some(folder.clone()),
        added_by_public_key: cap.mcp_public_b64().to_string(),
        added_at: now_iso8601(),
        file_size: 0,
        enc_type: "collab".to_string(),
        share_token_json: None,
    };

    let merged = commit_manifest_change(cap, &base, move |m| m.files.push(marker)).await?;
    Ok(ManifestMutation {
        manifest_version: merged.version,
        path: Some(folder),
    })
}

/// Remove a file from the group by TOMBSTONE (add its id to `removed_file_ids` +
/// merge + PUT). NEVER calls the server `DELETE` (global/irreversible). A no-op if
/// the id is absent (idempotent).
pub async fn remove_file(
    cap: &CapabilityBundle,
    file_id: &str,
) -> Result<ManifestMutation, StoreError> {
    if cap.collab_write_token().is_none() {
        return Err(StoreError::Collab(CollabError::WriteNotConfigured));
    }
    let id = file_id.trim();
    if id.is_empty() {
        return Err(StoreError::InvalidInput("file_id is empty".into()));
    }
    if !cap.try_consume_write_token() {
        return Err(StoreError::RateLimited);
    }

    let base = fetch_base(cap).await?;
    let removed_path = base.files.iter().find(|f| f.id == id).map(logical_path_of);

    let id_owned = id.to_string();
    let merged = commit_manifest_change(cap, &base, move |m| {
        if !m.removed_file_ids.iter().any(|t| t == &id_owned) {
            m.removed_file_ids.push(id_owned.clone());
        }
        m.files.retain(|f| f.id != id_owned);
    })
    .await?;

    Ok(ManifestMutation {
        manifest_version: merged.version,
        path: removed_path,
    })
}

#[cfg(test)]
mod tests {
    use crate::manifest::{CollaborationFile, CollaborationGroup};

    fn group(id: &str, version: i64, files: Vec<CollaborationFile>) -> CollaborationGroup {
        CollaborationGroup {
            id: id.to_string(),
            name: format!("name-{id}"),
            owner_public_key: "owner".to_string(),
            manifest_bucket: "fula-metadata".to_string(),
            manifest_key: "mk".to_string(),
            created_at: "2026-01-01T00:00:00.000Z".to_string(),
            expires_at: None,
            is_revoked: false,
            files,
            removed_file_ids: vec![],
            version,
            updated_at: "2026-01-01T00:00:00.000Z".to_string(),
        }
    }

    fn file(id: &str, name: &str, added_at: &str) -> CollaborationFile {
        CollaborationFile {
            id: id.to_string(),
            file_name: name.to_string(),
            content_type: None,
            bucket: "b".to_string(),
            storage_key: format!("sk-{id}"),
            path_scope: None,
            added_by_public_key: "pk".to_string(),
            added_at: added_at.to_string(),
            file_size: 1,
            enc_type: "collab".to_string(),
            share_token_json: None,
        }
    }

    /// The commit ordering (`remote.merge_with(&local)`) preserves BOTH a
    /// concurrent human ADD and the AI's additive file. (Passes under either merge
    /// direction — included for completeness.)
    #[test]
    fn commit_merge_keeps_ai_add_and_concurrent_human_add() {
        let base = group("g", 1, vec![file("A", "a.txt", "2026-01-02T00:00:00.000Z")]);
        let mut local = base.clone();
        local.files.push(file("F", "f.txt", "2026-01-04T00:00:00.000Z"));
        let remote = group(
            "g",
            2,
            vec![
                file("A", "a.txt", "2026-01-02T00:00:00.000Z"),
                file("B", "b.txt", "2026-01-03T00:00:00.000Z"),
            ],
        );
        let merged = remote.merge_with(&local, "2026-02-02T00:00:00.000Z");
        let ids: std::collections::HashSet<&str> =
            merged.files.iter().map(|f| f.id.as_str()).collect();
        assert!(ids.contains("A") && ids.contains("B") && ids.contains("F"));
        assert_eq!(merged.version, 3);
    }

    /// THE discriminating case (advisor-requested): a concurrent human MODIFY of an
    /// EXISTING entry (a rename, same id) must survive, while the AI's additive
    /// file is still added. This passes ONLY because `remote` (the fresh server
    /// copy) is the merge `self`; `local.merge_with(&remote)` would lose the rename.
    #[test]
    fn commit_merge_preserves_concurrent_human_rename_of_existing_file() {
        let base = group("g", 1, vec![file("A", "old.txt", "2026-01-02T00:00:00.000Z")]);
        // AI built local from a (now stale) base + F, carrying the OLD A.
        let mut local = base.clone();
        local.files.push(file("F", "f.txt", "2026-01-04T00:00:00.000Z"));
        // Human concurrently RENAMED A -> "new" and bumped the version.
        let remote = group("g", 2, vec![file("A", "new.txt", "2026-01-05T00:00:00.000Z")]);

        let merged = remote.merge_with(&local, "2026-02-02T00:00:00.000Z");
        let a = merged.files.iter().find(|f| f.id == "A").expect("A present");
        assert_eq!(a.file_name, "new.txt", "the human rename must win (remote is self)");
        assert!(merged.files.iter().any(|f| f.id == "F"), "the AI's add must survive");
    }

    /// The tombstone ∩ concurrent-add edge (GLM-flagged): if the AI tombstones an
    /// id that a human concurrently (re-)added, the tombstone wins and the file is
    /// dropped from `files`. Documented behavior — assert it explicitly.
    #[test]
    fn tombstone_wins_over_concurrent_readd() {
        let remote = group("g", 2, vec![file("Z", "z.txt", "2026-01-06T00:00:00.000Z")]);
        let mut local = group("g", 1, vec![]);
        local.removed_file_ids.push("Z".to_string());

        let merged = remote.merge_with(&local, "2026-02-02T00:00:00.000Z");
        assert!(
            !merged.files.iter().any(|f| f.id == "Z"),
            "a tombstone drops the file even if concurrently re-added"
        );
        assert!(merged.removed_file_ids.iter().any(|t| t == "Z"));
    }
}
