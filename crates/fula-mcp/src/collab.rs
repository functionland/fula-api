//! # Collaboration HTTP client (`/api/collab/{group_id}/*`)
//!
//! Thin async wrappers over the plain-HTTP collaboration endpoints the FxFiles
//! app and `pinning-webui` portal already serve in production. This module owns
//! ONLY the HTTP framing + JSON envelopes; every byte of crypto is delegated to
//! [`crate::manifest`] (the `ENC1:` manifest envelope + collab-file blobs) and
//! `fula-crypto` (owner-file share decryption, wired in [`crate::read`]).
//!
//! ## Endpoints
//!
//! READ (no auth):
//! - `GET  {base}/api/collab/{group}/manifest-sync`
//!   → `{ "encryptedManifest": "ENC1:…" }` | `{ "data": "<manifest-json|ENC1:…>" }`
//!   (HTTP 404 ⇒ the group has no manifest yet ⇒ `Ok(None)`).
//! - `GET  {base}/api/collab/{group}/file/{fileId}` → raw collab-file blob.
//! - `GET  {base}/api/collab/{group}/fula-fetch?bucket=&key=` → an owner's
//!   fula-encrypted object (single block, or one chunk of a chunked file).
//!
//! WRITE (Bearer `collab_write_token`):
//! - `PUT  {base}/api/collab/{group}/manifest-sync` body `{"encryptedManifest":…}`.
//! - `POST {base}/api/collab/{group}/upload` header `x-collab-file-id: {uuid}`,
//!   `Content-Type: application/octet-stream`, body = the collab-file blob.
//!
//! The server-side `DELETE /file/:fileId` is **never** called — the AI removes
//! its files by writing a TOMBSTONE into the manifest (`removed_file_ids`); the
//! object delete is global/irreversible and would break other group members.

use serde::Deserialize;

use crate::manifest::{enc1_decrypt, CollaborationGroup, ManifestError};

/// The mandatory prefix on an encrypted manifest envelope (mirrors `manifest.rs`).
const ENC1_PREFIX: &str = "ENC1:";

/// Errors surfaced by the collaboration HTTP client.
#[derive(Debug, thiserror::Error)]
pub enum CollabError {
    /// The HTTP request could not be sent / the response body could not be read.
    #[error("collab HTTP transport error: {0}")]
    Http(String),

    /// The endpoint returned a non-success status that is not a recognized
    /// not-found / auth case.
    #[error("collab endpoint {what} returned HTTP {status}")]
    Status {
        /// A short label for which endpoint failed (for the audit log).
        what: &'static str,
        /// The HTTP status code.
        status: u16,
    },

    /// A WRITE was rejected with 401/403 — the `collab_write_token` is invalid,
    /// expired, or not authorized to write this group. Surfaced distinctly so the
    /// caller can refresh-and-retry once (mirrors the connection-JWT refresh).
    #[error("collab write authorization rejected (HTTP {status})")]
    Auth {
        /// The rejecting status (401 or 403).
        status: u16,
    },

    /// A WRITE was attempted but the bundle carries no `collab_write_token`.
    #[error("collab write not configured: the capability bundle has no collab_write_token")]
    WriteNotConfigured,

    /// A requested object (collab file or owner file) was not found (HTTP 404).
    #[error("collab object not found: {0}")]
    NotFound(String),

    /// The manifest envelope failed to decrypt (wrong link secret / group, or
    /// tampering). Opaque by construction (see [`ManifestError`]).
    #[error("manifest decrypt failed: {0}")]
    Decrypt(#[from] ManifestError),

    /// A JSON body (the manifest-sync envelope, the manifest itself, or the
    /// upload response) failed to parse.
    #[error("collab JSON parse error: {0}")]
    Json(String),

    /// The manifest-sync response carried neither `encryptedManifest` nor `data`.
    #[error("manifest-sync response had neither `encryptedManifest` nor `data`")]
    EmptyManifestPayload,

    /// The manifest body was NOT an `ENC1:` (link-secret-authenticated) envelope.
    /// We refuse to trust an unauthenticated plaintext manifest: a malicious or
    /// compromised server could forge the file listing (and the merge-on-write
    /// would launder forged tombstones into an authenticated re-PUT). The MCP
    /// holds the link secret and current clients always write `ENC1:`.
    #[error("manifest is not an authenticated ENC1 envelope (refusing unauthenticated manifest)")]
    UnauthenticatedManifest,

    /// A response body exceeded the maximum we will buffer (defense against an
    /// oversized/malicious body causing OOM). `what` labels the endpoint.
    #[error("collab {what} response exceeded the {max}-byte cap")]
    TooLarge {
        /// A short label for which endpoint was over the cap.
        what: &'static str,
        /// The byte cap that was exceeded.
        max: usize,
    },
}

/// Maximum bytes we will buffer for a manifest-sync response. The manifest is a
/// file *index* (not file data), so 16 MiB is generous; this caps OOM from an
/// oversized/malicious body even when `Content-Length` is absent or lies.
const MAX_MANIFEST_BYTES: usize = 16 * 1024 * 1024;

/// Read a response body into memory, failing if it exceeds `max`. Uses the
/// inherent `Response::chunk` (no extra dependency) so the cap holds regardless
/// of a missing/forged `Content-Length`.
async fn read_capped(
    mut resp: reqwest::Response,
    max: usize,
    what: &'static str,
) -> Result<Vec<u8>, CollabError> {
    let mut buf: Vec<u8> = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| CollabError::Http(e.to_string()))?
    {
        if buf.len() + chunk.len() > max {
            return Err(CollabError::TooLarge { what, max });
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

/// The `manifest-sync` GET response envelope. The server returns the encrypted
/// manifest under `encryptedManifest` (current) or `data` (legacy); both are
/// optional so a 200 with an unexpected shape is a clean error, not a panic.
#[derive(Debug, Deserialize)]
struct ManifestSyncResponse {
    #[serde(rename = "encryptedManifest")]
    encrypted_manifest: Option<String>,
    data: Option<String>,
}

/// The `upload` POST response. All fields optional — the server is authoritative
/// about where it stored the blob, but the collab read path addresses the file
/// by its `fileId` (not by `storageKey`), so a sparse response is non-fatal.
#[derive(Debug, Clone, Deserialize)]
pub struct UploadResponse {
    /// Storage key the server assigned to the uploaded blob.
    #[serde(rename = "storageKey")]
    pub storage_key: Option<String>,
    /// Bucket the server stored the blob in.
    pub bucket: Option<String>,
    /// Echo of the `x-collab-file-id` the caller supplied.
    #[serde(rename = "fileId")]
    pub file_id: Option<String>,
    /// Stored size in bytes.
    pub size: Option<i64>,
}

// ════════════════════════════════════════════════════════════════════════════
// URL helpers
// ════════════════════════════════════════════════════════════════════════════

/// `{base}/api/collab/{group}` with any trailing slash on `base` trimmed.
fn collab_base(webui_base: &str, group_id: &str) -> String {
    format!(
        "{}/api/collab/{}",
        webui_base.trim_end_matches('/'),
        group_id
    )
}

/// `{base}/api/collab/{group}/{endpoint}`.
fn collab_url(webui_base: &str, group_id: &str, endpoint: &str) -> String {
    format!("{}/{}", collab_base(webui_base, group_id), endpoint)
}

// ════════════════════════════════════════════════════════════════════════════
// Manifest payload parsing (pure — unit-tested without HTTP)
// ════════════════════════════════════════════════════════════════════════════

/// Decode a manifest-sync payload string into a [`CollaborationGroup`].
///
/// SECURITY: the body MUST be an `ENC1:` (link-secret-authenticated) envelope —
/// an unauthenticated plaintext manifest is REJECTED ([`CollabError::Unauthenticated\
/// Manifest`]). Trusting plaintext would let a malicious/compromised server forge
/// the file listing, which the merge-on-write would then launder into an
/// authenticated re-PUT. The MCP holds the link secret and current clients always
/// write `ENC1:`. Kept pure (no HTTP) so the envelope handling is unit-testable.
pub fn parse_manifest_payload(
    raw: &str,
    link_secret: &[u8],
    group_id: &str,
) -> Result<CollaborationGroup, CollabError> {
    if !raw.starts_with(ENC1_PREFIX) {
        return Err(CollabError::UnauthenticatedManifest);
    }
    let plain = enc1_decrypt(raw, link_secret, group_id)?;
    serde_json::from_slice(&plain).map_err(|e| CollabError::Json(e.to_string()))
}

// ════════════════════════════════════════════════════════════════════════════
// READ (no auth)
// ════════════════════════════════════════════════════════════════════════════

/// `GET manifest-sync` → decrypt → [`CollaborationGroup`].
///
/// Returns `Ok(None)` when the group has no manifest yet (HTTP 404).
pub async fn fetch_manifest(
    client: &reqwest::Client,
    webui_base: &str,
    group_id: &str,
    link_secret: &[u8],
) -> Result<Option<CollaborationGroup>, CollabError> {
    let url = collab_url(webui_base, group_id, "manifest-sync");
    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| CollabError::Http(e.to_string()))?;

    let status = resp.status();
    if status == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !status.is_success() {
        return Err(CollabError::Status {
            what: "manifest-sync(GET)",
            status: status.as_u16(),
        });
    }

    // Bounded read (caps OOM from an oversized/malicious body even if the
    // Content-Length is absent or lies), then parse the envelope.
    let bytes = read_capped(resp, MAX_MANIFEST_BYTES, "manifest-sync(GET)").await?;
    let body: ManifestSyncResponse =
        serde_json::from_slice(&bytes).map_err(|e| CollabError::Json(e.to_string()))?;
    let raw = body
        .encrypted_manifest
        .or(body.data)
        .ok_or(CollabError::EmptyManifestPayload)?;
    let group = parse_manifest_payload(&raw, link_secret, group_id)?;
    Ok(Some(group))
}

/// `GET file/{fileId}` → the raw collab-file blob (`nonce||ct||tag`).
pub async fn fetch_collab_file(
    client: &reqwest::Client,
    webui_base: &str,
    group_id: &str,
    file_id: &str,
) -> Result<Vec<u8>, CollabError> {
    let url = format!("{}/file/{}", collab_base(webui_base, group_id), file_id);
    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| CollabError::Http(e.to_string()))?;

    let status = resp.status();
    if status == reqwest::StatusCode::NOT_FOUND {
        return Err(CollabError::NotFound(format!("collab file {file_id}")));
    }
    if !status.is_success() {
        return Err(CollabError::Status {
            what: "file(GET)",
            status: status.as_u16(),
        });
    }
    let bytes = resp
        .bytes()
        .await
        .map_err(|e| CollabError::Http(e.to_string()))?;
    Ok(bytes.to_vec())
}

/// `GET fula-fetch?bucket=&key=` → an owner's fula-encrypted object bytes.
///
/// For a single-block file this is the whole ciphertext; for a chunked file it
/// is called once per chunk with `key = "{storage_key}.chunks/{i:08}"`.
pub async fn fula_fetch(
    client: &reqwest::Client,
    webui_base: &str,
    group_id: &str,
    bucket: &str,
    key: &str,
) -> Result<Vec<u8>, CollabError> {
    let url = format!("{}/fula-fetch", collab_base(webui_base, group_id));
    let resp = client
        .get(&url)
        .query(&[("bucket", bucket), ("key", key)])
        .send()
        .await
        .map_err(|e| CollabError::Http(e.to_string()))?;

    let status = resp.status();
    if status == reqwest::StatusCode::NOT_FOUND {
        return Err(CollabError::NotFound(format!("owner object {bucket}/{key}")));
    }
    if !status.is_success() {
        return Err(CollabError::Status {
            what: "fula-fetch(GET)",
            status: status.as_u16(),
        });
    }
    let bytes = resp
        .bytes()
        .await
        .map_err(|e| CollabError::Http(e.to_string()))?;
    Ok(bytes.to_vec())
}

// ════════════════════════════════════════════════════════════════════════════
// WRITE (Bearer collab_write_token)
// ════════════════════════════════════════════════════════════════════════════

/// `PUT manifest-sync` body `{"encryptedManifest": enc1}` (Bearer).
///
/// A 401/403 surfaces as [`CollabError::Auth`] so the caller can refresh the
/// write token and retry once.
pub async fn put_manifest(
    client: &reqwest::Client,
    webui_base: &str,
    group_id: &str,
    write_token: &str,
    enc1: &str,
) -> Result<(), CollabError> {
    let url = collab_url(webui_base, group_id, "manifest-sync");
    let resp = client
        .put(&url)
        .bearer_auth(write_token)
        .json(&serde_json::json!({ "encryptedManifest": enc1 }))
        .send()
        .await
        .map_err(|e| CollabError::Http(e.to_string()))?;

    let status = resp.status();
    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        return Err(CollabError::Auth {
            status: status.as_u16(),
        });
    }
    if !status.is_success() {
        return Err(CollabError::Status {
            what: "manifest-sync(PUT)",
            status: status.as_u16(),
        });
    }
    Ok(())
}

/// `POST upload` with the collab-file blob (Bearer + `x-collab-file-id`).
///
/// A 401/403 surfaces as [`CollabError::Auth`] for refresh-and-retry.
pub async fn upload_collab_file(
    client: &reqwest::Client,
    webui_base: &str,
    group_id: &str,
    write_token: &str,
    file_id: &str,
    blob: Vec<u8>,
) -> Result<UploadResponse, CollabError> {
    let url = format!("{}/upload", collab_base(webui_base, group_id));
    let resp = client
        .post(&url)
        .bearer_auth(write_token)
        .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
        .header("x-collab-file-id", file_id)
        .body(blob)
        .send()
        .await
        .map_err(|e| CollabError::Http(e.to_string()))?;

    let status = resp.status();
    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        return Err(CollabError::Auth {
            status: status.as_u16(),
        });
    }
    if !status.is_success() {
        return Err(CollabError::Status {
            what: "upload(POST)",
            status: status.as_u16(),
        });
    }
    resp.json::<UploadResponse>()
        .await
        .map_err(|e| CollabError::Json(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{enc1_encrypt, CollaborationGroup};

    fn sample_group() -> CollaborationGroup {
        serde_json::from_str(
            r#"{"id":"group-xyz","name":"N","ownerPublicKey":"o","manifestKey":"k","createdAt":"c","updatedAt":"u","files":[]}"#,
        )
        .unwrap()
    }

    #[test]
    fn url_helpers_trim_trailing_slash() {
        assert_eq!(
            collab_base("https://cloud.fx.land/", "g1"),
            "https://cloud.fx.land/api/collab/g1"
        );
        assert_eq!(
            collab_url("https://cloud.fx.land", "g1", "manifest-sync"),
            "https://cloud.fx.land/api/collab/g1/manifest-sync"
        );
    }

    #[test]
    fn parse_manifest_payload_decrypts_enc1() {
        let secret = [7u8; 32];
        let group_id = "group-xyz";
        let group = sample_group();
        let json = serde_json::to_vec(&group).unwrap();
        let enc1 = enc1_encrypt(&json, &secret, group_id);

        let back = parse_manifest_payload(&enc1, &secret, group_id).unwrap();
        assert_eq!(back, group);
    }

    #[test]
    fn parse_manifest_payload_rejects_unauthenticated_plaintext() {
        // SECURITY: a non-`ENC1:` (plaintext, unauthenticated) manifest MUST be
        // refused — trusting it would let a malicious server forge the file listing.
        let group = sample_group();
        let raw = serde_json::to_string(&group).unwrap();
        let err = parse_manifest_payload(&raw, &[0u8; 32], "ignored").unwrap_err();
        assert!(matches!(err, CollabError::UnauthenticatedManifest));
    }

    #[test]
    fn parse_manifest_payload_wrong_secret_fails() {
        let group_id = "group-xyz";
        let enc1 = enc1_encrypt(b"{}", &[1u8; 32], group_id);
        let err = parse_manifest_payload(&enc1, &[2u8; 32], group_id).unwrap_err();
        assert!(matches!(err, CollabError::Decrypt(_)));
    }

    #[test]
    fn manifest_sync_response_deserializes_both_shapes() {
        let a: ManifestSyncResponse =
            serde_json::from_str(r#"{"encryptedManifest":"ENC1:abc"}"#).unwrap();
        assert_eq!(a.encrypted_manifest.as_deref(), Some("ENC1:abc"));
        assert!(a.data.is_none());

        let b: ManifestSyncResponse = serde_json::from_str(r#"{"data":"{}"}"#).unwrap();
        assert_eq!(b.data.as_deref(), Some("{}"));
        assert!(b.encrypted_manifest.is_none());
    }

    #[test]
    fn upload_response_tolerates_sparse_body() {
        let r: UploadResponse =
            serde_json::from_str(r#"{"fileId":"f1","size":42}"#).unwrap();
        assert_eq!(r.file_id.as_deref(), Some("f1"));
        assert_eq!(r.size, Some(42));
        assert!(r.storage_key.is_none());
        assert!(r.bucket.is_none());
    }
}
