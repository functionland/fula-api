//! # `read_file` — the AI's collaboration READ operation
//!
//! Reads a file referenced by the group's manifest, by its `file_id` or by a
//! logical `path`. Authorization is membership in the group: every entry the
//! manifest lists is, by construction, shared with the group, so there is no
//! `ai/`-scope gate — only "is this entry in THIS group's manifest".
//!
//! ## Two on-wire encodings (`encType`)
//!
//! - **`collab`** — a blob encrypted under the per-file collab key (HKDF of the
//!   link secret + file id). Fetched whole from `GET /file/{id}` and decrypted with
//!   [`collab_file_decrypt`].
//! - **`fula`** — an OWNER's fula-encrypted object, shared into the group via a
//!   `fula_crypto` [`ShareToken`] (in `share_token_json`, addressed to the group
//!   **link keypair**). We accept the share to recover the DEK + nonce / chunked
//!   metadata, fetch the ciphertext via `GET /fula-fetch`, and decrypt.
//!
//! ## fula decrypt — a faithful port of `fula-client`'s share-read path
//!
//! The recipe below mirrors `fula-client`'s `get_object_with_share` byte-for-byte
//! (the path the FxFiles app + web portal use), so the MCP reads exactly what
//! those clients produce:
//!
//! - **single block** (`chunked_metadata` absent): one fetch of `storage_key`;
//!   nonce = base64-STANDARD decode of the share's `nonce`; AAD =
//!   `fula:v4:content:{storage_key}`; decrypt gated on `encryption_version`
//!   (`Some(>=4)` ⇒ AAD; `Some(<4)` ⇒ no AAD; `None` ⇒ try-AAD-then-plaintext).
//! - **chunked** (`chunked_metadata` present): decoder gated on the metadata
//!   `format` (`"streaming-v2"` ⇒ AAD prefix `fula:v4:chunk:{storage_key}`, else no
//!   AAD); each chunk fetched as a SEPARATE object at `{storage_key}.chunks/{i:08}`
//!   (via [`ChunkedFileMetadata::chunk_key`]); the decoder appends the decimal
//!   `:{i}` to the AAD internally.
//!
//! NOTE (deliberate fidelity, flagged for review): the `encryption_version == None`
//! single-block branch keeps `fula-client`'s try-AAD-then-plaintext fallback. That
//! fallback drops the storage-key AAD binding for legacy (`None`-version) objects.
//! We mirror the authoritative reader rather than being stricter (compatibility:
//! the MCP must read everything the app can). Hardening that fallback belongs in
//! `fula-client` (which this crate must not modify). Collab `fula` files written by
//! current clients carry `encryption_version = Some(4)`, so the common path is
//! always AAD-bound.

use bytes::Bytes;

use base64::Engine as _;
use fula_crypto::{
    Aead, AcceptedShare, ChunkedDecoder, ChunkedFileMetadata, DekKey, Nonce, ShareRecipient,
    ShareToken,
};

use crate::capability::{CapabilityBundle, CapabilityError};
use crate::collab::{self, CollabError};
use crate::manifest::{collab_file_decrypt, CollaborationFile, CollaborationGroup};
use crate::tree::{is_directory, is_tombstoned, logical_path_of, normalize_folder};

/// How the caller addresses the file to read.
#[derive(Debug, Clone)]
pub enum ReadBy {
    /// By the file's UUID (the unambiguous, primary key).
    FileId(String),
    /// By a logical path (best-effort: matched against each entry's derived
    /// logical path, then its bare filename).
    Path(String),
}

/// Errors surfaced by [`read_file`].
#[derive(Debug, thiserror::Error)]
pub enum ReadError {
    /// A collaboration HTTP / manifest failure (incl. a 404 on the blob).
    #[error("collaboration error: {0}")]
    Collab(#[from] CollabError),

    /// Deriving the group link keypair failed (malformed link secret).
    #[error("capability error: {0}")]
    Capability(#[from] CapabilityError),

    /// Neither a file id nor a path was supplied, or it was empty.
    #[error("invalid input: {0}")]
    InvalidInput(String),

    /// No matching file in the manifest (or the manifest itself is absent).
    #[error("not found: {0}")]
    NotFound(String),

    /// Parsing / accepting the `fula` share token failed.
    #[error("share acceptance failed: {0}")]
    Share(String),

    /// Decryption (collab blob or owner file) failed.
    #[error("decryption failed: {0}")]
    Crypto(String),
}

/// The plaintext + metadata of a read file. `bytes` are redacted from [`Debug`].
#[derive(Clone)]
pub struct ReadOutcome {
    /// The file's UUID.
    pub file_id: String,
    /// The display filename.
    pub file_name: String,
    /// The derived logical path.
    pub path: String,
    /// The recorded MIME type, if any.
    pub content_type: Option<String>,
    /// The on-wire encoding (`"collab"` / `"fula"`).
    pub enc_type: String,
    /// Plaintext size in bytes.
    pub size: usize,
    /// The decrypted plaintext.
    pub bytes: Bytes,
}

impl std::fmt::Debug for ReadOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReadOutcome")
            .field("file_id", &self.file_id)
            .field("file_name", &self.file_name)
            .field("path", &self.path)
            .field("content_type", &self.content_type)
            .field("enc_type", &self.enc_type)
            .field("size", &self.size)
            .field("bytes", &"<redacted plaintext>")
            .finish()
    }
}

/// Resolve a [`ReadBy`] to a live (non-tombstoned, non-directory) manifest entry.
fn resolve<'a>(
    manifest: &'a CollaborationGroup,
    by: &ReadBy,
) -> Result<&'a CollaborationFile, ReadError> {
    match by {
        ReadBy::FileId(id) => {
            let id = id.trim();
            if id.is_empty() {
                return Err(ReadError::InvalidInput("file_id is empty".into()));
            }
            manifest
                .files
                .iter()
                .find(|f| f.id == id && !is_tombstoned(manifest, &f.id) && !is_directory(f))
                .ok_or_else(|| ReadError::NotFound(format!("no file with id `{id}`")))
        }
        ReadBy::Path(p) => {
            let raw = p.trim();
            if raw.is_empty() {
                return Err(ReadError::InvalidInput("path is empty".into()));
            }
            let want = normalize_folder(raw)
                .map_err(|e| ReadError::InvalidInput(e.to_string()))?
                .ok_or_else(|| {
                    ReadError::NotFound("path resolves to the group root (not a file)".into())
                })?;
            manifest
                .files
                .iter()
                .filter(|f| !is_tombstoned(manifest, &f.id) && !is_directory(f))
                .find(|f| logical_path_of(f) == want || f.file_name == raw)
                .ok_or_else(|| ReadError::NotFound(format!("no file at path `{want}`")))
        }
    }
}

/// Decrypt a single-block `fula` object (ciphertext already fetched). Pure — no
/// I/O — so the AAD + version-gate + nonce decode are unit-testable.
fn decrypt_single_block(
    accepted: &AcceptedShare,
    ciphertext: &[u8],
    storage_key: &str,
) -> Result<Vec<u8>, ReadError> {
    let nonce_b64 = accepted
        .nonce
        .as_deref()
        .ok_or_else(|| ReadError::Crypto("single-block fula file has no nonce".into()))?;
    let nonce_bytes = base64::engine::general_purpose::STANDARD
        .decode(nonce_b64)
        .map_err(|e| ReadError::Crypto(format!("nonce base64: {e}")))?;
    let nonce = Nonce::from_bytes(&nonce_bytes).map_err(|e| ReadError::Crypto(e.to_string()))?;

    let aead = Aead::new_default(&accepted.dek);
    let aad = format!("fula:v4:content:{storage_key}");

    // Version gate — mirrors fula-client's get_object_with_share exactly.
    let plaintext = match accepted.encryption_version {
        Some(v) if v >= 4 => aead
            .decrypt_with_aad(&nonce, ciphertext, aad.as_bytes())
            .map_err(|e| ReadError::Crypto(e.to_string()))?,
        Some(_) => aead
            .decrypt(&nonce, ciphertext)
            .map_err(|e| ReadError::Crypto(e.to_string()))?,
        None => match aead.decrypt_with_aad(&nonce, ciphertext, aad.as_bytes()) {
            Ok(p) => p,
            Err(_) => aead
                .decrypt(&nonce, ciphertext)
                .map_err(|e| ReadError::Crypto(e.to_string()))?,
        },
    };
    Ok(plaintext)
}

/// Assemble a chunked `fula` object from its already-fetched per-chunk
/// ciphertexts. Pure — no I/O. The decoder choice is gated on the metadata
/// `format` (streaming-v2 ⇒ AAD prefix `fula:v4:chunk:{storage_key}`).
fn assemble_chunked(
    dek: DekKey,
    meta: ChunkedFileMetadata,
    chunks: &[(u32, Vec<u8>)],
    storage_key: &str,
) -> Result<Vec<u8>, ReadError> {
    let mut decoder = if meta.format == "streaming-v2" {
        ChunkedDecoder::with_aad(dek, meta, format!("fula:v4:chunk:{storage_key}"))
    } else {
        ChunkedDecoder::new(dek, meta)
    };
    for (i, ct) in chunks {
        decoder
            .decrypt_chunk(*i, ct)
            .map_err(|e| ReadError::Crypto(e.to_string()))?;
    }
    decoder
        .finalize()
        .map(|b| b.to_vec())
        .map_err(|e| ReadError::Crypto(e.to_string()))
}

/// Fetch + decrypt a `fula` (owner) file referenced by a manifest entry.
async fn read_fula(
    cap: &CapabilityBundle,
    file: &CollaborationFile,
    accepted: AcceptedShare,
) -> Result<Vec<u8>, ReadError> {
    let storage_key = file.storage_key.as_str();

    if let Some(chunked_json) = accepted.chunked_metadata.as_deref() {
        let meta: ChunkedFileMetadata = serde_json::from_str(chunked_json)
            .map_err(|e| ReadError::Crypto(format!("chunked metadata: {e}")))?;
        let num_chunks = meta.num_chunks;
        let mut chunks: Vec<(u32, Vec<u8>)> = Vec::with_capacity(num_chunks as usize);
        for i in 0..num_chunks {
            let chunk_key = ChunkedFileMetadata::chunk_key(storage_key, i);
            let ct = collab::fula_fetch(
                cap.http(),
                cap.webui_base(),
                cap.group_id(),
                &file.bucket,
                &chunk_key,
            )
            .await?;
            chunks.push((i, ct));
        }
        assemble_chunked(accepted.dek, meta, &chunks, storage_key)
    } else {
        let ct = collab::fula_fetch(
            cap.http(),
            cap.webui_base(),
            cap.group_id(),
            &file.bucket,
            storage_key,
        )
        .await?;
        decrypt_single_block(&accepted, &ct, storage_key)
    }
}

/// Read + decrypt a file in the collaboration group, addressed by id or path.
pub async fn read_file(cap: &CapabilityBundle, by: &ReadBy) -> Result<ReadOutcome, ReadError> {
    let manifest =
        collab::fetch_manifest(cap.http(), cap.webui_base(), cap.group_id(), cap.link_secret())
            .await?
            .ok_or_else(|| ReadError::NotFound("the group has no manifest".into()))?;

    let file = resolve(&manifest, by)?;

    let plaintext = match file.enc_type.as_str() {
        "collab" => {
            let blob =
                collab::fetch_collab_file(cap.http(), cap.webui_base(), cap.group_id(), &file.id)
                    .await?;
            collab_file_decrypt(&blob, cap.link_secret(), &file.id)
                .map_err(|e| ReadError::Crypto(e.to_string()))?
        }
        "fula" => {
            let link_keypair = cap.link_keypair()?;
            let token_json = file.share_token_json.as_deref().ok_or_else(|| {
                ReadError::Share("fula file has no share_token_json".into())
            })?;
            let token: ShareToken = serde_json::from_str(token_json)
                .map_err(|e| ReadError::Share(format!("share token parse: {e}")))?;
            let accepted = ShareRecipient::new(&link_keypair)
                .accept_share(&token)
                .map_err(|e| ReadError::Share(e.to_string()))?;
            read_fula(cap, file, accepted).await?
        }
        other => return Err(ReadError::Crypto(format!("unknown encType `{other}`"))),
    };

    let path = logical_path_of(file);
    Ok(ReadOutcome {
        file_id: file.id.clone(),
        file_name: file.file_name.clone(),
        path,
        content_type: file.content_type.clone(),
        enc_type: file.enc_type.clone(),
        size: plaintext.len(),
        bytes: Bytes::from(plaintext),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{CollaborationFile, CollaborationGroup};
    // `Aead`, `Nonce`, `DekKey` come from the module's top-level imports via
    // `super::*`; only these extras are needed here.
    use fula_crypto::{sharing::ShareBuilder, ChunkedEncoder, KekKeyPair};

    fn empty_group() -> CollaborationGroup {
        serde_json::from_str(
            r#"{"id":"g","name":"n","ownerPublicKey":"o","manifestKey":"k","createdAt":"c","updatedAt":"u","files":[]}"#,
        )
        .unwrap()
    }

    fn file(id: &str, name: &str, scope: Option<&str>, enc: &str) -> CollaborationFile {
        CollaborationFile {
            id: id.to_string(),
            file_name: name.to_string(),
            content_type: None,
            bucket: "b".to_string(),
            storage_key: format!("sk-{id}"),
            path_scope: scope.map(str::to_string),
            added_by_public_key: "pk".to_string(),
            added_at: "2026-01-01T00:00:00.000Z".to_string(),
            file_size: 1,
            enc_type: enc.to_string(),
            share_token_json: None,
        }
    }

    #[test]
    fn resolve_by_id_and_path_and_skips_tombstones_and_dirs() {
        let mut g = empty_group();
        g.files.push(file("F1", "memo.txt", Some("/notes"), "collab"));
        g.files.push(file("F2", "old.txt", None, "collab"));
        g.removed_file_ids.push("F2".to_string());
        // A directory marker.
        let mut dir = file("D1", "notes", Some("/notes"), "collab");
        dir.content_type = Some(crate::tree::DIRECTORY_CONTENT_TYPE.to_string());
        g.files.push(dir);

        assert_eq!(resolve(&g, &ReadBy::FileId("F1".into())).unwrap().id, "F1");
        assert_eq!(
            resolve(&g, &ReadBy::Path("/notes/memo.txt".into())).unwrap().id,
            "F1"
        );
        // Bare filename fallback.
        assert_eq!(resolve(&g, &ReadBy::Path("memo.txt".into())).unwrap().id, "F1");
        // Tombstoned id is not resolvable.
        assert!(matches!(
            resolve(&g, &ReadBy::FileId("F2".into())),
            Err(ReadError::NotFound(_))
        ));
        // A directory id is not a readable file.
        assert!(matches!(
            resolve(&g, &ReadBy::FileId("D1".into())),
            Err(ReadError::NotFound(_))
        ));
        // Unknown path.
        assert!(matches!(
            resolve(&g, &ReadBy::Path("/nope.txt".into())),
            Err(ReadError::NotFound(_))
        ));
    }

    /// Single-block fula decrypt via a CONSTRUCTED v4 share token (addressed to the
    /// group link keypair): builds the exact `fula:v4:content:{storage_key}` AAD +
    /// inline nonce the producer uses, then decrypts through `decrypt_single_block`.
    #[test]
    fn fula_single_block_decrypts_via_constructed_share_token() {
        let owner = KekKeyPair::generate();
        let link = KekKeyPair::generate(); // the group link keypair
        let dek = DekKey::generate();
        let storage_key = "obfs-single-123";
        let plaintext = b"hello fula single block payload";

        let nonce = Nonce::generate();
        let aad = format!("fula:v4:content:{storage_key}");
        let ciphertext = Aead::new_default(&dek)
            .encrypt_with_aad(&nonce, plaintext, aad.as_bytes())
            .unwrap();
        let nonce_b64 = base64::engine::general_purpose::STANDARD.encode(nonce.as_bytes());

        let token = ShareBuilder::new(&owner, link.public_key(), &dek)
            .path_scope(storage_key)
            .nonce(nonce_b64)
            .encryption_version(4)
            .build()
            .unwrap();
        let accepted = ShareRecipient::new(&link).accept_share(&token).unwrap();

        let out = decrypt_single_block(&accepted, &ciphertext, storage_key).unwrap();
        assert_eq!(out, plaintext);

        // A wrong storage_key (wrong AAD) must fail authentication.
        assert!(decrypt_single_block(&accepted, &ciphertext, "wrong-key").is_err());
    }

    /// Chunked fula decrypt via a CONSTRUCTED v4 share token: encodes multi-chunk
    /// streaming-v2 with the `fula:v4:chunk:{storage_key}` AAD prefix, then
    /// assembles through `assemble_chunked` (the read path's pure core).
    #[test]
    fn fula_chunked_decrypts_via_constructed_share_token() {
        let owner = KekKeyPair::generate();
        let link = KekKeyPair::generate();
        let dek = DekKey::generate();
        let storage_key = "obfs-chunk-456";
        let payload = vec![0x5au8; 200_000]; // > one 64 KiB chunk ⇒ multi-chunk

        let prefix = format!("fula:v4:chunk:{storage_key}");
        let mut enc =
            ChunkedEncoder::with_aad_and_chunk_size(dek.clone(), prefix.into_bytes(), 64 * 1024);
        let mut chunks: Vec<(u32, Vec<u8>)> = enc
            .update(&payload)
            .unwrap()
            .into_iter()
            .map(|c| (c.index, c.ciphertext.to_vec()))
            .collect();
        let (final_chunk, meta, _ob) = enc.finalize().unwrap();
        if let Some(c) = final_chunk {
            chunks.push((c.index, c.ciphertext.to_vec()));
        }
        assert!(meta.num_chunks > 1, "test must be multi-chunk");
        assert_eq!(meta.format, "streaming-v2");

        let token = ShareBuilder::new(&owner, link.public_key(), &dek)
            .path_scope(storage_key)
            .chunked_metadata(serde_json::to_string(&meta).unwrap())
            .encryption_version(4)
            .build()
            .unwrap();
        let accepted = ShareRecipient::new(&link).accept_share(&token).unwrap();
        assert!(accepted.chunked_metadata.is_some());

        let out = assemble_chunked(accepted.dek, meta, &chunks, storage_key).unwrap();
        assert_eq!(out, payload);
    }
}
