//! # `store_file` — the AI's scoped, encrypted WRITE operation (P5)
//!
//! This is the core "AI stores a file" library function. The MCP-protocol
//! wiring (tool dispatch) comes later (P9); here we build + test the operation
//! as a plain async library call.
//!
//! ## The model (locked in by the P2 finding)
//!
//! The AI writes each file into **its OWN workspace** — a dedicated bucket,
//! encrypted under the dedicated AI-workspace secret (NOT the user's master
//! KEK; see [`crate::capability`]). It then mints a per-file [`ShareToken`]
//! that wraps THAT file's content DEK to the **owner's** public key, so the
//! owner (FxFiles) can read what the AI wrote. The AI never writes the owner's
//! private forest. This needs zero new crypto — it is the role-swap of the
//! already-proven owner→recipient share flow (`tests/p2_shared_scope_write.rs`).
//!
//! ## Why we recover the DEK by re-reading the object's own metadata
//!
//! To mint the owner-share we need the file's content DEK. The SDK's
//! [`EncryptedClient::put_object_flat`] returns only `{ etag, version_id }` —
//! it does NOT hand back the DEK it generated. So, exactly as FxFiles itself
//! does before sharing (and as the P2 live e2e proves), we recover it:
//!
//! 1. [`EncryptedClient::list_files_from_forest`] maps our logical `key` to the
//!    obfuscated `storage_key`.
//! 2. [`EncryptedClient::get_object_encryption_metadata_with_fallback`] returns
//!    the COMPLETE `x-fula-encryption` JSON (`{ version, nonce?, wrapped_key,
//!    chunked? }`) — "with_fallback" guarantees the per-chunk `chunk_nonces`
//!    are present for chunked files (recovered from the forest / index body when
//!    the gateway header was stripped).
//! 3. We unwrap `wrapped_key` with the **workspace keypair** via
//!    [`Decryptor::decrypt_dek`]. The workspace OWNS this file (it wrote it), so
//!    its own keypair is the correct recipient of the wrapped DEK.
//!
//! This deliberately reuses the real SDK upload path (correct v4 AAD, real
//! chunking, a real forest entry) instead of re-implementing the wire format by
//! hand. The recovered DEK is identical to the one the SDK generated — there is
//! no second, divergent copy of the bytes.
//!
//! ## Single-block vs. chunked nonce handling (load-bearing)
//!
//! A SINGLE-BLOCK (v4) object carries a top-level `nonce`; the owner decrypts
//! with that one nonce + the v4 content AAD. A CHUNKED object carries **no
//! usable top-level nonce** — the per-chunk nonce table lives inside the
//! `chunked` block (`chunked.chunk_nonces`), and the owner's chunked decode path
//! reconstructs per-chunk nonces from the `chunked_metadata` baked into the
//! share token. We therefore read `nonce` and `chunked` **independently** and
//! pass whichever is present into [`mint_owner_share`], matching that builder's
//! `Option`-shaped contract exactly. (Mirrors
//! `fula-client/tests/large_chunked_share_e2e.rs`, the authoritative chunked
//! share reference.)
//!
//! ## Scope / authority boundary (security-critical)
//!
//! Before ANY network I/O we call [`CapabilityBundle::assert_in_scope`] with the
//! workspace key + the workspace scope + [`Permission::Write`]. This is the P3
//! canonicalized check: it rejects a non-canonical key (`..`, empty/doubled
//! segments, NUL) AND requires the bundle to actually hold a `Write` grant whose
//! canonical scope equals the workspace scope. A bundle that lacks the `ai/`
//! write grant cannot store — and the rejection happens with no I/O performed.
//!
//! Note the *bucket* boundary is enforced separately: the scope check authorizes
//! the KEY, while writes are confined to the AI's own buckets by the gateway,
//! which scopes the workspace JWT to the AI-workspace buckets. P5 relies on that
//! gateway-side scoping for the bucket; `assert_in_scope` owns the key.

use bytes::Bytes;
use fula_client::EncryptionConfig;
use fula_crypto::{DekKey, Decryptor, EncryptedData, ShareToken};
use thiserror::Error;
use uuid::Uuid;

use crate::capability::{CapabilityBundle, CapabilityError, Permission};
use crate::category::{classify, native_category_bucket, Category};

/// The single bucket the AI writes all of its workspace files into.
///
/// One bucket (rather than per-category buckets) keeps the AI's forest in one
/// place and matches the `ai/` scope the owner grants. Category lives in the
/// KEY (`ai/<category>/…`), not the bucket. The `native_category_bucket` (the
/// FxFiles `*-v8` content bucket) is recorded in the [`StoreOutcome`] for later
/// FxFiles adoption (P-adoption), but the AI does NOT write there — it would
/// have to write the owner's forest, which the model forbids.
pub const WORKSPACE_BUCKET: &str = "fula-ai-workspace";

/// The top-level key prefix (and the authorization scope) for every AI-written
/// file. Used to build BOTH the object key and the `assert_in_scope` scope
/// argument from one constant, so the two can never geometrically drift.
pub const WORKSPACE_KEY_PREFIX: &str = "ai";

/// Maximum length (in bytes) of the sanitized filename segment that goes into
/// the key. Keeps keys bounded regardless of caller-supplied filename length.
/// The uuid + category prefix are always retained, so even a fully-truncated
/// filename yields a unique, well-formed key.
const MAX_FILENAME_SEGMENT_LEN: usize = 96;

/// The outcome of a successful [`store_file`] call.
///
/// Carries everything downstream phases need:
/// - **P6 (`fula_read_file`: scoped download + decrypt)** uses
///   [`Self::bucket`] + [`Self::storage_key`] + [`Self::owner_share`]: it
///   `accept_share`s the token to recover the DEK / nonce / chunked-metadata /
///   scope, then fetches `storage_key` from `bucket` and decrypts. P6 should NOT
///   hardcode [`WORKSPACE_BUCKET`]; it reads `bucket` from here.
/// - **P8 (tag writer)** uses [`Self::key`] + [`Self::category`] (and may
///   surface [`Self::native_bucket`]) to record the file in the AI's index /
///   tag store.
#[derive(Clone)]
pub struct StoreOutcome {
    /// The canonical logical key the file was written under
    /// (`ai/<category>/<uuid>-<safe-filename>`). This is the human-meaningful
    /// path; the bytes live at [`Self::storage_key`].
    pub key: String,
    /// The bucket the file was written into ([`WORKSPACE_BUCKET`]). Carried
    /// explicitly so a reader need not know the constant.
    pub bucket: String,
    /// The obfuscated storage key the object actually lives at
    /// (`generate_flat_key(key, dek, salt)`). This is what a reader fetches and
    /// what the owner-share's `path_scope` commits to.
    pub storage_key: String,
    /// The S3 ETag returned by the upload.
    pub etag: String,
    /// The category the file classified as.
    pub category: Category,
    /// The FxFiles native content bucket this category would adopt into
    /// (`images-v8`, …), or `None` for non-content categories. Recorded for
    /// later FxFiles adoption; the AI does not write there in P5.
    pub native_bucket: Option<String>,
    /// The per-file [`ShareToken`] wrapping the content DEK to the OWNER's
    /// public key. The owner `accept_share`s this to read the file. Carries the
    /// DEK, the `path_scope` (= `storage_key`), the nonce (single-block) and/or
    /// chunked metadata, and `encryption_version = 4`.
    pub owner_share: ShareToken,
}

impl std::fmt::Debug for StoreOutcome {
    /// Redacting debug — the [`ShareToken`] wraps a content DEK, so we never
    /// print it. Only non-sensitive shape is shown.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoreOutcome")
            .field("key", &self.key)
            .field("bucket", &self.bucket)
            .field("storage_key", &self.storage_key)
            .field("etag", &self.etag)
            .field("category", &self.category)
            .field("native_bucket", &self.native_bucket)
            .field("owner_share", &"<redacted ShareToken>")
            .finish()
    }
}

/// Errors surfaced by [`store_file`].
#[derive(Debug, Error)]
pub enum StoreError {
    /// The scope/authority check failed, or a key/scope failed canonicalization.
    /// This is the access-DENIED / bad-key outcome and is raised BEFORE any I/O.
    #[error("capability check failed: {0}")]
    Capability(#[from] CapabilityError),

    /// Building the workspace client or a storage call (put / list / metadata)
    /// failed.
    #[error("workspace storage operation failed: {0}")]
    Client(String),

    /// The just-written object was not found in the forest listing, so its
    /// `storage_key` could not be resolved. Indicates the upload did not land or
    /// the forest is inconsistent — we do NOT guess a key.
    #[error("just-written object `{0}` not found in workspace forest listing")]
    ObjectNotFound(String),

    /// The object's encryption metadata was missing or malformed (could not
    /// parse the JSON, or `wrapped_key` was absent), so the per-file DEK could
    /// not be recovered.
    #[error("could not recover per-file DEK from object metadata: {0}")]
    DekRecovery(String),

    /// Minting the owner-share token failed.
    #[error("minting owner share token failed: {0}")]
    Share(String),

    /// The recovered metadata did not match the object shape we expect for a
    /// v4 object (wrong `version`, or an ambiguous/empty nonce-vs-chunked
    /// combination). Raised to refuse minting a share from metadata we cannot
    /// interpret unambiguously, rather than guessing.
    #[error("unexpected object metadata shape: {0}")]
    MetadataShape(String),
}

/// Sanitize one caller-supplied filename into a single safe key segment.
///
/// The resulting segment is fed VERBATIM into the storage-key hash
/// (`generate_flat_key` blake3's the logical path with no URL-decode layer
/// anywhere downstream), so this is about producing a *canonical, well-formed*
/// segment, not about escaping for a URL. We:
///
/// - take only the final path component (strip any `/` or `\\` the caller put
///   in a "filename"), so a value like `../../etc/passwd` or `a/b.txt` collapses
///   to its basename;
/// - keep an ASCII allowlist (`A–Z a–z 0–9 . - _`) verbatim and replace every
///   other byte (including spaces, unicode, control chars, NUL, `%`) with `_`;
/// - collapse the pathological all-dot results (`.`, `..`) — which the P3 key
///   canon rejects — to `_`;
/// - cap the length to [`MAX_FILENAME_SEGMENT_LEN`].
///
/// Returns `None` if nothing usable remains (empty input, or input that was
/// entirely separators); the caller then falls back to the uuid alone, which is
/// always a valid segment. The conservative ASCII allowlist is deliberate: the
/// key is content-addressed (the uuid guarantees uniqueness and the owner reads
/// by `storage_key`, not by eyeballing the filename), so we trade exact unicode
/// fidelity in the *key* for a guaranteed-canonical, log-safe, cross-platform
/// segment. The original filename can be preserved losslessly elsewhere (e.g. a
/// P8 tag / private-metadata field) if a future phase needs the exact name.
fn sanitize_filename_segment(filename: &str) -> Option<String> {
    // Take the basename: split on BOTH separators (a Windows-y caller may send
    // backslashes; the storage layer treats `\\` as an ordinary byte, but we do
    // not want it inside a "filename" segment).
    let base = filename
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(filename);

    let mut out = String::with_capacity(base.len().min(MAX_FILENAME_SEGMENT_LEN));
    for ch in base.chars() {
        if out.len() >= MAX_FILENAME_SEGMENT_LEN {
            break;
        }
        if ch.is_ascii_alphanumeric() || ch == '.' || ch == '-' || ch == '_' {
            out.push(ch);
        } else {
            out.push('_');
        }
    }

    // Reject empties and the all-dot forms the key canon would reject anyway.
    if out.is_empty() || out == "." || out == ".." {
        return None;
    }
    Some(out)
}

/// Build the canonical workspace key for a file:
/// `ai/<category>/<uuid>-<safe-filename>` (or `ai/<category>/<uuid>` when the
/// filename sanitizes to nothing).
///
/// PURE + offline-testable (the uuid is injected, not generated here): callers
/// in production pass a fresh [`Uuid::new_v4`]; tests pass a fixed uuid to assert
/// the exact shape. The result is guaranteed canonical for the P3 key check
/// (every segment is non-empty and free of `.`/`..`/`/`/NUL), so the same string
/// blessed by `assert_in_scope` is the one handed to storage.
pub fn build_workspace_key(category: Category, filename: &str, uuid: Uuid) -> String {
    let uuid_str = uuid.simple().to_string(); // 32 hex chars, no hyphens
    let last = match sanitize_filename_segment(filename) {
        Some(s) => format!("{uuid_str}-{s}"),
        None => uuid_str,
    };
    format!("{}/{}/{}", WORKSPACE_KEY_PREFIX, category.name(), last)
}

/// Recover the per-file content DEK (plus the nonce / chunked metadata needed to
/// build the owner share) from an object's own encryption metadata.
///
/// Split out from [`store_file`] so the recovery logic is unit-readable. Given
/// the COMPLETE `x-fula-encryption` JSON string and the workspace's encryption
/// config, this unwraps `wrapped_key` with the workspace keypair and returns the
/// DEK alongside the optional top-level `nonce` (single-block) and optional
/// serialized `chunked` block (chunked).
fn recover_dek_and_share_inputs(
    enc_meta_json: &str,
    encryption: &EncryptionConfig,
) -> Result<(DekKey, Option<String>, Option<String>), StoreError> {
    let meta: serde_json::Value = serde_json::from_str(enc_meta_json)
        .map_err(|e| StoreError::DekRecovery(format!("metadata is not valid JSON: {e}")))?;

    // Shape guard #1: this path mints a `mint_owner_share` token that hardcodes
    // encryption_version=4 and the reader decrypts with the v4 content AAD. If
    // the object is not v4 we must NOT silently mint a v4 share for it — the
    // owner would fail to decrypt. Refuse rather than guess. (The current
    // single-block + chunked upload paths both write version=4; a non-4 value
    // means we are looking at an object we don't understand.)
    match meta.get("version").and_then(|v| v.as_u64()) {
        Some(4) => {}
        other => {
            return Err(StoreError::MetadataShape(format!(
                "expected encryption version 4, metadata reports {other:?}"
            )));
        }
    }

    // Unwrap the per-file DEK with the WORKSPACE keypair (the workspace owns
    // this object, so its keypair is the wrapped-DEK recipient).
    let wrapped_value = meta.get("wrapped_key").cloned().ok_or_else(|| {
        StoreError::DekRecovery("metadata missing `wrapped_key` field".to_string())
    })?;
    let wrapped_key: EncryptedData = serde_json::from_value(wrapped_value)
        .map_err(|e| StoreError::DekRecovery(format!("malformed `wrapped_key`: {e}")))?;
    let keypair = encryption.key_manager().keypair();
    let dek = Decryptor::new(keypair)
        .decrypt_dek(&wrapped_key)
        .map_err(|e| StoreError::DekRecovery(format!("unwrap DEK with workspace keypair: {e}")))?;

    // Read nonce + chunked INDEPENDENTLY: a single-block v4 object has a usable
    // top-level `nonce` and NO `chunked`; a chunked object has a `chunked` block
    // (per-chunk nonces inside) and NO top-level nonce. These are the only two
    // legitimate shapes the upload paths produce.
    let nonce = meta
        .get("nonce")
        .and_then(|n| n.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());
    let chunked = match meta.get("chunked") {
        Some(c) if !c.is_null() => Some(
            serde_json::to_string(c)
                .map_err(|e| StoreError::DekRecovery(format!("serialize chunked metadata: {e}")))?,
        ),
        _ => None,
    };

    // Shape guard #2 (per external review): make the single-block-vs-chunked
    // decision DETERMINISTIC. Exactly one of {nonce, chunked} must be present.
    // Both-present is ambiguous; neither-present means we have no way for the
    // owner to decrypt — refuse to mint in either case rather than producing a
    // token the owner cannot open.
    match (&nonce, &chunked) {
        (Some(_), None) | (None, Some(_)) => {}
        (Some(_), Some(_)) => {
            return Err(StoreError::MetadataShape(
                "metadata carries BOTH a top-level nonce and a chunked block (ambiguous)"
                    .to_string(),
            ));
        }
        (None, None) => {
            return Err(StoreError::MetadataShape(
                "metadata carries NEITHER a top-level nonce nor a chunked block (cannot share)"
                    .to_string(),
            ));
        }
    }

    Ok((dek, nonce, chunked))
}

/// Store a file into the AI's encrypted workspace and mint an owner-readable
/// share token for it.
///
/// See the module docs for the full model. In brief: classify → build a
/// canonical workspace key → authorize the write (`assert_in_scope`, BEFORE any
/// I/O) → upload via the workspace client → recover the per-file DEK from the
/// object's own metadata → mint a [`ShareToken`] wrapping that DEK to the owner.
///
/// # Arguments
/// - `cap`: the in-memory capability bundle (workspace secret + scoped JWT +
///   owner public key + grants). Must hold a `Write` grant whose canonical scope
///   is [`WORKSPACE_KEY_PREFIX`] (`ai`).
/// - `content`: the plaintext file bytes (the AI's output). Encrypted by the
///   SDK under a fresh per-file DEK; the gateway only ever sees ciphertext.
/// - `filename`: the caller's filename (used for categorization + the key's
///   trailing segment; sanitized into the key).
/// - `mime`: explicit content type if known (drives classification + is passed
///   to the upload). `None`/empty falls back to a filename-extension lookup.
/// - `text`: an optional text payload (drives the Link/Note classification).
/// - `category_override`: force a category instead of classifying.
///
/// # Errors
/// - [`StoreError::Capability`] if the bundle lacks the `ai/` write grant or the
///   key is non-canonical (raised with NO I/O performed).
/// - [`StoreError::Client`] if a storage call fails.
/// - [`StoreError::ObjectNotFound`] if the upload's `storage_key` cannot be
///   resolved from the forest afterward.
/// - [`StoreError::DekRecovery`] if the per-file DEK cannot be recovered.
/// - [`StoreError::Share`] if the owner-share token cannot be minted.
pub async fn store_file(
    cap: &CapabilityBundle,
    content: Bytes,
    filename: &str,
    mime: Option<&str>,
    text: Option<&str>,
    category_override: Option<Category>,
) -> Result<StoreOutcome, StoreError> {
    // 1. Classify (or honor the override).
    let category = category_override.unwrap_or_else(|| classify(mime, filename, text));

    // 2. Build the canonical workspace key (fresh uuid per file).
    let key = build_workspace_key(category, filename, Uuid::new_v4());

    // 3. AUTHORIZE before any I/O. This rejects a non-canonical key AND a bundle
    //    that lacks the `ai/` write grant — and it short-circuits with no
    //    network call, which is what the offline "out-of-scope is rejected" test
    //    relies on. `?` converts CapabilityError -> StoreError::Capability.
    cap.assert_in_scope(&key, WORKSPACE_KEY_PREFIX, Permission::Write)?;

    // Build the workspace client ONCE and reuse it for the put + the metadata
    // fetch + the unwrap, so the SAME keypair that wrote the wrapped DEK is the
    // one that unwraps it.
    let client = cap.workspace_client()?;

    // 4. Upload (HPKE DEK-wrap + storage-key obfuscation + chunked content
    //    encryption + forest-index write — the real SDK path).
    let content_type = mime.filter(|m| !m.is_empty());
    let put = client
        .put_object_flat(WORKSPACE_BUCKET, &key, content, content_type)
        .await
        .map_err(|e| StoreError::Client(format!("put_object_flat: {e}")))?;

    // 5a. Resolve the obfuscated storage_key for the object we just wrote, by
    //     looking it up in our OWN forest listing by logical key.
    let listed = client
        .list_files_from_forest(WORKSPACE_BUCKET)
        .await
        .map_err(|e| StoreError::Client(format!("list_files_from_forest: {e}")))?;
    // Require EXACTLY ONE entry for our logical key (per external review): the
    // per-file uuid makes our key unique, so 0 matches means the write didn't
    // land (or the forest is inconsistent) and ≥2 means an ambiguous collision —
    // both are refusals rather than "pick the first/newest and hope".
    let mut matches = listed.iter().filter(|f| f.original_key == key);
    let storage_key = match (matches.next(), matches.next()) {
        (Some(f), None) => f.storage_key.clone(),
        (None, _) => return Err(StoreError::ObjectNotFound(key.clone())),
        (Some(_), Some(_)) => {
            return Err(StoreError::ObjectNotFound(format!(
                "{key} (ambiguous: multiple forest entries for one key)"
            )));
        }
    };

    // 5b. Fetch the COMPLETE encryption metadata (with_fallback guarantees the
    //     per-chunk nonces are present for chunked files) and recover the DEK +
    //     nonce / chunked inputs.
    let enc_meta_json = client
        .get_object_encryption_metadata_with_fallback(WORKSPACE_BUCKET, &storage_key)
        .await
        .map_err(|e| {
            StoreError::Client(format!("get_object_encryption_metadata_with_fallback: {e}"))
        })?;
    let (dek, nonce, chunked) =
        recover_dek_and_share_inputs(&enc_meta_json, client.encryption_config())?;

    // 6. Mint the owner-read share token. path_scope = storage_key (the FxFiles
    //    convention the read path resolves by). No expiry: the owner may need to
    //    read AI-authored files indefinitely; a time-boxed token would silently
    //    lock the owner out of their own data. (A future phase can add a
    //    caller-chosen expiry if a use-case wants ephemeral shares.)
    let owner_share = cap
        .mint_owner_share(&dek, &storage_key, nonce.as_deref(), chunked.as_deref(), None)
        .map_err(|e| StoreError::Share(e.to_string()))?;

    Ok(StoreOutcome {
        key,
        bucket: WORKSPACE_BUCKET.to_string(),
        storage_key,
        etag: put.etag,
        category,
        native_bucket: native_category_bucket(category).map(|s| s.to_string()),
        owner_share,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── key construction + sanitization (pure, offline) ────────────────────

    #[test]
    fn build_key_has_canonical_shape_with_category_and_uuid() {
        let uuid = Uuid::nil(); // 32 zero-hex chars
        let key = build_workspace_key(Category::Image, "photo.jpg", uuid);
        assert_eq!(key, "ai/image/00000000000000000000000000000000-photo.jpg");

        // The key must pass the P3 key canon (no empty/`..`/NUL segments). We
        // assert the structural invariants the canon enforces.
        let segs: Vec<&str> = key.split('/').collect();
        assert_eq!(segs.len(), 3, "ai / <category> / <uuid-file>");
        assert_eq!(segs[0], WORKSPACE_KEY_PREFIX);
        assert_eq!(segs[1], "image");
        assert!(!segs[2].is_empty());
        assert!(!key.contains("//"));
        assert!(!key.contains(".."));
    }

    #[test]
    fn build_key_routes_each_category_into_its_own_prefix() {
        // Classification → key routing: each category lands under ai/<name>/.
        let uuid = Uuid::nil();
        for (cat, name) in [
            (Category::Image, "image"),
            (Category::Screenshot, "screenshot"),
            (Category::Video, "video"),
            (Category::Audio, "audio"),
            (Category::Document, "document"),
            (Category::Note, "note"),
            (Category::Link, "link"),
            (Category::File, "file"),
            (Category::Other, "other"),
        ] {
            let key = build_workspace_key(cat, "x.bin", uuid);
            assert!(
                key.starts_with(&format!("ai/{name}/")),
                "category {cat:?} must route under ai/{name}/, got {key}"
            );
        }
    }

    #[test]
    fn native_bucket_routing_matches_category_map() {
        // The outcome's native_bucket must mirror native_category_bucket: the
        // four content categories map to their -v8 sibling; the rest are None.
        assert_eq!(native_category_bucket(Category::Image), Some("images-v8"));
        assert_eq!(native_category_bucket(Category::Screenshot), Some("images-v8"));
        assert_eq!(native_category_bucket(Category::Video), Some("videos-v8"));
        assert_eq!(native_category_bucket(Category::Audio), Some("audio-v8"));
        assert_eq!(native_category_bucket(Category::Document), Some("documents-v8"));
        assert_eq!(native_category_bucket(Category::Note), None);
        assert_eq!(native_category_bucket(Category::Link), None);
        assert_eq!(native_category_bucket(Category::File), None);
        assert_eq!(native_category_bucket(Category::Other), None);
    }

    #[test]
    fn sanitize_strips_path_separators_to_basename() {
        // A "filename" carrying separators collapses to its basename, so no
        // extra key segments (and no traversal) can be injected via the name.
        assert_eq!(sanitize_filename_segment("a/b/c.txt").as_deref(), Some("c.txt"));
        assert_eq!(
            sanitize_filename_segment("..\\..\\etc\\passwd").as_deref(),
            Some("passwd")
        );
        // A traversal-only basename sanitizes to None (caller falls back to uuid).
        assert_eq!(sanitize_filename_segment("../.."), None);
        assert_eq!(sanitize_filename_segment(".."), None);
        assert_eq!(sanitize_filename_segment("."), None);
    }

    #[test]
    fn sanitize_replaces_unsafe_bytes_and_keeps_allowlist() {
        // Allowlist (alnum . - _) kept verbatim; everything else → '_'.
        assert_eq!(
            sanitize_filename_segment("My File (1).PNG").as_deref(),
            Some("My_File__1_.PNG")
        );
        // Spaces, unicode, percent, NUL all become '_' (one '_' per char).
        // "rapport été %20\0.txt" → r a p p o r t [sp→_] [é→_] t [é→_] [sp→_]
        // [%→_] 2 0 [NUL→_] . t x t
        assert_eq!(
            sanitize_filename_segment("rapport été %20\0.txt").as_deref(),
            Some("rapport__t___20_.txt")
        );
        // Pure-allowlist names are untouched.
        assert_eq!(
            sanitize_filename_segment("q3-50_summary.v2.txt").as_deref(),
            Some("q3-50_summary.v2.txt")
        );
    }

    #[test]
    fn sanitize_caps_length() {
        let long = "a".repeat(500);
        let out = sanitize_filename_segment(&long).unwrap();
        assert_eq!(out.len(), MAX_FILENAME_SEGMENT_LEN);
    }

    #[test]
    fn build_key_falls_back_to_uuid_when_filename_unusable() {
        let uuid = Uuid::nil();
        // Empty / separators-only / traversal-only filenames → just the uuid.
        for bad in ["", "/", "///", "../..", "."] {
            let key = build_workspace_key(Category::Other, bad, uuid);
            assert_eq!(
                key, "ai/other/00000000000000000000000000000000",
                "unusable filename {bad:?} must yield uuid-only last segment"
            );
        }
    }

    // ── DEK recovery from metadata (pure, offline) ─────────────────────────
    //
    // These build a REAL encrypted object's metadata the way the SDK does (wrap
    // a DEK to a workspace keypair, format the v4 metadata JSON), then assert
    // recover_dek_and_share_inputs returns the same DEK + the right nonce /
    // chunked shape — without any network.

    use base64::Engine as _;
    use fula_client::{Config, EncryptedClient};
    use fula_crypto::{Aead, Encryptor, Nonce, SecretKey};

    /// Build a workspace EncryptedClient from a fixed secret (offline; the
    /// endpoint/JWT are never contacted in these pure tests).
    fn offline_workspace_client(secret_bytes: &[u8; 32]) -> EncryptedClient {
        let secret = SecretKey::from_bytes(secret_bytes).unwrap();
        let config = Config::new("https://offline.invalid".to_string())
            .with_token("offline-jwt".to_string())
            .with_encryption();
        let encryption = EncryptionConfig::from_secret_key(secret);
        EncryptedClient::new(config, encryption).unwrap()
    }

    #[test]
    fn recover_dek_single_block_metadata_round_trips() {
        let client = offline_workspace_client(&[5u8; 32]);
        let keypair = client.encryption_config().key_manager().keypair();

        // Produce a real wrapped DEK to the workspace keypair (as the SDK does).
        let dek = DekKey::generate();
        let wrapped = Encryptor::new(keypair.public_key())
            .encrypt_dek(&dek)
            .unwrap();
        let nonce = Nonce::generate();
        let meta = serde_json::json!({
            "version": 4,
            "algorithm": "AES-256-GCM",
            "nonce": base64::engine::general_purpose::STANDARD.encode(nonce.as_bytes()),
            "wrapped_key": serde_json::to_value(&wrapped).unwrap(),
            "kek_version": 1,
        })
        .to_string();

        let (rec_dek, rec_nonce, rec_chunked) =
            recover_dek_and_share_inputs(&meta, client.encryption_config()).unwrap();
        assert_eq!(rec_dek.as_bytes(), dek.as_bytes(), "recovered DEK must match");
        assert_eq!(
            rec_nonce.as_deref(),
            Some(base64::engine::general_purpose::STANDARD.encode(nonce.as_bytes())).as_deref()
        );
        assert!(rec_chunked.is_none(), "single-block object has no chunked block");
    }

    #[test]
    fn recover_dek_chunked_metadata_has_no_nonce_but_carries_chunked() {
        let client = offline_workspace_client(&[6u8; 32]);
        let keypair = client.encryption_config().key_manager().keypair();

        let dek = DekKey::generate();
        let wrapped = Encryptor::new(keypair.public_key())
            .encrypt_dek(&dek)
            .unwrap();
        // A chunked object: NO top-level nonce; per-chunk nonces inside `chunked`.
        let meta = serde_json::json!({
            "version": 4,
            "algorithm": "AES-256-GCM",
            "wrapped_key": serde_json::to_value(&wrapped).unwrap(),
            "kek_version": 1,
            "chunked": {
                "num_chunks": 2,
                "total_size": 1_500_000,
                "chunk_size": 786_432,
                "chunk_nonces": ["AAAAAAAAAAAAAAAA", "BBBBBBBBBBBBBBBB"]
            }
        })
        .to_string();

        let (rec_dek, rec_nonce, rec_chunked) =
            recover_dek_and_share_inputs(&meta, client.encryption_config()).unwrap();
        assert_eq!(rec_dek.as_bytes(), dek.as_bytes());
        assert!(rec_nonce.is_none(), "chunked object has no top-level nonce");
        let chunked = rec_chunked.expect("chunked metadata must be carried");
        let parsed: serde_json::Value = serde_json::from_str(&chunked).unwrap();
        assert_eq!(parsed["num_chunks"], 2);
        assert!(parsed["chunk_nonces"].as_array().unwrap().len() == 2);
    }

    #[test]
    fn recover_dek_rejects_malformed_metadata() {
        let client = offline_workspace_client(&[7u8; 32]);
        // Not JSON.
        assert!(matches!(
            recover_dek_and_share_inputs("not json", client.encryption_config()),
            Err(StoreError::DekRecovery(_))
        ));
        // Missing wrapped_key (but version is 4 so it passes the version gate).
        let no_wrap = serde_json::json!({ "version": 4, "nonce": "AAAA" }).to_string();
        assert!(matches!(
            recover_dek_and_share_inputs(&no_wrap, client.encryption_config()),
            Err(StoreError::DekRecovery(_))
        ));
    }

    /// Build well-formed v4 single-block metadata wrapping `dek` to `keypair`'s
    /// public key, but let the caller override `version` / drop fields to probe
    /// the shape guards.
    fn meta_with(
        keypair_pub: &fula_crypto::PublicKey,
        dek: &DekKey,
        version: serde_json::Value,
        include_nonce: bool,
        include_chunked: bool,
    ) -> String {
        let wrapped = Encryptor::new(keypair_pub).encrypt_dek(dek).unwrap();
        let mut meta = serde_json::json!({
            "version": version,
            "wrapped_key": serde_json::to_value(&wrapped).unwrap(),
        });
        if include_nonce {
            meta["nonce"] = serde_json::Value::String(
                base64::engine::general_purpose::STANDARD.encode(Nonce::generate().as_bytes()),
            );
        }
        if include_chunked {
            meta["chunked"] = serde_json::json!({
                "num_chunks": 2, "total_size": 1_000_000, "chunk_size": 786_432,
                "chunk_nonces": ["AAAAAAAAAAAAAAAA", "BBBBBBBBBBBBBBBB"]
            });
        }
        meta.to_string()
    }

    #[test]
    fn recover_dek_rejects_non_v4_version() {
        let client = offline_workspace_client(&[10u8; 32]);
        let kp = client.encryption_config().key_manager().keypair();
        let dek = DekKey::generate();
        // version=2 → refused before we even mint (a v4 share wouldn't decrypt).
        let m = meta_with(kp.public_key(), &dek, serde_json::json!(2), true, false);
        assert!(matches!(
            recover_dek_and_share_inputs(&m, client.encryption_config()),
            Err(StoreError::MetadataShape(_))
        ));
        // Missing version entirely → also refused.
        let m2 = meta_with(kp.public_key(), &dek, serde_json::Value::Null, true, false);
        assert!(matches!(
            recover_dek_and_share_inputs(&m2, client.encryption_config()),
            Err(StoreError::MetadataShape(_))
        ));
    }

    #[test]
    fn recover_dek_rejects_ambiguous_and_empty_shapes() {
        let client = offline_workspace_client(&[11u8; 32]);
        let kp = client.encryption_config().key_manager().keypair();
        let dek = DekKey::generate();
        // BOTH nonce and chunked present → ambiguous → refused.
        let both = meta_with(kp.public_key(), &dek, serde_json::json!(4), true, true);
        assert!(matches!(
            recover_dek_and_share_inputs(&both, client.encryption_config()),
            Err(StoreError::MetadataShape(_))
        ));
        // NEITHER present → cannot share → refused.
        let neither = meta_with(kp.public_key(), &dek, serde_json::json!(4), false, false);
        assert!(matches!(
            recover_dek_and_share_inputs(&neither, client.encryption_config()),
            Err(StoreError::MetadataShape(_))
        ));
    }

    // ── assert_in_scope is actually enforced (offline, no I/O) ─────────────
    //
    // We can't call the full async store_file offline (it needs the gateway),
    // but the security gate is a synchronous pre-I/O check. We prove it fires by
    // replicating EXACTLY the call store_file makes — same key, same scope, same
    // permission — against a bundle that lacks the grant, and assert it denies.

    use crate::capability::CapabilityBundle as Bundle;

    fn bundle_json(grant_scope: Option<&str>, can_write: bool) -> String {
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
        format!(
            r#"{{ "endpoint": "https://gw.example", "jwt": "j", "workspace_secret_b64": "{ws}", "mcp_secret_b64": "{mcp}", "owner_public_b64": "{owner}", "grants": {grants} }}"#
        )
    }

    /// The exact gate store_file performs: assert_in_scope(key, "ai", Write).
    fn store_gate(cap: &Bundle, key: &str) -> Result<(), StoreError> {
        cap.assert_in_scope(key, WORKSPACE_KEY_PREFIX, Permission::Write)?;
        Ok(())
    }

    #[test]
    fn store_gate_allows_write_with_ai_grant() {
        let cap = Bundle::from_json(&bundle_json(Some("ai/"), true)).unwrap();
        let key = build_workspace_key(Category::Note, "n.txt", Uuid::nil());
        assert!(store_gate(&cap, &key).is_ok());
    }

    #[test]
    fn store_gate_denies_when_no_grant() {
        // Bundle with NO grants → write denied before any I/O.
        let cap = Bundle::from_json(&bundle_json(None, false)).unwrap();
        let key = build_workspace_key(Category::Note, "n.txt", Uuid::nil());
        assert!(matches!(
            store_gate(&cap, &key),
            Err(StoreError::Capability(CapabilityError::OutOfScope { .. }))
        ));
    }

    #[test]
    fn store_gate_denies_read_only_grant() {
        // Read-only `ai/` grant → Write denied (geometry ok, authority not).
        let cap = Bundle::from_json(&bundle_json(Some("ai/"), false)).unwrap();
        let key = build_workspace_key(Category::Note, "n.txt", Uuid::nil());
        assert!(matches!(
            store_gate(&cap, &key),
            Err(StoreError::Capability(CapabilityError::OutOfScope { .. }))
        ));
    }

    #[test]
    fn store_gate_denies_mismatched_scope_grant() {
        // A grant for a DIFFERENT subtree (`other/`) must not authorize an ai/ key.
        let cap = Bundle::from_json(&bundle_json(Some("other/"), true)).unwrap();
        let key = build_workspace_key(Category::Note, "n.txt", Uuid::nil());
        assert!(matches!(
            store_gate(&cap, &key),
            Err(StoreError::Capability(CapabilityError::OutOfScope { .. }))
        ));
    }

    // ── owner-share round-trip (offline crypto, both sizes) ────────────────
    //
    // The store path mints an owner share via cap.mint_owner_share. These prove
    // the OWNER can accept that share and decrypt the AI-written bytes, for BOTH
    // a single-block and a (simulated) chunked object — reusing the exact P2
    // owner-read pattern. We drive mint_owner_share directly (the same call
    // store_file makes in step 6) since the upload itself needs the gateway.

    use fula_crypto::{ChunkedDecoder, ChunkedEncoder, EncryptedChunk, KekKeyPair, ShareRecipient};

    /// A bundle whose owner_public is derived from a known owner secret, so the
    /// test can play the owner and accept the minted share.
    fn bundle_with_known_owner(owner_secret: &[u8; 32]) -> Bundle {
        let owner_pub = SecretKey::from_bytes(owner_secret).unwrap().public_key();
        let ws = base64::engine::general_purpose::STANDARD.encode([8u8; 32]);
        let mcp = base64::engine::general_purpose::STANDARD.encode([9u8; 32]);
        let owner = base64::engine::general_purpose::STANDARD.encode(owner_pub.as_bytes());
        let json = format!(
            r#"{{ "endpoint": "https://gw.example", "jwt": "j", "workspace_secret_b64": "{ws}", "mcp_secret_b64": "{mcp}", "owner_public_b64": "{owner}", "grants": [{{ "scope": "ai/", "permissions": {{ "can_read": true, "can_write": true, "can_delete": false }} }}] }}"#
        );
        Bundle::from_json(&json).unwrap()
    }

    #[test]
    fn owner_share_single_block_round_trips_to_owner() {
        let owner_secret = [21u8; 32];
        let owner = KekKeyPair::from_secret_key(SecretKey::from_bytes(&owner_secret).unwrap());
        let cap = bundle_with_known_owner(&owner_secret);

        // Simulate the AI having written a single-block object: encrypt with a
        // fresh DEK + the v4 content AAD keyed by storage_key (exactly the
        // upload format), then mint the share the way store_file step 6 does.
        let storage_key = "QmStorageKeySingleBlock";
        let plaintext = b"small AI-written file that must round-trip to the owner";
        let dek = DekKey::generate();
        let nonce = Nonce::generate();
        let aad = format!("fula:v4:content:{storage_key}").into_bytes();
        let ciphertext = Aead::new_default(&dek)
            .encrypt_with_aad(&nonce, plaintext, &aad)
            .unwrap();
        let nonce_b64 = base64::engine::general_purpose::STANDARD.encode(nonce.as_bytes());

        let token = cap
            .mint_owner_share(&dek, storage_key, Some(&nonce_b64), None, None)
            .unwrap();

        // OWNER side: accept, recover DEK + nonce, decrypt → exact bytes.
        let accepted = ShareRecipient::new(&owner).accept_share(&token).unwrap();
        assert!(accepted.is_path_allowed(storage_key));
        assert_eq!(accepted.encryption_version, Some(4));
        let rec_nonce = {
            let raw = base64::engine::general_purpose::STANDARD
                .decode(accepted.nonce.as_ref().unwrap())
                .unwrap();
            Nonce::from_bytes(&raw).unwrap()
        };
        let decrypted = Aead::new_default(&accepted.dek)
            .decrypt_with_aad(&rec_nonce, &ciphertext, &aad)
            .unwrap();
        assert_eq!(decrypted.as_slice(), plaintext.as_slice());
    }

    #[test]
    fn owner_share_chunked_round_trips_to_owner() {
        let owner_secret = [22u8; 32];
        let owner = KekKeyPair::from_secret_key(SecretKey::from_bytes(&owner_secret).unwrap());
        let cap = bundle_with_known_owner(&owner_secret);

        // Simulate a CHUNKED object: encode >768KB with the chunked primitive,
        // collect the chunks + ChunkedFileMetadata, and serialize that metadata
        // as the `chunked` block carried in the share (no top-level nonce).
        let mut plaintext = vec![0u8; 1_000_000];
        for (i, b) in plaintext.iter_mut().enumerate() {
            *b = (i % 251) as u8; // deterministic, non-trivial content
        }
        let dek = DekKey::generate();
        let mut encoder = ChunkedEncoder::new(dek.clone());
        let mut chunks: Vec<EncryptedChunk> = encoder.update(&plaintext).unwrap();
        let (last, metadata, _outboard) = encoder.finalize().unwrap();
        if let Some(c) = last {
            chunks.push(c);
        }
        assert!(metadata.num_chunks >= 2, "must actually be multi-chunk");
        let chunked_json = serde_json::to_string(&metadata).unwrap();
        let storage_key = "QmStorageKeyChunked";

        // Mint the share the way store_file step 6 does for a chunked object:
        // nonce = None, chunked_metadata = Some(serialized metadata).
        let token = cap
            .mint_owner_share(&dek, storage_key, None, Some(&chunked_json), None)
            .unwrap();

        // OWNER side: accept, recover DEK + chunked metadata, decode → exact bytes.
        let accepted = ShareRecipient::new(&owner).accept_share(&token).unwrap();
        assert!(accepted.is_path_allowed(storage_key));
        let rec_meta: fula_crypto::ChunkedFileMetadata =
            serde_json::from_str(accepted.chunked_metadata.as_ref().expect("chunked metadata")).unwrap();
        let mut decoder = ChunkedDecoder::new(accepted.dek.clone(), rec_meta);
        for chunk in &chunks {
            decoder.decrypt_chunk(chunk.index, &chunk.ciphertext).unwrap();
        }
        let recovered = decoder.finalize().unwrap();
        assert_eq!(recovered.as_ref(), plaintext.as_slice());
    }

    #[test]
    fn owner_share_cannot_be_opened_by_stranger() {
        let cap = bundle_with_known_owner(&[23u8; 32]);
        let dek = DekKey::generate();
        let token = cap
            .mint_owner_share(&dek, "QmX", None, None, None)
            .unwrap();
        let stranger = KekKeyPair::generate();
        assert!(ShareRecipient::new(&stranger).accept_share(&token).is_err());
    }
}
