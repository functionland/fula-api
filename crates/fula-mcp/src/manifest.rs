//! # Collaboration manifest + collab-file crypto (byte-exact Dart/TS port)
//!
//! The MCP collaboration partner reads and writes the encrypted collaboration
//! **manifest** (the file index) and individual **collab files** using the SAME
//! crypto the FxFiles Dart app and the `pinning-webui` TypeScript portal already
//! use in production. This module is a byte-for-byte port of those routines so
//! the three implementations interoperate.
//!
//! Confirmed identical against Dart
//! (`lib/core/services/share_link_builder.dart` + `collaboration_service.dart`)
//! and TS (`pinning-webui/src/services/sharingService.ts`), and gated by a test
//! that DECRYPTS real vectors produced by the Dart code
//! (`tests/collab_crypto_vectors.rs`).
//!
//! ## Wire spec
//!
//! - **Key derivation** — HKDF-SHA256, IKM = the 32-byte link secret, **salt =
//!   EMPTY** (zero-length), `info` = UTF-8 of `manifest-enc-v1:{scopeId}` (the
//!   manifest key) or `collab-file-v1:{fileId}` (the per-file key), L = 32. An
//!   empty salt and an absent (`None`) salt yield the same PRK for HMAC, but we
//!   write it as the empty slice `&[]` to mirror the Dart source (which passes
//!   `nonce: Uint8List(0)`).
//! - **Symmetric encryption** (both the manifest body and collab files) —
//!   AES-256-GCM, **12-byte random nonce**, **NO additional authenticated data**,
//!   on-wire layout `nonce(12) || ciphertext || tag(16)` (the `aes-gcm` crate
//!   appends the 16-byte GCM tag to the ciphertext, matching the Dart
//!   `cryptography` package's `nonce + cipherText + mac.bytes` and WebCrypto).
//! - **Manifest envelope ("ENC1")** — `derive_manifest_key` → AES-GCM-encrypt
//!   `utf8(JSON.stringify(manifest))` → `"ENC1:" + base64_standard(nonce||ct||tag)`.
//!   `scopeId` is the `groupId`.
//! - **Collab file** — `derive_collab_file_key` → AES-GCM-encrypt the raw file
//!   bytes → store the raw `nonce||ct||tag` (NO `ENC1:` prefix, NO base64; it is
//!   uploaded as binary).
//!
//! ## JSON canonicalization note
//!
//! [`enc1_encrypt`] takes the manifest JSON as **pre-serialized bytes**, so the
//! CALLER owns JSON canonicalization. This is deliberate: cross-language JSON
//! serializers differ in key order / whitespace / number formatting, and the
//! READ side (Dart `jsonDecode` → `fromJson`, TS `JSON.parse`) is order-tolerant,
//! so a manifest written by Rust is readable by Dart/TS regardless of key order.
//! The [`CollaborationGroup`] serde structs below mirror the Dart field names and
//! `toJson` key order exactly (verified byte-for-byte in the test) so a Rust
//! re-serialization is also a faithful drop-in, but byte-identical JSON is NOT a
//! read-compatibility requirement.

use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead as AeadTrait, AeadCore, OsRng},
};
use base64::Engine as _;
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::{HashMap, HashSet};

/// AES-GCM nonce length (96 bits) — the 12 leading bytes of every blob.
const NONCE_LEN: usize = 12;
/// AES-GCM authentication tag length (128 bits) — the trailing 16 bytes.
const TAG_LEN: usize = 16;
/// The mandatory prefix on an encrypted manifest envelope.
const ENC1_PREFIX: &str = "ENC1:";

// ════════════════════════════════════════════════════════════════════════════
// Errors
// ════════════════════════════════════════════════════════════════════════════

/// Errors surfaced by the manifest / collab-file crypto.
#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    /// The envelope did not start with the `ENC1:` prefix.
    #[error("manifest envelope is missing the required \"ENC1:\" prefix")]
    MissingEnc1Prefix,

    /// The base64 body of an `ENC1:` envelope did not decode.
    #[error("base64 decode failed: {0}")]
    Base64(String),

    /// The blob was shorter than `nonce(12) + tag(16)` — it cannot be a valid
    /// AES-GCM output.
    #[error("ciphertext too short: need at least {min} bytes, got {got}")]
    TooShort {
        /// The minimum valid length (`NONCE_LEN + TAG_LEN`).
        min: usize,
        /// The actual length seen.
        got: usize,
    },

    /// AES-GCM authentication failed (wrong key/scope/file-id, or tampering).
    /// Deliberately opaque — it does not reveal which check failed.
    #[error("AES-GCM authentication failed (wrong key or corrupt ciphertext)")]
    Decrypt,
}

/// Result alias for the fallible manifest helpers.
pub type Result<T> = std::result::Result<T, ManifestError>;

// ════════════════════════════════════════════════════════════════════════════
// Key derivation — HKDF-SHA256, empty salt
// ════════════════════════════════════════════════════════════════════════════

/// HKDF-SHA256 with an **empty salt**, expanding `info` to exactly 32 bytes.
///
/// Mirrors the Dart `Hkdf(hmac: Hmac.sha256(), outputLength: 32).deriveKey(...,
/// nonce: Uint8List(0))` where the `nonce` parameter is the HKDF salt.
fn hkdf_sha256_32(ikm: &[u8], info: &[u8]) -> [u8; 32] {
    // `Some(&[])` = empty salt (NOT `None`, although both produce the same PRK
    // for HMAC because the key is zero-padded to the block size either way — we
    // write it explicitly to mirror the Dart source).
    let hk = Hkdf::<Sha256>::new(Some(&[]), ikm);
    let mut okm = [0u8; 32];
    // `expand` only errors if the requested length exceeds 255*HashLen; 32 is far
    // under that ceiling, so this is infallible here.
    hk.expand(info, &mut okm)
        .expect("HKDF-SHA256 expand of 32 bytes is infallible");
    okm
}

/// Derive a per-file AES-256 key from the link secret and `file_id`.
///
/// HKDF-SHA256, empty salt, `info = "collab-file-v1:{file_id}"`, 32 bytes.
pub fn derive_collab_file_key(link_secret: &[u8], file_id: &str) -> [u8; 32] {
    hkdf_sha256_32(link_secret, format!("collab-file-v1:{file_id}").as_bytes())
}

/// Derive the manifest-encryption AES-256 key from the link secret and
/// `scope_id` (the collaboration `groupId`).
///
/// HKDF-SHA256, empty salt, `info = "manifest-enc-v1:{scope_id}"`, 32 bytes.
pub fn derive_manifest_key(link_secret: &[u8], scope_id: &str) -> [u8; 32] {
    hkdf_sha256_32(link_secret, format!("manifest-enc-v1:{scope_id}").as_bytes())
}

// ════════════════════════════════════════════════════════════════════════════
// AES-256-GCM — nonce(12) || ciphertext || tag(16)
// ════════════════════════════════════════════════════════════════════════════

/// AES-256-GCM seal with a fresh random 12-byte nonce, NO AAD.
///
/// Returns `nonce(12) || ciphertext || tag(16)`. The `aes-gcm` crate appends the
/// 16-byte tag to the ciphertext, which is exactly the Dart/WebCrypto layout.
fn aes_gcm_seal(key: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
    let cipher =
        Aes256Gcm::new_from_slice(key).expect("AES-256 key is always 32 bytes");
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // 12 random bytes
    // AES-GCM `encrypt` of an in-memory buffer only fails if the plaintext is
    // larger than the GCM message ceiling (~64 GiB); collab payloads are never
    // close, so `.expect` is safe and keeps the public encrypt API infallible.
    let ct = cipher
        .encrypt(&nonce, plaintext)
        .expect("AES-256-GCM encryption of an in-memory buffer is infallible");
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(nonce.as_slice());
    out.extend_from_slice(&ct);
    out
}

/// AES-256-GCM open of a `nonce(12) || ciphertext || tag(16)` blob, NO AAD.
fn aes_gcm_open(key: &[u8; 32], blob: &[u8]) -> Result<Vec<u8>> {
    if blob.len() < NONCE_LEN + TAG_LEN {
        return Err(ManifestError::TooShort {
            min: NONCE_LEN + TAG_LEN,
            got: blob.len(),
        });
    }
    let cipher =
        Aes256Gcm::new_from_slice(key).expect("AES-256 key is always 32 bytes");
    let (nonce_bytes, ct_and_tag) = blob.split_at(NONCE_LEN);
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher
        .decrypt(nonce, ct_and_tag)
        .map_err(|_| ManifestError::Decrypt)
}

// ════════════════════════════════════════════════════════════════════════════
// Public envelope API
// ════════════════════════════════════════════════════════════════════════════

/// Encrypt a manifest into the `"ENC1:"` envelope.
///
/// `manifest_json` MUST already be the serialized JSON bytes (see the
/// module-level JSON-canonicalization note). Returns
/// `"ENC1:" + base64_standard(nonce||ct||tag)`.
pub fn enc1_encrypt(manifest_json: &[u8], link_secret: &[u8], scope_id: &str) -> String {
    let key = derive_manifest_key(link_secret, scope_id);
    let blob = aes_gcm_seal(&key, manifest_json);
    format!(
        "{ENC1_PREFIX}{}",
        base64::engine::general_purpose::STANDARD.encode(&blob)
    )
}

/// Decrypt an `"ENC1:"` manifest envelope back to the manifest JSON bytes.
///
/// # Errors
/// - [`ManifestError::MissingEnc1Prefix`] if `enc1` does not start with `ENC1:`.
/// - [`ManifestError::Base64`] if the body is not valid standard base64.
/// - [`ManifestError::Decrypt`] / [`ManifestError::TooShort`] on auth failure or
///   a truncated blob.
pub fn enc1_decrypt(enc1: &str, link_secret: &[u8], scope_id: &str) -> Result<Vec<u8>> {
    let body = enc1
        .strip_prefix(ENC1_PREFIX)
        .ok_or(ManifestError::MissingEnc1Prefix)?;
    let blob = base64::engine::general_purpose::STANDARD
        .decode(body)
        .map_err(|e| ManifestError::Base64(e.to_string()))?;
    let key = derive_manifest_key(link_secret, scope_id);
    aes_gcm_open(&key, &blob)
}

/// Encrypt raw collab-file bytes. Returns the raw `nonce(12) || ct || tag(16)`
/// blob (NO `ENC1:` prefix, NO base64 — it is uploaded as binary).
pub fn collab_file_encrypt(plaintext: &[u8], link_secret: &[u8], file_id: &str) -> Vec<u8> {
    let key = derive_collab_file_key(link_secret, file_id);
    aes_gcm_seal(&key, plaintext)
}

/// Decrypt a raw collab-file `nonce(12) || ct || tag(16)` blob.
///
/// # Errors
/// [`ManifestError::Decrypt`] / [`ManifestError::TooShort`] on auth failure or a
/// truncated blob.
pub fn collab_file_decrypt(blob: &[u8], link_secret: &[u8], file_id: &str) -> Result<Vec<u8>> {
    let key = derive_collab_file_key(link_secret, file_id);
    aes_gcm_open(&key, blob)
}

// ════════════════════════════════════════════════════════════════════════════
// Manifest model — mirrors the Dart `CollaborationGroup` / `CollaborationFile`
// ════════════════════════════════════════════════════════════════════════════

/// A file within a collaboration group. Field names + serialization order mirror
/// the Dart `CollaborationFile.toJson` EXACTLY (camelCase), including the
/// conditional omission of `contentType` / `pathScope` / `shareTokenJson` when
/// absent.
///
/// Timestamps (`addedAt`) are kept as the raw ISO-8601 **String** the Dart app
/// emits (`DateTime.toIso8601String()`), so they round-trip byte-for-byte
/// without a date dependency. Note the Dart app writes LOCAL (unzoned) times.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CollaborationFile {
    /// Unique identifier for this file entry.
    pub id: String,
    /// Original filename.
    pub file_name: String,
    /// MIME type (omitted from JSON when absent).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    /// Storage bucket for this file.
    pub bucket: String,
    /// CID / storage key of the encrypted file in storage.
    pub storage_key: String,
    /// Original path (for fula-encrypted files; omitted when absent).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_scope: Option<String>,
    /// Base64 public key of the user who added this file.
    pub added_by_public_key: String,
    /// When this file was added (ISO-8601 string, verbatim from Dart).
    pub added_at: String,
    /// File size in bytes.
    pub file_size: i64,
    /// Encryption type: `"fula"` (fula_client encrypted) or `"collab"`
    /// (collaboration-key encrypted). Defaults to `"fula"` on read, matching
    /// Dart's `json['encType'] as String? ?? 'fula'`.
    #[serde(default = "default_enc_type")]
    pub enc_type: String,
    /// fula_client share-token JSON (only for `encType == "fula"`; omitted when
    /// absent).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub share_token_json: Option<String>,
}

/// A named group of documents for bidirectional collaboration. Field names +
/// serialization order mirror the Dart `CollaborationGroup.toJson` EXACTLY.
///
/// `isRevoked` and `files` are ALWAYS emitted; `removedFileIds` is omitted when
/// empty; `expiresAt` is omitted when absent — matching Dart.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CollaborationGroup {
    /// Unique identifier.
    pub id: String,
    /// User-given name.
    pub name: String,
    /// Base64-encoded public key of the group creator.
    pub owner_public_key: String,
    /// Bucket where the manifest is stored. Defaults to `"fula-metadata"` on
    /// read, matching Dart's `?? 'fula-metadata'`.
    #[serde(default = "default_manifest_bucket")]
    pub manifest_bucket: String,
    /// Path to the manifest JSON in the bucket.
    pub manifest_key: String,
    /// When the group was created (ISO-8601 string).
    pub created_at: String,
    /// When the group expires (omitted from JSON when absent; `None` = no
    /// expiry).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    /// Whether this group has been revoked. Defaults to `false` on read.
    #[serde(default)]
    pub is_revoked: bool,
    /// Files in this group.
    #[serde(default)]
    pub files: Vec<CollaborationFile>,
    /// IDs of files that have been removed (tombstones for merge correctness).
    /// Omitted from JSON when empty, matching Dart's `if (removedFileIds.isNotEmpty)`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub removed_file_ids: Vec<String>,
    /// Version counter for conflict resolution. Defaults to `1` on read, matching
    /// Dart's `?? 1`.
    #[serde(default = "default_version")]
    pub version: i64,
    /// Last time the manifest was updated (ISO-8601 string).
    pub updated_at: String,
}

fn default_enc_type() -> String {
    "fula".to_string()
}
fn default_manifest_bucket() -> String {
    "fula-metadata".to_string()
}
fn default_version() -> i64 {
    1
}

impl CollaborationGroup {
    /// CRDT merge of two manifest versions — a faithful port of the Dart
    /// `CollaborationGroup.mergeWith`, with the wall-clock injected as `now`.
    ///
    /// Semantics (all security-relevant):
    /// - **Tombstones**: union `removedFileIds` from both sides (first-seen
    ///   insertion order preserved, mirroring Dart's `Set` literal).
    /// - **Files**: union by `id`; on a conflicting `id`, `self` wins (Dart
    ///   inserts `self.files` into a map, then `other.files` via `putIfAbsent`).
    ///   Then any tombstoned file is dropped, and the result is sorted by
    ///   `addedAt`.
    /// - **Revocation is monotonic**: revoked on EITHER side ⇒ revoked
    ///   (independent of version), so a stale non-revoked copy can never
    ///   un-revoke a group.
    /// - **Expiry can only SHORTEN**: the earlier of the two expiries wins
    ///   (`None` = no expiry = least restrictive, so a non-null expiry always
    ///   wins over `None`), so a stale higher-version copy cannot extend access.
    /// - **Version**: `max(self, other) + 1`.
    /// - The remaining scalar fields (`id`, `name`, `ownerPublicKey`,
    ///   `manifestBucket`, `manifestKey`, `createdAt`) are taken from the
    ///   higher-version side (`self` on a tie), matching Dart's
    ///   `higherVersion.copyWith(...)`.
    ///
    /// `now` is the ISO-8601 timestamp to stamp as `updatedAt`. The Dart code
    /// uses `DateTime.now()` internally; injecting it here keeps the merge a pure
    /// function (deterministic + testable) and avoids a date-library dependency.
    pub fn merge_with(&self, other: &CollaborationGroup, now: &str) -> CollaborationGroup {
        // Union tombstones, preserving first-seen order (self's ids first).
        let mut merged_tombstones: Vec<String> = Vec::new();
        {
            let mut seen: HashSet<&str> = HashSet::new();
            for id in self
                .removed_file_ids
                .iter()
                .chain(other.removed_file_ids.iter())
            {
                if seen.insert(id.as_str()) {
                    merged_tombstones.push(id.clone());
                }
            }
        }
        let tombstone_set: HashSet<&str> =
            merged_tombstones.iter().map(String::as_str).collect();

        // Union files by id with Dart map semantics: within `self`, a later
        // duplicate overwrites the value but keeps the original position; across
        // sides, `self` wins (other is `putIfAbsent`). Insertion order is kept
        // so the subsequent stable sort breaks ties identically.
        let mut order: Vec<String> = Vec::new();
        let mut by_id: HashMap<String, CollaborationFile> = HashMap::new();
        for f in &self.files {
            if !by_id.contains_key(&f.id) {
                order.push(f.id.clone());
            }
            by_id.insert(f.id.clone(), f.clone()); // self: last-wins on value
        }
        for f in &other.files {
            if !by_id.contains_key(&f.id) {
                order.push(f.id.clone());
                by_id.insert(f.id.clone(), f.clone()); // other: putIfAbsent
            }
        }
        let mut merged_files: Vec<CollaborationFile> = order
            .iter()
            .filter(|id| !tombstone_set.contains(id.as_str()))
            .map(|id| by_id.get(id).expect("id came from order").clone())
            .collect();
        // Stable sort by addedAt (parsed as a naive wall-clock instant).
        merged_files.sort_by(|a, b| cmp_iso8601(&a.added_at, &b.added_at));

        let base = if self.version >= other.version {
            self
        } else {
            other
        };

        CollaborationGroup {
            id: base.id.clone(),
            name: base.name.clone(),
            owner_public_key: base.owner_public_key.clone(),
            manifest_bucket: base.manifest_bucket.clone(),
            manifest_key: base.manifest_key.clone(),
            created_at: base.created_at.clone(),
            // Shrink-only expiry.
            expires_at: earlier_expiry(self.expires_at.as_deref(), other.expires_at.as_deref())
                .map(str::to_string),
            // Monotonic revocation.
            is_revoked: self.is_revoked || other.is_revoked,
            files: merged_files,
            removed_file_ids: merged_tombstones,
            // `saturating_add` is defense-in-depth against an i64::MAX overflow
            // wrapping to a negative version (a version regression); unreachable
            // in practice.
            version: self.version.max(other.version).saturating_add(1),
            updated_at: now.to_string(),
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// ISO-8601 naive comparison (dependency-free)
// ════════════════════════════════════════════════════════════════════════════

/// Parse an ISO-8601-ish timestamp (`YYYY-MM-DDTHH:MM:SS[.frac][Z]`) into a
/// comparable `(year, month, day, hour, minute, second, microseconds)` tuple,
/// treating it as a NAIVE wall-clock value (an optional trailing `Z` is
/// stripped, fractional seconds are normalized to microseconds).
///
/// This mirrors how the Dart app compares timestamps: the manifest stores
/// unzoned LOCAL `DateTime.now()` strings, and Dart's `DateTime.parse` +
/// `isBefore` compares them as naive wall-clock instants. Two timestamps from
/// the same timezone therefore order chronologically regardless of
/// fractional-second width or a `Z` suffix. Returns `None` for an unrecognized
/// shape (the caller then falls back to a lexicographic compare).
fn parse_iso8601_naive(s: &str) -> Option<(i64, u8, u8, u8, u8, u8, u32)> {
    let s = s.strip_suffix('Z').unwrap_or(s);
    let (date, time) = s.split_once('T')?;

    let mut d = date.split('-');
    let year: i64 = d.next()?.parse().ok()?;
    let month: u8 = d.next()?.parse().ok()?;
    let day: u8 = d.next()?.parse().ok()?;
    if d.next().is_some() {
        return None;
    }

    let mut t = time.split(':');
    let hour: u8 = t.next()?.parse().ok()?;
    let minute: u8 = t.next()?.parse().ok()?;
    let sec_part = t.next()?;
    if t.next().is_some() {
        return None;
    }

    let (sec_str, frac_str) = match sec_part.split_once('.') {
        Some((sec, frac)) => (sec, frac),
        None => (sec_part, ""),
    };
    let second: u8 = sec_str.parse().ok()?;

    // Normalize fractional seconds to exactly 6 digits (microseconds).
    let mut micros: u32 = 0;
    if !frac_str.is_empty() {
        let mut buf = String::with_capacity(6);
        for c in frac_str.chars().take(6) {
            if !c.is_ascii_digit() {
                return None;
            }
            buf.push(c);
        }
        while buf.len() < 6 {
            buf.push('0');
        }
        micros = buf.parse().ok()?;
    }

    Some((year, month, day, hour, minute, second, micros))
}

/// Compare two ISO-8601 naive timestamps, falling back to a lexicographic
/// string compare if either is unparseable.
fn cmp_iso8601(a: &str, b: &str) -> std::cmp::Ordering {
    match (parse_iso8601_naive(a), parse_iso8601_naive(b)) {
        (Some(pa), Some(pb)) => pa.cmp(&pb),
        _ => a.cmp(b),
    }
}

/// The earlier (more restrictive) of two expiries — the shrink-only rule.
/// `None` means "no expiry" (least restrictive), so a present expiry always wins
/// over `None`. Mirrors Dart `_earlierExpiry`.
fn earlier_expiry<'a>(a: Option<&'a str>, b: Option<&'a str>) -> Option<&'a str> {
    match (a, b) {
        (None, _) => b,
        (_, None) => a,
        (Some(x), Some(y)) => Some(min_expiry(x, y)),
    }
}

/// The earlier of two PRESENT expiries.
///
/// When both parse, compares them as naive wall-clock instants and, on an exact
/// tie, returns `y` — mirroring Dart `a.isBefore(b) ? a : b` (which returns `b`
/// when the two are equal), so the merged `expiresAt` STRING is byte-identical to
/// what Dart would emit.
///
/// FAIL-CLOSED on a malformed string. Every trusted producer
/// (`DateTime.toIso8601String()` / JS `toISOString()`) emits a parseable
/// fixed-width form (Dart itself throws on a bad one), but if a string is
/// nonetheless unparseable we NEVER let a lexicographic miscompare pick it — we
/// keep the side that IS a real instant, so a garbage expiry can never extend the
/// access window. Only if BOTH are unparseable (pure data corruption, with no
/// instant to compare) do we fall back to a deterministic lexicographic
/// tie-break.
fn min_expiry<'a>(x: &'a str, y: &'a str) -> &'a str {
    match (parse_iso8601_naive(x), parse_iso8601_naive(y)) {
        // Both real instants: chronological; tie -> `y` (Dart's `isBefore ? a : b`).
        (Some(px), Some(py)) => {
            if px < py {
                x
            } else {
                y
            }
        }
        // Exactly one real instant: keep it — a malformed string must not win and
        // extend access.
        (Some(_), None) => x,
        (None, Some(_)) => y,
        // Both malformed: nothing to compare chronologically; stay deterministic.
        (None, None) => {
            if x <= y {
                x
            } else {
                y
            }
        }
    }
}
