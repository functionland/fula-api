//! Common types for the client SDK

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A bucket
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Bucket {
    /// Bucket name
    pub name: String,
    /// Creation date
    pub creation_date: DateTime<Utc>,
}

/// An object in a bucket
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Object {
    /// Object key
    pub key: String,
    /// Last modified time
    pub last_modified: DateTime<Utc>,
    /// ETag
    pub etag: String,
    /// Size in bytes
    pub size: u64,
    /// Storage class
    pub storage_class: String,
}

/// Object metadata
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ObjectMetadata {
    /// Content type
    pub content_type: Option<String>,
    /// Content encoding
    pub content_encoding: Option<String>,
    /// Cache control
    pub cache_control: Option<String>,
    /// Content disposition
    pub content_disposition: Option<String>,
    /// User-defined metadata
    pub user_metadata: std::collections::HashMap<String, String>,
}

impl ObjectMetadata {
    /// Create new empty metadata
    pub fn new() -> Self {
        Self::default()
    }

    /// Set content type
    pub fn with_content_type(mut self, ct: impl Into<String>) -> Self {
        self.content_type = Some(ct.into());
        self
    }

    /// Add user metadata
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.user_metadata.insert(key.into(), value.into());
        self
    }
}

/// Result of listing objects
#[derive(Clone, Debug)]
pub struct ListObjectsResult {
    /// Bucket name
    pub name: String,
    /// Prefix used for filtering
    pub prefix: String,
    /// Objects matching the query
    pub objects: Vec<Object>,
    /// Common prefixes (folders)
    pub common_prefixes: Vec<String>,
    /// Whether there are more results
    pub is_truncated: bool,
    /// Token for fetching next page
    pub next_continuation_token: Option<String>,
}

/// Result of listing buckets
#[derive(Clone, Debug)]
pub struct ListBucketsResult {
    /// Owner ID
    pub owner_id: String,
    /// Owner display name
    pub owner_display_name: String,
    /// List of buckets
    pub buckets: Vec<Bucket>,
}

/// Put object result
#[derive(Clone, Debug)]
pub struct PutObjectResult {
    /// ETag of the uploaded object
    pub etag: String,
    /// Version ID (if versioning enabled)
    pub version_id: Option<String>,
}

/// Get object result
///
/// `data` carries decrypted plaintext on the encrypted-SDK path. The
/// hand-rolled `Debug` impl redacts the byte payload so a stray
/// `tracing::warn!("{:?}", result)` cannot dump user file contents.
#[derive(Clone)]
pub struct GetObjectResult {
    /// Object data
    pub data: bytes::Bytes,
    /// ETag
    pub etag: String,
    /// Content type
    pub content_type: Option<String>,
    /// Content length
    pub content_length: u64,
    /// Last modified
    pub last_modified: Option<DateTime<Utc>>,
    /// User metadata
    pub metadata: std::collections::HashMap<String, String>,
}

impl std::fmt::Debug for GetObjectResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GetObjectResult")
            .field("data", &format_args!("[{} bytes redacted]", self.data.len()))
            .field("etag", &self.etag)
            .field("content_type", &self.content_type)
            .field("content_length", &self.content_length)
            .field("last_modified", &self.last_modified)
            .field("metadata", &self.metadata)
            .finish()
    }
}

/// Phase 19 — origin of a successfully-served byte payload.
///
/// Apps that surface offline indicators inspect this field to decide
/// what to show: `Master` is the fast path, `LocalCache` is a redb
/// BLOCKS hit (no network), and `Gateway(url)` records which IPFS
/// gateway the gateway-race elected. Defaulting to `Master` keeps
/// pre-Phase-19 callers byte-identical (they ignore the field).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReadSource {
    /// Master S3 served the request directly.
    Master,
    /// On-disk redb BLOCKS table served the bytes — no network round-trip.
    LocalCache,
    /// Public IPFS gateway served the bytes (master-down fallback path).
    /// The string is the URL template (e.g. `https://ipfs.io/ipfs/{cid}`)
    /// used at fetch time, useful for diagnostics or "served by Cloudflare"
    /// surfacing in operator dashboards.
    Gateway(String),
}

/// Phase 19 — freshness signal for a successfully-served byte payload.
///
/// `Live` is the master-served fast path. `Cached { observed_at }` is
/// returned when bytes came from local redb (BLOCKS hit) — apps may
/// choose to surface "viewing a saved copy" UI based on age. The
/// `StaleByDesign` / `StaleByOutage` variants are reserved for Phase
/// 3.3 cold-start where the SDK can attribute snapshot age to the
/// publisher cadence vs. an actual master outage; today the master-down
/// fallback path emits `Cached`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReadFreshness {
    /// Master-served bytes (fresh).
    Live,
    /// Served from on-disk redb cache; `observed_at` is the unix-millis
    /// when the entry was first written. Apps display age relative to
    /// this if they care to show staleness.
    Cached { observed_at: u64 },
    /// Cold-start cross-device read; snapshot age within the configured
    /// publisher cadence (≤ `USERS_INDEX_FLUSH_INTERVAL`). Apps may
    /// surface "synced N min ago".
    ///
    /// **Phase 3.3 scaffolding — not emitted by Phase 19.** Wired in
    /// when the cold-start resolver lands (task #18); resolver computes
    /// `snapshot_age_secs = now - resolved.payload.updated_at_unix`
    /// and selects this vs. `StaleByOutage` based on whether age is
    /// inside the publisher cadence.
    StaleByDesign { snapshot_age_secs: u64 },
    /// Cold-start cross-device read; snapshot age exceeds the
    /// publisher cadence — likely indicates an actual master outage.
    ///
    /// **Phase 3.3 scaffolding — not emitted by Phase 19.** See
    /// `StaleByDesign` doc above.
    StaleByOutage { snapshot_age_secs: u64 },
}

/// Phase 19 — wrapper around `GetObjectResult` carrying transparency
/// fields (`source`, `freshness`).
///
/// **Why a wrapper instead of fields on `GetObjectResult`:** the
/// existing struct is part of the SDK's public API consumed by callers
/// that pattern-match it exhaustively. Adding fields breaks them. A
/// new wrapper type lets callers opt in to the transparency surface
/// while existing consumers (including encrypted-SDK internals that
/// read `.data` / `.etag`) keep using `GetObjectResult` unchanged.
///
/// `Debug` is hand-rolled to delegate to `GetObjectResult`'s redacted
/// impl — the wrapped plaintext bytes never appear in log output.
#[derive(Clone)]
pub struct OfflineGetResult {
    /// The underlying `GetObjectResult` — `data`, `etag`, etc., are on
    /// `inner`. Callers that don't care about transparency just read
    /// `result.inner.data`.
    pub inner: GetObjectResult,
    /// Where the bytes ultimately came from. See `ReadSource` for variants.
    pub source: ReadSource,
    /// How fresh the bytes are. See `ReadFreshness` for variants.
    pub freshness: ReadFreshness,
}

impl std::fmt::Debug for OfflineGetResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OfflineGetResult")
            .field("inner", &self.inner)
            .field("source", &self.source)
            .field("freshness", &self.freshness)
            .finish()
    }
}

/// Head object result
#[derive(Clone, Debug)]
pub struct HeadObjectResult {
    /// ETag
    pub etag: String,
    /// Content type
    pub content_type: Option<String>,
    /// Content length
    pub content_length: u64,
    /// Last modified
    pub last_modified: Option<DateTime<Utc>>,
    /// User metadata
    pub metadata: std::collections::HashMap<String, String>,
}

/// Copy object result
#[derive(Clone, Debug)]
pub struct CopyObjectResult {
    /// ETag of the copied object
    pub etag: String,
    /// Last modified
    pub last_modified: DateTime<Utc>,
}

/// Options for listing objects
#[derive(Clone, Debug, Default)]
pub struct ListObjectsOptions {
    /// Filter by prefix
    pub prefix: Option<String>,
    /// Delimiter for grouping
    pub delimiter: Option<String>,
    /// Maximum keys to return
    pub max_keys: Option<usize>,
    /// Continuation token from previous request
    pub continuation_token: Option<String>,
    /// Start listing after this key
    pub start_after: Option<String>,
}
