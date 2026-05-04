//! Flutter-friendly type definitions
//!
//! These types are designed to be easily serializable across FFI boundaries
//! and compatible with flutter_rust_bridge code generation.

use std::sync::Arc;

// Use tokio::sync on native, async_lock on WASM
#[cfg(not(target_arch = "wasm32"))]
use tokio::sync::RwLock;
#[cfg(not(target_arch = "wasm32"))]
pub(crate) use tokio::sync::Semaphore;

#[cfg(target_arch = "wasm32")]
use async_lock::RwLock;
#[cfg(target_arch = "wasm32")]
pub(crate) use async_lock::Semaphore;

// ============================================================================
// Configuration Types
// ============================================================================

/// Configuration for creating a Fula client
#[derive(Debug, Clone)]
pub struct FulaConfig {
    /// Gateway endpoint URL (e.g., "http://localhost:9000")
    pub endpoint: String,
    /// JWT access token for authentication
    pub access_token: Option<String>,
    /// Request timeout in seconds (default: 30)
    pub timeout_seconds: u64,
    /// Maximum retry attempts (default: 3)
    pub max_retries: u32,
    /// F10: per-chunk download timeout in seconds.
    ///
    /// Applied to every individual chunk fetched by the windowed chunked-download
    /// engine. Guards against a slow server trickling bytes below the global
    /// dead-connection threshold. Only active on native targets; wasm inherits
    /// the browser fetch default. Default: 300 (5 minutes).
    pub per_chunk_download_timeout_seconds: u64,
    /// F8: maximum plaintext size a buffered download will accept.
    ///
    /// Applied *before* any network I/O by the buffered download path. If the
    /// chunked metadata declares a `total_size` larger than this ceiling, the
    /// buffered path returns an error instead of allocating the buffer.
    /// Default: 256 MiB.
    pub buffered_download_max_bytes: u64,

    // ============================================================
    // Phase 2.1 — master-down detection (health gate)
    // ============================================================
    /// Enable the SDK's master health gate. Off by default
    /// (backward-compat). When on, the SDK observes request outcomes
    /// and short-circuits with `Network`/`MasterUnreachable` error
    /// after two consecutive failures, instead of paying the per-read
    /// timeout. Works on every platform fula-flutter ships against.
    pub health_gate_enabled: bool,

    /// TTL of the `Down` state when `health_gate_enabled = true`.
    /// After this duration elapses, the next request is allowed
    /// through as a probe. Default: 30 seconds.
    pub health_gate_ttl_seconds: u64,

    // ============================================================
    // Phase 2.2 — persistent block cache
    // ============================================================
    /// Enable the on-disk LRU block cache.
    ///
    /// **Native-only.** The cache is `redb`-backed and not available
    /// in browser-targeted builds. Setting `true` on a wasm32 target
    /// is silently inert — the underlying SDK skips construction and
    /// the offline path stays unavailable in the browser. On
    /// Android/iOS/Ubuntu/Windows the field activates Phase 2.2.
    pub block_cache_enabled: bool,

    /// Filesystem path for the block-cache redb database. Empty
    /// string = use the platform default (`dirs::data_local_dir()/
    /// fula/cache/blocks.redb`). Native-only; ignored on wasm32.
    pub block_cache_path: String,

    /// Maximum on-disk bytes for the block cache. Default: 256 MiB.
    /// The cache evicts to 80 % of this watermark when a `put` would
    /// push it past `max_bytes`. Native-only; ignored on wasm32.
    pub block_cache_max_bytes: u64,

    // ============================================================
    // Phase 2.3 / 2.4 — IPFS gateway race + offline GET fallback
    // ============================================================
    /// Enable falling back to public IPFS gateways when master is
    /// unreachable AND the SDK has previously cached the requested
    /// object's CID via Phase 2.2's KEY_TO_CID table.
    ///
    /// Requires `block_cache_enabled = true` (the cache holds the
    /// `(bucket, key) → cid` map the gateway race needs). Native-only;
    /// ignored on wasm32.
    pub gateway_fallback_enabled: bool,

    /// Custom gateway URL templates. Each must contain the literal
    /// `{cid}` token, which the SDK substitutes per fetch. Empty Vec
    /// means "use the SDK-shipped default list of six gateways"
    /// (Cloudflare, dweb.link, ipfs.io, trustless-gateway.link,
    /// 4everland.io, gateway.pinata.cloud). Native-only.
    pub gateway_fallback_urls: Vec<String>,

    /// Number of gateways the SDK races in parallel for any single
    /// CID. Default: 3. Capped at the gateway-pool length.
    /// Native-only.
    pub gateway_race_concurrency: u32,

    // ============================================================
    // Phase 3.3 — cold-start hybrid resolver
    // ============================================================
    //
    // The resolver activates iff ALL of the following four fields
    // are populated:
    //   - users_index_chain_rpc_url (non-empty)
    //   - users_index_anchor_address (non-empty)
    //   - users_index_ipns_name (non-empty)
    //   - users_index_user_key (non-empty)
    //
    // When any one is empty the resolver stays disabled; cold-start
    // GETs fall through with `UsersIndexResolutionFailed`. Default
    // values are all empty strings → resolver disabled (backward
    // compat with pre-Phase-3.3 builds).

    /// JSON-RPC URL for the chain anchor contract (Base or SKALE).
    /// Required to enable Phase 3.3 cold-start. Empty → disabled.
    pub users_index_chain_rpc_url: String,

    /// `FulaUsersIndexAnchor.sol` contract address (20 bytes hex,
    /// optionally `0x`-prefixed). Required to enable Phase 3.3.
    pub users_index_anchor_address: String,

    /// IPNS NAME (libp2p public-key hash, e.g. `k51qzi5...`) under
    /// which the master publishes the global users-index CBOR.
    /// Required to enable Phase 3.3.
    pub users_index_ipns_name: String,

    /// 32-hex-char `userKey` (= `BLAKE3("fula:user_id:" || sha256(lower(email)))[..16]`).
    /// Compute via the free function [`derive_user_key_from_email`]
    /// at sign-in time and pass in here. The SDK does not store the
    /// raw email. Required to enable Phase 3.3.
    pub users_index_user_key: String,

    /// IPNS-aware gateway URL templates (each must contain `{name}`).
    /// Empty Vec = use SDK-shipped defaults
    /// (Cloudflare/dweb.link/ipfs.io/4everland/Pinata).
    /// Native-only — wasm cold-start uses the typed-error path.
    pub users_index_ipns_gateway_urls: Vec<String>,

    /// `/ipfs/{cid}` gateway URL templates (each must contain `{cid}`).
    /// Empty Vec = use SDK-shipped 6-gateway default list.
    /// Native-only.
    pub users_index_ipfs_gateway_urls: Vec<String>,
}

impl Default for FulaConfig {
    fn default() -> Self {
        Self {
            endpoint: "http://localhost:9000".to_string(),
            access_token: None,
            timeout_seconds: 30,
            max_retries: 3,
            per_chunk_download_timeout_seconds: 300,
            buffered_download_max_bytes: 256 * 1024 * 1024,
            // Phase 2.x — all flags off by default (backward-compat).
            // Apps must opt in explicitly; existing Dart code sees
            // byte-identical behavior to pre-Phase-2.x builds.
            health_gate_enabled: false,
            health_gate_ttl_seconds: 30,
            block_cache_enabled: false,
            block_cache_path: String::new(),
            block_cache_max_bytes: 256 * 1024 * 1024,
            gateway_fallback_enabled: false,
            gateway_fallback_urls: Vec::new(),
            gateway_race_concurrency: 3,
            // Phase 3.3 — resolver disabled by default. Operator
            // sets the four required fields at sign-in to enable
            // cold-start; cold-start surfaces UsersIndexResolutionFailed
            // until they're set, mirroring the Rust core's behavior.
            users_index_chain_rpc_url: String::new(),
            users_index_anchor_address: String::new(),
            users_index_ipns_name: String::new(),
            users_index_user_key: String::new(),
            users_index_ipns_gateway_urls: Vec::new(),
            users_index_ipfs_gateway_urls: Vec::new(),
        }
    }
}

// ============================================================
// Phase 19 — transparency surfaces
// ============================================================

/// Where the bytes of a successfully-served read came from. Mirrors
/// `fula_client::ReadSource`. Apps surface "you're reading from
/// cache" / "served by a public gateway" UI based on this.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FulaReadSource {
    /// Master S3 served the request directly (fast path).
    Master,
    /// On-disk redb BLOCKS table served the bytes — no network at all.
    LocalCache,
    /// Public IPFS gateway served the bytes (master-down fallback).
    /// The string is the URL template (e.g. `https://ipfs.io/ipfs/{cid}`)
    /// that won the gateway race — useful for diagnostics or
    /// "served by ipfs.io" labeling.
    Gateway(String),
}

/// Freshness of a successfully-served read. Mirrors
/// `fula_client::ReadFreshness`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FulaReadFreshness {
    /// Master-served bytes (fresh, by definition).
    Live,
    /// Served from on-disk cache. `observed_at` is the unix-millis
    /// when the entry was first written to cache.
    Cached { observed_at: u64 },
    /// Cold-start cross-device read; snapshot age within the
    /// publisher cadence (≤ `USERS_INDEX_FLUSH_INTERVAL`). Apps
    /// can surface "synced N min ago".
    StaleByDesign { snapshot_age_secs: u64 },
    /// Cold-start cross-device read; snapshot age exceeds the
    /// publisher cadence — likely indicates an actual master outage.
    StaleByOutage { snapshot_age_secs: u64 },
}

/// Wrapper around `GetObjectResult` adding Phase 19 transparency
/// fields. Mirrors `fula_client::OfflineGetResult`. Apps that
/// don't care about transparency just read `.inner.data`.
#[derive(Debug, Clone)]
pub struct OfflineGetResult {
    /// Underlying `GetObjectResult` — `data`, `etag`, `content_type`,
    /// `content_length`, `last_modified`, `metadata` are on `inner`.
    pub inner: GetObjectResult,
    /// Where the bytes ultimately came from.
    pub source: FulaReadSource,
    /// How fresh the bytes are.
    pub freshness: FulaReadFreshness,
}

/// Master-server reachability transition events. Mirrors
/// `fula_client::MasterHealthEvent`. Subscribed via
/// `subscribe_master_health_events`; apps wire the stream to
/// online/offline UI affordances.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MasterHealthEvent {
    /// Master S3 is reachable; reads use the fast path.
    Online,
    /// Master S3 is unreachable; SDK is falling back to IPFS
    /// gateways (Phase 2.4) or cold-start resolver (Phase 3.3).
    OfflineFallbackActive { reason: String },
    /// Both master S3 AND chain RPC are unreachable. Cold-start
    /// reads fail; warm reads (cached metadata) still work via
    /// gateways. Apps should disable "open new bucket" / "first-
    /// read" UI affordances when this fires. Emitted only from
    /// the cold-start failure path — the health gate alone can't
    /// authoritatively detect "both down" without trying.
    SeverelyDegraded { reason: String },
}

/// Configuration for client-side encryption
#[derive(Debug, Clone)]
pub struct EncryptionConfig {
    /// Secret key bytes (32 bytes). If None, a new key is generated.
    pub secret_key: Option<Vec<u8>>,
    /// Enable metadata privacy (obfuscates file names)
    pub enable_metadata_privacy: bool,
    /// Obfuscation mode for file names
    pub obfuscation_mode: ObfuscationMode,
}

impl Default for EncryptionConfig {
    fn default() -> Self {
        Self {
            secret_key: None,
            enable_metadata_privacy: true,
            obfuscation_mode: ObfuscationMode::Deterministic,
        }
    }
}

/// Obfuscation mode for file name privacy
///
/// Controls how file paths are obfuscated before sending to the server.
/// This affects what the server can learn about your file structure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ObfuscationMode {
    /// Hash the key with a secret prefix (deterministic - same key = same hash)
    /// Allows server-side deduplication but reveals if same file uploaded twice.
    /// Server sees: `e/a7c3f9b2e8d14a6f` (reveals "e/" prefix)
    #[default]
    Deterministic,
    /// Random UUID for each upload (non-deterministic)
    /// Maximum privacy but no dedup.
    /// Server sees: `e/random-uuid-here`
    Random,
    /// Flat namespace - complete structure hiding (RECOMMENDED)
    ///
    /// Inspired by WNFS and Peergos:
    /// - All keys look like random CID-style hashes
    /// - No prefixes or structure hints
    /// - File tree stored in encrypted index (PrivateForest)
    /// - Server cannot determine folder structure, parent/child relationships
    ///
    /// Server sees: `QmX7a8f3e2d1c9b4a5e6f7d8c9a0b1e2f3a4b5c6d7e8f9`
    FlatNamespace,
    /// Preserve path structure but hash filenames
    /// e.g., "/photos/vacation/" + hash(filename)
    /// Allows folder-like organization while hiding filenames.
    /// Server sees: `/photos/vacation/e_a7c3f9b2`
    PreserveStructure,
}

/// Configuration for IPFS pinning service
#[derive(Debug, Clone)]
pub struct PinningConfig {
    /// Pinning service endpoint URL
    pub endpoint: String,
    /// Authentication token
    pub token: String,
}

// ============================================================================
// Result Types
// ============================================================================

/// Result of a put/upload operation
#[derive(Debug, Clone)]
pub struct PutResult {
    /// ETag of the uploaded object
    pub etag: String,
    /// Version ID (if versioning enabled)
    pub version_id: Option<String>,
}

/// Result of a get operation with metadata
#[derive(Debug, Clone)]
pub struct GetObjectResult {
    /// Object data
    pub data: Vec<u8>,
    /// ETag
    pub etag: String,
    /// Content type
    pub content_type: Option<String>,
    /// Size in bytes
    pub size: u64,
    /// Last modified timestamp (Unix epoch seconds)
    pub last_modified: i64,
    /// User metadata
    pub metadata: Vec<MetadataEntry>,
}

/// Result of a HEAD operation
#[derive(Debug, Clone)]
pub struct HeadResult {
    /// ETag
    pub etag: String,
    /// Content type
    pub content_type: Option<String>,
    /// Size in bytes
    pub size: u64,
    /// Last modified timestamp (Unix epoch seconds)
    pub last_modified: i64,
    /// User metadata
    pub metadata: Vec<MetadataEntry>,
}

/// Result of a copy operation
#[derive(Debug, Clone)]
pub struct CopyResult {
    /// ETag of the copied object
    pub etag: String,
    /// Last modified timestamp (Unix epoch seconds)
    pub last_modified: i64,
}

/// Result of listing objects
#[derive(Debug, Clone)]
pub struct ListObjectsResult {
    /// Objects in the current page
    pub objects: Vec<ObjectInfo>,
    /// Common prefixes (for delimiter-based listing)
    pub common_prefixes: Vec<String>,
    /// Whether there are more results
    pub is_truncated: bool,
    /// Token for fetching next page
    pub next_token: Option<String>,
}

// ============================================================================
// Info Types
// ============================================================================

/// Information about a bucket
#[derive(Debug, Clone)]
pub struct BucketInfo {
    /// Bucket name
    pub name: String,
    /// Creation timestamp (Unix epoch seconds)
    pub created_at: i64,
}

/// Information about an object
#[derive(Debug, Clone)]
pub struct ObjectInfo {
    /// Object key
    pub key: String,
    /// Size in bytes
    pub size: u64,
    /// Last modified timestamp (Unix epoch seconds)
    pub last_modified: i64,
    /// ETag
    pub etag: String,
    /// Storage class
    pub storage_class: String,
}

/// Metadata for a decrypted file
#[derive(Debug, Clone)]
pub struct FileMetadata {
    /// Storage key (obfuscated name used in storage)
    pub storage_key: String,
    /// Original key (actual file path/name)
    pub original_key: String,
    /// Original file size in bytes
    pub size: u64,
    /// Content type
    pub content_type: Option<String>,
    /// Creation timestamp (Unix epoch seconds)
    pub created_at: Option<i64>,
    /// Modification timestamp (Unix epoch seconds)
    pub modified_at: Option<i64>,
    /// Whether the file is encrypted
    pub is_encrypted: bool,
}

/// Decrypted object with all metadata
#[derive(Debug, Clone)]
pub struct DecryptedObjectInfo {
    /// Decrypted data
    pub data: Vec<u8>,
    /// Original key/path
    pub original_key: String,
    /// Original size
    pub size: u64,
    /// Content type
    pub content_type: Option<String>,
    /// User metadata
    pub metadata: Vec<MetadataEntry>,
}

/// Directory listing result
#[derive(Debug, Clone)]
pub struct DirectoryListing {
    /// Bucket name
    pub bucket: String,
    /// Prefix used for listing
    pub prefix: Option<String>,
    /// Directory entries
    pub entries: Vec<DirectoryEntry>,
}

/// A directory entry (file or subdirectory)
#[derive(Debug, Clone)]
pub struct DirectoryEntry {
    /// Name of entry
    pub name: String,
    /// Whether this is a directory
    pub is_directory: bool,
    /// Files in this directory (if is_directory)
    pub files: Vec<FileMetadata>,
}

/// A key-value metadata entry
#[derive(Debug, Clone)]
pub struct MetadataEntry {
    /// Metadata key
    pub key: String,
    /// Metadata value
    pub value: String,
}

/// Object metadata for upload
#[derive(Debug, Clone, Default)]
pub struct ObjectMetadata {
    /// Content type
    pub content_type: Option<String>,
    /// Cache control header
    pub cache_control: Option<String>,
    /// User metadata entries
    pub user_metadata: Vec<MetadataEntry>,
}

/// Options for listing objects
#[derive(Debug, Clone, Default)]
pub struct ListOptions {
    /// Prefix filter
    pub prefix: Option<String>,
    /// Delimiter for hierarchical listing
    pub delimiter: Option<String>,
    /// Maximum keys to return
    pub max_keys: Option<u32>,
    /// Continuation token for pagination
    pub continuation_token: Option<String>,
}

/// Serialized forest subtree (for sharing)
#[derive(Debug, Clone)]
pub struct ForestSubtree {
    /// Serialized subtree data
    pub serialized: Vec<u8>,
}

// ============================================================================
// Sharing Types
// ============================================================================

/// Share mode for creating share tokens
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShareMode {
    /// Read-only access
    Read,
    /// Read and write access
    Write,
    /// Time-limited access
    Temporal,
    /// Snapshot (point-in-time) access
    Snapshot,
}

/// Permissions granted by a share
#[derive(Debug, Clone)]
pub struct SharePermissions {
    /// Can read content
    pub can_read: bool,
    /// Can write/modify content
    pub can_write: bool,
    /// Expiration timestamp (Unix epoch seconds), None = never expires
    pub expires_at: Option<i64>,
}

// ============================================================================
// Rotation Types
// ============================================================================

/// Report from a bucket rotation operation
#[derive(Debug, Clone)]
pub struct RotationReport {
    /// Total objects processed
    pub total: u32,
    /// Objects successfully rotated
    pub rotated: u32,
    /// Objects skipped (already current)
    pub skipped: u32,
    /// Objects that failed rotation
    pub failed: u32,
    /// Details of failures
    pub failures: Vec<RotationFailure>,
}

/// Details of a rotation failure
#[derive(Debug, Clone)]
pub struct RotationFailure {
    /// Storage key that failed
    pub storage_key: String,
    /// Error message
    pub error: String,
}

// ============================================================================
// Multipart Upload Types
// ============================================================================

/// Progress of an upload operation
#[derive(Debug, Clone)]
pub struct UploadProgress {
    /// Bytes uploaded so far
    pub bytes_uploaded: u64,
    /// Total bytes to upload
    pub total_bytes: u64,
    /// Current part number
    pub current_part: u32,
    /// Total number of parts
    pub total_parts: u32,
    /// Percentage complete (0.0 - 100.0)
    pub percentage: f64,
}

// ============================================================================
// Handle Types (Opaque wrappers for FFI)
// ============================================================================

/// Handle to a FulaClient instance
///
/// This is an opaque handle that wraps the underlying client.
/// It is thread-safe and can be shared across async operations.
#[derive(Clone)]
pub struct FulaClientHandle {
    pub(crate) inner: Arc<fula_client::FulaClient>,
    /// Phase 19 — dispatcher for `MasterHealthEvent` stream
    /// subscribers. The Config's `health_callback` (set by
    /// `build_inner_config`) captures a clone of this `Arc` and
    /// forwards each transition to all live subscribers AND to a
    /// "last event seen" slot exposed via `get_last_master_health_event`.
    /// Always present so apps can subscribe at any time without
    /// re-creating the client.
    pub(crate) health_dispatcher: Arc<HealthEventDispatcher>,
}

/// Handle to an EncryptedClient instance
///
/// This wraps the encrypted client with interior mutability for forest state.
#[derive(Clone)]
pub struct EncryptedClientHandle {
    pub(crate) inner: Arc<RwLock<fula_client::EncryptedClient>>,
    /// Phase 19 — same dispatcher pattern as FulaClientHandle.
    /// Encrypted-client construction also threads the callback into
    /// the underlying `fula_client::Config` so warm-cache + cold-
    /// start transitions both surface to subscribers.
    pub(crate) health_dispatcher: Arc<HealthEventDispatcher>,
}

/// Phase 19 — internal dispatcher that captures `MasterHealthEvent`
/// transitions for two consumption patterns:
///
///   1. **Polling drain** (`poll_master_health_events`): apps call
///      this periodically (or on UI rebuilds) and receive every
///      event observed since the last call. The internal buffer is
///      a bounded `VecDeque` capped at `MAX_BUFFERED_EVENTS`; if the
///      app falls so far behind that the buffer overflows, oldest
///      events are dropped first (apps care about the *latest* state,
///      not the entire history).
///
///   2. **Latest-state read** (`get_last_master_health_event`):
///      returns the most recent event without draining. Useful for
///      apps that want to display "you're offline" immediately on
///      mount based on whatever the SDK has observed so far.
///
/// **Why polling instead of a Dart `Stream`:** wiring `StreamSink<T>`
/// requires the FRB codegen to have seen `MasterHealthEvent` — a
/// chicken-and-egg dependency on `flutter_rust_bridge_codegen
/// generate` having run after this commit. Polling sidesteps that
/// while still giving apps every event in order. A future iteration
/// can layer a `Stream<MasterHealthEvent>` on top once codegen has
/// registered the type, without breaking this polling API.
///
/// Wrapping the buffer in `parking_lot::Mutex` (sync, no `await`)
/// is required because the dispatcher is invoked from the SDK's hot
/// path inside `health_gate::fire_event`, which doesn't tolerate
/// async locks.
pub struct HealthEventDispatcher {
    /// Pending events not yet drained by `poll_master_health_events`.
    /// Bounded by [`MAX_BUFFERED_EVENTS`].
    buffer: parking_lot::Mutex<std::collections::VecDeque<MasterHealthEvent>>,
    /// Most recent event observed, regardless of whether it was
    /// drained. Read by `get_last_master_health_event`.
    last_event: parking_lot::Mutex<Option<MasterHealthEvent>>,
}

/// Maximum number of pending events held by [`HealthEventDispatcher`]
/// before older ones get dropped. 64 is plenty for typical apps —
/// a healthy session sees a handful of transitions per hour at most.
const MAX_BUFFERED_EVENTS: usize = 64;

impl HealthEventDispatcher {
    pub(crate) fn new() -> Self {
        Self {
            buffer: parking_lot::Mutex::new(std::collections::VecDeque::new()),
            last_event: parking_lot::Mutex::new(None),
        }
    }

    /// Called from the `health_callback` set on the underlying
    /// `fula_client::Config`. Captures the event for both polling
    /// drain and latest-state read.
    pub(crate) fn dispatch(&self, event: fula_client::MasterHealthEvent) {
        let app_event: MasterHealthEvent = event.into();
        *self.last_event.lock() = Some(app_event.clone());
        let mut buf = self.buffer.lock();
        if buf.len() >= MAX_BUFFERED_EVENTS {
            // Drop oldest to make room for newest. Apps care about
            // the latest state more than ancient history.
            buf.pop_front();
        }
        buf.push_back(app_event);
    }

    pub(crate) fn drain_events(&self) -> Vec<MasterHealthEvent> {
        let mut buf = self.buffer.lock();
        buf.drain(..).collect()
    }

    pub(crate) fn last_event(&self) -> Option<MasterHealthEvent> {
        self.last_event.lock().clone()
    }
}

/// Handle to an accepted share
pub struct AcceptedShareHandle {
    pub(crate) inner: fula_crypto::AcceptedShare,
}

/// Handle to a key rotation manager
#[derive(Clone)]
pub struct RotationManagerHandle {
    pub(crate) inner: Arc<fula_crypto::KeyRotationManager>,
}

/// Handle to an ongoing multipart upload
///
/// The inner [`MultipartUpload`](fula_client::MultipartUpload) uses interior
/// mutability, so parallel `upload_part` calls can run their HTTP I/O without
/// serialising. The `semaphore` bounds how many parts are in flight at once
/// to avoid saturating the mobile radio, file handles, or the pinning
/// service with a burst of concurrent POSTs.
#[derive(Clone)]
pub struct MultipartHandle {
    pub(crate) inner: Arc<fula_client::MultipartUpload>,
    pub(crate) semaphore: Arc<Semaphore>,
    #[allow(dead_code)]
    pub(crate) client: Arc<fula_client::FulaClient>,
}

// ============================================================================
// Type Conversions
// ============================================================================

impl From<fula_client::Bucket> for BucketInfo {
    fn from(b: fula_client::Bucket) -> Self {
        Self {
            name: b.name,
            created_at: b.creation_date.timestamp(),
        }
    }
}

impl From<fula_client::Object> for ObjectInfo {
    fn from(o: fula_client::Object) -> Self {
        Self {
            key: o.key,
            size: o.size,
            last_modified: o.last_modified.timestamp(),
            etag: o.etag,
            storage_class: o.storage_class,
        }
    }
}

impl From<fula_client::PutObjectResult> for PutResult {
    fn from(r: fula_client::PutObjectResult) -> Self {
        Self {
            etag: r.etag,
            version_id: r.version_id,
        }
    }
}

impl From<fula_client::HeadObjectResult> for HeadResult {
    fn from(r: fula_client::HeadObjectResult) -> Self {
        Self {
            etag: r.etag,
            content_type: r.content_type,
            size: r.content_length,
            last_modified: r.last_modified.map(|d| d.timestamp()).unwrap_or(0),
            metadata: r.metadata.into_iter()
                .map(|(k, v)| MetadataEntry { key: k, value: v })
                .collect(),
        }
    }
}

impl From<fula_client::CopyObjectResult> for CopyResult {
    fn from(r: fula_client::CopyObjectResult) -> Self {
        Self {
            etag: r.etag,
            last_modified: r.last_modified.timestamp(),
        }
    }
}

impl From<fula_client::ListObjectsResult> for ListObjectsResult {
    fn from(r: fula_client::ListObjectsResult) -> Self {
        Self {
            objects: r.objects.into_iter().map(|o| o.into()).collect(),
            common_prefixes: r.common_prefixes,
            is_truncated: r.is_truncated,
            next_token: r.next_continuation_token,
        }
    }
}

impl From<fula_client::FileMetadata> for FileMetadata {
    fn from(m: fula_client::FileMetadata) -> Self {
        Self {
            storage_key: m.storage_key,
            original_key: m.original_key,
            size: m.original_size,
            content_type: m.content_type,
            created_at: m.created_at,
            modified_at: m.modified_at,
            is_encrypted: m.is_encrypted,
        }
    }
}

impl From<fula_client::GetObjectResult> for GetObjectResult {
    fn from(r: fula_client::GetObjectResult) -> Self {
        Self {
            data: r.data.to_vec(),
            etag: r.etag,
            content_type: r.content_type,
            size: r.content_length,
            last_modified: r.last_modified.map(|d| d.timestamp()).unwrap_or(0),
            metadata: r.metadata.into_iter()
                .map(|(k, v)| MetadataEntry { key: k, value: v })
                .collect(),
        }
    }
}

// Phase 19 transparency conversions. These bridge the Rust-core
// `fula_client::*` types to FRB-friendly Dart-side equivalents.
// They're plain unit/struct/string-payload variants so FRB v2's
// codegen produces a sealed Dart class without any custom adapter.

impl From<fula_client::ReadSource> for FulaReadSource {
    fn from(s: fula_client::ReadSource) -> Self {
        match s {
            fula_client::ReadSource::Master => FulaReadSource::Master,
            fula_client::ReadSource::LocalCache => FulaReadSource::LocalCache,
            fula_client::ReadSource::Gateway(url) => FulaReadSource::Gateway(url),
        }
    }
}

impl From<fula_client::ReadFreshness> for FulaReadFreshness {
    fn from(f: fula_client::ReadFreshness) -> Self {
        match f {
            fula_client::ReadFreshness::Live => FulaReadFreshness::Live,
            fula_client::ReadFreshness::Cached { observed_at } => {
                FulaReadFreshness::Cached { observed_at }
            }
            fula_client::ReadFreshness::StaleByDesign { snapshot_age_secs } => {
                FulaReadFreshness::StaleByDesign { snapshot_age_secs }
            }
            fula_client::ReadFreshness::StaleByOutage { snapshot_age_secs } => {
                FulaReadFreshness::StaleByOutage { snapshot_age_secs }
            }
        }
    }
}

impl From<fula_client::OfflineGetResult> for OfflineGetResult {
    fn from(r: fula_client::OfflineGetResult) -> Self {
        Self {
            inner: r.inner.into(),
            source: r.source.into(),
            freshness: r.freshness.into(),
        }
    }
}

impl From<fula_client::MasterHealthEvent> for MasterHealthEvent {
    fn from(e: fula_client::MasterHealthEvent) -> Self {
        match e {
            fula_client::MasterHealthEvent::Online => MasterHealthEvent::Online,
            fula_client::MasterHealthEvent::OfflineFallbackActive { reason } => {
                MasterHealthEvent::OfflineFallbackActive { reason }
            }
            fula_client::MasterHealthEvent::SeverelyDegraded { reason } => {
                MasterHealthEvent::SeverelyDegraded { reason }
            }
        }
    }
}

impl From<fula_client::DecryptedObjectInfo> for DecryptedObjectInfo {
    fn from(r: fula_client::DecryptedObjectInfo) -> Self {
        Self {
            data: r.data.to_vec(),
            original_key: r.original_key,
            size: r.original_size,
            content_type: r.content_type,
            metadata: r.user_metadata.into_iter()
                .map(|(k, v)| MetadataEntry { key: k, value: v })
                .collect(),
        }
    }
}

// RotationReport conversion is handled in rotation.rs since
// fula_client::encryption::RotationReport is not publicly exported

impl From<ListOptions> for fula_client::ListObjectsOptions {
    fn from(o: ListOptions) -> Self {
        Self {
            prefix: o.prefix,
            delimiter: o.delimiter,
            max_keys: o.max_keys.map(|n| n as usize),
            continuation_token: o.continuation_token,
            start_after: None,
        }
    }
}

impl From<ObjectMetadata> for fula_client::ObjectMetadata {
    fn from(m: ObjectMetadata) -> Self {
        let mut result = Self::new();
        if let Some(ct) = m.content_type {
            result = result.with_content_type(&ct);
        }
        if let Some(cc) = m.cache_control {
            result.cache_control = Some(cc);
        }
        for entry in m.user_metadata {
            result.user_metadata.insert(entry.key, entry.value);
        }
        result
    }
}
