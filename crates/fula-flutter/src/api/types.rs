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
        }
    }
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
}

/// Handle to an EncryptedClient instance
///
/// This wraps the encrypted client with interior mutability for forest state.
#[derive(Clone)]
pub struct EncryptedClientHandle {
    pub(crate) inner: Arc<RwLock<fula_client::EncryptedClient>>,
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
