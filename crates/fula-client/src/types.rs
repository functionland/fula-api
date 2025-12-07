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
#[derive(Clone, Debug)]
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
