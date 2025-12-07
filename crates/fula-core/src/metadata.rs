//! Object and bucket metadata types

use cid::Cid;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Storage class for objects
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StorageClass {
    /// Standard storage (default)
    #[default]
    Standard,
    /// Infrequent access
    StandardIa,
    /// One zone infrequent access
    OneZoneIa,
    /// Glacier
    Glacier,
    /// Deep archive
    DeepArchive,
    /// Intelligent tiering
    IntelligentTiering,
}

impl StorageClass {
    /// Get the string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Standard => "STANDARD",
            Self::StandardIa => "STANDARD_IA",
            Self::OneZoneIa => "ONEZONE_IA",
            Self::Glacier => "GLACIER",
            Self::DeepArchive => "DEEP_ARCHIVE",
            Self::IntelligentTiering => "INTELLIGENT_TIERING",
        }
    }
}

/// Encryption metadata for client-side encrypted objects
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptionMetadata {
    /// Encryption algorithm used
    pub algorithm: String,
    /// Encapsulated key (base64 encoded)
    pub encapsulated_key: String,
    /// Key version for rotation tracking
    pub key_version: u32,
    /// Nonce used for encryption (base64 encoded)
    pub nonce: String,
    /// Original content hash (before encryption)
    pub content_hash: Option<String>,
}

/// Metadata for a stored object
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ObjectMetadata {
    /// The CID of the raw data (or encrypted data)
    #[serde(with = "cid_serde")]
    pub cid: Cid,
    
    /// Size in bytes
    pub size: u64,
    
    /// ETag (usually MD5 hash for S3 compatibility)
    pub etag: String,
    
    /// Last modified timestamp
    pub last_modified: DateTime<Utc>,
    
    /// Storage class
    pub storage_class: StorageClass,
    
    /// Content type (MIME type)
    pub content_type: Option<String>,
    
    /// Content encoding
    pub content_encoding: Option<String>,
    
    /// Cache control directive
    pub cache_control: Option<String>,
    
    /// Content disposition
    pub content_disposition: Option<String>,
    
    /// User-defined metadata (x-amz-meta-* headers)
    #[serde(default)]
    pub user_metadata: HashMap<String, String>,
    
    /// Encryption information (for client-side encrypted objects)
    pub encryption_info: Option<EncryptionMetadata>,
    
    /// Tags
    #[serde(default)]
    pub tags: HashMap<String, String>,
    
    /// Version ID (if versioning enabled)
    pub version_id: Option<String>,
    
    /// Whether this is a delete marker
    #[serde(default)]
    pub is_delete_marker: bool,
    
    /// CID of the Bao outboard data (for verified streaming)
    #[serde(default, with = "option_cid_serde")]
    pub bao_outboard_cid: Option<Cid>,
    
    /// Owner ID (hashed)
    pub owner_id: Option<String>,
    
    /// Checksum (BLAKE3)
    pub checksum_blake3: Option<String>,
}

impl ObjectMetadata {
    /// Create new metadata for an object
    pub fn new(cid: Cid, size: u64, etag: String) -> Self {
        Self {
            cid,
            size,
            etag,
            last_modified: Utc::now(),
            storage_class: StorageClass::default(),
            content_type: None,
            content_encoding: None,
            cache_control: None,
            content_disposition: None,
            user_metadata: HashMap::new(),
            encryption_info: None,
            tags: HashMap::new(),
            version_id: None,
            is_delete_marker: false,
            bao_outboard_cid: None,
            owner_id: None,
            checksum_blake3: None,
        }
    }

    /// Create a delete marker
    pub fn delete_marker(version_id: String) -> Self {
        Self {
            cid: Cid::default(),
            size: 0,
            etag: String::new(),
            last_modified: Utc::now(),
            storage_class: StorageClass::default(),
            content_type: None,
            content_encoding: None,
            cache_control: None,
            content_disposition: None,
            user_metadata: HashMap::new(),
            encryption_info: None,
            tags: HashMap::new(),
            version_id: Some(version_id),
            is_delete_marker: true,
            bao_outboard_cid: None,
            owner_id: None,
            checksum_blake3: None,
        }
    }

    /// Set content type
    pub fn with_content_type(mut self, content_type: impl Into<String>) -> Self {
        self.content_type = Some(content_type.into());
        self
    }

    /// Set encryption info
    pub fn with_encryption(mut self, encryption: EncryptionMetadata) -> Self {
        self.encryption_info = Some(encryption);
        self
    }

    /// Add user metadata
    pub fn with_user_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.user_metadata.insert(key.into(), value.into());
        self
    }

    /// Set owner
    pub fn with_owner(mut self, owner_id: impl Into<String>) -> Self {
        self.owner_id = Some(owner_id.into());
        self
    }

    /// Check if object is encrypted
    pub fn is_encrypted(&self) -> bool {
        self.encryption_info.is_some()
    }
}

/// Bucket metadata
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BucketMetadata {
    /// Bucket name
    pub name: String,
    
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    
    /// Owner ID (hashed)
    pub owner_id: String,
    
    /// Current root CID of the Prolly Tree
    #[serde(with = "cid_serde")]
    pub root_cid: Cid,
    
    /// Whether versioning is enabled
    #[serde(default)]
    pub versioning_enabled: bool,
    
    /// Default storage class
    #[serde(default)]
    pub default_storage_class: StorageClass,
    
    /// Bucket tags
    #[serde(default)]
    pub tags: HashMap<String, String>,
    
    /// CORS configuration
    pub cors_config: Option<CorsConfiguration>,
    
    /// Lifecycle rules
    #[serde(default)]
    pub lifecycle_rules: Vec<LifecycleRule>,
    
    /// Object count (cached)
    pub object_count: u64,
    
    /// Total size in bytes (cached)
    pub total_size: u64,
    
    /// Last modified timestamp
    pub last_modified: DateTime<Utc>,
}

impl BucketMetadata {
    /// Create new bucket metadata
    pub fn new(name: String, owner_id: String, root_cid: Cid) -> Self {
        let now = Utc::now();
        Self {
            name,
            created_at: now,
            owner_id,
            root_cid,
            versioning_enabled: false,
            default_storage_class: StorageClass::default(),
            tags: HashMap::new(),
            cors_config: None,
            lifecycle_rules: Vec::new(),
            object_count: 0,
            total_size: 0,
            last_modified: now,
        }
    }

    /// Update the root CID
    pub fn with_root_cid(mut self, root_cid: Cid) -> Self {
        self.root_cid = root_cid;
        self.last_modified = Utc::now();
        self
    }

    /// Enable versioning
    pub fn with_versioning(mut self) -> Self {
        self.versioning_enabled = true;
        self
    }
}

/// CORS configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CorsConfiguration {
    pub rules: Vec<CorsRule>,
}

/// CORS rule
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CorsRule {
    pub allowed_origins: Vec<String>,
    pub allowed_methods: Vec<String>,
    pub allowed_headers: Vec<String>,
    pub expose_headers: Vec<String>,
    pub max_age_seconds: Option<u32>,
}

/// Lifecycle rule
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LifecycleRule {
    pub id: String,
    pub enabled: bool,
    pub prefix: Option<String>,
    pub expiration_days: Option<u32>,
    pub transition_storage_class: Option<StorageClass>,
    pub transition_days: Option<u32>,
}

/// Owner information
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Owner {
    /// Owner ID (hashed sub claim from JWT)
    pub id: String,
    /// Display name
    pub display_name: Option<String>,
}

impl Owner {
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            display_name: None,
        }
    }

    pub fn with_display_name(mut self, name: impl Into<String>) -> Self {
        self.display_name = Some(name.into());
        self
    }
}

mod cid_serde {
    use cid::Cid;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(cid: &Cid, s: S) -> Result<S::Ok, S::Error> {
        cid.to_string().serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Cid, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

mod option_cid_serde {
    use cid::Cid;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(cid: &Option<Cid>, s: S) -> Result<S::Ok, S::Error> {
        match cid {
            Some(c) => c.to_string().serialize(s),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Cid>, D::Error> {
        let opt: Option<String> = Option::deserialize(d)?;
        match opt {
            Some(s) => s.parse().map(Some).map_err(serde::de::Error::custom),
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_object_metadata_creation() {
        let cid = fula_blockstore::cid_utils::create_cid(
            b"test",
            fula_blockstore::cid_utils::CidCodec::Raw,
        );
        let metadata = ObjectMetadata::new(cid, 100, "abc123".to_string())
            .with_content_type("application/json")
            .with_owner("user123");

        assert_eq!(metadata.size, 100);
        assert_eq!(metadata.content_type, Some("application/json".to_string()));
        assert_eq!(metadata.owner_id, Some("user123".to_string()));
    }

    #[test]
    fn test_storage_class() {
        assert_eq!(StorageClass::Standard.as_str(), "STANDARD");
        assert_eq!(StorageClass::Glacier.as_str(), "GLACIER");
    }

    #[test]
    fn test_bucket_metadata() {
        let cid = fula_blockstore::cid_utils::create_cid(
            b"root",
            fula_blockstore::cid_utils::CidCodec::DagCbor,
        );
        let bucket = BucketMetadata::new("my-bucket".to_string(), "owner123".to_string(), cid);

        assert_eq!(bucket.name, "my-bucket");
        assert!(!bucket.versioning_enabled);
    }
}
