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
    
    /// ETag (CID for single uploads, BLAKE3-hash-of-CIDs-{partCount} for multipart)
    /// Using CID as ETag is S3-compliant: AWS docs state "The ETag may or may not be an MD5 digest"
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

    /// Blinded lookup key for the per-user bucketsIndex CBOR published in
    /// Phase 3 chain snapshots. Computed client-side as
    /// `BLAKE3(MetadataKey || bucket_name)` truncated to 16 bytes (matches
    /// `hashed_user_id`'s 128-bit convention). `None` for buckets created
    /// before this field was added; populated lazily on the next forest
    /// flush via `BucketManager::populate_bucket_lookup_h`. Replace-on-change
    /// — a user reinstalling, signing in on a second device, or otherwise
    /// rotating their derivation gets the new lookup_h on their next PUT.
    /// `#[serde(default)]` makes existing `fula-bucket-registry` CBOR blocks
    /// deserialize fine without migration.
    #[serde(default)]
    pub bucket_lookup_h: Option<[u8; 16]>,

    /// **v0.4.4** — CID of the SDK's encrypted forest manifest object
    /// (`EncryptedShardManifestV7` JSON envelope), as a string.
    ///
    /// Distinct from `root_cid` (which is master's bucket Prolly Tree
    /// listing index, used by master internally and pinned for IPFS
    /// availability). The SDK's cold-start path needs THIS value, not
    /// `root_cid`, because it deserializes via `serde_json::from_slice`
    /// expecting the JSON envelope at `derive_index_key(forest_dek, bucket)`.
    ///
    /// Populated by `BucketManager::populate_forest_manifest_cid` (REPLACE
    /// semantics — every Phase 2 root commit produces a fresh CID, master
    /// must track the latest, unlike `bucket_lookup_h` which is set-once).
    /// `None` for buckets created before this field was added; lazily
    /// populated on the next forest flush from a v0.4.4+ SDK that sends
    /// the `x-amz-meta-fula-forest-manifest` sentinel header.
    /// `#[serde(default)]` makes existing CBOR blocks deserialize fine.
    #[serde(default)]
    pub forest_manifest_cid: Option<String>,
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
            bucket_lookup_h: None,
            forest_manifest_cid: None,
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

    // ============================================================
    // Phase 1.2 (master-independent reads) — bucket_lookup_h tests
    // ============================================================

    #[test]
    fn test_bucket_lookup_h_default_is_none() {
        // Newly-created BucketMetadata must have bucket_lookup_h = None.
        // The field is populated lazily on the next forest flush via the SDK header.
        let cid = fula_blockstore::cid_utils::create_cid(
            b"root",
            fula_blockstore::cid_utils::CidCodec::DagCbor,
        );
        let bucket = BucketMetadata::new("b".to_string(), "owner".to_string(), cid);
        assert_eq!(bucket.bucket_lookup_h, None);
    }

    #[test]
    fn test_bucket_lookup_h_dagcbor_roundtrip() {
        // BucketMetadata with Some(...) and None must both round-trip cleanly
        // through dag-cbor (the production registry format).
        let cid = fula_blockstore::cid_utils::create_cid(
            b"root",
            fula_blockstore::cid_utils::CidCodec::DagCbor,
        );

        // None case
        let none_bucket = BucketMetadata::new("b1".into(), "owner".into(), cid);
        let bytes = serde_ipld_dagcbor::to_vec(&none_bucket).expect("serialize None");
        let restored: BucketMetadata =
            serde_ipld_dagcbor::from_slice(&bytes).expect("deserialize None");
        assert_eq!(restored.bucket_lookup_h, None);
        assert_eq!(restored.name, "b1");

        // Some case
        let mut some_bucket = BucketMetadata::new("b2".into(), "owner".into(), cid);
        let h: [u8; 16] = [
            0xd2, 0xe4, 0xc4, 0x3d, 0xa6, 0x60, 0xe0, 0xb8,
            0x5e, 0x7b, 0x08, 0xb6, 0x98, 0x91, 0x26, 0xb3,
        ];
        some_bucket.bucket_lookup_h = Some(h);
        let bytes = serde_ipld_dagcbor::to_vec(&some_bucket).expect("serialize Some");
        let restored: BucketMetadata =
            serde_ipld_dagcbor::from_slice(&bytes).expect("deserialize Some");
        assert_eq!(restored.bucket_lookup_h, Some(h));
        assert_eq!(restored.name, "b2");
    }

    #[test]
    fn test_bucket_lookup_h_legacy_cbor_deserializes_to_none() {
        // BACKWARD-COMPAT GOLD STANDARD (Phase 1.2 hard-constraint #1):
        // existing fula-bucket-registry blocks pinned to IPFS BEFORE this
        // field was added must deserialize cleanly into the new struct,
        // with bucket_lookup_h = None. Production data must not break.
        //
        // We simulate this by defining a struct with the same shape as
        // BucketMetadata but WITHOUT the new field, serializing it via
        // dag-cbor, then deserializing as the new BucketMetadata. The
        // #[serde(default)] on the new field is what makes this work.
        #[derive(Serialize, Deserialize)]
        struct LegacyBucketMetadata {
            name: String,
            created_at: DateTime<Utc>,
            owner_id: String,
            #[serde(with = "cid_serde")]
            root_cid: Cid,
            #[serde(default)]
            versioning_enabled: bool,
            #[serde(default)]
            default_storage_class: StorageClass,
            #[serde(default)]
            tags: HashMap<String, String>,
            cors_config: Option<CorsConfiguration>,
            #[serde(default)]
            lifecycle_rules: Vec<LifecycleRule>,
            object_count: u64,
            total_size: u64,
            last_modified: DateTime<Utc>,
            // NOTE: deliberately no `bucket_lookup_h` field — this is the
            // pre-Phase-1.2 shape.
        }

        let cid = fula_blockstore::cid_utils::create_cid(
            b"root",
            fula_blockstore::cid_utils::CidCodec::DagCbor,
        );
        let now = Utc::now();
        let legacy = LegacyBucketMetadata {
            name: "videos".to_string(),
            created_at: now,
            owner_id: "9797dfb1947e5315e62c11f2ce477c28".to_string(),
            root_cid: cid,
            versioning_enabled: false,
            default_storage_class: StorageClass::default(),
            tags: HashMap::new(),
            cors_config: None,
            lifecycle_rules: Vec::new(),
            object_count: 2984,
            total_size: 764_932_382,
            last_modified: now,
        };

        let legacy_bytes =
            serde_ipld_dagcbor::to_vec(&legacy).expect("serialize legacy bucket");

        // Deserialize the legacy bytes as the NEW BucketMetadata struct.
        // This is exactly what happens at runtime when master loads a
        // pre-Phase-1.2 fula-bucket-registry block from IPFS.
        let modern: BucketMetadata =
            serde_ipld_dagcbor::from_slice(&legacy_bytes).expect("legacy → modern");

        assert_eq!(modern.name, "videos");
        assert_eq!(modern.owner_id, "9797dfb1947e5315e62c11f2ce477c28");
        assert_eq!(modern.object_count, 2984);
        assert_eq!(modern.total_size, 764_932_382);
        // The critical assertion — Phase 1.2's serde(default) preserves
        // the no-migration property for existing CBOR registries.
        assert_eq!(modern.bucket_lookup_h, None);
        // v0.4.4: same property for the new forest_manifest_cid field.
        assert_eq!(modern.forest_manifest_cid, None);
    }

    #[test]
    fn test_forest_manifest_cid_round_trip_with_lookup_h_set() {
        // v0.4.4: a fully-populated post-v0.4.4 BucketMetadata with both
        // bucket_lookup_h AND forest_manifest_cid set must round-trip
        // through dag-cbor without losing either field. This is the
        // happy-path serde test for the new field.
        let cid = fula_blockstore::cid_utils::create_cid(
            b"root",
            fula_blockstore::cid_utils::CidCodec::DagCbor,
        );
        let mut bucket = BucketMetadata::new(
            "images".into(),
            "4da2c0616b1d39660f9f94e145fbce4f".into(),
            cid,
        );
        let h: [u8; 16] = [
            0xb0, 0x7a, 0x53, 0x23, 0x57, 0xa8, 0x61, 0xb9,
            0xb6, 0x0d, 0xd6, 0x02, 0xbf, 0xe8, 0x26, 0x7a,
        ];
        bucket.bucket_lookup_h = Some(h);
        bucket.forest_manifest_cid =
            Some("bafyreihxyfxxjtsqaiyfchqh6mmvhqvlmydbf4dmtsdsvn7rqcnrs6fqnm".into());

        let bytes = serde_ipld_dagcbor::to_vec(&bucket).expect("serialize");
        let restored: BucketMetadata =
            serde_ipld_dagcbor::from_slice(&bytes).expect("deserialize");

        assert_eq!(restored.bucket_lookup_h, Some(h));
        assert_eq!(
            restored.forest_manifest_cid.as_deref(),
            Some("bafyreihxyfxxjtsqaiyfchqh6mmvhqvlmydbf4dmtsdsvn7rqcnrs6fqnm"),
        );
        assert_eq!(restored.name, "images");
    }
}
