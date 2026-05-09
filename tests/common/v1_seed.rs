//! Seed a v1 (monolithic `EncryptedForest`) blob into a bucket's `index_key`.
//!
//! Production is shipping from v0.2.26 (v1/v2 monolithic) directly to v7.
//! The migration code at `crates/fula-client/src/encryption.rs` fires on the
//! first load when `observed_seq.is_none()` — which is exactly the legacy
//! shape: `EncryptedForest { version: 1, sequence: None, .. }`. This helper
//! constructs that legacy blob against the same DEK a client derives, and
//! PUTs it at the deterministic `index_key` for the bucket, so the next
//! `EncryptedClient::load_forest` call sees the bucket as a v1 candidate.

use bytes::Bytes;
use fula_client::EncryptedClient;
use fula_crypto::{
    derive_dir_index_key, derive_index_key, EncryptedForest, ForestDirectoryEntry,
    ForestFileEntry, PrivateForest,
};
use std::collections::HashMap;

/// A "virtual" directory entry the caller wants replayed into the v1 forest.
///
/// The simple path+metadata shape is intentional — migration tests care about
/// preservation of path, metadata, and subtree_dek. Everything else defaults
/// to what `ForestDirectoryEntry::default` would emit.
#[derive(Clone, Debug, Default)]
pub struct SeedDir {
    pub path: String,
    pub files: Vec<String>,
    pub subdirs: Vec<String>,
    pub metadata: Option<HashMap<String, String>>,
}

/// A file entry to seed — path + storage key + plaintext size.
///
/// Does NOT upload the corresponding ciphertext object; the migration path
/// does not re-read file bodies, only the forest index. Tests that also
/// need the referenced objects to resolve should upload them separately via
/// the client's encrypted put path *after* migration completes.
#[derive(Clone, Debug)]
pub struct SeedFile {
    pub path: String,
    pub storage_key: String,
    pub size: u64,
    pub content_type: Option<String>,
    pub content_hash: Option<String>,
    pub user_metadata: HashMap<String, String>,
    /// Whether the file is flagged as "must be fetched encrypted" — i.e. the
    /// `NEW-2.1` guard applies. Seeding `true` here is what migration tests
    /// use to prove the flag survives the migration.
    pub encrypted: bool,
}

impl SeedFile {
    pub fn new(path: impl Into<String>, size: u64) -> Self {
        let path = path.into();
        Self {
            storage_key: storage_key_for_seed(&path),
            path,
            size,
            content_type: Some("application/octet-stream".to_string()),
            content_hash: None,
            user_metadata: HashMap::new(),
            encrypted: false,
        }
    }

    pub fn with_encrypted(mut self, v: bool) -> Self {
        self.encrypted = v;
        self
    }

    pub fn with_metadata(mut self, kv: &[(&str, &str)]) -> Self {
        self.user_metadata = kv
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        self
    }

    pub fn with_content_hash(mut self, h: impl Into<String>) -> Self {
        self.content_hash = Some(h.into());
        self
    }
}

/// Deterministic pseudo-storage-key for seeded entries. Uses a BLAKE3 of the
/// path so tests get stable values across runs; matches the shape (`Qm` +
/// 44 hex chars) the production code emits.
fn storage_key_for_seed(path: &str) -> String {
    let mut h = blake3::Hasher::new();
    h.update(b"seed-v1:");
    h.update(path.as_bytes());
    let out = h.finalize();
    format!("Qm{}", hex::encode(&out.as_bytes()[..22]))
}

/// Build a `PrivateForest` populated with the supplied files + directories.
/// Directories not explicitly listed are auto-filled with empty entries along
/// each file's ancestor chain.
pub fn build_v1_private_forest(files: &[SeedFile], dirs: &[SeedDir]) -> PrivateForest {
    let mut forest = PrivateForest::new();

    // Ensure every explicit dir exists first so its metadata is authoritative.
    for d in dirs {
        let entry = ForestDirectoryEntry {
            path: d.path.clone(),
            files: d.files.clone(),
            subdirs: d.subdirs.clone(),
            metadata: d.metadata.clone(),
            subtree_dek: None,
        };
        forest.directories.insert(d.path.clone(), entry);
    }

    // Auto-synthesise ancestor directories for each file so the forest
    // structure is self-consistent (mirrors v1 client behaviour).
    for f in files {
        let mut cursor = String::from("/");
        if let Some(parent) = parent_dir(&f.path) {
            let segments: Vec<&str> =
                parent.trim_start_matches('/').split('/').filter(|s| !s.is_empty()).collect();
            for seg in segments {
                let this = if cursor == "/" {
                    format!("/{}", seg)
                } else {
                    format!("{}/{}", cursor, seg)
                };
                forest
                    .directories
                    .entry(this.clone())
                    .or_insert_with(|| ForestDirectoryEntry {
                        path: this.clone(),
                        files: Vec::new(),
                        subdirs: Vec::new(),
                        metadata: None,
                        subtree_dek: None,
                    });
                cursor = this;
            }
        }

        let entry = ForestFileEntry {
            path: f.path.clone(),
            storage_key: f.storage_key.clone(),
            size: f.size,
            content_type: f.content_type.clone(),
            created_at: 0,
            modified_at: 0,
            content_hash: f.content_hash.clone(),
            user_metadata: f.user_metadata.clone(),
            encrypted: f.encrypted,
            min_version: 0,
            storage_cid: None,
        };
        forest.files.insert(f.path.clone(), entry);
    }

    forest
}

fn parent_dir(path: &str) -> Option<&str> {
    path.rfind('/').map(|i| if i == 0 { "/" } else { &path[..i] })
}

/// Seed the given `EncryptedClient`'s bucket with a legacy v1 forest blob.
///
/// Returns the ETag the server assigned to the v1 `index_key`. Tests that
/// need to simulate a concurrent writer (to force a 412 during migration)
/// can overwrite the blob after receiving this ETag and drop its match.
///
/// The caller is responsible for calling `client.create_bucket(bucket)`
/// beforehand.
pub async fn seed_v1_forest(
    client: &EncryptedClient,
    bucket: &str,
    files: &[SeedFile],
    dirs: &[SeedDir],
) -> String {
    let forest = build_v1_private_forest(files, dirs);
    let km = client.encryption_config().key_manager();
    let forest_dek = km.derive_path_key(&format!("forest:{}", bucket));
    let index_key = derive_index_key(&forest_dek, bucket);

    let enc = EncryptedForest::encrypt(&forest, &forest_dek)
        .expect("encrypt v1 forest");
    assert_eq!(enc.version, 1, "seeded forest must be v1");
    assert!(enc.sequence.is_none(), "v1 must have no sequence");

    let bytes = enc.to_bytes().expect("serialize v1 forest");
    let result = client
        .inner()
        .put_object(bucket, &index_key, Bytes::from(bytes))
        .await
        .expect("put v1 forest blob");
    result.etag
}

/// Return the deterministic v1 index-key for a bucket (lets tests check or
/// overwrite it directly).
pub fn index_key_for(client: &EncryptedClient, bucket: &str) -> String {
    let km = client.encryption_config().key_manager();
    let forest_dek = km.derive_path_key(&format!("forest:{}", bucket));
    derive_index_key(&forest_dek, bucket)
}

/// Return the deterministic F-1.3 directory-index key for a bucket. Used by
/// tests that need to overwrite or delete the dir-index blob directly to
/// exercise the rebuild-from-forest recovery path.
pub fn dir_index_key_for(client: &EncryptedClient, bucket: &str) -> String {
    let km = client.encryption_config().key_manager();
    let forest_dek = km.derive_path_key(&format!("forest:{}", bucket));
    derive_dir_index_key(&forest_dek, bucket)
}
