//! Multipart upload management

use chrono::{DateTime, Utc, Duration};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use uuid::Uuid;

/// Multipart upload state
#[derive(Clone, Debug)]
pub struct MultipartUpload {
    /// Upload ID
    pub upload_id: String,
    /// Bucket name
    pub bucket: String,
    /// Object key
    pub key: String,
    /// Owner ID
    pub owner_id: String,
    /// Creation time
    pub created_at: DateTime<Utc>,
    /// Content type
    pub content_type: Option<String>,
    /// User metadata
    pub metadata: BTreeMap<String, String>,
    /// Uploaded parts
    pub parts: BTreeMap<u32, UploadPart>,
}

impl MultipartUpload {
    /// Create a new multipart upload
    pub fn new(bucket: String, key: String, owner_id: String) -> Self {
        Self {
            upload_id: Uuid::new_v4().to_string(),
            bucket,
            key,
            owner_id,
            created_at: Utc::now(),
            content_type: None,
            metadata: BTreeMap::new(),
            parts: BTreeMap::new(),
        }
    }

    /// Add a part
    pub fn add_part(&mut self, part: UploadPart) {
        self.parts.insert(part.part_number, part);
    }

    /// Get all parts sorted by part number
    pub fn sorted_parts(&self) -> Vec<&UploadPart> {
        self.parts.values().collect()
    }

    /// Get total size
    pub fn total_size(&self) -> u64 {
        self.parts.values().map(|p| p.size).sum()
    }

    /// Check if complete (all parts present and in order)
    pub fn is_complete(&self, expected_parts: &[(u32, String)]) -> bool {
        for (part_num, expected_etag) in expected_parts {
            match self.parts.get(part_num) {
                Some(part) if &part.etag == expected_etag => continue,
                _ => return false,
            }
        }
        true
    }
}

/// An uploaded part
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UploadPart {
    /// Part number (1-10000)
    pub part_number: u32,
    /// ETag (MD5 hash of part content)
    pub etag: String,
    /// Part size in bytes
    pub size: u64,
    /// CID of the part data in IPFS
    pub cid: String,
    /// Upload timestamp
    pub uploaded_at: DateTime<Utc>,
    /// BLAKE3 checksum
    pub checksum_blake3: Option<String>,
}

impl UploadPart {
    /// Create a new part
    pub fn new(part_number: u32, etag: String, size: u64, cid: String) -> Self {
        Self {
            part_number,
            etag,
            size,
            cid,
            uploaded_at: Utc::now(),
            checksum_blake3: None,
        }
    }
}

/// Manager for multipart uploads
pub struct MultipartManager {
    /// Active uploads (upload_id -> MultipartUpload)
    uploads: DashMap<String, MultipartUpload>,
    /// Expiry duration in seconds
    expiry_secs: u64,
}

impl MultipartManager {
    /// Create a new manager
    pub fn new(expiry_secs: u64) -> Self {
        Self {
            uploads: DashMap::new(),
            expiry_secs,
        }
    }

    /// Create a new multipart upload
    pub fn create_upload(&self, bucket: String, key: String, owner_id: String) -> MultipartUpload {
        let upload = MultipartUpload::new(bucket, key, owner_id);
        self.uploads.insert(upload.upload_id.clone(), upload.clone());
        upload
    }

    /// Get an upload by ID
    pub fn get_upload(&self, upload_id: &str) -> Option<MultipartUpload> {
        self.uploads.get(upload_id).map(|r| r.clone())
    }

    /// Add a part to an upload
    pub fn add_part(&self, upload_id: &str, part: UploadPart) -> Option<()> {
        self.uploads.get_mut(upload_id).map(|mut upload| {
            upload.add_part(part);
        })
    }

    /// Complete an upload (remove from manager)
    pub fn complete_upload(&self, upload_id: &str) -> Option<MultipartUpload> {
        self.uploads.remove(upload_id).map(|(_, upload)| upload)
    }

    /// Abort an upload
    pub fn abort_upload(&self, upload_id: &str) -> Option<MultipartUpload> {
        self.uploads.remove(upload_id).map(|(_, upload)| upload)
    }

    /// List uploads for a bucket
    pub fn list_uploads(&self, bucket: &str) -> Vec<MultipartUpload> {
        self.uploads
            .iter()
            .filter(|r| r.bucket == bucket)
            .map(|r| r.clone())
            .collect()
    }

    /// List parts for an upload
    pub fn list_parts(&self, upload_id: &str) -> Option<Vec<UploadPart>> {
        self.uploads.get(upload_id).map(|upload| {
            upload.sorted_parts().into_iter().cloned().collect()
        })
    }

    /// Clean up expired uploads
    pub fn cleanup_expired(&self) -> usize {
        let expiry_threshold = Utc::now() - Duration::seconds(self.expiry_secs as i64);
        let expired: Vec<_> = self.uploads
            .iter()
            .filter(|r| r.created_at < expiry_threshold)
            .map(|r| r.upload_id.clone())
            .collect();
        
        let count = expired.len();
        for id in expired {
            self.uploads.remove(&id);
        }
        count
    }

    /// Get upload count
    pub fn upload_count(&self) -> usize {
        self.uploads.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_multipart_upload_creation() {
        let manager = MultipartManager::new(3600);
        let upload = manager.create_upload(
            "test-bucket".to_string(),
            "test-key".to_string(),
            "user123".to_string(),
        );

        assert!(!upload.upload_id.is_empty());
        assert_eq!(upload.bucket, "test-bucket");
        assert_eq!(upload.key, "test-key");
    }

    #[test]
    fn test_add_parts() {
        let manager = MultipartManager::new(3600);
        let upload = manager.create_upload(
            "bucket".to_string(),
            "key".to_string(),
            "owner".to_string(),
        );

        manager.add_part(&upload.upload_id, UploadPart::new(1, "etag1".to_string(), 1000, "cid1".to_string()));
        manager.add_part(&upload.upload_id, UploadPart::new(2, "etag2".to_string(), 2000, "cid2".to_string()));

        let parts = manager.list_parts(&upload.upload_id).unwrap();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0].part_number, 1);
        assert_eq!(parts[1].part_number, 2);
    }

    #[test]
    fn test_complete_upload() {
        let manager = MultipartManager::new(3600);
        let upload = manager.create_upload(
            "bucket".to_string(),
            "key".to_string(),
            "owner".to_string(),
        );
        let upload_id = upload.upload_id.clone();

        assert!(manager.get_upload(&upload_id).is_some());
        
        let completed = manager.complete_upload(&upload_id);
        assert!(completed.is_some());
        assert!(manager.get_upload(&upload_id).is_none());
    }

    #[test]
    fn test_list_bucket_uploads() {
        let manager = MultipartManager::new(3600);
        manager.create_upload("bucket1".to_string(), "key1".to_string(), "owner".to_string());
        manager.create_upload("bucket1".to_string(), "key2".to_string(), "owner".to_string());
        manager.create_upload("bucket2".to_string(), "key3".to_string(), "owner".to_string());

        let bucket1_uploads = manager.list_uploads("bucket1");
        assert_eq!(bucket1_uploads.len(), 2);

        let bucket2_uploads = manager.list_uploads("bucket2");
        assert_eq!(bucket2_uploads.len(), 1);
    }
}
