//! Multipart upload management
//!
//! ## Issue #13 — reaper / per-user cap
//!
//! The manager runs a periodic background sweeper (`start_reaper`) that
//! drops abandoned multipart sessions whose `last_activity_at` is older
//! than `expiry_secs`. Slow legitimate uploads survive — every successful
//! `add_part` refreshes `last_activity_at`.
//!
//! ### Why we DO NOT touch the blockstore in the reaper
//!
//! The orphan chunks uploaded by `upload_part` are never pinned, but
//! `BlockStore::delete_block(cid)` is **unsafe** in a content-addressed
//! store: an "abandoned" multipart part's CID can byte-equal a block
//! reachable from a completed pinned DAG (CID dedup of identical chunks
//! across files, resumed uploads, etc.). Deleting the chunk would corrupt
//! the unrelated pinned object.
//!
//! Resolution: the reaper only cleans the in-memory `DashMap` (which is
//! the primary DoS surface — unbounded growth). Orphan blockstore chunks
//! are left to the operator's scheduled IPFS GC, which is reachability-
//! aware. Document the GC requirement in deployment notes.
//!
//! ### Per-user concurrent-upload cap
//!
//! `with_per_user_cap(N)` adds a defense-in-depth ceiling on
//! in-flight uploads per `owner_id`. `try_create_upload` returns
//! `Err(MultipartError::PerUserCapExceeded)` when a user is at the cap.
//! Slots are released by `complete_upload`, `abort_upload`, and the reaper.
//! Opportunistically, `try_create_upload` also reaps the calling user's
//! expired uploads before counting toward the cap so a malicious user
//! can't accumulate state between background sweeps.

use chrono::{DateTime, Duration, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Arc;
use tracing::{debug, info, warn};
use uuid::Uuid;

/// State of a multipart upload. The state transition is enforced
/// atomically so the reaper and `complete_upload` cannot both claim
/// the same upload (race-safe under DashMap entry locking).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MultipartState {
    /// The default state. Parts can be added; reaper may collect if
    /// `last_activity_at` is older than expiry.
    Active,
    /// `complete_upload` has claimed the upload and is assembling the
    /// final object. Reaper must not collect.
    Completing,
}

/// Errors returned by the multipart manager when an operation cannot
/// proceed without callers seeing the cause.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MultipartError {
    /// The caller's `owner_id` already has `cap` uploads in flight.
    PerUserCapExceeded {
        owner_id: String,
        cap: usize,
        current: usize,
    },
}

impl std::fmt::Display for MultipartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MultipartError::PerUserCapExceeded {
                owner_id,
                cap,
                current,
            } => write!(
                f,
                "per-user multipart cap exceeded for owner '{owner_id}': {current}/{cap} in flight",
            ),
        }
    }
}

impl std::error::Error for MultipartError {}

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
    /// Last activity (initiate, add_part). Reaper expires by THIS field,
    /// not `created_at`, so slow legitimate uploads survive.
    pub last_activity_at: DateTime<Utc>,
    /// State machine — reaper / complete coordination.
    pub state: MultipartState,
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
        let now = Utc::now();
        Self {
            upload_id: Uuid::new_v4().to_string(),
            bucket,
            key,
            owner_id,
            created_at: now,
            last_activity_at: now,
            state: MultipartState::Active,
            content_type: None,
            metadata: BTreeMap::new(),
            parts: BTreeMap::new(),
        }
    }

    /// Add a part — refreshes `last_activity_at`.
    pub fn add_part(&mut self, part: UploadPart) {
        self.parts.insert(part.part_number, part);
        self.last_activity_at = Utc::now();
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
    /// ETag (CID of part content - content-addressed identifier)
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
    /// Per-owner in-flight count (only counts `Active` and `Completing` entries).
    /// Updated atomically alongside `uploads` so the cap check stays in sync.
    per_user_count: DashMap<String, usize>,
    /// Expiry duration in seconds (last-activity-based).
    expiry_secs: u64,
    /// Per-user concurrent-multipart cap. `None` means unbounded
    /// (legacy / test-friendly default). Production sets this via
    /// `with_per_user_cap` so a single user cannot accumulate
    /// unbounded session state.
    per_user_cap: Option<usize>,
}

impl MultipartManager {
    /// Create a new manager with the configured expiry. The per-user
    /// cap defaults to `None` (unbounded); call `with_per_user_cap` to
    /// configure it.
    pub fn new(expiry_secs: u64) -> Self {
        Self {
            uploads: DashMap::new(),
            per_user_count: DashMap::new(),
            expiry_secs,
            per_user_cap: None,
        }
    }

    /// Apply a per-user concurrent-multipart cap. `try_create_upload`
    /// returns `Err(MultipartError::PerUserCapExceeded)` when a user is
    /// at this cap. Slots are released on complete / abort / reap.
    pub fn with_per_user_cap(mut self, cap: usize) -> Self {
        self.per_user_cap = Some(cap);
        self
    }

    /// Try to create a new multipart upload. Returns
    /// `Err(MultipartError::PerUserCapExceeded)` if the owner is at
    /// the cap (after opportunistically reaping any expired uploads
    /// for this owner).
    pub fn try_create_upload(
        &self,
        bucket: String,
        key: String,
        owner_id: String,
        content_type: Option<String>,
        metadata: BTreeMap<String, String>,
    ) -> Result<MultipartUpload, MultipartError> {
        // Opportunistic per-user reap: drops expired uploads for this
        // owner so a malicious user can't accumulate state between
        // background sweeps.
        self.reap_expired_for_owner(&owner_id);

        if let Some(cap) = self.per_user_cap {
            let current = self.per_user_count.get(&owner_id).map(|r| *r).unwrap_or(0);
            if current >= cap {
                return Err(MultipartError::PerUserCapExceeded {
                    owner_id,
                    cap,
                    current,
                });
            }
        }

        let mut upload = MultipartUpload::new(bucket, key, owner_id.clone());
        upload.content_type = content_type;
        upload.metadata = metadata;
        debug!(
            upload_id = %upload.upload_id,
            bucket = %upload.bucket,
            key = %upload.key,
            owner = %owner_id,
            "Creating multipart upload"
        );

        // Bump per-user counter BEFORE inserting so the cap check stays
        // consistent under racing creates.
        *self.per_user_count.entry(owner_id.clone()).or_insert(0) += 1;
        self.uploads.insert(upload.upload_id.clone(), upload.clone());
        debug!(total_uploads = self.uploads.len(), "Upload inserted into manager");
        Ok(upload)
    }

    /// Get an upload by ID
    pub fn get_upload(&self, upload_id: &str) -> Option<MultipartUpload> {
        self.uploads.get(upload_id).map(|r| r.clone())
    }

    /// Add a part to an upload. Returns `None` if the upload does not exist.
    /// Refreshes `last_activity_at` so slow uploads survive the reaper.
    pub fn add_part(&self, upload_id: &str, part: UploadPart) -> Option<()> {
        debug!(upload_id = %upload_id, part_number = part.part_number, "Adding part to upload");
        let result = self.uploads.get_mut(upload_id).map(|mut upload| {
            upload.add_part(part);
            debug!(upload_id = %upload_id, total_parts = upload.parts.len(), "Part added to upload");
        });
        if result.is_none() {
            warn!(upload_id = %upload_id, "Upload not found when adding part");
        }
        result
    }

    /// Complete an upload (atomic state transition from Active -> Completing,
    /// then remove). Returns `None` if the upload was already claimed
    /// (e.g., by the reaper) or never existed. The race-safe path:
    /// `entry().and_modify` runs under DashMap shard write-lock, so a
    /// concurrent reaper either sees `Completing` (and skips) or
    /// observes the row already removed.
    pub fn complete_upload(&self, upload_id: &str) -> Option<MultipartUpload> {
        debug!(upload_id = %upload_id, total_uploads = self.uploads.len(), "Completing multipart upload");

        // Atomically transition Active -> Completing. The reaper checks
        // `state == Active` under the same shard lock before removing.
        let claimed = match self.uploads.get_mut(upload_id) {
            Some(mut entry) => {
                if entry.state == MultipartState::Active {
                    entry.state = MultipartState::Completing;
                    true
                } else {
                    // Already Completing — duplicate complete call.
                    false
                }
            }
            None => false,
        };
        if !claimed {
            warn!(upload_id = %upload_id, "Upload not found / already claimed when completing");
            return None;
        }

        let removed = self.uploads.remove(upload_id).map(|(_, u)| u);
        if let Some(ref upload) = removed {
            self.decrement_user_count(&upload.owner_id);
            debug!(
                upload_id = %upload.upload_id,
                parts_count = upload.parts.len(),
                "Upload removed from manager"
            );
        }
        removed
    }

    /// Abort an upload (releases per-user slot).
    pub fn abort_upload(&self, upload_id: &str) -> Option<MultipartUpload> {
        let removed = self.uploads.remove(upload_id).map(|(_, u)| u);
        if let Some(ref upload) = removed {
            self.decrement_user_count(&upload.owner_id);
        }
        removed
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

    /// Reap expired uploads. Expiry is **last-activity-based** so slow
    /// legitimate uploads (long pauses between parts) survive as long
    /// as parts keep arriving. Only `Active` uploads are reaped —
    /// `Completing` uploads are mid-assembly and must not be touched.
    ///
    /// Returns the reaped sessions so callers can log / metric them.
    /// Does NOT delete blockstore chunks (see module docs).
    pub fn cleanup_expired(&self) -> Vec<MultipartUpload> {
        let threshold = Utc::now() - Duration::seconds(self.expiry_secs as i64);
        let mut reaped = Vec::new();

        // Collect candidates first (don't hold the shard lock across removal).
        let expired_ids: Vec<String> = self
            .uploads
            .iter()
            .filter(|r| r.state == MultipartState::Active && r.last_activity_at < threshold)
            .map(|r| r.upload_id.clone())
            .collect();

        for id in expired_ids {
            // Re-check state under the shard write-lock — a concurrent
            // `complete_upload` may have just transitioned to Completing.
            if let Some((_, upload)) = self.uploads.remove_if(&id, |_, u| {
                u.state == MultipartState::Active && u.last_activity_at < threshold
            }) {
                self.decrement_user_count(&upload.owner_id);
                reaped.push(upload);
            }
        }

        if !reaped.is_empty() {
            info!(
                reaped_count = reaped.len(),
                total_remaining = self.uploads.len(),
                "Reaped abandoned multipart uploads"
            );
        }
        reaped
    }

    /// Internal helper: reap only the expired uploads belonging to one
    /// owner. Used by `try_create_upload` for opportunistic cleanup.
    fn reap_expired_for_owner(&self, owner_id: &str) {
        let threshold = Utc::now() - Duration::seconds(self.expiry_secs as i64);
        let expired_ids: Vec<String> = self
            .uploads
            .iter()
            .filter(|r| {
                r.owner_id == owner_id
                    && r.state == MultipartState::Active
                    && r.last_activity_at < threshold
            })
            .map(|r| r.upload_id.clone())
            .collect();

        for id in expired_ids {
            if let Some((_, upload)) = self.uploads.remove_if(&id, |_, u| {
                u.owner_id == owner_id
                    && u.state == MultipartState::Active
                    && u.last_activity_at < threshold
            }) {
                self.decrement_user_count(&upload.owner_id);
            }
        }
    }

    fn decrement_user_count(&self, owner_id: &str) {
        if let Some(mut entry) = self.per_user_count.get_mut(owner_id) {
            if *entry > 0 {
                *entry -= 1;
            }
            if *entry == 0 {
                drop(entry);
                self.per_user_count.remove(owner_id);
            }
        }
    }

    /// Get upload count (across all users / buckets).
    pub fn upload_count(&self) -> usize {
        self.uploads.len()
    }

    /// Get in-flight upload count for a specific owner.
    pub fn user_upload_count(&self, owner_id: &str) -> usize {
        self.per_user_count.get(owner_id).map(|r| *r).unwrap_or(0)
    }

    // -------- test helpers (cfg-on for integration tests in this repo) ---

    /// Age an upload's `last_activity_at` backward by `dur` (for tests).
    #[doc(hidden)]
    pub fn test_age_last_activity(&self, upload_id: &str, dur: Duration) {
        if let Some(mut entry) = self.uploads.get_mut(upload_id) {
            entry.last_activity_at = entry.last_activity_at - dur;
        }
    }

    /// Age an upload's `created_at` backward by `dur` (for tests).
    /// `last_activity_at` is NOT touched so we can test that the reaper
    /// uses last-activity, not created-at.
    #[doc(hidden)]
    pub fn test_age_created_at(&self, upload_id: &str, dur: Duration) {
        if let Some(mut entry) = self.uploads.get_mut(upload_id) {
            entry.created_at = entry.created_at - dur;
        }
    }
}

/// Spawn a periodic background task that reaps abandoned multipart
/// uploads. Mirrors `handlers::locks::start_sweeper`. The task lives
/// for the lifetime of the process and cheaply holds an `Arc` clone
/// of the manager.
///
/// Does NOT touch the blockstore — orphan chunks are left to operator
/// IPFS GC (deletion is unsafe in a content-addressed store; see
/// module docs).
pub fn start_reaper(manager: Arc<MultipartManager>, interval_secs: u64) {
    let expiry_secs = manager.expiry_secs;
    let mgr = Arc::clone(&manager);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // Skip the first immediate tick so startup doesn't see a no-op sweep.
        interval.tick().await;
        loop {
            interval.tick().await;
            let reaped = mgr.cleanup_expired();
            if !reaped.is_empty() {
                info!(
                    reaped = reaped.len(),
                    "multipart reaper: dropped abandoned uploads"
                );
            }
        }
    });
    warn!(
        interval_secs,
        expiry_secs,
        "multipart-upload reaper started"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_multipart_upload_creation() {
        let manager = MultipartManager::new(3600);
        let upload = manager
            .try_create_upload(
                "test-bucket".to_string(),
                "test-key".to_string(),
                "user123".to_string(),
                None,
                BTreeMap::new(),
            )
            .expect("create");

        assert!(!upload.upload_id.is_empty());
        assert_eq!(upload.bucket, "test-bucket");
        assert_eq!(upload.key, "test-key");
        assert_eq!(upload.state, MultipartState::Active);
    }

    #[test]
    fn test_add_parts() {
        let manager = MultipartManager::new(3600);
        let upload = manager
            .try_create_upload(
                "bucket".to_string(),
                "key".to_string(),
                "owner".to_string(),
                None,
                BTreeMap::new(),
            )
            .unwrap();

        manager.add_part(
            &upload.upload_id,
            UploadPart::new(1, "etag1".to_string(), 1000, "cid1".to_string()),
        );
        manager.add_part(
            &upload.upload_id,
            UploadPart::new(2, "etag2".to_string(), 2000, "cid2".to_string()),
        );

        let parts = manager.list_parts(&upload.upload_id).unwrap();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0].part_number, 1);
        assert_eq!(parts[1].part_number, 2);
    }

    #[test]
    fn test_complete_upload() {
        let manager = MultipartManager::new(3600);
        let upload = manager
            .try_create_upload(
                "bucket".to_string(),
                "key".to_string(),
                "owner".to_string(),
                None,
                BTreeMap::new(),
            )
            .unwrap();
        let upload_id = upload.upload_id.clone();

        assert!(manager.get_upload(&upload_id).is_some());

        let completed = manager.complete_upload(&upload_id);
        assert!(completed.is_some());
        assert!(manager.get_upload(&upload_id).is_none());
    }

    #[test]
    fn test_list_bucket_uploads() {
        let manager = MultipartManager::new(3600);
        manager
            .try_create_upload(
                "bucket1".to_string(),
                "key1".to_string(),
                "owner".to_string(),
                None,
                BTreeMap::new(),
            )
            .unwrap();
        manager
            .try_create_upload(
                "bucket1".to_string(),
                "key2".to_string(),
                "owner".to_string(),
                None,
                BTreeMap::new(),
            )
            .unwrap();
        manager
            .try_create_upload(
                "bucket2".to_string(),
                "key3".to_string(),
                "owner".to_string(),
                None,
                BTreeMap::new(),
            )
            .unwrap();

        let bucket1_uploads = manager.list_uploads("bucket1");
        assert_eq!(bucket1_uploads.len(), 2);

        let bucket2_uploads = manager.list_uploads("bucket2");
        assert_eq!(bucket2_uploads.len(), 1);
    }

    #[test]
    fn cleanup_returns_reaped_and_decrements_user_count() {
        let manager = MultipartManager::new(1).with_per_user_cap(4);
        let u1 = manager
            .try_create_upload(
                "b".into(),
                "k1".into(),
                "u".into(),
                None,
                BTreeMap::new(),
            )
            .unwrap();
        manager.test_age_last_activity(&u1.upload_id, Duration::seconds(10));
        assert_eq!(manager.user_upload_count("u"), 1);

        let reaped = manager.cleanup_expired();
        assert_eq!(reaped.len(), 1);
        assert_eq!(reaped[0].upload_id, u1.upload_id);
        assert_eq!(manager.user_upload_count("u"), 0);
        assert_eq!(manager.upload_count(), 0);
    }
}
