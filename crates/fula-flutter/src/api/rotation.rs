//! Key rotation operations
//!
//! Functions for rotating encryption keys to maintain security.
//! Key rotation re-wraps data encryption keys with a new key encryption key.

use std::sync::Arc;

use crate::api::types::*;

// ============================================================================
// Rotation Manager
// ============================================================================

/// Create a new key rotation manager
///
/// The rotation manager handles the key rotation process,
/// including tracking which keys have been rotated.
pub async fn create_rotation_manager(client: &EncryptedClientHandle) -> RotationManagerHandle {
    let guard = &*client.inner;
    let manager = guard.create_rotation_manager();
    RotationManagerHandle {
        inner: Arc::new(manager),
    }
}

// ============================================================================
// Rotation Operations
// ============================================================================

/// Get the KEK (Key Encryption Key) version used for an object
///
/// Returns None if the object doesn't have version metadata.
pub async fn get_kek_version(
    client: &EncryptedClientHandle,
    bucket: String,
    storage_key: String,
) -> anyhow::Result<Option<u32>> {
    let guard = &*client.inner;
    let version = guard.get_object_kek_version(&bucket, &storage_key).await?;
    Ok(version)
}

/// Re-wrap a single object's DEK with the current KEK
///
/// Returns the new KEK version.
///
/// # KNOWN RACE (introduced 2026-08-23, tracked — read before extending)
///
/// `rewrap_object_dek` is a GET-modify-PUT of the object's encryption
/// metadata plus a forest mutation, and it takes **no** per-bucket lock —
/// unlike `put_object_flat` / `flush_forest` / `delete_object_flat`, which
/// all take `bucket_write_mutex`. Until this handle became a bare `Arc`,
/// the bridge's coarse `RwLock` serialised rotation against uploads by
/// accident. It no longer does.
///
/// The exposure is TOCTOU: if an upload modifies the object between
/// rotation's GET and its PUT, the PUT overwrites the newly-uploaded data
/// with the re-encrypted OLD data.
///
/// Deliberately NOT "fixed" by taking `bucket_write_mutex` here:
/// `rotate_bucket_inner` drives this through `buffer_unordered(
/// MAX_CONCURRENT_REWRAPS)`, so a per-bucket lock would serialise a
/// deliberately-parallel operation — a fix that looks right and quietly
/// destroys rotation throughput. A per-OBJECT lock would not help either
/// unless the upload paths took the same one (they hold only the
/// per-bucket mutex).
///
/// The correct fix is optimistic concurrency: send the GET's ETag as
/// `If-Match` on the rewrap PUT so a concurrent upload makes the PUT fail
/// and the object is simply re-rotated. That belongs in
/// `fula-client::rewrap_object_dek`, not here.
///
/// Why it is acceptable to ship meanwhile: key rotation has no call site
/// in FxFiles (the Dart wrappers exist but nothing invokes them), and the
/// window requires a rotation and an upload of the SAME object to overlap.
pub async fn rewrap_object(
    client: &EncryptedClientHandle,
    bucket: String,
    storage_key: String,
    manager: &RotationManagerHandle,
) -> anyhow::Result<u32> {
    let guard = &*client.inner;
    let version = guard.rewrap_object_dek(&bucket, &storage_key, &manager.inner).await?;
    Ok(version)
}

/// Rotate all objects in a bucket
///
/// This re-wraps the DEK for every object in the bucket.
/// Returns a report with success/failure counts.
pub async fn rotate_bucket(
    client: &EncryptedClientHandle,
    bucket: String,
    manager: &RotationManagerHandle,
) -> anyhow::Result<RotationReport> {
    let guard = &*client.inner;
    let report = guard.rotate_bucket(&bucket, &manager.inner).await?;

    // Manual conversion since fula_client::encryption::RotationReport is not exported
    Ok(RotationReport {
        total: report.total as u32,
        rotated: report.rotated as u32,
        skipped: report.skipped as u32,
        failed: report.failed as u32,
        failures: report.failures.into_iter()
            .map(|(k, e)| RotationFailure { storage_key: k, error: e })
            .collect(),
    })
}

// ============================================================================
// Report Helpers
// ============================================================================

impl RotationReport {
    /// Check if all rotations succeeded
    pub async fn is_success(&self) -> bool {
        self.failed == 0
    }

    /// Get success rate as percentage
    pub async fn success_rate(&self) -> f64 {
        if self.total == 0 {
            100.0
        } else {
            ((self.rotated + self.skipped) as f64 / self.total as f64) * 100.0
        }
    }
}
