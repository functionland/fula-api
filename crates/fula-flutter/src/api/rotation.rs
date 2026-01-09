//! Key rotation operations
//!
//! Functions for rotating encryption keys to maintain security.
//! Key rotation re-wraps data encryption keys with a new key encryption key.

use std::sync::Arc;

use crate::api::types::*;
use crate::api::error::FulaResult;

// ============================================================================
// Rotation Manager
// ============================================================================

/// Create a new key rotation manager
///
/// The rotation manager handles the key rotation process,
/// including tracking which keys have been rotated.
pub fn create_rotation_manager(client: &EncryptedClientHandle) -> RotationManagerHandle {
    let guard = client.inner.read();
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
) -> FulaResult<Option<u32>> {
    let guard = client.inner.read();
    let version = guard.get_object_kek_version(&bucket, &storage_key).await?;
    Ok(version)
}

/// Re-wrap a single object's DEK with the current KEK
///
/// Returns the new KEK version.
pub async fn rewrap_object(
    client: &EncryptedClientHandle,
    bucket: String,
    storage_key: String,
    manager: &RotationManagerHandle,
) -> FulaResult<u32> {
    let guard = client.inner.write();
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
) -> FulaResult<RotationReport> {
    let guard = client.inner.read();
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
    pub fn is_success(&self) -> bool {
        self.failed == 0
    }

    /// Get success rate as percentage
    pub fn success_rate(&self) -> f64 {
        if self.total == 0 {
            100.0
        } else {
            ((self.rotated + self.skipped) as f64 / self.total as f64) * 100.0
        }
    }
}
