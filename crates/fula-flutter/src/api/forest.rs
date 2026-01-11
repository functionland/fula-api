//! Forest/FlatNamespace operations
//!
//! These functions manage the encrypted file index (PrivateForest)
//! for organized file storage with human-readable paths.

use bytes::Bytes;
use anyhow::Context;

use crate::api::types::*;

// ============================================================================
// Forest Management
// ============================================================================

/// Load the forest index from storage
pub async fn load_forest(
    client: &EncryptedClientHandle,
    bucket: String,
) -> anyhow::Result<()> {
    let guard = client.inner.write().await;
    guard.load_forest(&bucket).await?;
    Ok(())
}

/// Save the forest index to storage
///
/// This is an alias for flush_forest. It saves any pending changes
/// in the forest cache to storage.
pub async fn save_forest(
    client: &EncryptedClientHandle,
    bucket: String,
) -> anyhow::Result<()> {
    let guard = client.inner.read().await;
    guard.flush_forest(&bucket).await?;
    Ok(())
}

/// Flush any pending forest changes to storage
pub async fn flush_forest(
    client: &EncryptedClientHandle,
    bucket: String,
) -> anyhow::Result<()> {
    let guard = client.inner.write().await;
    guard.flush_forest(&bucket).await?;
    Ok(())
}

/// Check if there are pending (unsaved) forest changes
pub async fn has_pending_changes(client: &EncryptedClientHandle, bucket: String) -> bool {
    let guard = client.inner.read().await;
    guard.has_pending_forest_changes(&bucket)
}

// ============================================================================
// Flat Namespace Operations
// ============================================================================

/// Upload a file with immediate forest save
///
/// This is the recommended method for most use cases.
/// The file path is preserved in the encrypted forest index.
pub async fn put_flat(
    client: &EncryptedClientHandle,
    bucket: String,
    path: String,
    data: Vec<u8>,
    content_type: Option<String>,
) -> anyhow::Result<PutResult> {
    let guard = client.inner.write().await;
    let result = guard.put_object_flat(
        &bucket,
        &path,
        Bytes::from(data),
        content_type.as_deref(),
    ).await?;
    Ok(result.into())
}

/// Upload a file without immediate forest save (deferred)
///
/// Use this for batch uploads, then call `flush_forest` when done.
/// More efficient for uploading many files at once.
pub async fn put_flat_deferred(
    client: &EncryptedClientHandle,
    bucket: String,
    path: String,
    data: Vec<u8>,
    content_type: Option<String>,
) -> anyhow::Result<PutResult> {
    let guard = client.inner.write().await;
    let result = guard.put_object_flat_deferred(
        &bucket,
        &path,
        Bytes::from(data),
        content_type.as_deref(),
    ).await?;
    Ok(result.into())
}

/// Download a file by its path
pub async fn get_flat(
    client: &EncryptedClientHandle,
    bucket: String,
    path: String,
) -> anyhow::Result<Vec<u8>> {
    let guard = client.inner.read().await;
    let data = guard.get_object_flat(&bucket, &path).await?;
    Ok(data.to_vec())
}

/// Delete a file by its path
pub async fn delete_flat(
    client: &EncryptedClientHandle,
    bucket: String,
    path: String,
) -> anyhow::Result<()> {
    let guard = client.inner.write().await;
    guard.delete_object_flat(&bucket, &path).await?;
    Ok(())
}

/// List all files from the forest index (no network calls)
///
/// This reads from the local forest index, which is faster
/// than listing from the server.
pub async fn list_from_forest(
    client: &EncryptedClientHandle,
    bucket: String,
) -> anyhow::Result<Vec<FileMetadata>> {
    let guard = client.inner.read().await;
    let result = guard.list_files_from_forest(&bucket).await?;
    Ok(result.into_iter().map(|m| m.into()).collect())
}

// ============================================================================
// Subtree Operations (for Sharing)
// ============================================================================

/// Extract a subtree from the forest for sharing
///
/// This creates a serialized subtree that can be shared with others.
/// The subtree includes all files under the given prefix.
pub async fn get_forest_subtree(
    client: &EncryptedClientHandle,
    bucket: String,
    prefix: String,
) -> anyhow::Result<ForestSubtree> {
    let guard = client.inner.read().await;
    let subtree = guard.get_forest_subtree(&bucket, &prefix).await?;

    // Serialize the subtree
    let serialized = serde_json::to_vec(&subtree)
        .context("Failed to serialize subtree")?;

    Ok(ForestSubtree { serialized })
}
