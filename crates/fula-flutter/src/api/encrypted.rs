//! Encrypted client operations
//!
//! These functions wrap EncryptedClient for client-side encrypted storage.

use bytes::Bytes;

use crate::api::types::*;

// ============================================================================
// Basic Encrypted Operations
// ============================================================================

/// Upload an encrypted object
pub async fn put_encrypted(
    client: &EncryptedClientHandle,
    bucket: String,
    key: String,
    data: Vec<u8>,
) -> anyhow::Result<PutResult> {
    let guard = client.inner.read().await;
    let result = guard.put_object_encrypted(&bucket, &key, Bytes::from(data)).await?;
    Ok(result.into())
}

/// Upload an encrypted object with specific content type
pub async fn put_encrypted_with_type(
    client: &EncryptedClientHandle,
    bucket: String,
    key: String,
    data: Vec<u8>,
    content_type: String,
) -> anyhow::Result<PutResult> {
    let guard = client.inner.read().await;
    let result = guard.put_object_encrypted_with_type(
        &bucket,
        &key,
        Bytes::from(data),
        Some(&content_type),
    ).await?;
    Ok(result.into())
}

/// Download and decrypt an object by original key
pub async fn get_decrypted(
    client: &EncryptedClientHandle,
    bucket: String,
    key: String,
) -> anyhow::Result<Vec<u8>> {
    let guard = client.inner.read().await;
    let data = guard.get_object_decrypted(&bucket, &key).await?;
    Ok(data.to_vec())
}

/// Download and decrypt an object by storage key
pub async fn get_decrypted_by_storage_key(
    client: &EncryptedClientHandle,
    bucket: String,
    storage_key: String,
) -> anyhow::Result<Vec<u8>> {
    let guard = client.inner.read().await;
    let data = guard.get_object_decrypted_by_storage_key(&bucket, &storage_key).await?;
    Ok(data.to_vec())
}

/// Download and decrypt with full metadata
pub async fn get_with_private_metadata(
    client: &EncryptedClientHandle,
    bucket: String,
    storage_key: String,
) -> anyhow::Result<DecryptedObjectInfo> {
    let guard = client.inner.read().await;
    let result = guard.get_object_with_private_metadata(&bucket, &storage_key).await?;
    Ok(result.into())
}

/// Delete an encrypted object by original key
pub async fn delete_encrypted(
    client: &EncryptedClientHandle,
    bucket: String,
    key: String,
) -> anyhow::Result<()> {
    let guard = client.inner.read().await;
    guard.delete_object(&bucket, &key).await?;
    Ok(())
}

/// Delete an encrypted object by storage key
pub async fn delete_by_storage_key(
    client: &EncryptedClientHandle,
    bucket: String,
    storage_key: String,
) -> anyhow::Result<()> {
    let guard = client.inner.read().await;
    guard.delete_object_by_storage_key(&bucket, &storage_key).await?;
    Ok(())
}

// ============================================================================
// Metadata-Only Operations
// ============================================================================

/// Get decrypted metadata without downloading content
pub async fn head_decrypted(
    client: &EncryptedClientHandle,
    bucket: String,
    storage_key: String,
) -> anyhow::Result<FileMetadata> {
    let guard = client.inner.read().await;
    let result = guard.head_object_decrypted(&bucket, &storage_key).await?;
    Ok(result.into())
}

/// List objects with decrypted metadata
pub async fn list_decrypted(
    client: &EncryptedClientHandle,
    bucket: String,
    options: ListOptions,
) -> anyhow::Result<Vec<FileMetadata>> {
    let guard = client.inner.read().await;
    let result = guard.list_objects_decrypted(&bucket, Some(options.into())).await?;
    Ok(result.into_iter().map(|m| m.into()).collect())
}

/// List directory structure
pub async fn list_directory(
    client: &EncryptedClientHandle,
    bucket: String,
    prefix: Option<String>,
) -> anyhow::Result<DirectoryListing> {
    let guard = client.inner.read().await;
    let result = guard.list_directory(&bucket, prefix.as_deref()).await?;

    // Convert the internal DirectoryListing to our type
    let entries: Vec<DirectoryEntry> = result.directories
        .into_iter()
        .map(|(name, files)| DirectoryEntry {
            name,
            is_directory: true,
            files: files.into_iter().map(|f| f.into()).collect(),
        })
        .collect();

    Ok(DirectoryListing {
        bucket: result.bucket,
        prefix: result.prefix,
        entries,
    })
}

// ============================================================================
// Key Management
// ============================================================================

/// Export the secret key for backup
pub async fn export_secret_key(client: &EncryptedClientHandle) -> Vec<u8> {
    let guard = client.inner.read().await;
    guard.encryption_config().export_secret_key().as_bytes().to_vec()
}

/// Get the public key for sharing
pub async fn get_public_key(client: &EncryptedClientHandle) -> Vec<u8> {
    let guard = client.inner.read().await;
    guard.encryption_config().public_key().as_bytes().to_vec()
}

/// Check if client uses FlatNamespace mode
pub async fn is_flat_namespace(client: &EncryptedClientHandle) -> bool {
    let guard = client.inner.read().await;
    guard.is_flat_namespace()
}

// ============================================================================
// Bucket Operations (delegated)
// ============================================================================

/// List buckets (delegated to inner client)
pub async fn enc_list_buckets(client: &EncryptedClientHandle) -> anyhow::Result<Vec<BucketInfo>> {
    let guard = client.inner.read().await;
    let result = guard.list_buckets().await?;
    Ok(result.buckets.into_iter().map(|b| b.into()).collect())
}

/// Create bucket (delegated to inner client)
pub async fn enc_create_bucket(client: &EncryptedClientHandle, name: String) -> anyhow::Result<()> {
    let guard = client.inner.read().await;
    guard.create_bucket(&name).await?;
    Ok(())
}

/// Delete bucket (delegated to inner client)
pub async fn enc_delete_bucket(client: &EncryptedClientHandle, name: String) -> anyhow::Result<()> {
    let guard = client.inner.read().await;
    guard.delete_bucket(&name).await?;
    Ok(())
}
