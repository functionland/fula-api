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

/// Derive X25519 public key from private key bytes
///
/// **IMPORTANT**: Use this function instead of Dart's X25519 public key derivation
/// to ensure compatibility between Flutter and Web/WASM clients.
///
/// This ensures that both FxFiles and Web UI derive the exact same public key
/// from the same private key bytes, avoiding cryptographic mismatches.
///
/// # Arguments
/// * `secret_key_bytes` - 32-byte X25519 private key (raw bytes, not clamped)
///
/// # Returns
/// * `Ok(Vec<u8>)` - 32-byte X25519 public key
/// * `Err` - If secret_key_bytes is not exactly 32 bytes
///
/// # Example
/// ```dart
/// // In Flutter/Dart, generate random 32 bytes:
/// final secretKeyBytes = Uint8List(32);
/// Random.secure().nextBytes(secretKeyBytes);
///
/// // Derive public key using Rust (ensures cross-platform compatibility):
/// final publicKeyBytes = await derivePublicKeyFromSecret(secretKeyBytes);
///
/// // Now use publicKeyBytes for createShareToken
/// // and secretKeyBytes in the share URL
/// ```
pub fn derive_public_key_from_secret(secret_key_bytes: Vec<u8>) -> anyhow::Result<Vec<u8>> {
    if secret_key_bytes.len() != 32 {
        anyhow::bail!("Secret key must be exactly 32 bytes, got {}", secret_key_bytes.len());
    }

    let mut arr = [0u8; 32];
    arr.copy_from_slice(&secret_key_bytes);

    let secret = fula_crypto::SecretKey::from_bytes(&arr)
        .map_err(|e| anyhow::anyhow!("Invalid secret key: {}", e))?;
    let public = secret.public_key();

    Ok(public.as_bytes().to_vec())
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
