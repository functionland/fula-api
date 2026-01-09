//! Core FulaClient wrapper operations
//!
//! These functions wrap the underlying FulaClient for plain (unencrypted) operations.

use std::sync::Arc;
use std::time::Duration;
use bytes::Bytes;

use crate::api::types::*;
use crate::api::error::{FulaError, FulaResult};

// ============================================================================
// Client Creation
// ============================================================================

/// Create a new Fula client with the given configuration
pub fn create_client(config: FulaConfig) -> FulaResult<FulaClientHandle> {
    let inner_config = fula_client::Config::new(&config.endpoint)
        .with_timeout(Duration::from_secs(config.timeout_seconds));

    let inner_config = if let Some(token) = config.access_token {
        inner_config.with_token(token)
    } else {
        inner_config
    };

    let client = fula_client::FulaClient::new(inner_config)?;

    Ok(FulaClientHandle {
        inner: Arc::new(client),
    })
}

/// Create a new encrypted client with the given configuration
pub fn create_encrypted_client(
    config: FulaConfig,
    encryption: EncryptionConfig,
) -> FulaResult<EncryptedClientHandle> {
    let inner_config = fula_client::Config::new(&config.endpoint)
        .with_timeout(Duration::from_secs(config.timeout_seconds));

    let inner_config = if let Some(token) = config.access_token {
        inner_config.with_token(token)
    } else {
        inner_config
    };

    // Create encryption config
    let enc_config = if let Some(secret_key) = encryption.secret_key {
        if secret_key.len() != 32 {
            return Err(FulaError::InvalidConfig(
                "Secret key must be exactly 32 bytes".to_string()
            ));
        }
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&secret_key);
        let secret = fula_crypto::SecretKey::from_bytes(&key_bytes)
            .map_err(|e| FulaError::Encryption(e.to_string()))?;
        fula_client::EncryptionConfig::from_secret_key(secret)
    } else {
        fula_client::EncryptionConfig::new()
    };

    let enc_config = enc_config.with_metadata_privacy(encryption.enable_metadata_privacy);
    let enc_config = match encryption.obfuscation_mode {
        ObfuscationMode::Deterministic => {
            enc_config.with_obfuscation_mode(fula_client::KeyObfuscation::DeterministicHash)
        }
        ObfuscationMode::Random => {
            enc_config.with_obfuscation_mode(fula_client::KeyObfuscation::RandomUuid)
        }
    };

    let client = fula_client::EncryptedClient::new(inner_config, enc_config)?;

    Ok(EncryptedClientHandle {
        inner: Arc::new(parking_lot::RwLock::new(client)),
    })
}

/// Create encrypted client with pinning support
pub fn create_encrypted_client_with_pinning(
    config: FulaConfig,
    encryption: EncryptionConfig,
    pinning: PinningConfig,
) -> FulaResult<EncryptedClientHandle> {
    let inner_config = fula_client::Config::new(&config.endpoint)
        .with_timeout(Duration::from_secs(config.timeout_seconds));

    let inner_config = if let Some(token) = config.access_token {
        inner_config.with_token(token)
    } else {
        inner_config
    };

    // Create encryption config
    let enc_config = if let Some(secret_key) = encryption.secret_key {
        if secret_key.len() != 32 {
            return Err(FulaError::InvalidConfig(
                "Secret key must be exactly 32 bytes".to_string()
            ));
        }
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&secret_key);
        let secret = fula_crypto::SecretKey::from_bytes(&key_bytes)
            .map_err(|e| FulaError::Encryption(e.to_string()))?;
        fula_client::EncryptionConfig::from_secret_key(secret)
    } else {
        fula_client::EncryptionConfig::new()
    };

    let enc_config = enc_config.with_metadata_privacy(encryption.enable_metadata_privacy);

    let pinning_creds = fula_client::PinningCredentials::new(
        pinning.endpoint,
        pinning.token,
    );

    let client = fula_client::EncryptedClient::new_with_pinning(
        inner_config,
        enc_config,
        pinning_creds,
    )?;

    Ok(EncryptedClientHandle {
        inner: Arc::new(parking_lot::RwLock::new(client)),
    })
}

// ============================================================================
// Bucket Operations
// ============================================================================

/// List all buckets
pub async fn list_buckets(client: &FulaClientHandle) -> FulaResult<Vec<BucketInfo>> {
    let result = client.inner.list_buckets().await?;
    Ok(result.buckets.into_iter().map(|b| b.into()).collect())
}

/// Create a new bucket
pub async fn create_bucket(client: &FulaClientHandle, name: String) -> FulaResult<()> {
    client.inner.create_bucket(&name).await?;
    Ok(())
}

/// Delete a bucket
pub async fn delete_bucket(client: &FulaClientHandle, name: String) -> FulaResult<()> {
    client.inner.delete_bucket(&name).await?;
    Ok(())
}

/// Check if a bucket exists
pub async fn bucket_exists(client: &FulaClientHandle, name: String) -> FulaResult<bool> {
    Ok(client.inner.bucket_exists(&name).await?)
}

// ============================================================================
// Object Operations
// ============================================================================

/// Upload an object
pub async fn put_object(
    client: &FulaClientHandle,
    bucket: String,
    key: String,
    data: Vec<u8>,
) -> FulaResult<PutResult> {
    let result = client.inner.put_object(&bucket, &key, Bytes::from(data)).await?;
    Ok(result.into())
}

/// Upload an object with metadata
pub async fn put_object_with_metadata(
    client: &FulaClientHandle,
    bucket: String,
    key: String,
    data: Vec<u8>,
    metadata: ObjectMetadata,
) -> FulaResult<PutResult> {
    let result = client.inner.put_object_with_metadata(
        &bucket,
        &key,
        Bytes::from(data),
        Some(metadata.into()),
    ).await?;
    Ok(result.into())
}

/// Download an object
pub async fn get_object(
    client: &FulaClientHandle,
    bucket: String,
    key: String,
) -> FulaResult<Vec<u8>> {
    let data = client.inner.get_object(&bucket, &key).await?;
    Ok(data.to_vec())
}

/// Download an object with metadata
pub async fn get_object_with_metadata(
    client: &FulaClientHandle,
    bucket: String,
    key: String,
) -> FulaResult<GetObjectResult> {
    let result = client.inner.get_object_with_metadata(&bucket, &key).await?;
    Ok(result.into())
}

/// Get object metadata without downloading content
pub async fn head_object(
    client: &FulaClientHandle,
    bucket: String,
    key: String,
) -> FulaResult<HeadResult> {
    let result = client.inner.head_object(&bucket, &key).await?;
    Ok(result.into())
}

/// Delete an object
pub async fn delete_object(
    client: &FulaClientHandle,
    bucket: String,
    key: String,
) -> FulaResult<()> {
    client.inner.delete_object(&bucket, &key).await?;
    Ok(())
}

/// Check if an object exists
pub async fn object_exists(
    client: &FulaClientHandle,
    bucket: String,
    key: String,
) -> FulaResult<bool> {
    Ok(client.inner.object_exists(&bucket, &key).await?)
}

/// Copy an object
pub async fn copy_object(
    client: &FulaClientHandle,
    src_bucket: String,
    src_key: String,
    dst_bucket: String,
    dst_key: String,
) -> FulaResult<CopyResult> {
    let result = client.inner.copy_object(&src_bucket, &src_key, &dst_bucket, &dst_key).await?;
    Ok(result.into())
}

/// List objects in a bucket
pub async fn list_objects(
    client: &FulaClientHandle,
    bucket: String,
    options: ListOptions,
) -> FulaResult<ListObjectsResult> {
    let result = client.inner.list_objects(&bucket, Some(options.into())).await?;
    Ok(result.into())
}
