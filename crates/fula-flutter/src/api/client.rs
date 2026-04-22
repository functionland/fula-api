//! Core FulaClient wrapper operations
//!
//! These functions wrap the underlying FulaClient for plain (unencrypted) operations.

use std::sync::Arc;
use std::time::Duration;
use bytes::Bytes;
use anyhow::Context;

// Use tokio::sync on native, async_lock on WASM
#[cfg(not(target_arch = "wasm32"))]
use tokio::sync::RwLock;
#[cfg(target_arch = "wasm32")]
use async_lock::RwLock;

use crate::api::types::*;

// ============================================================================
// Client Creation
// ============================================================================

/// Create a new Fula client with the given configuration
pub fn create_client(config: FulaConfig) -> anyhow::Result<FulaClientHandle> {
    let mut inner_config = fula_client::Config::new(&config.endpoint)
        .with_timeout(Duration::from_secs(config.timeout_seconds));
    inner_config.per_chunk_download_timeout =
        Duration::from_secs(config.per_chunk_download_timeout_seconds);
    inner_config.buffered_download_max_bytes = config.buffered_download_max_bytes;

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
) -> anyhow::Result<EncryptedClientHandle> {
    let mut inner_config = fula_client::Config::new(&config.endpoint)
        .with_timeout(Duration::from_secs(config.timeout_seconds));
    inner_config.per_chunk_download_timeout =
        Duration::from_secs(config.per_chunk_download_timeout_seconds);
    inner_config.buffered_download_max_bytes = config.buffered_download_max_bytes;

    let inner_config = if let Some(token) = config.access_token {
        inner_config.with_token(token)
    } else {
        inner_config
    };

    // Create encryption config
    let enc_config = if let Some(secret_key) = encryption.secret_key {
        if secret_key.len() != 32 {
            anyhow::bail!("Secret key must be exactly 32 bytes");
        }
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&secret_key);
        let secret = fula_crypto::SecretKey::from_bytes(&key_bytes)
            .context("Encryption error")?;
        fula_client::EncryptionConfig::from_secret_key(secret)
    } else {
        fula_client::EncryptionConfig::new()
    };

    let enc_config = enc_config.with_metadata_privacy(encryption.enable_metadata_privacy);
    #[allow(deprecated)]
    let enc_config = match encryption.obfuscation_mode {
        ObfuscationMode::Deterministic => {
            enc_config.with_obfuscation_mode(fula_client::KeyObfuscation::DeterministicHash)
        }
        ObfuscationMode::Random => {
            enc_config.with_obfuscation_mode(fula_client::KeyObfuscation::RandomUuid)
        }
        ObfuscationMode::FlatNamespace => {
            enc_config.with_obfuscation_mode(fula_client::KeyObfuscation::FlatNamespace)
        }
        ObfuscationMode::PreserveStructure => {
            enc_config.with_obfuscation_mode(fula_client::KeyObfuscation::PreserveStructure)
        }
    };

    let client = fula_client::EncryptedClient::new(inner_config, enc_config)?;

    Ok(EncryptedClientHandle {
        inner: Arc::new(RwLock::new(client)),
    })
}

/// Create encrypted client with pinning support
pub fn create_encrypted_client_with_pinning(
    config: FulaConfig,
    encryption: EncryptionConfig,
    pinning: PinningConfig,
) -> anyhow::Result<EncryptedClientHandle> {
    let mut inner_config = fula_client::Config::new(&config.endpoint)
        .with_timeout(Duration::from_secs(config.timeout_seconds));
    inner_config.per_chunk_download_timeout =
        Duration::from_secs(config.per_chunk_download_timeout_seconds);
    inner_config.buffered_download_max_bytes = config.buffered_download_max_bytes;

    let inner_config = if let Some(token) = config.access_token {
        inner_config.with_token(token)
    } else {
        inner_config
    };

    // Create encryption config
    let enc_config = if let Some(secret_key) = encryption.secret_key {
        if secret_key.len() != 32 {
            anyhow::bail!("Secret key must be exactly 32 bytes");
        }
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&secret_key);
        let secret = fula_crypto::SecretKey::from_bytes(&key_bytes)
            .context("Encryption error")?;
        fula_client::EncryptionConfig::from_secret_key(secret)
    } else {
        fula_client::EncryptionConfig::new()
    };

    let enc_config = enc_config.with_metadata_privacy(encryption.enable_metadata_privacy);
    #[allow(deprecated)]
    let enc_config = match encryption.obfuscation_mode {
        ObfuscationMode::Deterministic => {
            enc_config.with_obfuscation_mode(fula_client::KeyObfuscation::DeterministicHash)
        }
        ObfuscationMode::Random => {
            enc_config.with_obfuscation_mode(fula_client::KeyObfuscation::RandomUuid)
        }
        ObfuscationMode::FlatNamespace => {
            enc_config.with_obfuscation_mode(fula_client::KeyObfuscation::FlatNamespace)
        }
        ObfuscationMode::PreserveStructure => {
            enc_config.with_obfuscation_mode(fula_client::KeyObfuscation::PreserveStructure)
        }
    };

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
        inner: Arc::new(RwLock::new(client)),
    })
}

// ============================================================================
// Bucket Operations
// ============================================================================

/// List all buckets
pub async fn list_buckets(client: &FulaClientHandle) -> anyhow::Result<Vec<BucketInfo>> {
    let result = client.inner.list_buckets().await?;
    Ok(result.buckets.into_iter().map(|b| b.into()).collect())
}

/// Create a new bucket
pub async fn create_bucket(client: &FulaClientHandle, name: String) -> anyhow::Result<()> {
    client.inner.create_bucket(&name).await?;
    Ok(())
}

/// Delete a bucket
pub async fn delete_bucket(client: &FulaClientHandle, name: String) -> anyhow::Result<()> {
    client.inner.delete_bucket(&name).await?;
    Ok(())
}

/// Check if a bucket exists
pub async fn bucket_exists(client: &FulaClientHandle, name: String) -> anyhow::Result<bool> {
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
) -> anyhow::Result<PutResult> {
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
) -> anyhow::Result<PutResult> {
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
) -> anyhow::Result<Vec<u8>> {
    let data = client.inner.get_object(&bucket, &key).await?;
    Ok(data.to_vec())
}

/// Download an object with metadata
pub async fn get_object_with_metadata(
    client: &FulaClientHandle,
    bucket: String,
    key: String,
) -> anyhow::Result<GetObjectResult> {
    let result = client.inner.get_object_with_metadata(&bucket, &key).await?;
    Ok(result.into())
}

/// Get object metadata without downloading content
pub async fn head_object(
    client: &FulaClientHandle,
    bucket: String,
    key: String,
) -> anyhow::Result<HeadResult> {
    let result = client.inner.head_object(&bucket, &key).await?;
    Ok(result.into())
}

/// Delete an object
pub async fn delete_object(
    client: &FulaClientHandle,
    bucket: String,
    key: String,
) -> anyhow::Result<()> {
    client.inner.delete_object(&bucket, &key).await?;
    Ok(())
}

/// Check if an object exists
pub async fn object_exists(
    client: &FulaClientHandle,
    bucket: String,
    key: String,
) -> anyhow::Result<bool> {
    Ok(client.inner.object_exists(&bucket, &key).await?)
}

/// Copy an object
pub async fn copy_object(
    client: &FulaClientHandle,
    src_bucket: String,
    src_key: String,
    dst_bucket: String,
    dst_key: String,
) -> anyhow::Result<CopyResult> {
    let result = client.inner.copy_object(&src_bucket, &src_key, &dst_bucket, &dst_key).await?;
    Ok(result.into())
}

/// List objects in a bucket
pub async fn list_objects(
    client: &FulaClientHandle,
    bucket: String,
    options: ListOptions,
) -> anyhow::Result<ListObjectsResult> {
    let result = client.inner.list_objects(&bucket, Some(options.into())).await?;
    Ok(result.into())
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use super::*;

    #[test]
    fn fula_config_roundtrip_plumbs_f8_f10_fields() {
        let cfg = FulaConfig {
            endpoint: "http://localhost:9000".into(),
            access_token: None,
            timeout_seconds: 30,
            max_retries: 3,
            per_chunk_download_timeout_seconds: 120,
            buffered_download_max_bytes: 64 * 1024 * 1024,
        };
        let handle = create_client(cfg).expect("create_client should succeed");
        let inner_cfg = handle.inner.config();
        assert_eq!(
            inner_cfg.per_chunk_download_timeout,
            Duration::from_secs(120),
            "FulaConfig::per_chunk_download_timeout_seconds must plumb into fula_client::Config::per_chunk_download_timeout",
        );
        assert_eq!(
            inner_cfg.buffered_download_max_bytes,
            64 * 1024 * 1024,
            "FulaConfig::buffered_download_max_bytes must plumb into fula_client::Config::buffered_download_max_bytes",
        );
    }

    #[test]
    fn fula_config_default_plumbs_audit_defaults() {
        let cfg = FulaConfig::default();
        let handle = create_client(cfg).expect("create_client should succeed");
        let inner_cfg = handle.inner.config();
        assert_eq!(
            inner_cfg.per_chunk_download_timeout,
            Duration::from_secs(300),
        );
        assert_eq!(
            inner_cfg.buffered_download_max_bytes,
            256 * 1024 * 1024,
        );
    }
}
