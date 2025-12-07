//! Client-side encryption support

use crate::{ClientError, FulaClient, Result, Config};
use crate::types::*;
use bytes::Bytes;
use fula_crypto::{
    keys::{KeyManager},
    hpke::{Encryptor, Decryptor, EncryptedData},
    symmetric::{Aead, Nonce},
};
use std::sync::Arc;

/// Configuration for client-side encryption
pub struct EncryptionConfig {
    /// Key manager for encryption keys (wrapped in Arc for sharing)
    key_manager: Arc<KeyManager>,
}

impl EncryptionConfig {
    /// Create with a new random key
    pub fn new() -> Self {
        Self {
            key_manager: Arc::new(KeyManager::new()),
        }
    }

    /// Create from an existing secret key
    pub fn from_secret_key(secret: fula_crypto::keys::SecretKey) -> Self {
        Self {
            key_manager: Arc::new(KeyManager::from_secret_key(secret)),
        }
    }

    /// Get the public key for sharing
    pub fn public_key(&self) -> &fula_crypto::keys::PublicKey {
        self.key_manager.public_key()
    }

    /// Export the secret key (handle with care!)
    pub fn export_secret_key(&self) -> &fula_crypto::keys::SecretKey {
        self.key_manager.keypair().secret_key()
    }
}

impl Default for EncryptionConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// Client with client-side encryption enabled
pub struct EncryptedClient {
    inner: FulaClient,
    encryption: EncryptionConfig,
}

impl EncryptedClient {
    /// Create a new encrypted client
    pub fn new(config: Config, encryption: EncryptionConfig) -> Result<Self> {
        let inner = FulaClient::new(config)?;
        Ok(Self { inner, encryption })
    }

    /// Get the underlying client
    pub fn inner(&self) -> &FulaClient {
        &self.inner
    }

    /// Get the encryption config
    pub fn encryption_config(&self) -> &EncryptionConfig {
        &self.encryption
    }

    /// Put an encrypted object
    pub async fn put_object_encrypted(
        &self,
        bucket: &str,
        key: &str,
        data: impl Into<Bytes>,
    ) -> Result<PutObjectResult> {
        let data = data.into();
        
        // Generate a DEK for this object
        let dek = self.encryption.key_manager.generate_dek();
        
        // Encrypt the data with the DEK
        let nonce = Nonce::generate();
        let aead = Aead::new_default(&dek);
        let ciphertext = aead.encrypt(&nonce, &data)
            .map_err(ClientError::Encryption)?;

        // Encrypt the DEK with HPKE for the owner
        let encryptor = Encryptor::new(self.encryption.public_key());
        let wrapped_dek = encryptor.encrypt_dek(&dek)
            .map_err(ClientError::Encryption)?;

        // Serialize encryption metadata
        let enc_metadata = serde_json::json!({
            "version": 1,
            "algorithm": "AES-256-GCM",
            "nonce": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, nonce.as_bytes()),
            "wrapped_key": serde_json::to_value(&wrapped_dek).unwrap(),
        });

        // Upload with encryption metadata
        let metadata = ObjectMetadata::new()
            .with_content_type("application/octet-stream")
            .with_metadata("x-fula-encrypted", "true")
            .with_metadata("x-fula-encryption", &enc_metadata.to_string());

        self.inner.put_object_with_metadata(
            bucket,
            key,
            Bytes::from(ciphertext),
            Some(metadata),
        ).await
    }

    /// Get and decrypt an object
    pub async fn get_object_decrypted(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<Bytes> {
        let result = self.inner.get_object_with_metadata(bucket, key).await?;
        
        // Check if object is encrypted
        let is_encrypted = result.metadata
            .get("x-fula-encrypted")
            .map(|v| v == "true")
            .unwrap_or(false);

        if !is_encrypted {
            return Ok(result.data);
        }

        // Parse encryption metadata
        let enc_metadata_str = result.metadata
            .get("x-fula-encryption")
            .ok_or_else(|| ClientError::Encryption(
                fula_crypto::CryptoError::Decryption("Missing encryption metadata".to_string())
            ))?;

        let enc_metadata: serde_json::Value = serde_json::from_str(enc_metadata_str)
            .map_err(|e| ClientError::Encryption(
                fula_crypto::CryptoError::Decryption(e.to_string())
            ))?;

        // Extract nonce
        let nonce_b64 = enc_metadata["nonce"].as_str()
            .ok_or_else(|| ClientError::Encryption(
                fula_crypto::CryptoError::Decryption("Missing nonce".to_string())
            ))?;
        let nonce_bytes = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            nonce_b64,
        ).map_err(|e| ClientError::Encryption(
            fula_crypto::CryptoError::Decryption(e.to_string())
        ))?;
        let nonce = Nonce::from_bytes(&nonce_bytes)
            .map_err(ClientError::Encryption)?;

        // Unwrap the DEK
        let wrapped_key: EncryptedData = serde_json::from_value(
            enc_metadata["wrapped_key"].clone()
        ).map_err(|e| ClientError::Encryption(
            fula_crypto::CryptoError::Decryption(e.to_string())
        ))?;

        let decryptor = Decryptor::new(self.encryption.key_manager.keypair());
        let dek = decryptor.decrypt_dek(&wrapped_key)
            .map_err(ClientError::Encryption)?;

        // Decrypt the data
        let aead = Aead::new_default(&dek);
        let plaintext = aead.decrypt(&nonce, &result.data)
            .map_err(ClientError::Encryption)?;

        Ok(Bytes::from(plaintext))
    }

    // Delegate non-encrypted operations to inner client

    /// List buckets
    pub async fn list_buckets(&self) -> Result<ListBucketsResult> {
        self.inner.list_buckets().await
    }

    /// Create bucket
    pub async fn create_bucket(&self, bucket: &str) -> Result<()> {
        self.inner.create_bucket(bucket).await
    }

    /// Delete bucket
    pub async fn delete_bucket(&self, bucket: &str) -> Result<()> {
        self.inner.delete_bucket(bucket).await
    }

    /// List objects
    pub async fn list_objects(
        &self,
        bucket: &str,
        options: Option<ListObjectsOptions>,
    ) -> Result<ListObjectsResult> {
        self.inner.list_objects(bucket, options).await
    }

    /// Delete object
    pub async fn delete_object(&self, bucket: &str, key: &str) -> Result<()> {
        self.inner.delete_object(bucket, key).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encryption_config() {
        let config1 = EncryptionConfig::new();
        let config2 = EncryptionConfig::new();
        
        // Different configs should have different keys
        assert_ne!(
            config1.public_key().as_bytes(),
            config2.public_key().as_bytes()
        );
    }
}
