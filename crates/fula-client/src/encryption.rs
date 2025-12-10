//! Client-side encryption support
//!
//! Provides end-to-end encryption for Fula storage including:
//! - Content encryption (AES-256-GCM)
//! - Key wrapping (HPKE)
//! - Metadata privacy (file names, sizes, timestamps)

use crate::{ClientError, FulaClient, Result, Config};
use crate::types::*;
use bytes::Bytes;
use fula_crypto::{
    keys::KeyManager,
    hpke::{Encryptor, Decryptor, EncryptedData},
    symmetric::{Aead, Nonce},
    private_metadata::{PrivateMetadata, EncryptedPrivateMetadata, KeyObfuscation, obfuscate_key},
    private_forest::{PrivateForest, EncryptedForest, ForestFileEntry, derive_index_key},
    sharing::{ShareToken, AcceptedShare, ShareRecipient},
    rotation::{KeyRotationManager, WrappedKeyInfo},
    ChunkedEncoder, ChunkedFileMetadata, should_use_chunked,
};
use std::sync::{Arc, RwLock};
use std::collections::HashMap;

/// Configuration for client-side encryption
pub struct EncryptionConfig {
    /// Key manager for encryption keys (wrapped in Arc for sharing)
    key_manager: Arc<KeyManager>,
    /// Whether to enable metadata privacy (file name obfuscation)
    metadata_privacy: bool,
    /// Key obfuscation mode
    obfuscation_mode: KeyObfuscation,
}

impl EncryptionConfig {
    /// Create a new encryption config with random keys
    /// Metadata privacy is ENABLED by default with FlatNamespace mode (RECOMMENDED)
    /// 
    /// FlatNamespace provides complete structure hiding:
    /// - Storage keys look like random CID-style hashes
    /// - No prefixes or structure hints visible to server
    /// - Server cannot determine folder structure or parent/child relationships
    pub fn new() -> Self {
        Self {
            key_manager: Arc::new(KeyManager::new()),
            metadata_privacy: true,
            obfuscation_mode: KeyObfuscation::FlatNamespace,
        }
    }

    /// Create without metadata privacy (filenames visible to server)
    pub fn new_without_privacy() -> Self {
        Self {
            key_manager: Arc::new(KeyManager::new()),
            metadata_privacy: false,
            obfuscation_mode: KeyObfuscation::DeterministicHash,
        }
    }

    /// Create with FlatNamespace mode - RECOMMENDED for maximum privacy
    /// 
    /// This mode provides complete structure hiding:
    /// - Storage keys look like random CID-style hashes (e.g., `QmX7a8f3...`)
    /// - No prefixes or structure hints visible to server
    /// - Server cannot determine folder structure or parent/child relationships
    /// - File tree is stored in an encrypted PrivateForest index
    /// 
    /// Inspired by WNFS (WebNative File System) and Peergos.
    pub fn new_flat_namespace() -> Self {
        Self {
            key_manager: Arc::new(KeyManager::new()),
            metadata_privacy: true,
            obfuscation_mode: KeyObfuscation::FlatNamespace,
        }
    }

    /// Create from an existing secret key (uses FlatNamespace by default)
    pub fn from_secret_key(secret: fula_crypto::keys::SecretKey) -> Self {
        Self {
            key_manager: Arc::new(KeyManager::from_secret_key(secret)),
            metadata_privacy: true,
            obfuscation_mode: KeyObfuscation::FlatNamespace,
        }
    }

    /// Enable or disable metadata privacy
    pub fn with_metadata_privacy(mut self, enabled: bool) -> Self {
        self.metadata_privacy = enabled;
        self
    }

    /// Set the key obfuscation mode
    pub fn with_obfuscation_mode(mut self, mode: KeyObfuscation) -> Self {
        self.obfuscation_mode = mode;
        self
    }

    /// Check if metadata privacy is enabled
    pub fn has_metadata_privacy(&self) -> bool {
        self.metadata_privacy
    }

    /// Get the public key for sharing
    pub fn public_key(&self) -> &fula_crypto::keys::PublicKey {
        self.key_manager.public_key()
    }

    /// Export the secret key (handle with care!)
    pub fn export_secret_key(&self) -> &fula_crypto::keys::SecretKey {
        self.key_manager.keypair().secret_key()
    }

    /// Get the key manager
    pub fn key_manager(&self) -> &KeyManager {
        &self.key_manager
    }
}

impl Default for EncryptionConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// Pinning credentials for remote pinning services
#[derive(Clone, Debug)]
pub struct PinningCredentials {
    /// Pinning service endpoint URL
    pub endpoint: String,
    /// Bearer token for authentication
    pub token: String,
}

impl PinningCredentials {
    /// Create new pinning credentials
    pub fn new(endpoint: impl Into<String>, token: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            token: token.into(),
        }
    }
}

/// Client with client-side encryption enabled
pub struct EncryptedClient {
    inner: FulaClient,
    encryption: EncryptionConfig,
    /// Private forest index for FlatNamespace mode (cached)
    forest_cache: RwLock<HashMap<String, PrivateForest>>,
    /// Optional pinning credentials for remote pinning
    pinning: Option<PinningCredentials>,
}

impl EncryptedClient {
    /// Create a new encrypted client
    pub fn new(config: Config, encryption: EncryptionConfig) -> Result<Self> {
        let inner = FulaClient::new(config)?;
        Ok(Self { 
            inner, 
            encryption,
            forest_cache: RwLock::new(HashMap::new()),
            pinning: None,
        })
    }

    /// Get the underlying client
    pub fn inner(&self) -> &FulaClient {
        &self.inner
    }

    /// Create a new encrypted client with pinning credentials
    pub fn new_with_pinning(
        config: Config, 
        encryption: EncryptionConfig,
        pinning: PinningCredentials,
    ) -> Result<Self> {
        let inner = FulaClient::new(config)?;
        Ok(Self { 
            inner, 
            encryption,
            forest_cache: RwLock::new(HashMap::new()),
            pinning: Some(pinning),
        })
    }

    /// Set pinning credentials (builder pattern)
    pub fn with_pinning(mut self, pinning: PinningCredentials) -> Self {
        self.pinning = Some(pinning);
        self
    }

    /// Get the encryption config
    pub fn encryption_config(&self) -> &EncryptionConfig {
        &self.encryption
    }

    /// Put an encrypted object with optional content type
    pub async fn put_object_encrypted_with_type(
        &self,
        bucket: &str,
        key: &str,
        data: impl Into<Bytes>,
        content_type: Option<&str>,
    ) -> Result<PutObjectResult> {
        let data = data.into();
        let original_size = data.len() as u64;
        
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

        // Determine the storage key and metadata based on privacy settings
        let (storage_key, private_metadata_json) = if self.encryption.metadata_privacy {
            // Create private metadata with original info
            let private_meta = PrivateMetadata::new(key, original_size)
                .with_content_type(content_type.unwrap_or("application/octet-stream"));
            
            // Encrypt private metadata with the per-file DEK
            let encrypted_meta = EncryptedPrivateMetadata::encrypt(&private_meta, &dek)
                .map_err(ClientError::Encryption)?;
            
            // Generate obfuscated storage key using PATH-DERIVED DEK (not per-file DEK)
            // This ensures we can compute the same storage key later for retrieval
            let path_dek = self.encryption.key_manager.derive_path_key(key);
            let storage_key = obfuscate_key(key, &path_dek, self.encryption.obfuscation_mode.clone());
            
            (storage_key, Some(encrypted_meta.to_json().map_err(ClientError::Encryption)?))
        } else {
            (key.to_string(), None)
        };

        // Serialize encryption metadata with KEK version
        let kek_version = self.encryption.key_manager.version();
        let mut enc_metadata = serde_json::json!({
            "version": 2,
            "algorithm": "AES-256-GCM",
            "nonce": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, nonce.as_bytes()),
            "wrapped_key": serde_json::to_value(&wrapped_dek).unwrap(),
            "kek_version": kek_version,
            "metadata_privacy": self.encryption.metadata_privacy,
        });

        // Add encrypted private metadata if enabled
        if let Some(private_meta) = private_metadata_json {
            enc_metadata["private_metadata"] = serde_json::Value::String(private_meta);
        }

        // Upload with encryption metadata (server sees obfuscated key)
        let metadata = ObjectMetadata::new()
            .with_content_type("application/octet-stream") // Server always sees generic type
            .with_metadata("x-fula-encrypted", "true")
            .with_metadata("x-fula-encryption", &enc_metadata.to_string());

        // Use pinning if credentials are configured
        if let Some(ref pinning) = self.pinning {
            self.inner.put_object_with_metadata_and_pinning(
                bucket,
                &storage_key,
                Bytes::from(ciphertext),
                Some(metadata),
                &pinning.endpoint,
                &pinning.token,
            ).await
        } else {
            self.inner.put_object_with_metadata(
                bucket,
                &storage_key,
                Bytes::from(ciphertext),
                Some(metadata),
            ).await
        }
    }

    /// Put an encrypted object (convenience method)
    pub async fn put_object_encrypted(
        &self,
        bucket: &str,
        key: &str,
        data: impl Into<Bytes>,
    ) -> Result<PutObjectResult> {
        self.put_object_encrypted_with_type(bucket, key, data, None).await
    }

    /// Get and decrypt an object using the original key
    /// 
    /// If metadata privacy is enabled, this will automatically compute the
    /// storage key from the original key using deterministic hashing.
    pub async fn get_object_decrypted(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<Bytes> {
        // For metadata privacy, we need to find the storage key
        // Since we use deterministic hashing, we can compute it
        // But we need the DEK first, which creates a chicken-and-egg problem
        // 
        // Solution: If metadata privacy is enabled, we use the path-derived DEK
        // to compute the storage key, fetch the object, then use the wrapped DEK
        // to decrypt the actual data.
        
        let storage_key = if self.encryption.metadata_privacy {
            // Use a path-derived DEK for key obfuscation lookup
            let path_dek = self.encryption.key_manager.derive_path_key(key);
            obfuscate_key(key, &path_dek, self.encryption.obfuscation_mode.clone())
        } else {
            key.to_string()
        };

        self.get_object_decrypted_by_storage_key(bucket, &storage_key).await
    }

    /// Get and decrypt an object using the storage key directly
    /// 
    /// Use this when you already have the obfuscated storage key
    /// (e.g., from list_objects_decrypted)
    /// 
    /// Handles both single-block and chunked objects automatically.
    pub async fn get_object_decrypted_by_storage_key(
        &self,
        bucket: &str,
        storage_key: &str,
    ) -> Result<Bytes> {
        let result = self.inner.get_object_with_metadata(bucket, storage_key).await?;
        
        // Check if object is encrypted
        let is_encrypted = result.metadata
            .get("x-fula-encrypted")
            .map(|v| v == "true")
            .unwrap_or(false);

        if !is_encrypted {
            return Ok(result.data);
        }

        // Check if this is a chunked object
        let is_chunked = result.metadata
            .get("x-fula-chunked")
            .map(|v| v == "true")
            .unwrap_or(false);

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

        // Unwrap the DEK (common to both chunked and non-chunked)
        let wrapped_key: EncryptedData = serde_json::from_value(
            enc_metadata["wrapped_key"].clone()
        ).map_err(|e| ClientError::Encryption(
            fula_crypto::CryptoError::Decryption(e.to_string())
        ))?;

        let decryptor = Decryptor::new(self.encryption.key_manager.keypair());
        let dek = decryptor.decrypt_dek(&wrapped_key)
            .map_err(ClientError::Encryption)?;

        if is_chunked {
            // CHUNKED DOWNLOAD: Download and decrypt each chunk
            self.get_object_chunked_internal(bucket, storage_key, &enc_metadata, &dek).await
        } else {
            // SINGLE OBJECT: Decrypt directly
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

            let aead = Aead::new_default(&dek);
            let plaintext = aead.decrypt(&nonce, &result.data)
                .map_err(ClientError::Encryption)?;

            Ok(Bytes::from(plaintext))
        }
    }

    /// Internal: Download and decrypt a chunked file
    async fn get_object_chunked_internal(
        &self,
        bucket: &str,
        storage_key: &str,
        enc_metadata: &serde_json::Value,
        dek: &fula_crypto::keys::DekKey,
    ) -> Result<Bytes> {
        // Parse chunked metadata
        let chunked_meta: ChunkedFileMetadata = serde_json::from_value(
            enc_metadata["chunked"].clone()
        ).map_err(|e| ClientError::Encryption(
            fula_crypto::CryptoError::Decryption(format!("Invalid chunked metadata: {}", e))
        ))?;

        // Create decoder
        let mut decoder = fula_crypto::ChunkedDecoder::new(dek.clone(), chunked_meta.clone());

        // Pre-allocate result buffer
        let mut plaintext = Vec::with_capacity(chunked_meta.total_size as usize);

        // Download and decrypt each chunk in order
        for chunk_index in 0..chunked_meta.num_chunks {
            let chunk_key = ChunkedFileMetadata::chunk_key(storage_key, chunk_index);
            
            let chunk_result = self.inner.get_object(bucket, &chunk_key).await?;
            
            let chunk_plaintext = decoder.decrypt_chunk(chunk_index, &chunk_result)
                .map_err(ClientError::Encryption)?;
            
            plaintext.extend_from_slice(&chunk_plaintext);
        }

        Ok(Bytes::from(plaintext))
    }

    /// Decrypted object info with private metadata
    pub async fn get_object_with_private_metadata(
        &self,
        bucket: &str,
        storage_key: &str,
    ) -> Result<DecryptedObjectInfo> {
        let result = self.inner.get_object_with_metadata(bucket, storage_key).await?;
        
        let is_encrypted = result.metadata
            .get("x-fula-encrypted")
            .map(|v| v == "true")
            .unwrap_or(false);

        if !is_encrypted {
            let size = result.data.len() as u64;
            return Ok(DecryptedObjectInfo {
                data: result.data,
                original_key: storage_key.to_string(),
                original_size: size,
                content_type: result.metadata.get("content-type").cloned(),
                user_metadata: HashMap::new(),
            });
        }

        let enc_metadata_str = result.metadata
            .get("x-fula-encryption")
            .ok_or_else(|| ClientError::Encryption(
                fula_crypto::CryptoError::Decryption("Missing encryption metadata".to_string())
            ))?;

        let enc_metadata: serde_json::Value = serde_json::from_str(enc_metadata_str)
            .map_err(|e| ClientError::Encryption(
                fula_crypto::CryptoError::Decryption(e.to_string())
            ))?;

        // Unwrap the DEK
        let wrapped_key: EncryptedData = serde_json::from_value(
            enc_metadata["wrapped_key"].clone()
        ).map_err(|e| ClientError::Encryption(
            fula_crypto::CryptoError::Decryption(e.to_string())
        ))?;

        let decryptor = Decryptor::new(self.encryption.key_manager.keypair());
        let dek = decryptor.decrypt_dek(&wrapped_key)
            .map_err(ClientError::Encryption)?;

        // Decrypt data
        let nonce_b64 = enc_metadata["nonce"].as_str().unwrap();
        let nonce_bytes = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            nonce_b64,
        ).map_err(|e| ClientError::Encryption(
            fula_crypto::CryptoError::Decryption(e.to_string())
        ))?;
        let nonce = Nonce::from_bytes(&nonce_bytes)
            .map_err(ClientError::Encryption)?;

        let aead = Aead::new_default(&dek);
        let plaintext = aead.decrypt(&nonce, &result.data)
            .map_err(ClientError::Encryption)?;

        // Decrypt private metadata if present
        let (original_key, original_size, content_type, user_metadata) = 
            if let Some(private_meta_str) = enc_metadata["private_metadata"].as_str() {
                let encrypted_meta = EncryptedPrivateMetadata::from_json(private_meta_str)
                    .map_err(ClientError::Encryption)?;
                let private_meta = encrypted_meta.decrypt(&dek)
                    .map_err(ClientError::Encryption)?;
                
                (
                    private_meta.original_key,
                    private_meta.actual_size,
                    private_meta.content_type,
                    private_meta.user_metadata,
                )
            } else {
                (storage_key.to_string(), plaintext.len() as u64, None, HashMap::new())
            };

        Ok(DecryptedObjectInfo {
            data: Bytes::from(plaintext),
            original_key,
            original_size,
            content_type,
            user_metadata,
        })
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

    /// List objects (returns obfuscated keys if metadata privacy is enabled)
    pub async fn list_objects(
        &self,
        bucket: &str,
        options: Option<ListObjectsOptions>,
    ) -> Result<ListObjectsResult> {
        self.inner.list_objects(bucket, options).await
    }

    /// Delete object using original key
    pub async fn delete_object(&self, bucket: &str, key: &str) -> Result<()> {
        let storage_key = if self.encryption.metadata_privacy {
            let path_dek = self.encryption.key_manager.derive_path_key(key);
            obfuscate_key(key, &path_dek, self.encryption.obfuscation_mode.clone())
        } else {
            key.to_string()
        };
        self.inner.delete_object(bucket, &storage_key).await
    }

    /// Delete object using storage key directly
    pub async fn delete_object_by_storage_key(&self, bucket: &str, storage_key: &str) -> Result<()> {
        self.inner.delete_object(bucket, storage_key).await
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // METADATA-ONLY OPERATIONS (No file content download required)
    // These methods are optimized for file managers and directory browsers
    // ═══════════════════════════════════════════════════════════════════════════

    /// Get file metadata WITHOUT downloading the file content.
    /// 
    /// This is ideal for file managers that need to display file information
    /// (name, size, type, timestamps) without the bandwidth cost of downloading files.
    /// 
    /// Returns decrypted metadata including:
    /// - Original filename (not the obfuscated storage key)
    /// - Original file size (not ciphertext size)
    /// - Content type
    /// - Timestamps
    /// - User-defined metadata
    pub async fn head_object_decrypted(
        &self,
        bucket: &str,
        storage_key: &str,
    ) -> Result<FileMetadata> {
        // HEAD request - only gets headers, NOT file content
        let head_result = self.inner.head_object(bucket, storage_key).await?;
        
        // Security audit fix #9: Check correct metadata keys (x-fula-encrypted, x-fula-encryption)
        // The upload code uses x-amz-meta-x-fula-* which becomes x-fula-* in user_metadata
        let is_encrypted = head_result.metadata
            .get("x-fula-encrypted")
            .map(|v| v == "true")
            .unwrap_or(false);

        if !is_encrypted {
            return Ok(FileMetadata {
                storage_key: storage_key.to_string(),
                original_key: storage_key.to_string(),
                original_size: head_result.content_length,
                content_type: head_result.content_type,
                created_at: None,
                modified_at: None,
                user_metadata: HashMap::new(),
                is_encrypted: false,
            });
        }

        // Parse encryption metadata from headers
        let enc_metadata_str = head_result.metadata
            .get("x-fula-encryption")
            .ok_or_else(|| ClientError::Encryption(
                fula_crypto::CryptoError::Decryption("Missing encryption metadata".to_string())
            ))?;

        let enc_metadata: serde_json::Value = serde_json::from_str(enc_metadata_str)
            .map_err(|e| ClientError::Encryption(
                fula_crypto::CryptoError::Decryption(e.to_string())
            ))?;

        // Unwrap the DEK (needed to decrypt private metadata)
        let wrapped_key: EncryptedData = serde_json::from_value(
            enc_metadata["wrapped_key"].clone()
        ).map_err(|e| ClientError::Encryption(
            fula_crypto::CryptoError::Decryption(e.to_string())
        ))?;

        let decryptor = Decryptor::new(self.encryption.key_manager.keypair());
        let dek = decryptor.decrypt_dek(&wrapped_key)
            .map_err(ClientError::Encryption)?;

        // Decrypt private metadata if present (this is tiny - just a few hundred bytes)
        if let Some(private_meta_str) = enc_metadata["private_metadata"].as_str() {
            let encrypted_meta = EncryptedPrivateMetadata::from_json(private_meta_str)
                .map_err(ClientError::Encryption)?;
            let private_meta = encrypted_meta.decrypt(&dek)
                .map_err(ClientError::Encryption)?;
            
            Ok(FileMetadata {
                storage_key: storage_key.to_string(),
                original_key: private_meta.original_key,
                original_size: private_meta.actual_size,
                content_type: private_meta.content_type,
                created_at: Some(private_meta.created_at),
                modified_at: Some(private_meta.modified_at),
                user_metadata: private_meta.user_metadata,
                is_encrypted: true,
            })
        } else {
            // No private metadata - use visible metadata
            Ok(FileMetadata {
                storage_key: storage_key.to_string(),
                original_key: storage_key.to_string(),
                original_size: head_result.content_length,
                content_type: head_result.content_type,
                created_at: None,
                modified_at: None,
                user_metadata: HashMap::new(),
                is_encrypted: true,
            })
        }
    }

    /// List all objects in a bucket with decrypted metadata.
    /// 
    /// **This does NOT download any file content** - only metadata headers.
    /// Perfect for building file managers, directory browsers, or sync tools.
    /// 
    /// For each file, returns:
    /// - Original filename (decrypted)
    /// - Original size
    /// - Content type
    /// - Timestamps
    /// 
    /// Bandwidth: Only ~1-2KB per file (just headers), not the file content.
    pub async fn list_objects_decrypted(
        &self,
        bucket: &str,
        options: Option<ListObjectsOptions>,
    ) -> Result<Vec<FileMetadata>> {
        // Get list of storage keys
        let list_result = self.inner.list_objects(bucket, options).await?;
        
        let mut files = Vec::with_capacity(list_result.objects.len());
        
        for obj in list_result.objects {
            // HEAD each object to get metadata without downloading content
            match self.head_object_decrypted(bucket, &obj.key).await {
                Ok(metadata) => files.push(metadata),
                Err(e) => {
                    // Log error but continue with other files
                    tracing::warn!("Failed to get metadata for {}: {:?}", obj.key, e);
                    // Include with storage key as fallback
                    files.push(FileMetadata {
                        storage_key: obj.key.clone(),
                        original_key: obj.key,
                        original_size: obj.size,
                        content_type: None,
                        created_at: None,
                        modified_at: None,
                        user_metadata: HashMap::new(),
                        is_encrypted: false,
                    });
                }
            }
        }
        
        Ok(files)
    }

    /// List objects as a directory tree structure.
    /// 
    /// Groups files by their original directory paths for easy tree rendering.
    /// Does NOT download file content - only metadata.
    pub async fn list_directory(
        &self,
        bucket: &str,
        prefix: Option<&str>,
    ) -> Result<DirectoryListing> {
        // For FlatNamespace, use the forest directly
        if self.encryption.obfuscation_mode == KeyObfuscation::FlatNamespace {
            return self.list_directory_from_forest(bucket, prefix).await;
        }

        let options = prefix.map(|p| ListObjectsOptions {
            prefix: Some(p.to_string()),
            ..Default::default()
        });

        let files = self.list_objects_decrypted(bucket, options).await?;
        
        let mut directories: HashMap<String, Vec<FileMetadata>> = HashMap::new();
        
        for file in files {
            let dir = if let Some(last_slash) = file.original_key.rfind('/') {
                file.original_key[..last_slash].to_string()
            } else {
                "/".to_string()
            };
            
            directories.entry(dir).or_default().push(file);
        }
        
        Ok(DirectoryListing {
            bucket: bucket.to_string(),
            prefix: prefix.map(|s| s.to_string()),
            directories,
        })
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // FLATNAMESPACE / PRIVATE FOREST SUPPORT
    // Complete structure hiding - server sees only random CID-like hashes
    // ═══════════════════════════════════════════════════════════════════════════

    /// Check if FlatNamespace mode is enabled
    pub fn is_flat_namespace(&self) -> bool {
        self.encryption.obfuscation_mode == KeyObfuscation::FlatNamespace
    }

    /// Load the private forest index for a bucket
    /// 
    /// The forest contains the encrypted directory structure and path→storage_key mapping.
    /// This is only used in FlatNamespace mode.
    pub async fn load_forest(&self, bucket: &str) -> Result<PrivateForest> {
        // Check cache first
        {
            let cache = self.forest_cache.read().unwrap();
            if let Some(forest) = cache.get(bucket) {
                return Ok(forest.clone());
            }
        }

        // Security audit fix #8: Use DETERMINISTIC key derivation for forest index
        // This ensures we can find the same forest across sessions
        // The key is derived from: master_key + "forest:" + bucket_name
        let forest_dek = self.encryption.key_manager.derive_path_key(&format!("forest:{}", bucket));
        let index_key = derive_index_key(&forest_dek, bucket);

        // Try to load from storage
        match self.inner.get_object_with_metadata(bucket, &index_key).await {
            Ok(result) => {
                // Decrypt the forest
                let encrypted = EncryptedForest::from_bytes(&result.data)
                    .map_err(ClientError::Encryption)?;
                let forest = encrypted.decrypt(&forest_dek)
                    .map_err(ClientError::Encryption)?;
                
                // Cache it
                {
                    let mut cache = self.forest_cache.write().unwrap();
                    cache.insert(bucket.to_string(), forest.clone());
                }
                
                Ok(forest)
            }
            Err(_) => {
                // No forest exists yet - create empty one
                let forest = PrivateForest::new();
                
                // Cache it
                {
                    let mut cache = self.forest_cache.write().unwrap();
                    cache.insert(bucket.to_string(), forest.clone());
                }
                
                Ok(forest)
            }
        }
    }

    /// Save the private forest index for a bucket
    pub async fn save_forest(&self, bucket: &str, forest: &PrivateForest) -> Result<()> {
        // Security audit fix #8: Use DETERMINISTIC key derivation (same as load_forest)
        let forest_dek = self.encryption.key_manager.derive_path_key(&format!("forest:{}", bucket));
        let index_key = derive_index_key(&forest_dek, bucket);

        // Encrypt the forest
        let encrypted = EncryptedForest::encrypt(forest, &forest_dek)
            .map_err(ClientError::Encryption)?;
        let data = encrypted.to_bytes()
            .map_err(ClientError::Encryption)?;

        // Upload (the index looks like any other encrypted blob)
        let metadata = ObjectMetadata::new()
            .with_content_type("application/octet-stream")
            .with_metadata("x-fula-forest", "true");

        self.inner.put_object_with_metadata(
            bucket,
            &index_key,
            Bytes::from(data),
            Some(metadata),
        ).await?;

        // Update cache
        {
            let mut cache = self.forest_cache.write().unwrap();
            cache.insert(bucket.to_string(), forest.clone());
        }

        Ok(())
    }

    /// Put an encrypted object using FlatNamespace mode
    /// 
    /// This automatically updates AND SAVES the forest index after each file.
    /// For bulk uploads, use `put_object_flat_deferred` + `flush_forest` instead.
    pub async fn put_object_flat(
        &self,
        bucket: &str,
        key: &str,
        data: impl Into<Bytes>,
        content_type: Option<&str>,
    ) -> Result<PutObjectResult> {
        let result = self.put_object_flat_deferred(bucket, key, data, content_type).await?;
        self.flush_forest(bucket).await?;
        Ok(result)
    }

    /// Put an encrypted object using FlatNamespace mode WITHOUT saving forest
    /// 
    /// Use this for bulk uploads. Call `flush_forest` after uploading all files
    /// to persist the forest index. This is much more efficient for many files.
    /// 
    /// # Example
    /// ```ignore
    /// // Upload 100 files efficiently
    /// for file in files {
    ///     client.put_object_flat_deferred(bucket, &file.path, file.data, None).await?;
    /// }
    /// // Save forest once at the end
    /// client.flush_forest(bucket).await?;
    /// ```
    pub async fn put_object_flat_deferred(
        &self,
        bucket: &str,
        key: &str,
        data: impl Into<Bytes>,
        content_type: Option<&str>,
    ) -> Result<PutObjectResult> {
        let data = data.into();
        let original_size = data.len() as u64;
        
        // Load or create forest (from cache if available)
        let mut forest = self.load_forest(bucket).await?;
        
        // Generate a DEK for this object
        let dek = self.encryption.key_manager.generate_dek();
        
        // Generate flat storage key (no structure hints!)
        let storage_key = forest.generate_key(key, &dek);

        // Encrypt the DEK with HPKE
        let encryptor = Encryptor::new(self.encryption.public_key());
        let wrapped_dek = encryptor.encrypt_dek(&dek)
            .map_err(ClientError::Encryption)?;

        // Create private metadata
        let private_meta = PrivateMetadata::new(key, original_size)
            .with_content_type(content_type.unwrap_or("application/octet-stream"));
        
        let encrypted_meta = EncryptedPrivateMetadata::encrypt(&private_meta, &dek)
            .map_err(ClientError::Encryption)?;

        // Add to forest index (in memory only)
        let entry = ForestFileEntry::from_metadata(&private_meta, storage_key.clone());
        forest.upsert_file(entry);

        let kek_version = self.encryption.key_manager.version();

        // Check if we need chunked upload (for IPFS block size limit)
        let result = if should_use_chunked(data.len()) {
            // CHUNKED UPLOAD: Split into chunks under IPFS 1MB limit
            self.put_object_chunked_internal(
                bucket,
                &storage_key,
                &data,
                &dek,
                &wrapped_dek,
                &encrypted_meta,
                kek_version,
            ).await?
        } else {
            // SINGLE OBJECT: File is small enough for one block
            let nonce = Nonce::generate();
            let aead = Aead::new_default(&dek);
            let ciphertext = aead.encrypt(&nonce, &data)
                .map_err(ClientError::Encryption)?;

            // Serialize encryption metadata
            let enc_metadata = serde_json::json!({
                "version": 2,
                "algorithm": "AES-256-GCM",
                "nonce": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, nonce.as_bytes()),
                "wrapped_key": serde_json::to_value(&wrapped_dek).unwrap(),
                "kek_version": kek_version,
                "metadata_privacy": true,
                "obfuscation_mode": "flat",
                "private_metadata": encrypted_meta.to_json().map_err(ClientError::Encryption)?,
            });

            let metadata = ObjectMetadata::new()
                .with_content_type("application/octet-stream")
                .with_metadata("x-fula-encrypted", "true")
                .with_metadata("x-fula-encryption", &enc_metadata.to_string());

            if let Some(ref pinning) = self.pinning {
                self.inner.put_object_with_metadata_and_pinning(
                    bucket,
                    &storage_key,
                    Bytes::from(ciphertext),
                    Some(metadata),
                    &pinning.endpoint,
                    &pinning.token,
                ).await?
            } else {
                self.inner.put_object_with_metadata(
                    bucket,
                    &storage_key,
                    Bytes::from(ciphertext),
                    Some(metadata),
                ).await?
            }
        };

        // Update cache (but don't save to storage yet)
        {
            let mut cache = self.forest_cache.write().unwrap();
            cache.insert(bucket.to_string(), forest);
        }

        Ok(result)
    }

    /// Internal: Upload a large file using chunked encoding
    async fn put_object_chunked_internal(
        &self,
        bucket: &str,
        storage_key: &str,
        data: &[u8],
        dek: &fula_crypto::keys::DekKey,
        wrapped_dek: &EncryptedData,
        encrypted_meta: &EncryptedPrivateMetadata,
        kek_version: u32,
    ) -> Result<PutObjectResult> {
        // Create chunked encoder
        let mut encoder = ChunkedEncoder::new(dek.clone());
        
        // Process all data through encoder
        let mut all_chunks = encoder.update(data)
            .map_err(ClientError::Encryption)?;
        
        // Finalize to get last chunk and metadata
        let (final_chunk, chunked_metadata, _outboard) = encoder.finalize()
            .map_err(ClientError::Encryption)?;
        
        if let Some(chunk) = final_chunk {
            all_chunks.push(chunk);
        }
        
        // Upload each chunk as a separate object
        for chunk in &all_chunks {
            let chunk_key = ChunkedFileMetadata::chunk_key(storage_key, chunk.index);
            
            // Upload chunk (no encryption metadata needed, just raw encrypted bytes)
            let chunk_metadata = ObjectMetadata::new()
                .with_content_type("application/octet-stream")
                .with_metadata("x-fula-chunk", "true")
                .with_metadata("x-fula-chunk-index", &chunk.index.to_string());
            
            if let Some(ref pinning) = self.pinning {
                self.inner.put_object_with_metadata_and_pinning(
                    bucket,
                    &chunk_key,
                    chunk.ciphertext.clone(),
                    Some(chunk_metadata),
                    &pinning.endpoint,
                    &pinning.token,
                ).await?;
            } else {
                self.inner.put_object_with_metadata(
                    bucket,
                    &chunk_key,
                    chunk.ciphertext.clone(),
                    Some(chunk_metadata),
                ).await?;
            }
        }
        
        // Create index object with encryption metadata and chunk info
        let enc_metadata = serde_json::json!({
            "version": 2,
            "algorithm": "AES-256-GCM",
            "wrapped_key": serde_json::to_value(wrapped_dek).unwrap(),
            "kek_version": kek_version,
            "metadata_privacy": true,
            "obfuscation_mode": "flat",
            "private_metadata": encrypted_meta.to_json().map_err(ClientError::Encryption)?,
            "chunked": serde_json::to_value(&chunked_metadata).unwrap(),
        });
        
        // The index object is small - just metadata, no file content
        let index_body = enc_metadata.to_string();
        let metadata = ObjectMetadata::new()
            .with_content_type("application/json")
            .with_metadata("x-fula-encrypted", "true")
            .with_metadata("x-fula-chunked", "true")
            .with_metadata("x-fula-encryption", &index_body);
        
        // Upload index object
        let result = if let Some(ref pinning) = self.pinning {
            self.inner.put_object_with_metadata_and_pinning(
                bucket,
                storage_key,
                Bytes::from(index_body.clone()),
                Some(metadata),
                &pinning.endpoint,
                &pinning.token,
            ).await?
        } else {
            self.inner.put_object_with_metadata(
                bucket,
                storage_key,
                Bytes::from(index_body.clone()),
                Some(metadata),
            ).await?
        };
        
        Ok(result)
    }

    /// Flush the forest index to storage
    /// 
    /// Call this after bulk uploads using `put_object_flat_deferred`.
    /// This persists the in-memory forest index to encrypted storage.
    pub async fn flush_forest(&self, bucket: &str) -> Result<()> {
        let forest = {
            let cache = self.forest_cache.read().unwrap();
            cache.get(bucket).cloned()
        };
        
        if let Some(forest) = forest {
            self.save_forest(bucket, &forest).await?;
        }
        
        Ok(())
    }

    /// Check if there are unsaved forest changes
    pub fn has_pending_forest_changes(&self, bucket: &str) -> bool {
        let cache = self.forest_cache.read().unwrap();
        cache.contains_key(bucket)
    }

    /// Get an object using FlatNamespace mode
    /// 
    /// Uses the forest index to resolve original path → storage key.
    pub async fn get_object_flat(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<Bytes> {
        // Load forest to get the storage key
        let forest = self.load_forest(bucket).await?;
        
        let storage_key = forest.get_storage_key(key)
            .ok_or_else(|| ClientError::NotFound { bucket: bucket.to_string(), key: key.to_string() })?;

        self.get_object_decrypted_by_storage_key(bucket, storage_key).await
    }

    /// List directory from forest index (FlatNamespace mode)
    /// 
    /// This is much faster than HEAD requests because the forest already
    /// contains all metadata.
    async fn list_directory_from_forest(
        &self,
        bucket: &str,
        prefix: Option<&str>,
    ) -> Result<DirectoryListing> {
        let forest = self.load_forest(bucket).await?;
        
        let prefix_str = prefix.unwrap_or("/");
        let files = forest.list_recursive(prefix_str);
        
        let mut directories: HashMap<String, Vec<FileMetadata>> = HashMap::new();
        
        for entry in files {
            let dir = if let Some(last_slash) = entry.path.rfind('/') {
                entry.path[..last_slash].to_string()
            } else {
                "/".to_string()
            };
            
            let metadata = FileMetadata {
                storage_key: entry.storage_key.clone(),
                original_key: entry.path.clone(),
                original_size: entry.size,
                content_type: entry.content_type.clone(),
                created_at: Some(entry.created_at),
                modified_at: Some(entry.modified_at),
                user_metadata: entry.user_metadata.clone(),
                is_encrypted: true,
            };
            
            directories.entry(dir).or_default().push(metadata);
        }
        
        Ok(DirectoryListing {
            bucket: bucket.to_string(),
            prefix: prefix.map(|s| s.to_string()),
            directories,
        })
    }

    /// List all files from forest (FlatNamespace mode)
    /// 
    /// No network requests needed - uses cached/loaded forest index.
    pub async fn list_files_from_forest(
        &self,
        bucket: &str,
    ) -> Result<Vec<FileMetadata>> {
        let forest = self.load_forest(bucket).await?;
        
        let files: Vec<FileMetadata> = forest.list_all_files()
            .into_iter()
            .map(|entry| FileMetadata {
                storage_key: entry.storage_key.clone(),
                original_key: entry.path.clone(),
                original_size: entry.size,
                content_type: entry.content_type.clone(),
                created_at: Some(entry.created_at),
                modified_at: Some(entry.modified_at),
                user_metadata: entry.user_metadata.clone(),
                is_encrypted: true,
            })
            .collect();
        
        Ok(files)
    }

    /// Delete a file in FlatNamespace mode
    /// 
    /// Removes from storage and updates forest index.
    pub async fn delete_object_flat(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<()> {
        let mut forest = self.load_forest(bucket).await?;
        
        // Get storage key before removing from forest
        let storage_key = forest.get_storage_key(key)
            .ok_or_else(|| ClientError::NotFound { bucket: bucket.to_string(), key: key.to_string() })?
            .to_string();

        // Remove from storage
        self.inner.delete_object(bucket, &storage_key).await?;

        // Remove from forest
        forest.remove_file(key);

        // Save updated forest
        self.save_forest(bucket, &forest).await?;

        Ok(())
    }

    /// Get the private forest for sharing (extract subtree)
    /// 
    /// This allows sharing a portion of your file tree with someone else.
    pub async fn get_forest_subtree(
        &self,
        bucket: &str,
        prefix: &str,
    ) -> Result<PrivateForest> {
        let forest = self.load_forest(bucket).await?;
        Ok(forest.extract_subtree(prefix))
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // SHARING INTEGRATION
    // Read objects using ShareToken - fully wired into gateway flows
    // ═══════════════════════════════════════════════════════════════════════════

    /// Get and decrypt an object using a ShareToken
    /// 
    /// This allows recipients of a share to read encrypted objects without
    /// having the owner's keys. The ShareToken contains a wrapped DEK that
    /// was encrypted for the recipient's public key.
    /// 
    /// # Arguments
    /// * `bucket` - The bucket containing the object
    /// * `storage_key` - The storage key of the object
    /// * `accepted_share` - An accepted share containing the DEK
    /// 
    /// # Returns
    /// The decrypted object data
    pub async fn get_object_with_share(
        &self,
        bucket: &str,
        storage_key: &str,
        accepted_share: &AcceptedShare,
    ) -> Result<Bytes> {
        // Validate the share is still valid
        if !accepted_share.is_valid() {
            return Err(ClientError::Encryption(
                fula_crypto::CryptoError::ShareExpired
            ));
        }

        // Validate path scope
        if !accepted_share.is_path_allowed(storage_key) {
            return Err(ClientError::Encryption(
                fula_crypto::CryptoError::AccessDenied(
                    format!("Path {} is outside share scope {}", storage_key, accepted_share.path_scope)
                )
            ));
        }

        // Check read permission
        if !accepted_share.permissions.can_read {
            return Err(ClientError::Encryption(
                fula_crypto::CryptoError::AccessDenied("Share does not grant read permission".to_string())
            ));
        }

        // Fetch the object
        let result = self.inner.get_object_with_metadata(bucket, storage_key).await?;
        
        // Check if encrypted
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

        // Use the DEK from the accepted share (already decrypted for recipient)
        let aead = Aead::new_default(&accepted_share.dek);
        let plaintext = aead.decrypt(&nonce, &result.data)
            .map_err(ClientError::Encryption)?;

        Ok(Bytes::from(plaintext))
    }

    /// Accept a ShareToken and get an AcceptedShare for reading objects
    /// 
    /// This is a convenience method that combines ShareRecipient::accept_share
    /// with our encryption config's secret key.
    pub fn accept_share(&self, token: &ShareToken) -> Result<AcceptedShare> {
        let recipient = ShareRecipient::new(self.encryption.key_manager.keypair());
        recipient.accept_share(token)
            .map_err(ClientError::Encryption)
    }

    /// Get object using a raw ShareToken (convenience method)
    /// 
    /// Combines accept_share + get_object_with_share in one call.
    pub async fn get_object_with_token(
        &self,
        bucket: &str,
        storage_key: &str,
        token: &ShareToken,
    ) -> Result<Bytes> {
        let accepted = self.accept_share(token)?;
        self.get_object_with_share(bucket, storage_key, &accepted).await
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // KEY ROTATION INTEGRATION
    // Re-wrap DEKs without re-encrypting content
    // ═══════════════════════════════════════════════════════════════════════════

    /// Create a KeyRotationManager from this client's encryption config
    pub fn create_rotation_manager(&self) -> KeyRotationManager {
        KeyRotationManager::new(self.encryption.key_manager.keypair().clone())
    }

    /// Get the KEK version stored in an object's metadata
    /// 
    /// Returns None if the object doesn't have version info (legacy objects).
    pub async fn get_object_kek_version(
        &self,
        bucket: &str,
        storage_key: &str,
    ) -> Result<Option<u32>> {
        let head_result = self.inner.head_object(bucket, storage_key).await?;
        
        let enc_metadata_str = match head_result.metadata.get("x-fula-encryption") {
            Some(s) => s,
            None => return Ok(None),
        };

        let enc_metadata: serde_json::Value = serde_json::from_str(enc_metadata_str)
            .map_err(|e| ClientError::Encryption(
                fula_crypto::CryptoError::Decryption(e.to_string())
            ))?;

        Ok(enc_metadata["kek_version"].as_u64().map(|v| v as u32))
    }

    /// Re-wrap an object's DEK with the current KEK
    /// 
    /// This updates the object's encryption metadata without re-encrypting
    /// the content. Used during key rotation.
    /// 
    /// # Arguments
    /// * `bucket` - The bucket containing the object
    /// * `storage_key` - The storage key of the object  
    /// * `rotation_manager` - The rotation manager with old and new KEKs
    /// 
    /// # Returns
    /// The new KEK version after re-wrapping
    pub async fn rewrap_object_dek(
        &self,
        bucket: &str,
        storage_key: &str,
        rotation_manager: &KeyRotationManager,
    ) -> Result<u32> {
        // Get the object with metadata
        let result = self.inner.get_object_with_metadata(bucket, storage_key).await?;
        
        let enc_metadata_str = result.metadata
            .get("x-fula-encryption")
            .ok_or_else(|| ClientError::Encryption(
                fula_crypto::CryptoError::Decryption("Missing encryption metadata".to_string())
            ))?;

        let mut enc_metadata: serde_json::Value = serde_json::from_str(enc_metadata_str)
            .map_err(|e| ClientError::Encryption(
                fula_crypto::CryptoError::Decryption(e.to_string())
            ))?;

        // Get the wrapped key and version
        let wrapped_dek: EncryptedData = serde_json::from_value(
            enc_metadata["wrapped_key"].clone()
        ).map_err(|e| ClientError::Encryption(
            fula_crypto::CryptoError::Decryption(e.to_string())
        ))?;

        // Get the KEK version (default to 1 for legacy objects)
        let kek_version = enc_metadata["kek_version"]
            .as_u64()
            .map(|v| v as u32)
            .unwrap_or(1);

        // Create a WrappedKeyInfo for the rotation manager
        let wrapped_info = WrappedKeyInfo {
            wrapped_dek,
            kek_version,
            object_path: storage_key.to_string(),
        };

        // Unwrap with old KEK and rewrap with new KEK
        let new_wrapped = rotation_manager.rewrap_dek(&wrapped_info)
            .map_err(ClientError::Encryption)?;

        // Update metadata
        enc_metadata["wrapped_key"] = serde_json::to_value(&new_wrapped.wrapped_dek)
            .map_err(|e| ClientError::Encryption(
                fula_crypto::CryptoError::Encryption(e.to_string())
            ))?;
        enc_metadata["kek_version"] = serde_json::Value::Number(
            new_wrapped.kek_version.into()
        );

        // Re-upload with updated metadata (same ciphertext)
        let metadata = ObjectMetadata::new()
            .with_content_type(
                result.metadata.get("content-type")
                    .map(|s| s.as_str())
                    .unwrap_or("application/octet-stream")
            )
            .with_metadata("x-fula-encrypted", "true")
            .with_metadata("x-fula-encryption", &enc_metadata.to_string());

        self.inner.put_object_with_metadata(
            bucket,
            storage_key,
            result.data,
            Some(metadata),
        ).await?;

        Ok(rotation_manager.current_version())
    }

    /// Rotate all objects in a bucket to use the new KEK
    /// 
    /// Returns the number of objects successfully rotated and any failures.
    pub async fn rotate_bucket(
        &self,
        bucket: &str,
        rotation_manager: &KeyRotationManager,
    ) -> Result<RotationReport> {
        let objects = self.inner.list_objects(bucket, None).await?;
        
        let mut report = RotationReport {
            total: objects.objects.len(),
            rotated: 0,
            skipped: 0,
            failed: 0,
            failures: Vec::new(),
        };

        for obj in objects.objects {
            // Skip forest index
            if obj.key.starts_with("Qm") && obj.key.len() > 40 {
                // Check if it's the forest index
                let head = self.inner.head_object(bucket, &obj.key).await;
                if let Ok(h) = head {
                    if h.metadata.get("x-fula-forest").is_some() {
                        report.skipped += 1;
                        continue;
                    }
                }
            }

            match self.rewrap_object_dek(bucket, &obj.key, rotation_manager).await {
                Ok(_) => report.rotated += 1,
                Err(e) => {
                    report.failed += 1;
                    report.failures.push((obj.key, e.to_string()));
                }
            }
        }

        Ok(report)
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // STREAMING ENCRYPTION FOR LARGE FILES (WNFS-inspired)
    // Block-level encryption with index object pattern
    // ═══════════════════════════════════════════════════════════════════════════

    /// Upload a large file using chunked/streaming encryption
    /// 
    /// This method splits large files into encrypted chunks, uploads each
    /// chunk as a separate object, and creates an index object with metadata.
    /// Inspired by WNFS's "file = encrypted blocks + index" pattern.
    /// 
    /// # Arguments
    /// * `bucket` - Target bucket
    /// * `key` - Original file path/key
    /// * `data` - File content
    /// * `chunk_size` - Size of each chunk (default 256KB)
    /// 
    /// # Returns
    /// Result with the storage key for the index object
    pub async fn put_object_chunked(
        &self,
        bucket: &str,
        key: &str,
        data: &[u8],
        chunk_size: Option<usize>,
    ) -> Result<PutObjectResult> {
        use fula_crypto::chunked::{ChunkedEncoder, ChunkedFileMetadata, DEFAULT_CHUNK_SIZE};
        
        let chunk_size = chunk_size.unwrap_or(DEFAULT_CHUNK_SIZE);
        let dek = self.encryption.key_manager.generate_dek();
        
        // Generate storage key using obfuscation (same as put_object_encrypted)
        let storage_key = if self.encryption.metadata_privacy {
            let path_dek = self.encryption.key_manager.derive_path_key(key);
            obfuscate_key(key, &path_dek, self.encryption.obfuscation_mode.clone())
        } else {
            key.to_string()
        };
        
        // Create chunked encoder
        let mut encoder = ChunkedEncoder::with_chunk_size(dek.clone(), chunk_size);
        
        // Process all data and collect chunks
        let mut chunks = encoder.update(data)?;
        let (final_chunk, mut metadata, outboard) = encoder.finalize()?;
        
        if let Some(chunk) = final_chunk {
            chunks.push(chunk);
        }
        
        // Upload each chunk as a separate object
        for chunk in &chunks {
            let chunk_key = ChunkedFileMetadata::chunk_key(&storage_key, chunk.index);
            
            self.inner.put_object_with_metadata(
                bucket,
                &chunk_key,
                chunk.ciphertext.clone(),
                Some(ObjectMetadata::new()
                    .with_content_type("application/octet-stream")
                    .with_metadata("x-fula-chunk", "true")
                    .with_metadata("x-fula-chunk-index", &chunk.index.to_string())),
            ).await?;
        }
        
        // Update metadata with content type detection
        metadata.content_type = Some(
            mime_guess::from_path(key)
                .first_or_octet_stream()
                .to_string()
        );
        
        // Wrap the DEK with HPKE
        let encryptor = Encryptor::new(self.encryption.key_manager.public_key());
        let wrapped_dek = encryptor.encrypt_dek(&dek)?;
        
        // Create index object metadata
        let kek_version = self.encryption.key_manager.version();
        let enc_metadata = serde_json::json!({
            "version": 3,
            "format": "streaming-v1",
            "algorithm": "AES-256-GCM",
            "wrapped_key": serde_json::to_value(&wrapped_dek).unwrap(),
            "kek_version": kek_version,
            "chunked": metadata,
            "bao_outboard": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, outboard.to_bytes()),
        });
        
        // Upload index object (small, contains metadata only)
        let index_metadata = ObjectMetadata::new()
            .with_content_type("application/json")
            .with_metadata("x-fula-encrypted", "true")
            .with_metadata("x-fula-chunked", "true")
            .with_metadata("x-fula-encryption", &enc_metadata.to_string());
        
        let result = self.inner.put_object_with_metadata(
            bucket,
            &storage_key,
            Bytes::from(b"CHUNKED".to_vec()), // Marker content
            Some(index_metadata),
        ).await?;
        
        // Update forest cache if we have one
        if let Ok(mut cache) = self.forest_cache.write() {
            if let Some(forest) = cache.get_mut(bucket) {
                let now = chrono::Utc::now().timestamp();
                forest.upsert_file(ForestFileEntry {
                    path: key.to_string(),
                    storage_key: storage_key.clone(),
                    size: data.len() as u64,
                    content_type: metadata.content_type.clone(),
                    created_at: now,
                    modified_at: now,
                    user_metadata: HashMap::new(),
                    content_hash: None,
                });
            }
        }
        
        Ok(result)
    }

    /// Download and decrypt a chunked file
    /// 
    /// Fetches the index object, then downloads and decrypts chunks as needed.
    pub async fn get_object_chunked(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<Bytes> {
        use fula_crypto::chunked::{ChunkedDecoder, ChunkedFileMetadata};
        
        // Resolve path to storage key (same as get_object_decrypted)
        let storage_key = if self.encryption.metadata_privacy {
            let path_dek = self.encryption.key_manager.derive_path_key(key);
            obfuscate_key(key, &path_dek, self.encryption.obfuscation_mode.clone())
        } else {
            key.to_string()
        };
        
        // Fetch index object
        let index_result = self.inner.get_object_with_metadata(bucket, &storage_key).await?;
        
        // Check if chunked
        let is_chunked = index_result.metadata
            .get("x-fula-chunked")
            .map(|v| v == "true")
            .unwrap_or(false);
        
        if !is_chunked {
            // Fall back to regular decryption
            return self.get_object_decrypted(bucket, key).await;
        }
        
        // Parse encryption metadata
        let enc_metadata_str = index_result.metadata
            .get("x-fula-encryption")
            .ok_or_else(|| ClientError::Encryption(
                fula_crypto::CryptoError::Decryption("Missing encryption metadata".to_string())
            ))?;
        
        let enc_metadata: serde_json::Value = serde_json::from_str(enc_metadata_str)
            .map_err(|e| ClientError::Encryption(
                fula_crypto::CryptoError::Decryption(e.to_string())
            ))?;
        
        // Unwrap DEK
        let wrapped_dek: EncryptedData = serde_json::from_value(enc_metadata["wrapped_key"].clone())
            .map_err(|e| ClientError::Encryption(
                fula_crypto::CryptoError::Decryption(e.to_string())
            ))?;
        
        let decryptor = Decryptor::new(self.encryption.key_manager.keypair());
        let dek = decryptor.decrypt_dek(&wrapped_dek)?;
        
        // Parse chunked metadata
        let chunked_meta: ChunkedFileMetadata = serde_json::from_value(enc_metadata["chunked"].clone())
            .map_err(|e| ClientError::Encryption(
                fula_crypto::CryptoError::Decryption(e.to_string())
            ))?;
        
        // Create decoder
        let mut decoder = ChunkedDecoder::new(dek, chunked_meta.clone());
        
        // Download and decrypt each chunk
        for chunk_idx in 0..chunked_meta.num_chunks {
            let chunk_key = ChunkedFileMetadata::chunk_key(&storage_key, chunk_idx);
            let chunk_data = self.inner.get_object(bucket, &chunk_key).await?;
            decoder.decrypt_chunk(chunk_idx, &chunk_data)?;
        }
        
        // Finalize and return
        decoder.finalize()
            .map_err(ClientError::Encryption)
    }

    /// Download a byte range from a chunked file (partial read)
    /// 
    /// Only downloads the chunks needed for the requested range.
    pub async fn get_object_range(
        &self,
        bucket: &str,
        key: &str,
        offset: u64,
        length: u64,
    ) -> Result<Bytes> {
        use fula_crypto::chunked::ChunkedFileMetadata;
        
        // Resolve path to storage key
        let storage_key = if self.encryption.metadata_privacy {
            let path_dek = self.encryption.key_manager.derive_path_key(key);
            obfuscate_key(key, &path_dek, self.encryption.obfuscation_mode.clone())
        } else {
            key.to_string()
        };
        
        // Fetch index object
        let index_result = self.inner.get_object_with_metadata(bucket, &storage_key).await?;
        
        // Check if chunked
        let is_chunked = index_result.metadata
            .get("x-fula-chunked")
            .map(|v| v == "true")
            .unwrap_or(false);
        
        if !is_chunked {
            // Fall back to full download and slice
            let full = self.get_object_decrypted(bucket, key).await?;
            let start = offset as usize;
            let end = (offset + length) as usize;
            return Ok(full.slice(start.min(full.len())..end.min(full.len())));
        }
        
        // Parse encryption metadata
        let enc_metadata_str = index_result.metadata
            .get("x-fula-encryption")
            .ok_or_else(|| ClientError::Encryption(
                fula_crypto::CryptoError::Decryption("Missing encryption metadata".to_string())
            ))?;
        
        let enc_metadata: serde_json::Value = serde_json::from_str(enc_metadata_str)
            .map_err(|e| ClientError::Encryption(
                fula_crypto::CryptoError::Decryption(e.to_string())
            ))?;
        
        // Unwrap DEK
        let wrapped_dek: EncryptedData = serde_json::from_value(enc_metadata["wrapped_key"].clone())
            .map_err(|e| ClientError::Encryption(
                fula_crypto::CryptoError::Decryption(e.to_string())
            ))?;
        
        let decryptor = Decryptor::new(self.encryption.key_manager.keypair());
        let dek = decryptor.decrypt_dek(&wrapped_dek)?;
        
        // Parse chunked metadata
        let chunked_meta: ChunkedFileMetadata = serde_json::from_value(enc_metadata["chunked"].clone())
            .map_err(|e| ClientError::Encryption(
                fula_crypto::CryptoError::Decryption(e.to_string())
            ))?;
        
        // Determine which chunks we need
        let needed_chunks = chunked_meta.chunks_for_range(offset, length);
        
        // Download and decrypt only needed chunks
        let mut decrypted_chunks = Vec::new();
        
        for chunk_idx in needed_chunks {
            let chunk_key = ChunkedFileMetadata::chunk_key(&storage_key, chunk_idx);
            let chunk_data = self.inner.get_object(bucket, &chunk_key).await?;
            
            let nonce = chunked_meta.get_chunk_nonce(chunk_idx)
                .map_err(ClientError::Encryption)?;
            
            // Decrypt this chunk with the DEK
            let aead = Aead::new_default(&dek);
            let plaintext = aead.decrypt(&nonce, &chunk_data)
                .map_err(ClientError::Encryption)?;
            
            decrypted_chunks.push((chunk_idx, plaintext));
        }
        
        // Extract the requested range from decrypted chunks
        let chunk_size = chunked_meta.chunk_size as u64;
        let mut result = Vec::with_capacity(length as usize);
        
        for (chunk_idx, chunk_data) in decrypted_chunks {
            let chunk_start = chunk_idx as u64 * chunk_size;
            let chunk_end = chunk_start + chunk_data.len() as u64;
            
            // Calculate overlap with requested range
            let range_start = offset.max(chunk_start);
            let range_end = (offset + length).min(chunk_end);
            
            if range_start < range_end {
                let local_start = (range_start - chunk_start) as usize;
                let local_end = (range_end - chunk_start) as usize;
                result.extend_from_slice(&chunk_data[local_start..local_end]);
            }
        }
        
        Ok(Bytes::from(result))
    }

    /// Check if a file should use chunked upload based on size
    pub fn should_use_chunked(size: usize) -> bool {
        fula_crypto::should_use_chunked(size)
    }
}

/// File metadata (without file content) - optimized for file managers
#[derive(Debug, Clone)]
pub struct FileMetadata {
    /// The obfuscated storage key (what server sees)
    pub storage_key: String,
    /// Original file name/path (decrypted)
    pub original_key: String,
    /// Original file size in bytes (not ciphertext size)
    pub original_size: u64,
    /// Content type (MIME type)
    pub content_type: Option<String>,
    /// Creation timestamp (Unix seconds)
    pub created_at: Option<i64>,
    /// Last modified timestamp (Unix seconds)
    pub modified_at: Option<i64>,
    /// User-defined metadata
    pub user_metadata: HashMap<String, String>,
    /// Whether file is encrypted
    pub is_encrypted: bool,
}

impl FileMetadata {
    /// Get the filename (last component of path)
    pub fn filename(&self) -> &str {
        self.original_key.rsplit('/').next().unwrap_or(&self.original_key)
    }

    /// Get the directory path (without filename)
    pub fn directory(&self) -> &str {
        if let Some(last_slash) = self.original_key.rfind('/') {
            &self.original_key[..last_slash]
        } else {
            ""
        }
    }

    /// Get human-readable size
    pub fn size_human(&self) -> String {
        const KB: u64 = 1024;
        const MB: u64 = KB * 1024;
        const GB: u64 = MB * 1024;
        
        if self.original_size >= GB {
            format!("{:.1} GB", self.original_size as f64 / GB as f64)
        } else if self.original_size >= MB {
            format!("{:.1} MB", self.original_size as f64 / MB as f64)
        } else if self.original_size >= KB {
            format!("{:.1} KB", self.original_size as f64 / KB as f64)
        } else {
            format!("{} B", self.original_size)
        }
    }
}

/// Directory listing result
#[derive(Debug, Clone)]
pub struct DirectoryListing {
    /// Bucket name
    pub bucket: String,
    /// Prefix filter (if any)
    pub prefix: Option<String>,
    /// Files grouped by directory path
    pub directories: HashMap<String, Vec<FileMetadata>>,
}

impl DirectoryListing {
    /// Get all unique directory paths
    pub fn get_directories(&self) -> Vec<&str> {
        self.directories.keys().map(|s| s.as_str()).collect()
    }

    /// Get files in a specific directory
    pub fn get_files(&self, directory: &str) -> Option<&Vec<FileMetadata>> {
        self.directories.get(directory)
    }

    /// Get total file count
    pub fn file_count(&self) -> usize {
        self.directories.values().map(|v| v.len()).sum()
    }

    /// Get total size of all files
    pub fn total_size(&self) -> u64 {
        self.directories.values()
            .flat_map(|v| v.iter())
            .map(|f| f.original_size)
            .sum()
    }
}

/// Decrypted object information including private metadata
#[derive(Debug, Clone)]
pub struct DecryptedObjectInfo {
    /// Decrypted file data
    pub data: Bytes,
    /// Original file name/path (decrypted from private metadata)
    pub original_key: String,
    /// Original file size (not ciphertext size)
    pub original_size: u64,
    /// Original content type
    pub content_type: Option<String>,
    /// User-defined metadata
    pub user_metadata: HashMap<String, String>,
}

/// Report from a bucket key rotation operation
#[derive(Debug, Clone)]
pub struct RotationReport {
    /// Total number of objects in the bucket
    pub total: usize,
    /// Number of objects successfully rotated
    pub rotated: usize,
    /// Number of objects skipped (e.g., forest index)
    pub skipped: usize,
    /// Number of objects that failed to rotate
    pub failed: usize,
    /// Details of failed rotations (path, error message)
    pub failures: Vec<(String, String)>,
}

impl RotationReport {
    /// Check if rotation was fully successful
    pub fn is_success(&self) -> bool {
        self.failed == 0
    }

    /// Get success rate as a percentage
    pub fn success_rate(&self) -> f64 {
        if self.total == 0 {
            100.0
        } else {
            (self.rotated as f64 / (self.total - self.skipped) as f64) * 100.0
        }
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
