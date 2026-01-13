//! # Fula JS
//!
//! JavaScript/TypeScript SDK for Fula decentralized storage.
//!
//! This crate provides WASM bindings for browser-based applications
//! using wasm-bindgen. It wraps the fula-client and fula-crypto crates
//! with a clean JavaScript API.
//!
//! ## Usage
//!
//! ```javascript
//! import init, { createEncryptedClient, getDecrypted, deriveKey } from '@functionland/fula-client';
//!
//! await init();
//!
//! const secretKey = deriveKey('my-app-v1', new TextEncoder().encode(userId + email));
//! const client = await createEncryptedClient(
//!   { endpoint: 'https://gateway:9000', accessToken: jwt },
//!   { secretKey, obfuscationMode: 'flatNamespace' }
//! );
//!
//! const data = await getDecrypted(client, 'bucket', '/path/to/file');
//! ```

use wasm_bindgen::prelude::*;
use serde::{Serialize, Deserialize};
use std::sync::Arc;
use bytes::Bytes;

// Use async_lock for WASM (no tokio)
use futures::lock::Mutex;

// ============================================================================
// Initialization
// ============================================================================

/// Initialize the WASM module. Call this before any other functions.
#[wasm_bindgen(start)]
pub fn init() {
    console_error_panic_hook::set_once();
}

// ============================================================================
// Configuration Types (JS <-> Rust via serde)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsFulaConfig {
    /// Gateway endpoint URL (e.g., "https://gateway:9000")
    pub endpoint: String,
    /// JWT access token for authentication
    pub access_token: Option<String>,
    /// Request timeout in seconds (default: 30)
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
}

fn default_timeout() -> u64 { 30 }

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsEncryptionConfig {
    /// 32-byte secret key (base64 encoded or Uint8Array). If null, generates new key.
    pub secret_key: Option<Vec<u8>>,
    /// Enable metadata privacy (obfuscate file names). Default: true
    #[serde(default = "default_true")]
    pub enable_metadata_privacy: bool,
    /// Obfuscation mode: "flatNamespace", "deterministic", "random", "preserveStructure"
    #[serde(default = "default_obfuscation")]
    pub obfuscation_mode: String,
}

fn default_true() -> bool { true }
fn default_obfuscation() -> String { "flatNamespace".to_string() }

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsListOptions {
    pub prefix: Option<String>,
    pub delimiter: Option<String>,
    pub max_keys: Option<u32>,
    pub continuation_token: Option<String>,
}

// ============================================================================
// Result Types (returned to JS)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsPutResult {
    pub etag: String,
    pub version_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsFileMetadata {
    pub storage_key: String,
    pub original_key: String,
    pub size: u64,
    pub content_type: Option<String>,
    pub created_at: Option<i64>,
    pub modified_at: Option<i64>,
    pub is_encrypted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsBucketInfo {
    pub name: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsDirectoryEntry {
    pub name: String,
    pub is_directory: bool,
    pub files: Vec<JsFileMetadata>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsDirectoryListing {
    pub bucket: String,
    pub prefix: Option<String>,
    pub entries: Vec<JsDirectoryEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsSharePermissions {
    pub can_read: bool,
    pub can_write: bool,
    pub expires_at: Option<i64>,
}

// ============================================================================
// Client Handles (opaque types exposed to JS)
// ============================================================================

/// Handle to an encrypted Fula client
#[wasm_bindgen]
pub struct EncryptedClient {
    inner: Arc<Mutex<fula_client::EncryptedClient>>,
}

/// Handle to an accepted share for accessing shared files
#[wasm_bindgen]
pub struct AcceptedShare {
    inner: fula_crypto::AcceptedShare,
}

// ============================================================================
// Client Creation
// ============================================================================

/// Create an encrypted client for secure storage operations
///
/// @param config - Client configuration (endpoint, accessToken, etc.)
/// @param encryption - Encryption configuration (secretKey, obfuscationMode, etc.)
/// @returns EncryptedClient handle
#[wasm_bindgen(js_name = createEncryptedClient)]
pub async fn create_encrypted_client(
    config: JsValue,
    encryption: JsValue,
) -> Result<EncryptedClient, JsError> {
    let config: JsFulaConfig = serde_wasm_bindgen::from_value(config)
        .map_err(|e| JsError::new(&format!("Invalid config: {}", e)))?;
    let encryption: JsEncryptionConfig = serde_wasm_bindgen::from_value(encryption)
        .map_err(|e| JsError::new(&format!("Invalid encryption config: {}", e)))?;

    // Build client config
    let mut client_config = fula_client::Config::new(&config.endpoint)
        .with_timeout(std::time::Duration::from_secs(config.timeout_seconds));

    if let Some(token) = config.access_token {
        client_config = client_config.with_token(token);
    }

    // Build encryption config
    let enc_config = if let Some(secret_key) = encryption.secret_key {
        if secret_key.len() != 32 {
            return Err(JsError::new("Secret key must be exactly 32 bytes"));
        }
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&secret_key);
        let secret = fula_crypto::SecretKey::from_bytes(&key_bytes)
            .map_err(|e| JsError::new(&format!("Invalid secret key: {}", e)))?;
        fula_client::EncryptionConfig::from_secret_key(secret)
    } else {
        fula_client::EncryptionConfig::new()
    };

    let enc_config = enc_config.with_metadata_privacy(encryption.enable_metadata_privacy);
    let enc_config = match encryption.obfuscation_mode.as_str() {
        "deterministic" => enc_config.with_obfuscation_mode(fula_client::KeyObfuscation::DeterministicHash),
        "random" => enc_config.with_obfuscation_mode(fula_client::KeyObfuscation::RandomUuid),
        "preserveStructure" => enc_config.with_obfuscation_mode(fula_client::KeyObfuscation::PreserveStructure),
        _ => enc_config.with_obfuscation_mode(fula_client::KeyObfuscation::FlatNamespace), // Default
    };

    let client = fula_client::EncryptedClient::new(client_config, enc_config)
        .map_err(|e| JsError::new(&format!("Failed to create client: {}", e)))?;

    Ok(EncryptedClient {
        inner: Arc::new(Mutex::new(client)),
    })
}

// ============================================================================
// Encrypted Operations
// ============================================================================

/// Upload encrypted data
///
/// @param client - EncryptedClient handle
/// @param bucket - Bucket name
/// @param key - Object key (path)
/// @param data - Data to upload (Uint8Array)
/// @returns PutResult with etag
#[wasm_bindgen(js_name = putEncrypted)]
pub async fn put_encrypted(
    client: &EncryptedClient,
    bucket: &str,
    key: &str,
    data: &[u8],
) -> Result<JsValue, JsError> {
    let guard = client.inner.lock().await;
    let result = guard.put_object_encrypted(bucket, key, Bytes::from(data.to_vec()))
        .await
        .map_err(|e| JsError::new(&format!("Upload failed: {}", e)))?;

    let js_result = JsPutResult {
        etag: result.etag,
        version_id: result.version_id,
    };
    serde_wasm_bindgen::to_value(&js_result)
        .map_err(|e| JsError::new(&format!("Serialization error: {}", e)))
}

/// Upload encrypted data with content type
#[wasm_bindgen(js_name = putEncryptedWithType)]
pub async fn put_encrypted_with_type(
    client: &EncryptedClient,
    bucket: &str,
    key: &str,
    data: &[u8],
    content_type: &str,
) -> Result<JsValue, JsError> {
    let guard = client.inner.lock().await;
    let result = guard.put_object_encrypted_with_type(bucket, key, Bytes::from(data.to_vec()), Some(content_type))
        .await
        .map_err(|e| JsError::new(&format!("Upload failed: {}", e)))?;

    let js_result = JsPutResult {
        etag: result.etag,
        version_id: result.version_id,
    };
    serde_wasm_bindgen::to_value(&js_result)
        .map_err(|e| JsError::new(&format!("Serialization error: {}", e)))
}

/// Download and decrypt data by original key
///
/// @param client - EncryptedClient handle
/// @param bucket - Bucket name
/// @param key - Original object key (path)
/// @returns Decrypted data as Uint8Array
#[wasm_bindgen(js_name = getDecrypted)]
pub async fn get_decrypted(
    client: &EncryptedClient,
    bucket: &str,
    key: &str,
) -> Result<Vec<u8>, JsError> {
    let guard = client.inner.lock().await;
    let data = guard.get_object_decrypted(bucket, key)
        .await
        .map_err(|e| JsError::new(&format!("Download failed: {}", e)))?;
    Ok(data.to_vec())
}

/// Download and decrypt data by storage key
#[wasm_bindgen(js_name = getDecryptedByStorageKey)]
pub async fn get_decrypted_by_storage_key(
    client: &EncryptedClient,
    bucket: &str,
    storage_key: &str,
) -> Result<Vec<u8>, JsError> {
    let guard = client.inner.lock().await;
    let data = guard.get_object_decrypted_by_storage_key(bucket, storage_key)
        .await
        .map_err(|e| JsError::new(&format!("Download failed: {}", e)))?;
    Ok(data.to_vec())
}

/// Delete an encrypted object
#[wasm_bindgen(js_name = deleteEncrypted)]
pub async fn delete_encrypted(
    client: &EncryptedClient,
    bucket: &str,
    key: &str,
) -> Result<(), JsError> {
    let guard = client.inner.lock().await;
    guard.delete_object(bucket, key)
        .await
        .map_err(|e| JsError::new(&format!("Delete failed: {}", e)))?;
    Ok(())
}

/// List objects with decrypted metadata
///
/// @param client - EncryptedClient handle
/// @param bucket - Bucket name
/// @param options - List options (prefix, maxKeys, etc.)
/// @returns Array of FileMetadata
#[wasm_bindgen(js_name = listDecrypted)]
pub async fn list_decrypted(
    client: &EncryptedClient,
    bucket: &str,
    options: JsValue,
) -> Result<JsValue, JsError> {
    let options: Option<JsListOptions> = if options.is_null() || options.is_undefined() {
        None
    } else {
        Some(serde_wasm_bindgen::from_value(options)
            .map_err(|e| JsError::new(&format!("Invalid options: {}", e)))?)
    };

    let list_opts = options.map(|o| fula_client::ListObjectsOptions {
        prefix: o.prefix,
        delimiter: o.delimiter,
        max_keys: o.max_keys.map(|n| n as usize),
        continuation_token: o.continuation_token,
        start_after: None,
    });

    let guard = client.inner.lock().await;
    let result = guard.list_objects_decrypted(bucket, list_opts)
        .await
        .map_err(|e| JsError::new(&format!("List failed: {}", e)))?;

    let js_result: Vec<JsFileMetadata> = result.into_iter().map(|m| JsFileMetadata {
        storage_key: m.storage_key,
        original_key: m.original_key,
        size: m.original_size,
        content_type: m.content_type,
        created_at: m.created_at,
        modified_at: m.modified_at,
        is_encrypted: m.is_encrypted,
    }).collect();

    serde_wasm_bindgen::to_value(&js_result)
        .map_err(|e| JsError::new(&format!("Serialization error: {}", e)))
}

/// List directory structure
#[wasm_bindgen(js_name = listDirectory)]
pub async fn list_directory(
    client: &EncryptedClient,
    bucket: &str,
    prefix: Option<String>,
) -> Result<JsValue, JsError> {
    let guard = client.inner.lock().await;
    let result = guard.list_directory(bucket, prefix.as_deref())
        .await
        .map_err(|e| JsError::new(&format!("List failed: {}", e)))?;

    let entries: Vec<JsDirectoryEntry> = result.directories
        .into_iter()
        .map(|(name, files)| JsDirectoryEntry {
            name,
            is_directory: true,
            files: files.into_iter().map(|f| JsFileMetadata {
                storage_key: f.storage_key,
                original_key: f.original_key,
                size: f.original_size,
                content_type: f.content_type,
                created_at: f.created_at,
                modified_at: f.modified_at,
                is_encrypted: f.is_encrypted,
            }).collect(),
        })
        .collect();

    let js_result = JsDirectoryListing {
        bucket: result.bucket,
        prefix: result.prefix,
        entries,
    };

    serde_wasm_bindgen::to_value(&js_result)
        .map_err(|e| JsError::new(&format!("Serialization error: {}", e)))
}

// ============================================================================
// Bucket Operations
// ============================================================================

/// List all buckets
#[wasm_bindgen(js_name = listBuckets)]
pub async fn list_buckets(client: &EncryptedClient) -> Result<JsValue, JsError> {
    let guard = client.inner.lock().await;
    let result = guard.list_buckets()
        .await
        .map_err(|e| JsError::new(&format!("List buckets failed: {}", e)))?;

    let js_result: Vec<JsBucketInfo> = result.buckets.into_iter().map(|b| JsBucketInfo {
        name: b.name,
        created_at: b.creation_date.timestamp(),
    }).collect();

    serde_wasm_bindgen::to_value(&js_result)
        .map_err(|e| JsError::new(&format!("Serialization error: {}", e)))
}

/// Create a bucket
#[wasm_bindgen(js_name = createBucket)]
pub async fn create_bucket(client: &EncryptedClient, name: &str) -> Result<(), JsError> {
    let guard = client.inner.lock().await;
    guard.create_bucket(name)
        .await
        .map_err(|e| JsError::new(&format!("Create bucket failed: {}", e)))?;
    Ok(())
}

/// Delete a bucket
#[wasm_bindgen(js_name = deleteBucket)]
pub async fn delete_bucket(client: &EncryptedClient, name: &str) -> Result<(), JsError> {
    let guard = client.inner.lock().await;
    guard.delete_bucket(name)
        .await
        .map_err(|e| JsError::new(&format!("Delete bucket failed: {}", e)))?;
    Ok(())
}

// ============================================================================
// Key Management
// ============================================================================

/// Export the secret key for backup (32 bytes)
///
/// Store this securely - it's the master encryption key!
#[wasm_bindgen(js_name = exportSecretKey)]
pub async fn export_secret_key(client: &EncryptedClient) -> Vec<u8> {
    let guard = client.inner.lock().await;
    guard.encryption_config().export_secret_key().as_bytes().to_vec()
}

/// Get the public key for sharing (32 bytes)
#[wasm_bindgen(js_name = getPublicKey)]
pub async fn get_public_key(client: &EncryptedClient) -> Vec<u8> {
    let guard = client.inner.lock().await;
    guard.encryption_config().public_key().as_bytes().to_vec()
}

/// Derive a 32-byte key from context and input
///
/// Use this to derive encryption keys from Google credentials:
/// ```javascript
/// const key = deriveKey('my-app-v1', new TextEncoder().encode(userId + email));
/// ```
#[wasm_bindgen(js_name = deriveKey)]
pub fn derive_key(context: &str, input: &[u8]) -> Vec<u8> {
    fula_crypto::hashing::derive_key(context, input).as_bytes().to_vec()
}

// ============================================================================
// Sharing
// ============================================================================

/// Accept a share token and get an AcceptedShare for accessing shared files
///
/// @param client - EncryptedClient handle
/// @param token_json - JSON string containing the ShareToken
/// @returns AcceptedShare handle
#[wasm_bindgen(js_name = acceptShare)]
pub async fn accept_share(
    client: &EncryptedClient,
    token_json: &str,
) -> Result<AcceptedShare, JsError> {
    let token: fula_crypto::ShareToken = serde_json::from_str(token_json)
        .map_err(|e| JsError::new(&format!("Invalid share token JSON: {}", e)))?;

    let guard = client.inner.lock().await;
    let accepted = guard.accept_share(&token)
        .map_err(|e| JsError::new(&format!("Failed to accept share: {}", e)))?;

    Ok(AcceptedShare { inner: accepted })
}

/// Get a shared file using an accepted share
///
/// @param client - EncryptedClient handle
/// @param bucket - Bucket name
/// @param storage_key - Storage key of the shared file
/// @param share - AcceptedShare handle
/// @returns Decrypted data as Uint8Array
#[wasm_bindgen(js_name = getWithShare)]
pub async fn get_with_share(
    client: &EncryptedClient,
    bucket: &str,
    storage_key: &str,
    share: &AcceptedShare,
) -> Result<Vec<u8>, JsError> {
    let guard = client.inner.lock().await;
    let data = guard.get_object_with_share(bucket, storage_key, &share.inner)
        .await
        .map_err(|e| JsError::new(&format!("Failed to get shared file: {}", e)))?;
    Ok(data.to_vec())
}

/// Get a shared file directly using a share token JSON
///
/// @param client - EncryptedClient handle
/// @param bucket - Bucket name
/// @param storage_key - Storage key of the shared file
/// @param token_json - JSON string containing the ShareToken
/// @returns Decrypted data as Uint8Array
#[wasm_bindgen(js_name = getWithToken)]
pub async fn get_with_token(
    client: &EncryptedClient,
    bucket: &str,
    storage_key: &str,
    token_json: &str,
) -> Result<Vec<u8>, JsError> {
    let token: fula_crypto::ShareToken = serde_json::from_str(token_json)
        .map_err(|e| JsError::new(&format!("Invalid share token JSON: {}", e)))?;

    let guard = client.inner.lock().await;
    let data = guard.get_object_with_token(bucket, storage_key, &token)
        .await
        .map_err(|e| JsError::new(&format!("Failed to get shared file: {}", e)))?;
    Ok(data.to_vec())
}

/// Get share permissions
#[wasm_bindgen(js_name = getSharePermissions)]
pub fn get_share_permissions(share: &AcceptedShare) -> Result<JsValue, JsError> {
    let perms = JsSharePermissions {
        can_read: share.inner.permissions.can_read,
        can_write: share.inner.permissions.can_write,
        expires_at: share.inner.expires_at,
    };
    serde_wasm_bindgen::to_value(&perms)
        .map_err(|e| JsError::new(&format!("Serialization error: {}", e)))
}

/// Check if a share is still valid (not expired)
#[wasm_bindgen(js_name = isShareValid)]
pub fn is_share_valid(share: &AcceptedShare) -> bool {
    share.inner.is_valid()
}

// ============================================================================
// Utility Functions
// ============================================================================

/// Check if client uses FlatNamespace mode
#[wasm_bindgen(js_name = isFlatNamespace)]
pub async fn is_flat_namespace(client: &EncryptedClient) -> bool {
    let guard = client.inner.lock().await;
    guard.is_flat_namespace()
}

/// Get SDK version
#[wasm_bindgen(js_name = getVersion)]
pub fn get_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[wasm_bindgen_test]
    fn test_derive_key() {
        let key1 = derive_key("test-context", b"input1");
        let key2 = derive_key("test-context", b"input2");
        let key3 = derive_key("test-context", b"input1");

        assert_eq!(key1.len(), 32);
        assert_ne!(key1, key2);
        assert_eq!(key1, key3); // Deterministic
    }

    #[wasm_bindgen_test]
    fn test_version() {
        let version = get_version();
        assert!(!version.is_empty());
    }
}
