//! Sharing operations
//!
//! Functions for creating and accepting share tokens to share
//! encrypted files with other users.

use crate::api::types::*;
use crate::api::error::{FulaError, FulaResult};

// ============================================================================
// Share Token Creation
// ============================================================================

/// Create a share token for a file
///
/// This requires the recipient's public key. The token allows the recipient
/// to decrypt the specified file.
///
/// # Arguments
/// * `client` - The encrypted client handle
/// * `storage_key` - The storage key of the file to share
/// * `recipient_public_key` - The recipient's public key (32 bytes)
/// * `expires_at` - Optional expiration timestamp (Unix epoch seconds)
///
/// Returns a JSON-serialized share token that can be sent to the recipient.
pub fn create_share_token(
    client: &EncryptedClientHandle,
    storage_key: String,
    recipient_public_key: Vec<u8>,
    expires_at: Option<i64>,
) -> FulaResult<String> {
    use fula_crypto::sharing::ShareBuilder;

    // Validate recipient public key length
    if recipient_public_key.len() != 32 {
        return Err(FulaError::InvalidConfig(
            "Recipient public key must be exactly 32 bytes".to_string()
        ));
    }

    let guard = client.inner.read();
    let enc_config = guard.encryption_config();

    // Get owner's keypair and derive DEK for the storage key
    let keypair = enc_config.key_manager().keypair();
    let dek = enc_config.key_manager().derive_path_key(&storage_key);

    // Parse recipient public key
    let mut pk_bytes = [0u8; 32];
    pk_bytes.copy_from_slice(&recipient_public_key);
    let recipient_pk = fula_crypto::PublicKey::from_bytes(&pk_bytes)
        .map_err(|e| FulaError::ShareError(format!("Invalid recipient public key: {}", e)))?;

    // Build share token
    let mut builder = ShareBuilder::new(keypair, &recipient_pk, &dek)
        .path_scope(&storage_key);

    if let Some(ts) = expires_at {
        builder = builder.expires_at(ts);
    }

    let token = builder.build()
        .map_err(|e| FulaError::ShareError(format!("Failed to build share token: {}", e)))?;

    let json = serde_json::to_string(&token)
        .map_err(|e| FulaError::ShareError(format!("Failed to serialize token: {}", e)))?;

    Ok(json)
}

/// Create a share token with a specific mode
///
/// # Arguments
/// * `client` - The encrypted client handle
/// * `storage_key` - The storage key of the file to share
/// * `recipient_public_key` - The recipient's public key (32 bytes)
/// * `mode` - Share mode (Temporal or Snapshot)
/// * `expires_at` - Optional expiration timestamp (Unix epoch seconds)
///
/// Note: Snapshot mode requires additional binding data. This function defaults
/// to temporal mode for Snapshot shares since we don't have content hash info.
pub fn create_share_token_with_mode(
    client: &EncryptedClientHandle,
    storage_key: String,
    recipient_public_key: Vec<u8>,
    mode: ShareMode,
    expires_at: Option<i64>,
) -> FulaResult<String> {
    use fula_crypto::sharing::ShareBuilder;

    // Validate recipient public key length
    if recipient_public_key.len() != 32 {
        return Err(FulaError::InvalidConfig(
            "Recipient public key must be exactly 32 bytes".to_string()
        ));
    }

    let guard = client.inner.read();
    let enc_config = guard.encryption_config();

    // Get owner's keypair and derive DEK for the storage key
    let keypair = enc_config.key_manager().keypair();
    let dek = enc_config.key_manager().derive_path_key(&storage_key);

    // Parse recipient public key
    let mut pk_bytes = [0u8; 32];
    pk_bytes.copy_from_slice(&recipient_public_key);
    let recipient_pk = fula_crypto::PublicKey::from_bytes(&pk_bytes)
        .map_err(|e| FulaError::ShareError(format!("Invalid recipient public key: {}", e)))?;

    // Build share token with appropriate mode
    let builder = ShareBuilder::new(keypair, &recipient_pk, &dek)
        .path_scope(&storage_key);

    // Apply mode (temporal is default, snapshot not supported without binding)
    let builder = match mode {
        ShareMode::Read => builder.read_only(),
        ShareMode::Write => builder.read_write(),
        ShareMode::Temporal => builder.temporal(),
        ShareMode::Snapshot => {
            // Snapshot requires binding data - we'd need content hash, size, etc.
            // For now, fall back to temporal
            builder.temporal()
        }
    };

    // Apply expiration if provided
    let builder = if let Some(ts) = expires_at {
        builder.expires_at(ts)
    } else {
        builder
    };

    let token = builder.build()
        .map_err(|e| FulaError::ShareError(format!("Failed to build share token: {}", e)))?;

    let json = serde_json::to_string(&token)
        .map_err(|e| FulaError::ShareError(format!("Failed to serialize token: {}", e)))?;

    Ok(json)
}

// ============================================================================
// Share Acceptance
// ============================================================================

/// Accept a share token received from another user
pub fn accept_share(client: &EncryptedClientHandle, token_json: String) -> FulaResult<AcceptedShareHandle> {
    let token: fula_crypto::ShareToken = serde_json::from_str(&token_json)
        .map_err(|e| FulaError::ShareError(format!("Invalid token format: {}", e)))?;

    let guard = client.inner.read();
    let accepted = guard.accept_share(&token)
        .map_err(|e| FulaError::ShareError(e.to_string()))?;

    Ok(AcceptedShareHandle { inner: accepted })
}

/// Download a file using an accepted share
pub async fn get_with_share(
    client: &EncryptedClientHandle,
    bucket: String,
    storage_key: String,
    share: &AcceptedShareHandle,
) -> FulaResult<Vec<u8>> {
    let guard = client.inner.read();
    let data = guard.get_object_with_share(&bucket, &storage_key, &share.inner).await?;
    Ok(data.to_vec())
}

/// Download a file directly with a token (accept + download in one step)
pub async fn get_with_token(
    client: &EncryptedClientHandle,
    bucket: String,
    storage_key: String,
    token_json: String,
) -> FulaResult<Vec<u8>> {
    let token: fula_crypto::ShareToken = serde_json::from_str(&token_json)
        .map_err(|e| FulaError::ShareError(format!("Invalid token format: {}", e)))?;

    let guard = client.inner.read();
    let data = guard.get_object_with_token(&bucket, &storage_key, &token).await?;
    Ok(data.to_vec())
}

// ============================================================================
// Share Info
// ============================================================================

/// Get permissions granted by an accepted share
pub fn get_share_permissions(share: &AcceptedShareHandle) -> SharePermissions {
    SharePermissions {
        can_read: share.inner.permissions.can_read,
        can_write: share.inner.permissions.can_write,
        expires_at: share.inner.expires_at,
    }
}

/// Check if an accepted share has expired
pub fn is_share_expired(share: &AcceptedShareHandle) -> bool {
    if let Some(expires_at) = share.inner.expires_at {
        let now = chrono::Utc::now().timestamp();
        now > expires_at
    } else {
        false
    }
}
