//! Sharing operations
//!
//! Functions for creating and accepting share tokens to share
//! encrypted files with other users.

use crate::api::types::*;

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
/// * `bucket` - The bucket containing the file
/// * `storage_key` - The storage key of the file to share
/// * `recipient_public_key` - The recipient's public key (32 bytes)
/// * `expires_at` - Optional expiration timestamp (Unix epoch seconds)
///
/// Returns a JSON-serialized share token that can be sent to the recipient.
pub async fn create_share_token(
    client: &EncryptedClientHandle,
    bucket: String,
    storage_key: String,
    recipient_public_key: Vec<u8>,
    expires_at: Option<i64>,
) -> anyhow::Result<String> {
    use fula_crypto::sharing::ShareBuilder;
    use fula_crypto::hpke::{Decryptor, EncryptedData};

    // Validate recipient public key length
    if recipient_public_key.len() != 32 {
        anyhow::bail!("Recipient public key must be exactly 32 bytes");
    }

    let guard = &*client.inner;
    let enc_config = guard.encryption_config();

    // Get owner's keypair
    let keypair = enc_config.key_manager().keypair();

    // Issue #11: fetch the wrapped-DEK metadata with offline fallback.
    // Online: HEAD against master (unchanged from prior behavior).
    // Offline / master unreachable: fall back to forest entry's
    // user_metadata["x-fula-encryption"] (populated at upload by
    // encryption.rs:5955-5968).
    let enc_metadata_str = guard
        .get_object_encryption_metadata_with_fallback(&bucket, &storage_key)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to fetch object metadata: {}", e))?;

    let enc_metadata: serde_json::Value = serde_json::from_str(&enc_metadata_str)
        .map_err(|e| anyhow::anyhow!("Failed to parse encryption metadata: {}", e))?;

    // Extract and unwrap the actual DEK used during upload
    let wrapped_key: EncryptedData = serde_json::from_value(
        enc_metadata["wrapped_key"].clone()
    ).map_err(|e| anyhow::anyhow!("Failed to parse wrapped_key: {}", e))?;

    let decryptor = Decryptor::new(keypair);
    let dek = decryptor.decrypt_dek(&wrapped_key)
        .map_err(|e| anyhow::anyhow!("Failed to unwrap DEK: {}", e))?;

    // Parse recipient public key
    let mut pk_bytes = [0u8; 32];
    pk_bytes.copy_from_slice(&recipient_public_key);
    let recipient_pk = fula_crypto::PublicKey::from_bytes(&pk_bytes)
        .map_err(|e| anyhow::anyhow!("Invalid recipient public key: {}", e))?;

    // Build share token with the ACTUAL DEK from upload
    let mut builder = ShareBuilder::new(keypair, &recipient_pk, &dek)
        .path_scope(&storage_key);

    if let Some(ts) = expires_at {
        builder = builder.expires_at(ts);
    }

    // Include nonce in share token so recipient can decrypt without S3 metadata headers
    if let Some(nonce_str) = enc_metadata["nonce"].as_str() {
        builder = builder.nonce(nonce_str);
    }

    // Stamp the content encryption version so the recipient knows whether to
    // expect AAD binding (v4+) or bare AEAD (v2). Without this, fula-client
    // has to guess for single-object shares, which can mis-handle edge cases.
    if let Some(v) = enc_metadata["version"].as_u64() {
        builder = builder.encryption_version(v as u8);
    }

    // Include chunked metadata for large files (> 768KB)
    if enc_metadata.get("chunked").is_some() {
        let chunked_json = serde_json::to_string(&enc_metadata["chunked"])
            .map_err(|e| anyhow::anyhow!("Failed to serialize chunked metadata: {}", e))?;
        builder = builder.chunked_metadata(chunked_json);
    }

    let token = builder.build()
        .map_err(|e| anyhow::anyhow!("Failed to build share token: {}", e))?;

    let json = serde_json::to_string(&token)
        .map_err(|e| anyhow::anyhow!("Failed to serialize token: {}", e))?;

    Ok(json)
}

/// Create a share token with a specific mode
///
/// # Arguments
/// * `client` - The encrypted client handle
/// * `bucket` - The bucket containing the file
/// * `storage_key` - The storage key of the file to share
/// * `recipient_public_key` - The recipient's public key (32 bytes)
/// * `mode` - Share mode (Temporal or Snapshot)
/// * `expires_at` - Optional expiration timestamp (Unix epoch seconds)
///
/// Note: Snapshot mode requires additional binding data. This function defaults
/// to temporal mode for Snapshot shares since we don't have content hash info.
pub async fn create_share_token_with_mode(
    client: &EncryptedClientHandle,
    bucket: String,
    storage_key: String,
    recipient_public_key: Vec<u8>,
    mode: ShareMode,
    expires_at: Option<i64>,
) -> anyhow::Result<String> {
    use fula_crypto::sharing::ShareBuilder;
    use fula_crypto::hpke::{Decryptor, EncryptedData};

    // Validate recipient public key length
    if recipient_public_key.len() != 32 {
        anyhow::bail!("Recipient public key must be exactly 32 bytes");
    }

    let guard = &*client.inner;
    let enc_config = guard.encryption_config();

    // Get owner's keypair
    let keypair = enc_config.key_manager().keypair();

    // Issue #11: fetch the wrapped-DEK metadata with offline fallback.
    // Online: HEAD against master (unchanged from prior behavior).
    // Offline / master unreachable: fall back to forest entry's
    // user_metadata["x-fula-encryption"] (populated at upload by
    // encryption.rs:5955-5968).
    let enc_metadata_str = guard
        .get_object_encryption_metadata_with_fallback(&bucket, &storage_key)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to fetch object metadata: {}", e))?;

    let enc_metadata: serde_json::Value = serde_json::from_str(&enc_metadata_str)
        .map_err(|e| anyhow::anyhow!("Failed to parse encryption metadata: {}", e))?;

    // Extract and unwrap the actual DEK used during upload
    let wrapped_key: EncryptedData = serde_json::from_value(
        enc_metadata["wrapped_key"].clone()
    ).map_err(|e| anyhow::anyhow!("Failed to parse wrapped_key: {}", e))?;

    let decryptor = Decryptor::new(keypair);
    let dek = decryptor.decrypt_dek(&wrapped_key)
        .map_err(|e| anyhow::anyhow!("Failed to unwrap DEK: {}", e))?;

    // Parse recipient public key
    let mut pk_bytes = [0u8; 32];
    pk_bytes.copy_from_slice(&recipient_public_key);
    let recipient_pk = fula_crypto::PublicKey::from_bytes(&pk_bytes)
        .map_err(|e| anyhow::anyhow!("Invalid recipient public key: {}", e))?;

    // Build share token with the ACTUAL DEK from upload
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

    // Include nonce in share token so recipient can decrypt without S3 metadata headers
    let builder = if let Some(nonce_str) = enc_metadata["nonce"].as_str() {
        builder.nonce(nonce_str)
    } else {
        builder
    };

    // Stamp the content encryption version so the recipient knows whether to
    // expect AAD binding (v4+) or bare AEAD (v2). Without this, fula-client
    // has to guess for single-object shares, which can mis-handle edge cases.
    let builder = if let Some(v) = enc_metadata["version"].as_u64() {
        builder.encryption_version(v as u8)
    } else {
        builder
    };

    // Include chunked metadata for large files (> 768KB)
    let builder = if enc_metadata.get("chunked").is_some() {
        let chunked_json = serde_json::to_string(&enc_metadata["chunked"])
            .map_err(|e| anyhow::anyhow!("Failed to serialize chunked metadata: {}", e))?;
        builder.chunked_metadata(chunked_json)
    } else {
        builder
    };

    let token = builder.build()
        .map_err(|e| anyhow::anyhow!("Failed to build share token: {}", e))?;

    let json = serde_json::to_string(&token)
        .map_err(|e| anyhow::anyhow!("Failed to serialize token: {}", e))?;

    Ok(json)
}

// ============================================================================
// Secret Wrapping (Method-2 AI pairing — no client / no stored file needed)
// ============================================================================

/// Wrap an ARBITRARY 32-byte secret for a recipient X25519 public key,
/// producing a serialized v5 ShareToken (JSON).
///
/// Unlike [`create_share_token`], this needs NO client and NO previously-stored
/// file: it wraps the raw 32 bytes you pass in. It is the producer side of the
/// secure "Method 2" AI-pairing — FxFiles' fail-closed `CollabLinkSecretWrapper`
/// calls this to wrap a collaboration link secret for an AI/MCP recipient's
/// public key. The recipient (the local MCP's
/// `McpIdentity::accept_link_secret`, i.e. `fula_crypto` `ShareRecipient`)
/// opens the token to recover the EXACT secret bytes.
///
/// The sender/owner keypair is generated EPHEMERALLY inside `fula-crypto`: the
/// v5 token AAD binds the RECIPIENT public key, not the sender, so the caller
/// needs no stable identity of its own.
///
/// # Arguments
/// * `secret` - the 32 raw secret bytes to wrap.
/// * `recipient_public_key` - the recipient's 32-byte X25519 public key.
/// * `path_scope` - optional scope string bound into the token (defaults to `"/"`).
/// * `expires_in_seconds` - optional expiry as seconds-from-now (`None` = never).
///
/// Returns the JSON-serialized ShareToken. Fails closed (returns `Err`) if
/// `secret` or `recipient_public_key` is not exactly 32 bytes.
pub async fn wrap_secret_for_recipient(
    secret: Vec<u8>,
    recipient_public_key: Vec<u8>,
    path_scope: Option<String>,
    expires_in_seconds: Option<i64>,
) -> anyhow::Result<String> {
    let token = fula_crypto::sharing::wrap_secret_for_recipient(
        &secret,
        &recipient_public_key,
        path_scope.as_deref(),
        expires_in_seconds,
    )
    .map_err(|e| anyhow::anyhow!("Failed to wrap secret for recipient: {}", e))?;

    serde_json::to_string(&token)
        .map_err(|e| anyhow::anyhow!("Failed to serialize share token: {}", e))
}

// ============================================================================
// Share Acceptance
// ============================================================================

/// Accept a share token received from another user
pub async fn accept_share(client: &EncryptedClientHandle, token_json: String) -> anyhow::Result<AcceptedShareHandle> {
    let token: fula_crypto::ShareToken = serde_json::from_str(&token_json)
        .map_err(|e| anyhow::anyhow!("Invalid token format: {}", e))?;

    let guard = &*client.inner;
    let accepted = guard.accept_share(&token)
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;

    Ok(AcceptedShareHandle { inner: accepted })
}

/// Download a file using an accepted share
pub async fn get_with_share(
    client: &EncryptedClientHandle,
    bucket: String,
    storage_key: String,
    original_key: String,
    share: &AcceptedShareHandle,
) -> anyhow::Result<Vec<u8>> {
    let guard = &*client.inner;
    let data = guard.get_object_with_share(&bucket, &storage_key, &original_key, &share.inner).await?;
    Ok(data.to_vec())
}

/// Download a file directly with a token (accept + download in one step)
pub async fn get_with_token(
    client: &EncryptedClientHandle,
    bucket: String,
    storage_key: String,
    original_key: String,
    token_json: String,
) -> anyhow::Result<Vec<u8>> {
    let token: fula_crypto::ShareToken = serde_json::from_str(&token_json)
        .map_err(|e| anyhow::anyhow!("Invalid token format: {}", e))?;

    let guard = &*client.inner;
    let data = guard.get_object_with_token(&bucket, &storage_key, &original_key, &token).await?;
    Ok(data.to_vec())
}

// ============================================================================
// Share Info
// ============================================================================

/// Get permissions granted by an accepted share
pub async fn get_share_permissions(share: &AcceptedShareHandle) -> SharePermissions {
    SharePermissions {
        can_read: share.inner.permissions.can_read,
        can_write: share.inner.permissions.can_write,
        expires_at: share.inner.expires_at,
    }
}

/// Check if an accepted share has expired
pub async fn is_share_expired(share: &AcceptedShareHandle) -> bool {
    if let Some(expires_at) = share.inner.expires_at {
        let now = chrono::Utc::now().timestamp();
        now > expires_at
    } else {
        false
    }
}
