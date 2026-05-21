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

/// F8: Buffered, root-hash-verified download by original key.
///
/// Holds the full plaintext in RAM and only returns after the BAO root-hash
/// check passes, closing the mid-stream truncation / chunk-reorder window
/// that the streaming variant accepts. Rejects files larger than
/// `FulaConfig::buffered_download_max_bytes` before any network I/O.
///
/// Prefer this over `get_decrypted` for disaster-recovery consumers that
/// must not observe any plaintext until the whole file has been verified.
pub async fn get_decrypted_buffered(
    client: &EncryptedClientHandle,
    bucket: String,
    key: String,
) -> anyhow::Result<Vec<u8>> {
    let guard = client.inner.read().await;
    let mut buf: Vec<u8> = Vec::new();
    guard
        .get_object_decrypted_buffered_to_writer(&bucket, &key, &mut buf)
        .await?;
    Ok(buf)
}

/// F8: Buffered, root-hash-verified download by storage key.
///
/// See `get_decrypted_buffered` for semantics.
pub async fn get_decrypted_buffered_by_storage_key(
    client: &EncryptedClientHandle,
    bucket: String,
    storage_key: String,
) -> anyhow::Result<Vec<u8>> {
    let guard = client.inner.read().await;
    let mut buf: Vec<u8> = Vec::new();
    guard
        .get_object_decrypted_buffered_to_writer_by_storage_key(&bucket, &storage_key, &mut buf)
        .await?;
    Ok(buf)
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

/// Derive a 32-byte key using Argon2id (memory-hard KDF)
///
/// **IMPORTANT**: Use this function to derive encryption keys from user credentials
/// instead of platform-specific PBKDF2 implementations.
///
/// This ensures both FxFiles (Flutter) and WebUI (WASM) derive the exact same key
/// from the same inputs, with brute-force resistance from Argon2id's memory-hardness.
///
/// Parameters:
/// - Memory: 64 MiB
/// - Iterations: 3
/// - Parallelism: 1 (for cross-platform consistency)
///
/// # Arguments
/// * `context` - A context string used as salt (e.g., "fula-files-v1")
/// * `input` - The input bytes (e.g., UTF-8 encoded "google:{userId}:{email}")
///
/// # Returns
/// * 32-byte derived key
///
/// # Example
/// ```dart
/// // Derive encryption key from Google credentials (same as WebUI):
/// final input = utf8.encode('google:${userId}:${email}');
/// final secretKey = await deriveKey(context: 'fula-files-v1', input: input);
///
/// // Use secretKey for createEncryptedClient
/// ```
pub fn derive_key(context: String, input: Vec<u8>) -> Vec<u8> {
    fula_crypto::hashing::derive_key_argon2id(&context, &input).to_vec()
}

/// Derive a 32-byte sub-key from a high-entropy parent key using
/// BLAKE3's keyed-derivation mode (`blake3::Hasher::new_derive_key`).
///
/// Used by the E2E plan Phase 5 to derive `K_index` and `K_entry_seed`
/// from the user's already-derived `KEK_seed` (= `_encryptionKey` in
/// FxFiles, produced by Argon2id). BLAKE3-derive is the right primitive
/// here because:
/// 1. Input is already key-strength (32 bytes from Argon2id) — no need
///    for memory-hardness again.
/// 2. Output is byte-identical to the Rust side's
///    `derive_entry_signing_seed` / `derive_user_buckets_index_key`,
///    which use the same `blake3::Hasher::new_derive_key(context)`.
///
/// Distinct from [`derive_key`] (Argon2id, memory-hard, for stretching
/// a user-typed passphrase into a master key).
///
/// # Arguments
/// * `context` — domain-separation tag (e.g., `"fula:user-buckets-index:v1"`)
/// * `input`   — parent key bytes (e.g., the 32-byte `KEK_seed`)
///
/// # Returns
/// * 32-byte derived sub-key.
pub fn blake3_derive_key(context: String, input: Vec<u8>) -> Vec<u8> {
    fula_crypto::hashing::derive_key(&context, &input).as_bytes().to_vec()
}

/// Derive a 32-byte key using Argon2id with an EXPLICIT per-user salt.
///
/// This is the audit F-A1 / issue #14 Mode B variant. Compared to
/// [`derive_key`], which uses the `context` bytes as the salt, this
/// variant takes the salt as a separate parameter so callers can
/// supply a per-user random salt — closing the F-A1 finding (the
/// master key is no longer derivable from public identity attributes
/// alone).
///
/// Cross-platform parity: the underlying
/// `fula_crypto::hashing::derive_key_argon2id_with_salt` is pure Rust
/// and is reachable from both native (FxFiles) and WASM (WebUI) so the
/// derived key is byte-identical across platforms for the same
/// (context, input, salt) triple.
///
/// Mode A users continue to call [`derive_key`] (legacy behavior,
/// unchanged). Mode B users call this function with their per-user
/// random salt.
///
/// # Arguments
/// * `context` — domain-separation tag (e.g., `"fula-files-v1-google-pw"`)
/// * `input`   — UTF-8 bytes of the identity-plus-seed string
///               (e.g., `"google:<sub>:<email>:<seed>"`)
/// * `salt`    — per-user random salt; minimum 8 bytes, recommended 32
///
/// # Returns
/// * 32-byte derived key, or an error string if the salt is too short
pub fn derive_key_with_salt(
    context: String,
    input: Vec<u8>,
    salt: Vec<u8>,
) -> Result<Vec<u8>, String> {
    fula_crypto::hashing::derive_key_argon2id_with_salt_checked(&context, &input, &salt)
        .map(|k| k.to_vec())
        .map_err(|e| e.to_string())
}

// ============================================================================
// Mode B / Mode C identity (audit F-A1 + F-A3 redesign, 2026-05-18)
// ============================================================================

/// Compute the **Mode B** `effective_user_id` (OAuth + seed).
///
/// Returns a 16-byte identifier suitable as the JWT `sub` claim (after
/// hex encoding). The seed never leaves the device; whoever can
/// compute this id IS that user.
///
/// `provider` should be a canonical lowercase tag — `"google"` or
/// `"apple"`. `oauth_sub` is the IDP-issued opaque identifier. `seed`
/// is the user-entered passphrase / password; it is NFKC-normalized
/// internally before hashing.
///
/// See `fula_crypto::effective_user_id::compute_effective_user_id_mode_b`
/// for the full derivation specification.
pub fn compute_effective_user_id_mode_b(
    provider: String,
    oauth_sub: String,
    seed: String,
) -> Vec<u8> {
    fula_crypto::effective_user_id::compute_effective_user_id_mode_b(&provider, &oauth_sub, &seed)
        .to_vec()
}

/// Compute the **Mode C** (seed-only) `effective_user_id`.
///
/// Returns a 16-byte identifier suitable as the JWT `sub` claim (after
/// hex encoding). Two callers with the same seed produce the same
/// id — by design (the seed IS the identity). High-entropy seeds make
/// accidental collisions infeasible.
///
/// `seed` is NFKC-normalized internally before hashing.
pub fn compute_effective_user_id_mode_c(seed: String) -> Vec<u8> {
    fula_crypto::effective_user_id::compute_effective_user_id_mode_c(&seed).to_vec()
}

/// Derive a deterministic 32-byte Ed25519 signing-key seed from the
/// user's seed.
///
/// Use the returned bytes to construct an Ed25519 signing key (e.g.,
/// in Dart via the `cryptography` package or the `ed25519` package).
/// The corresponding public key is what the token issuer stores at
/// registration time; subsequent sign-ins use challenge-response
/// (issuer sends a nonce, client signs with this key, issuer verifies).
///
/// Domain-separated from the `effective_user_id` derivations so the
/// signing seed and the user-id are independent functions of the
/// user's input.
pub fn derive_signing_seed(seed: String) -> Vec<u8> {
    fula_crypto::effective_user_id::derive_signing_seed_from_seed(&seed).to_vec()
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
