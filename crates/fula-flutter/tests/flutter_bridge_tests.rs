//! Integration tests for fula-flutter bridge
//!
//! These tests verify that the Flutter bridge wrapper types and functions
//! work correctly for both native and WASM builds.

use fula_flutter::api::types::*;
use fula_flutter::api::error::FulaError;

// ============================================================================
// Configuration Type Tests
// ============================================================================

#[test]
fn test_fula_config_default() {
    let config = FulaConfig::default();
    assert_eq!(config.endpoint, "http://localhost:9000");
    assert!(config.access_token.is_none());
    assert_eq!(config.timeout_seconds, 30);
    assert_eq!(config.max_retries, 3);
    // F10 default: 5 minutes.
    assert_eq!(config.per_chunk_download_timeout_seconds, 300);
    // F8 default: 256 MiB ceiling on buffered downloads.
    assert_eq!(config.buffered_download_max_bytes, 256 * 1024 * 1024);
}

#[test]
fn test_fula_config_with_values() {
    // Construct via `..Default::default()` so adding new fields to
    // `FulaConfig` (e.g., Phase 2.x / 3.3 / 19) doesn't require
    // updating this test. The pre-Phase-2.x fields below are the
    // ones this test specifically exercises; everything else inherits
    // from `Default::default()` which is the documented backward-
    // compat shape (all new flags off / empty).
    let config = FulaConfig {
        endpoint: "https://api.example.com".to_string(),
        access_token: Some("test-token".to_string()),
        timeout_seconds: 60,
        max_retries: 5,
        per_chunk_download_timeout_seconds: 120,
        buffered_download_max_bytes: 64 * 1024 * 1024,
        ..Default::default()
    };
    assert_eq!(config.endpoint, "https://api.example.com");
    assert_eq!(config.access_token, Some("test-token".to_string()));
    assert_eq!(config.timeout_seconds, 60);
    assert_eq!(config.max_retries, 5);
    assert_eq!(config.per_chunk_download_timeout_seconds, 120);
    assert_eq!(config.buffered_download_max_bytes, 64 * 1024 * 1024);
}

#[test]
fn test_encryption_config_default() {
    let config = EncryptionConfig::default();
    assert!(config.secret_key.is_none());
    assert!(config.enable_metadata_privacy);
    assert_eq!(config.obfuscation_mode, ObfuscationMode::Deterministic);
}

#[test]
fn test_encryption_config_with_key() {
    let key = vec![0u8; 32];
    let config = EncryptionConfig {
        secret_key: Some(key.clone()),
        enable_metadata_privacy: false,
        obfuscation_mode: ObfuscationMode::Random,
    };
    assert_eq!(config.secret_key, Some(key));
    assert!(!config.enable_metadata_privacy);
    assert_eq!(config.obfuscation_mode, ObfuscationMode::Random);
}

#[test]
fn test_pinning_config() {
    let config = PinningConfig {
        endpoint: "https://pin.example.com".to_string(),
        token: "pinning-token".to_string(),
    };
    assert_eq!(config.endpoint, "https://pin.example.com");
    assert_eq!(config.token, "pinning-token");
}

// ============================================================================
// Result Type Tests
// ============================================================================

#[test]
fn test_put_result() {
    let result = PutResult {
        etag: "abc123".to_string(),
        version_id: Some("v1".to_string()),
    };
    assert_eq!(result.etag, "abc123");
    assert_eq!(result.version_id, Some("v1".to_string()));
}

#[test]
fn test_put_result_no_version() {
    let result = PutResult {
        etag: "def456".to_string(),
        version_id: None,
    };
    assert_eq!(result.etag, "def456");
    assert!(result.version_id.is_none());
}

#[test]
fn test_head_result() {
    let result = HeadResult {
        etag: "etag123".to_string(),
        content_type: Some("application/json".to_string()),
        size: 1024,
        last_modified: 1704067200,
        metadata: vec![
            MetadataEntry {
                key: "author".to_string(),
                value: "test".to_string(),
            },
        ],
    };
    assert_eq!(result.size, 1024);
    assert_eq!(result.content_type, Some("application/json".to_string()));
    assert_eq!(result.metadata.len(), 1);
    assert_eq!(result.metadata[0].key, "author");
}

#[test]
fn test_copy_result() {
    let result = CopyResult {
        etag: "copy-etag".to_string(),
        last_modified: 1704153600,
    };
    assert_eq!(result.etag, "copy-etag");
    assert_eq!(result.last_modified, 1704153600);
}

#[test]
fn test_list_objects_result() {
    let result = ListObjectsResult {
        objects: vec![
            ObjectInfo {
                key: "file1.txt".to_string(),
                size: 100,
                last_modified: 1704067200,
                etag: "etag1".to_string(),
                storage_class: "STANDARD".to_string(),
            },
            ObjectInfo {
                key: "file2.txt".to_string(),
                size: 200,
                last_modified: 1704153600,
                etag: "etag2".to_string(),
                storage_class: "STANDARD".to_string(),
            },
        ],
        common_prefixes: vec!["folder/".to_string()],
        is_truncated: false,
        next_token: None,
    };
    assert_eq!(result.objects.len(), 2);
    assert_eq!(result.common_prefixes.len(), 1);
    assert!(!result.is_truncated);
    assert!(result.next_token.is_none());
}

#[test]
fn test_list_objects_result_truncated() {
    let result = ListObjectsResult {
        objects: vec![],
        common_prefixes: vec![],
        is_truncated: true,
        next_token: Some("continuation-token".to_string()),
    };
    assert!(result.is_truncated);
    assert_eq!(result.next_token, Some("continuation-token".to_string()));
}

// ============================================================================
// Info Type Tests
// ============================================================================

#[test]
fn test_bucket_info() {
    let info = BucketInfo {
        name: "my-bucket".to_string(),
        created_at: 1704067200,
    };
    assert_eq!(info.name, "my-bucket");
    assert_eq!(info.created_at, 1704067200);
}

#[test]
fn test_object_info() {
    let info = ObjectInfo {
        key: "path/to/file.txt".to_string(),
        size: 4096,
        last_modified: 1704067200,
        etag: "obj-etag".to_string(),
        storage_class: "STANDARD".to_string(),
    };
    assert_eq!(info.key, "path/to/file.txt");
    assert_eq!(info.size, 4096);
}

#[test]
fn test_file_metadata() {
    let metadata = FileMetadata {
        storage_key: "e/abc123".to_string(),
        original_key: "/documents/report.pdf".to_string(),
        size: 102400,
        content_type: Some("application/pdf".to_string()),
        created_at: Some(1704067200),
        modified_at: Some(1704153600),
        is_encrypted: true,
    };
    assert_eq!(metadata.storage_key, "e/abc123");
    assert_eq!(metadata.original_key, "/documents/report.pdf");
    assert_eq!(metadata.size, 102400);
    assert!(metadata.is_encrypted);
}

#[test]
fn test_decrypted_object_info() {
    let info = DecryptedObjectInfo {
        data: vec![1, 2, 3, 4, 5],
        original_key: "/test/file.bin".to_string(),
        size: 5,
        content_type: Some("application/octet-stream".to_string()),
        metadata: vec![],
    };
    assert_eq!(info.data.len(), 5);
    assert_eq!(info.original_key, "/test/file.bin");
    assert_eq!(info.size, 5);
}

#[test]
fn test_directory_listing() {
    let listing = DirectoryListing {
        bucket: "test-bucket".to_string(),
        prefix: Some("/photos/".to_string()),
        entries: vec![
            DirectoryEntry {
                name: "vacation".to_string(),
                is_directory: true,
                files: vec![],
            },
            DirectoryEntry {
                name: "profile.jpg".to_string(),
                is_directory: false,
                files: vec![
                    FileMetadata {
                        storage_key: "e/xyz789".to_string(),
                        original_key: "/photos/profile.jpg".to_string(),
                        size: 50000,
                        content_type: Some("image/jpeg".to_string()),
                        created_at: None,
                        modified_at: None,
                        is_encrypted: true,
                    },
                ],
            },
        ],
    };
    assert_eq!(listing.bucket, "test-bucket");
    assert_eq!(listing.prefix, Some("/photos/".to_string()));
    assert_eq!(listing.entries.len(), 2);
    assert!(listing.entries[0].is_directory);
    assert!(!listing.entries[1].is_directory);
}

#[test]
fn test_metadata_entry() {
    let entry = MetadataEntry {
        key: "custom-header".to_string(),
        value: "custom-value".to_string(),
    };
    assert_eq!(entry.key, "custom-header");
    assert_eq!(entry.value, "custom-value");
}

#[test]
fn test_object_metadata() {
    let metadata = ObjectMetadata {
        content_type: Some("text/plain".to_string()),
        cache_control: Some("max-age=3600".to_string()),
        user_metadata: vec![
            MetadataEntry {
                key: "author".to_string(),
                value: "test-user".to_string(),
            },
        ],
    };
    assert_eq!(metadata.content_type, Some("text/plain".to_string()));
    assert_eq!(metadata.cache_control, Some("max-age=3600".to_string()));
    assert_eq!(metadata.user_metadata.len(), 1);
}

#[test]
fn test_object_metadata_default() {
    let metadata = ObjectMetadata::default();
    assert!(metadata.content_type.is_none());
    assert!(metadata.cache_control.is_none());
    assert!(metadata.user_metadata.is_empty());
}

#[test]
fn test_list_options() {
    let options = ListOptions {
        prefix: Some("/documents/".to_string()),
        delimiter: Some("/".to_string()),
        max_keys: Some(100),
        continuation_token: None,
    };
    assert_eq!(options.prefix, Some("/documents/".to_string()));
    assert_eq!(options.delimiter, Some("/".to_string()));
    assert_eq!(options.max_keys, Some(100));
    assert!(options.continuation_token.is_none());
}

#[test]
fn test_list_options_default() {
    let options = ListOptions::default();
    assert!(options.prefix.is_none());
    assert!(options.delimiter.is_none());
    assert!(options.max_keys.is_none());
    assert!(options.continuation_token.is_none());
}

// ============================================================================
// Sharing Type Tests
// ============================================================================

#[test]
fn test_share_mode_variants() {
    let read = ShareMode::Read;
    let write = ShareMode::Write;
    let temporal = ShareMode::Temporal;
    let snapshot = ShareMode::Snapshot;

    assert_eq!(read, ShareMode::Read);
    assert_eq!(write, ShareMode::Write);
    assert_eq!(temporal, ShareMode::Temporal);
    assert_eq!(snapshot, ShareMode::Snapshot);
}

#[test]
fn test_share_permissions() {
    let perms = SharePermissions {
        can_read: true,
        can_write: false,
        expires_at: Some(1704240000),
    };
    assert!(perms.can_read);
    assert!(!perms.can_write);
    assert_eq!(perms.expires_at, Some(1704240000));
}

#[test]
fn test_share_permissions_no_expiry() {
    let perms = SharePermissions {
        can_read: true,
        can_write: true,
        expires_at: None,
    };
    assert!(perms.can_read);
    assert!(perms.can_write);
    assert!(perms.expires_at.is_none());
}

// ============================================================================
// Rotation Type Tests
// ============================================================================

#[test]
fn test_rotation_report() {
    let report = RotationReport {
        total: 100,
        rotated: 95,
        skipped: 3,
        failed: 2,
        failures: vec![
            RotationFailure {
                storage_key: "e/fail1".to_string(),
                error: "Connection timeout".to_string(),
            },
            RotationFailure {
                storage_key: "e/fail2".to_string(),
                error: "Invalid key format".to_string(),
            },
        ],
    };
    assert_eq!(report.total, 100);
    assert_eq!(report.rotated, 95);
    assert_eq!(report.skipped, 3);
    assert_eq!(report.failed, 2);
    assert_eq!(report.failures.len(), 2);
}

#[test]
fn test_rotation_report_helpers() {
    let report = RotationReport {
        total: 50,
        rotated: 45,
        skipped: 5,
        failed: 0,
        failures: vec![],
    };
    assert!(report.is_success());
    assert_eq!(report.success_rate(), 100.0);
}

#[test]
fn test_rotation_report_with_failures() {
    let report = RotationReport {
        total: 100,
        rotated: 80,
        skipped: 10,
        failed: 10,
        failures: vec![
            RotationFailure {
                storage_key: "key1".to_string(),
                error: "error1".to_string(),
            },
        ],
    };
    assert!(!report.is_success());
    assert_eq!(report.success_rate(), 90.0);
}

#[test]
fn test_rotation_failure() {
    let failure = RotationFailure {
        storage_key: "e/problem-key".to_string(),
        error: "Decryption failed".to_string(),
    };
    assert_eq!(failure.storage_key, "e/problem-key");
    assert_eq!(failure.error, "Decryption failed");
}

// ============================================================================
// Multipart Upload Type Tests
// ============================================================================

#[test]
fn test_upload_progress_new() {
    let progress = UploadProgress::new(500_000, 1_000_000, 1, 2);
    assert_eq!(progress.bytes_uploaded, 500_000);
    assert_eq!(progress.total_bytes, 1_000_000);
    assert_eq!(progress.current_part, 1);
    assert_eq!(progress.total_parts, 2);
    assert_eq!(progress.percentage, 50.0);
}

#[test]
fn test_upload_progress_complete() {
    let progress = UploadProgress::new(1_000_000, 1_000_000, 2, 2);
    assert_eq!(progress.percentage, 100.0);
}

#[test]
fn test_upload_progress_zero_total() {
    let progress = UploadProgress::new(0, 0, 1, 1);
    assert_eq!(progress.percentage, 0.0);
}

#[test]
fn test_upload_progress_struct() {
    let progress = UploadProgress {
        bytes_uploaded: 10_000,
        total_bytes: 50_000,
        current_part: 1,
        total_parts: 5,
        percentage: 20.0,
    };
    assert_eq!(progress.bytes_uploaded, 10_000);
    assert_eq!(progress.total_bytes, 50_000);
    assert_eq!(progress.percentage, 20.0);
}

// ============================================================================
// Error Type Tests
// ============================================================================

#[test]
fn test_fula_error_variants() {
    let network_err = FulaError::Network("Connection refused".to_string());
    let not_found = FulaError::NotFound {
        bucket: "bucket".to_string(),
        key: "key".to_string(),
    };
    let bucket_not_found = FulaError::BucketNotFound("bucket".to_string());
    let access_denied = FulaError::AccessDenied("No permission".to_string());
    let encryption = FulaError::Encryption("Invalid key".to_string());
    let invalid_config = FulaError::InvalidConfig("Bad endpoint".to_string());
    let upload_failed = FulaError::UploadFailed("Part failed".to_string());
    let download_failed = FulaError::DownloadFailed("Stream error".to_string());
    let xml_parse = FulaError::XmlParse("Invalid XML".to_string());
    let invalid_response = FulaError::InvalidResponse("Bad format".to_string());
    let share_error = FulaError::ShareError("Token expired".to_string());
    let forest_error = FulaError::ForestError("Corrupt index".to_string());
    let internal = FulaError::Internal("Unexpected state".to_string());

    // Verify Display implementation works
    assert!(format!("{}", network_err).contains("Connection refused"));
    assert!(format!("{}", not_found).contains("bucket"));
    assert!(format!("{}", bucket_not_found).contains("bucket"));
    assert!(format!("{}", access_denied).contains("No permission"));
    assert!(format!("{}", encryption).contains("Invalid key"));
    assert!(format!("{}", invalid_config).contains("Bad endpoint"));
    assert!(format!("{}", upload_failed).contains("Part failed"));
    assert!(format!("{}", download_failed).contains("Stream error"));
    assert!(format!("{}", xml_parse).contains("Invalid XML"));
    assert!(format!("{}", invalid_response).contains("Bad format"));
    assert!(format!("{}", share_error).contains("Token expired"));
    assert!(format!("{}", forest_error).contains("Corrupt index"));
    assert!(format!("{}", internal).contains("Unexpected state"));
}

// ============================================================================
// Forest Subtree Type Tests
// ============================================================================

#[test]
fn test_forest_subtree() {
    let subtree = ForestSubtree {
        serialized: vec![1, 2, 3, 4, 5, 6, 7, 8],
    };
    assert_eq!(subtree.serialized.len(), 8);
}

// ============================================================================
// Clone Trait Tests (for FFI handles)
// ============================================================================

#[test]
fn test_multipart_handle_is_clone() {
    // This is a compile-time check - if MultipartHandle isn't Clone, this won't compile
    fn assert_clone<T: Clone>() {}
    assert_clone::<MultipartHandle>();
}

#[test]
fn test_fula_client_handle_is_clone() {
    fn assert_clone<T: Clone>() {}
    assert_clone::<FulaClientHandle>();
}

#[test]
fn test_encrypted_client_handle_is_clone() {
    fn assert_clone<T: Clone>() {}
    assert_clone::<EncryptedClientHandle>();
}

#[test]
fn test_rotation_manager_handle_is_clone() {
    fn assert_clone<T: Clone>() {}
    assert_clone::<RotationManagerHandle>();
}

// ============================================================================
// Chunked Constants Tests
// ============================================================================

#[test]
fn test_chunked_constants() {
    use fula_flutter::api::chunked::{DEFAULT_CHUNK_SIZE, CHUNKED_THRESHOLD};

    assert!(DEFAULT_CHUNK_SIZE > 0);
    assert!(CHUNKED_THRESHOLD > 0);
    assert!(CHUNKED_THRESHOLD <= (DEFAULT_CHUNK_SIZE as u64) * 1000); // Reasonable threshold
}

#[test]
fn test_should_use_chunked() {
    use fula_flutter::api::chunked::{should_use_chunked, CHUNKED_THRESHOLD};

    // Small files should not use chunked
    assert!(!should_use_chunked(1024));
    assert!(!should_use_chunked(CHUNKED_THRESHOLD - 1));
    // At exactly the threshold, don't use chunked (implementation is >)
    assert!(!should_use_chunked(CHUNKED_THRESHOLD));

    // Files larger than threshold should use chunked
    assert!(should_use_chunked(CHUNKED_THRESHOLD + 1));
    assert!(should_use_chunked(100_000_000));
}

// ============================================================================
// ObfuscationMode Tests
// ============================================================================

#[test]
fn test_obfuscation_mode_default() {
    let mode = ObfuscationMode::default();
    assert_eq!(mode, ObfuscationMode::Deterministic);
}

#[test]
fn test_obfuscation_mode_eq() {
    assert_eq!(ObfuscationMode::Deterministic, ObfuscationMode::Deterministic);
    assert_eq!(ObfuscationMode::Random, ObfuscationMode::Random);
    assert_ne!(ObfuscationMode::Deterministic, ObfuscationMode::Random);
}

// ============================================================================
// Sharing Crypto Tests - Verify DEK handling in share tokens
// ============================================================================

/// Test that ShareBuilder correctly uses the provided DEK
#[test]
fn test_share_token_uses_provided_dek() {
    use fula_crypto::keys::{KekKeyPair, DekKey};
    use fula_crypto::sharing::{ShareBuilder, ShareRecipient};

    let owner = KekKeyPair::generate();
    let recipient = KekKeyPair::generate();

    // Generate a specific DEK (simulating what happens during upload)
    let upload_dek = DekKey::generate();
    let original_dek_bytes = upload_dek.as_bytes().to_vec();

    // Create share token with the SAME DEK used during upload
    let token = ShareBuilder::new(&owner, recipient.public_key(), &upload_dek)
        .path_scope("/test/file.txt")
        .build()
        .unwrap();

    // Recipient accepts the share
    let recipient_handler = ShareRecipient::new(&recipient);
    let accepted = recipient_handler.accept_share(&token).unwrap();

    // CRITICAL: The DEK recipient receives must match upload DEK
    assert_eq!(
        accepted.dek.as_bytes().to_vec(),
        original_dek_bytes,
        "Share token must contain the SAME DEK used during encryption"
    );
}

/// Test that different files get different DEKs (random generation)
#[test]
fn test_different_files_get_different_deks() {
    use fula_crypto::keys::DekKey;

    // Simulate what happens during upload - each file gets a NEW random DEK
    let dek1 = DekKey::generate();
    let dek2 = DekKey::generate();
    let dek3 = DekKey::generate();

    // All DEKs must be different
    assert_ne!(dek1.as_bytes(), dek2.as_bytes(), "Each file should have unique DEK");
    assert_ne!(dek2.as_bytes(), dek3.as_bytes(), "Each file should have unique DEK");
    assert_ne!(dek1.as_bytes(), dek3.as_bytes(), "Each file should have unique DEK");
}

/// Test that derive_path_key produces DETERMINISTIC output (NOT suitable for FlatNamespace)
#[test]
fn test_derive_path_key_is_deterministic() {
    use fula_crypto::keys::{KekKeyPair, KeyManager};

    let keypair = KekKeyPair::generate();
    let key_manager = KeyManager::from_secret_key(keypair.secret_key().clone());

    let path = "test/file.txt";

    // Derive DEK twice from same path
    let derived1 = key_manager.derive_path_key(path);
    let derived2 = key_manager.derive_path_key(path);

    // Derived keys should be IDENTICAL (deterministic)
    assert_eq!(
        derived1.as_bytes(),
        derived2.as_bytes(),
        "derive_path_key should be deterministic"
    );
}

/// Test that random DEK differs from derived DEK
/// This is the core of the bug we fixed - upload uses random, share MUST NOT use derived
#[test]
fn test_random_dek_differs_from_derived() {
    use fula_crypto::keys::{KekKeyPair, DekKey, KeyManager};

    let keypair = KekKeyPair::generate();
    let key_manager = KeyManager::from_secret_key(keypair.secret_key().clone());

    let path = "test/file.txt";

    // Generate random DEK (what upload does in FlatNamespace mode)
    let random_dek = DekKey::generate();

    // Derive DEK from path (what the OLD buggy share code did)
    let derived_dek = key_manager.derive_path_key(path);

    // These MUST be different - if they're the same, decryption would fail
    assert_ne!(
        random_dek.as_bytes(),
        derived_dek.as_bytes(),
        "Random DEK and derived DEK must be different - sharing bug would cause decryption failure"
    );
}

/// Test end-to-end encryption/decryption with share token
#[test]
fn test_share_token_decryption_roundtrip() {
    use fula_crypto::keys::{KekKeyPair, DekKey};
    use fula_crypto::symmetric::{Aead, Nonce};
    use fula_crypto::sharing::{ShareBuilder, ShareRecipient};

    let owner = KekKeyPair::generate();
    let recipient = KekKeyPair::generate();

    // Simulate file upload: generate random DEK and encrypt
    let upload_dek = DekKey::generate();
    let plaintext = b"Secret file contents that only authorized recipient should see";

    let nonce = Nonce::generate();
    let aead = Aead::new_default(&upload_dek);
    let ciphertext = aead.encrypt(&nonce, plaintext).unwrap();

    // Create share token with the upload DEK
    let token = ShareBuilder::new(&owner, recipient.public_key(), &upload_dek)
        .path_scope("/shared/secret.txt")
        .build()
        .unwrap();

    // Recipient accepts share and decrypts
    let recipient_handler = ShareRecipient::new(&recipient);
    let accepted = recipient_handler.accept_share(&token).unwrap();

    // Decrypt with the DEK from share token
    let decrypt_aead = Aead::new_default(&accepted.dek);
    let decrypted = decrypt_aead.decrypt(&nonce, &ciphertext).unwrap();

    assert_eq!(decrypted, plaintext.to_vec(), "Decryption with shared DEK must succeed");
}

/// Test that sharing one file does NOT expose other files
#[test]
fn test_share_isolation() {
    use fula_crypto::keys::{KekKeyPair, DekKey};
    use fula_crypto::symmetric::{Aead, Nonce};
    use fula_crypto::sharing::{ShareBuilder, ShareRecipient};

    let owner = KekKeyPair::generate();
    let recipient = KekKeyPair::generate();

    // Upload two files with DIFFERENT random DEKs
    let file1_dek = DekKey::generate();
    let file2_dek = DekKey::generate();

    let file1_plaintext = b"File 1: This IS shared";
    let file2_plaintext = b"File 2: This is NOT shared - private!";

    let nonce1 = Nonce::generate();
    let nonce2 = Nonce::generate();

    let aead1 = Aead::new_default(&file1_dek);
    let aead2 = Aead::new_default(&file2_dek);

    let file1_ciphertext = aead1.encrypt(&nonce1, file1_plaintext).unwrap();
    let file2_ciphertext = aead2.encrypt(&nonce2, file2_plaintext).unwrap();

    // Share ONLY file1
    let token = ShareBuilder::new(&owner, recipient.public_key(), &file1_dek)
        .path_scope("/shared/file1.txt")
        .build()
        .unwrap();

    // Recipient accepts share
    let recipient_handler = ShareRecipient::new(&recipient);
    let accepted = recipient_handler.accept_share(&token).unwrap();

    // Recipient CAN decrypt file1
    let decrypt_aead1 = Aead::new_default(&accepted.dek);
    let decrypted1 = decrypt_aead1.decrypt(&nonce1, &file1_ciphertext).unwrap();
    assert_eq!(decrypted1, file1_plaintext.to_vec(), "Shared file should decrypt");

    // Recipient CANNOT decrypt file2 (different DEK)
    let decrypt_result = decrypt_aead1.decrypt(&nonce2, &file2_ciphertext);
    assert!(
        decrypt_result.is_err(),
        "Non-shared file must NOT be decryptable with shared DEK"
    );
}

/// Test that wrong recipient cannot use share token
#[test]
fn test_share_token_wrong_recipient_fails() {
    use fula_crypto::keys::{KekKeyPair, DekKey};
    use fula_crypto::sharing::{ShareBuilder, ShareRecipient};

    let owner = KekKeyPair::generate();
    let intended_recipient = KekKeyPair::generate();
    let attacker = KekKeyPair::generate();

    let dek = DekKey::generate();

    // Create token for intended_recipient
    let token = ShareBuilder::new(&owner, intended_recipient.public_key(), &dek)
        .path_scope("/secret/")
        .build()
        .unwrap();

    // Attacker tries to use the token
    let attacker_handler = ShareRecipient::new(&attacker);
    let result = attacker_handler.accept_share(&token);

    assert!(result.is_err(), "Wrong recipient must not be able to decrypt share token");
}

/// Test share path scope enforcement
#[test]
fn test_share_path_scope() {
    use fula_crypto::keys::{KekKeyPair, DekKey};
    use fula_crypto::sharing::ShareBuilder;

    let owner = KekKeyPair::generate();
    let recipient = KekKeyPair::generate();
    let dek = DekKey::generate();

    // Share only /photos/vacation/
    let token = ShareBuilder::new(&owner, recipient.public_key(), &dek)
        .path_scope("/photos/vacation/")
        .build()
        .unwrap();

    // Token should be valid for paths within scope
    assert!(token.is_valid_for_path("/photos/vacation/beach.jpg"));
    assert!(token.is_valid_for_path("/photos/vacation/subfolder/image.png"));

    // Token should NOT be valid for paths outside scope
    assert!(!token.is_valid_for_path("/photos/other/secret.jpg"));
    assert!(!token.is_valid_for_path("/documents/private.pdf"));
    assert!(!token.is_valid_for_path("/photos/vacatio")); // Partial match not allowed
}

/// Test share expiration
#[test]
fn test_share_expiration() {
    use fula_crypto::keys::{KekKeyPair, DekKey};
    use fula_crypto::sharing::{ShareBuilder, ShareRecipient, current_timestamp};

    let owner = KekKeyPair::generate();
    let recipient = KekKeyPair::generate();
    let dek = DekKey::generate();

    // Create already-expired token
    let expired_token = ShareBuilder::new(&owner, recipient.public_key(), &dek)
        .path_scope("/test/")
        .expires_at(current_timestamp() - 100) // Already expired
        .build()
        .unwrap();

    assert!(expired_token.is_expired(), "Token should be expired");

    // Recipient should not be able to accept expired token
    let recipient_handler = ShareRecipient::new(&recipient);
    let result = recipient_handler.accept_share(&expired_token);
    assert!(result.is_err(), "Expired token should be rejected");
}
