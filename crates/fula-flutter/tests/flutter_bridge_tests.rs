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
}

#[test]
fn test_fula_config_with_values() {
    let config = FulaConfig {
        endpoint: "https://api.example.com".to_string(),
        access_token: Some("test-token".to_string()),
        timeout_seconds: 60,
        max_retries: 5,
    };
    assert_eq!(config.endpoint, "https://api.example.com");
    assert_eq!(config.access_token, Some("test-token".to_string()));
    assert_eq!(config.timeout_seconds, 60);
    assert_eq!(config.max_retries, 5);
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
