//! WASM-specific tests for fula-flutter
//!
//! These tests are designed to run in a WASM environment using wasm-bindgen-test.
//! Run with: `wasm-pack test --headless --chrome` or `wasm-pack test --node`

#![cfg(target_arch = "wasm32")]

use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

// ============================================================================
// Type Tests (WASM)
// ============================================================================

use fula_flutter::api::types::*;

#[wasm_bindgen_test]
fn test_fula_config_default_wasm() {
    let config = FulaConfig::default();
    assert_eq!(config.endpoint, "http://localhost:9000");
    assert!(config.access_token.is_none());
    assert_eq!(config.timeout_seconds, 30);
}

#[wasm_bindgen_test]
fn test_encryption_config_default_wasm() {
    let config = EncryptionConfig::default();
    assert!(config.secret_key.is_none());
    assert!(config.enable_metadata_privacy);
    assert_eq!(config.obfuscation_mode, ObfuscationMode::Deterministic);
}

#[wasm_bindgen_test]
fn test_put_result_wasm() {
    let result = PutResult {
        etag: "wasm-etag".to_string(),
        version_id: None,
    };
    assert_eq!(result.etag, "wasm-etag");
}

#[wasm_bindgen_test]
fn test_list_objects_result_wasm() {
    let result = ListObjectsResult {
        objects: vec![],
        common_prefixes: vec![],
        is_truncated: false,
        next_token: None,
    };
    assert!(!result.is_truncated);
}

#[wasm_bindgen_test]
fn test_file_metadata_wasm() {
    let metadata = FileMetadata {
        storage_key: "wasm-key".to_string(),
        original_key: "/wasm/test.txt".to_string(),
        size: 256,
        content_type: Some("text/plain".to_string()),
        created_at: None,
        modified_at: None,
        is_encrypted: true,
    };
    assert!(metadata.is_encrypted);
    assert_eq!(metadata.size, 256);
}

#[wasm_bindgen_test]
fn test_share_permissions_wasm() {
    let perms = SharePermissions {
        can_read: true,
        can_write: false,
        expires_at: Some(1704240000),
    };
    assert!(perms.can_read);
    assert!(!perms.can_write);
}

#[wasm_bindgen_test]
async fn test_rotation_report_wasm() {
    let report = RotationReport {
        total: 10,
        rotated: 8,
        skipped: 1,
        failed: 1,
        failures: vec![],
    };
    assert!(!report.is_success().await);
    assert_eq!(report.success_rate().await, 90.0);
}

#[wasm_bindgen_test]
fn test_upload_progress_wasm() {
    let progress = UploadProgress::new(1000, 2000, 1, 2);
    assert_eq!(progress.percentage, 50.0);
}

// ============================================================================
// Chunked Operation Tests (WASM)
// ============================================================================

#[wasm_bindgen_test]
async fn test_chunked_threshold_wasm() {
    use fula_flutter::api::chunked::{should_use_chunked, CHUNKED_THRESHOLD};

    // Small files should not use chunked
    assert!(!should_use_chunked(1024).await);

    // At threshold, don't use chunked (implementation is >)
    assert!(!should_use_chunked(CHUNKED_THRESHOLD).await);

    // Files larger than threshold should use chunked
    assert!(should_use_chunked(CHUNKED_THRESHOLD + 1).await);
}

// ============================================================================
// Error Handling Tests (WASM)
// ============================================================================

use fula_flutter::api::error::FulaError;

#[wasm_bindgen_test]
fn test_error_display_wasm() {
    let err = FulaError::Network("WASM network error".to_string());
    let msg = format!("{}", err);
    assert!(msg.contains("WASM network error"));
}

#[wasm_bindgen_test]
fn test_not_found_error_wasm() {
    let err = FulaError::NotFound {
        bucket: "wasm-bucket".to_string(),
        key: "missing.txt".to_string(),
    };
    let msg = format!("{}", err);
    assert!(msg.contains("wasm-bucket"));
    assert!(msg.contains("missing.txt"));
}
