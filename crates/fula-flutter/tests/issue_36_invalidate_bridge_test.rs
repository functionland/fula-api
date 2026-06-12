//! Issue #36 — bridge-level tests for the newly exposed forest-cache
//! invalidation functions.
//!
//! The behavioural acceptance criteria (cross-device staleness escape +
//! dirty-safe contract) are pinned at the `EncryptedClient` layer in
//! `fula-client/tests/issue_36_invalidate_forest_cache.rs` — both the
//! Flutter and JS bindings are thin delegates to those methods. What
//! THIS file pins is the binding wiring itself: the functions exist on
//! the `crate::api` surface flutter_rust_bridge scans (so a codegen run
//! exposes them to Dart), take the documented signatures, and are safe
//! no-ops on a client with no loaded forest (no network, no panic) —
//! apps may call them from any refresh path unconditionally.

#![cfg(not(target_arch = "wasm32"))]

use fula_flutter::api::client::create_encrypted_client;
use fula_flutter::api::forest::{
    has_pending_changes, invalidate_all_forest_caches, invalidate_forest_cache,
};
use fula_flutter::api::types::{EncryptedClientHandle, EncryptionConfig, FulaConfig};
use futures::executor::block_on;

/// Construct a handle without touching the network: client construction
/// is local; the endpoint below is never contacted because the test only
/// exercises cache-management calls.
fn test_handle() -> EncryptedClientHandle {
    let config = FulaConfig {
        endpoint: "http://127.0.0.1:1".to_string(),
        ..Default::default()
    };
    let encryption = EncryptionConfig {
        secret_key: Some(vec![0x36u8; 32]),
        ..Default::default()
    };
    block_on(create_encrypted_client(config, encryption)).expect("create encrypted client")
}

/// The new bridge functions must be callable, idempotent, and safe on a
/// client that has never loaded the bucket's forest — the "call it from
/// every SWR revalidation path" usage pattern from the issue.
#[test]
fn invalidate_bridge_functions_are_callable_and_idempotent() {
    let handle = test_handle();

    block_on(invalidate_forest_cache(&handle, "issue36-bucket".to_string()));
    block_on(invalidate_forest_cache(&handle, "issue36-bucket".to_string()));
    block_on(invalidate_all_forest_caches(&handle));
    block_on(invalidate_all_forest_caches(&handle));

    assert!(
        !block_on(has_pending_changes(&handle, "issue36-bucket".to_string())),
        "no pending changes can exist on a never-written bucket"
    );
}
