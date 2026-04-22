//! Fula Flutter API
//!
//! This module contains all the public API functions for Flutter bindings.
//! These functions are designed to work with flutter_rust_bridge code generation.

// Module declarations
pub mod types;
pub mod error;
pub mod client;
pub mod encrypted;
pub mod forest;
pub mod sharing;
pub mod rotation;
pub mod chunked;
pub mod multipart;
pub mod metrics;

// Re-export all public types
pub use types::*;
pub use error::{FulaError, FulaResult};

// Re-export client functions
pub use client::{
    create_client,
    create_encrypted_client,
    create_encrypted_client_with_pinning,
    list_buckets,
    create_bucket,
    delete_bucket,
    bucket_exists,
    put_object,
    put_object_with_metadata,
    get_object,
    get_object_with_metadata,
    head_object,
    delete_object,
    object_exists,
    copy_object,
    list_objects,
};

// Re-export encrypted functions
pub use encrypted::{
    put_encrypted,
    put_encrypted_with_type,
    get_decrypted,
    get_decrypted_by_storage_key,
    get_decrypted_buffered,
    get_decrypted_buffered_by_storage_key,
    get_with_private_metadata,
    delete_encrypted,
    delete_by_storage_key,
    head_decrypted,
    list_decrypted,
    list_directory,
    export_secret_key,
    get_public_key,
    derive_key,
    derive_public_key_from_secret,
    is_flat_namespace,
    enc_list_buckets,
    enc_create_bucket,
    enc_delete_bucket,
};

// Re-export metrics
pub use metrics::{wal_append_failure_count, flush_backoff_count, wal_truncated_groups_count};

// Re-export forest functions
pub use forest::{
    load_forest,
    save_forest,
    flush_forest,
    has_pending_changes,
    put_flat,
    put_flat_deferred,
    get_flat,
    delete_flat,
    list_from_forest,
    get_forest_subtree,
};

// Re-export file-path-based functions. Native impls read the file directly on
// the Rust side (avoiding the FFI round-trip for 1GB+ files); WASM impls
// return an error since browsers don't expose filesystem paths — WASM callers
// should read the file themselves and use `put_flat`.
pub use forest::{
    put_flat_from_path,
    put_flat_from_path_deferred,
    get_file_size,
};

// Re-export sharing functions
pub use sharing::{
    create_share_token,
    create_share_token_with_mode,
    accept_share,
    get_with_share,
    get_with_token,
    get_share_permissions,
    is_share_expired,
};

// Re-export rotation functions
pub use rotation::{
    create_rotation_manager,
    get_kek_version,
    rewrap_object,
    rotate_bucket,
};

// Re-export chunked functions
pub use chunked::{
    put_chunked,
    get_chunked,
    get_range,
    should_use_chunked,
    DEFAULT_CHUNK_SIZE,
    CHUNKED_THRESHOLD,
};

// Re-export multipart functions
pub use multipart::{
    start_multipart,
    upload_part,
    complete_multipart,
    abort_multipart,
    get_upload_id,
    get_completed_parts,
    upload_large_file_simple,
};
