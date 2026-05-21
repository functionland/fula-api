//! # Fula Client SDK
//!
//! A client SDK for Fula decentralized storage with S3-compatible API.
//!
//! ## Features
//!
//! - **S3-Compatible**: Works with any S3-compatible tools and libraries
//! - **Client-Side Encryption**: Optional HPKE-based encryption
//! - **Cross-Platform**: Works on Android, iOS, Web, Windows, macOS, Linux
//! - **Streaming**: Support for large files via multipart upload
//!
//! ## Example
//!
//! ```rust,ignore
//! use fula_client::{FulaClient, Config};
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     // Create client
//!     let client = FulaClient::new(Config {
//!         endpoint: "http://localhost:9000".to_string(),
//!         access_token: Some("your-jwt-token".to_string()),
//!         ..Default::default()
//!     })?;
//!
//!     // Create a bucket
//!     client.create_bucket("my-bucket").await?;
//!
//!     // Upload a file
//!     client.put_object("my-bucket", "hello.txt", b"Hello, World!").await?;
//!
//!     // Download a file
//!     let data = client.get_object("my-bucket", "hello.txt").await?;
//!     println!("Content: {}", String::from_utf8_lossy(&data));
//!
//!     Ok(())
//! }
//! ```

#[cfg(not(target_arch = "wasm32"))]
mod block_cache;
mod client;
mod config;
mod encryption;
mod error;
#[cfg(not(target_arch = "wasm32"))]
mod gateway_fetch;
mod health_gate;
mod multipart;
#[cfg(not(target_arch = "wasm32"))]
mod registry_resolver;
mod types;
/// E2E plan Phase 4 — encrypted bucketsIndex writer + envelope
/// encrypt/decrypt helpers. Native-only because it relies on the
/// reqwest blocking HTTP client and the same dag-cbor codec the
/// resolver uses. wasm target can add a separate browser-friendly
/// variant later if needed.
#[cfg(not(target_arch = "wasm32"))]
mod users_index_writer;
/// Phase 3.3 helper module — wasm-friendly userKey derivation
/// extracted from `registry_resolver.rs` so the wasm-bindgen
/// binding can expose it. Source-of-truth lives here; the
/// resolver re-exports it on native.
mod user_key;
#[cfg(not(target_arch = "wasm32"))]
mod orphan_queue;
/// Walkable-v8 (W.9.3) — SDK self-verification of master-attested CIDs.
/// Cross-platform (wasm + native) so the dual-pointer wire format is
/// stamped consistently regardless of which target persists the blob.
mod walkable_v8;
#[cfg(not(target_arch = "wasm32"))]
mod wal;

// Cross-module test serializer. Unit tests in wal.rs, orphan_queue.rs, and the
// f9_manifest_version_pin_mac module in encryption.rs all mutate
// `FULA_STATE_DIR`; without a single shared lock, tests in each module can set
// the env var concurrently and read each other's temp dir.
#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
pub(crate) static TEST_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

pub use client::FulaClient;
pub use config::Config;
#[cfg(not(target_arch = "wasm32"))]
pub use users_index_writer::{
    build_payload_from_buckets_list, EncryptedBucketsIndexEnvelope, LatestEntryResponse,
    PublishOutcome, ServerBucketEntry, UsersIndexWriter,
};
pub use encryption::{EncryptedClient, EncryptionConfig, DecryptedObjectInfo, FileMetadata, DirectoryListing, PinningCredentials, S3BlobBackend};

/// Crash-injection atomics used by the workspace integration tests to
/// simulate client-side aborts between phases of `migrate_v1_to_v7_internal`.
/// Only present when the `test-fault-injection` feature is enabled; off in
/// every production build.
#[cfg(feature = "test-fault-injection")]
pub mod test_faults {
    pub use crate::encryption::test_faults::*;
}
pub use error::{ClientError, Result};
pub use multipart::{MultipartUpload, UploadProgress, ProgressCallback, upload_large_file, MultipartAbortGuard};
pub use types::*;

/// Phase 19 — transparency surfaces. `HealthCallback` is the closure
/// type apps wire via `Config::with_health_callback` to observe master
/// reachability transitions. `MasterHealthEvent` is the variant the
/// callback receives. Re-exported here so app-level code can construct
/// callbacks without depending on internal module paths.
pub use health_gate::{HealthCallback, MasterHealthEvent};

/// Phase 2.2 — the persistent block cache. Exposed publicly so
/// integration tests + diagnostic tooling can probe cache state
/// without relying on internal module paths. Apps construct the
/// cache implicitly via `Config::block_cache_enabled`; direct
/// construction is uncommon outside tests.
#[cfg(not(target_arch = "wasm32"))]
pub use block_cache::{BlockCache, BlockCacheError};

/// Phase 3.3 — userKey derivation, available on EVERY target
/// (wasm + native). See `user_key.rs` module-level docs for which
/// function to call:
///
/// - **`derive_user_key_from_jwt_sub`** (preferred) — matches master
///   byte-for-byte. Pass the JWT `sub` claim through unchanged.
/// - **`derive_user_key_from_email`** (legacy) — broken for
///   pre-migration-011 users whose JWT sub is plaintext email.
///   Kept for source compatibility with already-shipped apps.
pub use user_key::{derive_user_key_from_email, derive_user_key_from_jwt_sub};

/// Phase 3.3 — cold-start hybrid resolver public API. Native-only;
/// the resolver itself is gated to `cfg(not(target_arch = "wasm32"))`.
/// `derive_user_key_from_email` is re-exported above (cross-target);
/// callers using the `fula_client::registry_resolver::derive_user_key_from_email`
/// path also still resolve through the in-module `pub use`.
#[cfg(not(target_arch = "wasm32"))]
pub use registry_resolver::{
    decode_user_buckets_index, default_ipfs_gateway_urls, default_ipns_gateway_urls,
    fetch_cid_via_gateways, BucketEntry, GlobalUsersIndex, ResolutionSource,
    ResolvedUsersIndex, ResolverConfig, UserBucketsIndex, UsersIndexResolver,
};

/// Process-wide count of WAL append failures (F11).
///
/// The WAL is the crash-recovery log for in-memory forest upserts. When
/// `wal::append` fails, the in-memory dirty state has outrun its on-disk
/// record — a subsequent crash / power-loss can lose the upsert even
/// though the client reported success. This counter increments on every
/// such failure so operators can alert on rising values.
///
/// The counter is monotonic and process-wide (not per-client); it does
/// not reset. Wire it into your metrics pipeline alongside whatever
/// `tracing::warn!` subscriber you already have — the two are
/// complementary (log for the incident, counter for the rate).
///
/// Not available on wasm32; the WAL is native-only.
#[cfg(not(target_arch = "wasm32"))]
pub fn wal_append_failure_count() -> u64 {
    wal::append_failure_count()
}

/// Total flush-forest retry backoff sleeps observed since process start
/// (M-2). Monotonic process-wide counter; incremented each time the
/// `flush_forest` retry loop sleeps on a 412 concurrent-modification race
/// before re-attempting.
///
/// Native-only; on wasm32 `flush_forest` does a single attempt with no
/// retry/backoff.
#[cfg(not(target_arch = "wasm32"))]
pub fn flush_backoff_count() -> u64 {
    encryption::flush_backoff_count()
}

/// Total `S3BlobBackend::{get, put}` retries triggered by transient 5xx
/// responses (typically nginx `limit_req` 503 on bursty HAMT walks) since
/// process start. Monotonic process-wide counter.
///
/// Native-only; the wasm32 `BlobBackend` impl is single-attempt.
#[cfg(not(target_arch = "wasm32"))]
pub fn blob_backend_retry_count() -> u64 {
    encryption::blob_backend_retry_count()
}

/// Count of WAL groups discarded on load due to partial-group truncation
/// (M-4). A transactional multi-entry op written via the internal
/// `append_group` path is applied all-or-none on replay: if any member is
/// missing at load time (power-loss between writes and the trailing fsync,
/// MAC corruption of a member line, index collision), every surviving
/// member is dropped and this counter increments once per discarded group.
///
/// Monotonic, process-wide. Native-only; the WAL is compiled out on wasm32.
#[cfg(not(target_arch = "wasm32"))]
pub fn wal_truncated_groups_count() -> u64 {
    wal::truncated_groups_count()
}

// Re-export useful crypto types for encryption configuration
pub use fula_crypto::private_metadata::KeyObfuscation;
pub use fula_crypto::private_forest::{PrivateForest, ForestFileEntry, ForestDirectoryEntry};
