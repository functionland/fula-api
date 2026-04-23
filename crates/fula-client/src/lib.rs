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

mod client;
mod config;
mod encryption;
mod error;
mod multipart;
mod types;
#[cfg(not(target_arch = "wasm32"))]
mod orphan_queue;
#[cfg(not(target_arch = "wasm32"))]
mod wal;

// Cross-module test serializer. Unit tests in wal.rs and orphan_queue.rs both
// mutate `FULA_STATE_DIR`; without a single shared lock, tests in each module
// can set the env var concurrently and read each other's temp dir.
#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
pub(crate) static TEST_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

pub use client::FulaClient;
pub use config::Config;
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
