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

pub use client::FulaClient;
pub use config::Config;
pub use encryption::{EncryptedClient, EncryptionConfig, DecryptedObjectInfo};
pub use error::{ClientError, Result};
pub use multipart::{MultipartUpload, UploadProgress, ProgressCallback, upload_large_file};
pub use types::*;

// Re-export useful crypto types for encryption configuration
pub use fula_crypto::private_metadata::KeyObfuscation;
