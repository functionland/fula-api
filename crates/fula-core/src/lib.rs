//! # Fula Core
//!
//! Core storage engine for the Fula decentralized storage system.
//!
//! This crate provides:
//! - **Prolly Trees**: Probabilistic B-Trees for efficient bucket indexing
//! - **Bucket Management**: S3-compatible bucket operations
//! - **Object Metadata**: Rich metadata for stored objects
//! - **CRDT Support**: Conflict-free replicated data types for distributed updates
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────┐
//! │              S3 API Layer               │
//! ├─────────────────────────────────────────┤
//! │          Bucket Manager                 │
//! ├─────────────────────────────────────────┤
//! │    Prolly Tree Index    │    CRDT       │
//! ├─────────────────────────────────────────┤
//! │           BlockStore                    │
//! └─────────────────────────────────────────┘
//! ```

pub mod bucket;
pub mod crdt;
pub mod error;
pub mod metadata;
pub mod prolly;

pub use bucket::{Bucket, BucketConfig, BucketManager};
pub use error::{CoreError, Result};
pub use metadata::{ObjectMetadata, EncryptionMetadata, StorageClass};
pub use prolly::{ProllyTree, ProllyNode, ProllyConfig};

/// Version of the storage format
pub const STORAGE_VERSION: &str = "1.0.0";
