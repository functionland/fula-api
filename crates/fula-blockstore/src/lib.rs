//! # Fula Blockstore
//!
//! IPFS block storage layer for the Fula decentralized storage system.
//!
//! This crate provides:
//! - **Block operations**: Put, get, and delete IPFS blocks
//! - **Chunking**: Split large files into 256KB blocks
//! - **CID generation**: Create content identifiers using BLAKE3
//! - **Cluster pinning**: Manage replication via IPFS Cluster
//! - **Caching**: In-memory LRU cache for hot blocks
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────┐
//! │            Application Layer            │
//! ├─────────────────────────────────────────┤
//! │           BlockStore Trait              │
//! ├─────────────┬─────────────┬─────────────┤
//! │  IpfsStore  │ ClusterStore│ MemoryStore │
//! ├─────────────┴─────────────┴─────────────┤
//! │              IPFS/Cluster               │
//! └─────────────────────────────────────────┘
//! ```
//!
//! ## Example
//!
//! ```rust,ignore
//! use fula_blockstore::{IpfsBlockStore, BlockStore};
//!
//! let store = IpfsBlockStore::new("http://localhost:5001").await?;
//! let cid = store.put_block(&data).await?;
//! let retrieved = store.get_block(&cid).await?;
//! ```

pub mod block;
pub mod chunker;
pub mod cid_utils;
pub mod cluster;
pub mod error;
pub mod ipfs;
pub mod ipfs_pinning;
pub mod memory;
pub mod pinning_service;

pub use block::{Block, BlockData, BlockRef};
pub use chunker::{Chunker, ChunkerConfig, ChunkResult};
pub use cid_utils::{create_cid, CidCodec};
pub use cluster::{ClusterClient, ClusterConfig, PinStatus, ReplicationFactor};
pub use error::{BlockStoreError, Result};
pub use ipfs::{IpfsBlockStore, IpfsConfig};
pub use ipfs_pinning::{FlexibleBlockStore, IpfsPinningBlockStore, IpfsPinningConfig};
pub use memory::MemoryBlockStore;
pub use pinning_service::{
    ListPinsQuery, Pin, PinningServiceClient, PinningServiceConfig, PinningStatus,
    PinStatusResponse,
};

use async_trait::async_trait;
use cid::Cid;
use bytes::Bytes;

/// Default chunk size (256 KB)
pub const DEFAULT_CHUNK_SIZE: usize = 256 * 1024;

/// Maximum block size (1 MB)
pub const MAX_BLOCK_SIZE: usize = 1024 * 1024;

/// Trait for block storage backends
#[async_trait]
pub trait BlockStore: Send + Sync {
    /// Store a block and return its CID
    async fn put_block(&self, data: &[u8]) -> Result<Cid>;

    /// Retrieve a block by CID
    async fn get_block(&self, cid: &Cid) -> Result<Bytes>;

    /// Check if a block exists
    async fn has_block(&self, cid: &Cid) -> Result<bool>;

    /// Delete a block
    async fn delete_block(&self, cid: &Cid) -> Result<()>;

    /// Get block size without retrieving content
    async fn block_size(&self, cid: &Cid) -> Result<u64>;

    /// Store raw IPLD data
    async fn put_ipld<T: serde::Serialize + Send + Sync>(&self, data: &T) -> Result<Cid>;

    /// Retrieve and deserialize IPLD data
    async fn get_ipld<T: serde::de::DeserializeOwned>(&self, cid: &Cid) -> Result<T>;
}

/// Trait for pinning operations (IPFS Cluster)
#[async_trait]
pub trait PinStore: BlockStore {
    /// Pin a CID for persistence
    async fn pin(&self, cid: &Cid, name: Option<&str>) -> Result<()>;

    /// Unpin a CID
    async fn unpin(&self, cid: &Cid) -> Result<()>;

    /// Check if a CID is pinned
    async fn is_pinned(&self, cid: &Cid) -> Result<bool>;

    /// List all pins
    async fn list_pins(&self) -> Result<Vec<Cid>>;

    /// Get pin status
    async fn pin_status(&self, cid: &Cid) -> Result<PinStatus>;
}

/// Trait for DAG operations
#[async_trait]
pub trait DagStore: BlockStore {
    /// Put a DAG node
    async fn put_dag(&self, data: &[u8], links: Vec<Cid>) -> Result<Cid>;

    /// Get all links from a DAG node
    async fn get_links(&self, cid: &Cid) -> Result<Vec<Cid>>;

    /// Resolve a path in a DAG
    async fn resolve_path(&self, root: &Cid, path: &str) -> Result<Cid>;
}
