//! # Fula Gateway
//!
//! S3-compatible gateway server for Fula decentralized storage.
//!
//! This crate provides:
//! - **S3 API**: Full S3-compatible REST API
//! - **Authentication**: OAuth 2.0 / JWT token validation
//! - **Rate Limiting**: Per-user request throttling
//! - **Multipart Upload**: Large file handling with resume support
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────┐
//! │                   HTTP Clients                      │
//! │           (boto3, AWS SDK, curl, etc.)              │
//! └─────────────────────────┬───────────────────────────┘
//!                           │
//! ┌─────────────────────────▼───────────────────────────┐
//! │                    Fula Gateway                      │
//! ├─────────────────────────────────────────────────────┤
//! │  Auth Middleware │ Rate Limiter │ Request Parser    │
//! ├─────────────────────────────────────────────────────┤
//! │               S3 API Handlers                        │
//! │  (PutObject, GetObject, ListObjects, etc.)          │
//! ├─────────────────────────────────────────────────────┤
//! │                   fula-core                          │
//! │         (Buckets, Prolly Trees, CRDTs)              │
//! ├─────────────────────────────────────────────────────┤
//! │                 fula-blockstore                      │
//! │            (IPFS, IPFS Cluster)                      │
//! └─────────────────────────────────────────────────────┘
//! ```

pub mod auth;
pub mod config;
pub mod error;
pub mod handlers;
pub mod middleware;
pub mod multipart;
pub mod routes;
pub mod server;
pub mod state;
pub mod xml;

pub use config::GatewayConfig;
pub use error::{ApiError, S3ErrorCode};
pub use server::run_server;
pub use state::AppState;
