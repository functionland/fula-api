//! # Fula Flutter
//!
//! Flutter bindings for Fula decentralized storage.
//!
//! This crate provides a unified API for both Android (FFI) and Web (WASM) platforms
//! using flutter_rust_bridge.
//!
//! ## Features
//!
//! - **Client-side encryption** with post-quantum cryptography
//! - **S3-compatible** storage operations
//! - **FlatNamespace** for organized file management
//! - **Sharing** via encrypted tokens
//! - **Key rotation** support
//!
//! ## Usage
//!
//! This crate is designed to be used via flutter_rust_bridge code generation.
//! The generated Dart bindings provide a type-safe API for Flutter apps.

pub mod api;

// Re-export the main API types at crate root for convenience
pub use api::*;
