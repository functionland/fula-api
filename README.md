# Fula Storage API

**S3-Compatible Decentralized Storage Engine powered by IPFS**

[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.83+-orange.svg)](https://www.rust-lang.org)

## Overview

Fula Storage provides an Amazon S3-compatible API backed by a decentralized network of IPFS nodes. It enables developers to build applications using familiar S3 tools and SDKs while benefiting from:

- **🌐 Decentralization**: Data is stored across a network of individually owned IPFS nodes
- **🔒 End-to-End Encryption**: Client-side HPKE encryption - storage nodes never see your data
- **✅ Verified Streaming**: BLAKE3/Bao ensures data integrity from untrusted nodes
- **🔄 Conflict-Free Sync**: CRDT-based metadata for distributed updates
- **📈 Efficient Indexing**: Prolly Trees for O(log n) bucket operations

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Application Layer                         │
│         (boto3, AWS SDK, curl, any S3 client)               │
├─────────────────────────────────────────────────────────────┤
│                     Fula Gateway                             │
│    ┌─────────────┬──────────────┬──────────────────────┐    │
│    │    Auth     │ Rate Limiter │   S3 API Handlers    │    │
│    └─────────────┴──────────────┴──────────────────────┘    │
├─────────────────────────────────────────────────────────────┤
│                      fula-core                               │
│    ┌─────────────┬──────────────┬──────────────────────┐    │
│    │Prolly Trees │    Buckets   │       CRDTs          │    │
│    └─────────────┴──────────────┴──────────────────────┘    │
├─────────────────────────────────────────────────────────────┤
│                   fula-blockstore                            │
│    ┌─────────────┬──────────────┬──────────────────────┐    │
│    │    IPFS     │ IPFS Cluster │      Chunking        │    │
│    └─────────────┴──────────────┴──────────────────────┘    │
├─────────────────────────────────────────────────────────────┤
│                    fula-crypto                               │
│    ┌─────────────┬──────────────┬──────────────────────┐    │
│    │    HPKE     │   BLAKE3     │        Bao           │    │
│    └─────────────┴──────────────┴──────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

## Quick Start

### Using Docker Compose

```bash
# Clone the repository
git clone https://github.com/functionland/fula-api
cd fula-api

# Start the stack
docker-compose up -d

# The gateway is now available at http://localhost:9000
```

### Using AWS CLI

```bash
# Configure endpoint
export AWS_ENDPOINT_URL=http://localhost:9000

# Create a bucket
aws s3 mb s3://my-bucket

# Upload a file
aws s3 cp file.txt s3://my-bucket/

# List objects
aws s3 ls s3://my-bucket/

# Download a file
aws s3 cp s3://my-bucket/file.txt .
```

### Using the Rust Client SDK

```rust
use fula_client::{FulaClient, Config};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let client = FulaClient::new(Config::new("http://localhost:9000"))?;

    // Create bucket
    client.create_bucket("my-bucket").await?;

    // Upload object
    client.put_object("my-bucket", "hello.txt", b"Hello, World!").await?;

    // Download object
    let data = client.get_object("my-bucket", "hello.txt").await?;
    println!("{}", String::from_utf8_lossy(&data));

    Ok(())
}
```

## Features

### S3 API Compatibility

| Operation | Status |
|-----------|--------|
| CreateBucket | ✅ |
| DeleteBucket | ✅ |
| ListBuckets | ✅ |
| HeadBucket | ✅ |
| PutObject | ✅ |
| GetObject | ✅ |
| DeleteObject | ✅ |
| HeadObject | ✅ |
| CopyObject | ✅ |
| ListObjectsV2 | ✅ |
| CreateMultipartUpload | ✅ |
| UploadPart | ✅ |
| CompleteMultipartUpload | ✅ |
| AbortMultipartUpload | ✅ |
| ListParts | ✅ |
| ListMultipartUploads | ✅ |

### Client-Side Encryption

```rust
use fula_client::{Config, EncryptedClient, EncryptionConfig};

let encryption = EncryptionConfig::new();
let client = EncryptedClient::new(
    Config::new("http://localhost:9000"),
    encryption,
)?;

// Data is encrypted before upload
client.put_object_encrypted("bucket", "secret.txt", b"sensitive data").await?;

// Data is decrypted after download
let data = client.get_object_decrypted("bucket", "secret.txt").await?;
```

### Large File Uploads

```rust
use fula_client::multipart::upload_large_file;

let etag = upload_large_file(
    client,
    "bucket",
    "large-file.bin",
    large_data,
    Some(Box::new(|progress| {
        println!("Progress: {:.1}%", progress.percentage());
    })),
).await?;
```

## Crates

| Crate | Description |
|-------|-------------|
| `fula-crypto` | Cryptographic primitives (HPKE, BLAKE3, Bao) |
| `fula-blockstore` | IPFS block storage and chunking |
| `fula-core` | Storage engine (Prolly Trees, CRDTs) |
| `fula-cli` | S3-compatible gateway server |
| `fula-client` | Client SDK with encryption support |

## Configuration

See [.env.example](.env.example) for all configuration options.

Key settings:

```bash
# Gateway
FULA_HOST=0.0.0.0
FULA_PORT=9000

# IPFS
IPFS_API_URL=http://localhost:5001
CLUSTER_API_URL=http://localhost:9094

# Authentication
JWT_SECRET=your-secret-key
```

## Development

### Building from Source

```bash
# Install Rust 1.83+
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Build all crates
cargo build --release

# Run tests
cargo test

# Run the gateway
cargo run --package fula-cli -- --no-auth
```

### Running Examples

```bash
# Basic usage
cargo run --example basic_usage

# Encryption
cargo run --example encrypted_storage

# Multipart upload
cargo run --example multipart_upload

# S3 compatibility guide
cargo run --example s3_compatible
```

## Security

### Trust Model

- **Storage nodes are untrusted**: All sensitive data is encrypted client-side
- **Gateway is trusted for routing**: But never sees encryption keys
- **Keys never leave the client**: HPKE ensures end-to-end encryption

### Key Management

- Generate keys locally using `EncryptionConfig::new()`
- Export/backup secret keys securely
- Lost keys = lost data (no recovery possible)

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Acknowledgments

- [IPFS](https://ipfs.io/) - The InterPlanetary File System
- [IPFS Cluster](https://cluster.ipfs.io/) - Pinset orchestration
- [rs-wnfs](https://github.com/wnfs-wg/rs-wnfs) - HAMT implementation reference
- [BLAKE3](https://github.com/BLAKE3-team/BLAKE3) - Fast cryptographic hashing
- [Bao](https://github.com/oconnor663/bao) - Verified streaming
