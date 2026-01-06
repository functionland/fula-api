# Fula Storage API

**S3-Compatible Decentralized Storage Engine powered by IPFS**

[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.83+-orange.svg)](https://www.rust-lang.org)

## Overview

Fula Storage provides an Amazon S3-compatible API backed by a decentralized network of IPFS nodes. It enables developers to build applications using familiar S3 tools and SDKs while benefiting from:

- **🌐 Decentralization**: Data is stored across a network of individually owned IPFS nodes
- **🔒 End-to-End Encryption**: Client-side HPKE encryption - storage nodes never see your data
- **🛡️ Quantum-Safe Cryptography**: Hybrid X25519 + ML-KEM-768 (NIST FIPS 203) for post-quantum security
- **✅ Verified Streaming**: BLAKE3/Bao ensures data integrity from untrusted nodes
- **🔄 Conflict-Free Sync**: CRDT-based metadata for distributed updates
- **📈 Efficient Indexing**: Prolly Trees for O(log n) bucket operations

## 📖 Documentation

- **[Introduction](https://functionland.github.io/fula-api/)** - Architecture, concepts, and how it works
- **[API Reference](https://functionland.github.io/fula-api/api.html)** - Complete endpoint documentation with examples
- **[SDK Examples](https://functionland.github.io/fula-api/sdk.html)** - Code examples for Rust, Python, JavaScript
- **[Platform Guides](https://functionland.github.io/fula-api/platforms.html)** - Next.js, React Native, .NET, Flutter, Swift, Kotlin

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
│                    fula-crypto (Quantum-Safe)                │
│    ┌─────────────┬──────────────┬──────────────────────┐    │
│    │ Hybrid KEM  │   BLAKE3     │        Bao           │    │
│    │ X25519+MLKEM│              │                      │    │
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

Fula supports **AWS Signature V4** authentication, enabling full compatibility with standard S3 tools. Embed your JWT token in the access key with a `JWT:` prefix:

```bash
# Configure credentials (~/.aws/credentials)
cat >> ~/.aws/credentials << EOF
[fula]
aws_access_key_id = JWT:your-jwt-token-here
aws_secret_access_key = not-used
EOF

# Use AWS CLI with Fula gateway
aws s3 mb s3://my-bucket --endpoint-url http://localhost:9000 --profile fula
aws s3 cp file.txt s3://my-bucket/ --endpoint-url http://localhost:9000 --profile fula
aws s3 ls s3://my-bucket/ --endpoint-url http://localhost:9000 --profile fula
```

### Using Python (boto3)

```python
import boto3

# Configure with JWT embedded in access key
s3 = boto3.client('s3',
    endpoint_url='http://localhost:9000',
    aws_access_key_id=f'JWT:{jwt_token}',
    aws_secret_access_key='not-used',
    region_name='us-east-1'
)

# Use S3 API normally
s3.create_bucket(Bucket='my-bucket')
s3.put_object(Bucket='my-bucket', Key='hello.txt', Body=b'Hello World!')
```

### Using JavaScript (AWS SDK)

```javascript
import { S3Client, PutObjectCommand } from "@aws-sdk/client-s3";

const s3 = new S3Client({
  endpoint: "http://localhost:9000",
  region: "us-east-1",
  forcePathStyle: true,
  credentials: {
    accessKeyId: `JWT:${jwtToken}`,
    secretAccessKey: "not-used"
  }
});

await s3.send(new PutObjectCommand({
  Bucket: "my-bucket",
  Key: "hello.txt",
  Body: "Hello World!"
}));
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

// FlatNamespace mode is default - complete structure hiding!
// Server sees only random CID-like hashes (QmX7a8f3e2d1...)
let encryption = EncryptionConfig::new();
let client = EncryptedClient::new(
    Config::new("http://localhost:9000"),
    encryption,
)?;

// Data encrypted with FlatNamespace - server cannot see folder structure
client.put_object_flat("bucket", "/photos/vacation/beach.jpg", data, None).await?;

// List files from encrypted PrivateForest index
let files = client.list_files_from_forest("bucket").await?;
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
| `fula-crypto` | Quantum-safe cryptography (Hybrid X25519+ML-KEM, HPKE, BLAKE3, Bao) |
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

# Security verification
cargo run --example security_verification

# Sharing Demo
cargo run --example sharing_demo

# Metadata Privacy
cargo run --example metadata_privacy

# Metadata fetch only
cargo run --example file_manager_demo

# FlatNamespace (maximum privacy - complete structure hiding)
cargo run --example flat_namespace_demo


```

## Security

### 🛡️ Quantum-Safe Cryptography

Fula implements **post-quantum cryptographic protection** using a hybrid approach that provides defense-in-depth:

| Component | Algorithm | Security Level |
|-----------|-----------|----------------|
| Key Encapsulation | **X25519 + ML-KEM-768** | Hybrid classical + post-quantum |
| Symmetric Encryption | AES-256-GCM / ChaCha20-Poly1305 | 256-bit (quantum-resistant) |
| Hashing | BLAKE3 | 256-bit (quantum-resistant) |
| Integrity | Bao (BLAKE3-based) | Verified streaming |

**Why Hybrid?**
- If quantum computers break X25519 (Shor's algorithm), ML-KEM-768 still protects your data
- If ML-KEM has unforeseen weaknesses, X25519 still provides classical security
- ML-KEM-768 is NIST FIPS 203 standardized (formerly Kyber768)

```rust
use fula_crypto::{HybridKeyPair, hybrid_encapsulate, hybrid_decapsulate};

// Generate quantum-safe keypair (X25519 + ML-KEM-768)
let keypair = HybridKeyPair::generate();

// Sender encapsulates shared secret
let (encapsulated_key, shared_secret) = hybrid_encapsulate(keypair.public_key())?;

// Recipient decapsulates
let recovered = hybrid_decapsulate(&encapsulated_key, keypair.secret_key())?;
assert_eq!(shared_secret, recovered);
```

### Trust Model

- **Storage nodes are untrusted**: All sensitive data is encrypted client-side
- **Gateway is trusted for routing**: But never sees encryption keys
- **Keys never leave the client**: HPKE ensures end-to-end encryption
- **Per-user bucket isolation**: Each user's buckets are automatically namespaced - multiple users can have buckets with the same name without conflicts

### Key Management

- Generate keys locally using `EncryptionConfig::new()` (uses FlatNamespace by default)
- Complete structure hiding - server cannot see folder/file relationships
- Export/backup secret keys securely
- Lost keys = lost data (no recovery possible)

### Privacy Notice

⚠️ **Important**: For private data, always use the **Encrypted Client SDK** (`EncryptedClient`).

Raw S3 tools (AWS CLI, boto3) do NOT encrypt data - they upload plaintext that gateway operators can see.

**What's encrypted** (with EncryptedClient):
- ✅ File content
- ✅ File names (FlatNamespace mode)
- ✅ Directory structure
- ✅ User IDs (hashed)

**What remains visible**:
- ⚠️ Bucket names
- ⚠️ Approximate file sizes
- ⚠️ Request timestamps

See [docs/PRIVACY.md](docs/PRIVACY.md) for full privacy policy.

### Large File Support (WNFS-inspired)

For files larger than 5MB, use chunked upload for better memory efficiency and partial read support:

```rust
use fula_client::EncryptedClient;

// Large file - use chunked upload
let large_data = std::fs::read("movie.mp4")?;
if EncryptedClient::should_use_chunked(large_data.len()) {
    client.put_object_chunked(
        "my-bucket",
        "/videos/movie.mp4",
        &large_data,
        Some(512 * 1024), // 512KB chunks (optional)
    ).await?;
}

// Partial read - only downloads needed chunks
let partial = client.get_object_range(
    "my-bucket",
    "/videos/movie.mp4",
    1024 * 1024,  // offset: 1MB
    1024 * 1024,  // length: 1MB
).await?;
```

**Benefits:**
- Memory efficient: processes one chunk at a time
- Partial reads: download only the bytes you need
- Resumable: failed uploads can restart from last chunk
- Integrity: Bao hash tree for verified streaming

See [docs/wnfs-borrowed-features.md](docs/wnfs-borrowed-features.md) for implementation details.

## Production Deployment

For production Ubuntu deployments with security hardening:

```bash
# Download and run the installer
curl -fsSL https://raw.githubusercontent.com/functionland/fula-api/main/install.sh | sudo bash
```

The installer will:
- Install Docker and dependencies
- Configure nginx with TLS (Let's Encrypt)
- Set up rate limiting and fail2ban
- Configure firewall (UFW)
- Create systemd service
- Optionally set up local IPFS node

See [install.sh](install.sh) for details.

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


## Update

```
~/fula-api# git pull
~/fula-api# rsync -a --delete /root/fula-api/ /opt/fula-api/
~/fula-api# cp docker-compose.yml /etc/fula/
/opt/fula-api# docker-compose -f /etc/fula/docker-compose.yml build --no-cache gateway
systemctl restart fula-gateway
```