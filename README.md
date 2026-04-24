# Fula Storage API

**S3-Compatible Decentralized Storage Engine powered by IPFS**

[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.83+-orange.svg)](https://www.rust-lang.org)

## Overview

Fula Storage provides an Amazon S3-compatible API backed by a decentralized network of IPFS nodes. It enables developers to build applications using familiar S3 tools and SDKs while benefiting from:

- **🌐 Decentralization**: Data is stored across a network of individually owned IPFS nodes
- **🔒 End-to-End Encryption**: Client-side AEAD (AES-256-GCM) with per-file keys wrapped via RFC 9180 HPKE over X25519 — storage nodes never see your data. A hybrid X25519 + ML-KEM-768 primitive ships in `fula-crypto::hybrid_kem` for applications that want post-quantum wrapping today; the default client path is X25519-only while that migration is in flight.
- **✅ Verified Streaming**: BLAKE3/Bao root hash plus per-chunk AAD binding ensures large files reassemble from exactly the bytes that were uploaded
- **🧭 Private index (forest)**: an encrypted per-bucket index that maps real paths to scrambled storage keys — now a sharded HAMT (v7) borrowed from [rs-wnfs](https://github.com/wnfs-wg/rs-wnfs), so a bucket with millions of entries doesn't require downloading the whole index
- **🔄 Conflict-Free Sync**: CRDT-based metadata for distributed updates
- **📈 Efficient Indexing**: Prolly Trees for O(log n) bucket operations on the server side

## How it works (plain English)

**Encryption & storage.** Every file gets its own random 32-byte key. Files up to 768 KB are sealed as a single blob; anything larger is sliced into 256 KB pieces and each piece is sealed separately with a tag that names the file and the piece — so pieces can't be shuffled, swapped, or replayed across files. The real filename and folder are replaced by a random-looking ID before anything leaves your machine, and the per-file key is itself wrapped with your own keypair so only you can open it. A small encrypted index (the "private forest") remembers which scrambled ID belongs to which real filename; it lives in the same bucket but is itself encrypted, and for large libraries it's stored as a sharded hash-array-mapped-trie (HAMT) so the client only loads the pieces it needs.

**Decryption.** Your personal key unwraps the per-file key, the client decrypts the blob (or reassembles and checks each piece against its tag and the file's BLAKE3 root hash), and you get your bytes back. The forest also pins a hash of the original plaintext, so tampering after upload is detected even if the server somehow produced a blob with a valid inner tag.

**Sharing.** To share, the client re-wraps the file's key for the recipient's public key and attaches a short note — what they can do, when the share expires, and which path it covers. The result is a small token placed in the URL fragment after `#`, so the server never sees the key. The recipient pastes the link, their own key unwraps the token, and they fetch the encrypted bytes through a lightweight proxy endpoint (no S3 account required for the recipient). Your personal key stays private; you're only handing over that one file's lock. Shares come in two flavors: **temporal** (always resolves to the current version of the shared path) or **snapshot** (locked to the exact content hash at share time, refuses to serve a newer version).

## 📖 Documentation

- **[Introduction](https://functionland.github.io/fula-api/)** - Architecture, concepts, and how it works
- **[API Reference](https://functionland.github.io/fula-api/api.html)** - Complete endpoint documentation with examples
- **[SDK Examples](https://functionland.github.io/fula-api/sdk.html)** - Code examples for Rust, Python, JavaScript
- **[Platform Guides](https://functionland.github.io/fula-api/platforms.html)** - Next.js, React Native, .NET, Flutter, Swift, Kotlin

## Architecture

```
┌────────────────────────────────────────────────────────────────┐
│                      Application Layer                         │
│          (boto3, AWS SDK, Flutter/React-Native app, browser)   │
├────────────────────────────────────────────────────────────────┤
│           fula-client  /  fula-flutter  /  fula-js (WASM)      │
│  ┌──────────────┬────────────────────┬──────────────────────┐  │
│  │  Per-file    │  Chunked streaming │  Sharded HAMT v7     │  │
│  │  AEAD +      │  (256 KB chunks,   │  private forest      │  │
│  │  path        │   per-chunk AAD,   │  (encrypted index,   │  │
│  │  obfuscation │   Bao root hash)   │   lazy shard load)   │  │
│  └──────────────┴────────────────────┴──────────────────────┘  │
├────────────────────────────────────────────────────────────────┤
│                       Fula Gateway                             │
│    ┌─────────────┬──────────────┬──────────────────────┐       │
│    │    Auth     │ Rate Limiter │   S3 API Handlers    │       │
│    └─────────────┴──────────────┴──────────────────────┘       │
├────────────────────────────────────────────────────────────────┤
│                        fula-core                               │
│    ┌─────────────┬──────────────┬──────────────────────┐       │
│    │Prolly Trees │    Buckets   │       CRDTs          │       │
│    └─────────────┴──────────────┴──────────────────────┘       │
├────────────────────────────────────────────────────────────────┤
│                     fula-blockstore                            │
│    ┌─────────────┬──────────────┬──────────────────────┐       │
│    │    IPFS     │ IPFS Cluster │  FastCDC (IPFS-layer)│       │
│    └─────────────┴──────────────┴──────────────────────┘       │
├────────────────────────────────────────────────────────────────┤
│                        fula-crypto                             │
│  ┌───────────────┬──────────────┬──────────────┬────────────┐  │
│  │  RFC 9180     │   BLAKE3     │     Bao      │ hybrid_kem │  │
│  │  HPKE         │   hashing    │   verified   │ X25519 +   │  │
│  │  (X25519 KEM) │              │   streaming  │ ML-KEM-768 │  │
│  │               │              │              │ (opt-in)   │  │
│  └───────────────┴──────────────┴──────────────┴────────────┘  │
└────────────────────────────────────────────────────────────────┘
```

The client stack (top) is where all encryption, obfuscation, and forest-index
work happens. The gateway and block-store layers never see plaintext, nor
real paths — they see random-looking content-addressed keys.

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
| `fula-crypto` | Cryptographic primitives: RFC 9180 HPKE over X25519 (`hpke.rs`), AES-256-GCM/ChaCha20-Poly1305 AEAD (`symmetric.rs`), chunked streaming with per-chunk AAD (`chunked.rs`), BLAKE3 + Bao verified streaming (`streaming.rs`, `hashing.rs`), sharded HAMT v7 private forest (`sharded_hamt_forest.rs`, vendored `wnfs_hamt/`), share tokens (`sharing.rs`), key rotation (`rotation.rs`), opt-in hybrid PQ KEM X25519 + ML-KEM-768 (`hybrid_kem.rs`) |
| `fula-blockstore` | IPFS block storage (content-addressed) |
| `fula-core` | Storage engine: Prolly Trees for server-side bucket metadata, CRDT sync |
| `fula-cli` | S3-compatible gateway server |
| `fula-client` | Client SDK: encrypts, obfuscates paths, maintains the sharded HAMT forest, handles resumable chunked uploads, downgrade-gated reads |
| `fula-flutter` | `flutter_rust_bridge` bindings over `fula-client` for the FxFiles app |
| `fula-js` | WASM/TypeScript bindings (`wasm-bindgen`) for browsers — powers the web share-viewer and anything embedding `@functionland/fula-client` |

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

### 🔐 Cryptographic Primitives

| Component | Algorithm | Where it's used |
|-----------|-----------|-----------------|
| Symmetric AEAD (content) | AES-256-GCM (default), ChaCha20-Poly1305 | Per-file and per-chunk content encryption, 12-byte random nonce, 16-byte tag, AAD `fula:v4:content:{storage_key}` (single) / `fula:v4:chunk:{storage_key}:{index}` (chunked) |
| Key Encapsulation (KEM) | RFC 9180 HPKE over X25519 (HkdfSha256, ChaCha20-Poly1305) | Wrapping the per-file DEK for the owner's keypair and for share recipients; DEK-wrap AAD = `fula:v2:dek-wrap` |
| Integrity | BLAKE3 + Bao verified streaming | Root hash of the plaintext of chunked files; checked at `finalize_and_verify` |
| Forest integrity pin | Unkeyed BLAKE3 over plaintext | Stored in the forest entry so a swap of tagged-but-wrong ciphertext still fails (audit finding H-1) |
| Version pin | `min_version: u8` in forest entry | Rejects downgrade to pre-AAD blobs after a v4 upload (audit finding H-2) |
| Post-quantum KEM (opt-in) | `fula_crypto::hybrid_kem` — X25519 + ML-KEM-768 (libcrux-ml-kem, NIST FIPS 203) | Available as a primitive; **not** wired into the default `EncryptedClient` wrap path yet. Applications can use it directly if they want PQ wrapping today. |

```rust
// Opt-in hybrid PQ wrap — standalone primitive, not the default client path.
use fula_crypto::{HybridKeyPair, hybrid_encapsulate, hybrid_decapsulate};

let keypair = HybridKeyPair::generate();
let (encapsulated_key, shared_secret) = hybrid_encapsulate(keypair.public_key())?;
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

**What's encrypted** (with `EncryptedClient` in its default `FlatNamespace` mode):
- ✅ File content (AEAD with per-file DEK; chunked files also carry per-chunk AAD)
- ✅ File names and folder paths (server only sees CID-like `Qm…` keys; the forest index that maps the real path back is itself encrypted)
- ✅ Directory structure (no `/` in storage keys; folder membership is only visible inside the encrypted forest)
- ✅ User IDs (hashed via BLAKE3 KDF + path-specific key derivation)
- ✅ Listings: the `list_files_from_forest` path decrypts the forest client-side; the server cannot answer `ls` queries with structural info

**What remains visible to the gateway**:
- ⚠️ Bucket names (not encrypted by design — they're routing identifiers)
- ⚠️ Approximate ciphertext sizes (per-file for single-object; per-chunk for chunked — the 256 KB chunking partially smooths this for large files)
- ⚠️ Request timestamps and access patterns
- ⚠️ The existence of chunk objects at `{storage_key}.chunks/{index:08}` (the pattern reveals "this file is chunked" and roughly how many chunks)

See [docs/PRIVACY.md](docs/PRIVACY.md) for full privacy policy.

### Large File Support (WNFS-inspired)

Chunking is **automatic**. Anything larger than 768 KB (the `CHUNKED_THRESHOLD`, also the IPFS block-size safety ceiling) is split into 256 KB chunks by default, each sealed with its own AEAD tag bound to the file and chunk index (`fula:v4:chunk:{storage_key}:{index}`). You keep calling `put_object_encrypted`; the client picks the right path:

```rust
use fula_client::EncryptedClient;

// Same API for small and large files — chunking is automatic.
let data = std::fs::read("movie.mp4")?;
client.put_object_encrypted("my-bucket", "/videos/movie.mp4", &data).await?;

// Partial read — only downloads the chunks covering the requested range.
let partial = client.get_object_range(
    "my-bucket",
    "/videos/movie.mp4",
    1024 * 1024,  // offset: 1 MiB
    1024 * 1024,  // length: 1 MiB
).await?;

// Explicit chunked API is still available if you want to override the
// default chunk size (clamped to [64 KB, 768 KB]):
client.put_object_chunked("my-bucket", "/videos/movie.mp4", &data, Some(256 * 1024)).await?;
```

**Benefits:**
- Memory efficient: chunks are decrypted and written one at a time (bounded window = 16 concurrent fetches)
- Partial reads: download only the bytes you need
- Resumable: failed uploads can restart from the last chunk (see `put_object_encrypted_resumable`)
- Integrity: per-chunk AEAD + Bao root hash over the whole plaintext, verified on `finalize`
- Downgrade-proof: the forest entry pins `min_version = 4`, so an attacker-authored legacy (no-AAD) blob at the same storage key is rejected on read (H-2)

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
cd /opt/fula-api
/opt/fula-api# docker-compose -f /etc/fula/docker-compose.yml build --no-cache gateway
systemctl restart fula-gateway
```