# WNFS-Inspired Features in Fula

This document describes features borrowed from the [WNFS (WebNative File System)](https://github.com/wnfs-wg/rs-wnfs) project and adapted for Fula's encrypted IPFS gateway architecture.

## Overview

Fula borrows two key architectural patterns from WNFS while maintaining its own strengths:

| Feature | WNFS Pattern | Fula Adaptation | Status |
|---------|--------------|-----------------|--------|
| **Large File Streaming** | Block-level encryption + index node | Chunked encryption + index object | ✅ Implemented |
| **HAMT Forest Index** | HamtForest for scalable tree indexing | HamtIndex/ShardedIndex for PrivateForest | ✅ Module ready, integration pending |

---

## 1. Streaming Encryption for Large Files

### Problem Solved

The original `EncryptedClient` encrypted entire files in memory before upload, which:
- Limited maximum file size by available RAM
- Prevented partial/range reads without downloading the entire file
- Made progress tracking difficult for large uploads

### WNFS Inspiration

From `wnfs/src/private/file.rs`:

```rust
/// Keys and pointers to encrypted content stored in a `PrivateForest`.
pub struct PrivateForestContent {
    pub key: SnapshotKey,
    pub base_name: NameAccumulator,
    pub block_count: u64,
    pub block_content_size: u64,
}
```

WNFS splits files into fixed-size blocks, each encrypted separately and stored under its own CID. A small "file node" (index) contains the key, block count, and pointers.

### Fula Implementation

**New module:** `crates/fula-crypto/src/chunked.rs`

```rust
/// Metadata for a chunked/streaming encrypted file
pub struct ChunkedFileMetadata {
    pub format: String,          // "streaming-v1"
    pub chunk_size: u32,         // Size of each chunk (default 256KB)
    pub num_chunks: u32,         // Number of chunks
    pub total_size: u64,         // Total file size
    pub root_hash: String,       // Bao root hash for integrity
    pub chunk_nonces: Vec<String>, // Per-chunk nonces
    pub content_type: Option<String>,
}
```

**Key components:**

- **`ChunkedEncoder`**: Processes data in chunks, encrypts each with AES-256-GCM
- **`ChunkedDecoder`**: Decrypts chunks and reassembles the file
- **`ChunkedFileMetadata`**: Stored in the index object's `x-fula-encryption` header

**New EncryptedClient methods:**

```rust
// Upload large file as encrypted chunks
pub async fn put_object_chunked(
    &self,
    bucket: &str,
    key: &str,
    data: &[u8],
    chunk_size: Option<usize>,
) -> Result<PutObjectResult>;

// Download and decrypt chunked file
pub async fn get_object_chunked(
    &self,
    bucket: &str,
    key: &str,
) -> Result<Bytes>;

// Partial read - only downloads needed chunks
pub async fn get_object_range(
    &self,
    bucket: &str,
    key: &str,
    offset: u64,
    length: u64,
) -> Result<Bytes>;

// Check if file should use chunked upload
pub fn should_use_chunked(size: usize) -> bool;
```

### Storage Layout

For a file `/photos/vacation.mp4` with storage key `abc123`:

```
abc123              <- Index object (small, contains metadata)
abc123.chunks/00000000  <- Encrypted chunk 0
abc123.chunks/00000001  <- Encrypted chunk 1
abc123.chunks/00000002  <- Encrypted chunk 2
...
```

### Metadata Format (version 3)

```json
{
  "version": 3,
  "format": "streaming-v1",
  "algorithm": "AES-256-GCM",
  "wrapped_key": { /* HPKE-wrapped DEK */ },
  "kek_version": 1,
  "chunked": {
    "format": "streaming-v1",
    "chunk_size": 262144,
    "num_chunks": 10,
    "total_size": 2621440,
    "root_hash": "...",
    "chunk_nonces": ["...", "..."],
    "content_type": "video/mp4"
  },
  "bao_outboard": "..."
}
```

### Compatibility

| Aspect | Preserved? | Notes |
|--------|------------|-------|
| S3 Compatibility | ✅ | Chunks are regular S3 objects |
| HPKE Encryption | ✅ | DEK still wrapped with HPKE in index |
| Full Privacy | ✅ | All chunks encrypted, index encrypted |
| Metadata Listing | ✅ | PrivateForest tracks files normally |
| Backward Compat | ✅ | `format: "streaming-v1"` distinguishes from v2 |

---

## 2. HAMT-Based Forest Index

### Problem Solved

The current `PrivateForest` stores all files in a flat `HashMap<String, ForestFileEntry>`:
- Entire forest must be loaded/decrypted to list any directory
- For buckets with millions of files, the forest JSON becomes very large
- No sharding or lazy loading

### WNFS Inspiration

From `wnfs-hamt/src/hamt.rs`:

```rust
/// Hash Array Mapped Trie (HAMT) for efficient key-value storage
pub struct Hamt<K, V, H = blake3::Hasher> {
    pub root: Arc<Node<K, V, H>>,
    pub version: Version,
}
```

WNFS uses a HAMT (Hash Array Mapped Trie) for its forest, allowing:
- O(log N) lookups, inserts, and deletes
- Lazy loading of subtrees
- Efficient serialization of changed portions only

### Fula Implementation

**New module:** `crates/fula-crypto/src/hamt_index.rs`

**Two implementations:**

#### 1. Full HAMT (`HamtIndex<V>`)

```rust
/// A HAMT-based index for file entries
pub struct HamtIndex<V: Clone> {
    pub version: u8,
    pub root: HamtNode<V>,
    pub count: usize,
}

pub enum HamtNode<V: Clone> {
    Empty,
    Bucket { entries: Vec<(String, V)> },
    Branch { bitmap: u16, children: Vec<HamtNode<V>> },
}
```

**Operations:**
- `insert(path, value)` - O(log N)
- `get(path)` - O(log N)
- `remove(path)` - O(log N)
- `iter_prefix(prefix)` - Iterate entries with path prefix

#### 2. Sharded Index (`ShardedIndex<V>`)

A simpler alternative for moderate scale:

```rust
/// Sharded prefix index for efficient prefix queries
pub struct ShardedIndex<V: Clone> {
    pub version: u8,
    pub num_shards: usize,
    pub shards: Vec<HashMap<String, V>>,
    pub count: usize,
}
```

Shards entries by BLAKE3 hash prefix (default 16 shards).

### Integration Plan

The HAMT modules are ready but not yet integrated into `PrivateForest`. The integration will:

1. Add a version field to `PrivateForest`:
   ```rust
   enum PrivateForestFormat {
       FlatMapV1,  // Current format
       HamtV2,     // New HAMT-backed format
   }
   ```

2. On load: detect format and deserialize appropriately
3. On save: optionally migrate to HAMT format
4. Keep the same `PrivateForest` API (`upsert_file`, `get_file`, etc.)

### Test Coverage

```
test hamt_index::tests::test_hamt_basic_operations ... ok
test hamt_index::tests::test_hamt_many_entries ... ok
test hamt_index::tests::test_hamt_prefix_iteration ... ok
test hamt_index::tests::test_hamt_hashmap_conversion ... ok
test hamt_index::tests::test_sharded_index_basic ... ok
test hamt_index::tests::test_sharded_distribution ... ok
```

---

## 3. What We Didn't Borrow

Some WNFS features were explicitly **not** adopted because they don't fit Fula's architecture:

| WNFS Feature | Why Not Adopted |
|--------------|-----------------|
| **Ratchets** | Per-node forward secrecy is complex; Fula uses KEK rotation instead |
| **Name Accumulators** | RSA-based setup is heavy; Fula uses BLAKE3 path hashing |
| **Multivalue HAMT** | Fula doesn't need conflict resolution for concurrent writes |
| **TemporalKey/SnapshotKey** | Fula uses simpler DEK-per-file model |

---

## 4. Feature Comparison After Enhancements

| Aspect | Fula (Before) | Fula (After) | WNFS |
|--------|---------------|--------------|------|
| **Large file handling** | Whole-file encryption | Chunked + partial reads | Block-level |
| **Forest scalability** | Flat HashMap | HAMT available | HamtForest |
| **Partial reads** | Not supported | ✅ `get_object_range()` | ✅ Block addressing |
| **Streaming upload** | Not supported | ✅ `put_object_chunked()` | ✅ Streaming |
| **Memory usage** | O(file size) | O(chunk size) | O(block size) |

---

## 5. Usage Examples

### Chunked Upload

```rust
use fula_client::EncryptedClient;

let client = EncryptedClient::new(config);

// Large file - use chunked upload
let large_data = std::fs::read("movie.mp4")?;
if EncryptedClient::should_use_chunked(large_data.len()) {
    client.put_object_chunked(
        "my-bucket",
        "/videos/movie.mp4",
        &large_data,
        Some(512 * 1024), // 512KB chunks
    ).await?;
}
```

### Partial Read

```rust
// Read only bytes 1MB to 2MB of a file
let partial = client.get_object_range(
    "my-bucket",
    "/videos/movie.mp4",
    1024 * 1024,  // offset
    1024 * 1024,  // length
).await?;
```

### HAMT Index

```rust
use fula_crypto::HamtIndex;

let mut index: HamtIndex<String> = HamtIndex::new();

// Add files
index.insert("/photos/beach.jpg".to_string(), "cid1".to_string());
index.insert("/photos/mountain.jpg".to_string(), "cid2".to_string());

// Lookup
assert_eq!(index.get("/photos/beach.jpg"), Some(&"cid1".to_string()));

// Prefix iteration
for (path, cid) in index.iter_prefix("/photos/") {
    println!("{}: {}", path, cid);
}
```

---

## 6. Implementation Status

| Component | Status | Files |
|-----------|--------|-------|
| `ChunkedEncoder` | ✅ Complete | `crates/fula-crypto/src/chunked.rs` |
| `ChunkedDecoder` | ✅ Complete | `crates/fula-crypto/src/chunked.rs` |
| `ChunkedFileMetadata` | ✅ Complete | `crates/fula-crypto/src/chunked.rs` |
| `put_object_chunked` | ✅ Complete | `crates/fula-client/src/encryption.rs` |
| `get_object_chunked` | ✅ Complete | `crates/fula-client/src/encryption.rs` |
| `get_object_range` | ✅ Complete | `crates/fula-client/src/encryption.rs` |
| `HamtIndex` | ✅ Complete | `crates/fula-crypto/src/hamt_index.rs` |
| `ShardedIndex` | ✅ Complete | `crates/fula-crypto/src/hamt_index.rs` |
| HAMT in PrivateForest | ✅ Complete | `crates/fula-crypto/src/private_forest.rs` |
| `AsyncStreamingEncoder` | ✅ Complete | `crates/fula-crypto/src/chunked.rs` |
| `VerifiedStreamingDecoder` | ✅ Complete | `crates/fula-crypto/src/chunked.rs` |
| `ForestFormat` (versioning) | ✅ Complete | `crates/fula-crypto/src/private_forest.rs` |

---

## 7. Test Results

```
Chunked encryption tests (7 tests):
  test_chunked_roundtrip ... ok
  test_chunk_key_generation ... ok
  test_chunks_for_range ... ok
  test_should_use_chunked ... ok
  test_async_streaming_encoder ... ok
  test_verified_streaming_decoder ... ok
  test_verified_decoder_detects_corruption ... ok

HAMT index tests (6 tests):
  test_hamt_basic_operations ... ok
  test_hamt_many_entries ... ok
  test_hamt_prefix_iteration ... ok
  test_hamt_hashmap_conversion ... ok
  test_sharded_index_basic ... ok
  test_sharded_distribution ... ok

Private Forest HAMT tests (4 tests):
  test_hamt_forest_basic ... ok
  test_hamt_migration ... ok
  test_hamt_operations ... ok
  test_hamt_serialization_roundtrip ... ok

Total: 105 tests in fula-crypto
```

---

## 8. Completed Future Work

All originally planned future work items have been implemented:

### ✅ 1. HAMT Integration into PrivateForest
- **Format versioning**: `ForestFormat::FlatMapV1` vs `ForestFormat::HamtV2`
- **Automatic migration**: `migrate_to_hamt()` and `migrate_to_flat()`
- **Auto-migration threshold**: 1000 files triggers automatic HAMT migration
- **Backward compatible**: Old forests load as FlatMapV1

```rust
// Create HAMT-backed forest
let forest = PrivateForest::new_hamt();

// Or migrate existing forest
let mut forest = PrivateForest::new();
// ... add files ...
if forest.should_migrate_to_hamt() {
    forest.migrate_to_hamt();
}
```

### ✅ 2. True Streaming Upload (AsyncRead)
- **`AsyncStreamingEncoder`**: Accepts `AsyncRead` sources
- **O(chunk_size) memory**: Processes data as it arrives
- **Tokio compatible**: Works with async file I/O

```rust
use fula_crypto::AsyncStreamingEncoder;

let file = tokio::fs::File::open("large_file.mp4").await?;
let mut encoder = AsyncStreamingEncoder::new(dek);
let chunks = encoder.process_reader(file).await?;
let (metadata, outboard) = encoder.finalize();
```

### ✅ 3. Verified Streaming Download (Bao)
- **`VerifiedStreamingDecoder`**: Verifies integrity during decryption
- **Progressive verification**: Updates hash state per chunk
- **Corruption detection**: Detects tampering at finalize

```rust
use fula_crypto::VerifiedStreamingDecoder;

let mut decoder = VerifiedStreamingDecoder::new(dek, metadata)?;
for chunk in chunks {
    decoder.decrypt_and_verify(chunk.index, &chunk.ciphertext)?;
}
let is_valid = decoder.finalize_and_verify()?;
```

---

## 9. Remaining Future Work

4. **Borrow more from WNFS**
   - Asynchronous offline sharing protocol
   - Store-and-forward share discovery

---

## References

- [WNFS Specification](https://github.com/wnfs-wg/spec)
- [rs-wnfs Repository](https://github.com/wnfs-wg/rs-wnfs)
- [Fula WNFS Comparison](./wnfs-comparison.md)
