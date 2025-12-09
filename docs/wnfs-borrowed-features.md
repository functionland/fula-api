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
| `SecretLink` | ✅ Complete | `crates/fula-crypto/src/secret_link.rs` |
| `SecretLinkBuilder` | ✅ Complete | `crates/fula-crypto/src/secret_link.rs` |
| `ShareMode` | ✅ Complete | `crates/fula-crypto/src/sharing.rs` |
| `SnapshotBinding` | ✅ Complete | `crates/fula-crypto/src/sharing.rs` |
| `SubtreeKeyManager` | ✅ Complete | `crates/fula-crypto/src/subtree_keys.rs` |
| `SubtreeShareToken` | ✅ Complete | `crates/fula-crypto/src/subtree_keys.rs` |
| `ShareEnvelope` | ✅ Complete | `crates/fula-crypto/src/inbox.rs` |
| `ShareInbox` | ✅ Complete | `crates/fula-crypto/src/inbox.rs` |

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

Secret Link tests (14 tests):
  test_secret_link_creation ... ok
  test_secret_link_to_url ... ok
  test_secret_link_roundtrip ... ok
  test_secret_link_with_label ... ok
  test_secret_link_with_metadata ... ok
  test_extract_opaque_id ... ok
  test_is_valid_secret_link_url ... ok
  test_parse_invalid_url_no_fragment ... ok
  test_parse_invalid_url_wrong_path ... ok
  test_parse_invalid_payload ... ok
  test_gateway_url_trailing_slash ... ok
  test_secret_link_permissions ... ok
  test_secret_link_path_validation ... ok
  test_fragment_never_contains_sensitive_chars ... ok

Snapshot/Temporal Share Mode tests (12 tests):
  test_temporal_share_default ... ok
  test_snapshot_share_creation ... ok
  test_snapshot_share_with_values ... ok
  test_snapshot_verification_valid ... ok
  test_snapshot_verification_content_changed ... ok
  test_snapshot_verification_size_changed ... ok
  test_temporal_share_always_valid ... ok
  test_snapshot_requires_binding ... ok
  test_snapshot_binding_storage_key ... ok
  test_is_snapshot_valid_helper ... ok
  test_share_mode_enum ... ok
  test_share_token_serialization_with_mode ... ok

Subtree Keys tests (14 tests - Peergos Cryptree-inspired):
  test_encrypted_subtree_dek_roundtrip ... ok
  test_subtree_key_manager_create ... ok
  test_subtree_key_manager_resolve ... ok
  test_subtree_key_manager_nested_resolution ... ok
  test_subtree_key_rotation ... ok
  test_subtree_key_load ... ok
  test_subtree_share_token_creation ... ok
  test_subtree_share_accept ... ok
  test_wrong_recipient_cannot_accept ... ok
  test_path_normalization ... ok
  test_list_subtrees ... ok
  test_remove_subtree ... ok
  test_subtree_share_serialization ... ok

Async Inbox tests (10 tests - WNFS-inspired):
  test_share_envelope_creation ... ok
  test_inbox_entry_encrypt_decrypt ... ok
  test_wrong_recipient_cannot_decrypt ... ok
  test_share_inbox_workflow ... ok
  test_inbox_dismiss ... ok
  test_inbox_cleanup ... ok
  test_inbox_path_generation ... ok
  test_share_envelope_builder ... ok
  test_multiple_shares_same_recipient ... ok
  test_inbox_entry_serialization ... ok

Total: 154 tests in fula-crypto
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

### ✅ 4. Secret Link URL Patterns (Peergos-Inspired)
- **Fragment privacy**: All key material in URL fragment, never sent to server
- **`SecretLink`**: Create and parse share links with embedded tokens
- **`SecretLinkBuilder`**: Fluent API for building links with labels and metadata
- **URL-safe encoding**: Base64url encoding without padding

```rust
use fula_crypto::{SecretLink, SecretLinkBuilder, ShareBuilder, KekKeyPair, DekKey};

// Create a secret link (key material only in fragment)
let token = ShareBuilder::new(&owner, recipient.public_key(), &dek)
    .path_scope("/photos/vacation/")
    .expires_in(3600)
    .build()?;

let link = SecretLinkBuilder::new(&token, "https://gateway.example")
    .label("Vacation Photos")
    .build()?;

let url = link.to_url()?;
// => "https://gateway.example/fula/share/abc123#eyJ2ZXJzaW9uIjox..."
// Server only sees: /fula/share/abc123

// Parse received link
let parsed = SecretLink::parse(&url)?;
let extracted_token = parsed.extract_token();
```

### ✅ 5. Snapshot vs Temporal Share Modes (WNFS-Inspired)
- **`ShareMode` enum**: `Temporal` (default) vs `Snapshot` variants
- **`SnapshotBinding`**: Content hash, size, and timestamp for snapshot verification
- **Backward compatible**: Existing shares default to Temporal mode
- **Verification methods**: `verify_snapshot()` and `is_snapshot_valid()`

```rust
use fula_crypto::{ShareBuilder, SnapshotBinding, ShareMode};

// Temporal share (default) - access evolves with content
let temporal_share = ShareBuilder::new(&owner, recipient.public_key(), &dek)
    .path_scope("/photos/vacation/")
    .temporal()
    .build()?;

// Snapshot share - bound to specific content version
let snapshot_share = ShareBuilder::new(&owner, recipient.public_key(), &dek)
    .path_scope("/documents/contract.pdf")
    .snapshot_with("abc123def456", 102400, 1700000000)
    .build()?;

// Verify snapshot validity
assert!(snapshot_share.is_snapshot_valid("abc123def456"));
```

### ✅ 6. Multi-Device Key Management & Threat Model Documentation
- **Comprehensive threat model**: `docs/THREAT_MODEL.md` with adversary analysis
- **Multi-device patterns**: Shared identity, per-device keys, hierarchical keys
- **Device loss handling**: Rotation procedures, revocation strategies
- **Key backup strategies**: Paper backup, HSM, encrypted cloud
- **WNFS comparison**: Security model differences documented

### ✅ 7. Shallow Cryptree-Style Subtree Keys (Peergos-Inspired)
- **`SubtreeKeyManager`**: Manages master + subtree DEKs hierarchy
- **`EncryptedSubtreeDek`**: Encrypted subtree key stored in directory entries
- **`SubtreeShareToken`**: Share entire subtrees with recipients
- **Key resolution**: Most specific prefix match, falls back to master
- **Subtree rotation**: Re-key individual subtrees for revocation

```rust
use fula_crypto::{SubtreeKeyManager, SubtreeShareBuilder, DekKey};

// Create subtree key hierarchy
let mut manager = SubtreeKeyManager::with_master_dek(master_dek);
let (photos_dek, encrypted) = manager.create_subtree("/photos/")?;

// Files automatically use the right DEK
let dek = manager.resolve_dek("/photos/beach.jpg");  // Returns photos_dek
let dek = manager.resolve_dek("/readme.txt");        // Returns master_dek

// Revoke by rotating subtree key
let rotation = manager.rotate_subtree("/photos/")?;
// Old shares become invalid, new shares use rotation.new_dek
```

### ✅ 8. Async/Offline Inbox Sharing (WNFS-Inspired)
- **`ShareEnvelope`**: Container for ShareToken + metadata (label, message, sharer info)
- **`InboxEntry`**: HPKE-encrypted envelope for store-and-forward sharing
- **`ShareInbox`**: Manager for inbox operations (enqueue, list, accept, dismiss)
- **`ShareEnvelopeBuilder`**: Fluent API for creating share envelopes
- **Inbox location**: `/.fula/inbox/<recipient-hash>/` convention

```rust
use fula_crypto::{ShareEnvelopeBuilder, ShareInbox, KekKeyPair, DekKey};

// Sharer creates and enqueues share
let (envelope, entry) = ShareEnvelopeBuilder::new(&sharer, recipient.public_key(), &dek)
    .path_scope("/photos/")
    .label("Vacation Photos")
    .message("Check these out!")
    .sharer_name("Alice")
    .build()?;

// Store in recipient's inbox location
let path = ShareInbox::entry_storage_path(recipient.public_key(), &entry.id);

// Later, recipient lists and accepts shares
let mut inbox = ShareInbox::new();
inbox.add_entry(entry);
let pending = inbox.list_pending(&recipient);
let accepted = inbox.accept_entry(&entry_id, &recipient)?;
```

---

## 9. Remaining Future Work

All major WNFS/Peergos-inspired features have been implemented:
- ✅ HAMT integration for large forests
- ✅ Chunked streaming encryption
- ✅ Secret links (key material in URL fragment)
- ✅ Snapshot vs Temporal share modes
- ✅ Subtree keys (Cryptree-style)
- ✅ Async/offline inbox sharing
- ✅ Multi-device key management documentation
- ✅ Comprehensive threat model

**Optional future enhancements:**
- Coarse forest sharding (only if very large buckets become an issue)
- Integration with DID/identity systems for sharer verification
- Push notifications for inbox updates

---

## References

- [WNFS Specification](https://github.com/wnfs-wg/spec)
- [rs-wnfs Repository](https://github.com/wnfs-wg/rs-wnfs)
- [Fula WNFS Comparison](./wnfs-comparison.md)
