//! Integration tests for Fula Storage API
//!
//! These tests verify end-to-end functionality of the storage system.

use fula_blockstore::MemoryBlockStore;
use fula_core::{BucketManager, metadata::Owner};
use fula_crypto::{
    keys::{KekKeyPair, KeyManager},
    hpke::{Encryptor, Decryptor},
    hashing::hash,
    symmetric::{encrypt, decrypt},
};
use std::sync::Arc;

/// Test BLAKE3 hashing
#[test]
fn test_blake3_hashing() {
    let data = b"Hello, World!";
    let hash1 = hash(data);
    let hash2 = hash(data);
    
    // Same input produces same hash
    assert_eq!(hash1, hash2);
    
    // Different input produces different hash
    let hash3 = hash(b"Different data");
    assert_ne!(hash1, hash3);
}

/// Test symmetric encryption roundtrip
#[test]
fn test_symmetric_encryption() {
    use fula_crypto::keys::DekKey;
    
    let key = DekKey::generate();
    let plaintext = b"Secret message";
    
    let (nonce, ciphertext) = encrypt(&key, plaintext).unwrap();
    let decrypted = decrypt(&key, &nonce, &ciphertext).unwrap();
    
    assert_eq!(plaintext.as_slice(), decrypted.as_slice());
}

/// Test HPKE encryption for sharing
#[test]
fn test_hpke_encryption() {
    // Generate recipient key pair
    let recipient = KekKeyPair::generate();
    
    // Encrypt data for recipient
    let encryptor = Encryptor::new(recipient.public_key());
    let encrypted = encryptor.encrypt(b"Shared secret").unwrap();
    
    // Recipient decrypts
    let decryptor = Decryptor::new(&recipient);
    let decrypted = decryptor.decrypt(&encrypted).unwrap();
    
    assert_eq!(b"Shared secret".as_slice(), decrypted.as_slice());
}

/// Test HPKE with wrong key fails
#[test]
fn test_hpke_wrong_key_fails() {
    let keypair1 = KekKeyPair::generate();
    let keypair2 = KekKeyPair::generate();
    
    let encryptor = Encryptor::new(keypair1.public_key());
    let encrypted = encryptor.encrypt(b"Secret").unwrap();
    
    // Try to decrypt with wrong key
    let decryptor = Decryptor::new(&keypair2);
    let result = decryptor.decrypt(&encrypted);
    
    assert!(result.is_err());
}

/// Test key management
#[test]
fn test_key_manager() {
    let mut km = KeyManager::new();
    
    // Generate DEKs
    let dek1 = km.generate_dek();
    let dek2 = km.generate_dek();
    assert_ne!(dek1.as_bytes(), dek2.as_bytes());
    
    // Path-based key derivation
    let path_key1 = km.derive_path_key("/bucket/file1.txt");
    let path_key2 = km.derive_path_key("/bucket/file2.txt");
    assert_ne!(path_key1.as_bytes(), path_key2.as_bytes());
    
    // Key rotation
    let v1 = km.version();
    km.rotate();
    assert_eq!(km.version(), v1 + 1);
}

/// Test block store operations
#[tokio::test]
async fn test_memory_blockstore() {
    use fula_blockstore::BlockStore;
    
    let store = MemoryBlockStore::new();
    
    // Put a block
    let data = b"Test block data";
    let cid = store.put_block(data).await.unwrap();
    
    // Get the block back
    let retrieved = store.get_block(&cid).await.unwrap();
    assert_eq!(data.as_slice(), retrieved.as_ref());
    
    // Check existence
    assert!(store.has_block(&cid).await.unwrap());
    
    // Delete block
    store.delete_block(&cid).await.unwrap();
    assert!(!store.has_block(&cid).await.unwrap());
}

/// Test chunking
#[test]
fn test_file_chunking() {
    use fula_blockstore::{Chunker, ChunkerConfig};
    
    // Create 1MB of data
    let data: Vec<u8> = (0..1024 * 1024).map(|i| (i % 256) as u8).collect();
    
    let config = ChunkerConfig::with_chunk_size(256 * 1024).unwrap(); // 256KB chunks
    let chunker = Chunker::with_config(config);
    
    let result = chunker.chunk_bytes(&data);
    
    // Should have 4 chunks
    assert_eq!(result.chunk_count, 4);
    assert_eq!(result.total_size, 1024 * 1024);
    
    // Reassemble and verify
    let reassembled = chunker.reassemble(&result.chunks);
    assert_eq!(data.as_slice(), reassembled.as_ref());
}

/// Test CID generation
#[test]
fn test_cid_generation() {
    use fula_blockstore::cid_utils::{create_cid, verify_cid, CidCodec};
    
    let data = b"Content addressed data";
    let cid = create_cid(data, CidCodec::Raw);
    
    // Verify CID
    assert!(verify_cid(data, &cid));
    assert!(!verify_cid(b"Wrong data", &cid));
}

/// Test bucket management
#[tokio::test]
async fn test_bucket_operations() {
    let store = Arc::new(MemoryBlockStore::new());
    let manager = BucketManager::new(store);
    
    let owner = Owner::new("test-user");
    
    // Create bucket
    let metadata = manager.create_bucket("test-bucket".to_string(), owner).await.unwrap();
    assert_eq!(metadata.name, "test-bucket");
    
    // Check bucket exists
    assert!(manager.bucket_exists("test-bucket"));
    assert!(!manager.bucket_exists("nonexistent"));
    
    // List buckets
    let buckets = manager.list_buckets();
    assert_eq!(buckets.len(), 1);
    
    // Delete bucket
    manager.delete_bucket("test-bucket").await.unwrap();
    assert!(!manager.bucket_exists("test-bucket"));
}

/// Test object storage in bucket
#[tokio::test]
async fn test_object_operations() {
    use fula_core::{Bucket, BucketConfig, metadata::ObjectMetadata};
    
    let store = Arc::new(MemoryBlockStore::new());
    let owner = Owner::new("test-user");
    
    let mut bucket = Bucket::create(
        "test-bucket".to_string(),
        owner,
        store.clone(),
        BucketConfig::default(),
    ).await.unwrap();
    
    // Create object metadata
    let cid = fula_blockstore::cid_utils::create_cid(
        b"test content",
        fula_blockstore::cid_utils::CidCodec::Raw,
    );
    let metadata = ObjectMetadata::new(cid, 12, "abc123".to_string());
    
    // Put object
    bucket.put_object("test-key".to_string(), metadata).await.unwrap();
    
    // Get object
    let retrieved = bucket.get_object("test-key").await.unwrap();
    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap().size, 12);
    
    // List objects
    let list = bucket.list_objects(None, None, None, None).await.unwrap();
    assert_eq!(list.objects.len(), 1);
    
    // Delete object
    bucket.delete_object("test-key").await.unwrap();
    let deleted = bucket.get_object("test-key").await.unwrap();
    assert!(deleted.is_none());
}

/// Test Prolly Tree operations
#[tokio::test]
async fn test_prolly_tree() {
    use fula_core::prolly::ProllyTree;
    
    let store = Arc::new(MemoryBlockStore::new());
    let mut tree: ProllyTree<String, i32, _> = ProllyTree::new(store.clone());
    
    // Insert values
    tree.set("a".to_string(), 1).await.unwrap();
    tree.set("b".to_string(), 2).await.unwrap();
    tree.set("c".to_string(), 3).await.unwrap();
    
    // Get values
    assert_eq!(tree.get(&"a".to_string()).await.unwrap(), Some(1));
    assert_eq!(tree.get(&"b".to_string()).await.unwrap(), Some(2));
    assert_eq!(tree.get(&"z".to_string()).await.unwrap(), None);
    
    // Update value
    tree.set("a".to_string(), 10).await.unwrap();
    assert_eq!(tree.get(&"a".to_string()).await.unwrap(), Some(10));
    
    // Flush and reload
    let root_cid = tree.flush().await.unwrap();
    
    let loaded: ProllyTree<String, i32, _> = ProllyTree::load(store, root_cid).await.unwrap();
    assert_eq!(loaded.get(&"a".to_string()).await.unwrap(), Some(10));
}

/// Test CRDT operations
#[test]
fn test_crdt_lww_map() {
    use fula_core::crdt::LWWMap;
    
    let mut map1: LWWMap<String, i32> = LWWMap::new("node1");
    let mut map2: LWWMap<String, i32> = LWWMap::new("node2");
    
    // Concurrent updates
    map1.insert("key1".to_string(), 1);
    map2.insert("key2".to_string(), 2);
    
    // Merge
    map1.merge(&map2);
    
    // Both keys present
    assert_eq!(map1.get(&"key1".to_string()), Some(&1));
    assert_eq!(map1.get(&"key2".to_string()), Some(&2));
}

/// Test CRDT OR-Set
#[test]
fn test_crdt_or_set() {
    use fula_core::crdt::ORSet;
    
    let mut set1: ORSet<String> = ORSet::new("node1");
    let mut set2: ORSet<String> = ORSet::new("node2");
    
    // Add elements
    set1.add("a".to_string());
    set2.add("b".to_string());
    set2.add("c".to_string());
    
    // Merge
    set1.merge(&set2);
    
    // All elements present
    assert!(set1.contains(&"a".to_string()));
    assert!(set1.contains(&"b".to_string()));
    assert!(set1.contains(&"c".to_string()));
    assert_eq!(set1.len(), 3);
}

/// Test Bao verified streaming
#[test]
fn test_bao_streaming() {
    use fula_crypto::streaming::{encode, verify};
    
    let data = b"Data for verified streaming";
    
    // Encode with Bao
    let outboard = encode(data);
    
    // Verify succeeds
    assert!(verify(data, &outboard).is_ok());
    
    // Verify fails with wrong data
    assert!(verify(b"Wrong data", &outboard).is_err());
}

/// Test multipart upload manager
#[test]
fn test_multipart_manager() {
    use fula_cli::multipart::{MultipartManager, UploadPart};
    
    let manager = MultipartManager::new(3600);
    
    // Create upload
    let upload = manager.create_upload(
        "bucket".to_string(),
        "key".to_string(),
        "owner".to_string(),
    );
    
    // Add parts
    manager.add_part(&upload.upload_id, UploadPart::new(1, "etag1".to_string(), 1000, "cid1".to_string()));
    manager.add_part(&upload.upload_id, UploadPart::new(2, "etag2".to_string(), 1000, "cid2".to_string()));
    
    // List parts
    let parts = manager.list_parts(&upload.upload_id).unwrap();
    assert_eq!(parts.len(), 2);
    
    // Complete upload
    let completed = manager.complete_upload(&upload.upload_id);
    assert!(completed.is_some());
    assert!(manager.get_upload(&upload.upload_id).is_none());
}

/// Test XML response generation
#[test]
fn test_xml_generation() {
    use fula_cli::xml;
    use chrono::Utc;
    
    let buckets = vec![
        ("bucket1".to_string(), Utc::now()),
        ("bucket2".to_string(), Utc::now()),
    ];
    
    let xml = xml::list_all_my_buckets_result("owner123", "Test User", &buckets);
    
    assert!(xml.contains("<Name>bucket1</Name>"));
    assert!(xml.contains("<Name>bucket2</Name>"));
    assert!(xml.contains("xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\""));
}
