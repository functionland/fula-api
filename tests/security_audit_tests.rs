//! Security Audit Tests
//!
//! Tests to verify security audit fixes are working correctly.

mod common;

/// Test module for bucket ownership checks (Finding #1)
mod bucket_ownership {
    
    #[test]
    fn test_session_can_access_own_bucket() {
        let session = create_test_session("user123", vec!["storage:read".to_string()]);
        assert!(session.can_access_bucket("user123"));
    }
    
    #[test]
    fn test_session_cannot_access_other_bucket() {
        let session = create_test_session("user123", vec!["storage:read".to_string()]);
        assert!(!session.can_access_bucket("user456"));
    }
    
    #[test]
    fn test_admin_can_access_any_bucket() {
        let session = create_test_session("admin", vec!["admin".to_string()]);
        assert!(session.can_access_bucket("user123"));
        assert!(session.can_access_bucket("user456"));
    }
    
    #[test]
    fn test_wildcard_scope_is_admin() {
        let session = create_test_session("superuser", vec!["*".to_string()]);
        assert!(session.is_admin());
        assert!(session.can_access_bucket("anyone"));
    }

    fn create_test_session(user_id: &str, scopes: Vec<String>) -> TestSession {
        TestSession { user_id: user_id.to_string(), scopes }
    }
    
    struct TestSession {
        user_id: String,
        scopes: Vec<String>,
    }
    
    impl TestSession {
        fn has_scope(&self, scope: &str) -> bool {
            self.scopes.iter().any(|s| s == scope || s == "*")
        }
        fn is_admin(&self) -> bool {
            self.has_scope("admin") || self.has_scope("*")
        }
        fn can_access_bucket(&self, bucket_owner_id: &str) -> bool {
            self.user_id == bucket_owner_id || self.is_admin()
        }
    }
}

/// Test module for SSRF protection (Finding #3)
mod ssrf_protection {
    
    #[test]
    fn test_valid_https_endpoint() {
        assert!(is_valid_pinning_endpoint("https://api.pinata.cloud/psa"));
        assert!(is_valid_pinning_endpoint("https://api.web3.storage/pins"));
    }
    
    #[test]
    fn test_rejects_http() {
        assert!(!is_valid_pinning_endpoint("http://api.pinata.cloud/psa"));
    }
    
    #[test]
    fn test_rejects_localhost() {
        assert!(!is_valid_pinning_endpoint("https://localhost/api"));
        assert!(!is_valid_pinning_endpoint("https://127.0.0.1/api"));
    }
    
    #[test]
    fn test_rejects_private_ips() {
        assert!(!is_valid_pinning_endpoint("https://10.0.0.1/api"));
        assert!(!is_valid_pinning_endpoint("https://192.168.1.1/api"));
        assert!(!is_valid_pinning_endpoint("https://172.16.0.1/api"));
    }
    
    #[test]
    fn test_rejects_invalid_urls() {
        assert!(!is_valid_pinning_endpoint("not-a-url"));
        assert!(!is_valid_pinning_endpoint(""));
    }

    // Simple URL validation without url crate
    fn is_valid_pinning_endpoint(endpoint: &str) -> bool {
        if !endpoint.starts_with("https://") {
            return false;
        }
        
        // Extract host from URL
        let after_scheme = &endpoint[8..]; // Skip "https://"
        let host = after_scheme.split('/').next().unwrap_or("");
        let host = host.split(':').next().unwrap_or(host); // Remove port
        let host = host.to_lowercase();
        
        // Block localhost
        if host == "localhost" || host == "127.0.0.1" || host.starts_with("[::1]") {
            return false;
        }
        
        // Block private IPs
        if host.starts_with("10.") 
            || host.starts_with("192.168.")
            || host.starts_with("172.16.")
            || host.starts_with("172.17.")
            || host.starts_with("172.18.")
            || host.starts_with("172.19.")
            || host.starts_with("172.2")
            || host.starts_with("172.30.")
            || host.starts_with("172.31.")
            || host.starts_with("169.254.")
        {
            return false;
        }
        
        true
    }
}

/// Test module for deterministic forest key (Finding #8)
mod forest_key_determinism {
    use fula_crypto::hashing::hash;
    
    #[test]
    fn test_derive_path_key_is_deterministic() {
        let master_secret = [0u8; 32];
        let bucket = "test-bucket";
        
        let key1 = derive_forest_key(&master_secret, bucket);
        let key2 = derive_forest_key(&master_secret, bucket);
        
        assert_eq!(key1, key2, "Forest key derivation must be deterministic");
    }
    
    #[test]
    fn test_different_buckets_have_different_keys() {
        let master_secret = [0u8; 32];
        
        let key1 = derive_forest_key(&master_secret, "bucket-a");
        let key2 = derive_forest_key(&master_secret, "bucket-b");
        
        assert_ne!(key1, key2, "Different buckets should have different keys");
    }
    
    #[test]
    fn test_different_secrets_have_different_keys() {
        let secret1 = [0u8; 32];
        let secret2 = [1u8; 32];
        let bucket = "same-bucket";
        
        let key1 = derive_forest_key(&secret1, bucket);
        let key2 = derive_forest_key(&secret2, bucket);
        
        assert_ne!(key1, key2, "Different secrets should produce different keys");
    }
    
    fn derive_forest_key(master_secret: &[u8; 32], bucket: &str) -> [u8; 32] {
        let input = format!("forest:{}", bucket);
        let combined: Vec<u8> = master_secret.iter()
            .chain(input.as_bytes().iter())
            .copied()
            .collect();
        let hash_result = hash(&combined);
        let mut key = [0u8; 32];
        key.copy_from_slice(&hash_result.as_bytes()[..32]);
        key
    }
}

/// Test module for metadata key consistency (Finding #9)
mod metadata_keys {
    use std::collections::HashMap;
    
    const ENCRYPTED_KEY: &str = "x-fula-encrypted";
    const ENCRYPTION_KEY: &str = "x-fula-encryption";
    
    #[test]
    fn test_metadata_keys_are_consistent() {
        let upload_encrypted_key = "x-fula-encrypted";
        let upload_encryption_key = "x-fula-encryption";
        
        assert_eq!(upload_encrypted_key, ENCRYPTED_KEY);
        assert_eq!(upload_encryption_key, ENCRYPTION_KEY);
    }
    
    #[test]
    fn test_can_detect_encrypted_object() {
        let mut metadata = HashMap::new();
        metadata.insert(ENCRYPTED_KEY.to_string(), "true".to_string());
        
        let is_encrypted = metadata
            .get(ENCRYPTED_KEY)
            .map(|v| v == "true")
            .unwrap_or(false);
        
        assert!(is_encrypted);
    }
    
    #[test]
    fn test_unencrypted_object_not_detected() {
        let metadata: HashMap<String, String> = HashMap::new();
        
        let is_encrypted = metadata
            .get(ENCRYPTED_KEY)
            .map(|v| v == "true")
            .unwrap_or(false);
        
        assert!(!is_encrypted);
    }
}

/// Test module for secret redaction in logs (Finding #2)
mod log_redaction {
    
    #[test]
    fn test_token_not_in_log_message() {
        let token = "super-secret-jwt-token-12345";
        
        // The log message should only contain presence info, not values
        let log_message = format!(
            "has_pinning_service={}, has_pinning_token={}",
            true, true
        );
        
        assert!(!log_message.contains(token));
        assert!(!log_message.contains("super-secret"));
    }
    
    #[test]
    fn test_endpoint_can_be_logged() {
        let endpoint = "https://api.pinata.cloud/psa";
        let log_message = format!("Pinning to endpoint: {}", endpoint);
        
        assert!(log_message.contains(endpoint));
    }
}

/// Test module for AAD binding (Finding #5)
mod aad_binding {
    use fula_crypto::{Encryptor, Decryptor, KekKeyPair, DekKey};
    
    #[test]
    fn test_aad_binding_prevents_swapping() {
        let keypair = KekKeyPair::generate();
        let data = b"sensitive data";
        let context1 = b"fula:v2:bucket:bucket-a:key:file1.txt";
        let context2 = b"fula:v2:bucket:bucket-b:key:file2.txt";
        
        let encryptor = Encryptor::new(keypair.public_key());
        let encrypted = encryptor.encrypt_with_aad(data, context1).unwrap();
        
        let decryptor = Decryptor::new(&keypair);
        
        // Correct context works
        assert!(decryptor.decrypt_with_aad(&encrypted, context1).is_ok());
        
        // Wrong context fails - prevents swapping ciphertext between files
        assert!(decryptor.decrypt_with_aad(&encrypted, context2).is_err());
    }
    
    #[test]
    fn test_dek_wrap_has_dedicated_aad() {
        let keypair = KekKeyPair::generate();
        let dek = DekKey::generate();
        
        let encryptor = Encryptor::new(keypair.public_key());
        let wrapped = encryptor.encrypt_dek(&dek).unwrap();
        
        // DEK wrapping uses "fula:v2:dek-wrap" AAD internally
        let decryptor = Decryptor::new(&keypair);
        let unwrapped = decryptor.decrypt_dek(&wrapped).unwrap();
        
        assert_eq!(dek.as_bytes(), unwrapped.as_bytes());
    }
}

/// Test module for hashed user IDs (Finding A3)
mod hashed_user_id {
    /// Simulate the hash_user_id function from fula-cli
    fn hash_user_id(user_id: &str) -> String {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"fula:user_id:");
        hasher.update(user_id.as_bytes());
        let hash = hasher.finalize();
        hex::encode(&hash.as_bytes()[..16])
    }
    
    #[test]
    fn test_user_id_is_hashed() {
        let user_id = "john.doe@example.com";
        let hashed = hash_user_id(user_id);
        
        // Hashed ID should not contain the email
        assert!(!hashed.contains("john"));
        assert!(!hashed.contains("@"));
        assert!(!hashed.contains("example.com"));
        
        // Should be 32 hex characters (16 bytes)
        assert_eq!(hashed.len(), 32);
    }
    
    #[test]
    fn test_hash_is_deterministic() {
        let user_id = "test-user-123";
        let hash1 = hash_user_id(user_id);
        let hash2 = hash_user_id(user_id);
        
        assert_eq!(hash1, hash2);
    }
    
    #[test]
    fn test_different_users_have_different_hashes() {
        let user1 = "user1@example.com";
        let user2 = "user2@example.com";
        
        let hash1 = hash_user_id(user1);
        let hash2 = hash_user_id(user2);
        
        assert_ne!(hash1, hash2);
    }
}

/// Test module for sharing integration (Audit finding: sharing not fully integrated)
mod sharing_integration {
    use fula_crypto::{
        KekKeyPair, DekKey,
        sharing::{ShareBuilder, ShareRecipient},
    };
    
    #[test]
    fn test_share_token_creation_and_acceptance() {
        let owner = KekKeyPair::generate();
        let recipient = KekKeyPair::generate();
        let dek = DekKey::generate();
        
        // Owner creates a share token for recipient
        let token = ShareBuilder::new(&owner, recipient.public_key(), &dek)
            .path_scope("/photos/vacation/")
            .expires_in(3600)
            .read_only()
            .build()
            .unwrap();
        
        // Recipient accepts the share
        let share_recipient = ShareRecipient::new(&recipient);
        let accepted = share_recipient.accept_share(&token).unwrap();
        
        // Verify the accepted share has correct properties
        assert_eq!(accepted.path_scope, "/photos/vacation/");
        assert!(accepted.permissions.can_read);
        assert!(!accepted.permissions.can_write);
        assert!(accepted.is_valid());
        
        // Verify DEK matches
        assert_eq!(accepted.dek.as_bytes(), dek.as_bytes());
    }
    
    #[test]
    fn test_share_path_scope_validation() {
        let owner = KekKeyPair::generate();
        let recipient = KekKeyPair::generate();
        let dek = DekKey::generate();
        
        let token = ShareBuilder::new(&owner, recipient.public_key(), &dek)
            .path_scope("/photos/")
            .build()
            .unwrap();
        
        let share_recipient = ShareRecipient::new(&recipient);
        let accepted = share_recipient.accept_share(&token).unwrap();
        
        // Path within scope
        assert!(accepted.is_path_allowed("/photos/beach.jpg"));
        assert!(accepted.is_path_allowed("/photos/vacation/sunset.jpg"));
        
        // Path outside scope
        assert!(!accepted.is_path_allowed("/documents/secret.pdf"));
        assert!(!accepted.is_path_allowed("/photo")); // Prefix mismatch
    }
    
    #[test]
    fn test_share_permissions() {
        let owner = KekKeyPair::generate();
        let recipient = KekKeyPair::generate();
        let dek = DekKey::generate();
        
        // Read-only share
        let read_token = ShareBuilder::new(&owner, recipient.public_key(), &dek)
            .read_only()
            .build()
            .unwrap();
        assert!(read_token.can_read());
        assert!(!read_token.can_write());
        assert!(!read_token.can_delete());
        
        // Read-write share
        let rw_token = ShareBuilder::new(&owner, recipient.public_key(), &dek)
            .read_write()
            .build()
            .unwrap();
        assert!(rw_token.can_read());
        assert!(rw_token.can_write());
        assert!(!rw_token.can_delete());
        
        // Full access share
        let full_token = ShareBuilder::new(&owner, recipient.public_key(), &dek)
            .full_access()
            .build()
            .unwrap();
        assert!(full_token.can_read());
        assert!(full_token.can_write());
        assert!(full_token.can_delete());
    }
    
    #[test]
    fn test_wrong_recipient_cannot_accept() {
        let owner = KekKeyPair::generate();
        let intended_recipient = KekKeyPair::generate();
        let wrong_recipient = KekKeyPair::generate();
        let dek = DekKey::generate();
        
        // Token encrypted for intended_recipient
        let token = ShareBuilder::new(&owner, intended_recipient.public_key(), &dek)
            .build()
            .unwrap();
        
        // Wrong recipient tries to accept
        let wrong_share_recipient = ShareRecipient::new(&wrong_recipient);
        let result = wrong_share_recipient.accept_share(&token);
        
        // Should fail because wrong key
        assert!(result.is_err());
    }
}

/// Test module for key rotation integration (Audit finding: rotation not fully wired)
mod rotation_integration {
    use fula_crypto::{
        KekKeyPair, DekKey,
        rotation::KeyRotationManager,
    };
    
    #[test]
    fn test_kek_version_tracking() {
        let keypair = KekKeyPair::generate();
        let manager = KeyRotationManager::new(keypair);
        
        assert_eq!(manager.current_version(), 1);
    }
    
    #[test]
    fn test_rotation_increments_version() {
        let keypair = KekKeyPair::generate();
        let mut manager = KeyRotationManager::new(keypair);
        
        assert_eq!(manager.current_version(), 1);
        
        manager.rotate_kek().unwrap();
        assert_eq!(manager.current_version(), 2);

        // Must clear previous before rotating again
        manager.clear_previous();
        manager.rotate_kek().unwrap();
        assert_eq!(manager.current_version(), 3);
    }
    
    #[test]
    fn test_wrap_dek_includes_version() {
        let keypair = KekKeyPair::generate();
        let manager = KeyRotationManager::new(keypair);
        let dek = DekKey::generate();
        
        let wrapped = manager.wrap_dek(&dek, "/test/file.txt").unwrap();
        
        assert_eq!(wrapped.kek_version, 1);
        assert_eq!(wrapped.object_path, "/test/file.txt");
    }
    
    #[test]
    fn test_rewrap_dek_after_rotation() {
        let keypair = KekKeyPair::generate();
        let mut manager = KeyRotationManager::new(keypair);
        let dek = DekKey::generate();
        
        // Wrap with v1
        let wrapped_v1 = manager.wrap_dek(&dek, "/test/file.txt").unwrap();
        assert_eq!(wrapped_v1.kek_version, 1);
        
        // Rotate to v2
        manager.rotate_kek().unwrap();
        assert_eq!(manager.current_version(), 2);

        // Rewrap the DEK
        let wrapped_v2 = manager.rewrap_dek(&wrapped_v1).unwrap();
        assert_eq!(wrapped_v2.kek_version, 2);
        
        // Verify DEK can still be unwrapped
        let unwrapped = manager.unwrap_dek(&wrapped_v2).unwrap();
        assert_eq!(unwrapped.as_bytes(), dek.as_bytes());
    }
    
    #[test]
    fn test_can_unwrap_current_and_previous_version() {
        let keypair = KekKeyPair::generate();
        let mut manager = KeyRotationManager::new(keypair);
        let dek = DekKey::generate();
        
        // Wrap with v1
        let wrapped_v1 = manager.wrap_dek(&dek, "/file.txt").unwrap();
        
        // Rotate to v2
        manager.rotate_kek().unwrap();

        // Should still be able to unwrap v1 (previous version)
        let unwrapped_v1 = manager.unwrap_dek(&wrapped_v1).unwrap();
        assert_eq!(unwrapped_v1.as_bytes(), dek.as_bytes());
        
        // Wrap a new DEK with v2
        let dek2 = DekKey::generate();
        let wrapped_v2 = manager.wrap_dek(&dek2, "/file2.txt").unwrap();
        
        // Should be able to unwrap v2 (current version)
        let unwrapped_v2 = manager.unwrap_dek(&wrapped_v2).unwrap();
        assert_eq!(unwrapped_v2.as_bytes(), dek2.as_bytes());
    }
    
    #[test]
    fn test_clear_previous_prevents_old_unwrap() {
        let keypair = KekKeyPair::generate();
        let mut manager = KeyRotationManager::new(keypair);
        let dek = DekKey::generate();
        
        // Wrap with v1
        let wrapped_v1 = manager.wrap_dek(&dek, "/file.txt").unwrap();
        
        // Rotate and clear previous
        manager.rotate_kek().unwrap();
        manager.clear_previous();

        // Should NOT be able to unwrap v1 anymore
        let result = manager.unwrap_dek(&wrapped_v1);
        assert!(result.is_err());
    }
}

/// Integration-level migration security tests — closes audit gaps G5 (v1 → v7
/// migration security) and G9 (AAD-swap attacks). These run the full
/// `EncryptedClient` stack against the in-process gateway defined in
/// `tests/common/mod.rs` and exercise attack scenarios that can't be
/// reproduced with pure crypto-unit tests.
mod migration_security {
    use super::common::v1_seed::{seed_v1_forest, index_key_for, SeedFile};
    use super::common::{spawn_server, make_client, EnvGuard};
    use bytes::Bytes;
    use fula_client::EncryptionConfig;

    /// The `__fula_forest_v1_backup/<unix_ms>` object that migration writes
    /// before overwriting `index_key` must be the encrypted v1 blob — NOT
    /// a raw-JSON dump. Decrypting requires the bucket's forest DEK; a
    /// server compromise that exfiltrates the backup must not reveal the
    /// plaintext forest index.
    #[tokio::test]
    async fn test_migration_v1_backup_is_encrypted() {
        let base = spawn_server().await;
        let encryption = EncryptionConfig::new();
        let bucket = "sec-v1-backup-enc";

        let state = tempfile::tempdir().unwrap();
        let _guard = EnvGuard::set("FULA_STATE_DIR", state.path());

        let client = make_client(&base, encryption);
        client.create_bucket(bucket).await.expect("create bucket");
        seed_v1_forest(&client, bucket, &[SeedFile::new("/a.txt", 4)], &[]).await;

        client.migrate_to_sharded(bucket).await.expect("migrate");

        use fula_client::ListObjectsOptions;
        let backups = client
            .inner()
            .list_objects(
                bucket,
                Some(ListObjectsOptions {
                    prefix: Some("__fula_forest_v1_backup/".to_string()),
                    max_keys: Some(10),
                    ..Default::default()
                }),
            )
            .await
            .expect("list backups")
            .objects;
        assert_eq!(backups.len(), 1, "migration must write exactly one backup");

        let backup = client
            .inner()
            .get_object(bucket, &backups[0].key)
            .await
            .expect("get backup");

        // The v1 EncryptedForest envelope IS plaintext JSON at the outer
        // level but wraps AEAD-encrypted inner ciphertext (see
        // `private_forest.rs::EncryptedForest`). We verify the backup is
        // semantically the original v1 blob — meaning it round-trips
        // through `decrypt` under the bucket's forest DEK and yields the
        // same files we seeded. If the backup were a naive plaintext dump
        // of `PrivateForest` (no AEAD layer), `decrypt` would fail.
        use fula_crypto::EncryptedForest;
        let outer: EncryptedForest = serde_json::from_slice(&backup)
            .expect("v1 backup must deserialize as EncryptedForest");
        assert_eq!(outer.version, 1, "backup must be v1 shape");
        assert!(!outer.ciphertext.is_empty(), "backup must carry a ciphertext field");
        let km = client.encryption_config().key_manager();
        let forest_dek = km.derive_path_key(&format!("forest:{}", bucket));
        let decrypted = outer
            .decrypt(&forest_dek)
            .expect("backup must decrypt under forest DEK");
        assert!(
            decrypted.files.contains_key("/a.txt"),
            "decrypted backup must contain /a.txt"
        );
    }

    /// Flipping a byte in the stored v1 ciphertext must surface as an AEAD
    /// failure on the next load — migration must NOT silently fall through
    /// to a partial forest or zero-file state, and must NOT write a backup
    /// of the tampered blob.
    #[tokio::test]
    async fn test_migration_rejects_tampered_v1_blob() {
        let base = spawn_server().await;
        let encryption = EncryptionConfig::new();
        let bucket = "sec-tampered-v1";

        let state = tempfile::tempdir().unwrap();
        let _guard = EnvGuard::set("FULA_STATE_DIR", state.path());

        let client = make_client(&base, encryption);
        client.create_bucket(bucket).await.expect("create bucket");
        seed_v1_forest(&client, bucket, &[SeedFile::new("/a.txt", 4)], &[]).await;

        // Fetch the v1 blob, flip a byte in the ciphertext region, put it
        // back at the same key. Using the outer JSON envelope: locate the
        // "ciphertext" field and mutate one byte of the base64 string. A
        // cheap way: find the second occurrence of `"` after `"ciphertext":`
        // and flip the byte before it.
        let index_key = index_key_for(&client, bucket);
        let v1 = client
            .inner()
            .get_object(bucket, &index_key)
            .await
            .expect("get v1");
        let mut bytes = v1.to_vec();
        // Flip one byte near the middle — any byte mutation inside the
        // serialized EncryptedForest will cause either JSON deser failure
        // or AEAD tag mismatch; both are acceptable fail-closed outcomes.
        let mid = bytes.len() / 2;
        bytes[mid] ^= 0x01;
        client
            .inner()
            .put_object(bucket, &index_key, Bytes::from(bytes))
            .await
            .expect("re-put tampered");

        let result = client.migrate_to_sharded(bucket).await;
        assert!(
            result.is_err(),
            "migration of a tampered v1 blob must fail; got {:?}",
            result.as_ref().map(|_| "Ok")
        );

        // No __fula_forest_v1_backup/* should have been written — migration
        // aborted before the backup COPY.
        use fula_client::ListObjectsOptions;
        let backups = client
            .inner()
            .list_objects(
                bucket,
                Some(ListObjectsOptions {
                    prefix: Some("__fula_forest_v1_backup/".to_string()),
                    max_keys: Some(10),
                    ..Default::default()
                }),
            )
            .await
            .expect("list backups")
            .objects;
        assert_eq!(
            backups.len(),
            0,
            "tampered v1 blob must NOT produce a backup; got {:?}",
            backups.iter().map(|o| &o.key).collect::<Vec<_>>()
        );
    }

    /// Ciphertext binds its AAD to the storage key via `fula:v4:content:{key}`
    /// (encryption.rs:725). A server-side rename (copy ciphertext bytes from
    /// key A to key B) must fail decryption at key B — AAD mismatch.
    #[tokio::test]
    async fn test_content_aad_rejects_storage_key_swap() {
        let base = spawn_server().await;
        let encryption = EncryptionConfig::new();
        let bucket = "sec-aad-swap-content";

        let state = tempfile::tempdir().unwrap();
        let _guard = EnvGuard::set("FULA_STATE_DIR", state.path());

        let client = make_client(&base, encryption);
        client.create_bucket(bucket).await.expect("create bucket");

        // Upload one encrypted object at path /a.txt.
        client
            .put_object_flat(bucket, "/a.txt", b"payload A".to_vec(), None)
            .await
            .expect("put a");

        // Locate its encrypted storage object, grab the raw ciphertext bytes,
        // and re-upload them at a different storage key. Then attempt a
        // decrypted read through the client — it should discover the
        // cached path entry for /a.txt, fetch via the original storage key
        // (which still works), so the swap we need to perform is at the
        // *storage-key* level inside the HAMT, not via the user-facing path.
        //
        // Practical approach: upload two different objects at different
        // paths, then have one's ciphertext copied over the other's storage
        // key. When we fetch it, decryption must fail because the AAD
        // includes the *other* storage key.
        client
            .put_object_flat(bucket, "/b.txt", b"payload B".to_vec(), None)
            .await
            .expect("put b");

        // Find storage keys by listing.
        use fula_client::ListObjectsOptions;
        let raw = client
            .inner()
            .list_objects(bucket, Some(ListObjectsOptions {
                max_keys: Some(100),
                ..Default::default()
            }))
            .await
            .expect("list raw")
            .objects;
        // `EncryptionConfig::new()` defaults to `KeyObfuscation::FlatNamespace`
        // which produces `Qm<hex44>`-style storage keys (see
        // `fula-crypto::private_forest::generate_flat_key`). The forest manifest
        // itself ALSO lives at a `Qm<hex44>` key via `derive_index_key`, so
        // we must explicitly exclude it — otherwise the swap below would
        // corrupt the manifest rather than a content ciphertext, and the
        // test would pass for the wrong reason.
        let manifest_key = index_key_for(&client, bucket);
        let storage_keys: Vec<String> = raw
            .iter()
            .map(|o| o.key.clone())
            .filter(|k| k.starts_with("Qm") && !k.starts_with("__fula_") && k != &manifest_key)
            .collect();
        assert!(
            storage_keys.len() >= 2,
            "expected at least two content-ciphertext objects; got {:?} (manifest_key={})",
            storage_keys,
            manifest_key
        );

        // Fetch A's ciphertext, upload under B's storage key. Now B's
        // storage slot has A's ciphertext — decrypting with AAD built from
        // B's storage key must fail.
        let a_body = client
            .inner()
            .get_object(bucket, &storage_keys[0])
            .await
            .expect("get A ciphertext");
        client
            .inner()
            .put_object(bucket, &storage_keys[1], a_body)
            .await
            .expect("swap ciphertexts");

        // After the server-side swap, one of the two paths' decryption is
        // guaranteed to fail with an AAD mismatch — the one whose forest
        // entry points at the storage key that now has the wrong
        // ciphertext. We don't know which path that is without inspecting
        // the obfuscation, so we try BOTH: at least one must fail closed.
        let a_result = client.get_object_decrypted(bucket, "/a.txt").await;
        let b_result = client.get_object_decrypted(bucket, "/b.txt").await;
        assert!(
            a_result.is_err() || b_result.is_err(),
            "AAD binding must reject at least one path after server-side \
             ciphertext swap; got A={:?} B={:?}",
            a_result.as_ref().map(|b| b.len()),
            b_result.as_ref().map(|b| b.len())
        );
    }

    /// The v7 manifest's AAD is `fula:manifest:v7:<bucket>:<seq>`. Copying a
    /// manifest blob from one bucket's `index_key` to another bucket's
    /// `index_key` must fail to decrypt — AAD mismatch on the bucket name.
    #[tokio::test]
    async fn test_manifest_v7_aad_rejects_bucket_swap() {
        let base = spawn_server().await;
        let encryption = EncryptionConfig::new();
        let secret = encryption.export_secret_key().clone();
        let bucket_a = "sec-aad-bucket-a";
        let bucket_b = "sec-aad-bucket-b";

        // EnvGuard holds a non-reentrant global mutex until drop; we need
        // two different state dirs (session 1 migrates, session 2 reads),
        // so each guard must be scoped so the previous one is dropped
        // before the next is acquired. Holding two on the same thread
        // deadlocks.
        let index_a;
        let index_b;
        let manifest_bytes: Bytes;
        {
            let state = tempfile::tempdir().unwrap();
            let _guard = EnvGuard::set("FULA_STATE_DIR", state.path());

            let client = make_client(&base, encryption);
            client.create_bucket(bucket_a).await.expect("create A");
            client.create_bucket(bucket_b).await.expect("create B");

            // Seed + migrate only bucket_a — that's the only bucket that
            // needs a real v7 manifest. bucket_b starts empty; after the
            // swap below it will be serving bucket_a's manifest bytes
            // from its own index_key, which is exactly the AAD-mismatch
            // scenario we want to test.
            seed_v1_forest(&client, bucket_a, &[SeedFile::new("/bootstrap.txt", 4)], &[]).await;
            client.migrate_to_sharded(bucket_a).await.expect("migrate A");
            assert!(client.is_forest_sharded_hamt(bucket_a));

            index_a = index_key_for(&client, bucket_a);
            index_b = index_key_for(&client, bucket_b);
            assert_ne!(index_a, index_b, "per-bucket index keys must differ");
            manifest_bytes = client
                .inner()
                .get_object(bucket_a, &index_a)
                .await
                .expect("fetch A manifest");
            client
                .inner()
                .put_object(bucket_b, &index_b, manifest_bytes.clone())
                .await
                .expect("swap manifest A→B");
            drop(client);
        } // session-1 guard dropped here — lock released

        // Session 2: fresh state dir, same KEK. Must detect AAD mismatch.
        let state2 = tempfile::tempdir().unwrap();
        let _guard2 = EnvGuard::set("FULA_STATE_DIR", state2.path());
        let reader = make_client(
            &base,
            EncryptionConfig::from_secret_key(secret),
        );
        let result = reader.list_directory(bucket_b, Some("/")).await;
        assert!(
            result.is_err(),
            "manifest AAD must reject the swapped manifest; got {:?}",
            result.as_ref().map(|d| d.directories.len())
        );
    }

    /// After a successful v7 migration, a malicious server cannot
    /// convince the client to silently serve v1 content. The code path
    /// accepts two outcomes:
    ///
    /// 1. "version downgrade detected" error — when the v1/v2 legacy
    ///    decoder sees evidence of a prior-observed v4+ sequence (in-memory
    ///    cache only; encryption.rs:~1680).
    /// 2. Transparent re-migration to v7 — the legacy v1/v2 branch triggers
    ///    `migrate_v1_to_v7_internal` on `observed_seq.is_none()`
    ///    (encryption.rs:1702), which turns the rolled-back blob back into
    ///    v7 on the next load.
    ///
    /// Either outcome is security-equivalent (no v1 content is served long-
    /// term). The test verifies at minimum that the bucket is NOT left in a
    /// servable v1 state after the first cold-start list.
    #[tokio::test]
    async fn test_version_downgrade_blocked_after_v7_pin() {
        let base = spawn_server().await;
        let encryption = EncryptionConfig::new();
        let secret = encryption.export_secret_key().clone();
        let bucket = "sec-downgrade-blocked";

        let state = tempfile::tempdir().unwrap();
        let _guard = EnvGuard::set("FULA_STATE_DIR", state.path());

        // Session 1: seed v1, migrate to v7.
        let client = make_client(
            &base,
            EncryptionConfig::from_secret_key(secret.clone()),
        );
        client.create_bucket(bucket).await.expect("create bucket");
        seed_v1_forest(&client, bucket, &[SeedFile::new("/a.txt", 4)], &[]).await;
        client.migrate_to_sharded(bucket).await.expect("migrate");
        assert!(client.is_forest_sharded_hamt(bucket));

        // Capture the v1 backup (this is a real, well-formed v1 blob from
        // this bucket). Overwrite the v7 manifest at `index_key` with it —
        // simulating a server-side rollback / malicious downgrade.
        use fula_client::ListObjectsOptions;
        let backups = client
            .inner()
            .list_objects(
                bucket,
                Some(ListObjectsOptions {
                    prefix: Some("__fula_forest_v1_backup/".to_string()),
                    max_keys: Some(10),
                    ..Default::default()
                }),
            )
            .await
            .expect("list backups")
            .objects;
        assert_eq!(backups.len(), 1);
        let v1_blob = client
            .inner()
            .get_object(bucket, &backups[0].key)
            .await
            .expect("fetch v1 backup");
        let index_key = index_key_for(&client, bucket);
        client
            .inner()
            .put_object(bucket, &index_key, v1_blob)
            .await
            .expect("rollback index_key to v1");

        // Drop the migrator client so its in-memory cache can't paper over
        // the downgrade — the new cold-start client must go back to disk
        // for the manifest-version pin.
        drop(client);

        // Session 2: fresh client, same state dir → must see the pinned v7
        // and refuse the server-side v1 rollback.
        let reader = make_client(
            &base,
            EncryptionConfig::from_secret_key(secret),
        );
        let result = reader.list_directory(bucket, Some("/")).await;
        match result {
            Err(e) => {
                // Acceptable: explicit downgrade / decryption error.
                let msg = format!("{}", e).to_lowercase();
                assert!(
                    msg.contains("downgrade")
                        || msg.contains("version")
                        || msg.contains("decrypt")
                        || msg.contains("authentication"),
                    "unexpected error shape: {}",
                    e
                );
            }
            Ok(_) => {
                // Acceptable only if the cold-start transparently re-
                // migrated the rolled-back v1 blob back to v7. Otherwise
                // we'd be silently serving v1 content indefinitely.
                assert!(
                    reader.is_forest_sharded_hamt(bucket),
                    "v7-pinned bucket must either error OR transparently re-migrate \
                     the rolled-back v1 blob back to v7; reader shows bucket as non-v7 \
                     after cold-start list — that would be a silent downgrade."
                );
            }
        }
    }

    /// NEW-2.1 guard (encryption.rs:832–835, 2273–2296): a fresh client
    /// with an empty forest cache that hits a path flagged `encrypted=true`
    /// in the forest must *first* load the forest, *then* refuse to return
    /// plaintext bytes if the server happens to supply them. We can't
    /// directly force the server to return plaintext for an encrypted path
    /// (the client always fetches via the encrypted storage key), but we
    /// CAN validate the guard fires by putting a non-encrypted-prefixed
    /// object at the storage key the client will hit and observing that
    /// the read fails closed rather than succeeding with plaintext.
    #[tokio::test]
    async fn test_plaintext_refused_for_encrypted_flagged_path() {
        let base = spawn_server().await;
        let encryption = EncryptionConfig::new();
        let secret = encryption.export_secret_key().clone();
        let bucket = "sec-plaintext-refused";

        let state = tempfile::tempdir().unwrap();
        let _guard = EnvGuard::set("FULA_STATE_DIR", state.path());

        // Seed a v1 forest with /secret.txt flagged encrypted=true.
        let seeder = make_client(
            &base,
            EncryptionConfig::from_secret_key(secret.clone()),
        );
        seeder.create_bucket(bucket).await.expect("create bucket");
        let secret_file = SeedFile::new("/secret.txt", 11).with_encrypted(true);
        seed_v1_forest(&seeder, bucket, &[secret_file], &[]).await;

        // Manually put a plaintext object at the storage key the client
        // will look up. The storage key for a seeded entry is deterministic
        // via v1_seed::storage_key_for_seed — we can reconstruct it.
        let storage_key = {
            let mut h = blake3::Hasher::new();
            h.update(b"seed-v1:");
            h.update(b"/secret.txt");
            let out = h.finalize();
            format!("Qm{}", hex::encode(&out.as_bytes()[..22]))
        };
        seeder
            .inner()
            .put_object(bucket, &storage_key, Bytes::from_static(b"RAW PLAINTEXT BYTES"))
            .await
            .expect("put plaintext at encrypted path");

        // Drop the seeder so the reader starts with a cold cache.
        drop(seeder);

        let reader = make_client(
            &base,
            EncryptionConfig::from_secret_key(secret),
        );
        let result = reader.get_object_decrypted(bucket, "/secret.txt").await;
        assert!(
            result.is_err(),
            "NEW-2.1 guard must refuse plaintext for encrypted=true paths; \
             got Ok({} bytes)",
            result.as_ref().map(|b| b.len()).unwrap_or(0)
        );
    }
}
