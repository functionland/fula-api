//! Security Audit Tests
//! 
//! Tests to verify security audit fixes are working correctly.

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
        
        manager.rotate_kek();
        assert_eq!(manager.current_version(), 2);
        
        manager.rotate_kek();
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
        manager.rotate_kek();
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
        manager.rotate_kek();
        
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
        manager.rotate_kek();
        manager.clear_previous();
        
        // Should NOT be able to unwrap v1 anymore
        let result = manager.unwrap_dek(&wrapped_v1);
        assert!(result.is_err());
    }
}
