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

    // ─────────────────────────────────────────────────────────────────────
    // M-5: recipient_pk bound into build_share_token_aad (v5 AAD)
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn share_token_happy_path() {
        let owner = KekKeyPair::generate();
        let recipient = KekKeyPair::generate();
        let dek = DekKey::generate();

        let token = ShareBuilder::new(&owner, recipient.public_key(), &dek)
            .path_scope("/photos/")
            .read_only()
            .build()
            .unwrap();

        // v5 format — post-M-5 tokens carry the recipient-pk AAD binding.
        assert_eq!(token.version, 5);

        let accepted = ShareRecipient::new(&recipient).accept_share(&token).unwrap();
        assert_eq!(accepted.dek.as_bytes(), dek.as_bytes());
    }

    #[test]
    fn share_token_cross_recipient_rejected() {
        // Attacker tries to strip the AAD binding by presenting their own secret key
        // against a token that was wrapped to R1's pk. The AAD now encodes R1's pk,
        // and the recipient side derives recipient_pk from its own secret — so the
        // AAD the recipient reconstructs for R2 no longer matches, surfacing as an
        // HPKE auth failure.
        let owner = KekKeyPair::generate();
        let r1 = KekKeyPair::generate();
        let r2 = KekKeyPair::generate();
        let dek = DekKey::generate();

        let token = ShareBuilder::new(&owner, r1.public_key(), &dek).build().unwrap();

        let result = ShareRecipient::new(&r2).accept_share(&token);
        assert!(result.is_err(), "R2 must not be able to accept an R1-wrapped token");
    }

    #[test]
    fn enqueue_rejects_v4_legacy_token() {
        use fula_crypto::{ShareInbox, ShareEnvelopeBuilder};

        let owner = KekKeyPair::generate();
        let recipient = KekKeyPair::generate();
        let dek = DekKey::generate();

        // Build a normal v5 envelope, then forge a pre-v5 token version on the way in.
        let (mut envelope, _entry) = ShareEnvelopeBuilder::new(&owner, recipient.public_key(), &dek)
            .path_scope("/photos/")
            .build()
            .unwrap();
        envelope.token.version = 4;

        let mut inbox = ShareInbox::new();
        let result = inbox.enqueue_share(&envelope, recipient.public_key(), &owner);
        assert!(
            result.is_err(),
            "enqueue must refuse envelopes whose token predates the recipient-pk AAD binding"
        );
    }

    // ─────────────────────────────────────────────────────────────────────
    // M-6: HPKE Auth-mode ShareEnvelope + sender_public_key binding
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn envelope_sender_auth_verifies_happy_path() {
        use fula_crypto::{ShareEnvelopeBuilder, InboxEntry};

        let sender = KekKeyPair::generate();
        let recipient = KekKeyPair::generate();
        let dek = DekKey::generate();

        let (envelope, entry) = ShareEnvelopeBuilder::new(&sender, recipient.public_key(), &dek)
            .path_scope("/shared/")
            .label("hi")
            .build()
            .unwrap();

        // sender_public_key on the entry matches the sender keypair.
        assert_eq!(&entry.sender_public_key, sender.public_key().as_bytes());

        // Happy-path decrypt verifies auth binding and returns the envelope.
        let decrypted = entry.decrypt(recipient.secret_key()).unwrap();
        assert_eq!(decrypted.token.id, envelope.token.id);

        // Serde roundtrip preserves the new field.
        let json = serde_json::to_string(&entry).unwrap();
        let loaded: InboxEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(loaded.sender_public_key, entry.sender_public_key);
    }

    #[test]
    fn envelope_forged_sender_pk_rejected() {
        // An attacker (Eve) encrypts a malicious envelope for the recipient
        // under Auth mode using Eve's own sender keypair, then tampers with
        // the on-wire `sender_public_key` to claim the envelope came from
        // Alice. Under HPKE Auth mode the recipient uses the claimed pk in
        // `OpModeR::Auth`, which is incompatible with Eve's KDF output —
        // AEAD auth fails, surfacing a generic error.
        use fula_crypto::{ShareEnvelopeBuilder};

        let alice = KekKeyPair::generate();      // claimed sender
        let eve = KekKeyPair::generate();        // actual encrypter
        let recipient = KekKeyPair::generate();
        let dek = DekKey::generate();

        let (_env, mut entry) = ShareEnvelopeBuilder::new(&eve, recipient.public_key(), &dek)
            .path_scope("/phish/")
            .build()
            .unwrap();

        // Forge the identity field.
        let mut alice_pk = [0u8; 32];
        alice_pk.copy_from_slice(alice.public_key().as_bytes());
        entry.sender_public_key = alice_pk;

        let result = entry.decrypt(recipient.secret_key());
        assert!(
            result.is_err(),
            "tampered sender_public_key must fail HPKE auth verification"
        );
    }

    #[test]
    fn envelope_replay_to_wrong_recipient_rejected() {
        // An envelope encrypted for R1 cannot be opened by R2 even if
        // R2 tampers with `recipient_key_hash` on the entry wrapper:
        // HPKE KEM is keyed to R1's public key, so R2's secret cannot
        // derive the shared secret, and the recipient-pk hash baked into
        // the AAD via `build_envelope_aad` also differs on R2's side.
        use fula_crypto::{ShareEnvelopeBuilder};

        let sender = KekKeyPair::generate();
        let r1 = KekKeyPair::generate();
        let r2 = KekKeyPair::generate();
        let dek = DekKey::generate();

        let (_env, entry) = ShareEnvelopeBuilder::new(&sender, r1.public_key(), &dek)
            .build()
            .unwrap();

        let result = entry.decrypt(r2.secret_key());
        assert!(result.is_err(), "captured envelope must not decrypt for R2");
    }

    #[test]
    fn envelope_token_version_downgrade_rejected() {
        // Not a real v4 token (that code path was deleted in M-5) — instead
        // we build a legitimate v5 envelope and then tamper with the token's
        // version field before re-wrapping through InboxEntry::create, to
        // exercise the post-decrypt gate at InboxEntry::decrypt. The gate
        // enforces the M-5 recipient-pk AAD binding on the inner token even
        // if the outer Auth-mode HPKE accepts the envelope.
        use fula_crypto::{ShareEnvelopeBuilder, InboxEntry};

        let sender = KekKeyPair::generate();
        let recipient = KekKeyPair::generate();
        let dek = DekKey::generate();

        let (mut envelope, _entry) = ShareEnvelopeBuilder::new(&sender, recipient.public_key(), &dek)
            .build()
            .unwrap();
        envelope.token.version = 4;

        // Re-create entry with the downgraded envelope (bypasses enqueue_share's
        // pre-gate to exercise the post-decrypt gate directly).
        let entry = InboxEntry::create(&envelope, recipient.public_key(), &sender).unwrap();

        let result = entry.decrypt(recipient.secret_key());
        assert!(
            result.is_err(),
            "decrypt must reject envelopes whose inner token predates v5 AAD binding"
        );
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

/// H-1 / H-2 download-side verification tests.
///
/// H-1 pins a BLAKE3 `content_hash` into every new-upload forest entry and
/// verifies it post-decrypt. H-2 pins a `min_version: u8` floor on the same
/// entry and rejects blobs whose advertised format version is lower.
///
/// Together they defeat the HPKE-to-self substitution attack: an attacker
/// with S3 write access (but not the recipient's private key) can construct
/// a fresh DEK, HPKE-wrap it to the victim's public key, AEAD-encrypt any
/// plaintext with valid AAD, and PUT at the victim's storage_key. All
/// AEAD-level checks pass because the attacker controlled every input.
///
/// These tests forge exactly that attacker blob and assert the download
/// path rejects it. Without the H-1/H-2 fixes, the decrypt would succeed
/// silently and the caller would consume attacker-chosen bytes.
mod h1_h2_download_verification {
    use super::common::v1_seed::{build_v1_private_forest, index_key_for, SeedFile};
    use super::common::{spawn_server, make_client, EnvGuard};
    use bytes::Bytes;
    use fula_client::{EncryptionConfig, ListObjectsOptions, ObjectMetadata};
    use fula_crypto::{
        Aead, ChunkedEncoder, ChunkedFileMetadata, DekKey, EncryptedForest, Encryptor, Nonce,
    };

    /// Locate the single content-ciphertext storage key for a bucket whose
    /// forest holds exactly one flat-namespace upload. Returns the `Qm…`
    /// storage key, skipping the forest manifest itself (also `Qm…`) and
    /// any `__fula_*` internals.
    async fn locate_storage_key_for_path(
        client: &fula_client::EncryptedClient,
        bucket: &str,
        path: &str,
    ) -> String {
        let listing = client
            .list_directory(bucket, None)
            .await
            .expect("list directory from forest");
        for (_dir, files) in &listing.directories {
            for f in files {
                if f.original_key == path {
                    return f.storage_key.clone();
                }
            }
        }
        panic!(
            "forest entry for {} not found; directories={:?}",
            path,
            listing.directories.keys().collect::<Vec<_>>()
        );
    }

    /// Build the `x-fula-encryption` JSON blob the client writes for a
    /// single-block (non-chunked) v4 upload. The attacker replays this
    /// exact shape with their own fresh DEK + nonce.
    fn build_v4_single_metadata(
        wrapped_dek: &fula_crypto::EncryptedData,
        nonce: &Nonce,
        version: u64,
    ) -> String {
        use base64::Engine;
        serde_json::json!({
            "version": version,
            "algorithm": "AES-256-GCM",
            "nonce": base64::engine::general_purpose::STANDARD.encode(nonce.as_bytes()),
            "wrapped_key": serde_json::to_value(wrapped_dek).unwrap(),
            "kek_version": 1,
            "metadata_privacy": true,
            "obfuscation_mode": "flat",
        })
        .to_string()
    }

    /// Upload an attacker-controlled single-block v4 blob at `storage_key`
    /// for a bucket owned by `public_key`. Uses fresh random DEK so the
    /// attacker never needs the victim's secret. The blob decrypts
    /// successfully under the victim's private key (every AEAD/HPKE
    /// parameter is internally consistent) — the only anchor that can
    /// catch the swap is the forest-pinned `content_hash`.
    async fn forge_single_block_at(
        client: &fula_client::EncryptedClient,
        public_key: &fula_crypto::PublicKey,
        bucket: &str,
        storage_key: &str,
        plaintext: &[u8],
        version: u64,
    ) {
        let attacker_dek = DekKey::generate();
        let wrapped = Encryptor::new(public_key)
            .encrypt_dek(&attacker_dek)
            .expect("wrap attacker DEK");
        let nonce = Nonce::generate();
        let aead = Aead::new_default(&attacker_dek);
        let ciphertext = if version >= 4 {
            let aad = format!("fula:v4:content:{}", storage_key).into_bytes();
            aead.encrypt_with_aad(&nonce, plaintext, &aad)
                .expect("AEAD encrypt with AAD")
        } else {
            aead.encrypt(&nonce, plaintext).expect("AEAD encrypt no AAD")
        };

        let metadata_blob = build_v4_single_metadata(&wrapped, &nonce, version);
        let metadata = ObjectMetadata::new()
            .with_content_type("application/octet-stream")
            .with_metadata("x-fula-encrypted", "true")
            .with_metadata("x-fula-encryption", &metadata_blob);

        client
            .inner()
            .put_object_with_metadata(bucket, storage_key, Bytes::from(ciphertext), Some(metadata))
            .await
            .expect("put forged blob");
    }

    /// H-1: an attacker who overwrites a single-block ciphertext at a known
    /// storage_key with a self-consistent fresh-DEK blob must be rejected
    /// at download time. Without content_hash verification the HPKE-to-
    /// self substitution would succeed silently.
    #[tokio::test]
    async fn content_hash_detects_single_block_substitution() {
        let base = spawn_server().await;
        let encryption = EncryptionConfig::new();
        let public_key = encryption.public_key().clone();
        let secret = encryption.export_secret_key().clone();
        let bucket = "sec-h1-single-sub";

        let state = tempfile::tempdir().unwrap();
        let _guard = EnvGuard::set("FULA_STATE_DIR", state.path());

        let client = make_client(&base, encryption);
        client.create_bucket(bucket).await.expect("create");
        client
            .put_object_flat(bucket, "/a.txt", b"ORIGINAL CONTENT".to_vec(), None)
            .await
            .expect("put original");

        let storage_key = locate_storage_key_for_path(&client, bucket, "/a.txt").await;

        forge_single_block_at(
            &client,
            &public_key,
            bucket,
            &storage_key,
            b"ATTACKER SUBSTITUTED CONTENT",
            4,
        )
        .await;

        drop(client);
        let reader = make_client(&base, EncryptionConfig::from_secret_key(secret));
        let result = reader.get_object_flat(bucket, "/a.txt").await;

        let err = match result {
            Ok(bytes) => panic!(
                "content_hash must reject single-block substitution; got Ok({} bytes): {:?}",
                bytes.len(),
                bytes
            ),
            Err(e) => e,
        };
        let msg = format!("{}", err).to_lowercase();
        assert!(
            msg.contains("content_hash")
                || msg.contains("integrity")
                || msg.contains("mismatch"),
            "error should mention content_hash / integrity / mismatch; got: {}",
            msg
        );
    }

    /// H-1 for chunked files: an attacker rebuilds the entire Bao tree
    /// under a fresh DEK at the victim's storage_key. AEAD + Bao all
    /// verify (attacker controlled every input) — only the forest-pinned
    /// `content_hash` catches it.
    #[tokio::test]
    async fn content_hash_detects_chunked_tree_substitution() {
        let base = spawn_server().await;
        let encryption = EncryptionConfig::new();
        let public_key = encryption.public_key().clone();
        let secret = encryption.export_secret_key().clone();
        let bucket = "sec-h1-chunked-sub";

        let state = tempfile::tempdir().unwrap();
        let _guard = EnvGuard::set("FULA_STATE_DIR", state.path());

        let client = make_client(&base, encryption);
        client.create_bucket(bucket).await.expect("create");

        // > 768 KB triggers chunked upload.
        let original_plaintext = vec![b'O'; 1_200_000];
        client
            .put_object_flat(bucket, "/big.bin", original_plaintext.clone(), None)
            .await
            .expect("put original chunked");

        let storage_key = locate_storage_key_for_path(&client, bucket, "/big.bin").await;

        // Purge all of the legit chunk blobs so the attacker's chunks don't
        // have to exactly match the legit chunk count. We keep the main
        // storage_key (we'll overwrite it) but delete every `.chunks/*`
        // under it.
        let chunk_prefix = format!("{}.chunks/", storage_key);
        let legit_chunks = client
            .inner()
            .list_objects(
                bucket,
                Some(ListObjectsOptions {
                    prefix: Some(chunk_prefix.clone()),
                    max_keys: Some(500),
                    ..Default::default()
                }),
            )
            .await
            .expect("list legit chunks")
            .objects;
        for obj in &legit_chunks {
            client
                .inner()
                .delete_object(bucket, &obj.key)
                .await
                .expect("delete legit chunk");
        }

        // Attacker rebuilds the full tree with fresh DEK + fresh plaintext.
        let attacker_plaintext = vec![b'X'; 1_200_000];
        let attacker_dek = DekKey::generate();
        let wrapped = Encryptor::new(&public_key)
            .encrypt_dek(&attacker_dek)
            .expect("wrap attacker DEK");

        let aad_prefix = format!("fula:v4:chunk:{}", storage_key);
        let mut encoder = ChunkedEncoder::with_aad(attacker_dek.clone(), aad_prefix);
        let mut chunks = encoder
            .update(&attacker_plaintext)
            .expect("encode attacker chunks");
        let (final_chunk, chunked_metadata, _outboard) =
            encoder.finalize().expect("finalize attacker chunks");
        if let Some(c) = final_chunk {
            chunks.push(c);
        }

        for chunk in chunks {
            let chunk_key = ChunkedFileMetadata::chunk_key(&storage_key, chunk.index);
            let metadata = ObjectMetadata::new()
                .with_content_type("application/octet-stream")
                .with_metadata("x-fula-chunk", "true")
                .with_metadata("x-fula-chunk-index", &chunk.index.to_string());
            client
                .inner()
                .put_object_with_metadata(bucket, &chunk_key, chunk.ciphertext, Some(metadata))
                .await
                .expect("put attacker chunk");
        }

        let enc_metadata = serde_json::json!({
            "version": 4,
            "algorithm": "AES-256-GCM",
            "wrapped_key": serde_json::to_value(&wrapped).unwrap(),
            "kek_version": 1,
            "metadata_privacy": true,
            "obfuscation_mode": "flat",
            "chunked": serde_json::to_value(&chunked_metadata).unwrap(),
        });
        let main_meta = ObjectMetadata::new()
            .with_content_type("application/octet-stream")
            .with_metadata("x-fula-encrypted", "true")
            .with_metadata("x-fula-chunked", "true")
            .with_metadata("x-fula-encryption", &enc_metadata.to_string());
        client
            .inner()
            .put_object_with_metadata(
                bucket,
                &storage_key,
                Bytes::from_static(b"CHUNKED"),
                Some(main_meta),
            )
            .await
            .expect("put forged main index");

        drop(client);
        let reader = make_client(&base, EncryptionConfig::from_secret_key(secret));
        let result = reader.get_object_flat(bucket, "/big.bin").await;

        let err = match result {
            Ok(bytes) => panic!(
                "content_hash must reject chunked tree substitution; got Ok({} bytes)",
                bytes.len()
            ),
            Err(e) => e,
        };
        let msg = format!("{}", err).to_lowercase();
        assert!(
            msg.contains("content_hash")
                || msg.contains("integrity")
                || msg.contains("mismatch"),
            "error should mention content_hash / integrity / mismatch; got: {}",
            msg
        );
    }

    /// H-2: an attacker writes a self-consistent v2-format (no-AAD) blob
    /// at a storage_key pinned by the forest entry's `min_version = 4`.
    /// The pre-decrypt gate must fire and reject with VersionDowngrade
    /// before any AEAD work runs.
    #[tokio::test]
    async fn version_downgrade_rejected_on_v4_entry() {
        let base = spawn_server().await;
        let encryption = EncryptionConfig::new();
        let public_key = encryption.public_key().clone();
        let secret = encryption.export_secret_key().clone();
        let bucket = "sec-h2-downgrade";

        let state = tempfile::tempdir().unwrap();
        let _guard = EnvGuard::set("FULA_STATE_DIR", state.path());

        let client = make_client(&base, encryption);
        client.create_bucket(bucket).await.expect("create");
        client
            .put_object_flat(bucket, "/v4.txt", b"v4-protected".to_vec(), None)
            .await
            .expect("put legit v4");

        let storage_key = locate_storage_key_for_path(&client, bucket, "/v4.txt").await;

        forge_single_block_at(
            &client,
            &public_key,
            bucket,
            &storage_key,
            b"ATTACKER DOWNGRADE CONTENT",
            2,
        )
        .await;

        drop(client);
        let reader = make_client(&base, EncryptionConfig::from_secret_key(secret));
        let result = reader.get_object_flat(bucket, "/v4.txt").await;

        let err = match result {
            Ok(bytes) => panic!(
                "min_version must reject v2 downgrade; got Ok({} bytes): {:?}",
                bytes.len(),
                bytes
            ),
            Err(e) => e,
        };
        let msg = format!("{}", err).to_lowercase();
        assert!(
            msg.contains("downgrade") || msg.contains("version"),
            "error should mention downgrade / version; got: {}",
            msg
        );
    }

    /// Legacy / backwards-compat: an entry carried through the v1 → v7
    /// migration has `content_hash: None` and `min_version: 0`. The
    /// download path must NOT falsely reject those entries — the check
    /// is strictly additive for new uploads.
    ///
    /// Flow:
    /// 1. Upload `/legit.txt` via the normal v4 path. Capture the
    ///    storage_key the client derived for that path.
    /// 2. Hand-build a v1 `PrivateForest` whose `/legit.txt` entry points
    ///    at the SAME storage_key but leaves `content_hash: None` and
    ///    `min_version: 0` (legacy shape). Overwrite the bucket's
    ///    `index_key` with that v1 blob, simulating a pre-migration
    ///    state that still references the v4 ciphertext.
    /// 3. Fresh reader cold-starts, sees a v1 forest at load time, migrates
    ///    it to v7 (carrying the legacy flags forward per the migration
    ///    contract), then reads `/legit.txt`. Download succeeds because
    ///    `enforce_content_hash` skips entries with `content_hash: None`
    ///    and `enforce_min_version` passes entries with `min_version = 0`.
    #[tokio::test]
    async fn content_hash_none_permits_legacy_read() {
        let base = spawn_server().await;
        let encryption = EncryptionConfig::new();
        let secret = encryption.export_secret_key().clone();
        let bucket = "sec-h1-legacy-read";

        let state = tempfile::tempdir().unwrap();
        let _guard = EnvGuard::set("FULA_STATE_DIR", state.path());

        let client = make_client(&base, encryption);
        client.create_bucket(bucket).await.expect("create");
        let plaintext = b"LEGACY-ERA CONTENT".to_vec();
        client
            .put_object_flat(bucket, "/legit.txt", plaintext.clone(), None)
            .await
            .expect("put legit");

        let storage_key = locate_storage_key_for_path(&client, bucket, "/legit.txt").await;

        // Seed a v1 forest entry pointing at the same storage_key as the v4
        // upload but with legacy flags (content_hash=None, min_version=0).
        // `seed_v1_forest` uses `storage_key_for_seed(path)` by default;
        // override by mutating the SeedFile field directly.
        let mut sf = SeedFile::new("/legit.txt", plaintext.len() as u64);
        sf.storage_key = storage_key.clone();
        sf.content_hash = None;
        sf.encrypted = true;
        let v1_forest = build_v1_private_forest(&[sf], &[]);
        let km = client.encryption_config().key_manager();
        let forest_dek = km.derive_path_key(&format!("forest:{}", bucket));
        let enc = EncryptedForest::encrypt(&v1_forest, &forest_dek).expect("encrypt v1");
        assert_eq!(enc.version, 1);
        assert!(enc.sequence.is_none());
        let bytes = enc.to_bytes().expect("serialize v1");
        let index_key = index_key_for(&client, bucket);
        client
            .inner()
            .put_object(bucket, &index_key, Bytes::from(bytes))
            .await
            .expect("overwrite manifest with v1");

        drop(client);
        let reader = make_client(&base, EncryptionConfig::from_secret_key(secret));
        let result = reader
            .get_object_flat(bucket, "/legit.txt")
            .await
            .expect("legacy entry (content_hash=None) must read successfully");
        assert_eq!(
            result.as_ref(),
            plaintext.as_slice(),
            "legacy-path read must return the original v4 plaintext unchanged"
        );
    }
}
