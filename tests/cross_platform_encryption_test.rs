//! Cross-platform encryption compatibility test
//!
//! This test verifies that encryption done via one platform (e.g., Flutter/native)
//! can be decrypted by another platform (e.g., WebUI/WASM).
//!
//! The test simulates the full encryption flow:
//! 1. Derive key using Argon2id (same as both platforms)
//! 2. Create keypair from derived key
//! 3. Encrypt data with HPKE-wrapped DEK
//! 4. Decrypt with the same key (simulating cross-platform)

use fula_crypto::{
    hashing::derive_key_argon2id,
    keys::{SecretKey, KeyManager, DekKey},
    hpke::{Encryptor, Decryptor, EncryptedData},
    symmetric::{Aead, Nonce},
};

/// Test data that simulates what FxFiles would encrypt
const TEST_PLAINTEXT: &[u8] = b"Hello from FxFiles! This is a test file content.";
const TEST_CONTEXT: &str = "fula-files-v1";
const TEST_INPUT: &str = "google:123456789:test@example.com";

#[test]
fn test_argon2id_key_derivation_consistency() {
    // Derive key twice - should be identical
    let key1 = derive_key_argon2id(TEST_CONTEXT, TEST_INPUT.as_bytes());
    let key2 = derive_key_argon2id(TEST_CONTEXT, TEST_INPUT.as_bytes());

    assert_eq!(key1, key2, "Argon2id should produce consistent keys");
    assert_eq!(key1.len(), 32, "Key should be 32 bytes");

    println!("Derived key (first 4 bytes): {:02x} {:02x} {:02x} {:02x}",
             key1[0], key1[1], key1[2], key1[3]);
}

#[test]
fn test_keypair_derivation_from_secret() {
    // Derive the secret key
    let secret_bytes = derive_key_argon2id(TEST_CONTEXT, TEST_INPUT.as_bytes());

    // Create secret key and derive public key
    let secret = SecretKey::from_bytes(&secret_bytes).expect("Valid secret key");
    let public = secret.public_key();

    // Derive again - should get same public key
    let secret2 = SecretKey::from_bytes(&secret_bytes).expect("Valid secret key");
    let public2 = secret2.public_key();

    assert_eq!(public.as_bytes(), public2.as_bytes(), "Public keys should match");

    println!("Public key (base64): {}", public.to_base64());
}

#[test]
fn test_hpke_encrypt_decrypt_roundtrip() {
    // Step 1: Derive key (simulating Flutter/FxFiles)
    let secret_bytes = derive_key_argon2id(TEST_CONTEXT, TEST_INPUT.as_bytes());
    let secret = SecretKey::from_bytes(&secret_bytes).expect("Valid secret key");
    let public = secret.public_key();

    // Step 2: Generate random DEK and encrypt it with HPKE
    let dek = DekKey::generate();
    let encryptor = Encryptor::new(&public);
    let wrapped_dek = encryptor.encrypt_dek(&dek).expect("DEK encryption failed");

    println!("Wrapped DEK version: {}", wrapped_dek.version);
    println!("Wrapped DEK encapsulated key: {}", wrapped_dek.encapsulated_key.to_base64());
    println!("Wrapped DEK ciphertext length: {}", wrapped_dek.ciphertext.len());

    // Step 3: Encrypt the plaintext with DEK
    let nonce = Nonce::generate();
    let aead = Aead::new_default(&dek);
    let ciphertext = aead.encrypt(&nonce, TEST_PLAINTEXT).expect("Encryption failed");

    println!("Ciphertext length: {}", ciphertext.len());
    println!("Nonce (base64): {}", base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        nonce.as_bytes()
    ));

    // Step 4: Simulate "different platform" by creating new keypair from same secret
    // This is what WebUI/WASM would do
    let secret_bytes_2 = derive_key_argon2id(TEST_CONTEXT, TEST_INPUT.as_bytes());
    let secret_2 = SecretKey::from_bytes(&secret_bytes_2).expect("Valid secret key");

    // Create KeyManager (same as EncryptedClient does)
    let key_manager = KeyManager::from_secret_key(secret_2);

    // Step 5: Decrypt the DEK using HPKE
    let decryptor = Decryptor::new(key_manager.keypair());
    let decrypted_dek = decryptor.decrypt_dek(&wrapped_dek).expect("DEK decryption failed");

    // Verify DEK matches
    assert_eq!(dek.as_bytes(), decrypted_dek.as_bytes(), "Decrypted DEK should match original");

    // Step 6: Decrypt the ciphertext
    let aead_decrypt = Aead::new_default(&decrypted_dek);
    let decrypted = aead_decrypt.decrypt(&nonce, &ciphertext).expect("Decryption failed");

    assert_eq!(decrypted, TEST_PLAINTEXT, "Decrypted content should match original");

    println!("SUCCESS: Cross-platform encryption/decryption works!");
}

#[test]
fn test_full_encryption_metadata_format() {
    // This test creates the full encryption metadata format used by fula-client
    // and verifies it can be parsed and decrypted

    let secret_bytes = derive_key_argon2id(TEST_CONTEXT, TEST_INPUT.as_bytes());
    let secret = SecretKey::from_bytes(&secret_bytes).expect("Valid secret key");
    let public = secret.public_key();

    // Generate DEK and wrap with HPKE
    let dek = DekKey::generate();
    let encryptor = Encryptor::new(&public);
    let wrapped_dek = encryptor.encrypt_dek(&dek).expect("DEK encryption failed");

    // Encrypt content
    let nonce = Nonce::generate();
    let aead = Aead::new_default(&dek);
    let ciphertext = aead.encrypt(&nonce, TEST_PLAINTEXT).expect("Encryption failed");

    // Create metadata JSON (same format as fula-client uses in x-fula-encryption header)
    let enc_metadata = serde_json::json!({
        "version": 2,
        "algorithm": "AES-256-GCM",
        "nonce": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, nonce.as_bytes()),
        "wrapped_key": serde_json::to_value(&wrapped_dek).unwrap(),
        "kek_version": 1,
        "metadata_privacy": true,
    });

    let metadata_json = serde_json::to_string_pretty(&enc_metadata).unwrap();
    println!("Encryption metadata JSON:\n{}", metadata_json);

    // Now simulate WebUI parsing and decrypting
    let parsed: serde_json::Value = serde_json::from_str(&metadata_json).unwrap();

    // Parse wrapped_key back to EncryptedData
    let wrapped_key: EncryptedData = serde_json::from_value(
        parsed["wrapped_key"].clone()
    ).expect("Failed to parse wrapped_key");

    // Decrypt DEK
    let key_manager = KeyManager::from_secret_key(
        SecretKey::from_bytes(&secret_bytes).unwrap()
    );
    let decryptor = Decryptor::new(key_manager.keypair());
    let decrypted_dek = decryptor.decrypt_dek(&wrapped_key).expect("DEK decryption failed");

    // Parse nonce
    let nonce_b64 = parsed["nonce"].as_str().unwrap();
    let nonce_bytes = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        nonce_b64
    ).unwrap();
    let nonce = Nonce::from_bytes(&nonce_bytes).unwrap();

    // Decrypt content
    let aead_decrypt = Aead::new_default(&decrypted_dek);
    let decrypted = aead_decrypt.decrypt(&nonce, &ciphertext).expect("Decryption failed");

    assert_eq!(decrypted, TEST_PLAINTEXT);
    println!("SUCCESS: Full metadata format encryption/decryption works!");
}

#[test]
fn test_serialize_deserialize_encrypted_data() {
    // Test that EncryptedData serializes and deserializes correctly
    let secret_bytes = derive_key_argon2id(TEST_CONTEXT, TEST_INPUT.as_bytes());
    let secret = SecretKey::from_bytes(&secret_bytes).unwrap();
    let public = secret.public_key();

    let dek = DekKey::generate();
    let encryptor = Encryptor::new(&public);
    let wrapped_dek = encryptor.encrypt_dek(&dek).unwrap();

    // Serialize to JSON
    let json = serde_json::to_string(&wrapped_dek).unwrap();
    println!("Serialized EncryptedData: {}", json);

    // Deserialize back
    let deserialized: EncryptedData = serde_json::from_str(&json).unwrap();

    // Verify fields match
    assert_eq!(wrapped_dek.version, deserialized.version);
    assert_eq!(
        wrapped_dek.encapsulated_key.as_bytes(),
        deserialized.encapsulated_key.as_bytes()
    );
    assert_eq!(wrapped_dek.ciphertext, deserialized.ciphertext);

    // Verify can still decrypt
    let key_manager = KeyManager::from_secret_key(
        SecretKey::from_bytes(&secret_bytes).unwrap()
    );
    let decryptor = Decryptor::new(key_manager.keypair());
    let decrypted_dek = decryptor.decrypt_dek(&deserialized).unwrap();

    assert_eq!(dek.as_bytes(), decrypted_dek.as_bytes());
    println!("SUCCESS: EncryptedData serialization/deserialization works!");
}

/// This test outputs data that can be used to test JS/WASM decryption
#[test]
fn test_generate_test_vector_for_js() {
    let secret_bytes = derive_key_argon2id(TEST_CONTEXT, TEST_INPUT.as_bytes());
    let secret = SecretKey::from_bytes(&secret_bytes).unwrap();
    let public = secret.public_key();

    let dek = DekKey::generate();
    let encryptor = Encryptor::new(&public);
    let wrapped_dek = encryptor.encrypt_dek(&dek).unwrap();

    let nonce = Nonce::generate();
    let aead = Aead::new_default(&dek);
    let ciphertext = aead.encrypt(&nonce, TEST_PLAINTEXT).unwrap();

    let test_vector = serde_json::json!({
        "description": "Test vector for cross-platform encryption verification",
        "context": TEST_CONTEXT,
        "input": TEST_INPUT,
        "derived_key_hex": hex::encode(&secret_bytes),
        "public_key_base64": public.to_base64(),
        "plaintext": String::from_utf8_lossy(TEST_PLAINTEXT),
        "encryption_metadata": {
            "version": 2,
            "algorithm": "AES-256-GCM",
            "nonce": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, nonce.as_bytes()),
            "wrapped_key": serde_json::to_value(&wrapped_dek).unwrap(),
        },
        "ciphertext_base64": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &ciphertext),
    });

    println!("\n=== TEST VECTOR FOR JS/WASM ===\n");
    println!("{}", serde_json::to_string_pretty(&test_vector).unwrap());
    println!("\n=== END TEST VECTOR ===\n");
}
