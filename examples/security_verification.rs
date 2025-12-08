//! Security Verification Example
//!
//! This example demonstrates and verifies the security properties of the
//! Fula encryption system through various attack scenarios.
//!
//! Run with: cargo run --example security_verification
//!
//! Security properties verified:
//! 1. Server-side data is encrypted and unreadable
//! 2. Wrong keys cannot decrypt data
//! 3. Tampered ciphertext is detected
//! 4. Key recovery works correctly
//! 5. Different encryption sessions produce different ciphertexts
//! 6. Nonces are unique per encryption

use fula_client::{Config, EncryptedClient, EncryptionConfig, FulaClient};
use fula_crypto::{
    keys::{KekKeyPair, SecretKey},
    hpke::{Encryptor, Decryptor},
    symmetric::Nonce,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("🔒 Fula Storage - Security Verification Suite\n");
    println!("This example verifies the security properties of client-side encryption.\n");
    println!("═══════════════════════════════════════════════════════════════════════\n");

    // Run all security tests
    test_1_encrypted_data_is_unreadable().await?;
    test_2_wrong_key_cannot_decrypt().await?;
    test_3_tampered_ciphertext_detected()?;
    test_4_key_recovery_works().await?;
    test_5_different_sessions_different_ciphertext()?;
    test_6_nonce_uniqueness()?;
    test_7_server_never_sees_plaintext().await?;
    test_8_multi_recipient_isolation()?;
    test_9_key_derivation_security()?;
    test_10_ciphertext_indistinguishability()?;

    println!("\n═══════════════════════════════════════════════════════════════════════");
    println!("✅ All security verification tests PASSED!");
    println!("═══════════════════════════════════════════════════════════════════════\n");

    Ok(())
}

/// Test 1: Verify that encrypted data stored on the server is not readable
async fn test_1_encrypted_data_is_unreadable() -> anyhow::Result<()> {
    println!("🔐 Test 1: Encrypted data is unreadable on server");
    println!("   Testing that server-stored data doesn't contain plaintext...");

    // Use without_privacy so we can inspect raw server data with known keys
    let encryption = EncryptionConfig::new_without_privacy();
    let config = Config::new("http://localhost:9000")
        .with_token("test-token");
    let encrypted_client = EncryptedClient::new(config.clone(), encryption)?;

    // Create a test bucket
    let bucket = "security-test-1";
    let _ = encrypted_client.create_bucket(bucket).await;

    // Upload sensitive data encrypted
    let secret_data = "TOP SECRET: Launch codes are 12345-ABCDE-67890";
    encrypted_client.put_object_encrypted(
        bucket,
        "classified.txt",
        secret_data.as_bytes().to_vec(),
    ).await?;

    // Now fetch the raw data using a non-encrypted client
    let raw_client = FulaClient::new(config)?;
    let raw_data = raw_client.get_object(bucket, "classified.txt").await?;
    let raw_string = String::from_utf8_lossy(&raw_data);

    // Verify the secret is NOT in the raw data
    assert!(
        !raw_string.contains("TOP SECRET"),
        "SECURITY FAILURE: Plaintext found in server data!"
    );
    assert!(
        !raw_string.contains("12345"),
        "SECURITY FAILURE: Secret codes found in server data!"
    );
    assert!(
        !raw_string.contains("Launch codes"),
        "SECURITY FAILURE: Sensitive text found in server data!"
    );

    // Verify the raw data is binary/encrypted (not readable text)
    let printable_ratio = raw_data.iter()
        .filter(|&&b| b >= 32 && b <= 126)
        .count() as f64 / raw_data.len() as f64;
    
    // Encrypted data should have low printable character ratio
    // (random bytes, not structured text)
    assert!(
        printable_ratio < 0.9,
        "SECURITY FAILURE: Data appears to be mostly plaintext ({}% printable)",
        (printable_ratio * 100.0) as u32
    );

    // Cleanup
    encrypted_client.delete_object(bucket, "classified.txt").await?;
    encrypted_client.delete_bucket(bucket).await?;

    println!("   ✅ PASSED: Server data is encrypted and unreadable");
    Ok(())
}

/// Test 2: Verify that wrong keys cannot decrypt data
async fn test_2_wrong_key_cannot_decrypt() -> anyhow::Result<()> {
    println!("\n🔐 Test 2: Wrong keys cannot decrypt data");
    println!("   Testing that attacker with different keys cannot read data...");

    // Owner's encryption config (without privacy for predictable key paths)
    let owner_encryption = EncryptionConfig::new_without_privacy();
    let owner_config = Config::new("http://localhost:9000")
        .with_token("owner-token");
    let owner_client = EncryptedClient::new(owner_config, owner_encryption)?;

    // Create bucket and upload encrypted data
    let bucket = "security-test-2";
    let _ = owner_client.create_bucket(bucket).await;

    let secret = "Bank account: 1234567890, PIN: 9999";
    owner_client.put_object_encrypted(bucket, "bank.txt", secret.as_bytes().to_vec()).await?;

    // Attacker tries with different keys (also without privacy to use same key path)
    let attacker_encryption = EncryptionConfig::new_without_privacy();
    let attacker_config = Config::new("http://localhost:9000")
        .with_token("attacker-token");
    let attacker_client = EncryptedClient::new(attacker_config, attacker_encryption)?;

    // Attacker attempts to decrypt
    let result = attacker_client.get_object_decrypted(bucket, "bank.txt").await;
    
    assert!(
        result.is_err(),
        "SECURITY FAILURE: Attacker was able to decrypt data with wrong keys!"
    );

    // Verify the error is a decryption error
    let err_msg = format!("{:?}", result.unwrap_err());
    assert!(
        err_msg.contains("Encryption") || err_msg.contains("Decryption") || err_msg.contains("crypto"),
        "Expected decryption error, got: {}", err_msg
    );

    // Cleanup
    owner_client.delete_object(bucket, "bank.txt").await?;
    owner_client.delete_bucket(bucket).await?;

    println!("   ✅ PASSED: Wrong keys correctly rejected");
    Ok(())
}

/// Test 3: Verify that tampered ciphertext is detected
fn test_3_tampered_ciphertext_detected() -> anyhow::Result<()> {
    println!("\n🔐 Test 3: Tampered ciphertext detection");
    println!("   Testing that modified ciphertext fails authentication...");

    let keypair = KekKeyPair::generate();
    let plaintext = b"This message must not be tampered with!";

    // Encrypt the message
    let encryptor = Encryptor::new(keypair.public_key());
    let mut encrypted = encryptor.encrypt(plaintext)?;

    // Save original ciphertext for comparison
    let original_ciphertext = encrypted.ciphertext.clone();

    // Tamper with the ciphertext (flip a bit)
    if !encrypted.ciphertext.is_empty() {
        encrypted.ciphertext[0] ^= 0x01;
    }

    // Attempt to decrypt tampered data
    let decryptor = Decryptor::new(&keypair);
    let result = decryptor.decrypt(&encrypted);

    assert!(
        result.is_err(),
        "SECURITY FAILURE: Tampered ciphertext was accepted!"
    );

    // Restore and verify original works
    encrypted.ciphertext = original_ciphertext;
    let decrypted = decryptor.decrypt(&encrypted)?;
    assert_eq!(plaintext.as_slice(), decrypted.as_slice());

    // Test tampering with encapsulated key (RFC 9180 HPKE handles nonce internally)
    let mut encrypted2 = encryptor.encrypt(plaintext)?;
    
    // Tamper with encapsulated key
    encrypted2.encapsulated_key.ephemeral_public[0] ^= 0x01;

    let result2 = decryptor.decrypt(&encrypted2);
    assert!(
        result2.is_err(),
        "SECURITY FAILURE: Tampered encapsulated key was accepted!"
    );

    println!("   ✅ PASSED: Tampered ciphertext correctly rejected");
    Ok(())
}

/// Test 4: Verify key recovery works correctly
async fn test_4_key_recovery_works() -> anyhow::Result<()> {
    println!("\n🔐 Test 4: Key recovery functionality");
    println!("   Testing that exported keys can decrypt data...");

    // Original encryption setup (without privacy for predictable key paths)
    let encryption = EncryptionConfig::new_without_privacy();
    
    // Export the secret key (simulating backup)
    let secret_key_backup = encryption.export_secret_key().to_base64();
    
    let config = Config::new("http://localhost:9000")
        .with_token("test-token");
    let client = EncryptedClient::new(config.clone(), encryption)?;

    // Upload encrypted data
    let bucket = "security-test-4";
    let _ = client.create_bucket(bucket).await;

    let important_data = "Critical backup data that must be recoverable!";
    client.put_object_encrypted(bucket, "backup.dat", important_data.as_bytes().to_vec()).await?;

    // Simulate key loss - create new client with recovered key
    let recovered_secret = SecretKey::from_base64(&secret_key_backup)?;
    let recovered_encryption = EncryptionConfig::from_secret_key(recovered_secret)
        .with_metadata_privacy(false); // Match original client settings
    let recovered_client = EncryptedClient::new(config, recovered_encryption)?;

    // Decrypt with recovered key
    let decrypted = recovered_client.get_object_decrypted(bucket, "backup.dat").await?;
    let decrypted_str = String::from_utf8(decrypted.to_vec())?;

    assert_eq!(
        important_data, decrypted_str,
        "SECURITY FAILURE: Recovered keys did not decrypt data correctly!"
    );

    // Cleanup
    client.delete_object(bucket, "backup.dat").await?;
    client.delete_bucket(bucket).await?;

    println!("   ✅ PASSED: Key recovery works correctly");
    Ok(())
}

/// Test 5: Verify different encryption sessions produce different ciphertexts
fn test_5_different_sessions_different_ciphertext() -> anyhow::Result<()> {
    println!("\n🔐 Test 5: Ciphertext randomness");
    println!("   Testing that same plaintext produces different ciphertexts...");

    let keypair = KekKeyPair::generate();
    let plaintext = b"Identical message encrypted multiple times";

    let encryptor = Encryptor::new(keypair.public_key());
    
    // Encrypt the same message multiple times
    let encrypted1 = encryptor.encrypt(plaintext)?;
    let encrypted2 = encryptor.encrypt(plaintext)?;
    let encrypted3 = encryptor.encrypt(plaintext)?;

    // Verify all ciphertexts are different
    assert_ne!(
        encrypted1.ciphertext, encrypted2.ciphertext,
        "SECURITY FAILURE: Identical ciphertexts detected!"
    );
    assert_ne!(
        encrypted2.ciphertext, encrypted3.ciphertext,
        "SECURITY FAILURE: Identical ciphertexts detected!"
    );
    assert_ne!(
        encrypted1.ciphertext, encrypted3.ciphertext,
        "SECURITY FAILURE: Identical ciphertexts detected!"
    );

    // Verify all can still be decrypted to same plaintext
    let decryptor = Decryptor::new(&keypair);
    assert_eq!(plaintext.as_slice(), decryptor.decrypt(&encrypted1)?.as_slice());
    assert_eq!(plaintext.as_slice(), decryptor.decrypt(&encrypted2)?.as_slice());
    assert_eq!(plaintext.as_slice(), decryptor.decrypt(&encrypted3)?.as_slice());

    println!("   ✅ PASSED: Each encryption produces unique ciphertext");
    Ok(())
}

/// Test 6: Verify nonce uniqueness
fn test_6_nonce_uniqueness() -> anyhow::Result<()> {
    println!("\n🔐 Test 6: Nonce uniqueness");
    println!("   Testing that nonces are never reused...");

    let mut nonces = std::collections::HashSet::new();
    
    // Generate many nonces and verify uniqueness
    for _ in 0..10000 {
        let nonce = Nonce::generate();
        let nonce_bytes = nonce.as_bytes().to_vec();
        
        assert!(
            nonces.insert(nonce_bytes),
            "SECURITY FAILURE: Nonce collision detected!"
        );
    }

    // Verify nonces have sufficient randomness (entropy check)
    let nonce1 = Nonce::generate();
    let nonce2 = Nonce::generate();
    
    // Count differing bytes (should be most of them for random nonces)
    let differing_bytes = nonce1.as_bytes().iter()
        .zip(nonce2.as_bytes().iter())
        .filter(|(a, b)| a != b)
        .count();
    
    assert!(
        differing_bytes > nonce1.as_bytes().len() / 2,
        "SECURITY FAILURE: Nonces appear predictable!"
    );

    println!("   ✅ PASSED: Nonces are unique and random");
    Ok(())
}

/// Test 7: Verify server never sees plaintext in any form
async fn test_7_server_never_sees_plaintext() -> anyhow::Result<()> {
    println!("\n🔐 Test 7: Server-side plaintext isolation");
    println!("   Testing that plaintext never reaches the server...");

    // Without privacy so we can inspect raw server data with known keys
    let encryption = EncryptionConfig::new_without_privacy();
    let config = Config::new("http://localhost:9000")
        .with_token("test-token");
    let client = EncryptedClient::new(config.clone(), encryption)?;

    let bucket = "security-test-7";
    let _ = client.create_bucket(bucket).await;

    // Multiple sensitive patterns to check
    let sensitive_patterns = [
        "CREDIT_CARD: 4111-1111-1111-1111",
        "SSN: 123-45-6789",
        "PASSWORD: hunter2",
        "API_KEY: sk_live_xyz123",
    ];

    for (i, pattern) in sensitive_patterns.iter().enumerate() {
        let key = format!("sensitive_{}.txt", i);
        client.put_object_encrypted(bucket, &key, pattern.as_bytes().to_vec()).await?;

        // Fetch raw from server
        let raw_client = FulaClient::new(config.clone())?;
        let raw_data = raw_client.get_object(bucket, &key).await?;

        // Check that NO part of the sensitive pattern appears
        let raw_str = String::from_utf8_lossy(&raw_data);
        for word in pattern.split(&[' ', ':', '-'][..]) {
            if word.len() > 3 {  // Only check meaningful tokens
                assert!(
                    !raw_str.contains(word),
                    "SECURITY FAILURE: Sensitive token '{}' found in server data!", word
                );
            }
        }

        client.delete_object(bucket, &key).await?;
    }

    client.delete_bucket(bucket).await?;

    println!("   ✅ PASSED: Server never sees plaintext");
    Ok(())
}

/// Test 8: Multi-recipient encryption isolation
fn test_8_multi_recipient_isolation() -> anyhow::Result<()> {
    println!("\n🔐 Test 8: Multi-recipient isolation");
    println!("   Testing that recipients cannot access each other's keys...");

    // Create three recipients
    let alice = KekKeyPair::generate();
    let bob = KekKeyPair::generate();
    let charlie = KekKeyPair::generate();

    let secret_for_alice = b"Alice's secret message";
    let secret_for_bob = b"Bob's secret message";

    // Encrypt for Alice
    let alice_encryptor = Encryptor::new(alice.public_key());
    let alice_encrypted = alice_encryptor.encrypt(secret_for_alice)?;

    // Encrypt for Bob
    let bob_encryptor = Encryptor::new(bob.public_key());
    let bob_encrypted = bob_encryptor.encrypt(secret_for_bob)?;

    // Alice can decrypt her message
    let alice_decryptor = Decryptor::new(&alice);
    let alice_decrypted = alice_decryptor.decrypt(&alice_encrypted)?;
    assert_eq!(secret_for_alice.as_slice(), alice_decrypted.as_slice());

    // Bob can decrypt his message
    let bob_decryptor = Decryptor::new(&bob);
    let bob_decrypted = bob_decryptor.decrypt(&bob_encrypted)?;
    assert_eq!(secret_for_bob.as_slice(), bob_decrypted.as_slice());

    // Alice CANNOT decrypt Bob's message
    assert!(
        alice_decryptor.decrypt(&bob_encrypted).is_err(),
        "SECURITY FAILURE: Alice decrypted Bob's message!"
    );

    // Bob CANNOT decrypt Alice's message
    assert!(
        bob_decryptor.decrypt(&alice_encrypted).is_err(),
        "SECURITY FAILURE: Bob decrypted Alice's message!"
    );

    // Charlie CANNOT decrypt either
    let charlie_decryptor = Decryptor::new(&charlie);
    assert!(
        charlie_decryptor.decrypt(&alice_encrypted).is_err(),
        "SECURITY FAILURE: Charlie decrypted Alice's message!"
    );
    assert!(
        charlie_decryptor.decrypt(&bob_encrypted).is_err(),
        "SECURITY FAILURE: Charlie decrypted Bob's message!"
    );

    println!("   ✅ PASSED: Recipients are properly isolated");
    Ok(())
}

/// Test 9: Key derivation security
fn test_9_key_derivation_security() -> anyhow::Result<()> {
    println!("\n🔐 Test 9: Key derivation security");
    println!("   Testing key derivation properties...");

    // Test that different contexts produce different keys
    use fula_crypto::hashing::derive_key;
    
    let master_secret = b"master secret key material";
    
    let key1 = derive_key("context-1", master_secret);
    let key2 = derive_key("context-2", master_secret);
    let key3 = derive_key("context-1", master_secret);  // Same as key1

    assert_ne!(
        key1.as_bytes(), key2.as_bytes(),
        "SECURITY FAILURE: Different contexts produced same key!"
    );
    assert_eq!(
        key1.as_bytes(), key3.as_bytes(),
        "SECURITY FAILURE: Same context produced different keys!"
    );

    // Test that derived keys have full entropy
    let key_bytes = key1.as_bytes();
    let unique_bytes: std::collections::HashSet<_> = key_bytes.iter().collect();
    
    assert!(
        unique_bytes.len() > key_bytes.len() / 2,
        "SECURITY FAILURE: Derived key has low entropy!"
    );

    println!("   ✅ PASSED: Key derivation is secure");
    Ok(())
}

/// Test 10: Ciphertext indistinguishability
fn test_10_ciphertext_indistinguishability() -> anyhow::Result<()> {
    println!("\n🔐 Test 10: Ciphertext indistinguishability");
    println!("   Testing that ciphertexts don't leak message information...");

    let keypair = KekKeyPair::generate();
    let encryptor = Encryptor::new(keypair.public_key());

    // Messages of same length should produce ciphertexts of same length
    let msg1 = b"AAAAAAAAAA";  // 10 bytes of A
    let msg2 = b"BBBBBBBBBB";  // 10 bytes of B

    let enc1 = encryptor.encrypt(msg1)?;
    let enc2 = encryptor.encrypt(msg2)?;

    assert_eq!(
        enc1.ciphertext.len(), enc2.ciphertext.len(),
        "Ciphertexts have different lengths for same-length messages"
    );

    // Messages of different lengths should not be distinguishable by content analysis
    // Use messages long enough to have meaningful entropy measurement
    let msg_a = b"This is message A with some reasonable length for entropy testing!!!";
    let msg_b = b"This is message B with some reasonable length for entropy testing!!!";

    let enc_a = encryptor.encrypt(msg_a)?;
    let enc_b = encryptor.encrypt(msg_b)?;

    // Both ciphertexts should look random (high byte diversity relative to length)
    fn byte_diversity(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }
        let unique: std::collections::HashSet<_> = data.iter().collect();
        // For random data, we expect ~63% unique bytes for length >= 256
        // For shorter data, unique/len should be high (close to 1.0 for very short)
        unique.len() as f64 / data.len().min(256) as f64
    }

    let diversity_a = byte_diversity(&enc_a.ciphertext);
    let diversity_b = byte_diversity(&enc_b.ciphertext);

    // Both should have good byte diversity (random-looking)
    // For AES-GCM output, we expect high diversity
    assert!(
        diversity_a > 0.3,
        "SECURITY FAILURE: Ciphertext A has low byte diversity: {:.2}",
        diversity_a
    );
    assert!(
        diversity_b > 0.3,
        "SECURITY FAILURE: Ciphertext B has low byte diversity: {:.2}",
        diversity_b
    );

    // Ciphertexts of same-length plaintexts should have same length
    assert_eq!(
        enc_a.ciphertext.len(),
        enc_b.ciphertext.len(),
        "Same-length messages should produce same-length ciphertexts"
    );

    println!("   ✅ PASSED: Ciphertexts are indistinguishable");
    Ok(())
}
