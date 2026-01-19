//! Exact Flow Test - Simulates FxFiles encryption and WebUI decryption
//!
//! This test replicates the EXACT encryption flow used by FxFiles
//! and outputs data in the EXACT format that WebUI would receive.

use fula_crypto::{
    hashing::derive_key_argon2id,
    keys::{SecretKey, KeyManager, DekKey},
    hpke::{Encryptor, Decryptor, EncryptedData},
    symmetric::{Aead, Nonce},
    private_metadata::{KeyObfuscation, obfuscate_key},
};

const TEST_CONTEXT: &str = "fula-files-v1";
const TEST_INPUT: &str = "google:123456789:test@example.com";
const TEST_PLAINTEXT: &[u8] = b"Hello from FxFiles! This is test content.";
const TEST_FILENAME: &str = "test-photo.jpg";
const TEST_BUCKET: &str = "photos";

/// Simulates EXACTLY what FxFiles/fula-client does when uploading an encrypted file
/// See: crates/fula-client/src/encryption.rs - put_object_encrypted_with_type()
fn simulate_fxfiles_encryption(
    secret_key_bytes: &[u8; 32],
    plaintext: &[u8],
    original_filename: &str,
) -> (String, Vec<u8>, String) {
    // Step 1: Create KeyManager from secret key (same as EncryptionConfig::from_secret_key)
    let secret = SecretKey::from_bytes(secret_key_bytes).unwrap();
    let key_manager = KeyManager::from_secret_key(secret);

    // Step 2: Generate random DEK for this file
    let dek = DekKey::generate();

    // Step 3: Encrypt the DEK with HPKE for the owner's public key
    // See encryption.rs line 217-219
    let encryptor = Encryptor::new(key_manager.public_key());
    let wrapped_dek = encryptor.encrypt_dek(&dek).unwrap();

    // Step 4: Generate storage key (obfuscated filename)
    // In FlatNamespace mode, this is a random-looking hash
    let storage_key = obfuscate_key(original_filename, &dek, KeyObfuscation::FlatNamespace);

    // Step 5: Encrypt the file content with DEK using AES-256-GCM
    let nonce = Nonce::generate();
    let aead = Aead::new_default(&dek);
    let ciphertext = aead.encrypt(&nonce, plaintext).unwrap();

    // Step 6: Create encryption metadata JSON (stored in x-fula-encryption header)
    // See encryption.rs line 243-252
    // Note: We skip private_metadata for simplicity - the core issue is HPKE/DEK unwrapping
    let enc_metadata = serde_json::json!({
        "version": 2,
        "algorithm": "AES-256-GCM",
        "nonce": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, nonce.as_bytes()),
        "wrapped_key": serde_json::to_value(&wrapped_dek).unwrap(),
        "kek_version": 1,
        "metadata_privacy": true,
    });

    let metadata_json = serde_json::to_string(&enc_metadata).unwrap();

    (storage_key, ciphertext, metadata_json)
}

/// Simulates EXACTLY what WebUI/WASM should do when decrypting
/// See: crates/fula-client/src/encryption.rs - get_object_decrypted_by_storage_key()
fn simulate_webui_wasm_decryption(
    secret_key_bytes: &[u8; 32],
    ciphertext: &[u8],
    metadata_json: &str,
) -> Result<Vec<u8>, String> {
    // Step 1: Create KeyManager from secret key
    let secret = SecretKey::from_bytes(secret_key_bytes)
        .map_err(|e| format!("Invalid secret key: {}", e))?;
    let key_manager = KeyManager::from_secret_key(secret);

    // Step 2: Parse encryption metadata
    let enc_metadata: serde_json::Value = serde_json::from_str(metadata_json)
        .map_err(|e| format!("Failed to parse metadata: {}", e))?;

    // Step 3: Extract and decrypt the wrapped DEK using HPKE
    // This is where decryption fails if keys don't match!
    let wrapped_key: EncryptedData = serde_json::from_value(
        enc_metadata["wrapped_key"].clone()
    ).map_err(|e| format!("Failed to parse wrapped_key: {}", e))?;

    let decryptor = Decryptor::new(key_manager.keypair());
    let dek = decryptor.decrypt_dek(&wrapped_key)
        .map_err(|e| format!("HPKE DEK decryption failed: {}", e))?;

    // Step 4: Parse nonce
    let nonce_b64 = enc_metadata["nonce"].as_str()
        .ok_or("Missing nonce")?;
    let nonce_bytes = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        nonce_b64,
    ).map_err(|e| format!("Failed to decode nonce: {}", e))?;
    let nonce = Nonce::from_bytes(&nonce_bytes)
        .map_err(|e| format!("Invalid nonce: {}", e))?;

    // Step 5: Decrypt content with DEK
    let aead = Aead::new_default(&dek);
    let plaintext = aead.decrypt(&nonce, ciphertext)
        .map_err(|e| format!("AES-GCM decryption failed: {}", e))?;

    Ok(plaintext)
}

/// Simulates what WebUI's decryptEnvelope() does - WRONG approach!
/// See: pinning-webui/src/services/encryptionService.ts - decryptEnvelopeV1()
fn simulate_webui_wrong_decryption(
    secret_key_bytes: &[u8; 32],
    _ciphertext: &[u8],
    metadata_json: &str,
) -> Result<Vec<u8>, String> {
    // WebUI's decryptEnvelope expects a JSON body like:
    // {"version":1,"ciphertext":"...","nonce":"...","tag":"..."}
    //
    // But FxFiles stores:
    // - Body: raw AES-GCM ciphertext
    // - Headers: metadata JSON with wrapped_key, nonce, etc.
    //
    // WebUI tries to use the raw secret key for AES-GCM decryption
    // instead of first unwrapping the DEK via HPKE!

    let enc_metadata: serde_json::Value = serde_json::from_str(metadata_json)
        .map_err(|e| format!("Failed to parse metadata: {}", e))?;

    // WebUI looks for "ciphertext" field - which doesn't exist in our format!
    if enc_metadata.get("ciphertext").is_none() {
        return Err("WebUI expects 'ciphertext' field in JSON body, but FxFiles stores it in raw body".to_string());
    }

    // Even if it existed, WebUI would try to decrypt with raw secret key
    // instead of HPKE-unwrapped DEK - this is wrong!
    Err("WebUI's decryptEnvelope uses wrong key (raw secret instead of DEK)".to_string())
}

#[test]
fn test_exact_fxfiles_to_webui_flow() {
    println!("\n=== Exact Flow Test: FxFiles Encryption -> WebUI Decryption ===\n");

    // Step 1: Derive key (same on both platforms)
    println!("Step 1: Deriving key with Argon2id...");
    let secret_key_bytes = derive_key_argon2id(TEST_CONTEXT, TEST_INPUT.as_bytes());
    println!("  Context: {}", TEST_CONTEXT);
    println!("  Input: {}", TEST_INPUT);
    println!("  Derived key (hex): {}", hex::encode(&secret_key_bytes));
    println!("");

    // Step 2: Simulate FxFiles encryption
    println!("Step 2: Simulating FxFiles encryption...");
    let (storage_key, ciphertext, metadata_json) = simulate_fxfiles_encryption(
        &secret_key_bytes,
        TEST_PLAINTEXT,
        TEST_FILENAME,
    );
    println!("  Original filename: {}", TEST_FILENAME);
    println!("  Storage key (obfuscated): {}", storage_key);
    println!("  Ciphertext length: {} bytes", ciphertext.len());
    println!("  Metadata JSON:\n{}", serde_json::to_string_pretty(
        &serde_json::from_str::<serde_json::Value>(&metadata_json).unwrap()
    ).unwrap());
    println!("");

    // Step 3: Simulate WebUI WASM decryption (correct path)
    println!("Step 3: Simulating WebUI WASM decryption (correct path)...");
    match simulate_webui_wasm_decryption(&secret_key_bytes, &ciphertext, &metadata_json) {
        Ok(decrypted) => {
            println!("  SUCCESS! Decrypted {} bytes", decrypted.len());
            println!("  Decrypted content: {}", String::from_utf8_lossy(&decrypted));
            assert_eq!(decrypted, TEST_PLAINTEXT, "Decrypted content should match");
            println!("  VERIFIED: Content matches original!");
        }
        Err(e) => {
            println!("  FAILED: {}", e);
            panic!("WASM decryption should succeed");
        }
    }
    println!("");

    // Step 4: Simulate WebUI wrong decryption path
    println!("Step 4: Simulating WebUI's decryptEnvelope() (WRONG path)...");
    match simulate_webui_wrong_decryption(&secret_key_bytes, &ciphertext, &metadata_json) {
        Ok(_) => {
            println!("  Unexpected success - this path should fail!");
        }
        Err(e) => {
            println!("  Expected failure: {}", e);
            println!("  This explains why WebUI can't decrypt FxFiles data!");
        }
    }
    println!("");

    println!("=== Test Complete ===\n");
}

#[test]
fn test_output_test_vector_for_webui() {
    // Generate a test vector that can be used to test WebUI
    let secret_key_bytes = derive_key_argon2id(TEST_CONTEXT, TEST_INPUT.as_bytes());
    let (storage_key, ciphertext, metadata_json) = simulate_fxfiles_encryption(
        &secret_key_bytes,
        TEST_PLAINTEXT,
        TEST_FILENAME,
    );

    let test_vector = serde_json::json!({
        "description": "Test vector simulating FxFiles encrypted file",
        "credentials": {
            "context": TEST_CONTEXT,
            "input": TEST_INPUT,
            "derived_key_hex": hex::encode(&secret_key_bytes),
        },
        "encrypted_file": {
            "bucket": TEST_BUCKET,
            "storage_key": storage_key,
            "original_filename": TEST_FILENAME,
            "ciphertext_base64": base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                &ciphertext
            ),
            "metadata_json": serde_json::from_str::<serde_json::Value>(&metadata_json).unwrap(),
        },
        "expected": {
            "plaintext": String::from_utf8_lossy(TEST_PLAINTEXT),
            "plaintext_base64": base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                TEST_PLAINTEXT
            ),
        },
        "s3_headers": {
            "x-amz-meta-x-fula-encrypted": "true",
            "x-amz-meta-x-fula-encryption": metadata_json,
        }
    });

    println!("\n=== TEST VECTOR FOR WEBUI ===\n");
    println!("{}", serde_json::to_string_pretty(&test_vector).unwrap());
    println!("\n=== END TEST VECTOR ===\n");
}
