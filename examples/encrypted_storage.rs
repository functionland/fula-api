//! Client-side encryption example
//!
//! This example demonstrates:
//! - Generating encryption keys
//! - Uploading encrypted data
//! - Downloading and decrypting data
//! - Key management
//!
//! Run with: cargo run --example encrypted_storage

use fula_client::{Config, EncryptedClient, EncryptionConfig};
use fula_crypto::keys::SecretKey;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("🔐 Fula Storage - Client-Side Encryption Example\n");

    // ==================== Key Generation ====================
    
    println!("🔑 Generating encryption keys...");
    
    // Generate a new encryption configuration (creates new keys)
    let encryption = EncryptionConfig::new();
    
    // Get the public key for sharing
    let public_key = encryption.public_key();
    println!("   Public Key: {}", public_key.to_base64());
    
    // Export secret key (for backup - handle with care!)
    let secret_key = encryption.export_secret_key();
    let secret_b64 = secret_key.to_base64();
    println!("   Secret Key: {}... (truncated)", &secret_b64[..20]);

    // ==================== Create Encrypted Client ====================
    
    let config = Config::new("http://localhost:9000")
        .with_token("your-jwt-token-here")
        .with_encryption();

    let client = EncryptedClient::new(config, encryption)?;
    
    println!("\n✅ Encrypted client created");

    // ==================== Create Bucket ====================
    
    println!("\n📦 Creating encrypted bucket...");
    match client.create_bucket("encrypted-bucket").await {
        Ok(_) => println!("   ✅ Bucket created"),
        Err(e) => println!("   ⚠️  {}", e),
    }

    // ==================== Upload Encrypted Data ====================
    
    println!("\n📤 Uploading encrypted file...");
    
    let sensitive_data = r#"{
        "api_keys": {
            "production": "sk_live_abc123xyz",
            "staging": "sk_test_def456uvw"
        },
        "database": {
            "host": "db.example.com",
            "password": "super-secret-password"
        }
    }"#;

    client.put_object_encrypted(
        "encrypted-bucket",
        "secrets/api-keys.json",
        sensitive_data.as_bytes().to_vec(),
    ).await?;
    
    println!("   ✅ Data encrypted and uploaded");
    println!("   📝 The data stored on IPFS is encrypted - storage nodes cannot read it!");

    // ==================== Download and Decrypt ====================
    
    println!("\n📥 Downloading and decrypting...");
    
    let decrypted = client.get_object_decrypted(
        "encrypted-bucket",
        "secrets/api-keys.json",
    ).await?;
    
    println!("   ✅ Data decrypted successfully");
    println!("   Content preview: {}...", 
        String::from_utf8_lossy(&decrypted[..50.min(decrypted.len())]));

    // ==================== Key Recovery Demo ====================
    
    println!("\n🔄 Demonstrating key recovery...");
    
    // Simulate recovering with stored secret key
    let recovered_secret = SecretKey::from_base64(&secret_b64)?;
    let recovered_encryption = EncryptionConfig::from_secret_key(recovered_secret);
    
    // Create a new client with recovered keys
    let config2 = Config::new("http://localhost:9000")
        .with_token("your-jwt-token-here");
    let recovered_client = EncryptedClient::new(config2, recovered_encryption)?;
    
    // Decrypt with recovered keys
    let decrypted2 = recovered_client.get_object_decrypted(
        "encrypted-bucket",
        "secrets/api-keys.json",
    ).await?;
    
    println!("   ✅ Successfully decrypted with recovered keys");
    assert_eq!(decrypted, decrypted2);
    println!("   ✅ Data matches original");

    // ==================== Cleanup ====================
    
    println!("\n🧹 Cleaning up...");
    client.delete_object("encrypted-bucket", "secrets/api-keys.json").await?;
    client.delete_bucket("encrypted-bucket").await?;
    println!("   ✅ Cleaned up");

    println!("\n✨ Encryption example completed!");
    println!("\n⚠️  IMPORTANT SECURITY NOTES:");
    println!("   - Never expose your secret key in logs or source code");
    println!("   - Store secret keys securely (hardware security module, secure enclave, etc.)");
    println!("   - If you lose your secret key, encrypted data cannot be recovered");
    println!("   - The gateway never sees your encryption keys - true end-to-end encryption");

    Ok(())
}
