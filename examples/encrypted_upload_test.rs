//! Test encrypted upload with pinning
//!
//! Run: cargo run --example encrypted_upload_test
//!
//! Prerequisites:
//! 1. Gateway running: cargo run -p fula-cli -- --no-auth
//! 2. IPFS daemon running: ipfs daemon
//! 3. Optional: Set environment variables for remote pinning:
//!    - PINNING_SERVICE_ENDPOINT (e.g., https://api.pinata.cloud/psa)
//!    - PINNING_SERVICE_TOKEN (your JWT token)
//!
//! Pinning behavior:
//! - All uploads are automatically pinned to local IPFS (built-in)
//! - If pinning credentials are provided, also pins to remote service (Pinata, etc.)

use fula_client::{Config, FulaClient, EncryptedClient, EncryptionConfig, KeyObfuscation};
use std::env;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .init();

    println!("============================================================");
    println!("      Encrypted Upload with IPFS Pinning Test               ");
    println!("============================================================\n");

    // Gateway URL
    let gateway_url = "http://localhost:9000";
    
    // Check for pinning credentials
    let pinning_service = env::var("PINNING_SERVICE_ENDPOINT").ok();
    let pinning_token = env::var("PINNING_SERVICE_TOKEN").ok();
    
    if pinning_service.is_some() && pinning_token.is_some() {
        println!("[PINNING] Remote pinning service configured");
        println!("   Endpoint: {}", pinning_service.as_ref().unwrap());
        println!("   (Token provided)\n");
    } else {
        println!("[PINNING] No remote pinning credentials found");
        println!("   Set PINNING_SERVICE_ENDPOINT and PINNING_SERVICE_TOKEN");
        println!("   to enable remote pinning (e.g., to Pinata)\n");
        println!("   NOTE: Local IPFS pinning is always enabled!\n");
    }

    // ==================== Part 1: Basic Upload with Local IPFS Pinning ====================
    
    println!("=== Part 1: Basic Upload (Auto-pinned to Local IPFS) ===\n");
    
    let client = FulaClient::new(Config::new(gateway_url))?;
    
    // Create bucket
    let bucket = "pinning-test-bucket";
    println!("[BUCKET] Creating bucket: {}", bucket);
    match client.create_bucket(bucket).await {
        Ok(_) => println!("   [OK] Bucket created"),
        Err(e) => println!("   [WARN] {}", e),
    }
    
    // Upload a file (automatically pinned to local IPFS)
    let data = b"Hello from Fula! This is pinned to IPFS.";
    println!("\n[UPLOAD] Uploading file (auto-pinned to local IPFS)...");
    let result = client.put_object(bucket, "hello.txt", data.to_vec()).await?;
    println!("   [OK] Uploaded! ETag: {}", result.etag);
    println!("   [INFO] File is now pinned to your local IPFS node");

    // ==================== Part 2: Upload with Remote Pinning ====================
    
    println!("\n=== Part 2: Upload with Remote Pinning Service ===\n");
    
    if let (Some(service), Some(token)) = (&pinning_service, &pinning_token) {
        let pinned_data = b"This file is pinned to both local IPFS AND remote service!";
        println!("[UPLOAD] Uploading with remote pinning...");
        
        let result = client.put_object_with_pinning(
            bucket,
            "pinned-remotely.txt",
            pinned_data.to_vec(),
            service,
            token,
        ).await?;
        
        println!("   [OK] Uploaded! ETag: {}", result.etag);
        println!("   [OK] Pinned to local IPFS");
        println!("   [OK] Pinned to remote service: {}", service);
        println!("\n   Check your pinning service dashboard to verify!");
    } else {
        println!("[SKIP] Remote pinning skipped (no credentials)");
        println!("   To test remote pinning, run:");
        println!("   $env:PINNING_SERVICE_ENDPOINT=\"https://api.pinata.cloud/psa\"");
        println!("   $env:PINNING_SERVICE_TOKEN=\"your-jwt-token\"");
        println!("   cargo run --example encrypted_upload_test");
    }

    // ==================== Part 3: Encrypted Upload ====================
    
    println!("\n=== Part 3: Encrypted Upload (Maximum Privacy) ===\n");
    
    let config = Config::new(gateway_url);
    let encryption_config = EncryptionConfig::new()
        .with_obfuscation_mode(KeyObfuscation::FlatNamespace);
    
    println!("[ENCRYPTION] Mode: FlatNamespace");
    println!("   - File paths are hidden from server");
    println!("   - Content is encrypted client-side");
    println!("   - Server sees only random CIDs\n");

    let encrypted_client = EncryptedClient::new(config, encryption_config)?;
    
    // Create encrypted bucket
    let enc_bucket = "encrypted-pinning-test";
    match encrypted_client.inner().create_bucket(enc_bucket).await {
        Ok(_) => println!("[BUCKET] Created: {}", enc_bucket),
        Err(e) => println!("[BUCKET] {}", e),
    }

    let secret_data = b"This is encrypted AND pinned to IPFS!";
    let file_path = "secrets/classified.txt";
    
    println!("\n[UPLOAD] Encrypting and uploading...");
    println!("   Original path: {}", file_path);
    println!("   Original size: {} bytes", secret_data.len());
    
    let result = encrypted_client
        .put_object_encrypted(enc_bucket, file_path, secret_data.to_vec())
        .await?;
    
    println!("   [OK] Encrypted and uploaded!");
    println!("   ETag: {}", result.etag);
    println!("   [INFO] Encrypted blob is pinned to local IPFS");

    // Retrieve and decrypt
    println!("\n[DOWNLOAD] Retrieving and decrypting...");
    let decrypted = encrypted_client
        .get_object_decrypted(enc_bucket, file_path)
        .await?;
    
    if decrypted.as_ref() == secret_data {
        println!("   [OK] Decryption successful!");
        println!("   Decrypted: {:?}", String::from_utf8_lossy(&decrypted));
    } else {
        println!("   [ERROR] Decryption failed!");
    }

    // ==================== Summary ====================
    
    println!("\n============================================================");
    println!("                        Summary                             ");
    println!("============================================================");
    println!("");
    println!("Pinning Levels:");
    println!("  1. Local IPFS  - ALWAYS enabled (built into gateway)");
    println!("  2. Remote      - Enabled when credentials provided");
    println!("");
    println!("To verify local pinning:");
    println!("  ipfs pin ls");
    println!("");
    println!("To test remote pinning:");
    println!("  Set PINNING_SERVICE_ENDPOINT and PINNING_SERVICE_TOKEN");
    println!("  then check your service's dashboard");
    println!("");
    println!("[DONE] All tests completed!");
    
    Ok(())
}
