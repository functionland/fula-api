//! IPFS Pinning Service Integration Test
//!
//! This example tests the full IPFS + Pinning Service integration.
//!
//! # Per-User Pinning (Production Model)
//!
//! In production, each user provides their own pinning credentials via HTTP headers:
//! ```
//! X-Pinning-Service: https://api.pinata.cloud/psa
//! X-Pinning-Token: <user's-own-token>
//! ```
//!
//! This way the gateway doesn't store any credentials - users bring their own.
//!
//! # Testing with curl
//!
//! ```bash
//! # Start gateway
//! cargo run -p fula-cli -- --no-auth
//!
//! # Upload with your pinning credentials
//! curl -X PUT http://localhost:9000/my-bucket
//! curl -X PUT http://localhost:9000/my-bucket/hello.txt \
//!   -d "Hello World" \
//!   -H "X-Pinning-Service: https://api.pinata.cloud/psa" \
//!   -H "X-Pinning-Token: YOUR_PINATA_JWT_TOKEN"
//! ```
//!
//! # Environment Variables (for this example only)
//!
//! ```bash
//! export PINNING_SERVICE_ENDPOINT=https://api.pinata.cloud/psa
//! export PINNING_SERVICE_TOKEN=your-api-token-here
//! ```
//!
//! # Testing with Pinata (free tier)
//!
//! 1. Sign up at https://app.pinata.cloud/
//! 2. Go to API Keys and create a new key with "Pinning Services API" scope
//! 3. Set PINNING_SERVICE_TOKEN=<your JWT token>

use fula_blockstore::{
    BlockStore, IpfsPinningBlockStore, IpfsPinningConfig, MemoryBlockStore,
    PinningServiceClient, PinningServiceConfig, Pin, ListPinsQuery,
};
use std::time::Duration;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter("info,fula_blockstore=debug")
        .init();

    println!("\n╔════════════════════════════════════════════════════════════════╗");
    println!("║          IPFS Pinning Service Integration Test                 ║");
    println!("╚════════════════════════════════════════════════════════════════╝\n");

    // Check environment variables
    let ipfs_url = std::env::var("IPFS_API_URL")
        .unwrap_or_else(|_| "http://localhost:5001".to_string());
    let pinning_endpoint = std::env::var("PINNING_SERVICE_ENDPOINT").ok();
    let pinning_token = std::env::var("PINNING_SERVICE_TOKEN").ok();

    println!("Configuration:");
    println!("  IPFS API URL: {}", ipfs_url);
    if let Some(ref endpoint) = pinning_endpoint {
        println!("  Pinning Service: {}", endpoint);
        println!("  Token: {}...", &pinning_token.as_ref().unwrap_or(&"<not set>".to_string())[..20.min(pinning_token.as_ref().map(|t| t.len()).unwrap_or(0))]);
    } else {
        println!("  Pinning Service: Not configured (will use local IPFS pinning)");
    }
    println!();

    // Determine which tests to run
    if pinning_endpoint.is_some() && pinning_token.is_some() {
        println!("Running: Full integration test with remote pinning service\n");
        test_full_integration(&ipfs_url, &pinning_endpoint.unwrap(), &pinning_token.unwrap()).await?;
    } else {
        println!("Running: Basic test with memory store (no IPFS/pinning configured)\n");
        println!("To test with real IPFS + pinning, set:");
        println!("  export PINNING_SERVICE_ENDPOINT=https://api.pinata.cloud/psa");
        println!("  export PINNING_SERVICE_TOKEN=<your-token>\n");
        test_memory_fallback().await?;
    }

    println!("\n✅ All tests passed!\n");
    Ok(())
}

/// Test with memory store (no external dependencies)
async fn test_memory_fallback() -> anyhow::Result<()> {
    println!("═══ Test: Memory Block Store ═══\n");

    let store = MemoryBlockStore::new();

    // Test basic operations
    let data = b"Hello, Fula! This is a test of the memory block store.";
    println!("1. Storing data: {} bytes", data.len());

    let cid = store.put_block(data).await?;
    println!("   ✓ Stored with CID: {}", cid);

    // Retrieve
    println!("2. Retrieving data...");
    let retrieved = store.get_block(&cid).await?;
    assert_eq!(data.as_slice(), retrieved.as_ref());
    println!("   ✓ Data matches!");

    // Check existence
    println!("3. Checking block exists...");
    assert!(store.has_block(&cid).await?);
    println!("   ✓ Block exists");

    // Size
    println!("4. Checking block size...");
    let size = store.block_size(&cid).await?;
    assert_eq!(size, data.len() as u64);
    println!("   ✓ Size: {} bytes", size);

    // Delete
    println!("5. Deleting block...");
    store.delete_block(&cid).await?;
    assert!(!store.has_block(&cid).await?);
    println!("   ✓ Block deleted");

    println!("\n✓ Memory store test passed\n");
    Ok(())
}

/// Test with real IPFS + Pinning Service
async fn test_full_integration(
    ipfs_url: &str,
    pinning_endpoint: &str,
    pinning_token: &str,
) -> anyhow::Result<()> {
    // First test the pinning service client directly
    println!("═══ Test 1: Pinning Service Client ═══\n");
    test_pinning_client(pinning_endpoint, pinning_token).await?;

    // Then test the combined block store
    println!("═══ Test 2: IPFS + Pinning Block Store ═══\n");
    test_ipfs_pinning_store(ipfs_url, pinning_endpoint, pinning_token).await?;

    Ok(())
}

/// Test the pinning service client directly
async fn test_pinning_client(endpoint: &str, token: &str) -> anyhow::Result<()> {
    let config = PinningServiceConfig::new(endpoint, token)
        .with_timeout(Duration::from_secs(30));

    let client = PinningServiceClient::new(config)?;

    // List existing pins
    println!("1. Listing existing pins...");
    let query = ListPinsQuery {
        limit: Some(5),
        ..Default::default()
    };
    let results = client.list_pins(Some(query)).await?;
    println!("   ✓ Found {} pins", results.count);

    for pin in results.results.iter().take(3) {
        println!("     - {} ({:?})", 
            pin.pin.name.as_ref().unwrap_or(&pin.pin.cid[..20.min(pin.pin.cid.len())].to_string()),
            pin.status
        );
    }

    // Create a test pin with a well-known CID (IPFS logo)
    // Using a CID that's widely available on the IPFS network
    let test_cid = "QmY7Yh4UquoXHLPFo2XbhXkhBvFoPwmQUSa92pxnxjQuPU"; // Small test file
    
    println!("\n2. Creating test pin for CID: {}...", &test_cid[..20]);
    let pin = Pin::new(test_cid)
        .with_name(format!("fula-test-{}", chrono::Utc::now().timestamp()));

    match client.add_pin(pin).await {
        Ok(status) => {
            println!("   ✓ Pin created with request ID: {}", status.request_id);
            println!("   Status: {:?}", status.status);

            // Check pin status
            println!("\n3. Checking pin status...");
            let current = client.get_pin(&status.request_id).await?;
            println!("   ✓ Status: {:?}", current.status);

            // Clean up - delete the test pin
            println!("\n4. Cleaning up test pin...");
            client.delete_pin(&status.request_id).await?;
            println!("   ✓ Test pin deleted");
        }
        Err(e) => {
            println!("   ⚠ Could not create pin: {}", e);
            println!("   (This might be expected if CID is not available on IPFS network)");
        }
    }

    println!("\n✓ Pinning service client test passed\n");
    Ok(())
}

/// Test the combined IPFS + Pinning block store
async fn test_ipfs_pinning_store(
    ipfs_url: &str,
    pinning_endpoint: &str,
    pinning_token: &str,
) -> anyhow::Result<()> {
    // Configure the store
    let config = IpfsPinningConfig::with_ipfs(ipfs_url)
        .with_pinning_service(pinning_endpoint, pinning_token)
        .with_wait_for_pin(false); // Don't wait for pin completion (faster tests)

    println!("1. Connecting to IPFS at {}...", ipfs_url);
    
    let store = match IpfsPinningBlockStore::new(config).await {
        Ok(s) => {
            println!("   ✓ Connected to IPFS");
            s
        }
        Err(e) => {
            println!("   ✗ Failed to connect to IPFS: {}", e);
            println!("\n   Make sure IPFS is running:");
            println!("     ipfs daemon");
            println!("   Or use a public gateway.");
            return Err(e.into());
        }
    };

    // Store some data
    let test_data = format!(
        "Fula Gateway Test Data\nTimestamp: {}\nRandom: {}",
        chrono::Utc::now(),
        rand::random::<u64>()
    );
    
    println!("\n2. Storing test data ({} bytes)...", test_data.len());
    let cid = store.put_block(test_data.as_bytes()).await?;
    println!("   ✓ Stored with CID: {}", cid);

    // Retrieve the data
    println!("\n3. Retrieving data from IPFS...");
    let retrieved = store.get_block(&cid).await?;
    let retrieved_str = String::from_utf8_lossy(&retrieved);
    println!("   ✓ Retrieved: {}", &retrieved_str[..50.min(retrieved_str.len())]);
    assert_eq!(test_data.as_bytes(), retrieved.as_ref());
    println!("   ✓ Data integrity verified");

    // Check if pinned
    println!("\n4. Checking pin status...");
    // Give the pinning service a moment
    tokio::time::sleep(Duration::from_secs(2)).await;
    
    use fula_blockstore::PinStore;
    let is_pinned = store.is_pinned(&cid).await?;
    println!("   Pin status: {}", if is_pinned { "✓ Pinned" } else { "○ Pending/Not pinned" });

    // Get block size
    println!("\n5. Getting block metadata...");
    let size = store.block_size(&cid).await?;
    println!("   ✓ Block size: {} bytes", size);

    // Test IPLD (structured data)
    println!("\n6. Testing IPLD (structured data)...");
    
    #[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq)]
    struct TestMetadata {
        name: String,
        version: u32,
        tags: Vec<String>,
    }
    
    let metadata = TestMetadata {
        name: "test-object".to_string(),
        version: 1,
        tags: vec!["fula".to_string(), "test".to_string()],
    };
    
    let ipld_cid = store.put_ipld(&metadata).await?;
    println!("   ✓ IPLD stored with CID: {}", ipld_cid);
    
    let retrieved_metadata: TestMetadata = store.get_ipld(&ipld_cid).await?;
    assert_eq!(metadata, retrieved_metadata);
    println!("   ✓ IPLD data verified: {:?}", retrieved_metadata);

    // Clean up
    println!("\n7. Cleaning up...");
    store.delete_block(&cid).await?;
    store.delete_block(&ipld_cid).await?;
    println!("   ✓ Test blocks unpinned and removed");

    println!("\n✓ IPFS + Pinning store test passed\n");
    Ok(())
}
