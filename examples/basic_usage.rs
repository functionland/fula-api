//! Basic usage example for the Fula S3-compatible storage API
//!
//! This example demonstrates:
//! - Creating a bucket
//! - Uploading objects
//! - Listing objects
//! - Downloading objects
//! - Deleting objects
//!
//! Run with: cargo run --example basic_usage

use fula_client::{FulaClient, Config, ListObjectsOptions};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    println!("🚀 Fula Storage - Basic Usage Example\n");

    // Create client configuration
    let config = Config::new("http://localhost:9000")
        .with_token("your-jwt-token-here"); // Replace with actual token

    // Create the client
    let client = FulaClient::new(config)?;

    // ==================== Bucket Operations ====================
    
    println!("📦 Creating bucket 'my-test-bucket'...");
    match client.create_bucket("my-test-bucket").await {
        Ok(_) => println!("   ✅ Bucket created successfully"),
        Err(e) => println!("   ⚠️  {}", e),
    }

    // List all buckets
    println!("\n📋 Listing all buckets...");
    let buckets = client.list_buckets().await?;
    for bucket in &buckets.buckets {
        println!("   - {} (created: {})", bucket.name, bucket.creation_date);
    }

    // ==================== Object Operations ====================
    
    // Upload a text file
    println!("\n📤 Uploading 'hello.txt'...");
    let result = client.put_object(
        "my-test-bucket",
        "hello.txt",
        b"Hello, World! This is stored on IPFS.".to_vec(),
    ).await?;
    println!("   ✅ Uploaded with ETag: {}", result.etag);

    // Upload a JSON file
    println!("\n📤 Uploading 'data/config.json'...");
    let json_data = serde_json::json!({
        "app": "fula-example",
        "version": "1.0.0",
        "settings": {
            "encryption": true,
            "replication": 3
        }
    });
    client.put_object(
        "my-test-bucket",
        "data/config.json",
        serde_json::to_vec_pretty(&json_data)?,
    ).await?;
    println!("   ✅ JSON file uploaded");

    // Upload more files for listing demo
    for i in 1..=5 {
        client.put_object(
            "my-test-bucket",
            &format!("data/file{}.txt", i),
            format!("Content of file {}", i).into_bytes(),
        ).await?;
    }
    println!("   ✅ Uploaded 5 additional files");

    // List objects with prefix
    println!("\n📋 Listing objects with prefix 'data/'...");
    let list_result = client.list_objects(
        "my-test-bucket",
        Some(ListObjectsOptions {
            prefix: Some("data/".to_string()),
            ..Default::default()
        }),
    ).await?;
    
    for obj in &list_result.objects {
        println!("   - {} ({} bytes)", obj.key, obj.size);
    }

    // List with delimiter to show "folders"
    println!("\n📁 Listing with delimiter '/' to show folders...");
    let list_result = client.list_objects(
        "my-test-bucket",
        Some(ListObjectsOptions {
            delimiter: Some("/".to_string()),
            ..Default::default()
        }),
    ).await?;
    
    println!("   Files:");
    for obj in &list_result.objects {
        println!("   - {}", obj.key);
    }
    println!("   Folders:");
    for prefix in &list_result.common_prefixes {
        println!("   - {}", prefix);
    }

    // Download an object
    println!("\n📥 Downloading 'hello.txt'...");
    let data = client.get_object("my-test-bucket", "hello.txt").await?;
    println!("   Content: {}", String::from_utf8_lossy(&data));

    // Check if object exists
    println!("\n🔍 Checking if 'nonexistent.txt' exists...");
    let exists = client.object_exists("my-test-bucket", "nonexistent.txt").await?;
    println!("   Exists: {}", exists);

    // Copy an object
    println!("\n📋 Copying 'hello.txt' to 'hello-copy.txt'...");
    let copy_result = client.copy_object(
        "my-test-bucket", "hello.txt",
        "my-test-bucket", "hello-copy.txt",
    ).await?;
    println!("   ✅ Copied with ETag: {}", copy_result.etag);

    // Delete an object
    println!("\n🗑️  Deleting 'hello-copy.txt'...");
    client.delete_object("my-test-bucket", "hello-copy.txt").await?;
    println!("   ✅ Deleted");

    // ==================== Cleanup ====================
    
    println!("\n🧹 Cleaning up...");
    
    // Delete all objects in the bucket
    let all_objects = client.list_objects("my-test-bucket", None).await?;
    for obj in all_objects.objects {
        client.delete_object("my-test-bucket", &obj.key).await?;
        println!("   Deleted: {}", obj.key);
    }

    // Delete the bucket
    client.delete_bucket("my-test-bucket").await?;
    println!("   ✅ Bucket deleted");

    println!("\n✨ Example completed successfully!");

    Ok(())
}
