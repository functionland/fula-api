//! Multipart upload example for large files
//!
//! This example demonstrates:
//! - Uploading large files using multipart upload
//! - Tracking upload progress
//! - Handling upload failures
//!
//! Run with: cargo run --example multipart_upload

use bytes::Bytes;
use fula_client::{FulaClient, Config, MultipartUpload, UploadProgress, upload_large_file};
use std::sync::Arc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("📦 Fula Storage - Multipart Upload Example\n");

    // Create client
    let config = Config::new("http://localhost:9000")
        .with_token("your-jwt-token-here");
    let client = Arc::new(FulaClient::new(config)?);

    // Create bucket
    println!("📦 Creating bucket...");
    match client.create_bucket("large-files").await {
        Ok(_) => println!("   ✅ Bucket created"),
        Err(e) => println!("   ⚠️  {}", e),
    }

    // ==================== Simple Large File Upload ====================
    
    println!("\n📤 Uploading a large file (simulated 2MB)...");
    
    // Create simulated large data (2MB of random-ish data)
    // Note: Each chunk must be < 1MB for IPFS compatibility
    let large_data: Vec<u8> = (0..2 * 1024 * 1024)
        .map(|i| (i % 256) as u8)
        .collect();
    
    // Upload with progress callback
    let progress_callback = Box::new(|progress: UploadProgress| {
        let percent = progress.percentage();
        let mb_uploaded = progress.bytes_uploaded as f64 / (1024.0 * 1024.0);
        let mb_total = progress.total_bytes as f64 / (1024.0 * 1024.0);
        
        println!(
            "   Progress: {:.1}% ({:.1}/{:.1} MB) - Part {}/{}",
            percent,
            mb_uploaded,
            mb_total,
            progress.current_part,
            progress.total_parts
        );
    });

    let etag = upload_large_file(
        Arc::clone(&client),
        "large-files",
        "big-data.bin",
        Bytes::from(large_data),
        Some(progress_callback),
    ).await?;
    
    println!("   ✅ Upload complete! ETag: {}", etag);

    // ==================== Manual Multipart Upload ====================
    
    println!("\n📤 Manual multipart upload (with resume capability)...");
    
    // Start upload
    let mut upload = MultipartUpload::start(
        Arc::clone(&client),
        "large-files",
        "chunked-file.bin",
    ).await?;
    
    println!("   Upload ID: {}", upload.upload_id());
    
    // Upload parts manually (could be done in parallel)
    // Note: chunks must be < 1MB for IPFS compatibility
    let chunk_size = 256 * 1024; // 256KB chunks (IPFS compatible)
    let num_parts = 3;
    
    for part_num in 1..=num_parts {
        let chunk_data: Vec<u8> = (0..chunk_size)
            .map(|i| ((i + part_num as usize * chunk_size) % 256) as u8)
            .collect();
        
        println!("   Uploading part {}...", part_num);
        upload.upload_part(part_num as u32, Bytes::from(chunk_data)).await?;
        println!("   ✅ Part {} uploaded", part_num);
        
        // Simulate potential interruption point
        // In a real app, you'd save upload.upload_id() to resume later
    }
    
    // Complete the upload
    let final_etag = upload.complete().await?;
    println!("   ✅ Multipart upload complete! ETag: {}", final_etag);

    // ==================== Verify Upload ====================
    
    println!("\n🔍 Verifying uploaded files...");
    
    let objects = client.list_objects("large-files", None).await?;
    for obj in &objects.objects {
        let size_mb = obj.size as f64 / (1024.0 * 1024.0);
        println!("   - {} ({:.1} MB)", obj.key, size_mb);
    }

    // ==================== Cleanup ====================
    
    println!("\n🧹 Cleaning up...");
    for obj in objects.objects {
        client.delete_object("large-files", &obj.key).await?;
    }
    client.delete_bucket("large-files").await?;
    println!("   ✅ Cleaned up");

    println!("\n✨ Multipart upload example completed!");
    println!("\n💡 Tips for production:");
    println!("   - Save upload_id to resume interrupted uploads");
    println!("   - Use parallel part uploads for better performance");
    println!("   - Implement exponential backoff for retries");
    println!("   - Consider chunk sizes based on network conditions");

    Ok(())
}
