//! Benchmark: Deep Nested Structure
//!
//! Tests creating deeply nested folder structure.
//! Default: 10 levels deep with 10 files at the bottom
//!
//! Run with: cargo run --example benchmark_deep_structure --release
//!
//! Configuration:
//!   - BENCHMARK_GATEWAY_URL=http://localhost:9000
//!   - BENCHMARK_DEEP_LEVELS=10
//!   - BENCHMARK_FILES_AT_BOTTOM=10
//!   - PINNING_SERVICE_ENDPOINT (optional)
//!   - PINNING_SERVICE_TOKEN (optional)

use std::env;
use std::time::Instant;

// Include common benchmark utilities
include!("benchmark_common.rs");

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(env::var("RUST_LOG").unwrap_or_else(|_| "warn".to_string()))
        .init();

    let config = BenchmarkConfig::from_env();
    
    println!("{}", "═".repeat(80));
    println!("        BENCHMARK: Deep Nested Structure ({} levels)", config.deep_levels);
    println!("{}", "═".repeat(80));
    println!();
    println!("Configuration:");
    println!("  ├─ Gateway: {}", config.gateway_url);
    println!("  ├─ Depth: {} levels", config.deep_levels);
    println!("  ├─ Files at bottom: {}", config.files_at_bottom);
    println!("  └─ Remote pinning: {}", if config.has_pinning() { "enabled" } else { "disabled" });
    println!();

    // Create client
    println!("🔧 Creating encrypted client...");
    let client = create_client(&config)?;
    
    let bucket = "bench-deep-structure";
    match client.inner().create_bucket(bucket).await {
        Ok(_) => println!("   └─ Bucket created: {}", bucket),
        Err(e) => println!("   └─ Bucket: {} ({})", bucket, e),
    }

    // Build deep path
    let mut deep_path = String::from("/deep");
    for level in 0..config.deep_levels {
        deep_path.push_str(&format!("/level_{}", level));
    }
    
    println!("\n🌲 Creating {}-level deep structure...", config.deep_levels);
    println!("   Path: {}...", &deep_path[..50.min(deep_path.len())]);

    // Upload files at the bottom
    let start = Instant::now();
    let mut paths: Vec<String> = Vec::new();
    
    for file_idx in 0..config.files_at_bottom {
        let file_path = format!("{}/file_{}.txt", deep_path, file_idx);
        let content = format!("Deep file {} at level {}", file_idx, config.deep_levels);
        
        client.put_object_flat_deferred(bucket, &file_path, content.into_bytes(), None).await?;
        paths.push(file_path);
    }
    
    client.flush_forest(bucket).await?;
    let upload_time = start.elapsed();
    
    println!("   └─ Created {} files in {:?}", paths.len(), upload_time);

    // List the deep directory
    println!("\n📋 Listing deep directory...");
    let list_start = Instant::now();
    let listing = client.list_directory(bucket, Some(&deep_path)).await?;
    let list_time = list_start.elapsed();
    
    let files_count: usize = listing.directories.values().map(|v| v.len()).sum();
    println!("   └─ Listed {} entries in {:?}", files_count, list_time);

    // Download a file
    println!("\n📥 Downloading a file from deep path...");
    let download_start = Instant::now();
    let data = client.get_object_flat(bucket, &paths[0]).await?;
    let download_time = download_start.elapsed();
    println!("   └─ Downloaded {} bytes in {:?}", data.len(), download_time);

    // Summary
    println!("\n{}", "═".repeat(80));
    println!("                           RESULTS");
    println!("{}", "═".repeat(80));
    println!("  ├─ Depth: {} levels", config.deep_levels);
    println!("  ├─ Files created: {}", paths.len());
    println!("  ├─ Upload time: {:?}", upload_time);
    println!("  ├─ List time: {:?}", list_time);
    println!("  └─ Download time: {:?}", download_time);
    println!("{}", "═".repeat(80));

    Ok(())
}
