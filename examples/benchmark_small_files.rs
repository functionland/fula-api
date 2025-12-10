//! Benchmark: Small Files (Sequential)
//!
//! Tests uploading many small files in sequence.
//! Default: 20 folders × 100 files each (2000 files total)
//!
//! Run with: cargo run --example benchmark_small_files --release
//!
//! Configuration:
//!   - BENCHMARK_GATEWAY_URL=http://localhost:9000
//!   - BENCHMARK_SMALL_FOLDERS=20
//!   - BENCHMARK_FILES_PER_FOLDER=100
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
    println!("        BENCHMARK: Small Files (Sequential Upload)");
    println!("{}", "═".repeat(80));
    println!();
    println!("Configuration:");
    println!("  ├─ Gateway: {}", config.gateway_url);
    println!("  ├─ Folders: {}", config.small_folders);
    println!("  ├─ Files per folder: {}", config.files_per_folder);
    println!("  └─ Remote pinning: {}", if config.has_pinning() { "enabled" } else { "disabled" });
    println!();

    // Create client
    println!("🔧 Creating encrypted client...");
    let client = create_client(&config)?;
    
    let bucket = "bench-small-files";
    match client.inner().create_bucket(bucket).await {
        Ok(_) => println!("   └─ Bucket created: {}", bucket),
        Err(e) => println!("   └─ Bucket: {} ({})", bucket, e),
    }

    // Upload small files
    println!("\n📁 Uploading {} folders × {} files each...", 
        config.small_folders, config.files_per_folder);

    let mut paths: Vec<String> = Vec::new();
    let mut total_bytes = 0usize;
    let start = Instant::now();

    for folder_idx in 0..config.small_folders {
        let folder_name = format!("folder_{:02}", folder_idx);
        print!("   Folder {}/{}: ", folder_idx + 1, config.small_folders);
        
        for file_idx in 0..config.files_per_folder {
            let file_size = generate_small_file_size(file_idx);
            let data = generate_random_data(file_size);
            let path = format!("/{}/file_{:03}.bin", folder_name, file_idx);
            
            client.put_object_flat_deferred(bucket, &path, data, None).await?;
            
            paths.push(path);
            total_bytes += file_size;
        }
        
        // Flush once per folder
        client.flush_forest(bucket).await?;
        println!("✓ ({} files)", config.files_per_folder);
    }

    let upload_time = start.elapsed();
    println!("\n   └─ Upload complete: {} files, {} in {:?}",
        paths.len(), format_bytes(total_bytes), upload_time);

    // List directories
    println!("\n📋 Listing all directories...");
    let list_start = Instant::now();
    let listing = client.list_directory(bucket, None).await?;
    let list_time = list_start.elapsed();
    println!("   └─ Listed {} directories in {:?}", listing.directories.len(), list_time);

    // Download sample
    println!("\n📥 Downloading & decrypting sample files...");
    let sample_count = (paths.len() / 10).max(10).min(paths.len());
    let download_start = Instant::now();
    
    for (i, path) in paths.iter().take(sample_count).enumerate() {
        let _data = client.get_object_flat(bucket, path).await?;
        if i % 10 == 0 { print!("."); }
    }
    println!();
    
    let download_time = download_start.elapsed();
    println!("   └─ Downloaded {} files in {:?}", sample_count, download_time);

    // Summary
    println!("\n{}", "═".repeat(80));
    println!("                           RESULTS");
    println!("{}", "═".repeat(80));
    println!("  ├─ Files uploaded: {}", paths.len());
    println!("  ├─ Total data: {}", format_bytes(total_bytes));
    println!("  ├─ Upload time: {:?}", upload_time);
    println!("  ├─ Download time (sample): {:?}", download_time);
    println!("  ├─ List time: {:?}", list_time);
    if upload_time.as_secs_f64() > 0.0 {
        let throughput = total_bytes as f64 / upload_time.as_secs_f64() / 1024.0 / 1024.0;
        let files_per_sec = paths.len() as f64 / upload_time.as_secs_f64();
        println!("  ├─ Upload throughput: {:.2} MB/s", throughput);
        println!("  └─ Files/second: {:.2}", files_per_sec);
    }
    println!("{}", "═".repeat(80));

    Ok(())
}
