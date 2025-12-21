//! Benchmark: Large File Upload
//!
//! Tests uploading a single large file.
//! Default: 100 MB file
//!
//! Run with: cargo run --example benchmark_large_file --release
//!
//! Configuration:
//!   - BENCHMARK_GATEWAY_URL=http://localhost:9000
//!   - BENCHMARK_LARGE_FILE_MB=100
//!   - PINNING_SERVICE_ENDPOINT (optional)
//!   - PINNING_SERVICE_TOKEN (optional)

use std::env;
use std::time::Instant;

// Include common benchmark utilities
include!("shared/benchmark_common.rs");

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(env::var("RUST_LOG").unwrap_or_else(|_| "warn".to_string()))
        .init();

    let config = BenchmarkConfig::from_env();
    
    if config.large_file_mb == 0 {
        println!("Large file benchmark skipped (BENCHMARK_LARGE_FILE_MB=0)");
        return Ok(());
    }

    let large_size = config.large_file_mb * 1024 * 1024;
    
    println!("{}", "═".repeat(80));
    println!("           BENCHMARK: Large File Upload ({} MB)", config.large_file_mb);
    println!("{}", "═".repeat(80));
    println!();
    println!("Configuration:");
    println!("  ├─ Gateway: {}", config.gateway_url);
    println!("  ├─ File size: {} MB", config.large_file_mb);
    println!("  └─ Remote pinning: {}", if config.has_pinning() { "enabled" } else { "disabled" });
    println!();

    // Create client
    println!("🔧 Creating encrypted client...");
    let client = create_client(&config)?;
    
    let bucket = "bench-large-file";
    match client.inner().create_bucket(bucket).await {
        Ok(_) => println!("   └─ Bucket created: {}", bucket),
        Err(e) => println!("   └─ Bucket: {} ({})", bucket, e),
    }

    // Generate large file
    println!("\n📦 Generating {} MB of random data...", config.large_file_mb);
    let gen_start = Instant::now();
    let large_data = generate_random_data(large_size);
    println!("   └─ Generated in {:?}", gen_start.elapsed());

    // Upload
    let path = "/large_files/big_file.bin";
    println!("\n⬆️  Uploading {} file...", format_bytes(large_size));
    
    let upload_start = Instant::now();
    client.put_object_flat_deferred(bucket, path, large_data.clone(), None).await?;
    client.flush_forest(bucket).await?;
    let upload_time = upload_start.elapsed();
    
    println!("   └─ Upload complete: {:?}", upload_time);

    // Download
    println!("\n⬇️  Downloading & decrypting...");
    let download_start = Instant::now();
    let downloaded = client.get_object_flat(bucket, path).await?;
    let download_time = download_start.elapsed();
    
    // Verify
    if downloaded.len() != large_size {
        println!("   └─ ❌ Size mismatch! Expected {}, got {}", large_size, downloaded.len());
        return Err(anyhow::anyhow!("Downloaded size mismatch"));
    }
    println!("   └─ Download complete: {:?} ({} verified)", download_time, format_bytes(downloaded.len()));

    // Summary
    println!("\n{}", "═".repeat(80));
    println!("                           RESULTS");
    println!("{}", "═".repeat(80));
    println!("  ├─ File size: {}", format_bytes(large_size));
    println!("  ├─ Upload time: {:?}", upload_time);
    println!("  ├─ Download time: {:?}", download_time);
    if upload_time.as_secs_f64() > 0.0 {
        let upload_throughput = large_size as f64 / upload_time.as_secs_f64() / 1024.0 / 1024.0;
        let download_throughput = large_size as f64 / download_time.as_secs_f64() / 1024.0 / 1024.0;
        println!("  ├─ Upload throughput: {:.2} MB/s", upload_throughput);
        println!("  └─ Download throughput: {:.2} MB/s", download_throughput);
    }
    println!("{}", "═".repeat(80));

    Ok(())
}
