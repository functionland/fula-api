//! Benchmark: Parallel File Uploads
//!
//! Tests uploading multiple files in parallel using concurrent tasks.
//! Default: 100 files with concurrency of 10
//!
//! Run with: cargo run --example benchmark_parallel --release
//!
//! Configuration:
//!   - BENCHMARK_GATEWAY_URL=http://localhost:9000
//!   - BENCHMARK_PARALLEL_FILES=100
//!   - BENCHMARK_PARALLEL_CONCURRENCY=10
//!   - PINNING_SERVICE_ENDPOINT (optional)
//!   - PINNING_SERVICE_TOKEN (optional)

use std::env;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;
use tokio::sync::Semaphore;

// Include common benchmark utilities
include!("benchmark_common.rs");

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(env::var("RUST_LOG").unwrap_or_else(|_| "warn".to_string()))
        .init();

    let config = BenchmarkConfig::from_env();
    
    println!("{}", "═".repeat(80));
    println!("          BENCHMARK: Parallel File Uploads");
    println!("{}", "═".repeat(80));
    println!();
    println!("Configuration:");
    println!("  ├─ Gateway: {}", config.gateway_url);
    println!("  ├─ Total files: {}", config.parallel_files);
    println!("  ├─ Concurrency: {}", config.parallel_concurrency);
    println!("  └─ Remote pinning: {}", if config.has_pinning() { "enabled" } else { "disabled" });
    println!();

    // Create client (wrapped in Arc for sharing across tasks)
    println!("🔧 Creating encrypted client...");
    let client = Arc::new(create_client(&config)?);
    
    let bucket = "bench-parallel";
    match client.inner().create_bucket(bucket).await {
        Ok(_) => println!("   └─ Bucket created: {}", bucket),
        Err(e) => println!("   └─ Bucket: {} ({})", bucket, e),
    }

    // Prepare file data
    println!("\n📦 Preparing {} files...", config.parallel_files);
    let prep_start = Instant::now();
    
    let files: Vec<(String, Vec<u8>)> = (0..config.parallel_files)
        .map(|i| {
            let size = generate_small_file_size(i);
            let data = generate_random_data(size);
            let path = format!("/parallel/file_{:04}.bin", i);
            (path, data)
        })
        .collect();
    
    let total_bytes: usize = files.iter().map(|(_, d)| d.len()).sum();
    println!("   └─ Prepared {} files ({}) in {:?}", 
        files.len(), format_bytes(total_bytes), prep_start.elapsed());

    // Parallel upload using semaphore for concurrency control
    println!("\n⬆️  Uploading {} files with concurrency {}...", 
        config.parallel_files, config.parallel_concurrency);
    
    let uploaded = Arc::new(AtomicUsize::new(0));
    let errors = Arc::new(AtomicUsize::new(0));
    let semaphore = Arc::new(Semaphore::new(config.parallel_concurrency));
    let upload_start = Instant::now();

    // Spawn all upload tasks
    let mut handles = Vec::new();
    let successful_paths = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    
    for (i, (path, data)) in files.into_iter().enumerate() {
        let client = Arc::clone(&client);
        let uploaded = Arc::clone(&uploaded);
        let errors = Arc::clone(&errors);
        let semaphore = Arc::clone(&semaphore);
        let successful_paths = Arc::clone(&successful_paths);
        
        let handle = tokio::spawn(async move {
            // Acquire semaphore permit to limit concurrency
            let _permit = semaphore.acquire().await.unwrap();
            
            match client.put_object_flat(bucket, &path, data, None).await {
                Ok(_) => {
                    let count = uploaded.fetch_add(1, Ordering::Relaxed) + 1;
                    if count % 10 == 0 {
                        eprint!(".");
                    }
                    successful_paths.lock().await.push(path);
                }
                Err(e) => {
                    errors.fetch_add(1, Ordering::Relaxed);
                    eprintln!("\nFile {}: {}", i, e);
                }
            }
        });
        handles.push(handle);
    }
    
    // Wait for all uploads to complete
    for handle in handles {
        let _ = handle.await;
    }
    
    eprintln!(); // New line after progress dots
    
    let upload_time = upload_start.elapsed();
    let successful = uploaded.load(Ordering::Relaxed);
    let failed = errors.load(Ordering::Relaxed);

    println!("   ├─ Uploaded: {}/{} files", successful, config.parallel_files);
    if failed > 0 {
        println!("   ├─ Failed: {} files", failed);
    }
    println!("   └─ Time: {:?}", upload_time);

    // Parallel download (sample)
    let paths = successful_paths.lock().await.clone();
    let sample_size = (paths.len() / 10).max(10).min(paths.len());
    let sample_paths: Vec<String> = paths.into_iter().take(sample_size).collect();

    if !sample_paths.is_empty() {
        println!("\n⬇️  Downloading {} sample files in parallel...", sample_paths.len());
        
        let download_start = Instant::now();
        let downloaded = Arc::new(AtomicUsize::new(0));

        let mut download_handles = Vec::new();
        for path in sample_paths {
            let client = Arc::clone(&client);
            let downloaded = Arc::clone(&downloaded);
            let semaphore = Arc::clone(&semaphore);
            
            let handle = tokio::spawn(async move {
                let _permit = semaphore.acquire().await.unwrap();
                
                match client.get_object_flat(bucket, &path).await {
                    Ok(_) => {
                        let count = downloaded.fetch_add(1, Ordering::Relaxed) + 1;
                        if count % 10 == 0 {
                            eprint!(".");
                        }
                    }
                    Err(e) => {
                        eprintln!("\nDownload error: {}", e);
                    }
                }
            });
            download_handles.push(handle);
        }
        
        for handle in download_handles {
            let _ = handle.await;
        }
        
        eprintln!(); // New line
        
        let download_time = download_start.elapsed();
        println!("   └─ Downloaded {} files in {:?}", downloaded.load(Ordering::Relaxed), download_time);
    }

    // Summary
    println!("\n{}", "═".repeat(80));
    println!("                           RESULTS");
    println!("{}", "═".repeat(80));
    println!("  ├─ Files uploaded: {}/{}", successful, config.parallel_files);
    println!("  ├─ Total data: {}", format_bytes(total_bytes));
    println!("  ├─ Concurrency: {}", config.parallel_concurrency);
    println!("  ├─ Upload time: {:?}", upload_time);
    
    if upload_time.as_secs_f64() > 0.0 && successful > 0 {
        let throughput = total_bytes as f64 / upload_time.as_secs_f64() / 1024.0 / 1024.0;
        let files_per_sec = successful as f64 / upload_time.as_secs_f64();
        println!("  ├─ Upload throughput: {:.2} MB/s", throughput);
        println!("  └─ Files/second: {:.2}", files_per_sec);
    }
    println!("{}", "═".repeat(80));

    // Compare with sequential
    if upload_time.as_secs_f64() > 0.0 {
        println!("\n📊 COMPARISON: Parallel vs Sequential");
        println!("   Parallel uploads completed {} files in {:?}", successful, upload_time);
        println!("   That's {:.1}x faster than sequential at ~1 file/sec", 
            successful as f64 / upload_time.as_secs_f64());
    }

    Ok(())
}
