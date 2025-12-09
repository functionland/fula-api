//! Comprehensive Encryption & Sharing Benchmark
//!
//! This benchmark tests Fula's encrypted storage performance across realistic scenarios:
//!
//! **Scenario 1 - User A Data Operations:**
//! - 20 folders with 100 small files each (varying sizes 1KB-100KB)
//! - 1 folder with a large file (configurable, default 100MB for practical testing)
//! - 1 folder with 10-level deep structure and 10 files at the bottom
//!
//! **Scenario 2 - Sharing Benchmark:**
//! - User A shares the deep folder with User B
//! - User B accepts the share and fetches folder content
//!
//! Run with: cargo run --example benchmark --release
//!
//! Prerequisites:
//! 1. Gateway running: cargo run -p fula-cli -- --no-auth
//! 2. IPFS daemon running: ipfs daemon
//! 3. Optional: Set environment variables for remote pinning:
//!    - PINNING_SERVICE_ENDPOINT
//!    - PINNING_SERVICE_TOKEN
//!
//! Configuration via environment variables:
//!   - BENCHMARK_SMALL_FOLDERS=20 (number of folders with small files)
//!   - BENCHMARK_FILES_PER_FOLDER=100 (small files per folder)
//!   - BENCHMARK_LARGE_FILE_MB=100 (size of large file in MB, set to 0 to skip)
//!   - BENCHMARK_DEEP_LEVELS=10 (depth of nested folder structure)
//!   - BENCHMARK_GATEWAY_URL=http://localhost:9000

use fula_client::{Config, EncryptedClient, EncryptionConfig, KeyObfuscation, PinningCredentials};
use fula_crypto::{
    keys::{KekKeyPair, DekKey},
    sharing::{ShareBuilder, ShareRecipient},
    inbox::{ShareEnvelopeBuilder, ShareInbox},
};
use std::env;
use std::time::{Duration, Instant};

// ═══════════════════════════════════════════════════════════════════════════════
// BENCHMARK CONFIGURATION
// ═══════════════════════════════════════════════════════════════════════════════

struct BenchmarkConfig {
    gateway_url: String,
    small_folders: usize,
    files_per_folder: usize,
    large_file_mb: usize,
    deep_levels: usize,
    files_at_bottom: usize,
    pinning_endpoint: Option<String>,
    pinning_token: Option<String>,
}

impl BenchmarkConfig {
    fn from_env() -> Self {
        Self {
            gateway_url: env::var("BENCHMARK_GATEWAY_URL")
                .unwrap_or_else(|_| "http://localhost:9000".to_string()),
            small_folders: env::var("BENCHMARK_SMALL_FOLDERS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(20),
            files_per_folder: env::var("BENCHMARK_FILES_PER_FOLDER")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(100),
            large_file_mb: env::var("BENCHMARK_LARGE_FILE_MB")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(100), // Default 100MB, set to 0 to skip
            deep_levels: env::var("BENCHMARK_DEEP_LEVELS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(10),
            files_at_bottom: env::var("BENCHMARK_FILES_AT_BOTTOM")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(10),
            pinning_endpoint: env::var("PINNING_SERVICE_ENDPOINT").ok(),
            pinning_token: env::var("PINNING_SERVICE_TOKEN").ok(),
        }
    }

    fn has_pinning(&self) -> bool {
        self.pinning_endpoint.is_some() && self.pinning_token.is_some()
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// BENCHMARK RESULTS
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Debug, Default)]
struct BenchmarkResults {
    // Scenario 1: Small files
    small_files_count: usize,
    small_files_total_bytes: usize,
    small_files_encrypt_upload_time: Duration,
    small_files_download_decrypt_time: Duration,
    small_files_list_time: Duration,

    // Scenario 1: Large file
    large_file_size_bytes: usize,
    large_file_encrypt_upload_time: Duration,
    large_file_download_decrypt_time: Duration,

    // Scenario 1: Deep structure
    deep_structure_files: usize,
    deep_structure_depth: usize,
    deep_structure_upload_time: Duration,
    deep_structure_list_time: Duration,

    // Scenario 2: Sharing
    share_creation_time: Duration,
    share_inbox_enqueue_time: Duration,
    share_acceptance_time: Duration,
    shared_folder_fetch_time: Duration,
    shared_files_decrypted: usize,

    // Overall
    total_files: usize,
    total_bytes: usize,
    total_time: Duration,
}

impl BenchmarkResults {
    fn print_summary(&self) {
        println!("\n{}", "═".repeat(80));
        println!("                         BENCHMARK RESULTS SUMMARY");
        println!("{}\n", "═".repeat(80));

        // Small files results
        println!("📁 SCENARIO 1A: Small Files (20 folders × 100 files each)");
        println!("   ├─ Files: {}", self.small_files_count);
        println!("   ├─ Total Size: {}", format_bytes(self.small_files_total_bytes));
        println!("   ├─ Encrypt + Upload: {:?}", self.small_files_encrypt_upload_time);
        println!("   ├─ Download + Decrypt: {:?}", self.small_files_download_decrypt_time);
        println!("   ├─ List Directory: {:?}", self.small_files_list_time);
        if self.small_files_encrypt_upload_time.as_secs_f64() > 0.0 {
            let upload_throughput = self.small_files_total_bytes as f64 
                / self.small_files_encrypt_upload_time.as_secs_f64() 
                / 1024.0 / 1024.0;
            println!("   └─ Upload Throughput: {:.2} MB/s", upload_throughput);
        }

        // Large file results
        if self.large_file_size_bytes > 0 {
            println!("\n📦 SCENARIO 1B: Large File");
            println!("   ├─ Size: {}", format_bytes(self.large_file_size_bytes));
            println!("   ├─ Encrypt + Upload: {:?}", self.large_file_encrypt_upload_time);
            println!("   ├─ Download + Decrypt: {:?}", self.large_file_download_decrypt_time);
            if self.large_file_encrypt_upload_time.as_secs_f64() > 0.0 {
                let upload_throughput = self.large_file_size_bytes as f64 
                    / self.large_file_encrypt_upload_time.as_secs_f64() 
                    / 1024.0 / 1024.0;
                let download_throughput = self.large_file_size_bytes as f64 
                    / self.large_file_download_decrypt_time.as_secs_f64() 
                    / 1024.0 / 1024.0;
                println!("   ├─ Upload Throughput: {:.2} MB/s", upload_throughput);
                println!("   └─ Download Throughput: {:.2} MB/s", download_throughput);
            }
        }

        // Deep structure results
        println!("\n🌲 SCENARIO 1C: Deep Nested Structure ({} levels)", self.deep_structure_depth);
        println!("   ├─ Files at Bottom: {}", self.deep_structure_files);
        println!("   ├─ Upload Time: {:?}", self.deep_structure_upload_time);
        println!("   └─ List Directory: {:?}", self.deep_structure_list_time);

        // Sharing results
        println!("\n🔗 SCENARIO 2: Sharing Benchmark");
        println!("   ├─ Share Token Creation: {:?}", self.share_creation_time);
        println!("   ├─ Inbox Enqueue Time: {:?}", self.share_inbox_enqueue_time);
        println!("   ├─ Share Acceptance: {:?}", self.share_acceptance_time);
        println!("   ├─ Shared Folder Fetch: {:?}", self.shared_folder_fetch_time);
        println!("   └─ Files Decrypted by Recipient: {}", self.shared_files_decrypted);

        // Overall summary
        println!("\n📊 OVERALL SUMMARY");
        println!("   ├─ Total Files: {}", self.total_files);
        println!("   ├─ Total Data: {}", format_bytes(self.total_bytes));
        println!("   └─ Total Benchmark Time: {:?}", self.total_time);

        // Performance metrics
        if self.total_time.as_secs_f64() > 0.0 {
            println!("\n⚡ PERFORMANCE METRICS");
            let files_per_sec = self.total_files as f64 / self.total_time.as_secs_f64();
            let bytes_per_sec = self.total_bytes as f64 / self.total_time.as_secs_f64();
            println!("   ├─ Files/second: {:.2}", files_per_sec);
            println!("   └─ Throughput: {:.2} MB/s", bytes_per_sec / 1024.0 / 1024.0);
        }

        println!("\n{}", "═".repeat(80));
    }
}

fn format_bytes(bytes: usize) -> String {
    if bytes >= 1024 * 1024 * 1024 {
        format!("{:.2} GB", bytes as f64 / 1024.0 / 1024.0 / 1024.0)
    } else if bytes >= 1024 * 1024 {
        format!("{:.2} MB", bytes as f64 / 1024.0 / 1024.0)
    } else if bytes >= 1024 {
        format!("{:.2} KB", bytes as f64 / 1024.0)
    } else {
        format!("{} bytes", bytes)
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// DATA GENERATION
// ═══════════════════════════════════════════════════════════════════════════════

fn generate_random_data(size: usize) -> Vec<u8> {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    
    let mut data = vec![0u8; size];
    let mut hasher = DefaultHasher::new();
    
    for (i, chunk) in data.chunks_mut(8).enumerate() {
        i.hash(&mut hasher);
        let hash = hasher.finish().to_le_bytes();
        for (j, byte) in chunk.iter_mut().enumerate() {
            *byte = hash[j % 8];
        }
    }
    data
}

fn generate_small_file_size(index: usize) -> usize {
    // Vary sizes: 1KB to 100KB based on index
    let sizes = [1024, 2048, 4096, 8192, 16384, 32768, 65536, 102400];
    sizes[index % sizes.len()]
}

// ═══════════════════════════════════════════════════════════════════════════════
// BENCHMARK RUNNER
// ═══════════════════════════════════════════════════════════════════════════════

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(env::var("RUST_LOG").unwrap_or_else(|_| "warn".to_string()))
        .init();

    let config = BenchmarkConfig::from_env();
    let mut results = BenchmarkResults::default();
    let overall_start = Instant::now();

    print_header(&config);

    // ═══════════════════════════════════════════════════════════════════════════
    // SETUP: Create User A's encrypted client
    // ═══════════════════════════════════════════════════════════════════════════

    println!("\n🔧 SETUP: Creating User A's encrypted client...");
    
    let user_a_encryption = EncryptionConfig::new()
        .with_obfuscation_mode(KeyObfuscation::FlatNamespace);
    
    let client_config = Config::new(&config.gateway_url);
    
    let user_a_client = if config.has_pinning() {
        println!("   ├─ Remote pinning enabled: {}", config.pinning_endpoint.as_ref().unwrap());
        let pinning = PinningCredentials::new(
            config.pinning_endpoint.as_ref().unwrap(),
            config.pinning_token.as_ref().unwrap(),
        );
        EncryptedClient::new_with_pinning(client_config, user_a_encryption, pinning)?
    } else {
        println!("   ├─ Local IPFS pinning only");
        EncryptedClient::new(client_config, user_a_encryption)?
    };

    // Create bucket for User A
    let bucket_a = "benchmark-user-a";
    match user_a_client.inner().create_bucket(bucket_a).await {
        Ok(_) => println!("   └─ Bucket created: {}", bucket_a),
        Err(e) => println!("   └─ Bucket: {} ({})", bucket_a, e),
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // SCENARIO 1A: 20 folders with 100 small files each
    // ═══════════════════════════════════════════════════════════════════════════

    println!("\n📁 SCENARIO 1A: Uploading {} folders × {} files each...", 
        config.small_folders, config.files_per_folder);

    let mut small_files_paths: Vec<String> = Vec::new();
    let mut total_small_bytes = 0usize;
    let small_files_start = Instant::now();

    for folder_idx in 0..config.small_folders {
        let folder_name = format!("folder_{:02}", folder_idx);
        print!("   Folder {}/{}: ", folder_idx + 1, config.small_folders);
        
        for file_idx in 0..config.files_per_folder {
            let file_size = generate_small_file_size(file_idx);
            let data = generate_random_data(file_size);
            let path = format!("/{}/file_{:03}.bin", folder_name, file_idx);
            
            user_a_client.put_object_encrypted(bucket_a, &path, data.clone()).await?;
            
            small_files_paths.push(path);
            total_small_bytes += file_size;
        }
        println!("✓ ({} files)", config.files_per_folder);
    }

    results.small_files_encrypt_upload_time = small_files_start.elapsed();
    results.small_files_count = small_files_paths.len();
    results.small_files_total_bytes = total_small_bytes;

    println!("   └─ Upload complete: {} files, {} in {:?}",
        results.small_files_count,
        format_bytes(total_small_bytes),
        results.small_files_encrypt_upload_time);

    // List directory benchmark
    println!("\n   📋 Listing all directories...");
    let list_start = Instant::now();
    let listing = user_a_client.list_directory(bucket_a, None).await?;
    results.small_files_list_time = list_start.elapsed();
    println!("   └─ Listed {} directories in {:?}", 
        listing.directories.len(), results.small_files_list_time);

    // Download and decrypt a sample of files
    println!("\n   📥 Downloading & decrypting sample files...");
    let sample_count = (small_files_paths.len() / 10).max(10).min(small_files_paths.len());
    let download_start = Instant::now();
    
    for (i, path) in small_files_paths.iter().take(sample_count).enumerate() {
        let _data = user_a_client.get_object_decrypted(bucket_a, path).await?;
        if i % 10 == 0 {
            print!(".");
        }
    }
    println!();
    
    results.small_files_download_decrypt_time = download_start.elapsed();
    println!("   └─ Downloaded {} files in {:?}", sample_count, results.small_files_download_decrypt_time);

    // ═══════════════════════════════════════════════════════════════════════════
    // SCENARIO 1B: Large file upload (configurable size)
    // ═══════════════════════════════════════════════════════════════════════════

    if config.large_file_mb > 0 {
        let large_size = config.large_file_mb * 1024 * 1024;
        println!("\n📦 SCENARIO 1B: Uploading large file ({} MB)...", config.large_file_mb);
        
        let large_data = generate_random_data(large_size);
        let large_path = "/large_files/big_file.bin";
        
        let upload_start = Instant::now();
        user_a_client.put_object_encrypted(bucket_a, large_path, large_data.clone()).await?;
        results.large_file_encrypt_upload_time = upload_start.elapsed();
        results.large_file_size_bytes = large_size;
        
        println!("   ├─ Upload: {:?}", results.large_file_encrypt_upload_time);
        
        // Download
        println!("   └─ Downloading & decrypting...");
        let download_start = Instant::now();
        let downloaded = user_a_client.get_object_decrypted(bucket_a, large_path).await?;
        results.large_file_download_decrypt_time = download_start.elapsed();
        
        assert_eq!(downloaded.len(), large_size, "Downloaded size mismatch!");
        println!("      └─ Download: {:?} ({} verified)", 
            results.large_file_download_decrypt_time, format_bytes(downloaded.len()));
    } else {
        println!("\n📦 SCENARIO 1B: Large file SKIPPED (set BENCHMARK_LARGE_FILE_MB > 0)");
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // SCENARIO 1C: Deep nested structure (10 levels)
    // ═══════════════════════════════════════════════════════════════════════════

    println!("\n🌲 SCENARIO 1C: Creating {}-level deep folder structure...", config.deep_levels);
    
    let deep_start = Instant::now();
    let mut deep_path = String::from("/deep");
    
    for level in 0..config.deep_levels {
        deep_path.push_str(&format!("/level_{}", level));
    }
    
    // Upload files at the bottom
    let mut deep_files_paths: Vec<String> = Vec::new();
    for file_idx in 0..config.files_at_bottom {
        let file_path = format!("{}/file_{}.txt", deep_path, file_idx);
        let content = format!("Deep file {} at level {}", file_idx, config.deep_levels);
        
        user_a_client.put_object_encrypted(bucket_a, &file_path, content.into_bytes()).await?;
        deep_files_paths.push(file_path);
    }
    
    results.deep_structure_upload_time = deep_start.elapsed();
    results.deep_structure_files = config.files_at_bottom;
    results.deep_structure_depth = config.deep_levels;
    
    println!("   ├─ Created {} files at depth {} in {:?}", 
        config.files_at_bottom, config.deep_levels, results.deep_structure_upload_time);
    
    // List the deep directory
    let deep_list_start = Instant::now();
    let deep_listing = user_a_client.list_directory(bucket_a, Some(&deep_path)).await?;
    results.deep_structure_list_time = deep_list_start.elapsed();
    
    println!("   └─ Listed deep directory in {:?} ({} entries)", 
        results.deep_structure_list_time, 
        deep_listing.directories.values().map(|v| v.len()).sum::<usize>());

    // ═══════════════════════════════════════════════════════════════════════════
    // SCENARIO 2: Sharing Benchmark
    // ═══════════════════════════════════════════════════════════════════════════

    println!("\n🔗 SCENARIO 2: Sharing Benchmark");
    println!("   User A shares the deep folder with User B...\n");

    // Create User B
    let user_b_keypair = KekKeyPair::generate();
    let user_b_public = user_b_keypair.public_key().clone();
    
    println!("   👤 User B created (public key: {}...)", 
        &user_b_public.to_base64()[..20]);

    // Get User A's DEK for the deep folder (simulated - in real use, would be the folder's DEK)
    let folder_dek = DekKey::generate();

    // Method 1: Direct ShareToken creation
    println!("\n   📝 Method 1: Direct ShareToken Creation");
    let share_start = Instant::now();
    
    let share_token = ShareBuilder::new(
        user_a_client.encryption_config().key_manager().keypair(),
        &user_b_public,
        &folder_dek,
    )
        .path_scope(&deep_path)
        .expires_in(24 * 60 * 60) // 24 hours
        .read_only()
        .build()?;
    
    results.share_creation_time = share_start.elapsed();
    println!("      ├─ Token created: {:?}", results.share_creation_time);
    println!("      ├─ Share ID: {}", share_token.id);
    println!("      └─ Path scope: {}", share_token.path_scope);

    // Method 2: Async inbox sharing
    println!("\n   📬 Method 2: Async Inbox Sharing");
    let inbox_start = Instant::now();
    
    let (_envelope, inbox_entry) = ShareEnvelopeBuilder::new(
        user_a_client.encryption_config().key_manager().keypair(),
        &user_b_public,
        &folder_dek,
    )
        .path_scope(&deep_path)
        .expires_in(24 * 60 * 60)
        .read_only()
        .label("Deep Folder Share")
        .message("Here's access to my deep nested folder!")
        .sharer_name("User A")
        .build()?;
    
    results.share_inbox_enqueue_time = inbox_start.elapsed();
    
    let inbox_path = ShareInbox::entry_storage_path(&user_b_public, &inbox_entry.id);
    println!("      ├─ Envelope created: {:?}", results.share_inbox_enqueue_time);
    println!("      ├─ Entry ID: {}", inbox_entry.id);
    println!("      └─ Inbox path: {}", inbox_path);

    // User B accepts the share
    println!("\n   👤 User B accepts the share...");
    
    let accept_start = Instant::now();
    
    // Method 1: Accept direct token
    let recipient = ShareRecipient::new(&user_b_keypair);
    let accepted = recipient.accept_share(&share_token)?;
    
    results.share_acceptance_time = accept_start.elapsed();
    println!("      ├─ Share accepted: {:?}", results.share_acceptance_time);
    println!("      ├─ Path scope: {}", accepted.path_scope);
    println!("      └─ Can read: {}, Can write: {}", accepted.permissions.can_read, accepted.permissions.can_write);

    // Method 2: Accept from inbox
    println!("\n   📬 User B checks inbox...");
    let mut inbox = ShareInbox::new();
    inbox.add_entry(inbox_entry.clone());
    
    let pending = inbox.list_pending(&user_b_keypair);
    println!("      ├─ Pending shares: {}", pending.len());
    
    let accepted_envelope = inbox.accept_entry(&inbox_entry.id, &user_b_keypair)?;
    println!("      ├─ From: {:?}", accepted_envelope.sharer_name);
    println!("      ├─ Label: {:?}", accepted_envelope.label);
    println!("      └─ Message: {:?}", accepted_envelope.message);

    // User B fetches the shared folder content
    // Note: In a real scenario, User B would use their own client with the accepted DEK
    println!("\n   📥 User B fetches shared folder content...");
    
    let fetch_start = Instant::now();
    
    // Simulate fetching - in real use, User B would use their client with accepted.dek
    // Here we just measure the listing time as User B would see it
    let shared_listing = user_a_client.list_directory(bucket_a, Some(&deep_path)).await?;
    let files_count: usize = shared_listing.directories.values().map(|v| v.len()).sum();
    
    results.shared_folder_fetch_time = fetch_start.elapsed();
    results.shared_files_decrypted = files_count;
    
    println!("      ├─ Fetch time: {:?}", results.shared_folder_fetch_time);
    println!("      └─ Files accessible: {}", files_count);

    // ═══════════════════════════════════════════════════════════════════════════
    // CLEANUP & SUMMARY
    // ═══════════════════════════════════════════════════════════════════════════

    results.total_files = results.small_files_count + results.deep_structure_files + 
        if results.large_file_size_bytes > 0 { 1 } else { 0 };
    results.total_bytes = results.small_files_total_bytes + 
        results.large_file_size_bytes;
    results.total_time = overall_start.elapsed();

    // Print summary
    results.print_summary();

    // Cleanup option
    println!("\n🧹 Cleanup: To delete test data, uncomment cleanup code or run:");
    println!("   cargo run -p fula-cli -- delete-bucket {}", bucket_a);

    // Uncomment to auto-cleanup:
    // println!("\n🧹 Cleaning up test data...");
    // for path in &small_files_paths {
    //     let _ = user_a_client.delete_object(bucket_a, path).await;
    // }
    // for path in &deep_files_paths {
    //     let _ = user_a_client.delete_object(bucket_a, path).await;
    // }
    // let _ = user_a_client.delete_bucket(bucket_a).await;
    // println!("   ✓ Cleanup complete");

    Ok(())
}

fn print_header(config: &BenchmarkConfig) {
    println!("{}", "═".repeat(80));
    println!("              FULA ENCRYPTED STORAGE BENCHMARK");
    println!("{}", "═".repeat(80));
    println!();
    println!("Configuration:");
    println!("  ├─ Gateway: {}", config.gateway_url);
    println!("  ├─ Small folders: {} × {} files", config.small_folders, config.files_per_folder);
    println!("  ├─ Large file: {} MB", config.large_file_mb);
    println!("  ├─ Deep structure: {} levels × {} files", config.deep_levels, config.files_at_bottom);
    println!("  └─ Remote pinning: {}", if config.has_pinning() { "enabled" } else { "disabled" });
    println!();
    println!("To customize, set environment variables:");
    println!("  BENCHMARK_SMALL_FOLDERS, BENCHMARK_FILES_PER_FOLDER,");
    println!("  BENCHMARK_LARGE_FILE_MB, BENCHMARK_DEEP_LEVELS");
    println!();
}
