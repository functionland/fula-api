//! Benchmark: Sharing Between Users
//!
//! Tests sharing encrypted data between User A and User B.
//!
//! Run with: cargo run --example benchmark_sharing --release
//!
//! Configuration:
//!   - BENCHMARK_GATEWAY_URL=http://localhost:9000
//!   - PINNING_SERVICE_ENDPOINT (optional)
//!   - PINNING_SERVICE_TOKEN (optional)

use fula_crypto::{
    keys::{KekKeyPair, DekKey},
    sharing::{ShareBuilder, ShareRecipient},
    inbox::{ShareEnvelopeBuilder, ShareInbox},
};
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
    println!("             BENCHMARK: Sharing Between Users");
    println!("{}", "═".repeat(80));
    println!();
    println!("Configuration:");
    println!("  ├─ Gateway: {}", config.gateway_url);
    println!("  └─ Remote pinning: {}", if config.has_pinning() { "enabled" } else { "disabled" });
    println!();

    // Create User A's client
    println!("🔧 Creating User A's encrypted client...");
    let user_a_client = create_client(&config)?;
    
    let bucket = "bench-sharing";
    match user_a_client.inner().create_bucket(bucket).await {
        Ok(_) => println!("   └─ Bucket created: {}", bucket),
        Err(e) => println!("   └─ Bucket: {} ({})", bucket, e),
    }

    // Upload some test files
    println!("\n📁 User A uploads test files...");
    let folder_path = "/shared_folder";
    
    for i in 0..5 {
        let path = format!("{}/file_{}.txt", folder_path, i);
        let content = format!("Shared file {} content", i);
        user_a_client.put_object_flat_deferred(bucket, &path, content.into_bytes(), None).await?;
    }
    user_a_client.flush_forest(bucket).await?;
    println!("   └─ Uploaded 5 files to {}", folder_path);

    // Create User B
    println!("\n👤 Creating User B...");
    let user_b_keypair = KekKeyPair::generate();
    let user_b_public = user_b_keypair.public_key().clone();
    println!("   └─ Public key: {}...", &user_b_public.to_base64()[..20]);

    // Generate DEK for the folder
    let folder_dek = DekKey::generate();

    // Method 1: Direct ShareToken
    println!("\n📝 Method 1: Direct ShareToken Creation");
    let share_start = Instant::now();
    
    let share_token = ShareBuilder::new(
        user_a_client.encryption_config().key_manager().keypair(),
        &user_b_public,
        &folder_dek,
    )
        .path_scope(folder_path)
        .expires_in(24 * 60 * 60)
        .read_only()
        .build()?;
    
    let share_creation_time = share_start.elapsed();
    println!("   ├─ Token created: {:?}", share_creation_time);
    println!("   ├─ Share ID: {}", share_token.id);
    println!("   └─ Path scope: {}", share_token.path_scope);

    // Method 2: Inbox Sharing
    println!("\n📬 Method 2: Async Inbox Sharing");
    let inbox_start = Instant::now();
    
    let (_envelope, inbox_entry) = ShareEnvelopeBuilder::new(
        user_a_client.encryption_config().key_manager().keypair(),
        &user_b_public,
        &folder_dek,
    )
        .path_scope(folder_path)
        .expires_in(24 * 60 * 60)
        .read_only()
        .label("Shared Folder")
        .message("Here's access to my shared folder!")
        .sharer_name("User A")
        .build()?;
    
    let inbox_enqueue_time = inbox_start.elapsed();
    
    let inbox_path = ShareInbox::entry_storage_path(&user_b_public, &inbox_entry.id);
    println!("   ├─ Envelope created: {:?}", inbox_enqueue_time);
    println!("   ├─ Entry ID: {}", inbox_entry.id);
    println!("   └─ Inbox path: {}", inbox_path);

    // User B accepts the share
    println!("\n👤 User B accepts the share (Method 1)...");
    let accept_start = Instant::now();
    
    let recipient = ShareRecipient::new(&user_b_keypair);
    let accepted = recipient.accept_share(&share_token)?;
    
    let acceptance_time = accept_start.elapsed();
    println!("   ├─ Accepted: {:?}", acceptance_time);
    println!("   ├─ Path scope: {}", accepted.path_scope);
    println!("   └─ Permissions: read={}, write={}", 
        accepted.permissions.can_read, accepted.permissions.can_write);

    // User B checks inbox (Method 2)
    println!("\n📬 User B checks inbox (Method 2)...");
    let mut inbox = ShareInbox::new();
    inbox.add_entry(inbox_entry.clone());
    
    let pending = inbox.list_pending(&user_b_keypair);
    println!("   ├─ Pending shares: {}", pending.len());
    
    let accepted_envelope = inbox.accept_entry(&inbox_entry.id, &user_b_keypair)?;
    println!("   ├─ From: {:?}", accepted_envelope.sharer_name);
    println!("   ├─ Label: {:?}", accepted_envelope.label);
    println!("   └─ Message: {:?}", accepted_envelope.message);

    // User B fetches shared content
    println!("\n📥 User B fetches shared folder content...");
    let fetch_start = Instant::now();
    let listing = user_a_client.list_directory(bucket, Some(folder_path)).await?;
    let fetch_time = fetch_start.elapsed();
    
    let files_count: usize = listing.directories.values().map(|v| v.len()).sum();
    println!("   ├─ Fetch time: {:?}", fetch_time);
    println!("   └─ Files accessible: {}", files_count);

    // Summary
    println!("\n{}", "═".repeat(80));
    println!("                           RESULTS");
    println!("{}", "═".repeat(80));
    println!("  ├─ Share token creation: {:?}", share_creation_time);
    println!("  ├─ Inbox envelope creation: {:?}", inbox_enqueue_time);
    println!("  ├─ Share acceptance: {:?}", acceptance_time);
    println!("  ├─ Shared folder fetch: {:?}", fetch_time);
    println!("  └─ Files shared: {}", files_count);
    println!("{}", "═".repeat(80));

    Ok(())
}
