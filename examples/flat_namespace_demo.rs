//! FlatNamespace Demo - Complete Structure Hiding
//!
//! This example demonstrates how to use FlatNamespace mode for maximum privacy.
//! With FlatNamespace:
//!
//! - Server sees only random CID-like hashes (e.g., `QmX7a8f3e2d1...`)
//! - No prefixes or structure hints (unlike `e/hash` in DeterministicHash mode)
//! - Server cannot determine folder structure or parent/child relationships
//! - File tree is stored in an encrypted PrivateForest index
//!
//! This is inspired by WNFS (WebNative File System) and Peergos.
//!
//! Run with: cargo run --example flat_namespace_demo
//! (Requires fula-gateway running: cargo run --package fula-cli -- --no-auth)

use fula_client::{Config, EncryptedClient, EncryptionConfig};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("═══════════════════════════════════════════════════════════════");
    println!("        🔐 FlatNamespace Demo - Maximum Privacy Mode");
    println!("═══════════════════════════════════════════════════════════════\n");

    // Create client with FlatNamespace mode (RECOMMENDED for maximum privacy)
    let encryption = EncryptionConfig::new_flat_namespace();
    let config = Config::new("http://localhost:9000").with_token("demo-token");
    let client = EncryptedClient::new(config, encryption)?;

    let bucket = "flat-namespace-demo";

    // Create bucket
    println!("📦 Creating bucket: {}\n", bucket);
    if let Err(_) = client.create_bucket(bucket).await {
        println!("   (Bucket may already exist, continuing...)\n");
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // DEMO 1: Upload files with FlatNamespace
    // ═══════════════════════════════════════════════════════════════════════════
    
    println!("{}", "─".repeat(65));
    println!("📤 DEMO 1: Upload Files (Server sees NO structure hints)");
    println!("{}\n", "─".repeat(65));

    let files = vec![
        ("/photos/vacation/beach.jpg", "image/jpeg", "Beach photo content"),
        ("/photos/vacation/sunset.jpg", "image/jpeg", "Sunset photo content"),
        ("/photos/family/portrait.jpg", "image/jpeg", "Family portrait"),
        ("/documents/report.pdf", "application/pdf", "Annual report content"),
        ("/documents/notes.txt", "text/plain", "Meeting notes"),
    ];

    for (path, content_type, content) in &files {
        client.put_object_flat(bucket, path, content.as_bytes().to_vec(), Some(content_type)).await?;
        println!("   ✓ Uploaded: {}", path);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // DEMO 2: What the server sees vs. what you see
    // ═══════════════════════════════════════════════════════════════════════════
    
    println!("\n{}", "─".repeat(65));
    println!("👁️  DEMO 2: Server View vs Client View");
    println!("{}\n", "─".repeat(65));

    // Get raw list from server (what server sees)
    let raw_list = client.inner().list_objects(bucket, None).await?;
    
    println!("SERVER VIEW (What storage node sees):");
    println!("┌────────────────────────────────────────────────────┐");
    for obj in &raw_list.objects {
        // Server only sees opaque CID-like keys
        println!("│ {} │", obj.key);
    }
    println!("└────────────────────────────────────────────────────┘");
    println!("   → Server CANNOT determine:");
    println!("      • Which objects are files vs folders");
    println!("      • Parent/child relationships");
    println!("      • File names or paths");
    println!("      • Directory structure");

    // Get decrypted list (what you see)
    println!("\nCLIENT VIEW (What owner sees after decryption):");
    println!("┌────────────────────────────────────────────────────┐");
    
    let files_list = client.list_files_from_forest(bucket).await?;
    for file in &files_list {
        println!("│ {:<50} │", file.original_key);
    }
    println!("└────────────────────────────────────────────────────┘");

    // ═══════════════════════════════════════════════════════════════════════════
    // DEMO 3: Directory browsing (from encrypted index)
    // ═══════════════════════════════════════════════════════════════════════════
    
    println!("\n{}", "─".repeat(65));
    println!("📁 DEMO 3: Directory Browsing (from PrivateForest index)");
    println!("{}\n", "─".repeat(65));

    let listing = client.list_directory(bucket, None).await?;
    
    println!("Directory Tree:");
    for dir in listing.get_directories() {
        println!("\n📁 {}/", if dir.is_empty() { "/" } else { dir });
        
        if let Some(files) = listing.get_files(dir) {
            for file in files {
                let icon = match file.content_type.as_deref() {
                    Some(t) if t.starts_with("image/") => "🖼️ ",
                    Some(t) if t.contains("pdf") => "📄",
                    _ => "📄",
                };
                println!("   {} {} ({})", icon, file.filename(), file.size_human());
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // DEMO 4: Download a file using original path
    // ═══════════════════════════════════════════════════════════════════════════
    
    println!("\n{}", "─".repeat(65));
    println!("📥 DEMO 4: Download File (path resolved from PrivateForest)");
    println!("{}\n", "─".repeat(65));

    let path_to_download = "/documents/report.pdf";
    println!("Downloading: {}", path_to_download);
    
    let content = client.get_object_flat(bucket, path_to_download).await?;
    println!("   Content: \"{}\"", String::from_utf8_lossy(&content));
    println!("   Size: {} bytes", content.len());

    // ═══════════════════════════════════════════════════════════════════════════
    // DEMO 5: Share a subtree
    // ═══════════════════════════════════════════════════════════════════════════
    
    println!("\n{}", "─".repeat(65));
    println!("🤝 DEMO 5: Extract Subtree for Sharing");
    println!("{}\n", "─".repeat(65));

    let subtree = client.get_forest_subtree(bucket, "/photos/vacation").await?;
    
    println!("Extracted subtree for sharing: /photos/vacation/");
    println!("   Files in subtree: {}", subtree.file_count());
    for file in subtree.list_all_files() {
        println!("   • {}", file.path);
    }
    println!("\n   → This subtree can be encrypted and shared with others");
    println!("   → Recipients can decrypt only this folder, not your whole filesystem");

    // ═══════════════════════════════════════════════════════════════════════════
    // COMPARISON
    // ═══════════════════════════════════════════════════════════════════════════
    
    println!("\n{}", "═".repeat(65));
    println!("📊 COMPARISON: Key Obfuscation Modes");
    println!("{}\n", "═".repeat(65));

    println!("┌──────────────────┬───────────────────────────────────────────┐");
    println!("│ Mode             │ What Server Sees                          │");
    println!("├──────────────────┼───────────────────────────────────────────┤");
    println!("│ DeterministicHash│ e/a7c3f9b2e8d14a6f  (reveals 'e/' prefix) │");
    println!("│ RandomUuid       │ e/550e8400-e29b-41d4  (reveals 'e/' prefix)│");
    println!("│ PreserveStructure│ /photos/e_a7c3f9b2  (reveals folder path!) │");
    println!("│ FlatNamespace ✓  │ QmX7a8f3e2d1c9b4a5  (NO HINTS!)           │");
    println!("└──────────────────┴───────────────────────────────────────────┘");

    println!("\n🎉 Demo complete!");
    println!("\nKey Takeaways:");
    println!("   • FlatNamespace provides maximum privacy");
    println!("   • Server cannot determine any file structure");
    println!("   • All metadata stored in encrypted PrivateForest index");
    println!("   • File manager, sharing, and key rotation all supported");

    Ok(())
}
