//! File Manager Demo
//!
//! This example demonstrates how to build a file manager application
//! that can browse encrypted files WITHOUT downloading all the content.
//!
//! Key features demonstrated:
//! 1. List all files with decrypted metadata (names, sizes, types, timestamps)
//! 2. Browse directory structure
//! 3. Only download file content when user requests it
//!
//! Run with: cargo run --example file_manager_demo
//! (Requires fula-gateway running: cargo run --package fula-cli -- --no-auth)

use fula_client::{Config, EncryptedClient, EncryptionConfig};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("═══════════════════════════════════════════════════════════════");
    println!("           📁 Encrypted File Manager Demo");
    println!("═══════════════════════════════════════════════════════════════\n");

    // Create encrypted client
    let encryption = EncryptionConfig::new(); // Metadata privacy enabled by default
    let config = Config::new("http://localhost:9000").with_token("demo-token");
    let client = EncryptedClient::new(config, encryption)?;

    // Setup: Create bucket and upload some test files
    let bucket = "file-manager-demo";
    let _ = client.create_bucket(bucket).await;

    println!("📤 Uploading sample files (with encrypted metadata)...\n");
    
    // Upload files with different types
    let files_to_upload = [
        ("/documents/report-2024.pdf", "application/pdf", "Annual financial report content..."),
        ("/documents/notes.txt", "text/plain", "Meeting notes from last week..."),
        ("/photos/vacation/beach.jpg", "image/jpeg", "[JPEG binary data would be here]"),
        ("/photos/vacation/sunset.jpg", "image/jpeg", "[Another JPEG image]"),
        ("/photos/family/birthday.png", "image/png", "[PNG image data]"),
        ("/music/song1.mp3", "audio/mpeg", "[MP3 audio data]"),
        ("/videos/clip.mp4", "video/mp4", "[Large video file data would be here]"),
    ];

    for (path, content_type, content) in files_to_upload {
        client.put_object_encrypted_with_type(
            bucket, 
            path, 
            content.as_bytes().to_vec(),
            Some(content_type),
        ).await?;
        println!("   ✓ Uploaded: {}", path);
    }

    println!("\n{}", "─".repeat(65));
    println!("📊 DEMO 1: List All Files (Metadata Only - No Content Download)");
    println!("{}\n", "─".repeat(65));

    // This only downloads ~1-2KB per file (headers), NOT the file content!
    let files = client.list_objects_decrypted(bucket, None).await?;
    
    println!("Found {} files:\n", files.len());
    println!("{:<40} {:>10} {:<20}", "FILENAME", "SIZE", "TYPE");
    println!("{}", "─".repeat(75));
    
    for file in &files {
        let content_type = file.content_type.as_deref().unwrap_or("unknown");
        println!(
            "{:<40} {:>10} {:<20}",
            file.original_key,
            file.size_human(),
            content_type
        );
    }

    println!("\n💡 Note: No file content was downloaded! Only metadata headers.\n");

    println!("{}", "─".repeat(65));
    println!("📂 DEMO 2: Directory Tree View");
    println!("{}\n", "─".repeat(65));

    let listing = client.list_directory(bucket, None).await?;
    
    println!("Directory structure:");
    println!();
    
    let mut dirs: Vec<_> = listing.get_directories();
    dirs.sort();
    
    for dir in dirs {
        println!("📁 {}/", if dir.is_empty() { "(root)" } else { dir });
        
        if let Some(files) = listing.get_files(dir) {
            for file in files {
                let icon = get_file_icon(file.content_type.as_deref());
                println!("   {} {} ({})", icon, file.filename(), file.size_human());
            }
        }
        println!();
    }

    println!("Total: {} files, {} total size\n", 
        listing.file_count(), 
        format_size(listing.total_size())
    );

    println!("{}", "─".repeat(65));
    println!("🔍 DEMO 3: Filter by Prefix (e.g., /photos/)");
    println!("{}\n", "─".repeat(65));

    let photo_listing = client.list_directory(bucket, Some("/photos/")).await?;
    
    println!("Files in /photos/:");
    for (dir, files) in &photo_listing.directories {
        println!("\n  📁 {}/", dir);
        for file in files {
            println!("     🖼️  {} - {}", file.filename(), file.size_human());
        }
    }

    println!("\n{}", "─".repeat(65));
    println!("📥 DEMO 4: Download Specific File Only When Needed");
    println!("{}\n", "─".repeat(65));

    // User clicks on a file - NOW we download the content
    let selected_file = "/documents/notes.txt";
    println!("User selected: {}", selected_file);
    println!("Downloading content...\n");

    let content = client.get_object_decrypted(bucket, selected_file).await?;
    println!("Content ({} bytes):", content.len());
    println!("─────────────────────");
    println!("{}", String::from_utf8_lossy(&content));
    println!("─────────────────────\n");

    println!("{}", "─".repeat(65));
    println!("🔒 DEMO 5: What the Server Actually Sees");
    println!("{}\n", "─".repeat(65));

    println!("Server's view of your files:");
    println!("{:<45} {:>10}", "STORAGE KEY (Obfuscated)", "SIZE");
    println!("{}", "─".repeat(60));

    let raw_list = client.list_objects(bucket, None).await?;
    for obj in &raw_list.objects {
        println!("{:<45} {:>10}", obj.key, format_size(obj.size));
    }

    println!("\n❌ Server cannot see:");
    println!("   • Original filenames");
    println!("   • File types (all show as application/octet-stream)");
    println!("   • Original sizes (sees ciphertext size)");
    println!("   • File content (encrypted)");

    // Cleanup
    println!("\n🧹 Cleaning up...");
    for (path, _, _) in files_to_upload {
        let _ = client.delete_object(bucket, path).await;
    }
    let _ = client.delete_bucket(bucket).await;

    println!("\n═══════════════════════════════════════════════════════════════");
    println!("✅ Demo completed!");
    println!("═══════════════════════════════════════════════════════════════\n");

    Ok(())
}

fn get_file_icon(content_type: Option<&str>) -> &'static str {
    match content_type {
        Some(t) if t.starts_with("image/") => "🖼️ ",
        Some(t) if t.starts_with("video/") => "🎬",
        Some(t) if t.starts_with("audio/") => "🎵",
        Some(t) if t.contains("pdf") => "📄",
        Some(t) if t.starts_with("text/") => "📝",
        _ => "📄",
    }
}

fn format_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    
    if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}
