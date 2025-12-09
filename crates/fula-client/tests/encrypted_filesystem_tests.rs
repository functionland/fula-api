//! Encrypted Filesystem Stress Tests
//!
//! Comprehensive tests for encrypted file system edge cases:
//! 1. Deep folder structures (50 levels)
//! 2. Large files (100GB simulated)
//! 3. Large folders (2000 files)
//!
//! Each scenario tests:
//! - File read/write operations
//! - Sharing functionality
//! - Metadata-only listing for file managers
//! - Key rotation
//!
//! Run with: cargo test --package fula-client --test encrypted_filesystem_tests -- --nocapture

use fula_crypto::{
    private_forest::{PrivateForest, ForestFileEntry, EncryptedForest},
    keys::KeyManager,
};
use std::collections::HashMap;
use std::time::Instant;

fn now_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

// ═══════════════════════════════════════════════════════════════════════════════
// TEST 1: DEEP FOLDER STRUCTURE (50 LEVELS)
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_deep_folder_structure_50_levels() {
    println!("\n{}", "═".repeat(70));
    println!("TEST 1: Deep Folder Structure (50 levels)");
    println!("{}\n", "═".repeat(70));

    let mut forest = PrivateForest::new();
    let key_manager = KeyManager::new();
    let dek = key_manager.generate_dek();

    // Build a path 50 levels deep
    let depth = 50;
    let mut path_parts: Vec<String> = Vec::with_capacity(depth);
    for i in 0..depth {
        path_parts.push(format!("level_{:02}", i));
    }
    let deep_path = format!("/{}/file.txt", path_parts.join("/"));
    
    println!("📁 Testing path with {} levels deep:", depth);
    println!("   {}", &deep_path[..80.min(deep_path.len())]);
    println!("   ... ({} total characters)\n", deep_path.len());

    // ─────────────────────────────────────────────────────────────────────────
    // Test 1.1: Write encrypted file at deep path
    // ─────────────────────────────────────────────────────────────────────────
    println!("📝 Test 1.1: Write encrypted file at deep path");
    let start = Instant::now();
    
    // Generate storage key using FlatNamespace
    let storage_key = forest.generate_key(&deep_path, &dek);
    
    // Create file entry
    let entry = ForestFileEntry {
        path: deep_path.clone(),
        storage_key: storage_key.clone(),
        size: 1024,
        content_type: Some("text/plain".to_string()),
        created_at: now_timestamp(),
        modified_at: now_timestamp(),
        content_hash: None,
        user_metadata: HashMap::new(),
    };
    forest.upsert_file(entry);
    
    let write_time = start.elapsed();
    println!("   ✓ Write completed in {:?}", write_time);
    assert!(write_time.as_millis() < 100, "Write should complete in <100ms");

    // ─────────────────────────────────────────────────────────────────────────
    // Test 1.2: Read file from deep path
    // ─────────────────────────────────────────────────────────────────────────
    println!("📖 Test 1.2: Read file from deep path");
    let start = Instant::now();
    
    let retrieved_key = forest.get_storage_key(&deep_path);
    assert!(retrieved_key.is_some(), "Should find file at deep path");
    assert_eq!(retrieved_key.unwrap(), &storage_key);
    
    let read_time = start.elapsed();
    println!("   ✓ Read completed in {:?}", read_time);
    assert!(read_time.as_millis() < 50, "Read should complete in <50ms");

    // ─────────────────────────────────────────────────────────────────────────
    // Test 1.3: Metadata listing for file manager
    // ─────────────────────────────────────────────────────────────────────────
    println!("📋 Test 1.3: Metadata listing for file manager");
    let start = Instant::now();
    
    // List files at various depth levels
    for level in [0usize, 10, 25, 49] {
        let prefix = if level == 0 {
            "/".to_string()
        } else {
            format!("/{}", path_parts[..level].join("/"))
        };
        let files = forest.list_directory(&prefix);
        let subdirs = forest.list_subdirs(&prefix);
        let display_prefix = if prefix.len() > 40 { 
            format!("{}...", &prefix[..40]) 
        } else { 
            prefix 
        };
        println!("   Level {}: {} files, {} subdirs at '{}'", level, files.len(), subdirs.len(), display_prefix);
    }
    
    let list_time = start.elapsed();
    println!("   ✓ Listing completed in {:?}", list_time);
    assert!(list_time.as_millis() < 100, "Listing should complete in <100ms");

    // ─────────────────────────────────────────────────────────────────────────
    // Test 1.4: Sharing subtree from deep path
    // ─────────────────────────────────────────────────────────────────────────
    println!("🤝 Test 1.4: Sharing subtree from deep path");
    let start = Instant::now();
    
    // Extract subtree from midpoint
    let mid_path = format!("/{}", path_parts[..25].join("/"));
    let subtree = forest.extract_subtree(&mid_path);
    
    assert!(subtree.file_count() > 0, "Subtree should contain the deep file");
    
    let share_time = start.elapsed();
    println!("   ✓ Subtree extraction completed in {:?}", share_time);
    println!("   Subtree contains {} files", subtree.file_count());

    // ─────────────────────────────────────────────────────────────────────────
    // Test 1.5: Encrypt/decrypt forest (simulates persistence)
    // ─────────────────────────────────────────────────────────────────────────
    println!("🔐 Test 1.5: Forest encryption/decryption (key rotation prep)");
    let start = Instant::now();
    
    let encrypted = EncryptedForest::encrypt(&forest, &dek).expect("Should encrypt forest");
    let serialized = encrypted.to_bytes().expect("Should serialize");
    
    let deserialized = EncryptedForest::from_bytes(&serialized).expect("Should deserialize");
    let decrypted = deserialized.decrypt(&dek).expect("Should decrypt forest");
    
    assert_eq!(decrypted.file_count(), forest.file_count());
    
    let crypto_time = start.elapsed();
    println!("   ✓ Encrypt/decrypt cycle completed in {:?}", crypto_time);
    println!("   Serialized size: {} bytes", serialized.len());

    println!("\n✅ TEST 1 PASSED: Deep folder structure (50 levels) handled correctly\n");
}

// ═══════════════════════════════════════════════════════════════════════════════
// TEST 2: LARGE FILE SIZE (100GB SIMULATED)
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_large_file_100gb_simulated() {
    println!("\n{}", "═".repeat(70));
    println!("TEST 2: Large File Size (100GB simulated)");
    println!("{}\n", "═".repeat(70));

    let mut forest = PrivateForest::new();
    let key_manager = KeyManager::new();
    let dek = key_manager.generate_dek();

    // Simulate a 100GB file
    const FILE_SIZE: u64 = 100 * 1024 * 1024 * 1024; // 100 GB
    const CHUNK_SIZE: u64 = 256 * 1024 * 1024; // 256 MB chunks
    let num_chunks = (FILE_SIZE + CHUNK_SIZE - 1) / CHUNK_SIZE;
    
    println!("📦 Simulating 100GB file:");
    println!("   File size: {} GB", FILE_SIZE / (1024 * 1024 * 1024));
    println!("   Chunk size: {} MB", CHUNK_SIZE / (1024 * 1024));
    println!("   Total chunks: {}\n", num_chunks);

    // ─────────────────────────────────────────────────────────────────────────
    // Test 2.1: Write large file metadata
    // ─────────────────────────────────────────────────────────────────────────
    println!("📝 Test 2.1: Write large file metadata");
    let start = Instant::now();
    
    let file_path = "/backups/database_backup_2024.tar.gz";
    let storage_key = forest.generate_key(file_path, &dek);
    
    // Create file entry with large size
    let entry = ForestFileEntry {
        path: file_path.to_string(),
        storage_key: storage_key.clone(),
        size: FILE_SIZE,
        content_type: Some("application/gzip".to_string()),
        created_at: now_timestamp(),
        modified_at: now_timestamp(),
        content_hash: None,
        user_metadata: {
            let mut meta = HashMap::new();
            meta.insert("chunks".to_string(), num_chunks.to_string());
            meta.insert("chunk_size".to_string(), CHUNK_SIZE.to_string());
            meta
        },
    };
    forest.upsert_file(entry);
    
    let write_time = start.elapsed();
    println!("   ✓ Metadata write completed in {:?}", write_time);
    assert!(write_time.as_millis() < 50, "Metadata write should be fast");

    // ─────────────────────────────────────────────────────────────────────────
    // Test 2.2: Simulate chunked encryption (metadata for each chunk)
    // ─────────────────────────────────────────────────────────────────────────
    println!("🔐 Test 2.2: Simulate chunked encryption ({} chunks)", num_chunks);
    let start = Instant::now();
    
    // Track chunk storage keys (in real implementation, stored with file)
    let mut chunk_keys: Vec<String> = Vec::with_capacity(num_chunks as usize);
    
    for chunk_idx in 0..num_chunks {
        let chunk_path = format!("{}/.chunks/{:06}", file_path, chunk_idx);
        let chunk_key = forest.generate_key(&chunk_path, &dek);
        chunk_keys.push(chunk_key);
        
        // Progress update every 100 chunks
        if chunk_idx % 100 == 0 && chunk_idx > 0 {
            let elapsed = start.elapsed();
            let rate = chunk_idx as f64 / elapsed.as_secs_f64();
            let remaining = (num_chunks - chunk_idx) as f64 / rate;
            println!("   Processing chunk {}/{} ({:.1} chunks/sec, ~{:.1}s remaining)", 
                     chunk_idx, num_chunks, rate, remaining);
        }
    }
    
    let chunk_time = start.elapsed();
    let chunks_per_sec = num_chunks as f64 / chunk_time.as_secs_f64();
    println!("   ✓ Generated {} chunk keys in {:?} ({:.0} chunks/sec)", 
             num_chunks, chunk_time, chunks_per_sec);
    
    // For 100GB file at 1GB/s, we need >100 chunks/sec minimum
    assert!(chunks_per_sec > 100.0, "Should generate >100 chunk keys/sec for acceptable performance");

    // ─────────────────────────────────────────────────────────────────────────
    // Test 2.3: Read large file metadata
    // ─────────────────────────────────────────────────────────────────────────
    println!("📖 Test 2.3: Read large file metadata");
    let start = Instant::now();
    
    let retrieved = forest.get_file(file_path);
    assert!(retrieved.is_some(), "Should find large file");
    
    let file_entry = retrieved.unwrap();
    assert_eq!(file_entry.size, FILE_SIZE);
    
    let read_time = start.elapsed();
    println!("   ✓ Metadata read completed in {:?}", read_time);
    println!("   Retrieved size: {} GB", file_entry.size / (1024 * 1024 * 1024));

    // ─────────────────────────────────────────────────────────────────────────
    // Test 2.4: Metadata listing (file manager view)
    // ─────────────────────────────────────────────────────────────────────────
    println!("📋 Test 2.4: Metadata listing for file manager");
    let start = Instant::now();
    
    let files = forest.list_directory("/backups");
    assert_eq!(files.len(), 1);
    
    // Verify human-readable size display
    let size_display = format_size(files[0].size);
    println!("   Listed: {} ({})", files[0].path, size_display);
    
    let list_time = start.elapsed();
    println!("   ✓ Listing completed in {:?}", list_time);

    // ─────────────────────────────────────────────────────────────────────────
    // Test 2.5: Sharing (extracting subtree with large file)
    // ─────────────────────────────────────────────────────────────────────────
    println!("🤝 Test 2.5: Sharing subtree with large file");
    let start = Instant::now();
    
    let subtree = forest.extract_subtree("/backups");
    assert_eq!(subtree.file_count(), 1);
    
    let share_time = start.elapsed();
    println!("   ✓ Subtree extraction completed in {:?}", share_time);

    // ─────────────────────────────────────────────────────────────────────────
    // Test 2.6: Key rotation simulation
    // ─────────────────────────────────────────────────────────────────────────
    println!("🔄 Test 2.6: Key rotation simulation");
    let start = Instant::now();
    
    // Generate new DEK for rotation
    let new_dek = key_manager.generate_dek();
    
    // Re-encrypt forest with new key
    let encrypted = EncryptedForest::encrypt(&forest, &new_dek).expect("Should encrypt");
    let rotated = encrypted.decrypt(&new_dek).expect("Should decrypt with new key");
    
    assert_eq!(rotated.file_count(), forest.file_count());
    
    let rotation_time = start.elapsed();
    println!("   ✓ Forest key rotation completed in {:?}", rotation_time);
    
    // Note: Actual file chunk re-encryption would happen separately and stream-based
    println!("   Note: Chunk re-encryption would be streaming-based for 100GB file");

    println!("\n✅ TEST 2 PASSED: Large file (100GB) metadata handled correctly\n");
}

// ═══════════════════════════════════════════════════════════════════════════════
// TEST 3: LARGE FOLDER (2000 FILES)
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_large_folder_2000_files() {
    println!("\n{}", "═".repeat(70));
    println!("TEST 3: Large Folder (2000 files)");
    println!("{}\n", "═".repeat(70));

    let mut forest = PrivateForest::new();
    let key_manager = KeyManager::new();
    let dek = key_manager.generate_dek();

    const NUM_FILES: usize = 2000;
    let folder_path = "/photos/vacation_2024";
    
    println!("📁 Testing folder with {} files\n", NUM_FILES);

    // ─────────────────────────────────────────────────────────────────────────
    // Test 3.1: Write 2000 files to single folder
    // ─────────────────────────────────────────────────────────────────────────
    println!("📝 Test 3.1: Write {} files to single folder", NUM_FILES);
    let start = Instant::now();
    
    for i in 0..NUM_FILES {
        let file_path = format!("{}/IMG_{:04}.jpg", folder_path, i);
        let storage_key = forest.generate_key(&file_path, &dek);
        
        let entry = ForestFileEntry {
            path: file_path,
            storage_key,
            size: 3_500_000 + (i as u64 * 1000), // ~3.5MB each, varying sizes
            content_type: Some("image/jpeg".to_string()),
            created_at: now_timestamp() - (NUM_FILES - i) as i64 * 60,
            modified_at: now_timestamp(),
            content_hash: None,
            user_metadata: {
                let mut meta = HashMap::new();
                meta.insert("camera".to_string(), "iPhone 15 Pro".to_string());
                meta.insert("location".to_string(), format!("Photo location {}", i));
                meta
            },
        };
        forest.upsert_file(entry);
        
        if i > 0 && i % 500 == 0 {
            println!("   Written {}/{} files...", i, NUM_FILES);
        }
    }
    
    let write_time = start.elapsed();
    let files_per_sec = NUM_FILES as f64 / write_time.as_secs_f64();
    println!("   ✓ Wrote {} files in {:?} ({:.0} files/sec)", NUM_FILES, write_time, files_per_sec);
    assert!(files_per_sec > 1000.0, "Should write >1000 files/sec");

    // ─────────────────────────────────────────────────────────────────────────
    // Test 3.2: Read random files
    // ─────────────────────────────────────────────────────────────────────────
    println!("📖 Test 3.2: Read random files");
    let start = Instant::now();
    
    // Read 100 random files
    for i in (0..NUM_FILES).step_by(20) {
        let file_path = format!("{}/IMG_{:04}.jpg", folder_path, i);
        let retrieved = forest.get_storage_key(&file_path);
        assert!(retrieved.is_some(), "Should find file {}", file_path);
    }
    
    let read_time = start.elapsed();
    println!("   ✓ Read 100 files in {:?}", read_time);
    assert!(read_time.as_millis() < 100, "Reading 100 files should take <100ms");

    // ─────────────────────────────────────────────────────────────────────────
    // Test 3.3: Metadata listing for file manager (full folder)
    // ─────────────────────────────────────────────────────────────────────────
    println!("📋 Test 3.3: Metadata listing for file manager (full folder)");
    let start = Instant::now();
    
    let files = forest.list_directory(folder_path);
    assert_eq!(files.len(), NUM_FILES, "Should list all {} files", NUM_FILES);
    
    let list_time = start.elapsed();
    let files_per_sec = NUM_FILES as f64 / list_time.as_secs_f64();
    println!("   ✓ Listed {} files in {:?} ({:.0} files/sec)", NUM_FILES, list_time, files_per_sec);
    assert!(list_time.as_millis() < 500, "Listing 2000 files should take <500ms");

    // Calculate total size
    let total_size: u64 = files.iter().map(|f| f.size).sum();
    println!("   Total folder size: {}", format_size(total_size));

    // ─────────────────────────────────────────────────────────────────────────
    // Test 3.4: Paginated listing (file manager pagination)
    // ─────────────────────────────────────────────────────────────────────────
    println!("📋 Test 3.4: Paginated listing (50 files per page)");
    let start = Instant::now();
    
    let page_size = 50;
    let total_pages = (NUM_FILES + page_size - 1) / page_size;
    
    // Simulate paginated access
    let all_files = forest.list_directory(folder_path);
    for page in 0..total_pages {
        let page_start = page * page_size;
        let page_end = (page_start + page_size).min(NUM_FILES);
        let page_files = &all_files[page_start..page_end];
        
        // Verify page content
        assert_eq!(page_files.len(), page_end - page_start);
    }
    
    let pagination_time = start.elapsed();
    println!("   ✓ Paginated through {} pages in {:?}", total_pages, pagination_time);

    // ─────────────────────────────────────────────────────────────────────────
    // Test 3.5: Sharing entire folder
    // ─────────────────────────────────────────────────────────────────────────
    println!("🤝 Test 3.5: Sharing entire folder ({} files)", NUM_FILES);
    let start = Instant::now();
    
    let subtree = forest.extract_subtree(folder_path);
    assert_eq!(subtree.file_count(), NUM_FILES);
    
    let share_time = start.elapsed();
    println!("   ✓ Subtree extraction completed in {:?}", share_time);
    assert!(share_time.as_millis() < 500, "Sharing 2000 files should take <500ms");

    // ─────────────────────────────────────────────────────────────────────────
    // Test 3.6: Forest encryption for persistence
    // ─────────────────────────────────────────────────────────────────────────
    println!("🔐 Test 3.6: Forest encryption/decryption");
    let start = Instant::now();
    
    let encrypted = EncryptedForest::encrypt(&forest, &dek).expect("Should encrypt");
    let serialized = encrypted.to_bytes().expect("Should serialize");
    
    println!("   Serialized forest size: {} KB", serialized.len() / 1024);
    
    let deserialized = EncryptedForest::from_bytes(&serialized).expect("Should deserialize");
    let decrypted = deserialized.decrypt(&dek).expect("Should decrypt");
    
    assert_eq!(decrypted.file_count(), NUM_FILES);
    
    let crypto_time = start.elapsed();
    println!("   ✓ Encrypt/decrypt cycle completed in {:?}", crypto_time);
    assert!(crypto_time.as_millis() < 1000, "Encrypt/decrypt 2000 files should take <1s");

    // ─────────────────────────────────────────────────────────────────────────
    // Test 3.7: Key rotation with large folder
    // ─────────────────────────────────────────────────────────────────────────
    println!("🔄 Test 3.7: Key rotation with {} files", NUM_FILES);
    let start = Instant::now();
    
    // Generate new key
    let new_dek = key_manager.generate_dek();
    
    // Re-encrypt forest index
    let encrypted_new = EncryptedForest::encrypt(&forest, &new_dek).expect("Should encrypt with new key");
    let decrypted_new = encrypted_new.decrypt(&new_dek).expect("Should decrypt with new key");
    
    assert_eq!(decrypted_new.file_count(), NUM_FILES);
    
    let rotation_time = start.elapsed();
    println!("   ✓ Key rotation completed in {:?}", rotation_time);
    
    // Note about actual file re-encryption
    println!("   Note: Individual file re-encryption would be batched for {} files", NUM_FILES);

    // ─────────────────────────────────────────────────────────────────────────
    // Test 3.8: Delete multiple files
    // ─────────────────────────────────────────────────────────────────────────
    println!("🗑️  Test 3.8: Delete multiple files");
    let start = Instant::now();
    
    // Delete every 10th file (200 files total)
    let mut deleted_count = 0;
    for i in (0..NUM_FILES).step_by(10) {
        let file_path = format!("{}/IMG_{:04}.jpg", folder_path, i);
        forest.remove_file(&file_path);
        deleted_count += 1;
    }
    
    let delete_time = start.elapsed();
    println!("   ✓ Deleted {} files in {:?}", deleted_count, delete_time);
    assert_eq!(forest.file_count(), NUM_FILES - deleted_count);

    println!("\n✅ TEST 3 PASSED: Large folder (2000 files) handled correctly\n");
}

// ═══════════════════════════════════════════════════════════════════════════════
// COMBINED STRESS TEST
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_combined_stress_scenario() {
    println!("\n{}", "═".repeat(70));
    println!("COMBINED STRESS TEST: All scenarios together");
    println!("{}\n", "═".repeat(70));

    let mut forest = PrivateForest::new();
    let key_manager = KeyManager::new();
    let dek = key_manager.generate_dek();

    // Create structure:
    // /deep/path/.../50_levels/file.txt (deep)
    // /backups/huge_file.tar (100GB metadata)
    // /photos/vacation/IMG_0000..1999.jpg (2000 files)

    let start = Instant::now();

    // Add deep file
    let deep_path = format!("/{}/file.txt", (0..50).map(|i| format!("l{}", i)).collect::<Vec<_>>().join("/"));
    let entry = ForestFileEntry {
        path: deep_path.clone(),
        storage_key: forest.generate_key(&deep_path, &dek),
        size: 1024,
        content_type: Some("text/plain".to_string()),
        created_at: now_timestamp(),
        modified_at: now_timestamp(),
        content_hash: None,
        user_metadata: HashMap::new(),
    };
    forest.upsert_file(entry);

    // Add large file
    let large_path = "/backups/huge_file.tar";
    let entry = ForestFileEntry {
        path: large_path.to_string(),
        storage_key: forest.generate_key(large_path, &dek),
        size: 100 * 1024 * 1024 * 1024, // 100GB
        content_type: Some("application/x-tar".to_string()),
        created_at: now_timestamp(),
        modified_at: now_timestamp(),
        content_hash: None,
        user_metadata: HashMap::new(),
    };
    forest.upsert_file(entry);

    // Add 2000 files
    for i in 0..2000 {
        let path = format!("/photos/vacation/IMG_{:04}.jpg", i);
        let entry = ForestFileEntry {
            path: path.clone(),
            storage_key: forest.generate_key(&path, &dek),
            size: 3_500_000,
            content_type: Some("image/jpeg".to_string()),
            created_at: now_timestamp(),
            modified_at: now_timestamp(),
            content_hash: None,
            user_metadata: HashMap::new(),
        };
        forest.upsert_file(entry);
    }

    let setup_time = start.elapsed();
    println!("📊 Setup completed in {:?}", setup_time);
    println!("   Total files: {}", forest.file_count());

    // Encrypt and decrypt entire forest
    let start = Instant::now();
    let encrypted = EncryptedForest::encrypt(&forest, &dek).expect("encrypt");
    let serialized = encrypted.to_bytes().expect("serialize");
    let deserialized = EncryptedForest::from_bytes(&serialized).expect("deserialize");
    let decrypted = deserialized.decrypt(&dek).expect("decrypt");
    
    let crypto_time = start.elapsed();
    println!("🔐 Full forest encrypt/decrypt: {:?}", crypto_time);
    println!("   Serialized size: {} KB", serialized.len() / 1024);
    
    assert_eq!(decrypted.file_count(), forest.file_count());

    // List all files
    let start = Instant::now();
    let all_files = forest.list_all_files();
    let list_time = start.elapsed();
    println!("📋 Listed all {} files in {:?}", all_files.len(), list_time);

    println!("\n✅ COMBINED STRESS TEST PASSED\n");
}

// ═══════════════════════════════════════════════════════════════════════════════
// HELPER FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════════════

fn format_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    const TB: u64 = GB * 1024;

    if bytes >= TB {
        format!("{:.2} TB", bytes as f64 / TB as f64)
    } else if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}
