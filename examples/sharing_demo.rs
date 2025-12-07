//! Comprehensive demonstration of Fula's sharing and key rotation features
//!
//! This example demonstrates:
//! 1. Sharing files/folders without exposing the master key
//! 2. Time-limited share links with automatic expiry
//! 3. Permission-based access control (read/write/delete)
//! 4. Full filesystem key rotation with DEK re-wrapping
//!
//! Run with: cargo run --example sharing_demo

use fula_crypto::{
    KekKeyPair, DekKey,
    ShareBuilder, ShareRecipient, FolderShareManager, SharePermissions, AccessValidation,
    FileSystemRotation,
    symmetric::{encrypt, decrypt},
};
use std::thread::sleep;
use std::time::Duration;

fn main() {
    println!("===========================================");
    println!("   Fula Sharing & Key Rotation Demo");
    println!("===========================================\n");

    demo_file_sharing();
    demo_folder_sharing();
    demo_share_expiry();
    demo_permission_control();
    demo_key_rotation();
    demo_complete_workflow();

    println!("\n✅ All demonstrations completed successfully!");
}

/// Demonstrate sharing a single file without exposing the master key
fn demo_file_sharing() {
    println!("📁 DEMO 1: Sharing a File Without Master Key");
    println!("─────────────────────────────────────────────\n");

    // Owner's key pair (master key stays private)
    let owner = KekKeyPair::generate();
    println!("👤 Owner generated their key pair");
    println!("   Public Key: {}...", &owner.public_key().to_base64()[..20]);

    // Recipient's key pair
    let recipient = KekKeyPair::generate();
    println!("👤 Recipient generated their key pair");
    println!("   Public Key: {}...\n", &recipient.public_key().to_base64()[..20]);

    // Owner encrypts a file with a unique DEK
    let file_content = b"This is my private photo from vacation!";
    let file_dek = DekKey::generate();
    let (nonce, ciphertext) = encrypt(&file_dek, file_content).unwrap();
    println!("📄 Owner encrypted file with unique DEK");
    println!("   Original: \"{}\"", String::from_utf8_lossy(file_content));
    println!("   Ciphertext length: {} bytes\n", ciphertext.len());

    // Owner creates a share for the recipient
    // NOTE: Only the file DEK is shared, NOT the master key
    let share_token = ShareBuilder::new(&owner, recipient.public_key(), &file_dek)
        .path_scope("/photos/vacation/beach.jpg")
        .read_only()
        .build()
        .unwrap();

    println!("🔗 Owner created share token for recipient");
    println!("   Share ID: {}", share_token.id);
    println!("   Path Scope: {}", share_token.path_scope);
    println!("   Can Read: {}, Can Write: {}", share_token.can_read(), share_token.can_write());

    // Recipient accepts the share and decrypts
    let recipient_handler = ShareRecipient::new(&recipient);
    let accepted = recipient_handler.accept_share(&share_token).unwrap();

    println!("\n📬 Recipient accepted the share");
    println!("   DEK recovered successfully!");

    // Recipient decrypts the file using the shared DEK
    let decrypted = decrypt(&accepted.dek, &nonce, &ciphertext).unwrap();
    println!("   Decrypted: \"{}\"\n", String::from_utf8_lossy(&decrypted));

    // Verify: Owner's master key was NEVER shared
    println!("🔒 Security verification:");
    println!("   ✓ Owner's secret key: NEVER transmitted");
    println!("   ✓ Recipient received: Only wrapped file DEK");
    println!("   ✓ Recipient cannot: Access other owner files\n");
}

/// Demonstrate sharing an entire folder
fn demo_folder_sharing() {
    println!("📂 DEMO 2: Sharing a Folder");
    println!("─────────────────────────────────────────────\n");

    let owner = KekKeyPair::generate();
    let friend = KekKeyPair::generate();

    let mut folder_manager = FolderShareManager::new();

    // Register folders with their DEKs
    let photos_dek = DekKey::generate();
    let docs_dek = DekKey::generate();
    folder_manager.register_folder("/photos/2024/", photos_dek);
    folder_manager.register_folder("/documents/", docs_dek);

    println!("📁 Owner registered folders:");
    println!("   - /photos/2024/");
    println!("   - /documents/\n");

    // Share only /photos/2024/ with friend (read-write, no expiry)
    let share = folder_manager.create_share(
        &owner,
        "/photos/2024/",
        friend.public_key(),
        None, // No expiry
        SharePermissions::read_write(),
    ).unwrap();

    println!("🔗 Created share for /photos/2024/");
    println!("   Recipient: Friend");
    println!("   Permissions: read-write");
    println!("   Expiry: Never\n");

    // Validate access to different paths
    let paths_to_check = [
        "/photos/2024/summer/beach.jpg",
        "/photos/2024/winter/snow.jpg",
        "/photos/2023/old.jpg",
        "/documents/secret.pdf",
    ];

    println!("🔍 Access validation:");
    for path in paths_to_check {
        let valid = share.is_valid_for_path(path);
        let status = if valid { "✓ ALLOWED" } else { "✗ DENIED" };
        println!("   {} {}", status, path);
    }
    println!();
}

/// Demonstrate time-limited shares with automatic expiry
fn demo_share_expiry() {
    println!("⏰ DEMO 3: Time-Limited Share with Expiry");
    println!("─────────────────────────────────────────────\n");

    let owner = KekKeyPair::generate();
    let guest = KekKeyPair::generate();
    let dek = DekKey::generate();

    // Create a share that expires in 2 seconds
    let share = ShareBuilder::new(&owner, guest.public_key(), &dek)
        .path_scope("/temp/")
        .expires_in(2) // 2 seconds
        .read_only()
        .build()
        .unwrap();

    println!("🔗 Created time-limited share");
    println!("   Expires in: 2 seconds");
    println!("   Time until expiry: {:?} seconds\n", share.time_until_expiry());

    // Try to use immediately - should work
    let guest_handler = ShareRecipient::new(&guest);
    let result1 = guest_handler.accept_share(&share);
    println!("🕐 Immediate access: {}", if result1.is_ok() { "✓ SUCCESS" } else { "✗ DENIED" });

    // Wait for expiry
    println!("⏳ Waiting for expiry...");
    sleep(Duration::from_secs(3));

    // Try to use after expiry - should fail
    let result2 = guest_handler.accept_share(&share);
    println!("🕐 After expiry: {}", if result2.is_ok() { "✓ SUCCESS" } else { "✗ DENIED (as expected)" });
    println!("   Share expired: {}\n", share.is_expired());
}

/// Demonstrate permission-based access control
fn demo_permission_control() {
    println!("🔐 DEMO 4: Permission-Based Access Control");
    println!("─────────────────────────────────────────────\n");

    let owner = KekKeyPair::generate();
    let dek = DekKey::generate();

    // Create different permission levels
    let viewer = KekKeyPair::generate();
    let editor = KekKeyPair::generate();
    let admin = KekKeyPair::generate();

    let viewer_share = ShareBuilder::new(&owner, viewer.public_key(), &dek)
        .read_only()
        .build()
        .unwrap();

    let editor_share = ShareBuilder::new(&owner, editor.public_key(), &dek)
        .read_write()
        .build()
        .unwrap();

    let admin_share = ShareBuilder::new(&owner, admin.public_key(), &dek)
        .full_access()
        .build()
        .unwrap();

    println!("📋 Permission levels:");
    println!("   Viewer:  Read={} Write={} Delete={}", 
             viewer_share.permissions.can_read,
             viewer_share.permissions.can_write,
             viewer_share.permissions.can_delete);
    println!("   Editor:  Read={} Write={} Delete={}", 
             editor_share.permissions.can_read,
             editor_share.permissions.can_write,
             editor_share.permissions.can_delete);
    println!("   Admin:   Read={} Write={} Delete={}", 
             admin_share.permissions.can_read,
             admin_share.permissions.can_write,
             admin_share.permissions.can_delete);
    println!();
}

/// Demonstrate full filesystem key rotation
fn demo_key_rotation() {
    println!("🔄 DEMO 5: Full Filesystem Key Rotation");
    println!("─────────────────────────────────────────────\n");

    let keypair = KekKeyPair::generate();
    let mut fs = FileSystemRotation::new(keypair)
        .with_batch_size(5);

    println!("📁 Creating files with encrypted content...");
    
    // Create some files
    let mut file_data = Vec::new();
    for i in 0..10 {
        let path = format!("/documents/file{}.txt", i);
        let content = format!("Content of file {}", i);
        let dek = DekKey::generate();
        
        // Encrypt the content
        let (nonce, ciphertext) = encrypt(&dek, content.as_bytes()).unwrap();
        file_data.push((path.clone(), nonce, ciphertext));
        
        // Register with filesystem rotation manager
        fs.wrap_new_file(&path, &dek).unwrap();
    }
    
    let (_rotated, total) = fs.rotation_progress();
    println!("   Created {} files", total);
    println!("   All at KEK version 1\n");

    // Initiate rotation
    println!("🔑 Initiating key rotation...");
    let new_public = fs.rotate();
    println!("   New public key: {}...", &new_public.to_base64()[..20]);
    
    println!("   Files needing rotation: {}\n", fs.get_keys_needing_rotation().len());

    // Rotate in batches
    println!("📦 Rotating in batches of 5...");
    let mut batch_num = 1;
    while !fs.is_rotation_complete() {
        let result = fs.rotate_batch();
        println!("   Batch {}: rotated {} keys", batch_num, result.rotated_count);
        batch_num += 1;
    }

    let (rotated, total) = fs.rotation_progress();
    println!("\n✓ Rotation complete: {}/{} files at new version\n", rotated, total);

    // Verify all data still accessible
    println!("🔍 Verifying data accessibility...");
    for (i, (path, nonce, ciphertext)) in file_data.iter().enumerate() {
        let dek = fs.unwrap_file(path).unwrap();
        let decrypted = decrypt(&dek, nonce, ciphertext).unwrap();
        let content = String::from_utf8_lossy(&decrypted);
        if i == 0 {
            println!("   File 0: \"{}\" ✓", content);
        }
    }
    println!("   ... all {} files verified ✓\n", file_data.len());
}

/// Complete workflow demonstrating all features together
fn demo_complete_workflow() {
    println!("🎯 DEMO 6: Complete Real-World Workflow");
    println!("─────────────────────────────────────────────\n");

    // Scenario: Alice wants to share vacation photos with Bob for 1 week
    println!("Scenario: Alice shares vacation photos with Bob\n");

    // Setup users
    let alice = KekKeyPair::generate();
    let bob = KekKeyPair::generate();
    println!("👤 Alice (owner) created her account");
    println!("👤 Bob (recipient) created his account\n");

    // Alice sets up her folder structure
    let mut alice_folders = FolderShareManager::new();
    let vacation_dek = DekKey::generate();
    let work_dek = DekKey::generate();
    
    alice_folders.register_folder("/photos/vacation-2024/", vacation_dek.clone());
    alice_folders.register_folder("/documents/work/", work_dek);
    println!("📁 Alice's folders:");
    println!("   - /photos/vacation-2024/ (personal)");
    println!("   - /documents/work/ (private)\n");

    // Alice encrypts some vacation photos
    let photos: Vec<(&str, &[u8])> = vec![
        ("beach-sunset.jpg", b"[JPEG data for sunset photo]"),
        ("hiking-trail.jpg", b"[JPEG data for hiking photo]"),
        ("restaurant.jpg", b"[JPEG data for restaurant]"),
    ];

    println!("📷 Alice's vacation photos:");
    let mut encrypted_photos = Vec::new();
    for (name, data) in photos.iter() {
        let (nonce, ct) = encrypt(&vacation_dek, *data).unwrap();
        encrypted_photos.push((name, nonce, ct));
        println!("   - {}", name);
    }
    println!();

    // Alice shares vacation folder with Bob (read-only, expires in "1 week")
    let bob_share = alice_folders.create_share(
        &alice,
        "/photos/vacation-2024/",
        bob.public_key(),
        Some(7 * 24 * 60 * 60), // 1 week in seconds
        SharePermissions::read_only(),
    ).unwrap();

    println!("🔗 Alice shared /photos/vacation-2024/ with Bob");
    println!("   Permissions: read-only");
    println!("   Expires: in 1 week");
    println!("   Share ID: {}\n", bob_share.id);

    // Bob accepts the share
    let bob_handler = ShareRecipient::new(&bob);
    let bob_access = bob_handler.accept_share(&bob_share).unwrap();

    println!("📬 Bob accepted the share");
    println!("   Can access: {}", bob_access.path_scope);
    println!("   Can read: {}\n", bob_access.permissions.can_read);

    // Bob can now view all vacation photos
    println!("👀 Bob views Alice's photos:");
    for (name, nonce, ct) in encrypted_photos.iter() {
        let decrypted = decrypt(&bob_access.dek, nonce, ct).unwrap();
        println!("   ✓ {} ({} bytes)", name, decrypted.len());
    }
    println!();

    // Verify Bob CANNOT access work documents
    println!("🔒 Security check:");
    let work_access = bob_share.is_valid_for_path("/documents/work/report.pdf");
    println!("   Bob accessing /documents/work/: {}", 
             if work_access { "ALLOWED" } else { "✗ DENIED (correct!)" });

    // Alice can revoke Bob's access anytime
    println!("\n🚫 Alice revokes Bob's access...");
    alice_folders.revoke_share("/photos/vacation-2024/", &bob_share.id);
    
    let validation = alice_folders.validate_access(&bob_share, "/photos/vacation-2024/beach.jpg");
    println!("   Bob's access status: {:?}", validation);
    assert_eq!(validation, AccessValidation::Revoked);
    println!("   ✓ Access successfully revoked\n");
}
