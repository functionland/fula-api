//! Metadata Privacy Example
//!
//! This example demonstrates how Fula protects file metadata (names, sizes, timestamps)
//! from the storage server, not just the file content.
//!
//! With metadata privacy enabled:
//! - File names are obfuscated (server sees hashed keys, not real filenames)
//! - File sizes shown to server are ciphertext sizes (not original)
//! - Content types are hidden
//! - Timestamps in private metadata are encrypted
//!
//! Run with: cargo run --example metadata_privacy
//! (Requires fula-gateway running: cargo run --package fula-cli -- --no-auth)

use fula_crypto::{
    DekKey, KekKeyPair,
    private_metadata::{PrivateMetadata, EncryptedPrivateMetadata, KeyObfuscation, obfuscate_key},
};

fn main() {
    println!("===========================================");
    println!("   Fula Metadata Privacy Demonstration");
    println!("===========================================\n");

    demo_key_obfuscation();
    demo_private_metadata_encryption();
    demo_server_sees_vs_client_sees();
    
    println!("\n✅ All metadata privacy demonstrations completed!");
}

/// Demonstrate how file names are obfuscated
fn demo_key_obfuscation() {
    println!("📁 DEMO 1: File Name Obfuscation");
    println!("─────────────────────────────────────────\n");

    let user_dek = DekKey::generate();
    
    let original_files = [
        "/photos/vacation/beach_sunset.jpg",
        "/documents/tax_returns_2024.pdf",
        "/personal/diary.txt",
        "/work/salary_negotiation.docx",
    ];

    println!("Original file paths vs. what the server sees:\n");
    
    for original in original_files {
        let obfuscated = obfuscate_key(original, &user_dek, KeyObfuscation::DeterministicHash);
        println!("  Original:   {}", original);
        println!("  Server sees: {}", obfuscated);
        println!();
    }

    // Demonstrate that same file = same hash (for retrieval)
    println!("✓ Key obfuscation is deterministic (same file → same hash):");
    let test_file = "/photos/secret.jpg";
    let hash1 = obfuscate_key(test_file, &user_dek, KeyObfuscation::DeterministicHash);
    let hash2 = obfuscate_key(test_file, &user_dek, KeyObfuscation::DeterministicHash);
    println!("  First computation:  {}", hash1);
    println!("  Second computation: {}", hash2);
    println!("  Match: {}\n", hash1 == hash2);

    // Different users get different hashes
    println!("✓ Different users get different hashes (same filename):");
    let user2_dek = DekKey::generate();
    let hash_user1 = obfuscate_key(test_file, &user_dek, KeyObfuscation::DeterministicHash);
    let hash_user2 = obfuscate_key(test_file, &user2_dek, KeyObfuscation::DeterministicHash);
    println!("  User 1: {}", hash_user1);
    println!("  User 2: {}", hash_user2);
    println!("  Different: {}\n", hash_user1 != hash_user2);
}

/// Demonstrate private metadata encryption
fn demo_private_metadata_encryption() {
    println!("🔐 DEMO 2: Private Metadata Encryption");
    println!("─────────────────────────────────────────\n");

    let dek = DekKey::generate();
    
    // Create private metadata with sensitive info
    let private_meta = PrivateMetadata::new("/medical/blood_test_results.pdf", 156_789)
        .with_content_type("application/pdf")
        .with_user_metadata("patient_id", "12345678")
        .with_user_metadata("lab", "CityLab Medical Center")
        .with_timestamps(1701388800, 1701475200); // Dec 2023

    println!("Private metadata (plaintext - known only to client):");
    println!("  Original filename:  {}", private_meta.original_key);
    println!("  Actual file size:   {} bytes", private_meta.actual_size);
    println!("  Content type:       {:?}", private_meta.content_type);
    println!("  Patient ID:         {:?}", private_meta.user_metadata.get("patient_id"));
    println!("  Lab:                {:?}", private_meta.user_metadata.get("lab"));
    println!();

    // Encrypt it
    let encrypted = EncryptedPrivateMetadata::encrypt(&private_meta, &dek).unwrap();
    let json = encrypted.to_json().unwrap();

    println!("Encrypted metadata (what server stores):");
    println!("  Version: {}", encrypted.version);
    println!("  Ciphertext length: {} bytes", encrypted.ciphertext.len());
    println!("  JSON representation: {}...", &json[..80.min(json.len())]);
    println!();

    // Decrypt and verify
    let decrypted = encrypted.decrypt(&dek).unwrap();
    println!("Decrypted metadata (client recovers original):");
    println!("  Original filename:  {}", decrypted.original_key);
    println!("  Actual file size:   {} bytes", decrypted.actual_size);
    println!("  Match: {}\n", decrypted.original_key == private_meta.original_key);

    // Wrong key can't decrypt
    let wrong_dek = DekKey::generate();
    let decrypt_result = encrypted.decrypt(&wrong_dek);
    println!("✓ Wrong key cannot decrypt private metadata: {}\n", decrypt_result.is_err());
}

/// Demonstrate what server sees vs what client sees
fn demo_server_sees_vs_client_sees() {
    println!("👁️ DEMO 3: Server View vs. Client View");
    println!("─────────────────────────────────────────\n");

    let _user_keypair = KekKeyPair::generate(); // Owner's key pair (would be used in real scenario)
    let dek = DekKey::generate();
    
    // Simulate a file upload
    let original_filename = "/finances/investment_portfolio_2024.xlsx";
    let original_content = b"Sensitive financial data with account numbers and balances...";
    let original_size = original_content.len();
    let content_type = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet";
    
    // What gets encrypted
    let private_meta = PrivateMetadata::new(original_filename, original_size as u64)
        .with_content_type(content_type);
    let encrypted_meta = EncryptedPrivateMetadata::encrypt(&private_meta, &dek).unwrap();
    
    // Simulated encrypted content (in reality this is AES-GCM ciphertext)
    let ciphertext_size = original_size + 16 + 12; // data + tag + nonce overhead
    let storage_key = obfuscate_key(original_filename, &dek, KeyObfuscation::DeterministicHash);

    println!("┌─────────────────────────────────────────────────────────────┐");
    println!("│                    SERVER'S VIEW (Public)                   │");
    println!("├─────────────────────────────────────────────────────────────┤");
    println!("│ Storage Key:    {}             │", storage_key);
    println!("│ Visible Size:   {} bytes (ciphertext)                     │", ciphertext_size);
    println!("│ Content-Type:   application/octet-stream                    │");
    println!("│ Encrypted Meta: [base64 blob - {} bytes]                  │", encrypted_meta.ciphertext.len());
    println!("│                                                             │");
    println!("│ ❌ Cannot see: filename, real size, content type, content   │");
    println!("└─────────────────────────────────────────────────────────────┘");
    println!();
    
    // Client decrypts and sees
    let decrypted_meta = encrypted_meta.decrypt(&dek).unwrap();
    
    println!("┌─────────────────────────────────────────────────────────────┐");
    println!("│                   CLIENT'S VIEW (Private)                   │");
    println!("├─────────────────────────────────────────────────────────────┤");
    println!("│ Original Name:  {}  │", decrypted_meta.original_key);
    println!("│ Original Size:  {} bytes                                  │", decrypted_meta.actual_size);
    println!("│ Content-Type:   {:?}          │", decrypted_meta.content_type.unwrap_or_default());
    println!("│                                                             │");
    println!("│ ✅ Full access to all original metadata and content         │");
    println!("└─────────────────────────────────────────────────────────────┘");
    println!();

    println!("Summary of what's protected:");
    println!("  ✅ File name:      Hidden (server sees hash)");
    println!("  ✅ File size:      Hidden (server sees ciphertext size)");
    println!("  ✅ Content type:   Hidden (server sees 'application/octet-stream')");
    println!("  ✅ Timestamps:     Hidden (encrypted in private metadata)");
    println!("  ✅ User metadata:  Hidden (encrypted in private metadata)");
    println!("  ✅ File content:   Encrypted (AES-256-GCM)");
    println!();
}
