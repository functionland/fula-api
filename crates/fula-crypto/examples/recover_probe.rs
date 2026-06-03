//! One-block recovery probe (DIAGNOSTIC — not production).
//!
//! Validates that a user's 32-byte root secret derives the correct forest key
//! and decrypts a bucket's encrypted shard-manifest root. This is the
//! make-or-break check before building a full forest reconstructor: if the
//! manifest decrypts, key + derivation + format are all confirmed.
//!
//! The secret is read from an env var (never a file) so it does not get
//! committed. Usage:
//!
//!   # Mode 1 — print the derived index_key (the manifest's object key):
//!   $env:FULA_SECRET_HEX="<64-hex>"; $env:FULA_BUCKET="images"
//!   cargo run -p fula-crypto --example recover_probe
//!
//!   # Mode 2 — also decrypt a fetched manifest block:
//!   #   (look up pin name  object:<bucket>/<index_key>  -> CID, then
//!   #    `ipfs block get <CID> > manifest.bin`)
//!   cargo run -p fula-crypto --example recover_probe -- manifest.bin

use fula_crypto::{derive_index_key, EncryptedShardManifestV7, KeyManager, SecretKey};

fn main() {
    let secret_hex = std::env::var("FULA_SECRET_HEX")
        .expect("set FULA_SECRET_HEX to the 64-hex (32-byte) root secret");
    let bucket = std::env::var("FULA_BUCKET").unwrap_or_else(|_| "images".to_string());

    let secret_bytes = hex::decode(secret_hex.trim()).expect("FULA_SECRET_HEX must be valid hex");
    assert_eq!(
        secret_bytes.len(),
        32,
        "root secret must be exactly 32 bytes (got {})",
        secret_bytes.len()
    );

    let secret = SecretKey::from_bytes(&secret_bytes).expect("invalid X25519 secret key");
    let km = KeyManager::from_secret_key(secret);

    let forest_dek = km.derive_path_key(&format!("forest:{}", bucket));
    let index_key = derive_index_key(&forest_dek, &bucket);

    println!("bucket     = {}", bucket);
    println!("index_key  = {}", index_key);
    println!(
        "  -> look up pin name  object:{}/{}  in the CSV to get the manifest CID,",
        bucket, index_key
    );
    println!("     then:  ipfs block get <that-cid> > manifest.bin");

    // Mode 2: a manifest block file was supplied — decrypt and introspect it.
    if let Some(path) = std::env::args().nth(1) {
        println!("\n--- decrypting manifest block: {} ---", path);
        let blob = std::fs::read(&path).expect("read manifest block file");
        println!("block size = {} bytes", blob.len());
        // Show a small hex preview so a non-JSON wrapper is obvious.
        let preview_len = blob.len().min(48);
        println!("first {} bytes (hex) = {}", preview_len, hex::encode(&blob[..preview_len]));

        let envelope = match EncryptedShardManifestV7::from_bytes(&blob) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("\nFAILED to parse EncryptedShardManifestV7 JSON envelope: {e}");
                eprintln!(
                    "(block may be a UnixFS/dag-pb wrapper or another layer — the hex preview \
                     above will show if it is not JSON; if so we fetch the inner content instead)"
                );
                std::process::exit(2);
            }
        };
        println!("envelope.version  = {}", envelope.version);
        println!("envelope.sequence = {}", envelope.sequence);

        match envelope.decrypt_v7(&forest_dek, &bucket) {
            Ok((root, seq)) => {
                println!("\n[OK] DECRYPT SUCCEEDED — the key is correct for this bucket.");
                println!("manifest.version    = {}", root.version);
                println!("manifest.format     = {}", root.format);
                println!("manifest.num_shards = {}", root.num_shards);
                println!("manifest.shard_salt = {}", hex::encode(&root.shard_salt));
                println!("manifest.seq        = {}", seq);
                println!("page_index entries  = {}", root.page_index.len());
                println!(
                    "dir_index_cid       = {:?}   (Some => walkable-v8 CID hint present)",
                    root.dir_index_cid
                );
                for (pid, pref) in root.page_index.iter() {
                    println!("  page {:?} -> {:?}", pid, pref);
                }
            }
            Err(e) => {
                eprintln!("\n[FAIL] envelope parsed but AEAD decrypt failed: {e}");
                eprintln!("(wrong secret/bucket, or a different DEK derivation than expected)");
                std::process::exit(3);
            }
        }
    }
}
