//! TEMP forest-diagnostic probe — NOT COMMITTED (creds from env).
//!
//! Answers "does this bucket genuinely have no files, or does it have content
//! the walk can't reach?" by loading the forest manifest (cached even when the
//! page walk fails) and reading sharded_forest_diagnostic.
//!
//! Run (PowerShell):
//!   $env:FULA_JWT="<token>"; $env:FULA_KEK_INPUT="google:<sub>:<email>"; $env:FULA_BUCKET="documents"
//!   cargo run -p fula-client --example forest_diag_e2e --features test-fault-injection

use fula_client::{Config, EncryptedClient, EncryptionConfig};
use fula_crypto::keys::SecretKey;
use std::time::Duration;

#[tokio::main]
async fn main() {
    let jwt = std::env::var("FULA_JWT").expect("set FULA_JWT");
    let kek = std::env::var("FULA_KEK_INPUT").expect("set FULA_KEK_INPUT");
    let bucket = std::env::var("FULA_BUCKET").unwrap_or_else(|_| "documents".to_string());
    let master = std::env::var("FULA_S3").unwrap_or_else(|_| "https://s3.cloud.fx.land".to_string());

    let secret_bytes = fula_crypto::hashing::derive_key_argon2id("fula-files-v1", kek.as_bytes());
    let secret = SecretKey::from_bytes(&secret_bytes).expect("secret");

    let cache_dir = std::env::temp_dir().join(format!("fula-diag-{}", std::process::id()));
    std::fs::create_dir_all(&cache_dir).ok();

    let mut cfg = Config::new(master.as_str()).with_token(jwt.clone());
    cfg.timeout = Duration::from_secs(120);
    cfg.health_gate_enabled = false;
    cfg.block_cache_enabled = true;
    cfg.block_cache_path = Some(cache_dir.join("blocks.redb"));
    cfg.block_cache_max_bytes = 256 * 1024 * 1024;
    cfg.gateway_fallback_enabled = true;
    cfg.gateway_fallback_urls = Vec::new();
    cfg.gateway_race_concurrency = 3;
    let client = EncryptedClient::new(cfg, EncryptionConfig::from_secret_key(secret))
        .expect("client build");

    println!("== list_directory({}) ==", bucket);
    match client.list_directory(&bucket, None).await {
        Ok(listing) => {
            let files: usize = listing.directories.iter().map(|(_, i)| i.len()).sum();
            println!("  OK: {} dirs, {} files", listing.directories.len(), files);
            for (_d, items) in listing.directories.iter() {
                for f in items.iter().take(10) {
                    println!("    {} ({} B)", f.original_key, f.original_size);
                }
            }
        }
        Err(e) => println!("  FAIL: {}", e),
    }

    println!("== sharded_forest_diagnostic({}) ==", bucket);
    match client.sharded_forest_diagnostic(&bucket) {
        Some(d) => println!(
            "  total_shards={}  shards_with_root={}  page_count={}  manifest_seq={:?}  dir_index_seq={:?}",
            d.total_shards, d.shards_with_root, d.page_count, d.manifest_sequence, d.dir_index_seq
        ),
        None => println!("  forest NOT loaded as v7 sharded (None) — manifest didn't cache"),
    }
}
