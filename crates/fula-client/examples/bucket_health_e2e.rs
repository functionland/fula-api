//! TEMP bucket-health probe — NOT COMMITTED (reads creds from env).
//!
//! Enumerates every bucket the user owns and runs `list_directory` on each,
//! WITHOUT any server-side index repair, to see which buckets the client-side
//! recovery (#24 forest-walk) can list on its own — and the exact error on the
//! ones it can't. This grounds the "does the app actually self-heal listing?"
//! question that the healing plan depends on.
//!
//! Run (PowerShell):
//!   $env:FULA_JWT="<token>"; $env:FULA_KEK_INPUT="google:<sub>:<email>"
//!   cargo run -p fula-client --example bucket_health_e2e

use fula_client::{Config, EncryptedClient, EncryptionConfig};
use fula_crypto::keys::SecretKey;
use std::time::Duration;

#[tokio::main]
async fn main() {
    let jwt = std::env::var("FULA_JWT").expect("set FULA_JWT");
    let kek = std::env::var("FULA_KEK_INPUT").expect("set FULA_KEK_INPUT");
    let master = std::env::var("FULA_S3").unwrap_or_else(|_| "https://s3.cloud.fx.land".to_string());

    let secret_bytes = fula_crypto::hashing::derive_key_argon2id("fula-files-v1", kek.as_bytes());
    let secret = SecretKey::from_bytes(&secret_bytes).expect("secret");

    let cache_dir = std::env::temp_dir().join(format!("fula-bh-{}", std::process::id()));
    std::fs::create_dir_all(&cache_dir).ok();

    let mut cfg = Config::new(master.as_str()).with_token(jwt.clone());
    cfg.timeout = Duration::from_secs(60);
    cfg.health_gate_enabled = true;
    cfg.health_gate_ttl = Duration::from_secs(30);
    cfg.block_cache_enabled = true;
    cfg.block_cache_path = Some(cache_dir.join("blocks.redb"));
    cfg.block_cache_max_bytes = 256 * 1024 * 1024;
    cfg.gateway_fallback_enabled = true;
    cfg.gateway_fallback_urls = Vec::new(); // SDK default public gateways
    cfg.gateway_race_concurrency = 3;
    let client = EncryptedClient::new(cfg, EncryptionConfig::from_secret_key(secret))
        .expect("client build");

    let res = client.list_buckets().await.expect("list_buckets");
    println!("[bh] owner={} buckets={}\n", res.owner_id, res.buckets.len());

    for b in &res.buckets {
        let r = match client.list_directory(&b.name, None).await {
            Ok(listing) => {
                let files: usize = listing.directories.iter().map(|(_, items)| items.len()).sum();
                format!("OK   dirs={} files={}", listing.directories.len(), files)
            }
            Err(e) => format!("FAIL {}", e.to_string().chars().take(110).collect::<String>()),
        };
        println!("[bh] {:<42} {}", b.name, r);
    }
}
