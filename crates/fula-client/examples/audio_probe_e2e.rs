//! TEMP audio-bucket client-side probe — NOT COMMITTED (creds from env).
//!
//! Times the SDK's forest walk (list_directory) + a download for `audio` and
//! `other`, with full errors. The walk IS the "reconstruct" half of the
//! on-demand client fix — if it returns entries, the client has what it needs
//! to push to the server. Read-only; pushes nothing.
//!
//! Run (PowerShell):
//!   $env:FULA_JWT="<token>"; $env:FULA_KEK_INPUT="google:<sub>:<email>"
//!   cargo run -p fula-client --example audio_probe_e2e

use fula_client::{Config, EncryptedClient, EncryptionConfig};
use fula_crypto::keys::SecretKey;
use std::time::{Duration, Instant};

#[tokio::main]
async fn main() {
    let jwt = std::env::var("FULA_JWT").expect("set FULA_JWT");
    let kek = std::env::var("FULA_KEK_INPUT").expect("set FULA_KEK_INPUT");
    let master = std::env::var("FULA_S3").unwrap_or_else(|_| "https://s3.cloud.fx.land".to_string());

    let secret_bytes = fula_crypto::hashing::derive_key_argon2id("fula-files-v1", kek.as_bytes());
    let secret = SecretKey::from_bytes(&secret_bytes).expect("secret");

    let cache_dir = std::env::temp_dir().join(format!("fula-audio-{}", std::process::id()));
    std::fs::create_dir_all(&cache_dir).ok();

    let mut cfg = Config::new(master.as_str()).with_token(jwt.clone());
    cfg.timeout = Duration::from_secs(120);
    cfg.health_gate_enabled = false; // raw behavior, don't trip the global gate
    cfg.block_cache_enabled = true;
    cfg.block_cache_path = Some(cache_dir.join("blocks.redb"));
    cfg.block_cache_max_bytes = 256 * 1024 * 1024;
    cfg.gateway_fallback_enabled = true;
    cfg.gateway_fallback_urls = Vec::new(); // SDK default public gateways
    cfg.gateway_race_concurrency = 3;
    let client = EncryptedClient::new(cfg, EncryptionConfig::from_secret_key(secret))
        .expect("client build");

    for bucket in ["audio"] {
        let t = Instant::now();
        match client.list_directory(bucket, None).await {
            Ok(listing) => {
                let mut files: Vec<(String, String, u64)> = Vec::new();
                for (_d, items) in listing.directories.iter() {
                    for f in items {
                        files.push((f.original_key.clone(), f.storage_key.clone(), f.original_size));
                    }
                }
                println!(
                    "\n[{}] LIST ok in {:.1?} — {} dirs, {} files",
                    bucket, t.elapsed(), listing.directories.len(), files.len()
                );
                for (name, sk, size) in files.iter().take(12) {
                    println!("    {}  ({} B)  sk={}", name, size, &sk[..sk.len().min(16)]);
                }
                if let Some((name, key, _)) = files.iter().min_by_key(|(_, _, s)| *s) {
                    let td = Instant::now();
                    match client.get_object_flat(bucket, key).await {
                        Ok(b) => println!("    DOWNLOAD smallest '{}' OK {} B in {:.1?}", name, b.len(), td.elapsed()),
                        Err(e) => println!("    DOWNLOAD smallest '{}' FAIL in {:.1?} — {}", name, td.elapsed(),
                            e.to_string().chars().take(120).collect::<String>()),
                    }
                }
            }
            Err(e) => println!("\n[{}] LIST FAIL in {:.1?} — {}", bucket, t.elapsed(), e),
        }
    }
}
