//! TEMP online-vs-offline download comparison. NOT COMMITTED (reads creds from env).
//!
//! For each of the N smallest videos, downloads it ONLINE (real master) and
//! OFFLINE (bogus master => master-unreachable => offline-fallback / gateway race),
//! sharing ONE on-disk block cache (warmed by an initial online list), and prints
//! both outcomes side by side. This is the apples-to-apples test the user asked for.
//!
//! Run (PowerShell):
//!   $env:FULA_JWT="<token>"; $env:FULA_KEK_INPUT="google:<sub>:<email>"
//!   cargo run -p fula-client --example videos_download_e2e

use fula_client::{Config, EncryptedClient, EncryptionConfig};
use fula_crypto::keys::SecretKey;
use std::time::Duration;

fn build(master: &str, jwt: &str, cache: &std::path::Path, secret: SecretKey, health_gate: bool) -> EncryptedClient {
    let mut cfg = Config::new(master).with_token(jwt.to_string());
    cfg.timeout = Duration::from_secs(60);
    cfg.health_gate_enabled = health_gate;
    cfg.health_gate_ttl = Duration::from_secs(30);
    cfg.block_cache_enabled = true;
    cfg.block_cache_path = Some(cache.to_path_buf());
    cfg.block_cache_max_bytes = 512 * 1024 * 1024;
    cfg.gateway_fallback_enabled = true;
    cfg.gateway_fallback_urls = Vec::new(); // SDK default public gateways
    cfg.gateway_race_concurrency = 3;
    EncryptedClient::new(cfg, EncryptionConfig::from_secret_key(secret)).expect("client build")
}

fn cat(r: &Result<bytes::Bytes, fula_client::ClientError>) -> String {
    match r {
        Ok(b) => format!("OK {}B", b.len()),
        Err(e) => {
            let m = e.to_string();
            if m.contains("NoSuchKey") { "FAIL NoSuchKey".into() }
            else if m.contains("aead") || m.contains("decryption failed") { "FAIL aead".into() }
            else if m.to_lowercase().contains("unreachable") || m.contains("MasterUnreachable") { "FAIL master-unreachable".into() }
            else if m.contains("Gone") || m.contains("unavailable") { "FAIL 410-gone".into() }
            else { format!("FAIL {}", m.chars().take(48).collect::<String>()) }
        }
    }
}

#[tokio::main]
async fn main() {
    let jwt = std::env::var("FULA_JWT").expect("set FULA_JWT");
    let kek = std::env::var("FULA_KEK_INPUT").expect("set FULA_KEK_INPUT");
    let bucket = std::env::var("FULA_BUCKET").unwrap_or_else(|_| "videos".to_string());
    let master = std::env::var("FULA_S3").unwrap_or_else(|_| "https://s3.cloud.fx.land".to_string());
    let n: usize = std::env::var("FULA_N").ok().and_then(|s| s.parse().ok()).unwrap_or(5);

    let secret_bytes = fula_crypto::hashing::derive_key_argon2id("fula-files-v1", kek.as_bytes());
    let secret = SecretKey::from_bytes(&secret_bytes).expect("secret");

    let cache_dir = std::env::temp_dir().join(format!("fula-cmp-{}", std::process::id()));
    std::fs::create_dir_all(&cache_dir).ok();
    let cache_path = cache_dir.join("blocks.redb");

    let online = build(&master, &jwt, &cache_path, secret.clone(), true);

    println!("[cmp] warming forest cache via online list ...");
    let listing = online.list_directory(&bucket, None).await.expect("online list_directory");
    let mut files: Vec<(String, String, u64)> = Vec::new();
    for (_d, items) in listing.directories.iter() {
        for f in items { files.push((f.storage_key.clone(), f.original_key.clone(), f.original_size)); }
    }
    files.sort_by_key(|(_, _, s)| *s);
    let sample: Vec<_> = files.into_iter().take(n).collect();
    println!("[cmp] {} files; comparing the {} smallest\n", sample.len(), n);

    // Offline client: bogus unreachable master, SAME on-disk cache, health gate off
    // so the first call immediately treats master as down.
    let offline = build("http://127.0.0.1:1", &jwt, &cache_path, secret.clone(), false);
    match offline.list_directory(&bucket, None).await {
        Ok(_) => println!("[cmp] offline forest load from cache: OK\n"),
        Err(e) => println!("[cmp] offline forest load from cache: FAIL ({})\n", e),
    }

    println!("[cmp] {:<46}  {:<22} | {:<22}", "file", "ONLINE", "OFFLINE");
    for (sk, key, size) in &sample {
        let on = cat(&online.get_object_flat(&bucket, key).await);
        let off = cat(&offline.get_object_flat(&bucket, key).await);
        let name: String = key.chars().rev().take(44).collect::<String>().chars().rev().collect();
        println!("[cmp] {:<46}  {:<22} | {:<22}   sk={}", name, on, off, &sk[..sk.len().min(12)]);
    }
}
