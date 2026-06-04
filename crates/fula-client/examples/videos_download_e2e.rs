//! TEMP download diagnostic. NOT COMMITTED (reads creds from env; deleted after run).
//!
//! Downloads the smallest N videos ONLINE and categorizes each outcome so we can
//! see the failure-mode breakdown after the download-path recovery change:
//!   OK         — recovered + decrypted (size match)
//!   NoSuchKey  — a 404 propagated (object/chunk has NO cid-hint => unrecoverable
//!                client-side, i.e. a pre-walkable-v8 upload)
//!   aead       — bytes fetched but AEAD decrypt failed (deeper issue)
//!   other      — anything else
//!
//! Run (PowerShell):
//!   $env:FULA_JWT="<token>"; $env:FULA_KEK_INPUT="google:<sub>:<email>"
//!   cargo run -p fula-client --example videos_download_e2e

use fula_client::{Config, EncryptedClient, EncryptionConfig};
use fula_crypto::keys::SecretKey;
use std::time::Duration;

#[tokio::main]
async fn main() {
    let jwt = std::env::var("FULA_JWT").expect("set FULA_JWT");
    let kek_input =
        std::env::var("FULA_KEK_INPUT").expect("set FULA_KEK_INPUT, e.g. google:<sub>:<email>");
    let bucket = std::env::var("FULA_BUCKET").unwrap_or_else(|_| "videos".to_string());
    let master =
        std::env::var("FULA_S3").unwrap_or_else(|_| "https://s3.cloud.fx.land".to_string());
    let n: usize = std::env::var("FULA_N")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(8);

    let secret_bytes =
        fula_crypto::hashing::derive_key_argon2id("fula-files-v1", kek_input.as_bytes());
    let secret = SecretKey::from_bytes(&secret_bytes).expect("invalid secret key bytes");

    let cache_dir = std::env::temp_dir().join(format!("fula-dl-e2e-{}", std::process::id()));
    let mut cfg = Config::new(&master).with_token(jwt);
    cfg.timeout = Duration::from_secs(180);
    cfg.health_gate_enabled = true;
    cfg.health_gate_ttl = Duration::from_secs(30);
    cfg.block_cache_enabled = true;
    cfg.block_cache_path = Some(cache_dir);
    cfg.block_cache_max_bytes = 256 * 1024 * 1024;
    cfg.gateway_fallback_enabled = true;
    cfg.gateway_fallback_urls = Vec::new();
    cfg.gateway_race_concurrency = 3;
    let enc = EncryptionConfig::from_secret_key(secret);
    let client = EncryptedClient::new(cfg, enc).expect("EncryptedClient construction");

    println!("[dl-e2e] listing {bucket} ...");
    let listing = client.list_directory(&bucket, None).await.expect("list_directory");
    let mut files: Vec<(String, String, u64)> = Vec::new(); // (storage_key, original_key, size)
    for (_dir, items) in listing.directories.iter() {
        for f in items {
            files.push((f.storage_key.clone(), f.original_key.clone(), f.original_size));
        }
    }
    files.sort_by_key(|(_, _, size)| *size);
    let sample: Vec<_> = files.iter().take(n).cloned().collect();
    println!(
        "[dl-e2e] {} files listed; downloading the {} smallest ONLINE\n",
        files.len(),
        sample.len()
    );

    let (mut ok, mut nokey, mut aead, mut other) = (0u32, 0u32, 0u32, 0u32);
    for (sk, key, size) in &sample {
        let skp = &sk[..sk.len().min(14)];
        print!("[dl-e2e] {key:?}  (sk={skp}..., {size} B) ... ");
        match client.get_object_flat(&bucket, key).await {
            Ok(bytes) => {
                println!("OK ({} B, match={})", bytes.len(), bytes.len() as u64 == *size);
                ok += 1;
            }
            Err(e) => {
                let m = e.to_string();
                let cat = if m.contains("NoSuchKey") {
                    nokey += 1;
                    "NoSuchKey (no cid-hint => unrecoverable)"
                } else if m.contains("aead") || m.contains("decryption failed") {
                    aead += 1;
                    "aead (decrypt failed)"
                } else {
                    other += 1;
                    "other"
                };
                println!("FAIL [{cat}]: {m}");
            }
        }
    }

    println!(
        "\n[dl-e2e] breakdown of {} downloads: OK={ok}  NoSuchKey={nokey}  aead={aead}  other={other}",
        sample.len()
    );
}
