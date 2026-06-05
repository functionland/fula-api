//! TEMP audio recovery E2E verify harness — NOT COMMITTED (creds from env).
//!
//! COLD client (no block cache, gateway-fallback OFF = server-only) that proves
//! the audio bucket is usable after the server index rebuild: list -> download
//! -> upload -> re-list/roundtrip. Re-running it in a fresh process is the
//! "second cold client" check (persistence + cold-start).
//!
//! Run (PowerShell):
//!   $env:FULA_JWT="<token>"; $env:FULA_KEK_INPUT="google:<sub>:<email>"
//!   cargo run -p fula-client --example audio_e2e
//!   # 2nd cold client (no upload, just verify the prior test file is there):
//!   $env:FULA_E2E_CHECKONLY="1"; cargo run -p fula-client --example audio_e2e

use fula_client::{Config, EncryptedClient, EncryptionConfig};
use fula_crypto::keys::SecretKey;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const TEST_KEY: &str = "e2e-recovery-test/probe.txt";

#[tokio::main]
async fn main() {
    let jwt = std::env::var("FULA_JWT").expect("set FULA_JWT");
    let kek = std::env::var("FULA_KEK_INPUT").expect("set FULA_KEK_INPUT");
    let master = std::env::var("FULA_S3").unwrap_or_else(|_| "https://s3.cloud.fx.land".to_string());
    let checkonly = std::env::var("FULA_E2E_CHECKONLY").is_ok();
    let bucket = "audio";

    let secret_bytes = fula_crypto::hashing::derive_key_argon2id("fula-files-v1", kek.as_bytes());
    let secret = SecretKey::from_bytes(&secret_bytes).expect("secret");

    // COLD client: fresh process, no block cache, server-only (no gateway bypass)
    // — this proves the rebuilt SERVER index actually serves the bucket.
    let cache_dir = std::env::temp_dir().join(format!("fula-audioe2e-{}", std::process::id()));
    std::fs::create_dir_all(&cache_dir).ok();
    let mut cfg = Config::new(master.as_str()).with_token(jwt.clone());
    cfg.timeout = Duration::from_secs(120);
    cfg.health_gate_enabled = false;
    cfg.block_cache_enabled = false; // COLD
    cfg.gateway_fallback_enabled = false; // server-only
    let client = EncryptedClient::new(cfg, EncryptionConfig::from_secret_key(secret)).expect("client");

    // ---- LIST ----
    let t = Instant::now();
    let listing = match client.list_directory(bucket, None).await {
        Ok(l) => l,
        Err(e) => {
            println!("[FAIL] list: {}", e);
            std::process::exit(1);
        }
    };
    let mut files: Vec<(String, String, u64)> = Vec::new();
    for (_d, items) in listing.directories.iter() {
        for f in items {
            files.push((f.original_key.clone(), f.storage_key.clone(), f.original_size));
        }
    }
    println!("[OK] list in {:.1?} — {} files", t.elapsed(), files.len());

    // ---- DOWNLOAD smallest real file (verify size) ----
    if let Some((name, key, size)) = files
        .iter()
        .filter(|(n, _, _)| n != TEST_KEY)
        .min_by_key(|(_, _, s)| *s)
    {
        let td = Instant::now();
        match client.get_object_flat(bucket, key).await {
            Ok(b) => {
                let ok = b.len() as u64 == *size;
                println!(
                    "[{}] download '{}' {} B in {:.1?} (expected {})",
                    if ok { "OK" } else { "WARN" },
                    name,
                    b.len(),
                    td.elapsed(),
                    size
                );
            }
            Err(e) => println!(
                "[FAIL] download '{}': {}",
                name,
                e.to_string().chars().take(160).collect::<String>()
            ),
        }
    }

    // ---- CHECK prior test file (2nd-client / persistence proof) ----
    if let Some((_, key, _)) = files.iter().find(|(n, _, _)| n == TEST_KEY) {
        match client.get_object_flat(bucket, key).await {
            Ok(b) => println!(
                "[OK] prior test file present + downloads ({} B): {}",
                b.len(),
                String::from_utf8_lossy(&b).chars().take(60).collect::<String>()
            ),
            Err(e) => println!("[FAIL] prior test file download: {}", e),
        }
    } else {
        println!("[info] no prior test file yet");
    }

    if checkonly {
        println!("CHECKONLY done");
        return;
    }

    // ---- UPLOAD a test file (proves write + flush post-recovery) ----
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let content = format!("fula-audio-recovery-e2e ts={}\n", ts);
    let tu = Instant::now();
    match client
        .put_object_flat(bucket, TEST_KEY, content.clone().into_bytes(), Some("text/plain"))
        .await
    {
        Ok(_) => println!("[OK] upload '{}' in {:.1?}", TEST_KEY, tu.elapsed()),
        Err(e) => {
            println!("[FAIL] upload: {}", e);
            std::process::exit(1);
        }
    }

    // ---- RE-LIST + roundtrip verify ----
    match client.list_directory(bucket, None).await {
        Ok(l) => {
            let mut found = None;
            for (_d, items) in l.directories.iter() {
                for f in items {
                    if f.original_key == TEST_KEY {
                        found = Some(f.storage_key.clone());
                    }
                }
            }
            match found {
                Some(sk) => match client.get_object_flat(bucket, &sk).await {
                    Ok(b) => println!(
                        "[{}] roundtrip: uploaded file re-listed + downloaded, content match = {}",
                        if b == content.as_bytes() { "OK" } else { "WARN" },
                        b == content.as_bytes()
                    ),
                    Err(e) => println!("[FAIL] roundtrip download: {}", e),
                },
                None => println!("[FAIL] roundtrip: uploaded file not found in re-list"),
            }
        }
        Err(e) => println!("[FAIL] re-list: {}", e),
    }
    println!("VERIFY done");
}
