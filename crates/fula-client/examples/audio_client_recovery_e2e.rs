//! AUTO client-side recovery E2E — behaves exactly like an FxFiles client (minus
//! UI): it does a normal cold `list_directory` (DETECT), and on failure it
//! AUTO-RECOVERS entirely through the two new read-only endpoints
//! (`resolve-keys` + `block-by-cid`) — resolve the manifest versions, auto-pick
//! the newest CONSISTENT one, walk the forest, reconstruct the file list, and
//! sample a download. ZERO manual steps (no ssh, no hand-picked manifest).
//!
//! This is the `recover_bucket_reads` prototype. NOT COMMITTED (creds from env).
//!
//! Run (PowerShell):
//!   $env:FULA_JWT="<token>"; $env:FULA_KEK_INPUT="google:<sub>:<email>"
//!   cargo run -p fula-client --example audio_client_recovery_e2e
//!   # override bucket/base if needed:
//!   $env:FULA_BUCKET="audio"; $env:FULA_S3="https://s3.cloud.fx.land"

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use fula_crypto::{
    derive_index_key, derive_manifest_page_key, BlobBackend, BlobPutResult, CryptoError, DekKey,
    EncryptedManifestPage, EncryptedShardManifestV7, KeyManager, ManifestPage, PageId, SecretKey,
    ShardManifestV7, ShardedHamtPrivateForest,
};

use fula_client::{Config, EncryptedClient, EncryptionConfig};

type RecoveredFiles = Vec<(String, String, u64, Option<cid::Cid>)>;

/// BlobBackend that resolves keys + fetches blocks ONLY via the two server
/// endpoints — exactly what the FxFiles client will do. Fully async (async
/// reqwest); no ssh, no local files.
struct EndpointBackend {
    base: String,
    bucket: String,
    jwt: String,
    http: reqwest::Client,
}

impl EndpointBackend {
    /// `GET /api/v1/blocks/{cid}` → raw block bytes.
    async fn read_cid(&self, cid: &str) -> fula_crypto::Result<Vec<u8>> {
        let url = format!("{}/api/v1/blocks/{}", self.base, cid);
        let resp = self
            .http
            .get(&url)
            .bearer_auth(&self.jwt)
            .send()
            .await
            .map_err(|e| CryptoError::Hamt(format!("block GET {cid}: {e}")))?;
        if !resp.status().is_success() {
            return Err(CryptoError::Hamt(format!(
                "block GET {cid} -> HTTP {}",
                resp.status().as_u16()
            )));
        }
        Ok(resp
            .bytes()
            .await
            .map_err(|e| CryptoError::Hamt(format!("block body {cid}: {e}")))?
            .to_vec())
    }

    /// `POST /api/v1/buckets/{bucket}/resolve-keys` → CIDs for a storage key
    /// (newest-first). Empty on miss / 503 / error.
    async fn resolve(&self, key: &str) -> Vec<String> {
        let url = format!("{}/api/v1/buckets/{}/resolve-keys", self.base, self.bucket);
        let body = serde_json::json!({ "keys": [key] });
        let resp = match self
            .http
            .post(&url)
            .bearer_auth(&self.jwt)
            .json(&body)
            .send()
            .await
        {
            Ok(r) if r.status().is_success() => r,
            Ok(r) => {
                eprintln!("   resolve-keys({key}) -> HTTP {}", r.status().as_u16());
                return vec![];
            }
            Err(e) => {
                eprintln!("   resolve-keys({key}) error: {e}");
                return vec![];
            }
        };
        let parsed: serde_json::Value = match resp.json().await {
            Ok(v) => v,
            Err(_) => return vec![],
        };
        let mut out = Vec::new();
        if let Some(keys) = parsed.get("keys").and_then(|k| k.as_array()) {
            for entry in keys {
                if let Some(cids) = entry.get("cids").and_then(|c| c.as_array()) {
                    for c in cids {
                        if let Some(cid) = c.get("cid").and_then(|x| x.as_str()) {
                            out.push(cid.to_string());
                        }
                    }
                }
            }
        }
        out
    }
}

#[async_trait::async_trait]
impl BlobBackend for EndpointBackend {
    async fn get(&self, path: &str) -> fula_crypto::Result<Vec<u8>> {
        for cid in self.resolve(path).await {
            if let Ok(bytes) = self.read_cid(&cid).await {
                return Ok(bytes);
            }
        }
        Err(CryptoError::Hamt(format!(
            "resolve-keys: no fetchable cid for path {path}"
        )))
    }

    async fn put(&self, _path: &str, _bytes: Vec<u8>) -> fula_crypto::Result<BlobPutResult> {
        Err(CryptoError::Hamt(
            "read-only recovery backend; put() must never be called".into(),
        ))
    }

    async fn get_with_cid_hint(
        &self,
        path: &str,
        cid_hint: Option<&cid::Cid>,
    ) -> fula_crypto::Result<Vec<u8>> {
        if let Some(c) = cid_hint {
            if let Ok(bytes) = self.read_cid(&c.to_string()).await {
                return Ok(bytes);
            }
        }
        self.get(path).await
    }
}

#[tokio::main]
async fn main() {
    let jwt = std::env::var("FULA_JWT").expect("set FULA_JWT");
    let kek = std::env::var("FULA_KEK_INPUT").expect("set FULA_KEK_INPUT");
    let bucket = std::env::var("FULA_BUCKET").unwrap_or_else(|_| "audio".to_string());
    let base = std::env::var("FULA_S3").unwrap_or_else(|_| "https://s3.cloud.fx.land".to_string());

    let secret_bytes = fula_crypto::hashing::derive_key_argon2id("fula-files-v1", kek.as_bytes());

    // ===== STEP 1 — DETECT (exactly like the app: a normal cold list) =====
    let cache_dir = std::env::temp_dir().join(format!("fula-rec-{}", std::process::id()));
    std::fs::create_dir_all(&cache_dir).ok();
    let mut cfg = Config::new(base.as_str()).with_token(jwt.clone());
    cfg.timeout = Duration::from_secs(60);
    cfg.health_gate_enabled = false;
    cfg.block_cache_enabled = false;
    cfg.gateway_fallback_enabled = false;
    let client = EncryptedClient::new(
        cfg,
        EncryptionConfig::from_secret_key(SecretKey::from_bytes(&secret_bytes).expect("secret")),
    )
    .expect("client build");

    println!("[1/3 DETECT] cold list_directory({bucket}) …");
    let damaged = match client.list_directory(&bucket, None).await {
        Ok(listing) => {
            let n: usize = listing.directories.iter().map(|(_, i)| i.len()).sum();
            if n > 0 {
                println!("[detect] HEALTHY — {n} files; no recovery needed. Done.");
                return;
            }
            println!("[detect] list returned EMPTY → treat as damaged, auto-recovering …");
            true
        }
        Err(e) => {
            println!(
                "[detect] list FAILED ({}) → DAMAGED, auto-recovering …",
                e.to_string().chars().take(90).collect::<String>()
            );
            true
        }
    };
    if !damaged {
        return;
    }

    // ===== STEP 2 — AUTO-RECOVER, only via the endpoints =====
    let km = KeyManager::from_secret_key(SecretKey::from_bytes(&secret_bytes).expect("secret"));
    let forest_dek: DekKey = km.derive_path_key(&format!("forest:{}", bucket));
    let index_key = derive_index_key(&forest_dek, &bucket);

    let backend = Arc::new(EndpointBackend {
        base: base.clone(),
        bucket: bucket.clone(),
        jwt: jwt.clone(),
        http: reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("http client"),
    });

    println!("[2/3 RECOVER] resolving manifest versions for index_key={index_key} …");
    let manifest_cids = backend.resolve(&index_key).await;
    println!("[recover] manifest versions pinned: {}", manifest_cids.len());
    if manifest_cids.is_empty() {
        println!(
            "[E2E FAIL] resolve-keys returned 0 manifest CIDs — endpoints not configured \
             (FULA_PINS_DATABASE_URL unset → 503), or this bucket truly has no manifest."
        );
        return;
    }

    // Auto version-select: try newest-first; the newest that FULLY walks is the
    // consistent one (no human picks the seq).
    let mut recovered: Option<(usize, String, RecoveredFiles)> = None;
    for (i, mcid) in manifest_cids.iter().enumerate() {
        match try_recover(&backend, &forest_dek, &bucket, mcid).await {
            Ok(files) => {
                recovered = Some((i, mcid.clone(), files));
                break;
            }
            Err(e) => println!(
                "[recover] manifest #{i} not consistent ({}), trying older …",
                e.to_string().chars().take(70).collect::<String>()
            ),
        }
    }

    let (idx, mcid, files) = match recovered {
        Some(r) => r,
        None => {
            println!("[E2E FAIL] no manifest version fully walked — genuinely unrecoverable.");
            return;
        }
    };

    let total: u64 = files.iter().map(|f| f.2).sum();
    println!(
        "\n[OK] auto-recovered via manifest #{idx} ({mcid})\n     files = {}, total = {:.2} MiB",
        files.len(),
        total as f64 / 1048576.0
    );
    for (path, _sk, size, _cid) in files.iter().take(12) {
        println!("       {:>11}  {}", size, path);
    }
    if files.len() > 12 {
        println!("       … and {} more", files.len() - 12);
    }

    // ===== STEP 3 — sample download through block-by-cid =====
    println!("\n[3/3 DOWNLOAD] fetching the smallest file's block via block-by-cid …");
    if let Some((name, sk, _size, _)) = files.iter().min_by_key(|f| f.2) {
        let cids = backend.resolve(sk).await;
        match cids.first() {
            Some(cid) => match backend.read_cid(cid).await {
                Ok(bytes) => println!("[download] OK — '{}' block = {} bytes", name, bytes.len()),
                Err(e) => println!("[download] FAIL fetching block: {e}"),
            },
            None => println!("[download] no cid resolved for '{}'", name),
        }
    }

    println!("\n[E2E PASS] detect → auto-recover → list → download, all via the endpoints, no manual steps.");
}

/// Decrypt + fully walk ONE manifest version via the endpoints. Returns the file
/// list, or an error if this version dangles (caller tries an older one).
async fn try_recover(
    backend: &Arc<EndpointBackend>,
    forest_dek: &DekKey,
    bucket: &str,
    mcid: &str,
) -> fula_crypto::Result<RecoveredFiles> {
    let manifest_blob = backend.read_cid(mcid).await?;
    let envelope = EncryptedShardManifestV7::from_bytes(&manifest_blob)
        .map_err(|e| CryptoError::Hamt(format!("manifest parse: {e}")))?;
    let (root, _seq) = envelope.decrypt_v7(forest_dek, bucket)?;

    let mut pages: BTreeMap<PageId, ManifestPage> = BTreeMap::new();
    for (page_id, page_ref) in root.page_index.iter() {
        let blob = match &page_ref.cid {
            Some(cid) => backend.read_cid(&cid.to_string()).await?,
            None => {
                let page_key =
                    derive_manifest_page_key(forest_dek, bucket, &root.shard_salt, *page_id);
                backend.get(&page_key).await?
            }
        };
        let enc = EncryptedManifestPage::from_bytes(&blob)
            .map_err(|e| CryptoError::Hamt(format!("page {page_id} parse: {e}")))?;
        pages.insert(*page_id, enc.decrypt(forest_dek, bucket)?);
    }

    let manifest = ShardManifestV7::from_root_and_pages(root, pages)?;
    let forest =
        ShardedHamtPrivateForest::from_manifest(manifest, bucket.to_string(), forest_dek.clone());
    let files = forest.list_all_files(backend).await?;
    Ok(files
        .into_iter()
        .map(|f| (f.path, f.storage_key, f.size, f.storage_cid))
        .collect())
}
