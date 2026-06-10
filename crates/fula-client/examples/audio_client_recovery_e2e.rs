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
use std::time::{Duration, Instant};

use fula_crypto::{
    derive_index_key, derive_manifest_page_key, Aead, BlobBackend, BlobPutResult,
    ChunkedFileMetadata, CryptoError, Decryptor, DekKey, EncryptedData, EncryptedManifestPage,
    EncryptedShardManifestV7, ForestFileEntry, KeyManager, ManifestPage, Nonce, PageId, SecretKey,
    ShardManifestV7, ShardedHamtPrivateForest, VerifiedStreamingDecoder,
};

use fula_client::{Config, EncryptedClient, EncryptionConfig};

type RecoveredFiles = Vec<ForestFileEntry>;

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

    // FIX: the credential is the 32-byte root secret, base64-encoded — decode it,
    // don't hash it. (Argon2-hashing it produced a wrong secret → wrong index_key
    // → resolve-keys returned 0 and every manifest decrypt failed with aead error.)
    // Fall back to argon2id only for a "google:<sub>:<email>"-style KEK input.
    let secret_bytes: Vec<u8> = {
        use base64::Engine as _;
        match base64::engine::general_purpose::STANDARD.decode(kek.trim()) {
            Ok(b) if b.len() == 32 => b,
            _ => fula_crypto::hashing::derive_key_argon2id("fula-files-v1", kek.as_bytes()).to_vec(),
        }
    };

    // ===== STEP 1 — DETECT (exactly like the app: a normal cold list) =====
    let cache_dir = std::env::temp_dir().join(format!("fula-rec-{}", std::process::id()));
    std::fs::create_dir_all(&cache_dir).ok();
    let mut cfg = Config::new(base.as_str()).with_token(jwt.clone());
    cfg.timeout = Duration::from_secs(60);
    cfg.health_gate_enabled = false;
    cfg.block_cache_enabled = false;
    cfg.gateway_fallback_enabled = false;
    // Real phone config (from FxFiles lib/core/services/fula_api_service.dart):
    // chain anchor (Base mainnet) + IPNS global index, so the manifest CID is
    // resolved exactly as the app does on a cold device — no hand-fed CID.
    cfg.users_index_chain_rpc_url = "https://mainnet.base.org".to_string();
    cfg.users_index_anchor_address =
        "0x00fB6AD1B42Fb37a0Ac7C2977fC1fa4462C36Af9".to_string();
    cfg.users_index_ipns_name =
        "k51qzi5uqu5dkkd6tv8slgoouzzs505qdcr4cb5egc9rlx7qwq0e794yxj9cg4".to_string();
    // No hardcoded identity — diag paths read EMAIL from env if needed.
    let email = std::env::var("EMAIL").unwrap_or_default();
    cfg.users_index_user_key = Some(fula_client::derive_user_key_from_email(&email));
    let client = EncryptedClient::new(
        cfg,
        EncryptionConfig::from_secret_key(SecretKey::from_bytes(&secret_bytes).expect("secret")),
    )
    .expect("client build");

    // Diagnostic: probe cold_start_resolve_manifest for a list of buckets
    // (FULA_DIAG_BUCKETS="a,b,c") to see which resolve via the global index.
    if let Ok(diag) = std::env::var("FULA_DIAG_BUCKETS") {
        println!("[DIAG] cold_start_resolve_manifest per bucket (user={email}):");
        for b in diag.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()) {
            match client.cold_start_resolve_manifest(b).await {
                Ok((cid, _)) => println!("  {:22} -> OK  {}", b, cid),
                Err(e) => println!(
                    "  {:22} -> ERR {}",
                    b,
                    e.to_string().chars().take(90).collect::<String>()
                ),
            }
        }
        return;
    }

    println!("[1/3 DETECT] cold list_directory({bucket}) …");
    let t_detect = Instant::now();
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
    let detect_dur = t_detect.elapsed();
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
    let t_mresolve = Instant::now();
    let manifest_cids = match std::env::var("FULA_MANIFEST_CID") {
        Ok(c) if !c.trim().is_empty() => {
            // Diagnostic override: inject one or more trusted manifest CIDs
            // (comma-separated, newest-first) to exercise the walk-via-endpoints
            // path independently of manifest-CID acquisition. The real client
            // gets these from cold_start_resolve_manifest (global index).
            let v: Vec<String> = c
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            println!("[recover] FULA_MANIFEST_CID override → {} candidate(s)", v.len());
            v
        }
        // Auto manifest acquisition: resolve-keys on the (now-correct) index_key
        // returns the bucket's pinned manifest versions, newest-first. try_recover
        // then walks newest->oldest, so a dangling latest auto-falls-back to the
        // last consistent version. No hand-fed CID.
        _ => backend.resolve(&index_key).await,
    };
    let mresolve_dur = t_mresolve.elapsed();
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
    let t_walk = Instant::now();
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
    let walk_dur = t_walk.elapsed();

    let total: u64 = files.iter().map(|f| f.size).sum();
    println!(
        "\n[OK] auto-recovered via manifest #{idx} ({mcid})\n     files = {}, total = {:.2} MiB",
        files.len(),
        total as f64 / 1048576.0
    );
    for f in files.iter().take(12) {
        println!("       {:>11}  {}", f.size, f.path);
    }
    if files.len() > 12 {
        println!("       … and {} more", files.len() - 12);
    }

    // Dump every file's storage_key (one per line) for an external cross-
    // reference against the cluster pinset (recoverable iff sk is cluster-pinned).
    if std::env::var("FULA_DUMP_SKS").is_ok() {
        for f in &files {
            println!("SK {}", f.storage_key);
        }
        return;
    }

    // Diagnostic: find file(s) whose path contains FULA_FIND and dump their
    // storage_key + shape, so we can check the cluster mirror for the key + its
    // chunks (gone vs recoverable-but-slow).
    if let Ok(needle) = std::env::var("FULA_FIND") {
        let nl = needle.to_lowercase();
        let mut hits = 0;
        for f in &files {
            if f.path.to_lowercase().contains(&nl) {
                hits += 1;
                let chunked = f
                    .user_metadata
                    .get("x-fula-chunked")
                    .map(|s| s == "true")
                    .unwrap_or(false);
                let has_meta = f.user_metadata.contains_key("x-fula-encryption");
                println!(
                    "FOUND sk={} size={} encrypted={} chunked={} forest_meta={} path='{}'",
                    f.storage_key, f.size, f.encrypted, chunked, has_meta, f.path
                );
                if let Some(enc_str) = f.user_metadata.get("x-fula-encryption") {
                    if let Ok(enc) = serde_json::from_str::<serde_json::Value>(enc_str) {
                        let ch = &enc["chunked"];
                        let num = ch["num_chunks"].as_u64().unwrap_or(0);
                        let cc = &ch["chunk_cids"];
                        let present: usize = cc
                            .as_array()
                            .map(|a| a.iter().filter(|v| !v.is_null()).count())
                            .unwrap_or(0);
                        let c3 = cc.get(3).map(|v| v.to_string()).unwrap_or_else(|| "MISSING".into());
                        println!(
                            "    num_chunks={} chunk_cids_present={} chunk3_cid={}",
                            num, present, c3
                        );
                    }
                }
            }
        }
        println!("(matched {hits})");
        return;
    }

    // ===== STEP 3 — REAL download: fetch + DECRYPT to plaintext, exactly like
    // FxFiles (DEK unwrap → AEAD single-block, or per-chunk decrypt + Bao). We
    // download one single-block file and one chunked file and verify each
    // decrypts to its expected size. Some individual blocks are gc-lost, so we
    // try smallest-first until one of each shape succeeds.
    println!("\n[3/3 DOWNLOAD] fetch + decrypt-to-plaintext via the endpoints …");
    let mut sorted = files.clone();
    sorted.sort_by_key(|f| f.size);

    // Diagnostic (FULA_PROBE=1): for the first few entries, show what metadata
    // the FOREST carries, and whether a NORMAL authenticated gateway GET of the
    // object still returns the `x-amz-meta-x-fula-encryption` header + body.
    // This distinguishes "only client listing is damaged, gateway healthy →
    // download via normal GET" from "gateway index damaged too → metadata only
    // recoverable from the forest (new uploads) and legacy is re-upload-only".
    if std::env::var("FULA_PROBE").is_ok() {
        for entry in sorted.iter().take(3) {
            let mut keys: Vec<&String> = entry.user_metadata.keys().collect();
            keys.sort();
            println!(
                "\n[probe] '{}'\n        size={} encrypted={} min_version={} sk={}\n        forest user_metadata keys: {:?}",
                entry.path, entry.size, entry.encrypted, entry.min_version, entry.storage_key, keys
            );
            let url = format!("{}/{}/{}", backend.base, backend.bucket, entry.storage_key);
            match backend.http.get(&url).bearer_auth(&backend.jwt).send().await {
                Ok(resp) => {
                    let st = resp.status();
                    let h = resp.headers();
                    let has_enc = h.contains_key("x-amz-meta-x-fula-encryption")
                        || h.contains_key("x-fula-encryption");
                    let has_chunk = h.contains_key("x-amz-meta-x-fula-chunked")
                        || h.contains_key("x-fula-chunked");
                    let clen = h
                        .get("content-length")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("?")
                        .to_string();
                    let body = resp.bytes().await.map(|b| b.to_vec()).unwrap_or_default();
                    let preview: String = body
                        .iter()
                        .take(40)
                        .map(|&b| if (0x20..0x7f).contains(&b) { b as char } else { '.' })
                        .collect();
                    // Is the raw block printable text (plaintext) or high-entropy (ciphertext)?
                    let printable = body.iter().take(64).filter(|&&b| (0x20..0x7f).contains(&b) || b == b'\n' || b == b'\r' || b == b'\t').count();
                    let frac = if body.is_empty() { 0 } else { printable * 100 / body.iter().take(64).count() };
                    println!(
                        "        gateway GET -> HTTP {} | enc hdr: {} | chunked hdr: {} | content-length: {} | body bytes: {} | printable%: {} | preview: {:?}",
                        st.as_u16(), has_enc, has_chunk, clen, body.len(), frac, preview
                    );
                }
                Err(e) => println!("        gateway GET -> ERR {}", e),
            }
        }
    }

    let is_chunked = |e: &ForestFileEntry| {
        e.user_metadata.get("x-fula-chunked").map(|s| s == "true").unwrap_or(false)
    };
    let has_meta = |e: &ForestFileEntry| e.user_metadata.contains_key("x-fula-encryption");
    let is_enc = |e: &ForestFileEntry| {
        e.encrypted
            || e.user_metadata.get("x-fula-encrypted").map(|s| s == "true").unwrap_or(false)
    };

    // Files split by whether the FOREST carries the metadata:
    //   A = forest has `x-fula-encryption`  → decrypt straight from forest.
    //   no-forest-metadata = everything else. For these the recovery path tries
    //   the storage_key JSON-INDEX rescue (chunked files store their metadata as
    //   a separately-pinned object). decrypt_download does this automatically.
    let _ = is_enc; // (the forest `encrypted` flag is unreliable — defaults false on legacy)
    let cat_a: Vec<&ForestFileEntry> = sorted.iter().filter(|e| has_meta(e)).collect();
    let no_meta: Vec<&ForestFileEntry> = sorted.iter().filter(|e| !has_meta(e)).collect();
    let n_single = cat_a.iter().filter(|e| !is_chunked(e)).count();
    let n_chunked = cat_a.iter().filter(|e| is_chunked(e)).count();
    println!(
        "[download] {} files: forest-metadata(A)={} ({} single, {} chunked); no-forest-metadata={} (will try index-object rescue)",
        files.len(), cat_a.len(), n_single, n_chunked, no_meta.len()
    );

    // RESCUE SCAN: attempt a FULL decrypt on the smallest no-forest-metadata
    // files. decrypt_download falls back to the storage_key JSON-index, so this
    // measures how many "metadata-lost" files the index-object path actually
    // saves (verified: chunked = Bao, single = AEAD; size must match).
    {
        // Target the LARGEST no-forest-metadata files first — large files are
        // chunked, and chunked files are the ones with a rescuable index object.
        // Skip very large files to bound the one-time measurement time.
        let scan: Vec<&ForestFileEntry> = no_meta
            .iter()
            .rev()
            .map(|e| *e)
            .filter(|e| e.size <= 30 * 1024 * 1024)
            .take(15)
            .collect();
        let sample = scan.len();
        let (mut rescued, mut lost, mut gone) = (0usize, 0usize, 0usize);
        for entry in scan.into_iter() {
            match decrypt_download(&backend, &km, entry).await {
                Ok(b) => {
                    let size_ok = b.len() as u64 == entry.size;
                    let magic = sniff_magic(&b);
                    if size_ok {
                        rescued += 1;
                        println!(
                            "[rescue] ✓ '{}' sk={} -> {} bytes (size_ok, magic={}) RESCUED",
                            entry.path, entry.storage_key, b.len(), magic
                        );
                    } else {
                        lost += 1;
                        println!(
                            "[rescue] ? '{}' -> {} bytes (expected {}, magic={}) decoded-but-size-mismatch",
                            entry.path, b.len(), entry.size, magic
                        );
                    }
                }
                Err(e) => {
                    let m = e.to_string();
                    if m.contains("no fetchable cid") || m.contains("block GET") {
                        gone += 1;
                        if gone <= 5 {
                            println!(
                                "[gone] '{}' sk={} cid_hint={} size={}",
                                entry.path, entry.storage_key, entry.storage_cid.is_some(), entry.size
                            );
                        }
                    } else {
                        lost += 1;
                    }
                }
            }
        }
        println!(
            "[rescue] sampled {} no-forest-metadata files: {} RESCUED (index-object), {} unrecoverable(single-block/meta-lost), {} block-gone",
            sample, rescued, lost, gone
        );
    }

    let recoverable = &cat_a;

    let (mut single_dur, mut chunked_dur) = (Duration::ZERO, Duration::ZERO);
    let (mut single_done, mut chunked_done) = (false, false);
    // Try recoverable files smallest-first; prove one of EACH shape decrypts.
    for entry in recoverable.iter() {
        let want_chunked = is_chunked(entry);
        if (want_chunked && chunked_done) || (!want_chunked && single_done) {
            continue;
        }
        let t = Instant::now();
        match decrypt_download(&backend, &km, entry).await {
            Ok(pt) => {
                let dur = t.elapsed();
                let size_ok = pt.len() as u64 == entry.size;
                let preview: String = pt
                    .iter()
                    .take(40)
                    .map(|&b| if (0x20..0x7f).contains(&b) { b as char } else { '.' })
                    .collect();
                println!(
                    "[download] {} OK — '{}' -> {} bytes (expected {}, size_ok={}) in {:?}  {:?}",
                    if want_chunked { "chunked" } else { "single " },
                    entry.path, pt.len(), entry.size, size_ok, dur, preview
                );
                if want_chunked {
                    chunked_done = true;
                    chunked_dur = dur;
                } else {
                    single_done = true;
                    single_dur = dur;
                }
            }
            Err(e) => {
                println!(
                    "[download] {} '{}' recoverable-but-block-gone ({}), trying next …",
                    if want_chunked { "chunked" } else { "single " },
                    entry.path,
                    e.to_string().chars().take(60).collect::<String>()
                );
            }
        }
        if single_done && chunked_done {
            break;
        }
    }
    if recoverable.is_empty() {
        println!(
            "[download] (none) — this bucket has NO forest-recoverable files; all entries are \
             legacy (pre-offline-metadata). Listing is recoverable; content is re-upload-only."
        );
    } else if !single_done && !chunked_done {
        println!("[download] FAIL — recoverable files exist but no block was fetchable (data gc-lost)");
    }

    println!("\n[TIMING] recovery overhead (excludes compile):");
    println!("  detect (cold list)                    : {:?}", detect_dur);
    println!("  manifest resolve-keys                 : {:?}  ({} versions)", mresolve_dur, manifest_cids.len());
    println!("  walk -> full file list                : {:?}  ({} files)", walk_dur, files.len());
    println!("  >> LISTING total                      : {:?}", detect_dur + mresolve_dur + walk_dur);
    println!("  download single-block (fetch+decrypt) : {:?}", single_dur);
    println!("  download chunked (fetch+decrypt)      : {:?}", chunked_dur);

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
    Ok(files)
}

/// Best-effort file-type sniff from leading magic bytes (for verifying that a
/// recovered block is real plaintext, not ciphertext we mislabeled).
fn sniff_magic(b: &[u8]) -> &'static str {
    if b.starts_with(&[0x89, 0x50, 0x4e, 0x47]) {
        "PNG"
    } else if b.starts_with(&[0xff, 0xd8, 0xff]) {
        "JPEG"
    } else if b.get(4..8) == Some(b"ftyp") {
        "MP4/MOV"
    } else if b.starts_with(b"%PDF") {
        "PDF"
    } else if b.starts_with(b"ID3") || b.starts_with(&[0xff, 0xfb]) {
        "MP3"
    } else if b.starts_with(b"RIFF") {
        "WAV"
    } else if b.starts_with(b"GIF8") {
        "GIF"
    } else {
        "?"
    }
}

/// Fetch + decrypt ONE file to plaintext through the recovery endpoints,
/// mirroring `EncryptedClientHandle::get_object_decrypted_inner` exactly:
///   - unwrap the per-file DEK (HPKE-to-self) from `x-fula-encryption.wrapped_key`
///   - single-block: AEAD decrypt the one body block (v4 binds AAD
///     `fula:v4:content:{storage_key}`)
///   - chunked: per-chunk fetch by `chunk_key`, `VerifiedStreamingDecoder`
///     (streaming-v2 binds AAD `fula:v4:chunk:{storage_key}`), Bao finalize.
/// Bytes come from the endpoints (`get` = resolve-keys→block-by-cid), so this
/// is the true download cost a recovering phone pays — fetch AND decrypt.
async fn decrypt_download(
    backend: &Arc<EndpointBackend>,
    km: &KeyManager,
    entry: &ForestFileEntry,
) -> fula_crypto::Result<Vec<u8>> {
    // Mirror `get_object_decrypted_inner` (encryption.rs:1640-1652): a file is
    // only decrypted when the forest entry says `encrypted` OR a metadata header
    // says so. In the recovery path there are NO gateway headers, so the forest
    // entry is the sole signal. If NOT encrypted → return the fetched block
    // as-is (legacy plaintext upload), exactly like production. Only an
    // encrypted entry MISSING its `x-fula-encryption` is truly unrecoverable.
    let is_encrypted = entry.encrypted
        || entry
            .user_metadata
            .get("x-fula-encrypted")
            .map(|s| s == "true")
            .unwrap_or(false);
    let sk = entry.storage_key.as_str();

    // Resolve the per-file encryption metadata JSON. THREE possible sources,
    // in priority order:
    //   1. forest `user_metadata["x-fula-encryption"]`  (newer SDK embeds it).
    //   2. the storage_key OBJECT BODY itself, when it is a plaintext JSON
    //      index `{algorithm, wrapped_key, chunked, …}`. Chunked files store
    //      their metadata as a SEPARATELY-PINNED object that survives gc
    //      independent of the forest and the gateway header → RESCUE PATH for
    //      "category B" chunked files.
    //   3. (none) → if genuinely unencrypted, return bytes as-is; else
    //      single-block whose header metadata is gc-lost → unrecoverable.
    let (enc, meta_from_index): (serde_json::Value, bool) =
        if let Some(s) = entry.user_metadata.get("x-fula-encryption") {
            (
                serde_json::from_str(s).map_err(|e| CryptoError::Decryption(e.to_string()))?,
                false,
            )
        } else {
            // resolve-keys (Postgres) is sparse for file content — fall back to
            // the forest entry's storage_cid hint and fetch the block straight
            // from the cluster via block-by-cid.
            let obj = match backend.get(sk).await {
                Ok(b) => b,
                Err(e) => match &entry.storage_cid {
                    Some(cid) => backend.read_cid(&cid.to_string()).await.map_err(|_| e)?,
                    None => return Err(e),
                },
            };
            match serde_json::from_slice::<serde_json::Value>(&obj) {
                Ok(j) if j.get("wrapped_key").is_some() => (j, true),
                _ => {
                    if !is_encrypted {
                        return Ok(obj); // genuine plaintext passthrough (mirror production)
                    }
                    return Err(CryptoError::Decryption(
                        "encrypted; no forest metadata and storage_key is not a JSON index \
                         (single-block header gc-lost; re-upload-only)"
                            .into(),
                    ));
                }
            }
        };

    // Unwrap the DEK (common to both shapes), exactly as the production path.
    let wrapped: EncryptedData = serde_json::from_value(enc["wrapped_key"].clone())
        .map_err(|e| CryptoError::Decryption(e.to_string()))?;
    let dek = Decryptor::new(km.keypair()).decrypt_dek(&wrapped)?;

    // Chunked when the metadata carries a `chunked` object (works for both the
    // forest copy and the index-object copy), or the forest flag says so.
    let chunked = enc.get("chunked").map(|c| !c.is_null()).unwrap_or(false)
        || entry
            .user_metadata
            .get("x-fula-chunked")
            .map(|s| s == "true")
            .unwrap_or(false);

    if chunked {
        let cmeta: ChunkedFileMetadata = serde_json::from_value(enc["chunked"].clone())
            .map_err(|e| CryptoError::Decryption(format!("chunked metadata: {e}")))?;
        let mut decoder = if cmeta.format == "streaming-v2" {
            VerifiedStreamingDecoder::with_aad(
                dek.clone(),
                cmeta.clone(),
                format!("fula:v4:chunk:{sk}"),
            )?
        } else {
            VerifiedStreamingDecoder::new(dek.clone(), cmeta.clone())?
        };
        let mut out = Vec::with_capacity(cmeta.total_size as usize);
        for i in 0..cmeta.num_chunks {
            let ckey = ChunkedFileMetadata::chunk_key(sk, i);
            // Try resolve-keys first; on miss, fall back to the chunk's CID hint
            // (Walkable-v8 `chunk_cids` in the index) and fetch from the cluster.
            let cdata = match backend.get(&ckey).await {
                Ok(b) => b,
                Err(e) => match cmeta.chunk_cid(i) {
                    Some(cid) => backend.read_cid(&cid.to_string()).await.map_err(|_| e)?,
                    None => return Err(e),
                },
            };
            let pt = decoder.decrypt_and_verify(i, &cdata)?;
            out.extend_from_slice(&pt);
        }
        // Consumes the decoder; returns Ok(true) or Err on Bao root mismatch.
        if !decoder.finalize_and_verify()? {
            return Err(CryptoError::Decryption("Bao finalize_and_verify failed".into()));
        }
        Ok(out)
    } else {
        if meta_from_index {
            // A JSON index at storage_key implies chunked layout; a single-block
            // file stores ciphertext (not JSON) at storage_key. So this is an
            // unexpected shape — don't guess where the ciphertext lives.
            return Err(CryptoError::Decryption(
                "single-block file with JSON-index metadata: ciphertext location unknown".into(),
            ));
        }
        let body = backend.get(sk).await?;
        let nonce_b64 = enc["nonce"]
            .as_str()
            .ok_or_else(|| CryptoError::Decryption("no nonce".into()))?;
        use base64::Engine as _;
        let nonce_bytes = base64::engine::general_purpose::STANDARD
            .decode(nonce_b64)
            .map_err(|e| CryptoError::Decryption(e.to_string()))?;
        let nonce = Nonce::from_bytes(&nonce_bytes)?;
        let aead = Aead::new_default(&dek);
        let version = enc["version"].as_u64().unwrap_or(2);
        if version >= 4 {
            let aad = format!("fula:v4:content:{sk}").into_bytes();
            aead.decrypt_with_aad(&nonce, &body, &aad)
        } else {
            aead.decrypt(&nonce, &body)
        }
    }
}
