//! Full forest-walk recovery (DIAGNOSTIC — read-only, not production).
//!
//! Reconstructs a bucket's complete file list (path -> storage_key/size/cid)
//! from its encrypted sharded-HAMT-v7 forest, using ONLY:
//!   * the user's 32-byte root secret (env `FULA_SECRET_HEX`, never a file),
//!   * a directory of raw forest blocks exported by CID (`ipfs block get`),
//!   * the pin-map CSV (`name,cid`) that translates object path -> CID.
//!
//! It bypasses the (broken) gateway prolly index entirely: every block is
//! resolved by CID via the pin map, so a destroyed server-side index does not
//! matter. Drives the REAL fula-crypto load path (`from_manifest` +
//! `list_all_files`) so the result is exactly what the SDK would see.
//!
//! Usage:
//!   $env:FULA_SECRET_HEX="<64-hex>"; $env:FULA_BUCKET="images"
//!   cargo run -p fula-crypto --example recover_walk -- <blocks_dir> <pinmap.csv>
//!
//! Multi-version note: a content-addressed storage_key is re-encrypted (new
//! nonce -> new CID) on every flush, so the CSV holds many CIDs per name. All
//! encryptions of one storage_key share the same plaintext and shard, so ANY
//! present block decrypts identically — we keep all candidates and return the
//! first whose block file exists locally.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use fula_crypto::{
    derive_index_key, derive_manifest_page_key, CryptoError, DekKey, EncryptedManifestPage,
    EncryptedShardManifestV7, KeyManager, ManifestPage, PageId, SecretKey, ShardManifestV7,
    ShardedHamtPrivateForest,
};
use fula_crypto::{BlobBackend, BlobPutResult};
use std::sync::atomic::{AtomicUsize, Ordering};

static SSH_FETCHES: AtomicUsize = AtomicUsize::new(0);

/// On-demand, read-only fetch of one block from the master by CID
/// (`ipfs block get`). Lets the walk pull exactly the forest-structure blocks it
/// references (~dozens) without pre-exporting the user's entire bare-pin set
/// (which is scattered across 120k+ rows under a non-bucket-scoped user_id).
fn ssh_block_get(cid: &str) -> Option<Vec<u8>> {
    let out = std::process::Command::new("ssh")
        .args([
            "-i",
            "c:/users/ehsan/documents/functionland.pem",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "BatchMode=yes",
            "root@cloud.fx.land",
            &format!("docker exec ipfs_host ipfs block get {cid}"),
        ])
        .output()
        .ok()?;
    if out.status.success() && !out.stdout.is_empty() {
        let n = SSH_FETCHES.fetch_add(1, Ordering::Relaxed) + 1;
        if n % 25 == 0 {
            eprintln!("   … {n} blocks fetched on-demand");
        }
        Some(out.stdout)
    } else {
        None
    }
}

/// Read-only: ask the master's pin DB for the latest CID of a storage key whose
/// path isn't in the (incomplete) pin map. Only hit as a fallback for legacy
/// pointers with no CID hint.
fn ssh_resolve_cid(path: &str) -> Option<String> {
    let path = path.replace('\'', "''"); // defensive SQL-escape
    let remote = format!(
        "U=$(docker exec postgres-pinning printenv POSTGRES_USER); D=$(docker exec postgres-pinning printenv POSTGRES_DB); docker exec -i postgres-pinning psql -U \"$U\" -d \"$D\" -t -A -c \"SELECT cid FROM pins WHERE name='{path}' ORDER BY updated_at DESC LIMIT 1\""
    );
    let out = std::process::Command::new("ssh")
        .args([
            "-i",
            "c:/users/ehsan/documents/functionland.pem",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "BatchMode=yes",
            "root@cloud.fx.land",
            &remote,
        ])
        .output()
        .ok()?;
    let cid = String::from_utf8(out.stdout).ok()?.trim().to_string();
    if cid.is_empty() {
        None
    } else {
        Some(cid)
    }
}

/// Read-only blob backend: object path -> candidate CIDs (pin map) -> local
/// block file bytes. Implements only `get`; `put` is rejected.
struct PinMapBackend {
    /// path (e.g. `Qm…` page key or `__fula_forest_v7_nodes/<hex>`) -> [cid…]
    map: HashMap<String, Vec<String>>,
    blocks_dir: PathBuf,
}

impl PinMapBackend {
    /// Read a block directly by CID string (bypasses the path->cid pin map).
    /// Used for walkable-v8 CID hints, which are authoritative even when the
    /// master's mutable object pins are stale.
    fn read_cid(&self, cid: &str) -> fula_crypto::Result<Vec<u8>> {
        let p = self.blocks_dir.join(cid);
        if let Ok(bytes) = std::fs::read(&p) {
            return Ok(bytes);
        }
        // Not in the local export: fetch on-demand from the master (read-only),
        // cache it locally, and return. This is what makes the walk independent
        // of which pins happened to be in the (incomplete) pre-export.
        if let Some(bytes) = ssh_block_get(cid) {
            let _ = std::fs::write(&p, &bytes);
            return Ok(bytes);
        }
        Err(CryptoError::Hamt(format!(
            "block {cid} not present in {} and on-demand fetch failed (genuinely unavailable?)",
            self.blocks_dir.display()
        )))
    }
}

#[async_trait::async_trait]
impl BlobBackend for PinMapBackend {
    async fn get(&self, path: &str) -> fula_crypto::Result<Vec<u8>> {
        // Pin-map candidates first (route through read_cid so each can be
        // fetched on-demand if missing locally).
        if let Some(cids) = self.map.get(path) {
            for cid in cids {
                if let Ok(bytes) = self.read_cid(cid) {
                    return Ok(bytes);
                }
            }
        }
        // Path absent from the pin map (e.g. a forest object pinned under a
        // user_id the export wasn't scoped to): resolve its latest CID from the
        // master's pin DB, then fetch on-demand.
        if let Some(cid) = ssh_resolve_cid(path) {
            if let Ok(bytes) = self.read_cid(&cid) {
                return Ok(bytes);
            }
        }
        Err(CryptoError::Hamt(format!(
            "pin map has no entry for path {path} and DB resolve/fetch failed"
        )))
    }

    async fn put(&self, _path: &str, _bytes: Vec<u8>) -> fula_crypto::Result<BlobPutResult> {
        Err(CryptoError::Hamt(
            "recover_walk backend is read-only; put() must never be called during a walk".into(),
        ))
    }

    /// Walkable-v8: a parent's `StoredV2 { storage_key, cid }` pointer forwards
    /// the child's CID here. Prefer it — it's authoritative and resolves nodes
    /// whose storage_key isn't in the (incomplete) pin map. Fall back to the
    /// path-keyed map only when there is no hint (legacy `Stored` pointers).
    async fn get_with_cid_hint(
        &self,
        path: &str,
        cid_hint: Option<&cid::Cid>,
    ) -> fula_crypto::Result<Vec<u8>> {
        if let Some(c) = cid_hint {
            if let Ok(bytes) = self.read_cid(&c.to_string()) {
                return Ok(bytes);
            }
        }
        self.get(path).await
    }
}

/// Parse the `name,cid` CSV into a path -> [cid] multimap. Two pin-name shapes
/// map to backend paths:
///   `object:<bucket>/<path>`         -> `<path>`   (data objects, pages, manifest)
///   `__fula_forest_v7_nodes/<hex>`   -> same        (HAMT node, user-external pin)
fn load_pin_map(csv_path: &str, bucket: &str) -> HashMap<String, Vec<String>> {
    let text = std::fs::read_to_string(csv_path).expect("read pin-map CSV");
    let object_prefix = format!("object:{}/", bucket);
    let mut map: HashMap<String, Vec<String>> = HashMap::new();
    for (i, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // header
        if i == 0 && line.starts_with("name,") {
            continue;
        }
        // name has no comma in either shape, so split on the first comma only.
        let Some((name, cid)) = line.split_once(',') else {
            continue;
        };
        let name = name.trim().trim_matches('"');
        let cid = cid.trim().trim_matches('"');
        if cid.is_empty() {
            continue;
        }
        let path = if let Some(rest) = name.strip_prefix(&object_prefix) {
            rest.to_string()
        } else if name.starts_with("__fula_forest_v7_nodes/") {
            name.to_string()
        } else {
            continue; // bucket:, v8-node:, other buckets — irrelevant to the walk
        };
        map.entry(path).or_default().push(cid.to_string());
    }
    map
}

fn main() {
    let secret_hex =
        std::env::var("FULA_SECRET_HEX").expect("set FULA_SECRET_HEX to the 64-hex root secret");
    let bucket = std::env::var("FULA_BUCKET").unwrap_or_else(|_| "images".to_string());
    let mut args = std::env::args().skip(1);
    let blocks_dir = PathBuf::from(args.next().expect("arg1: blocks directory"));
    let csv_path = args.next().expect("arg2: pin-map CSV path");

    let secret_bytes = hex::decode(secret_hex.trim()).expect("FULA_SECRET_HEX must be valid hex");
    let secret = SecretKey::from_bytes(&secret_bytes).expect("invalid X25519 secret");
    let km = KeyManager::from_secret_key(secret);
    let forest_dek: DekKey = km.derive_path_key(&format!("forest:{}", bucket));
    let index_key = derive_index_key(&forest_dek, &bucket);

    let map = load_pin_map(&csv_path, &bucket);
    println!("bucket            = {}", bucket);
    println!("index_key         = {}", index_key);
    println!("pin-map paths     = {}", map.len());
    println!("blocks dir        = {}", blocks_dir.display());

    let backend = Arc::new(PinMapBackend {
        map,
        blocks_dir: blocks_dir.clone(),
    });

    let result = futures::executor::block_on(run(&backend, &forest_dek, &bucket, &index_key));
    match result {
        Ok(files) => {
            let total: u64 = files.iter().map(|f| f.2).sum();
            println!("\n========================================");
            println!("[OK] WALK COMPLETE");
            println!("files reconstructed = {}", files.len());
            println!("total size          = {} bytes ({:.2} MiB)", total, total as f64 / 1048576.0);
            println!("========================================\n");
            for (path, sk, size, cid) in files.iter().take(40) {
                println!("  {:>10}  {}  sk={}  cid={:?}", size, path, sk, cid);
            }
            if files.len() > 40 {
                println!("  … and {} more (full list written to file)", files.len() - 40);
            }
            // Write the full list next to the blocks dir (a known-writable path).
            let out_path = blocks_dir
                .parent()
                .unwrap_or(blocks_dir.as_path())
                .join("recover_walk_files.txt");
            let mut body = String::from("size\tpath\tstorage_key\tcontent_cid\n");
            for (p, sk, size, cid) in files.iter() {
                body.push_str(&format!("{}\t{}\t{}\t{:?}\n", size, p, sk, cid));
            }
            match std::fs::write(&out_path, body) {
                Ok(()) => println!("\nfull list -> {}", out_path.display()),
                Err(e) => eprintln!("\n(could not write full list: {e})"),
            }
        }
        Err(e) => {
            eprintln!("\n[FAIL] walk error: {e}");
            eprintln!("(if this is a 'no local block file' error, that CID was not exported; if a");
            eprintln!(" decrypt/content-address error, the wrong block version was served for a path)");
            std::process::exit(4);
        }
    }
}

async fn run(
    backend: &Arc<PinMapBackend>,
    forest_dek: &DekKey,
    bucket: &str,
    index_key: &str,
) -> fula_crypto::Result<Vec<(String, String, u64, Option<cid::Cid>)>> {
    // 1. Manifest root. The master's `object:<bucket>/<index_key>` pin can be
    //    STALE (point at an old manifest), so allow an explicit override to the
    //    real latest manifest CID; otherwise fall back to the pin map.
    let manifest_blob = match std::env::var("FULA_MANIFEST_CID") {
        Ok(mcid) if !mcid.trim().is_empty() => {
            println!("manifest cid      = {} (explicit override)", mcid.trim());
            backend.read_cid(mcid.trim())?
        }
        _ => backend.get(index_key).await?,
    };
    let envelope = EncryptedShardManifestV7::from_bytes(&manifest_blob)
        .map_err(|e| CryptoError::Hamt(format!("manifest envelope parse failed: {e}")))?;
    let (root, root_seq) = envelope.decrypt_v7(forest_dek, bucket)?;
    println!(
        "manifest          = v{} {} shards={} seq={} pages={} dir_index_cid={:?}",
        root.version,
        root.format,
        root.num_shards,
        root_seq,
        root.page_index.len(),
        root.dir_index_cid
    );

    // 2. Fetch + decrypt every referenced manifest page (same forest_dek).
    let mut pages: std::collections::BTreeMap<PageId, ManifestPage> =
        std::collections::BTreeMap::new();
    for (page_id, page_ref) in root.page_index.iter() {
        // Walkable-v8: the manifest carries each page's CID directly, so fetch
        // by CID (authoritative) rather than via the possibly-stale pin map.
        let blob = match &page_ref.cid {
            Some(cid) => backend.read_cid(&cid.to_string())?,
            None => {
                let page_key =
                    derive_manifest_page_key(forest_dek, bucket, &root.shard_salt, *page_id);
                backend.get(&page_key).await?
            }
        };
        let enc_page = EncryptedManifestPage::from_bytes(&blob)
            .map_err(|e| CryptoError::Hamt(format!("page {page_id} parse failed: {e}")))?;
        let page = enc_page.decrypt(forest_dek, bucket)?;
        println!(
            "  page {page_id}: shards={} (cid={:?})",
            page.shards.len(),
            page_ref.cid
        );
        pages.insert(*page_id, page);
    }

    // 3. Reassemble the full manifest (validates page seq >= root seq).
    let manifest = ShardManifestV7::from_root_and_pages(root, pages)?;

    // 4. Build the in-memory forest reader and enumerate every file. shard_dek
    //    and bucket_salt are wired internally per shard; the backend serves the
    //    `__fula_forest_v7_nodes/<hex>` node fetches.
    let forest = ShardedHamtPrivateForest::from_manifest(manifest, bucket.to_string(), forest_dek.clone());
    let files = forest.list_all_files(backend).await?;

    Ok(files
        .into_iter()
        .map(|f| (f.path, f.storage_key, f.size, f.storage_cid))
        .collect())
}
