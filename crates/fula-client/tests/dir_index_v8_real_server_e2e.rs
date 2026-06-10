//! plan-D5 (v8) — sharded directory-index REAL-SERVER end-to-end test.
//!
//! The crypto-layer tests prove the sharding MATH (the v7 single-blob path
//! hits the 1 MiB cliff at 30k directories; v8 shards it with every shard
//! < 256 KiB and a clean decrypt+merge round-trip — see
//! `private_forest.rs::dir_index_v8_30k_entries_handled_via_sharding_d5`).
//! The wiremock integration test (`dir_index_v8_sharded_read.rs`) proves the
//! SDK read-path dispatch/merge against an in-memory mock. The crypto AEAD
//! negative tests (`dir_index_v8_cross_shard_swap_rejected_d5`,
//! `..._cross_bucket_aad_rejected_d5`, `..._sequence_replay_rejected_d5`)
//! prove the AAD binding + seq floor are enforced. None of those can prove the
//! one thing only the live, UNCHANGED master can: that the real gateway
//!
//!   (a) ACCEPTS the sharded dir-index PUTs — the conditional
//!       `If-None-Match: *` / `If-Match` headers, the `fula-bucket-lookup-h`
//!       header, and the derived per-shard storage keys — and returns the
//!       body's CID as the ETag, and
//!   (b) RETAINS + SERVES those shard objects on read-back (GC-protected like
//!       manifest pages; the cid-hint native fetch resolves them).
//!
//! **Why a plain round-trip is not enough** (advisor must-fix). A missing or
//! corrupt dir-index shard degrades transparently to *rebuild-from-forest*
//! (the HAMT is the source of truth), so a successful list+download ALONE
//! could be silently rebuilding on every read and would pass even if the shard
//! write/serve path were completely broken. This test therefore proves the
//! sharded write is correct INDEPENDENTLY of the SDK read path:
//!
//!   * It recomputes the EXACT set of non-empty shards the writer should have
//!     produced (by running the production `split_directory_index_into_shards`
//!     over a locally-built ground-truth `DirectoryIndex`), and asserts the
//!     master holds EXACTLY that set of shard objects — no more, no less (a
//!     missing shard = a dropped flush; an extra = a routing nondeterminism).
//!   * It GETs every non-empty shard's raw bytes with a SEPARATE non-encrypted
//!     client, decodes + decrypts each, asserts each shard's plaintext equals
//!     the ground-truth sub-index for that shard, and asserts the UNION across
//!     all shards reconstructs the full ground-truth index — all without ever
//!     touching the SDK read/rebuild path.
//!   * It asserts the legacy v7 single-blob dir-index key is ABSENT (the v8
//!     write must not also write a single-blob index).
//!
//! Only after that does it exercise the SDK read path (Part 3) and the offline
//! paths (Part 4).
//!
//! Mirrors FxFiles' production path: `walkable_v8_writer_enabled = true`
//! (fula_api_service.dart:256), the same SDK methods the thin FRB bridge calls
//! (`put_object_flat` = `putFlat`, `put_object_flat_deferred` + `flush_forest`
//! = `putFlatDeferred` + `flushForest`, `get_object_flat` = `getFlat` —
//! fula-flutter/src/api/forest.rs), a MIX of auto-flush and deferred writes,
//! and a chunk-boundary corpus that straddles the SDK's 768 KiB auto-chunk
//! threshold (`fula_crypto::CHUNKED_THRESHOLD`, 256 KiB chunks) so the
//! chunked-encrypted path FxFiles uses for photos/videos/PDFs fires — at the
//! exact off-by-one and exact-chunk-multiple boundaries.
//!
//! NOTE: the sharded dir-index write is NOT gated on
//! `walkable_v8_writer_enabled` — that flag only adds the per-shard CID
//! self-verify stamp; sharding fires for every fresh bucket regardless. The
//! flag is set here purely to match production byte-for-byte.
//!
//! ## Running (PowerShell, from repo root)
//!
//! ```powershell
//! # load the e2e credentials env file, then:
//! cargo test -p fula-client --test dir_index_v8_real_server_e2e --release `
//!     -- --ignored --nocapture
//! ```
//!
//! Required env: `FULA_JWT`, `FULA_S3`.
//! Optional env:
//!   * `FULA_TEST_PROVIDER` + `FULA_TEST_OAUTH_SUB` + `FULA_TEST_EMAIL` —
//!     derive the account's real secret (matches FxFiles auth_service.dart
//!     Argon2id("fula-files-v1", "{provider}:{sub}:{email}")), so the fresh
//!     `-v8` bucket is created in the account's own key namespace exactly as
//!     FxFiles would, and Part 5 (v7 coexistence) can run. Without it a random
//!     secret is used and Part 5 is skipped.
//!   * `FULA_TEST_BUCKET` — override the generated `dirv8-e2e-<epoch>-v8` name.
//!   * `FULA_IMAGES_BUCKET` / `FULA_BUCKET` — the existing v7 bucket Part 5
//!     reads for coexistence (default `images`).
//!   * `FULA_VERIFY_IMAGES_BUCKET=1` — assert that v7 bucket lists ≥1 file.
//!   * `FULA_E2E_KEEP_BUCKET=1` — skip the best-effort cleanup at the end.
//!   * `FULA_TIMEOUT_SECS` (default 60).
//!
//! Marked `#[ignore]` so the standard `cargo test` skips it (needs a reachable
//! master + valid creds). It does a best-effort delete of the bucket it
//! creates at the end (unless `FULA_E2E_KEEP_BUCKET=1`) and prints the name.

#![cfg(not(target_arch = "wasm32"))]

use bytes::Bytes;
use fula_client::{Config, EncryptedClient, EncryptionConfig, FulaClient};
use fula_crypto::keys::{KeyManager, SecretKey};
use fula_crypto::private_forest::{
    derive_dir_index_key, derive_dir_index_route_key, derive_dir_index_shard_key,
    split_directory_index_into_shards, DirectoryIndex, EncryptedDirectoryIndexShard,
    DIR_INDEX_V8_NUM_SHARDS,
};
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;
use tempfile::TempDir;

/// SDK auto-chunk threshold (`fula_crypto::CHUNKED_THRESHOLD`). Files strictly
/// LARGER than this are split into 256 KiB chunks by `put_object_flat`.
const CHUNK_THRESHOLD: usize = 768 * 1024;

/// Read an env var; return `None` (and print a skip notice) when missing/empty
/// so the test gracefully skips without creds instead of a confusing failure.
fn read_required_env(var: &str) -> Option<String> {
    match std::env::var(var) {
        Ok(v) if !v.is_empty() => Some(v),
        _ => {
            eprintln!(
                "[dir-index-v8-e2e] {} is not set or empty — skipping. \
                 Set it to a real value to run.",
                var
            );
            None
        }
    }
}

fn env_flag(var: &str) -> bool {
    std::env::var(var)
        .map(|v| matches!(v.to_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false)
}

/// Build an `EncryptedClient` mirroring FxFiles' production flags
/// (fula_api_service.dart) — including `walkable_v8_writer_enabled = true`.
/// `master` may be a bogus URL for the offline phase; `health_gate=false` then
/// surfaces the connect error on the first call instead of waiting for the
/// gate's two-failure threshold.
fn build_v8_client(
    master: &str,
    jwt: &str,
    cache: &std::path::Path,
    secret: SecretKey,
    health_gate: bool,
    timeout_secs: u64,
) -> EncryptedClient {
    let mut cfg = Config::new(master).with_token(jwt);
    cfg.timeout = Duration::from_secs(timeout_secs);
    cfg.health_gate_enabled = health_gate;
    cfg.health_gate_ttl = Duration::from_secs(30);
    cfg.block_cache_enabled = true;
    cfg.block_cache_path = Some(cache.to_path_buf());
    cfg.block_cache_max_bytes = 256 * 1024 * 1024;
    cfg.gateway_fallback_enabled = true;
    cfg.gateway_fallback_urls = Vec::new(); // SDK-shipped default gateways
    cfg.gateway_race_concurrency = 3;
    // The one production-critical v8 flag: FxFiles ships this `true`
    // (fula_api_service.dart:256). Enables per-shard CID self-verify on write
    // and cid-hint native fetch on read-back.
    cfg.walkable_v8_writer_enabled = true;
    EncryptedClient::new(cfg, EncryptionConfig::from_secret_key(secret))
        .expect("EncryptedClient construction must succeed")
}

/// Deterministic content for a file of `n` bytes (content-irrelevant pattern).
fn payload(n: usize) -> Vec<u8> {
    (0..n).map(|i| ((i * 131 + 7) % 256) as u8).collect()
}

/// The e2e corpus: `(path, bytes, use_auto_flush)`.
///
///   * ~60 small files across ~35 directories of varying depth → drives the
///     dir-index across many of the 16 shards (the v8 dimension).
///   * Unicode + same-basename-different-dir paths → routing is keyed on the
///     directory path; exercise non-ASCII + collision-prone names.
///   * A chunk-boundary cluster straddling the 768 KiB auto-chunk threshold
///     and the 256 KiB chunk size → mirrors FxFiles' chunked-encrypted path
///     at the off-by-one and exact-multiple boundaries (advisor must-fix).
///
/// `use_auto_flush=true` → uploaded via `put_object_flat` (FxFiles `putFlat`,
/// flushes per file); `false` → `put_object_flat_deferred` (FxFiles
/// `putFlatDeferred`, batched then one `flush_forest`). The MIX exercises the
/// interaction of auto-flush and deferred writes against shared shards.
fn e2e_corpus() -> Vec<(String, Vec<u8>, bool)> {
    let mut v: Vec<(String, Vec<u8>, bool)> = Vec::new();

    // Small files across many top-level dirs.
    for d in 0..24 {
        for f in 0..2 {
            let auto = d % 2 == 0;
            v.push((
                format!("/d{:02}/f{}.txt", d, f),
                format!("top-{}-{}", d, f).into_bytes(),
                auto,
            ));
        }
    }
    // Nested dirs (depth) — spreads entries across more shards.
    for d in 0..8 {
        v.push((
            format!("/nested/a{:02}/b/c.txt", d),
            format!("nested-{}", d).into_bytes(),
            d % 2 == 0,
        ));
    }
    // Unicode + same-basename-in-different-dirs.
    v.push(("/データ/写真/img.txt".to_string(), b"unicode-1".to_vec(), false));
    v.push(("/docs/cafe\u{0301}/re\u{0301}sume\u{0301}.txt".to_string(), b"unicode-2".to_vec(), true));
    v.push(("/x/shared.txt".to_string(), b"same-basename-x".to_vec(), false));
    v.push(("/y/shared.txt".to_string(), b"same-basename-y".to_vec(), true));

    // Chunk-boundary cluster (FxFiles chunked-encrypted parity). All under one
    // dir so they don't dominate the dir-count.
    v.push(("/chunk/below.bin".to_string(), payload(CHUNK_THRESHOLD - 1), true)); // single block
    v.push(("/chunk/at_threshold.bin".to_string(), payload(CHUNK_THRESHOLD), false)); // == threshold ⇒ single
    v.push(("/chunk/just_over.bin".to_string(), payload(CHUNK_THRESHOLD + 1), true)); // chunked, 1-byte final chunk
    v.push(("/chunk/exact_multiple.bin".to_string(), payload(2 * CHUNK_THRESHOLD), false)); // 6×256KiB exact ⇒ no empty trailing chunk
    v.push(("/chunk/multi.bin".to_string(), payload(5 * 1024 * 1024), true)); // ~20 chunks

    v
}

/// Build the ground-truth `DirectoryIndex` exactly as the writer does: one
/// `insert_file` per uploaded logical path (chunked files are ONE logical
/// entry — the chunk objects are not in the dir-index). This is the SAME
/// primitive the SDK forest calls on each upload, so the result must equal the
/// writer's dir-index, independent of any SDK read path.
fn ground_truth_index(files: &[(String, Vec<u8>, bool)]) -> DirectoryIndex {
    let mut gt = DirectoryIndex::new();
    for (path, _, _) in files {
        gt.insert_file(path);
    }
    gt
}

#[tokio::test]
#[ignore]
async fn dir_index_v8_sharded_real_server_e2e() {
    let jwt = match read_required_env("FULA_JWT") {
        Some(v) => v,
        None => return,
    };
    let s3 = match read_required_env("FULA_S3") {
        Some(v) => v,
        None => return,
    };
    let timeout_secs: u64 = std::env::var("FULA_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(60);

    // Secret: the account's real derived key when the triple is present
    // (faithful to how FxFiles creates a `-v8` bucket, and required for Part 6
    // coexistence), else random.
    let provider = std::env::var("FULA_TEST_PROVIDER").ok().filter(|s| !s.is_empty());
    let oauth_sub = std::env::var("FULA_TEST_OAUTH_SUB").ok().filter(|s| !s.is_empty());
    let email = std::env::var("FULA_TEST_EMAIL").ok().filter(|s| !s.is_empty());
    let (secret, secret_is_real) =
        if let (Some(p), Some(s), Some(e)) = (provider.as_ref(), oauth_sub.as_ref(), email.as_ref()) {
            let input = format!("{}:{}:{}", p, s, e);
            let key = fula_crypto::hashing::derive_key_argon2id("fula-files-v1", input.as_bytes());
            (
                SecretKey::from_bytes(&key).expect("32-byte secret from Argon2id"),
                true,
            )
        } else {
            (SecretKey::generate(), false)
        };

    let epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let bucket = std::env::var("FULA_TEST_BUCKET")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("dirv8-e2e-{}-v8", epoch));

    let files = e2e_corpus();
    let expected_keys: BTreeSet<String> = files.iter().map(|(k, _, _)| k.clone()).collect();
    let chunked_count = files.iter().filter(|(_, b, _)| b.len() > CHUNK_THRESHOLD).count();
    let auto_count = files.iter().filter(|(_, _, a)| *a).count();

    eprintln!("\n[dir-index-v8-e2e] master = {}", s3);
    eprintln!("[dir-index-v8-e2e] bucket = {}  (fresh -v8 bucket)", bucket);
    eprintln!(
        "[dir-index-v8-e2e] secret = {}",
        if secret_is_real { "real (account triple)" } else { "random" }
    );
    eprintln!(
        "[dir-index-v8-e2e] corpus = {} files ({} auto-flush / {} deferred, {} chunked >768KiB)",
        files.len(),
        auto_count,
        files.len() - auto_count,
        chunked_count
    );

    // ─── Part 1 — write a fresh v8 bucket: MIX of auto-flush + deferred ───
    eprintln!("\n[dir-index-v8-e2e] part 1: upload (mixed putFlat / putFlatDeferred) → flush");
    let upload_cache = TempDir::new().expect("tempdir: upload cache");
    {
        let client = build_v8_client(
            &s3,
            &jwt,
            &upload_cache.path().join("blocks.redb"),
            secret.clone(),
            true,
            timeout_secs,
        );
        match client.create_bucket(&bucket).await {
            Ok(_) => eprintln!("[dir-index-v8-e2e]   bucket ready (created or pre-existing)"),
            Err(e) => eprintln!(
                "[dir-index-v8-e2e]   create_bucket: {:?} (proceeding; may be already-exists)",
                e
            ),
        }
        for (k, data, auto) in &files {
            let body = Bytes::from(data.clone());
            if *auto {
                client
                    .put_object_flat(&bucket, k, body, Some("application/octet-stream"))
                    .await
                    .unwrap_or_else(|e| panic!("put_object_flat {k} ({} bytes): {e:?}", data.len()));
            } else {
                client
                    .put_object_flat_deferred(&bucket, k, body, Some("application/octet-stream"))
                    .await
                    .unwrap_or_else(|e| {
                        panic!("put_object_flat_deferred {k} ({} bytes): {e:?}", data.len())
                    });
            }
        }
        client
            .flush_forest(&bucket)
            .await
            .expect("flush_forest must succeed against the real master");
        eprintln!("[dir-index-v8-e2e]   uploaded + flushed OK");
    }

    // ─── Part 2 — INDEPENDENT proof that the EXACT expected shard set exists
    //     on the UNCHANGED master, that each shard's plaintext matches ground
    //     truth, that the union reconstructs the full index, and that the
    //     legacy single-blob key is absent. No SDK read/rebuild path here. ───
    eprintln!("\n[dir-index-v8-e2e] part 2: independently verify shard objects on the master");
    let km = KeyManager::from_secret_key(secret.clone());
    let forest_dek = km.derive_path_key(&format!("forest:{}", bucket));
    let route_key = derive_dir_index_route_key(&forest_dek, &bucket);
    let raw = FulaClient::new(Config::new(&s3).with_token(&jwt)).expect("raw FulaClient::new");

    // Ground truth + the EXACT non-empty shard set the writer should produce.
    let gt = ground_truth_index(&files);
    let expected_shards: BTreeMap<u8, DirectoryIndex> =
        split_directory_index_into_shards(&gt, &route_key);
    let expected_shard_ids: BTreeSet<u8> = expected_shards.keys().copied().collect();
    assert!(
        expected_shard_ids.len() >= 2,
        "test corpus too small: ground-truth split into only {} shard(s); need ≥2 to \
         meaningfully exercise multi-shard routing",
        expected_shard_ids.len()
    );

    // HEAD every one of the 16 shard keys → the set physically present.
    let mut present_shard_ids: BTreeSet<u8> = BTreeSet::new();
    for idx in 0..DIR_INDEX_V8_NUM_SHARDS {
        let shard_key = derive_dir_index_shard_key(&forest_dek, &bucket, idx);
        if let Ok(h) = raw.head_object(&bucket, &shard_key).await {
            present_shard_ids.insert(idx);
            eprintln!(
                "[dir-index-v8-e2e]   shard {:>2} present (content_length={})",
                idx, h.content_length
            );
        }
    }
    eprintln!(
        "[dir-index-v8-e2e]   expected non-empty shards: {:?}",
        expected_shard_ids.iter().collect::<Vec<_>>()
    );
    eprintln!(
        "[dir-index-v8-e2e]   present on master:         {:?}",
        present_shard_ids.iter().collect::<Vec<_>>()
    );
    assert_eq!(
        present_shard_ids, expected_shard_ids,
        "the set of dir-index shard objects on the master must EXACTLY equal the set the \
         writer should have produced (computed locally via split_directory_index_into_shards). \
         A MISSING shard = a dropped/under-driven Phase-1.6 flush (the exact bug a plain \
         round-trip would mask via rebuild-from-forest). An EXTRA shard = routing nondeterminism \
         between write and the local model. Missing={:?} Extra={:?}",
        expected_shard_ids.difference(&present_shard_ids).collect::<Vec<_>>(),
        present_shard_ids.difference(&expected_shard_ids).collect::<Vec<_>>(),
    );

    // GET + decode + decrypt EVERY non-empty shard; assert per-shard plaintext
    // equality against ground truth, and accumulate the union.
    let mut reconstructed = DirectoryIndex {
        version: gt.version,
        entries: std::collections::HashMap::new(),
    };
    for (&idx, expected_sub) in &expected_shards {
        let shard_key = derive_dir_index_shard_key(&forest_dek, &bucket, idx);
        let bytes = raw
            .get_object(&bucket, &shard_key)
            .await
            .unwrap_or_else(|e| panic!("GET shard {idx} bytes from master: {e:?}"));
        assert!(!bytes.is_empty(), "served shard {idx} object is empty");
        let env = EncryptedDirectoryIndexShard::from_bytes(bytes.as_ref())
            .unwrap_or_else(|e| panic!("master must serve a well-formed v8 shard envelope for {idx}: {e:?}"));
        assert_eq!(
            env.shard_idx, idx,
            "served shard envelope shard_idx ({}) must match the requested idx ({})",
            env.shard_idx, idx
        );
        let (got_sub, _seq) = env
            .decrypt(&forest_dek, &bucket)
            .unwrap_or_else(|e| panic!("decrypt served shard {idx} under the per-shard key: {e:?}"));
        assert_eq!(
            got_sub.entries, expected_sub.entries,
            "shard {idx} plaintext directory entries (served by the master) must equal the \
             ground-truth sub-index for that shard. A mismatch = the writer routed/serialized \
             entries differently than the production split function — a write-path correctness bug \
             that rebuild-from-forest would silently mask on read.",
        );
        reconstructed.entries.extend(got_sub.entries);
    }
    assert_eq!(
        reconstructed.entries, gt.entries,
        "the UNION of all shard plaintexts (reconstructed purely from raw shard objects on the \
         master, with no SDK read/rebuild path) must equal the full ground-truth directory index. \
         A diff = the on-wire sharded representation is incomplete or wrong.",
    );
    eprintln!(
        "[dir-index-v8-e2e]   {} shards GET+decode+decrypt OK; union == ground truth ({} dir entries)",
        expected_shards.len(),
        gt.entries.len()
    );

    // The v8 write must NOT also write a legacy v7 single-blob dir-index.
    let legacy_key = derive_dir_index_key(&forest_dek, &bucket);
    assert!(
        raw.head_object(&bucket, &legacy_key).await.is_err(),
        "a v8 (sharded) bucket must NOT carry a legacy single-blob dir-index object at {} — \
         its presence means the writer double-wrote both formats",
        legacy_key
    );
    eprintln!("[dir-index-v8-e2e]   legacy single-blob dir-index key absent (no double-write)");

    // ─── Part 3 — FRESH-CACHE sharded read: a brand-new empty cache dir forces
    //     the read to genuinely fetch the manifest + every shard from the
    //     master (not residual warm state), exercising load_directory_index_sharded
    //     over the network. Every file (incl. chunked) must round-trip. ───
    eprintln!("\n[dir-index-v8-e2e] part 3: fresh-cache read via the sharded path (genuine master fetch)");
    let fresh_cache = TempDir::new().expect("tempdir: fresh read cache");
    {
        let client = build_v8_client(
            &s3,
            &jwt,
            &fresh_cache.path().join("blocks.redb"),
            secret.clone(),
            true,
            timeout_secs,
        );
        let listed = client
            .list_files_from_forest(&bucket)
            .await
            .expect("fresh-cache list_files_from_forest");
        let listed_keys: BTreeSet<String> = listed.iter().map(|f| f.original_key.clone()).collect();
        assert_eq!(
            listed_keys, expected_keys,
            "fresh-cache v8 sharded listing must equal the uploaded set ({} expected, {} got) — \
             a diff means the sharded read dropped directory entries",
            expected_keys.len(),
            listed_keys.len()
        );
        for (k, data, _) in &files {
            let got = client
                .get_object_flat(&bucket, k)
                .await
                .unwrap_or_else(|e| panic!("fresh-cache get_object_flat {k}: {e:?}"));
            assert_eq!(
                got.as_ref(),
                data.as_slice(),
                "round-trip byte mismatch for {k} ({} bytes) on fresh-cache sharded read",
                data.len()
            );
        }
        eprintln!(
            "[dir-index-v8-e2e]   fresh-cache list + {} downloads OK (incl. {} chunked)",
            files.len(),
            chunked_count
        );
    }

    // ─── Part 4 — WARM-OFFLINE: prove folders+files still load when the S3
    //     endpoint is unreachable. HONEST FRAMING (advisor): this serves from
    //     the on-disk block cache populated by a prior ONLINE read — it proves
    //     "warm reads do not depend on origin reachability", NOT "reads from an
    //     IPFS gateway". The genuine gateway-direct path is cold-start (see the
    //     UNVERIFIED note at the end). ───
    eprintln!("\n[dir-index-v8-e2e] part 4: warm-offline (cache-independence; NOT a gateway proof)");
    let warm_cache = TempDir::new().expect("tempdir: warm cache");
    {
        // 5a — online read warms the cache (manifest + dir-index shards + blocks).
        let online = build_v8_client(
            &s3,
            &jwt,
            &warm_cache.path().join("blocks.redb"),
            secret.clone(),
            true,
            timeout_secs,
        );
        let _ = online
            .list_files_from_forest(&bucket)
            .await
            .expect("warm-up online list");
        for (k, _, _) in &files {
            online
                .get_object_flat(&bucket, k)
                .await
                .unwrap_or_else(|e| panic!("warm-up online download {k}: {e:?}"));
        }
        drop(online);

        // 5b — offline (bogus master, same warm cache, health gate off) must
        // still list + download from cache without any reachable origin.
        let offline = build_v8_client(
            "http://127.0.0.1:1",
            &jwt,
            &warm_cache.path().join("blocks.redb"),
            secret.clone(),
            false,
            timeout_secs,
        );
        let listed = offline
            .list_files_from_forest(&bucket)
            .await
            .expect("warm-offline list must succeed from cache");
        let listed_keys: BTreeSet<String> = listed.iter().map(|f| f.original_key.clone()).collect();
        assert_eq!(
            listed_keys, expected_keys,
            "warm-offline list (S3 unreachable) must equal the uploaded set — folders must load \
             from the warm cache when the origin is down"
        );
        for (k, data, _) in &files {
            let got = offline
                .get_object_flat(&bucket, k)
                .await
                .unwrap_or_else(|e| panic!("warm-offline download {k} (S3 unreachable): {e:?}"));
            assert_eq!(
                got.as_ref(),
                data.as_slice(),
                "warm-offline byte mismatch for {k} — files must load from the warm cache when \
                 the origin is down"
            );
        }
        eprintln!(
            "[dir-index-v8-e2e]   warm-offline list + {} downloads OK with S3 unreachable (served from cache)",
            files.len()
        );
    }

    // ─── Part 5 (opt-in) — v7 coexistence: an OLD single-blob bucket still
    //     reads correctly under the new dispatch (empty dir_index_shards ⇒
    //     legacy path). Requires the account's real secret. ───
    if secret_is_real {
        // The coexistence read targets the account's existing v7 `images`
        // bucket (what FULA_VERIFY_IMAGES_BUCKET refers to). Overridable via
        // FULA_IMAGES_BUCKET. NOTE: this is intentionally NOT FULA_BUCKET —
        // that var is the test-upload default and may point elsewhere.
        let legacy_bucket = std::env::var("FULA_IMAGES_BUCKET")
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "images".to_string());
        eprintln!(
            "\n[dir-index-v8-e2e] part 5: v7 coexistence — read existing bucket '{}'",
            legacy_bucket
        );
        let coexist_cache = TempDir::new().expect("tempdir: coexistence cache");
        let client = build_v8_client(
            &s3,
            &jwt,
            &coexist_cache.path().join("blocks.redb"),
            secret.clone(),
            true,
            timeout_secs,
        );
        match client.list_files_from_forest(&legacy_bucket).await {
            Ok(listed) => {
                eprintln!(
                    "[dir-index-v8-e2e]   v7 coexistence: '{}' lists {} files via the legacy path",
                    legacy_bucket,
                    listed.len()
                );
                if env_flag("FULA_VERIFY_IMAGES_BUCKET") {
                    assert!(
                        !listed.is_empty(),
                        "FULA_VERIFY_IMAGES_BUCKET set but '{}' lists 0 files — either a v7 read \
                         regression under the new dispatch, or the derived secret doesn't match \
                         the account's actual encryption key",
                        legacy_bucket
                    );
                }
            }
            Err(e) => panic!(
                "v7 coexistence read of '{}' FAILED under the new dispatch code: {:?} — an old \
                 single-blob bucket must still read via the legacy path",
                legacy_bucket, e
            ),
        }
    } else {
        eprintln!("\n[dir-index-v8-e2e] part 5: v7 coexistence SKIPPED (no real-secret triple set)");
    }

    // ─── Best-effort cleanup (after all assertions pass). ───
    if env_flag("FULA_E2E_KEEP_BUCKET") {
        eprintln!(
            "\n[dir-index-v8-e2e] cleanup SKIPPED (FULA_E2E_KEEP_BUCKET set); bucket '{}' left in place",
            bucket
        );
    } else {
        // Fully empty the bucket via RAW list+delete (logical files + dir-index
        // shards + manifest/pages + content-addressed forest nodes), then drop
        // it. A logical `delete_object_flat` per file leaves the internal
        // objects, so `DELETE /{bucket}` would 409 BucketNotEmpty. Reuses the
        // raw probe client from Part 2.
        let mut all_keys: Vec<String> = Vec::new();
        let mut token: Option<String> = None;
        loop {
            let opts = fula_client::ListObjectsOptions {
                max_keys: Some(1000),
                continuation_token: token.clone(),
                ..Default::default()
            };
            match raw.list_objects(&bucket, Some(opts)).await {
                Ok(res) => {
                    for o in res.objects {
                        all_keys.push(o.key);
                    }
                    if res.is_truncated && res.next_continuation_token.is_some() {
                        token = res.next_continuation_token;
                    } else {
                        break;
                    }
                }
                Err(e) => {
                    eprintln!("[dir-index-v8-e2e] cleanup list_objects failed: {e:?}");
                    break;
                }
            }
        }
        let mut deleted = 0usize;
        for k in &all_keys {
            if raw.delete_object(&bucket, k).await.is_ok() {
                deleted += 1;
            }
        }
        let bucket_deleted = raw.delete_bucket(&bucket).await.is_ok();
        eprintln!(
            "\n[dir-index-v8-e2e] cleanup: deleted {}/{} raw objects, delete_bucket={}",
            deleted,
            all_keys.len(),
            bucket_deleted
        );
        if !bucket_deleted {
            eprintln!(
                "[dir-index-v8-e2e] NOTE: bucket '{}' may remain — run cleanup_test_bucket with \
                 FULA_CLEANUP_BUCKET={} to remove it.",
                bucket, bucket
            );
        }
    }

    eprintln!(
        "\n[dir-index-v8-e2e] PASS — v8 sharded dir-index writes the EXACT expected shard set, \
         the unchanged master retains+serves valid shard bytes, the union reconstructs the full \
         index, and every file (incl. chunked) round-trips via the sharded read path + warm-offline."
    );
    eprintln!(
        "[dir-index-v8-e2e] UNVERIFIED HERE: \"reads directly from an IPFS gateway with S3 down AND \
         a cold cache\" is the cold-start path — it needs chain-RPC + IPNS + anchor + \
         FULA_BLOCK_GATEWAY_URLS config (not in the default creds). Run \
         `offline_cold_start_documents_bucket_e2e` / the fxfiles-open-bucket flow in offline_e2e.rs \
         with that env to exercise it; those now cover the v8 sharded dir-index too."
    );
}
