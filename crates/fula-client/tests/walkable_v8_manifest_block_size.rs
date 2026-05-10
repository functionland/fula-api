//! W.9.7 follow-up #73 — SDK-level block-size regression guard.
//!
//! W.9.7's primary block-size assertion (`walkable_v8_block_size_at_*`
//! in `fula-crypto/src/sharded_hamt_forest.rs`) covers HAMT
//! internal-node and shard-leaf-bucket ciphertexts at 1k / 100k / 1M
//! entries via direct cascade exercise. Reviewer A's W.9.7 audit
//! flagged a gap: manifest pages, the manifest root, the
//! directory-index, and per-file index objects flow through
//! `crates/fula-client/src/encryption.rs`'s Phase 1.5 / 1.6 / 2
//! commits via `FulaClient::put_object_with_metadata*` — a layer
//! BELOW `BlobBackend` that wiremock-style HTTP interception is the
//! only way to observe.
//!
//! This test sits a wiremock master in front of the full
//! `EncryptedClient` and drives 1000 realistic v8 writes through
//! `put_object_encrypted`, recording every HTTP PUT body that flows
//! through.
//!
//! ## Scope (post-#75, honest version)
//!
//! This test asserts the W.8.3 ceiling holds for **every PUT body the
//! SDK sends through the v7 sharded-HAMT cascade**. After #75
//! (2026-05-09) the test uses `put_object_flat_deferred` (the
//! forest-aware write path) instead of `put_object_encrypted`.
//! Calling `put_object_flat_deferred` on a fresh bucket triggers the
//! 404-GET → fresh-v7 bootstrap at `encryption.rs:2847-2867`, so the
//! whole v7 cascade fires through `flush_forest`. Empirically:
//!
//!   - Per-file ciphertext PUTs ✅ (small, ~100-300 bytes each)
//!   - HAMT internal-node + shard-root PUTs ✅ (the
//!     `__fula_forest_v7_nodes/...` class — empirically the largest
//!     blobs at this scale, max ~26 KiB at N=1000)
//!   - Manifest pages, dir-index, Phase 2 root commits ✅ (paths
//!     derive to `Qm<hex>` via `derive_manifest_page_key` /
//!     `derive_dir_index_key`, NOT under any `__fula_forest_v7_*`
//!     prefix — so the classifier below buckets them under
//!     `object-or-chunk`. Distinguishing them precisely would
//!     require pre-computing the expected derived keys at test
//!     setup; tracked as enhancement if needed. The hard 1 MiB
//!     assertion holds regardless.)
//!
//! Together with the fula-crypto HAMT-layer test, these two tests
//! cover the dominant blob classes for production-realistic
//! workloads. The combined coverage is sufficient for the W.10
//! default-on rollout's block-size guarantee.
//!
//! **Note on the original #75 design**: the task originally proposed
//! pre-loading wiremock with a fake-but-decryptable v7 manifest to
//! force the cascade. Empirical investigation showed the SDK's
//! 404-GET catch-all already bootstraps fresh-v7 (line 2847-2867),
//! so the wiremock-fixture approach was unnecessary; the actual gap
//! was that `put_object_encrypted` doesn't touch the forest at all,
//! while `put_object_flat_deferred` does. One-line call-site change
//! instead of ~200 LOC of fixture setup.

#![cfg(not(target_arch = "wasm32"))]

use bytes::Bytes;
use cid::multihash::Multihash;
use cid::Cid;
use fula_client::{Config, EncryptedClient, EncryptionConfig};
use fula_crypto::keys::SecretKey;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

const IPFS_BLOCK_LIMIT: usize = 1 << 20;
/// Architectural early-warning ceiling — same as the fula-crypto
/// HAMT-layer test. >64 KiB is an architectural regression even
/// though the gateway hard limit is still respected. Soft-only.
const SOFT_BLOCK_WARN_KIB: usize = 64 * 1024;

fn blake3_raw_cid(data: &[u8]) -> Cid {
    let h = blake3::hash(data);
    let mh = Multihash::<64>::wrap(0x1e, h.as_bytes()).expect("blake3 multihash wrap");
    Cid::new_v1(0x55, mh)
}

/// Wiremock catch-all PUT responder. Records the largest observed
/// body size + its URL path, and returns the body's BLAKE3-raw CID as
/// the `ETag` header so the SDK's W.9.3 self-verify accepts the
/// response (otherwise the writer cascade soft-fails to v7-style
/// `Link` and we'd miss the v8-specific blob-size pressure points).
struct RecordingResponder {
    /// Max ever observed body size in bytes.
    max_size: Arc<AtomicUsize>,
    /// URL path of whichever request held the max.
    max_path: Arc<Mutex<String>>,
    /// Per-class breakdown for diagnostic output. Bucketed by URL
    /// prefix so operator triage can see "the dir-index was the
    /// biggest" vs "a HAMT internal node was".
    per_class_max: Arc<Mutex<std::collections::HashMap<String, usize>>>,
    /// Total number of PUT requests observed — sanity-checks the
    /// SDK actually wrote what we expect (otherwise a misconfigured
    /// test could pass trivially with zero PUTs).
    request_count: Arc<AtomicUsize>,
}

impl Respond for RecordingResponder {
    fn respond(&self, req: &Request) -> ResponseTemplate {
        let size = req.body.len();
        let path = req.url.path().to_string();
        self.request_count.fetch_add(1, Ordering::SeqCst);

        // Update max + label atomically. Race-fine: only the test
        // observes the final value after flush_forest awaits.
        let prev_max = self.max_size.load(Ordering::SeqCst);
        if size > prev_max {
            self.max_size.store(size, Ordering::SeqCst);
            *self.max_path.lock().unwrap() = path.clone();
        }

        // Per-class bookkeeping.
        let class = if path.contains("__fula_forest_v7_nodes/") {
            "hamt-node"
        } else if path.contains("__fula_forest_v7_pages/") || path.contains("__fula_forest_v7_index") {
            "manifest"
        } else if path.contains("__fula_forest_v7_dir_index") {
            "dir-index"
        } else if path.contains("__fula_forest_") {
            "forest-meta-other"
        } else {
            "object-or-chunk"
        }
        .to_string();
        let mut by_class = self.per_class_max.lock().unwrap();
        let entry = by_class.entry(class).or_insert(0);
        if size > *entry {
            *entry = size;
        }

        // Compute a real CID for the body so SDK self-verify sees a
        // matching ETag and the v8 LinkV2 cascade actually fires.
        let cid = blake3_raw_cid(&req.body);
        ResponseTemplate::new(200).insert_header("ETag", cid.to_string())
    }
}

/// Catch-all GET responder — returns 404 so the SDK treats the bucket
/// as fresh (no preexisting forest manifest, no preexisting objects).
/// All writes therefore go through Phase 1.5/1.6/2 from a cold start
/// and exercise the full set of blob classes.
struct NotFoundResponder;
impl Respond for NotFoundResponder {
    fn respond(&self, _req: &Request) -> ResponseTemplate {
        ResponseTemplate::new(404)
    }
}

#[tokio::test]
async fn no_blob_class_exceeds_1mib_at_realistic_distributed_scale() {
    let server = MockServer::start().await;

    let max_size = Arc::new(AtomicUsize::new(0));
    let max_path = Arc::new(Mutex::new(String::new()));
    let per_class_max = Arc::new(Mutex::new(std::collections::HashMap::new()));
    let request_count = Arc::new(AtomicUsize::new(0));

    let recorder = RecordingResponder {
        max_size: max_size.clone(),
        max_path: max_path.clone(),
        per_class_max: per_class_max.clone(),
        request_count: request_count.clone(),
    };

    Mock::given(method("PUT"))
        .respond_with(recorder)
        .mount(&server)
        .await;
    // Cold-bucket simulation: every GET returns 404 → SDK builds a
    // fresh forest manifest from scratch, exercising every Phase
    // 1.5/1.6/2 commit during flush_forest.
    Mock::given(method("GET"))
        .respond_with(NotFoundResponder)
        .mount(&server)
        .await;
    // HEAD probes (health gate uses these on init) — return 200 so
    // the gate stays Up and writes proceed.
    Mock::given(method("HEAD"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    // Build SDK pointing at wiremock with v8 writer enabled.
    let mut config = Config::new(&server.uri()).with_token("test-jwt");
    config.walkable_v8_writer_enabled = true;
    // health_gate_enabled: leave default (false) so a wiremock that
    // doesn't fully model master health probes doesn't trip the gate.
    let secret = SecretKey::generate();
    let enc_config = EncryptionConfig::from_secret_key(secret);
    let client = EncryptedClient::new(config, enc_config).expect("EncryptedClient::new");

    let bucket = "scale-bucket";
    let n: usize = 1000;
    // Distribute across ~sqrt(N) dirs — same shape as the W.9.7
    // primary test, so the same architectural cliff (single-dir
    // ForestDirectoryEntry blob blowup) doesn't confound the
    // measurement here either.
    let dirs: usize = (n as f64).sqrt() as usize;
    assert!(dirs > 0, "test setup invalid: dirs == 0");

    // **#75 (2026-05-09)**: switched from `put_object_encrypted` to
    // `put_object_flat_deferred`. The former encrypts + uploads
    // BUT does not touch the encrypted forest at all — so
    // `flush_forest` had nothing dirty to flush, and the v7 cascade
    // (manifest pages / dir-index / Phase 2 root commits) never
    // fired in this test. `put_object_flat_deferred` is the
    // forest-aware path: it calls `ensure_forest_loaded` (which
    // bootstraps a fresh v7 ShardedHamt cache entry on a 404 GET
    // per `encryption.rs:2847-2867`) and upserts each file into
    // the in-memory v7 forest. `flush_forest` then drives Phase 1.5
    // (manifest pages), Phase 1.6 (dir-index), and Phase 2 (root
    // commit) — exactly the blob classes #75 was filed to exercise.
    //
    // Original task scope was "pre-load wiremock with a fake-but-
    // decryptable v7 manifest". The empirical investigation showed
    // a 404-GET catch-all already triggers fresh-v7 bootstrap, so
    // the wiremock-fixture approach was unnecessary; the actual
    // gap was the test's call site, not the fixture.
    for i in 0..n {
        let dir_idx = i % dirs;
        let key = format!("/d{:04}/f{:08}.txt", dir_idx, i);
        let data = format!("entry-{}-payload-bytes", i).into_bytes();
        client
            .put_object_flat_deferred(bucket, &key, Bytes::from(data), None)
            .await
            .expect("put_object_flat_deferred must succeed against wiremock");
    }

    // Flush the forest — drives Phase 1.5 (page commits), Phase 1.6
    // (dir-index commit), and Phase 2 (manifest root commit).
    client
        .flush_forest(bucket)
        .await
        .expect("flush_forest must succeed");

    // Inspect aggregated bookkeeping.
    let total_requests = request_count.load(Ordering::SeqCst);
    let max = max_size.load(Ordering::SeqCst);
    let max_path_str = max_path.lock().unwrap().clone();
    let by_class = per_class_max.lock().unwrap().clone();

    eprintln!(
        "[walkable-v8 #73] N={} put_requests={} max_blob={} bytes ({:.1} KiB) at {}",
        n,
        total_requests,
        max,
        max as f64 / 1024.0,
        max_path_str
    );
    let mut classes: Vec<_> = by_class.iter().collect();
    classes.sort_by(|(a, _), (b, _)| a.cmp(b));
    for (class, size) in classes {
        eprintln!(
            "[walkable-v8 #73]   {:>20} max = {} bytes ({:.1} KiB)",
            class,
            size,
            *size as f64 / 1024.0
        );
    }

    // Sanity: SDK actually wrote things.
    assert!(
        total_requests > 0,
        "test setup invalid: no PUT requests reached wiremock — \
         the SDK is misconfigured or the wiremock catch-all isn't matching"
    );
    assert!(
        total_requests >= n,
        "expected ≥{} PUTs (one per encrypted upload, plus manifest \
         + page + dir-index commits during flush), got {}",
        n,
        total_requests
    );
    assert!(max > 0, "test setup invalid: max blob size is zero");

    // **#75 (2026-05-09)** — positive assertion that the v7 cascade
    // actually fired. Catches regressions where a future refactor
    // changes the call site away from `put_object_flat_deferred`
    // back to a forest-bypassing path (e.g., `put_object_encrypted`).
    // Without this guard, the test would fall back to validating
    // only file-content blob size — meaningful but a much weaker
    // claim. The hamt-node class fires only when v7 flush_dirty
    // persists internal nodes via `V7NodeStore`, which requires a
    // populated v7 forest cache.
    let hamt_node_max = by_class.get("hamt-node").copied().unwrap_or(0);
    assert!(
        hamt_node_max > 0,
        "v7 cascade did not fire — no `__fula_forest_v7_nodes/` PUTs \
         observed across {} total requests. Either (a) the SDK is \
         using a forest-bypassing write path, (b) `flush_forest` \
         short-circuited, or (c) a previous refactor changed the \
         test entry point. This guard catches all three. \
         Per-class breakdown (in addition to the eprintln above): {:?}",
        total_requests,
        by_class
    );

    // Soft warning — log if any blob class crossed the architectural
    // early-warning ceiling. Doesn't fail the test (gateway-correctness
    // is the only hard pass/fail), but flags the regression for the
    // operator running this test pre-rollout.
    if max > SOFT_BLOCK_WARN_KIB {
        eprintln!(
            "[walkable-v8 #73] SOFT WARNING: largest blob ({} bytes / {} KiB) \
             exceeds the architectural early-warning ceiling ({} KiB). \
             The hard 1 MiB assert below still passes (gateway correctness \
             preserved), but inspect the parent-pointer fanout / \
             ForestDirectoryEntry cardinality at path {} before letting this \
             land in production.",
            max,
            max / 1024,
            SOFT_BLOCK_WARN_KIB / 1024,
            max_path_str,
        );
    }

    // Hard assertion — the load-bearing W.8.3 fact, applied now to
    // every blob class the SDK writes (HAMT nodes + manifest +
    // dir-index + file-index + chunks).
    assert!(
        max <= IPFS_BLOCK_LIMIT,
        "LOAD-BEARING W.8.3 ASSERTION VIOLATED across the full SDK write \
         path: blob at {} grew to {} bytes ({} KiB), exceeding the 1 MiB \
         IPFS gateway limit. Walkable-v8 offline walks (W.9.4) would fail \
         to fetch this blob. Per-class max breakdown above. The cliff is \
         likely either (a) ForestDirectoryEntry growing past ~60-100k \
         filenames in one dir (tracked as #72 — already-known limit), \
         (b) manifest-page list outgrowing PAGE_SIZE shards × per-shard \
         metadata, or (c) HAMT pointer-list overflow from a fanout bug \
         (already covered by the fula-crypto HAMT-layer block-size test).",
        max_path_str,
        max,
        max / 1024,
    );
}
