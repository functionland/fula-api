//! Walkable-v8 scale benchmark (W.9.7).
//!
//! Measures the **curves** that pin the architectural claims in plan
//! W.8: write throughput, walk time, manifest size, internal-node
//! count. The complementary block-size assertion test (in
//! `sharded_hamt_forest::tests::walkable_v8_block_size_*`) measures
//! the **fact** that no IPFS block exceeds 1 MiB at any scale.
//!
//! # What this answers
//!
//! - **Write throughput**: entries/sec at 1k / 10k / 50k. Establishes
//!   a regression-detection baseline for future cascade refactors.
//! - **Walk time** (`list_recursive`): grows as `O(N + log_16 N)` —
//!   linear in the number of returned files plus the per-shard load
//!   cost. The bench plots both inputs to validate the claim.
//! - **Manifest size**: the encrypted root + page blobs. Should grow
//!   sub-linearly because PageRef rows are bounded by `MAX_PAGES`
//!   and the per-page blob is a constant-size `Vec<ShardV7>`.
//! - **Internal-node count**: the number of HAMT internal-node blobs
//!   pinned to the backend. Should grow as `~N / 16` (HAMT branching
//!   factor) at low N, then plateau as shards saturate.
//! - **Total bytes pinned**: sum of every persisted blob's size.
//!   **HAMT-internal-node ciphertexts only** — `flush_dirty` only
//!   persists nodes via `V7NodeStore` (`__fula_forest_v7_nodes/`
//!   prefix); manifest root, manifest pages, and dir-index are
//!   returned in-memory by the forest's flush, not PUT to the
//!   bench's `BlobBackend`. So this bench measures the surface
//!   where LinkV2 pointer overhead actually lives — but the broader
//!   "total bytes pinned including manifest/page/dir-index" claim
//!   from plan W.8 is not validated by THIS bench. Empirical finding
//!   (#74, 2026-05-09): HAMT-only growth is 2.2-4.6% across N=1k/10k/50k
//!   and 16/256-shard configurations — meaningfully BELOW plan W.8.2's
//!   "5-20%" prediction. Plan text needs adjustment.
//!
//! # Why a separate bench file
//!
//! Per advisor's W.9.7 brief: "benches measure curves, tests assert
//! facts — don't conflate." The bench output (criterion's HTML
//! reports) is the canonical signal for "did the architectural
//! curves change after my refactor". The block-size assertion
//! lives in `tests/` because it's pass/fail.
//!
//! # How to run
//!
//! ```text
//! cargo bench --bench walkable_v8_scale
//! ```
//!
//! Criterion writes results under `target/criterion/`. For
//! pre-rollout sign-off, also run the `#[ignore]` block-size tests
//! (see W.9.7 task description).

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use fula_crypto::{
    keys::DekKey,
    private_forest::ForestFileEntry,
    sharded_hamt_forest::ShardedHamtPrivateForest,
    wnfs_hamt::{BlobBackend, BlobPutResult},
    Result as CryptoResult,
};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

// ════════════════════════════════════════════════════════════════════════
// In-bench backend
// ════════════════════════════════════════════════════════════════════════

/// Walkable-v8-aware in-memory backend. Returns `Some(BLAKE3-raw-cid)`
/// from `put` so the writer cascade emits `LinkV2` pointers (the v8
/// path); the existing `BenchBackend` in `crypto_benchmarks.rs`
/// returns `BlobPutResult::none()` and would silently regress this
/// bench to v7 wire format.
struct WalkableV8BenchBackend {
    objects: Mutex<HashMap<String, Vec<u8>>>,
}

impl WalkableV8BenchBackend {
    fn new() -> Self {
        Self {
            objects: Mutex::new(HashMap::new()),
        }
    }

    fn cid_for(bytes: &[u8]) -> cid::Cid {
        let h = blake3::hash(bytes);
        let mh = cid::multihash::Multihash::<64>::wrap(0x1e, h.as_bytes())
            .expect("blake3 multihash wrap");
        cid::Cid::new_v1(0x55, mh)
    }

    fn object_count(&self) -> usize {
        self.objects.lock().unwrap().len()
    }

    fn total_bytes(&self) -> usize {
        self.objects
            .lock()
            .unwrap()
            .values()
            .map(|v| v.len())
            .sum()
    }

    fn internal_node_count(&self) -> usize {
        // HAMT internal-node objects are stored under the
        // `__fula_forest_v7_nodes/` prefix per `V7NodeStore::object_path`.
        self.objects
            .lock()
            .unwrap()
            .keys()
            .filter(|k| k.starts_with("__fula_forest_v7_nodes/"))
            .count()
    }
}

#[async_trait::async_trait]
impl BlobBackend for WalkableV8BenchBackend {
    async fn get(&self, path: &str) -> CryptoResult<Vec<u8>> {
        self.objects
            .lock()
            .unwrap()
            .get(path)
            .cloned()
            .ok_or_else(|| {
                fula_crypto::CryptoError::Hamt(format!("object not found: {}", path))
            })
    }

    async fn put(&self, path: &str, bytes: Vec<u8>) -> CryptoResult<BlobPutResult> {
        let cid = Self::cid_for(&bytes);
        self.objects
            .lock()
            .unwrap()
            .insert(path.to_string(), bytes);
        Ok(BlobPutResult { cid: Some(cid) })
    }
}

/// **#74 (2026-05-09)** — v7 baseline backend. Returns
/// `BlobPutResult::none()` from `put` so the writer cascade emits
/// legacy `Pointer::Link(StorageKey)` (v7 wire format) instead of
/// `Pointer::LinkV2 { storage_key, cid }` (v8). Lets each bench run
/// both backends side-by-side and report the actual v8-over-v7
/// growth — validates plan W.8.2's "5-20% relative growth" claim
/// and W.8.4's "no extra round trips" claim with empirical numbers
/// instead of predictions.
struct LegacyV7BenchBackend {
    objects: Mutex<HashMap<String, Vec<u8>>>,
}

impl LegacyV7BenchBackend {
    fn new() -> Self {
        Self {
            objects: Mutex::new(HashMap::new()),
        }
    }

    fn object_count(&self) -> usize {
        self.objects.lock().unwrap().len()
    }

    fn total_bytes(&self) -> usize {
        self.objects
            .lock()
            .unwrap()
            .values()
            .map(|v| v.len())
            .sum()
    }

    fn internal_node_count(&self) -> usize {
        self.objects
            .lock()
            .unwrap()
            .keys()
            .filter(|k| k.starts_with("__fula_forest_v7_nodes/"))
            .count()
    }
}

#[async_trait::async_trait]
impl BlobBackend for LegacyV7BenchBackend {
    async fn get(&self, path: &str) -> CryptoResult<Vec<u8>> {
        self.objects
            .lock()
            .unwrap()
            .get(path)
            .cloned()
            .ok_or_else(|| {
                fula_crypto::CryptoError::Hamt(format!("object not found: {}", path))
            })
    }

    async fn put(&self, path: &str, bytes: Vec<u8>) -> CryptoResult<BlobPutResult> {
        // v7 path: no CID surfaced → writer emits Link(StorageKey).
        self.objects
            .lock()
            .unwrap()
            .insert(path.to_string(), bytes);
        Ok(BlobPutResult::none())
    }
}

// ════════════════════════════════════════════════════════════════════════
// Helpers
// ════════════════════════════════════════════════════════════════════════

fn bench_dek() -> DekKey {
    DekKey::from_bytes(&[0x77u8; 32]).unwrap()
}

fn make_entry(path: &str) -> ForestFileEntry {
    ForestFileEntry {
        path: path.to_string(),
        // Minimal-size storage_key field — bench cares about HAMT
        // shape, not realistic per-file metadata.
        storage_key: format!("Qm{}", hex::encode(&blake3::hash(path.as_bytes()).as_bytes()[..22])),
        size: 0,
        content_type: None,
        created_at: 0,
        modified_at: 0,
        content_hash: None,
        user_metadata: Default::default(),
        encrypted: false,
        min_version: 0,
        storage_cid: None,
    }
}

/// Populate a forest with `n` entries (256-shard, v8 backend — the
/// production-default configuration). Returns the populated forest
/// + backend so post-population queries can inspect the state.
async fn populate_forest(
    n: usize,
) -> (
    ShardedHamtPrivateForest,
    Arc<WalkableV8BenchBackend>,
) {
    populate_forest_v8(n, 256).await
}

/// **#74**: v8 populate parameterized by `num_shards`. Used to
/// reproduce the W.8.2 prediction "~32 internal nodes at 1k" which
/// was calibrated for a 16-shard configuration; the bench's 256-shard
/// default would otherwise leave that prediction unverifiable.
async fn populate_forest_v8(
    n: usize,
    num_shards: usize,
) -> (
    ShardedHamtPrivateForest,
    Arc<WalkableV8BenchBackend>,
) {
    let backend = Arc::new(WalkableV8BenchBackend::new());
    let mut forest = ShardedHamtPrivateForest::new("bench-bucket", bench_dek(), num_shards);
    // **#74**: distribute across `sqrt(N)` parent dirs so dir-local
    // routing actually exercises multiple shards. Single-dir
    // population would route ALL entries to one shard regardless of
    // num_shards, making the 16-vs-256-shard comparison degenerate
    // (identical HAMT shapes, identical bytes). Matches the W.9.7
    // stress test's distribution heuristic.
    let dirs_per_layer: usize = ((n as f64).sqrt() as usize).max(1);
    for i in 0..n {
        let dir_idx = i % dirs_per_layer;
        let path = format!("/d{:04}/f{:08}.bin", dir_idx, i);
        forest
            .upsert_file(make_entry(&path), &backend)
            .await
            .unwrap();
    }
    forest.flush_dirty(&backend).await.unwrap();
    (forest, backend)
}

/// **#74**: v7 baseline populate. Same shape as `populate_forest_v8`
/// but the writer cascade emits legacy `Pointer::Link(StorageKey)`
/// because the backend returns `BlobPutResult::none()`. Lets each
/// structural-metrics measurement compute v7-vs-v8 deltas.
async fn populate_forest_v7(
    n: usize,
    num_shards: usize,
) -> (
    ShardedHamtPrivateForest,
    Arc<LegacyV7BenchBackend>,
) {
    let backend = Arc::new(LegacyV7BenchBackend::new());
    let mut forest = ShardedHamtPrivateForest::new("bench-bucket", bench_dek(), num_shards);
    // Same distribution as `populate_forest_v8` so the v7-vs-v8
    // comparison is apples-to-apples.
    let dirs_per_layer: usize = ((n as f64).sqrt() as usize).max(1);
    for i in 0..n {
        let dir_idx = i % dirs_per_layer;
        let path = format!("/d{:04}/f{:08}.bin", dir_idx, i);
        forest
            .upsert_file(make_entry(&path), &backend)
            .await
            .unwrap();
    }
    forest.flush_dirty(&backend).await.unwrap();
    (forest, backend)
}

// ════════════════════════════════════════════════════════════════════════
// Benches
// ════════════════════════════════════════════════════════════════════════

/// Write throughput at increasing N. Plots `entries/sec`. The expected
/// shape: roughly constant per-entry cost (HAMT depth grows
/// logarithmically), so total time grows linearly with N. A regression
/// where total time grew faster than linear would surface here as a
/// declining throughput curve.
fn bench_walkable_v8_write_throughput(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let mut group = c.benchmark_group("walkable_v8_write_throughput");
    group.sample_size(10);

    // **#74**: bench BOTH v7 and v8 throughput so plan W.8.4's
    // "no extra round trips" claim can be empirically validated —
    // v8 entries/sec should equal v7 entries/sec to within
    // measurement noise. If v8 is meaningfully slower, the writer
    // cascade introduced extra round trips somewhere.
    for &n in [1_000usize, 10_000, 50_000].iter() {
        group.throughput(Throughput::Elements(n as u64));
        group.bench_with_input(BenchmarkId::new("v8/entries", n), &n, |b, &n| {
            b.iter(|| {
                rt.block_on(async {
                    let _ = populate_forest_v8(n, 256).await;
                });
            });
        });
        group.bench_with_input(BenchmarkId::new("v7/entries", n), &n, |b, &n| {
            b.iter(|| {
                rt.block_on(async {
                    let _ = populate_forest_v7(n, 256).await;
                });
            });
        });
    }
    group.finish();
}

/// `list_recursive` walk time — the "open the bucket and list every
/// file" path that a v8 reader would exercise on cold-start. Measured
/// after a full populate + flush so the walker traverses persisted
/// HAMT nodes (matches the production "freshly-installed device
/// re-opens forest from manifest" timing).
fn bench_walkable_v8_walk_time(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let mut group = c.benchmark_group("walkable_v8_walk_time");
    group.sample_size(10);

    for &n in [1_000usize, 10_000, 50_000].iter() {
        // Pre-populate ONCE per N so the timed loop measures only the
        // walk cost, not the populate cost.
        let (forest_template, backend) = rt.block_on(async {
            let r = populate_forest(n).await;
            r
        });
        let manifest = forest_template.manifest().clone();

        group.throughput(Throughput::Elements(n as u64));
        group.bench_with_input(BenchmarkId::new("entries", n), &n, |b, _| {
            b.iter(|| {
                rt.block_on(async {
                    // Re-open from manifest each iteration so each
                    // run measures cold-walk cost (no cached
                    // ShardedHamt internal state from a prior
                    // iteration). `list_recursive` takes `&self` so
                    // the binding doesn't need `mut`.
                    let reader = ShardedHamtPrivateForest::from_manifest(
                        manifest.clone(),
                        "bench-bucket",
                        bench_dek(),
                    );
                    let _files = reader.list_recursive("/", &backend).await.unwrap();
                });
            });
        });
    }
    group.finish();
}

/// Reports a one-shot sweep of structural metrics across N. NOT
/// timed — criterion runs the closure once per iteration anyway,
/// but the values are deterministic given N. Output goes to stdout
/// so the operator can read the manifest-size and internal-node-count
/// curves alongside the timing numbers.
///
/// Use this group's output to verify the W.8 architectural claims:
/// - manifest size grows sub-linearly with N
/// - internal-node count grows roughly linearly at low N then plateaus
/// - total bytes pinned grows linearly with N (each entry contributes
///   ~one leaf-bucket entry's worth of bytes)
fn bench_walkable_v8_structural_metrics(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let mut group = c.benchmark_group("walkable_v8_structural_metrics");
    group.sample_size(10);

    // **#74 (2026-05-09)** — for each (shard_count, N) configuration,
    // populate BOTH v7 and v8 backends and report side-by-side numbers
    // plus the v8-over-v7 % delta. Validates plan W.8.2's "5-20%
    // relative growth" claim and W.8.4's "no extra round trips"
    // claim with empirical numbers.
    //
    // Two shard configurations:
    // - **256**: production default (matches the existing
    //   `walkable_v8_block_size_*` tests). Reflects realistic
    //   FxFiles-scale sharding.
    // - **16**: the configuration W.8.2's "~32 internal nodes at 1k"
    //   prediction was originally calibrated against. Lets the
    //   operator verify the prediction without changing plan text.
    for &num_shards in [16usize, 256usize].iter() {
        for &n in [1_000usize, 10_000, 50_000].iter() {
            let (_v8_forest, v8_backend) = rt.block_on(async {
                populate_forest_v8(n, num_shards).await
            });
            let (_v7_forest, v7_backend) = rt.block_on(async {
                populate_forest_v7(n, num_shards).await
            });

            let v8_total = v8_backend.total_bytes();
            let v7_total = v7_backend.total_bytes();
            let pct_growth = if v7_total > 0 {
                (v8_total as f64 - v7_total as f64) / v7_total as f64 * 100.0
            } else {
                0.0
            };

            eprintln!(
                "[#74 v7-vs-v8 shards={} N={}] \
                 v7: objects={} internal_nodes={} total_bytes={} | \
                 v8: objects={} internal_nodes={} total_bytes={} | \
                 v8-over-v7-bytes-delta: {:+.2}%",
                num_shards,
                n,
                v7_backend.object_count(),
                v7_backend.internal_node_count(),
                v7_total,
                v8_backend.object_count(),
                v8_backend.internal_node_count(),
                v8_total,
                pct_growth,
            );

            group.bench_with_input(
                BenchmarkId::new(format!("shards={}_snapshot", num_shards), n),
                &n,
                |b, _| {
                    b.iter(|| {
                        let _ = v8_backend.object_count();
                    });
                },
            );
        }
    }
    group.finish();
}

criterion_group!(
    walkable_v8_scale,
    bench_walkable_v8_write_throughput,
    bench_walkable_v8_walk_time,
    bench_walkable_v8_structural_metrics
);
criterion_main!(walkable_v8_scale);
