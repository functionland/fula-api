//! #91 regression guard: `get_object_flat` MUST NOT trigger an O(N)
//! `find_by_storage_key` linear scan over the v7 sharded HAMT.
//!
//! Bug history: prior to #91, the v7 read path in `get_object_flat`
//! walked the HAMT once via `get_file(path)` to translate the user's
//! logical path into a `ForestFileEntry`, then dropped the entry and
//! called `get_object_decrypted_by_storage_key(storage_key)`. That
//! callee invoked `forest_entry_lookup` → `find_by_storage_key` →
//! `list_all_files` — an O(N) full-forest scan. For warm-cache reads
//! the wasted I/O was hidden by master-S3 latency dominating the budget,
//! but for cold-cache offline reads (master down + every internal-node
//! fetch is a 1-30s gateway race) the scan dwarfed the actual file
//! fetch. A 100-entry bucket would issue ~100 gateway races for a
//! single 50KB file read — minutes per read.
//!
//! Fix: `get_object_flat`'s v7 branch now passes the entry directly to
//! a new `get_object_decrypted_by_entry` private method, which
//! delegates to a shared `_inner` body that takes the entry instead of
//! looking it up. Public `_by_storage_key` API unchanged for callers
//! without an entry (share-token path, path-based public API).
//!
//! This test is the load-bearing regression guard. Without it a future
//! refactor could silently re-introduce the O(N) scan and the bug would
//! return invisibly until production cold-cache reads slowed to a
//! crawl. The bound below (`MAX_READ_GETS`) is conservative — a real
//! O(N) scan on N=64 entries would issue ≥64 GETs, comfortably above
//! the threshold; the post-fix path issues ≤O(log N) GETs for the
//! HAMT walk plus 1 for the file fetch, well under the threshold.

#![cfg(not(target_arch = "wasm32"))]

use bytes::Bytes;
use cid::multihash::Multihash;
use cid::Cid;
use fula_client::{Config, EncryptedClient, EncryptionConfig};
use fula_crypto::keys::SecretKey;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

/// Number of files to write before issuing the read. Picked to be
/// well above the O(log N) HAMT depth (so an O(N) scan would be
/// distinguishable from the bounded walk) but small enough that the
/// test runs in a couple of seconds.
const N_FILES: usize = 64;

/// Upper bound on GETs the read phase is allowed to issue against the
/// wiremock master after `invalidate_all_forest_caches` forces a fresh
/// load.
///
/// **Empirically observed post-fix**: 6 GETs (1 manifest + 1 dir-index
/// probe + 1 shard root + 1 internal-node walk + 1 leaf bucket + 1 file
/// body, roughly).
///
/// **Pre-fix expected**: ≥40 GETs. `find_by_storage_key` →
/// `list_all_files` → `collect_all_entries` would
/// `ensure_shard_loaded` for every one of the 16 v7 default shards
/// (16 GETs minimum just for shard roots) plus walk every leaf bucket
/// across all shards (~16-30 more GETs depending on HAMT branching
/// and entry distribution). The total is comfortably ≥40 in any
/// realistic shard layout — see `sharded_hamt_forest.rs:1499-1506`
/// for the O(N) scan implementation.
///
/// **Threshold = 16**: tight enough to catch any regression that
/// re-introduces a per-shard fetch (the cheapest O(N) scan still
/// has to fetch all 16 shard roots), loose enough that the post-fix
/// path's ~6 GETs has 10× slack against unrelated test
/// infrastructure changes.
const MAX_READ_GETS: usize = 16;

fn blake3_raw_cid(data: &[u8]) -> Cid {
    let h = blake3::hash(data);
    let mh = Multihash::<64>::wrap(0x1e, h.as_bytes()).expect("blake3 multihash wrap");
    Cid::new_v1(0x55, mh)
}

/// Body-stashing wiremock responder: PUTs record (path → body) so GETs
/// can replay them; tracks GET counts gated by a flag so we only count
/// GETs in the read phase (not setup-phase forest_load probing). Also
/// returns the body's BLAKE3-raw CID as the `ETag` on PUT response so
/// the SDK's W.9.3 self-verify accepts the round-trip and the v8
/// LinkV2 cascade actually fires.
struct BodyStashingResponder {
    stash: Arc<Mutex<HashMap<String, Vec<u8>>>>,
}

impl Respond for BodyStashingResponder {
    fn respond(&self, req: &Request) -> ResponseTemplate {
        let path = req.url.path().to_string();
        let body = req.body.clone();
        let cid = blake3_raw_cid(&body);
        self.stash.lock().unwrap().insert(path, body);
        ResponseTemplate::new(200).insert_header("ETag", cid.to_string())
    }
}

struct ServingGetResponder {
    stash: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    get_count: Arc<AtomicUsize>,
    counting_active: Arc<AtomicBool>,
}

impl Respond for ServingGetResponder {
    fn respond(&self, req: &Request) -> ResponseTemplate {
        let path = req.url.path().to_string();
        if self.counting_active.load(Ordering::SeqCst) {
            self.get_count.fetch_add(1, Ordering::SeqCst);
        }
        let stash = self.stash.lock().unwrap();
        match stash.get(&path) {
            Some(bytes) => {
                let cid = blake3_raw_cid(bytes);
                ResponseTemplate::new(200)
                    .insert_header("ETag", cid.to_string())
                    .set_body_bytes(bytes.clone())
            }
            None => ResponseTemplate::new(404),
        }
    }
}

#[tokio::test]
async fn get_object_flat_does_not_o_n_scan_v7_forest() {
    let server = MockServer::start().await;

    let stash: Arc<Mutex<HashMap<String, Vec<u8>>>> = Arc::new(Mutex::new(HashMap::new()));
    let get_count = Arc::new(AtomicUsize::new(0));
    let counting_active = Arc::new(AtomicBool::new(false));

    let put_responder = BodyStashingResponder {
        stash: stash.clone(),
    };
    let get_responder = ServingGetResponder {
        stash: stash.clone(),
        get_count: get_count.clone(),
        counting_active: counting_active.clone(),
    };

    Mock::given(method("PUT"))
        .respond_with(put_responder)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .respond_with(get_responder)
        .mount(&server)
        .await;
    Mock::given(method("HEAD"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let mut config = Config::new(&server.uri()).with_token("test-jwt");
    config.walkable_v8_writer_enabled = true;
    let secret = SecretKey::generate();
    let enc_config = EncryptionConfig::from_secret_key(secret);
    let client = EncryptedClient::new(config, enc_config).expect("EncryptedClient::new");

    let bucket = "regression-bucket";

    // Phase 1: write N files. GET counting is OFF so any forest-load
    // probing during ensure_forest_loaded doesn't pollute the read
    // measurement. Each file is small (well under chunked threshold)
    // so put_object_flat_deferred takes the single-block path that
    // stamps `ForestFileEntry.storage_cid` via the W.9.3 self-verify.
    for i in 0..N_FILES {
        let key = format!("/file-{:04}.txt", i);
        let data = format!("payload-for-{}", i).into_bytes();
        client
            .put_object_flat_deferred(bucket, &key, Bytes::from(data), None)
            .await
            .expect("put_object_flat_deferred");
    }

    client
        .flush_forest(bucket)
        .await
        .expect("flush_forest");

    // CRITICAL: invalidate the forest cache before reading.
    //
    // `flush_dirty` (sharded_hamt_forest.rs:1772) takes `&self` on the
    // node store and does NOT rewrite the in-memory pointer state from
    // `InMemory(node)` → `Stored(key)` after persist. The Arc-held node
    // tree retains its `InMemory` pointers post-flush. Without
    // invalidation, a subsequent `get_object_flat` walks the in-memory
    // tree directly without issuing ANY backend GETs — and so does the
    // bug-equivalent `find_by_storage_key` linear scan, since it also
    // walks via `flat_map` over the same in-memory pointers. The test
    // would then trivially pass with or without the fix, defeating the
    // regression-guard purpose entirely.
    //
    // Invalidating the forest cache evicts the in-memory tree. The
    // next `ensure_forest_loaded` re-fetches the manifest CBOR from
    // wiremock, which decodes shard roots as `Stored`/`StoredV2`
    // pointers (the on-disk wire form). Walking those then forces
    // real backend GETs — exactly the behavior a fresh-installed
    // device would see, which is the scenario the fix targets.
    client.invalidate_all_forest_caches();

    // Phase 2: pick one file and read it. Turn on GET counting only
    // for this read so any forest-load bookkeeping during the prior
    // phase doesn't double-count.
    let target_idx = N_FILES / 2;
    let target_key = format!("/file-{:04}.txt", target_idx);
    let expected_payload = format!("payload-for-{}", target_idx).into_bytes();

    counting_active.store(true, Ordering::SeqCst);
    let read_back = client
        .get_object_flat(bucket, &target_key)
        .await
        .expect("get_object_flat must round-trip the just-written file");
    counting_active.store(false, Ordering::SeqCst);

    assert_eq!(
        read_back.as_ref(),
        expected_payload.as_slice(),
        "round-trip plaintext mismatch — refactor must preserve byte-equality \
         of decrypted file contents"
    );

    let observed_gets = get_count.load(Ordering::SeqCst);
    assert!(
        observed_gets <= MAX_READ_GETS,
        "regression: get_object_flat issued {} GETs reading 1 file from a \
         bucket of {} entries (threshold: {}). The pre-#91 O(N) scan via \
         forest_entry_lookup → find_by_storage_key would have produced \
         ≥{} GETs. A count above the threshold means a redundant full-forest \
         scan has been re-introduced into the read path.",
        observed_gets, N_FILES, MAX_READ_GETS, N_FILES
    );

    eprintln!(
        "#91 regression guard PASS: get_object_flat issued {} GETs (≤{}) on a \
         {}-entry v7 bucket — bounded by O(log N) HAMT walk, not O(N) scan",
        observed_gets, MAX_READ_GETS, N_FILES
    );
}
