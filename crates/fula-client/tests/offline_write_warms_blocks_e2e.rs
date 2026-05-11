//! Regression test for issue #8 (the load-bearing breaker): writes do not
//! warm the local BLOCKS cache, so the freshly-written bytes are
//! unreadable offline unless an explicit master-up READ later re-fetches
//! the same CID.
//!
//! ## Why this test exists
//!
//! User-reported flow (FxFiles, real device):
//!
//! 1. Online (real S3 endpoint): upload a file → master returns ETag =
//!    BLAKE3 raw-codec CID of the encrypted ciphertext.
//! 2. Online: list the bucket → SDK serves from in-memory forest cache
//!    (dirty since the upload), NO master fetch, NO BLOCKS populate.
//! 3. Reinit to a bogus endpoint (simulate master-down).
//! 4. Offline: list the bucket → fresh client, empty in-memory state →
//!    walks via `try_offline_fallback_with_cid_hint` → `cache.get(cid)`
//!    → MISS (writes never populated BLOCKS) → propagates
//!    `Master unreachable` error.
//!
//! The pre-fix code path: `S3BlobBackend::put` succeeds with a verified
//! CID but never calls `block_cache.put(&cid, &bytes)`. Subsequent
//! offline reads of that CID find an empty BLOCKS table.
//!
//! The post-fix path: `S3BlobBackend::put` (and equivalent seams in
//! `FulaClient::put_object_*`) call `cache.put(&cid, &bytes)` on every
//! successful PUT when walkable-v8 is enabled, so the just-written
//! bytes are immediately available for offline reads with no
//! dependency on a follow-up master-up read or on public-gateway DHT
//! propagation.
//!
//! ## What this test asserts
//!
//! Two distinct facts, in order:
//!
//! **Phase A — fix-#3 is active at the BlobBackend seam:** after a
//! `S3BlobBackend::put` succeeds against a wiremock master that
//! returns `ETag = BLAKE3(body)` (matching v0.4.4+ master behavior),
//! `block_cache.get(&cid)` returns the just-PUT bytes. Pre-fix this
//! is a MISS; post-fix it is a HIT.
//!
//! **Phase B — fix-#3 makes offline reads succeed:** after Phase A,
//! pointing the same backend at a bogus master URL and calling
//! `S3BlobBackend::get_with_cid_hint(path, Some(&cid))` returns the
//! original bytes WITHOUT any network call to a public IPFS gateway.
//! Pre-fix this returns an error; post-fix it returns the bytes from
//! BLOCKS.
//!
//! The wiremock gateways are configured to 404 every CID — models the
//! real production reality that freshly-pinned CIDs are not yet
//! propagated to public IPFS DHT, so the gateway race can NOT save
//! the offline read. The only thing that can save it is BLOCKS being
//! populated at write time.

#![cfg(not(target_arch = "wasm32"))]

use cid::Cid;
use cid::multihash::Multihash;
use fula_client::{Config, FulaClient, S3BlobBackend};
use fula_crypto::wnfs_hamt::BlobBackend;
use tempfile::TempDir;
use wiremock::matchers::{method, path_regex};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

const MULTIHASH_BLAKE3: u64 = 0x1e;
const CODEC_RAW: u64 = 0x55;

fn blake3_raw_cid(data: &[u8]) -> Cid {
    let h = blake3::hash(data);
    let mh = Multihash::<64>::wrap(MULTIHASH_BLAKE3, h.as_bytes())
        .expect("blake3 multihash wrap");
    Cid::new_v1(CODEC_RAW, mh)
}

/// wiremock responder that computes ETag = BLAKE3(body) per PUT.
/// Mirrors v0.4.4+ master behavior — master receives the encrypted
/// ciphertext, hashes it, returns the resulting CID string as the
/// ETag header so the SDK's walkable-v8 self-verify accepts it.
struct EchoCidEtag;

impl Respond for EchoCidEtag {
    fn respond(&self, req: &Request) -> ResponseTemplate {
        let cid = blake3_raw_cid(&req.body);
        // ETag header convention: master returns the CID string
        // (unquoted is fine; the SDK trims quotes).
        ResponseTemplate::new(200).insert_header("ETag", cid.to_string().as_str())
    }
}

fn build_config(master_url: &str, cache_path: &std::path::Path) -> Config {
    let mut config = Config::new(master_url);
    config.timeout = std::time::Duration::from_secs(10);
    config.walkable_v8_writer_enabled = true;
    config.health_gate_enabled = true;
    config.block_cache_enabled = true;
    config.block_cache_path = Some(cache_path.to_path_buf());
    config.block_cache_max_bytes = 256 * 1024 * 1024;
    // Gateways point at a URL template that doesn't resolve.
    // Models the real production reality: just-pinned CIDs are not
    // yet propagated to public IPFS DHT, so the gateway race will
    // NOT save the offline read. Only BLOCKS can.
    config.gateway_fallback_enabled = true;
    config.gateway_fallback_urls = vec![
        // 127.0.0.1:1 always rejects connections — fastest possible
        // failure, no DNS or TCP timeout wait.
        "http://127.0.0.1:1/ipfs/{cid}".to_string(),
    ];
    config.gateway_race_concurrency = 1;
    config
}

/// Issue #8 / fix #3 regression test.
///
/// Demonstrates that `S3BlobBackend::put` must populate BLOCKS so a
/// subsequent offline read can serve the just-written bytes without
/// requiring either a follow-up master-up read or a public-IPFS-DHT
/// hit on the just-pinned CID.
///
/// Pre-fix: this test FAILS at the Phase-A assertion (`cache.get(&cid)`
/// returns `Ok(None)` because PUT never wrote to BLOCKS).
///
/// Post-fix: this test PASSES — both Phase A (cache populated) and
/// Phase B (offline read serves from cache) succeed.
#[tokio::test]
async fn write_warms_blocks_cache_so_offline_read_succeeds() {
    // ── Phase A setup: wiremock master with realistic CID-ETag behavior.
    let master = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path_regex(r"^/test-bucket/.+$"))
        .respond_with(EchoCidEtag)
        .mount(&master)
        .await;

    let tmp = TempDir::new().expect("tempdir");
    let cache_path = tmp.path().join("blocks.redb");

    let online_client = FulaClient::new(build_config(&master.uri(), &cache_path))
        .expect("build online FulaClient");
    let online_backend = S3BlobBackend::new(online_client.clone(), "test-bucket".to_string());

    // The "encrypted HAMT node ciphertext" — opaque to this layer.
    let body: Vec<u8> = b"v7 HAMT node ciphertext for issue-8 regression test".to_vec();
    let path = "__fula_forest_v7_nodes/aabbccddeeff";

    let put_result = online_backend
        .put(path, body.clone())
        .await
        .expect("master PUT must succeed against wiremock returning 200 + CID ETag");

    let cid = put_result
        .cid
        .expect(
            "walkable-v8 self-verify must yield Some(cid) when master returns \
             a parseable CID ETag that matches BLAKE3(body)",
        );

    // Sanity: the CID master returned must match what we'd compute locally.
    assert_eq!(
        cid,
        blake3_raw_cid(&body),
        "wiremock master returned a non-BLAKE3(body) CID — test setup wrong"
    );

    // ── Phase A assertion: BLOCKS must have the bytes NOW, with no
    //    intervening read. THIS IS THE LOAD-BEARING ASSERTION FOR FIX #3.
    let cache = online_client
        .block_cache()
        .expect("block_cache must be configured in this test");
    let cached = cache
        .get(&cid)
        .expect("redb read must not error")
        .expect(
            "BLOCKS must contain the just-PUT bytes — if this fails, \
             S3BlobBackend::put (or its FulaClient inner) is not warming \
             the cache after a successful PUT. That is precisely the \
             bug issue #8 reports.",
        );
    assert_eq!(
        cached.as_ref(),
        body.as_slice(),
        "cached bytes must byte-match the just-PUT body",
    );

    // ── Phase B setup: a SECOND, fresh client (simulating reinit) with
    //    a BOGUS master URL but the SAME on-disk cache.
    drop(online_backend);
    drop(online_client);

    let bogus_master = "http://127.0.0.1:1";
    let offline_client = FulaClient::new(build_config(bogus_master, &cache_path))
        .expect("build offline FulaClient against bogus URL");
    let offline_backend = S3BlobBackend::new(offline_client.clone(), "test-bucket".to_string());

    // ── Phase B assertion: offline read MUST succeed solely from BLOCKS,
    //    proving fix #3 closes the user-reported gap. The gateway is
    //    127.0.0.1:1 (always-rejects), so a successful return here means
    //    bytes came from the local cache — exactly what the user needs
    //    on a device that goes offline after a write.
    let offline_bytes = offline_backend
        .get_with_cid_hint(path, Some(&cid))
        .await
        .expect(
            "offline read with cid-hint MUST succeed — bytes are in BLOCKS \
             from Phase A's PUT, and the cid-hint variant of \
             try_offline_fallback short-circuits to a BLOCKS hit before \
             attempting the gateway race. If this fails, fix #3 did not \
             land or the offline-fallback wiring regressed.",
        );

    assert_eq!(
        offline_bytes.as_slice(),
        body.as_slice(),
        "offline bytes must byte-match the originally-PUT body — a \
         mismatch would mean either cache corruption or BLOCKS \
         serving stale data",
    );
}
