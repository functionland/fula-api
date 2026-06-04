//! Walkable-v8 reader integration test (W.9.4): end-to-end offline
//! walk via the cid-hint path.
//!
//! Verifies that the new `BlobBackend::get_with_cid_hint` route on
//! `S3BlobBackend` engages the cold-cache offline-fallback when master
//! returns a `MasterUnreachable`-shaped error and the caller supplies a
//! CID. This is the load-bearing wire between the HAMT walker
//! (`ChildPtr::resolve_owned` for `StoredV2` pointers) and the
//! existing Phase-2.4 gateway race; without this test, the writer
//! side of W.9.3 could be stamping cids that never get used at read
//! time and the regression would be invisible to all the in-module
//! tests in `fula-crypto`.
//!
//! Test strategy:
//!   * Mount a wiremock master that **always returns 503** so every
//!     master-side fetch trips the master-unreachable classifier.
//!   * Mount a wiremock IPFS gateway that serves bytes by CID; we
//!     pre-populate it with the encrypted ciphertext for a single
//!     HAMT-node-shaped blob.
//!   * Call `S3BlobBackend::get_with_cid_hint` with the matching CID.
//!     Assert the bytes come from the gateway path AND
//!     `verify_cid_against_bytes` passed (a tampered gateway response
//!     would surface as `Storage` / `Network`, not as `Ok`).

#![cfg(not(target_arch = "wasm32"))]

use cid::Cid;
use cid::multihash::Multihash;
use fula_client::{Config, FulaClient, S3BlobBackend};
use fula_crypto::wnfs_hamt::BlobBackend;
use wiremock::matchers::{method, path as wm_path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const MULTIHASH_BLAKE3: u64 = 0x1e;
const CODEC_RAW: u64 = 0x55;

/// Build the same v1 raw-codec BLAKE3-multihash CID master would emit
/// on PUT. Mirrors `walkable_v8::local_blake3_raw_cid`'s contract.
fn blake3_raw_cid(data: &[u8]) -> Cid {
    let h = blake3::hash(data);
    let mh = Multihash::<64>::wrap(MULTIHASH_BLAKE3, h.as_bytes())
        .expect("blake3 multihash wrap");
    Cid::new_v1(CODEC_RAW, mh)
}

/// Construct a Config wired for full Phase-2.x offline-fallback infra.
/// Walkable-v8 reader path is NOT gated on the writer flag — the
/// wire-format `LinkV2` variant is the gate. So this test sets up the
/// resolver-side flags only.
fn mk_config_with_gateway(master_url: &str, gateway_url_template: &str) -> Config {
    let tmp_path = std::env::temp_dir()
        .join(format!("fula-walkable-v8-test-{}", uuid::Uuid::new_v4()));
    let mut config = Config::new(master_url);
    config.health_gate_enabled = true;
    config.block_cache_enabled = true;
    config.block_cache_path = Some(tmp_path);
    config.gateway_fallback_enabled = true;
    config.gateway_fallback_urls = vec![gateway_url_template.to_string()];
    config.gateway_race_concurrency = 1;
    config
}

/// End-to-end offline walk via `get_with_cid_hint`: master is down,
/// the cid hint routes through `get_object_with_offline_fallback_known_cid`
/// → gateway race → `verify_cid_against_bytes`. The caller (HAMT walker
/// in production; this test direct-calls the BlobBackend trait method)
/// receives the raw ciphertext bytes content-verified against the
/// supplied cid.
#[tokio::test]
async fn s3_backend_get_with_cid_hint_uses_gateway_when_master_down() {
    let master = MockServer::start().await;
    let gateway = MockServer::start().await;

    // The "encrypted HAMT node ciphertext" bytes — opaque to this
    // layer (no AEAD on the integration test path; we're measuring
    // the BlobBackend cid-hint plumbing only). Production code would
    // run AEAD on the bytes after they exit this layer.
    let body = b"opaque-v8-hamt-node-ciphertext-bytes-for-test".to_vec();
    let body_cid = blake3_raw_cid(&body);

    // Master responds 503 to GET so the offline classifier fires.
    Mock::given(method("GET"))
        .and(wm_path("/images/__fula_forest_v7_nodes/abc123"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&master)
        .await;

    // Gateway serves the body at /ipfs/{cid}.
    let gateway_path = format!("/ipfs/{}", body_cid);
    Mock::given(method("GET"))
        .and(wm_path(gateway_path.as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body.clone()))
        .mount(&gateway)
        .await;

    let gateway_template = format!("{}/ipfs/{{cid}}", gateway.uri());
    let config = mk_config_with_gateway(&master.uri(), &gateway_template);
    let client = FulaClient::new(config).expect("build FulaClient");
    let backend = S3BlobBackend::new(client, "images".to_string());

    let result = backend
        .get_with_cid_hint("__fula_forest_v7_nodes/abc123", Some(&body_cid))
        .await
        .expect(
            "get_with_cid_hint must engage the gateway race when master is \
             down + cid hint is supplied — load-bearing W.9.4 contract",
        );

    assert_eq!(
        result, body,
        "bytes from gateway must match — verify_cid_against_bytes inside \
         get_object_with_offline_fallback_known_cid would have rejected a \
         mismatch, so a successful Ok confirms the gateway path executed and \
         passed CID verification"
    );
}

/// Default-off / no-cid-hint variant: when the caller supplies `None`,
/// the cid-hint path delegates to the no-hint variant — which in turn
/// uses the warm-cache offline path. With no warm-cache prepopulation
/// this should fail cleanly (no panic, no garbage), matching the
/// no-hint baseline behaviour.
#[tokio::test]
async fn s3_backend_get_with_cid_hint_none_falls_through_to_no_hint_path() {
    let master = MockServer::start().await;

    // Master 503s every GET so the no-hint path tries the offline
    // fallback. Without warm-cache or cid hint, the fallback returns
    // the original master-down error.
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&master)
        .await;

    let config = mk_config_with_gateway(&master.uri(), "https://nowhere.example/ipfs/{cid}");
    let client = FulaClient::new(config).expect("build FulaClient");
    let backend = S3BlobBackend::new(client, "images".to_string());

    let result = backend
        .get_with_cid_hint("__fula_forest_v7_nodes/no-hint", None)
        .await;

    assert!(
        result.is_err(),
        "no cid hint + master down + no warm-cache entry must return an \
         error (matching the no-hint variant); a successful Ok would mean \
         cid-hint path is fabricating responses"
    );
}

/// Tampered gateway response: gateway returns bytes that do NOT
/// content-address to the supplied cid. `verify_cid_against_bytes`
/// inside the gateway race must reject; the cid-hint fetch surfaces
/// the underlying master-down error rather than the tampered bytes.
#[tokio::test]
async fn s3_backend_get_with_cid_hint_rejects_gateway_tamper() {
    let master = MockServer::start().await;
    let gateway = MockServer::start().await;

    let real_body = b"real-bytes".to_vec();
    let real_cid = blake3_raw_cid(&real_body);
    let tampered_body = b"tampered-bytes".to_vec();
    assert_ne!(blake3_raw_cid(&tampered_body), real_cid);

    Mock::given(method("GET"))
        .and(wm_path("/images/__fula_forest_v7_nodes/tampered"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&master)
        .await;

    // Gateway returns DIFFERENT bytes than the cid claims to address.
    // verify_cid_against_bytes inside the gateway race must reject.
    let gateway_path = format!("/ipfs/{}", real_cid);
    Mock::given(method("GET"))
        .and(wm_path(gateway_path.as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(tampered_body.clone()))
        .mount(&gateway)
        .await;

    let gateway_template = format!("{}/ipfs/{{cid}}", gateway.uri());
    let config = mk_config_with_gateway(&master.uri(), &gateway_template);
    let client = FulaClient::new(config).expect("build FulaClient");
    let backend = S3BlobBackend::new(client, "images".to_string());

    let result = backend
        .get_with_cid_hint("__fula_forest_v7_nodes/tampered", Some(&real_cid))
        .await;

    assert!(
        result.is_err(),
        "gateway returning bytes that don't content-address to the cid MUST \
         fail (verify_cid_against_bytes inside the offline fallback). A \
         successful return here would mean the offline-walk path is serving \
         attacker-controlled bytes — the load-bearing security property \
         walkable-v8 inherits from gateway_fetch."
    );
}

/// Online orphaned-node recovery (issue #24). Master is UP but returns
/// `404 NoSuchKey` for a forest node whose storage-key -> CID index entry
/// was destroyed by a server-side `ipfs repo gc`, while the node's block
/// still exists in IPFS by CID. The forest cid-hint fetch MUST recover it
/// via the verified gateway race (the same mechanism the master-down path
/// already uses), not abort the walk.
///
/// Pre-fix this FAILS: `get_with_cid_hint` routes through
/// `get_object_with_offline_fallback_known_cid`, which only engages the
/// race on `is_master_unreachable_error`; a 404 is not master-down, so it
/// propagates and the `.expect()` below panics. Post-fix the forest-scoped
/// wrapper also recovers on a `NotFound`, so the node resolves by CID.
#[tokio::test]
async fn s3_backend_get_with_cid_hint_recovers_orphaned_node_on_master_404() {
    let master = MockServer::start().await;
    let gateway = MockServer::start().await;

    let body = b"opaque-v8-hamt-node-ciphertext-orphaned-by-gc".to_vec();
    let body_cid = blake3_raw_cid(&body);

    // Master is UP but the storage-key -> CID index entry is gone:
    // returns 404 NoSuchKey (NOT a master-down 5xx).
    Mock::given(method("GET"))
        .and(wm_path("/images/__fula_forest_v7_nodes/orphaned"))
        .respond_with(
            ResponseTemplate::new(404).set_body_string(
                r#"<Error><Code>NoSuchKey</Code><Message>not here</Message></Error>"#,
            ),
        )
        .mount(&master)
        .await;

    // The node's block still exists in IPFS, addressable by CID.
    let gateway_path = format!("/ipfs/{}", body_cid);
    Mock::given(method("GET"))
        .and(wm_path(gateway_path.as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body.clone()))
        .mount(&gateway)
        .await;

    let gateway_template = format!("{}/ipfs/{{cid}}", gateway.uri());
    let config = mk_config_with_gateway(&master.uri(), &gateway_template);
    let client = FulaClient::new(config).expect("build FulaClient");
    let backend = S3BlobBackend::new(client, "images".to_string());

    let result = backend
        .get_with_cid_hint("__fula_forest_v7_nodes/orphaned", Some(&body_cid))
        .await
        .expect(
            "issue #24: a forest node that 404s by storage-key but exists by \
             CID must be recovered via the verified gateway race even with \
             master UP. Pre-fix this propagates the 404 and aborts the walk.",
        );

    assert_eq!(
        result, body,
        "recovered bytes must content-address to the manifest-supplied CID; \
         a successful Ok confirms the gateway race executed and passed \
         verify_cid_against_bytes",
    );
}

/// Download-path recovery: a gc-orphaned DATA CHUNK (404 NoSuchKey from a
/// REACHABLE master, block still present on a gateway by CID) is recovered via
/// the verified gateway race — the same mechanism the forest walk uses, now
/// extended to the encrypted-download path (file index object + data chunks).
///
/// This exercises `get_object_with_recovery_known_cid` with a `.chunks/`-style
/// key — the method the windowed/range chunk-download callers
/// (`download_chunks_windowed_to_writer`, `get_range`) and the single-block
/// file-object fetch now route through. Pre-fix those callers used the
/// propagate-404 method, so a single gc-orphaned chunk 404'd and aborted the
/// whole download (offline mode already recovered it; online did not). The real
/// download path is covered end-to-end by the uncommitted E2E; this locks the
/// method contract the routing depends on.
#[tokio::test]
async fn recovery_known_cid_recovers_orphaned_chunk_on_master_404() {
    let master = MockServer::start().await;
    let gateway = MockServer::start().await;

    let body = b"opaque-encrypted-chunk-ciphertext-orphaned-by-gc".to_vec();
    let body_cid = blake3_raw_cid(&body);

    // A data-chunk key (mirrors `ChunkedFileMetadata::chunk_key`:
    // `<storage_key>.chunks/<idx>`). Master is UP but 404s it (gc-orphaned),
    // exactly like `.../.chunks/00000006` in the production logs.
    let chunk_key = "Qm6efdexamplestoragekey.chunks/00000006";
    Mock::given(method("GET"))
        .and(wm_path(format!("/videos/{}", chunk_key)))
        .respond_with(
            ResponseTemplate::new(404).set_body_string(
                r#"<Error><Code>NoSuchKey</Code><Message>not here</Message></Error>"#,
            ),
        )
        .mount(&master)
        .await;

    // The chunk's block still exists in IPFS, addressable by CID.
    let gateway_path = format!("/ipfs/{}", body_cid);
    Mock::given(method("GET"))
        .and(wm_path(gateway_path.as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body.clone()))
        .mount(&gateway)
        .await;

    let gateway_template = format!("{}/ipfs/{{cid}}", gateway.uri());
    let config = mk_config_with_gateway(&master.uri(), &gateway_template);
    let client = FulaClient::new(config).expect("build FulaClient");

    let result = client
        .get_object_with_recovery_known_cid("videos", chunk_key, &body_cid)
        .await
        .expect(
            "a gc-orphaned data chunk that 404s by storage-key but exists by \
             CID must be recovered via the verified gateway race (download-path \
             recovery). Pre-fix the download caller used the propagate-404 \
             method and the 404 aborted the download.",
        );

    assert_eq!(
        result.inner.data.as_ref(),
        body.as_slice(),
        "recovered chunk bytes must content-address to the index-supplied CID; \
         a successful Ok confirms the gateway race ran + passed \
         verify_cid_against_bytes (the chunk is additionally Bao-verified \
         downstream during real-download assembly)",
    );
}
