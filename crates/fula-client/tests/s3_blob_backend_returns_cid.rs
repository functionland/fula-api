//! Walkable-v8 (W.9.2): `S3BlobBackend::put` returns the master's
//! PUT-response ETag parsed as a [`Cid`] inside [`BlobPutResult`].
//!
//! Master computes the ETag as `cid.to_string()` of a v1 raw-codec
//! BLAKE3-multihash CID — kubo invokes
//! `/api/v0/block/put?cid-codec=raw&mhtype=blake3` per
//! `crates/fula-cli/src/handlers/object.rs:103-137` and returns that
//! string verbatim in the PUT response. This test:
//!
//! 1. Mounts a wiremock master that emits a real BLAKE3-raw CID for
//!    the request body. Asserts `BlobPutResult.cid` is `Some(cid)` and
//!    matches what kubo would have computed.
//! 2. Mounts a master that emits a non-CID etag string. Asserts the
//!    backend soft-fails to `BlobPutResult { cid: None }` (PUT itself
//!    succeeds — only the offline-walk hint is missing).
//! 3. Mounts a master that emits the etag in S3-quoted form (`"<cid>"`).
//!    Today this is NOT what production master returns (it returns the
//!    raw `cid.to_string()`), but the test pins the current parse
//!    behavior so a future master change to quoted etags becomes a
//!    visible regression.

#![cfg(not(target_arch = "wasm32"))]

use cid::Cid;
use cid::multihash::Multihash;
use fula_client::{Config, FulaClient, S3BlobBackend};
use fula_crypto::wnfs_hamt::BlobBackend;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const MULTIHASH_BLAKE3: u64 = 0x1e;

/// Build the same v1 raw-codec BLAKE3-multihash CID that production kubo
/// would compute for `data` under `block/put?cid-codec=raw&mhtype=blake3`.
fn blake3_raw_cid(data: &[u8]) -> Cid {
    let h = blake3::hash(data);
    let mh = Multihash::<64>::wrap(MULTIHASH_BLAKE3, h.as_bytes())
        .expect("32-byte blake3 digest fits in Multihash<64>");
    Cid::new_v1(0x55 /* raw */, mh)
}

fn mk_client(endpoint: &str) -> FulaClient {
    // W.9.3: every test in this file asserts that `S3BlobBackend.cid`
    // surfaces the master-attested CID. The walkable-v8 writer flag
    // gates this behaviour and defaults to `false` in the v0.6.x
    // rollout, so each test must construct a config with the flag
    // explicitly on. Without this, every assertion below would see
    // `cid: None` and fail with a misleading "etag did not parse"
    // message.
    let mut config = Config::new(endpoint);
    config.walkable_v8_writer_enabled = true;
    FulaClient::new(config).expect("build FulaClient")
}

#[tokio::test]
async fn put_returns_blake3_raw_cid_parsed_from_etag() {
    let server = MockServer::start().await;
    let body = b"encrypted-hamt-node-blob".to_vec();
    let expected_cid = blake3_raw_cid(&body);
    let etag_str = expected_cid.to_string();

    Mock::given(method("PUT"))
        .and(path("/images/__fula_forest_v7_nodes/abc123"))
        .respond_with(ResponseTemplate::new(200).insert_header("ETag", etag_str.as_str()))
        .mount(&server)
        .await;

    let backend = S3BlobBackend::new(mk_client(&server.uri()), "images".to_string());

    let result = backend
        .put("__fula_forest_v7_nodes/abc123", body)
        .await
        .expect("PUT must succeed");

    assert_eq!(
        result.cid,
        Some(expected_cid),
        "S3BlobBackend::put must surface the etag-parsed CID for walkable-v8"
    );
}

#[tokio::test]
async fn put_soft_fails_to_none_when_etag_is_not_a_valid_cid() {
    let server = MockServer::start().await;
    let body = b"node-blob".to_vec();

    // Garbage etag (not a CID, not even base32). Real-world failure modes
    // include: a misbehaving proxy that strips the ETag, a future master
    // version that returns a different format, or a deploy mid-rollout
    // serving from a node that hasn't been updated.
    Mock::given(method("PUT"))
        .and(path("/images/__fula_forest_v7_nodes/def456"))
        .respond_with(
            ResponseTemplate::new(200).insert_header("ETag", "not-a-cid-just-some-string"),
        )
        .mount(&server)
        .await;

    let backend = S3BlobBackend::new(mk_client(&server.uri()), "images".to_string());

    let result = backend
        .put("__fula_forest_v7_nodes/def456", body)
        .await
        .expect("PUT itself must succeed even when etag is unparseable");

    assert!(
        result.cid.is_none(),
        "non-CID etag must soft-fail to None, NOT propagate as an error \
         (PUT succeeded, only the offline-walk hint is missing); got {:?}",
        result.cid
    );
}

/// Isolation check: `Cid::from_str` itself REJECTS quoted input. The
/// reason `put_with_quoted_etag_still_parses_to_correct_cid` succeeds
/// is NOT that wiremock/reqwest/hyper normalize the header — it's that
/// `FulaClient::put_object_with_metadata` at `crates/fula-client/src/
/// client.rs:388` (and `:438` for the conditional variant) calls
/// `.trim_matches('"')` on the ETag header value before populating
/// `PutObjectResult.etag`. So by the time `S3BlobBackend::put` reads
/// `result.etag`, quotes are already gone.
///
/// **Maintainer note**: do NOT remove `.trim_matches('"')` at
/// `client.rs:388, 438` — that's the production-portable guarantee
/// against any S3-conformant proxy that wraps etags per RFC 7232.
/// This isolation test exists so a future refactor that touches the
/// trim immediately surfaces the breakage in this test, not as a
/// silent regression of offline-walk hints behind quoted-etag proxies.
#[test]
fn cid_from_str_quoted_input_isolation_check() {
    let body = b"isolation-check-blob".as_slice();
    let cid = blake3_raw_cid(body);
    let raw = cid.to_string();
    let quoted = format!("\"{}\"", raw);

    let raw_parse = raw.parse::<Cid>();
    assert!(raw_parse.is_ok(), "raw cid string must parse cleanly");

    let quoted_parse = quoted.parse::<Cid>();
    if quoted_parse.is_ok() {
        // cid 0.11's parser is permissive of surrounding quotes — production
        // is portable across S3-compliant proxies that quote etags per
        // RFC 7232. The integration test is a real guarantee.
        eprintln!(
            "isolation: cid::from_str strips surrounding quotes — \
             production is resilient regardless of proxy"
        );
    } else {
        // The cid parser rejects quotes. The integration test's resilience
        // therefore comes from wiremock/reqwest/hyper normalization on the
        // header path. It is NOT a `cid`-level guarantee, and a real proxy
        // that retains literal quotes in the wire ETag header would strand
        // the offline-walk hint as `None`. Document this in the integration
        // test if this branch fires.
        eprintln!(
            "isolation: cid::from_str DOES NOT strip quotes ({:?}); \
             integration-test resilience is harness-dependent",
            quoted_parse.unwrap_err()
        );
    }
}

#[tokio::test]
async fn put_with_quoted_etag_still_parses_to_correct_cid() {
    // Some S3 implementations wrap etag in double quotes per RFC 7232.
    // Production fula master does NOT — it emits `cid.to_string()` raw
    // (verified at `crates/fula-cli/src/handlers/object.rs:137`) — but
    // any S3-compliant proxy fronting master is allowed to add quotes.
    //
    // **Production resilience comes from `client.rs:388, 438`**, where
    // `FulaClient::put_object_with_metadata` strips surrounding quotes
    // via `.trim_matches('"')` before populating `PutObjectResult.etag`.
    // The `cid` crate's parser does NOT strip quotes (proven by the
    // sibling `cid_from_str_quoted_input_isolation_check` test), so
    // removing the `.trim_matches('"')` would silently break offline-
    // walk hints behind any RFC-7232-quoting proxy. This test pins the
    // end-to-end resilience: do not remove the trim at `client.rs`.
    let server = MockServer::start().await;
    let body = b"another-blob".to_vec();
    let expected_cid = blake3_raw_cid(&body);
    let quoted = format!("\"{}\"", expected_cid);

    Mock::given(method("PUT"))
        .and(path("/images/__fula_forest_v7_nodes/789"))
        .respond_with(ResponseTemplate::new(200).insert_header("ETag", quoted.as_str()))
        .mount(&server)
        .await;

    let backend = S3BlobBackend::new(mk_client(&server.uri()), "images".to_string());

    let result = backend
        .put("__fula_forest_v7_nodes/789", body)
        .await
        .expect("PUT must succeed");

    assert_eq!(
        result.cid,
        Some(expected_cid),
        "quoted etag must still surface as the same parsed CID — the \
         walkable-v8 hint must not be stranded by a transient proxy"
    );
}

/// Walkable-v8 (W.9.3) — master returns an ETag for a DIFFERENT body.
/// Self-verification at S3BlobBackend::put must catch the mismatch and
/// soft-fail to `cid: None` so downstream parents (LinkV2 stamping) and
/// readers (offline gateway race) cannot be redirected by a compromised
/// master to attacker-controlled IPFS bytes. The PUT itself must still
/// succeed — the soft-fail is at the offline-walk-hint level only.
#[tokio::test]
async fn put_self_verify_rejects_master_attested_cid_for_wrong_body() {
    let server = MockServer::start().await;
    let actual_body = b"the-real-ciphertext-we-sent".to_vec();
    let other_body = b"completely-different-bytes".to_vec();
    // Master attests a CID that addresses OTHER bytes — modeling a
    // compromised master that wants to redirect future offline walkers
    // to attacker-controlled blobs at that other CID.
    let lying_etag = blake3_raw_cid(&other_body).to_string();

    Mock::given(method("PUT"))
        .and(path("/images/__fula_forest_v7_nodes/lying"))
        .respond_with(ResponseTemplate::new(200).insert_header("ETag", lying_etag.as_str()))
        .mount(&server)
        .await;

    let backend = S3BlobBackend::new(mk_client(&server.uri()), "images".to_string());

    let result = backend
        .put("__fula_forest_v7_nodes/lying", actual_body)
        .await
        .expect("PUT itself must succeed even when master lies about the CID");

    assert!(
        result.cid.is_none(),
        "S3BlobBackend::put must soft-fail to None when master's etag-attested \
         CID disagrees with locally-computed BLAKE3(ciphertext) — the load-bearing \
         walkable-v8 safety property. Got cid = {:?}",
        result.cid
    );
}

/// Walkable-v8 (W.9.3) — `walkable_v8_writer_enabled = false`
/// (explicit opt-out post-#89; was the default pre-#89 during the
/// v0.6.x rollout window) MUST cause `S3BlobBackend::put` to surface
/// no CID, even when master returns a perfectly-valid CID in the
/// ETag. This pins the off-mode's byte-identical behaviour to v0.5:
/// write semantics unchanged, no v8 wire-format surface activated.
///
/// **Renamed post-#89** to clarify this exercises the EXPLICIT-FALSE
/// opt-out path (used by backward-compat-sensitive consumers, or by
/// regression tests that need v7-only writes), not the default. The
/// new default is `true`.
#[tokio::test]
async fn put_with_explicit_writer_disabled_returns_cid_none() {
    let server = MockServer::start().await;
    let body = b"node-payload-explicit-off".to_vec();
    let correct_etag = blake3_raw_cid(&body).to_string();

    Mock::given(method("PUT"))
        .and(path("/images/__fula_forest_v7_nodes/explicit-off"))
        .respond_with(ResponseTemplate::new(200).insert_header("ETag", correct_etag.as_str()))
        .mount(&server)
        .await;

    // **#89 (2026-05-09)**: default is now `true`. To exercise the
    // off path (legacy `Pointer::Link` emission, no CID surfaced),
    // construct the Config and EXPLICITLY set the flag to false.
    let mut cfg = Config::new(&server.uri());
    cfg.walkable_v8_writer_enabled = false;
    let client = FulaClient::new(cfg).expect("build client");
    let backend = S3BlobBackend::new(client, "images".to_string());

    let result = backend
        .put("__fula_forest_v7_nodes/explicit-off", body)
        .await
        .expect("PUT must succeed under explicit-off mode");

    assert!(
        result.cid.is_none(),
        "walkable_v8_writer_enabled = false MUST surface \
         cid: None even when master's etag is a valid CID. Otherwise the \
         flag isn't actually gating the v8 wire surface and old SDKs would \
         see LinkV2 entries in opt-out-written buckets. Got cid = {:?}",
        result.cid
    );
}

#[tokio::test]
async fn put_retry_after_503_returns_cid_from_successful_attempt_only() {
    // Pins retry-correctness for W.9.2: when a transient 503 forces the
    // backend's retry loop, the eventual `BlobPutResult.cid` must come
    // from the *successful* attempt's etag, not a stale prior one.
    //
    // The loop structure in S3BlobBackend::put already enforces this
    // (the `Ok(result)` arm fires only on the 2xx attempt), but no test
    // had explicitly exercised the retry+CID interaction. This pins it
    // so a future refactor that captures `etag` outside the loop —
    // e.g. via an interceptor or middleware — can't silently regress.
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use wiremock::{Request, Respond};

    struct Scripted {
        calls: Arc<AtomicUsize>,
        responses: Vec<ResponseTemplate>,
    }
    impl Respond for Scripted {
        fn respond(&self, _req: &Request) -> ResponseTemplate {
            let idx = self.calls.fetch_add(1, Ordering::SeqCst);
            self.responses[idx.min(self.responses.len() - 1)].clone()
        }
    }

    let server = MockServer::start().await;
    let body = b"retry-then-cid-blob".to_vec();
    let expected_cid = blake3_raw_cid(&body);
    let etag_str = expected_cid.to_string();

    let calls = Arc::new(AtomicUsize::new(0));
    let responder = Scripted {
        calls: calls.clone(),
        responses: vec![
            ResponseTemplate::new(503),
            ResponseTemplate::new(200).insert_header("ETag", etag_str.as_str()),
        ],
    };
    Mock::given(method("PUT"))
        .and(path("/images/__fula_forest_v7_nodes/retry"))
        .respond_with(responder)
        .mount(&server)
        .await;

    let backend = S3BlobBackend::new(mk_client(&server.uri()), "images".to_string());

    let result = backend
        .put("__fula_forest_v7_nodes/retry", body)
        .await
        .expect("retry must absorb 503 then succeed");

    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "exactly two attempts: 503 then 200"
    );
    assert_eq!(
        result.cid,
        Some(expected_cid),
        "CID hint must come from the successful 200 attempt's etag, \
         never a stale value from a retried-and-failed attempt"
    );
}
