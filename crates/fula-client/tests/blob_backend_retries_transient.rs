//! Regression test for the v7 LIST-failure fix.
//!
//! Background: after the v1→v7 migration of a large bucket, LIST walks the
//! sharded HAMT via `list_all_files`, which fans out to many concurrent
//! `S3BlobBackend::get` calls on `/bucket/__fula_forest_v7_nodes/<key>`. When
//! the gateway is fronted by an nginx `limit_req` with a `burst` smaller than
//! the in-flight count, some requests come back as HTTP 503 with an empty
//! body — a single one of those aborted the whole LIST.
//!
//! The fix adds bounded fixed-delay retries (300 ms base + 0-100 ms jitter,
//! up to 4 attempts) in `S3BlobBackend::{get, put}` for the transient class
//! HTTP 429/500/502/503/504 / `SlowDown` / `InternalError` /
//! `ServiceUnavailable`. This test exercises that retry path end-to-end
//! against a `wiremock::MockServer` that emits 503 → 503 → 200 and asserts:
//!
//! 1. The outer call returns `Ok`.
//! 2. `blob_backend_retry_count()` observes exactly the number of retry
//!    sleeps we expect.
//! 3. Non-transient responses (e.g. 404) are NOT retried.

#![cfg(not(target_arch = "wasm32"))]

use fula_client::{Config, FulaClient, S3BlobBackend, blob_backend_retry_count};
use fula_crypto::BlobBackend;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

/// The retry counter is process-wide; tests in this file all mutate it.
/// Serialize counter-sensitive tests under a shared lock so the `before →
/// after` delta measured by each test is actually its own increments.
static COUNTER_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Responder that emits the Nth response from a list; cycles if called more
/// than `responses.len()` times. Lets us script "503, 503, 200" against a
/// single path without wiremock's expectation counters fighting us.
struct Scripted {
    calls: Arc<AtomicUsize>,
    responses: Vec<ResponseTemplate>,
}

impl Respond for Scripted {
    fn respond(&self, _req: &Request) -> ResponseTemplate {
        let idx = self.calls.fetch_add(1, Ordering::SeqCst);
        let slot = idx.min(self.responses.len() - 1);
        self.responses[slot].clone()
    }
}

fn mk_client(endpoint: &str) -> FulaClient {
    // 10 s per-request timeout is ample for mock responses; the test doesn't
    // need a real connect timeout.
    let cfg = Config::new(endpoint);
    FulaClient::new(cfg).expect("build FulaClient")
}

#[tokio::test]
async fn get_retries_through_two_503s_then_succeeds() {
    let _guard = COUNTER_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let server = MockServer::start().await;

    let calls = Arc::new(AtomicUsize::new(0));
    let responder = Scripted {
        calls: calls.clone(),
        responses: vec![
            ResponseTemplate::new(503),
            ResponseTemplate::new(503),
            ResponseTemplate::new(200).set_body_bytes(b"hamt-node-bytes".to_vec()),
        ],
    };
    Mock::given(method("GET"))
        .and(path("/images/__fula_forest_v7_nodes/deadbeef"))
        .respond_with(responder)
        .mount(&server)
        .await;

    let before = blob_backend_retry_count();
    let client = mk_client(&server.uri());
    let backend = S3BlobBackend::new(client, "images".to_string());

    let got = backend
        .get("__fula_forest_v7_nodes/deadbeef")
        .await
        .expect("retry should absorb two 503s");

    assert_eq!(got, b"hamt-node-bytes");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        3,
        "mock should have been hit once per attempt"
    );
    let retries = blob_backend_retry_count() - before;
    assert_eq!(retries, 2, "two 503s → two retry sleeps, then success");
}

#[tokio::test]
async fn put_retries_through_one_503_then_succeeds() {
    let _guard = COUNTER_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let server = MockServer::start().await;

    let calls = Arc::new(AtomicUsize::new(0));
    let responder = Scripted {
        calls: calls.clone(),
        responses: vec![
            ResponseTemplate::new(503),
            ResponseTemplate::new(200).insert_header("ETag", "\"abc123\""),
        ],
    };
    Mock::given(method("PUT"))
        .and(path("/images/__fula_forest_v7_nodes/cafebabe"))
        .respond_with(responder)
        .mount(&server)
        .await;

    let before = blob_backend_retry_count();
    let client = mk_client(&server.uri());
    let backend = S3BlobBackend::new(client, "images".to_string());

    backend
        .put("__fula_forest_v7_nodes/cafebabe", b"encrypted-node-blob".to_vec())
        .await
        .expect("retry should absorb the 503");

    assert_eq!(calls.load(Ordering::SeqCst), 2);
    let retries = blob_backend_retry_count() - before;
    assert_eq!(retries, 1, "one 503 → one retry sleep");
}

#[tokio::test]
async fn get_gives_up_after_max_attempts_on_persistent_503() {
    let _guard = COUNTER_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let server = MockServer::start().await;

    let calls = Arc::new(AtomicUsize::new(0));
    let responder = Scripted {
        calls: calls.clone(),
        // Always 503 — more entries than attempts so Scripted never wraps.
        responses: vec![
            ResponseTemplate::new(503),
            ResponseTemplate::new(503),
            ResponseTemplate::new(503),
            ResponseTemplate::new(503),
            ResponseTemplate::new(503),
        ],
    };
    Mock::given(method("GET"))
        .and(path("/images/__fula_forest_v7_nodes/persistently-broken"))
        .respond_with(responder)
        .mount(&server)
        .await;

    let client = mk_client(&server.uri());
    let backend = S3BlobBackend::new(client, "images".to_string());

    let err = backend
        .get("__fula_forest_v7_nodes/persistently-broken")
        .await
        .expect_err("persistent 503 must eventually surface");

    // Four total attempts = `BLOB_BACKEND_MAX_ATTEMPTS`.
    assert_eq!(calls.load(Ordering::SeqCst), 4, "attempts capped at 4");
    // Error message should mention the storage-backend failure; we don't
    // pin the exact string (ClientError::to_string is wrapped via
    // client_err_to_crypto → CryptoError::Storage).
    let msg = err.to_string();
    assert!(
        msg.to_lowercase().contains("storage") || msg.contains("503"),
        "unexpected error message: {msg}"
    );
}

#[tokio::test]
async fn get_does_not_retry_on_404() {
    let _guard = COUNTER_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let server = MockServer::start().await;

    let calls = Arc::new(AtomicUsize::new(0));
    let responder = Scripted {
        calls: calls.clone(),
        responses: vec![ResponseTemplate::new(404)],
    };
    Mock::given(method("GET"))
        .and(path("/images/__fula_forest_v7_nodes/not-there"))
        .respond_with(responder)
        .mount(&server)
        .await;

    let before = blob_backend_retry_count();
    let client = mk_client(&server.uri());
    let backend = S3BlobBackend::new(client, "images".to_string());

    let _err = backend
        .get("__fula_forest_v7_nodes/not-there")
        .await
        .expect_err("404 must not be retried");

    assert_eq!(calls.load(Ordering::SeqCst), 1, "404 is terminal");
    assert_eq!(
        blob_backend_retry_count(),
        before,
        "non-transient error must not bump retry counter"
    );
}
