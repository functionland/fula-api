//! Integration tests for RFC 7232 conditional writes (If-Match / If-None-Match)
//! on the PUT object endpoint.
//!
//! Exercises the contract that fula-client's `put_object_with_metadata_conditional`
//! relies on: server returns HTTP 412 with `x-amz-error-code: PreconditionFailed`
//! when the precondition fails.

use fula_cli::{AppState, GatewayConfig, routes};
use reqwest::{Client, StatusCode};
use std::sync::Arc;
use tokio::net::TcpListener;

async fn spawn_server() -> String {
    let mut config = GatewayConfig::default();
    config.host = "127.0.0.1".to_string();
    config.port = 0;
    config.auth_enabled = false;
    config.use_memory_store = true;
    config.registry_cid_path = None;
    config.jwt_secret = Some("test-secret-123".to_string());

    let state = Arc::new(AppState::new(config.clone()).await.unwrap());
    let app = routes::create_router(state);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    format!("http://{}", addr)
}

/// Extract the ETag from a response, stripping surrounding quotes.
fn etag_of(res: &reqwest::Response) -> String {
    res.headers()
        .get("ETag")
        .unwrap()
        .to_str()
        .unwrap()
        .trim_matches('"')
        .to_string()
}

#[tokio::test]
async fn test_put_without_conditional_headers_succeeds() {
    let base = spawn_server().await;
    let client = Client::new();
    client.put(&format!("{}/bkt-plain", base)).send().await.unwrap();

    let res = client
        .put(&format!("{}/bkt-plain/k1", base))
        .body("hello")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert!(!etag_of(&res).is_empty());
}

#[tokio::test]
async fn test_if_none_match_star_rejects_existing() {
    let base = spawn_server().await;
    let client = Client::new();
    client.put(&format!("{}/bkt-inm", base)).send().await.unwrap();

    // First PUT creates the object; If-None-Match: * on an absent key succeeds.
    let res = client
        .put(&format!("{}/bkt-inm/k1", base))
        .header("If-None-Match", "*")
        .body("v1")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK, "create-if-absent should succeed on new key");

    // Second PUT with If-None-Match: * must fail with 412.
    let res = client
        .put(&format!("{}/bkt-inm/k1", base))
        .header("If-None-Match", "*")
        .body("v2")
        .send()
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::PRECONDITION_FAILED,
        "If-None-Match: * on existing key must 412"
    );

    // x-amz-error-code header must identify the S3 error.
    let code = res
        .headers()
        .get("x-amz-error-code")
        .expect("x-amz-error-code header missing")
        .to_str()
        .unwrap();
    assert_eq!(code, "PreconditionFailed");
}

#[tokio::test]
async fn test_if_match_stale_etag_rejects() {
    let base = spawn_server().await;
    let client = Client::new();
    client.put(&format!("{}/bkt-im-stale", base)).send().await.unwrap();

    // Seed the key.
    client
        .put(&format!("{}/bkt-im-stale/k1", base))
        .body("v1")
        .send()
        .await
        .unwrap();

    // Stale If-Match → 412.
    let res = client
        .put(&format!("{}/bkt-im-stale/k1", base))
        .header("If-Match", "\"QmStaleEtagThatDoesNotExist\"")
        .body("v2")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::PRECONDITION_FAILED);
}

#[tokio::test]
async fn test_if_match_current_etag_succeeds() {
    let base = spawn_server().await;
    let client = Client::new();
    client.put(&format!("{}/bkt-im-ok", base)).send().await.unwrap();

    // Initial PUT.
    let res = client
        .put(&format!("{}/bkt-im-ok/k1", base))
        .body("v1")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let current = etag_of(&res);

    // PUT again with the correct If-Match.
    let res = client
        .put(&format!("{}/bkt-im-ok/k1", base))
        .header("If-Match", format!("\"{}\"", current))
        .body("v2")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_if_match_star_on_absent_key_rejects() {
    let base = spawn_server().await;
    let client = Client::new();
    client.put(&format!("{}/bkt-im-star-absent", base)).send().await.unwrap();

    // If-Match: * on a non-existent key must fail.
    let res = client
        .put(&format!("{}/bkt-im-star-absent/newkey", base))
        .header("If-Match", "*")
        .body("v1")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::PRECONDITION_FAILED);
}

#[tokio::test]
async fn test_if_match_etag_list_matches() {
    let base = spawn_server().await;
    let client = Client::new();
    client.put(&format!("{}/bkt-im-list", base)).send().await.unwrap();

    let res = client
        .put(&format!("{}/bkt-im-list/k1", base))
        .body("v1")
        .send()
        .await
        .unwrap();
    let current = etag_of(&res);

    // Second entry in the list matches → PUT must succeed.
    let res = client
        .put(&format!("{}/bkt-im-list/k1", base))
        .header(
            "If-Match",
            format!("\"QmNope\", \"{}\"", current),
        )
        .body("v2")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
}
