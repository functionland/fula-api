//! Mock-HTTP WIRING tests for the collaboration client (`collab.rs`).
//!
//! These assert that the reqwest calls hit the right PATH + QUERY + HEADERS + BODY
//! the documented `/api/collab/*` contract expects — the one layer the pure
//! `parse_manifest_payload` tests cannot cover (a wrong query-param name, a typo'd
//! `x-collab-file-id`, a missing Bearer, a wrong body key would all compile + pass
//! the pure tests). They use `wiremock` over loopback, so they run in normal
//! `cargo test`. They do NOT prove the LIVE server's behavior — only that the
//! client speaks the documented contract (see `collab_read_e2e` / `collab_write_e2e`
//! for the live gates).

use fula_mcp::collab::{
    fetch_collab_file, fetch_manifest, fula_fetch, put_manifest, upload_collab_file, CollabError,
};
use fula_mcp::manifest::{enc1_encrypt, CollaborationGroup};
use wiremock::matchers::{body_json, header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const GROUP: &str = "group-xyz";
const SECRET: [u8; 32] = [9u8; 32];

fn sample_group() -> CollaborationGroup {
    serde_json::from_str(
        r#"{"id":"group-xyz","name":"N","ownerPublicKey":"o","manifestKey":"k","createdAt":"c","updatedAt":"u","files":[]}"#,
    )
    .unwrap()
}

#[tokio::test]
async fn fetch_manifest_decrypts_enc1_envelope() {
    let server = MockServer::start().await;
    let group = sample_group();
    let enc1 = enc1_encrypt(&serde_json::to_vec(&group).unwrap(), &SECRET, GROUP);
    Mock::given(method("GET"))
        .and(path(format!("/api/collab/{GROUP}/manifest-sync")))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({ "encryptedManifest": enc1 })),
        )
        .mount(&server)
        .await;

    let client = reqwest::Client::new();
    let out = fetch_manifest(&client, &server.uri(), GROUP, &SECRET)
        .await
        .unwrap();
    assert_eq!(out.unwrap(), group);
}

#[tokio::test]
async fn fetch_manifest_rejects_unauthenticated_plaintext_data_field() {
    // SECURITY: a server returning a plaintext (non-ENC1) manifest is REFUSED —
    // it is unauthenticated and could forge the file listing. (Mirrors the unit
    // test; here it's exercised end-to-end through the HTTP client.)
    let server = MockServer::start().await;
    let group = sample_group();
    let plaintext = serde_json::to_string(&group).unwrap();
    Mock::given(method("GET"))
        .and(path(format!("/api/collab/{GROUP}/manifest-sync")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({ "data": plaintext })))
        .mount(&server)
        .await;

    let client = reqwest::Client::new();
    let err = fetch_manifest(&client, &server.uri(), GROUP, &SECRET)
        .await
        .unwrap_err();
    assert!(matches!(err, fula_mcp::collab::CollabError::UnauthenticatedManifest));
}

#[tokio::test]
async fn fetch_manifest_404_is_none() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/api/collab/{GROUP}/manifest-sync")))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;

    let client = reqwest::Client::new();
    assert!(fetch_manifest(&client, &server.uri(), GROUP, &SECRET)
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn fetch_collab_file_returns_bytes_and_404_is_not_found() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/api/collab/{GROUP}/file/f1")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![7u8, 8, 9]))
        .mount(&server)
        .await;

    let client = reqwest::Client::new();
    assert_eq!(
        fetch_collab_file(&client, &server.uri(), GROUP, "f1").await.unwrap(),
        vec![7, 8, 9]
    );
    // An unmocked file id ⇒ wiremock 404 ⇒ NotFound.
    let r = fetch_collab_file(&client, &server.uri(), GROUP, "missing").await;
    assert!(matches!(r, Err(CollabError::NotFound(_))));
}

#[tokio::test]
async fn fula_fetch_sends_bucket_and_key_query() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/api/collab/{GROUP}/fula-fetch")))
        .and(query_param("bucket", "bucket-1"))
        .and(query_param("key", "obfs/key.chunks/00000000"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![1u8, 2, 3, 4]))
        .mount(&server)
        .await;

    let client = reqwest::Client::new();
    let bytes = fula_fetch(
        &client,
        &server.uri(),
        GROUP,
        "bucket-1",
        "obfs/key.chunks/00000000",
    )
    .await
    .unwrap();
    assert_eq!(bytes, vec![1, 2, 3, 4]);
}

#[tokio::test]
async fn put_manifest_sends_bearer_and_encrypted_manifest_body() {
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path(format!("/api/collab/{GROUP}/manifest-sync")))
        .and(header("authorization", "Bearer wt-123"))
        .and(body_json(serde_json::json!({ "encryptedManifest": "ENC1:abc" })))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({ "ok": true })))
        .mount(&server)
        .await;

    let client = reqwest::Client::new();
    put_manifest(&client, &server.uri(), GROUP, "wt-123", "ENC1:abc")
        .await
        .unwrap();
}

#[tokio::test]
async fn put_manifest_401_maps_to_auth() {
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path(format!("/api/collab/{GROUP}/manifest-sync")))
        .respond_with(ResponseTemplate::new(401))
        .mount(&server)
        .await;

    let client = reqwest::Client::new();
    let r = put_manifest(&client, &server.uri(), GROUP, "wt", "ENC1:x").await;
    assert!(matches!(r, Err(CollabError::Auth { status: 401 })));
}

#[tokio::test]
async fn upload_sends_bearer_file_id_header_and_octet_stream() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/api/collab/{GROUP}/upload")))
        .and(header("authorization", "Bearer wt"))
        .and(header("x-collab-file-id", "fid-1"))
        .and(header("content-type", "application/octet-stream"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "storageKey": "sk-1", "bucket": "bk-1", "fileId": "fid-1", "size": 3
        })))
        .mount(&server)
        .await;

    let client = reqwest::Client::new();
    let resp = upload_collab_file(&client, &server.uri(), GROUP, "wt", "fid-1", vec![1, 2, 3])
        .await
        .unwrap();
    assert_eq!(resp.storage_key.as_deref(), Some("sk-1"));
    assert_eq!(resp.bucket.as_deref(), Some("bk-1"));
    assert_eq!(resp.file_id.as_deref(), Some("fid-1"));
    assert_eq!(resp.size, Some(3));
}

#[tokio::test]
async fn upload_403_maps_to_auth() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/api/collab/{GROUP}/upload")))
        .respond_with(ResponseTemplate::new(403))
        .mount(&server)
        .await;

    let client = reqwest::Client::new();
    let r = upload_collab_file(&client, &server.uri(), GROUP, "wt", "fid", vec![0u8]).await;
    assert!(matches!(r, Err(CollabError::Auth { status: 403 })));
}
