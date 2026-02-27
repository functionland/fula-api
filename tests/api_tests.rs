use fula_cli::{GatewayConfig, AppState, routes};
use std::sync::Arc;
use tokio::net::TcpListener;
use reqwest::{Client, StatusCode};
use jsonwebtoken::{encode, EncodingKey, Header};
use serde::{Serialize, Deserialize};
use chrono::{Utc, Duration};

// Helper to spawn a server on a random port
async fn spawn_server(auth_enabled: bool) -> (String, String) {
    let mut config = GatewayConfig::default();
    config.host = "127.0.0.1".to_string();
    config.port = 0; // Random port
    config.auth_enabled = auth_enabled;
    config.use_memory_store = true; // Use memory store for tests (no IPFS dependency)
    config.registry_cid_path = None; // No persistent registry for tests

    // Set a secret for auth tests
    let jwt_secret = "test-secret-123".to_string();
    config.jwt_secret = Some(jwt_secret.clone());

    let state = Arc::new(AppState::new(config.clone()).await.unwrap());
    let app = routes::create_router(state);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    (format!("http://{}", addr), jwt_secret)
}

/// JWT claims for test tokens
#[derive(Debug, Serialize, Deserialize)]
struct TestClaims {
    sub: String,
    exp: i64,
    scope: String,
    name: Option<String>,
}

/// Generate a valid JWT token for a specific user
fn generate_test_token(user_id: &str, secret: &str) -> String {
    let claims = TestClaims {
        sub: user_id.to_string(),
        exp: (Utc::now() + Duration::hours(1)).timestamp(),
        scope: "storage:read storage:write storage:delete".to_string(),
        name: Some(format!("Test User {}", user_id)),
    };
    encode(&Header::default(), &claims, &EncodingKey::from_secret(secret.as_bytes())).unwrap()
}

#[tokio::test]
async fn test_bucket_lifecycle() {
    let (base_url, _) = spawn_server(false).await;
    let client = Client::new();
    let bucket_name = "lifecycle-bucket";

    // 1. List buckets (should be empty)
    let res = client.get(&format!("{}/", base_url)).send().await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = res.text().await.unwrap();
    assert!(body.contains("<ListAllMyBucketsResult"));
    assert!(!body.contains(bucket_name));

    // 2. Create bucket
    let res = client.put(&format!("{}/{}", base_url, bucket_name))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // 3. Verify bucket exists (Head)
    let res = client.head(&format!("{}/{}", base_url, bucket_name))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // 4. List buckets (should contain it)
    let res = client.get(&format!("{}/", base_url)).send().await.unwrap();
    let body = res.text().await.unwrap();
    assert!(body.contains(bucket_name));

    // 5. Delete bucket
    let res = client.delete(&format!("{}/{}", base_url, bucket_name))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NO_CONTENT);

    // 6. Verify bucket gone
    let res = client.head(&format!("{}/{}", base_url, bucket_name))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_object_lifecycle() {
    let (base_url, _) = spawn_server(false).await;
    let client = Client::new();
    let bucket_name = "object-bucket";
    let object_key = "test-file.txt";
    let content = "Hello, Fula!";

    // Create bucket
    client.put(&format!("{}/{}", base_url, bucket_name)).send().await.unwrap();

    // 1. Put Object
    let res = client.put(&format!("{}/{}/{}", base_url, bucket_name, object_key))
        .body(content)
        .header("Content-Type", "text/plain")
        .header("Content-Length", content.len())
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    
    // Check ETag
    let etag = res.headers().get("ETag").unwrap().to_str().unwrap();
    assert!(!etag.is_empty());

    // 2. Get Object
    let res = client.get(&format!("{}/{}/{}", base_url, bucket_name, object_key))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.text().await.unwrap(), content);

    // 3. List Objects
    let res = client.get(&format!("{}/{}?list-type=2", base_url, bucket_name))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = res.text().await.unwrap();
    assert!(body.contains(object_key));
    assert!(body.contains("<KeyCount>1</KeyCount>"));

    // 4. Delete Object
    let res = client.delete(&format!("{}/{}/{}", base_url, bucket_name, object_key))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NO_CONTENT);

    // 5. Get Object (should be 404)
    let res = client.get(&format!("{}/{}/{}", base_url, bucket_name, object_key))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_edge_cases() {
    let (base_url, _) = spawn_server(false).await;
    let client = Client::new();
    let bucket_name = "edge-bucket";
    
    // 1. Create duplicate bucket (should fail with 409)
    client.put(&format!("{}/{}", base_url, bucket_name)).send().await.unwrap();
    let res = client.put(&format!("{}/{}", base_url, bucket_name)).send().await.unwrap();
    assert_eq!(res.status(), StatusCode::CONFLICT); // BucketAlreadyExists

    // 2. Delete non-empty bucket
    // Add an object
    client.put(&format!("{}/{}/file.txt", base_url, bucket_name))
        .body("data")
        .send()
        .await
        .unwrap();
        
    // Try to delete bucket
    let res = client.delete(&format!("{}/{}", base_url, bucket_name))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CONFLICT); // BucketNotEmpty
    
    // 3. Get non-existent bucket
    let res = client.get(&format!("{}/non-existent", base_url)).send().await.unwrap();
    // Assuming Get Bucket (List Objects) on non-existent
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_security_auth_enforcement() {
    // Spawn with auth ENABLED
    let (base_url, _) = spawn_server(true).await;
    let client = Client::new();
    
    // 1. Try to list buckets without token
    let res = client.get(&format!("{}/", base_url)).send().await.unwrap();
    // Expect 403 Forbidden (or 401, but current impl seems to be 403)
    assert!(res.status() == StatusCode::FORBIDDEN || res.status() == StatusCode::UNAUTHORIZED);
    
    // 2. Try with invalid token
    let res = client.get(&format!("{}/", base_url))
        .header("Authorization", "Bearer invalid-token")
        .send()
        .await
        .unwrap();
    assert!(res.status() == StatusCode::FORBIDDEN || res.status() == StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_metadata_headers() {
    let (base_url, _) = spawn_server(false).await;
    let client = Client::new();
    let bucket = "meta-bucket";
    let key = "meta-file";
    
    client.put(&format!("{}/{}", base_url, bucket)).send().await.unwrap();
    
    // Put with metadata
    let res = client.put(&format!("{}/{}/{}", base_url, bucket, key))
        .body("content")
        .header("x-amz-meta-author", "tester")
        .header("x-amz-meta-version", "1.0")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    
    // Head object to check metadata
    let res = client.head(&format!("{}/{}/{}", base_url, bucket, key))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    
    let headers = res.headers();
    assert_eq!(headers.get("x-amz-meta-author").unwrap(), "tester");
    assert_eq!(headers.get("x-amz-meta-version").unwrap(), "1.0");
}

#[tokio::test]
async fn test_integrity_check() {
    use base64::{Engine as _, engine::general_purpose};
    use md5::{Md5, Digest};

    let (base_url, _) = spawn_server(false).await;
    let client = Client::new();
    let bucket = "integrity-bucket";
    let key = "file.txt";
    let content = "Integrity check data";
    
    client.put(&format!("{}/{}", base_url, bucket)).send().await.unwrap();
    
    // Calculate valid MD5
    let mut hasher = Md5::new();
    hasher.update(content.as_bytes());
    let digest = hasher.finalize();
    let valid_md5 = general_purpose::STANDARD.encode(digest);
    
    // 1. Upload with valid MD5 -> Success
    let res = client.put(&format!("{}/{}/{}", base_url, bucket, key))
        .body(content)
        .header("Content-MD5", &valid_md5)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    
    // 2. Upload with INVALID MD5 -> Failure
    let invalid_md5 = general_purpose::STANDARD.encode(b"1234567890123456"); // 16 bytes
    let res = client.put(&format!("{}/{}/{}", base_url, bucket, "bad.txt"))
        .body(content)
        .header("Content-MD5", invalid_md5)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

// ============================================================================
// MULTI-TENANT ISOLATION TESTS
// ============================================================================

/// Test that two different users can create buckets with the same name
#[tokio::test]
async fn test_multitenant_same_bucket_name() {
    let (base_url, secret) = spawn_server(true).await;
    let client = Client::new();

    let token_alice = generate_test_token("alice@example.com", &secret);
    let token_bob = generate_test_token("bob@example.com", &secret);
    let bucket_name = "shared-name-bucket";

    // Alice creates bucket "shared-name-bucket"
    let res = client.put(&format!("{}/{}", base_url, bucket_name))
        .header("Authorization", format!("Bearer {}", token_alice))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK, "Alice should be able to create bucket");

    // Bob creates bucket with SAME name - should succeed (per-user isolation)
    let res = client.put(&format!("{}/{}", base_url, bucket_name))
        .header("Authorization", format!("Bearer {}", token_bob))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK, "Bob should be able to create bucket with same name");

    // Both users should see their own bucket in listings
    let res = client.get(&format!("{}/", base_url))
        .header("Authorization", format!("Bearer {}", token_alice))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = res.text().await.unwrap();
    assert!(body.contains(bucket_name), "Alice should see her bucket");

    let res = client.get(&format!("{}/", base_url))
        .header("Authorization", format!("Bearer {}", token_bob))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = res.text().await.unwrap();
    assert!(body.contains(bucket_name), "Bob should see his bucket");
}

/// Test that users cannot access each other's buckets
#[tokio::test]
async fn test_multitenant_bucket_isolation() {
    let (base_url, secret) = spawn_server(true).await;
    let client = Client::new();

    let token_alice = generate_test_token("alice@example.com", &secret);
    let token_bob = generate_test_token("bob@example.com", &secret);

    // Alice creates her bucket
    let alice_bucket = "alice-private-bucket";
    client.put(&format!("{}/{}", base_url, alice_bucket))
        .header("Authorization", format!("Bearer {}", token_alice))
        .send()
        .await
        .unwrap();

    // Bob tries to access Alice's bucket - should get 404 (not found for Bob)
    let res = client.head(&format!("{}/{}", base_url, alice_bucket))
        .header("Authorization", format!("Bearer {}", token_bob))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND, "Bob should not find Alice's bucket");

    // Bob tries to list objects in Alice's bucket - should get 404
    let res = client.get(&format!("{}/{}?list-type=2", base_url, alice_bucket))
        .header("Authorization", format!("Bearer {}", token_bob))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND, "Bob should not list Alice's bucket");

    // Bob tries to delete Alice's bucket - should get 404
    let res = client.delete(&format!("{}/{}", base_url, alice_bucket))
        .header("Authorization", format!("Bearer {}", token_bob))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND, "Bob should not delete Alice's bucket");
}

/// Test that objects are isolated between users with same bucket name
#[tokio::test]
async fn test_multitenant_object_isolation() {
    let (base_url, secret) = spawn_server(true).await;
    let client = Client::new();

    let token_alice = generate_test_token("alice@example.com", &secret);
    let token_bob = generate_test_token("bob@example.com", &secret);
    let bucket_name = "photos";
    let object_key = "vacation.jpg";

    // Both users create bucket with same name
    client.put(&format!("{}/{}", base_url, bucket_name))
        .header("Authorization", format!("Bearer {}", token_alice))
        .send()
        .await
        .unwrap();
    client.put(&format!("{}/{}", base_url, bucket_name))
        .header("Authorization", format!("Bearer {}", token_bob))
        .send()
        .await
        .unwrap();

    // Alice uploads an object
    let alice_content = "Alice's vacation photo";
    let res = client.put(&format!("{}/{}/{}", base_url, bucket_name, object_key))
        .header("Authorization", format!("Bearer {}", token_alice))
        .body(alice_content)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // Alice can read her object
    let res = client.get(&format!("{}/{}/{}", base_url, bucket_name, object_key))
        .header("Authorization", format!("Bearer {}", token_alice))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.text().await.unwrap(), alice_content);

    // Bob cannot read Alice's object (his bucket is empty)
    let res = client.get(&format!("{}/{}/{}", base_url, bucket_name, object_key))
        .header("Authorization", format!("Bearer {}", token_bob))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND, "Bob should not see Alice's object");

    // Bob uploads his own object with same key
    let bob_content = "Bob's vacation photo";
    let res = client.put(&format!("{}/{}/{}", base_url, bucket_name, object_key))
        .header("Authorization", format!("Bearer {}", token_bob))
        .body(bob_content)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // Bob reads his object - should get Bob's content, not Alice's
    let res = client.get(&format!("{}/{}/{}", base_url, bucket_name, object_key))
        .header("Authorization", format!("Bearer {}", token_bob))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.text().await.unwrap(), bob_content);

    // Alice's object should still be intact
    let res = client.get(&format!("{}/{}/{}", base_url, bucket_name, object_key))
        .header("Authorization", format!("Bearer {}", token_alice))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.text().await.unwrap(), alice_content);
}

/// Test that bucket listings only show user's own buckets
#[tokio::test]
async fn test_multitenant_list_buckets_isolation() {
    let (base_url, secret) = spawn_server(true).await;
    let client = Client::new();

    let token_alice = generate_test_token("alice@example.com", &secret);
    let token_bob = generate_test_token("bob@example.com", &secret);

    // Alice creates multiple buckets
    for bucket in &["alice-bucket-1", "alice-bucket-2", "alice-bucket-3"] {
        client.put(&format!("{}/{}", base_url, bucket))
            .header("Authorization", format!("Bearer {}", token_alice))
            .send()
            .await
            .unwrap();
    }

    // Bob creates his bucket
    client.put(&format!("{}/{}", base_url, "bob-bucket"))
        .header("Authorization", format!("Bearer {}", token_bob))
        .send()
        .await
        .unwrap();

    // Alice lists buckets - should only see her 3 buckets
    let res = client.get(&format!("{}/", base_url))
        .header("Authorization", format!("Bearer {}", token_alice))
        .send()
        .await
        .unwrap();
    let body = res.text().await.unwrap();
    assert!(body.contains("alice-bucket-1"));
    assert!(body.contains("alice-bucket-2"));
    assert!(body.contains("alice-bucket-3"));
    assert!(!body.contains("bob-bucket"), "Alice should not see Bob's bucket");

    // Bob lists buckets - should only see his 1 bucket
    let res = client.get(&format!("{}/", base_url))
        .header("Authorization", format!("Bearer {}", token_bob))
        .send()
        .await
        .unwrap();
    let body = res.text().await.unwrap();
    assert!(body.contains("bob-bucket"));
    assert!(!body.contains("alice-bucket"), "Bob should not see Alice's buckets");
}

/// Test that delete operations are isolated
#[tokio::test]
async fn test_multitenant_delete_isolation() {
    let (base_url, secret) = spawn_server(true).await;
    let client = Client::new();

    let token_alice = generate_test_token("alice@example.com", &secret);
    let token_bob = generate_test_token("bob@example.com", &secret);
    let bucket_name = "delete-test-bucket";

    // Both users create bucket with same name
    client.put(&format!("{}/{}", base_url, bucket_name))
        .header("Authorization", format!("Bearer {}", token_alice))
        .send()
        .await
        .unwrap();
    client.put(&format!("{}/{}", base_url, bucket_name))
        .header("Authorization", format!("Bearer {}", token_bob))
        .send()
        .await
        .unwrap();

    // Alice uploads an object
    client.put(&format!("{}/{}/file.txt", base_url, bucket_name))
        .header("Authorization", format!("Bearer {}", token_alice))
        .body("Alice's data")
        .send()
        .await
        .unwrap();

    // Bob deletes his (empty) bucket
    let res = client.delete(&format!("{}/{}", base_url, bucket_name))
        .header("Authorization", format!("Bearer {}", token_bob))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NO_CONTENT, "Bob should delete his empty bucket");

    // Alice's bucket and object should still exist
    let res = client.head(&format!("{}/{}", base_url, bucket_name))
        .header("Authorization", format!("Bearer {}", token_alice))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK, "Alice's bucket should still exist");

    let res = client.get(&format!("{}/{}/file.txt", base_url, bucket_name))
        .header("Authorization", format!("Bearer {}", token_alice))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK, "Alice's object should still exist");
    assert_eq!(res.text().await.unwrap(), "Alice's data");
}

/// Test object operations after multiple put/get cycles (cache consistency)
#[tokio::test]
async fn test_multitenant_cache_consistency() {
    let (base_url, secret) = spawn_server(true).await;
    let client = Client::new();

    let token_user = generate_test_token("cache-test-user@example.com", &secret);
    let bucket_name = "cache-test-bucket";

    // Create bucket
    client.put(&format!("{}/{}", base_url, bucket_name))
        .header("Authorization", format!("Bearer {}", token_user))
        .send()
        .await
        .unwrap();

    // Perform multiple put/get cycles to test cache consistency
    for i in 0..5 {
        let key = format!("file-{}.txt", i);
        let content = format!("Content version {}", i);

        // Put object
        let res = client.put(&format!("{}/{}/{}", base_url, bucket_name, key))
            .header("Authorization", format!("Bearer {}", token_user))
            .body(content.clone())
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK, "Put {} should succeed", i);

        // Immediately get object
        let res = client.get(&format!("{}/{}/{}", base_url, bucket_name, key))
            .header("Authorization", format!("Bearer {}", token_user))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK, "Get {} should succeed", i);
        assert_eq!(res.text().await.unwrap(), content, "Content {} should match", i);
    }

    // List objects - should have all 5
    let res = client.get(&format!("{}/{}?list-type=2", base_url, bucket_name))
        .header("Authorization", format!("Bearer {}", token_user))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = res.text().await.unwrap();
    assert!(body.contains("<KeyCount>5</KeyCount>"), "Should have 5 objects");
}

/// Test that a new user starts with no buckets
#[tokio::test]
async fn test_multitenant_new_user_empty() {
    let (base_url, secret) = spawn_server(true).await;
    let client = Client::new();

    // Create a token for a brand new user
    let token_new_user = generate_test_token("brand-new-user@example.com", &secret);

    // List buckets - should be empty
    let res = client.get(&format!("{}/", base_url))
        .header("Authorization", format!("Bearer {}", token_new_user))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = res.text().await.unwrap();
    assert!(body.contains("<Buckets></Buckets>") || body.contains("<Buckets/>") ||
            (!body.contains("<Bucket>") && body.contains("<Buckets>")),
            "New user should have no buckets");
}

// ============================================================================
// S3 PROTOCOL CORRECTNESS TESTS
// ============================================================================

/// Regression test: GET object must never be compressed server-side.
///
/// Real AWS S3 never applies Content-Encoding to GET responses. When
/// CompressionLayer was active, it would gzip the body, strip Content-Length,
/// and force chunked transfer encoding. AWS CLI and other S3 tools that expect
/// Content-Length would receive corrupted files (chunked framing leaked into
/// the data).
///
/// See: https://github.com/functionland/fula-api/issues/XXX
#[tokio::test]
async fn test_get_object_no_server_side_compression() {
    let (base_url, _) = spawn_server(false).await;

    // Disable reqwest auto-decompression so we can inspect raw headers
    let client = Client::builder()
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .build()
        .unwrap();

    let bucket = "compression-test-bucket";
    let key = "image.jpg";

    // Fake JPEG: starts with FF D8 FF (JPEG SOI + APP0 marker), then random binary
    let fake_jpeg: Vec<u8> = {
        let mut v = vec![0xFF, 0xD8, 0xFF, 0xE0];
        v.extend_from_slice(&[0x42; 2048]); // 2KB of binary padding
        v
    };
    let original_len = fake_jpeg.len();

    // Create bucket
    client.put(&format!("{}/{}", base_url, bucket)).send().await.unwrap();

    // Upload the binary object
    let res = client.put(&format!("{}/{}/{}", base_url, bucket, key))
        .body(fake_jpeg.clone())
        .header("Content-Type", "image/jpeg")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // Download with Accept-Encoding: gzip (simulates AWS CLI behavior)
    let res = client.get(&format!("{}/{}/{}", base_url, bucket, key))
        .header("Accept-Encoding", "gzip, deflate, br")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let headers = res.headers();

    // Content-Length MUST be present (S3 protocol requirement)
    let content_length = headers.get("Content-Length")
        .expect("Content-Length header must be present on S3 GET responses");
    assert_eq!(
        content_length.to_str().unwrap(),
        original_len.to_string(),
        "Content-Length must match original object size"
    );

    // Transfer-Encoding MUST NOT be present
    assert!(
        headers.get("Transfer-Encoding").is_none(),
        "Transfer-Encoding must not be set on S3 GET responses"
    );

    // Content-Encoding MUST NOT be set (server did not compress)
    assert!(
        headers.get("Content-Encoding").is_none(),
        "Server must not add Content-Encoding to GET responses"
    );

    // Body must be byte-for-byte identical to the uploaded object
    let body_bytes = res.bytes().await.unwrap();
    assert_eq!(body_bytes.len(), original_len, "Body length must match original");
    assert_eq!(
        &body_bytes[..4],
        &[0xFF, 0xD8, 0xFF, 0xE0],
        "Body must start with JPEG magic bytes, not chunked framing"
    );
    assert_eq!(
        body_bytes.as_ref(),
        fake_jpeg.as_slice(),
        "Downloaded bytes must be identical to uploaded bytes"
    );
}

/// Test that text objects also aren't compressed (even though they're compressible)
#[tokio::test]
async fn test_get_text_object_no_compression() {
    let (base_url, _) = spawn_server(false).await;

    let client = Client::builder()
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .build()
        .unwrap();

    let bucket = "text-compression-bucket";
    let key = "data.json";
    // Highly compressible content
    let content = r#"{"key": "value", "repeated": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#;

    client.put(&format!("{}/{}", base_url, bucket)).send().await.unwrap();

    client.put(&format!("{}/{}/{}", base_url, bucket, key))
        .body(content)
        .header("Content-Type", "application/json")
        .send()
        .await
        .unwrap();

    let res = client.get(&format!("{}/{}/{}", base_url, bucket, key))
        .header("Accept-Encoding", "gzip")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let headers = res.headers();
    assert!(headers.get("Content-Length").is_some(), "Content-Length must be present");
    assert!(headers.get("Transfer-Encoding").is_none(), "Transfer-Encoding must not be set");
    assert!(headers.get("Content-Encoding").is_none(), "Content-Encoding must not be set");

    assert_eq!(res.text().await.unwrap(), content, "Text content must be returned uncompressed");
}

/// Range requests must preserve Content-Length matching the range, not the full object,
/// and must never be compressed or chunked.
#[tokio::test]
async fn test_range_request_no_compression() {
    let (base_url, _) = spawn_server(false).await;

    let client = Client::builder()
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .build()
        .unwrap();

    let bucket = "range-compression-bucket";
    let key = "largefile.bin";
    let data: Vec<u8> = (0..=255u8).cycle().take(4096).collect(); // 4KB

    client.put(&format!("{}/{}", base_url, bucket)).send().await.unwrap();
    client.put(&format!("{}/{}/{}", base_url, bucket, key))
        .body(data.clone())
        .send()
        .await
        .unwrap();

    // Request bytes 100-199 with Accept-Encoding: gzip
    let res = client.get(&format!("{}/{}/{}", base_url, bucket, key))
        .header("Range", "bytes=100-199")
        .header("Accept-Encoding", "gzip, deflate, br")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::PARTIAL_CONTENT);

    let headers = res.headers();
    let content_length: usize = headers.get("Content-Length")
        .expect("Content-Length must be present on range responses")
        .to_str().unwrap().parse().unwrap();
    assert_eq!(content_length, 100, "Content-Length must equal the range size");
    assert!(headers.get("Transfer-Encoding").is_none(), "No Transfer-Encoding on range response");
    assert!(headers.get("Content-Encoding").is_none(), "No Content-Encoding on range response");

    let body = res.bytes().await.unwrap();
    assert_eq!(body.len(), 100);
    assert_eq!(body.as_ref(), &data[100..200], "Range bytes must match original slice");
}

/// HEAD requests must return Content-Length matching the object size, with no body.
/// Compression middleware historically drops Content-Length on HEAD responses.
#[tokio::test]
async fn test_head_request_content_length_preserved() {
    let (base_url, _) = spawn_server(false).await;

    let client = Client::builder()
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .build()
        .unwrap();

    let bucket = "head-test-bucket";
    let key = "document.pdf";
    let content = vec![0x25, 0x50, 0x44, 0x46]; // %PDF header + padding
    let mut data = content.clone();
    data.extend_from_slice(&[0x00; 1024]);
    let expected_len = data.len();

    client.put(&format!("{}/{}", base_url, bucket)).send().await.unwrap();
    client.put(&format!("{}/{}/{}", base_url, bucket, key))
        .body(data)
        .header("Content-Type", "application/pdf")
        .send()
        .await
        .unwrap();

    let res = client.head(&format!("{}/{}/{}", base_url, bucket, key))
        .header("Accept-Encoding", "gzip, deflate, br")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let headers = res.headers();
    let content_length: usize = headers.get("Content-Length")
        .expect("Content-Length must be present on HEAD responses")
        .to_str().unwrap().parse().unwrap();
    assert_eq!(content_length, expected_len, "HEAD Content-Length must match object size");
    assert!(headers.get("Transfer-Encoding").is_none(), "No Transfer-Encoding on HEAD response");
    assert!(headers.get("Content-Encoding").is_none(), "No Content-Encoding on HEAD response");
}

/// Large highly-compressible objects must still be returned uncompressed.
/// Some compression middleware only kicks in above a size threshold.
#[tokio::test]
async fn test_large_compressible_object_no_compression() {
    let (base_url, _) = spawn_server(false).await;

    let client = Client::builder()
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .build()
        .unwrap();

    let bucket = "large-compression-bucket";
    let key = "big.txt";
    // 128KB of repeated 'a' — extremely compressible
    let content = "a".repeat(128 * 1024);
    let original_len = content.len();

    client.put(&format!("{}/{}", base_url, bucket)).send().await.unwrap();
    client.put(&format!("{}/{}/{}", base_url, bucket, key))
        .body(content.clone())
        .header("Content-Type", "text/plain")
        .send()
        .await
        .unwrap();

    let res = client.get(&format!("{}/{}/{}", base_url, bucket, key))
        .header("Accept-Encoding", "gzip, deflate, br")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let headers = res.headers();
    let cl: usize = headers.get("Content-Length")
        .expect("Content-Length must be present")
        .to_str().unwrap().parse().unwrap();
    assert_eq!(cl, original_len, "Content-Length must equal uncompressed size");
    assert!(headers.get("Transfer-Encoding").is_none(), "No Transfer-Encoding");
    assert!(headers.get("Content-Encoding").is_none(), "No Content-Encoding");

    let body = res.text().await.unwrap();
    assert_eq!(body.len(), original_len, "Body must be full uncompressed size");
    assert_eq!(body, content);
}

/// Regression test: PUT with HTTP chunked transfer-encoded body must be decoded.
///
/// AWS CLI sends request bodies with chunked transfer encoding that a reverse
/// proxy (nginx) may forward without decoding. Without decoding, the chunked
/// framing (e.g., "100000\r\n") gets stored as part of the object data,
/// corrupting the file.
#[tokio::test]
async fn test_put_object_decodes_chunked_body() {
    let (base_url, _) = spawn_server(false).await;
    let client = Client::builder()
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .build()
        .unwrap();

    let bucket = "chunked-decode-bucket";
    let key = "photo.jpg";

    // Simulate a JPEG file (starts with FF D8 FF)
    let original_data: Vec<u8> = {
        let mut v = vec![0xFF, 0xD8, 0xFF, 0xE0];
        v.extend_from_slice(&[0x42; 2044]); // 2048 bytes total
        v
    };

    // Wrap the data in HTTP chunked transfer encoding framing
    // This simulates what happens when nginx strips Transfer-Encoding header
    // but forwards the raw chunked body
    let chunk_size_hex = format!("{:x}", original_data.len());
    let mut chunked_body: Vec<u8> = Vec::new();
    chunked_body.extend_from_slice(chunk_size_hex.as_bytes()); // "800"
    chunked_body.extend_from_slice(b"\r\n");
    chunked_body.extend_from_slice(&original_data);
    chunked_body.extend_from_slice(b"\r\n");
    chunked_body.extend_from_slice(b"0\r\n\r\n"); // Terminal chunk

    assert_ne!(chunked_body.len(), original_data.len(), "Chunked body should be larger");

    // Create bucket
    client.put(&format!("{}/{}", base_url, bucket)).send().await.unwrap();

    // Upload the chunked-encoded body (simulating broken proxy behavior)
    let res = client.put(&format!("{}/{}/{}", base_url, bucket, key))
        .body(chunked_body)
        .header("Content-Type", "image/jpeg")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // Download and verify the gateway decoded the chunked framing
    let res = client.get(&format!("{}/{}/{}", base_url, bucket, key))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let body = res.bytes().await.unwrap();
    assert_eq!(
        body.len(), original_data.len(),
        "Downloaded size ({}) should match original ({}), not chunked body",
        body.len(), original_data.len()
    );
    assert_eq!(
        &body[..4], &[0xFF, 0xD8, 0xFF, 0xE0],
        "Body must start with JPEG magic, not chunked framing"
    );
    assert_eq!(body.as_ref(), original_data.as_slice(), "Decoded body must match original");
}

/// Test that chunked decoding handles aws-chunked format (with chunk-signature extensions)
#[tokio::test]
async fn test_put_object_decodes_aws_chunked_body() {
    let (base_url, _) = spawn_server(false).await;
    let client = Client::builder()
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .build()
        .unwrap();

    let bucket = "aws-chunked-bucket";
    let key = "data.bin";
    let original_data = b"Hello, this is test data for aws-chunked decoding!";

    // Build aws-chunked encoded body:
    // <hex-size>;chunk-signature=<fake-sig>\r\n<data>\r\n0;chunk-signature=<fake-sig>\r\n\r\n
    let fake_sig = "a".repeat(64);
    let mut chunked_body: Vec<u8> = Vec::new();
    chunked_body.extend_from_slice(format!("{:x};chunk-signature={}\r\n", original_data.len(), fake_sig).as_bytes());
    chunked_body.extend_from_slice(original_data);
    chunked_body.extend_from_slice(b"\r\n");
    chunked_body.extend_from_slice(format!("0;chunk-signature={}\r\n\r\n", fake_sig).as_bytes());

    // Create bucket
    client.put(&format!("{}/{}", base_url, bucket)).send().await.unwrap();

    // Upload with x-amz-decoded-content-length header (AWS streaming signature signal)
    let res = client.put(&format!("{}/{}/{}", base_url, bucket, key))
        .body(chunked_body)
        .header("Content-Encoding", "aws-chunked")
        .header("x-amz-decoded-content-length", original_data.len().to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // Download and verify
    let res = client.get(&format!("{}/{}/{}", base_url, bucket, key))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let body = res.bytes().await.unwrap();
    assert_eq!(body.as_ref(), original_data, "Body must be decoded aws-chunked content");
}

/// Test that normal (non-chunked) uploads are NOT affected by chunked decoding
#[tokio::test]
async fn test_put_object_normal_body_unaffected() {
    let (base_url, _) = spawn_server(false).await;
    let client = Client::new();

    let bucket = "normal-body-bucket";
    let key = "binary.dat";

    // Binary data that could theoretically look like a chunk header if we're not careful
    // (starts with bytes that are valid hex chars in ASCII)
    let original_data: Vec<u8> = vec![0x41, 0x42, 0x43, 0x44, 0x45, 0x46]; // "ABCDEF" in ASCII

    // Create bucket
    client.put(&format!("{}/{}", base_url, bucket)).send().await.unwrap();

    // Upload normally
    let res = client.put(&format!("{}/{}/{}", base_url, bucket, key))
        .body(original_data.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // Download - should be identical
    let res = client.get(&format!("{}/{}/{}", base_url, bucket, key))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let body = res.bytes().await.unwrap();
    assert_eq!(body.as_ref(), original_data.as_slice(), "Normal upload must not be modified");
}

/// Test duplicate bucket creation for same user fails
#[tokio::test]
async fn test_multitenant_duplicate_bucket_same_user() {
    let (base_url, secret) = spawn_server(true).await;
    let client = Client::new();

    let token_user = generate_test_token("duplicate-test@example.com", &secret);
    let bucket_name = "my-unique-bucket";

    // Create bucket first time - should succeed
    let res = client.put(&format!("{}/{}", base_url, bucket_name))
        .header("Authorization", format!("Bearer {}", token_user))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // Create same bucket again - should fail with 409
    let res = client.put(&format!("{}/{}", base_url, bucket_name))
        .header("Authorization", format!("Bearer {}", token_user))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CONFLICT, "Duplicate bucket for same user should fail");
}
