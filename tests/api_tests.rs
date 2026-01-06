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
