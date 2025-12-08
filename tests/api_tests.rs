use fula_cli::{GatewayConfig, AppState, routes};
use std::sync::Arc;
use tokio::net::TcpListener;
use reqwest::{Client, StatusCode};

// Helper to spawn a server on a random port
async fn spawn_server(auth_enabled: bool) -> (String, String) {
    let mut config = GatewayConfig::default();
    config.host = "127.0.0.1".to_string();
    config.port = 0; // Random port
    config.auth_enabled = auth_enabled;
    
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
