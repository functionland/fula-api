//! F8 — buffered chunked-download integrity-before-emission guarantee.
//!
//! The streaming download API (`get_object_decrypted_to_writer`) writes
//! per-chunk plaintext as each chunk decrypts, which means a truncation
//! or tamper caught at root-hash finalize has already leaked partial
//! plaintext into the caller's writer. The new buffered variant
//! (`get_object_decrypted_buffered_to_writer`) accumulates the full
//! decrypted payload in memory, only runs `finalize_and_verify`, and
//! only then flushes to the caller. This file proves the guarantee by:
//!
//! 1. Uploading a chunked encrypted file through the normal client path.
//! 2. Tampering with one chunk's ciphertext directly at the storage layer.
//! 3. Showing that `get_object_decrypted_buffered_to_writer` errors AND
//!    leaves the caller's writer empty.
//! 4. Showing — for contrast — that the streaming variant errors but
//!    DOES emit some plaintext to the writer before the failure, which
//!    is precisely the F8 hazard the buffered variant closes.

use bytes::Bytes;
use fula_client::{Config, EncryptedClient, EncryptionConfig};
use fula_cli::{AppState, GatewayConfig, routes};
use std::sync::Arc;
use tokio::net::TcpListener;

async fn spawn_server() -> String {
    let mut config = GatewayConfig::default();
    config.host = "127.0.0.1".to_string();
    config.port = 0;
    config.auth_enabled = false;
    config.use_memory_store = true;
    config.registry_cid_path = None;
    config.jwt_secret = Some("test-secret-f8".to_string());
    // Raise the rate-limit so the bulk put_object doesn't trigger SlowDown.
    config.rate_limit_rps = 1_000_000;

    let state = Arc::new(AppState::new(config.clone()).await.unwrap());
    let app = routes::create_router(state);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    format!("http://{}", addr)
}

fn make_client(endpoint: &str) -> EncryptedClient {
    let config = Config::new(endpoint).with_encryption();
    EncryptedClient::new(config, EncryptionConfig::new()).expect("encrypted client")
}

/// Upload `data` to `bucket/key` as an encrypted chunked object, then return
/// `(storage_key, chunk_keys)` — the main (metadata) storage key and the
/// list of `{storage_key}.chunks/{i:08}` subordinate keys the gateway
/// observed. Tests tamper with one of these to trigger a decode failure.
async fn upload_chunked_and_list(
    client: &EncryptedClient,
    bucket: &str,
    key: &str,
    data: Vec<u8>,
) -> (String, Vec<String>) {
    // `put_object_encrypted` is the single-block path; it never chunks. For
    // F8 we want to exercise the chunked download engine, so we drive
    // `put_object_chunked` directly with a sub-MAX_CHUNK_SIZE chunk size so
    // a moderate-sized payload produces multiple chunk objects (enough that
    // tampering with the last chunk leaves earlier ones to be emitted by
    // the streaming variant).
    let _result = client
        .put_object_chunked(bucket, key, &data, Some(256 * 1024))
        .await
        .expect("put_object_chunked");

    // The gateway's listing sees every storage key in the bucket, including
    // the main metadata object and its `.chunks/*` subordinates.
    let all = client
        .inner()
        .list_objects(bucket, None)
        .await
        .expect("list_objects");
    let mut main_key: Option<String> = None;
    let mut chunk_keys: Vec<String> = Vec::new();
    for obj in all.objects {
        if obj.key.contains(".chunks/") {
            chunk_keys.push(obj.key);
        } else {
            main_key = Some(obj.key);
        }
    }
    chunk_keys.sort();
    (main_key.expect("main storage key"), chunk_keys)
}

// ═══════════════════════════════════════════════════════════════════════════
// F8.1 — buffered variant: integrity failure keeps writer empty.
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn f8_buffered_download_leaves_writer_empty_on_tampered_chunk() {
    let base = spawn_server().await;
    let client = make_client(&base);
    let bucket = "f8-buffered";
    client.create_bucket(bucket).await.expect("create bucket");

    // 1 MiB plaintext — well over MAX_CHUNK_SIZE (768 KiB) so the put path
    // takes the chunked branch. Using a varied byte pattern rather than
    // zeros so a lucky tamper isn't indistinguishable from correct plaintext.
    let data: Vec<u8> = (0..1_048_576u32).map(|i| (i & 0xFF) as u8).collect();

    let (storage_key, chunk_keys) = upload_chunked_and_list(
        &client, bucket, "/big.bin", data.clone(),
    ).await;
    assert!(
        chunk_keys.len() >= 2,
        "file must produce multiple chunks; got {} chunk objects",
        chunk_keys.len()
    );

    // Sanity: untampered buffered download round-trips exactly.
    let mut good: Vec<u8> = Vec::new();
    client
        .get_object_decrypted_buffered_to_writer_by_storage_key(bucket, &storage_key, &mut good)
        .await
        .expect("untampered buffered download succeeds");
    assert_eq!(good, data, "untampered buffered download must match original");

    // Tamper: overwrite the MIDDLE chunk with garbage of matching length.
    let mid = chunk_keys.len() / 2;
    let victim = &chunk_keys[mid];
    let orig = client.inner().get_object(bucket, victim).await.expect("get victim chunk");
    let mut garbled = orig.to_vec();
    for b in garbled.iter_mut() {
        *b ^= 0xA5;
    }
    client
        .inner()
        .put_object(bucket, victim, Bytes::from(garbled))
        .await
        .expect("overwrite chunk with tampered ciphertext");

    // F8 guarantee: buffered download MUST fail AND writer MUST be empty.
    let mut sink: Vec<u8> = Vec::new();
    let err = client
        .get_object_decrypted_buffered_to_writer_by_storage_key(bucket, &storage_key, &mut sink)
        .await
        .expect_err("tampered chunk must fail buffered download");
    assert!(
        sink.is_empty(),
        "F8 violation: buffered writer received {} bytes before integrity \
         failure (expected 0). error was: {:?}",
        sink.len(),
        err,
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// F8.2 — contrast: streaming variant leaks partial plaintext before failing.
//
// This is the hazard F8 exists to address: the streaming engine verifies
// each chunk's AEAD before emitting, but a tampered later chunk only
// trips detection AFTER earlier (untampered) chunks have already been
// written to the caller's sink. This test exists both to pin that
// behavior (so nobody "fixes" it and inadvertently removes the distinction
// between the two APIs) and to make the buffered variant's added guarantee
// visible: F8.1 passes because F8.2 fails, not because both trivially
// produce empty sinks.
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn f8_streaming_download_does_emit_partial_plaintext_on_tamper() {
    let base = spawn_server().await;
    let client = make_client(&base);
    let bucket = "f8-streaming-contrast";
    client.create_bucket(bucket).await.expect("create bucket");

    let data: Vec<u8> = (0..1_048_576u32).map(|i| (i & 0xFF) as u8).collect();
    let (storage_key, chunk_keys) = upload_chunked_and_list(
        &client, bucket, "/big.bin", data.clone(),
    ).await;
    assert!(
        chunk_keys.len() >= 2,
        "file must produce multiple chunks; got {} chunk objects",
        chunk_keys.len()
    );

    // Tamper with the LAST chunk so the streaming path decodes every earlier
    // chunk cleanly (and emits their plaintext) before tripping on the tail.
    let victim = chunk_keys.last().unwrap();
    let orig = client.inner().get_object(bucket, victim).await.expect("get victim chunk");
    let mut garbled = orig.to_vec();
    for b in garbled.iter_mut() {
        *b ^= 0xA5;
    }
    client
        .inner()
        .put_object(bucket, victim, Bytes::from(garbled))
        .await
        .expect("overwrite tail chunk");

    let mut sink: Vec<u8> = Vec::new();
    let err = client
        .get_object_decrypted_to_writer_by_storage_key(bucket, &storage_key, &mut sink)
        .await
        .expect_err("tampered tail must fail streaming download");
    assert!(
        !sink.is_empty(),
        "streaming download is expected to emit pre-failure plaintext \
         (this is the hazard F8 fixes); writer had 0 bytes. error: {:?}",
        err,
    );
    // And critically: that partially-emitted plaintext is not the full file.
    assert_ne!(
        sink, data,
        "streaming sink must not match the original plaintext once a chunk \
         was tampered — root-hash check would have caught the tail but the \
         sink got whatever decoded successfully up to that point"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// F8.3 — buffered variant size ceiling rejects oversize pre-network.
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn f8_buffered_download_rejects_oversize_file() {
    let base = spawn_server().await;
    // Configure a ceiling smaller than the uploaded file. The client still
    // points at a real server — the point is the *client-side* guard fires
    // BEFORE the decode engine is ever handed a manifest whose total_size
    // exceeds the ceiling.
    let mut cfg = Config::new(&base).with_encryption();
    cfg.buffered_download_max_bytes = 512 * 1024; // 512 KiB ceiling
    let client = EncryptedClient::new(cfg, EncryptionConfig::new()).expect("client");
    let bucket = "f8-ceiling";
    client.create_bucket(bucket).await.expect("create bucket");

    let data: Vec<u8> = (0..1_048_576u32).map(|i| (i & 0xFF) as u8).collect();
    let (storage_key, _chunks) = upload_chunked_and_list(
        &client, bucket, "/too-big.bin", data,
    ).await;

    let mut sink: Vec<u8> = Vec::new();
    let err = client
        .get_object_decrypted_buffered_to_writer_by_storage_key(bucket, &storage_key, &mut sink)
        .await
        .expect_err("buffered download must reject oversize file");
    assert!(
        sink.is_empty(),
        "writer must remain empty when ceiling rejects a file; got {} bytes",
        sink.len(),
    );
    match err {
        fula_client::ClientError::DownloadFailed(msg) => assert!(
            msg.contains("buffered download exceeds configured ceiling"),
            "expected ceiling error, got: {}",
            msg
        ),
        other => panic!("expected DownloadFailed, got {:?}", other),
    }

    // Streaming variant must still work — F8 adds a new API, not a new limit
    // on the existing one.
    let mut stream_sink: Vec<u8> = Vec::new();
    client
        .get_object_decrypted_to_writer_by_storage_key(bucket, &storage_key, &mut stream_sink)
        .await
        .expect("streaming download must not be limited by the buffered ceiling");
    assert_eq!(
        stream_sink.len(),
        1_048_576,
        "streaming variant must deliver the full untampered file regardless \
         of buffered_download_max_bytes"
    );
}
