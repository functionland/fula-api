//! E2E (real server): the PUSH-model streaming upload must produce a normally
//! downloadable, BYTE-EXACT object on the real gateway. Validates P2 of
//! docs/web-streaming-resumable-upload-plan.md against production — not just the
//! hermetic mock in streaming_upload_roundtrip.rs.
//!
//! Drives the exact sequence the FRB handle uses:
//!   streaming_begin -> plan-only ChunkedEncoder (pass 1) -> streaming_finalize_plan
//!     -> streaming_put_chunk loop (pass 2) -> streaming_finish
//! then downloads via get_object_flat and asserts byte-exact. The file is large
//! enough (~50 MB, ~200 chunks at 256 KB) that the index metadata exceeds the
//! gateway's 16 KB header budget, so this also exercises header_safe_enc_metadata
//! stripping + the body/forest fallback on the real server.
//!
//! `#[ignore]` — needs network + real credentials. Run (PowerShell, env loaded
//! from e2e-credentials.env):
//!   cargo test -p fula-client --test streaming_upload_e2e --release -- --ignored --nocapture
//!
//! Required env: FULA_S3, FULA_JWT, FULA_TEST_PROVIDER, FULA_TEST_OAUTH_SUB,
//! FULA_TEST_EMAIL (the Mode A derivation triple).

#![cfg(not(target_arch = "wasm32"))]

use fula_client::{Config, EncryptedClient, EncryptionConfig};
use fula_crypto::chunked::ChunkedEncoder;
use fula_crypto::keys::SecretKey;

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("missing required env {name}"))
}

#[tokio::test]
#[ignore = "real-server; needs FULA_S3 + FULA_JWT + Mode A triple"]
async fn streaming_upload_large_file_roundtrips_on_real_server() {
    let s3 = env("FULA_S3");
    let jwt = env("FULA_JWT");
    let input = format!(
        "{}:{}:{}",
        env("FULA_TEST_PROVIDER"),
        env("FULA_TEST_OAUTH_SUB"),
        env("FULA_TEST_EMAIL"),
    );
    let kek = fula_crypto::hashing::derive_key_argon2id("fula-files-v1", input.as_bytes());
    let secret = SecretKey::from_bytes(&kek).expect("32-byte secret from Argon2id");

    let mut config = Config::new(&s3).with_token(&jwt);
    // Match FxFiles production: stamps chunk_cids into the index metadata.
    config.walkable_v8_writer_enabled = true;
    let client = EncryptedClient::new(config, EncryptionConfig::from_secret_key(secret))
        .expect("EncryptedClient::new");

    let epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let bucket = format!("e2e-streaming-{epoch}-v8");
    eprintln!("[streaming_e2e] BUCKET={bucket}");
    if let Err(e) = client.create_bucket(&bucket).await {
        eprintln!("[streaming_e2e] create_bucket({bucket}) -> {e} (continuing)");
    }

    // ~50 MB -> ~200 chunks at 256 KB -> index metadata over the 16 KB header
    // budget (exercises header_safe_enc_metadata stripping + body fallback).
    let size = 50 * 1024 * 1024;
    let mut data = vec![0u8; size];
    for (i, b) in data.iter_mut().enumerate() {
        *b = ((i * 31 + 7) % 251) as u8;
    }
    let key_path = "/big-streamed.bin";

    // ---- streaming upload (push model; mirrors the FRB handle) ----
    eprintln!("[streaming_e2e] streaming_begin...");
    let (storage_key, dek, wrapped_dek, kek_version) = client
        .streaming_begin(&bucket, key_path)
        .await
        .expect("streaming_begin");

    // pass 1: plan-only encoder (default 256 KB chunks, matching production),
    // fed in arbitrary 1 MiB streaming slices.
    let aad_prefix = format!("fula:v4:chunk:{}", storage_key);
    let mut encoder =
        ChunkedEncoder::with_aad(dek.clone(), aad_prefix.into_bytes()).into_plan_only();
    eprintln!("[streaming_e2e] pass 1 (plan)...");
    for slice in data.chunks(1024 * 1024) {
        encoder.update(slice).expect("plan update");
    }
    let (chunked_metadata, private_meta, encrypted_meta) = client
        .streaming_finalize_plan(encoder, &dek, &storage_key, key_path, Some("application/octet-stream"))
        .expect("streaming_finalize_plan");

    let cs = chunked_metadata.chunk_size as usize;
    let num_chunks = chunked_metadata.num_chunks as usize;
    eprintln!("[streaming_e2e] {num_chunks} chunks @ {cs} bytes; pass 2 (upload)...");
    assert!(
        num_chunks > 120,
        "need >120 chunks to exceed the 16 KB header budget (got {num_chunks})"
    );

    // pass 2: upload each chunk from its committed nonce.
    let mut chunk_cids = vec![None; num_chunks];
    for i in 0..num_chunks {
        let start = i * cs;
        let end = ((i + 1) * cs).min(data.len());
        let (_chunk_key, cid) = client
            .streaming_put_chunk(
                &bucket,
                &storage_key,
                &chunked_metadata,
                i as u32,
                &data[start..end],
                &dek,
            )
            .await
            .unwrap_or_else(|e| panic!("streaming_put_chunk[{i}] failed: {e}"));
        chunk_cids[i] = cid;
        if i % 50 == 0 {
            eprintln!("[streaming_e2e]   uploaded chunk {i}/{num_chunks}");
        }
    }

    eprintln!("[streaming_e2e] streaming_finish...");
    client
        .streaming_finish(
            &bucket,
            key_path,
            &storage_key,
            &wrapped_dek,
            &encrypted_meta,
            kek_version,
            &private_meta,
            chunked_metadata,
            chunk_cids,
        )
        .await
        .expect("streaming_finish");
    eprintln!("[streaming_e2e] upload OK");

    // ---- download + verify byte-exact (the gate) ----
    eprintln!("[streaming_e2e] downloading via get_object_flat...");
    let downloaded = client
        .get_object_flat(&bucket, key_path)
        .await
        .expect("get_object_flat");
    assert_eq!(downloaded.len(), data.len(), "round-trip length mismatch");
    assert_eq!(
        downloaded.as_ref(),
        data.as_slice(),
        "streaming upload -> download MUST be byte-exact on the real gateway"
    );
    eprintln!(
        "[streaming_e2e] OK: {} bytes ({} chunks) round-tripped byte-exact via streaming on the real gateway",
        data.len(),
        num_chunks
    );
}
