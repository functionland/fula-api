//! E2E (real server): SHARE + COLLABORATE token creation must work for a LARGE
//! chunked file after the 0.6.13 header-stripping fix.
//!
//! Bug context: `header_safe_enc_metadata` strips the per-chunk arrays
//! (`chunk_nonces` / `chunk_cids`) from the `x-fula-encryption` HTTP header for
//! large (chunked) files so the index PUT fits the gateway's
//! `large_client_header_buffers`. Share/collab tokens are built by
//! `get_object_encryption_metadata_with_fallback` -> `ShareBuilder.chunked_metadata`
//! (fula-flutter `create_share_token`; FxFiles `collaboration_service.dart` uses
//! the SAME call), and the recipient CANNOT decrypt unless the token carries the
//! FULL `chunk_nonces`. This test proves fix #1 recovers them from the forest /
//! index body even though the stored HTTP header is stripped.
//!
//! Assertions:
//!   1. NON-VACUOUS: the stored HEAD `x-fula-encryption` header IS stripped (has
//!      a `chunked` block but NO `chunk_nonces`). Confirms the file crosses the
//!      16 KB header budget and the strip actually happened — without this the
//!      rest of the test could pass on a small file that was never stripped.
//!   2. FIX #1: `get_object_encryption_metadata_with_fallback` returns COMPLETE
//!      metadata (non-empty `chunked.chunk_nonces`).
//!   3. SHARE/COLLAB: the built share token's `chunked_metadata` carries
//!      non-empty `chunk_nonces`.
//!   4. END-TO-END: a recipient (share-to-self; same account/JWT, no proxy)
//!      decrypts via `get_object_with_share` to the EXACT uploaded bytes.
//!
//! `#[ignore]` — needs network + real credentials. Run (PowerShell, env from
//! e2e-credentials.env):
//!   cargo test -p fula-client --test large_chunked_share_e2e --release -- --ignored --nocapture
//!
//! Required env: FULA_S3, FULA_JWT, FULA_TEST_PROVIDER, FULA_TEST_OAUTH_SUB,
//! FULA_TEST_EMAIL (the Mode A derivation triple).

#![cfg(not(target_arch = "wasm32"))]

use bytes::Bytes;
use fula_client::{Config, EncryptedClient, EncryptionConfig, FulaClient};
use fula_crypto::{
    hpke::{Decryptor, EncryptedData},
    keys::{PublicKey, SecretKey},
    sharing::{ShareBuilder, ShareToken},
};

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("missing required env {name}"))
}

/// True iff `v["chunked"]["chunk_nonces"]` is a present, non-empty array.
fn chunked_block_has_nonces(v: &serde_json::Value) -> bool {
    v.get("chunked")
        .and_then(|c| c.get("chunk_nonces"))
        .and_then(|n| n.as_array())
        .map(|a| !a.is_empty())
        .unwrap_or(false)
}

/// True iff `v["chunk_nonces"]` is a present, non-empty array (the share
/// token's `chunked_metadata` IS the `chunked` block, so nonces are top-level).
fn top_level_has_nonces(v: &serde_json::Value) -> bool {
    v.get("chunk_nonces")
        .and_then(|n| n.as_array())
        .map(|a| !a.is_empty())
        .unwrap_or(false)
}

#[tokio::test]
#[ignore = "real-server; needs FULA_S3 + FULA_JWT + Mode A triple"]
async fn large_chunked_share_token_carries_chunk_nonces() {
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
    // Match FxFiles production: stamps chunk_cids into the index metadata, which
    // (with ~480 chunks) pushes it well past the gateway header budget.
    config.walkable_v8_writer_enabled = true;
    let client = EncryptedClient::new(config, EncryptionConfig::from_secret_key(secret))
        .expect("EncryptedClient::new");

    let epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let bucket = format!("e2e-share-bigchunk-{epoch}-v8");
    eprintln!("[share_e2e] BUCKET={bucket}");
    if let Err(e) = client.create_bucket(&bucket).await {
        eprintln!("[share_e2e] create_bucket({bucket}) -> {e} (continuing)");
    }

    // ~120 MB -> ~480 chunks at 256 KB -> ~70 KB index metadata, well over the
    // 16 KB header budget, so `header_safe_enc_metadata` MUST strip the header.
    let size = 120 * 1024 * 1024;
    let mut data = vec![0u8; size];
    for (i, b) in data.iter_mut().enumerate() {
        *b = (i % 251) as u8;
    }
    let key_path = "/big-share.bin";

    eprintln!(
        "[share_e2e] uploading {} bytes (~{} chunks)...",
        size,
        size / (256 * 1024)
    );
    client
        .put_object_flat(
            &bucket,
            key_path,
            Bytes::from(data.clone()),
            Some("application/octet-stream"),
        )
        .await
        .expect("upload large chunked file");
    eprintln!("[share_e2e] upload OK");

    // storage_key (HMAC-derived) for the file — same lookup FxFiles uses.
    let listed = client
        .list_files_from_forest(&bucket)
        .await
        .expect("list_files_from_forest");
    let file_meta = listed
        .iter()
        .find(|f| f.original_key == key_path)
        .unwrap_or_else(|| panic!("listing must include {key_path}"));
    let storage_key = file_meta.storage_key.clone();
    eprintln!("[share_e2e] storage_key={storage_key}");

    // ── Assertion 1 (NON-VACUOUS): the stored HTTP header IS stripped. ──
    // Read the raw S3 user-metadata header via a plain (non-encrypted) client.
    let raw = FulaClient::new(Config::new(&s3).with_token(&jwt)).expect("plain FulaClient::new");
    let head = raw.head_object(&bucket, &storage_key).await.expect("head_object");
    let header_str = head
        .metadata
        .get("x-fula-encryption")
        .expect("encrypted object must carry an x-fula-encryption header");
    let header_json: serde_json::Value =
        serde_json::from_str(header_str).expect("parse header JSON");
    assert!(
        header_json.get("chunked").is_some(),
        "test file must be chunked; header={header_str}"
    );
    assert!(
        !chunked_block_has_nonces(&header_json),
        "VACUOUS TEST GUARD: the stored header still carries chunk_nonces — the \
         metadata did not exceed the 16 KB budget, so header-stripping was never \
         exercised. chunked block: {:?}",
        header_json.get("chunked")
    );
    eprintln!("[share_e2e] OK #1: stored header is STRIPPED (chunked block present, no chunk_nonces)");

    // ── Assertion 2 (FIX #1): with_fallback recovers the FULL metadata. ──
    let full_str = client
        .get_object_encryption_metadata_with_fallback(&bucket, &storage_key)
        .await
        .expect("get_object_encryption_metadata_with_fallback");
    let full_json: serde_json::Value =
        serde_json::from_str(&full_str).expect("parse full metadata JSON");
    assert!(
        chunked_block_has_nonces(&full_json),
        "FIX #1: with_fallback MUST return metadata WITH chunk_nonces (recovered \
         from forest / index body), got: chunked={:?}",
        full_json.get("chunked")
    );
    eprintln!("[share_e2e] OK #2: with_fallback recovered chunk_nonces despite stripped header");

    // ── Assertion 3 (SHARE/COLLAB): the built token carries chunk_nonces. ──
    // Mirrors fula-flutter::create_share_token (collab uses the same call).
    let wrapped_key: EncryptedData =
        serde_json::from_value(full_json["wrapped_key"].clone()).expect("parse wrapped_key");
    let owner_keypair = client.encryption_config().key_manager().keypair();
    let dek = Decryptor::new(owner_keypair)
        .decrypt_dek(&wrapped_key)
        .expect("owner unwraps own DEK");

    // Share to self (same account/JWT) so the recipient read needs no proxy.
    let recipient_pk = SecretKey::from_bytes(&kek)
        .expect("recipient secret")
        .public_key();
    let mut builder = ShareBuilder::new(owner_keypair, &recipient_pk, &dek)
        .path_scope(&storage_key)
        .read_only();
    if let Some(nonce) = full_json["nonce"].as_str() {
        builder = builder.nonce(nonce);
    }
    if let Some(v) = full_json["version"].as_u64() {
        builder = builder.encryption_version(v as u8);
    }
    let chunked_json =
        serde_json::to_string(&full_json["chunked"]).expect("serialize chunked metadata");
    builder = builder.chunked_metadata(chunked_json);
    let token = builder.build().expect("ShareBuilder.build");
    let token_json = serde_json::to_string(&token).expect("serialize ShareToken");

    // Parse the token JSON as a generic value (robust to field visibility) and
    // verify its embedded chunked_metadata carries non-empty chunk_nonces.
    let token_value: serde_json::Value =
        serde_json::from_str(&token_json).expect("parse token JSON");
    let token_chunked_str = token_value["chunked_metadata"]
        .as_str()
        .expect("token must carry a chunked_metadata string");
    let token_chunked_json: serde_json::Value =
        serde_json::from_str(token_chunked_str).expect("parse token chunked_metadata");
    assert!(
        top_level_has_nonces(&token_chunked_json),
        "SHARE/COLLAB: token chunked_metadata MUST carry non-empty chunk_nonces; got {:?}",
        token_chunked_json
    );
    eprintln!("[share_e2e] OK #3: share/collab token carries chunk_nonces");

    // ── Assertion 4 (END-TO-END): recipient decrypts to the exact bytes. ──
    let parsed: ShareToken = serde_json::from_str(&token_json).expect("recipient parses token");
    let accepted = client.accept_share(&parsed).expect("accept_share (share-to-self)");
    let downloaded = client
        .get_object_with_share(&bucket, &storage_key, &storage_key, &accepted)
        .await
        .expect("recipient get_object_with_share");
    assert_eq!(
        downloaded.len(),
        data.len(),
        "decrypted length must equal the uploaded length"
    );
    assert!(
        downloaded[..] == data[..],
        "recipient must decrypt to the EXACT bytes the owner uploaded"
    );
    eprintln!(
        "[share_e2e] OK #4: recipient decrypted {} bytes — exact match",
        downloaded.len()
    );

    // Cleanup (best-effort).
    let _ = client.delete_object_flat(&bucket, key_path).await;
    let _ = client.delete_bucket(&bucket).await;
    eprintln!("[share_e2e] PASS");
}
