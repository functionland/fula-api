//! Phase 2 — GATED live e2e of the share-recipient WRITE path (Option 1).
//!
//! This is the live-gateway counterpart to the offline crypto proof in
//! `tests/p2_shared_scope_write.rs`. It exercises the recommended P2 mechanism
//! over the REAL wire format:
//!
//!   1. The "AI" (an `EncryptedClient` built from its OWN Mode-A secret) uploads
//!      a file into ITS OWN disposable bucket via `put_object_flat` — the same
//!      call P1 proved (HPKE DEK-wrap + storage-key obfuscation + chunked content
//!      encryption + forest-index write). The AI owns these bytes + this forest.
//!   2. The AI recovers the per-file DEK + obfuscated storage_key from its own
//!      forest/metadata (list_files_from_forest +
//!      get_object_encryption_metadata_with_fallback + unwrap with its own
//!      keypair) — exactly the lookup FxFiles does before sharing
//!      (`fula-client/tests/sharing_e2e.rs`).
//!   3. The AI mints a `ShareToken` wrapping THAT DEK to a SEPARATE "owner"
//!      keypair (the owner's public key is public; the AI never holds the owner's
//!      secret). path_scope carries the `ai/` scope; nonce + encryption_version
//!      are baked in.
//!   4. The OWNER recovers the DEK from the token (`accept_share`) and reads the
//!      file back byte-identically via `get_object_with_share`.
//!
//! Why the read uses the AI's own client: `get_object_with_share` resolves the
//! object by `storage_key`, bypassing the forest, but the underlying S3 GET is
//! still scoped by the caller's JWT to the caller's own buckets (see the
//! production note in `fula-client/tests/sharing_e2e.rs` lines ~431-445 — a
//! cross-account read must go through the `/api/share/v2/fetch` proxy). To keep
//! this test SELF-CONTAINED (no dependency on the production share proxy) we
//! isolate exactly the P2 question — "can a recipient-minted, OWNER-wrapped token
//! decrypt the AI-written bytes by storage_key over the live format?" — by
//! issuing the share-read from the AI's own client. The owner-side crypto
//! (accept_share -> DEK) is identical to a cross-account read; only the byte
//! fetch's JWT differs. The cross-account proxy hop is orthogonal infra, already
//! covered by `sharing_e2e.rs`.
//!
//! Double-gated so a plain `cargo test` stays green OFFLINE (mirrors P1's
//! `tests/e2e_roundtrip.rs`):
//!   1. `#[ignore]` — excluded from a normal run; needs `-- --ignored`.
//!   2. `FULA_E2E=1` — even under `--ignored`, the body is a no-op unless set.
//!
//! Credentials: the operator's local creds file (NOT committed), default
//! `C:\Users\ehsan\.claude\cache\e2e-credentials.env`, override via
//! `FULA_E2E_CREDS`. Dedicated test accounts, treated as production: writes only
//! under a unique disposable bucket and always cleans up.

use std::collections::HashMap;
use std::time::Duration;

use base64::Engine as _;
use fula_client::{Config, EncryptedClient, EncryptionConfig};
use fula_crypto::{
    Aead, DekKey, KekKeyPair, Nonce, PublicKey, SecretKey, ShareBuilder, ShareRecipient,
    hpke::{Decryptor, EncryptedData},
};
use fula_mcp::derive_mode_a_secret;
use rand::RngCore;

const DEFAULT_CREDS_PATH: &str = r"C:\Users\ehsan\.claude\cache\e2e-credentials.env";

/// Minimal `.env` parser (same shape as P1's e2e_roundtrip).
fn parse_env_file(contents: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for raw in contents.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim().to_string();
        let value = value.trim().trim_matches('"').trim_matches('\'').to_string();
        if !key.is_empty() {
            map.insert(key, value);
        }
    }
    map
}

fn cred<'a>(creds: &'a HashMap<String, String>, key: &str) -> Option<String> {
    creds
        .get(key)
        .cloned()
        .or_else(|| std::env::var(key).ok())
        .filter(|v| !v.is_empty())
}

#[tokio::test]
#[ignore = "hits a live Fula gateway; run with FULA_E2E=1 and `-- --ignored`"]
async fn e2e_ai_writes_shared_scope_owner_reads_back() {
    // ---- Gate 2: opt-in even under --ignored ------------------------------
    if std::env::var("FULA_E2E").as_deref() != Ok("1") {
        eprintln!("FULA_E2E != 1 — skipping live P2 shared-scope-write e2e (expected offline).");
        return;
    }

    // ---- Load credentials -------------------------------------------------
    let creds_path =
        std::env::var("FULA_E2E_CREDS").unwrap_or_else(|_| DEFAULT_CREDS_PATH.to_string());
    let contents = std::fs::read_to_string(&creds_path)
        .unwrap_or_else(|e| panic!("FULA_E2E=1 but could not read creds file {creds_path}: {e}"));
    let creds = parse_env_file(&contents);

    let endpoint = cred(&creds, "FULA_S3").expect("FULA_S3 endpoint required");
    let jwt = cred(&creds, "FULA_JWT").expect("FULA_JWT required");
    // The AI acts under the primary test account's storage credentials (it has a
    // JWT for storage auth) but holds only a derived per-file/folder DEK, never a
    // master key it didn't derive. For this isolated test the AI's encryption
    // identity is the primary account's Mode-A secret; the OWNER is a SEPARATE,
    // freshly-generated keypair to prove the wrap targets a distinct party.
    let provider = cred(&creds, "FULA_TEST_PROVIDER").expect("FULA_TEST_PROVIDER required");
    let oauth_sub = cred(&creds, "FULA_TEST_OAUTH_SUB").expect("FULA_TEST_OAUTH_SUB required");
    let email = cred(&creds, "FULA_TEST_EMAIL").expect("FULA_TEST_EMAIL required");
    let timeout_secs: u64 = cred(&creds, "FULA_TIMEOUT_SECS")
        .and_then(|s| s.parse().ok())
        .unwrap_or(60);

    // Disposable, uniquely-named bucket (clean v7 forest) unless the operator
    // pins one with FULA_TEST_BUCKET. Same isolation pattern as P1.
    let explicit_bucket = cred(&creds, "FULA_TEST_BUCKET");
    let bucket = explicit_bucket
        .clone()
        .unwrap_or_else(|| format!("p2-shared-write-{}", uuid::Uuid::new_v4()));
    let owns_bucket = explicit_bucket.is_none();

    // ---- AI's encrypted client (Mode A) -----------------------------------
    let ai_secret = derive_mode_a_secret(&provider, &oauth_sub, &email)
        .expect("AI Mode A secret derivation must succeed");
    let config = Config::new(endpoint.clone())
        .with_token(jwt)
        .with_encryption()
        .with_timeout(Duration::from_secs(timeout_secs));
    let encryption = EncryptionConfig::from_secret_key(ai_secret);
    let ai_client =
        EncryptedClient::new(config, encryption).expect("AI client construction must succeed");

    // ---- The OWNER: a SEPARATE keypair the AI only knows the PUBLIC half of -
    let mut owner_seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut owner_seed);
    let owner = KekKeyPair::from_secret_key(SecretKey::from_bytes(&owner_seed).unwrap());
    let owner_public: PublicKey = owner.public_key().clone();

    // ---- Unique file under the `ai/` shared scope -------------------------
    let logical_path = format!("ai/e2e/{}.bin", uuid::Uuid::new_v4());
    let mut payload = vec![0u8; 48 * 1024]; // 48 KiB unique blob
    rand::thread_rng().fill_bytes(&mut payload);

    let outcome: Result<(), String> = async {
        if owns_bucket {
            ai_client
                .create_bucket(&bucket)
                .await
                .map_err(|e| format!("create_bucket failed: {e}"))?;
        }

        // 1. AI writes the file into its OWN bucket/forest under `ai/...`.
        ai_client
            .put_object_flat(
                &bucket,
                &logical_path,
                payload.clone(),
                Some("application/octet-stream"),
            )
            .await
            .map_err(|e| format!("AI put_object_flat failed: {e}"))?;

        // 2. AI recovers storage_key from its own forest listing.
        let listed = ai_client
            .list_files_from_forest(&bucket)
            .await
            .map_err(|e| format!("AI list_files_from_forest failed: {e}"))?;
        let file_meta = listed
            .iter()
            .find(|f| f.original_key == logical_path)
            .ok_or_else(|| format!("AI forest listing missing just-written {logical_path}"))?;
        let storage_key = file_meta.storage_key.clone();

        // 2b. AI fetches the encryption metadata it just wrote, unwraps the
        //     per-file DEK with its OWN keypair (it owns this file), and pulls
        //     the nonce — exactly the lookup FxFiles does before sharing.
        let enc_meta_str = ai_client
            .get_object_encryption_metadata_with_fallback(&bucket, &storage_key)
            .await
            .map_err(|e| format!("AI get_object_encryption_metadata failed: {e}"))?;
        let enc_meta: serde_json::Value = serde_json::from_str(&enc_meta_str)
            .map_err(|e| format!("parse enc metadata: {e}"))?;
        let wrapped_key: EncryptedData =
            serde_json::from_value(enc_meta["wrapped_key"].clone())
                .map_err(|e| format!("parse wrapped_key: {e}"))?;
        let ai_keypair = ai_client.encryption_config().key_manager().keypair();
        let content_dek: DekKey = Decryptor::new(ai_keypair)
            .decrypt_dek(&wrapped_key)
            .map_err(|e| format!("AI unwrap own DEK: {e}"))?;
        let nonce_str = enc_meta["nonce"]
            .as_str()
            .ok_or_else(|| "enc metadata missing nonce".to_string())?
            .to_string();
        let enc_version = enc_meta["version"].as_u64().unwrap_or(4) as u8;

        // 3. AI mints a ShareToken wrapping the content DEK to the OWNER,
        //    scoped to the `ai/` path, with nonce + version baked in.
        let mut builder = ShareBuilder::new(ai_keypair, &owner_public, &content_dek)
            .path_scope(&storage_key) // FxFiles convention: path_scope = storage_key
            .read_write()
            .nonce(&nonce_str)
            .encryption_version(enc_version);
        if let Some(chunked) = enc_meta.get("chunked") {
            if !chunked.is_null() {
                let chunked_json = serde_json::to_string(chunked)
                    .map_err(|e| format!("serialize chunked meta: {e}"))?;
                builder = builder.chunked_metadata(chunked_json);
            }
        }
        let token = builder.build().map_err(|e| format!("AI mint token: {e}"))?;

        // Transmit (serialize/deserialize as it would cross to the owner).
        let token_json = serde_json::to_string(&token).map_err(|e| e.to_string())?;
        let received: fula_crypto::ShareToken =
            serde_json::from_str(&token_json).map_err(|e| e.to_string())?;

        // 4. OWNER recovers the DEK from the token and reads the bytes back.
        //    accept_share is the owner's own keypair; the byte fetch uses the
        //    AI's client (same JWT scope as the bucket) — see module docs.
        let accepted = ShareRecipient::new(&owner)
            .accept_share(&received)
            .map_err(|e| format!("owner accept_share: {e}"))?;
        if !accepted.is_path_allowed(&storage_key) {
            return Err("owner: file outside declared share scope".to_string());
        }

        let downloaded = ai_client
            .get_object_with_share(&bucket, &storage_key, &storage_key, &accepted)
            .await
            .map_err(|e| format!("owner get_object_with_share: {e}"))?;
        if downloaded.as_ref() != payload.as_slice() {
            return Err(format!(
                "round-trip mismatch: wrote {} bytes, owner read {} bytes",
                payload.len(),
                downloaded.len()
            ));
        }

        // Independent cross-check: decrypt raw bytes with the owner-recovered
        // DEK directly (v4 AAD), proving the DEK — not some ambient client
        // state — is what unlocks the content.
        let raw = ai_client
            .inner()
            .get_object(&bucket, &storage_key)
            .await
            .map_err(|e| format!("fetch raw ciphertext: {e}"))?;
        let nonce_bytes = base64::engine::general_purpose::STANDARD
            .decode(&nonce_str)
            .map_err(|e| format!("decode nonce: {e}"))?;
        let nonce = Nonce::from_bytes(&nonce_bytes).map_err(|e| format!("nonce: {e}"))?;
        let aad = format!("fula:v4:content:{storage_key}").into_bytes();
        let decrypted = Aead::new_default(&accepted.dek)
            .decrypt_with_aad(&nonce, &raw, &aad)
            .map_err(|e| format!("owner direct-DEK decrypt: {e}"))?;
        if decrypted != payload {
            return Err("owner direct-DEK decrypt mismatch".to_string());
        }

        Ok(())
    }
    .await;

    // ---- Cleanup that ALWAYS runs -----------------------------------------
    if let Err(e) = ai_client.delete_object_flat(&bucket, &logical_path).await {
        eprintln!("WARNING: cleanup delete of {bucket}/{logical_path} failed: {e}");
    }
    if owns_bucket {
        match ai_client.delete_bucket(&bucket).await {
            Ok(()) => eprintln!("cleanup: deleted disposable bucket {bucket}"),
            Err(e) => eprintln!(
                "note: disposable bucket {bucket} left behind (forest-index objects remain; \
                 expected — no encrypted-client API drains them): {e}"
            ),
        }
    }

    outcome.unwrap_or_else(|e| panic!("P2 shared-scope-write e2e failed for {bucket}: {e}"));
    eprintln!("P2 shared-scope-write e2e OK: AI wrote {bucket}, owner read it back byte-identical");
}
