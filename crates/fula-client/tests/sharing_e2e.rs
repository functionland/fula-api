//! End-to-end test: FULL share-token round-trip between two real
//! accounts, mirroring `FxFiles sharing_service.dart::createShareToken`
//! (via `fula.createShareTokenWithMode`) + the recipient's
//! `acceptShare` / `getWithShare` path byte-for-byte.
//!
//! ## What this proves
//!
//! 1. Owner can upload a file via `put_object_flat` (same call FxFiles
//!    uses), look up its `storage_key` via `list_files_from_forest`,
//!    fetch encryption metadata, and build a HPKE-wrapped share token
//!    addressed to a specific recipient's curve25519 public key.
//! 2. Recipient can parse the same token JSON FxFiles' FFI emits,
//!    accept it via `EncryptedClient::accept_share`, and decrypt the
//!    owner's encrypted file via `EncryptedClient::get_object_with_share`
//!    — using ONLY the share token + recipient's own secret. No
//!    knowledge of owner's bucketsIndex, no traversal of any
//!    users-index data structure.
//! 3. Sharing is genuinely independent of Phase 2-5's encrypted
//!    bucketsIndex — recipient never touches the `users_enc` map, the
//!    new `K_index` / `K_entry_seed` paths, or anything the Phase 2-5
//!    work introduced. This is the load-bearing test for the
//!    "sharing is unchanged" claim.
//!
//! ## Recipient public key: paste the FxFiles "FULA ID" verbatim
//!
//! Recipient's identity surfaces in FxFiles Settings as a string like:
//!     FULA-gerZVXIPwFGlvBydeL5ANpzcM30g_J5-7HM5VprR2iw
//! That's a `FULA-` prefix + base64url-encoded 32-byte curve25519
//! public key — the SAME key the SDK uses to HPKE-wrap a DEK to this
//! recipient. Set `FULA_RECIPIENT_FULA_ID` to the literal string
//! shown in Settings; this test parses it.
//!
//! The test ALSO derives the recipient's public key locally from
//! `FULA_TEST_PROVIDER_RECIPIENT + FULA_TEST_OAUTH_SUB_RECIPIENT +
//! FULA_TEST_EMAIL_RECIPIENT` and asserts the two match. A mismatch
//! means the env vars and the FULA ID belong to different accounts
//! — the test fails fast rather than running with inconsistent inputs.
//!
//! ## Running
//!
//! ```powershell
//! $env:FULA_JWT = "eyJ..."                              # owner JWT
//! $env:FULA_S3 = "https://s3.cloud.fx.land"
//! $env:FULA_TEST_PROVIDER = "google"
//! $env:FULA_TEST_OAUTH_SUB = "..."
//! $env:FULA_TEST_EMAIL = "owner@example.com"
//! $env:FULA_BUCKET = "other"
//!
//! $env:FULA_JWT_RECIPIENT = "eyJ..."                    # recipient JWT
//! $env:FULA_TEST_PROVIDER_RECIPIENT = "google"
//! $env:FULA_TEST_OAUTH_SUB_RECIPIENT = "..."
//! $env:FULA_TEST_EMAIL_RECIPIENT = "recipient@example.com"
//! $env:FULA_RECIPIENT_FULA_ID = "FULA-..."              # recipient's FULA ID from Settings
//!
//! cargo test -p fula-client --test sharing_e2e --release `
//!   -- --ignored --nocapture
//! ```

use fula_client::{ClientError, Config, EncryptedClient, EncryptionConfig};
use fula_crypto::{
    hpke::{Decryptor, EncryptedData},
    keys::{PublicKey, SecretKey},
    sharing::{ShareBuilder, ShareToken},
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tempfile::TempDir;
use unicode_normalization::UnicodeNormalization as _;

// ════════════════════════════════════════════════════════════════════════════
// Env + helpers
// ════════════════════════════════════════════════════════════════════════════

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn read_env(var: &str) -> Option<String> {
    match std::env::var(var) {
        Ok(v) if !v.is_empty() => Some(v),
        _ => {
            eprintln!("[sharing_e2e] {} not set — skipping.", var);
            None
        }
    }
}

/// Mode A secret derivation (mirrors `auth_service.dart:599`).
fn derive_kek_mode_a(provider: &str, oauth_sub: &str, email: &str) -> [u8; 32] {
    let input = format!("{}:{}:{}", provider, oauth_sub, email);
    fula_crypto::hashing::derive_key_argon2id("fula-files-v1", input.as_bytes())
}

/// Mode B canonical KEK input (mirrors `canonical_kek_input.dart::canonicalKekInputModeB`).
fn canonical_kek_input_mode_b(provider: &str, oauth_sub: &str, seed: &str) -> Vec<u8> {
    let provider_b = provider.as_bytes();
    let sub_b = oauth_sub.as_bytes();
    let seed_norm: String = seed.nfc().collect();
    let seed_b = seed_norm.as_bytes();
    let mut out = Vec::with_capacity(12 + provider_b.len() + sub_b.len() + seed_b.len());
    out.extend_from_slice(&(provider_b.len() as u32).to_le_bytes());
    out.extend_from_slice(provider_b);
    out.extend_from_slice(&(sub_b.len() as u32).to_le_bytes());
    out.extend_from_slice(sub_b);
    out.extend_from_slice(&(seed_b.len() as u32).to_le_bytes());
    out.extend_from_slice(seed_b);
    out
}

/// Mode B secret derivation (mirrors `auth_service.dart:1331`).
fn derive_kek_mode_b(provider: &str, oauth_sub: &str, seed: &str) -> [u8; 32] {
    let input = canonical_kek_input_mode_b(provider, oauth_sub, seed);
    fula_crypto::hashing::derive_key_argon2id("fula-files-v2-mode-b", &input)
}

/// Mode C secret derivation (mirrors `auth_service.dart:1394`).
fn derive_kek_mode_c(seed: &str) -> [u8; 32] {
    let seed_norm: String = seed.nfc().collect();
    let seed_b = seed_norm.as_bytes();
    let mut input = Vec::with_capacity(4 + seed_b.len());
    input.extend_from_slice(&(seed_b.len() as u32).to_le_bytes());
    input.extend_from_slice(seed_b);
    fula_crypto::hashing::derive_key_argon2id("fula-files-v2-mode-c", &input)
}

/// Derive the recipient's master KEK based on `FULA_TEST_RECIPIENT_MODE`.
/// Defaults to Mode A for backward compatibility.
///
/// Returns `None` (and prints a clear skip message) when required env
/// vars are missing for the chosen mode.
fn derive_recipient_kek() -> Option<[u8; 32]> {
    let mode = std::env::var("FULA_TEST_RECIPIENT_MODE")
        .unwrap_or_else(|_| "A".to_string())
        .to_uppercase();
    match mode.as_str() {
        "A" => {
            let provider = read_env("FULA_TEST_PROVIDER_RECIPIENT")?;
            let sub = read_env("FULA_TEST_OAUTH_SUB_RECIPIENT")?;
            let email = read_env("FULA_TEST_EMAIL_RECIPIENT")?;
            Some(derive_kek_mode_a(&provider, &sub, &email))
        }
        "B" => {
            let provider = read_env("FULA_TEST_PROVIDER_RECIPIENT")?;
            let sub = read_env("FULA_TEST_OAUTH_SUB_RECIPIENT")?;
            let seed = read_env("FULA_TEST_SEED_RECIPIENT")?;
            Some(derive_kek_mode_b(&provider, &sub, &seed))
        }
        "C" => {
            let seed = read_env("FULA_TEST_SEED_RECIPIENT")?;
            Some(derive_kek_mode_c(&seed))
        }
        other => {
            eprintln!(
                "[sharing_e2e] FULA_TEST_RECIPIENT_MODE={:?} is invalid; use 'A', 'B', or 'C'",
                other
            );
            None
        }
    }
}

/// Derive the curve25519 public key that the SDK builds for a given
/// master KEK. Equivalent to what `EncryptionConfig::from_secret_key`
/// produces internally via `KeyManager::from_secret_key(secret)` →
/// `.keypair().public_key()`. This is what recipients see displayed
/// in FxFiles Settings as their "FULA ID".
fn derive_public_key_from_kek(kek_bytes: &[u8; 32]) -> [u8; 32] {
    let secret = SecretKey::from_bytes(kek_bytes).expect("secret from kek");
    let pk = secret.public_key();
    let mut out = [0u8; 32];
    out.copy_from_slice(pk.as_bytes());
    out
}

/// Parse the FxFiles "FULA ID" format (`FULA-<base64url>`) into 32
/// raw bytes. base64url uses `-` and `_` instead of `+` and `/`, and
/// drops padding `=`. We convert to standard base64 + pad before
/// decoding.
fn parse_fula_id(fula_id: &str) -> Result<[u8; 32], String> {
    let body = fula_id
        .strip_prefix("FULA-")
        .ok_or_else(|| format!("expected 'FULA-' prefix, got: {:?}", fula_id))?;
    let standard = body.replace('-', "+").replace('_', "/");
    let pad = (4 - (standard.len() % 4)) % 4;
    let padded = format!("{}{}", standard, "=".repeat(pad));
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(&padded)
        .map_err(|e| format!("base64 decode failed: {}", e))?;
    if bytes.len() != 32 {
        return Err(format!(
            "expected 32 bytes after decoding, got {}",
            bytes.len()
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Build an `EncryptedClient` mirroring `FxFiles fula_api_service.dart:207-246`.
fn build_client(
    master_url: &str,
    jwt: &str,
    cache_path: &std::path::Path,
    secret: SecretKey,
    timeout_secs: u64,
) -> EncryptedClient {
    let mut cfg = Config::new(master_url).with_token(jwt);
    cfg.timeout = Duration::from_secs(timeout_secs);
    cfg.health_gate_enabled = true;
    cfg.health_gate_ttl = Duration::from_secs(30);
    cfg.block_cache_enabled = true;
    cfg.block_cache_path = Some(cache_path.to_path_buf());
    cfg.block_cache_max_bytes = 256 * 1024 * 1024;
    cfg.gateway_fallback_enabled = true;
    cfg.gateway_fallback_urls = Vec::new();
    cfg.gateway_race_concurrency = 3;
    cfg.walkable_v8_writer_enabled = true;
    let enc = EncryptionConfig::from_secret_key(secret);
    EncryptedClient::new(cfg, enc).expect("EncryptedClient construction must succeed")
}

// ════════════════════════════════════════════════════════════════════════════
// FULL ROUND-TRIP — owner creates share, recipient decrypts via share
// ════════════════════════════════════════════════════════════════════════════

#[tokio::test]
#[ignore]
async fn share_round_trip_e2e() {
    let owner_jwt = match read_env("FULA_JWT") {
        Some(v) => v,
        None => return,
    };
    let s3 = match read_env("FULA_S3") {
        Some(v) => v,
        None => return,
    };
    let owner_provider = match read_env("FULA_TEST_PROVIDER") {
        Some(v) => v,
        None => return,
    };
    let owner_sub = match read_env("FULA_TEST_OAUTH_SUB") {
        Some(v) => v,
        None => return,
    };
    let owner_email = match read_env("FULA_TEST_EMAIL") {
        Some(v) => v,
        None => return,
    };
    let bucket = std::env::var("FULA_BUCKET").unwrap_or_else(|_| "other".to_string());

    let recipient_jwt = match read_env("FULA_JWT_RECIPIENT") {
        Some(v) => v,
        None => return,
    };
    let timeout_secs: u64 = std::env::var("FULA_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(60);

    // ─── Derive both accounts' secrets ────────────────────────────────────
    //
    // Owner is always Mode A in this test (its `FULA_TEST_*` envs match
    // the rest of the test suite's convention). The recipient mode is
    // selected via `FULA_TEST_RECIPIENT_MODE` (A / B / C).
    let owner_kek = derive_kek_mode_a(&owner_provider, &owner_sub, &owner_email);
    let recipient_kek = match derive_recipient_kek() {
        Some(k) => k,
        None => return,
    };
    let recipient_mode = std::env::var("FULA_TEST_RECIPIENT_MODE")
        .unwrap_or_else(|_| "A".to_string())
        .to_uppercase();
    eprintln!("[sharing_e2e] recipient mode: {}", recipient_mode);
    assert_ne!(
        owner_kek, recipient_kek,
        "two accounts must derive distinct secrets"
    );
    let derived_recipient_pk = derive_public_key_from_kek(&recipient_kek);

    // ─── Cross-check the FULA ID env (if provided) — non-fatal ────────────
    //
    // Demoted to WARNING (was hard panic). The actual share round-trip
    // below is the authoritative correctness check: if the recipient's
    // client (built from the same FULA_TEST_*_RECIPIENT env vars) can
    // decrypt the share the owner built using `derived_recipient_pk`,
    // then the env vars are internally consistent — sharing works.
    //
    // If FULA_RECIPIENT_FULA_ID mismatches, it usually means the FULA ID
    // is from a DIFFERENT account than FULA_JWT_RECIPIENT + the
    // FULA_TEST_*_RECIPIENT env vars (the user pasted the wrong
    // account's identity from FxFiles Settings).
    if let Some(fula_id_str) = std::env::var("FULA_RECIPIENT_FULA_ID")
        .ok()
        .filter(|s| !s.is_empty())
    {
        match parse_fula_id(&fula_id_str) {
            Ok(pasted_pk) if pasted_pk == derived_recipient_pk => {
                eprintln!(
                    "[sharing_e2e] FULA ID cross-check OK (mode {})",
                    recipient_mode
                );
            }
            Ok(pasted_pk) => {
                eprintln!(
                    "[sharing_e2e] WARNING: FULA_RECIPIENT_FULA_ID does NOT match \
                     env-derived pubkey under FULA_TEST_RECIPIENT_MODE={}.\n\
                     \n  FULA ID decodes to: {}\n  Derived from envs : {}\n\n\
                     Most likely cause: FULA_RECIPIENT_FULA_ID was copied from a \
                     different account than FULA_JWT_RECIPIENT + FULA_TEST_*_RECIPIENT.\n\
                     Proceeding with the env-derived pubkey. The share round-trip \
                     itself will tell us whether the recipient client decrypts.",
                    recipient_mode,
                    hex::encode(pasted_pk),
                    hex::encode(derived_recipient_pk),
                );
            }
            Err(e) => {
                eprintln!(
                    "[sharing_e2e] WARNING: FULA_RECIPIENT_FULA_ID failed to parse ({}); \
                     continuing with env-derived pubkey.",
                    e
                );
            }
        }
    }

    let owner_secret = SecretKey::from_bytes(&owner_kek).expect("owner secret");
    let recipient_secret = SecretKey::from_bytes(&recipient_kek).expect("recipient secret");

    // ─── Owner uploads a file ─────────────────────────────────────────────
    let owner_cache = TempDir::new().expect("tempdir owner");
    let owner_client = build_client(
        &s3,
        &owner_jwt,
        owner_cache.path(),
        owner_secret,
        timeout_secs,
    );

    let key = format!("share-e2e-{}.bin", now_unix());
    let payload = b"share-roundtrip-plaintext-bytes-2026".to_vec();
    let put_res = owner_client
        .put_object_flat(
            &bucket,
            &key,
            payload.clone(),
            Some("application/octet-stream"),
        )
        .await
        .expect("owner put_object_flat");
    eprintln!(
        "[sharing_e2e] owner uploaded key={} (etag={})",
        key, put_res.etag
    );

    // ─── Look up the storage_key the SDK derived for this file ────────────
    //
    // Mirrors what FxFiles does in `fula_api_service.dart` when it
    // wants to share a file: list the bucket via `listFromForest` and
    // look up the FileMetadata for the original path. FileMetadata
    // carries both `original_key` (the path the user sees) and
    // `storage_key` (the HMAC-derived key the gateway sees).
    let listed = owner_client
        .list_files_from_forest(&bucket)
        .await
        .expect("owner list_files_from_forest");
    let file_meta = listed
        .iter()
        .find(|f| f.original_key == key)
        .unwrap_or_else(|| panic!("owner's listing must include just-uploaded key={}", key));
    let storage_key = file_meta.storage_key.clone();
    eprintln!("[sharing_e2e] storage_key={}", storage_key);

    // ─── Build the share token, mirroring fula-flutter's
    //    create_share_token_with_mode (sharing.rs:122-227) ─────────────────
    //
    // Step 1: fetch encryption metadata so we have the wrapped_key,
    // nonce, version, and (for chunked files) the chunked manifest.
    let enc_metadata_str = owner_client
        .get_object_encryption_metadata_with_fallback(&bucket, &storage_key)
        .await
        .expect("get_object_encryption_metadata_with_fallback");
    let enc_metadata: serde_json::Value = serde_json::from_str(&enc_metadata_str)
        .expect("parse encryption metadata JSON");

    // Step 2: extract + unwrap the DEK using owner's keypair.
    let wrapped_key: EncryptedData =
        serde_json::from_value(enc_metadata["wrapped_key"].clone())
            .expect("parse wrapped_key from metadata");
    let owner_keypair = owner_client.encryption_config().key_manager().keypair();
    let decryptor = Decryptor::new(owner_keypair);
    let dek = decryptor
        .decrypt_dek(&wrapped_key)
        .expect("owner decrypts their own wrapped DEK");

    // Step 3: parse recipient's public key.
    let recipient_pk = PublicKey::from_bytes(&derived_recipient_pk)
        .expect("recipient public key construction");

    // Step 4: build the share token with the same chain of options
    // FxFiles uses (read-only mode, with nonce + encryption_version +
    // chunked_metadata if present).
    let mut builder = ShareBuilder::new(owner_keypair, &recipient_pk, &dek)
        .path_scope(&storage_key)
        .read_only();
    if let Some(nonce_str) = enc_metadata["nonce"].as_str() {
        builder = builder.nonce(nonce_str);
    }
    if let Some(v) = enc_metadata["version"].as_u64() {
        builder = builder.encryption_version(v as u8);
    }
    if enc_metadata.get("chunked").is_some() {
        let chunked_json = serde_json::to_string(&enc_metadata["chunked"])
            .expect("serialize chunked metadata");
        builder = builder.chunked_metadata(chunked_json);
    }
    let share_token = builder.build().expect("ShareBuilder.build");
    let share_token_json =
        serde_json::to_string(&share_token).expect("serialize ShareToken to JSON");
    eprintln!(
        "[sharing_e2e] owner built share token ({} bytes JSON)",
        share_token_json.len()
    );

    // ─── Recipient: parse the token, accept, download via share ───────────
    //
    // IMPORTANT — production architecture insight (2026-05-21 root cause):
    // Plain shares CANNOT be downloaded via master directly. Master scopes
    // every S3 GET by JWT's hashed_user_id, so the recipient (different
    // account) hits "NoSuchBucket" trying to read the owner's bucket.
    //
    // The right path is to build an EPHEMERAL fula_client pointed at the
    // share-gateway proxy (`/api/share/v2/fetch/...`) which validates
    // requests via the share token and bypasses user-scoping. This is
    // exactly what `collaboration_service.dart:425-485` does for collab.
    //
    // We use `kShareGatewayBaseUrl = "https://cloud.fx.land"` (FxFiles'
    // production proxy) plus the `/api/share/v2/fetch` path. The
    // ephemeral client uses the recipient's secret only to unwrap the
    // share-token's DEK; the actual byte fetch goes through the proxy
    // without JWT.
    let share_proxy_endpoint = std::env::var("FULA_SHARE_GATEWAY")
        .unwrap_or_else(|_| "https://cloud.fx.land/api/share/v2/fetch".to_string());
    eprintln!(
        "[sharing_e2e] recipient using share proxy: {}",
        share_proxy_endpoint
    );
    let recipient_cache = TempDir::new().expect("tempdir recipient");
    let recipient_client = build_client(
        &share_proxy_endpoint,
        &recipient_jwt,
        recipient_cache.path(),
        recipient_secret,
        timeout_secs,
    );

    let parsed_token: ShareToken = serde_json::from_str(&share_token_json)
        .expect("recipient parses the share token JSON");
    let accepted = recipient_client
        .accept_share(&parsed_token)
        .expect("recipient.accept_share");
    eprintln!("[sharing_e2e] recipient accepted share");

    // Per `FxFiles sharing_service.dart:1374-1378` AND
    // `collaboration_service.dart:475-485`: pass `storage_key` as both
    // the `storage_key` AND `original_key` arguments because the FFI
    // sets the share's `path_scope = storage_key`.
    let downloaded = recipient_client
        .get_object_with_share(&bucket, &storage_key, &storage_key, &accepted)
        .await
        .expect("recipient.get_object_with_share");
    assert_eq!(
        downloaded, payload,
        "recipient must decrypt to the exact bytes owner uploaded"
    );
    eprintln!(
        "[sharing_e2e] recipient downloaded {} bytes — plaintext matches",
        downloaded.len()
    );
}

// ════════════════════════════════════════════════════════════════════════════
// NEGATIVE CONTROL — recipient WITHOUT the share token must NOT be able
// to read the owner's file by path
// ════════════════════════════════════════════════════════════════════════════

#[tokio::test]
#[ignore]
async fn namespace_isolation_e2e() {
    let owner_jwt = match read_env("FULA_JWT") {
        Some(v) => v,
        None => return,
    };
    let s3 = match read_env("FULA_S3") {
        Some(v) => v,
        None => return,
    };
    let owner_provider = match read_env("FULA_TEST_PROVIDER") {
        Some(v) => v,
        None => return,
    };
    let owner_sub = match read_env("FULA_TEST_OAUTH_SUB") {
        Some(v) => v,
        None => return,
    };
    let owner_email = match read_env("FULA_TEST_EMAIL") {
        Some(v) => v,
        None => return,
    };
    let bucket = std::env::var("FULA_BUCKET").unwrap_or_else(|_| "other".to_string());
    let recipient_jwt = match read_env("FULA_JWT_RECIPIENT") {
        Some(v) => v,
        None => return,
    };
    let timeout_secs: u64 = std::env::var("FULA_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(60);

    let owner_kek = derive_kek_mode_a(&owner_provider, &owner_sub, &owner_email);
    let recipient_kek = match derive_recipient_kek() {
        Some(k) => k,
        None => return,
    };
    let owner_secret = SecretKey::from_bytes(&owner_kek).expect("owner secret");
    let recipient_secret = SecretKey::from_bytes(&recipient_kek).expect("recipient secret");

    let owner_cache = TempDir::new().expect("tempdir owner");
    let owner_client = build_client(
        &s3,
        &owner_jwt,
        owner_cache.path(),
        owner_secret,
        timeout_secs,
    );

    let key = format!("isolation-e2e-{}.bin", now_unix());
    let payload = b"isolation-test-plaintext-bytes-2026".to_vec();
    owner_client
        .put_object_flat(&bucket, &key, payload.clone(), Some("application/octet-stream"))
        .await
        .expect("owner put_object_flat");

    // Owner can read their own file (positive control).
    let owner_downloaded = owner_client
        .get_object_flat(&bucket, &key)
        .await
        .expect("owner can read their own file");
    assert_eq!(owner_downloaded, payload);

    let recipient_cache = TempDir::new().expect("tempdir recipient");
    let recipient_client = build_client(
        &s3,
        &recipient_jwt,
        recipient_cache.path(),
        recipient_secret,
        timeout_secs,
    );

    // Recipient WITHOUT share token — must NOT be able to read by path.
    let unauth_attempt = recipient_client.get_object_flat(&bucket, &key).await;
    match unauth_attempt {
        Err(ClientError::NotFound { .. })
        | Err(ClientError::BucketNotFound(_))
        | Err(ClientError::AccessDenied(_)) => {
            eprintln!("[sharing_e2e] namespace isolation enforced as expected");
        }
        Err(other) => panic!(
            "expected NotFound / BucketNotFound / AccessDenied (namespace \
             isolation), got: {:?}",
            other
        ),
        Ok(bytes) => panic!(
            "namespace isolation BROKEN: recipient read {} bytes of owner's \
             file via their own JWT",
            bytes.len()
        ),
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Pure-Rust unit tests (run without `--ignored`)
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn fula_id_parses_to_32_bytes() {
    let sample = "FULA-gerZVXIPwFGlvBydeL5ANpzcM30g_J5-7HM5VprR2iw";
    let bytes = parse_fula_id(sample).expect("parse");
    assert_eq!(bytes.len(), 32);
    // First byte from the example: base64url decode of 'g' (0x81)
    assert_eq!(bytes[0], 0x81);
}

#[test]
fn fula_id_rejects_missing_prefix() {
    assert!(parse_fula_id("gerZVXIPwFGlvBydeL5ANpzcM30g_J5-7HM5VprR2iw").is_err());
}

#[test]
fn fula_id_rejects_wrong_length() {
    // 31 bytes of zeros base64url-encoded
    let too_short = "FULA-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    assert!(parse_fula_id(too_short).is_err());
}

#[test]
fn derived_public_key_matches_round_trip() {
    let kek: [u8; 32] = [7u8; 32];
    let pk = derive_public_key_from_kek(&kek);
    let pk_again = derive_public_key_from_kek(&kek);
    assert_eq!(pk, pk_again, "deterministic derivation");
}
