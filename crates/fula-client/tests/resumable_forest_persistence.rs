//! Regression test for fula-api#23: `put_object_encrypted_resumable_with_cancel`
//! must durably persist the forest update on the master, not just in the
//! local in-memory cache + WAL.
//!
//! ## Why this test exists
//!
//! Before the #23 fix, the resumable chunked upload path
//! (`put_object_encrypted_resumable_with_cancel` → `finalize_and_register_resumed_upload`
//! → `register_encrypted_chunked_upload_in_forest`) would:
//!
//! 1. Encrypt + upload all chunks ✓
//! 2. PUT the index object ✓
//! 3. Upsert the forest entry **in-memory only** (`ForestCacheEntry::Monolithic { dirty: true, .. }`)
//! 4. Append the entry to the on-disk WAL
//! 5. Delete the manifest
//! 6. Return success with a valid etag
//!
//! Step 4 (WAL) + the in-memory cache made the file appear in `list_directory`
//! for the SAME client instance — but a FRESH client (post-restart, post-
//! storage-clear, post-device-swap) loading the bucket from the master saw
//! the pre-upload forest because the master never received the forest
//! update. The flush sequence (`save_sharded_hamt_forest` / `save_monolithic_forest`
//! → `Persisting bucket registry to IPFS` → `Bucket root CID enqueued for
//! durable pin (W.9.6)`) is what actually pushes the forest to master, and
//! that only fires inside `flush_forest_locked` — which the resumable path
//! did not call.
//!
//! The non-resumable path (`put_object_flat`) was unaffected because it
//! ends with an explicit `self.flush_forest_locked(bucket).await?` (see
//! `encryption.rs:6217`).
//!
//! ## What this test verifies
//!
//! Two FulaClient instances against the SAME master + same secret:
//!
//! 1. **Client A**: uploads via `put_object_encrypted_resumable_with_cancel`,
//!    then is dropped entirely. Its in-memory cache and the on-disk WAL
//!    must NOT influence client B's view.
//! 2. **Client B**: created fresh, no shared block cache or WAL state.
//!    Calls `list_files_from_forest(bucket)` — the file uploaded by A
//!    MUST appear. Then calls `get_object_flat` and verifies the bytes.
//!
//! Without the fix, client B's list would not include the new file
//! (its in-memory forest is freshly loaded from master, which never
//! received the update). With the fix, client B sees the file because
//! `finalize_and_register_resumed_upload` now calls `flush_forest_locked`
//! after `register_encrypted_chunked_upload_in_forest` returns Ok.
//!
//! ## Running
//!
//! Marked `#[ignore]` because it requires a live master + JWT. Same
//! envvar convention as `offline_e2e.rs`:
//!
//! ```bash
//! FULA_JWT="..." FULA_S3="https://s3.cloud.fx.land" \
//!   cargo test -p fula-client --test resumable_forest_persistence \
//!   --release -- --ignored --nocapture
//! ```
//!
//! Optional:
//! - `FULA_BUCKET` (default `other`)
//! - `FULA_TIMEOUT_SECS` (default `60`)
//! - `FULA_PAYLOAD_BYTES` (default `1572864` = 1.5 MB — large enough to
//!   force the chunked path so we exercise the actual broken function
//!   `put_object_encrypted_resumable_with_cancel`, not a single-object
//!   fallback).

#![cfg(not(target_arch = "wasm32"))]

use fula_client::{Config, EncryptedClient, EncryptionConfig};
use fula_crypto::keys::SecretKey;
use std::path::Path;
use std::time::Duration;
use tempfile::TempDir;

fn read_required_env(var: &str) -> Option<String> {
    match std::env::var(var) {
        Ok(v) if !v.is_empty() => Some(v),
        _ => {
            eprintln!(
                "[resumable_forest_persistence] {} is not set or empty — skipping. \
                 Set it to a real value to run.",
                var
            );
            None
        }
    }
}

/// Build a client with the SAME knobs FxFiles ships in production
/// (mirrors `offline_e2e::build_client`). Each client gets its own
/// block-cache path so phases don't accidentally share warm-cache state
/// — that's the WHOLE POINT of the test: client B must NOT inherit
/// client A's in-memory or on-disk caches.
fn build_client(
    master_url: &str,
    jwt: &str,
    cache_path: &Path,
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

    let enc = EncryptionConfig::from_secret_key(secret);
    EncryptedClient::new(cfg, enc).expect("EncryptedClient construction must succeed")
}

#[tokio::test]
#[ignore]
async fn resumable_upload_persists_forest_across_client_restart() {
    let jwt = match read_required_env("FULA_JWT") {
        Some(v) => v,
        None => return,
    };
    let s3_url = match read_required_env("FULA_S3") {
        Some(v) => v,
        None => return,
    };
    let bucket = std::env::var("FULA_BUCKET")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "other".to_string());
    let timeout_secs: u64 = std::env::var("FULA_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(60);
    let payload_size: usize = std::env::var("FULA_PAYLOAD_BYTES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1_572_864); // 1.5 MB — > 768 KB chunked threshold

    eprintln!(
        "[resumable_forest_persistence] master={} bucket={} payload_bytes={} timeout={}s",
        s3_url, bucket, payload_size, timeout_secs,
    );

    // Distinct cache dirs for A and B so client B genuinely has no warm
    // state. Without this the test could pass simply because client B
    // inherited client A's redb block cache; we need B to load forest
    // fresh from master to actually exercise the #23 fix.
    let cache_dir_a = TempDir::new().expect("tempdir for client A cache");
    let cache_dir_b = TempDir::new().expect("tempdir for client B cache");
    let cache_path_a = cache_dir_a.path().join("blocks.redb");
    let cache_path_b = cache_dir_b.path().join("blocks.redb");

    // Same secret across both clients so the encryption is interoperable
    // — same scenario as "device A uploaded, device B reads".
    let secret = SecretKey::generate();

    // Manifest under a tempdir too — `put_object_encrypted_resumable_with_cancel`
    // writes the upload manifest there during chunk uploads and deletes it
    // on clean completion (post #23 fix: after the flush succeeds).
    let manifest_dir = TempDir::new().expect("tempdir for resumable manifest");
    let manifest_path = manifest_dir.path().join("resumable.manifest");

    let test_key = format!(
        "resumable-forest-persistence-{}.bin",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    );
    let payload: Vec<u8> = (0..payload_size).map(|i| (i % 256) as u8).collect();

    eprintln!(
        "[resumable_forest_persistence] test object = {} ({} bytes, chunked path)",
        test_key,
        payload.len()
    );

    // ─── Phase A — Upload via the RESUMABLE path, drop the client ──────
    eprintln!("\n[resumable_forest_persistence] phase A: upload via put_object_encrypted_resumable_with_cancel");
    {
        let client = build_client(
            &s3_url,
            &jwt,
            &cache_path_a,
            secret.clone(),
            timeout_secs,
        );

        let put_result = client
            .put_object_encrypted_resumable_with_cancel(
                &bucket,
                &test_key,
                payload.clone(),
                Some("application/octet-stream"),
                &manifest_path,
                None, // no cancel handle
            )
            .await
            .expect("resumable upload must return Ok");

        eprintln!(
            "[resumable_forest_persistence]   upload OK (etag={})",
            put_result.etag
        );

        // Sanity within the SAME client: the file appears in its list.
        // This is the "in-memory cache shows the file" check — without
        // the fix this would still pass (the cache is updated locally
        // regardless of master flush). The real test is phase B.
        let files = client
            .list_files_from_forest(&bucket)
            .await
            .expect("same-client list must succeed");
        assert!(
            files.iter().any(|f| f.original_key == test_key),
            "phase A same-client list missing the just-uploaded file (got {} files); \
             this should pass even WITHOUT the #23 fix",
            files.len(),
        );
        eprintln!(
            "[resumable_forest_persistence]   same-client list OK ({} files)",
            files.len()
        );

        // Client dropped here at scope exit. Its in-memory forest_cache
        // is gone. The on-disk WAL is gone too (it lives under the
        // cache_dir_a tempdir, which the TempDir owner will clean up
        // when it drops at the outer scope — but client B already uses
        // a different cache dir, so even before drop the WAL is
        // isolated). The manifest file was deleted by the SDK on clean
        // completion (post #23 fix only — confirm that side-effect):
        assert!(
            !manifest_path.exists(),
            "manifest should be deleted on clean completion (was at {})",
            manifest_path.display(),
        );
    }

    // ─── Phase B — Fresh client, fresh cache, fresh WAL ────────────────
    // The KEY assertion: a brand-new client with NO inherited state must
    // see the file in the bucket. This proves the master-side forest was
    // actually updated. Pre-#23-fix this assertion FAILS — the master's
    // bucket forest reflects pre-upload state and the file is missing.
    eprintln!("\n[resumable_forest_persistence] phase B: fresh client must see the file in list");
    {
        let client = build_client(
            &s3_url,
            &jwt,
            &cache_path_b,
            secret.clone(),
            timeout_secs,
        );
        let files = client
            .list_files_from_forest(&bucket)
            .await
            .expect("fresh-client list must succeed");

        let found = files.iter().any(|f| f.original_key == test_key);
        eprintln!(
            "[resumable_forest_persistence]   fresh-client list: {} files, target {}",
            files.len(),
            if found { "FOUND" } else { "MISSING" }
        );
        assert!(
            found,
            "FRESH-CLIENT REGRESSION: file uploaded via put_object_encrypted_resumable_with_cancel \
             is missing from the master's forest after the client that uploaded it was dropped. \
             This is the exact behaviour of fula-api#23: the upload returns Ok with a valid etag \
             but the forest update never reaches master (lives only in the original client's \
             in-memory cache + WAL). Bucket list now has {} files; expected to include '{}'.",
            files.len(),
            test_key,
        );

        // Download check — defensive: even if the file appeared in the
        // listing, verify the bytes round-trip. A "listed but unreadable"
        // failure would point at a separate chunk-pinning bug (orphaned
        // chunks). Belt-and-braces.
        let dl = client
            .get_object_flat(&bucket, &test_key)
            .await
            .expect("fresh-client download must succeed");
        assert_eq!(
            dl.as_ref(),
            payload.as_slice(),
            "fresh-client download bytes do not match the uploaded payload",
        );
        eprintln!(
            "[resumable_forest_persistence]   fresh-client download OK ({} bytes verified)",
            dl.len()
        );
    }

    eprintln!("\n[resumable_forest_persistence] PASS — resumable upload durably persists forest");
}
