//! LIVE collaboration manifest round-trip — env-gated, skipped offline.
//!
//! Closes the "only tested against our own mocks" gap for the manifest-sync path.
//! Against the REAL `/api/collab/{group}/manifest-sync` endpoint (a fresh, random
//! throwaway group), it:
//!   1. builds a representative [`CollaborationGroup`] (a root file, a file inside a
//!      `/notes` subfolder, and the `/notes` directory marker),
//!   2. `enc1_encrypt`s it under a random 32-byte link secret,
//!   3. `PUT`s it with a real api_key Bearer,
//!   4. reads it back through `collab::fetch_manifest` and asserts the decrypted +
//!      parsed group equals the original (files + `path_scope` + directory marker
//!      all survive the live round-trip).
//!
//! What it validates that the `collab_http_mock` wiremock test CANNOT: the LIVE
//! server's actual response envelope (which field it returns), real TLS + auth
//! framing, and that the server stores the opaque `ENC1:` blob byte-for-byte (any
//! transform would break the AES-GCM tag and fail the decrypt). The blob is opaque
//! to the server, so this does not — and cannot — validate any server-side manifest
//! logic; the gap being closed is purely the client's wire-shape + ENC1 crypto path.
//!
//! Gated on BOTH `FULA_E2E=1` and `FULA_JWT` (a real api_key Bearer that
//! `PUT manifest-sync` accepts), so it is a no-op in normal/offline `cargo test`.
//! Base defaults to `https://cloud.fx.land` (override with `FULA_WEBUI_BASE`).
//!
//! ```sh
//! FULA_E2E=1 FULA_JWT='<api_key bearer>' \
//!   cargo test -p fula-mcp --test collab_manifest_live_e2e -- --nocapture
//! ```

use fula_mcp::collab::{fetch_manifest, put_manifest};
use fula_mcp::manifest::{enc1_encrypt, CollaborationFile, CollaborationGroup};
use rand::RngCore;
use uuid::Uuid;

/// The `content_type` marking a manifest entry as a folder (mirrors `tree.rs`).
const DIRECTORY_CONTENT_TYPE: &str = "application/x-directory";

struct LiveCfg {
    base: String,
    jwt: String,
}

/// Resolve the live-test config, or `None` (with a skip note) when not gated on.
fn gated() -> Option<LiveCfg> {
    if std::env::var("FULA_E2E").is_err() {
        eprintln!("skipping collab_manifest_live_e2e: set FULA_E2E=1 to run");
        return None;
    }
    let jwt = match std::env::var("FULA_JWT") {
        Ok(j) if !j.trim().is_empty() => j.trim().to_string(),
        _ => {
            eprintln!("skipping collab_manifest_live_e2e: FULA_JWT not set");
            return None;
        }
    };
    let base = std::env::var("FULA_WEBUI_BASE")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .map(|s| s.trim().trim_end_matches('/').to_string())
        .unwrap_or_else(|| "https://cloud.fx.land".to_string());
    Some(LiveCfg { base, jwt })
}

/// A small but representative manifest: a root file, a file under a `/notes`
/// subfolder, and the `/notes` directory marker — so the round-trip exercises a
/// plain entry, a `path_scope`d entry, and a directory marker.
fn sample_group(group_id: &str) -> CollaborationGroup {
    let f_root = CollaborationFile {
        id: Uuid::new_v4().to_string(),
        file_name: "root.txt".to_string(),
        content_type: Some("text/plain".to_string()),
        bucket: "fula-metadata".to_string(),
        storage_key: format!(".fula/collab/{group_id}/files/root"),
        path_scope: None,
        added_by_public_key: "test-pk".to_string(),
        added_at: "2026-01-02T03:04:05.000Z".to_string(),
        file_size: 11,
        enc_type: "collab".to_string(),
        share_token_json: None,
    };
    let f_sub = CollaborationFile {
        id: Uuid::new_v4().to_string(),
        file_name: "memo.txt".to_string(),
        content_type: Some("text/plain".to_string()),
        bucket: "fula-metadata".to_string(),
        storage_key: format!(".fula/collab/{group_id}/files/memo"),
        path_scope: Some("/notes".to_string()),
        added_by_public_key: "test-pk".to_string(),
        added_at: "2026-01-02T03:04:06.000Z".to_string(),
        file_size: 22,
        enc_type: "collab".to_string(),
        share_token_json: None,
    };
    let d_notes = CollaborationFile {
        id: Uuid::new_v4().to_string(),
        file_name: "notes".to_string(),
        content_type: Some(DIRECTORY_CONTENT_TYPE.to_string()),
        bucket: "fula-metadata".to_string(),
        storage_key: String::new(),
        path_scope: Some("/notes".to_string()),
        added_by_public_key: "test-pk".to_string(),
        added_at: "2026-01-02T03:04:07.000Z".to_string(),
        file_size: 0,
        enc_type: "collab".to_string(),
        share_token_json: None,
    };
    CollaborationGroup {
        id: group_id.to_string(),
        name: "live-e2e-roundtrip".to_string(),
        owner_public_key: "test-owner-pk".to_string(),
        manifest_bucket: "fula-metadata".to_string(),
        manifest_key: format!("manifests/{group_id}.json"),
        created_at: "2026-01-02T03:04:05.000Z".to_string(),
        expires_at: None,
        is_revoked: false,
        files: vec![f_root, f_sub, d_notes],
        removed_file_ids: Vec::new(),
        version: 1,
        updated_at: "2026-01-02T03:04:08.000Z".to_string(),
    }
}

#[tokio::test]
async fn live_put_then_fetch_manifest_roundtrip() {
    let Some(cfg) = gated() else { return };

    // Fresh throwaway group + link secret per run (never collides with a real group).
    let group_id = Uuid::new_v4().to_string();
    let mut link_secret = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut link_secret);

    let group = sample_group(&group_id);
    let enc1 = enc1_encrypt(
        &serde_json::to_vec(&group).expect("serialize manifest"),
        &link_secret,
        &group_id,
    );
    assert!(
        enc1.starts_with("ENC1:"),
        "encrypted manifest must carry the ENC1 envelope"
    );

    let http = reqwest::Client::new();

    // 1) PUT the encrypted manifest with the real api_key Bearer (the WRITE path).
    put_manifest(&http, &cfg.base, &group_id, &cfg.jwt, &enc1)
        .await
        .expect("live PUT manifest-sync must return 2xx with FULA_JWT");
    eprintln!("PUT ok: group_id={group_id} base={}", cfg.base);

    // 2) Raw GET — assert the LIVE response SHAPE and that the server stored the
    //    opaque ENC1 blob verbatim (anti-circularity: any transform would also break
    //    the GCM decrypt in step 3, so this can only pass if storage is faithful).
    let raw = http
        .get(format!("{}/api/collab/{}/manifest-sync", cfg.base, group_id))
        .send()
        .await
        .expect("raw GET manifest-sync");
    assert!(
        raw.status().is_success(),
        "raw GET must be 2xx, got {}",
        raw.status()
    );
    let envelope: serde_json::Value = raw.json().await.expect("manifest-sync JSON envelope");
    let returned = envelope
        .get("encryptedManifest")
        .or_else(|| envelope.get("data"))
        .and_then(|v| v.as_str())
        .expect("live response must carry `encryptedManifest` or `data`");
    assert_eq!(returned, enc1, "server must return the ENC1 blob byte-for-byte");

    // 3) The real READ path: fetch_manifest GETs → decrypts → parses to the original.
    let fetched = fetch_manifest(&http, &cfg.base, &group_id, &link_secret)
        .await
        .expect("fetch_manifest must succeed")
        .expect("manifest must be present (we just PUT it)");

    // Targeted survival asserts (clearer diagnostics than bare equality on failure).
    assert_eq!(
        fetched.files.len(),
        3,
        "all three entries survive the round-trip"
    );
    let sub = fetched
        .files
        .iter()
        .find(|f| f.file_name == "memo.txt")
        .expect("subfolder file present");
    assert_eq!(
        sub.path_scope.as_deref(),
        Some("/notes"),
        "path_scope subfolder survives the real round-trip"
    );
    let dir = fetched
        .files
        .iter()
        .find(|f| f.file_name == "notes")
        .expect("directory marker present");
    assert_eq!(
        dir.content_type.as_deref(),
        Some(DIRECTORY_CONTENT_TYPE),
        "directory marker content_type survives the real round-trip"
    );

    // Full structural equality (every field, in order).
    assert_eq!(fetched, group, "round-tripped manifest must equal the original");

    // 4) Negative control: a WRONG link secret must FAIL to decrypt — proves we are
    //    actually authenticating the ENC1 envelope, not trivially parsing plaintext.
    let mut wrong = link_secret;
    wrong[0] ^= 0xFF;
    let bad = fetch_manifest(&http, &cfg.base, &group_id, &wrong).await;
    assert!(
        bad.is_err(),
        "a wrong link secret must not decrypt the manifest, got {bad:?}"
    );

    eprintln!("collab_manifest_live_e2e PASS: ENC1 PUT->GET->decrypt round-trip verified live");
}
