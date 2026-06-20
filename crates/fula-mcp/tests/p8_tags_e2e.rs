//! Phase 8 — GATED live e2e of the tag operations (`tag_file` / `list_tags`).
//!
//! The live-gateway counterpart to the offline tests in `src/tags.rs`. It proves
//! the format-fidelity deliverable end-to-end over the REAL wire format:
//!
//!   1. `store_file` two distinct files into the AI workspace (so the tags
//!      reference real stored objects by their logical key, as `remoteKey`).
//!   2. `tag_file` the FIRST file with two tags, then `tag_file` the SECOND file
//!      with one shared + one new tag. This deliberately exercises the
//!      **read-modify-write OVERWRITE path** — the tag document is one fixed key
//!      re-written on every call — which nothing else in the suite covers (P5/6/7
//!      all wrote fresh-uuid keys). The shared tag also proves cross-file dedup.
//!   3. `list_tags` returns the union of tags.
//!   4. **Adoption guarantee:** read the document back with a SEPARATE workspace
//!      client built from the SAME workspace secret (this mirrors "anyone with
//!      the workspace secret — i.e. FxFiles — can read + parse it", not merely
//!      "the writer can re-read"), `serde_json`-parse it as `TagCloudMetadata`,
//!      and assert: both files' associations are present (the overwrite did not
//!      lose the first write), the shared tag has `fileCount == 2`, the camelCase
//!      JSON keys are exactly the Dart shape, and the nullable association fields
//!      are present as `null`.
//!
//! Why a second workspace client (not a cross-account proxy): the tag document is
//! encrypted with the workspace secret, which FxFiles holds. The adoption read is
//! therefore a same-secret read — exactly what a second client models. This keeps
//! the test self-contained (no production cross-account machinery) while proving
//! the real guarantee P14 depends on.
//!
//! Double-gated so a plain `cargo test` stays green OFFLINE:
//!   1. `#[ignore]` — excluded from a normal run; needs `-- --ignored`.
//!   2. `FULA_E2E=1` — even under `--ignored`, the body is a no-op unless set.
//!
//! Credentials: the operator's local creds file (NOT committed), default
//! `C:\Users\ehsan\.claude\cache\e2e-credentials.env`, override via
//! `FULA_E2E_CREDS`. Dedicated test accounts, treated as production: writes only
//! into the disposable workspace bucket and always cleans up.

use std::collections::HashMap;

use base64::Engine as _;
use bytes::Bytes;
use fula_client::{Config, EncryptedClient, EncryptionConfig};
use fula_crypto::SecretKey;
use fula_mcp::capability::CapabilityBundle;
use fula_mcp::store::{store_file, WORKSPACE_BUCKET};
use fula_mcp::tags::{
    list_tags, tag_file, tag_metadata_location, TagCloudMetadata, TAG_METADATA_KEY,
};
use rand::RngCore;

const DEFAULT_CREDS_PATH: &str = r"C:\Users\ehsan\.claude\cache\e2e-credentials.env";

/// Minimal `.env` parser (same shape as the P1/P2/P5/P6/P7 e2e tests).
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

fn cred(creds: &HashMap<String, String>, key: &str) -> Option<String> {
    creds
        .get(key)
        .cloned()
        .or_else(|| std::env::var(key).ok())
        .filter(|v| !v.is_empty())
}

/// Build the capability-bundle JSON from a GIVEN workspace secret + a random MCP
/// secret + a random owner public key + creds, granting `ai/` read-write-delete,
/// and carrying an explicit `user_id` (so the document's `userId` field is
/// exercised for fidelity). The workspace secret is passed in (not random) so the
/// test can build a SECOND client from the same secret for the adoption read.
fn bundle_json(
    endpoint: &str,
    jwt: &str,
    workspace_secret_b64: &str,
    user_id: &str,
    timeout_secs: u64,
) -> String {
    let mut mcp = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut mcp);
    let mcp_b64 = base64::engine::general_purpose::STANDARD.encode(mcp);
    // A throwaway owner public key (tags don't mint owner shares; the bundle just
    // requires a valid 32-byte owner public key to parse).
    let mut owner = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut owner);
    let owner_pub_b64 = base64::engine::general_purpose::STANDARD
        .encode(SecretKey::from_bytes(&owner).unwrap().public_key().as_bytes());
    format!(
        r#"{{
          "endpoint": {endpoint:?},
          "jwt": {jwt:?},
          "workspace_secret_b64": "{workspace_secret_b64}",
          "mcp_secret_b64": "{mcp_b64}",
          "owner_public_b64": "{owner_pub_b64}",
          "user_id": "{user_id}",
          "timeout_secs": {timeout_secs},
          "grants": [
            {{ "scope": "ai/", "permissions": {{ "can_read": true, "can_write": true, "can_delete": true }} }}
          ]
        }}"#
    )
}

/// A second, independent workspace client built directly from the same secret —
/// models FxFiles reading the document for adoption.
fn adopter_client(endpoint: &str, jwt: &str, ws_secret: &[u8; 32], timeout_secs: u64) -> EncryptedClient {
    let secret = SecretKey::from_bytes(ws_secret).unwrap();
    let config = Config::new(endpoint.to_string())
        .with_token(jwt.to_string())
        .with_encryption()
        .with_timeout(std::time::Duration::from_secs(timeout_secs.max(1)));
    let encryption = EncryptionConfig::from_secret_key(secret);
    EncryptedClient::new(config, encryption).expect("adopter workspace client")
}

#[tokio::test]
#[ignore = "hits a live Fula gateway; run with FULA_E2E=1 and `-- --ignored`"]
async fn e2e_tag_file_overwrite_and_adoption_read() {
    // ---- Gate 2: opt-in even under --ignored ------------------------------
    if std::env::var("FULA_E2E").as_deref() != Ok("1") {
        eprintln!("FULA_E2E != 1 — skipping live P8 tags e2e (expected offline).");
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
    let timeout_secs: u64 = cred(&creds, "FULA_TIMEOUT_SECS")
        .and_then(|s| s.parse().ok())
        .unwrap_or(120);

    // ---- A dedicated random workspace secret (NOT the user's master key) ---
    // Held by BOTH the AI's bundle and the adopter client (= FxFiles knows it).
    let mut ws = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut ws);
    let ws_b64 = base64::engine::general_purpose::STANDARD.encode(ws);

    let user_id = "e2e0123456789abc"; // 16-hex-ish; exercises the userId field.
    let cap = CapabilityBundle::from_json(&bundle_json(
        &endpoint, &jwt, &ws_b64, user_id, timeout_secs,
    ))
    .expect("capability bundle must parse");

    let client = cap.workspace_client().expect("workspace client");
    let _ = client.create_bucket(WORKSPACE_BUCKET).await; // best-effort; may already exist

    // Confirm the published location helper agrees with the constant.
    assert_eq!(tag_metadata_location(), (WORKSPACE_BUCKET, TAG_METADATA_KEY));

    let run: Result<(), String> = async {
        // ───────────── Store two distinct files ─────────────
        let tag = uuid::Uuid::new_v4();
        let mut a_bytes = vec![0u8; 16 * 1024];
        rand::thread_rng().fill_bytes(&mut a_bytes);
        let mut b_bytes = vec![0u8; 16 * 1024];
        rand::thread_rng().fill_bytes(&mut b_bytes);

        let a = store_file(
            &cap,
            Bytes::from(a_bytes),
            &format!("p8-a-{tag}.png"),
            Some("image/png"),
            None,
            None,
        )
        .await
        .map_err(|e| format!("store_file(A) failed: {e}"))?;
        let b = store_file(
            &cap,
            Bytes::from(b_bytes),
            &format!("p8-b-{tag}.pdf"),
            Some("application/pdf"),
            None,
            None,
        )
        .await
        .map_err(|e| format!("store_file(B) failed: {e}"))?;

        // ───────────── tag_file: first file, two tags ─────────────
        let out_a = tag_file(
            &cap,
            &a.key,
            &["Travel".to_string(), "Receipts".to_string()],
        )
        .await
        .map_err(|e| format!("tag_file(A) failed: {e}"))?;
        if out_a.created_tags.len() != 2 {
            return Err(format!("tag_file(A) expected 2 created tags, got {:?}", out_a.created_tags));
        }
        if out_a.added_associations != 2 {
            return Err(format!("tag_file(A) expected 2 associations, got {}", out_a.added_associations));
        }

        // ───────────── tag_file: second file, one SHARED + one NEW tag ─────────────
        // This is the OVERWRITE path: it must LOAD the prior document (with A's
        // tags), reuse "Receipts", add "Invoices", and add B's associations —
        // WITHOUT losing A's. "Receipts" must NOT be recreated.
        let out_b = tag_file(
            &cap,
            &b.key,
            &["Receipts".to_string(), "Invoices".to_string()],
        )
        .await
        .map_err(|e| format!("tag_file(B) failed: {e}"))?;
        if out_b.created_tags != vec!["Invoices".to_string()] {
            return Err(format!(
                "tag_file(B) expected only 'Invoices' created (Receipts reused), got {:?}",
                out_b.created_tags
            ));
        }
        if out_b.added_associations != 2 {
            return Err(format!("tag_file(B) expected 2 associations, got {}", out_b.added_associations));
        }
        // The in-memory outcome must already show BOTH files retained (proves the
        // read-modify-write loaded the prior doc, not an empty one).
        if out_b.metadata.tags.len() != 3 {
            return Err(format!("after B, expected 3 tags total, got {}", out_b.metadata.tags.len()));
        }

        // ───────────── list_tags: union of all tags ─────────────
        let listed = list_tags(&cap).await.map_err(|e| format!("list_tags failed: {e}"))?;
        let mut names: Vec<String> = listed.iter().map(|t| t.name.clone()).collect();
        names.sort();
        if names != vec!["Invoices".to_string(), "Receipts".to_string(), "Travel".to_string()] {
            return Err(format!("list_tags unexpected: {names:?}"));
        }

        // ───────────── ADOPTION READ: a SECOND client (same secret = FxFiles) ─────────────
        let adopter = adopter_client(&endpoint, &jwt, &ws, timeout_secs);
        let raw = adopter
            .get_object_flat(WORKSPACE_BUCKET, TAG_METADATA_KEY)
            .await
            .map_err(|e| format!("adopter get tag doc failed: {e}"))?;

        // (a) It parses as TagCloudMetadata (the adoption merge would do this).
        let doc: TagCloudMetadata = serde_json::from_slice(&raw)
            .map_err(|e| format!("adopter could not parse TagCloudMetadata: {e}"))?;

        // (b) BOTH files' associations are present (overwrite lost nothing).
        let a_assoc = doc.tagged_files.iter().filter(|tf| tf.remote_key.as_deref() == Some(a.key.as_str())).count();
        let b_assoc = doc.tagged_files.iter().filter(|tf| tf.remote_key.as_deref() == Some(b.key.as_str())).count();
        if a_assoc != 2 {
            return Err(format!("file A should have 2 associations after overwrite, got {a_assoc}"));
        }
        if b_assoc != 2 {
            return Err(format!("file B should have 2 associations, got {b_assoc}"));
        }

        // (c) The shared "Receipts" tag covers BOTH files (fileCount == 2).
        let receipts = doc.tags.iter().find(|t| t.name == "Receipts")
            .ok_or_else(|| "Receipts tag missing from adopted doc".to_string())?;
        if receipts.file_count != 2 {
            return Err(format!("Receipts.fileCount should be 2 (both files), got {}", receipts.file_count));
        }

        // (d) userId fidelity: the document carries the bundle's user_id.
        if doc.user_id != user_id {
            return Err(format!("doc.userId expected {user_id}, got {}", doc.user_id));
        }

        // (e) BYTE-SHAPE fidelity: the raw JSON has the exact Dart camelCase keys,
        //     and the nullable association fields are present as null.
        let raw_str = String::from_utf8_lossy(&raw);
        for needle in [
            r#""userId":"#, r#""tags":"#, r#""taggedFiles":"#, r#""updatedAt":"#, r#""version":"#,
            r#""colorValue":"#, r#""fileCount":"#, r#""tagId":"#, r#""remoteKey":"#,
            r#""fileName":"#, r#""taggedAt":"#, r#""localPath":null"#, r#""iosAssetId":null"#,
        ] {
            if !raw_str.contains(needle) {
                return Err(format!("adopted JSON missing expected fragment {needle}: {raw_str}"));
            }
        }

        // Best-effort object cleanup (bucket teardown runs below regardless).
        let _ = client.delete_object_flat(WORKSPACE_BUCKET, TAG_METADATA_KEY).await;
        let _ = client.delete_object_flat(&a.bucket, &a.key).await;
        let _ = client.delete_object_flat(&b.bucket, &b.key).await;
        Ok(())
    }
    .await;

    // ---- Cleanup that ALWAYS runs -----------------------------------------
    match client.delete_bucket(WORKSPACE_BUCKET).await {
        Ok(()) => eprintln!("cleanup: deleted workspace bucket {WORKSPACE_BUCKET}"),
        Err(e) => eprintln!(
            "note: workspace bucket {WORKSPACE_BUCKET} left behind (forest-index objects remain; \
             expected): {e}"
        ),
    }

    run.unwrap_or_else(|e| panic!("P8 tags e2e failed: {e}"));
    eprintln!(
        "P8 tags e2e OK: AI tagged two files (overwrite path), list_tags returned the union, and a \
         second same-secret client adopted the TagCloudMetadata doc — both files' associations \
         present, shared tag fileCount=2, Dart camelCase shape + explicit nulls verified."
    );
}
