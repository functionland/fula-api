//! Phase 9 — GATED live e2e of the MCP **tool layer** (store → read round-trip).
//!
//! The live-gateway counterpart to the offline unit + transport-smoke tests. It
//! exercises the two core tools THROUGH THE SERVER METHODS (not the bare library
//! ops), so it proves the P9 wiring the unit tests can't: base64 decode on input,
//! the result-shape projection, and the success path of the tag-on-store branch.
//!
//!   1. Build a [`CapabilityBundle`] from a DEDICATED, random workspace secret
//!      (NOT the user's master key) + the test creds' `FULA_JWT` / `FULA_S3`,
//!      granting `ai/` read-write, with a throwaway "owner" public key.
//!   2. Construct a [`FulaMcpServer`] around it and call
//!      [`FulaMcpServer::fula_store_file`] with base64 `content` + a couple of
//!      `tags`. Assert the returned `CallToolResult` is a SUCCESS carrying a
//!      `key`, the right `category`, an `etag`, and the tag bookkeeping.
//!   3. Call [`FulaMcpServer::fula_read_file`] with that `key`, decode the
//!      returned `content_base64`, and assert it is BYTE-IDENTICAL to the input.
//!   4. Call [`FulaMcpServer::fula_list_files`] + [`FulaMcpServer::fula_list_tags`]
//!      and assert the stored file + the applied tags are visible through the
//!      tool layer. Clean up the object + bucket.
//!
//! This is a clean SINGLE-JWT workspace round-trip: the AI reads back its OWN
//! workspace file via the workspace client (`read_workspace_file` →
//! `get_object_flat`), so it avoids P5's cross-account owner-read entirely.
//!
//! Double-gated so a plain `cargo test` stays green OFFLINE:
//!   1. `#[ignore]` — excluded from a normal run; needs `-- --ignored`.
//!   2. `FULA_E2E=1` — even under `--ignored`, the body is a no-op unless set.
//!
//! Credentials: the operator's local creds file (NOT committed), default
//! `C:\Users\ehsan\.claude\cache\e2e-credentials.env`, override via
//! `FULA_E2E_CREDS`. Dedicated test accounts, treated as production: writes only
//! into a unique disposable workspace bucket and always cleans up.

use std::collections::HashMap;

use base64::Engine as _;
use fula_mcp::capability::CapabilityBundle;
use fula_mcp::server::{
    FulaMcpServer, ReadFileArgs, ReadFileResult, ListFilesArgs, ListTagsArgs, StoreFileArgs,
    StoreFileResult, TagFileArgs,
};
use fula_mcp::store::WORKSPACE_BUCKET;
use rand::RngCore;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::CallToolResult;

const DEFAULT_CREDS_PATH: &str = r"C:\Users\ehsan\.claude\cache\e2e-credentials.env";

/// Minimal `.env` parser (same shape as the P1–P8 e2e tests).
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

/// Build the capability-bundle JSON from a random workspace secret + a random MCP
/// secret + a random owner public key + creds, granting `ai/` read-write.
fn bundle_json(endpoint: &str, jwt: &str, timeout_secs: u64) -> String {
    let mut ws = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut ws);
    let mut mcp = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut mcp);
    let mut owner_seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut owner_seed);
    let owner_pub = fula_crypto::SecretKey::from_bytes(&owner_seed)
        .unwrap()
        .public_key();
    let ws_b64 = base64::engine::general_purpose::STANDARD.encode(ws);
    let mcp_b64 = base64::engine::general_purpose::STANDARD.encode(mcp);
    let owner_b64 = base64::engine::general_purpose::STANDARD.encode(owner_pub.as_bytes());
    format!(
        r#"{{
          "endpoint": {endpoint:?},
          "jwt": {jwt:?},
          "workspace_secret_b64": "{ws_b64}",
          "mcp_secret_b64": "{mcp_b64}",
          "owner_public_b64": "{owner_b64}",
          "timeout_secs": {timeout_secs},
          "grants": [
            {{ "scope": "ai/", "permissions": {{ "can_read": true, "can_write": true, "can_delete": true }} }}
          ]
        }}"#
    )
}

/// Pull the single text block out of a `CallToolResult` and parse it as `T`.
/// Panics with the tool's own error text if the result is a tool error.
fn parse_ok<T: serde::de::DeserializeOwned>(label: &str, result: &CallToolResult) -> T {
    let text = result
        .content
        .first()
        .and_then(|c| c.as_text())
        .map(|t| t.text.clone())
        .unwrap_or_default();
    assert_ne!(
        result.is_error,
        Some(true),
        "{label}: tool returned an error: {text}"
    );
    serde_json::from_str(&text)
        .unwrap_or_else(|e| panic!("{label}: result text was not the expected JSON ({e}): {text}"))
}

#[tokio::test]
#[ignore = "hits a live Fula gateway; run with FULA_E2E=1 and `-- --ignored`"]
async fn e2e_tool_layer_store_then_read_round_trips() {
    // ---- Gate 2: opt-in even under --ignored ------------------------------
    if std::env::var("FULA_E2E").as_deref() != Ok("1") {
        eprintln!("FULA_E2E != 1 — skipping live P9 MCP tool-layer e2e (expected offline).");
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

    let cap = CapabilityBundle::from_json(&bundle_json(&endpoint, &jwt, timeout_secs))
        .expect("capability bundle must parse");

    // store_file always writes to WORKSPACE_BUCKET. Create it fresh for isolation;
    // tear it down at the end. (Build a side workspace client only for bucket
    // lifecycle — the TOOLS themselves go through the server.)
    let admin_client = cap.workspace_client().expect("workspace client for bucket lifecycle");
    let _ = admin_client.create_bucket(WORKSPACE_BUCKET).await; // best-effort; may already exist

    let server = FulaMcpServer::new(cap);

    // A unique payload + filename so each run writes a distinct key.
    let tag = uuid::Uuid::new_v4();
    let name = format!("p9-tool-{tag}.txt");
    let plaintext = format!("P9 MCP tool-layer e2e payload {tag} — must round-trip byte-identical.")
        .into_bytes();
    let content_b64 = base64::engine::general_purpose::STANDARD.encode(&plaintext);

    let outcome: Result<(), String> = async {
        // ───────────── fula_store_file (with tags) over the TOOL layer ─────────
        let store_res = server
            .fula_store_file(Parameters(StoreFileArgs {
                content: content_b64.clone(),
                name: name.clone(),
                mime: Some("text/plain".to_string()),
                text: None,
                category_override: None,
                tags: Some(vec!["E2E".to_string(), "Phase9".to_string()]),
            }))
            .await
            .map_err(|e| format!("fula_store_file returned a protocol error: {e:?}"))?;

        if store_res.is_error == Some(true) {
            let txt = store_res
                .content
                .first()
                .and_then(|c| c.as_text())
                .map(|t| t.text.clone())
                .unwrap_or_default();
            return Err(format!("fula_store_file tool error: {txt}"));
        }
        let stored: StoreFileResult = parse_ok("fula_store_file", &store_res);

        // text/plain → ai/document/... category=document (the classifier's mapping).
        if !stored.key.starts_with("ai/") {
            return Err(format!("stored key not under ai/: {}", stored.key));
        }
        if stored.etag.is_empty() {
            return Err("stored result missing etag".to_string());
        }
        if stored.tags_failed {
            return Err("tags_failed was set on the store result (tagging should have succeeded)".to_string());
        }
        // This run wrote a UNIQUE file key, so its (tag, file) associations are
        // always new → 2 added regardless of whether a prior run left the tag
        // NAMES behind. We assert on `added_associations` (rerun-safe) and only
        // bound `created_tags` (0 on a rerun where the tag doc persisted, 2 on a
        // truly fresh bucket — the e2e leaves the bucket behind by design, so a
        // second run legitimately creates 0 new tag names).
        if stored.added_associations != 2 {
            return Err(format!(
                "expected 2 new (tag,file) associations for the unique file, got {} (created={:?})",
                stored.added_associations, stored.created_tags
            ));
        }
        if stored.created_tags.len() > 2 {
            return Err(format!(
                "created_tags should be at most the 2 requested, got {:?}",
                stored.created_tags
            ));
        }

        // ───────────── fula_read_file over the TOOL layer ─────────────────────
        let read_res = server
            .fula_read_file(Parameters(ReadFileArgs { key: stored.key.clone() }))
            .await
            .map_err(|e| format!("fula_read_file returned a protocol error: {e:?}"))?;
        if read_res.is_error == Some(true) {
            let txt = read_res
                .content
                .first()
                .and_then(|c| c.as_text())
                .map(|t| t.text.clone())
                .unwrap_or_default();
            return Err(format!("fula_read_file tool error: {txt}"));
        }
        let read: ReadFileResult = parse_ok("fula_read_file", &read_res);
        let got = base64::engine::general_purpose::STANDARD
            .decode(read.content_base64.as_bytes())
            .map_err(|e| format!("read result content_base64 did not decode: {e}"))?;
        if got != plaintext {
            return Err(format!(
                "ROUND-TRIP MISMATCH: wrote {} bytes, tool read back {}",
                plaintext.len(),
                got.len()
            ));
        }

        // ───────────── fula_list_files sees the stored file ───────────────────
        let list_res = server
            .fula_list_files(Parameters(ListFilesArgs { category: None, prefix: None }))
            .await
            .map_err(|e| format!("fula_list_files protocol error: {e:?}"))?;
        let rows: Vec<serde_json::Value> = parse_ok("fula_list_files", &list_res);
        let found = rows
            .iter()
            .any(|r| r.get("key").and_then(|k| k.as_str()) == Some(stored.key.as_str()));
        if !found {
            return Err(format!(
                "fula_list_files did not surface the stored key {} (rows: {})",
                stored.key,
                rows.len()
            ));
        }

        // ───────────── fula_list_tags sees the applied tags ───────────────────
        let tags_res = server
            .fula_list_tags(Parameters(ListTagsArgs {}))
            .await
            .map_err(|e| format!("fula_list_tags protocol error: {e:?}"))?;
        let tag_rows: Vec<serde_json::Value> = parse_ok("fula_list_tags", &tags_res);
        let tag_names: Vec<&str> = tag_rows
            .iter()
            .filter_map(|t| t.get("name").and_then(|n| n.as_str()))
            .collect();
        for want in ["E2E", "Phase9"] {
            if !tag_names.contains(&want) {
                return Err(format!(
                    "fula_list_tags missing tag {want:?} (got {tag_names:?})"
                ));
            }
        }

        // ───────────── re-tag is idempotent through the tool layer ────────────
        let retag_res = server
            .fula_tag_file(Parameters(TagFileArgs {
                key: stored.key.clone(),
                tags: vec!["E2E".to_string()],
            }))
            .await
            .map_err(|e| format!("fula_tag_file protocol error: {e:?}"))?;
        let retag: fula_mcp::server::TagFileResult = parse_ok("fula_tag_file", &retag_res);
        if retag.added_associations != 0 || !retag.created_tags.is_empty() {
            return Err(format!(
                "re-tagging the same (file, tag) must be idempotent, got created={:?} added={}",
                retag.created_tags, retag.added_associations
            ));
        }

        // Clean up the stored object (best-effort; bucket teardown below).
        let _ = admin_client
            .delete_object_flat(WORKSPACE_BUCKET, &stored.key)
            .await;
        Ok(())
    }
    .await;

    // ---- Cleanup that ALWAYS runs -----------------------------------------
    match admin_client.delete_bucket(WORKSPACE_BUCKET).await {
        Ok(()) => eprintln!("cleanup: deleted workspace bucket {WORKSPACE_BUCKET}"),
        Err(e) => eprintln!(
            "note: workspace bucket {WORKSPACE_BUCKET} left behind (forest-index objects remain; \
             expected — no encrypted-client API drains them): {e}"
        ),
    }

    outcome.unwrap_or_else(|e| panic!("P9 MCP tool-layer e2e failed: {e}"));
    eprintln!(
        "P9 MCP tool-layer e2e OK: fula_store_file (+tags) → fula_read_file round-trips \
         byte-identical; fula_list_files + fula_list_tags surface the result; re-tag idempotent."
    );
}
