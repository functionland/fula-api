//! Phase 7 — GATED live e2e of the `list_files` + `search` enumeration ops.
//!
//! The live-gateway counterpart to the offline tests in `src/list.rs`. It
//! exercises scoped enumeration over the REAL wire format:
//!
//!   1. `store_file` (reuse P5) a handful of files across DIFFERENT categories
//!      into a disposable workspace bucket (image, note, document, + a chunked
//!      binary → `file`).
//!   2. `list_files` over the whole `ai/` scope → assert EVERY stored key appears
//!      with the right category, and nothing outside `ai/` does.
//!   3. `list_files` with a category filter → assert it narrows to exactly the
//!      stored keys of that category.
//!   4. `search` by a unique filename fragment → assert it returns exactly the
//!      matching stored file(s).
//!   5. Cleanup (delete each object + tear down the bucket).
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
use fula_crypto::{KekKeyPair, SecretKey};
use fula_mcp::capability::CapabilityBundle;
use fula_mcp::category::Category;
use fula_mcp::list::{list_files, search, ListFilter};
use fula_mcp::store::{store_file, WORKSPACE_BUCKET};
use rand::RngCore;

const DEFAULT_CREDS_PATH: &str = r"C:\Users\ehsan\.claude\cache\e2e-credentials.env";

/// Minimal `.env` parser (same shape as the P1/P2/P5/P6 e2e tests).
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

/// Build the capability-bundle JSON: random workspace + MCP secrets, a random
/// owner public key, creds endpoint/JWT, granting `ai/` read-write-delete (read
/// for the enumeration, write for the stores, delete for cleanup).
fn bundle_json(endpoint: &str, jwt: &str, owner_public_b64: &str, timeout_secs: u64) -> String {
    let mut ws = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut ws);
    let mut mcp = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut mcp);
    let ws_b64 = base64::engine::general_purpose::STANDARD.encode(ws);
    let mcp_b64 = base64::engine::general_purpose::STANDARD.encode(mcp);
    format!(
        r#"{{
          "endpoint": {endpoint:?},
          "jwt": {jwt:?},
          "workspace_secret_b64": "{ws_b64}",
          "mcp_secret_b64": "{mcp_b64}",
          "owner_public_b64": "{owner_public_b64}",
          "timeout_secs": {timeout_secs},
          "grants": [
            {{ "scope": "ai/", "permissions": {{ "can_read": true, "can_write": true, "can_delete": true }} }}
          ]
        }}"#
    )
}

#[tokio::test]
#[ignore = "hits a live Fula gateway; run with FULA_E2E=1 and `-- --ignored`"]
async fn e2e_list_files_and_search_scoped() {
    // ---- Gate 2: opt-in even under --ignored ------------------------------
    if std::env::var("FULA_E2E").as_deref() != Ok("1") {
        eprintln!("FULA_E2E != 1 — skipping live P7 list/search e2e (expected offline).");
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

    // ---- A SEPARATE owner keypair (bundle holds only its PUBLIC half) ------
    let mut owner_seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut owner_seed);
    let owner = KekKeyPair::from_secret_key(SecretKey::from_bytes(&owner_seed).unwrap());
    let owner_public_b64 =
        base64::engine::general_purpose::STANDARD.encode(owner.public_key().as_bytes());

    let cap = CapabilityBundle::from_json(&bundle_json(
        &endpoint,
        &jwt,
        &owner_public_b64,
        timeout_secs,
    ))
    .expect("capability bundle must parse");

    let client = cap.workspace_client().expect("workspace client");
    let _ = client.create_bucket(WORKSPACE_BUCKET).await; // best-effort; may already exist

    // Unique tag so this run's keys are distinct (and a leftover bucket from a
    // prior aborted run can't make us assert on someone else's files).
    let tag = uuid::Uuid::new_v4().simple().to_string();

    // Store one file per category we want to prove routing+listing for. The
    // filename embeds the tag so `search` can find exactly our files.
    // (image → ai/image, text note → ai/note, pdf → ai/document, big binary →
    // ai/file via the chunked path.)
    let img_name = format!("p7-{tag}-photo.png");
    let note_name = format!("p7-{tag}-summary.txt");
    let doc_name = format!("p7-{tag}-report.pdf");
    let bin_name = format!("p7-{tag}-archive.bin");

    let mut small = vec![0u8; 16 * 1024];
    rand::thread_rng().fill_bytes(&mut small);
    let mut note_bytes = vec![0u8; 256];
    rand::thread_rng().fill_bytes(&mut note_bytes);
    let mut doc_bytes = vec![0u8; 8 * 1024];
    rand::thread_rng().fill_bytes(&mut doc_bytes);
    let mut big = vec![0u8; 1_500_000]; // > 768 KB → chunked
    rand::thread_rng().fill_bytes(&mut big);

    let outcome: Result<(), String> = async {
        // ───────────── store across categories ─────────────
        let img_out = store_file(&cap, Bytes::from(small.clone()), &img_name, Some("image/png"), None, None)
            .await
            .map_err(|e| format!("store image: {e}"))?;
        let note_out = store_file(&cap, Bytes::from(note_bytes.clone()), &note_name, Some("text/plain"), None, None)
            .await
            .map_err(|e| format!("store note: {e}"))?;
        let doc_out = store_file(&cap, Bytes::from(doc_bytes.clone()), &doc_name, Some("application/pdf"), None, None)
            .await
            .map_err(|e| format!("store document: {e}"))?;
        let bin_out = store_file(&cap, Bytes::from(big.clone()), &bin_name, Some("application/octet-stream"), None, None)
            .await
            .map_err(|e| format!("store binary: {e}"))?;

        // Sanity: the store path routed each into its category prefix.
        for (out, want) in [
            (&img_out, "ai/image/"),
            (&note_out, "ai/note/"),
            (&doc_out, "ai/document/"),
            (&bin_out, "ai/file/"),
        ] {
            if !out.key.starts_with(want) {
                return Err(format!("stored key {} not under {want}", out.key));
            }
        }
        let stored_keys = [
            img_out.key.clone(),
            note_out.key.clone(),
            doc_out.key.clone(),
            bin_out.key.clone(),
        ];

        // ───────────── list_files (whole ai/ scope) ─────────────
        let all = list_files(&cap, &ListFilter::default())
            .await
            .map_err(|e| format!("list_files(all): {e}"))?;

        // Every stored key must appear, with the right category.
        let find = |k: &str| all.iter().find(|e| e.key == k);
        for (key, want_cat) in [
            (&img_out.key, Category::Image),
            (&note_out.key, Category::Note),
            (&doc_out.key, Category::Document),
            (&bin_out.key, Category::File),
        ] {
            match find(key) {
                Some(e) if e.category == want_cat => {}
                Some(e) => {
                    return Err(format!(
                        "listed {key} has category {:?}, expected {want_cat:?}",
                        e.category
                    ))
                }
                None => return Err(format!("stored key {key} missing from list_files(all)")),
            }
        }

        // Confinement: EVERY listed entry must be inside ai/ (no user-bucket key).
        for e in &all {
            if !e.key.starts_with("ai/") {
                return Err(format!("list_files leaked a non-ai/ key: {}", e.key));
            }
        }

        // ───────────── list_files by category ─────────────
        let images = list_files(
            &cap,
            &ListFilter { category: Some(Category::Image), prefix: None },
        )
        .await
        .map_err(|e| format!("list_files(image): {e}"))?;
        // Must contain our image and NOT the note/doc/bin; all results category=Image.
        if !images.iter().any(|e| e.key == img_out.key) {
            return Err("category list (image) missing the stored image".to_string());
        }
        for e in &images {
            if e.category != Category::Image {
                return Err(format!("category list (image) returned {:?}: {}", e.category, e.key));
            }
            if e.key == note_out.key || e.key == doc_out.key || e.key == bin_out.key {
                return Err(format!("category list (image) wrongly included {}", e.key));
            }
        }

        // ───────────── search by filename fragment ─────────────
        // The tag is unique to this run; searching it returns exactly our 4 files.
        let hits = search(&cap, &tag)
            .await
            .map_err(|e| format!("search({tag}): {e}"))?;
        let hit_keys: std::collections::HashSet<&str> =
            hits.iter().map(|e| e.key.as_str()).collect();
        for k in &stored_keys {
            if !hit_keys.contains(k.as_str()) {
                return Err(format!("search({tag}) missing stored key {k}"));
            }
        }
        // And every hit is one of ours (the tag is unique) and inside ai/.
        for e in &hits {
            if !e.key.starts_with("ai/") {
                return Err(format!("search leaked a non-ai/ key: {}", e.key));
            }
        }

        // A narrower fragment that matches only one filename ("report" → the pdf).
        let report_hits = search(&cap, "report")
            .await
            .map_err(|e| format!("search(report): {e}"))?;
        if !report_hits.iter().any(|e| e.key == doc_out.key) {
            return Err("search(report) missing the document".to_string());
        }
        if report_hits.iter().any(|e| e.key == img_out.key) {
            return Err("search(report) wrongly matched the image".to_string());
        }

        // ───────────── cleanup objects ─────────────
        for out in [&img_out, &note_out, &doc_out, &bin_out] {
            let _ = client.delete_object_flat(&out.bucket, &out.key).await;
        }

        Ok(())
    }
    .await;

    // ---- Cleanup that ALWAYS runs -----------------------------------------
    match client.delete_bucket(WORKSPACE_BUCKET).await {
        Ok(()) => eprintln!("cleanup: deleted workspace bucket {WORKSPACE_BUCKET}"),
        Err(e) => eprintln!(
            "note: workspace bucket {WORKSPACE_BUCKET} left behind (forest-index objects remain; \
             expected — no encrypted-client API drains them): {e}"
        ),
    }

    outcome.unwrap_or_else(|e| panic!("P7 list/search e2e failed: {e}"));
    eprintln!(
        "P7 list/search e2e OK: stored files across categories, list_files surfaced each with the \
         right category (and only ai/ keys), category filter narrowed correctly, and search matched \
         by filename fragment."
    );
}
