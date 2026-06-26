//! LIVE collaboration READ integration test — env-gated, skipped offline.
//!
//! Given a REAL group's capability bundle in `FULA_MCP_CAPABILITY`, this lists the
//! group and READS every file, so a `fula`-encrypted owner file (single-block AND
//! chunked) is exercised against the live `/api/collab/*` endpoints. The chunked
//! per-chunk fetch (`{storage_key}.chunks/{i:08}` via `fula-fetch`) is the one part
//! of the decrypt recipe inferred from `fula-client` rather than pinned locally, so
//! reading a chunked file here is the meaningful live check.
//!
//! Gated on BOTH `FULA_E2E=1` and `FULA_MCP_CAPABILITY` (the bundle JSON), so it is
//! a no-op in normal/offline `cargo test`:
//!
//! ```sh
//! FULA_E2E=1 FULA_MCP_CAPABILITY='{...bundle...}' \
//!   cargo test -p fula-mcp --test collab_read_e2e -- --nocapture
//! ```

use fula_mcp::capability::CapabilityBundle;
use fula_mcp::list::{list_files, ListFilter};
use fula_mcp::read::{read_file, ReadBy};

fn gated_bundle() -> Option<CapabilityBundle> {
    if std::env::var("FULA_E2E").is_err() {
        eprintln!("skipping collab_read_e2e: set FULA_E2E=1 to run");
        return None;
    }
    let json = match std::env::var("FULA_MCP_CAPABILITY") {
        Ok(j) if !j.trim().is_empty() => j,
        _ => {
            eprintln!("skipping collab_read_e2e: FULA_MCP_CAPABILITY not set");
            return None;
        }
    };
    Some(CapabilityBundle::from_json(&json).expect("FULA_MCP_CAPABILITY must be a valid bundle"))
}

#[tokio::test]
async fn live_list_then_read_every_file() {
    let Some(cap) = gated_bundle() else { return };

    let rows = list_files(
        &cap,
        &ListFilter {
            include_directories: true,
            ..Default::default()
        },
    )
    .await
    .expect("list_files must succeed against the live group");
    eprintln!("collab_read_e2e: listed {} entries", rows.len());

    let files: Vec<_> = rows.iter().filter(|e| !e.is_directory).collect();
    assert!(
        !files.is_empty(),
        "the test group has no files to read; add one (incl. a chunked fula file) first"
    );

    let mut read_ok = 0usize;
    for f in &files {
        match read_file(&cap, &ReadBy::FileId(f.file_id.clone())).await {
            Ok(out) => {
                assert_eq!(out.file_id, f.file_id);
                assert_eq!(out.size, out.bytes.len());
                read_ok += 1;
                eprintln!(
                    "  read {} ({} bytes, enc={})",
                    out.path, out.size, out.enc_type
                );
            }
            Err(e) => panic!("failed to read {} ({}): {e}", f.path, f.file_id),
        }
    }
    assert_eq!(read_ok, files.len(), "every listed file must read+decrypt");

    // Resolving by logical path must reach the same file as by id.
    if let Some(first) = files.first() {
        let by_path = read_file(&cap, &ReadBy::Path(first.path.clone()))
            .await
            .expect("read by path");
        assert_eq!(by_path.file_id, first.file_id, "path and id must resolve identically");
    }
}
