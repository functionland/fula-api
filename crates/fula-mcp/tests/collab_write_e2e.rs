//! LIVE collaboration WRITE integration test — `#[ignore]`d.
//!
//! Exercises `store_file` → `create_folder` → `remove_file` against a real group.
//! Marked `#[ignore]` because the group-scoped `collab_write_token` is minted by a
//! server change that is NOT deployed yet: the WRITE endpoints (`POST upload`,
//! `PUT manifest-sync`) will reject the token until then. The write path is
//! code-complete; this test is the live gate to run once the server ships.
//!
//! Run explicitly with a write-capable bundle:
//!
//! ```sh
//! FULA_MCP_CAPABILITY='{...bundle WITH collab_write_token...}' \
//!   cargo test -p fula-mcp --test collab_write_e2e -- --ignored --nocapture
//! ```

use bytes::Bytes;
use fula_mcp::capability::CapabilityBundle;
use fula_mcp::store::{create_folder, remove_file, store_file};

#[tokio::test]
#[ignore = "live write: requires a deployed server that mints/accepts a collab_write_token"]
async fn live_store_folder_and_remove() {
    let json = std::env::var("FULA_MCP_CAPABILITY")
        .expect("set FULA_MCP_CAPABILITY (with a collab_write_token) to run this ignored test");
    let cap = CapabilityBundle::from_json(&json).expect("bundle must parse");

    // create a folder
    let folder = create_folder(&cap, "/mcp-e2e")
        .await
        .expect("create_folder must succeed");
    eprintln!("created folder (manifest v{})", folder.manifest_version);

    // store a small file into it
    let content = Bytes::from_static(b"hello from fula-mcp collaboration e2e");
    let stored = store_file(
        &cap,
        content,
        "mcp-e2e.txt",
        Some("text/plain"),
        None,
        Some("/mcp-e2e"),
        None,
    )
    .await
    .expect("store_file must succeed");
    eprintln!(
        "stored {} at {} (manifest v{})",
        stored.file_id, stored.path, stored.manifest_version
    );
    assert_eq!(stored.path, "/mcp-e2e/mcp-e2e.txt");

    // remove it (tombstone)
    let removed = remove_file(&cap, &stored.file_id)
        .await
        .expect("remove_file must succeed");
    eprintln!("removed (manifest v{})", removed.manifest_version);
    assert!(removed.manifest_version > stored.manifest_version);
}
