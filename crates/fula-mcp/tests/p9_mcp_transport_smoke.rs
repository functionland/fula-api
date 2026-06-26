//! OFFLINE transport smoke test for the stdio MCP server (collaboration rework).
//!
//! Drives a real in-process rmcp **client** against [`FulaMcpServer`] over a
//! `tokio::io::duplex` pipe — the same JSON-RPC protocol the stdio transport
//! speaks. It exercises the genuine MCP handshake (`initialize` + `tools/list`)
//! and asserts the collaboration tool set is advertised with non-trivial schemas.
//! `tools/list` is pure server metadata, so this runs fully OFFLINE.
//!
//! The bundle here is a throwaway: a fresh local identity, a link secret wrapped
//! to it, and an UNREACHABLE endpoint — `tools/list` never touches the network.

use fula_crypto::{sharing::ShareBuilder, DekKey, KekKeyPair};
use fula_mcp::capability::CapabilityBundle;
use fula_mcp::identity::McpIdentity;
use fula_mcp::server::FulaMcpServer;
use rmcp::ServiceExt;

/// The collaboration tools the server must advertise.
const EXPECTED_TOOLS: [&str; 8] = [
    "fula_read_file",
    "fula_list_files",
    "fula_search",
    "fula_store_file",
    "fula_create_folder",
    "fula_remove_file",
    "fula_tag_file",
    "fula_list_tags",
];

/// A throwaway collaboration bundle: a fresh local identity, a link secret wrapped
/// to it, and an UNREACHABLE endpoint. `tools/list` is metadata, so it is never
/// dereferenced.
fn dummy_bundle() -> CapabilityBundle {
    let dir = std::env::temp_dir().join(format!(
        "fula_mcp_smoke_{}_{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let id_path = dir.join("mcp_identity.key");
    let _ = std::fs::remove_file(&id_path);

    let identity = McpIdentity::load_or_generate(&id_path).unwrap();
    let owner = KekKeyPair::generate();
    let dek = DekKey::from_bytes(&[7u8; 32]).unwrap();
    let token = ShareBuilder::new(&owner, identity.public_key(), &dek)
        .path_scope("/collab/g")
        .build()
        .unwrap();
    let wrapped = serde_json::to_string(&token).unwrap();
    let json = format!(
        r#"{{"webui_base":"https://offline.invalid","group_id":"g","manifest_bucket":"b","manifest_key":"k","wrapped_link_secret":{wrapped:?},"identity_path":{id:?}}}"#,
        id = id_path.to_str().unwrap(),
    );
    CapabilityBundle::from_json(&json).expect("dummy bundle must parse")
}

#[tokio::test]
async fn initialize_and_tools_list_advertises_all_tools_with_schemas() {
    let server = FulaMcpServer::new(dummy_bundle());

    let (server_transport, client_transport) = tokio::io::duplex(8192);

    let server_handle = tokio::spawn(async move { server.serve(server_transport).await });
    let client = ()
        .serve(client_transport)
        .await
        .expect("client initialize handshake must succeed");

    let listed = client
        .peer()
        .list_tools(None)
        .await
        .expect("tools/list must succeed");

    let names: Vec<&str> = listed.tools.iter().map(|t| t.name.as_ref()).collect();

    for expected in EXPECTED_TOOLS {
        assert!(
            names.contains(&expected),
            "tools/list is missing `{expected}`; advertised: {names:?}"
        );
    }
    assert_eq!(
        listed.tools.len(),
        EXPECTED_TOOLS.len(),
        "expected exactly {} tools, got {}: {names:?}",
        EXPECTED_TOOLS.len(),
        listed.tools.len()
    );

    for tool in &listed.tools {
        let schema = &tool.input_schema;
        assert!(!schema.is_empty(), "tool `{}` has an empty input schema", tool.name);
        let ty = schema.get("type").and_then(|v| v.as_str());
        assert_eq!(
            ty,
            Some("object"),
            "tool `{}` input schema is not an object: {schema:?}",
            tool.name
        );
        // Every tool except the zero-arg `fula_list_tags` exposes `properties`.
        if tool.name.as_ref() != "fula_list_tags" {
            assert!(
                schema.contains_key("properties"),
                "tool `{}` (takes args) is missing `properties`: {schema:?}",
                tool.name
            );
        }
    }

    // Spot-check that `fula_store_file`'s real fields wired through schemars.
    let store = listed
        .tools
        .iter()
        .find(|t| t.name.as_ref() == "fula_store_file")
        .unwrap();
    let store_props = store
        .input_schema
        .get("properties")
        .and_then(|v| v.as_object())
        .expect("fula_store_file must have properties");
    for required_field in ["content", "name", "subfolder_path"] {
        assert!(
            store_props.contains_key(required_field),
            "fula_store_file schema missing `{required_field}`: {store_props:?}"
        );
    }
    // No local-FS `path` arg on store (exfiltration risk; the subfolder is a
    // logical group path, not a filesystem path).
    assert!(
        !store_props.contains_key("path"),
        "fula_store_file must NOT expose a `path` arg"
    );

    // `fula_read_file` addresses by file_id / path.
    let read = listed
        .tools
        .iter()
        .find(|t| t.name.as_ref() == "fula_read_file")
        .unwrap();
    let read_props = read
        .input_schema
        .get("properties")
        .and_then(|v| v.as_object())
        .expect("fula_read_file must have properties");
    assert!(read_props.contains_key("file_id") && read_props.contains_key("path"));

    client.cancel().await.ok();
    server_handle.abort();
}
