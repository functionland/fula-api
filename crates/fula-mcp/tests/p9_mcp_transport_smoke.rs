//! Phase 9 — OFFLINE transport smoke test for the stdio MCP server.
//!
//! Drives a real in-process rmcp **client** against [`FulaMcpServer`] over a
//! `tokio::io::duplex` pipe — the same JSON-RPC protocol the stdio transport
//! speaks, just over an in-memory duplex instead of stdin/stdout. This exercises
//! the genuine MCP handshake end to end:
//!
//!   1. `client.serve(transport)` performs the `initialize` request/response,
//!   2. `peer().list_tools(None)` issues `tools/list`,
//!
//! and asserts all SIX `fula_*` tools are advertised, each with a non-trivial
//! input JSON schema. No gateway is needed: `tools/list` is pure server
//! metadata, so this runs fully OFFLINE and is part of the normal `cargo test`.
//!
//! Why a duplex client rather than spawning the binary: it is faithful (real
//! rmcp client ↔ real rmcp server, real `initialize` + `tools/list` frames),
//! deterministic, and needs no env-injected bundle or subprocess plumbing on
//! Windows. The bundle here is a throwaway with a deterministic dummy secret and
//! an unreachable endpoint — `tools/list` never touches it.

use base64::Engine as _;
use fula_crypto::SecretKey;
use fula_mcp::capability::CapabilityBundle;
use fula_mcp::server::FulaMcpServer;
use rmcp::ServiceExt;

/// The six tools the server must advertise.
const EXPECTED_TOOLS: [&str; 6] = [
    "fula_store_file",
    "fula_read_file",
    "fula_list_files",
    "fula_search",
    "fula_tag_file",
    "fula_list_tags",
];

/// A throwaway bundle with a deterministic dummy secret + an UNREACHABLE
/// endpoint. `tools/list` is server metadata, so this is never dereferenced.
fn dummy_bundle() -> CapabilityBundle {
    let ws = base64::engine::general_purpose::STANDARD.encode([1u8; 32]);
    let mcp = base64::engine::general_purpose::STANDARD.encode([2u8; 32]);
    let owner = base64::engine::general_purpose::STANDARD
        .encode(SecretKey::from_bytes(&[3u8; 32]).unwrap().public_key().as_bytes());
    let json = format!(
        r#"{{ "endpoint": "https://offline.invalid", "jwt": "j", "workspace_secret_b64": "{ws}", "mcp_secret_b64": "{mcp}", "owner_public_b64": "{owner}", "grants": [{{ "scope": "ai/", "permissions": {{ "can_read": true, "can_write": true, "can_delete": false }} }}] }}"#
    );
    CapabilityBundle::from_json(&json).expect("dummy bundle must parse")
}

#[tokio::test]
async fn initialize_and_tools_list_advertises_all_six_tools_with_schemas() {
    let server = FulaMcpServer::new(dummy_bundle());

    // In-memory duplex stands in for stdio. One end drives the server, the other
    // the client; `.serve()` performs the MCP `initialize` handshake on connect.
    let (server_transport, client_transport) = tokio::io::duplex(8192);

    let server_handle = tokio::spawn(async move { server.serve(server_transport).await });
    // `()` is the default no-op ClientHandler; serving it runs `initialize`.
    let client = ()
        .serve(client_transport)
        .await
        .expect("client initialize handshake must succeed");

    // `tools/list` over the wire.
    let listed = client
        .peer()
        .list_tools(None)
        .await
        .expect("tools/list must succeed");

    let names: Vec<&str> = listed.tools.iter().map(|t| t.name.as_ref()).collect();

    // All six expected tools are present (and no fewer / no extras beyond them).
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

    // Each tool carries a non-trivial input schema (an object with properties, or
    // — for the zero-arg `fula_list_tags` — at least a well-formed object schema).
    for tool in &listed.tools {
        let schema = &tool.input_schema; // Arc<Map<String, Value>>
        assert!(
            !schema.is_empty(),
            "tool `{}` has an empty input schema",
            tool.name
        );
        // The schema must declare an object type (MCP tool args are objects).
        let ty = schema.get("type").and_then(|v| v.as_str());
        assert_eq!(
            ty,
            Some("object"),
            "tool `{}` input schema is not an object: {schema:?}",
            tool.name
        );
        // Tools that take arguments must expose `properties`; only the zero-arg
        // list_tags is permitted to have none.
        if tool.name.as_ref() != "fula_list_tags" {
            assert!(
                schema.contains_key("properties"),
                "tool `{}` (takes args) is missing `properties` in its schema: {schema:?}",
                tool.name
            );
        }
    }

    // Spot-check that the key arg names made it into the schema (proves the
    // serde/schemars derivation wired the real fields, not an empty placeholder).
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
    for required_field in ["content", "name"] {
        assert!(
            store_props.contains_key(required_field),
            "fula_store_file schema missing `{required_field}` property: {store_props:?}"
        );
    }
    // And the `path` field we deliberately DROPPED must NOT be present.
    assert!(
        !store_props.contains_key("path"),
        "fula_store_file must NOT expose a local-FS `path` arg (exfiltration risk)"
    );

    client.cancel().await.ok();
    server_handle.abort();
}
