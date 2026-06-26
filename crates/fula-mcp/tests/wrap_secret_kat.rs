//! # Cross-implementation KAT: secret-wrap producer <-> local-MCP consumer
//!
//! This is the correctness GATE for the `wrap_secret_for_recipient` binding that
//! unblocks the secure "Method 2" AI-pairing. It proves the PRODUCER side
//! (`fula_crypto::sharing::wrap_secret_for_recipient` — the EXACT shared core fn
//! that both the fula-flutter / Dart binding and the fula-js / wasm binding
//! call) interoperates with the CONSUMER side already merged into the local MCP
//! (`McpIdentity::accept_link_secret`, which is `ShareRecipient::accept_share`
//! followed by `*AcceptedShare.dek.as_bytes()`).
//!
//! The wire path mirrors production exactly: wrap -> serialize to JSON (what the
//! Dart / wasm bindings hand back) -> deserialize -> accept. A green KAT here
//! means a token produced by FxFiles (Dart) or the Cloudflare Worker (wasm) is
//! byte-for-byte openable by the merged MCP, and ONLY by the addressed recipient.

use fula_crypto::sharing::wrap_secret_for_recipient;
use fula_crypto::ShareToken;
use fula_mcp::identity::McpIdentity;

/// Fixed KAT vector: the bytes `0x00..=0x1f` (the same fixed secret the merged
/// `identity::accept_link_secret` unit test and the collab-crypto vectors use).
const SECRET: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];

#[test]
fn kat_wrapped_secret_round_trips_through_mcp_accept_link_secret() {
    // The recipient is a real MCP identity (the production consumer).
    let mcp = McpIdentity::generate();

    // PRODUCER: the exact shared core fn both bindings call.
    let token = wrap_secret_for_recipient(
        &SECRET,
        mcp.public_key().as_bytes(),
        Some("/collab/group-kat"),
        Some(3600),
    )
    .expect("wrap must succeed for valid 32-byte inputs");

    // Cross the wire as JSON — exactly what the Dart / wasm bindings return.
    let token_json = serde_json::to_string(&token).expect("serialize token to JSON");
    let token_back: ShareToken =
        serde_json::from_str(&token_json).expect("deserialize token from JSON");
    assert_eq!(token_back.version, 5, "must be a strict v5 token");

    // CONSUMER: the merged local-MCP Method-2 path recovers the EXACT secret.
    let recovered = mcp
        .accept_link_secret(&token_back)
        .expect("the addressed MCP must accept its token");
    assert_eq!(
        recovered, SECRET,
        "recovered link secret must equal the original 32 bytes"
    );
}

#[test]
fn kat_different_recipient_cannot_recover() {
    let intended = McpIdentity::generate();
    let token = wrap_secret_for_recipient(&SECRET, intended.public_key().as_bytes(), None, None)
        .expect("wrap must succeed");
    let token_json = serde_json::to_string(&token).unwrap();
    let token_back: ShareToken = serde_json::from_str(&token_json).unwrap();

    // A DIFFERENT MCP identity must NOT recover the secret — the v5 AAD binds the
    // intended recipient's X25519 public key, so a mismatched key fails closed.
    let stranger = McpIdentity::generate();
    assert!(
        stranger.accept_link_secret(&token_back).is_err(),
        "a non-addressed recipient must be rejected"
    );

    // ...and the intended recipient still recovers it (guards against a
    // wholesale-reject bug masking the negative assertion above).
    assert_eq!(intended.accept_link_secret(&token_back).unwrap(), SECRET);
}

#[test]
fn kat_producer_fails_closed_on_bad_lengths() {
    let mcp = McpIdentity::generate();
    let pk = mcp.public_key().as_bytes();

    // Secret must be exactly 32 bytes.
    assert!(wrap_secret_for_recipient(&[0u8; 31], pk, None, None).is_err());
    assert!(wrap_secret_for_recipient(&[0u8; 33], pk, None, None).is_err());

    // Recipient public key must be exactly 32 bytes.
    assert!(wrap_secret_for_recipient(&SECRET, &[0u8; 31], None, None).is_err());
    assert!(wrap_secret_for_recipient(&SECRET, &[0u8; 33], None, None).is_err());

    // The all-valid call still succeeds.
    assert!(wrap_secret_for_recipient(&SECRET, pk, None, None).is_ok());
}
