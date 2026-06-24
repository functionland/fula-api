//! HMAC service-auth minter for the co-located pinning service (B2).
//!
//! For AI/MCP writes the request bearer is a gateway-scoped JWT
//! (`token_use=mcp_s3`, `aud=fula-s3-gateway`) — deliberately NOT a login
//! session, so the pinning service (`:6000` Go) and the storage/quota check
//! (`:3001` TS) reject it. Instead of forwarding that token, the gateway asserts
//! the user identity via a short-lived HMAC over `(user_id, exp)`. This is the
//! MINTER; the verifiers live in `pinning-service/openapi/go/service_auth.go`
//! (Go) and the TS storage check. The wire format is locked across all three by
//! the shared test vector (`shared_vector_matches_go` below).

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

/// HTTP header carrying the service-auth assertion.
pub const SERVICE_AUTH_HEADER: &str = "X-Fula-Service-Auth";

/// Validity window for a freshly minted assertion (seconds). Short — it only has
/// to outlive one pin/quota round-trip; bounds replay if ever captured.
const SERVICE_AUTH_TTL_SECS: i64 = 60;

/// Mint an `X-Fula-Service-Auth` value:
///   `v1.<b64url(user_id)>.<exp_unix>.<b64url(HMAC_SHA256(secret, "v1."+uidb64+"."+exp))>`
/// MUST match the Go/TS verifiers byte-for-byte (locked by the shared-vector test).
pub fn mint_service_auth(user_id: &str, exp_unix: i64, secret: &str) -> String {
    let uid_b64 = URL_SAFE_NO_PAD.encode(user_id.as_bytes());
    let exp_str = exp_unix.to_string();
    let msg = format!("v1.{}.{}", uid_b64, exp_str);
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts a key of any length");
    mac.update(msg.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    format!("{}.{}", msg, sig_b64)
}

/// JWT claims we READ (not verify — the token is already validated upstream) to
/// decide whether to use service-auth.
#[derive(serde::Deserialize)]
struct AuthClaims {
    sub: Option<String>,
    token_use: Option<String>,
    #[serde(default)]
    aud: serde_json::Value,
    exp: Option<i64>,
}

fn decode_jwt_claims(token: &str) -> Option<AuthClaims> {
    let mut parts = token.split('.');
    let _header = parts.next()?;
    let payload = parts.next()?;
    let bytes = URL_SAFE_NO_PAD.decode(payload).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// If `token` is an MCP-scoped JWT (`token_use == "mcp_s3"`), return a freshly
/// minted service-auth header asserting its `sub`; otherwise `None` — the caller
/// keeps using the token as a Bearer, unchanged (normal users untouched). An
/// empty `secret` disables the path (returns `None`).
pub fn service_auth_for_token(token: &str, secret: &str) -> Option<String> {
    if secret.is_empty() {
        return None;
    }
    let claims = decode_jwt_claims(token)?;
    // Defense-in-depth: mint only for a still-valid, gateway-audience MCP token.
    // The gateway validates the token upstream, but a queued pin can be drained
    // after expiry and a future caller could reach here with an unvalidated
    // token — so re-check token_use, aud, and exp from the payload before
    // minting. (This is NOT a signature check — no key here — it only narrows
    // which tokens are eligible; it does not replace the gateway's validation.)
    if claims.token_use.as_deref() != Some("mcp_s3") {
        return None;
    }
    let aud_ok = match &claims.aud {
        serde_json::Value::String(s) => s == "fula-s3-gateway",
        serde_json::Value::Array(a) => a.iter().any(|v| v.as_str() == Some("fula-s3-gateway")),
        _ => false,
    };
    if !aud_ok {
        return None;
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    if claims.exp.map_or(true, |e| e <= now) {
        return None; // original token missing exp or already expired
    }
    let sub = claims.sub.filter(|s| !s.is_empty())?;
    Some(mint_service_auth(&sub, now + SERVICE_AUTH_TTL_SECS, secret))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Locks the wire format across Rust (mint) and Go/TS (verify): the Go test
    // openapi/go/service_auth_test.go emits this exact header for these inputs.
    #[test]
    fn shared_vector_matches_go() {
        let header = mint_service_auth(
            "2d2dfffdad62ff927abba1295c73a4eab7666813280ea8b356da845e440c41ff",
            4102444800,
            "fula-pin-svc-shared-test-secret-rotate-me",
        );
        assert_eq!(
            header,
            "v1.MmQyZGZmZmRhZDYyZmY5MjdhYmJhMTI5NWM3M2E0ZWFiNzY2NjgxMzI4MGVhOGIzNTZkYTg0NWU0NDBjNDFmZg.4102444800.7kiFsUP9DMnoeP00uwbUwy4tJmTC6rpy9Dce_e-jw3U"
        );
    }

    fn token_with(claims_json: &[u8]) -> String {
        format!("hdr.{}.sig", URL_SAFE_NO_PAD.encode(claims_json))
    }

    #[test]
    fn mcp_token_mints_service_auth() {
        // valid: mcp_s3 + correct aud + far-future exp
        let t = token_with(br#"{"sub":"user-abc","token_use":"mcp_s3","aud":"fula-s3-gateway","exp":4102444800}"#);
        let got = service_auth_for_token(&t, "secret").expect("mcp token should mint");
        assert!(got.starts_with("v1."));
        // aud may also be an array that contains the expected value
        let t2 = token_with(br#"{"sub":"u","token_use":"mcp_s3","aud":["x","fula-s3-gateway"],"exp":4102444800}"#);
        assert!(service_auth_for_token(&t2, "secret").is_some());
    }

    #[test]
    fn wrong_or_missing_aud_is_none() {
        let wrong = token_with(br#"{"sub":"u","token_use":"mcp_s3","aud":"someone-else","exp":4102444800}"#);
        assert!(service_auth_for_token(&wrong, "secret").is_none());
        let missing = token_with(br#"{"sub":"u","token_use":"mcp_s3","exp":4102444800}"#);
        assert!(service_auth_for_token(&missing, "secret").is_none());
    }

    #[test]
    fn expired_or_missing_exp_is_none() {
        let expired = token_with(br#"{"sub":"u","token_use":"mcp_s3","aud":"fula-s3-gateway","exp":100}"#);
        assert!(service_auth_for_token(&expired, "secret").is_none());
        let missing = token_with(br#"{"sub":"u","token_use":"mcp_s3","aud":"fula-s3-gateway"}"#);
        assert!(service_auth_for_token(&missing, "secret").is_none());
    }

    #[test]
    fn non_mcp_token_uses_bearer() {
        let t = token_with(br#"{"sub":"u","token_use":"storage"}"#);
        assert!(service_auth_for_token(&t, "secret").is_none());
    }

    #[test]
    fn empty_secret_disables() {
        let t = token_with(br#"{"sub":"u","token_use":"mcp_s3"}"#);
        assert!(service_auth_for_token(&t, "").is_none());
    }

    #[test]
    fn garbage_token_is_none() {
        assert!(service_auth_for_token("not-a-jwt", "secret").is_none());
    }
}
