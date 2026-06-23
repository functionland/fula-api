//! # `refresh` — silent connection-JWT auto-refresh (L1c)
//!
//! The MCP holds a long-lived **connection refresh token** (delivered in the
//! capability bundle, see [`crate::capability`]). The scoped gateway JWT it uses
//! for storage ops is short-lived; when it expires, a gateway op is rejected with
//! an auth error. Rather than tearing the paired connection down (which would
//! force the user to re-pair), the MCP silently mints a fresh scoped JWT:
//!
//! 1. POST `{refresh_url}` (pinning-webui's
//!    `/api/mcp/tokens/refresh-connection`) with `{ "refresh_token": "<token>" }`.
//! 2. Parse the fresh JWT from the response field **`token`** (the L1a contract
//!    returns `{ token, jti, expiresAt }` — NOT `jwt`).
//! 3. Swap it into the bundle ([`crate::capability::CapabilityBundle::set_jwt`])
//!    and retry the failed op **exactly once** (the op layer owns the retry; see
//!    [`crate::retry`]).
//!
//! ## Expired vs. REVOKED — the load-bearing distinction
//!
//! A refresh that itself returns **401/403** means the connection was **revoked**
//! (pinning-webui no longer honors this refresh token), not merely expired — that
//! is the real disconnect, and we must NOT keep trying. We surface it as the
//! terminal [`RefreshError::Revoked`]. Every other failure (transport, non-auth
//! HTTP status, a 2xx body missing `token`) is its own error. The op layer treats
//! *all* refresh failures the same way — give up and surface the original gateway
//! error — so the model sees one clean "auth failed" signal; the variants exist
//! for precise tests + logging, never to drive a second attempt.
//!
//! ## Secrets
//!
//! Neither the `refresh_token` nor any JWT is EVER logged here (or placed in an
//! error value). The error type carries only bounded, secret-free context (an
//! HTTP status number, a static reason). This mirrors the quota module's
//! discipline.
//!
//! ## Structure (mirrors [`crate::quota`])
//!
//! The policy lives in a PURE function, [`parse_refresh_response`], that maps an
//! HTTP `(status, body)` to `Result<String, RefreshError>` with zero I/O — so
//! every branch (revoked / non-auth status / missing-token / good) is a plain
//! unit test needing no mock server. The thin async wrapper
//! [`refresh_connection_jwt`] only gathers the response (with a short timeout) and
//! hands it to the pure parser; a transport failure short-circuits to
//! [`RefreshError::Transport`].

use std::time::Duration;

use thiserror::Error;

/// The per-request timeout for the refresh call. SHORT (matches the quota
/// pre-check's 5s ceiling): a refresh sits on the critical path of a retried op,
/// so it must not hang. A timeout becomes [`RefreshError::Transport`] →
/// the op layer surfaces the original gateway error.
const REFRESH_TIMEOUT: Duration = Duration::from_secs(5);

/// Why a connection-JWT refresh failed.
///
/// Bounded + secret-free: NO variant carries a URL, the refresh token, a JWT, or
/// a raw response body — only an HTTP status number or a static reason — so the
/// whole type is safe to format into a log. The op layer collapses every variant
/// to "surface the original gateway error" (no second attempt); the distinctions
/// exist for tests + precise tracing.
#[derive(Debug, Error)]
pub enum RefreshError {
    /// The refresh endpoint rejected the refresh token with an auth status
    /// (401/403). The connection was **REVOKED**, not merely expired — terminal.
    /// This is the real disconnect; do not retry.
    #[error("connection refresh rejected (revoked): HTTP {status}")]
    Revoked {
        /// The auth status (401 or 403). Bounded, non-secret.
        status: u16,
    },

    /// The refresh request could not be sent / timed out / DNS / TLS — a
    /// transport-level failure (no usable HTTP response).
    #[error("connection refresh transport error")]
    Transport,

    /// The refresh endpoint returned a non-2xx status that is NOT an auth
    /// rejection (e.g. 500/503/404). Transient or misconfiguration — surface the
    /// original error, do not retry.
    #[error("connection refresh failed: HTTP {status}")]
    HttpStatus {
        /// The non-2xx, non-auth status. Bounded, non-secret.
        status: u16,
    },

    /// A 2xx response whose body could not be parsed, or did not carry a
    /// non-empty `token` field (e.g. wrong endpoint / renamed field). We refuse
    /// to swap in a missing/empty token.
    #[error("connection refresh response missing a usable `token`")]
    MissingToken,

    /// No refresh URL and/or refresh token was configured, so a refresh cannot
    /// even be attempted. (The op layer only calls the refresh when a
    /// `refresh_token` is present, but the URL may still be `None` if neither
    /// `refresh_url` nor `storage_api_url` was set — see
    /// [`crate::capability::CapabilityBundle::refresh_url`].)
    #[error("connection refresh not configured (missing refresh URL or token)")]
    NotConfigured,
}

/// PURE policy: map a refresh HTTP `(status, body)` to a fresh JWT or a
/// [`RefreshError`]. Zero I/O — the whole expired-vs-revoked decision lives here
/// so every branch is a unit test with no network.
///
/// - **401 / 403** → [`RefreshError::Revoked`] (terminal; the connection is
///   revoked, not merely expired).
/// - any other **non-2xx** → [`RefreshError::HttpStatus`].
/// - a **2xx** body that parses and carries a non-empty `token` → `Ok(token)`.
/// - a **2xx** body that does not parse, or lacks/empties `token` →
///   [`RefreshError::MissingToken`].
///
/// The body is parsed leniently as JSON and only the `token` field is read (the
/// L1a contract also returns `jti` + `expiresAt`, which we ignore). We parse
/// `token`, deliberately NOT `jwt`.
pub fn parse_refresh_response(status: u16, body: &[u8]) -> Result<String, RefreshError> {
    // Auth rejection of the REFRESH TOKEN itself ⇒ the connection is revoked.
    // This is checked BEFORE the generic non-2xx branch so 401/403 is terminal.
    if status == 401 || status == 403 {
        return Err(RefreshError::Revoked { status });
    }
    if !(200..300).contains(&status) {
        return Err(RefreshError::HttpStatus { status });
    }

    // 2xx: parse the body and pull `token`. Any parse failure, a missing field,
    // or an empty value is a MissingToken (we never swap in nothing).
    let parsed: serde_json::Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => return Err(RefreshError::MissingToken),
    };
    match parsed.get("token").and_then(|t| t.as_str()) {
        Some(t) if !t.is_empty() => Ok(t.to_string()),
        _ => Err(RefreshError::MissingToken),
    }
}

/// Refresh the scoped gateway JWT against pinning-webui's refresh endpoint.
///
/// POSTs `{ "refresh_token": <token> }` to `refresh_url` with a short timeout and
/// returns the fresh JWT parsed from the response field `token`. The
/// expired-vs-revoked policy lives in [`parse_refresh_response`]; this wrapper
/// only gathers the response (mapping a send/timeout failure to
/// [`RefreshError::Transport`]).
///
/// `refresh_url` / `refresh_token` are passed in (rather than read from a global)
/// so the bundle can supply its private fields without exposing them — exactly
/// like [`crate::quota::check_quota_http`]. A `None`/empty URL or token short-
/// circuits to [`RefreshError::NotConfigured`] with NO network touched.
///
/// # Secrets
/// NEVER logs the `refresh_token` or the returned JWT. Returns only bounded,
/// secret-free [`RefreshError`] values.
pub async fn refresh_connection_jwt(
    refresh_url: Option<&str>,
    refresh_token: Option<&str>,
) -> Result<String, RefreshError> {
    let url = match refresh_url {
        Some(u) if !u.is_empty() => u,
        _ => return Err(RefreshError::NotConfigured),
    };
    let token = match refresh_token {
        Some(t) if !t.is_empty() => t,
        _ => return Err(RefreshError::NotConfigured),
    };

    let client = match reqwest::Client::builder().timeout(REFRESH_TIMEOUT).build() {
        Ok(c) => c,
        Err(_) => return Err(RefreshError::Transport),
    };

    // The refresh token travels in the JSON BODY (not a header / query) so it is
    // not captured in URL logs. serde_json::json! handles escaping.
    let resp = match client
        .post(url)
        .json(&serde_json::json!({ "refresh_token": token }))
        .send()
        .await
    {
        Ok(r) => r,
        Err(_) => return Err(RefreshError::Transport),
    };

    let status = resp.status().as_u16();
    // Read the body for the 2xx parse path; on a read failure fall back to an
    // empty body, which the pure parser treats as MissingToken on 2xx (and is
    // irrelevant on a non-2xx/auth status).
    let body = resp.bytes().await.map(|b| b.to_vec()).unwrap_or_default();
    parse_refresh_response(status, &body)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(json: &str) -> Vec<u8> {
        json.as_bytes().to_vec()
    }

    // ── parse_refresh_response: the expired-vs-revoked policy, every branch ──

    #[test]
    fn parses_token_from_2xx_body() {
        // The happy path: a 2xx body carrying `token` (plus the L1a `jti` /
        // `expiresAt`, which we ignore) yields the fresh JWT.
        let out = parse_refresh_response(
            200,
            &body(r#"{"token":"new.jwt.value","jti":"abc123","expiresAt":"2026-01-01T00:00:00Z"}"#),
        )
        .unwrap();
        assert_eq!(out, "new.jwt.value");
    }

    #[test]
    fn parses_token_on_201_too() {
        // Any 2xx is accepted, not just 200.
        let out = parse_refresh_response(201, &body(r#"{"token":"t2"}"#)).unwrap();
        assert_eq!(out, "t2");
    }

    #[test]
    fn revoked_on_401_and_403_is_terminal() {
        // CRUX of expired-vs-revoked: an auth rejection of the REFRESH TOKEN means
        // the connection is revoked (terminal), distinct from the expired-JWT case
        // that triggered the refresh. Must be Revoked, NOT HttpStatus.
        for status in [401u16, 403] {
            let err = parse_refresh_response(status, &body(r#"{"error":"revoked"}"#)).unwrap_err();
            assert!(
                matches!(err, RefreshError::Revoked { status: s } if s == status),
                "HTTP {status} must be terminal Revoked, got {err:?}"
            );
        }
    }

    #[test]
    fn non_auth_non_2xx_is_http_status_not_revoked() {
        // A transient/misconfig non-2xx (500/503/404/429) is HttpStatus — NOT
        // Revoked (we only treat 401/403 as revocation).
        for status in [404u16, 429, 500, 503] {
            let err = parse_refresh_response(status, &body("whatever")).unwrap_err();
            assert!(
                matches!(err, RefreshError::HttpStatus { status: s } if s == status),
                "HTTP {status} must be HttpStatus, got {err:?}"
            );
        }
    }

    #[test]
    fn missing_token_field_on_2xx_is_missing_token() {
        // A 2xx body WITHOUT `token` (wrong endpoint / renamed field) → we refuse
        // to swap in nothing. Note `jwt` is NOT accepted as an alias.
        let err = parse_refresh_response(200, &body(r#"{"jwt":"wrong-field-name"}"#)).unwrap_err();
        assert!(matches!(err, RefreshError::MissingToken), "got {err:?}");
        // Also: a present-but-empty token is rejected.
        let err2 = parse_refresh_response(200, &body(r#"{"token":""}"#)).unwrap_err();
        assert!(matches!(err2, RefreshError::MissingToken), "got {err2:?}");
    }

    #[test]
    fn malformed_2xx_body_is_missing_token() {
        // A 2xx body that is not JSON at all → MissingToken (never a panic).
        let err = parse_refresh_response(200, &body("not json at all")).unwrap_err();
        assert!(matches!(err, RefreshError::MissingToken), "got {err:?}");
        // Empty body too.
        let err2 = parse_refresh_response(200, &[]).unwrap_err();
        assert!(matches!(err2, RefreshError::MissingToken), "got {err2:?}");
    }

    // ── refresh_connection_jwt: unconfigured short-circuits (no network) ─────

    #[tokio::test]
    async fn unconfigured_url_or_token_short_circuits_without_network() {
        // No URL → NotConfigured, no network touched.
        assert!(matches!(
            refresh_connection_jwt(None, Some("rt")).await.unwrap_err(),
            RefreshError::NotConfigured
        ));
        // Empty URL is treated the same.
        assert!(matches!(
            refresh_connection_jwt(Some(""), Some("rt")).await.unwrap_err(),
            RefreshError::NotConfigured
        ));
        // URL but no token → NotConfigured.
        assert!(matches!(
            refresh_connection_jwt(Some("https://webui.example/refresh"), None)
                .await
                .unwrap_err(),
            RefreshError::NotConfigured
        ));
        // Empty token too.
        assert!(matches!(
            refresh_connection_jwt(Some("https://webui.example/refresh"), Some(""))
                .await
                .unwrap_err(),
            RefreshError::NotConfigured
        ));
    }

    #[test]
    fn refresh_error_display_is_secret_free() {
        // The Display of every variant must be bounded and carry no secret marker
        // (no token, no URL). A status number is fine.
        let errs = [
            RefreshError::Revoked { status: 403 },
            RefreshError::Transport,
            RefreshError::HttpStatus { status: 500 },
            RefreshError::MissingToken,
            RefreshError::NotConfigured,
        ];
        for e in errs {
            let s = format!("{e}");
            assert!(!s.is_empty());
            assert!(!s.to_lowercase().contains("bearer"));
            assert!(!s.contains("refresh_token"));
        }
    }
}
