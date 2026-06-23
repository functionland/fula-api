//! # `retry` — refresh-on-auth-error, retry-once wrapper (L1c)
//!
//! The shared glue that turns the [`crate::refresh`] HTTP helper + the bundle's
//! swappable JWT into a *transparent* recovery for the four AI-workspace ops
//! (`store` / `read` / `list` / `tags`). It wraps a SINGLE gateway call so that:
//!
//! 1. the call runs once;
//! 2. if it fails with a **gateway auth rejection** (the short scoped JWT
//!    expired) AND a `refresh_token` is configured, the wrapper silently
//!    refreshes the JWT ([`crate::refresh::refresh_connection_jwt`]), swaps it in
//!    ([`CapabilityBundle::set_jwt`]), rebuilds the client, and retries **exactly
//!    once**;
//! 3. on *any* failure of the refresh / rebuild / retried call, the **original**
//!    gateway error is surfaced (never the refresh error) — the model sees the
//!    real "auth failed" outcome.
//!
//! ## Why exactly once, and why never a loop
//!
//! The control flow is a FLAT, NON-RECURSIVE match: try → (maybe) refresh → try
//! again → return. There is no path that refreshes a second time, so a
//! permanently-failing auth (a truly revoked connection, a gateway outage)
//! surfaces promptly instead of hanging in a retry loop. A retried call that
//! *also* auth-fails just returns the original error — it does NOT refresh again.
//!
//! ## Why this wraps ONE call, not a whole op
//!
//! Several ops perform multiple gateway calls (e.g. `store_file` does
//! put → list → metadata). Wrapping the *whole* op would re-run side-effecting
//! calls (a second PUT → a double write / orphan). So the wrapper is applied
//! per-gateway-call. A subtlety it handles for free: an [`EncryptedClient`] built
//! before a refresh holds the OLD JWT (the token is cloned at build time), so the
//! wrapper REBUILDS the client from `cap` for the retry — picking up the swapped
//! token. Callers that chain several calls in one op should rebuild the client
//! from `cap` after the first wrapped call so later calls also see any swap (see
//! `store.rs`); rebuilding is cheap and a no-op when no refresh happened.
//!
//! ## Backward-compatibility (byte-identical when unconfigured)
//!
//! When the bundle has no `refresh_token`, the auth-error branch is skipped and
//! the wrapper returns the gateway error UNTOUCHED — so a pre-L1c bundle behaves
//! exactly as before (the op flattens the same `ClientError` into the same
//! op-specific error variant it always did). The wrapper only ever yields a
//! `ClientError`; it never converts a `CapabilityError`, so the caller's existing
//! `cap.workspace_client()?` (with its `CapabilityError → XError::Capability`
//! mapping) stays in front of the wrapper, unchanged.
//!
//! ## Secrets
//!
//! NEVER logs the refresh token or any JWT. Emits a tracing `info!` when a
//! refresh is ATTEMPTED (an auth rejection was seen) and a `warn!` when it FAILS —
//! both carrying only bounded, non-secret context.

use std::future::Future;

use fula_client::{ClientError, EncryptedClient};

use crate::capability::CapabilityBundle;
use crate::refresh::refresh_connection_jwt;

/// The gateway S3 error codes that mean "this request's bearer JWT was rejected
/// as unauthorized / expired / invalid" — i.e. a refresh might fix it.
///
/// These are the EXACT codes the gateway emits for auth rejections, confirmed
/// against `fula-cli`:
/// - `InvalidToken` — HTTP 401; emitted for `"Token has expired"`
///   (`fula-cli/src/middleware.rs`) and other invalid-token cases — the precise
///   expired-scoped-JWT signal that L1c targets.
/// - `AccessDenied` — HTTP 403; emitted for auth-required / malformed-or-ambiguous
///   MCP token / a revoked-connection deny (`fula-cli/src/{auth,middleware}.rs`).
/// - `Unauthorized` — not currently emitted by this gateway's `S3ErrorCode`, but
///   included defensively (a standard 401 code) so a future/variant gateway that
///   uses it is handled.
///
/// The client surfaces the gateway's `<Code>` verbatim in
/// [`ClientError::S3Error::code`] (it prefers the XML `<Code>` over a
/// status-derived `HTTP401`; see `fula-client/src/error.rs::from_s3_xml`), so a
/// literal-string match on these codes is correct.
const GATEWAY_AUTH_CODES: &[&str] = &["Unauthorized", "AccessDenied", "InvalidToken"];

/// Is `err` a gateway **auth rejection** (the bearer JWT was refused for being
/// unauthorized / expired / invalid)?
///
/// True iff it is a [`ClientError::S3Error`] whose `code` is one of
/// [`GATEWAY_AUTH_CODES`]. Deliberately NARROW: a rate-limit (`SlowDown`), a
/// quota rejection (`AccountProblem`), a not-found (`NoSuchKey`/`NoSuchBucket`),
/// or any transport error is NOT an auth rejection — refreshing the JWT would not
/// help, so we must not refresh (and must not mask the real error). Matched
/// structurally on the typed `code`, never by substring on a Display string.
pub fn is_gateway_auth_error(err: &ClientError) -> bool {
    matches!(err, ClientError::S3Error { code, .. } if GATEWAY_AUTH_CODES.contains(&code.as_str()))
}

/// Run a single gateway call with L1c refresh-on-auth-error, retry-once.
///
/// `op` is an async closure that takes a freshly-built [`EncryptedClient`] and
/// performs ONE gateway call returning `Result<T, ClientError>`. `first` is the
/// client to use for the initial attempt (the caller built it from `cap`, so its
/// `CapabilityError` was already mapped — keeping it out of this wrapper). On an
/// auth rejection the wrapper rebuilds the client itself for the retry.
///
/// Semantics (flat, non-recursive — at most ONE refresh, at most ONE retry):
/// - `op(first)` succeeds → `Ok(value)`.
/// - `op(first)` fails, and it is NOT an auth error OR no `refresh_token` is
///   configured → return that error UNTOUCHED (backward-compatible path).
/// - `op(first)` fails with an auth error AND a `refresh_token` is configured →
///   refresh; on refresh success swap the JWT, rebuild the client, and run
///   `op(client2)` ONCE. Its result is returned **only if `Ok`**; on ANY failure
///   of the refresh, the rebuild, or the retried call, the **original** error is
///   returned (no second refresh, no loop).
///
/// # Type parameters
/// - `T`: the op's success value.
/// - `F`: the op closure; called at most twice (once per client), so it is `Fn`.
/// - `Fut`: the future the closure returns.
pub async fn with_refresh_retry<T, F, Fut>(
    cap: &CapabilityBundle,
    first: EncryptedClient,
    op: F,
) -> Result<T, ClientError>
where
    F: Fn(EncryptedClient) -> Fut,
    Fut: Future<Output = Result<T, ClientError>>,
{
    // Attempt 1.
    let original = match op(first).await {
        Ok(v) => return Ok(v),
        Err(e) => e,
    };

    // Only an AUTH rejection with a configured refresh token is recoverable.
    // Everything else (rate limit, quota, not-found, transport, or no refresh
    // token) surfaces the original error UNCHANGED — the backward-compatible path.
    if !(is_gateway_auth_error(&original) && cap.refresh_token().is_some()) {
        return Err(original);
    }

    // An auth rejection + a refresh token ⇒ attempt a silent refresh. NO secrets
    // in the log line (no token, no JWT, no URL).
    tracing::info!("gateway auth rejected (JWT likely expired); attempting connection-JWT refresh");

    let new_jwt = match refresh_connection_jwt(cap.refresh_url(), cap.refresh_token()).await {
        Ok(t) => t,
        Err(refresh_err) => {
            // Refresh failed (revoked / transport / non-2xx / missing-token /
            // unconfigured URL). Surface the ORIGINAL gateway error — the model
            // sees the real disconnect. Log only the bounded refresh reason.
            tracing::warn!(
                reason = %refresh_err,
                "connection-JWT refresh failed; surfacing the original gateway error"
            );
            return Err(original);
        }
    };

    // Swap the fresh JWT into the bundle so the rebuilt client (and every later
    // op on this session) uses it.
    cap.set_jwt(new_jwt);

    // Rebuild the client so it carries the swapped JWT (the `first` client held
    // the stale one). If the rebuild fails, surface the original gateway error.
    let client2 = match cap.workspace_client() {
        Ok(c) => c,
        Err(_) => return Err(original),
    };

    // Retry EXACTLY ONCE. On any failure (including a second auth rejection) we
    // return the original error — we do NOT refresh again (no loop).
    match op(client2).await {
        Ok(v) => Ok(v),
        Err(_) => Err(original),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s3(code: &str) -> ClientError {
        ClientError::S3Error {
            code: code.to_string(),
            message: "x".to_string(),
            request_id: None,
        }
    }

    // ── is_gateway_auth_error: the matcher that decides whether to refresh ───

    #[test]
    fn auth_codes_match_true() {
        // The three gateway auth-rejection codes (incl. InvalidToken — the exact
        // expired-JWT code from fula-cli middleware) must all return true.
        assert!(is_gateway_auth_error(&s3("InvalidToken")));
        assert!(is_gateway_auth_error(&s3("AccessDenied")));
        assert!(is_gateway_auth_error(&s3("Unauthorized")));
    }

    #[test]
    fn non_auth_codes_match_false() {
        // CRUX: a rate-limit / quota / not-found must NOT be treated as auth —
        // refreshing the JWT would not help and would mask the real error.
        assert!(!is_gateway_auth_error(&s3("SlowDown")), "rate-limit is not auth");
        assert!(!is_gateway_auth_error(&s3("AccountProblem")), "quota is not auth");
        assert!(!is_gateway_auth_error(&s3("NoSuchKey")), "not-found is not auth");
        assert!(!is_gateway_auth_error(&s3("NoSuchBucket")));
        assert!(!is_gateway_auth_error(&s3("InternalError")));
        // A non-S3 transport error is never an auth rejection.
        assert!(!is_gateway_auth_error(&ClientError::UploadFailed("reset".into())));
        // Case-sensitive: a lowercased code is NOT a match (the gateway emits the
        // exact PascalCase code).
        assert!(!is_gateway_auth_error(&s3("invalidtoken")));
    }

    // ── with_refresh_retry: end-to-end through the wrapper, offline ──────────
    //
    // We drive the wrapper with closures that count calls and return canned
    // results, and a bundle whose refresh URL points at a LOCAL stub TcpListener
    // (so the real reqwest POST in refresh_connection_jwt has a deterministic
    // response with no external network). This exercises the actual
    // refresh-then-retry path, not a mock of it.

    use base64::Engine as _;
    use fula_crypto::SecretKey;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Spawn a one-shot HTTP/1.1 stub that replies to the FIRST connection with
    /// `status` + `json_body`, then returns its `http://127.0.0.1:port/...` URL.
    /// Loopback-only, so it passes the bundle's HTTPS-or-loopback validation.
    async fn spawn_refresh_stub(status_line: &'static str, json_body: &'static str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                // Read (and discard) the request headers+body enough to not RST.
                let mut buf = [0u8; 2048];
                let _ = sock.read(&mut buf).await;
                let resp = format!(
                    "{status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{json_body}",
                    json_body.len()
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.flush().await;
            }
        });
        format!("http://{addr}/api/mcp/tokens/refresh-connection")
    }

    /// A bundle whose refresh_url is `refresh_url` and which carries (or not) a
    /// refresh token. The endpoint is loopback-invalid for storage (never hit —
    /// the op closures are canned), and the refresh_url is the local stub.
    fn bundle_with_refresh(refresh_url: &str, with_token: bool) -> CapabilityBundle {
        let ws = base64::engine::general_purpose::STANDARD.encode([1u8; 32]);
        let mcp = base64::engine::general_purpose::STANDARD.encode([2u8; 32]);
        let owner = base64::engine::general_purpose::STANDARD
            .encode(SecretKey::from_bytes(&[3u8; 32]).unwrap().public_key().as_bytes());
        let token_field = if with_token {
            r#""refresh_token": "rt-secret","#
        } else {
            ""
        };
        let json = format!(
            r#"{{ "endpoint": "https://gw.invalid", "jwt": "old-jwt", {token_field} "refresh_url": "{refresh_url}", "workspace_secret_b64": "{ws}", "mcp_secret_b64": "{mcp}", "owner_public_b64": "{owner}", "grants": [] }}"#
        );
        CapabilityBundle::from_json(&json).unwrap()
    }

    #[tokio::test]
    async fn success_first_try_does_not_refresh_or_rebuild() {
        // No failure → op runs once, returns Ok; no refresh attempted.
        let cap = bundle_with_refresh("https://webui.invalid/refresh", true);
        let calls = Arc::new(AtomicU32::new(0));
        let c = calls.clone();
        let first = cap.workspace_client().unwrap();
        let out: Result<u32, ClientError> = with_refresh_retry(&cap, first, move |_client| {
            let c = c.clone();
            async move {
                c.fetch_add(1, Ordering::SeqCst);
                Ok(42)
            }
        })
        .await;
        assert_eq!(out.unwrap(), 42);
        assert_eq!(calls.load(Ordering::SeqCst), 1, "op runs exactly once on success");
    }

    #[tokio::test]
    async fn non_auth_error_surfaces_unchanged_without_refresh() {
        // A rate-limit error is NOT auth → returned untouched, op runs once, NO
        // refresh. (Backward-compatible behavior + the narrow matcher.)
        let cap = bundle_with_refresh("https://webui.invalid/refresh", true);
        let calls = Arc::new(AtomicU32::new(0));
        let c = calls.clone();
        let first = cap.workspace_client().unwrap();
        let out: Result<u32, ClientError> = with_refresh_retry(&cap, first, move |_client| {
            let c = c.clone();
            async move {
                c.fetch_add(1, Ordering::SeqCst);
                Err(ClientError::S3Error {
                    code: "SlowDown".into(),
                    message: "slow".into(),
                    request_id: None,
                })
            }
        })
        .await;
        assert!(matches!(out, Err(ClientError::S3Error { code, .. }) if code == "SlowDown"));
        assert_eq!(calls.load(Ordering::SeqCst), 1, "no retry for a non-auth error");
    }

    #[tokio::test]
    async fn auth_error_without_refresh_token_surfaces_unchanged() {
        // CRUX of backward-compat: an auth error but NO refresh_token configured →
        // the original auth error surfaces, op runs once, no refresh attempted.
        let cap = bundle_with_refresh("https://webui.invalid/refresh", false);
        let calls = Arc::new(AtomicU32::new(0));
        let c = calls.clone();
        let first = cap.workspace_client().unwrap();
        let out: Result<u32, ClientError> = with_refresh_retry(&cap, first, move |_client| {
            let c = c.clone();
            async move {
                c.fetch_add(1, Ordering::SeqCst);
                Err(ClientError::S3Error {
                    code: "InvalidToken".into(),
                    message: "Token has expired".into(),
                    request_id: None,
                })
            }
        })
        .await;
        assert!(
            matches!(out, Err(ClientError::S3Error { code, .. }) if code == "InvalidToken"),
            "no refresh token ⇒ original auth error surfaces"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1, "no retry without a refresh token");
    }

    #[tokio::test]
    async fn auth_error_then_successful_refresh_retries_once_and_swaps_jwt() {
        // The full happy recovery: attempt 1 auth-fails, the stub returns a fresh
        // token, the wrapper swaps it + retries, attempt 2 succeeds. The op sees
        // exactly 2 calls and the bundle JWT is swapped.
        let url = spawn_refresh_stub("HTTP/1.1 200 OK", r#"{"token":"fresh.jwt","jti":"j","expiresAt":"z"}"#).await;
        let cap = bundle_with_refresh(&url, true);
        let calls = Arc::new(AtomicU32::new(0));
        let c = calls.clone();
        let first = cap.workspace_client().unwrap();
        let out: Result<&'static str, ClientError> = with_refresh_retry(&cap, first, move |_client| {
            let c = c.clone();
            async move {
                let n = c.fetch_add(1, Ordering::SeqCst);
                if n == 0 {
                    Err(ClientError::S3Error {
                        code: "InvalidToken".into(),
                        message: "expired".into(),
                        request_id: None,
                    })
                } else {
                    Ok("ok-after-refresh")
                }
            }
        })
        .await;
        assert_eq!(out.unwrap(), "ok-after-refresh");
        assert_eq!(calls.load(Ordering::SeqCst), 2, "exactly one retry after refresh");
        // The bundle now carries the refreshed JWT.
        let swapped = cap
            .workspace_client()
            .unwrap()
            .inner()
            .config()
            .access_token
            .clone();
        assert_eq!(swapped.as_deref(), Some("fresh.jwt"), "JWT was swapped in");
    }

    #[tokio::test]
    async fn revoked_refresh_surfaces_original_error_no_retry() {
        // The refresh endpoint 403s ⇒ the connection is REVOKED (terminal). The
        // wrapper surfaces the ORIGINAL gateway auth error and does NOT retry the
        // op (it stays at 1 call) — the real disconnect.
        let url = spawn_refresh_stub("HTTP/1.1 403 Forbidden", r#"{"error":"revoked"}"#).await;
        let cap = bundle_with_refresh(&url, true);
        let calls = Arc::new(AtomicU32::new(0));
        let c = calls.clone();
        let first = cap.workspace_client().unwrap();
        let out: Result<u32, ClientError> = with_refresh_retry(&cap, first, move |_client| {
            let c = c.clone();
            async move {
                c.fetch_add(1, Ordering::SeqCst);
                Err(ClientError::S3Error {
                    code: "AccessDenied".into(),
                    message: "denied".into(),
                    request_id: None,
                })
            }
        })
        .await;
        assert!(
            matches!(out, Err(ClientError::S3Error { code, .. }) if code == "AccessDenied"),
            "a revoked refresh surfaces the ORIGINAL gateway error"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1, "no op retry when the connection is revoked");
    }

    #[tokio::test]
    async fn retry_that_also_auth_fails_returns_original_without_second_refresh() {
        // The no-loop guarantee: refresh succeeds, but the RETRIED op auth-fails
        // again. The wrapper must return the ORIGINAL error and NOT refresh a
        // second time. We prove "no second refresh" by pointing the refresh_url at
        // a ONE-SHOT stub: a second refresh would hit a dead port and could only
        // change the JWT — instead the JWT is swapped exactly once (to the single
        // stub's token), and the op runs exactly twice.
        let url = spawn_refresh_stub("HTTP/1.1 200 OK", r#"{"token":"second.jwt"}"#).await;
        let cap = bundle_with_refresh(&url, true);
        let calls = Arc::new(AtomicU32::new(0));
        let c = calls.clone();
        let first = cap.workspace_client().unwrap();
        let out: Result<u32, ClientError> = with_refresh_retry(&cap, first, move |_client| {
            let c = c.clone();
            async move {
                c.fetch_add(1, Ordering::SeqCst);
                // ALWAYS auth-fail (both attempts).
                Err(ClientError::S3Error {
                    code: "InvalidToken".into(),
                    message: "still expired".into(),
                    request_id: None,
                })
            }
        })
        .await;
        assert!(
            matches!(out, Err(ClientError::S3Error { code, .. }) if code == "InvalidToken"),
            "the original auth error surfaces after a single failed retry"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "op runs exactly twice: initial + ONE retry (never a third)"
        );
        // The JWT was swapped exactly once (to the single stub's token); a second
        // refresh never happened.
        let swapped = cap
            .workspace_client()
            .unwrap()
            .inner()
            .config()
            .access_token
            .clone();
        assert_eq!(swapped.as_deref(), Some("second.jwt"));
    }
}
