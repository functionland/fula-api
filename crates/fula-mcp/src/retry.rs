//! # `retry` — collab write-token refresh-on-auth, retry-once wrapper
//!
//! The collaboration WRITE endpoints (`PUT manifest-sync`, `POST upload`) carry a
//! group-scoped Bearer (`collab_write_token`). That token is short-lived; when it
//! expires the endpoint replies 401/403 ([`crate::collab::CollabError::Auth`]).
//! Rather than fail the write, the MCP silently re-mints the token and retries
//! **exactly once**:
//!
//! 1. run the write with the current token;
//! 2. if it fails with [`CollabError::Auth`] AND a `refresh_token` + `refresh_url`
//!    are configured, POST the refresh ([`crate::refresh::refresh_connection_jwt`],
//!    whose `{refresh_token} → {token}` wire shape the write-token minting reuses),
//!    swap the new token into the bundle ([`CapabilityBundle::set_collab_write_token`]),
//!    and retry the write **once** with it;
//! 3. on ANY failure of the refresh / retried write, surface the **original**
//!    `Auth` error (never the refresh error) — no second refresh, no loop.
//!
//! ## Why this wraps ONE write call, not a whole op
//!
//! `store_file` performs two writes (`POST upload` then `PUT manifest-sync`).
//! Wrapping the whole op would re-run a side-effecting call (a double upload). So
//! the wrapper is applied per write call. Retrying is safe here because an `Auth`
//! rejection means the server did NOT apply the write (no partial effect to undo).
//!
//! ## Backward-compatible & secret-safe
//!
//! With no `refresh_token`/`refresh_url`, the auth branch is skipped and the
//! original error surfaces unchanged. Neither the token nor the refresh token is
//! ever logged (only a bounded `info!`/`warn!` with no secret context).

use std::future::Future;

use crate::capability::CapabilityBundle;
use crate::collab::CollabError;
use crate::refresh::refresh_connection_jwt;

/// Run a single collab WRITE call with refresh-on-auth, retry-once.
///
/// `op` is an async closure that takes the current write token (by value, so it is
/// callable twice) and performs ONE write returning `Result<T, CollabError>`. For
/// a body-carrying write (`upload`), the closure should clone its payload per call.
///
/// Semantics (flat, non-recursive — at most ONE refresh, at most ONE retry):
/// - no `collab_write_token` configured → [`CollabError::WriteNotConfigured`]
///   (no network touched);
/// - `op` succeeds → `Ok(value)`;
/// - `op` fails with anything OTHER than [`CollabError::Auth`], or with `Auth` but
///   no refresh configured → that error UNCHANGED;
/// - `op` fails with `Auth` AND a refresh is configured → re-mint the token, swap
///   it in, run `op` ONCE more. Its result is returned only if `Ok`; on ANY
///   failure of the refresh or the retried write, the **original** `Auth` error is
///   returned.
pub async fn with_collab_write_retry<T, F, Fut>(
    cap: &CapabilityBundle,
    op: F,
) -> Result<T, CollabError>
where
    F: Fn(String) -> Fut,
    Fut: Future<Output = Result<T, CollabError>>,
{
    let token = match cap.collab_write_token() {
        Some(t) => t,
        None => return Err(CollabError::WriteNotConfigured),
    };

    // Attempt 1.
    let original = match op(token).await {
        Ok(v) => return Ok(v),
        Err(e) => e,
    };

    // Only an AUTH rejection with a configured refresh is recoverable. Everything
    // else (transport, non-auth status, not-found, not-configured) surfaces
    // unchanged.
    let recoverable = matches!(original, CollabError::Auth { .. })
        && cap.refresh_token().is_some()
        && cap.refresh_url().is_some();
    if !recoverable {
        return Err(original);
    }

    tracing::info!(
        "collab write auth rejected (write token likely expired); attempting write-token refresh"
    );

    let new_token = match refresh_connection_jwt(cap.refresh_url(), cap.refresh_token()).await {
        Ok(t) => t,
        Err(refresh_err) => {
            tracing::warn!(
                reason = %refresh_err,
                "collab write-token refresh failed; surfacing the original auth error"
            );
            return Err(original);
        }
    };

    // Swap the fresh token in so the retry (and any later write this session) uses
    // it.
    cap.set_collab_write_token(new_token.clone());

    // Retry EXACTLY ONCE. On any failure, surface the original error (no loop).
    match op(new_token).await {
        Ok(v) => Ok(v),
        Err(_) => Err(original),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fula_crypto::{sharing::ShareBuilder, DekKey, KekKeyPair};
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// A one-shot loopback HTTP/1.1 stub for the refresh endpoint.
    async fn spawn_refresh_stub(status_line: &'static str, json_body: &'static str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
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

    fn temp_identity_path(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "fula_mcp_retry_test_{}_{}_{:?}",
            tag,
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("mcp_identity.key")
    }

    /// Build a bundle with the given refresh_url + optional refresh_token +
    /// optional write token, wrapping a link secret for a fresh local identity.
    fn test_bundle(
        tag: &str,
        refresh_url: &str,
        with_refresh_token: bool,
        write_token: Option<&str>,
    ) -> CapabilityBundle {
        use crate::identity::McpIdentity;
        let id_path = temp_identity_path(tag);
        let _ = std::fs::remove_file(&id_path);
        let identity = McpIdentity::load_or_generate(&id_path).unwrap();
        let owner = KekKeyPair::generate();
        let dek = DekKey::from_bytes(&[9u8; 32]).unwrap();
        let token = ShareBuilder::new(&owner, identity.public_key(), &dek)
            .path_scope("/collab/g")
            .build()
            .unwrap();
        let wrapped = serde_json::to_string(&token).unwrap();
        let rt = if with_refresh_token {
            r#","refresh_token":"rt-secret""#
        } else {
            ""
        };
        let wt = match write_token {
            Some(t) => format!(r#","collab_write_token":"{t}""#),
            None => String::new(),
        };
        let json = format!(
            r#"{{"webui_base":"https://cloud.fx.land","group_id":"g","manifest_bucket":"b","manifest_key":"k","wrapped_link_secret":{wrapped:?},"identity_path":{id:?},"refresh_url":{ru:?}{rt}{wt}}}"#,
            id = id_path.to_str().unwrap(),
            ru = refresh_url,
        );
        CapabilityBundle::from_json(&json).unwrap()
    }

    #[tokio::test]
    async fn no_write_token_is_write_not_configured() {
        let cap = test_bundle("nowt", "https://webui.invalid/refresh", true, None);
        let out: Result<u32, CollabError> =
            with_collab_write_retry(&cap, |_t| async { Ok(1) }).await;
        assert!(matches!(out, Err(CollabError::WriteNotConfigured)));
    }

    #[tokio::test]
    async fn success_first_try_does_not_refresh() {
        let cap = test_bundle("ok", "https://webui.invalid/refresh", true, Some("wt"));
        let calls = Arc::new(AtomicU32::new(0));
        let c = calls.clone();
        let out: Result<u32, CollabError> = with_collab_write_retry(&cap, move |tok| {
            let c = c.clone();
            async move {
                assert_eq!(tok, "wt");
                c.fetch_add(1, Ordering::SeqCst);
                Ok(42)
            }
        })
        .await;
        assert_eq!(out.unwrap(), 42);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn non_auth_error_surfaces_without_refresh() {
        let cap = test_bundle("nonauth", "https://webui.invalid/refresh", true, Some("wt"));
        let calls = Arc::new(AtomicU32::new(0));
        let c = calls.clone();
        let out: Result<u32, CollabError> = with_collab_write_retry(&cap, move |_tok| {
            let c = c.clone();
            async move {
                c.fetch_add(1, Ordering::SeqCst);
                Err(CollabError::Status {
                    what: "upload(POST)",
                    status: 500,
                })
            }
        })
        .await;
        assert!(matches!(out, Err(CollabError::Status { status: 500, .. })));
        assert_eq!(calls.load(Ordering::SeqCst), 1, "no retry for a non-auth error");
    }

    #[tokio::test]
    async fn auth_without_refresh_token_surfaces_unchanged() {
        let cap = test_bundle("noauthtok", "https://webui.invalid/refresh", false, Some("wt"));
        let calls = Arc::new(AtomicU32::new(0));
        let c = calls.clone();
        let out: Result<u32, CollabError> = with_collab_write_retry(&cap, move |_tok| {
            let c = c.clone();
            async move {
                c.fetch_add(1, Ordering::SeqCst);
                Err(CollabError::Auth { status: 401 })
            }
        })
        .await;
        assert!(matches!(out, Err(CollabError::Auth { status: 401 })));
        assert_eq!(calls.load(Ordering::SeqCst), 1, "no retry without a refresh token");
    }

    #[tokio::test]
    async fn auth_then_refresh_retries_once_and_swaps_token() {
        let url = spawn_refresh_stub("HTTP/1.1 200 OK", r#"{"token":"fresh.wt"}"#).await;
        let cap = test_bundle("refresh", &url, true, Some("stale.wt"));
        let calls = Arc::new(AtomicU32::new(0));
        let c = calls.clone();
        let out: Result<&'static str, CollabError> = with_collab_write_retry(&cap, move |tok| {
            let c = c.clone();
            async move {
                let n = c.fetch_add(1, Ordering::SeqCst);
                if n == 0 {
                    assert_eq!(tok, "stale.wt");
                    Err(CollabError::Auth { status: 401 })
                } else {
                    assert_eq!(tok, "fresh.wt", "retry must use the refreshed token");
                    Ok("ok-after-refresh")
                }
            }
        })
        .await;
        assert_eq!(out.unwrap(), "ok-after-refresh");
        assert_eq!(calls.load(Ordering::SeqCst), 2, "exactly one retry after refresh");
        assert_eq!(cap.collab_write_token().as_deref(), Some("fresh.wt"));
    }

    #[tokio::test]
    async fn revoked_refresh_surfaces_original_no_retry() {
        let url = spawn_refresh_stub("HTTP/1.1 403 Forbidden", r#"{"error":"revoked"}"#).await;
        let cap = test_bundle("revoked", &url, true, Some("wt"));
        let calls = Arc::new(AtomicU32::new(0));
        let c = calls.clone();
        let out: Result<u32, CollabError> = with_collab_write_retry(&cap, move |_tok| {
            let c = c.clone();
            async move {
                c.fetch_add(1, Ordering::SeqCst);
                Err(CollabError::Auth { status: 403 })
            }
        })
        .await;
        assert!(matches!(out, Err(CollabError::Auth { status: 403 })));
        assert_eq!(calls.load(Ordering::SeqCst), 1, "no retry when the refresh is revoked");
    }
}
