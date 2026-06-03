//! Phase 3.2 A3 internal endpoints.
//!
//! Two endpoints, both bearer-token-protected:
//!
//! - `GET  /_internal/users-index-state` — returns the latest published
//!   `(global_cid, sequence, updated_at_unix)` so the 12h chain cron in
//!   `mainnet-reward-server` can fetch and submit on-chain.
//! - `POST /_internal/publish-now`       — fires a publisher tick on
//!   demand. Useful for deploy verification.
//!
//! ## Auth
//!
//! Bearer token from `users_index_publisher.config.internal_token`.
//! When `internal_token = None`: every request returns **503**
//! ("internal endpoints disabled"). Fail-closed: an operator who
//! forgets to set the token doesn't accidentally expose an unauthed
//! state-readout endpoint.
//!
//! When `internal_token = Some(t)`:
//! - missing/wrong bearer → **401**
//! - correct bearer       → **200**
//!
//! ## Wiring
//!
//! Routes are added to a dedicated branch in `routes.rs` so they bypass
//! the user-JWT auth middleware and use a small bearer-token check
//! instead. Endpoints return 503 when the publisher itself is `None`
//! (publisher feature disabled at startup) — this is the regression
//! check for "publisher disabled = byte-identical legacy behavior".

use crate::handlers::users_index_publisher::UsersIndexPublisher;
use crate::AppState;
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use fula_blockstore::FlexibleBlockStore;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// `GET /_internal/users-index-state` response body. Designed for the
/// chain cron — single deserialize, no fancy error envelopes.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct UsersIndexStateResponse {
    /// Latest published global users-index CID, or `null` if no
    /// publish has succeeded yet (fresh master).
    pub cid: Option<String>,
    /// Monotonic sequence embedded in the most recent global CBOR.
    pub sequence: u64,
    /// Wall-clock timestamp of the last successful publish.
    pub updated_at_unix: u64,
    /// IPNS key name (e.g., `fula-users-index`). Operators verify
    /// against their kubo `key list` output. Logged-only — clients
    /// resolve via the IPNS NAME (libp2p key hash), not this label.
    pub ipns_key_name: String,
}

/// `POST /_internal/publish-now` response body.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublishNowResponse {
    pub global_cid: String,
    pub sequence: u64,
    pub changed_users: usize,
    /// Number of users whose per-user CBOR pin failed this tick.
    /// Surfaces the per-user-error-tolerance count from
    /// `TickOutcome.failed_users` so an operator clicking
    /// "publish now" in the admin UI sees per-user pin failures
    /// without tailing logs. A non-zero value means the published
    /// global may exclude one or more users (or carry their prior
    /// CIDs). The per-user `warn!` lines inside `run_tick` identify
    /// WHICH users failed; this field is the count for surfacing.
    pub failed_users: usize,
    pub total_users: usize,
    pub global_rebuilt: bool,
}

/// Bearer-token check. Returns:
/// - `Ok(())` when the publisher is configured AND the bearer matches.
/// - `Err(503)` when the publisher OR `internal_token` is unset
///   (fail-closed; documented in module doc).
/// - `Err(401)` when the bearer is missing/wrong but auth IS configured.
fn authenticate(
    publisher: Option<&Arc<UsersIndexPublisher<FlexibleBlockStore>>>,
    headers: &HeaderMap,
) -> Result<(), Response> {
    let publisher = match publisher {
        Some(p) => p,
        None => {
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                "users-index publisher disabled",
            )
                .into_response());
        }
    };
    let configured = match publisher.config().internal_token.as_deref() {
        Some(t) if !t.is_empty() => t,
        _ => {
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                "internal endpoints disabled (no internal_token configured)",
            )
                .into_response());
        }
    };
    let presented = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .unwrap_or("");
    // Constant-time compare to defend against timing oracles.
    if !constant_time_eq(presented.as_bytes(), configured.as_bytes()) {
        return Err((StatusCode::UNAUTHORIZED, "invalid or missing bearer token").into_response());
    }
    Ok(())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// `GET /_internal/users-index-state`
pub async fn users_index_state(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    if let Err(resp) = authenticate(state.users_index_publisher.as_ref(), &headers) {
        return resp;
    }
    let publisher = state
        .users_index_publisher
        .as_ref()
        .expect("authenticate already proved Some");
    let latest = publisher.latest();
    let body = UsersIndexStateResponse {
        cid: latest.global_cid.map(|c| c.to_string()),
        sequence: latest.sequence,
        updated_at_unix: latest.updated_at_unix,
        ipns_key_name: publisher.config().ipns_key_name.clone(),
    };
    (StatusCode::OK, Json(body)).into_response()
}

/// `POST /_internal/publish-now`
pub async fn publish_now(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    if let Err(resp) = authenticate(state.users_index_publisher.as_ref(), &headers) {
        return resp;
    }
    let publisher = state
        .users_index_publisher
        .as_ref()
        .expect("authenticate already proved Some");
    match publisher.run_tick().await {
        Ok(outcome) => {
            let body = PublishNowResponse {
                global_cid: outcome.global_cid.to_string(),
                sequence: outcome.sequence,
                changed_users: outcome.changed_users,
                failed_users: outcome.failed_users,
                total_users: outcome.total_users,
                global_rebuilt: outcome.global_rebuilt,
            };
            (StatusCode::OK, Json(body)).into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "users-index publish-now failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("publish failed: {}", e),
            )
                .into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handlers::users_index_publisher::PublisherConfig;
    use axum::body::to_bytes;
    use axum::http::{Method, Request};
    use axum::Router;
    use fula_blockstore::MemoryBlockStore;
    use fula_core::BucketManager;
    use std::path::PathBuf;
    use std::time::Duration;
    use tempfile::TempDir;
    use tower::ServiceExt;

    /// Build a router exposing only the two internal endpoints — no
    /// JWT auth middleware in the way. Mirrors what `routes.rs` will
    /// wire, minus everything irrelevant to these endpoints.
    fn build_internal_router(state: Arc<AppState>) -> Router {
        Router::new()
            .route(
                "/_internal/users-index-state",
                axum::routing::get(users_index_state),
            )
            .route(
                "/_internal/publish-now",
                axum::routing::post(publish_now),
            )
            .with_state(state)
    }

    /// Build an `AppState` with a publisher backed by `MemoryBlockStore`,
    /// optionally wrapping it in an `Arc` to satisfy the FlexibleBlockStore
    /// type that AppState expects.
    async fn fixture_state(internal_token: Option<String>, with_publisher: bool) -> Arc<AppState> {
        // `keep()` returns the PathBuf and disables the TempDir's
        // auto-delete-on-drop. Files persist for the test process; the
        // OS cleans them up on next reboot if anything is left.
        let dir = TempDir::new().unwrap().keep();
        let state_path: PathBuf = dir.join("state.txt");

        let inner = FlexibleBlockStore::Memory(MemoryBlockStore::new());
        let block_store = Arc::new(inner);
        let bucket_manager = Arc::new(BucketManager::new(Arc::clone(&block_store)));

        let users_index_publisher = if with_publisher {
            let config = PublisherConfig {
                flush_interval: Duration::from_secs(300),
                first_publish_max_pins_per_sec: 100,
                ipns_lifetime: Duration::from_secs(36 * 3600),
                ipns_ttl: Duration::from_secs(15 * 60),
                ipns_key_name: "fula-users-index".to_string(),
                state_file_path: state_path,
                ipfs_api_url: "http://localhost:5001".to_string(),
                internal_token,
            };
            // No IPNS publisher — the internal endpoints don't depend on it.
            let p = UsersIndexPublisher::open_without_ipns(
                config,
                Arc::clone(&bucket_manager),
                Arc::clone(&block_store),
            )
            .expect("open");
            Some(Arc::new(p))
        } else {
            None
        };

        let config = crate::config::GatewayConfig::default();
        Arc::new(AppState {
            config,
            block_store,
            bucket_manager,
            multipart_manager: Arc::new(crate::multipart::MultipartManager::new(60)),
            lock_store: crate::handlers::locks::LockStore::new(),
            users_index_publisher,
            // W.9.6 pin queue not exercised by users-index-publisher
            // tests; leaving None routes pinning back through the
            // legacy fire-and-forget path which is fine for these
            // tests (they don't trigger PUTs / pinning).
            pin_queue: None,
            entries_store: None,
            local_retain: None,
            index_pin_set: None,
        })
    }

    #[tokio::test]
    async fn test_state_endpoint_503_when_publisher_disabled() {
        // Publisher = None. Operators who deploy without flipping the
        // env flag MUST get a 503, not a 500 or unauthed leak.
        let state = fixture_state(None, false).await;
        let app = build_internal_router(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/_internal/users-index-state")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn test_state_endpoint_503_when_no_token() {
        // Publisher is on but `internal_token = None`. Fail-closed.
        let state = fixture_state(None, true).await;
        let app = build_internal_router(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/_internal/users-index-state")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn test_state_endpoint_401_on_wrong_token() {
        let state = fixture_state(Some("supersecret".to_string()), true).await;
        let app = build_internal_router(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/_internal/users-index-state")
                    .header("authorization", "Bearer wrongtoken")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_state_endpoint_401_on_missing_bearer_prefix() {
        let state = fixture_state(Some("supersecret".to_string()), true).await;
        let app = build_internal_router(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/_internal/users-index-state")
                    // No "Bearer " prefix.
                    .header("authorization", "supersecret")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_state_endpoint_200_with_correct_token_returns_default_state() {
        // Fresh publisher, never ticked → cid is null, sequence is 0.
        // Verifies the JSON shape AND the "fresh" semantics.
        let state = fixture_state(Some("supersecret".to_string()), true).await;
        let app = build_internal_router(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/_internal/users-index-state")
                    .header("authorization", "Bearer supersecret")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let body: UsersIndexStateResponse = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body.cid, None);
        assert_eq!(body.sequence, 0);
        assert_eq!(body.updated_at_unix, 0);
        assert_eq!(body.ipns_key_name, "fula-users-index");
    }

    #[tokio::test]
    async fn test_publish_now_runs_tick_and_returns_outcome() {
        // After publish-now succeeds, a follow-up GET reads the
        // newly-committed state. Round-trip verification.
        let token = "supersecret".to_string();
        let state = fixture_state(Some(token.clone()), true).await;
        let app = build_internal_router(Arc::clone(&state));

        // Trigger publish-now.
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/_internal/publish-now")
                    .header("authorization", format!("Bearer {}", token))
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let body: PublishNowResponse = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body.sequence, 1);
        assert!(body.global_rebuilt);

        // GET the state — must reflect the just-published values.
        let resp = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/_internal/users-index-state")
                    .header("authorization", format!("Bearer {}", token))
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let state_body: UsersIndexStateResponse = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(state_body.cid, Some(body.global_cid));
        assert_eq!(state_body.sequence, 1);
    }

    #[tokio::test]
    async fn test_publish_now_503_when_publisher_disabled() {
        // Same fail-closed contract as the GET endpoint.
        let state = fixture_state(None, false).await;
        let app = build_internal_router(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/_internal/publish-now")
                    .header("authorization", "Bearer anything")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn test_constant_time_eq_correct() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(!constant_time_eq(b"hello", b"hellP"));
        assert!(!constant_time_eq(b"hello", b"hell"));
        assert!(!constant_time_eq(b"", b"x"));
        assert!(constant_time_eq(b"", b""));
    }

    /// Drive the **real** router from `routes::create_router` to verify
    /// `/_internal/*` actually bypasses the user-JWT `auth_middleware`.
    /// If the router merge accidentally inherited the parent's auth
    /// layer, this test fails (auth_middleware would respond with a
    /// 403 "Authentication required" S3 error before reaching our
    /// handler). The 503/SERVICE_UNAVAILABLE we expect comes from
    /// `authenticate()` in this module — proof the request reached us.
    #[tokio::test]
    async fn test_internal_route_bypasses_user_jwt_auth() {
        // auth_enabled=true: this is what production uses. A request
        // to a normal S3 route without a JWT would 403. The internal
        // route must reach our handler instead.
        let dir = TempDir::new().unwrap().keep();
        let state_path: PathBuf = dir.join("state.txt");
        let inner = FlexibleBlockStore::Memory(MemoryBlockStore::new());
        let block_store = Arc::new(inner);
        let bucket_manager = Arc::new(BucketManager::new(Arc::clone(&block_store)));

        let mut config = crate::config::GatewayConfig::default();
        config.auth_enabled = true;
        config.jwt_secret = Some("test-secret".to_string());

        let state = Arc::new(AppState {
            config,
            block_store,
            bucket_manager,
            multipart_manager: Arc::new(crate::multipart::MultipartManager::new(60)),
            lock_store: crate::handlers::locks::LockStore::new(),
            // Publisher disabled — we expect 503, not 401 (no token)
            // and not 403 (S3 auth would trigger if middleware leaked).
            users_index_publisher: None,
            pin_queue: None,
            entries_store: None,
            local_retain: None,
            index_pin_set: None,
        });

        let _ = state_path; // silence unused; only here to mirror prod path layout

        let app = crate::routes::create_router(Arc::clone(&state));
        let resp = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/_internal/users-index-state")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            resp.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "internal route MUST bypass user-JWT auth — got status {}",
            resp.status()
        );
    }

    /// Backward-compat regression: when the publisher is disabled
    /// (default for un-flagged deploys), the existing S3 routes must
    /// still respond. Specifically, the `auth_enabled=false` dev-mode
    /// path serves `/healthz` without any token. If publisher wiring
    /// somehow broke healthz, an old fula-client deployed against
    /// the new master would lose its container health check.
    #[tokio::test]
    async fn test_publisher_disabled_does_not_break_existing_routes() {
        let inner = FlexibleBlockStore::Memory(MemoryBlockStore::new());
        let block_store = Arc::new(inner);
        let bucket_manager = Arc::new(BucketManager::new(Arc::clone(&block_store)));

        let mut config = crate::config::GatewayConfig::default();
        config.auth_enabled = false; // dev mode, no JWT required
        config.jwt_secret = Some("test-secret".to_string());

        let state = Arc::new(AppState {
            config,
            block_store,
            bucket_manager,
            multipart_manager: Arc::new(crate::multipart::MultipartManager::new(60)),
            lock_store: crate::handlers::locks::LockStore::new(),
            users_index_publisher: None,
            pin_queue: None,
            entries_store: None,
            local_retain: None,
            index_pin_set: None,
        });

        let app = crate::routes::create_router(Arc::clone(&state));
        let resp = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/healthz")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "existing /healthz must still respond when publisher is disabled"
        );
    }
}
