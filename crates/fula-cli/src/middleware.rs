//! HTTP middleware for authentication, rate limiting, etc.
//!
//! Supports two authentication methods:
//! 1. Bearer token: `Authorization: Bearer <jwt>`
//! 2. AWS Signature V4: `Authorization: AWS4-HMAC-SHA256 Credential=JWT:<jwt>/...`
//!
//! The AWS Sig V4 method allows standard S3 clients (boto3, AWS CLI, etc.) to work
//! by embedding the JWT in the access key with a `JWT:` prefix.

use crate::{ApiError, S3ErrorCode, AppState};
use crate::auth::{extract_token_from_header, validate_token, claims_to_session, dev_session, extract_bearer_token, validate_admin_token};
use crate::state::hash_user_id;
use crate::state::{UserSession, AdminSession};
use chrono::{DateTime, Utc};
use axum::{
    body::Body,
    extract::{MatchedPath, State},
    http::Request,
    middleware::Next,
    response::Response,
};
use governor::{Quota, RateLimiter, state::keyed::DefaultKeyedStateStore};
use std::num::NonZeroU32;
use std::sync::Arc;

/// Rate limiter type
pub type KeyedRateLimiter = RateLimiter<String, DefaultKeyedStateStore<String>, governor::clock::DefaultClock>;

/// Create a rate limiter.
///
/// `requests_per_second` is the sustained token-refill rate; `burst` is the
/// token-bucket capacity. A client "list" of a bucket is a client-side forest
/// walk — hundreds of structural `__fula_forest_v7_nodes/<h>` GETs fired in a
/// sub-second burst — so the bucket capacity must comfortably exceed a bucket's
/// node count or the walk 429s partway through and the listing times out.
/// `burst` is floored at `requests_per_second` (a smaller burst would be
/// nonsensical) and both are floored at 1.
pub fn create_rate_limiter(requests_per_second: u32, burst: u32) -> Arc<KeyedRateLimiter> {
    let rps = NonZeroU32::new(requests_per_second.max(1)).unwrap();
    let burst = NonZeroU32::new(burst.max(requests_per_second).max(1)).unwrap();
    let quota = Quota::per_second(rps).allow_burst(burst);
    Arc::new(RateLimiter::keyed(quota))
}

/// P12 — is this matched route PATTERN one a scoped MCP token may use?
///
/// Allowed = the S3 object/bucket DATA routes only (the ones whose handlers run
/// `assert_mcp_scope`):
/// - `/{bucket}` and `/{bucket}/` — CreateBucket / DeleteBucket / HeadBucket /
///   ListObjects / batch-delete (POST),
/// - `/{bucket}/{*key}` — Put/Get/Head/Delete object + multipart + tagging.
///
/// Everything else (`/` ListBuckets, `/locks/*`, `/api/v1/*`, and any FUTURE
/// authenticated route) is denied — fail-CLOSED, including when `matched` is
/// `None` (a request that somehow reached auth with no matched route pattern).
/// Keyed on the route PATTERN (axum [`MatchedPath`]) so new routes are denied
/// by default rather than silently allowed.
pub(crate) fn mcp_route_allowed(matched: Option<&str>) -> bool {
    matches!(
        matched,
        Some("/{bucket}") | Some("/{bucket}/") | Some("/{bucket}/{*key}")
    )
}

/// Authentication middleware
///
/// Supports both Bearer token and AWS Signature V4 authentication:
/// - Bearer: `Authorization: Bearer <jwt>`
/// - AWS Sig V4: `Authorization: AWS4-HMAC-SHA256 Credential=JWT:<jwt>/...`
///
/// For AWS Sig V4, the access key must be prefixed with `JWT:` and contain the JWT token.
/// The secret access key can be any value (it's not used for validation since we validate the JWT).
pub async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    mut request: Request<Body>,
    next: Next,
) -> Result<Response, ApiError> {
    // Skip auth if disabled
    if !state.config.auth_enabled {
        let session = dev_session();
        request.extensions_mut().insert(session);
        return Ok(next.run(request).await);
    }

    // Extract token from Authorization header
    let auth_header = request
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok());

    let session = match auth_header {
        Some(header) => {
            // Extract JWT from either Bearer token or AWS Sig V4 format
            let token = extract_token_from_header(header, request.headers())?;

            let secret = state.config.jwt_secret.as_ref()
                .ok_or_else(|| ApiError::s3(S3ErrorCode::InternalError, "JWT secret not configured"))?;

            let claims = validate_token(&token, secret)?;
            // Audit F3: honor a manually-revoked key. No-op unless the revocation
            // deny-list is enabled (env switch + pins DB). Deny-list + fail-open,
            // so a currently-valid token is never rejected. `token` is the raw
            // JWT — the issuer hashes the same string into `api_keys.key_hash`.
            crate::revocation::ensure_not_revoked(state.revocation.as_deref(), &token)?;
            // P12: MCP jti revocation deny-list. Mirrors the F3 key deny-list
            // but keyed on the MCP token's `jti`. No-op unless the MCP
            // revocation source is enabled; fail-CLOSED is applied per-action in
            // the handlers (a write under an enabled-but-unreachable source is
            // denied), while the plain membership deny (a known-revoked jti)
            // applies to every verb here.
            crate::mcp_revocation::ensure_jti_not_revoked(
                state.mcp_revocation.as_deref(),
                claims.jti.as_deref(),
            )?;
            // P12: derive the scoped-MCP fence (fail-closed). For a normal
            // storage token this is `None` and changes nothing; for an MCP
            // token it REQUIRES a valid `mcp` claim or the token is refused.
            // Computed before `claims` is moved into `claims_to_session`.
            let mcp_scope = crate::auth::mcp_scope_from_claims(&claims)?;
            // L1b: the connection-binding pubkey (`cnf.mcp_pub_b64`), if any.
            // `None` for a non-MCP/unbound token (no `cnf` ⇒ never revoked).
            // Captured before `claims` is moved into `claims_to_session`.
            let connection_pubkey = claims.cnf.as_ref().map(|c| c.mcp_pub_b64.clone());
            // Pass the raw JWT token to the session for forwarding to pinning service
            let mut session = claims_to_session(claims, token);
            session.mcp_scope = mcp_scope;
            session.connection_pubkey = connection_pubkey;
            session
        }
        None => {
            return Err(ApiError::s3(
                S3ErrorCode::AccessDenied,
                "Authentication required. Use 'Bearer <jwt>' or AWS Signature V4 with 'JWT:<jwt>' as access key"
            ));
        }
    };

    // Check session expiration
    if session.is_expired() {
        return Err(ApiError::s3(S3ErrorCode::InvalidToken, "Token has expired"));
    }

    // P12 — DEFENSE-IN-DEPTH choke point. A scoped MCP token may ONLY hit the
    // S3 object/bucket DATA routes (where the per-handler `assert_mcp_scope`
    // enforces bucket+prefix+perms). Every other authenticated route
    // (ListBuckets `/`, `/locks/*`, the `/api/v1/*` recovery + index endpoints)
    // has no scope-aware fence and an MCP token has no legitimate use for it, so
    // it is denied here — a single place that fail-CLOSES for FUTURE routes too
    // (keyed on the matched route PATTERN, not the raw URI). Non-MCP storage
    // tokens are unaffected. The per-handler asserts remain as belt-and-braces.
    if session.mcp_scope.is_some() {
        let matched = request
            .extensions()
            .get::<MatchedPath>()
            .map(|m| m.as_str().to_string());
        if !mcp_route_allowed(matched.as_deref()) {
            tracing::warn!(
                route = matched.as_deref().unwrap_or("<unmatched>"),
                "MCP token denied on a non-data route (P12 allowlist)"
            );
            return Err(ApiError::s3(
                S3ErrorCode::AccessDenied,
                "MCP tokens are restricted to S3 object operations on the scoped bucket",
            ));
        }
    }

    // Store session in request extensions
    request.extensions_mut().insert(session);

    Ok(next.run(request).await)
}

/// Admin authentication middleware
///
/// Validates admin JWT tokens using a separate secret from user JWT.
/// Admin tokens must have:
/// - Valid expiration (exp claim)
/// - Admin scope ("admin" or "*")
///
/// The admin API must be explicitly enabled via FULA_ADMIN_API=true.
pub async fn admin_auth_middleware(
    State(state): State<Arc<AppState>>,
    mut request: Request<Body>,
    next: Next,
) -> Result<Response, ApiError> {
    // Check if admin API is enabled
    if !state.config.admin_api_enabled {
        tracing::warn!("Admin API request rejected: admin API is not enabled");
        return Err(ApiError::s3(
            S3ErrorCode::AccessDenied,
            "Admin API is not enabled",
        ));
    }

    // Get admin JWT secret
    let admin_secret = state.config.admin_jwt_secret.as_ref()
        .ok_or_else(|| {
            tracing::error!("Admin API enabled but ADMIN_JWT_SECRET not configured");
            ApiError::s3(S3ErrorCode::InternalError, "Admin API not properly configured")
        })?;

    // Extract token from Authorization header (Bearer only for admin)
    let auth_header = request
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| ApiError::s3(
            S3ErrorCode::AccessDenied,
            "Admin authentication required. Use 'Bearer <admin_jwt>'"
        ))?;

    let token = extract_bearer_token(auth_header)
        .ok_or_else(|| ApiError::s3(
            S3ErrorCode::InvalidToken,
            "Invalid Authorization header. Use 'Bearer <admin_jwt>'"
        ))?;

    // Validate admin token
    let claims = validate_admin_token(token, admin_secret)?;

    // Create admin session
    let expires_at = claims.exp
        .and_then(|exp| DateTime::from_timestamp(exp, 0))
        .unwrap_or_else(|| Utc::now());

    let session = AdminSession::new(claims.sub.clone(), expires_at);

    // Check session expiration
    if session.is_expired() {
        return Err(ApiError::s3(S3ErrorCode::InvalidToken, "Admin token has expired"));
    }

    // Log admin action. PII-safety: hash the admin's JWT sub before logging
    // so logs don't carry plaintext email for legacy-JWT admins. Same
    // BLAKE3-derived 16-byte form used elsewhere as the canonical opaque
    // identifier.
    let admin_id_hashed = hash_user_id(&claims.sub);
    tracing::info!(
        admin_id_hashed = %admin_id_hashed,
        path = %request.uri().path(),
        method = %request.method(),
        "Admin API request"
    );

    // Store admin session in request extensions
    request.extensions_mut().insert(session);

    Ok(next.run(request).await)
}

/// Rate limiting middleware
pub async fn rate_limit_middleware(
    State(limiter): State<Arc<KeyedRateLimiter>>,
    request: Request<Body>,
    next: Next,
) -> Result<Response, ApiError> {
    // Get user ID from session (added by auth middleware).
    // PII-safety: key the rate limiter on the OPAQUE hashed_user_id, not
    // the raw JWT sub. The map is in-memory only, but if metrics
    // (Prometheus, etc.) ever expose per-key counters, the raw form would
    // leak plaintext email for legacy-JWT users.
    let user_id = request
        .extensions()
        .get::<UserSession>()
        .map(|s| s.hashed_user_id.clone())
        .unwrap_or_else(|| "anonymous".to_string());

    // Check rate limit
    if limiter.check_key(&user_id).is_err() {
        return Err(ApiError::s3(
            S3ErrorCode::SlowDown,
            "Please reduce your request rate",
        ));
    }

    Ok(next.run(request).await)
}

/// Request ID middleware - adds x-amz-request-id header
pub async fn request_id_middleware(
    mut request: Request<Body>,
    next: Next,
) -> Response {
    let request_id = uuid::Uuid::new_v4().to_string();
    request.extensions_mut().insert(RequestId(request_id.clone()));
    
    let mut response = next.run(request).await;
    response.headers_mut().insert(
        "x-amz-request-id",
        request_id.parse().unwrap(),
    );
    response
}

/// Request ID extension
#[derive(Clone)]
pub struct RequestId(pub String);

/// Check if an IP address is localhost/loopback
/// Used to restrict admin endpoints to local access only
pub fn is_localhost(addr: &std::net::SocketAddr) -> bool {
    addr.ip().is_loopback() // Covers 127.0.0.1 and ::1
}

/// Logging middleware
pub async fn logging_middleware(
    request: Request<Body>,
    next: Next,
) -> Response {
    let method = request.method().clone();
    let uri = request.uri().clone();
    let start = std::time::Instant::now();

    let response = next.run(request).await;

    let duration = start.elapsed();
    let status = response.status();

    tracing::info!(
        method = %method,
        uri = %uri,
        status = %status.as_u16(),
        duration_ms = %duration.as_millis(),
        "Request completed"
    );

    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_rate_limiter() {
        let limiter = create_rate_limiter(100, 5000);

        // First request should pass
        assert!(limiter.check_key(&"user1".to_string()).is_ok());
    }

    #[test]
    fn test_rate_limiter_absorbs_forest_walk_burst() {
        // A bucket "list" fires hundreds of structural GETs at once; the burst
        // capacity must let a full walk through in one shot (regression guard
        // for the 100-rps cap that 429'd large-bucket listings mid-walk).
        let limiter = create_rate_limiter(1000, 5000);
        for _ in 0..5000 {
            assert!(limiter.check_key(&"walker".to_string()).is_ok());
        }
    }

    #[test]
    fn test_rate_limiter_burst_floored_at_rps() {
        // A nonsensical burst < rps is floored to rps, never below it.
        let limiter = create_rate_limiter(1000, 10);
        for _ in 0..1000 {
            assert!(limiter.check_key(&"u".to_string()).is_ok());
        }
    }

    // ── P12 MCP route-allowlist (pure function) ─────────────────────────────
    #[test]
    fn mcp_route_allowlist_allows_only_data_routes() {
        // The three S3 data-route patterns are allowed.
        assert!(mcp_route_allowed(Some("/{bucket}")));
        assert!(mcp_route_allowed(Some("/{bucket}/")));
        assert!(mcp_route_allowed(Some("/{bucket}/{*key}")));
    }

    #[test]
    fn mcp_route_allowlist_denies_everything_else_failclosed() {
        // ListBuckets, locks, api_v1 recovery/index, health — all denied.
        assert!(!mcp_route_allowed(Some("/")));
        assert!(!mcp_route_allowed(Some("/locks/{bucket}")));
        assert!(!mcp_route_allowed(Some("/locks/{bucket}/heartbeat")));
        assert!(!mcp_route_allowed(Some("/api/v1/blocks/{cid}")));
        assert!(!mcp_route_allowed(Some("/api/v1/buckets/{bucket}/resolve-keys")));
        assert!(!mcp_route_allowed(Some("/api/v1/buckets/list")));
        assert!(!mcp_route_allowed(Some("/api/v1/users-index/entry")));
        // Fail-CLOSED: a request with no matched route pattern is denied.
        assert!(!mcp_route_allowed(None));
        // An unknown/future route is denied by default.
        assert!(!mcp_route_allowed(Some("/some/future/route")));
    }

    // ── P12 MCP allowlist (real auth_middleware + MatchedPath, end-to-end) ───
    //
    // Proves the choke point actually works against axum's router: that
    // `MatchedPath` reaches `auth_middleware` and the pattern strings match, so
    // a real MCP token is ALLOWED on `/{bucket}` + `/{bucket}/{*key}` and DENIED
    // (403) on `/`, `/locks/{bucket}`, `/api/v1/blocks/{cid}` — while a normal
    // storage token passes the allowlist on every route.
    mod allowlist_integration {
        use super::*;
        use crate::auth::{Claims, McpScopeClaim, McpScopeEntry};
        use crate::state::AppState;
        use axum::body::Body;
        use axum::http::{Method, Request, StatusCode};
        use axum::routing::{get, put};
        use axum::Router;
        use chrono::{Duration as ChronoDuration, Utc};
        use fula_blockstore::MemoryBlockStore;
        use fula_core::BucketManager;
        use jsonwebtoken::{encode, EncodingKey, Header};
        use tower::ServiceExt;

        const SECRET: &str = "allowlist-test-secret";

        async fn test_state() -> Arc<AppState> {
            use fula_blockstore::FlexibleBlockStore;
            let block_store = Arc::new(FlexibleBlockStore::Memory(MemoryBlockStore::new()));
            let bucket_manager = Arc::new(BucketManager::new(Arc::clone(&block_store)));
            let mut config = crate::config::GatewayConfig::default();
            config.auth_enabled = true;
            config.jwt_secret = Some(SECRET.to_string());
            config.use_memory_store = true;
            Arc::new(AppState {
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
                pins_db: None,
                revocation: None,
                mcp_revocation: None,
                mcp_connection_revocation: None,
            })
        }

        /// A trivial OK handler — the test only cares whether the request
        /// reaches it (allowlist passed) or is rejected by the middleware (403).
        async fn ok_handler() -> StatusCode {
            StatusCode::OK
        }

        /// Router mirroring the real route PATTERNS, behind the real
        /// `auth_middleware`. Both allowed (data) and denied (aux) patterns.
        fn router(state: Arc<AppState>) -> Router {
            Router::new()
                // Allowed (data) routes
                .route("/{bucket}", put(ok_handler))
                .route("/{bucket}/{*key}", get(ok_handler))
                // Denied (aux / recovery) routes
                .route("/", get(ok_handler))
                .route("/locks/{bucket}", axum::routing::post(ok_handler))
                .route("/api/v1/blocks/{cid}", get(ok_handler))
                .layer(axum::middleware::from_fn_with_state(
                    Arc::clone(&state),
                    auth_middleware,
                ))
                .with_state(state)
        }

        fn mint(claims: &Claims) -> String {
            encode(&Header::default(), claims, &EncodingKey::from_secret(SECRET.as_bytes())).unwrap()
        }

        fn mcp_token() -> String {
            let claims = Claims {
                sub: "user-sub".to_string(),
                exp: Some((Utc::now() + ChronoDuration::hours(1)).timestamp()),
                iat: Some(Utc::now().timestamp()),
                iss: None,
                aud: None,
                scope: String::new(),
                name: None,
                jti: Some("jti-1".to_string()),
                token_use: Some("mcp_s3".to_string()),
                mcp: Some(McpScopeClaim {
                    v: 1,
                    scopes: vec![McpScopeEntry {
                        bucket: "fula-ai-workspace".to_string(),
                        prefix: "ai/".to_string(),
                        perms: vec!["read".into(), "write".into(), "list".into()],
                    }],
                }),
                cnf: None,
            };
            mint(&claims)
        }

        fn storage_token() -> String {
            let claims = Claims {
                sub: "storage-user".to_string(),
                exp: None,
                iat: None,
                iss: None,
                aud: None,
                scope: "storage:read storage:write".to_string(),
                name: None,
                jti: None,
                token_use: None,
                mcp: None,
                cnf: None,
            };
            mint(&claims)
        }

        async fn status_for(state: Arc<AppState>, method: Method, uri: &str, token: &str) -> StatusCode {
            let req = Request::builder()
                .method(method)
                .uri(uri)
                .header("Authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap();
            router(state).oneshot(req).await.unwrap().status()
        }

        #[tokio::test]
        async fn mcp_token_allowed_on_data_routes() {
            let state = test_state().await;
            // PUT /{bucket} and GET /{bucket}/{*key} are data routes → reach the
            // OK handler (NOT 403 from the allowlist).
            let s1 = status_for(Arc::clone(&state), Method::PUT, "/fula-ai-workspace", &mcp_token()).await;
            assert_eq!(s1, StatusCode::OK, "MCP token must be allowed on /{{bucket}}");
            let s2 = status_for(Arc::clone(&state), Method::GET, "/fula-ai-workspace/ai/x.txt", &mcp_token()).await;
            assert_eq!(s2, StatusCode::OK, "MCP token must be allowed on /{{bucket}}/{{*key}}");
        }

        #[tokio::test]
        async fn mcp_token_denied_on_aux_and_recovery_routes() {
            let state = test_state().await;
            // ListBuckets, locks, api_v1 block-read → 403 from the allowlist.
            let root = status_for(Arc::clone(&state), Method::GET, "/", &mcp_token()).await;
            assert_eq!(root, StatusCode::FORBIDDEN, "MCP token must be denied on / (ListBuckets)");
            let locks = status_for(Arc::clone(&state), Method::POST, "/locks/some-bucket", &mcp_token()).await;
            assert_eq!(locks, StatusCode::FORBIDDEN, "MCP token must be denied on /locks/*");
            let blocks = status_for(Arc::clone(&state), Method::GET, "/api/v1/blocks/somecid", &mcp_token()).await;
            assert_eq!(blocks, StatusCode::FORBIDDEN, "MCP token must be denied on /api/v1/blocks/{{cid}} (out-of-scope byte read)");
        }

        #[tokio::test]
        async fn storage_token_passes_allowlist_on_every_route() {
            // REGRESSION: a normal storage token is NOT subject to the MCP
            // allowlist — it reaches the handler on aux routes too (byte-identical).
            let state = test_state().await;
            for (m, uri) in [
                (Method::GET, "/"),
                (Method::POST, "/locks/some-bucket"),
                (Method::GET, "/api/v1/blocks/somecid"),
                (Method::PUT, "/fula-ai-workspace"),
            ] {
                let s = status_for(Arc::clone(&state), m.clone(), uri, &storage_token()).await;
                assert_eq!(s, StatusCode::OK, "storage token must pass the allowlist on {uri}");
            }
        }
    }
}
