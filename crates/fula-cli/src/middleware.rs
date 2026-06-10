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
    extract::State,
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
            // Pass the raw JWT token to the session for forwarding to pinning service
            claims_to_session(claims, token)
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
}
