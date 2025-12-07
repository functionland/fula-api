//! HTTP middleware for authentication, rate limiting, etc.

use crate::{ApiError, S3ErrorCode, AppState};
use crate::auth::{extract_bearer_token, validate_token, claims_to_session, dev_session};
use crate::state::UserSession;
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

/// Create a rate limiter
pub fn create_rate_limiter(requests_per_second: u32) -> Arc<KeyedRateLimiter> {
    let quota = Quota::per_second(NonZeroU32::new(requests_per_second).unwrap());
    Arc::new(RateLimiter::keyed(quota))
}

/// Authentication middleware
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
            let token = extract_bearer_token(header)
                .ok_or_else(|| ApiError::s3(S3ErrorCode::InvalidToken, "Invalid Authorization header format"))?;
            
            let secret = state.config.jwt_secret.as_ref()
                .ok_or_else(|| ApiError::s3(S3ErrorCode::InternalError, "JWT secret not configured"))?;
            
            let claims = validate_token(token, secret)?;
            claims_to_session(claims)
        }
        None => {
            // For S3 compatibility, also check for AWS Signature
            // For now, reject unauthenticated requests when auth is enabled
            return Err(ApiError::s3(S3ErrorCode::AccessDenied, "Authentication required"));
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

/// Rate limiting middleware
pub async fn rate_limit_middleware(
    State(limiter): State<Arc<KeyedRateLimiter>>,
    request: Request<Body>,
    next: Next,
) -> Result<Response, ApiError> {
    // Get user ID from session (added by auth middleware)
    let user_id = request
        .extensions()
        .get::<UserSession>()
        .map(|s| s.user_id.clone())
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
        let limiter = create_rate_limiter(100);
        
        // First request should pass
        assert!(limiter.check_key(&"user1".to_string()).is_ok());
    }
}
