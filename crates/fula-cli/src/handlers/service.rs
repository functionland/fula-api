//! Service-level handlers (ListBuckets)

use crate::{AppState, ApiError};
use crate::state::UserSession;
use crate::xml;
use axum::{
    extract::{Extension, State},
    response::{IntoResponse, Response},
    http::StatusCode,
};
use std::sync::Arc;

/// GET / - List buckets (S3 ListBuckets)
pub async fn list_buckets(
    State(state): State<Arc<AppState>>,
    Extension(session): Extension<UserSession>,
) -> Result<Response, ApiError> {
    // User-scoped bucket listing (returns only this user's buckets)
    let buckets = state.bucket_manager.list_buckets_for_user(&session.hashed_user_id);

    let user_buckets: Vec<_> = buckets
        .into_iter()
        .map(|b| (b.name, b.created_at))
        .collect();

    // Return hashed user ID in XML for privacy
    let xml_response = xml::list_all_my_buckets_result(
        &session.hashed_user_id,
        session.display_name.as_deref().unwrap_or("User"),
        &user_buckets,
    );

    Ok((
        StatusCode::OK,
        [("Content-Type", "application/xml")],
        xml_response,
    ).into_response())
}

/// HEAD / - Health check
pub async fn health_check() -> impl IntoResponse {
    (StatusCode::OK, "OK")
}

/// GET /healthz - unauthenticated container health check
pub async fn healthz() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

/// GET /fula/capabilities — unauthenticated protocol-capability advertisement
/// (Phase 2). Clients probe this ONCE per instance before using optional
/// protocols. An old master 404s here, so a client never sends e.g. the
/// empty-body remote-cid PUT to a build that would misstore it as a real
/// zero-byte object.
pub async fn capabilities(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    axum::Json(serde_json::json!({
        "remoteCidPut": state.config.remote_cid_put_enabled,
        // FM-4: clients/operators can discover wallet-auth support the same way.
        "eip712Auth": state.config.eip712_auth_enabled,
    }))
}
