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

/// GET / - List all buckets
pub async fn list_buckets(
    State(state): State<Arc<AppState>>,
    Extension(session): Extension<UserSession>,
) -> Result<Response, ApiError> {
    let buckets = state.bucket_manager.list_buckets();
    
    // Filter to buckets owned by this user (or show all for admin)
    // Security audit fix A3: Compare using hashed user IDs
    let user_buckets: Vec<_> = buckets
        .into_iter()
        .filter(|b| session.can_access_bucket(&b.owner_id))
        .map(|b| (b.name, b.created_at))
        .collect();

    // Return hashed user ID in XML for privacy (Security audit fix A3)
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
