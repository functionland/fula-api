//! Migration lock handlers.
//!
//! An advisory lock that serializes v1 -> v7 forest migrations across
//! multiple devices for the same bucket. The server does not know the
//! manifest's storage key (it is DEK-derived and never leaves the client),
//! so this lock is **advisory**: clients cooperatively acquire it around
//! migration work. Enforcement is via acquisition uniqueness (409 on
//! contention) plus a short TTL that the holder refreshes via heartbeat.
//! If the holder crashes, the TTL expires and another device can take
//! over — no path exists for a dead client to permanently strand a bucket.
//!
//! Namespace: `{hashed_user_id}:{bucket}` so one user cannot lock another
//! user's same-named bucket.
//!
//! Storage: in-memory only, cleared on process restart. The v7 manifest
//! PUT itself is conditional (If-Match on the v1 ETag) so a lock loss
//! across a restart cannot corrupt a bucket — the racing PUT simply 412s.

use crate::AppState;
use crate::state::UserSession;
use axum::{
    extract::{Extension, Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// How long a lock stays held without a heartbeat, in milliseconds.
const LOCK_TTL_MS: i64 = 60_000;

/// How often the sweeper wakes to drop expired records, in seconds.
const SWEEPER_INTERVAL_SECS: u64 = 30;

/// Header that carries the lock token on release / heartbeat.
const LOCK_TOKEN_HEADER: &str = "x-fula-lock-token";

/// An entry in the in-memory lock store.
#[derive(Clone, Debug)]
pub struct LockRecord {
    pub token: String,
    pub acquired_at_ms: i64,
    pub expires_at_ms: i64,
}

/// In-memory advisory-lock store keyed by `{hashed_user_id}:{bucket}`.
#[derive(Clone, Default)]
pub struct LockStore {
    inner: Arc<RwLock<HashMap<String, LockRecord>>>,
}

impl LockStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn namespace_key(hashed_user_id: &str, bucket: &str) -> String {
        format!("{}:{}", hashed_user_id, bucket)
    }

    fn now_ms() -> i64 {
        chrono::Utc::now().timestamp_millis()
    }

    /// Drop any records whose expiry has passed.
    async fn sweep_expired(&self) {
        let now = Self::now_ms();
        let mut store = self.inner.write().await;
        store.retain(|_, rec| rec.expires_at_ms > now);
    }

    async fn acquire(&self, hashed_user_id: &str, bucket: &str) -> Result<LockRecord, i64> {
        let key = Self::namespace_key(hashed_user_id, bucket);
        let now = Self::now_ms();
        let mut store = self.inner.write().await;
        if let Some(existing) = store.get(&key) {
            if existing.expires_at_ms > now {
                return Err(existing.expires_at_ms);
            }
        }
        let record = LockRecord {
            token: uuid::Uuid::new_v4().to_string(),
            acquired_at_ms: now,
            expires_at_ms: now + LOCK_TTL_MS,
        };
        store.insert(key, record.clone());
        Ok(record)
    }

    async fn release(
        &self,
        hashed_user_id: &str,
        bucket: &str,
        token: &str,
    ) -> Result<(), LockOpError> {
        let key = Self::namespace_key(hashed_user_id, bucket);
        let mut store = self.inner.write().await;
        match store.get(&key) {
            None => Err(LockOpError::NotFound),
            Some(rec) if rec.token != token => Err(LockOpError::TokenMismatch),
            Some(_) => {
                store.remove(&key);
                Ok(())
            }
        }
    }

    async fn heartbeat(
        &self,
        hashed_user_id: &str,
        bucket: &str,
        token: &str,
    ) -> Result<i64, LockOpError> {
        let key = Self::namespace_key(hashed_user_id, bucket);
        let now = Self::now_ms();
        let mut store = self.inner.write().await;
        match store.get_mut(&key) {
            None => Err(LockOpError::NotFound),
            Some(rec) if rec.token != token => Err(LockOpError::TokenMismatch),
            Some(rec) if rec.expires_at_ms <= now => {
                store.remove(&key);
                Err(LockOpError::NotFound)
            }
            Some(rec) => {
                rec.expires_at_ms = now + LOCK_TTL_MS;
                Ok(rec.expires_at_ms)
            }
        }
    }

    #[cfg(test)]
    async fn len(&self) -> usize {
        self.inner.read().await.len()
    }
}

#[derive(Debug)]
enum LockOpError {
    NotFound,
    TokenMismatch,
}

/// Response body for `POST /locks/{bucket}` on 200.
#[derive(Serialize, Deserialize)]
pub struct AcquireOk {
    pub token: String,
    pub expires_at: i64,
}

/// Response body for `POST /locks/{bucket}` on 409.
#[derive(Serialize, Deserialize)]
pub struct AcquireConflict {
    pub code: &'static str,
    pub expires_at: i64,
}

/// Response body for `POST /locks/{bucket}/heartbeat` on 200.
#[derive(Serialize, Deserialize)]
pub struct HeartbeatOk {
    pub expires_at: i64,
}

fn extract_lock_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get(LOCK_TOKEN_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

/// POST /locks/{bucket}
pub async fn acquire_lock(
    State(state): State<Arc<AppState>>,
    Extension(session): Extension<UserSession>,
    Path(bucket): Path<String>,
) -> Response {
    state.lock_store.sweep_expired().await;
    match state.lock_store.acquire(&session.hashed_user_id, &bucket).await {
        Ok(rec) => {
            info!(bucket = %bucket, "migration lock acquired");
            (
                StatusCode::OK,
                Json(AcquireOk {
                    token: rec.token,
                    expires_at: rec.expires_at_ms,
                }),
            )
                .into_response()
        }
        Err(expires_at) => {
            debug!(bucket = %bucket, "migration lock already held");
            (
                StatusCode::CONFLICT,
                Json(AcquireConflict {
                    code: "LockHeld",
                    expires_at,
                }),
            )
                .into_response()
        }
    }
}

/// DELETE /locks/{bucket}
pub async fn release_lock(
    State(state): State<Arc<AppState>>,
    Extension(session): Extension<UserSession>,
    Path(bucket): Path<String>,
    headers: HeaderMap,
) -> Response {
    let token = match extract_lock_token(&headers) {
        Some(t) => t,
        None => return (StatusCode::BAD_REQUEST, "missing x-fula-lock-token").into_response(),
    };
    match state.lock_store.release(&session.hashed_user_id, &bucket, &token).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(LockOpError::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(LockOpError::TokenMismatch) => StatusCode::FORBIDDEN.into_response(),
    }
}

/// POST /locks/{bucket}/heartbeat
pub async fn heartbeat_lock(
    State(state): State<Arc<AppState>>,
    Extension(session): Extension<UserSession>,
    Path(bucket): Path<String>,
    headers: HeaderMap,
) -> Response {
    let token = match extract_lock_token(&headers) {
        Some(t) => t,
        None => return (StatusCode::BAD_REQUEST, "missing x-fula-lock-token").into_response(),
    };
    match state.lock_store.heartbeat(&session.hashed_user_id, &bucket, &token).await {
        Ok(expires_at) => (StatusCode::OK, Json(HeartbeatOk { expires_at })).into_response(),
        Err(LockOpError::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(LockOpError::TokenMismatch) => StatusCode::FORBIDDEN.into_response(),
    }
}

/// Spawn a background task that periodically drops expired lock records.
///
/// Called once from `server::run_server` at startup. The task lives for the
/// lifetime of the process and cheaply holds a clone of the store.
pub fn start_sweeper(store: LockStore) {
    tokio::spawn(async move {
        let mut interval =
            tokio::time::interval(std::time::Duration::from_secs(SWEEPER_INTERVAL_SECS));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            store.sweep_expired().await;
        }
    });
    warn!(
        interval_secs = SWEEPER_INTERVAL_SECS,
        ttl_ms = LOCK_TTL_MS,
        "migration-lock sweeper started"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    const USER_A: &str = "user-a-hash";
    const USER_B: &str = "user-b-hash";
    const BUCKET: &str = "bucket-x";

    #[tokio::test]
    async fn acquire_on_free_returns_record_and_refuses_repeat() {
        let store = LockStore::new();
        let first = store.acquire(USER_A, BUCKET).await.expect("first acquire");
        assert_eq!(store.len().await, 1);

        // Repeat by same user hits the contention path.
        let err = store
            .acquire(USER_A, BUCKET)
            .await
            .expect_err("second acquire");
        assert_eq!(err, first.expires_at_ms);
    }

    #[tokio::test]
    async fn cross_user_namespace_isolation() {
        let store = LockStore::new();
        // Same bucket name, different users — must not collide.
        store.acquire(USER_A, BUCKET).await.expect("A acquires");
        store.acquire(USER_B, BUCKET).await.expect("B acquires");
        assert_eq!(store.len().await, 2);
    }

    #[tokio::test]
    async fn release_happy_path() {
        let store = LockStore::new();
        let rec = store.acquire(USER_A, BUCKET).await.unwrap();
        store
            .release(USER_A, BUCKET, &rec.token)
            .await
            .expect("release");
        assert_eq!(store.len().await, 0);
    }

    #[tokio::test]
    async fn release_wrong_token_is_forbidden() {
        let store = LockStore::new();
        let _rec = store.acquire(USER_A, BUCKET).await.unwrap();
        let err = store.release(USER_A, BUCKET, "not-a-real-token").await;
        assert!(matches!(err, Err(LockOpError::TokenMismatch)));
        // Record still there.
        assert_eq!(store.len().await, 1);
    }

    #[tokio::test]
    async fn release_missing_is_not_found() {
        let store = LockStore::new();
        let err = store.release(USER_A, BUCKET, "anything").await;
        assert!(matches!(err, Err(LockOpError::NotFound)));
    }

    #[tokio::test]
    async fn heartbeat_extends_expiry() {
        let store = LockStore::new();
        let rec = store.acquire(USER_A, BUCKET).await.unwrap();
        // Sleep 10ms so the refreshed expiry is strictly greater.
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        let extended = store
            .heartbeat(USER_A, BUCKET, &rec.token)
            .await
            .expect("heartbeat");
        assert!(extended > rec.expires_at_ms);
    }

    #[tokio::test]
    async fn heartbeat_wrong_token_rejected() {
        let store = LockStore::new();
        let _ = store.acquire(USER_A, BUCKET).await.unwrap();
        let err = store.heartbeat(USER_A, BUCKET, "bogus").await;
        assert!(matches!(err, Err(LockOpError::TokenMismatch)));
    }

    #[tokio::test]
    async fn sweeper_drops_expired_records() {
        let store = LockStore::new();
        let rec = store.acquire(USER_A, BUCKET).await.unwrap();
        // Manually age the record past its TTL.
        {
            let mut inner = store.inner.write().await;
            let key = LockStore::namespace_key(USER_A, BUCKET);
            let r = inner.get_mut(&key).unwrap();
            r.expires_at_ms = chrono::Utc::now().timestamp_millis() - 1;
            assert_eq!(r.token, rec.token); // sanity
        }
        store.sweep_expired().await;
        assert_eq!(store.len().await, 0);
    }

    #[tokio::test]
    async fn acquire_after_ttl_succeeds() {
        let store = LockStore::new();
        let _ = store.acquire(USER_A, BUCKET).await.unwrap();
        // Age into the past.
        {
            let mut inner = store.inner.write().await;
            let key = LockStore::namespace_key(USER_A, BUCKET);
            inner.get_mut(&key).unwrap().expires_at_ms =
                chrono::Utc::now().timestamp_millis() - 1;
        }
        // No sweep yet — acquire's own expiry check must also honour TTL.
        let second = store.acquire(USER_A, BUCKET).await.expect("after-ttl");
        // Token is fresh, not the old one.
        assert_ne!(second.token, "");
    }
}
