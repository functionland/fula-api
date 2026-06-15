//! FM-1 (Phase 2.5) — Postgres-backed shared bucket-root arbiter.
//!
//! The Stage-A federated masters already share one Postgres (billing,
//! sessions, pins); the same database is the lowest-infrastructure arbiter
//! for bucket-root CAS. Table (pinning-service migration 020):
//!
//!   bucket_roots(owner_id TEXT, bucket TEXT, root_cid TEXT NOT NULL,
//!                version BIGINT NOT NULL DEFAULT 1, updated_at TIMESTAMPTZ,
//!                PRIMARY KEY (owner_id, bucket))
//!
//! CAS semantics: one statement, race-safe under READ COMMITTED —
//!   INSERT .. ON CONFLICT (owner_id,bucket) DO UPDATE
//!     SET root_cid = $new, version = version+1, updated_at = now()
//!     WHERE bucket_roots.root_cid = $expected
//! rows_affected == 1 ⇒ Won (fresh row claimed, or expected matched);
//! rows_affected == 0 ⇒ another master moved the pointer ⇒ Conflict.
//!
//! Reuses the AppState `pins_db` sqlx pool — zero new dependencies.

use async_trait::async_trait;
use cid::Cid;
use fula_core::root_pointer::{CasOutcome, RootPointerStore};
use fula_core::{CoreError, Result};
use sqlx::PgPool;

pub struct PgRootStore {
    pool: PgPool,
}

impl PgRootStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl RootPointerStore for PgRootStore {
    async fn cas_root(
        &self,
        owner_id: &str,
        bucket: &str,
        expected: &Cid,
        new: &Cid,
    ) -> Result<CasOutcome> {
        let res = sqlx::query(
            r#"
            INSERT INTO bucket_roots (owner_id, bucket, root_cid, version, updated_at)
            VALUES ($1, $2, $3, 1, NOW())
            ON CONFLICT (owner_id, bucket) DO UPDATE
              SET root_cid = $3, version = bucket_roots.version + 1, updated_at = NOW()
              WHERE bucket_roots.root_cid = $4
            "#,
        )
        .bind(owner_id)
        .bind(bucket)
        .bind(new.to_string())
        .bind(expected.to_string())
        .execute(&self.pool)
        .await
        .map_err(|e| CoreError::StorageError(format!("bucket_roots CAS: {e}")))?;

        if res.rows_affected() == 1 {
            return Ok(CasOutcome::Won);
        }

        // Lost the race — report the pointer another master holds now.
        let current: Option<String> = sqlx::query_scalar(
            "SELECT root_cid FROM bucket_roots WHERE owner_id = $1 AND bucket = $2",
        )
        .bind(owner_id)
        .bind(bucket)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| CoreError::StorageError(format!("bucket_roots read: {e}")))?;

        Ok(CasOutcome::Conflict {
            current: current.and_then(|s| s.parse::<Cid>().ok()),
        })
    }

    async fn get_root(&self, owner_id: &str, bucket: &str) -> Result<Option<Cid>> {
        let current: Option<String> = sqlx::query_scalar(
            "SELECT root_cid FROM bucket_roots WHERE owner_id = $1 AND bucket = $2",
        )
        .bind(owner_id)
        .bind(bucket)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| CoreError::StorageError(format!("bucket_roots read: {e}")))?;

        Ok(current.and_then(|s| s.parse::<Cid>().ok()))
    }
}
