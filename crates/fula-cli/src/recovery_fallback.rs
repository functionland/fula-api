//! GC-recovery READ-FALLBACK for the S3 object-GET path.
//!
//! After an operator ran `ipfs repo gc`, the gateway's storage_key→CID prolly
//! index lost interior nodes, so a normal `GET /{bucket}/{key}` returns 404
//! (index has no mapping) or 410 (index points at a gc'd CID). But the data is
//! still pinned + replicated in **ipfs-cluster**, whose pin NAMES encode the
//! storage keys (`<sk>`, `<sk>.chunks/<i>`, `__fula_forest_v7_nodes/<h>`,
//! `object:<bucket>/<key>`). This module mirrors that name→CID map into a
//! dedicated Postgres table and, ON A GET MISS ONLY, resolves the key from the
//! mirror and re-fetches the block straight from the cluster — turning the
//! 404/410 into a served 200. Restores both downloads AND the client forest-walk
//! (so listing works), fleet-wide, with no app update.
//!
//! Safety / design (reviewed before prod):
//! - **Miss-path only.** The fallback is invoked exclusively from the two miss
//!   branches in `get_object` (index returned None; block store returned the
//!   narrow `NotFound`/`Unavailable`). Healthy 200 reads never reach it and pay
//!   zero extra cost. It is NEVER invoked on auth/range/timeout/connection/DB
//!   errors — those preserve the original error.
//! - **Separate table.** `recovery_key_cid` is a recovery-only mirror; the
//!   pinning-service's own `pins` table is never written, so lifecycle /
//!   accounting / unpin semantics are untouched.
//! - **Tenant-safe.** A storage_key is `BLAKE3(forest_dek‖path‖salt)` — derived
//!   from the caller's own secret, globally unique and unguessable; and the GET
//!   already passed `open_bucket_for_user` before the miss. Same model the
//!   `resolve-keys` endpoint already relies on.
//! - **Kill switch.** Gated behind `recovery_read_fallback_enabled` (auto when
//!   `pins_db` + `cluster_url` are configured; `Some(false)` disables instantly).
//! - **Reconcile is fail-safe.** A cluster API failure / empty response keeps
//!   the previous mirror (never wipes it); upserts suppress no-op writes.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use bytes::Bytes;
use cid::Cid;
use fula_blockstore::{BlockStore, ClusterClient, ClusterConfig};
use sqlx::{PgPool, Row};
use tracing::{debug, info, warn};

use crate::state::AppState;

/// Observability counters (read via logs / a future metrics endpoint).
pub static FALLBACK_ATTEMPTED: AtomicU64 = AtomicU64::new(0);
pub static FALLBACK_SUCCEEDED: AtomicU64 = AtomicU64::new(0);
pub static FALLBACK_NO_MAPPING: AtomicU64 = AtomicU64::new(0);
pub static FALLBACK_BLOCK_MISSING: AtomicU64 = AtomicU64::new(0);

/// Is the recovery read-fallback (and its reconcile job) enabled?
///
/// Auto-on when a pins DB pool exists, a cluster URL is configured, and we're
/// not on the in-memory store. `Some(false)` is the explicit kill switch.
pub fn enabled(state: &AppState) -> bool {
    if state.pins_db.is_none() {
        return false;
    }
    match state.config.recovery_read_fallback_enabled {
        Some(v) => v,
        None => !state.config.use_memory_store && !state.config.cluster_url.trim().is_empty(),
    }
}

/// Backstop timeout for a single recovery attempt (DB lookup + cluster block
/// fetch). `get_block` already has its own bounded budget; this guards against a
/// degraded cluster turning a cache-miss GET into a hang — a miss must fast-fail
/// to its original 404/410.
const RECOVER_TIMEOUT: Duration = Duration::from_secs(30);

/// Resolve a GET key to its CURRENT CID via the cluster mirror. Matches the
/// **bare storage_key** (the dominant cluster pin-name shape — `<sk>`,
/// `<sk>.chunks/<i>`, `__fula_forest_v7_nodes/<h>`) and, as a fallback, the
/// older `object:{bucket}/{key}` shape; newest-synced wins on the rare overlap.
///
/// Bare-key match is tenant-safe here: a storage_key is `BLAKE3(forest_dek‖…)`
/// — globally unique and unguessable, so `name = <sk>` can only ever match this
/// exact content's pin (no cross-object collision), and the served block is
/// AEAD-encrypted regardless. Same model the `resolve-keys` endpoint relies on.
async fn resolve_key_cid(pool: &PgPool, bucket: &str, key: &str) -> Option<Cid> {
    let object_name = format!("object:{}/{}", bucket, key);
    let row = sqlx::query(
        "SELECT cid FROM recovery_key_cid \
         WHERE name = $1 OR name = $2 \
         ORDER BY synced_at DESC LIMIT 1",
    )
    .bind(key)
    .bind(&object_name)
    .fetch_optional(pool)
    .await
    .ok()??;
    let cid_str: String = row.try_get("cid").ok()?;
    cid_str.parse::<Cid>().ok()
}

/// The bytes + the CID they were served from (the caller sets `ETag` from the
/// served CID, never the stale index ETag).
pub struct RecoveredBlock {
    pub data: Bytes,
    pub cid: Cid,
}

/// On a GET miss, try to recover the block via the cluster mirror. Returns
/// `Some` only when the key resolves to a CID AND that block is fetchable;
/// otherwise `None` so the caller returns its original 404/410 unchanged.
///
/// MUST be called only from a genuine miss branch (see module docs).
pub async fn try_recover_block(state: &AppState, bucket: &str, key: &str) -> Option<RecoveredBlock> {
    if !enabled(state) {
        return None;
    }
    let pool = state.pins_db.as_ref()?;
    FALLBACK_ATTEMPTED.fetch_add(1, Ordering::Relaxed);

    let attempt = async {
        let cid = match resolve_key_cid(pool, bucket, key).await {
            Some(c) => c,
            None => {
                FALLBACK_NO_MAPPING.fetch_add(1, Ordering::Relaxed);
                return None;
            }
        };

        // Re-fetch by the CURRENT cluster CID. `get_block` runs the cluster-aware
        // bounded/peered/locate read, so it pulls the block from a holder peer
        // even when it isn't local to the master's kubo.
        match state.block_store.get_block(&cid).await {
            Ok(data) => {
                FALLBACK_SUCCEEDED.fetch_add(1, Ordering::Relaxed);
                info!(
                    bucket = %bucket,
                    cid = %cid,
                    bytes = data.len(),
                    "recovery read-fallback: served gc-orphaned key from cluster mirror"
                );
                Some(RecoveredBlock { data, cid })
            }
            Err(e) => {
                // Mapped CID still unfetchable (block genuinely gone) — don't
                // mask the original error; let the caller return its 404/410.
                FALLBACK_BLOCK_MISSING.fetch_add(1, Ordering::Relaxed);
                debug!(bucket = %bucket, cid = %cid, error = %e, "recovery read-fallback: mapped CID unfetchable");
                None
            }
        }
    };

    match tokio::time::timeout(RECOVER_TIMEOUT, attempt).await {
        Ok(opt) => opt,
        Err(_) => {
            FALLBACK_BLOCK_MISSING.fetch_add(1, Ordering::Relaxed);
            warn!(bucket = %bucket, "recovery read-fallback: timed out; returning original miss");
            None
        }
    }
}

// ───────────────────────── reconcile (background) ─────────────────────────

async fn ensure_schema(pool: &PgPool) -> Result<(), sqlx::Error> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS recovery_key_cid (\
            name TEXT PRIMARY KEY, \
            cid TEXT NOT NULL, \
            synced_at TIMESTAMPTZ NOT NULL DEFAULT now() \
        )",
    )
    .execute(pool)
    .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_recovery_key_cid_cid ON recovery_key_cid(cid)")
        .execute(pool)
        .await?;
    Ok(())
}

/// Mirror the whole cluster pinset into `recovery_key_cid` once. Returns the
/// number of rows actually changed. Bails (leaving the prior mirror intact) on
/// a cluster API failure or an empty/zero-named response — never wipes a good
/// mirror because of a transient cluster hiccup.
async fn reconcile_once(pool: &PgPool, cluster_url: &str) -> anyhow::Result<u64> {
    // Use `/allocations` (pin SPECS: cid + name), NOT `/pins` (per-peer STATUS
    // aggregation, which is far too slow — it timed out at 300s on a 345k-pin
    // cluster, while `/allocations` returns the same set in ~23s). Still buffers
    // the response transiently (~a few hundred MB at very large scale);
    // streaming is a future optimization if memory pressure shows up. The
    // generous timeout guards a slow cluster without risking the 60s default.
    let mut cfg = ClusterConfig::with_url(cluster_url.to_string());
    cfg.timeout = Duration::from_secs(300);
    let cluster = ClusterClient::new(cfg).await?;
    let pins = cluster.list_allocations().await?;

    // Dedup by name (last CID wins) so a single UNNEST upsert can't hit the
    // same conflict row twice, and so versioned duplicates collapse.
    let mut map: HashMap<String, String> = HashMap::with_capacity(pins.len());
    for p in pins {
        if let Some(name) = p.name {
            if !name.is_empty() && !p.cid.is_empty() {
                map.insert(name, p.cid);
            }
        }
    }
    if map.is_empty() {
        anyhow::bail!("cluster returned 0 named pins; keeping previous mirror");
    }

    let entries: Vec<(String, String)> = map.into_iter().collect();
    let mut changed = 0u64;
    for chunk in entries.chunks(1000) {
        let names: Vec<String> = chunk.iter().map(|(n, _)| n.clone()).collect();
        let cids: Vec<String> = chunk.iter().map(|(_, c)| c.clone()).collect();
        let res = sqlx::query(
            "INSERT INTO recovery_key_cid (name, cid, synced_at) \
             SELECT u.name, u.cid, now() FROM UNNEST($1::text[], $2::text[]) AS u(name, cid) \
             ON CONFLICT (name) DO UPDATE SET cid = EXCLUDED.cid, synced_at = now() \
             WHERE recovery_key_cid.cid IS DISTINCT FROM EXCLUDED.cid",
        )
        .bind(&names)
        .bind(&cids)
        .execute(pool)
        .await?;
        changed += res.rows_affected();
    }
    Ok(changed)
}

/// Background loop: build/refresh the cluster→CID mirror every `interval`.
/// Best-effort; a failed cycle logs and retries next tick without disturbing
/// the existing mirror.
pub async fn run_reconcile_loop(pool: PgPool, cluster_url: String, interval: Duration) {
    if let Err(e) = ensure_schema(&pool).await {
        warn!(error = %e, "recovery reconcile: schema init failed; reconcile disabled");
        return;
    }
    info!(
        cluster_url = %cluster_url,
        interval_secs = interval.as_secs(),
        "recovery reconcile: mirroring cluster pinset → recovery_key_cid"
    );
    loop {
        match reconcile_once(&pool, &cluster_url).await {
            Ok(changed) => info!(rows_changed = changed, "recovery reconcile: mirror refreshed"),
            Err(e) => warn!(error = %e, "recovery reconcile: cycle failed (previous mirror kept)"),
        }
        tokio::time::sleep(interval).await;
    }
}

/// Spawn the reconcile loop iff the feature is enabled. Safe no-op otherwise.
/// Called from both server entry points.
pub fn spawn_reconcile_if_enabled(state: &std::sync::Arc<AppState>) {
    if !enabled(state) {
        return;
    }
    let Some(pool) = state.pins_db.clone() else {
        return;
    };
    let cluster_url = state.config.cluster_url.clone();
    let interval = Duration::from_secs(state.config.recovery_reconcile_interval_secs.max(60));
    tokio::spawn(async move {
        run_reconcile_loop(pool, cluster_url, interval).await;
    });
    info!("✓ Recovery read-fallback reconcile started");
}
