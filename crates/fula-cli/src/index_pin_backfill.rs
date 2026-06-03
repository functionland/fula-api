//! One-time startup backfill for the P0 index-node gc-safety fix.
//!
//! The per-PUT path (`handlers::object`) pins a bucket's index nodes on its
//! first write after rollout, but an IDLE bucket would stay gc-exposed until
//! its next PUT. This one-time sweep makes every existing bucket's index nodes
//! gc-safe immediately: it re-opens each bucket, enumerates its index nodes
//! (the walk re-localizes any node the cluster still holds), and **direct
//! local-pins** them.
//!
//! Direct local pins (NOT the replication backlog): the nodes earn a durable
//! cluster pin + diff-set tracking on the bucket's next PUT, so the backfill
//! only needs to close the local-gc window now — and a direct pin keeps the
//! local-retain backlog from filling with cluster-invisible index nodes the
//! verifier could never drain. Throttled + best-effort; a bucket whose index is
//! un-walkable (hard-loss) is skipped and logged. Run BEFORE re-enabling
//! `ipfs repo gc`.

use crate::state::AppState;
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};

/// Gentle per-node delay so the one-time sweep never saturates kubo (degraded
/// nodes are fetched from the cluster on pin, which is the real cost).
const BACKFILL_THROTTLE: Duration = Duration::from_millis(20);

/// Re-pin every existing bucket's index nodes for gc-safety. Idempotent
/// (already-pinned nodes are a fast no-op) and safe to run on every startup.
pub async fn run_index_pin_backfill(state: Arc<AppState>) {
    let Some(lr) = state.local_retain.clone() else {
        return; // gc-safety feature off — nothing to back-fill
    };
    let buckets = state.bucket_manager.list_buckets_with_keys();
    let total = buckets.len();
    info!(buckets = total, "index-node backfill: starting one-time gc-safety sweep");

    let mut healed = 0usize;
    let mut skipped = 0usize;
    let mut pinned_total = 0usize;

    for (internal_key, _meta) in buckets {
        let Some((user_id, bucket_name)) = internal_key.split_once(':') else {
            warn!(key = %internal_key, "index-node backfill: unparseable bucket key; skipping");
            skipped += 1;
            continue;
        };

        // Re-open the bucket and enumerate its index nodes. The walk fetches any
        // cluster-recoverable (degraded) node, re-localizing it.
        let bucket = match state
            .bucket_manager
            .open_bucket_for_user(user_id, bucket_name)
            .await
        {
            Ok(b) => b,
            Err(e) => {
                warn!(bucket = %bucket_name, error = %e, "index-node backfill: open failed; skipping");
                skipped += 1;
                continue;
            }
        };
        let nodes = match bucket.index_node_cids().await {
            Ok(n) => n,
            Err(e) => {
                warn!(bucket = %bucket_name, error = %e, "index-node backfill: index un-walkable (hard-loss?); skipping");
                skipped += 1;
                continue;
            }
        };

        let mut bucket_ok = true;
        for cid in &nodes {
            if let Err(e) = lr.pin_local_only(cid).await {
                warn!(bucket = %bucket_name, cid = %cid, error = %e, "index-node backfill: local pin failed; will be retried on the bucket's next PUT");
                bucket_ok = false;
                break;
            }
            pinned_total += 1;
            tokio::time::sleep(BACKFILL_THROTTLE).await;
        }
        if bucket_ok {
            healed += 1;
        } else {
            skipped += 1;
        }
    }

    info!(
        total,
        healed,
        skipped,
        pinned_total,
        "✓ index-node backfill complete — existing buckets' index nodes are gc-safe (ipfs repo gc may be re-enabled)"
    );
}
