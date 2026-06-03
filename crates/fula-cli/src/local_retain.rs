//! Local-retain-until-replicated verifier (GC-safety).
//!
//! Companion to [`crate::local_retain_queue`]. Holds the shared context the PUT
//! handler uses to *pin-locally-and-enqueue* a freshly stored block, and the
//! background loop that drains the backlog.
//!
//! ## The invariant
//!
//! A block leaves the master's local store ONLY after it is durably replicated
//! elsewhere. Concretely, each verifier cycle, per backlog CID:
//!   1. ask the cluster how many DISTINCT **non-master** holders report status
//!      exactly `"pinned"` ([`ClusterClient::pinned_holder_count`]);
//!   2. if that count `>=` the cluster's min-replication → drop the local pin
//!      (`pin/rm`) and remove the CID from the backlog — now `ipfs repo gc` may
//!      safely reclaim it;
//!   3. otherwise re-assert the local pin (`pin/add`, idempotent) so the block
//!      stays gc-safe even if the PUT-time pin failed.
//!
//! Status-first ordering avoids pin→unpin churn on already-replicated blocks.
//! Under-counting is always safe (block stays retained); the safety hole would
//! be over-counting, which `pinned_holder_count` is written to avoid (it counts
//! only confirmed `"pinned"`, never `"pinning"`/allocations, and excludes the
//! master itself).

use crate::error::ApiError;
use crate::local_retain_queue::LocalRetainQueue;
use cid::Cid;
use fula_blockstore::{BlockStoreError, ClusterClient, IpfsBlockStore, PinOutcome};
use futures::StreamExt;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, info, warn};

/// Per local pin/unpin RPC.
const PIN_OP_TIMEOUT: Duration = Duration::from_secs(15);
/// Per cluster `get_pin_status` call.
const STATUS_TIMEOUT: Duration = Duration::from_secs(10);
/// Max backlog CIDs processed per cycle.
const VERIFY_BATCH: usize = 256;
/// Max concurrent status-checks per cycle (bounds load on the cluster API).
const MAX_CONCURRENT_CHECKS: usize = 8;
/// Backfill runs at LOW concurrency + a per-op throttle so the one-time sweep of
/// a large datastore never saturates the kubo daemon and starves live
/// reads/uploads. (Default-on backfill at high concurrency previously pushed
/// ~300 pin ops/s and timed kubo out.) Slower, but safe to leave running.
const BACKFILL_CONCURRENCY: usize = 2;
const BACKFILL_THROTTLE: Duration = Duration::from_millis(50);
/// Warn once the oldest backlog entry has been awaiting replication longer than
/// this — a sign replication is stuck (cluster down / holders unhealthy) and a
/// growing set of blocks is pinned locally and never being offloaded.
const STUCK_AGE_WARN_SECS: u64 = 3600;

/// Shared local-retain state: the durable backlog plus the handles needed to
/// hold/drop local pins and read cluster replication status.
pub struct LocalRetainContext {
    queue: LocalRetainQueue,
    kubo: IpfsBlockStore,
    cluster: ClusterClient,
    /// The master's OWN cluster peer id — excluded from the replicated-holder
    /// count so the master holding a block locally doesn't count as a replica.
    master_peer_id: String,
    /// Drop the local copy only once this many DISTINCT non-master holders
    /// report `"pinned"` (the cluster's configured min replication factor).
    min_repl: usize,
}

impl LocalRetainContext {
    pub fn new(
        queue: LocalRetainQueue,
        kubo: IpfsBlockStore,
        cluster: ClusterClient,
        master_peer_id: String,
        min_repl: usize,
    ) -> Self {
        Self {
            queue,
            kubo,
            cluster,
            master_peer_id,
            // A zero/negative configured min would unpin immediately on 0
            // holders — clamp to at least 1 so we never drop the only copy.
            min_repl: min_repl.max(1),
        }
    }

    /// Pin `cid` locally on the master's kubo and record it in the backlog.
    /// Called from the PUT path right after the block is stored, to close the
    /// gc window before we return 200.
    ///
    /// **Pin failure is FATAL** (operator policy): the PUT must never return
    /// 200 for a block that isn't gc-safe, so a failed local pin propagates as
    /// an `ApiError` (→ 5xx) and the handler fails the upload — the client then
    /// retries rather than believing an un-retained write succeeded. The CID is
    /// still enqueued first (best-effort) so the verifier *also* re-asserts the
    /// pin on its next cycle, belt-and-suspenders alongside the client retry.
    ///
    /// The **enqueue itself is best-effort**: once the block is pinned it is
    /// already gc-safe, and a backlog-write failure only defers its *offload*
    /// until the next startup backfill (a storage leak, never data loss), so it
    /// must not fail the PUT.
    ///
    /// We only enqueue blocks we *freshly* direct-pinned. A block that is
    /// already pinned recursively (by a cluster pin) is gc-safe AND
    /// cluster-managed, so it needs no local-retain tracking — skipping it is
    /// what keeps the backlog small instead of mirroring the whole datastore.
    pub async fn retain(&self, cid: &Cid) -> Result<(), ApiError> {
        match self.kubo.pin_local(cid, PIN_OP_TIMEOUT).await {
            // Fresh direct pin held by us → track it so the verifier can drop it
            // once it is replicated to >= min_repl non-master holders.
            Ok(PinOutcome::Pinned) => {
                if let Err(e) = self.queue.enqueue(cid) {
                    warn!(cid = %cid, error = %e, "local-retain: backlog enqueue failed; block stays pinned (gc-safe) but untracked until next backfill");
                }
                Ok(())
            }
            // Already covered by a cluster recursive pin → gc-safe and
            // cluster-managed (it replicates + eventually drops it). Nothing for
            // local-retain to do or track.
            Ok(PinOutcome::AlreadyPinned) => Ok(()),
            // Genuine pin failure → FATAL (never 200 a block that isn't gc-safe).
            // Still enqueue so the verifier re-asserts the pin next cycle even if
            // the client doesn't retry.
            Err(e) => {
                if let Err(e2) = self.queue.enqueue(cid) {
                    warn!(cid = %cid, error = %e2, "local-retain: backlog enqueue failed after a failed pin");
                }
                warn!(cid = %cid, error = %e, "local-retain: PUT-time local pin failed (fatal) — failing the upload so the client retries");
                Err(ApiError::from(e))
            }
        }
    }

    /// Release a previously-retained block: stop tracking it in the backlog and
    /// unpin it locally so `ipfs repo gc` can reclaim it. Used to drop a
    /// SUPERSEDED index node (an old prolly-tree version no longer referenced by
    /// the current root) on a flush, so pinning every index node for gc-safety
    /// doesn't accumulate un-reclaimable index versions.
    ///
    /// Best-effort and **never fatal** — a failed release only defers reclaim (a
    /// storage leak, never data loss). Durability of *live* nodes is governed by
    /// the cluster pin, not this local pin.
    pub async fn release(&self, cid: &Cid) {
        if let Err(e) = self.queue.remove(cid) {
            warn!(cid = %cid, error = %e, "local-retain: backlog remove failed during release");
        }
        if let Err(e) = self.kubo.unpin_local(cid, PIN_OP_TIMEOUT).await {
            warn!(cid = %cid, error = %e, "local-retain: unpin_local failed during release (block stays locally pinned until next gc-safe sweep)");
        }
    }

    /// Pin `cid` locally on the master's kubo for gc-safety WITHOUT enqueuing it
    /// to the replication backlog. Used by the one-time index-node backfill:
    /// those nodes earn a durable cluster pin (and backlog tracking) on the
    /// bucket's next PUT, so the backfill only needs to make them gc-safe now.
    /// A direct pin also keeps the backlog from filling with cluster-invisible
    /// index nodes that the verifier could never drain. `AlreadyPinned` ⇒ Ok.
    pub async fn pin_local_only(&self, cid: &Cid) -> Result<(), ApiError> {
        self.kubo
            .pin_local(cid, PIN_OP_TIMEOUT)
            .await
            .map(|_| ())
            .map_err(ApiError::from)
    }

    /// Pending backlog size (monitoring).
    pub fn pending_count(&self) -> u64 {
        self.queue.pending_count().unwrap_or(0)
    }

    /// Emit a backlog depth/age line for monitoring after each verifier cycle.
    /// Silent when the backlog is empty (the steady state). Escalates to a
    /// warning once blocks have been waiting on replication longer than
    /// [`STUCK_AGE_WARN_SECS`] — i.e. replication is stuck and the locally
    /// retained set is growing without being offloaded.
    fn log_backlog_stats(&self) {
        match self.queue.backlog_stats() {
            Ok((0, _)) => {}
            Ok((pending, oldest_age_ms)) => {
                let oldest_age_secs = oldest_age_ms.unwrap_or(0) / 1000;
                if oldest_age_secs >= STUCK_AGE_WARN_SECS {
                    warn!(
                        pending,
                        oldest_age_secs,
                        "local-retain backlog: blocks awaiting replication for a long time — check cluster replication / holder health"
                    );
                } else {
                    info!(pending, oldest_age_secs, "local-retain backlog status");
                }
            }
            Err(e) => debug!(error = %e, "local-retain: backlog stats read failed"),
        }
    }

    /// One-time backfill: pin + enqueue every block already in the master's
    /// local store, so the verifier protects pre-existing un-replicated data
    /// (blocks that predate this feature, at risk on the next gc). Throttled by
    /// bounded concurrency; best-effort with progress logging. Safe to skip on
    /// very large datastores — the ongoing per-upload path still protects all
    /// new writes.
    pub async fn backfill(&self) {
        // `refs local` can be large + slow on a big store — generous timeout.
        let cids = match self.kubo.refs_local(Duration::from_secs(300)).await {
            Ok(c) => c,
            Err(e) => {
                warn!(error = %e, "local-retain backfill: could not list local refs; skipping");
                return;
            }
        };
        let total = cids.len();
        if total == 0 {
            return;
        }
        info!(
            total,
            concurrency = BACKFILL_CONCURRENCY,
            throttle_ms = BACKFILL_THROTTLE.as_millis() as u64,
            "local-retain backfill: gently pinning pre-existing local blocks (one-time, rate-limited so it never saturates kubo — may take hours on a large store; skip with --no-local-retain-backfill)"
        );
        let done = std::sync::atomic::AtomicUsize::new(0);
        futures::stream::iter(cids)
            .for_each_concurrent(BACKFILL_CONCURRENCY, |cid| {
                let done = &done;
                async move {
                    // Best-effort during backfill: a pin failure on a
                    // pre-existing block is non-fatal here (these blocks were
                    // already at risk before the feature); the per-upload path
                    // enforces the fatal contract for new writes. With smart
                    // retain, already-recursively-pinned blocks are a fast no-op
                    // and are NOT enqueued, so the backlog stays small.
                    let _ = self.retain(&cid).await;
                    // Gentle: pace the sweep so it doesn't compete with live
                    // reads/uploads for the kubo daemon.
                    tokio::time::sleep(BACKFILL_THROTTLE).await;
                    let n = done.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                    if n % 5000 == 0 {
                        info!(done = n, total, "local-retain backfill: progress");
                    }
                }
            })
            .await;
        info!(total, "local-retain backfill: complete");
    }

    /// One verifier pass over a batch of the backlog.
    async fn verify_once(&self) {
        let batch = match self.queue.list(VERIFY_BATCH) {
            Ok(b) => b,
            Err(e) => {
                warn!(error = %e, "local-retain: backlog list failed this cycle");
                return;
            }
        };
        if batch.is_empty() {
            return;
        }
        futures::stream::iter(batch)
            .for_each_concurrent(MAX_CONCURRENT_CHECKS, |cid| self.process_one(cid))
            .await;
    }

    /// Process one backlog CID: drop-if-replicated, else re-assert the pin.
    async fn process_one(&self, cid: Cid) {
        let count = match tokio::time::timeout(
            STATUS_TIMEOUT,
            self.cluster.pinned_holder_count(&cid, &self.master_peer_id),
        )
        .await
        {
            Ok(Ok(n)) => n,
            // Not tracked as a cluster pin yet (or no peer has it) → treat as
            // 0 replicas; keep it locally retained.
            Ok(Err(BlockStoreError::NotFound(_))) => 0,
            Ok(Err(e)) => {
                debug!(cid = %cid, error = %e, "local-retain: pin status failed; retry next cycle");
                return;
            }
            Err(_) => {
                debug!(cid = %cid, "local-retain: pin status timed out; retry next cycle");
                return;
            }
        };

        if count >= self.min_repl {
            // Durably replicated elsewhere → safe to drop the master's copy.
            match self.kubo.unpin_local(&cid, PIN_OP_TIMEOUT).await {
                Ok(()) => match self.queue.remove(&cid) {
                    Ok(()) => debug!(cid = %cid, holders = count, "local-retain: replicated; dropped local pin"),
                    Err(e) => warn!(cid = %cid, error = %e, "local-retain: unpinned but backlog-remove failed (idempotent; retries)"),
                },
                Err(e) => warn!(cid = %cid, error = %e, "local-retain: local unpin failed; retry next cycle"),
            }
        } else {
            // Not yet replicated → make sure it stays gc-safe (idempotent;
            // covers a PUT-time pin that failed).
            if let Err(e) = self.kubo.pin_local(&cid, PIN_OP_TIMEOUT).await {
                // Re-assert failed. If the block is ALSO gone from the master's
                // local store, an under-replicated block has lost its only
                // master copy → possible in-flight data loss. Probe local
                // presence (offline, local-only) to escalate at the right
                // severity instead of burying it at debug.
                if matches!(
                    self.kubo.get_raw_block_offline(&cid, STATUS_TIMEOUT).await,
                    Err(BlockStoreError::NotFound(_))
                ) {
                    error!(
                        cid = %cid,
                        holders = count,
                        min_repl = self.min_repl,
                        error = %e,
                        "local-retain: POSSIBLE DATA LOSS — under-replicated block is missing from the master local store and re-pin failed"
                    );
                } else {
                    debug!(cid = %cid, error = %e, "local-retain: re-assert local pin failed; retry next cycle");
                }
            }
        }
    }
}

/// Spawn the verifier loop. Returns immediately; the task lives for the
/// process lifetime (mirrors the other master background tasks).
pub fn spawn_verifier(ctx: Arc<LocalRetainContext>, interval: Duration) {
    info!(
        interval_secs = interval.as_secs(),
        min_repl = ctx.min_repl,
        pending = ctx.pending_count(),
        "local-retain verifier started"
    );
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(interval);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // Skip the immediate first tick so startup isn't a no-op burst.
        tick.tick().await;
        loop {
            tick.tick().await;
            ctx.verify_once().await;
            ctx.log_backlog_stats();
        }
    });
}
