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
use fula_blockstore::cluster::PinInfo;
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
/// Pin name used when the verifier RE-DRIVES a cluster pin for an
/// under-replicated backlog block (distinguishable in `pin ls` for triage).
const REDRIVE_PIN_NAME: &str = "local-retain-redrive";
/// Stop issuing cluster pin re-drives once this many cluster API calls have
/// failed in a row — a crude circuit breaker so a struggling/slow cluster
/// doesn't get flooded with redundant pin requests (status-timeout death
/// spiral). Resets to 0 on the first successful status call. Local pins are
/// still re-asserted while the breaker is open, so blocks stay gc-safe.
const STATUS_FAIL_BREAKER: u32 = 20;
/// New-data drop guard: a block must be observed at `>= min_repl` non-master
/// holders for AT LEAST this long before the master drops its local copy. This
/// absorbs eventually-consistent cluster status (a holder can report "pinned"
/// before it has fully materialised every leaf) so an unsupervised drop never
/// fires on a single transient/stale snapshot. Tunable via
/// `FULA_LOCAL_RETAIN_SETTLE_SECS` (0 = drop as soon as confirmed — only set
/// for an already-audited legacy drain).
const SETTLE_DEFAULT_SECS: u64 = 300;

/// Read a boolean knob from the environment. Unset or unrecognised → `default`.
fn env_bool(name: &str, default: bool) -> bool {
    match std::env::var(name)
        .ok()
        .as_deref()
        .map(|s| s.trim().to_ascii_lowercase())
        .as_deref()
    {
        Some("1" | "true" | "yes" | "on") => true,
        Some("0" | "false" | "no" | "off") => false,
        _ => default,
    }
}

/// Count DISTINCT non-master peers reporting status exactly `"pinned"` for a
/// pin. Mirrors [`ClusterClient::pinned_holder_count`] but reads an already
/// fetched [`PinInfo`] so the verifier needs only ONE status call per block
/// (it also wants the in-progress signal below). Under-counts by design —
/// only confirmed `"pinned"` ever counts toward dropping the master copy.
fn count_non_master_pinned(info: &PinInfo, master: &str) -> usize {
    info.peer_map
        .as_ref()
        .map(|m| {
            m.iter()
                .filter(|(id, st)| {
                    id.as_str() != master && st.status.eq_ignore_ascii_case("pinned")
                })
                .count()
        })
        .unwrap_or(0)
}

/// True if any non-master peer already has the block pinned OR is actively
/// pinning/queued — i.e. replication is already underway, so re-driving the
/// cluster pin would be redundant. Used to avoid hammering the cluster
/// consensus with repeat pin requests every cycle.
fn has_active_non_master_holder(info: &PinInfo, master: &str) -> bool {
    info.peer_map
        .as_ref()
        .map(|m| {
            m.iter().any(|(id, st)| {
                id.as_str() != master
                    && matches!(
                        st.status.to_ascii_lowercase().as_str(),
                        "pinned" | "pinning" | "pin_queued" | "queued"
                    )
            })
        })
        .unwrap_or(false)
}

/// The verifier's decision for one backlog block, given its cluster replication
/// state. Pure + total so the policy is unit-tested directly (the HTTP wiring
/// in `process_one` stays a thin executor of these actions).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RetainAction {
    /// Replicated on `>= min_repl` non-master holders → drop the master's local
    /// copy (and the root's leaves too, when `drop_leaves`).
    Drop { drop_leaves: bool },
    /// Under-replicated → keep gc-safe locally AND re-drive the cluster pin so
    /// replication actually starts/resumes.
    KeepAndRedrive,
    /// Under-replicated but replication is already underway, or re-drive is
    /// disabled / the cluster-API breaker is open → keep gc-safe locally only.
    KeepOnly,
}

/// Decide what to do with one backlog block.
///
/// * **Drop** only when ALL of: confirmed on `>= min_repl` non-master holders;
///   `auto_drop` on (a replicate-only supervised migration never unpins);
///   the cluster-API breaker is CLOSED (don't delete the only complete copy
///   while the cluster's own health signal is flaky); AND replication has been
///   **stable for the settle window** (`settled`). The settle guards against a
///   transient / lagging / phantom "pinned" status — an eventually-consistent
///   cluster can report a holder pinned before it has materialised every leaf,
///   and dropping on a single snapshot would bet the master's only complete
///   copy on that. No drop is unsupervised AND instantaneous.
/// * **Re-drive** only when under-replicated, re-drive enabled, nothing already
///   in progress, and the breaker is closed (don't pile onto a sick cluster).
/// * Otherwise keep the block gc-safe locally and do nothing else.
fn decide(
    holders: usize,
    min_repl: usize,
    auto_drop: bool,
    has_leaves: bool,
    redrive: bool,
    in_progress: bool,
    breaker_open: bool,
    settled: bool,
) -> RetainAction {
    if holders >= min_repl && auto_drop && !breaker_open && settled {
        return RetainAction::Drop {
            drop_leaves: has_leaves,
        };
    }
    if holders < min_repl && redrive && !in_progress && !breaker_open {
        return RetainAction::KeepAndRedrive;
    }
    RetainAction::KeepOnly
}

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
    /// Sweep cursor (redb key of the last visited backlog entry) so the
    /// verifier rotates through the WHOLE backlog across cycles instead of
    /// re-processing the lowest-key head forever (head-of-line starvation).
    /// In-memory: a restart simply resumes the sweep from the start, which
    /// still makes full progress — nothing is lost.
    cursor: std::sync::Mutex<Option<Vec<u8>>>,
    /// Re-drive a cluster pin for under-replicated backlog blocks (default on,
    /// `FULA_LOCAL_RETAIN_REDRIVE`). This is what actually replicates blocks
    /// whose original cluster pin never succeeded — without it the backlog can
    /// never drain. Idempotent at the cluster.
    redrive: bool,
    /// Auto-drop the local copy once a block is confirmed replicated to
    /// `>= min_repl` non-master holders (default on, `FULA_LOCAL_RETAIN_AUTO_DROP`).
    /// `false` = REPLICATE-ONLY: the verifier re-drives + keeps blocks gc-safe
    /// but NEVER unpins — used for the supervised one-time migration of the
    /// legacy backlog, where the operator audits real holders before
    /// authorising the irreversible drop of ~105 GB.
    auto_drop: bool,
    /// Consecutive cluster status/pin failures (circuit breaker, see
    /// [`STATUS_FAIL_BREAKER`]). `Relaxed` is fine — it's a fuzzy health gauge,
    /// not a correctness lock.
    status_failures: std::sync::atomic::AtomicU32,
    /// Drop-settle tracker: CID → first time it was seen at `>= min_repl`
    /// non-master holders. A drop requires that to persist for [`Self::settle_dur`];
    /// under-replicated / dropped CIDs are evicted. In-memory (a restart just
    /// re-starts the settle clock — safe, never drops earlier).
    settle: dashmap::DashMap<Cid, std::time::Instant>,
    /// How long replication must be stable before a drop (see [`SETTLE_DEFAULT_SECS`]).
    settle_dur: Duration,
}

impl LocalRetainContext {
    pub fn new(
        queue: LocalRetainQueue,
        kubo: IpfsBlockStore,
        cluster: ClusterClient,
        master_peer_id: String,
        min_repl: usize,
    ) -> Self {
        let redrive = env_bool("FULA_LOCAL_RETAIN_REDRIVE", true);
        let auto_drop = env_bool("FULA_LOCAL_RETAIN_AUTO_DROP", true);
        let settle_secs = std::env::var("FULA_LOCAL_RETAIN_SETTLE_SECS")
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .unwrap_or(SETTLE_DEFAULT_SECS);
        info!(
            redrive,
            auto_drop,
            settle_secs,
            min_repl = min_repl.max(1),
            "local-retain: verifier configured (redrive re-pins under-replicated backlog blocks; auto_drop=false = replicate-only for the supervised migration; settle_secs = how long replication must hold before a drop)"
        );
        Self {
            queue,
            kubo,
            cluster,
            master_peer_id,
            // A zero/negative configured min would unpin immediately on 0
            // holders — clamp to at least 1 so we never drop the only copy.
            min_repl: min_repl.max(1),
            cursor: std::sync::Mutex::new(None),
            redrive,
            auto_drop,
            status_failures: std::sync::atomic::AtomicU32::new(0),
            settle: dashmap::DashMap::new(),
            settle_dur: Duration::from_secs(settle_secs),
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

    /// Like [`Self::retain`] but for a large-object **root** (a UnixFS dag-pb
    /// root produced by chunking): direct-pin the root AND each of its raw
    /// leaves, then enqueue ONLY the root, flagged `has_leaves`. The verifier
    /// tracks the root — which IS individually cluster-pinned, so its status
    /// reflects real replication — and drops the leaves with it.
    ///
    /// Why this shape:
    ///   * closes the gc gap for large-object leaves WITHOUT a blanket
    ///     `refs local` backfill, so ONLY Fula data is ever pinned (never
    ///     transient IPFS-network cache);
    ///   * keeps the backlog small (roots, not leaves) and the cluster lean
    ///     (no per-leaf cluster pins — the root's recursive cluster pin
    ///     replicates the leaves);
    ///   * all pins are DIRECT, so dropping them never tears out a cluster
    ///     recursive pin (collision-safe).
    ///
    /// Root pin failure is FATAL (same contract as [`Self::retain`]); leaf pin
    /// failures are best-effort (logged) — the root's cluster pin is the
    /// replication backstop and the verifier re-drives it.
    pub async fn retain_with_leaves(&self, root: &Cid) -> Result<(), ApiError> {
        match self.kubo.pin_local(root, PIN_OP_TIMEOUT).await {
            // Fresh root → also pin its leaves (gc-safe) and track the root.
            Ok(PinOutcome::Pinned) => {
                // Leaves were just stored by the UnixFS add → present locally,
                // so enumerate OFFLINE (never hangs on the network). A DIRECT
                // pin of the dag-pb root does NOT protect its descendants, so if
                // we can't enumerate + pin every leaf the leaves are gc-exposed
                // until replication — FATAL, fail the upload (the client retries;
                // re-pinning is idempotent). The root stays pinned + enqueued so
                // the verifier retries too.
                let leaves = match self.kubo.refs_recursive_offline(root, PIN_OP_TIMEOUT).await {
                    Ok(l) => l,
                    Err(e) => {
                        let _ = self.queue.enqueue_with_leaves(root);
                        warn!(cid = %root, error = %e, "local-retain: leaf enumeration failed for large-object root (fatal) — failing the upload so the client retries");
                        return Err(ApiError::from(e));
                    }
                };
                if !leaves.is_empty() {
                    let failed = self.kubo.pin_local_many(&leaves, PIN_OP_TIMEOUT).await;
                    if failed > 0 {
                        let _ = self.queue.enqueue_with_leaves(root);
                        warn!(root = %root, failed, total = leaves.len(), "local-retain: large-object leaves failed to pin (fatal) — failing the upload so the client retries");
                        return Err(ApiError::from(BlockStoreError::PinFailed(format!(
                            "{} of {} large-object leaves not gc-safe",
                            failed,
                            leaves.len()
                        ))));
                    }
                }
                if let Err(e) = self.queue.enqueue_with_leaves(root) {
                    warn!(cid = %root, error = %e, "local-retain: backlog enqueue (with-leaves) failed; root stays pinned but untracked until next backfill");
                }
                Ok(())
            }
            // Already covered by a cluster recursive pin → the cluster holds the
            // root AND its leaves; nothing for us to pin or track.
            Ok(PinOutcome::AlreadyPinned) => Ok(()),
            Err(e) => {
                let _ = self.queue.enqueue_with_leaves(root);
                warn!(cid = %root, error = %e, "local-retain: PUT-time local pin of large-object root failed (fatal) — failing the upload so the client retries");
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

    /// One verifier pass over a batch of the backlog, advancing a persistent
    /// in-memory cursor so successive cycles sweep the ENTIRE backlog rather
    /// than re-checking the same lowest-key head every cycle. (Head-of-line
    /// bug: under-replicated blocks are never removed, so a plain
    /// `list(VERIFY_BATCH)` returns the same blocked head forever and one
    /// permanently-stuck block stalls all the rest.)
    async fn verify_once(&self) {
        let after = self.cursor.lock().unwrap().clone();
        let (batch, next) = match self.queue.list_from(after.as_deref(), VERIFY_BATCH) {
            Ok(x) => x,
            Err(e) => {
                warn!(error = %e, "local-retain: backlog list failed this cycle");
                return;
            }
        };
        if batch.is_empty() {
            // Reached the end of the keyspace → wrap to the start next cycle.
            *self.cursor.lock().unwrap() = None;
            return;
        }
        *self.cursor.lock().unwrap() = next;
        futures::stream::iter(batch)
            .for_each_concurrent(MAX_CONCURRENT_CHECKS, |(cid, has_leaves)| {
                self.process_one(cid, has_leaves)
            })
            .await;
    }

    /// Process one backlog CID:
    ///   * confirmed replicated (`>= min_repl` non-master holders) AND
    ///     `auto_drop` → drop the master's local copy;
    ///   * otherwise → keep it gc-safe locally (re-assert the pin) AND
    ///     RE-DRIVE its cluster pin if replication isn't already underway, so a
    ///     block whose original cluster pin never succeeded actually replicates
    ///     (the fix for the never-draining backlog).
    ///
    /// A single `get_pin_status` call serves both the holder count and the
    /// "already pinning?" check, so we don't re-issue a pin needlessly.
    ///
    /// NOTE on scope: the verifier acts ONLY on CIDs already in the backlog,
    /// which (with the blanket `refs local` backfill disabled) are exclusively
    /// blocks the PUT path stored on a user's behalf — never transient
    /// IPFS-network cache. So re-drive replicates Fula data only; it never
    /// scans or pins arbitrary local blocks.
    async fn process_one(&self, cid: Cid, has_leaves: bool) {
        use std::sync::atomic::Ordering;
        let info = match tokio::time::timeout(STATUS_TIMEOUT, self.cluster.get_pin_status(&cid))
            .await
        {
            Ok(Ok(info)) => {
                self.status_failures.store(0, Ordering::Relaxed);
                Some(info)
            }
            // Not tracked in the cluster pinset at all → 0 holders; a prime
            // candidate for re-drive (its original pin never landed).
            Ok(Err(BlockStoreError::NotFound(_))) => {
                self.status_failures.store(0, Ordering::Relaxed);
                None
            }
            Ok(Err(e)) => {
                self.status_failures.fetch_add(1, Ordering::Relaxed);
                debug!(cid = %cid, error = %e, "local-retain: pin status failed; retry next cycle");
                return;
            }
            Err(_) => {
                self.status_failures.fetch_add(1, Ordering::Relaxed);
                debug!(cid = %cid, "local-retain: pin status timed out; retry next cycle");
                return;
            }
        };

        let holders = info
            .as_ref()
            .map(|i| count_non_master_pinned(i, &self.master_peer_id))
            .unwrap_or(0);
        let in_progress = info
            .as_ref()
            .map(|i| has_active_non_master_holder(i, &self.master_peer_id))
            .unwrap_or(false);
        let breaker_open =
            self.status_failures.load(Ordering::Relaxed) >= STATUS_FAIL_BREAKER;

        // Drop-settle: require replication observed at >= min_repl to PERSIST
        // for `settle_dur` before unpinning — guards a transient / lagging /
        // phantom "pinned" from deleting the master's only complete copy. Track
        // the first-confirmed time per CID; evict when it falls back under
        // threshold. settle_dur == 0 → settled immediately.
        let settled = if holders >= self.min_repl {
            let first = *self.settle.entry(cid).or_insert_with(std::time::Instant::now);
            first.elapsed() >= self.settle_dur
        } else {
            self.settle.remove(&cid);
            false
        };

        match decide(
            holders,
            self.min_repl,
            self.auto_drop,
            has_leaves,
            self.redrive,
            in_progress,
            breaker_open,
            settled,
        ) {
            RetainAction::Drop { drop_leaves } => {
                // Confirmed + stable → stop tracking the settle for this CID.
                self.settle.remove(&cid);
                // Durably replicated elsewhere → drop the master's copy. For a
                // large-object root, first drop the leaves we direct-pinned
                // alongside it — enumerated OFFLINE (a damaged root yields a
                // partial set; un-enumerable leaves just stay pinned, the safe
                // direction) and BEFORE unpinning the root, so its DAG is still
                // intact to walk.
                if drop_leaves {
                    match self.kubo.refs_recursive_offline(&cid, STATUS_TIMEOUT).await {
                        Ok(leaves) if !leaves.is_empty() => {
                            self.kubo.unpin_local_many(&leaves, PIN_OP_TIMEOUT).await;
                            debug!(cid = %cid, leaves = leaves.len(), "local-retain: dropped large-object root's leaves");
                        }
                        Ok(_) => {}
                        Err(e) => debug!(cid = %cid, error = %e, "local-retain: leaf enumerate failed on drop; leaves stay pinned (safe)"),
                    }
                }
                match self.kubo.unpin_local(&cid, PIN_OP_TIMEOUT).await {
                    Ok(()) => match self.queue.remove(&cid) {
                        Ok(()) => debug!(cid = %cid, holders, "local-retain: replicated; dropped local pin"),
                        Err(e) => warn!(cid = %cid, error = %e, "local-retain: unpinned but backlog-remove failed (idempotent; retries)"),
                    },
                    Err(e) => warn!(cid = %cid, error = %e, "local-retain: local unpin failed; retry next cycle"),
                }
            }
            action @ (RetainAction::KeepAndRedrive | RetainAction::KeepOnly) => {
                // Under-replicated (or auto_drop disabled) → keep it gc-safe
                // locally (idempotent; covers a PUT-time pin that failed).
                if let Err(e) = self.kubo.pin_local(&cid, PIN_OP_TIMEOUT).await {
                    // Re-assert failed. If the block is ALSO gone from the
                    // master's local store, an under-replicated block has lost
                    // its only master copy → possible in-flight data loss.
                    if matches!(
                        self.kubo.get_raw_block_offline(&cid, STATUS_TIMEOUT).await,
                        Err(BlockStoreError::NotFound(_))
                    ) {
                        error!(
                            cid = %cid,
                            holders,
                            min_repl = self.min_repl,
                            error = %e,
                            "local-retain: POSSIBLE DATA LOSS — under-replicated block is missing from the master local store and re-pin failed"
                        );
                    } else {
                        debug!(cid = %cid, error = %e, "local-retain: re-assert local pin failed; retry next cycle");
                    }
                }
                // RE-DRIVE the cluster pin so replication actually starts/resumes
                // (decide() already gated on !in_progress && !breaker_open).
                if action == RetainAction::KeepAndRedrive {
                    match self.cluster.pin_cid(&cid, Some(REDRIVE_PIN_NAME)).await {
                        Ok(_) => debug!(cid = %cid, "local-retain: re-drove cluster pin (under-replicated)"),
                        Err(e) => {
                            self.status_failures.fetch_add(1, Ordering::Relaxed);
                            debug!(cid = %cid, error = %e, "local-retain: re-drive pin failed; retry next cycle");
                        }
                    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use fula_blockstore::cluster::PeerPinStatus;
    use std::collections::HashMap;

    fn peer(status: &str) -> PeerPinStatus {
        PeerPinStatus {
            peername: None,
            status: status.to_string(),
            timestamp: None,
            error: None,
        }
    }

    /// PinInfo whose peer_map has the master at `master_status` + one entry per
    /// `others` status.
    fn info_with(master_status: &str, others: &[&str]) -> PinInfo {
        let mut m = HashMap::new();
        m.insert("MASTER".to_string(), peer(master_status));
        for (i, s) in others.iter().enumerate() {
            m.insert(format!("peer{i}"), peer(s));
        }
        PinInfo {
            cid: "bafytest".to_string(),
            name: None,
            allocations: None,
            origins: None,
            created: None,
            metadata: None,
            peer_map: Some(m),
        }
    }

    #[test]
    fn count_excludes_master_and_only_counts_pinned() {
        // master pinned + 2 non-master pinned + 1 pinning → 2.
        let info = info_with("pinned", &["pinned", "pinned", "pinning"]);
        assert_eq!(count_non_master_pinned(&info, "MASTER"), 2);
    }

    #[test]
    fn count_is_zero_when_only_the_master_holds_it() {
        // The safety invariant: a block only the master has must read as 0
        // replicas so it is NEVER dropped.
        let info = info_with("pinned", &["unpinned", "pin_error"]);
        assert_eq!(count_non_master_pinned(&info, "MASTER"), 0);
    }

    #[test]
    fn active_holder_detects_in_progress_so_redrive_is_skipped() {
        // A non-master peer mid-pin → replication underway → skip re-drive.
        assert!(has_active_non_master_holder(
            &info_with("pinned", &["pinning"]),
            "MASTER"
        ));
        // Only master + failed/unpinned others → nothing underway → re-drive.
        assert!(!has_active_non_master_holder(
            &info_with("pinned", &["unpinned", "pin_error"]),
            "MASTER"
        ));
    }

    #[test]
    fn env_bool_parses_truthy_falsy_and_defaults() {
        assert!(env_bool("FULA_TEST_NONEXISTENT_KNOB_Q1", true));
        assert!(!env_bool("FULA_TEST_NONEXISTENT_KNOB_Q1", false));
        std::env::set_var("FULA_TEST_KNOB_Q2", "false");
        assert!(!env_bool("FULA_TEST_KNOB_Q2", true));
        std::env::set_var("FULA_TEST_KNOB_Q2", "ON");
        assert!(env_bool("FULA_TEST_KNOB_Q2", false));
        std::env::remove_var("FULA_TEST_KNOB_Q2");
    }

    // decide args: (holders, min_repl, auto_drop, has_leaves, redrive,
    //               in_progress, breaker_open, settled)
    #[test]
    fn decide_drops_only_when_replicated_settled_and_auto_drop_on() {
        // >= min_repl + auto_drop + breaker closed + SETTLED → Drop.
        assert_eq!(
            decide(2, 2, true, false, true, false, false, true),
            RetainAction::Drop { drop_leaves: false }
        );
        // has_leaves propagates to drop_leaves.
        assert_eq!(
            decide(3, 2, true, true, true, false, false, true),
            RetainAction::Drop { drop_leaves: true }
        );
        // auto_drop OFF (supervised migration) → NEVER drop, however replicated.
        assert_eq!(
            decide(5, 2, false, false, true, false, false, true),
            RetainAction::KeepOnly
        );
    }

    #[test]
    fn decide_does_not_drop_until_settled_or_with_breaker_open() {
        // Replicated but NOT yet settled → hold (guards a transient "pinned").
        assert_eq!(
            decide(2, 2, true, false, true, false, false, false),
            RetainAction::KeepOnly
        );
        // Replicated + settled but cluster breaker OPEN → don't delete the only
        // complete copy while the cluster's health signal is flaky.
        assert_eq!(
            decide(3, 2, true, false, true, false, true, true),
            RetainAction::KeepOnly
        );
    }

    #[test]
    fn decide_redrives_under_replicated_when_idle() {
        // 0 holders, redrive on, nothing in progress, breaker closed → re-drive.
        assert_eq!(
            decide(0, 2, true, false, true, false, false, false),
            RetainAction::KeepAndRedrive
        );
        // 1 < min_repl → still re-drive.
        assert_eq!(
            decide(1, 2, true, false, true, false, false, false),
            RetainAction::KeepAndRedrive
        );
    }

    #[test]
    fn decide_holds_off_when_in_progress_or_breaker_or_disabled() {
        // Replication already underway → don't re-issue the pin.
        assert_eq!(
            decide(0, 2, true, false, true, true, false, false),
            RetainAction::KeepOnly
        );
        // Breaker open (cluster unhealthy) → hold off re-drive.
        assert_eq!(
            decide(0, 2, true, false, true, false, true, false),
            RetainAction::KeepOnly
        );
        // Re-drive disabled entirely.
        assert_eq!(
            decide(0, 2, true, false, false, false, false, false),
            RetainAction::KeepOnly
        );
    }

    // ---- HTTP-wiring integration tests (wiremock kubo + cluster) ----
    // These exercise process_one's ACTUAL HTTP calls — what the unit `decide`
    // tests can't: an under-replicated block triggers a cluster pin (re-drive),
    // and a replicated+settled block triggers a local unpin (drop).
    use fula_blockstore::{ClusterConfig, IpfsConfig};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn test_cid() -> Cid {
        "bafkreigh2akiscaildc6v5q2xg34x5sqo5djznnha64x4jn3fjvu3j6jci"
            .parse()
            .unwrap()
    }

    async fn build_ctx(
        kubo_uri: String,
        cluster_uri: String,
    ) -> (LocalRetainContext, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let queue = LocalRetainQueue::open(dir.path().join("retain.redb")).unwrap();
        let kubo = IpfsBlockStore::new(IpfsConfig::with_url(kubo_uri))
            .await
            .expect("kubo init");
        let cluster = ClusterClient::new(ClusterConfig::with_url(cluster_uri))
            .await
            .expect("cluster init");
        let ctx = LocalRetainContext::new(queue, kubo, cluster, "MASTER".to_string(), 2);
        (ctx, dir)
    }

    #[tokio::test]
    async fn verifier_redrives_an_unpinned_block() {
        let cid = test_cid();
        let kubo = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v0/id"))
            .respond_with(ResponseTemplate::new(200).set_body_string("{}"))
            .mount(&kubo)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/v0/pin/add")) // the re-assert local pin
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"Pins":[cid.to_string()]})),
            )
            .mount(&kubo)
            .await;

        let cluster = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/id"))
            .respond_with(ResponseTemplate::new(200).set_body_string("{}"))
            .mount(&cluster)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/pins/{cid}"))) // status: untracked → 0 holders
            .respond_with(ResponseTemplate::new(404).set_body_string("not found"))
            .mount(&cluster)
            .await;
        // THE ASSERTION: the re-drive POST /pins/{cid} fires exactly once.
        Mock::given(method("POST"))
            .and(path(format!("/pins/{cid}")))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"cid": cid.to_string()})),
            )
            .expect(1)
            .mount(&cluster)
            .await;

        let (ctx, _dir) = build_ctx(kubo.uri(), cluster.uri()).await;
        ctx.queue.enqueue(&cid).unwrap();
        ctx.verify_once().await;
        // `cluster` MockServer drop verifies expect(1) — the re-drive fired.
    }

    #[tokio::test]
    async fn verifier_drops_a_replicated_settled_block() {
        let cid = test_cid();
        let kubo = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v0/id"))
            .respond_with(ResponseTemplate::new(200).set_body_string("{}"))
            .mount(&kubo)
            .await;
        // THE ASSERTION: the drop POST /api/v0/pin/rm fires exactly once.
        Mock::given(method("POST"))
            .and(path("/api/v0/pin/rm"))
            .respond_with(ResponseTemplate::new(200).set_body_string("{}"))
            .expect(1)
            .mount(&kubo)
            .await;

        let cluster = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/id"))
            .respond_with(ResponseTemplate::new(200).set_body_string("{}"))
            .mount(&cluster)
            .await;
        // Two non-master holders report "pinned" → replicated.
        Mock::given(method("GET"))
            .and(path(format!("/pins/{cid}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "cid": cid.to_string(),
                "peer_map": {
                    "peer1": {"status": "pinned"},
                    "peer2": {"status": "pinned"},
                    "MASTER": {"status": "pinned"}
                }
            })))
            .mount(&cluster)
            .await;

        let (mut ctx, _dir) = build_ctx(kubo.uri(), cluster.uri()).await;
        ctx.settle_dur = std::time::Duration::ZERO; // skip the settle window for the test
        ctx.queue.enqueue(&cid).unwrap();
        ctx.verify_once().await;
        // `kubo` MockServer drop verifies expect(1) — the drop fired.
    }
}
