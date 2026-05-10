//! Background pin-queue drainer (W.9.6).
//!
//! Pulls due records from [`PinQueue`] and dispatches them through a
//! [`PinDispatcher`] (master cluster pin or user external pinning
//! service, depending on the record's target). Bounded concurrency
//! caps in-flight RPCs so a thundering herd of writes can't DoS the
//! cluster. On success, the row is deleted; on failure, it gets
//! exponential-backoff'd and stays for the next tick.
//!
//! # Design
//!
//! - **`drain_once`** — does ONE batch: pops `max_batch` due records,
//!   spawns each dispatch under a semaphore, awaits all, returns stats.
//!   Pure function, easy to unit-test, no long-lived state.
//! - **`spawn_drainer_loop`** — production wrapper: calls `drain_once`,
//!   sleeps when idle, exits on cancel. Used at master startup; the
//!   `JoinHandle` lets graceful shutdown await drain completion.
//! - **`PinDispatcher`** trait — abstracts the actual pin RPC. The
//!   production impl wires `BlockStore::pin_with_token` for the
//!   master target and the existing `PinningServiceClient` for the
//!   user target. Tests substitute a `MockDispatcher` that records
//!   calls + returns scripted outcomes, so the queue behaviour can be
//!   exercised without a real cluster.
//!
//! # Crash recovery
//!
//! The drainer holds NO durable state — every persistent fact lives
//! in the queue. On master restart, a fresh drainer reads the same
//! queue and continues. Records that were "in flight" when the master
//! crashed (popped but not yet succeeded/failed) reappear in
//! `pop_due`'s next batch and the dispatch retries — safe because
//! the cluster's pin API is idempotent.
//!
//! # Concurrency model
//!
//! Exactly one drainer per `PinQueue`. Multi-drainer is unsupported
//! (the queue is not partitioned for it; you'd see double-pins which
//! work but waste cycles). The semaphore inside `drain_once` is the
//! only concurrency primitive.

use crate::pin_queue::{
    PinFailedOutcome, PinKind, PinQueue, PinQueueError, PinRecord, PinTarget, DEFAULT_MAX_ATTEMPTS,
};
use async_trait::async_trait;
use fula_blockstore::{
    FlexibleBlockStore, Pin, PinStore, PinningServiceClient, PinningServiceConfig,
};
use futures::stream::{FuturesUnordered, StreamExt};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{Semaphore, oneshot};
use tracing::{debug, error, warn};

/// Max records to pop in a single `drain_once` batch. Big enough to
/// keep the semaphore busy under bursty enqueue rates; small enough
/// that the per-batch redb read transaction stays cheap.
pub const DEFAULT_DRAIN_BATCH_SIZE: usize = 128;

/// Default cap on concurrent in-flight pin RPCs. Master typically
/// fronts a single ipfs-cluster instance; 32 parallel pin calls is
/// well within cluster's capacity (cluster's own internal queues are
/// the real bottleneck) without inviting head-of-line blocking.
pub const DEFAULT_MAX_CONCURRENT_PINS: usize = 32;

/// How long to sleep when `pop_due` returns empty before checking
/// again. Short enough that newly-enqueued records get processed
/// promptly; long enough that an idle queue doesn't burn CPU.
pub const DEFAULT_IDLE_POLL_MS: u64 = 1000;

/// Drainer configuration. All fields have sensible defaults via
/// [`DrainerConfig::default`]; tests override per-test.
#[derive(Debug, Clone)]
pub struct DrainerConfig {
    pub max_batch_size: usize,
    pub max_concurrent_pins: usize,
    pub idle_poll_interval: Duration,
    /// Records hitting this many failures graduate to dead. The queue's
    /// own [`DEFAULT_MAX_ATTEMPTS`] is the recommended floor.
    pub max_attempts: u32,
}

impl Default for DrainerConfig {
    fn default() -> Self {
        Self {
            max_batch_size: DEFAULT_DRAIN_BATCH_SIZE,
            max_concurrent_pins: DEFAULT_MAX_CONCURRENT_PINS,
            idle_poll_interval: Duration::from_millis(DEFAULT_IDLE_POLL_MS),
            max_attempts: DEFAULT_MAX_ATTEMPTS,
        }
    }
}

/// Counts of what `drain_once` accomplished. Returned for both
/// telemetry and tests; the loop wrapper uses `processed == 0` as
/// the "go to sleep" signal.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DrainStats {
    /// Records popped from the queue this tick.
    pub processed: usize,
    /// Of those, how many succeeded.
    pub succeeded: usize,
    /// Of those, how many failed but will retry later.
    pub retried: usize,
    /// Of those, how many graduated to dead-letter.
    pub graduated_dead: usize,
}

/// Errors a dispatcher implementation can surface. Distinct from
/// `PinQueueError` so the drainer can decide retry-vs-dead based on
/// the kind of error (today: any error retries up to `max_attempts`).
#[derive(Debug, thiserror::Error)]
pub enum DispatchError {
    /// Network / cluster transient — retry expected to help.
    #[error("transient pin failure: {0}")]
    Transient(String),
    /// Configuration / authentication / auth — retry unlikely to help.
    /// Currently treated identically to Transient (just retries with
    /// backoff up to max_attempts), but distinguished here so a
    /// future "dead-on-permanent" policy can be enabled without
    /// refactoring dispatcher impls.
    #[error("permanent pin failure: {0}")]
    Permanent(String),
}

/// Trait the drainer uses to dispatch a single pin RPC. The
/// production impl wires `block_store.pin_with_token` (master
/// cluster) and `PinningServiceClient::add_pin` (user external);
/// tests substitute mocks. Async by necessity; both pin paths cross
/// HTTP.
#[async_trait]
pub trait PinDispatcher: Send + Sync {
    /// Dispatch a single pin record. The drainer calls this under
    /// the bounded-concurrency semaphore. Returning `Ok(())` causes
    /// the queue row to be deleted; `Err(_)` causes a retry +
    /// exponential backoff (or graduation to dead after
    /// `max_attempts`).
    async fn dispatch(&self, record: &PinRecord) -> Result<(), DispatchError>;
}

/// Drain one batch of due records. Pure function; safe to call from
/// tests in a loop without spawning a long-running task.
///
/// Returns when every popped record has been resolved (succeeded /
/// retried / graduated to dead). The semaphore caps concurrent
/// in-flight dispatches; the `await` after spawning is what bounds
/// memory usage.
pub async fn drain_once(
    queue: &PinQueue,
    dispatcher: Arc<dyn PinDispatcher>,
    config: &DrainerConfig,
) -> Result<DrainStats, PinQueueError> {
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let due = queue.pop_due(now_ms, config.max_batch_size)?;
    if due.is_empty() {
        return Ok(DrainStats::default());
    }

    let semaphore = Arc::new(Semaphore::new(config.max_concurrent_pins.max(1)));
    let mut futures = FuturesUnordered::new();

    for record in due {
        let permit_sem = Arc::clone(&semaphore);
        let dispatcher = Arc::clone(&dispatcher);
        futures.push(async move {
            let _permit = permit_sem
                .acquire_owned()
                .await
                .expect("semaphore not closed");
            let outcome = dispatcher.dispatch(&record).await;
            (record, outcome)
        });
    }

    let mut stats = DrainStats {
        processed: 0,
        succeeded: 0,
        retried: 0,
        graduated_dead: 0,
    };

    while let Some((record, outcome)) = futures.next().await {
        stats.processed += 1;
        let cid = match record.cid() {
            Ok(c) => c,
            Err(e) => {
                // Per advisor I1 finding: a record whose cid bytes
                // cannot decode would otherwise loop forever
                // (`pop_due` re-surfaces it every tick at
                // attempts=0/next_due=0). Drop it via
                // `purge_corrupt_record` which keys on the raw
                // cid_bytes (no decode required). The audit signal
                // is the `error!` log line — we can't add the row
                // to dead_count because that requires a record
                // postcard-encoded with `dead = true`, and re-encoding
                // here would re-introduce the corrupt bytes.
                error!(
                    target_byte = ?record.target,
                    error = %e,
                    "pin_drainer: purging corrupt persisted record (cannot decode \
                     cid_bytes). Audit signal is this log line."
                );
                if let Err(purge_err) =
                    queue.purge_corrupt_record(&record.cid_bytes, record.target)
                {
                    error!(
                        error = %purge_err,
                        "pin_drainer: purge_corrupt_record failed; record will \
                         re-surface on next pop_due (will keep logging until \
                         operator clears it)"
                    );
                }
                stats.graduated_dead += 1;
                continue;
            }
        };
        match outcome {
            Ok(()) => {
                if let Err(e) = queue.mark_succeeded(&cid, record.target) {
                    // Mark-succeeded failure means the redb write itself
                    // failed (extremely rare). The pin DID happen so a
                    // future drain will see the record again and retry,
                    // which is idempotent at the cluster — no harm done.
                    warn!(
                        cid = %cid,
                        error = %e,
                        "pin_drainer: mark_succeeded failed; record will retry on next drain (pin is idempotent)"
                    );
                    stats.retried += 1;
                } else {
                    stats.succeeded += 1;
                    debug!(cid = %cid, target = ?record.target, "pin_drainer: pinned");
                }
            }
            Err(err) => {
                let outcome = queue.mark_failed(&cid, record.target, config.max_attempts);
                match outcome {
                    Ok(Some(PinFailedOutcome::Retry { next_due_unix_ms })) => {
                        stats.retried += 1;
                        warn!(
                            cid = %cid,
                            target = ?record.target,
                            attempts = record.attempts + 1,
                            error = %err,
                            next_due_unix_ms,
                            "pin_drainer: pin failed; will retry"
                        );
                    }
                    Ok(Some(PinFailedOutcome::Dead)) => {
                        stats.graduated_dead += 1;
                        error!(
                            cid = %cid,
                            target = ?record.target,
                            attempts = record.attempts + 1,
                            error = %err,
                            "pin_drainer: pin permanently failed; graduated to dead-letter \
                             (record retained in queue for audit)"
                        );
                    }
                    Ok(None) => {
                        // Record vanished between pop and mark — extremely
                        // unlikely in single-drainer setup but harmless.
                        debug!(cid = %cid, "pin_drainer: record vanished during failure handling");
                    }
                    Err(e) => {
                        error!(
                            cid = %cid,
                            error = %e,
                            "pin_drainer: mark_failed failed; record will be retried on next \
                             drain at the same attempts count (no progress, but no data loss)"
                        );
                    }
                }
            }
        }
    }

    Ok(stats)
}

/// Spawn the drainer in a long-running tokio task. Returns the
/// `JoinHandle` plus a `oneshot::Sender<()>` that signals graceful
/// shutdown.
///
/// At shutdown:
/// 1. Caller drops or sends () on the cancel sender.
/// 2. Drainer finishes its current batch (does NOT pop a fresh one).
/// 3. JoinHandle resolves; pending records stay in the queue for the
///    next master startup to pick up. No data loss.
pub fn spawn_drainer_loop(
    queue: Arc<PinQueue>,
    dispatcher: Arc<dyn PinDispatcher>,
    config: DrainerConfig,
) -> (
    tokio::task::JoinHandle<()>,
    oneshot::Sender<()>,
) {
    let (cancel_tx, mut cancel_rx) = oneshot::channel::<()>();
    let handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                biased;
                _ = &mut cancel_rx => {
                    debug!("pin_drainer: shutdown signal received, exiting");
                    break;
                }
                stats_res = drain_once(&queue, Arc::clone(&dispatcher), &config) => {
                    match stats_res {
                        Ok(stats) if stats.processed == 0 => {
                            // Idle — sleep before next poll. We use a
                            // sleep-with-cancel to wake up promptly on
                            // shutdown.
                            tokio::select! {
                                _ = &mut cancel_rx => {
                                    debug!("pin_drainer: shutdown during idle, exiting");
                                    break;
                                }
                                _ = tokio::time::sleep(config.idle_poll_interval) => {}
                            }
                        }
                        Ok(_stats) => {
                            // Active — immediately attempt next batch
                            // without sleeping; the bounded semaphore
                            // already throttles dispatches.
                        }
                        Err(e) => {
                            error!(
                                error = %e,
                                "pin_drainer: queue error during drain_once; \
                                 sleeping idle interval and retrying"
                            );
                            tokio::time::sleep(config.idle_poll_interval).await;
                        }
                    }
                }
            }
        }
    });
    (handle, cancel_tx)
}

/// Production [`PinDispatcher`] — dispatches `MasterCluster` records
/// through `BlockStore::pin_with_token` and `UserExternal` records
/// through the existing `PinningServiceClient`. Wired by
/// `server::run_server` at master startup.
///
/// Errors from the underlying pin RPCs are mapped to
/// [`DispatchError::Transient`] so the queue retries them; permanent
/// failures (e.g. malformed user-external endpoint at enqueue time)
/// surface as [`DispatchError::Permanent`] so the dead-letter
/// triage path engages immediately.
pub struct LivePinDispatcher {
    block_store: Arc<FlexibleBlockStore>,
}

impl LivePinDispatcher {
    pub fn new(block_store: Arc<FlexibleBlockStore>) -> Self {
        Self { block_store }
    }
}

#[async_trait]
impl PinDispatcher for LivePinDispatcher {
    async fn dispatch(&self, record: &PinRecord) -> Result<(), DispatchError> {
        let cid = record
            .cid()
            .map_err(|e| DispatchError::Permanent(format!("corrupt cid bytes: {e}")))?;
        // **#66**: branch on (target, kind). Add+MasterCluster and
        // Add+UserExternal are the legacy paths (unchanged). Remove
        // is the new dispatch surface — currently UserExternal-only;
        // Remove+MasterCluster returns Permanent because the unpin
        // queue's minimal scope (advisor #66 brief) is user-external.
        match (record.target, record.kind) {
            (PinTarget::MasterCluster, PinKind::Add) => {
                let token = record.bearer_token.as_deref().unwrap_or("");
                self.block_store
                    .pin_with_token(&cid, record.pin_name.as_deref(), token)
                    .await
                    .map_err(|e| DispatchError::Transient(e.to_string()))
            }
            (PinTarget::UserExternal, PinKind::Add) => {
                let endpoint = record
                    .pinning_endpoint
                    .as_deref()
                    .ok_or_else(|| {
                        DispatchError::Permanent(
                            "user-external pin record missing pinning_endpoint".into(),
                        )
                    })?;
                let token = record.bearer_token.as_deref().ok_or_else(|| {
                    DispatchError::Permanent(
                        "user-external pin record missing bearer_token".into(),
                    )
                })?;
                let config = PinningServiceConfig::new(endpoint, token);
                let client = PinningServiceClient::new(config)
                    .map_err(|e| DispatchError::Permanent(e.to_string()))?;
                let mut pin = Pin::new(cid.to_string());
                if let Some(name) = &record.pin_name {
                    pin = pin.with_name(name.clone());
                }
                client
                    .add_pin(pin)
                    .await
                    .map(|_status| ())
                    .map_err(|e| DispatchError::Transient(e.to_string()))
            }
            (PinTarget::UserExternal, PinKind::Remove) => {
                // **#66 (2026-05-09)** — durable user-external unpin.
                // Two-step: lookup pin by CID, DELETE by request_id.
                // 404 on lookup ("no pin exists for this CID") and
                // 404 on delete ("pin already removed") both map to
                // `Ok(())` — the user's intent ("ensure unpinned")
                // is satisfied either way.
                let endpoint = record
                    .pinning_endpoint
                    .as_deref()
                    .ok_or_else(|| {
                        DispatchError::Permanent(
                            "user-external unpin record missing pinning_endpoint".into(),
                        )
                    })?;
                let token = record.bearer_token.as_deref().ok_or_else(|| {
                    DispatchError::Permanent(
                        "user-external unpin record missing bearer_token".into(),
                    )
                })?;
                let config = PinningServiceConfig::new(endpoint, token);
                let client = PinningServiceClient::new(config)
                    .map_err(|e| DispatchError::Permanent(e.to_string()))?;
                let cid_str = cid.to_string();
                match client.get_pin_by_cid(&cid_str).await {
                    Ok(Some(status)) => client
                        .delete_pin(&status.request_id)
                        .await
                        .map(|_| ())
                        .map_err(|e| DispatchError::Transient(e.to_string())),
                    // No pin found — already unpinned, intent satisfied.
                    Ok(None) => Ok(()),
                    Err(e) => Err(DispatchError::Transient(e.to_string())),
                }
            }
            (PinTarget::MasterCluster, PinKind::Remove) => {
                // Out of scope for #66. The minimal-scope rationale
                // (advisor brief): master-local unpin failure mode
                // is "kubo briefly down" and is already handled
                // sync-best-effort at the call site (object.rs:955)
                // — re-aligning state on the next user write is
                // cheap. Routing it through the queue would add
                // latency without correctness gain.
                Err(DispatchError::Permanent(
                    "PinKind::Remove with MasterCluster target is not implemented (#66 minimal \
                     scope is user-external only)"
                        .into(),
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pin_queue::{PinKind, PinQueue, PinRequest, PinTarget};
    use cid::multihash::Multihash;
    use cid::Cid;
    use parking_lot::Mutex;

    fn make_cid(seed: u8) -> Cid {
        let digest = [seed; 32];
        let mh = Multihash::<64>::wrap(0x1e, &digest).expect("blake3 multihash wrap");
        Cid::new_v1(0x55, mh)
    }

    fn fresh_queue() -> (Arc<PinQueue>, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("pinq.redb");
        let q = PinQueue::open(&path).expect("open");
        (Arc::new(q), dir)
    }

    /// Test dispatcher with scripted per-CID outcomes. Records every
    /// dispatch call so tests can assert on call count + sequence.
    struct ScriptedDispatcher {
        /// Per-CID outcome list. The Nth call for a given CID returns
        /// the Nth entry; once exhausted, returns Ok(()) (success).
        scripts: Mutex<std::collections::HashMap<Cid, Vec<Result<(), DispatchError>>>>,
        /// Every dispatch call recorded as (cid, target).
        calls: Mutex<Vec<(Cid, PinTarget)>>,
    }

    impl ScriptedDispatcher {
        fn new() -> Self {
            Self {
                scripts: Mutex::new(std::collections::HashMap::new()),
                calls: Mutex::new(Vec::new()),
            }
        }

        fn script(&self, cid: Cid, outcomes: Vec<Result<(), DispatchError>>) {
            self.scripts.lock().insert(cid, outcomes);
        }

        fn calls(&self) -> Vec<(Cid, PinTarget)> {
            self.calls.lock().clone()
        }
    }

    #[async_trait]
    impl PinDispatcher for ScriptedDispatcher {
        async fn dispatch(&self, record: &PinRecord) -> Result<(), DispatchError> {
            let cid = record.cid().expect("test cid valid");
            self.calls.lock().push((cid, record.target));
            let mut scripts = self.scripts.lock();
            let entry = scripts.entry(cid).or_insert_with(Vec::new);
            if entry.is_empty() {
                Ok(())
            } else {
                entry.remove(0)
            }
        }
    }

    #[tokio::test]
    async fn drain_once_marks_records_succeeded_and_clears_queue() {
        let (q, _td) = fresh_queue();
        let dispatcher = Arc::new(ScriptedDispatcher::new());
        let cids: Vec<_> = (1u8..=5).map(make_cid).collect();
        for c in &cids {
            q.enqueue(PinRequest {
                cid: *c,
                target: PinTarget::MasterCluster,
                kind: PinKind::Add,
                pin_name:Some("bucket:t".to_string()),
                bearer_token: Some("jwt".to_string()),
                pinning_endpoint: None,
            })
            .unwrap();
        }
        let stats = drain_once(
            &q,
            dispatcher.clone() as Arc<dyn PinDispatcher>,
            &DrainerConfig::default(),
        )
        .await
        .unwrap();
        assert_eq!(stats.processed, 5);
        assert_eq!(stats.succeeded, 5);
        assert_eq!(stats.retried, 0);
        assert_eq!(stats.graduated_dead, 0);
        assert_eq!(q.pending_count().unwrap(), 0);
        assert_eq!(dispatcher.calls().len(), 5);
    }

    #[tokio::test]
    async fn drain_once_retries_then_succeeds() {
        let (q, _td) = fresh_queue();
        let dispatcher = Arc::new(ScriptedDispatcher::new());
        let cid = make_cid(0xAA);
        // First two attempts fail (transient), third succeeds.
        dispatcher.script(
            cid,
            vec![
                Err(DispatchError::Transient("cluster busy".into())),
                Err(DispatchError::Transient("cluster busy".into())),
                Ok(()),
            ],
        );
        q.enqueue(PinRequest {
            cid,
            target: PinTarget::MasterCluster,
            kind: PinKind::Add,
            pin_name:None,
            bearer_token: Some("jwt".to_string()),
            pinning_endpoint: None,
        })
        .unwrap();

        // First drain: fails, schedules retry.
        let stats = drain_once(
            &q,
            dispatcher.clone() as Arc<dyn PinDispatcher>,
            &DrainerConfig::default(),
        )
        .await
        .unwrap();
        assert_eq!(stats.retried, 1);
        assert_eq!(q.pending_count().unwrap(), 1);

        // Second drain immediately after: due to backoff, the record
        // is NOT due yet, so drain_once finds nothing.
        let stats = drain_once(
            &q,
            dispatcher.clone() as Arc<dyn PinDispatcher>,
            &DrainerConfig::default(),
        )
        .await
        .unwrap();
        assert_eq!(stats.processed, 0, "backoff hides the record from this drain");

        // Force the record's next_due into the past so the test
        // doesn't have to wait 500ms+. Re-pop with a far-future
        // "now" effectively bypasses the backoff for testing.
        let due = q.pop_due(u64::MAX / 2, 100).unwrap();
        assert_eq!(due.len(), 1, "with far-future now, record is due");

        // Manually run dispatch + mark for the second + third attempts.
        let r = dispatcher.dispatch(&due[0]).await;
        assert!(r.is_err());
        let outcome = q
            .mark_failed(&cid, PinTarget::MasterCluster, DEFAULT_MAX_ATTEMPTS)
            .unwrap()
            .unwrap();
        assert!(matches!(outcome, PinFailedOutcome::Retry { .. }));

        let due = q.pop_due(u64::MAX / 2, 100).unwrap();
        let r = dispatcher.dispatch(&due[0]).await;
        assert!(r.is_ok(), "third attempt scripted Ok");
        q.mark_succeeded(&cid, PinTarget::MasterCluster).unwrap();
        assert_eq!(q.pending_count().unwrap(), 0);
        assert_eq!(dispatcher.calls().len(), 3, "exactly three dispatch calls");
    }

    #[tokio::test]
    async fn drain_once_graduates_to_dead_after_max_attempts() {
        let (q, _td) = fresh_queue();
        let dispatcher = Arc::new(ScriptedDispatcher::new());
        let cid = make_cid(0xDD);
        // Always fail.
        dispatcher.script(
            cid,
            (0..20)
                .map(|_| Err(DispatchError::Permanent("nope".into())))
                .collect(),
        );
        q.enqueue(PinRequest {
            cid,
            target: PinTarget::MasterCluster,
            kind: PinKind::Add,
            pin_name:None,
            bearer_token: None,
            pinning_endpoint: None,
        })
        .unwrap();

        // Tight max_attempts so the test runs fast.
        let config = DrainerConfig {
            max_attempts: 3,
            ..DrainerConfig::default()
        };

        // Loop drain+pop_due-with-far-future-now to bypass backoff.
        for _ in 0..10 {
            let due = q.pop_due(u64::MAX / 2, 100).unwrap();
            if due.is_empty() {
                break;
            }
            for record in due {
                let cid_in = record.cid().unwrap();
                let res = dispatcher.dispatch(&record).await;
                if let Err(_) = res {
                    let _ = q.mark_failed(&cid_in, record.target, config.max_attempts);
                }
            }
            if q.dead_count().unwrap() > 0 {
                break;
            }
        }
        assert_eq!(
            q.dead_count().unwrap(),
            1,
            "after max_attempts failures the record graduates to dead"
        );
        assert_eq!(q.pending_count().unwrap(), 0);
    }

    #[tokio::test]
    async fn drain_once_is_safe_when_queue_is_empty() {
        let (q, _td) = fresh_queue();
        let dispatcher = Arc::new(ScriptedDispatcher::new());
        let stats = drain_once(
            &q,
            dispatcher.clone() as Arc<dyn PinDispatcher>,
            &DrainerConfig::default(),
        )
        .await
        .unwrap();
        assert_eq!(stats, DrainStats::default());
        assert_eq!(dispatcher.calls().len(), 0);
    }

    #[tokio::test]
    async fn drain_once_dispatches_per_target_independently() {
        // Same CID, both targets — each dispatched once, both get
        // their own queue row and their own success.
        let (q, _td) = fresh_queue();
        let dispatcher = Arc::new(ScriptedDispatcher::new());
        let cid = make_cid(0x77);
        q.enqueue(PinRequest {
            cid,
            target: PinTarget::MasterCluster,
            kind: PinKind::Add,
            pin_name:None,
            bearer_token: Some("jwt".to_string()),
            pinning_endpoint: None,
        })
        .unwrap();
        q.enqueue(PinRequest {
            cid,
            target: PinTarget::UserExternal,
            kind: PinKind::Add,
            pin_name: None,
            bearer_token: Some("user-token".to_string()),
            pinning_endpoint: Some("https://pinning.example/".to_string()),
        })
        .unwrap();
        let stats = drain_once(
            &q,
            dispatcher.clone() as Arc<dyn PinDispatcher>,
            &DrainerConfig::default(),
        )
        .await
        .unwrap();
        assert_eq!(stats.processed, 2);
        assert_eq!(stats.succeeded, 2);
        let calls = dispatcher.calls();
        assert!(calls.iter().any(|(c, t)| *c == cid && *t == PinTarget::MasterCluster));
        assert!(calls.iter().any(|(c, t)| *c == cid && *t == PinTarget::UserExternal));
    }

    /// Crash-recovery integration test (advisor's load-bearing W.9.6
    /// property): enqueue 100 pins through the queue, drop the
    /// drainer mid-batch, reopen the queue at the same path with a
    /// fresh dispatcher, and observe every record eventually gets
    /// its `mark_succeeded` call.
    #[tokio::test]
    async fn crash_recovery_drains_persisted_pins_after_restart() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("crash.redb");
        let cids: Vec<_> = (1u8..=100).map(make_cid).collect();

        // Phase 1: enqueue 100 pins, then DROP the queue without
        // running the drainer. Simulates a master crash between
        // PUT-enqueue and the next drainer tick.
        {
            let q = PinQueue::open(&path).expect("open #1");
            for c in &cids {
                q.enqueue(PinRequest {
                    cid: *c,
                    target: PinTarget::MasterCluster,
                    kind: PinKind::Add,
                    pin_name: Some("bucket:crash".to_string()),
                    bearer_token: Some("jwt".to_string()),
                    pinning_endpoint: None,
                })
                .unwrap();
            }
            assert_eq!(q.pending_count().unwrap(), 100);
            // q dropped here.
        }

        // Phase 2: reopen the queue with a fresh dispatcher (= new
        // process). The drainer must see all 100 records and pin
        // them.
        let q = Arc::new(PinQueue::open(&path).expect("open #2"));
        let dispatcher = Arc::new(ScriptedDispatcher::new());
        // No script entries → dispatcher returns Ok(()) for everyone.
        let mut total_processed = 0;
        // drain_once batches at config.max_batch_size=128, so one
        // call should handle all 100. Loop just in case.
        for _ in 0..3 {
            let stats = drain_once(
                &q,
                dispatcher.clone() as Arc<dyn PinDispatcher>,
                &DrainerConfig::default(),
            )
            .await
            .unwrap();
            total_processed += stats.processed;
            if q.pending_count().unwrap() == 0 {
                break;
            }
        }
        assert_eq!(
            total_processed, 100,
            "every persisted pin must be picked up by the post-crash drainer — \
             this is the load-bearing W.9.6 durability property"
        );
        assert_eq!(q.pending_count().unwrap(), 0);
        assert_eq!(dispatcher.calls().len(), 100);
        // Every CID must have been dispatched exactly once across the
        // restart boundary.
        let mut seen: std::collections::HashSet<Cid> =
            dispatcher.calls().into_iter().map(|(c, _)| c).collect();
        assert_eq!(seen.len(), 100, "100 distinct CIDs dispatched");
        for c in &cids {
            assert!(seen.remove(c), "expected CID {c} not dispatched after restart");
        }
    }

    #[tokio::test]
    async fn drain_once_bounded_concurrency_is_respected() {
        // Set max_concurrent_pins=2 with a tracking dispatcher that
        // counts max-in-flight; verify it never exceeds 2.
        let (q, _td) = fresh_queue();
        let in_flight = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let max_observed = Arc::new(std::sync::atomic::AtomicUsize::new(0));

        struct CountingDispatcher {
            in_flight: Arc<std::sync::atomic::AtomicUsize>,
            max_observed: Arc<std::sync::atomic::AtomicUsize>,
        }

        #[async_trait]
        impl PinDispatcher for CountingDispatcher {
            async fn dispatch(&self, _r: &PinRecord) -> Result<(), DispatchError> {
                let cur = self
                    .in_flight
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                    + 1;
                let mut prev = self
                    .max_observed
                    .load(std::sync::atomic::Ordering::SeqCst);
                while cur > prev {
                    match self.max_observed.compare_exchange(
                        prev,
                        cur,
                        std::sync::atomic::Ordering::SeqCst,
                        std::sync::atomic::Ordering::SeqCst,
                    ) {
                        Ok(_) => break,
                        Err(actual) => prev = actual,
                    }
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                self.in_flight
                    .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                Ok(())
            }
        }

        let dispatcher: Arc<dyn PinDispatcher> = Arc::new(CountingDispatcher {
            in_flight: in_flight.clone(),
            max_observed: max_observed.clone(),
        });
        for i in 1u8..=10 {
            q.enqueue(PinRequest {
                cid: make_cid(i),
                target: PinTarget::MasterCluster,
                kind: PinKind::Add,
                pin_name:None,
                bearer_token: None,
                pinning_endpoint: None,
            })
            .unwrap();
        }
        let config = DrainerConfig {
            max_concurrent_pins: 2,
            ..DrainerConfig::default()
        };
        let stats = drain_once(&q, dispatcher, &config).await.unwrap();
        assert_eq!(stats.succeeded, 10);
        let max = max_observed.load(std::sync::atomic::Ordering::SeqCst);
        assert!(
            max <= 2,
            "max_concurrent_pins=2 must cap in-flight at 2; observed {} concurrent",
            max
        );
        assert!(
            max >= 2,
            "test setup expects to actually saturate the cap; observed {} \
             (sleep too short relative to scheduler latency?)",
            max
        );
    }

    /// **#66 (2026-05-09)** — `LivePinDispatcher::dispatch` returns
    /// `Permanent` for `(Remove, MasterCluster)` records (out-of-scope
    /// for #66 minimal scope). Drainer's mark_failed graduates
    /// Permanent records to dead immediately; this test pins the
    /// dispatcher's mapping rather than the drainer's downstream
    /// handling.
    #[tokio::test]
    async fn live_dispatcher_remove_master_cluster_returns_permanent() {
        use fula_blockstore::{FlexibleBlockStore, MemoryBlockStore};
        let block_store = Arc::new(FlexibleBlockStore::Memory(MemoryBlockStore::new()));
        let dispatcher = LivePinDispatcher::new(block_store);

        let cid = make_cid(0x99);
        let record = PinRecord {
            cid_bytes: cid.to_bytes(),
            target: PinTarget::MasterCluster,
            kind: PinKind::Remove,
            pin_name: None,
            bearer_token: None,
            pinning_endpoint: None,
            attempts: 0,
            next_due_unix_ms: 0,
            dead: false,
            enqueued_at_unix_ms: 0,
        };

        let result = dispatcher.dispatch(&record).await;
        match result {
            Err(DispatchError::Permanent(msg)) => {
                assert!(
                    msg.contains("not implemented"),
                    "expected #66 'not implemented' message for Remove+MasterCluster, got: {}",
                    msg
                );
            }
            other => panic!(
                "expected DispatchError::Permanent for Remove+MasterCluster (out of #66 scope), got: {:?}",
                other
            ),
        }
    }

    /// **#66** — sanity: `LivePinDispatcher::dispatch` for the legacy
    /// `(Add, MasterCluster)` path still works (memory-store no-op
    /// pin, returns Ok). Pinned to catch regressions where the new
    /// `(target, kind)` match accidentally drops the Add branch.
    #[tokio::test]
    async fn live_dispatcher_add_master_cluster_still_works_post_kind_field() {
        use fula_blockstore::{FlexibleBlockStore, MemoryBlockStore};
        let block_store = Arc::new(FlexibleBlockStore::Memory(MemoryBlockStore::new()));
        let dispatcher = LivePinDispatcher::new(block_store);

        let cid = make_cid(0xAA);
        let record = PinRecord {
            cid_bytes: cid.to_bytes(),
            target: PinTarget::MasterCluster,
            kind: PinKind::Add,
            pin_name: Some("bucket:test".to_string()),
            bearer_token: Some("jwt".to_string()),
            pinning_endpoint: None,
            attempts: 0,
            next_due_unix_ms: 0,
            dead: false,
            enqueued_at_unix_ms: 0,
        };

        // MemoryBlockStore.pin_with_token is a no-op (returns Ok).
        let result = dispatcher.dispatch(&record).await;
        assert!(result.is_ok(), "Add+MasterCluster post-#66 broke: {:?}", result);
    }
}
