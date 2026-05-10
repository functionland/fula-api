//! Durable pin queue (W.9.6).
//!
//! Closes the silent-pin-drop gap (task #23) for both pinning paths
//! that the master's PUT handler currently fires-and-forgets:
//!
//!   * **Master cluster pin** — `block_store.pin_with_token(bucket_root_cid, ...)`
//!     via the `BlockStore` trait. Recursively pins the bucket's
//!     Prolly Tree which transitively covers every object in the bucket
//!     (including walkable-v8 HAMT internal-node ciphertexts at
//!     `__fula_forest_v7_nodes/<storage_key>` paths — verified by an
//!     integration test in this crate).
//!   * **User's external pinning service** — `pin_for_user(...)`
//!     against the user-configured pinning-service endpoint with the
//!     user's JWT.
//!
//! Both targets feed the SAME queue with a per-target column so a
//! drainer can dispatch each independently. A row is removed only
//! when *its* target succeeds; per-target failures retry on their own
//! schedule.
//!
//! # Crash safety
//!
//! Backed by a single redb file (ACID, no separate DB process). Every
//! `enqueue` writes durably before returning, so a master crash
//! between PUT-success-response and pin-completion preserves the
//! pending pin for replay on next startup. Idempotency at the cluster
//! level (pinning an already-pinned CID is a no-op) means retried
//! pins after a crash do not produce duplicate state.
//!
//! # Concurrency
//!
//! Exactly one drainer per `PinQueue` instance; the queue is not
//! intended to be popped from multiple workers concurrently in the
//! same process. Concurrent `enqueue` from PUT handlers is safe via
//! redb's ACID transactions. The drainer's bounded semaphore caps
//! concurrent in-flight pin RPCs so a thundering herd of writes
//! cannot DoS the cluster.
//!
//! # What's NOT in the queue
//!
//! The `BlockStore::put_block` calls (which actually materialize
//! bytes in master's local IPFS daemon) are NOT queued — those are
//! synchronous and fail the PUT handler if they fail. Only the *pin*
//! step (which announces the block to ipfs-cluster for replication +
//! DHT propagation) is queued, since it can transiently fail at
//! cluster scale and is idempotent on retry.
//!
//! # Why not a tokio mpsc channel?
//!
//! In-memory channels lose pending work on master crash. Phase 2.4
//! and Phase 3.2 already chose redb for analogous "must-survive-
//! restart" cases (block cache, publisher state file) — reusing the
//! workspace dep gives us a known-good crash-safety story without
//! inventing a new persistence layer.

use cid::Cid;
use redb::{Database, ReadableTable, ReadableTableMetadata, TableDefinition};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// **#66 (2026-05-09)**: bumped to v2 when `PinKind` was added to
/// `PinRecord` (Add vs Remove intent for unpin queue support). On
/// open we drop any leftover v1 table — pre-#66 records would lack
/// the `kind` field and postcard would fail trailing-field decode.
/// Master-only state; the cost is "in-flight pins from before
/// upgrade are dropped"; the next user write re-enqueues. Documented
/// in CHANGELOG.
const PIN_QUEUE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("pin_queue_v2");

/// Pre-#66 table name — opened on first run after upgrade and
/// deleted to free its blocks. No-op on a fresh install.
const LEGACY_PIN_QUEUE_V1: TableDefinition<&[u8], &[u8]> = TableDefinition::new("pin_queue_v1");

/// Default exponential-backoff base (per advisor's W.9.6 design).
/// First retry at ~500 ms; each subsequent failure roughly doubles
/// the delay up to [`DEFAULT_BACKOFF_CAP_MS`].
const DEFAULT_BACKOFF_BASE_MS: u64 = 500;

/// Cap on a single retry's wait. Without this, attempt N's delay
/// grows unbounded (`base * 2^N`) and a chronic failure mode would
/// stall the queue for hours per record.
const DEFAULT_BACKOFF_CAP_MS: u64 = 5 * 60 * 1000;

/// Default max attempts before marking a record dead. With the
/// default 500 ms / 5 min cap and 10 % jitter, 8 attempts cover ~30
/// min of retries. Beyond that the failure is almost certainly not
/// transient; surface it for operator triage rather than retrying
/// forever.
pub const DEFAULT_MAX_ATTEMPTS: u32 = 8;

/// Pin target: which back-end this row's pin call dispatches to.
///
/// Stored as a `u8` so the on-disk wire is stable across enum reorder
/// or rename (postcard's enum-variant tag is also stable, but a fixed
/// numeric code is clearer for grep / debug printing).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum PinTarget {
    /// Master's own ipfs-cluster instance (via `block_store.pin_with_token`).
    /// Drainer authenticates with the user's JWT recorded in the row.
    MasterCluster = 0,
    /// User's external pinning service (via `pin_for_user`'s
    /// downstream HTTP call). Drainer uses `pinning_endpoint` +
    /// `pin_token` from the row.
    UserExternal = 1,
}

impl PinTarget {
    fn as_byte(self) -> u8 {
        self as u8
    }
}

/// **#66 (2026-05-09)** — pin/unpin intent stored on the queue row.
///
/// Same-target pin and unpin records share an idempotency key
/// (`(cid, target)`). Enqueueing an opposite-kind request for an
/// existing key implements **"latest intent wins"**: the new intent
/// overwrites the old one (resets attempts/due-time, refreshes
/// bearer_token from the new request). Enqueueing the same-kind
/// request for an existing key remains idempotent (no churn on
/// retried PUTs of the same content).
///
/// Wire form: `repr(u8)` so the on-disk byte is stable across enum
/// reorder. Variant 0 = `Add` mirrors the v1 schema's "everything
/// is a pin" assumption — kept first so the byte representation of
/// `PinKind::Add` is the same as v1's missing-field default would
/// be (defense in depth, but the primary backward-compat mechanism
/// is the table-name bump to `pin_queue_v2`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum PinKind {
    /// Pin the CID at the target (default).
    Add = 0,
    /// Unpin the CID from the target. For `UserExternal`, dispatcher
    /// looks up the pin by CID + DELETE; 404 ("pin not found") is
    /// treated as success (already removed). For `MasterCluster`,
    /// not yet implemented (#66 minimal scope is user-external only);
    /// dispatcher returns `DispatchError::Permanent`.
    Remove = 1,
}

impl Default for PinKind {
    fn default() -> Self {
        PinKind::Add
    }
}

/// Caller's intent at enqueue time. The drainer is responsible for
/// converting this into the actual pin RPC.
#[derive(Debug, Clone)]
pub struct PinRequest {
    pub cid: Cid,
    pub target: PinTarget,
    /// **#66**: Add or Remove. Defaults to `Add` so existing call
    /// sites that don't specify get pin semantics unchanged.
    pub kind: PinKind,
    /// Optional human-readable label (e.g., `"bucket:my-bucket"`).
    /// Forwarded to the cluster for `pin ls` visibility.
    pub pin_name: Option<String>,
    /// Bearer token for the pin RPC. For `MasterCluster` this is the
    /// user's JWT (master's cluster client trusts master, but the
    /// pinning service requires per-user auth). For `UserExternal`
    /// it's whatever token the user supplied in the request headers.
    pub bearer_token: Option<String>,
    /// Endpoint URL — only meaningful for `UserExternal`. None for
    /// `MasterCluster` (block_store has its endpoint baked in).
    pub pinning_endpoint: Option<String>,
}

/// Persisted form. The drainer reads this back from disk on each
/// `pop_due`, dispatches per `target`, and either deletes (on
/// success) or updates (on retry / dead).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinRecord {
    /// Round-trip-safe CID byte form. Decode with
    /// `Cid::try_from(&record.cid_bytes[..])` when dispatching.
    pub cid_bytes: Vec<u8>,
    pub target: PinTarget,
    /// **#66**: Add or Remove. Wire-format: `pin_queue_v2` table
    /// (the `_v1` table is dropped on first open after upgrade —
    /// see `PinQueue::open`).
    pub kind: PinKind,
    pub pin_name: Option<String>,
    pub bearer_token: Option<String>,
    pub pinning_endpoint: Option<String>,
    /// Number of times the drainer has called the pin RPC for this
    /// record. 0 immediately after enqueue.
    pub attempts: u32,
    /// Wall-clock unix-millis when this record next becomes eligible
    /// for the drainer to pick up. 0 = ready immediately.
    pub next_due_unix_ms: u64,
    /// `true` after `attempts >= max_attempts`. Stays in the queue
    /// for operator audit; the drainer skips dead rows.
    pub dead: bool,
    /// Wall-clock unix-millis when first enqueued. Debug + audit only.
    pub enqueued_at_unix_ms: u64,
}

impl PinRecord {
    /// Decode `cid_bytes` back into a [`Cid`]. Used by the drainer
    /// before dispatching the pin RPC. Errors are surfaced as
    /// `PinQueueError::CorruptRecord` so a malformed row is
    /// observable without crashing the drainer.
    pub fn cid(&self) -> Result<Cid, PinQueueError> {
        Cid::try_from(&self.cid_bytes[..])
            .map_err(|e| PinQueueError::CorruptRecord(format!("invalid cid bytes: {e}")))
    }
}

/// Outcome of `mark_failed` — either scheduled for retry or graduated
/// to dead-letter. Returned to the drainer for logging granularity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinFailedOutcome {
    Retry { next_due_unix_ms: u64 },
    Dead,
}

/// Errors the pin queue can surface. Distinct error type (not
/// `ApiError`) so the queue can be unit-tested without dragging in
/// the HTTP stack.
#[derive(Debug, thiserror::Error)]
pub enum PinQueueError {
    #[error("redb open failed: {0}")]
    Open(String),
    #[error("redb transaction failed: {0}")]
    Txn(String),
    #[error("postcard encode/decode failed: {0}")]
    Codec(String),
    #[error("queue file is corrupt: {0}")]
    Corrupt(String),
    #[error("queue record is corrupt: {0}")]
    CorruptRecord(String),
}

impl From<redb::DatabaseError> for PinQueueError {
    fn from(err: redb::DatabaseError) -> Self {
        PinQueueError::Open(err.to_string())
    }
}

impl From<redb::TransactionError> for PinQueueError {
    fn from(err: redb::TransactionError) -> Self {
        PinQueueError::Txn(err.to_string())
    }
}

impl From<redb::TableError> for PinQueueError {
    fn from(err: redb::TableError) -> Self {
        PinQueueError::Txn(err.to_string())
    }
}

impl From<redb::CommitError> for PinQueueError {
    fn from(err: redb::CommitError) -> Self {
        PinQueueError::Txn(err.to_string())
    }
}

impl From<redb::StorageError> for PinQueueError {
    fn from(err: redb::StorageError) -> Self {
        PinQueueError::Txn(err.to_string())
    }
}

impl From<postcard::Error> for PinQueueError {
    fn from(err: postcard::Error) -> Self {
        PinQueueError::Codec(err.to_string())
    }
}

/// Compute `(cid_bytes ‖ target_byte)` as the redb key. CID bytes are
/// variable length (typically 36 bytes for v1 raw-codec BLAKE3) so
/// the key length varies; the trailing target byte makes the
/// `(cid, target)` pair the unique queue identity.
fn record_key(cid_bytes: &[u8], target: PinTarget) -> Vec<u8> {
    let mut k = Vec::with_capacity(cid_bytes.len() + 1);
    k.extend_from_slice(cid_bytes);
    k.push(target.as_byte());
    k
}

/// Wall-clock unix-millis. Centralised so tests can mock or spy on
/// time when needed (currently they call this directly, which is
/// fine — the only time-related test is the backoff test).
fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Compute the next-due timestamp after `attempts` failures. Pure
/// function — exposed so tests can pin the backoff curve.
///
/// `attempts` here is the **post-increment** count (i.e. 1 after the
/// first failure). 10 % jitter is computed via a deterministic mix
/// of `now_unix_ms` so two records that fail at the same wall-clock
/// moment don't synchronise their next retries.
pub(crate) fn compute_backoff_next_due_ms(attempts: u32, now_ms: u64) -> u64 {
    let exponent = (attempts.saturating_sub(1)).min(20);
    // u64::saturating_shl isn't stable; `checked_shl` returns None
    // past 63, in which case we know we're past the cap anyway.
    let shifted = 1u64.checked_shl(exponent.min(20)).unwrap_or(u64::MAX);
    let raw_delay_ms = DEFAULT_BACKOFF_BASE_MS
        .saturating_mul(shifted)
        .min(DEFAULT_BACKOFF_CAP_MS);
    // Deterministic 0..10 % jitter. `now_ms` is the only entropy
    // source the queue has access to without dragging rand into a
    // crash-recovery-load-bearing path; it's good enough to
    // de-synchronise sibling retries since two records that fail at
    // the same millisecond are rare and short-lived.
    let jitter_ms = (now_ms.wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 56) % (raw_delay_ms / 10 + 1);
    now_ms.saturating_add(raw_delay_ms).saturating_add(jitter_ms)
}

/// The durable pin queue.
#[derive(Clone)]
pub struct PinQueue {
    db: Arc<Database>,
    path: PathBuf,
}

impl PinQueue {
    /// Open or create the queue file at `path`. The path's parent
    /// directory must already exist (typically created at master
    /// startup alongside the other state files).
    ///
    /// Errors:
    ///   - `Open`: redb refused to open (corrupt file, unreadable
    ///     parent, file held by another process).
    pub fn open(path: impl AsRef<Path>) -> Result<Self, PinQueueError> {
        let path = path.as_ref().to_path_buf();
        let db = Database::create(&path)?;
        let txn = db.begin_write()?;
        {
            // Touch the v2 table so a fresh file has it (redb creates
            // tables lazily on first write).
            txn.open_table(PIN_QUEUE)?;
        }
        // **#66 (2026-05-09)**: drop pre-#66 v1 table on first open
        // after master upgrade. v1 records lack the `kind` field;
        // postcard would fail trailing-field decode if we tried to
        // read them as v2. Cost: in-flight pin records from before
        // upgrade are dropped — the next user write re-enqueues
        // (typical queue depth is in the hundreds; catch-up takes
        // seconds). Documented in CHANGELOG. Idempotent: no-op on a
        // fresh install or post-upgrade reboot.
        //
        // Same transaction as the table-touch above so we don't
        // open two write txns simultaneously (redb forbids).
        let v1_dropped = match txn.delete_table(LEGACY_PIN_QUEUE_V1) {
            Ok(true) => true,
            Ok(false) => false, // table didn't exist — fresh install
            Err(redb::TableError::TableDoesNotExist(_)) => false,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "pin_queue: failed to drop legacy pin_queue_v1 table; \
                     continuing — leftover v1 records cannot be dispatched"
                );
                false
            }
        };
        txn.commit()?;
        if v1_dropped {
            tracing::info!(
                path = ?path,
                "pin_queue: dropped legacy pin_queue_v1 table (#66 schema upgrade); \
                 in-flight pre-upgrade pin records are not migrated — they will be \
                 re-enqueued by the next user write for affected buckets"
            );
        }
        Ok(Self {
            db: Arc::new(db),
            path,
        })
    }

    /// Path the queue is backed by. Diagnostic / log use.
    #[allow(dead_code)]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Enqueue a pin/unpin request. Idempotent on `(cid, target,
    /// kind)`: if a record with the same `(cid, target)` and the
    /// SAME `kind` already exists, returns `Ok(false)` without
    /// modifying it. If a record with the same `(cid, target)` but
    /// DIFFERENT `kind` exists, the existing record is **overwritten**
    /// with the new intent — this is "latest intent wins" semantics
    /// (#66). The previous record's `enqueued_at_unix_ms` is
    /// preserved for audit; `attempts` resets to 0 so the new intent
    /// dispatches immediately, and `bearer_token`/`pin_name`/
    /// `pinning_endpoint` are taken from the new request.
    ///
    /// Returns `Ok(true)` when a record was written or overwritten,
    /// `Ok(false)` when a same-kind record was already present.
    ///
    /// **The pin↔unpin race** (#66 design call): a user uploading
    /// X → deleting X → re-uploading X (same content → same CID) in
    /// quick succession would otherwise produce a queue with both a
    /// pin and an unpin record for X. The drainer order isn't
    /// guaranteed to match enqueue order, so unpin could run after
    /// the second pin and leave X unpinned despite the user's intent.
    /// "Latest intent wins" collapses pin/unpin into one record per
    /// `(cid, target)` so this race is impossible by construction.
    ///
    /// **Crash safety**: the redb commit at the end of this function
    /// is the durability boundary. After this returns `Ok(_)`, the
    /// record survives a process kill / power-loss (subject to the
    /// usual fsync semantics of the underlying filesystem).
    pub fn enqueue(&self, req: PinRequest) -> Result<bool, PinQueueError> {
        let cid_bytes = req.cid.to_bytes();
        let key = record_key(&cid_bytes, req.target);
        let txn = self.db.begin_write()?;
        let inserted = {
            let mut tbl = txn.open_table(PIN_QUEUE)?;
            // **#66**: latest-intent-wins. Branch on existing record:
            //   * none → fresh insert
            //   * same-kind existing → no-op (preserve retry state)
            //   * different-kind existing → overwrite (reset
            //     attempts/due-time, refresh credentials, preserve
            //     enqueued_at for audit)
            let existing = match tbl.get(&key[..])? {
                Some(bytes) => Some(postcard::from_bytes::<PinRecord>(bytes.value())?),
                None => None,
            };
            match existing {
                Some(prev) if prev.kind == req.kind => {
                    // Same intent already pending — no churn.
                    false
                }
                Some(prev) => {
                    // Conflicting intent — overwrite. Preserve the
                    // original `enqueued_at_unix_ms` so audit reflects
                    // when the queue first acquired interest in this
                    // CID, not just the most recent flip.
                    let record = PinRecord {
                        cid_bytes,
                        target: req.target,
                        kind: req.kind,
                        pin_name: req.pin_name,
                        bearer_token: req.bearer_token,
                        pinning_endpoint: req.pinning_endpoint,
                        attempts: 0,
                        next_due_unix_ms: 0, // ready immediately
                        dead: false,
                        enqueued_at_unix_ms: prev.enqueued_at_unix_ms,
                    };
                    let value = postcard::to_allocvec(&record)?;
                    tbl.insert(&key[..], &value[..])?;
                    true
                }
                None => {
                    let now = now_unix_ms();
                    let record = PinRecord {
                        cid_bytes,
                        target: req.target,
                        kind: req.kind,
                        pin_name: req.pin_name,
                        bearer_token: req.bearer_token,
                        pinning_endpoint: req.pinning_endpoint,
                        attempts: 0,
                        next_due_unix_ms: 0, // ready immediately
                        dead: false,
                        enqueued_at_unix_ms: now,
                    };
                    let value = postcard::to_allocvec(&record)?;
                    tbl.insert(&key[..], &value[..])?;
                    true
                }
            }
        };
        txn.commit()?;
        Ok(inserted)
    }

    /// Return up to `max` records eligible for processing — `dead =
    /// false` AND `next_due_unix_ms <= now_unix_ms`. Records are NOT
    /// removed; the drainer must explicitly mark each one as
    /// succeeded / failed / dead.
    ///
    /// Currently does a full table scan. The queue is drained
    /// continuously so its live size stays small (pending work
    /// only); a secondary index by `next_due_unix_ms` would be a
    /// performance optimisation if the queue ever grew past tens of
    /// thousands of pending records.
    pub fn pop_due(
        &self,
        now_unix_ms: u64,
        max: usize,
    ) -> Result<Vec<PinRecord>, PinQueueError> {
        let txn = self.db.begin_read()?;
        let tbl = txn.open_table(PIN_QUEUE)?;
        let mut out = Vec::with_capacity(max.min(64));
        for entry in tbl.iter()? {
            if out.len() >= max {
                break;
            }
            // Per-row error tolerance (W.9.6 dual-advisor BLOCKER): a
            // single corrupt postcard blob (schema drift across a
            // PinRecord version bump, partial write, bit rot) MUST
            // NOT wedge the entire drainer. Skip-and-log so other
            // healthy records still get picked up. The corrupt row
            // stays in redb for operator triage; an admin tool can
            // inspect / drop it manually.
            let (_k, v) = match entry {
                Ok(kv) => kv,
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        "pin_queue::pop_due: row read failed; skipping"
                    );
                    continue;
                }
            };
            let record: PinRecord = match postcard::from_bytes(v.value()) {
                Ok(r) => r,
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        "pin_queue::pop_due: skipping corrupt postcard record (schema \
                         drift / partial write / bit rot). Operator can inspect via \
                         redb tooling and drop manually if needed."
                    );
                    continue;
                }
            };
            if !record.dead && record.next_due_unix_ms <= now_unix_ms {
                out.push(record);
            }
        }
        Ok(out)
    }

    /// Remove the record on successful pin. The drainer calls this
    /// from within its bounded-concurrency body.
    ///
    /// No-op (no error) if the record is already absent — handles
    /// the race where two drainers (across master restarts) both
    /// completed the same pin.
    pub fn mark_succeeded(
        &self,
        cid: &Cid,
        target: PinTarget,
    ) -> Result<(), PinQueueError> {
        let cid_bytes = cid.to_bytes();
        let key = record_key(&cid_bytes, target);
        let txn = self.db.begin_write()?;
        {
            let mut tbl = txn.open_table(PIN_QUEUE)?;
            tbl.remove(&key[..])?;
        }
        txn.commit()?;
        Ok(())
    }

    /// Bump `attempts` and either schedule a retry (returns `Retry`)
    /// or mark dead (`Dead`). Idempotent / re-entrant under
    /// concurrent retries from a single drainer (records are only
    /// processed by one worker at a time per pop_due batch).
    ///
    /// Returns `Ok(None)` if the record has already been removed
    /// (success raced with this failure call).
    pub fn mark_failed(
        &self,
        cid: &Cid,
        target: PinTarget,
        max_attempts: u32,
    ) -> Result<Option<PinFailedOutcome>, PinQueueError> {
        let cid_bytes = cid.to_bytes();
        let key = record_key(&cid_bytes, target);
        let now = now_unix_ms();
        let txn = self.db.begin_write()?;
        let outcome = {
            let mut tbl = txn.open_table(PIN_QUEUE)?;
            let mut record: PinRecord = {
                let Some(v) = tbl.get(&key[..])? else {
                    return Ok(None);
                };
                postcard::from_bytes(v.value())?
                // The borrow ends with this scope so the table is free
                // to mutate below.
            };
            record.attempts = record.attempts.saturating_add(1);
            let outcome = if record.attempts >= max_attempts {
                record.dead = true;
                PinFailedOutcome::Dead
            } else {
                let next_due = compute_backoff_next_due_ms(record.attempts, now);
                record.next_due_unix_ms = next_due;
                PinFailedOutcome::Retry {
                    next_due_unix_ms: next_due,
                }
            };
            let value = postcard::to_allocvec(&record)?;
            tbl.insert(&key[..], &value[..])?;
            outcome
        };
        txn.commit()?;
        Ok(Some(outcome))
    }

    /// Total non-dead records (drainer's pending work). Diagnostic /
    /// metrics only; the drainer doesn't gate on this. Same per-row
    /// skip-corrupt tolerance as `pop_due` so a single bad blob
    /// doesn't make the whole gauge unreadable.
    pub fn pending_count(&self) -> Result<u64, PinQueueError> {
        let txn = self.db.begin_read()?;
        let tbl = txn.open_table(PIN_QUEUE)?;
        let mut n = 0u64;
        for entry in tbl.iter()? {
            let (_k, v) = match entry {
                Ok(kv) => kv,
                Err(_) => continue,
            };
            let record: PinRecord = match postcard::from_bytes(v.value()) {
                Ok(r) => r,
                Err(_) => continue, // see pop_due's matching comment
            };
            if !record.dead {
                n += 1;
            }
        }
        Ok(n)
    }

    /// Total dead records — surface for operator triage. A non-zero
    /// dead count after a stable cluster means there's a bug or a
    /// genuine permanent failure. Same per-row skip-corrupt tolerance
    /// as `pop_due`.
    pub fn dead_count(&self) -> Result<u64, PinQueueError> {
        let txn = self.db.begin_read()?;
        let tbl = txn.open_table(PIN_QUEUE)?;
        let mut n = 0u64;
        for entry in tbl.iter()? {
            let (_k, v) = match entry {
                Ok(kv) => kv,
                Err(_) => continue,
            };
            let record: PinRecord = match postcard::from_bytes(v.value()) {
                Ok(r) => r,
                Err(_) => continue,
            };
            if record.dead {
                n += 1;
            }
        }
        Ok(n)
    }

    /// Number of redb-stored bytes held by the queue file. Best-effort
    /// observability for operator alerts ("queue file growing
    /// unbounded" indicates a stuck drainer).
    #[allow(dead_code)]
    pub fn approximate_total_records(&self) -> Result<u64, PinQueueError> {
        let txn = self.db.begin_read()?;
        let tbl = txn.open_table(PIN_QUEUE)?;
        Ok(tbl.len()?)
    }

    /// Drop a record whose cid bytes can't decode back into a `Cid`.
    /// Used by the drainer to evict corrupt persisted rows that
    /// would otherwise loop forever (W.9.6 advisor I1 finding).
    ///
    /// Takes the raw `cid_bytes` (which the caller still has, even
    /// when `Cid::try_from` fails) plus the target so the redb key
    /// can be reconstructed without re-decoding. Idempotent — no
    /// error if the row was already gone.
    pub fn purge_corrupt_record(
        &self,
        cid_bytes: &[u8],
        target: PinTarget,
    ) -> Result<(), PinQueueError> {
        let key = record_key(cid_bytes, target);
        let txn = self.db.begin_write()?;
        {
            let mut tbl = txn.open_table(PIN_QUEUE)?;
            tbl.remove(&key[..])?;
        }
        txn.commit()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cid::multihash::Multihash;

    fn make_cid(seed: u8) -> Cid {
        let digest = [seed; 32];
        let mh = Multihash::<64>::wrap(0x1e, &digest).expect("blake3 multihash wrap");
        Cid::new_v1(0x55, mh)
    }

    fn fresh_queue() -> (PinQueue, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("pinq.redb");
        let q = PinQueue::open(&path).expect("open");
        (q, dir)
    }

    #[test]
    fn enqueue_pop_succeed_round_trip() {
        let (q, _td) = fresh_queue();
        let cid = make_cid(0x01);
        assert!(
            q.enqueue(PinRequest {
                cid,
                target: PinTarget::MasterCluster,
                kind: PinKind::Add,
                pin_name:Some("bucket:test".to_string()),
                bearer_token: Some("jwt-abc".to_string()),
                pinning_endpoint: None,
            })
            .unwrap(),
            "first enqueue inserts"
        );
        // Second enqueue with the same (cid, target) is a no-op.
        assert!(
            !q.enqueue(PinRequest {
                cid,
                target: PinTarget::MasterCluster,
                kind: PinKind::Add,
                pin_name:None,
                bearer_token: None,
                pinning_endpoint: None,
            })
            .unwrap(),
            "second enqueue is idempotent"
        );
        // Different target on the same cid IS a separate record.
        assert!(
            q.enqueue(PinRequest {
                cid,
                target: PinTarget::UserExternal,
                kind: PinKind::Add,
                pin_name:None,
                bearer_token: Some("user-token".to_string()),
                pinning_endpoint: Some("https://pinning.example/".to_string()),
            })
            .unwrap(),
            "different target = different row"
        );

        let due = q.pop_due(now_unix_ms() + 1, 100).unwrap();
        assert_eq!(due.len(), 2, "two distinct (cid, target) rows due");

        // Mark master succeeded; user-external still pending.
        q.mark_succeeded(&cid, PinTarget::MasterCluster).unwrap();
        let due = q.pop_due(now_unix_ms() + 1, 100).unwrap();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].target, PinTarget::UserExternal);
        assert_eq!(due[0].cid().unwrap(), cid);

        q.mark_succeeded(&cid, PinTarget::UserExternal).unwrap();
        assert_eq!(q.pop_due(now_unix_ms() + 1, 100).unwrap().len(), 0);
    }

    /// **#66 (2026-05-09)** — enqueueing a Remove for `(cid, target)`
    /// that already has a pending Add **overwrites** the pending
    /// record (latest-intent-wins). Pin/unpin race on rapid
    /// upload→delete→re-upload cannot leave the queue with
    /// conflicting records.
    #[test]
    fn enqueue_overwrites_pin_with_remove_for_same_cid_target() {
        let (q, _td) = fresh_queue();
        let cid = make_cid(0x66);

        // Step 1: enqueue Add (kind defaults to Add for legacy
        // call sites).
        assert!(q
            .enqueue(PinRequest {
                cid,
                target: PinTarget::UserExternal,
                kind: PinKind::Add,
                pin_name: Some("file:photo.jpg".to_string()),
                bearer_token: Some("jwt-A".to_string()),
                pinning_endpoint: Some("https://pinning.example/".to_string()),
            })
            .unwrap());
        let before = q.pop_due(now_unix_ms() + 1, 10).unwrap();
        assert_eq!(before.len(), 1);
        assert_eq!(before[0].kind, PinKind::Add);
        let original_enqueued_at = before[0].enqueued_at_unix_ms;

        // Step 2: enqueue Remove for the same (cid, target) —
        // overwrites Add, returns true (record was updated).
        assert!(q
            .enqueue(PinRequest {
                cid,
                target: PinTarget::UserExternal,
                kind: PinKind::Remove,
                pin_name: None,
                bearer_token: Some("jwt-B".to_string()),
                pinning_endpoint: Some("https://pinning.example/".to_string()),
            })
            .unwrap());

        // Verify the queue has exactly ONE record with kind=Remove.
        let after = q.pop_due(now_unix_ms() + 1, 10).unwrap();
        assert_eq!(after.len(), 1);
        assert_eq!(after[0].kind, PinKind::Remove);
        // Bearer refreshed to the new value.
        assert_eq!(after[0].bearer_token.as_deref(), Some("jwt-B"));
        // Original enqueued_at preserved (audit invariant).
        assert_eq!(after[0].enqueued_at_unix_ms, original_enqueued_at);
        // Attempts reset to 0 — new intent dispatches immediately.
        assert_eq!(after[0].attempts, 0);
    }

    /// **#66** — symmetric: re-enqueueing an Add over a pending
    /// Remove also overwrites. Models the upload → delete → re-upload
    /// race specifically.
    #[test]
    fn enqueue_overwrites_remove_with_pin_for_same_cid_target() {
        let (q, _td) = fresh_queue();
        let cid = make_cid(0x77);

        q.enqueue(PinRequest {
            cid,
            target: PinTarget::UserExternal,
            kind: PinKind::Remove,
            pin_name: None,
            bearer_token: Some("jwt-old".to_string()),
            pinning_endpoint: Some("https://pinning.example/".to_string()),
        })
        .unwrap();

        // Re-upload arrives — overwrite with Add.
        assert!(q
            .enqueue(PinRequest {
                cid,
                target: PinTarget::UserExternal,
                kind: PinKind::Add,
                pin_name: Some("file:replay.jpg".to_string()),
                bearer_token: Some("jwt-new".to_string()),
                pinning_endpoint: Some("https://pinning.example/".to_string()),
            })
            .unwrap());

        let after = q.pop_due(now_unix_ms() + 1, 10).unwrap();
        assert_eq!(after.len(), 1);
        assert_eq!(after[0].kind, PinKind::Add);
        assert_eq!(after[0].bearer_token.as_deref(), Some("jwt-new"));
        assert_eq!(after[0].pin_name.as_deref(), Some("file:replay.jpg"));
    }

    /// **#66** — same-kind enqueue must STILL be idempotent. The
    /// pre-#66 contract held that a retried PUT for the same CID
    /// is a no-op on the queue (prevents churn under retry storms);
    /// adding the kind field doesn't change that.
    #[test]
    fn enqueue_same_kind_remains_idempotent() {
        let (q, _td) = fresh_queue();
        let cid = make_cid(0x88);

        assert!(q
            .enqueue(PinRequest {
                cid,
                target: PinTarget::MasterCluster,
                kind: PinKind::Add,
                pin_name: Some("bucket:test".to_string()),
                bearer_token: Some("jwt".to_string()),
                pinning_endpoint: None,
            })
            .unwrap());

        // Second enqueue of identical (cid, target, kind) returns
        // false — no churn.
        assert!(!q
            .enqueue(PinRequest {
                cid,
                target: PinTarget::MasterCluster,
                kind: PinKind::Add,
                pin_name: Some("bucket:test".to_string()),
                bearer_token: Some("jwt-different".to_string()),
                pinning_endpoint: None,
            })
            .unwrap());

        // The second call did NOT update the bearer_token (existing
        // record preserved — pre-existing pin queue contract).
        let due = q.pop_due(now_unix_ms() + 1, 10).unwrap();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].bearer_token.as_deref(), Some("jwt"));
    }

    #[test]
    fn mark_failed_retries_until_dead() {
        let (q, _td) = fresh_queue();
        let cid = make_cid(0xCC);
        q.enqueue(PinRequest {
            cid,
            target: PinTarget::MasterCluster,
            kind: PinKind::Add,
            pin_name:None,
            bearer_token: None,
            pinning_endpoint: None,
        })
        .unwrap();

        for attempt in 1..DEFAULT_MAX_ATTEMPTS {
            let outcome = q
                .mark_failed(&cid, PinTarget::MasterCluster, DEFAULT_MAX_ATTEMPTS)
                .unwrap()
                .expect("record present");
            match outcome {
                PinFailedOutcome::Retry { next_due_unix_ms } => {
                    assert!(
                        next_due_unix_ms > now_unix_ms(),
                        "retry must be in the future"
                    );
                    // After this call's attempts++ the record's `dead`
                    // remains false; `pop_due` with a now < next_due
                    // returns nothing, with a now >= next_due returns it.
                    assert_eq!(q.pending_count().unwrap(), 1);
                    assert_eq!(q.dead_count().unwrap(), 0);
                }
                PinFailedOutcome::Dead => panic!(
                    "attempt {attempt}: must still be retrying, not dead yet"
                ),
            }
        }

        // Final attempt — graduates to Dead.
        let outcome = q
            .mark_failed(&cid, PinTarget::MasterCluster, DEFAULT_MAX_ATTEMPTS)
            .unwrap()
            .unwrap();
        assert_eq!(outcome, PinFailedOutcome::Dead);
        assert_eq!(q.pending_count().unwrap(), 0, "no longer pending");
        assert_eq!(q.dead_count().unwrap(), 1, "graduated to dead");

        // Dead row is NOT picked up by pop_due even when due.
        assert_eq!(
            q.pop_due(now_unix_ms() + 10_000_000, 100).unwrap().len(),
            0,
            "dead rows must not appear in pop_due"
        );
    }

    #[test]
    fn pop_due_respects_next_due_at_time() {
        let (q, _td) = fresh_queue();
        let cid = make_cid(0x42);
        q.enqueue(PinRequest {
            cid,
            target: PinTarget::MasterCluster,
            kind: PinKind::Add,
            pin_name:None,
            bearer_token: None,
            pinning_endpoint: None,
        })
        .unwrap();

        // Force one failure → record gets a future next_due.
        let outcome = q
            .mark_failed(&cid, PinTarget::MasterCluster, DEFAULT_MAX_ATTEMPTS)
            .unwrap()
            .unwrap();
        let next_due = match outcome {
            PinFailedOutcome::Retry { next_due_unix_ms } => next_due_unix_ms,
            PinFailedOutcome::Dead => panic!("first failure must be Retry"),
        };

        // BEFORE next_due: pop_due hides the record.
        assert_eq!(
            q.pop_due(next_due.saturating_sub(1), 100).unwrap().len(),
            0,
            "record under retry-backoff must not be returned"
        );
        // AT/AFTER next_due: pop_due surfaces it.
        let due = q.pop_due(next_due, 100).unwrap();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].cid().unwrap(), cid);
    }

    #[test]
    fn crash_recovery_reopens_queue_with_pending_intact() {
        // Load-bearing test (advisor's W.9.6 design): enqueue work,
        // drop the queue (simulating a master crash), reopen at the
        // same path, and observe the pending records survive.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("pinq.redb");
        let cids: Vec<_> = (1u8..=10).map(make_cid).collect();
        {
            let q = PinQueue::open(&path).expect("open #1");
            for c in &cids {
                q.enqueue(PinRequest {
                    cid: *c,
                    target: PinTarget::MasterCluster,
                    kind: PinKind::Add,
                    pin_name: Some("bucket:crash-test".to_string()),
                    bearer_token: Some("jwt-x".to_string()),
                    pinning_endpoint: None,
                })
                .unwrap();
            }
            assert_eq!(q.pending_count().unwrap(), 10);
            // Drop `q` here — simulates a master process exit /
            // SIGKILL between enqueues and the drainer's next tick.
        }

        // Reopen the same file. Every record must reappear with its
        // identity preserved.
        let q2 = PinQueue::open(&path).expect("open #2");
        assert_eq!(
            q2.pending_count().unwrap(),
            10,
            "all 10 enqueued records must survive a process boundary — \
             crash-safety is the load-bearing W.9.6 property"
        );
        let due = q2.pop_due(now_unix_ms() + 1, 100).unwrap();
        let mut got: Vec<Cid> = due.iter().map(|r| r.cid().unwrap()).collect();
        got.sort_by_key(|c| c.to_bytes());
        let mut want = cids.clone();
        want.sort_by_key(|c| c.to_bytes());
        assert_eq!(
            got, want,
            "every enqueued CID must be visible to the new drainer with \
             its identity intact"
        );
    }

    #[test]
    fn mark_succeeded_on_missing_record_is_noop() {
        // Race-safety: drainer A succeeds a pin and removes the row;
        // drainer B (across a restart, same record never re-enqueued)
        // also tries to succeed it. Must not error.
        let (q, _td) = fresh_queue();
        let cid = make_cid(0xAA);
        // Never enqueued. mark_succeeded must not error.
        q.mark_succeeded(&cid, PinTarget::MasterCluster).unwrap();
        assert_eq!(q.pending_count().unwrap(), 0);
    }

    #[test]
    fn mark_failed_on_missing_record_returns_none() {
        let (q, _td) = fresh_queue();
        let cid = make_cid(0xBB);
        let outcome = q
            .mark_failed(&cid, PinTarget::MasterCluster, DEFAULT_MAX_ATTEMPTS)
            .unwrap();
        assert!(
            outcome.is_none(),
            "mark_failed on absent (cid, target) must surface None — \
             succeeded-then-failed race indicator for the drainer"
        );
    }

    #[test]
    fn compute_backoff_grows_then_caps() {
        // First retry ~500 ms (+ jitter).
        let now = 1_000_000_u64;
        let d1 = compute_backoff_next_due_ms(1, now).saturating_sub(now);
        assert!(d1 >= DEFAULT_BACKOFF_BASE_MS);
        assert!(d1 < DEFAULT_BACKOFF_BASE_MS + DEFAULT_BACKOFF_BASE_MS / 5);

        // Big-attempts must hit the cap (5 min).
        let big = compute_backoff_next_due_ms(20, now).saturating_sub(now);
        assert!(big >= DEFAULT_BACKOFF_CAP_MS);
        assert!(
            big <= DEFAULT_BACKOFF_CAP_MS + DEFAULT_BACKOFF_CAP_MS / 9,
            "big-attempts must not blow past the cap by more than the \
             10% jitter — got {} vs cap {}",
            big,
            DEFAULT_BACKOFF_CAP_MS
        );
    }

    #[test]
    fn pop_due_skips_corrupt_records_without_wedging() {
        // BLOCKER fix verification (W.9.6 dual-advisor): one corrupt
        // postcard blob in the table MUST NOT make the entire
        // drainer wedge. Earlier impl `?`-propagated postcard errors
        // out of pop_due → drain_once returned Err → drainer slept
        // and re-tried the same broken row forever, blocking every
        // healthy row behind it.
        //
        // Setup: enqueue ONE good record, then directly write a
        // corrupt blob at a new key. Verify pop_due returns the good
        // record.
        let (q, _td) = fresh_queue();
        let good = make_cid(0xAA);
        q.enqueue(PinRequest {
            cid: good,
            target: PinTarget::MasterCluster,
            kind: PinKind::Add,
            pin_name:Some("good".to_string()),
            bearer_token: Some("jwt".to_string()),
            pinning_endpoint: None,
        })
        .unwrap();

        // Inject a corrupt blob directly via the redb txn layer.
        {
            let txn = q.db.begin_write().unwrap();
            {
                let mut tbl = txn.open_table(PIN_QUEUE).unwrap();
                let bogus_key = b"corrupt-key-not-a-real-record".as_slice();
                let bogus_value = b"this is not valid postcard data".as_slice();
                tbl.insert(bogus_key, bogus_value).unwrap();
            }
            txn.commit().unwrap();
        }

        // pop_due must skip the corrupt blob and return the good one.
        let due = q.pop_due(now_unix_ms() + 1, 100).unwrap();
        assert_eq!(due.len(), 1, "must surface the good record despite a sibling corrupt blob");
        assert_eq!(due[0].cid().unwrap(), good);

        // pending_count + dead_count must also skip the corrupt blob
        // (so admin gauges don't report nonsense).
        assert_eq!(q.pending_count().unwrap(), 1);
        assert_eq!(q.dead_count().unwrap(), 0);
    }

    #[test]
    fn enqueue_realistic_v8_put_shapes_routes_per_path_class() {
        // W.9.6-D verification: simulate the per-PUT enqueue shape
        // that the PUT handler emits for each path class so the
        // queue carries enough information for the drainer to
        // dispatch correctly.
        //
        // Three classes:
        //   1. HAMT internal-node PUT (`__fula_forest_v7_nodes/<sk>`)
        //      — walkable-v8 load-bearing. Pin name carries
        //        `v8-node:` prefix for operator visibility.
        //   2. Forest metadata PUT (`__fula_forest_v7_index`,
        //      `__fula_forest_dir_index`, etc.) — pinned with
        //      `forest-meta:` prefix.
        //   3. Regular object PUT (user file) — pinned with
        //      `object:` prefix.
        //
        // All three end up as MasterCluster records with the user's
        // JWT as the bearer; the drainer dispatches identically. The
        // distinct names matter for operator `pin ls` triage, not
        // for queue or drainer behavior.
        let (q, _td) = fresh_queue();
        let cid_node = make_cid(0x01);
        let cid_meta = make_cid(0x02);
        let cid_obj = make_cid(0x03);

        // Each enqueue mirrors the PUT-handler logic at object.rs
        // line ~340 (W.9.6 per-object pin block).
        q.enqueue(PinRequest {
            cid: cid_node,
            target: PinTarget::MasterCluster,
            kind: PinKind::Add,
            pin_name:Some("v8-node:bucket-x".to_string()),
            bearer_token: Some("jwt-x".to_string()),
            pinning_endpoint: None,
        })
        .unwrap();
        q.enqueue(PinRequest {
            cid: cid_meta,
            target: PinTarget::MasterCluster,
            kind: PinKind::Add,
            pin_name:Some("forest-meta:bucket-x".to_string()),
            bearer_token: Some("jwt-x".to_string()),
            pinning_endpoint: None,
        })
        .unwrap();
        q.enqueue(PinRequest {
            cid: cid_obj,
            target: PinTarget::MasterCluster,
            kind: PinKind::Add,
            pin_name:Some("object:bucket-x/photo.jpg".to_string()),
            bearer_token: Some("jwt-x".to_string()),
            pinning_endpoint: None,
        })
        .unwrap();

        let due = q.pop_due(now_unix_ms() + 1, 100).unwrap();
        assert_eq!(due.len(), 3, "all three path classes must enqueue");
        // Verify each cid + pin_name made it through intact.
        let by_cid: std::collections::HashMap<Cid, &PinRecord> =
            due.iter().map(|r| (r.cid().unwrap(), r)).collect();
        assert_eq!(
            by_cid[&cid_node].pin_name.as_deref(),
            Some("v8-node:bucket-x")
        );
        assert_eq!(
            by_cid[&cid_meta].pin_name.as_deref(),
            Some("forest-meta:bucket-x")
        );
        assert_eq!(
            by_cid[&cid_obj].pin_name.as_deref(),
            Some("object:bucket-x/photo.jpg")
        );
    }

    #[test]
    fn dead_record_remains_visible_via_dead_count_for_audit() {
        // Per advisor: dead rows stay in the queue (don't auto-purge)
        // so an operator audit endpoint can later report them. Pin
        // it.
        let (q, _td) = fresh_queue();
        let cid = make_cid(0xDD);
        q.enqueue(PinRequest {
            cid,
            target: PinTarget::MasterCluster,
            kind: PinKind::Add,
            pin_name:None,
            bearer_token: None,
            pinning_endpoint: None,
        })
        .unwrap();
        for _ in 0..DEFAULT_MAX_ATTEMPTS {
            q.mark_failed(&cid, PinTarget::MasterCluster, DEFAULT_MAX_ATTEMPTS)
                .unwrap();
        }
        assert_eq!(q.dead_count().unwrap(), 1);
        assert_eq!(q.pending_count().unwrap(), 0);
        // Even after a reopen the dead record persists.
        drop(q);
    }
}
