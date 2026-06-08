//! Durable "local-retain" backlog (GC-safety).
//!
//! Tracks CIDs the master has pinned **locally** on its own kubo (so
//! `ipfs repo gc` cannot reclaim them) and that are awaiting confirmation of
//! cluster replication. The background verifier (`crate::local_retain`) drains
//! this set: once a block is reported `pinned` on `>=` cluster-min-replication
//! DISTINCT **non-master** holders, it unpins the local copy and removes the
//! CID here. The invariant the whole mechanism upholds — *a block leaves the
//! master's local store only after it is durably replicated elsewhere* — is
//! enforced by the verifier; this module is just the crash-safe set.
//!
//! Crash-safe via a single redb file (ACID, no separate DB process). Keyed by
//! CID bytes; the value is the enqueue timestamp (diagnostics only). Enqueue
//! and remove are both idempotent so double-processing is harmless.

use cid::Cid;
use redb::{Database, ReadableTable, ReadableTableMetadata, TableDefinition};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

const LOCAL_RETAIN: TableDefinition<&[u8], u64> = TableDefinition::new("local_retain_v1");

/// High bit of the stored timestamp value, set to mark a CID as a large-object
/// ROOT whose raw leaves were direct-pinned alongside it. On dropping the root
/// after replication, the verifier re-enumerates (`refs --offline`) and drops
/// those leaves too. Unix-ms timestamps use ~41 bits, so bit 63 is free for
/// ~292 million years; old entries (bit clear) are plain leaf/block entries.
const HAS_LEAVES_BIT: u64 = 1 << 63;

/// Errors from the local-retain backlog store.
#[derive(Debug, thiserror::Error)]
pub enum LocalRetainError {
    #[error("redb open failed: {0}")]
    Open(String),
    #[error("redb operation failed: {0}")]
    Db(String),
    #[error("invalid cid key: {0}")]
    Cid(String),
}

impl From<redb::DatabaseError> for LocalRetainError {
    fn from(e: redb::DatabaseError) -> Self {
        LocalRetainError::Open(e.to_string())
    }
}
impl From<redb::TransactionError> for LocalRetainError {
    fn from(e: redb::TransactionError) -> Self {
        LocalRetainError::Db(e.to_string())
    }
}
impl From<redb::TableError> for LocalRetainError {
    fn from(e: redb::TableError) -> Self {
        LocalRetainError::Db(e.to_string())
    }
}
impl From<redb::StorageError> for LocalRetainError {
    fn from(e: redb::StorageError) -> Self {
        LocalRetainError::Db(e.to_string())
    }
}
impl From<redb::CommitError> for LocalRetainError {
    fn from(e: redb::CommitError) -> Self {
        LocalRetainError::Db(e.to_string())
    }
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Crash-safe set of CIDs awaiting cluster-replication confirmation.
pub struct LocalRetainQueue {
    db: Arc<Database>,
    path: PathBuf,
}

impl LocalRetainQueue {
    /// Open or create the backlog at `path`. The parent directory must exist
    /// (typically created at master startup alongside the other state files).
    pub fn open(path: impl AsRef<Path>) -> Result<Self, LocalRetainError> {
        let path = path.as_ref().to_path_buf();
        let db = Database::create(&path)?;
        let txn = db.begin_write()?;
        {
            // Touch the table so a fresh file has it (redb creates lazily).
            txn.open_table(LOCAL_RETAIN)?;
        }
        txn.commit()?;
        Ok(Self {
            db: Arc::new(db),
            path,
        })
    }

    /// Backing file path (diagnostics).
    #[allow(dead_code)]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Record a CID as locally-pinned-pending-replication. Idempotent: a
    /// repeated enqueue just refreshes the timestamp. The redb commit is the
    /// durability boundary — after `Ok(())` the entry survives a crash.
    pub fn enqueue(&self, cid: &Cid) -> Result<(), LocalRetainError> {
        let key = cid.to_bytes();
        let now = now_unix_ms();
        let txn = self.db.begin_write()?;
        {
            let mut tbl = txn.open_table(LOCAL_RETAIN)?;
            tbl.insert(&key[..], now)?;
        }
        txn.commit()?;
        Ok(())
    }

    /// Like [`Self::enqueue`] but marks the CID as a large-object ROOT whose
    /// raw leaves were direct-pinned alongside it (see [`HAS_LEAVES_BIT`]). The
    /// verifier, on dropping the root after replication, re-enumerates and
    /// drops those leaves too. Idempotent like `enqueue`.
    pub fn enqueue_with_leaves(&self, cid: &Cid) -> Result<(), LocalRetainError> {
        let key = cid.to_bytes();
        let now = now_unix_ms() | HAS_LEAVES_BIT;
        let txn = self.db.begin_write()?;
        {
            let mut tbl = txn.open_table(LOCAL_RETAIN)?;
            tbl.insert(&key[..], now)?;
        }
        txn.commit()?;
        Ok(())
    }

    /// Up to `max` pending CIDs (the verifier processes them in batches).
    pub fn list(&self, max: usize) -> Result<Vec<Cid>, LocalRetainError> {
        let txn = self.db.begin_read()?;
        let tbl = txn.open_table(LOCAL_RETAIN)?;
        let mut out = Vec::new();
        for item in tbl.iter()? {
            if out.len() >= max {
                break;
            }
            let (k, _v) = item?;
            match Cid::try_from(k.value()) {
                Ok(cid) => out.push(cid),
                Err(e) => tracing::warn!(
                    error = %e,
                    "local_retain: skipping unparseable cid key (will not retry)"
                ),
            }
        }
        Ok(out)
    }

    /// Like [`Self::list`] but starts strictly AFTER the `after` redb key (a
    /// cursor), so the verifier can sweep the ENTIRE backlog across cycles
    /// instead of re-processing the same lowest-key batch every cycle
    /// (head-of-line starvation: under-replicated blocks are never removed, so
    /// a plain `list(max)` returns the same blocked head forever and never
    /// reaches the rest — and one permanently-stuck block stalls everything).
    ///
    /// Returns the batch plus the redb key of the last entry visited; pass it
    /// back as `after` next cycle. An empty batch means the keyspace after the
    /// cursor is exhausted — the caller wraps to the start by passing
    /// `after: None`. Keys are CID bytes; iteration is in redb key order, which
    /// is stable, so the sweep is complete and deterministic.
    pub fn list_from(
        &self,
        after: Option<&[u8]>,
        max: usize,
    ) -> Result<(Vec<(Cid, bool)>, Option<Vec<u8>>), LocalRetainError> {
        use std::ops::Bound;
        let txn = self.db.begin_read()?;
        let tbl = txn.open_table(LOCAL_RETAIN)?;
        // Each item is (cid, has_leaves) — has_leaves from the value's marker bit.
        let mut out: Vec<(Cid, bool)> = Vec::new();
        let mut cursor: Option<Vec<u8>> = None;
        let lower: Bound<&[u8]> = match after {
            Some(a) => Bound::Excluded(a),
            None => Bound::Unbounded,
        };
        for item in tbl.range::<&[u8]>((lower, Bound::Unbounded))? {
            if out.len() >= max {
                break;
            }
            let (k, v) = item?;
            // Advance the cursor for EVERY visited key (including unparseable
            // ones) so a bad key can't wedge the sweep at a fixed position.
            cursor = Some(k.value().to_vec());
            let has_leaves = (v.value() & HAS_LEAVES_BIT) != 0;
            match Cid::try_from(k.value()) {
                Ok(cid) => out.push((cid, has_leaves)),
                Err(e) => tracing::warn!(
                    error = %e,
                    "local_retain: skipping unparseable cid key (will not retry)"
                ),
            }
        }
        Ok((out, cursor))
    }

    /// Remove a CID once its block is confirmed replicated (and the local pin
    /// dropped). Idempotent: removing an absent key is a no-op.
    pub fn remove(&self, cid: &Cid) -> Result<(), LocalRetainError> {
        let key = cid.to_bytes();
        let txn = self.db.begin_write()?;
        {
            let mut tbl = txn.open_table(LOCAL_RETAIN)?;
            tbl.remove(&key[..])?;
        }
        txn.commit()?;
        Ok(())
    }

    /// Number of CIDs still awaiting replication confirmation (monitoring).
    pub fn pending_count(&self) -> Result<u64, LocalRetainError> {
        let txn = self.db.begin_read()?;
        let tbl = txn.open_table(LOCAL_RETAIN)?;
        Ok(tbl.len()?)
    }

    /// `(pending_count, oldest_entry_age_ms)` for monitoring. The age is `None`
    /// when the backlog is empty. O(n) scan for the oldest enqueue timestamp —
    /// the backlog holds only un-replicated blocks, so it is small in steady
    /// state, and a large/old backlog is exactly the condition this surfaces.
    pub fn backlog_stats(&self) -> Result<(u64, Option<u64>), LocalRetainError> {
        let txn = self.db.begin_read()?;
        let tbl = txn.open_table(LOCAL_RETAIN)?;
        let count = tbl.len()?;
        let now = now_unix_ms();
        let mut oldest_age_ms: Option<u64> = None;
        for item in tbl.iter()? {
            let (_k, v) = item?;
            // Mask the HAS_LEAVES marker bit before treating the value as a
            // timestamp. `saturating_sub` guards against a clock that moved
            // backwards between enqueue and now (→ age 0 rather than a huge wrap).
            let age = now.saturating_sub(v.value() & !HAS_LEAVES_BIT);
            oldest_age_ms = Some(oldest_age_ms.map_or(age, |o| o.max(age)));
        }
        Ok((count, oldest_age_ms))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cid::multihash::Multihash;

    fn make_cid(seed: u8) -> Cid {
        let mh = Multihash::<64>::wrap(0x1e, &[seed; 32]).expect("blake3 multihash");
        Cid::new_v1(0x55, mh)
    }

    fn fresh() -> (LocalRetainQueue, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let q = LocalRetainQueue::open(dir.path().join("retain.redb")).expect("open");
        (q, dir)
    }

    #[test]
    fn enqueue_list_remove_roundtrip() {
        let (q, _d) = fresh();
        assert_eq!(q.pending_count().unwrap(), 0);

        let a = make_cid(1);
        let b = make_cid(2);
        q.enqueue(&a).unwrap();
        q.enqueue(&b).unwrap();
        // Idempotent re-enqueue doesn't grow the set.
        q.enqueue(&a).unwrap();
        assert_eq!(q.pending_count().unwrap(), 2);

        let listed = q.list(10).unwrap();
        assert_eq!(listed.len(), 2);
        assert!(listed.contains(&a) && listed.contains(&b));

        q.remove(&a).unwrap();
        // Idempotent remove of an absent key is fine.
        q.remove(&a).unwrap();
        assert_eq!(q.pending_count().unwrap(), 1);
        assert_eq!(q.list(10).unwrap(), vec![b]);
    }

    #[test]
    fn backlog_stats_reports_count_and_age() {
        let (q, _d) = fresh();
        // Empty backlog → zero count, no age.
        assert_eq!(q.backlog_stats().unwrap(), (0, None));

        q.enqueue(&make_cid(1)).unwrap();
        q.enqueue(&make_cid(2)).unwrap();
        let (count, age) = q.backlog_stats().unwrap();
        assert_eq!(count, 2);
        // Age is present and small (entries were just enqueued).
        let age = age.expect("non-empty backlog has an oldest age");
        assert!(age < 60_000, "oldest age should be < 60s, got {age}ms");
    }

    #[test]
    fn survives_reopen() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("retain.redb");
        let a = make_cid(7);
        {
            let q = LocalRetainQueue::open(&path).unwrap();
            q.enqueue(&a).unwrap();
        }
        let q2 = LocalRetainQueue::open(&path).unwrap();
        assert_eq!(q2.pending_count().unwrap(), 1);
        assert_eq!(q2.list(10).unwrap(), vec![a]);
    }

    #[test]
    fn list_from_cursor_sweeps_whole_backlog() {
        let (q, _d) = fresh();
        // More entries than a single batch.
        for i in 0..10u8 {
            q.enqueue(&make_cid(i)).unwrap();
        }
        assert_eq!(q.pending_count().unwrap(), 10);

        // Sweep in batches of 3, advancing the cursor. Must visit ALL 10
        // distinct CIDs — a plain `list(3)` would return the same head 3
        // forever (the head-of-line bug this method fixes).
        let mut seen = std::collections::HashSet::new();
        let mut cursor: Option<Vec<u8>> = None;
        for _ in 0..20 {
            let (batch, c) = q.list_from(cursor.as_deref(), 3).unwrap();
            if batch.is_empty() {
                break; // exhausted → caller wraps with None
            }
            assert!(batch.len() <= 3);
            for (cid, _has_leaves) in &batch {
                seen.insert(*cid);
            }
            cursor = c;
        }
        assert_eq!(
            seen.len(),
            10,
            "cursor sweep must visit every backlog entry, not just the lowest-key head"
        );
    }

    #[test]
    fn list_from_none_starts_from_beginning_and_signals_end() {
        let (q, _d) = fresh();
        q.enqueue(&make_cid(5)).unwrap();
        let (batch, cursor) = q.list_from(None, 10).unwrap();
        assert_eq!(batch.len(), 1);
        assert!(cursor.is_some());
        // Ranging strictly after the only key returns empty → end of sweep.
        let (batch2, _) = q.list_from(cursor.as_deref(), 10).unwrap();
        assert!(
            batch2.is_empty(),
            "after the last key there is nothing → caller wraps to start"
        );
    }

    #[test]
    fn enqueue_with_leaves_sets_the_flag() {
        let (q, _d) = fresh();
        let root = make_cid(3);
        let leaf = make_cid(4);
        q.enqueue_with_leaves(&root).unwrap();
        q.enqueue(&leaf).unwrap();
        let (batch, _) = q.list_from(None, 10).unwrap();
        let map: std::collections::HashMap<Cid, bool> = batch.into_iter().collect();
        assert_eq!(map.get(&root), Some(&true), "root must be marked has_leaves");
        assert_eq!(map.get(&leaf), Some(&false), "plain block must not be marked");
        // The flag bit must not corrupt the age (stats stay sane).
        let (count, age) = q.backlog_stats().unwrap();
        assert_eq!(count, 2);
        assert!(age.unwrap() < 60_000, "age must mask the flag bit");
    }
}
