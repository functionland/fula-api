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
            // `saturating_sub` guards against a clock that moved backwards
            // between enqueue and now (→ age 0 rather than a huge wrap).
            let age = now.saturating_sub(v.value());
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
}
