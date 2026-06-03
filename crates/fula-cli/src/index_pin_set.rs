//! Durable per-bucket record of the index-node CID set last *successfully*
//! pinned for gc-safety (the P0 index-node pinning fix).
//!
//! BACKGROUND: a bucket's server-side prolly INDEX stores child CIDs as plain
//! strings, not IPLD links, so recursive pins cover only the root block and gc
//! reclaims every other index node. The fix pins each index node explicitly.
//! Pinning ALL nodes every flush is safe but O(n)/PUT; the cheap path is to pin
//! only `current ∖ prev`. That diff is correct ONLY if `prev` is exactly the
//! set we previously *confirmed pinned* — otherwise (codex review) a node shared
//! by old+new trees but never actually pinned would be skipped and stay
//! gc-exposed. This store provides that honest `prev`:
//!
//!   * read `prev = get(bucket)` (ABSENT ⇒ empty ⇒ "pin ALL", rollout-safe),
//!   * pin `current ∖ prev` FATALLY,
//!   * only on success `put(bucket, current)`.
//!
//! Crash-safe via a single redb file. Keyed by an opaque bucket id (callers use
//! a per-user-scoped key); value is the length-prefixed concatenation of the
//! set's CID bytes.

use cid::Cid;
use redb::{Database, TableDefinition};
use std::path::{Path, PathBuf};
use std::sync::Arc;

const INDEX_PIN_SET: TableDefinition<&str, &[u8]> = TableDefinition::new("index_pin_set_v1");

/// Errors from the index-pin-set store.
#[derive(Debug, thiserror::Error)]
pub enum IndexPinSetError {
    #[error("redb open failed: {0}")]
    Open(String),
    #[error("redb operation failed: {0}")]
    Db(String),
}

impl From<redb::DatabaseError> for IndexPinSetError {
    fn from(e: redb::DatabaseError) -> Self {
        IndexPinSetError::Open(e.to_string())
    }
}
impl From<redb::TransactionError> for IndexPinSetError {
    fn from(e: redb::TransactionError) -> Self {
        IndexPinSetError::Db(e.to_string())
    }
}
impl From<redb::TableError> for IndexPinSetError {
    fn from(e: redb::TableError) -> Self {
        IndexPinSetError::Db(e.to_string())
    }
}
impl From<redb::StorageError> for IndexPinSetError {
    fn from(e: redb::StorageError) -> Self {
        IndexPinSetError::Db(e.to_string())
    }
}
impl From<redb::CommitError> for IndexPinSetError {
    fn from(e: redb::CommitError) -> Self {
        IndexPinSetError::Db(e.to_string())
    }
}

/// Length-prefixed (u32-BE) concatenation of CID bytes. CIDs are variable
/// length, so each is preceded by its byte length.
fn encode_cids(cids: &[Cid]) -> Vec<u8> {
    let mut out = Vec::new();
    for cid in cids {
        let b = cid.to_bytes();
        out.extend_from_slice(&(b.len() as u32).to_be_bytes());
        out.extend_from_slice(&b);
    }
    out
}

fn decode_cids(mut buf: &[u8]) -> Vec<Cid> {
    let mut out = Vec::new();
    while buf.len() >= 4 {
        let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        buf = &buf[4..];
        if buf.len() < len {
            break; // truncated/corrupt tail — return what parsed
        }
        match Cid::try_from(&buf[..len]) {
            Ok(cid) => out.push(cid),
            Err(e) => tracing::warn!(error = %e, "index_pin_set: skipping unparseable cid in stored set"),
        }
        buf = &buf[len..];
    }
    out
}

/// Crash-safe per-bucket "last confirmed-pinned index node set" store.
pub struct IndexPinSet {
    db: Arc<Database>,
    path: PathBuf,
}

impl IndexPinSet {
    /// Open or create the store at `path`. The parent directory must exist.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, IndexPinSetError> {
        let path = path.as_ref().to_path_buf();
        let db = Database::create(&path)?;
        let txn = db.begin_write()?;
        {
            // Touch the table so a fresh file has it (redb creates lazily).
            txn.open_table(INDEX_PIN_SET)?;
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

    /// The CID set last confirmed pinned for `bucket`, or empty if none recorded
    /// (which the caller must treat as "pin ALL current nodes").
    pub fn get(&self, bucket: &str) -> Result<Vec<Cid>, IndexPinSetError> {
        let txn = self.db.begin_read()?;
        let tbl = txn.open_table(INDEX_PIN_SET)?;
        Ok(match tbl.get(bucket)? {
            Some(v) => decode_cids(v.value()),
            None => Vec::new(),
        })
    }

    /// Replace the confirmed-pinned set for `bucket`. Call ONLY after every CID
    /// in `cids` has been successfully (fatally) pinned, so the stored set always
    /// reflects blocks that are actually gc-safe. The redb commit is the
    /// durability boundary.
    pub fn put(&self, bucket: &str, cids: &[Cid]) -> Result<(), IndexPinSetError> {
        let blob = encode_cids(cids);
        let txn = self.db.begin_write()?;
        {
            let mut tbl = txn.open_table(INDEX_PIN_SET)?;
            tbl.insert(bucket, &blob[..])?;
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
        let mh = Multihash::<64>::wrap(0x1e, &[seed; 32]).expect("blake3 multihash");
        Cid::new_v1(0x55, mh)
    }

    #[test]
    fn put_get_roundtrip_replace_and_independence() {
        let dir = tempfile::tempdir().unwrap();
        let s = IndexPinSet::open(dir.path().join("ips.redb")).unwrap();

        // Absent ⇒ empty (the "pin all" signal).
        assert!(s.get("u/b").unwrap().is_empty());

        let set1 = vec![make_cid(1), make_cid(2), make_cid(3)];
        s.put("u/b", &set1).unwrap();
        let got = s.get("u/b").unwrap();
        assert_eq!(got.len(), 3);
        assert!(set1.iter().all(|c| got.contains(c)));

        // Replace fully overwrites.
        let set2 = vec![make_cid(2), make_cid(9)];
        s.put("u/b", &set2).unwrap();
        let got2 = s.get("u/b").unwrap();
        assert_eq!(got2.len(), 2);
        assert!(got2.contains(&make_cid(9)) && got2.contains(&make_cid(2)));
        assert!(!got2.contains(&make_cid(1)));

        // Different bucket id is independent.
        assert!(s.get("u/other").unwrap().is_empty());
    }

    #[test]
    fn survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ips.redb");
        let set = vec![make_cid(5), make_cid(6)];
        {
            IndexPinSet::open(&path).unwrap().put("u/b", &set).unwrap();
        }
        let s2 = IndexPinSet::open(&path).unwrap();
        let got = s2.get("u/b").unwrap();
        assert_eq!(got.len(), 2);
        assert!(got.contains(&make_cid(5)) && got.contains(&make_cid(6)));
    }
}
