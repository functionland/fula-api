//! Persistent orphan-cleanup queue (NEW-F7).
//!
//! When `cleanup_orphaned_storage` fails to delete an object the caller can no
//! longer reference (either the main blob or any of its chunks), the
//! `(bucket, storage_key, num_chunks)` tuple is appended here so a future
//! session can retry. Without this queue an orphaned S3 blob would persist
//! until server-side garbage collection swept it — visible as a storage leak
//! and invisible to the client operator.
//!
//! **v7 scope note.** `cleanup_orphaned_storage` short-circuits at
//! `storage_key_still_referenced` for `ForestCacheEntry::ShardedHamt` — that
//! path conservatively returns `true` until v7 reference traversal is wired.
//! As of this module's introduction no v7 orphan ever reaches this queue;
//! the queue exists for v1/v6 (monolithic + sharded-forest) paths and will
//! begin covering v7 automatically once the v7 traversal lands.
//!
//! **Format.** One record per line, `{json}\t{hex_mac}\n`, MAC'd with a key
//! derived from the user's encryption material via
//! `derive_orphan_queue_mac_key`. Same on-disk shape as `wal.rs` so that
//! tamper / corrupt-tail handling is identical.
//!
//! **Idempotency.** Appends are deduped on `(storage_key)` so that repeated
//! cleanup failures do not grow the queue without bound. Drain re-runs
//! `cleanup_orphaned_storage` rather than raw `delete_object` so the
//! reference-check guard still applies if a content-addressed re-upload has
//! meanwhile revived the key.

use std::io::Write;
use std::path::PathBuf;

use fula_crypto::keys::{DekKey, KeyManager};
use serde::{Deserialize, Serialize};

use crate::error::{ClientError, Result};

const ORPHAN_QUEUE_FILE_VERSION: u8 = 1;

/// A single orphan-cleanup record. Kept minimal so drain can just re-run the
/// existing cleanup routine for each entry.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct OrphanEntry {
    /// Storage key of the orphaned object (keyed in the bucket namespace).
    pub storage_key: String,
    /// Number of chunks if this was a chunked upload; `None` for single-part.
    pub num_chunks: Option<u32>,
}

#[derive(Serialize, Deserialize)]
struct OrphanRecord {
    version: u8,
    entry: OrphanEntry,
}

fn queue_dir() -> Option<PathBuf> {
    let base = match std::env::var("FULA_STATE_DIR") {
        Ok(dir) if !dir.is_empty() => PathBuf::from(dir),
        _ => dirs::state_dir().or_else(dirs::data_local_dir)?,
    };
    Some(base.join("fula").join("orphan-queue"))
}

fn queue_path(bucket: &str) -> Option<PathBuf> {
    let dir = queue_dir()?;
    let bucket_hash = blake3::hash(bucket.as_bytes());
    let bucket_id: String = hex::encode(&bucket_hash.as_bytes()[..16]);
    Some(dir.join(format!("{}.queue", bucket_id)))
}

fn mac_line(mac_key: &DekKey, line: &str) -> String {
    let mac = blake3::keyed_hash(mac_key.as_bytes(), line.as_bytes());
    hex::encode(mac.as_bytes())
}

fn verify_mac(mac_key: &DekKey, line: &str, mac_hex: &str) -> bool {
    let Ok(actual) = hex::decode(mac_hex) else { return false; };
    if actual.len() != 32 {
        return false;
    }
    let expected = blake3::keyed_hash(mac_key.as_bytes(), line.as_bytes());
    expected
        .as_bytes()
        .iter()
        .zip(actual.iter())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}

/// Append an entry for `bucket` if no existing entry has the same
/// `storage_key`. Returns `Ok(true)` if the entry was appended, `Ok(false)`
/// if a duplicate already existed. Durable on return (flush + sync_data).
pub(crate) fn append_dedup(
    bucket: &str,
    mac_key: &DekKey,
    entry: OrphanEntry,
) -> Result<bool> {
    let Some(path) = queue_path(bucket) else {
        return Ok(false);
    };
    // Dedup on storage_key — cheap because the queue is bounded by the
    // number of orphaned objects we failed to delete, not by file count.
    let existing = load(bucket, mac_key).unwrap_or_default();
    if existing.iter().any(|e| e.storage_key == entry.storage_key) {
        return Ok(false);
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(ClientError::Io)?;
    }
    let record = OrphanRecord { version: ORPHAN_QUEUE_FILE_VERSION, entry };
    let json = serde_json::to_string(&record).map_err(|e| {
        ClientError::Encryption(fula_crypto::CryptoError::Encryption(format!(
            "orphan_queue serialize: {}", e
        )))
    })?;
    let mac = mac_line(mac_key, &json);
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(ClientError::Io)?;
    writeln!(f, "{}\t{}", json, mac).map_err(ClientError::Io)?;
    f.flush().map_err(ClientError::Io)?;
    f.sync_data().map_err(ClientError::Io)?;
    Ok(true)
}

/// Load all well-formed entries. Tail corruption is tolerated (malformed /
/// MAC-mismatched lines are logged and skipped) — same policy as wal.rs.
pub(crate) fn load(bucket: &str, mac_key: &DekKey) -> Result<Vec<OrphanEntry>> {
    let Some(path) = queue_path(bucket) else { return Ok(Vec::new()); };
    if !path.exists() {
        return Ok(Vec::new());
    }
    let contents = std::fs::read_to_string(&path).map_err(ClientError::Io)?;
    let mut out = Vec::new();
    for (lineno, raw) in contents.lines().enumerate() {
        let line = raw.trim_end_matches('\n');
        if line.is_empty() {
            continue;
        }
        let Some((json, mac_hex)) = line.rsplit_once('\t') else {
            tracing::warn!(%bucket, lineno, "orphan_queue: malformed line (no tab), skipping");
            continue;
        };
        if !verify_mac(mac_key, json, mac_hex) {
            tracing::warn!(%bucket, lineno, "orphan_queue: MAC mismatch, skipping");
            continue;
        }
        match serde_json::from_str::<OrphanRecord>(json) {
            Ok(rec) if rec.version == ORPHAN_QUEUE_FILE_VERSION => out.push(rec.entry),
            Ok(rec) => {
                tracing::warn!(%bucket, lineno, version = rec.version, "orphan_queue: unknown version");
            }
            Err(e) => {
                tracing::warn!(%bucket, lineno, error = %e, "orphan_queue: decode failed, skipping");
            }
        }
    }
    Ok(out)
}

/// Rewrite the queue file with exactly `keep`. Used after a drain to drop
/// the entries whose re-cleanup succeeded. Writes atomically via a temp
/// file + rename so a crash mid-rewrite cannot corrupt the queue.
pub(crate) fn rewrite(
    bucket: &str,
    mac_key: &DekKey,
    keep: &[OrphanEntry],
) -> Result<()> {
    let Some(path) = queue_path(bucket) else { return Ok(()); };
    if keep.is_empty() {
        return clear(bucket);
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(ClientError::Io)?;
    }
    let tmp = path.with_extension("queue.tmp");
    {
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp)
            .map_err(ClientError::Io)?;
        for entry in keep {
            let record = OrphanRecord {
                version: ORPHAN_QUEUE_FILE_VERSION,
                entry: entry.clone(),
            };
            let json = serde_json::to_string(&record).map_err(|e| {
                ClientError::Encryption(fula_crypto::CryptoError::Encryption(format!(
                    "orphan_queue serialize: {}", e
                )))
            })?;
            let mac = mac_line(mac_key, &json);
            writeln!(f, "{}\t{}", json, mac).map_err(ClientError::Io)?;
        }
        f.flush().map_err(ClientError::Io)?;
        f.sync_data().map_err(ClientError::Io)?;
    }
    std::fs::rename(&tmp, &path).map_err(ClientError::Io)?;
    Ok(())
}

/// Remove the queue file entirely. Called when the queue is drained to empty.
pub(crate) fn clear(bucket: &str) -> Result<()> {
    let Some(path) = queue_path(bucket) else { return Ok(()); };
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(ClientError::Io(e)),
    }
}

/// Derive a MAC key for the orphan queue using `KeyManager::derive_path_key`.
/// Distinct domain separator from wal / manifest-version MAC keys so the
/// keys cannot cross-verify each other's records.
pub(crate) fn derive_orphan_queue_mac_key(km: &KeyManager, bucket: &str) -> DekKey {
    km.derive_path_key(&format!("forest-orphan-queue-mac:{}", bucket))
}

/// Test-only: expose the on-disk queue path for integration tests.
#[cfg(test)]
#[allow(dead_code)]
pub(crate) fn test_path(bucket: &str) -> Option<PathBuf> {
    queue_path(bucket)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Shared with wal::tests — see lib.rs::TEST_ENV_LOCK.
    struct StateDirGuard {
        _dir: tempfile::TempDir,
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    fn tmp_state_dir() -> StateDirGuard {
        let lock = crate::TEST_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let dir = tempfile::tempdir().expect("tempdir");
        std::env::set_var("FULA_STATE_DIR", dir.path());
        StateDirGuard { _dir: dir, _lock: lock }
    }

    #[test]
    fn append_and_load_round_trip() {
        let _dir = tmp_state_dir();
        let bucket = "orphan-rt";
        let mac_key = DekKey::generate();
        let _ = clear(bucket);

        assert!(append_dedup(bucket, &mac_key, OrphanEntry {
            storage_key: "obj-a".into(),
            num_chunks: Some(4),
        }).expect("append a"));
        assert!(append_dedup(bucket, &mac_key, OrphanEntry {
            storage_key: "obj-b".into(),
            num_chunks: None,
        }).expect("append b"));

        let loaded = load(bucket, &mac_key).expect("load");
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].storage_key, "obj-a");
        assert_eq!(loaded[0].num_chunks, Some(4));
        assert_eq!(loaded[1].storage_key, "obj-b");
        assert_eq!(loaded[1].num_chunks, None);
    }

    #[test]
    fn dedup_on_storage_key_returns_false() {
        let _dir = tmp_state_dir();
        let bucket = "orphan-dedup";
        let mac_key = DekKey::generate();
        let _ = clear(bucket);

        assert!(append_dedup(bucket, &mac_key, OrphanEntry {
            storage_key: "dup".into(),
            num_chunks: Some(2),
        }).expect("first"));
        assert!(!append_dedup(bucket, &mac_key, OrphanEntry {
            storage_key: "dup".into(),
            num_chunks: Some(2),
        }).expect("dup"));
        // Even if num_chunks differs, dedup still fires on storage_key.
        assert!(!append_dedup(bucket, &mac_key, OrphanEntry {
            storage_key: "dup".into(),
            num_chunks: None,
        }).expect("dup with diff chunks"));

        let loaded = load(bucket, &mac_key).expect("load");
        assert_eq!(loaded.len(), 1);
    }

    #[test]
    fn mac_mismatch_is_skipped() {
        let _dir = tmp_state_dir();
        let bucket = "orphan-mac";
        let good_key = DekKey::generate();
        let wrong_key = DekKey::generate();
        let _ = clear(bucket);

        append_dedup(bucket, &good_key, OrphanEntry {
            storage_key: "obj".into(),
            num_chunks: None,
        }).expect("append");

        let loaded = load(bucket, &wrong_key).expect("load wrong key");
        assert!(loaded.is_empty());

        let loaded = load(bucket, &good_key).expect("load good");
        assert_eq!(loaded.len(), 1);
    }

    #[test]
    fn rewrite_keeps_only_given_entries() {
        let _dir = tmp_state_dir();
        let bucket = "orphan-rewrite";
        let mac_key = DekKey::generate();
        let _ = clear(bucket);

        for i in 0..3 {
            append_dedup(bucket, &mac_key, OrphanEntry {
                storage_key: format!("obj-{}", i),
                num_chunks: Some(i),
            }).expect("append");
        }

        // Keep only obj-1.
        let keep = vec![OrphanEntry {
            storage_key: "obj-1".into(),
            num_chunks: Some(1),
        }];
        rewrite(bucket, &mac_key, &keep).expect("rewrite");

        let loaded = load(bucket, &mac_key).expect("load after rewrite");
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].storage_key, "obj-1");

        // Rewriting to empty deletes the file entirely.
        rewrite(bucket, &mac_key, &[]).expect("rewrite empty");
        let loaded = load(bucket, &mac_key).expect("load after clear");
        assert!(loaded.is_empty());
    }
}
