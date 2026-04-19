//! Forest write-ahead log (WAL) for the sharded-forest flush path.
//!
//! NEW-7.2: the prior behavior on a `save_sharded_forest` 412 was to evict the
//! cache and propagate the error. That loses dirty forest entries whose file
//! bytes are already on S3, and — critically — leaves the bucket in a state
//! where a manifest PUT that lost its race can leave S3 shards at a sequence
//! the winning manifest doesn't know about, tripping the per-shard AEAD
//! sequence verifier and rendering the shard unreadable.
//!
//! The WAL records every pending upsert so the flush retry loop (see
//! `encryption::save_sharded_forest`) can replay them on top of the winner's
//! forest and re-issue the flush. Each WAL file is MAC'd with a key derived
//! from the user's encryption key so a local tamperer cannot cause spurious
//! work to be replayed against the forest.

use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use fula_crypto::keys::DekKey;
use fula_crypto::private_forest::ForestFileEntry;
use serde::{Deserialize, Serialize};

use crate::error::{ClientError, Result};

const WAL_FILE_VERSION: u8 = 1;

/// Monotonically-increasing count of `append()` invocations that entered
/// the on-disk I/O path and returned `Err`. The no-state-dir early return
/// is a documented silent no-op (matches the WASM path) and does not bump
/// this counter — only genuine durability-impacting failures do. (F11.)
static WAL_APPEND_FAILURES: AtomicU64 = AtomicU64::new(0);

/// A single WAL record.
///
/// **Format-agnostic.** The on-disk layout is deliberately the same across
/// every supported forest version (v1 monolithic through v7 sharded-HAMT).
/// Entries are keyed by user-facing path (plus storage_key for inserts) so
/// replay can target the correct shard on whatever manifest is live at
/// recovery time — the WAL carries no version field and does not care whether
/// the currently-active forest is monolithic or sharded.
///
/// **Interaction with v1 → v7 migration.** The load-time migration trigger
/// (`EncryptedClient::migrate_v1_to_v7_internal`) checks for WAL presence
/// before acquiring the server lock; a non-empty WAL short-circuits to
/// `DeferredTransientError`. Rationale: draining the WAL rewrites the v1
/// index blob, which invalidates the If-Match ETag the migration would bind
/// to the v7 manifest PUT. Waiting for the next access means the next
/// `ensure_forest_loaded` call drains the WAL via `recover_wal_after_load`
/// (which calls `flush_forest` — itself responsible for `wal::clear` on
/// success) and the following load-time trigger re-enters with a matching
/// ETag.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "op")]
pub(crate) enum WalEntry {
    /// An upsert of `entry` whose underlying object is already uploaded under
    /// `storage_key`. `key` is the user-facing path (needed so replay can
    /// target the correct shard in the new manifest).
    #[serde(rename = "insert")]
    Insert {
        key: String,
        entry: ForestFileEntry,
    },
    /// A removal of the forest entry for the user-facing path `key`.
    #[serde(rename = "remove")]
    Remove { key: String },
    /// Phase-1 of a sharded flush succeeded for shard `idx`, but the flush as a
    /// whole may still have raced on the phase-2 manifest PUT. Records the new
    /// on-S3 sequence and ETag so a subsequent replay can reconcile: the winning
    /// manifest won't mention our advancement, and without this record the
    /// retry's AEAD seq check would refuse to read our own shard.
    #[serde(rename = "shard_wrote")]
    ShardWrote { idx: usize, seq: u64, etag: Option<String> },
}

/// The on-disk WAL body before MAC. Kept deliberately small — each record is
/// one line of JSON to avoid partial-write issues when appending.
#[derive(Serialize, Deserialize)]
struct WalRecord {
    version: u8,
    entry: WalEntry,
}

/// Resolve the WAL directory, honoring `FULA_STATE_DIR` first then falling
/// back to the OS state/data-local directory. Returns None only when no state
/// directory is available (e.g. locked-down sandboxes).
fn wal_dir() -> Option<PathBuf> {
    let base = match std::env::var("FULA_STATE_DIR") {
        Ok(dir) if !dir.is_empty() => PathBuf::from(dir),
        _ => dirs::state_dir().or_else(dirs::data_local_dir)?,
    };
    Some(base.join("fula").join("wal"))
}

fn wal_path(bucket: &str) -> Option<PathBuf> {
    let dir = wal_dir()?;
    let bucket_hash = blake3::hash(bucket.as_bytes());
    let bucket_id: String = hex::encode(&bucket_hash.as_bytes()[..16]);
    Some(dir.join(format!("{}.wal", bucket_id)))
}

pub(crate) fn mac_line(mac_key: &DekKey, line: &str) -> String {
    let mac = blake3::keyed_hash(mac_key.as_bytes(), line.as_bytes());
    hex::encode(mac.as_bytes())
}

pub(crate) fn verify_mac(mac_key: &DekKey, line: &str, mac_hex: &str) -> bool {
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

/// Append a single entry to the bucket's WAL. The line format is
/// `<json>\t<hex_mac>\n`. After writing, the record is both flushed (libc
/// buffers) and `sync_data`'d (kernel page cache → disk), so neither a
/// process crash nor a power loss can lose a record that this function
/// returned `Ok` for. (NEW-F12.)
pub(crate) fn append(bucket: &str, mac_key: &DekKey, entry: WalEntry) -> Result<()> {
    let Some(path) = wal_path(bucket) else {
        // No state dir — silently continue (matches the no-op WASM path).
        return Ok(());
    };
    // F11: bump the failure counter once per real I/O-path failure so
    // operators can alert on WAL durability incidents. The closure owns
    // `entry` (WalRecord moves it in) so we do the move + fallible work
    // here, then react to the outcome outside.
    let result: Result<()> = (move || {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(ClientError::Io)?;
        }
        let record = WalRecord { version: WAL_FILE_VERSION, entry };
        let json = serde_json::to_string(&record).map_err(|e| {
            ClientError::Encryption(fula_crypto::CryptoError::Encryption(format!(
                "WAL serialize: {}", e
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
        Ok(())
    })();
    if result.is_err() {
        WAL_APPEND_FAILURES.fetch_add(1, Ordering::Relaxed);
    }
    result
}

/// Observable count of WAL append failures since process start. Never
/// resets; monotonic. Intended for metrics / operator alerting — a rising
/// value means in-memory dirty forest state is out-running its on-disk
/// crash-recovery log. (F11.)
#[allow(dead_code)] // Exposed for observability consumers + the F11 test.
pub(crate) fn append_failure_count() -> u64 {
    WAL_APPEND_FAILURES.load(Ordering::Relaxed)
}

/// Load all well-formed entries from the bucket's WAL. Entries whose MAC or
/// format fails verification are logged and skipped rather than aborting the
/// whole load — a corrupt tail is preferable to losing the earlier records.
pub(crate) fn load(bucket: &str, mac_key: &DekKey) -> Result<Vec<WalEntry>> {
    let Some(path) = wal_path(bucket) else { return Ok(Vec::new()); };
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
            tracing::warn!(%bucket, lineno, "WAL: malformed line (no tab), skipping");
            continue;
        };
        if !verify_mac(mac_key, json, mac_hex) {
            tracing::warn!(%bucket, lineno, "WAL: MAC mismatch, skipping");
            continue;
        }
        match serde_json::from_str::<WalRecord>(json) {
            Ok(rec) if rec.version == WAL_FILE_VERSION => out.push(rec.entry),
            Ok(rec) => {
                tracing::warn!(%bucket, lineno, version = rec.version, "WAL: unknown record version");
            }
            Err(e) => {
                tracing::warn!(%bucket, lineno, error = %e, "WAL: decode failed, skipping");
            }
        }
    }
    Ok(out)
}

/// Delete the WAL for `bucket`. Called on clean flush completion.
pub(crate) fn clear(bucket: &str) -> Result<()> {
    let Some(path) = wal_path(bucket) else { return Ok(()); };
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(ClientError::Io(e)),
    }
}

/// Return the on-disk WAL path for telemetry / error reporting.
pub(crate) fn path_for(bucket: &str) -> Option<PathBuf> {
    wal_path(bucket)
}

/// Derive a MAC key for the bucket's WAL using the `KeyManager::derive_path_key`
/// domain-separation pattern. Called by `encryption::EncryptedClient`.
pub(crate) fn derive_mac_key(
    km: &fula_crypto::keys::KeyManager,
    bucket: &str,
) -> DekKey {
    km.derive_path_key(&format!("forest-wal-mac:{}", bucket))
}

/// Derive a MAC key for the manifest-version pin file. Distinct domain
/// separator from the WAL MAC so the two keys cannot cross-verify each
/// other's records. (NEW-F9.)
pub(crate) fn derive_manifest_version_mac_key(
    km: &fula_crypto::keys::KeyManager,
    bucket: &str,
) -> DekKey {
    km.derive_path_key(&format!("forest-manifest-version-mac:{}", bucket))
}

/// Test-only: expose the wal file path so tests can corrupt / inspect it.
#[cfg(test)]
#[allow(dead_code)]
pub(crate) fn test_path(bucket: &str) -> Option<PathBuf> {
    wal_path(bucket)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fula_crypto::private_forest::ForestFileEntry;
    use std::collections::HashMap;

    // Shared with orphan_queue::tests — see lib.rs::TEST_ENV_LOCK.
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

    fn sample_entry(path: &str) -> ForestFileEntry {
        ForestFileEntry {
            path: path.to_string(),
            storage_key: format!("storage-for-{}", path),
            size: 42,
            content_type: Some("text/plain".to_string()),
            created_at: 1,
            modified_at: 1,
            content_hash: None,
            user_metadata: HashMap::new(),
            encrypted: true,
        }
    }

    #[test]
    fn append_and_load_round_trip() {
        let _dir = tmp_state_dir();
        let bucket = "round-trip-bucket";
        let mac_key = DekKey::generate();
        let _ = clear(bucket);

        append(bucket, &mac_key, WalEntry::Insert {
            key: "/a.txt".to_string(),
            entry: sample_entry("/a.txt"),
        }).expect("append insert");
        append(bucket, &mac_key, WalEntry::Remove {
            key: "/b.txt".to_string(),
        }).expect("append remove");

        let loaded = load(bucket, &mac_key).expect("load");
        assert_eq!(loaded.len(), 2);
        match &loaded[0] {
            WalEntry::Insert { key, entry } => {
                assert_eq!(key, "/a.txt");
                assert_eq!(entry.path, "/a.txt");
            }
            _ => panic!("expected Insert"),
        }
        match &loaded[1] {
            WalEntry::Remove { key } => assert_eq!(key, "/b.txt"),
            _ => panic!("expected Remove"),
        }

        clear(bucket).expect("clear");
        let loaded = load(bucket, &mac_key).expect("load after clear");
        assert!(loaded.is_empty());
    }

    #[test]
    fn mac_mismatch_is_skipped() {
        let _dir = tmp_state_dir();
        let bucket = "mac-mismatch-bucket";
        let good_key = DekKey::generate();
        let wrong_key = DekKey::generate();
        let _ = clear(bucket);

        append(bucket, &good_key, WalEntry::Insert {
            key: "/only.txt".to_string(),
            entry: sample_entry("/only.txt"),
        }).expect("append");

        // Loading with the wrong MAC key must not return the forged entry.
        let loaded = load(bucket, &wrong_key).expect("load with wrong key");
        assert!(loaded.is_empty(), "MAC-mismatched lines must be skipped");

        // Loading with the right key still works.
        let loaded = load(bucket, &good_key).expect("load with good key");
        assert_eq!(loaded.len(), 1);
    }

    #[test]
    fn malformed_line_is_skipped_but_valid_preserved() {
        let _dir = tmp_state_dir();
        let bucket = "malformed-bucket";
        let mac_key = DekKey::generate();
        let _ = clear(bucket);

        append(bucket, &mac_key, WalEntry::Insert {
            key: "/valid.txt".to_string(),
            entry: sample_entry("/valid.txt"),
        }).expect("append");

        // Directly append a garbage line with no tab.
        let path = wal_path(bucket).expect("wal path");
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("open append");
        writeln!(f, "this-line-has-no-tab").expect("write garbage");

        let loaded = load(bucket, &mac_key).expect("load");
        assert_eq!(loaded.len(), 1, "only the well-formed line should survive");
    }

    #[test]
    fn mac_key_domain_separated() {
        // forest-wal-mac keys differ from any forest DEK for the same bucket.
        let km = fula_crypto::keys::KeyManager::new();
        let wal_mac = derive_mac_key(&km, "bkt");
        let forest_dek = km.derive_path_key("forest:bkt");
        assert_ne!(wal_mac.as_bytes(), forest_dek.as_bytes(),
            "WAL MAC key and forest DEK must be domain-separated");
    }

    // F11: the failure metric must bump on genuine I/O failure and stay
    // flat on both no-op early-return and successful appends.
    #[test]
    fn append_failure_bumps_counter_only_on_error() {
        let _guard = tmp_state_dir();
        let bucket = "append-failure-bucket";
        let mac_key = DekKey::generate();
        let _ = clear(bucket);

        // Sabotage: create a regular file at `<state>/fula` so
        // create_dir_all(.../fula/wal) fails with NotADirectory-class Io.
        let state_path = std::env::var("FULA_STATE_DIR")
            .expect("tmp_state_dir sets FULA_STATE_DIR");
        let fula_blocker = PathBuf::from(&state_path).join("fula");
        std::fs::write(&fula_blocker, b"blocker")
            .expect("write blocker file");

        let before = append_failure_count();
        let err = append(bucket, &mac_key, WalEntry::Insert {
            key: "/x.txt".to_string(),
            entry: sample_entry("/x.txt"),
        }).expect_err("append must fail when `fula` is a regular file");
        let after = append_failure_count();

        assert!(matches!(err, ClientError::Io(_)),
            "expected Io error, got {:?}", err);
        assert_eq!(after - before, 1,
            "counter must increment exactly once per failed append");

        // Success path: remove the blocker, append again — counter must NOT move.
        std::fs::remove_file(&fula_blocker).expect("remove blocker");
        let before_ok = append_failure_count();
        append(bucket, &mac_key, WalEntry::Insert {
            key: "/y.txt".to_string(),
            entry: sample_entry("/y.txt"),
        }).expect("append succeeds after blocker removed");
        let after_ok = append_failure_count();
        assert_eq!(after_ok, before_ok,
            "counter must stay flat on successful append");
    }
}

