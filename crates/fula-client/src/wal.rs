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

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use fula_crypto::keys::DekKey;
use fula_crypto::private_forest::ForestFileEntry;
use serde::{Deserialize, Serialize};

use crate::error::{ClientError, Result};

const WAL_FILE_VERSION: u8 = 1;

/// **D4 audit fix — soft cap on WAL file size.**
///
/// Pre-fix the WAL grew without bound: a sustained master-down condition
/// (or persistent 412 races on flush) accumulated 1–3 entries per write
/// forever. Two failure modes followed:
///
/// 1. WAL eventually fills the user's disk — application-level OOM or
///    panic when `append` returns `EIO`.
/// 2. WAL load (`read_to_string`, now streaming via D4) tries to allocate
///    the whole file and OOMs at startup.
///
/// At 64 MB (~hundreds of thousands of file-write entries) the user has
/// already lost reach to master long enough that something is wrong. The
/// soft cap returns a typed error from `append` so callers can surface
/// "your local SDK has accumulated too many pending writes; investigate
/// master connectivity or wipe the WAL to drop unflushed work" rather
/// than crash on `EIO` / OOM.
///
/// Configurable via `FULA_WAL_SOFT_CAP_BYTES` env var (operator override
/// for unusual environments). 64 MB is a generous default — typical
/// per-write footprint is ~500 bytes, so this represents ~130k pending
/// writes before the cap fires.
const WAL_SOFT_CAP_BYTES_DEFAULT: u64 = 64 * 1024 * 1024;

fn wal_soft_cap_bytes() -> u64 {
    std::env::var("FULA_WAL_SOFT_CAP_BYTES")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(WAL_SOFT_CAP_BYTES_DEFAULT)
}

/// Monotonically-increasing count of `append()` invocations that entered
/// the on-disk I/O path and returned `Err`. The no-state-dir early return
/// is a documented silent no-op (matches the WASM path) and does not bump
/// this counter — only genuine durability-impacting failures do. (F11.)
static WAL_APPEND_FAILURES: AtomicU64 = AtomicU64::new(0);

/// M-4: Monotonic count of WAL groups discarded on load because the on-disk
/// record set was incomplete (fewer members than the group's declared count,
/// or index gaps). A rising value means `append_group` writes were truncated
/// between the per-line `write` and the trailing `sync_data` — the load path
/// drops every surviving member so replay never sees a partial transaction.
static WAL_TRUNCATED_GROUPS: AtomicU64 = AtomicU64::new(0);

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
    /// Phase-1.5 of a sharded-HAMT v7 flush succeeded for manifest page
    /// `page_id` (meta-HAMT). Written+fsynced BEFORE the corresponding PUT
    /// so a crash between the fsync and the PUT is idempotent: on replay we
    /// re-PUT under the same page key with the same seq. On a 412 race the
    /// `new_etag` / `new_seq` let us reconcile: the winner's root may
    /// reference a stale page, and without this record the retry's AEAD seq
    /// check would refuse to read our page back.
    #[serde(rename = "page_wrote")]
    PageWrote {
        page_id: u16,
        old_etag: Option<String>,
        new_etag: Option<String>,
        seq: u64,
    },
    /// The encrypted directory-index object was PUT successfully but the
    /// manifest-root update tying `new_etag` into `root.dir_index_etag` may
    /// still race. Replay re-issues the dir-index PUT (idempotent at the
    /// same key) and then retries the root PUT so listings stay consistent.
    #[serde(rename = "dir_index_wrote")]
    DirIndexWrote {
        old_etag: Option<String>,
        new_etag: Option<String>,
        seq: u64,
    },
    /// plan-D5 (v8) — one SHARD of the sharded directory index was PUT, but the
    /// manifest-root update tying `new_etag` into `root.dir_index_shards[idx]`
    /// may still race. Replay re-issues the shard PUT (idempotent at its
    /// index-addressed key) and retries the root PUT. Mirrors `PageWrote` for
    /// the dir-index shard layer.
    #[serde(rename = "dir_index_shard_wrote")]
    DirIndexShardWrote {
        shard_idx: u8,
        old_etag: Option<String>,
        new_etag: Option<String>,
        seq: u64,
    },
}

/// Group metadata tag for transactional multi-entry appends written via
/// `append_group`. All records in a group share a single `id`, carry their
/// own 0-based `index`, and the group's total `count`. On load, a group is
/// applied atomically only when every member is present and MAC-valid; a
/// missing or corrupt member discards the whole group and bumps
/// `WAL_TRUNCATED_GROUPS`. (M-4.)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct WalGroupMeta {
    /// 128-bit random hex identifier, unique per `append_group` call.
    pub(crate) id: String,
    /// 0-based position within the group.
    pub(crate) index: u32,
    /// Total number of records the group expects.
    pub(crate) count: u32,
}

/// The on-disk WAL body before MAC. Kept deliberately small — each record is
/// one line of JSON to avoid partial-write issues when appending.
#[derive(Serialize, Deserialize)]
struct WalRecord {
    version: u8,
    entry: WalEntry,
    /// `Some` only for records written by `append_group`. `skip_serializing_if`
    /// keeps the on-disk shape of single-entry `append` records byte-identical
    /// to the pre-M-4 format, so MAC verification of legacy lines is
    /// unaffected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    group: Option<WalGroupMeta>,
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

        // **D4 audit — soft-cap check before append.** If the WAL has
        // already accumulated past the soft cap, surface a typed
        // `ConcurrentModificationExhausted`-flavored error so the caller
        // (and operator) sees a clear signal that something is wrong with
        // master connectivity or flush coordination. Without this check,
        // sustained master-down silently accumulates dirty WAL entries
        // until disk fills or the load path OOMs at startup.
        let cap = wal_soft_cap_bytes();
        if let Ok(meta) = std::fs::metadata(&path) {
            if meta.len() > cap {
                tracing::error!(
                    %bucket,
                    wal_size = meta.len(),
                    cap,
                    "D4: WAL exceeds soft cap — likely sustained master-down or flush failure; \
                     refusing further appends until WAL is drained or wiped"
                );
                return Err(ClientError::UploadFailed(format!(
                    "WAL for bucket {} exceeds soft cap ({} bytes > {} bytes); \
                     master appears unreachable or flush is repeatedly losing 412 races. \
                     Pending writes cannot be durably recorded until either: (a) master \
                     becomes reachable and `flush_forest` succeeds (drains the WAL), or \
                     (b) the WAL is manually deleted (drops every unflushed write). \
                     Override the cap via FULA_WAL_SOFT_CAP_BYTES env var if intentional.",
                    bucket, meta.len(), cap,
                )));
            }
        }

        let record = WalRecord { version: WAL_FILE_VERSION, entry, group: None };
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
/// crash-recovery log. Re-exported publicly from the crate root as
/// `wal_append_failure_count`. (F11.)
pub(crate) fn append_failure_count() -> u64 {
    WAL_APPEND_FAILURES.load(Ordering::Relaxed)
}

/// Observable count of WAL groups discarded on load due to partial-group
/// truncation. Monotonic, process-wide; re-exported publicly as
/// `wal_truncated_groups_count`. (M-4.)
pub(crate) fn truncated_groups_count() -> u64 {
    WAL_TRUNCATED_GROUPS.load(Ordering::Relaxed)
}

/// Append a transactional group of entries with all-or-none replay semantics.
///
/// Each entry is written as its own line with a shared `group.id` tag; a
/// single `sync_data` fsync is issued after the entire group is on-disk
/// (vs. per-entry fsync in `append`). On load, the group is applied only if
/// every member is present — a partial group (typical of a power-loss between
/// the writes and the fsync, or a crash mid-write) is discarded in full and
/// `WAL_TRUNCATED_GROUPS` is incremented.
///
/// **Use this when** a logical op spans multiple WAL entries that must commit
/// together (e.g., a rename expressed as `Remove` + `Insert`, or a composite
/// upsert that edits two paths at once).
///
/// **Do NOT use this for** per-entry-idempotent logs such as the phase-1
/// shard-write emit loop. Those rely on individual durability: if the 3rd of
/// 5 shards fails to write, the first two shards must still be replayable so
/// the next flush can reconcile them. Grouping such writes would silently
/// drop valid reconciliation data on any partial failure.
///
/// Returns `Ok(())` on an empty slice. An I/O error (including a mid-group
/// failure) increments `WAL_APPEND_FAILURES` exactly once, matching `append`'s
/// metric contract.
///
/// Currently unused in production paths (all existing WAL writers are
/// single-entry or per-entry-idempotent). Kept as defense-in-depth so new
/// multi-step ops can opt into atomic replay without reinventing the
/// framing. Exercised by `#[cfg(test)]` coverage.
#[allow(dead_code)]
pub(crate) fn append_group(
    bucket: &str,
    mac_key: &DekKey,
    entries: &[WalEntry],
) -> Result<()> {
    if entries.is_empty() {
        return Ok(());
    }
    let Some(path) = wal_path(bucket) else {
        // No state dir — silently no-op, matching append().
        return Ok(());
    };
    let result: Result<()> = (|| {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(ClientError::Io)?;
        }
        // 128-bit random group id via DekKey's getrandom-backed constructor.
        // We never use it as a key — only its random-bytes property — and the
        // temporary DekKey is zeroized on drop, which is a harmless bonus.
        let id_bytes = DekKey::generate();
        let id = hex::encode(&id_bytes.as_bytes()[..16]);
        let count = entries.len() as u32;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(ClientError::Io)?;
        for (i, entry) in entries.iter().enumerate() {
            let record = WalRecord {
                version: WAL_FILE_VERSION,
                entry: entry.clone(),
                group: Some(WalGroupMeta {
                    id: id.clone(),
                    index: i as u32,
                    count,
                }),
            };
            let json = serde_json::to_string(&record).map_err(|e| {
                ClientError::Encryption(fula_crypto::CryptoError::Encryption(format!(
                    "WAL serialize: {}", e
                )))
            })?;
            let mac = mac_line(mac_key, &json);
            writeln!(f, "{}\t{}", json, mac).map_err(ClientError::Io)?;
        }
        f.flush().map_err(ClientError::Io)?;
        f.sync_data().map_err(ClientError::Io)?;
        Ok(())
    })();
    if result.is_err() {
        WAL_APPEND_FAILURES.fetch_add(1, Ordering::Relaxed);
    }
    result
}

/// Load all well-formed entries from the bucket's WAL. Entries whose MAC or
/// format fails verification are logged and skipped rather than aborting the
/// whole load — a corrupt tail is preferable to losing the earlier records.
///
/// Group-aware (M-4): records tagged with a `group` id are accumulated and
/// applied atomically in index order at the position of the group's first
/// member in the file. An incomplete group (any member missing, or index
/// collisions) is discarded and `WAL_TRUNCATED_GROUPS` is incremented once
/// per discarded group. Non-grouped (legacy) records pass through unchanged
/// and preserve their append order relative to groups.
pub(crate) fn load(bucket: &str, mac_key: &DekKey) -> Result<Vec<WalEntry>> {
    use std::collections::HashMap;

    let Some(path) = wal_path(bucket) else { return Ok(Vec::new()); };
    if !path.exists() {
        return Ok(Vec::new());
    }

    // **D4 audit fix — streaming load instead of `read_to_string`.**
    //
    // Pre-fix `load` did `std::fs::read_to_string(&path)`, which allocates
    // the entire WAL file into a single `String`. A WAL that grew large
    // under sustained master-down (now bounded by the soft cap in
    // `append`, but legacy WALs from pre-fix builds may already exceed
    // the cap) caused startup-time OOMs. Switching to `BufReader::lines()`
    // streams the file line-by-line: peak memory is one line plus the
    // accumulator state, regardless of file size.
    let f = std::fs::File::open(&path).map_err(ClientError::Io)?;
    let reader = BufReader::new(f);

    // Two-phase load: (1) walk the file in append order and place either a
    // Direct entry or a GroupRef placeholder into `items`; accumulate group
    // members into `groups`. (2) flatten `items`, replacing each GroupRef
    // with its members in index order, or discarding incomplete groups.
    enum Item {
        Direct(WalEntry),
        GroupRef(String),
    }
    struct GroupAccum {
        count: u32,
        members: HashMap<u32, WalEntry>,
    }

    let mut items: Vec<Item> = Vec::new();
    let mut groups: HashMap<String, GroupAccum> = HashMap::new();

    for (lineno, line_result) in reader.lines().enumerate() {
        let raw = match line_result {
            Ok(l) => l,
            Err(e) => {
                tracing::warn!(%bucket, lineno, error = %e, "WAL: read error, stopping load");
                break;
            }
        };
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
            Ok(rec) if rec.version == WAL_FILE_VERSION => {
                match rec.group {
                    None => items.push(Item::Direct(rec.entry)),
                    Some(meta) => {
                        // First time we see this group id, reserve its
                        // position in the output sequence. Later members
                        // just fold into the accumulator.
                        if !groups.contains_key(&meta.id) {
                            groups.insert(
                                meta.id.clone(),
                                GroupAccum { count: meta.count, members: HashMap::new() },
                            );
                            items.push(Item::GroupRef(meta.id.clone()));
                        }
                        let group = groups.get_mut(&meta.id).expect("just inserted");
                        group.members.insert(meta.index, rec.entry);
                    }
                }
            }
            Ok(rec) => {
                tracing::warn!(%bucket, lineno, version = rec.version, "WAL: unknown record version");
            }
            Err(e) => {
                tracing::warn!(%bucket, lineno, error = %e, "WAL: decode failed, skipping");
            }
        }
    }

    let mut out = Vec::new();
    for item in items {
        match item {
            Item::Direct(e) => out.push(e),
            Item::GroupRef(id) => {
                // Safe: every id pushed as GroupRef was inserted into `groups`
                // at the same iteration.
                let accum = groups.remove(&id).expect("group accumulator present");
                let complete = (accum.members.len() as u32) == accum.count
                    && (0..accum.count).all(|i| accum.members.contains_key(&i));
                if complete {
                    let mut ordered: Vec<(u32, WalEntry)> = accum.members.into_iter().collect();
                    ordered.sort_by_key(|(i, _)| *i);
                    for (_, entry) in ordered {
                        out.push(entry);
                    }
                } else {
                    tracing::warn!(
                        %bucket,
                        group_id = %id,
                        expected = accum.count,
                        got = accum.members.len(),
                        "WAL: incomplete group, discarding"
                    );
                    WAL_TRUNCATED_GROUPS.fetch_add(1, Ordering::Relaxed);
                }
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

/// Derive a MAC key for the walkable-v8 migration marker file (issue #10).
/// Distinct domain separator from the manifest-version pin and the WAL
/// MAC so cross-verification is impossible.
pub(crate) fn derive_walkable_v8_marker_mac_key(
    km: &fula_crypto::keys::KeyManager,
    bucket: &str,
) -> DekKey {
    km.derive_path_key(&format!("walkable-v8-migration-marker-mac:{}", bucket))
}

/// Test-only: expose the wal file path so tests can corrupt / inspect it.
#[cfg(test)]
#[allow(dead_code)]
pub(crate) fn test_path(bucket: &str) -> Option<PathBuf> {
    wal_path(bucket)
}

#[cfg(test)]
#[allow(deprecated)] // F1: tests legitimately use KeyManager::new() (random keypair); deprecation targets production callers only
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
            min_version: 0,
            storage_cid: None,
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

    // M-4: `append_group` writes an all-or-none transactional group; load
    // reconstructs it in index order at the first-member's file position.
    #[test]
    fn wal_complete_group_applied() {
        let _guard = tmp_state_dir();
        let bucket = "complete-group-bucket";
        let mac_key = DekKey::generate();
        let _ = clear(bucket);

        let entries = vec![
            WalEntry::Insert { key: "/g/0.txt".to_string(), entry: sample_entry("/g/0.txt") },
            WalEntry::Remove { key: "/g/stale.txt".to_string() },
            WalEntry::Insert { key: "/g/2.txt".to_string(), entry: sample_entry("/g/2.txt") },
        ];
        let before = truncated_groups_count();
        append_group(bucket, &mac_key, &entries).expect("append_group");

        let loaded = load(bucket, &mac_key).expect("load");
        assert_eq!(loaded.len(), 3, "complete group must surface every member");
        match &loaded[0] {
            WalEntry::Insert { key, .. } => assert_eq!(key, "/g/0.txt"),
            other => panic!("expected Insert at 0, got {:?}", other),
        }
        match &loaded[1] {
            WalEntry::Remove { key } => assert_eq!(key, "/g/stale.txt"),
            other => panic!("expected Remove at 1, got {:?}", other),
        }
        match &loaded[2] {
            WalEntry::Insert { key, .. } => assert_eq!(key, "/g/2.txt"),
            other => panic!("expected Insert at 2, got {:?}", other),
        }

        assert_eq!(
            truncated_groups_count(), before,
            "complete group must not bump the truncated-groups counter"
        );
    }

    // M-4: a group whose tail is lost to truncation is discarded wholesale;
    // the partial members must not leak into replay. The counter bumps once.
    #[test]
    fn wal_partial_group_discarded() {
        let _guard = tmp_state_dir();
        let bucket = "partial-group-bucket";
        let mac_key = DekKey::generate();
        let _ = clear(bucket);

        let entries = vec![
            WalEntry::Insert { key: "/p/0.txt".to_string(), entry: sample_entry("/p/0.txt") },
            WalEntry::Insert { key: "/p/1.txt".to_string(), entry: sample_entry("/p/1.txt") },
            WalEntry::Insert { key: "/p/2.txt".to_string(), entry: sample_entry("/p/2.txt") },
        ];
        append_group(bucket, &mac_key, &entries).expect("append_group");

        // Simulate mid-group truncation by lopping the last line off the file.
        let path = wal_path(bucket).expect("wal path");
        let contents = std::fs::read_to_string(&path).expect("read wal");
        let mut lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 3, "expected 3 on-disk lines before truncation");
        lines.pop();
        let truncated = lines.join("\n") + "\n";
        std::fs::write(&path, truncated).expect("truncate write");

        let before = truncated_groups_count();
        let loaded = load(bucket, &mac_key).expect("load");
        let after = truncated_groups_count();

        assert!(loaded.is_empty(), "incomplete group must not surface any members");
        assert_eq!(
            after - before, 1,
            "partial-group discard must bump truncated-groups exactly once"
        );
    }

    // M-4: legacy single-entry `append` records and new group-framed records
    // share one file without interfering; relative order is preserved.
    #[test]
    fn wal_legacy_and_grouped_records_coexist() {
        let _guard = tmp_state_dir();
        let bucket = "coexist-bucket";
        let mac_key = DekKey::generate();
        let _ = clear(bucket);

        append(bucket, &mac_key, WalEntry::Insert {
            key: "/legacy-1.txt".to_string(),
            entry: sample_entry("/legacy-1.txt"),
        }).expect("append legacy-1");

        append_group(bucket, &mac_key, &[
            WalEntry::Remove { key: "/grp/a.txt".to_string() },
            WalEntry::Insert {
                key: "/grp/b.txt".to_string(),
                entry: sample_entry("/grp/b.txt"),
            },
        ]).expect("append_group");

        append(bucket, &mac_key, WalEntry::Remove {
            key: "/legacy-2.txt".to_string(),
        }).expect("append legacy-2");

        let loaded = load(bucket, &mac_key).expect("load");
        assert_eq!(loaded.len(), 4, "1 legacy + 2 group + 1 legacy");
        match &loaded[0] {
            WalEntry::Insert { key, .. } => assert_eq!(key, "/legacy-1.txt"),
            other => panic!("expected legacy Insert first, got {:?}", other),
        }
        match &loaded[1] {
            WalEntry::Remove { key } => assert_eq!(key, "/grp/a.txt"),
            other => panic!("expected group Remove second, got {:?}", other),
        }
        match &loaded[2] {
            WalEntry::Insert { key, .. } => assert_eq!(key, "/grp/b.txt"),
            other => panic!("expected group Insert third, got {:?}", other),
        }
        match &loaded[3] {
            WalEntry::Remove { key } => assert_eq!(key, "/legacy-2.txt"),
            other => panic!("expected legacy Remove last, got {:?}", other),
        }
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

