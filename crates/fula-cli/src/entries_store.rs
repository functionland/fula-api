//! Per-user encrypted-bucketsIndex entry store.
//!
//! Persists, for each Mode B/C user, the latest signed entry that
//! points at their encrypted bucketsIndex CID:
//! `(user_key → { entry_pubkey, last_cid, last_seq, last_sig,
//!   highest_seq_ever_accepted, updated_at_unix })`.
//!
//! Lifetime: master accepts new entries via
//! [`PUT /api/v1/users-index/entry`], persists them here, and consults
//! this store both for the master HTTP `/per-user/latest` fast-path and
//! for the global users-index publisher's `users_enc` map (Phase 3).
//!
//! TOFU binding: the `entry_pubkey` is recorded on the first successful
//! submission for a given `user_key`. Subsequent submissions must be
//! signed by the same key (the handler verifies via
//! [`fula_crypto::verify_entry_signature`]). Admin can reset the
//! binding for legitimate recovery (lost seed → new identity) via a
//! separate `SYSTEM_KEY`-gated endpoint.
//!
//! Persistence: a single JSON file with atomic-rename writes. The
//! footprint is small (a few hundred bytes per user); even at 10⁶ users
//! the file is ~200 MB which is acceptable for in-memory load on
//! startup. If this becomes a bottleneck, swap the backend for redb
//! without changing the public API.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

/// One user's most recent signed entry — the unit the global CBOR
/// publisher copies into the `users_enc` map.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EntryRecord {
    /// 32-byte Ed25519 public key, hex-encoded. TOFU-bound on first
    /// publish; subsequent publishes must be signed by the matching
    /// private key.
    pub entry_pubkey_hex: String,
    /// Latest signed CID (dag-cbor base32 string of the encrypted
    /// bucketsIndex envelope).
    pub cid: String,
    /// Latest accepted sequence (monotonic per user).
    pub sequence: u64,
    /// Latest accepted signature (64-byte Ed25519, hex-encoded).
    pub signature_hex: String,
    /// Envelope format version this signature was bound to (matches
    /// the `envelope_v` baked into the AAD).
    pub envelope_version: u32,
    /// Wall-clock timestamp of the latest accepted publish.
    pub updated_at_unix: u64,
    /// Monotonicity guard — never decreases, even if a future API
    /// allows "rewriting history." Defends against replay attacks
    /// where a leaked older record is resubmitted to roll the user's
    /// view back.
    pub highest_seq_ever_accepted: u64,
}

/// On-disk wire format. Top-level is a flat map `user_key_hex →
/// EntryRecord`. Versioned so we can evolve the shape later.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct StoreFile {
    /// File schema version. v=1 is the current shape.
    v: u32,
    entries: HashMap<String, EntryRecord>,
}

impl Default for StoreFile {
    fn default() -> Self {
        Self {
            v: 1,
            entries: HashMap::new(),
        }
    }
}

/// In-memory + file-backed store of per-user entries.
///
/// Cloning is cheap (it's behind an `Arc<RwLock<...>>` internally).
#[derive(Clone)]
pub struct EntriesStore {
    inner: Arc<EntriesStoreInner>,
}

struct EntriesStoreInner {
    path: Option<PathBuf>,
    state: RwLock<HashMap<String, EntryRecord>>,
}

impl EntriesStore {
    /// Open or create an entries store at the given path. If `path` is
    /// `None`, runs purely in-memory (test mode / dev configs).
    ///
    /// Errors only when the file exists but cannot be parsed. A
    /// missing file is treated as "empty store" — not an error — so a
    /// first-ever boot just starts with no entries.
    pub fn open(path: Option<PathBuf>) -> anyhow::Result<Self> {
        let state = if let Some(ref p) = path {
            match std::fs::read_to_string(p) {
                Ok(contents) => {
                    let file: StoreFile = serde_json::from_str(&contents).map_err(|e| {
                        anyhow::anyhow!(
                            "failed to parse entries store at {}: {}",
                            p.display(),
                            e
                        )
                    })?;
                    if file.v != 1 {
                        return Err(anyhow::anyhow!(
                            "entries store at {} has unsupported schema version {} (expected 1)",
                            p.display(),
                            file.v,
                        ));
                    }
                    info!(
                        path = %p.display(),
                        entries = file.entries.len(),
                        "entries store loaded"
                    );
                    file.entries
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    info!(path = %p.display(), "entries store: fresh start (no file yet)");
                    HashMap::new()
                }
                Err(e) => {
                    return Err(anyhow::anyhow!(
                        "failed to read entries store at {}: {}",
                        p.display(),
                        e
                    ));
                }
            }
        } else {
            warn!("entries store: running in-memory only (no path configured)");
            HashMap::new()
        };

        Ok(Self {
            inner: Arc::new(EntriesStoreInner {
                path,
                state: RwLock::new(state),
            }),
        })
    }

    /// Look up a user's latest entry by their hashed user_key (lowercase
    /// 32-char hex).
    pub fn get(&self, user_key_hex: &str) -> Option<EntryRecord> {
        self.inner.state.read().get(user_key_hex).cloned()
    }

    /// Highest sequence master has ever accepted for this user. Returns
    /// 0 if the user has no entry. Used by the client's
    /// sequence-recovery path after storage clear (`GET /per-user/latest`
    /// also returns this so a fresh client can compute the next
    /// `sequence` to sign).
    pub fn highest_seq(&self, user_key_hex: &str) -> u64 {
        self.inner
            .state
            .read()
            .get(user_key_hex)
            .map(|r| r.highest_seq_ever_accepted)
            .unwrap_or(0)
    }

    /// Submit a new entry. Returns an outcome describing whether it
    /// was accepted, and on rejection, why.
    ///
    /// Backward compatibility note: this NEVER touches existing
    /// per-user data (BucketManager / forest manifests / file objects).
    /// The store only holds the new signed-entry pointer; existing
    /// users without an entry continue to use the legacy `users[]`
    /// plaintext path in the global CBOR (handled by the publisher in
    /// Phase 3).
    pub fn try_submit(&self, user_key_hex: &str, candidate: EntryRecord) -> SubmitOutcome {
        let mut state = self.inner.state.write();
        if let Some(existing) = state.get(user_key_hex) {
            // TOFU: pubkey must match the bound one.
            if existing.entry_pubkey_hex != candidate.entry_pubkey_hex {
                return SubmitOutcome::PubkeyMismatch {
                    bound: existing.entry_pubkey_hex.clone(),
                };
            }
            // Sequence monotonicity (Layer 3 of multi-device sync).
            if candidate.sequence <= existing.highest_seq_ever_accepted {
                return SubmitOutcome::StaleSequence {
                    current: existing.highest_seq_ever_accepted,
                };
            }
            // Accept; preserve the historical-max sequence.
            let mut new_record = candidate;
            new_record.highest_seq_ever_accepted = new_record
                .sequence
                .max(existing.highest_seq_ever_accepted);
            state.insert(user_key_hex.to_string(), new_record);
            drop(state);
            self.persist();
            SubmitOutcome::Accepted
        } else {
            // First-ever submission for this user_key → record the
            // TOFU binding. The pubkey is locked from here on.
            let mut new_record = candidate;
            new_record.highest_seq_ever_accepted = new_record.sequence;
            state.insert(user_key_hex.to_string(), new_record);
            drop(state);
            self.persist();
            SubmitOutcome::Accepted
        }
    }

    /// Administrative reset of a user's TOFU binding (lost-seed
    /// recovery flow). Drops the entire EntryRecord — the next submit
    /// from that user_key starts fresh and rebinds to whatever pubkey
    /// signs the first new entry. Logged at INFO so operators have an
    /// audit trail.
    pub fn admin_reset(&self, user_key_hex: &str) -> bool {
        let mut state = self.inner.state.write();
        let removed = state.remove(user_key_hex).is_some();
        drop(state);
        if removed {
            info!(user_key = user_key_hex, "TOFU binding reset by admin");
            self.persist();
        }
        removed
    }

    /// Snapshot all entries for the global CBOR publisher (Phase 3
    /// consumer). Cheap clone of the inner map; iteration is over the
    /// snapshot, not the live RwLock.
    pub fn snapshot_all(&self) -> HashMap<String, EntryRecord> {
        self.inner.state.read().clone()
    }

    /// Number of entries currently bound. Useful for metrics +
    /// startup logging.
    pub fn len(&self) -> usize {
        self.inner.state.read().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Write the current state to disk via atomic rename. No-op when
    /// no path is configured (in-memory mode).
    ///
    /// Failure is logged at WARN but not returned — the in-memory
    /// state is still authoritative for the running process; a write
    /// failure means we lose the update on restart, not now. Phase 2
    /// keeps this simple; if it becomes a problem we'll add fsync +
    /// stronger error surfaces.
    fn persist(&self) {
        let Some(ref path) = self.inner.path else {
            debug!("entries store persist skipped (in-memory mode)");
            return;
        };
        let file = StoreFile {
            v: 1,
            entries: self.inner.state.read().clone(),
        };
        let payload = match serde_json::to_string_pretty(&file) {
            Ok(s) => s,
            Err(e) => {
                warn!(error = %e, "failed to serialize entries store");
                return;
            }
        };
        // Atomic rename: write to a sibling temp file, then rename
        // over the target.
        let tmp = path.with_extension("tmp");
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                if let Err(e) = std::fs::create_dir_all(parent) {
                    warn!(error = %e, path = %parent.display(), "failed to create entries store parent dir");
                    return;
                }
            }
        }
        if let Err(e) = std::fs::write(&tmp, payload.as_bytes()) {
            warn!(error = %e, "failed to write entries store temp file");
            return;
        }
        if let Err(e) = std::fs::rename(&tmp, path) {
            warn!(error = %e, "failed to atomic-rename entries store");
        }
    }
}

/// Outcome of [`EntriesStore::try_submit`]. The handler maps these to
/// HTTP status codes.
#[derive(Debug, PartialEq, Eq)]
pub enum SubmitOutcome {
    /// Entry accepted and persisted.
    Accepted,
    /// TOFU binding already exists with a different pubkey — reject.
    /// `bound` is the hex of the currently-bound pubkey (returned to
    /// the caller for diagnostics).
    PubkeyMismatch { bound: String },
    /// Sequence is not strictly greater than the highest ever
    /// accepted — caller probably has a stale view; refetch and retry.
    /// `current` is the highest seq master has on record.
    StaleSequence { current: u64 },
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn sample_record(seq: u64, pk_hex: &str) -> EntryRecord {
        EntryRecord {
            entry_pubkey_hex: pk_hex.to_string(),
            cid: format!("bafyrei{:040}cid", seq),
            sequence: seq,
            signature_hex: format!("{:0128}", seq),
            envelope_version: 3,
            updated_at_unix: 1_700_000_000 + seq,
            highest_seq_ever_accepted: seq,
        }
    }

    const PK_A: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    const PK_B: &str = "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100";
    const USER_A: &str = "0123456789abcdef0123456789abcdef";

    #[test]
    fn in_memory_open_starts_empty() {
        let store = EntriesStore::open(None).unwrap();
        assert!(store.is_empty());
        assert!(store.get(USER_A).is_none());
        assert_eq!(store.highest_seq(USER_A), 0);
    }

    #[test]
    fn first_submit_records_tofu_binding() {
        let store = EntriesStore::open(None).unwrap();
        assert_eq!(
            store.try_submit(USER_A, sample_record(1, PK_A)),
            SubmitOutcome::Accepted,
        );
        let r = store.get(USER_A).unwrap();
        assert_eq!(r.entry_pubkey_hex, PK_A);
        assert_eq!(r.sequence, 1);
        assert_eq!(r.highest_seq_ever_accepted, 1);
    }

    #[test]
    fn second_submit_with_same_pubkey_advances_sequence() {
        let store = EntriesStore::open(None).unwrap();
        store.try_submit(USER_A, sample_record(1, PK_A));
        assert_eq!(
            store.try_submit(USER_A, sample_record(2, PK_A)),
            SubmitOutcome::Accepted,
        );
        assert_eq!(store.get(USER_A).unwrap().sequence, 2);
        assert_eq!(store.highest_seq(USER_A), 2);
    }

    #[test]
    fn submit_with_different_pubkey_rejected() {
        let store = EntriesStore::open(None).unwrap();
        store.try_submit(USER_A, sample_record(1, PK_A));
        let outcome = store.try_submit(USER_A, sample_record(2, PK_B));
        assert_eq!(
            outcome,
            SubmitOutcome::PubkeyMismatch {
                bound: PK_A.to_string()
            },
        );
        // Original record unchanged.
        assert_eq!(store.get(USER_A).unwrap().entry_pubkey_hex, PK_A);
        assert_eq!(store.get(USER_A).unwrap().sequence, 1);
    }

    #[test]
    fn stale_sequence_rejected() {
        let store = EntriesStore::open(None).unwrap();
        store.try_submit(USER_A, sample_record(5, PK_A));
        let outcome = store.try_submit(USER_A, sample_record(5, PK_A));
        assert_eq!(outcome, SubmitOutcome::StaleSequence { current: 5 });
        let outcome = store.try_submit(USER_A, sample_record(3, PK_A));
        assert_eq!(outcome, SubmitOutcome::StaleSequence { current: 5 });
    }

    #[test]
    fn admin_reset_drops_binding() {
        let store = EntriesStore::open(None).unwrap();
        store.try_submit(USER_A, sample_record(1, PK_A));
        assert!(store.admin_reset(USER_A));
        assert!(store.get(USER_A).is_none());
        // Different pubkey accepted after reset.
        assert_eq!(
            store.try_submit(USER_A, sample_record(1, PK_B)),
            SubmitOutcome::Accepted,
        );
        assert_eq!(store.get(USER_A).unwrap().entry_pubkey_hex, PK_B);
    }

    #[test]
    fn admin_reset_returns_false_when_no_binding() {
        let store = EntriesStore::open(None).unwrap();
        assert!(!store.admin_reset(USER_A));
    }

    #[test]
    fn snapshot_returns_all_entries() {
        let store = EntriesStore::open(None).unwrap();
        store.try_submit(USER_A, sample_record(1, PK_A));
        let other = "fedcba9876543210fedcba9876543210";
        store.try_submit(other, sample_record(2, PK_B));
        let snap = store.snapshot_all();
        assert_eq!(snap.len(), 2);
        assert_eq!(snap.get(USER_A).unwrap().sequence, 1);
        assert_eq!(snap.get(other).unwrap().sequence, 2);
    }

    /// Critical backward-compat property: the store NEVER modifies
    /// existing per-user data; it only adds new state for users who
    /// have opted into Mode B/C's signed-entry path. A legacy user
    /// without an entry simply doesn't appear here, and the publisher
    /// will fall back to their plaintext `users[]` entry (Phase 3).
    #[test]
    fn missing_user_returns_none_not_error() {
        let store = EntriesStore::open(None).unwrap();
        assert!(store.get("nonexistent_user").is_none());
        assert_eq!(store.highest_seq("nonexistent_user"), 0);
        // Snapshot is empty, NOT a sentinel "default" entry.
        assert!(store.snapshot_all().is_empty());
    }

    #[test]
    fn file_persistence_round_trip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("entries.json");

        // Write.
        {
            let store = EntriesStore::open(Some(path.clone())).unwrap();
            store.try_submit(USER_A, sample_record(7, PK_A));
        }

        // Re-open; state survives.
        let reopened = EntriesStore::open(Some(path.clone())).unwrap();
        let r = reopened.get(USER_A).unwrap();
        assert_eq!(r.sequence, 7);
        assert_eq!(r.entry_pubkey_hex, PK_A);
    }

    #[test]
    fn file_persistence_handles_missing_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("does_not_exist_yet.json");
        let store = EntriesStore::open(Some(path)).unwrap();
        assert!(store.is_empty());
    }

    #[test]
    fn file_persistence_rejects_unknown_schema_version() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("entries.json");
        std::fs::write(
            &path,
            r#"{"v": 999, "entries": {}}"#,
        )
        .unwrap();
        let result = EntriesStore::open(Some(path));
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("expected open to reject unknown schema version"),
        };
        assert!(err.to_string().contains("unsupported schema version"));
    }

    #[test]
    fn file_persistence_atomic_rename_does_not_corrupt() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("entries.json");
        let store = EntriesStore::open(Some(path.clone())).unwrap();
        // Many sequential submits — each persists. Final state must be
        // a complete, parseable file.
        for s in 1..=20 {
            store.try_submit(USER_A, sample_record(s, PK_A));
        }
        let reopened = EntriesStore::open(Some(path)).unwrap();
        assert_eq!(reopened.get(USER_A).unwrap().sequence, 20);
        assert_eq!(reopened.highest_seq(USER_A), 20);
    }
}
