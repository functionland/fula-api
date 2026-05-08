//! Phase 3.2 master-side users-index publisher.
//!
//! Builds a global users-index CBOR mapping every active user's
//! `userKey` (= `hashed_user_id`) to that user's per-user
//! `bucketsIndex` CID, pins it via the existing pinning chain
//! (cluster), and publishes the new CID via IPNS for SDK clients to
//! resolve during master-down cold-starts.
//!
//! This module owns three responsibilities:
//!
//! 1. **State persistence** (this file, A1) — a tiny 3-line text file
//!    that survives master restarts: `(latest_global_cid, sequence,
//!    updated_at_unix)`. Crash safety mirrored from
//!    `BucketManager::persist_registry_internal` (atomic write +
//!    `.bak` backup). Sequence is monotonic; it only increments.
//!
//! 2. **Tick logic** (A2 — coming next) — snapshot
//!    `BucketManager.buckets`, build per-user bucketsIndex CBORs
//!    only for users whose state changed since the last tick (diff
//!    cache), build the global users-index CBOR, pin both via cluster.
//!
//! 3. **IPNS publish + internal endpoints** (A3 — after A2) — call
//!    kubo `/api/v0/name/publish`; expose `GET /_internal/users-index-state`
//!    for the daily chain cron in `mainnet-reward-server`.
//!
//! Background-task lifecycle mirrors `handlers::locks::start_sweeper`:
//! one `tokio::spawn` from `server::run_server` after `AppState` is
//! wrapped in `Arc`. The task lives for the process lifetime.

// `dead_code` is permitted for module-level helpers that are exercised
// only in tests (e.g. `ipns_api_url_for_test`) or that are reserved for
// the planned Phase 3.3 SDK-side caller (e.g. structured config getters).
// Production paths (`run_tick`, `start_publisher_loop`, internal HTTP
// handlers) DO consume every field; this allow simply silences the
// warning chatter on the test-only accessors.
#![allow(dead_code)]

use anyhow::Result as AnyResult;
use cid::Cid;
use fula_blockstore::{BlockStore, PinStore};
use fula_core::{metadata::BucketMetadata, BucketManager};
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{info, warn};

/// State that persists across master restarts. Single source of truth
/// for "what did we last successfully publish?". Written **after** a
/// successful pin + IPNS publish. Read on startup.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PersistedState {
    /// CID of the most recently pinned global users-index CBOR.
    /// `None` = nothing has been published yet (fresh master).
    pub global_cid: Option<Cid>,
    /// Monotonic sequence number embedded in the most recent global
    /// users-index CBOR's payload. Always increments. SDK clients
    /// reject responses with a regression as a replay defense.
    pub sequence: u64,
    /// Wall-clock seconds-since-epoch when the most recent publish
    /// committed. Used for diagnostics and for the
    /// `/_internal/users-index-state` HTTP response.
    pub updated_at_unix: u64,
}

impl Default for PersistedState {
    fn default() -> Self {
        Self {
            global_cid: None,
            sequence: 0,
            updated_at_unix: 0,
        }
    }
}

impl PersistedState {
    /// Load state from `path`. Returns `Ok(default)` if the file
    /// doesn't exist (fresh master). Returns an error on any other
    /// I/O failure or parse problem — the caller surfaces this so
    /// the operator can fix it (e.g., truncated file from a
    /// half-completed write).
    ///
    /// Format: 3 lines separated by `\n`:
    ///   line 1 = CID string (or empty for `None`)
    ///   line 2 = sequence (u64 decimal)
    ///   line 3 = updated_at_unix (u64 decimal); optional — older
    ///            two-line files parse to `updated_at_unix = 0`
    pub fn load(path: &Path) -> Result<Self, PersistError> {
        let raw = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::default());
            }
            Err(e) => return Err(PersistError::Io(e)),
        };
        Self::parse(&raw)
    }

    fn parse(raw: &str) -> Result<Self, PersistError> {
        let mut lines = raw.lines();
        let cid_line = lines.next().unwrap_or("").trim();
        let seq_line = lines.next().unwrap_or("").trim();
        let ts_line = lines.next().unwrap_or("").trim();

        let global_cid = if cid_line.is_empty() {
            None
        } else {
            Some(cid_line.parse::<Cid>().map_err(|e| {
                PersistError::Parse(format!("invalid CID '{}': {}", cid_line, e))
            })?)
        };

        let sequence: u64 = if seq_line.is_empty() {
            0
        } else {
            seq_line.parse().map_err(|e| {
                PersistError::Parse(format!("invalid sequence '{}': {}", seq_line, e))
            })?
        };

        let updated_at_unix: u64 = if ts_line.is_empty() {
            0
        } else {
            ts_line.parse().map_err(|e| {
                PersistError::Parse(format!("invalid updated_at '{}': {}", ts_line, e))
            })?
        };

        Ok(Self {
            global_cid,
            sequence,
            updated_at_unix,
        })
    }

    fn serialize(&self) -> String {
        format!(
            "{}\n{}\n{}\n",
            self.global_cid.map_or(String::new(), |c| c.to_string()),
            self.sequence,
            self.updated_at_unix
        )
    }

    /// Atomically write to `path`. If `path` already exists, copy it
    /// to `path.bak` first (mirrors `BucketManager::persist_registry_internal`'s
    /// backup pattern). Tolerates missing parent directory by creating
    /// it; tolerates missing existing file by skipping the backup.
    pub fn save(&self, path: &Path) -> Result<(), PersistError> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(PersistError::Io)?;
            }
        }

        // Backup the previous state file before overwriting. This
        // mirrors the fula-bucket-registry persistence pattern; if a
        // crash interrupts the write, the operator can recover from
        // the .bak.
        if path.exists() {
            let backup_path = with_bak_suffix(path);
            // Best-effort backup; failure to back up should not block
            // the main write (we'd rather lose the .bak than the
            // primary). Surfaces only as a tracing log.
            if let Err(e) = std::fs::copy(path, &backup_path) {
                tracing::warn!(
                    error = %e,
                    backup_path = %backup_path.display(),
                    "users-index state-file backup failed; continuing with primary write"
                );
            }
        }

        // Atomic rename: write to a tmp sibling then rename onto the
        // target. On most filesystems this is atomic; on Windows it
        // requires the destination to be removable, which our
        // backup-first step makes safe.
        let tmp_path = path.with_extension("tmp");
        std::fs::write(&tmp_path, self.serialize()).map_err(PersistError::Io)?;
        std::fs::rename(&tmp_path, path).map_err(PersistError::Io)?;
        Ok(())
    }

    /// Compose the next state from a successful publish:
    /// increment sequence, set new CID, refresh timestamp.
    pub fn next(&self, new_cid: Cid) -> Self {
        Self {
            global_cid: Some(new_cid),
            sequence: self.sequence.saturating_add(1),
            updated_at_unix: now_unix(),
        }
    }
}

fn with_bak_suffix(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".bak");
    PathBuf::from(s)
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[derive(Debug, thiserror::Error)]
pub enum PersistError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("parse error: {0}")]
    Parse(String),
}

// ============================================================
// CBOR data structures (Phase 3.2.a)
// ============================================================

/// Per-user `bucketsIndex` CBOR. Pinned per user; one CBOR per user
/// per snapshot if their state changed. Map keys are either:
///   - 32-hex BLAKE3-derived `bucketLookupH` (Phase 1.2 blinded form)
///   - plaintext bucket name (Phase 1.2 lazy-migration legacy form)
/// `legacy=true` distinguishes the latter so SDK cold-start can
/// dispatch correctly.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserBucketsIndex {
    pub v: u32,
    /// `BTreeMap` for **deterministic** key ordering — same input
    /// must produce byte-identical CBOR (and thus the same CID)
    /// across master restarts and across hosts. dag-cbor sorts map
    /// keys but using BTreeMap upstream is belt-and-suspenders.
    pub buckets: BTreeMap<String, BucketEntry>,
    pub updated_at_unix: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BucketEntry {
    /// **MASTER's bucket Prolly Tree root CID** (`BucketMetadata.root_cid`)
    /// stringified. This is master's S3-listing index, NOT the SDK's
    /// encrypted forest manifest. Kept for forward compatibility (any
    /// future operator tooling that wants to walk master's tree from
    /// the published CBOR can still find the root here) and as a
    /// fallback for v0.4.4-pre SDKs that only know to read this field.
    /// String form (not IPLD link) so the CBOR's recursive-pin walk
    /// doesn't try to traverse it.
    pub manifest: String,
    /// **v0.4.4** — CID of the SDK's encrypted forest manifest object
    /// (`EncryptedShardManifestV7` JSON envelope) for this bucket.
    /// THIS is what v0.4.4+ SDKs read on cold-start to find the
    /// encrypted forest. Distinct from `manifest` above (master's
    /// CBOR Prolly Tree).
    ///
    /// `None` when master has not yet observed a v0.4.4+ SDK PUT
    /// carrying the `x-amz-meta-fula-forest-manifest` sentinel for
    /// this bucket. SDK falls back to `manifest` in that case (which
    /// is broken for cold-start but no worse than v0.4.3-and-prior).
    /// `#[serde(default, skip_serializing_if = "Option::is_none")]`
    /// preserves CBOR-shape compatibility with pre-v0.4.4 readers
    /// that don't know this field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forest_manifest_cid: Option<String>,
    /// `true` ⇔ map key is plaintext `bucket_name` (Phase 1.2 hadn't
    /// run for this bucket yet — i.e., user hasn't uploaded with a
    /// Phase-1.2-aware client since the field was introduced). SDK
    /// lookup falls through from blinded-key to legacy-name on miss.
    pub legacy: bool,
}

/// Global users-index CBOR. Master pins one per snapshot; the CID
/// is published via IPNS (every flush) and to the chain anchor
/// (every 12h).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GlobalUsersIndex {
    pub v: u32,
    /// Monotonic publisher sequence. Replay defense: SDK persists
    /// `highest_seen_sequence`; rejects payloads with regression.
    pub sequence: u64,
    pub updated_at_unix: u64,
    /// `userKey_hex` (32 hex chars = 16-byte hashed_user_id) →
    /// per-user bucketsIndex CID (string). BTreeMap for determinism.
    pub users: BTreeMap<String, String>,
}

// ============================================================
// Per-user diff cache
// ============================================================

/// One row of the publisher's diff cache. The publisher uses
/// `content_hash` to detect "this user's bucket set changed since
/// the last tick" without re-pinning a brand-new CBOR every time.
///
/// `content_hash` is BLAKE3 over a deterministic encoding of the
/// user's complete bucket set — see [`compute_user_content_hash`].
/// Changing any bucket's name, root_cid, or bucket_lookup_h
/// triggers a rebuild on the next tick.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PerUserDiffEntry {
    pub content_hash: [u8; 32],
    pub buckets_index_cid: Cid,
}

/// Build a per-user `bucketsIndex` CBOR from that user's full
/// bucket list. Pure — no I/O. The caller pins the resulting CBOR
/// via `BlockStore::put_ipld` + `PinStore::pin_with_token`.
pub fn build_user_buckets_index(
    buckets: &[BucketMetadata],
    now_unix: u64,
) -> UserBucketsIndex {
    let mut entries: BTreeMap<String, BucketEntry> = BTreeMap::new();
    for b in buckets {
        let (key, legacy) = match b.bucket_lookup_h {
            Some(h) => (hex::encode(h), false),
            None => (b.name.clone(), true),
        };
        entries.insert(
            key,
            BucketEntry {
                manifest: b.root_cid.to_string(),
                // v0.4.4: emit the SDK's encrypted forest manifest CID
                // when master has it populated. Treat empty-string-stored
                // values as None too (defensive against any serializer
                // that round-trips Some("") for an unset field).
                forest_manifest_cid: b
                    .forest_manifest_cid
                    .as_ref()
                    .filter(|s| !s.is_empty())
                    .cloned(),
                legacy,
            },
        );
    }
    UserBucketsIndex {
        v: 2,
        buckets: entries,
        updated_at_unix: now_unix,
    }
}

/// Build the global users-index CBOR from a per-user CID map.
/// `entries` is `userKey_hex (32 hex) → bucketsIndexCid`.
pub fn build_global_users_index(
    entries: &BTreeMap<String, Cid>,
    sequence: u64,
    now_unix: u64,
) -> GlobalUsersIndex {
    let users: BTreeMap<String, String> = entries
        .iter()
        .map(|(uk, cid)| (uk.clone(), cid.to_string()))
        .collect();
    GlobalUsersIndex {
        v: 1,
        sequence,
        updated_at_unix: now_unix,
        users,
    }
}

/// Compute a deterministic content hash over a user's full bucket
/// set. Used for diff-cache lookups: if this hash matches the
/// cached value, skip rebuilding+re-pinning the per-user CBOR.
///
/// Encoding: each bucket contributes the byte-concatenation of
/// `name_bytes || 0x00 || root_cid_bytes || 0x00 || lookup_h_bytes_or_marker`.
/// Buckets are sorted by `name` first (BLAKE3 is itself
/// order-sensitive). Domain separator at the start defends against
/// cross-namespace collisions.
pub(crate) fn compute_user_content_hash(buckets: &[BucketMetadata]) -> [u8; 32] {
    let mut sorted: Vec<&BucketMetadata> = buckets.iter().collect();
    sorted.sort_by(|a, b| a.name.cmp(&b.name));

    // v2: domain bumped to include `forest_manifest_cid` (v0.4.4). Without
    // this, master populating a fresh forest_manifest_cid on a bucket
    // whose other fields didn't change would not advance the diff hash —
    // the publisher would think "this user is unchanged, reuse the
    // cached per-user CID" and the new value would never get emitted in
    // the published CBOR. Bumping the domain forces a full re-pin of every
    // user's per-user CBOR on the first tick after upgrade; subsequent
    // ticks revert to differential pinning.
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"fula:users-index-publisher:user-content-hash:v2");
    for b in &sorted {
        hasher.update(b.name.as_bytes());
        hasher.update(&[0u8]);
        hasher.update(&b.root_cid.to_bytes());
        hasher.update(&[0u8]);
        match b.bucket_lookup_h {
            Some(h) => {
                hasher.update(b"H");
                hasher.update(&h);
            }
            None => {
                hasher.update(b"N");
            }
        }
        hasher.update(&[0u8]);
        // v0.4.4: include forest_manifest_cid in the diff hash. None and
        // empty-string both encode as "N" so the defensive parsing in
        // BucketEntry::cold_start_cid stays consistent with what the diff
        // cache treats as "no fresh forest manifest yet".
        match b.forest_manifest_cid.as_deref() {
            Some(s) if !s.is_empty() => {
                hasher.update(b"F");
                hasher.update(s.as_bytes());
            }
            _ => {
                hasher.update(b"N");
            }
        }
        hasher.update(&[0u8]);
    }
    let h = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(h.as_bytes());
    out
}

// ============================================================
// Publisher configuration
// ============================================================

#[derive(Clone, Debug)]
pub struct PublisherConfig {
    /// How often the publisher tick fires when there are changes.
    /// Default 5 min — matches the user-facing latency expectation
    /// for cross-device-fresh-data when using the IPNS path.
    pub flush_interval: Duration,
    /// Cap on the per-user pin operations the first tick fires per
    /// second. The first tick after deploy has to pin every user's
    /// bucketsIndex CBOR (cache is empty), so for large user sets
    /// this can be tens of thousands of pin requests. Throttle to
    /// avoid swamping the pinning-service.
    pub first_publish_max_pins_per_sec: u32,
    /// IPNS record lifetime. 36h gives a 24h margin over the 12h
    /// chain-cron cadence — see plan section 3.2.b.
    pub ipns_lifetime: Duration,
    /// IPNS DHT cache TTL hint for resolvers. 15min keeps the SDK's
    /// IPNS lookup latency low without aggressive re-fetch.
    pub ipns_ttl: Duration,
    /// Kubo IPNS key NAME (kubo's local label, e.g.,
    /// `fula-users-index`). Distinct from the IPNS NAME (libp2p
    /// public-key hash) that clients use. See plan 3.2.b.
    pub ipns_key_name: String,
    /// Path to the persisted `(global_cid, sequence, updated_at)`
    /// state file. Mirrors the `registry_cid_path` pattern.
    pub state_file_path: PathBuf,
    /// Kubo HTTP API URL (e.g., `http://localhost:5001`). Used for
    /// `/api/v0/name/publish`.
    pub ipfs_api_url: String,
    /// Internal-endpoint shared-secret token. Disabled (returns 503)
    /// if not set. Required in production.
    pub internal_token: Option<String>,
}

impl PublisherConfig {
    pub fn default_for(state_file_path: PathBuf, ipfs_api_url: String) -> Self {
        Self {
            flush_interval: Duration::from_secs(300),
            first_publish_max_pins_per_sec: 100,
            ipns_lifetime: Duration::from_secs(36 * 3600),
            ipns_ttl: Duration::from_secs(15 * 60),
            ipns_key_name: "fula-users-index".to_string(),
            state_file_path,
            ipfs_api_url,
            internal_token: None,
        }
    }
}

// ============================================================
// In-memory latest-published view (read by /_internal/users-index-state)
// ============================================================

/// Snapshot of the last-published state. Updated under a write lock
/// inside the publisher tick. Read by the internal HTTP endpoint
/// without blocking the publisher.
#[derive(Clone, Debug, Default)]
pub struct LatestPublished {
    pub global_cid: Option<Cid>,
    pub sequence: u64,
    pub updated_at_unix: u64,
}

impl From<&PersistedState> for LatestPublished {
    fn from(p: &PersistedState) -> Self {
        Self {
            global_cid: p.global_cid,
            sequence: p.sequence,
            updated_at_unix: p.updated_at_unix,
        }
    }
}

// ============================================================
// IPNS publisher (kubo HTTP API client)
// ============================================================

/// Kubo `/api/v0/name/publish` response body. We only care about
/// `Name` (= the IPNS NAME, libp2p key hash) for logging — clients
/// resolve via the configured IPNS NAME, not via this response.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct IpnsPublishResponse {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "Value")]
    pub value: String,
}

/// Thin client over kubo's `/api/v0/name/publish`. Plain HTTP POST,
/// no auth (kubo's API is localhost-only by default). Failures are
/// surfaced via `Result` and the caller decides what to do — for
/// the publisher tick, an IPNS failure logs at `warn!` and lets the
/// commit proceed (chain backup at 12h still works).
#[derive(Clone)]
pub struct IpnsPublisher {
    client: reqwest::Client,
    api_url: String,
}

impl IpnsPublisher {
    /// Construct a publisher targeting `api_url` (e.g.,
    /// `http://localhost:5001`). The client uses kubo's default
    /// timeout; the caller is responsible for outer timeouts if
    /// needed (advisor noted: don't add inner backoff/timeout).
    pub fn new(api_url: String) -> Self {
        Self {
            client: reqwest::Client::new(),
            api_url,
        }
    }

    /// Construct from an existing `reqwest::Client` (test hook —
    /// lets wiremock-based tests inject a client with custom timeouts
    /// if needed; production uses [`new`]).
    #[doc(hidden)]
    pub fn with_client(client: reqwest::Client, api_url: String) -> Self {
        Self { client, api_url }
    }

    /// Publish `cid` under IPNS `key_name` with the given lifetime
    /// + DHT-cache TTL.
    ///
    /// Kubo's API: `POST /api/v0/name/publish?arg=<cid>&key=<name>&lifetime=<dur>&ttl=<dur>`.
    /// Lifetime/ttl are Go duration strings (`36h`, `15m`, …).
    /// Returns the `(Name, Value)` from the response — `Name` is the
    /// IPNS NAME (libp2p public-key hash). `Value` is the path the
    /// IPNS record now resolves to (the input CID, prefixed with
    /// `/ipfs/`).
    pub async fn publish(
        &self,
        cid: &Cid,
        key_name: &str,
        lifetime: Duration,
        ttl: Duration,
    ) -> AnyResult<IpnsPublishResponse> {
        let url = format!(
            "{}/api/v0/name/publish?arg={}&key={}&lifetime={}&ttl={}",
            self.api_url.trim_end_matches('/'),
            cid,
            urlencoding::encode(key_name),
            format_go_duration(lifetime),
            format_go_duration(ttl),
        );
        let resp = self.client.post(&url).send().await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!(
                "kubo /api/v0/name/publish failed: status={}, body={}",
                status,
                body
            );
        }
        let body: IpnsPublishResponse = resp.json().await?;
        Ok(body)
    }
}

/// Format a `Duration` as a Go-style duration string accepted by
/// kubo (`<seconds>s` is universally accepted; we don't need
/// pretty-formatting). E.g., `36h` → `129600s`. Kubo accepts both.
fn format_go_duration(d: Duration) -> String {
    format!("{}s", d.as_secs())
}

// ============================================================
// Publisher skeleton
// ============================================================

/// The publisher. Generic over the block store so tests can use
/// `MemoryBlockStore` while production uses `FlexibleBlockStore`.
pub struct UsersIndexPublisher<S: BlockStore + PinStore + 'static> {
    config: PublisherConfig,
    bucket_manager: Arc<BucketManager<S>>,
    block_store: Arc<S>,
    /// Optional IPNS publisher. `None` disables IPNS — useful for
    /// tests that exercise just the pin/persist path, and for
    /// operators who want the chain-backup path only.
    ipns_publisher: Option<IpnsPublisher>,
    /// Per-user diff cache — owner_id → (content_hash, bucketsIndexCid).
    /// `Mutex` (not `RwLock`) because the tick is the only writer and
    /// the lock window is tiny (a HashMap insert).
    diff_cache: Mutex<HashMap<String, PerUserDiffEntry>>,
    /// Mirror of the on-disk state, refreshed after every successful
    /// publish. Read by the internal endpoint.
    latest: RwLock<LatestPublished>,
    /// Serializes `run_tick` invocations so a periodic firing and an
    /// admin `publish-now` call (A3) never race the rename of the state
    /// file or produce two competing `sequence` values for the same
    /// underlying state. Tokio mutex (not parking_lot) because the tick
    /// holds it across `await`s on the pin chain.
    tick_lock: tokio::sync::Mutex<()>,
}

/// Outcome of a single `run_tick` call. Useful for tests and for
/// observability counters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TickOutcome {
    /// Number of distinct users whose per-user CBOR was rebuilt and
    /// re-pinned this tick. Always equal to `total_users` on the
    /// first tick (cache is empty).
    pub changed_users: usize,
    /// Number of users whose per-user CBOR pin attempt failed this
    /// tick. Per-user failures are tolerated: the tick continues with
    /// the users that succeeded, the global is rebuilt with whatever
    /// state the diff-cache currently holds (which means failed users
    /// retain their PRIOR `bucketsIndexCid` if they had one, and are
    /// absent from the published global if they had no prior pin).
    /// Failed users are retried on the next tick because their
    /// `content_hash` still mismatches the cache row.
    ///
    /// Operators monitor this field: a sustained non-zero value
    /// across many ticks indicates a user whose data triggers a
    /// pinning-service edge case and warrants investigation. The
    /// publisher loop also emits a `warn!` line per failed user
    /// inside `run_tick` (with the user_id and full error chain) so
    /// the failing user is identifiable from logs alone.
    pub failed_users: usize,
    /// Total number of users in `BucketManager.buckets` at this tick.
    pub total_users: usize,
    /// CID of the global users-index CBOR pinned this tick.
    pub global_cid: Cid,
    /// Sequence number embedded in the global CBOR's payload.
    pub sequence: u64,
    /// `true` iff the global users-index actually changed (i.e., at
    /// least one user changed OR the cache was empty). When `false`
    /// the publisher could in principle skip the global rebuild —
    /// but for simplicity the current implementation always rebuilds
    /// the global CBOR. Field kept for future optimization.
    pub global_rebuilt: bool,
}

impl<S: BlockStore + PinStore + 'static> UsersIndexPublisher<S> {
    /// Construct from config + handles to the bucket manager and
    /// block store. Loads existing state-file on-disk; fresh master
    /// starts with `PersistedState::default()`.
    ///
    /// IPNS is enabled by default (constructed from `config.ipfs_api_url`).
    /// Tests may disable it via [`open_without_ipns`] to exercise the
    /// pin/persist path independently.
    pub fn open(
        config: PublisherConfig,
        bucket_manager: Arc<BucketManager<S>>,
        block_store: Arc<S>,
    ) -> Result<Self, PersistError> {
        let ipns_publisher = Some(IpnsPublisher::new(config.ipfs_api_url.clone()));
        Self::open_with_ipns(config, bucket_manager, block_store, ipns_publisher)
    }

    /// Construct without IPNS. Tick still pins + persists; the chain
    /// path (12h cron in `mainnet-reward-server`) still works. Useful
    /// for operators who don't want the kubo IPNS hop, and for the
    /// pin/persist-only unit tests.
    pub fn open_without_ipns(
        config: PublisherConfig,
        bucket_manager: Arc<BucketManager<S>>,
        block_store: Arc<S>,
    ) -> Result<Self, PersistError> {
        Self::open_with_ipns(config, bucket_manager, block_store, None)
    }

    /// Internal constructor — also used by tests to inject a
    /// wiremock-backed IPNS client.
    pub fn open_with_ipns(
        config: PublisherConfig,
        bucket_manager: Arc<BucketManager<S>>,
        block_store: Arc<S>,
        ipns_publisher: Option<IpnsPublisher>,
    ) -> Result<Self, PersistError> {
        let persisted = PersistedState::load(&config.state_file_path)?;
        let latest = LatestPublished::from(&persisted);
        Ok(Self {
            config,
            bucket_manager,
            block_store,
            ipns_publisher,
            diff_cache: Mutex::new(HashMap::new()),
            latest: RwLock::new(latest),
            tick_lock: tokio::sync::Mutex::new(()),
        })
    }

    /// Snapshot of the last successful publish. Cheap-clone via the
    /// underlying RwLock read guard.
    pub fn latest(&self) -> LatestPublished {
        self.latest.read().clone()
    }

    /// Read-only access to the publisher config. Used by the internal
    /// HTTP endpoints to surface `internal_token` (auth check) and
    /// `ipns_key_name` (response field).
    pub fn config(&self) -> &PublisherConfig {
        &self.config
    }

    /// Read the on-disk persisted state directly (bypasses the
    /// in-memory `latest` cache). Used by tests and by the startup
    /// chain-cross-check (see plan 3.2.b advisor note).
    pub fn read_persisted(&self) -> Result<PersistedState, PersistError> {
        PersistedState::load(&self.config.state_file_path)
    }

    /// Number of entries in the diff cache. Test-only accessor.
    #[cfg(test)]
    fn diff_cache_len(&self) -> usize {
        self.diff_cache.lock().len()
    }

    /// Atomically write the next state to disk and update the
    /// in-memory `latest` mirror. Called by `run_tick` AFTER a
    /// successful pin — the documented order is "pin → persist"
    /// (IPNS publish lands in A3, between these two). A crash
    /// between pin and persist leaks the orphan-pinned CBOR;
    /// cluster GC reaps it; on-chain `require(newSequence > sequence)`
    /// keeps sequence monotonic regardless. (Advisor note, plan 3.2.a.)
    fn commit_state(&self, next: PersistedState) -> Result<(), PersistError> {
        next.save(&self.config.state_file_path)?;
        *self.latest.write() = LatestPublished::from(&next);
        Ok(())
    }

    /// Run one publisher tick: snapshot the bucket manager, rebuild
    /// per-user CBORs only for users whose `content_hash` changed
    /// since the last tick, build the global users-index CBOR, pin
    /// both via the `PinStore` (cluster), persist the new state.
    ///
    /// IPNS publishing lands in A3 — this method does not call kubo's
    /// `name/publish`. Tests assert the pin chain and the persisted
    /// state; the IPNS step will plug in afterward without changing
    /// the contract here.
    ///
    /// **Concurrency.** `BucketManager.buckets` is a `DashMap`; we
    /// snapshot to a `Vec` in one synchronous block (no `await` while
    /// the iterator is alive — that would be a shard-guard-deadlock
    /// hazard).
    pub async fn run_tick(&self) -> AnyResult<TickOutcome> {
        // Single-tick-at-a-time. The periodic scheduler and the
        // admin `publish-now` (A3) will both invoke run_tick; this
        // ensures they never race the rename of the state file or
        // emit two competing `sequence` values from the same
        // starting state.
        let _guard = self.tick_lock.lock().await;

        // 1. Snapshot every user's full bucket set. `list_buckets`
        //    iterates the DashMap and clones each value; drops the
        //    iterator before returning, so no shard guard survives
        //    into our subsequent `await`s.
        let snapshot: Vec<BucketMetadata> = self.bucket_manager.list_buckets();

        // 2. Group by owner_id.
        let mut by_user: HashMap<String, Vec<BucketMetadata>> = HashMap::new();
        for b in snapshot {
            by_user.entry(b.owner_id.clone()).or_default().push(b);
        }
        let total_users = by_user.len();
        let now = now_unix();

        // 3. For each user: compute content_hash; if cache miss or
        //    diff, rebuild + pin per-user CBOR.
        let max_concurrent = self
            .config
            .first_publish_max_pins_per_sec
            .max(1) as usize;
        let to_rebuild: Vec<(String, Vec<BucketMetadata>)> = {
            let cache = self.diff_cache.lock();
            by_user
                .iter()
                .filter_map(|(owner_id, buckets)| {
                    let hash = compute_user_content_hash(buckets);
                    let unchanged = cache
                        .get(owner_id)
                        .map(|e| e.content_hash == hash)
                        .unwrap_or(false);
                    if unchanged {
                        None
                    } else {
                        Some((owner_id.clone(), buckets.clone()))
                    }
                })
                .collect()
            // cache guard drops here, before any `await`
        };

        // Buffer-unordered keeps at most `max_concurrent` pin ops in
        // flight at any time (advisor's first-publish throttle).
        //
        // Per-user error tolerance: each task returns
        // `(owner_id, AnyResult<(hash, cid)>)` so the outer loop can
        // identify WHICH user failed and log it. Without this, an
        // anyhow `?` in the inner closure would drop the owner_id
        // and the loop level would only see an opaque error.
        let block_store = Arc::clone(&self.block_store);
        let pin_results: Vec<(String, AnyResult<([u8; 32], Cid)>)> = {
            use futures::stream::{self, StreamExt};
            stream::iter(to_rebuild.into_iter().map(|(owner_id, buckets)| {
                let bs = Arc::clone(&block_store);
                async move {
                    let inner: AnyResult<([u8; 32], Cid)> = async {
                        let hash = compute_user_content_hash(&buckets);
                        let cbor = build_user_buckets_index(&buckets, now);
                        let cid = bs.put_ipld(&cbor).await?;
                        bs.pin(&cid, Some("fula-users-index-per-user")).await?;
                        Ok((hash, cid))
                    }
                    .await;
                    (owner_id, inner)
                }
            }))
            .buffer_unordered(max_concurrent)
            .collect()
            .await
        };

        // Per-user error tolerance: a single user's pin failure must
        // NOT abort the tick. Today's behavior (abort on first error)
        // means at scale a single corrupted user blocks every user's
        // cold-start visibility. With tolerance:
        //   - succeeded users update their diff_cache row
        //   - failed users keep their PRIOR diff_cache row (or have
        //     none if never succeeded)
        //   - global is rebuilt from the cache as it stands
        //   - failed users retry on the next tick because their
        //     `content_hash` still mismatches the (un-updated) cache row
        //
        // The `warn!` per failure carries owner_id + full anyhow chain
        // so an operator can identify the failing user and root cause
        // without combing through thread-of-execution traces.
        let mut changed_users = 0usize;
        let mut failed_users = 0usize;
        for (owner_id, r) in pin_results {
            match r {
                Ok((hash, cid)) => {
                    self.diff_cache.lock().insert(
                        owner_id,
                        PerUserDiffEntry {
                            content_hash: hash,
                            buckets_index_cid: cid,
                        },
                    );
                    changed_users += 1;
                }
                Err(e) => {
                    failed_users += 1;
                    warn!(
                        user = %owner_id,
                        error = %e,
                        "users-index publisher: per-user pin failed; user will retry on next tick"
                    );
                }
            }
        }

        // Prune diff-cache rows for users who disappeared from
        // `BucketManager` since the last tick (deleted account,
        // user deleted all their buckets, etc.). Without this, the
        // cache would grow forever AND — critically — a removed
        // user would keep appearing in published globals because
        // the early-return below would never fire a rebuild for a
        // pure-deletion tick. We track `users_pruned` to fold
        // deletions into the rebuild trigger.
        let users_pruned = {
            let mut cache = self.diff_cache.lock();
            let before = cache.len();
            cache.retain(|owner_id, _| by_user.contains_key(owner_id));
            before - cache.len()
        };

        let prior = self.latest.read().clone();

        // 4. Skip-if-no-change: every user's cache row matched AND
        //    no users were pruned AND we've already published at
        //    least once → tick is a no-op. Returning early avoids
        //    pin/unpin churn and keeps `sequence` from advancing
        //    for free, so the 12h chain cron sees the same
        //    `(cid, sequence)` and skips the on-chain publish.
        //    Including `users_pruned == 0` is load-bearing: a
        //    pure-deletion tick has `changed_users == 0` but MUST
        //    rebuild so the deleted user disappears from the
        //    published global.
        if changed_users == 0 && users_pruned == 0 && prior.global_cid.is_some() {
            return Ok(TickOutcome {
                changed_users: 0,
                // `failed_users` IS surfaced even on the no-op path —
                // operators need to see "we tried to advance state for
                // these N users this tick but couldn't" even when the
                // global itself is unchanged. Without this, repeated
                // failures on the same user would be invisible at the
                // tick-outcome layer (only via the per-user warn! line
                // inside run_tick).
                failed_users,
                total_users,
                global_cid: prior.global_cid.expect("checked is_some"),
                sequence: prior.sequence,
                global_rebuilt: false,
            });
        }

        // 5. Build the user → bucketsIndexCid map from the now-up-to-date
        //    cache. Iterating `by_user.keys()` ensures we include every
        //    user even if their cache row was already up to date.
        let mut user_to_cid: BTreeMap<String, Cid> = BTreeMap::new();
        let cache_snapshot = self.diff_cache.lock().clone();
        for owner_id in by_user.keys() {
            if let Some(entry) = cache_snapshot.get(owner_id) {
                user_to_cid.insert(owner_id.clone(), entry.buckets_index_cid);
            }
        }

        // 6. Build + pin global users-index CBOR. Sequence increments
        //    relative to the last persisted state; new state is committed
        //    only after the pin succeeds.
        let next_sequence = prior.sequence.saturating_add(1);
        let global = build_global_users_index(&user_to_cid, next_sequence, now);
        let global_cid = self.block_store.put_ipld(&global).await?;
        self.block_store
            .pin(&global_cid, Some("fula-users-index-global"))
            .await?;

        // 7. Best-effort unpin previous global. Failure is fine —
        //    cluster GC will eventually reap it.
        if let Some(prev) = prior.global_cid {
            if prev != global_cid {
                if let Err(e) = self.block_store.unpin(&prev).await {
                    tracing::debug!(
                        prev = %prev,
                        error = %e,
                        "users-index publisher: unpin previous global failed (best-effort; cluster GC will reap)"
                    );
                }
            }
        }

        // 8. IPNS publish (best-effort). Order is documented as
        //    "pin → IPNS → persist" (plan 3.2.b + advisor): an IPNS
        //    publish failure does NOT abort the commit because the
        //    chain-backup cron at 12h still works. If the publish
        //    succeeds but persist fails, the next tick republishes
        //    the same CID under sequence+1 — IPNS is idempotent on
        //    `(cid, sequence)`. If we flipped the order to
        //    persist-then-IPNS, a crash mid-IPNS would leave an
        //    advanced on-disk sequence pointing at a CID never
        //    published. Don't flip.
        if let Some(ipns) = &self.ipns_publisher {
            match ipns
                .publish(
                    &global_cid,
                    &self.config.ipns_key_name,
                    self.config.ipns_lifetime,
                    self.config.ipns_ttl,
                )
                .await
            {
                Ok(resp) => {
                    info!(
                        cid = %global_cid,
                        sequence = next_sequence,
                        ipns_name = %resp.name,
                        ipns_value = %resp.value,
                        "users-index publisher: IPNS publish succeeded"
                    );
                }
                Err(e) => {
                    warn!(
                        cid = %global_cid,
                        sequence = next_sequence,
                        error = %e,
                        "users-index publisher: IPNS publish failed (best-effort; chain backup at 12h still works; next tick will retry)"
                    );
                }
            }
        }

        // 9. Persist new state. commit_state is last so a crash mid-
        //    IPNS leaves us in a recoverable place — the next tick
        //    will retry IPNS with the same content (and on-chain
        //    sequence enforcement keeps things monotonic regardless).
        let next_state = PersistedState {
            global_cid: Some(global_cid),
            sequence: next_sequence,
            updated_at_unix: now,
        };
        self.commit_state(next_state)?;

        Ok(TickOutcome {
            changed_users,
            failed_users,
            total_users,
            global_cid,
            sequence: next_sequence,
            global_rebuilt: true,
        })
    }

    /// Test-only accessor: read the IPNS publisher's API URL.
    #[cfg(test)]
    fn ipns_api_url_for_test(&self) -> Option<String> {
        self.ipns_publisher.as_ref().map(|p| p.api_url.clone())
    }
}

/// Spawn a background task that calls `publisher.run_tick()` on
/// `flush_interval`. Mirrors `handlers::locks::start_sweeper`:
/// holds an `Arc` to the publisher, lives for the process lifetime.
///
/// `MissedTickBehavior::Delay` ensures that if a single tick takes
/// unusually long (e.g., master kubo blocked), the next tick fires
/// after a fresh `flush_interval` rather than firing back-to-back to
/// "catch up" — bursts can swamp the pinning service. The first tick
/// is gated by an immediate `interval.tick().await` at the top of
/// the loop, which fires after one interval has elapsed; if you want
/// the first tick at startup, log + call run_tick once before the
/// loop. We do NOT do that here: the operator's sequence-of-events
/// at master startup is `BucketManager.load_registry → spawn this
/// task → first tick fires after flush_interval` so the registry
/// has time to load and persist before the publisher reads from it.
pub fn start_publisher_loop<S: BlockStore + PinStore + 'static>(
    publisher: Arc<UsersIndexPublisher<S>>,
) {
    let interval_dur = publisher.config.flush_interval;
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(interval_dur);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // Skip the first tick (which fires immediately) — see fn doc.
        interval.tick().await;
        loop {
            interval.tick().await;
            match publisher.run_tick().await {
                Ok(outcome) => {
                    // Tick-level failure surfacing: when ≥ 1 user's
                    // pin failed but the tick otherwise progressed,
                    // emit a warn so the failure is visible at the
                    // loop layer (the per-user warn! inside run_tick
                    // identifies WHICH user; this one summarizes the
                    // shape so a log scraper / alerting rule can
                    // count `failed_users` per tick).
                    if outcome.failed_users > 0 {
                        warn!(
                            sequence = outcome.sequence,
                            changed_users = outcome.changed_users,
                            failed_users = outcome.failed_users,
                            total_users = outcome.total_users,
                            global_rebuilt = outcome.global_rebuilt,
                            "users-index publisher: tick had per-user pin failures; failed users will retry next tick"
                        );
                    }
                    if outcome.global_rebuilt {
                        info!(
                            sequence = outcome.sequence,
                            changed_users = outcome.changed_users,
                            failed_users = outcome.failed_users,
                            total_users = outcome.total_users,
                            cid = %outcome.global_cid,
                            "users-index publisher: tick committed new global"
                        );
                    } else {
                        tracing::debug!(
                            sequence = outcome.sequence,
                            total_users = outcome.total_users,
                            "users-index publisher: tick was no-op"
                        );
                    }
                }
                Err(e) => {
                    warn!(error = %e, "users-index publisher: tick failed; will retry on next interval");
                }
            }
        }
    });
    info!(
        interval_secs = interval_dur.as_secs(),
        "users-index publisher loop started"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use cid::multihash::Multihash;
    use fula_blockstore::MemoryBlockStore;
    use fula_core::metadata::Owner;
    use tempfile::TempDir;

    fn fixture_cid(seed: u8) -> Cid {
        let mut bytes = [0u8; 32];
        bytes[0] = seed;
        let mh = Multihash::<64>::wrap(0x1e /* blake3 */, &bytes).unwrap();
        Cid::new_v1(0x71 /* dag-cbor */, mh)
    }

    /// Build a synthetic `BucketMetadata` for the **pure** (no-IPFS)
    /// builder + content-hash tests. Uses `BucketMetadata::new` so the
    /// struct stays in sync with field additions. Real `run_tick`
    /// integration tests use `create_bucket_for_user` instead so they
    /// exercise the real DashMap insertion path.
    fn bucket_meta(
        owner_id: &str,
        name: &str,
        root_seed: u8,
        lookup_h: Option<[u8; 16]>,
    ) -> BucketMetadata {
        let mut m = BucketMetadata::new(
            name.to_string(),
            owner_id.to_string(),
            fixture_cid(root_seed),
        );
        m.bucket_lookup_h = lookup_h;
        m
    }

    /// Construct a publisher backed by `MemoryBlockStore` for tests.
    /// Returns `(publisher, store, manager)` so individual tests can
    /// poke at the manager (insert buckets etc.) and inspect the
    /// store (verify pins).
    fn fixture_publisher(
        path: PathBuf,
    ) -> (
        UsersIndexPublisher<MemoryBlockStore>,
        Arc<MemoryBlockStore>,
        Arc<BucketManager<MemoryBlockStore>>,
    ) {
        let store = Arc::new(MemoryBlockStore::new());
        let manager = Arc::new(BucketManager::new(Arc::clone(&store)));
        let publisher = UsersIndexPublisher::open(
            fixture_config(path),
            Arc::clone(&manager),
            Arc::clone(&store),
        )
        .expect("open");
        (publisher, store, manager)
    }

    // ============================================================
    // PersistedState round-trip
    // ============================================================

    #[test]
    fn test_persisted_state_default_is_empty() {
        let s = PersistedState::default();
        assert!(s.global_cid.is_none());
        assert_eq!(s.sequence, 0);
        assert_eq!(s.updated_at_unix, 0);
    }

    #[test]
    fn test_load_missing_file_returns_default() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("nonexistent.state");
        let s = PersistedState::load(&path).expect("missing file is not an error");
        assert_eq!(s, PersistedState::default());
    }

    #[test]
    fn test_save_then_load_roundtrip() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("state.txt");
        let cid = fixture_cid(0xab);
        let s = PersistedState {
            global_cid: Some(cid),
            sequence: 42,
            updated_at_unix: 1_700_000_000,
        };
        s.save(&path).expect("save");
        let loaded = PersistedState::load(&path).expect("load");
        assert_eq!(loaded, s);
    }

    #[test]
    fn test_save_creates_parent_directory() {
        // Mirrors `persist_registry_internal`'s parent-creation
        // behavior — operators may configure a path under a missing
        // directory; the publisher must not fail.
        let dir = TempDir::new().unwrap();
        let nested = dir.path().join("sub").join("dir").join("state.txt");
        let s = PersistedState::default();
        s.save(&nested).expect("save");
        assert!(nested.exists());
    }

    #[test]
    fn test_save_creates_bak_on_overwrite() {
        // Critical for crash recovery: the previous state file must
        // be backed up to .bak before being overwritten, so a half-
        // completed write doesn't lose the prior valid state.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("state.txt");
        let s1 = PersistedState {
            global_cid: Some(fixture_cid(1)),
            sequence: 1,
            updated_at_unix: 100,
        };
        s1.save(&path).expect("save 1");

        let s2 = PersistedState {
            global_cid: Some(fixture_cid(2)),
            sequence: 2,
            updated_at_unix: 200,
        };
        s2.save(&path).expect("save 2");

        let bak = with_bak_suffix(&path);
        assert!(bak.exists(), ".bak file must be created on overwrite");
        let bak_loaded = PersistedState::load(&bak).expect("load bak");
        assert_eq!(bak_loaded, s1, ".bak must hold the previous state");

        let primary_loaded = PersistedState::load(&path).expect("load primary");
        assert_eq!(primary_loaded, s2);
    }

    #[test]
    fn test_first_save_does_not_create_bak() {
        // No prior file → no .bak created. Avoids leaving a stray
        // empty file on first write.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("state.txt");
        let s = PersistedState::default();
        s.save(&path).expect("save");
        let bak = with_bak_suffix(&path);
        assert!(!bak.exists(), ".bak must NOT exist on first write");
    }

    #[test]
    fn test_parse_two_line_legacy_format() {
        // Forward-tolerant: an older two-line file (CID + sequence,
        // no timestamp) must parse with `updated_at = 0`. This isn't
        // a current production format, but the parser is permissive.
        let cid = fixture_cid(7);
        let raw = format!("{}\n5\n", cid);
        let s = PersistedState::parse(&raw).expect("parse");
        assert_eq!(s.global_cid, Some(cid));
        assert_eq!(s.sequence, 5);
        assert_eq!(s.updated_at_unix, 0);
    }

    #[test]
    fn test_parse_empty_lines_are_treated_as_missing() {
        // An empty-string CID line means "nothing published yet."
        // An empty sequence line means seq=0. Tolerates the
        // edge case where a pre-publish state file gets persisted.
        let s = PersistedState::parse("\n\n\n").expect("parse");
        assert_eq!(s, PersistedState::default());
    }

    #[test]
    fn test_parse_corrupt_cid_returns_error() {
        let raw = "not-a-cid\n0\n";
        let result = PersistedState::parse(raw);
        assert!(matches!(result, Err(PersistError::Parse(_))));
    }

    #[test]
    fn test_parse_corrupt_sequence_returns_error() {
        let cid = fixture_cid(1);
        let raw = format!("{}\nnot-a-number\n", cid);
        let result = PersistedState::parse(&raw);
        assert!(matches!(result, Err(PersistError::Parse(_))));
    }

    #[test]
    fn test_next_increments_sequence() {
        let s = PersistedState {
            global_cid: Some(fixture_cid(1)),
            sequence: 99,
            updated_at_unix: 1_700_000_000,
        };
        let next_cid = fixture_cid(2);
        let n = s.next(next_cid);
        assert_eq!(n.global_cid, Some(next_cid));
        assert_eq!(n.sequence, 100, "sequence must increment exactly once");
        assert!(
            n.updated_at_unix >= 1_700_000_000,
            "timestamp must be monotonic-or-equal"
        );
    }

    #[test]
    fn test_next_from_default_starts_at_one() {
        // First-ever publish: sequence transitions from 0 → 1.
        let initial = PersistedState::default();
        let n = initial.next(fixture_cid(0));
        assert_eq!(n.sequence, 1);
    }

    #[test]
    fn test_next_saturating_at_max() {
        // Defensive: if sequence somehow reaches u64::MAX (impossible
        // in practice but worth not panicking on), `saturating_add`
        // keeps us from overflow.
        let s = PersistedState {
            global_cid: Some(fixture_cid(1)),
            sequence: u64::MAX,
            updated_at_unix: 0,
        };
        let n = s.next(fixture_cid(2));
        assert_eq!(n.sequence, u64::MAX);
    }

    // ============================================================
    // UsersIndexPublisher::open + commit_state
    // ============================================================

    fn fixture_config(state_path: PathBuf) -> PublisherConfig {
        PublisherConfig::default_for(state_path, "http://localhost:5001".to_string())
    }

    #[test]
    fn test_open_with_empty_state_starts_fresh() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("state.txt");
        let (publisher, _store, _manager) = fixture_publisher(path);
        let latest = publisher.latest();
        assert!(latest.global_cid.is_none());
        assert_eq!(latest.sequence, 0);
    }

    #[test]
    fn test_open_with_existing_state_loads_it() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("state.txt");

        // Write existing state, then open
        let prior = PersistedState {
            global_cid: Some(fixture_cid(0xaa)),
            sequence: 17,
            updated_at_unix: 1_700_000_000,
        };
        prior.save(&path).expect("seed");

        let (publisher, _store, _manager) = fixture_publisher(path);
        let latest = publisher.latest();
        assert_eq!(latest.global_cid, Some(fixture_cid(0xaa)));
        assert_eq!(latest.sequence, 17);
        assert_eq!(latest.updated_at_unix, 1_700_000_000);
    }

    #[test]
    fn test_commit_state_updates_disk_and_memory() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("state.txt");
        let (publisher, _store, _manager) = fixture_publisher(path.clone());

        let next = PersistedState {
            global_cid: Some(fixture_cid(1)),
            sequence: 1,
            updated_at_unix: 1_700_000_001,
        };
        publisher.commit_state(next.clone()).expect("commit");

        // In-memory `latest` reflects the commit.
        let latest = publisher.latest();
        assert_eq!(latest.global_cid, next.global_cid);
        assert_eq!(latest.sequence, next.sequence);

        // On-disk file matches.
        let disk = PersistedState::load(&path).expect("reload");
        assert_eq!(disk, next);
    }

    #[test]
    fn test_commit_state_survives_subsequent_open() {
        // The crash-recovery path: master commits state, then
        // restarts. New publisher instance must see the committed
        // state.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("state.txt");

        {
            let (publisher, _store, _manager) = fixture_publisher(path.clone());
            let next = PersistedState {
                global_cid: Some(fixture_cid(0xee)),
                sequence: 12,
                updated_at_unix: 1_700_000_012,
            };
            publisher.commit_state(next).expect("commit");
            // publisher drops here, simulating master restart
        }

        let (publisher, _store, _manager) = fixture_publisher(path);
        let latest = publisher.latest();
        assert_eq!(latest.global_cid, Some(fixture_cid(0xee)));
        assert_eq!(latest.sequence, 12);
    }

    #[test]
    fn test_open_returns_error_on_corrupt_state_file() {
        // Operator must be told if the state file is corrupt rather
        // than silently starting with a default that would re-issue
        // already-used sequence numbers.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("state.txt");
        std::fs::write(&path, "not-a-cid\nnot-a-number\n").expect("seed");

        let store = Arc::new(MemoryBlockStore::new());
        let manager = Arc::new(BucketManager::new(Arc::clone(&store)));
        let result = UsersIndexPublisher::open(fixture_config(path), manager, store);
        assert!(matches!(result, Err(PersistError::Parse(_))));
    }

    // ============================================================
    // Phase 3.2 A2 — pure CBOR builders + content-hash determinism
    // ============================================================

    #[test]
    fn test_build_user_buckets_index_empty() {
        let cbor = build_user_buckets_index(&[], 1_700_000_000);
        assert_eq!(cbor.v, 2);
        assert!(cbor.buckets.is_empty());
        assert_eq!(cbor.updated_at_unix, 1_700_000_000);
    }

    #[test]
    fn test_build_user_buckets_index_legacy_only() {
        // Bucket with `bucket_lookup_h = None` → legacy plaintext key.
        let buckets = vec![bucket_meta("alice", "photos", 1, None)];
        let cbor = build_user_buckets_index(&buckets, 1_700_000_000);
        assert_eq!(cbor.buckets.len(), 1);
        let entry = cbor.buckets.get("photos").expect("photos under plaintext key");
        assert!(entry.legacy, "missing lookup_h → must be legacy");
        assert_eq!(entry.manifest, fixture_cid(1).to_string());
    }

    #[test]
    fn test_build_user_buckets_index_blinded_only() {
        let h = [0x42u8; 16];
        let buckets = vec![bucket_meta("alice", "photos", 1, Some(h))];
        let cbor = build_user_buckets_index(&buckets, 1_700_000_000);
        assert_eq!(cbor.buckets.len(), 1);
        let entry = cbor.buckets.get(&hex::encode(h)).expect("blinded key");
        assert!(!entry.legacy, "lookup_h present → must NOT be legacy");
        assert!(
            !cbor.buckets.contains_key("photos"),
            "blinded entry must not also leak under plaintext name"
        );
    }

    #[test]
    fn test_build_user_buckets_index_mixed_legacy_and_blinded() {
        // One bucket migrated, one not. Both appear in the CBOR
        // under their respective key types (Phase 1.2 lazy-
        // migration semantics).
        let h = [0xaau8; 16];
        let buckets = vec![
            bucket_meta("alice", "photos", 1, Some(h)),
            bucket_meta("alice", "tax-2024", 2, None),
        ];
        let cbor = build_user_buckets_index(&buckets, 1_700_000_000);
        assert_eq!(cbor.buckets.len(), 2);
        let blinded = cbor.buckets.get(&hex::encode(h)).expect("blinded entry");
        assert!(!blinded.legacy);
        let legacy = cbor
            .buckets
            .get("tax-2024")
            .expect("legacy entry under plaintext name");
        assert!(legacy.legacy);
    }

    #[test]
    fn test_compute_user_content_hash_is_deterministic() {
        // Same inputs in any iteration order must produce the same
        // hash. Critical: dag-cbor maps + the diff cache both rely
        // on this for determinism.
        let h = [0x11u8; 16];
        let a = vec![
            bucket_meta("alice", "photos", 1, Some(h)),
            bucket_meta("alice", "videos", 2, None),
        ];
        let b = vec![
            bucket_meta("alice", "videos", 2, None),
            bucket_meta("alice", "photos", 1, Some(h)),
        ];
        assert_eq!(compute_user_content_hash(&a), compute_user_content_hash(&b));
    }

    #[test]
    fn test_compute_user_content_hash_differs_on_root_cid_change() {
        // Same bucket name, different root_cid → different hash.
        // This is what triggers a re-pin on the next tick.
        let a = vec![bucket_meta("alice", "photos", 1, None)];
        let b = vec![bucket_meta("alice", "photos", 2, None)];
        assert_ne!(compute_user_content_hash(&a), compute_user_content_hash(&b));
    }

    #[test]
    fn test_compute_user_content_hash_differs_on_lookup_h_change() {
        // None → Some([..]) is the lazy-migration path. The
        // content_hash MUST detect this so the publisher rebuilds
        // the per-user CBOR (replacing legacy entry with blinded).
        let a = vec![bucket_meta("alice", "photos", 1, None)];
        let b = vec![bucket_meta("alice", "photos", 1, Some([0u8; 16]))];
        assert_ne!(compute_user_content_hash(&a), compute_user_content_hash(&b));
    }

    #[test]
    fn test_build_global_users_index_sorted_by_userkey() {
        // BTreeMap ordering — same input produces same byte-output
        // and same CID across master restarts/hosts.
        let mut entries: BTreeMap<String, Cid> = BTreeMap::new();
        entries.insert("zzz_user".to_string(), fixture_cid(1));
        entries.insert("aaa_user".to_string(), fixture_cid(2));
        let cbor = build_global_users_index(&entries, 5, 1_700_000_000);
        assert_eq!(cbor.v, 1);
        assert_eq!(cbor.sequence, 5);
        // First key in the BTreeMap iteration is the lex-smallest.
        let first = cbor.users.keys().next().expect("nonempty");
        assert_eq!(first, "aaa_user");
    }

    // ============================================================
    // Phase 3.2 A2 — run_tick orchestration tests
    // ============================================================
    //
    // run_tick tests use the real `create_bucket_for_user` /
    // `delete_bucket_for_user` / `populate_bucket_lookup_h` API
    // to seed `BucketManager` — no private-field reach-in. Root CIDs
    // are whatever the freshly-built forest produces; tests assert
    // *behavior* (sequence advance, pin/unpin, diff-cache state),
    // not exact CID values.

    async fn create_user_bucket<S>(
        manager: &BucketManager<S>,
        user_id: &str,
        bucket_name: &str,
    )
    where
        S: fula_blockstore::BlockStore + fula_blockstore::PinStore + 'static,
    {
        manager
            .create_bucket_for_user(
                user_id,
                bucket_name.to_string(),
                Owner::new(user_id),
            )
            .await
            .expect("create_bucket_for_user");
    }

    #[tokio::test]
    async fn test_run_tick_first_publish_pins_global_and_per_user() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("state.txt");
        let (publisher, store, manager) = fixture_publisher(path);

        // Two users, three buckets total.
        create_user_bucket(&manager, "alice", "photos").await;
        create_user_bucket(&manager, "alice", "videos").await;
        create_user_bucket(&manager, "bob", "docs").await;

        let outcome = publisher.run_tick().await.expect("tick");
        assert_eq!(outcome.total_users, 2);
        assert_eq!(outcome.changed_users, 2);
        assert!(outcome.global_rebuilt);
        assert_eq!(outcome.sequence, 1);

        // The global CBOR is pinned and retrievable.
        assert!(store.is_pinned(&outcome.global_cid).await.unwrap());

        // After the first tick, the persisted state mirrors the in-memory.
        let persisted = publisher.read_persisted().expect("read");
        assert_eq!(persisted.global_cid, Some(outcome.global_cid));
        assert_eq!(persisted.sequence, 1);

        // Decode the global CBOR and verify both users are present.
        let global_cbor: GlobalUsersIndex =
            store.get_ipld(&outcome.global_cid).await.expect("global");
        assert_eq!(global_cbor.users.len(), 2);
        assert!(global_cbor.users.contains_key("alice"));
        assert!(global_cbor.users.contains_key("bob"));
    }

    #[tokio::test]
    async fn test_run_tick_idempotent_skips_when_no_changes() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("state.txt");
        let (publisher, _store, manager) = fixture_publisher(path);

        create_user_bucket(&manager, "alice", "photos").await;
        let first = publisher.run_tick().await.expect("first");
        assert_eq!(first.sequence, 1);

        // Second tick — nothing changed in the manager.
        let second = publisher.run_tick().await.expect("second");
        assert_eq!(second.changed_users, 0);
        assert!(!second.global_rebuilt, "no-change tick must NOT rebuild");
        assert_eq!(second.sequence, 1, "sequence must NOT advance on no-op");
        assert_eq!(second.global_cid, first.global_cid);
    }

    #[tokio::test]
    async fn test_run_tick_advances_sequence_on_real_change() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("state.txt");
        let (publisher, _store, manager) = fixture_publisher(path);

        create_user_bucket(&manager, "alice", "photos").await;
        let first = publisher.run_tick().await.expect("first");

        // Add a new bucket → user content_hash changes → re-pin.
        create_user_bucket(&manager, "alice", "videos").await;
        let second = publisher.run_tick().await.expect("second");

        assert_eq!(second.changed_users, 1);
        assert_eq!(second.sequence, 2, "sequence advances by exactly 1");
        assert_ne!(second.global_cid, first.global_cid);
    }

    #[tokio::test]
    async fn test_run_tick_diff_cache_prunes_deleted_users() {
        // Pure-deletion tick: every surviving user's content_hash
        // matches cache (changed_users == 0), but the global MUST
        // still rebuild so the deleted user disappears from the
        // published map. This guards against the early-return
        // that previously fired on `changed_users == 0` alone.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("state.txt");
        let (publisher, store, manager) = fixture_publisher(path);

        create_user_bucket(&manager, "alice", "photos").await;
        create_user_bucket(&manager, "bob", "docs").await;
        let first = publisher.run_tick().await.expect("first");
        assert_eq!(publisher.diff_cache_len(), 2);

        // Verify both users present in the first global.
        let first_global: GlobalUsersIndex =
            store.get_ipld(&first.global_cid).await.expect("first global");
        assert!(first_global.users.contains_key("alice"));
        assert!(first_global.users.contains_key("bob"));

        // Delete bob's bucket — bob disappears from BucketManager.
        manager
            .delete_bucket_for_user("bob", "docs")
            .await
            .expect("delete");
        let second = publisher.run_tick().await.expect("second");
        assert_eq!(
            publisher.diff_cache_len(),
            1,
            "diff cache must shrink when a user disappears"
        );
        assert_eq!(second.changed_users, 0, "no per-user CBOR rebuilt");
        assert!(
            second.global_rebuilt,
            "pure-deletion tick MUST rebuild global"
        );
        assert_eq!(
            second.sequence, 2,
            "deletion-only tick advances sequence (chain cron must observe new state)"
        );
        assert_ne!(
            second.global_cid, first.global_cid,
            "global CID must change when membership changes"
        );

        let second_global: GlobalUsersIndex =
            store.get_ipld(&second.global_cid).await.expect("second global");
        assert!(second_global.users.contains_key("alice"));
        assert!(
            !second_global.users.contains_key("bob"),
            "deleted user MUST disappear from published global"
        );
        // Idempotency: alice's content didn't change, so her per-
        // user `bucketsIndexCid` MUST be byte-identical across the
        // two globals. If this drifts, something in the diff-cache
        // logic is silently re-pinning unchanged users.
        assert_eq!(
            first_global.users["alice"], second_global.users["alice"],
            "unchanged user's bucketsIndex CID must be stable across deletion ticks"
        );
    }

    #[tokio::test]
    async fn test_run_tick_after_restart_rebuilds_with_advanced_sequence() {
        // Crash-recovery scenario: master commits state, restarts.
        // The new publisher's in-memory diff cache is empty, so
        // every user looks "changed" on the first tick and the
        // sequence advances by 1. The per-user `bucketsIndexCid`s
        // are deterministic CIDs over the same content, so the
        // pin operations are idempotent — but the global CBOR
        // embeds a fresh `sequence` + `updated_at_unix`, so its
        // CID changes. Documented expected behavior.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("state.txt");

        let first_global_cid;
        {
            let (publisher, _store, manager) = fixture_publisher(path.clone());
            create_user_bucket(&manager, "alice", "photos").await;
            create_user_bucket(&manager, "bob", "docs").await;
            let first = publisher.run_tick().await.expect("first tick");
            assert_eq!(first.sequence, 1);
            first_global_cid = first.global_cid;
        } // publisher drops, simulating master restart

        // Re-open against the same state file AND a *fresh*
        // BucketManager. We re-create the same buckets so the
        // post-restart manager mirrors what `load_registry` would
        // produce in production (same owner_ids + bucket_names).
        let (publisher, _store, manager) = fixture_publisher(path);
        create_user_bucket(&manager, "alice", "photos").await;
        create_user_bucket(&manager, "bob", "docs").await;

        // State persisted before restart is loaded.
        assert_eq!(publisher.latest().sequence, 1);
        assert_eq!(publisher.latest().global_cid, Some(first_global_cid));

        // First post-restart tick: cache is empty → every user
        // gets a re-pin. Sequence advances exactly once.
        let second = publisher.run_tick().await.expect("post-restart tick");
        assert_eq!(second.changed_users, 2, "empty cache → all users re-pinned");
        assert_eq!(second.total_users, 2);
        assert_eq!(
            second.sequence, 2,
            "sequence advances by exactly 1 across restart"
        );
        assert!(second.global_rebuilt);
    }

    #[tokio::test]
    async fn test_run_tick_legacy_to_blinded_replaces_entry() {
        // Phase 3.2.1(d) backward-compat scenario: write under old
        // client (no lookup_h), then again under new client (with
        // lookup_h). The published CBOR must contain a single
        // blinded entry for the bucket — NOT both legacy and blinded.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("state.txt");
        let (publisher, store, manager) = fixture_publisher(path);

        create_user_bucket(&manager, "alice", "photos").await;
        let first = publisher.run_tick().await.expect("first");

        // Simulate the upgrade: populate lookup_h via the public
        // helper (this is what the PUT handler calls in production
        // when a Phase-1.2-aware client uploads).
        let h = [0x77u8; 16];
        let changed = manager
            .populate_bucket_lookup_h("alice", "photos", h)
            .expect("populate ok");
        assert!(changed, "must transition None → Some");

        let second = publisher.run_tick().await.expect("second");
        assert_eq!(second.changed_users, 1);
        assert_ne!(second.global_cid, first.global_cid);

        // Fetch and decode the per-user CBOR via the global. There
        // should be exactly ONE entry — keyed under the blinded
        // hex of `h`, not under "photos".
        let global_cbor: GlobalUsersIndex =
            store.get_ipld(&second.global_cid).await.expect("global");
        let alice_user_key = global_cbor
            .users
            .keys()
            .next()
            .expect("alice should be present");
        let alice_buckets_cid: Cid = global_cbor.users[alice_user_key]
            .parse()
            .expect("parse cid");
        let user_cbor: UserBucketsIndex = store
            .get_ipld(&alice_buckets_cid)
            .await
            .expect("user buckets");
        assert_eq!(
            user_cbor.buckets.len(),
            1,
            "exactly one bucket — legacy must NOT coexist with blinded"
        );
        assert!(
            user_cbor.buckets.contains_key(&hex::encode(h)),
            "blinded key present"
        );
        assert!(
            !user_cbor.buckets.contains_key("photos"),
            "plaintext name must NOT appear after migration"
        );
        let entry = user_cbor.buckets.get(&hex::encode(h)).unwrap();
        assert!(!entry.legacy);
    }

    // NOTE: there is intentionally no `test_run_tick_unpins_previous_global` test.
    // `MemoryBlockStore::unpin` is a no-op (memory.rs:108-111) and `is_pinned`
    // resolves to `has_block`, so the in-memory backend can't observe a
    // pin/unpin distinction. The unpin call itself is exercised — code path
    // executes — but observability requires a real `IpfsPinning` or `Cluster`
    // backend (covered in Phase 3.6 staging-mirror verification step 8).
    // Adding a counting `PinStore` wrapper here would be ~80 LOC of scaffolding
    // for one assertion; not worth it.

    #[tokio::test]
    async fn test_run_tick_no_users_first_publish_emits_empty_global() {
        // Edge case: master starts up with zero buckets. First tick
        // still publishes (so the SDK can fetch and find an empty
        // user map without falling back to chain).
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("state.txt");
        let (publisher, _store, _manager) = fixture_publisher(path);

        let outcome = publisher.run_tick().await.expect("tick");
        assert_eq!(outcome.total_users, 0);
        assert_eq!(outcome.changed_users, 0);
        assert!(outcome.global_rebuilt, "first publish must run even on empty");
        assert_eq!(outcome.sequence, 1);
    }

    // ============================================================
    // Phase 3.2 A3 — IPNS publisher tests (wiremock)
    // ============================================================

    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Construct a publisher that targets `mock_url` for IPNS calls
    /// (instead of a real kubo). The mock has full control over
    /// success/failure responses.
    fn fixture_publisher_with_ipns(
        state_path: PathBuf,
        ipns_api_url: String,
    ) -> (
        UsersIndexPublisher<MemoryBlockStore>,
        Arc<MemoryBlockStore>,
        Arc<BucketManager<MemoryBlockStore>>,
    ) {
        let store = Arc::new(MemoryBlockStore::new());
        let manager = Arc::new(BucketManager::new(Arc::clone(&store)));
        let mut config = fixture_config(state_path);
        // Speed up: short lifetime/ttl in tests (kubo accepts them
        // but our format function is tested below).
        config.ipns_lifetime = Duration::from_secs(60);
        config.ipns_ttl = Duration::from_secs(15);
        let ipns = IpnsPublisher::new(ipns_api_url);
        let publisher = UsersIndexPublisher::open_with_ipns(
            config,
            Arc::clone(&manager),
            Arc::clone(&store),
            Some(ipns),
        )
        .expect("open");
        (publisher, store, manager)
    }

    #[test]
    fn test_format_go_duration() {
        assert_eq!(format_go_duration(Duration::from_secs(36 * 3600)), "129600s");
        assert_eq!(format_go_duration(Duration::from_secs(15 * 60)), "900s");
        assert_eq!(format_go_duration(Duration::from_secs(0)), "0s");
    }

    #[tokio::test]
    async fn test_ipns_publisher_success() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v0/name/publish"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Name": "k51qzi5uqu5dh-mock",
                "Value": "/ipfs/QmFakeCidValue",
            })))
            .mount(&mock)
            .await;

        let publisher = IpnsPublisher::new(mock.uri());
        let cid = fixture_cid(0xab);
        let resp = publisher
            .publish(
                &cid,
                "fula-users-index",
                Duration::from_secs(36 * 3600),
                Duration::from_secs(15 * 60),
            )
            .await
            .expect("publish");
        assert_eq!(resp.name, "k51qzi5uqu5dh-mock");
        assert_eq!(resp.value, "/ipfs/QmFakeCidValue");
    }

    #[tokio::test]
    async fn test_ipns_publisher_propagates_5xx_error() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v0/name/publish"))
            .respond_with(ResponseTemplate::new(500).set_body_string("internal error"))
            .mount(&mock)
            .await;

        let publisher = IpnsPublisher::new(mock.uri());
        let cid = fixture_cid(0xab);
        let result = publisher
            .publish(
                &cid,
                "fula-users-index",
                Duration::from_secs(60),
                Duration::from_secs(15),
            )
            .await;
        assert!(result.is_err(), "5xx must surface as error");
        let err = format!("{}", result.unwrap_err());
        assert!(err.contains("status=500"), "error message exposes status");
    }

    #[tokio::test]
    async fn test_run_tick_calls_ipns_with_correct_cid_and_sequence() {
        // Verifies the integration point: run_tick fires kubo's
        // /api/v0/name/publish with the freshly-built global CID.
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v0/name/publish"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Name": "k51qzi5uqu5dh-mock",
                "Value": "/ipfs/QmIgnored",
            })))
            .expect(1) // exactly one IPNS publish per tick
            .mount(&mock)
            .await;

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("state.txt");
        let (publisher, _store, manager) =
            fixture_publisher_with_ipns(path, mock.uri());

        create_user_bucket(&manager, "alice", "photos").await;
        let outcome = publisher.run_tick().await.expect("tick");
        assert_eq!(outcome.sequence, 1);
        // wiremock's expect(1) verifies on drop that exactly one
        // request hit the IPNS endpoint.
    }

    #[tokio::test]
    async fn test_run_tick_succeeds_when_ipns_5xx() {
        // Operating-state matrix: kubo IPNS endpoint returns 500.
        // The tick MUST still return Ok, the persisted state MUST
        // still advance, and the global CID MUST still be pinned.
        // Otherwise a flaky kubo blocks the entire publisher,
        // which blocks subsequent writes on master.
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v0/name/publish"))
            .respond_with(ResponseTemplate::new(500).set_body_string("kubo down"))
            .mount(&mock)
            .await;

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("state.txt");
        let (publisher, store, manager) =
            fixture_publisher_with_ipns(path.clone(), mock.uri());

        create_user_bucket(&manager, "alice", "photos").await;
        let outcome = publisher.run_tick().await.expect("tick still Ok on IPNS 5xx");
        assert_eq!(outcome.sequence, 1);
        assert!(outcome.global_rebuilt);

        // Pin happened → block exists in store.
        assert!(store.is_pinned(&outcome.global_cid).await.unwrap());

        // Persist happened → state file reflects new sequence.
        let persisted = PersistedState::load(&path).expect("load");
        assert_eq!(persisted.sequence, 1);
        assert_eq!(persisted.global_cid, Some(outcome.global_cid));
    }

    #[tokio::test]
    async fn test_run_tick_no_ipns_configured_still_pins_and_persists() {
        // open_without_ipns: tick still pins + persists; chain backup
        // path is the only publish channel. Useful regression check
        // for operators who deploy without IPNS.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("state.txt");
        let store = Arc::new(MemoryBlockStore::new());
        let manager = Arc::new(BucketManager::new(Arc::clone(&store)));
        let publisher = UsersIndexPublisher::open_without_ipns(
            fixture_config(path.clone()),
            Arc::clone(&manager),
            Arc::clone(&store),
        )
        .expect("open");

        create_user_bucket(&manager, "alice", "photos").await;
        let outcome = publisher.run_tick().await.expect("tick");
        assert_eq!(outcome.sequence, 1);
        assert!(outcome.global_rebuilt);
        assert!(publisher.ipns_api_url_for_test().is_none());
    }

    // ============================================================
    // Per-user error tolerance (Phase 3.2 production hardening)
    // ============================================================
    //
    // Before this hardening: a single user's pin failure aborted the
    // ENTIRE tick (the `for r in pin_results { let (...) = r?; }`
    // pattern at the per-user collection step). At scale this means
    // one corrupted user blocks every user's cold-start visibility.
    //
    // After: per-user failures are tolerated. The tick continues with
    // succeeded users, the global is rebuilt from whatever the
    // diff_cache currently holds (failed users keep their PRIOR cache
    // row if any), and failed users naturally retry on the next tick
    // because their `content_hash` still mismatches the unchanged
    // cache row.
    //
    // The four scenarios below come from the advisor's required
    // matrix:
    //  1. Partial failure → succeeded users in global, failed users
    //     not in global, sequence advances.
    //  2. All-unchanged + 1 new-but-failing → no rebuild needed,
    //     sequence does NOT advance (early-return path), and the
    //     "stale-but-consistent" property holds: prior global keeps
    //     serving prior CIDs.
    //  3. All-fail-first-tick → empty global, sequence = 1,
    //     failed_users = N (deliberate empty-global semantic, same
    //     as zero-users-on-first-tick).
    //  4. Failed user retries successfully on next tick → eventually
    //     appears in global.

    /// Test-only fault-injecting block store. Wraps `MemoryBlockStore`
    /// and fails `put_ipld` whenever the serialized CBOR bytes contain
    /// the configured marker substring. Tests set up a fault by
    /// naming a bucket with the marker; the per-user CBOR for that
    /// user contains the bucket name (Phase 1.2 legacy mode keys
    /// entries by plaintext name when `bucket_lookup_h = None`), so
    /// `put_ipld(&UserBucketsIndex)` for that user fails with the
    /// marker present.
    ///
    /// **Why content-driven, not order-driven.** Production failures
    /// are content-driven (a specific user's data triggers a
    /// pinning-service edge case). Substring matching captures that
    /// failure shape and stays robust to any future refactor of
    /// `buffer_unordered` ordering inside `run_tick`.
    ///
    /// The marker is also (incidentally) present in `BucketRegistry`
    /// CBORs that `BucketManager::persist_registry` writes, but that
    /// failure is caught by `create_bucket_for_user` (line 909-911
    /// in bucket.rs) and only logged at warn level — the in-memory
    /// `BucketManager.buckets` is updated regardless, which is what
    /// the publisher reads.
    #[derive(Clone)]
    struct FaultyBlockStore {
        inner: Arc<MemoryBlockStore>,
        fail_marker: Arc<Mutex<Option<Vec<u8>>>>,
    }

    impl FaultyBlockStore {
        fn new(inner: Arc<MemoryBlockStore>) -> Self {
            Self {
                inner,
                fail_marker: Arc::new(Mutex::new(None)),
            }
        }

        /// Configure the marker. `Some(s)` causes `put_ipld` to fail
        /// when serialized bytes contain `s`. `None` clears injection.
        fn set_fail_marker(&self, marker: Option<&str>) {
            *self.fail_marker.lock() = marker.map(|s| s.as_bytes().to_vec());
        }

        /// Test helper: clone the inner store handle to inspect what
        /// got pinned (since FaultyBlockStore.pin delegates).
        fn inner(&self) -> Arc<MemoryBlockStore> {
            Arc::clone(&self.inner)
        }
    }

    #[async_trait::async_trait]
    impl fula_blockstore::BlockStore for FaultyBlockStore {
        async fn put_block(&self, data: &[u8]) -> fula_blockstore::Result<Cid> {
            self.inner.put_block(data).await
        }
        async fn get_block(&self, cid: &Cid) -> fula_blockstore::Result<bytes::Bytes> {
            self.inner.get_block(cid).await
        }
        async fn has_block(&self, cid: &Cid) -> fula_blockstore::Result<bool> {
            self.inner.has_block(cid).await
        }
        async fn delete_block(&self, cid: &Cid) -> fula_blockstore::Result<()> {
            self.inner.delete_block(cid).await
        }
        async fn block_size(&self, cid: &Cid) -> fula_blockstore::Result<u64> {
            self.inner.block_size(cid).await
        }
        async fn put_ipld<T: serde::Serialize + Send + Sync>(
            &self,
            data: &T,
        ) -> fula_blockstore::Result<Cid> {
            // Delegate to the inner store first so the bytes are
            // available for marker inspection via `get_block`. This
            // avoids depending on serde_ipld_dagcbor directly (which
            // isn't a fula-cli direct dep). The "block stored but
            // not pinned" outcome models real production failures
            // where a block reaches kubo but the cluster pin call
            // fails — which is exactly the failure-mode this
            // tolerance work guards against.
            let cid = self.inner.put_ipld(data).await?;
            // Snapshot the marker out of the parking_lot mutex guard
            // before any `.await`. parking_lot's `MutexGuard` is not
            // `Send`, so holding it across an await point makes the
            // future non-Send and tokio refuses to spawn it.
            let marker_snapshot: Option<Vec<u8>> = self.fail_marker.lock().clone();
            if let Some(marker) = marker_snapshot {
                if !marker.is_empty() {
                    let bytes = self.inner.get_block(&cid).await?;
                    if bytes.windows(marker.len()).any(|w| w == marker.as_slice()) {
                        return Err(fula_blockstore::BlockStoreError::PinFailed(
                            "test-injected fault: marker substring present in stored block".into(),
                        ));
                    }
                }
            }
            Ok(cid)
        }
        async fn get_ipld<T: serde::de::DeserializeOwned>(
            &self,
            cid: &Cid,
        ) -> fula_blockstore::Result<T> {
            self.inner.get_ipld(cid).await
        }
    }

    #[async_trait::async_trait]
    impl fula_blockstore::PinStore for FaultyBlockStore {
        async fn pin(&self, cid: &Cid, name: Option<&str>) -> fula_blockstore::Result<()> {
            self.inner.pin(cid, name).await
        }
        async fn pin_with_token(
            &self,
            cid: &Cid,
            name: Option<&str>,
            token: &str,
        ) -> fula_blockstore::Result<()> {
            self.inner.pin_with_token(cid, name, token).await
        }
        async fn unpin(&self, cid: &Cid) -> fula_blockstore::Result<()> {
            self.inner.unpin(cid).await
        }
        async fn is_pinned(&self, cid: &Cid) -> fula_blockstore::Result<bool> {
            self.inner.is_pinned(cid).await
        }
        async fn list_pins(&self) -> fula_blockstore::Result<Vec<Cid>> {
            self.inner.list_pins().await
        }
        async fn pin_status(&self, cid: &Cid) -> fula_blockstore::Result<fula_blockstore::PinStatus> {
            self.inner.pin_status(cid).await
        }
    }

    /// Marker substring used by the per-user-error-tolerance tests.
    /// Picked to be:
    ///   - lowercase letters + hyphens only → passes
    ///     `validate_bucket_name` so it can be a real bucket name
    ///   - long enough (19 chars) that a false-positive substring
    ///     match in random CBOR bytes is implausible
    const FAULT_MARKER: &str = "fault-inject-bucket";

    fn fixture_publisher_with_faulty_store(
        path: PathBuf,
    ) -> (
        UsersIndexPublisher<FaultyBlockStore>,
        Arc<FaultyBlockStore>,
        Arc<BucketManager<FaultyBlockStore>>,
    ) {
        let inner = Arc::new(MemoryBlockStore::new());
        let faulty = Arc::new(FaultyBlockStore::new(Arc::clone(&inner)));
        let manager = Arc::new(BucketManager::new(Arc::clone(&faulty)));
        let publisher = UsersIndexPublisher::open_without_ipns(
            fixture_config(path),
            Arc::clone(&manager),
            Arc::clone(&faulty),
        )
        .expect("open");
        (publisher, faulty, manager)
    }

    #[tokio::test]
    async fn test_run_tick_partial_failure_publishes_succeeded_users() {
        // Scenario 1: alice has a normal bucket, bob has a bucket
        // whose name contains FAULT_MARKER. Bob's per-user CBOR
        // pin fails. Alice's succeeds. The tick continues, advances
        // sequence, and the published global contains alice but
        // NOT bob.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("state.txt");
        let (publisher, store, manager) = fixture_publisher_with_faulty_store(path);

        store.set_fail_marker(Some(FAULT_MARKER));

        create_user_bucket(&manager, "alice", "photos").await;
        // Bob's bucket name contains the marker. The per-user CBOR
        // for bob is keyed by plaintext bucket name (Phase 1.2 legacy
        // mode), so the marker substring lands in the CBOR bytes.
        create_user_bucket(&manager, "bob", FAULT_MARKER).await;

        let outcome = publisher
            .run_tick()
            .await
            .expect("tick MUST return Ok despite per-user pin failure");

        assert_eq!(
            outcome.changed_users, 1,
            "exactly one user's CBOR was newly pinned (alice)"
        );
        assert_eq!(
            outcome.failed_users, 1,
            "exactly one user's pin failed (bob)"
        );
        assert_eq!(outcome.total_users, 2);
        assert!(
            outcome.global_rebuilt,
            "global must be rebuilt to reflect alice's commit"
        );
        assert_eq!(outcome.sequence, 1);

        // Decode the global CBOR: alice present, bob absent.
        let inner = store.inner();
        let global: GlobalUsersIndex =
            inner.get_ipld(&outcome.global_cid).await.expect("global");
        assert!(
            global.users.contains_key("alice"),
            "alice's userKey must be in published global"
        );
        assert!(
            !global.users.contains_key("bob"),
            "bob's userKey must NOT be in published global (his pin failed)"
        );
    }

    #[tokio::test]
    async fn test_run_tick_failed_user_keeps_prior_cid_in_global() {
        // Scenario 2 (advisor-mandated rigor): tick 1 — alice + bob
        // both succeed. Tick 2 — alice gets a new bucket (will succeed),
        // bob gets a marker bucket (will fail). The "stale-but-
        // consistent" property: bob's entry in tick 2's published
        // global must equal bob's PRIOR CID (from tick 1), NOT his
        // new failed-pin CID.
        //
        // This guards against a future refactor that might
        // accidentally republish bob with a stale-or-empty entry. If
        // that happens, cold-start would point at content that isn't
        // pinned, breaking bob's reads.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("state.txt");
        let (publisher, store, manager) = fixture_publisher_with_faulty_store(path);

        // Tick 1: both users succeed.
        create_user_bucket(&manager, "alice", "photos").await;
        create_user_bucket(&manager, "bob", "docs").await;
        let first = publisher.run_tick().await.expect("first tick");
        assert_eq!(first.changed_users, 2);
        assert_eq!(first.failed_users, 0);

        // Capture bob's PRIOR per-user bucketsIndex CID.
        let inner = store.inner();
        let first_global: GlobalUsersIndex =
            inner.get_ipld(&first.global_cid).await.expect("first global");
        // CIDs in the global are stored as strings (not Cid), so
        // clone for comparison after the next get_ipld call.
        let bob_prior_cid = first_global.users["bob"].clone();
        let alice_prior_cid = first_global.users["alice"].clone();

        // Defensive sanity: bob's prior CID's bytes are present in
        // the inner store. If a future refactor made `bob_prior_cid`
        // a default/empty Cid, the equality assertion below would
        // pass for the wrong reason. This catches that.
        let bob_prior_cid_parsed: Cid = bob_prior_cid.parse().expect("parse prior cid");
        assert!(
            inner.get_block(&bob_prior_cid_parsed).await.is_ok(),
            "bob's prior bucketsIndex CID must reference real bytes (sanity)"
        );

        // Now turn on fault injection.
        store.set_fail_marker(Some(FAULT_MARKER));

        // Alice gets a new (clean) bucket → her CBOR rebuilds + pins OK.
        create_user_bucket(&manager, "alice", "videos").await;
        // Bob gets a marker bucket → his per-user CBOR pin fails.
        create_user_bucket(&manager, "bob", FAULT_MARKER).await;

        let second = publisher.run_tick().await.expect("second tick");
        assert_eq!(
            second.changed_users, 1,
            "alice's CBOR rebuild succeeded; bob's failed"
        );
        assert_eq!(
            second.failed_users, 1,
            "bob's pin failed"
        );
        assert!(
            second.global_rebuilt,
            "alice's change forces global rebuild"
        );
        assert_eq!(second.sequence, 2, "sequence advances on real change");
        assert_ne!(
            second.global_cid, first.global_cid,
            "global CID must change because alice changed"
        );

        // Decode tick 2's global. bob's entry MUST be his PRIOR cid;
        // alice's entry MUST be her new cid.
        let second_global: GlobalUsersIndex =
            inner.get_ipld(&second.global_cid).await.expect("second global");
        assert_eq!(
            second_global.users["bob"], bob_prior_cid,
            "stale-but-consistent: bob's failed pin must NOT erase his prior CID; \
             cold-start serves bob's prior bucketsIndex (still pinned + accessible)"
        );
        assert_ne!(
            second_global.users["alice"], alice_prior_cid,
            "alice's CID changed because her content changed and her pin succeeded"
        );
    }

    #[tokio::test]
    async fn test_run_tick_all_users_fail_first_tick_publishes_empty_global() {
        // Scenario 3: every user's pin fails on the first tick.
        // No prior state to preserve → publisher proceeds to publish
        // an EMPTY global (same code path as "zero users on first
        // tick", which the existing
        // `test_run_tick_no_users_first_publish_emits_empty_global`
        // test already pins down).
        //
        // Operators see this as a nonzero `failed_users` in TickOutcome
        // + per-user `warn!` lines. The empty-global publish itself
        // is not a regression: the next tick when users start
        // succeeding republishes with non-empty global, sequence
        // advances. The chain anchor cron eventually submits the
        // first non-empty CID. No data corruption, no stuck state.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("state.txt");
        let (publisher, store, manager) = fixture_publisher_with_faulty_store(path);

        store.set_fail_marker(Some(FAULT_MARKER));

        // Both users have marker buckets → both pins fail.
        create_user_bucket(&manager, "alice", FAULT_MARKER).await;
        // Different bucket name to ensure two distinct users (BucketManager
        // accepts duplicate names per-user but we want two USERS).
        let bob_bucket_name = format!("{}-2", FAULT_MARKER);
        create_user_bucket(&manager, "bob", &bob_bucket_name).await;

        let outcome = publisher
            .run_tick()
            .await
            .expect("tick MUST return Ok even when every per-user pin fails");

        assert_eq!(
            outcome.changed_users, 0,
            "no per-user CBOR was successfully pinned"
        );
        assert_eq!(outcome.failed_users, 2);
        assert_eq!(outcome.total_users, 2);
        assert!(
            outcome.global_rebuilt,
            "first publish must run even when every user failed (same as zero-users path)"
        );
        assert_eq!(outcome.sequence, 1);

        let inner = store.inner();
        let global: GlobalUsersIndex =
            inner.get_ipld(&outcome.global_cid).await.expect("global");
        assert_eq!(
            global.users.len(),
            0,
            "global has zero users — every user's CBOR pin failed"
        );
    }

    #[tokio::test]
    async fn test_run_tick_failed_user_retries_on_next_tick() {
        // Scenario 4: bob fails on tick 1. Marker is cleared between
        // ticks. On tick 2, bob's content_hash STILL mismatches his
        // (unupdated) diff_cache row, so he's in `to_rebuild`. His
        // pin succeeds this time; he appears in tick 2's global.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("state.txt");
        let (publisher, store, manager) = fixture_publisher_with_faulty_store(path);

        // Set up: alice clean, bob with marker.
        create_user_bucket(&manager, "alice", "photos").await;
        create_user_bucket(&manager, "bob", FAULT_MARKER).await;

        // Tick 1: marker active → bob fails.
        store.set_fail_marker(Some(FAULT_MARKER));
        let first = publisher.run_tick().await.expect("first tick");
        assert_eq!(first.changed_users, 1);
        assert_eq!(first.failed_users, 1);

        let inner = store.inner();
        let first_global: GlobalUsersIndex =
            inner.get_ipld(&first.global_cid).await.expect("first global");
        assert!(
            !first_global.users.contains_key("bob"),
            "bob absent from tick 1's global (failed pin)"
        );

        // Tick 2: clear the marker. bob's content_hash still doesn't
        // match the (empty) cache row, so he's re-attempted. Pin
        // succeeds this time → bob is in the global.
        store.set_fail_marker(None);
        let second = publisher.run_tick().await.expect("second tick");
        assert_eq!(
            second.changed_users, 1,
            "bob's retry succeeded; alice was unchanged"
        );
        assert_eq!(second.failed_users, 0);
        assert!(second.global_rebuilt);
        assert_eq!(second.sequence, 2);

        let second_global: GlobalUsersIndex =
            inner.get_ipld(&second.global_cid).await.expect("second global");
        assert!(
            second_global.users.contains_key("bob"),
            "bob present in tick 2's global (retry succeeded)"
        );
        assert!(
            second_global.users.contains_key("alice"),
            "alice still present (unchanged across the two ticks)"
        );
    }
}
