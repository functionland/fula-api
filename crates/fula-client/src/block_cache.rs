//! Persistent LRU block cache (Phase 2.2 of master-independent reads).
//!
//! Stores **encrypted** IPFS blocks fetched from the gateway race so that,
//! during a master outage, re-reading the same file is served entirely
//! from local disk instead of re-fetching from public gateways.
//!
//! Backed by a single redb file (ACID, no separate DB process). Two
//! tables:
//! - `blocks`: CID multihash bytes → encrypted block bytes
//! - `meta`:   CID multihash bytes → last-access unix-millis (for LRU)
//!
//! # Concurrency model
//!
//! - **One SDK instance per cache path.** redb requires exclusive access
//!   to its file. Constructing two `BlockCache`s pointing at the same
//!   path returns [`BlockCacheError::AlreadyOpen`].
//! - **Concurrent get/put are safe** within a single instance via
//!   redb's ACID transactions.
//! - **Eviction is serialized** by an internal async mutex so concurrent
//!   `put`s that all cross the budget don't all run eviction at once.
//!
//! # Eviction policy
//!
//! When `put` would push the cache over `max_bytes`, evict to a
//! **80 %-of-budget low watermark** (rather than exactly the budget).
//! That amortizes the eviction cost — without it, every put just-over
//! the threshold would pay mutex + write-txn overhead to evict a single
//! tiny entry.
//!
//! # Security
//!
//! The cache stores **encrypted** block bytes content-addressed by their
//! IPFS CID. It does **not** verify CID-on-insert — CID verification is
//! the caller's responsibility (Phase 2.3 enforces it before calling
//! `put`). The cache makes no security promises about content secrecy
//! beyond what file-system permissions provide.
//!
//! # Backward compatibility
//!
//! Phase 2.2 is purely additive new infrastructure. No existing data is
//! touched; there is no migration. The cache is opt-in via SDK config
//! (Phase 2.4 wires it in). A first-time-ever open creates an empty
//! redb file at the configured path.

#![cfg(not(target_arch = "wasm32"))]

use bytes::Bytes;
use cid::Cid;
use redb::{Database, ReadableTable, ReadableTableMetadata, TableDefinition};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;

const BLOCKS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("blocks");
const META: TableDefinition<&[u8], u64> = TableDefinition::new("meta");

/// Phase 2.4 lookup table: maps `(bucket, key)` (hashed with a
/// domain separator) → CID bytes. Used by the offline-fallback path
/// to translate an S3-key request into the IPFS CID it can fetch via
/// the gateway race. Populated as a side-effect of master-up reads
/// in `FulaClient::get_object_with_offline_fallback`.
///
/// Key format: `BLAKE3("fula:block-cache:key-to-cid:v1" || bucket || 0x00 || key)[..32]`
/// — fixed 32 bytes, collision-resistant, fast B-tree lookup. Value:
/// raw CID bytes (the same encoding used as the BLOCKS table key, so
/// a `KEY_TO_CID` lookup directly gives the bytes needed to query
/// BLOCKS or to construct a `Cid` for the gateway race).
const KEY_TO_CID: TableDefinition<&[u8], &[u8]> = TableDefinition::new("key_to_cid");

/// Phase 3.3.5 small-key-value metadata table. Stores resolver
/// hot-start state across SDK restarts:
///   - `users_index/cid`              → CID bytes (cid.to_bytes())
///   - `users_index/sequence`         → u64 BE
///   - `users_index/observed_at_unix` → u64 BE
///
/// Three rows, ~80 bytes total. The cached `(cid, sequence)` seeds
/// the resolver's replay-defense floor on construction; a fresh
/// `observed_at` lets the resolver short-circuit IPNS+chain when
/// the entry is within `ResolverConfig::soft_ttl`.
///
/// Schema versioning: deliberately omitted in 3.3.5 (advisor cut).
/// When a v2 schema lands, add a `metadata.schema_id` constant +
/// drop-on-mismatch logic together with the real migration story.
const METADATA: TableDefinition<&[u8], &[u8]> = TableDefinition::new("metadata");

/// Metadata row keys (string literals stored as `&[u8]`).
const META_USERS_INDEX_CID: &[u8] = b"users_index/cid";
const META_USERS_INDEX_SEQUENCE: &[u8] = b"users_index/sequence";
const META_USERS_INDEX_OBSERVED_AT: &[u8] = b"users_index/observed_at_unix";

/// Issue #8 fix #2 — list_buckets offline cache.
///
/// The raw S3 list-buckets XML body stored after each successful
/// master-up call. Served back on `MasterUnreachable` so the SDK has
/// a working offline fallback for the top-level "what buckets exist"
/// query, the same way it does for object reads via the cid-hint
/// path.
///
/// **Per-JWT scoping (security).** Each user's cached XML lives
/// under its own row keyed by `sha256(access_token)[..16]` (hex).
/// A shared cache file (rare in FxFiles which uses per-app sandbox,
/// but possible on multi-user devices) can hold cached responses
/// for many distinct accounts without one being able to serve
/// another's cached state. JWT rotation does invalidate the cache
/// (new token → new key), which is acceptable — a fresh master-up
/// call re-populates within seconds.
///
/// FxFiles already implements a similar Dart-side `listBucketsCached`
/// shim — moving it into the SDK means every consumer benefits
/// without re-implementing it.
const META_LIST_BUCKETS_PREFIX: &str = "list_buckets/";
const META_LIST_BUCKETS_XML_SUFFIX: &str = "/response_xml";
const META_LIST_BUCKETS_OBSERVED_AT_SUFFIX: &str = "/observed_at_unix";

/// Build the per-scope METADATA keys for the list-buckets cache.
/// `scope` is `sha256(jwt)[..16]` hex (32 chars) — see
/// `FulaClient::list_buckets_cache_scope`.
fn list_buckets_keys(scope: &str) -> (Vec<u8>, Vec<u8>) {
    let xml_key = format!("{}{}{}", META_LIST_BUCKETS_PREFIX, scope, META_LIST_BUCKETS_XML_SUFFIX);
    let obs_key = format!("{}{}{}", META_LIST_BUCKETS_PREFIX, scope, META_LIST_BUCKETS_OBSERVED_AT_SUFFIX);
    (xml_key.into_bytes(), obs_key.into_bytes())
}

/// Eviction low-watermark: when triggered, free space until usage is at
/// or below this fraction of `max_bytes`. 80 % is the industry-standard
/// "evict-once-amortize-many-puts" point.
const EVICT_LOW_WATERMARK_NUMERATOR: u64 = 80;
const EVICT_LOW_WATERMARK_DENOMINATOR: u64 = 100;

/// Errors specific to the block cache. Surfaced separately from
/// `ClientError` so tests can match without coupling to the global
/// error enum.
#[derive(Debug, thiserror::Error)]
pub enum BlockCacheError {
    /// Another process (or a previously-leaked instance in the same
    /// process) holds the redb file lock.
    ///
    /// Only one `BlockCache` may be open per path at a time.
    #[error("block cache file is already open by another instance: {path}")]
    AlreadyOpen { path: PathBuf },

    /// The cache file exists but is not a valid redb database.
    ///
    /// The caller decides whether to delete and recreate it. We do not
    /// auto-delete — losing hundreds of MB of cache silently is a
    /// foot-gun.
    #[error("block cache file is corrupt: {0}")]
    Corrupt(String),

    /// A `put` was attempted with a block whose size exceeds the cache
    /// budget. The cache cannot accept it; the caller should fetch
    /// directly without caching.
    #[error("block size {size} bytes exceeds cache budget {budget} bytes")]
    BlockTooLarge { size: u64, budget: u64 },

    #[error("redb error: {0}")]
    Redb(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

impl From<redb::DatabaseError> for BlockCacheError {
    fn from(e: redb::DatabaseError) -> Self {
        // Single classification policy applied wherever DatabaseError
        // surfaces (both inside `open()`'s map_err and via `?` in
        // future callers). Lock-style errors → AlreadyOpen; corruption
        // markers → Corrupt; everything else → generic Redb.
        let s = e.to_string();
        let lower = s.to_lowercase();
        if lower.contains("in use") || lower.contains("locked") || lower.contains("lock") {
            // Path is unknown at this conversion site — caller will see
            // the message but lose the path. `open()` constructs
            // AlreadyOpen directly with the path; this is the fallback
            // for any other call site that uses `?`.
            BlockCacheError::AlreadyOpen { path: PathBuf::new() }
        } else if lower.contains("corrupt") || lower.contains("checksum") {
            BlockCacheError::Corrupt(s)
        } else {
            BlockCacheError::Redb(s)
        }
    }
}

impl From<redb::TransactionError> for BlockCacheError {
    fn from(e: redb::TransactionError) -> Self {
        BlockCacheError::Redb(e.to_string())
    }
}
impl From<redb::TableError> for BlockCacheError {
    fn from(e: redb::TableError) -> Self {
        BlockCacheError::Redb(e.to_string())
    }
}
impl From<redb::StorageError> for BlockCacheError {
    fn from(e: redb::StorageError) -> Self {
        BlockCacheError::Redb(e.to_string())
    }
}
impl From<redb::CommitError> for BlockCacheError {
    fn from(e: redb::CommitError) -> Self {
        BlockCacheError::Redb(e.to_string())
    }
}

/// LRU block cache backed by a single redb file.
///
/// Cheap-clone via `Arc`: clones share the same database, so a `put`
/// observed by one clone is immediately visible to all others.
#[derive(Clone, Debug)]
pub struct BlockCache {
    inner: Arc<BlockCacheInner>,
}

struct BlockCacheInner {
    db: Database,
    max_bytes: u64,
    /// Live byte counter, kept in sync with the BLOCKS table on every
    /// `put` / eviction. Re-synced from the table on `open()` to recover
    /// from any prior abort that left the counter desynced.
    current_bytes: AtomicU64,
    /// Serializes eviction passes so concurrent over-budget puts don't
    /// each run their own eviction.
    evict_lock: Mutex<()>,
}

// `redb::Database` doesn't implement `Debug`, so we hand-roll a
// minimal `Debug` for `BlockCacheInner` that prints just the
// observable knobs. Required because `UsersIndexResolver` derives
// `Debug` and now holds an `Option<Arc<BlockCache>>`.
impl std::fmt::Debug for BlockCacheInner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlockCacheInner")
            .field("max_bytes", &self.max_bytes)
            .field("current_bytes", &self.current_bytes.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}

impl BlockCache {
    /// Open or create the block cache at `path` with a budget of
    /// `max_bytes` total stored block-bytes.
    ///
    /// On open, scans the BLOCKS table to compute the current byte
    /// count (recovers from any earlier abort that left the in-memory
    /// counter desynced).
    pub fn open(path: impl AsRef<Path>, max_bytes: u64) -> Result<Self, BlockCacheError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }

        let db = Database::create(path).map_err(|e| {
            // redb returns a specific variant for "another process holds
            // the lock" — but the variant name has shifted across redb
            // versions. Do a string check as a portability hedge and
            // map to AlreadyOpen so callers don't have to read redb
            // source to interpret it.
            let s = e.to_string().to_lowercase();
            if s.contains("in use") || s.contains("locked") || s.contains("lock") {
                BlockCacheError::AlreadyOpen { path: path.to_path_buf() }
            } else {
                BlockCacheError::from(e)
            }
        })?;

        // Ensure tables exist (idempotent — opening a non-existent
        // table inside a write txn creates it).
        let init_txn = db.begin_write()?;
        {
            let _ = init_txn.open_table(BLOCKS)?;
            let _ = init_txn.open_table(META)?;
            // Phase 2.4 — additive table. An older redb file written
            // before Phase 2.4 will not have it; opening it here
            // creates it lazily without touching BLOCKS / META data.
            let _ = init_txn.open_table(KEY_TO_CID)?;
            // Phase 3.3.5 — resolver hot-start metadata. Same
            // additive-on-open pattern; older Phase 2.x cache files
            // gain it transparently on next open.
            let _ = init_txn.open_table(METADATA)?;
        }
        init_txn.commit()?;

        // Re-sync the byte counter by scanning. One-time cost at startup;
        // eliminates the class of bugs where a prior abort desynced the
        // atomic counter.
        let mut total: u64 = 0;
        {
            let read = db.begin_read()?;
            let table = read.open_table(BLOCKS)?;
            let iter = table.iter()?;
            for entry in iter {
                let (_, val) = entry?;
                total += val.value().len() as u64;
            }
        }

        Ok(BlockCache {
            inner: Arc::new(BlockCacheInner {
                db,
                max_bytes,
                current_bytes: AtomicU64::new(total),
                evict_lock: Mutex::new(()),
            }),
        })
    }

    // The three accessors below — `max_bytes`, `current_bytes`,
    // `entry_count` — are public monitoring API for SDK consumers
    // (apps that want to surface "cache 240 / 256 MiB used" UI, or
    // for ops dashboards). The fula-client crate itself doesn't call
    // them internally, hence the `#[allow(dead_code)]` to silence
    // the workspace-default warning. Phase 19 (`HealthCallback` /
    // `ReadFreshness`) will likely expose these via a typed status
    // struct rather than direct field access; keep the accessors
    // public until then so app integrators have a stable surface.

    /// Configured budget in bytes.
    #[allow(dead_code)]
    pub fn max_bytes(&self) -> u64 {
        self.inner.max_bytes
    }

    /// Approximate current byte usage. Eventually consistent under
    /// concurrent writes (the next read after all writes settle is
    /// exact).
    #[allow(dead_code)]
    pub fn current_bytes(&self) -> u64 {
        self.inner.current_bytes.load(Ordering::Acquire)
    }

    /// Number of cached blocks. O(1) approximation via the underlying
    /// table length.
    #[allow(dead_code)]
    pub fn entry_count(&self) -> Result<u64, BlockCacheError> {
        let read = self.inner.db.begin_read()?;
        let table = read.open_table(BLOCKS)?;
        Ok(table.len()?)
    }

    /// Look up a block by its CID. Returns `None` if not cached.
    /// Updates the last-access timestamp on hit (for LRU ordering).
    ///
    /// PERF: this currently uses a write txn to update last-access on
    /// hit, which serializes against other writers. Phase 2.4 will
    /// expose this in the hot read path; if profiling shows contention,
    /// switch to deferred or probabilistic access-time updates (e.g.,
    /// buffer in-memory and flush periodically, or update on 1-in-N
    /// reads). LRU is approximate by definition.
    pub fn get(&self, cid: &Cid) -> Result<Option<Bytes>, BlockCacheError> {
        let key = cid.to_bytes();
        // Single write txn so the get-then-update-meta is atomic; under
        // concurrent get/put the timestamp ordering stays consistent.
        let txn = self.inner.db.begin_write()?;
        let result = {
            let blocks = txn.open_table(BLOCKS)?;
            let val = blocks.get(key.as_slice())?;
            val.map(|v| Bytes::copy_from_slice(v.value()))
        };
        if result.is_some() {
            let mut meta = txn.open_table(META)?;
            meta.insert(key.as_slice(), now_ms())?;
        }
        txn.commit()?;
        Ok(result)
    }

    /// Insert (or overwrite) a block. Triggers LRU eviction down to the
    /// 80 %-of-budget low watermark if this insert would cross
    /// `max_bytes`.
    ///
    /// Idempotent under repeat-inserts of the same CID with identical
    /// bytes — `current_bytes` accounting tracks the net delta.
    pub async fn put(&self, cid: &Cid, data: &[u8]) -> Result<(), BlockCacheError> {
        let new_size = data.len() as u64;
        if new_size > self.inner.max_bytes {
            // A single block larger than the entire budget can't be
            // cached. Surface as a typed variant so Phase 2.4 can
            // dispatch on it ("skip caching, fetch directly").
            return Err(BlockCacheError::BlockTooLarge {
                size: new_size,
                budget: self.inner.max_bytes,
            });
        }

        // Eviction: if this insert would push us over budget, evict
        // (under the lock) until we're at the low watermark. Note the
        // budget check uses the *current* size, not the post-insert
        // size — over-tightening to "fit exactly" leads to churn.
        let cur = self.inner.current_bytes.load(Ordering::Acquire);
        if cur + new_size > self.inner.max_bytes {
            let _guard = self.inner.evict_lock.lock().await;
            // Re-check under the lock — another concurrent put may have
            // already evicted enough.
            let cur = self.inner.current_bytes.load(Ordering::Acquire);
            if cur + new_size > self.inner.max_bytes {
                let target = (self.inner.max_bytes * EVICT_LOW_WATERMARK_NUMERATOR
                    / EVICT_LOW_WATERMARK_DENOMINATOR)
                    .saturating_sub(new_size);
                self.evict_to(target)?;
            }
        }

        let key = cid.to_bytes();
        let now = now_ms();
        let txn = self.inner.db.begin_write()?;
        let prior_size: u64 = {
            let mut blocks = txn.open_table(BLOCKS)?;
            let prior = blocks
                .get(key.as_slice())?
                .map(|v| v.value().len() as u64)
                .unwrap_or(0);
            blocks.insert(key.as_slice(), data)?;
            prior
        };
        {
            let mut meta = txn.open_table(META)?;
            meta.insert(key.as_slice(), now)?;
        }
        txn.commit()?;

        // Adjust the byte counter by net delta. Idempotent for
        // identical re-inserts (delta = 0).
        if new_size > prior_size {
            self.inner
                .current_bytes
                .fetch_add(new_size - prior_size, Ordering::AcqRel);
        } else if prior_size > new_size {
            self.inner
                .current_bytes
                .fetch_sub(prior_size - new_size, Ordering::AcqRel);
        }
        Ok(())
    }

    /// Phase 2.4 — record an `(bucket, key) → cid` mapping observed
    /// during a successful master-up read. Lets the offline-fallback
    /// path translate a future S3-key request into the IPFS CID it
    /// can fetch via the gateway race.
    ///
    /// Idempotent on repeated calls with the same arguments. The
    /// underlying redb table grows unbounded today (one entry per
    /// distinct `(bucket, key)` tuple ever observed). At expected
    /// scale (a few thousand objects per device) this is fine; if
    /// growth becomes an issue, eviction can be added at the same
    /// point as block-cache LRU eviction in a future iteration.
    /// Note that the mapping is small (~40 bytes per entry vs.
    /// kilobytes for typical block payloads), so the BLOCKS table's
    /// LRU pressure dominates space concerns by orders of magnitude.
    pub fn record_key_cid(
        &self,
        bucket: &str,
        key: &str,
        cid: &Cid,
    ) -> Result<(), BlockCacheError> {
        let lookup_key = derive_key_cid_lookup(bucket, key);
        let cid_bytes = cid.to_bytes();
        let txn = self.inner.db.begin_write()?;
        {
            let mut table = txn.open_table(KEY_TO_CID)?;
            table.insert(lookup_key.as_slice(), cid_bytes.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    /// Phase 2.4 — look up a previously-observed CID for `(bucket, key)`.
    /// Returns `None` if the SDK has not seen this object during a
    /// master-up read yet (the cold-start case, which the wrapper
    /// surfaces as `MasterUnreachable` so Phase 3.3 can take over).
    pub fn lookup_cid(&self, bucket: &str, key: &str) -> Result<Option<Cid>, BlockCacheError> {
        let lookup_key = derive_key_cid_lookup(bucket, key);
        let read = self.inner.db.begin_read()?;
        let table = read.open_table(KEY_TO_CID)?;
        match table.get(lookup_key.as_slice())? {
            Some(v) => {
                let bytes = v.value();
                // Round-trip through Cid to validate; corrupt entries
                // are rare (would mean redb bit-flip) but failing
                // closed is safer than serving a malformed CID to the
                // gateway race.
                Cid::try_from(bytes)
                    .map(Some)
                    .map_err(|e| BlockCacheError::Corrupt(format!("invalid CID in KEY_TO_CID: {}", e)))
            }
            None => Ok(None),
        }
    }

    /// Phase 3.3.5 — persist the resolver's last successful resolve
    /// so a future SDK process can skip the IPNS+chain dance when
    /// it's still fresh AND seed the replay-defense floor across
    /// restarts.
    ///
    /// Single redb write transaction (atomic across the three rows).
    /// Crate-private: apps must not plant resolver state directly.
    pub(crate) fn store_users_index_state(
        &self,
        cid: &Cid,
        sequence: u64,
        observed_at_unix: u64,
    ) -> Result<(), BlockCacheError> {
        let cid_bytes = cid.to_bytes();
        let txn = self.inner.db.begin_write()?;
        {
            let mut table = txn.open_table(METADATA)?;
            table.insert(META_USERS_INDEX_CID, cid_bytes.as_slice())?;
            table.insert(META_USERS_INDEX_SEQUENCE, sequence.to_be_bytes().as_slice())?;
            table.insert(
                META_USERS_INDEX_OBSERVED_AT,
                observed_at_unix.to_be_bytes().as_slice(),
            )?;
        }
        txn.commit()?;
        Ok(())
    }

    /// Phase 3.3.5 — load the resolver hot-start state. Returns
    /// `None` if any of the three rows is missing or malformed
    /// (treats partial writes as if the cache were empty — the
    /// resolver then falls through to a full IPNS+chain resolve).
    pub(crate) fn load_users_index_state(
        &self,
    ) -> Result<Option<(Cid, u64, u64)>, BlockCacheError> {
        let read = self.inner.db.begin_read()?;
        let table = read.open_table(METADATA)?;

        let cid_bytes = match table.get(META_USERS_INDEX_CID)? {
            Some(v) => v.value().to_vec(),
            None => return Ok(None),
        };
        let cid = match Cid::try_from(cid_bytes.as_slice()) {
            Ok(c) => c,
            // Malformed → treat as no state (defensive). Don't
            // surface as Corrupt — that would block all hot-start
            // reads on a single bad row instead of degrading to a
            // fresh resolve.
            Err(e) => {
                tracing::warn!(error = %e, "users-index metadata: invalid CID; treating as empty");
                return Ok(None);
            }
        };

        let seq_bytes = match table.get(META_USERS_INDEX_SEQUENCE)? {
            Some(v) => v.value().to_vec(),
            None => return Ok(None),
        };
        let observed_bytes = match table.get(META_USERS_INDEX_OBSERVED_AT)? {
            Some(v) => v.value().to_vec(),
            None => return Ok(None),
        };
        if seq_bytes.len() != 8 || observed_bytes.len() != 8 {
            tracing::warn!("users-index metadata: malformed length; treating as empty");
            return Ok(None);
        }

        let mut seq = [0u8; 8];
        seq.copy_from_slice(&seq_bytes);
        let mut obs = [0u8; 8];
        obs.copy_from_slice(&observed_bytes);

        Ok(Some((
            cid,
            u64::from_be_bytes(seq),
            u64::from_be_bytes(obs),
        )))
    }

    /// Issue #8 fix #2 — store the raw list-buckets XML body, scoped
    /// to the JWT-derived `scope` key, so a subsequent master-down
    /// call by the SAME user can serve it offline.
    ///
    /// `scope` is `sha256(access_token)[..16]` hex — see
    /// `FulaClient::list_buckets_cache_scope`. Per-JWT scoping
    /// prevents cross-account pollution on shared cache files: user
    /// A's cached XML cannot be served to user B even if both share
    /// the same redb file.
    ///
    /// Overwrites on each call (one row per scope). The freshness
    /// timestamp is stored alongside so callers can surface staleness.
    pub(crate) fn store_list_buckets_xml(
        &self,
        scope: &str,
        xml: &str,
        observed_at_unix: u64,
    ) -> Result<(), BlockCacheError> {
        let (xml_key, obs_key) = list_buckets_keys(scope);
        let txn = self.inner.db.begin_write()?;
        {
            let mut table = txn.open_table(METADATA)?;

            // Prune stale scopes: when JWTs rotate (e.g., every few
            // hours), each new token derives a new `scope` key. Without
            // pruning, every prior scope's rows linger forever in the
            // METADATA table (one user × 24 rotations/day × 1 KB ≈
            // 9 MB/year, never reclaimed since METADATA isn't LRU-evicted).
            //
            // Policy: keep only the current scope's two rows. Past
            // scopes are unreachable anyway (no live JWT can derive
            // them), so dropping them loses nothing.
            //
            // O(n) over METADATA where n is "JWT-rotation history" —
            // bounded by usage pattern, but a few-hundred entries is
            // negligible.
            let prefix = META_LIST_BUCKETS_PREFIX.as_bytes();
            let mut to_remove: Vec<Vec<u8>> = Vec::new();
            for entry in table.iter()? {
                let (k, _) = entry?;
                let key_bytes = k.value();
                if key_bytes.starts_with(prefix)
                    && key_bytes != xml_key.as_slice()
                    && key_bytes != obs_key.as_slice()
                {
                    to_remove.push(key_bytes.to_vec());
                }
            }
            for k in to_remove {
                table.remove(k.as_slice())?;
            }

            table.insert(xml_key.as_slice(), xml.as_bytes())?;
            table.insert(obs_key.as_slice(), observed_at_unix.to_be_bytes().as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    /// Issue #8 fix #2 — load the previously-cached list-buckets XML
    /// body scoped to `scope`. Returns `None` if no entry exists for
    /// THIS JWT. Returns the observed-at-unix timestamp alongside so
    /// the caller can surface staleness.
    pub(crate) fn load_list_buckets_xml(
        &self,
        scope: &str,
    ) -> Result<Option<(String, u64)>, BlockCacheError> {
        let (xml_key, obs_key) = list_buckets_keys(scope);
        let read = self.inner.db.begin_read()?;
        let table = read.open_table(METADATA)?;
        let xml_bytes = match table.get(xml_key.as_slice())? {
            Some(v) => v.value().to_vec(),
            None => return Ok(None),
        };
        let xml = match String::from_utf8(xml_bytes) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, "list_buckets cache: invalid UTF-8; treating as empty");
                return Ok(None);
            }
        };
        let observed_at = match table.get(obs_key.as_slice())? {
            Some(v) => {
                let bytes = v.value();
                if bytes.len() != 8 {
                    tracing::warn!("list_buckets cache: malformed observed_at length; treating as 0");
                    0
                } else {
                    let mut buf = [0u8; 8];
                    buf.copy_from_slice(bytes);
                    u64::from_be_bytes(buf)
                }
            }
            None => 0,
        };
        Ok(Some((xml, observed_at)))
    }

    /// Evict LRU entries until `current_bytes <= target_bytes`. Caller
    /// must hold `evict_lock`. Atomic via a single redb write txn.
    fn evict_to(&self, target_bytes: u64) -> Result<(), BlockCacheError> {
        // Snapshot meta entries sorted by last-access ascending. At
        // 256 MiB / 1 KiB blocks this is ~256 k entries — a few hundred
        // microseconds. Acceptable.
        let txn = self.inner.db.begin_write()?;
        let mut entries: Vec<(Vec<u8>, u64)> = {
            let meta = txn.open_table(META)?;
            meta.iter()?
                .filter_map(Result::ok)
                .map(|(k, v)| (k.value().to_vec(), v.value()))
                .collect()
        };
        entries.sort_by_key(|(_, ts)| *ts);

        let mut bytes_freed: u64 = 0;
        let mut evicted_keys: Vec<Vec<u8>> = Vec::new();
        let cur = self.inner.current_bytes.load(Ordering::Acquire);
        let need = cur.saturating_sub(target_bytes);

        {
            let mut blocks = txn.open_table(BLOCKS)?;
            let mut meta = txn.open_table(META)?;
            for (key, _ts) in entries {
                if bytes_freed >= need {
                    break;
                }
                let block_size = blocks
                    .get(key.as_slice())?
                    .map(|v| v.value().len() as u64)
                    .unwrap_or(0);
                blocks.remove(key.as_slice())?;
                meta.remove(key.as_slice())?;
                bytes_freed = bytes_freed.saturating_add(block_size);
                evicted_keys.push(key);
            }
        }
        txn.commit()?;

        self.inner
            .current_bytes
            .fetch_sub(bytes_freed, Ordering::AcqRel);
        tracing::debug!(
            evicted = evicted_keys.len(),
            bytes_freed = bytes_freed,
            target = target_bytes,
            "block_cache: LRU eviction complete"
        );
        Ok(())
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Phase 2.4 — derive the redb-key for the KEY_TO_CID table.
///
/// `BLAKE3("fula:block-cache:key-to-cid:v1" || bucket || 0x00 || key)[..32]`.
/// Domain separator pins the namespace; the embedded `0x00` between
/// bucket and key forecloses any ambiguity from S3 keys that contain
/// `/` (a single concatenation without separator could collide
/// `bucket=foo, key=bar` with `bucket=foo/bar, key=`). 32-byte output
/// is fixed-length for fast B-tree lookups.
fn derive_key_cid_lookup(bucket: &str, key: &str) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"fula:block-cache:key-to-cid:v1");
    hasher.update(bucket.as_bytes());
    hasher.update(&[0u8]);
    hasher.update(key.as_bytes());
    let h = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(h.as_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use cid::multihash::Multihash;
    use std::time::Duration;
    use tempfile::TempDir;

    /// Build a deterministic CID from a small u64 seed for test fixtures.
    fn test_cid(seed: u64) -> Cid {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&seed.to_le_bytes());
        let mh = Multihash::<64>::wrap(0x1e /* blake3 */, &bytes).unwrap();
        Cid::new_v1(0x55 /* raw */, mh)
    }

    fn open_cache(dir: &TempDir, max: u64) -> BlockCache {
        BlockCache::open(dir.path().join("cache.redb"), max).expect("open")
    }

    #[tokio::test]
    async fn test_put_get_roundtrip() {
        let dir = TempDir::new().unwrap();
        let cache = open_cache(&dir, 1024 * 1024);

        let cid = test_cid(1);
        let data = b"hello world";
        cache.put(&cid, data).await.expect("put");

        let got = cache.get(&cid).expect("get").expect("hit");
        assert_eq!(got.as_ref(), data);
    }

    #[tokio::test]
    async fn test_get_missing_returns_none() {
        let dir = TempDir::new().unwrap();
        let cache = open_cache(&dir, 1024 * 1024);

        let cid = test_cid(42);
        assert!(cache.get(&cid).expect("get").is_none());
    }

    #[tokio::test]
    async fn test_persistence_across_open_close() {
        // Backward-compat-critical: an existing on-disk cache must
        // survive an SDK restart and serve cached blocks.
        let dir = TempDir::new().unwrap();
        let cid = test_cid(7);
        let data = b"persistent block bytes";

        {
            let cache = open_cache(&dir, 1024 * 1024);
            cache.put(&cid, data).await.expect("put");
            // drop happens at end of scope
        }
        {
            let cache = open_cache(&dir, 1024 * 1024);
            let got = cache.get(&cid).expect("get").expect("survived restart");
            assert_eq!(got.as_ref(), data);
            // current_bytes is correctly re-synced from the DB on open.
            assert_eq!(cache.current_bytes(), data.len() as u64);
        }
    }

    #[tokio::test]
    async fn test_idempotent_put_does_not_grow() {
        // Re-inserting the same CID with identical bytes must not double-count.
        let dir = TempDir::new().unwrap();
        let cache = open_cache(&dir, 1024 * 1024);
        let cid = test_cid(5);
        let data = vec![0u8; 4096];

        cache.put(&cid, &data).await.expect("put 1");
        let after_first = cache.current_bytes();
        cache.put(&cid, &data).await.expect("put 2");
        let after_second = cache.current_bytes();

        assert_eq!(after_first, data.len() as u64);
        assert_eq!(after_second, after_first, "re-insert must not grow current_bytes");
        assert_eq!(cache.entry_count().expect("count"), 1);
    }

    #[tokio::test]
    async fn test_eviction_on_overflow_keeps_size_under_budget() {
        // Insert N blocks of size B each, with budget = (N/2) * B.
        // After all inserts settle, current_bytes <= max_bytes * 100/100.
        // (We aim for the 80 % low watermark on each eviction.)
        let dir = TempDir::new().unwrap();
        let block_size = 16 * 1024; // 16 KiB
        let n_blocks = 20;
        let budget = (n_blocks as u64 / 2) * block_size; // ~10 blocks fit

        let cache = open_cache(&dir, budget);

        for i in 0..n_blocks {
            let cid = test_cid(i);
            let data = vec![i as u8; block_size as usize];
            cache.put(&cid, &data).await.expect("put");
        }

        let cur = cache.current_bytes();
        assert_eq!(cache.max_bytes(), budget, "max_bytes accessor returns the configured budget");
        assert!(
            cur <= budget,
            "current_bytes {} must be <= max_bytes {}",
            cur,
            budget
        );
        // We had eviction (otherwise current_bytes would equal n_blocks * block_size).
        assert!(
            cur < (n_blocks as u64) * block_size,
            "expected at least one eviction; current={}, total-without-evict={}",
            cur,
            (n_blocks as u64) * block_size
        );
    }

    #[tokio::test]
    async fn test_lru_oldest_evicted_first() {
        // Insert 3 blocks; access #0 to refresh it; insert a 4th to
        // trigger eviction. The evicted block must be #1 (oldest
        // last-access), NOT #0 (just accessed).
        let dir = TempDir::new().unwrap();
        let block_size = 1024;
        // Budget exactly 3 blocks — the 4th insert must evict.
        let cache = open_cache(&dir, 3 * block_size);

        let data = vec![0u8; block_size as usize];
        cache.put(&test_cid(0), &data).await.expect("put 0");
        // Sleep 5ms so timestamps are reliably ordered.
        tokio::time::sleep(Duration::from_millis(5)).await;
        cache.put(&test_cid(1), &data).await.expect("put 1");
        tokio::time::sleep(Duration::from_millis(5)).await;
        cache.put(&test_cid(2), &data).await.expect("put 2");
        tokio::time::sleep(Duration::from_millis(5)).await;

        // Refresh #0 → it becomes the most-recently-accessed.
        let _ = cache.get(&test_cid(0)).expect("get 0").expect("hit 0");
        tokio::time::sleep(Duration::from_millis(5)).await;

        // Insert #3 → must evict (low-watermark = 80% of 3 = 2.4 blocks
        // of budget; eviction frees enough to fit the new 1-block).
        cache.put(&test_cid(3), &data).await.expect("put 3");

        // #1 (oldest) should be gone; #0 (refreshed) should still be
        // present.
        assert!(
            cache.get(&test_cid(0)).expect("get").is_some(),
            "refreshed #0 must survive eviction"
        );
        assert!(
            cache.get(&test_cid(1)).expect("get").is_none(),
            "oldest #1 must be evicted"
        );
    }

    #[tokio::test]
    async fn test_concurrent_puts_no_corruption_under_eviction() {
        // The hard concurrency case: K concurrent puts, each within
        // budget alone, but K-puts collectively over-budget. Verify
        // post-condition: current_bytes <= max_bytes.
        let dir = TempDir::new().unwrap();
        let block_size = 4 * 1024; // 4 KiB
        let n_concurrent = 16;
        // Budget = half of total → at least half must be evicted.
        let budget = (n_concurrent as u64 / 2) * block_size;

        let cache = open_cache(&dir, budget);

        let mut handles = Vec::new();
        for i in 0..n_concurrent {
            let cache = cache.clone();
            let data = vec![i as u8; block_size as usize];
            let cid = test_cid(i);
            handles.push(tokio::spawn(async move {
                cache.put(&cid, &data).await
            }));
        }
        for h in handles {
            h.await.expect("task panicked").expect("put failed");
        }

        // The mutex + watermark policy guarantees we never permanently
        // exceed budget — even though briefly between checks we might
        // see a transient overshoot.
        let cur = cache.current_bytes();
        assert!(
            cur <= budget,
            "post-concurrency current_bytes {} > budget {}",
            cur,
            budget
        );
    }

    #[tokio::test]
    async fn test_block_too_large_returns_typed_error() {
        // A block larger than the entire cache budget must surface as
        // BlockTooLarge — not as a generic Redb(...) string error —
        // so Phase 2.4 can dispatch on it cleanly ("skip caching,
        // fetch directly").
        let dir = TempDir::new().unwrap();
        let cache = open_cache(&dir, 1024); // 1 KiB budget

        let cid = test_cid(99);
        let big_block = vec![0u8; 4096]; // 4 KiB > 1 KiB budget

        match cache.put(&cid, &big_block).await {
            Err(BlockCacheError::BlockTooLarge { size, budget }) => {
                assert_eq!(size, 4096);
                assert_eq!(budget, 1024);
            }
            other => panic!("expected BlockTooLarge, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_idempotent_open_after_clean_shutdown() {
        // Simulates: SDK opens cache, writes, drops cleanly, re-opens.
        // This is the common case for short-lived CLIs.
        let dir = TempDir::new().unwrap();
        for round in 0..3 {
            let cache = open_cache(&dir, 1024 * 1024);
            let cid = test_cid(round as u64 * 100);
            let data = vec![round as u8; 256];
            cache.put(&cid, &data).await.expect("put");
            assert!(cache.get(&cid).expect("get").is_some());
            // current_bytes should equal data sizes accumulated across rounds.
            assert!(cache.current_bytes() >= 256);
        }
    }

    // ============================================================
    // Phase 2.4 — KEY_TO_CID lookup table tests
    // ============================================================

    #[tokio::test]
    async fn test_record_and_lookup_key_cid_roundtrip() {
        let dir = TempDir::new().unwrap();
        let cache = open_cache(&dir, 1024 * 1024);

        let cid = test_cid(123);
        cache
            .record_key_cid("photos", "vacation/dsc_001.jpg", &cid)
            .expect("record");

        let got = cache
            .lookup_cid("photos", "vacation/dsc_001.jpg")
            .expect("lookup")
            .expect("present");
        assert_eq!(got, cid, "round-trip yields the exact CID");
    }

    #[tokio::test]
    async fn test_lookup_missing_key_returns_none() {
        let dir = TempDir::new().unwrap();
        let cache = open_cache(&dir, 1024 * 1024);
        let got = cache.lookup_cid("photos", "never-seen.jpg").expect("lookup");
        assert!(got.is_none(), "cold-start must return None, not error");
    }

    #[tokio::test]
    async fn test_record_idempotent_on_repeat() {
        // Re-recording the same (bucket, key, cid) triple must not error,
        // and the lookup must continue returning the same CID. This is
        // load-bearing: the offline-fallback wrapper records on every
        // master-up read, so the same object will be re-recorded on each
        // refetch.
        let dir = TempDir::new().unwrap();
        let cache = open_cache(&dir, 1024 * 1024);

        let cid = test_cid(7);
        for _ in 0..5 {
            cache.record_key_cid("docs", "tax/2024.pdf", &cid).expect("record");
        }
        let got = cache.lookup_cid("docs", "tax/2024.pdf").expect("lookup").expect("hit");
        assert_eq!(got, cid);
    }

    #[tokio::test]
    async fn test_record_overwrites_when_cid_changes() {
        // After an object is updated on master, the etag (= CID)
        // changes. The next master-up read records the NEW CID under
        // the same `(bucket, key)` — and the old CID entry is replaced.
        // Otherwise offline reads would serve a stale block forever.
        let dir = TempDir::new().unwrap();
        let cache = open_cache(&dir, 1024 * 1024);

        let cid_v1 = test_cid(1);
        let cid_v2 = test_cid(2);

        cache.record_key_cid("photos", "live.jpg", &cid_v1).expect("v1");
        cache.record_key_cid("photos", "live.jpg", &cid_v2).expect("v2");

        let got = cache.lookup_cid("photos", "live.jpg").expect("lookup").expect("hit");
        assert_eq!(got, cid_v2, "must reflect the latest recorded CID");
        assert_ne!(got, cid_v1);
    }

    #[tokio::test]
    async fn test_distinct_buckets_dont_collide() {
        // Same key in different buckets must map to distinct CIDs. The
        // BLAKE3 domain-separated lookup-key derivation guarantees this;
        // a regression here would mean two users seeing each other's data
        // via the offline path.
        let dir = TempDir::new().unwrap();
        let cache = open_cache(&dir, 1024 * 1024);

        let cid_a = test_cid(10);
        let cid_b = test_cid(11);

        cache.record_key_cid("alice-bucket", "shared.txt", &cid_a).expect("a");
        cache.record_key_cid("bob-bucket", "shared.txt", &cid_b).expect("b");

        let got_a = cache
            .lookup_cid("alice-bucket", "shared.txt")
            .expect("lookup")
            .expect("hit");
        let got_b = cache
            .lookup_cid("bob-bucket", "shared.txt")
            .expect("lookup")
            .expect("hit");
        assert_eq!(got_a, cid_a);
        assert_eq!(got_b, cid_b);
        assert_ne!(got_a, got_b, "isolation between buckets is mandatory");
    }

    #[tokio::test]
    async fn test_key_to_cid_survives_restart() {
        // Same persistence contract as the BLOCKS table: lookups must
        // survive SDK process restart. Without this, every SDK launch
        // would degrade to "cold start until the cache repopulates",
        // which defeats the warm-device offline guarantee.
        let dir = TempDir::new().unwrap();
        let cid = test_cid(99);

        {
            let cache = open_cache(&dir, 1024 * 1024);
            cache
                .record_key_cid("persist-bucket", "important.bin", &cid)
                .expect("record");
        }
        {
            let cache = open_cache(&dir, 1024 * 1024);
            let got = cache
                .lookup_cid("persist-bucket", "important.bin")
                .expect("lookup")
                .expect("hit after restart");
            assert_eq!(got, cid);
        }
    }

    #[test]
    fn test_derive_key_cid_lookup_is_deterministic() {
        // Same inputs → same hash. Required for repeated record/lookup
        // to land in the same redb key.
        let h1 = derive_key_cid_lookup("foo", "bar");
        let h2 = derive_key_cid_lookup("foo", "bar");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_derive_key_cid_lookup_separator_prevents_concat_collision() {
        // The 0x00 byte between bucket and key is load-bearing.
        // Without it, ("foo/bar", "") and ("foo", "/bar") would collide.
        // With it, they hash differently because the null byte is
        // disambiguating.
        let h1 = derive_key_cid_lookup("foo/bar", "");
        let h2 = derive_key_cid_lookup("foo", "/bar");
        assert_ne!(h1, h2, "domain separator must prevent concat-collision");
    }

    #[test]
    fn test_derive_key_cid_lookup_outputs_32_bytes() {
        let h = derive_key_cid_lookup("any-bucket", "any-key");
        assert_eq!(h.len(), 32, "BLAKE3 output is exactly 32 bytes");
    }

    // ============================================================
    // Phase 3.3.5 — METADATA table tests
    // ============================================================

    #[tokio::test]
    async fn test_load_users_index_state_returns_none_on_fresh_cache() {
        let dir = TempDir::new().unwrap();
        let cache = open_cache(&dir, 1024 * 1024);
        let got = cache.load_users_index_state().expect("load");
        assert!(
            got.is_none(),
            "fresh cache must have no resolver state — full IPNS+chain resolve required on first run"
        );
    }

    #[tokio::test]
    async fn test_store_and_load_users_index_state_roundtrip() {
        let dir = TempDir::new().unwrap();
        let cache = open_cache(&dir, 1024 * 1024);
        let cid = test_cid(0xab);

        cache
            .store_users_index_state(&cid, 42, 1_700_000_000)
            .expect("store");

        let (got_cid, got_seq, got_observed) = cache
            .load_users_index_state()
            .expect("load")
            .expect("present");
        assert_eq!(got_cid, cid);
        assert_eq!(got_seq, 42);
        assert_eq!(got_observed, 1_700_000_000);
    }

    #[tokio::test]
    async fn test_users_index_state_survives_restart() {
        // Replay-defense critical: the `(cid, sequence)` floor MUST
        // persist across SDK restarts so a malicious gateway can't
        // serve a stale-but-valid payload to a fresh process.
        let dir = TempDir::new().unwrap();
        let cid = test_cid(0xee);

        {
            let cache = open_cache(&dir, 1024 * 1024);
            cache
                .store_users_index_state(&cid, 99, 1_700_000_999)
                .expect("store");
        }
        {
            let cache = open_cache(&dir, 1024 * 1024);
            let (got_cid, got_seq, got_obs) = cache
                .load_users_index_state()
                .expect("load")
                .expect("survived");
            assert_eq!(got_cid, cid);
            assert_eq!(got_seq, 99);
            assert_eq!(got_obs, 1_700_000_999);
        }
    }

    #[tokio::test]
    async fn test_store_users_index_state_overwrites() {
        // Each successful resolver run writes the latest `(cid, seq, ts)`.
        // A subsequent write must overwrite the prior row, not stack.
        let dir = TempDir::new().unwrap();
        let cache = open_cache(&dir, 1024 * 1024);

        let cid_v1 = test_cid(1);
        cache.store_users_index_state(&cid_v1, 5, 100).expect("v1");

        let cid_v2 = test_cid(2);
        cache.store_users_index_state(&cid_v2, 10, 200).expect("v2");

        let (got_cid, got_seq, got_obs) = cache
            .load_users_index_state()
            .expect("load")
            .expect("hit");
        assert_eq!(got_cid, cid_v2);
        assert_eq!(got_seq, 10);
        assert_eq!(got_obs, 200);
    }
}
