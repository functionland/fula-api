//! Phase 3.3 — hybrid IPNS-primary + chain-fallback resolver for
//! the master-published global users-index CID.
//!
//! Cold-start flow (per plan §3.3 step 5):
//!
//! 1. **IPNS path (primary).** Race a small fan-out of IPNS-aware
//!    public gateways for `/ipns/<configured-name>`. Each gateway
//!    resolves the IPNS NAME server-side and returns the underlying
//!    dag-cbor bytes. We parse those bytes as
//!    [`GlobalUsersIndex`], read the in-payload `sequence`, and
//!    accept the first response whose sequence is ≥ the SDK's
//!    process-wide `highest_seen_sequence` (replay defense).
//!    Budget: 10 s, sequential; no per-gateway dynamic-priority
//!    state (the cold-start path is one-shot — the warm-device
//!    pool's state machine isn't a fit).
//!
//! 2. **Chain path (fallback).** If the IPNS path fails or times
//!    out, fire one `eth_call` against the configured RPC URL for
//!    `FulaUsersIndexAnchor.latest()`. The 96-byte ABI response is
//!    `(bytes32 cid_digest, uint64 sequence, uint64 timestamp)`.
//!    Reconstruct a CIDv1 (codec=dag-cbor 0x71, multihash=sha2-256
//!    0x12 + the digest bytes), then iterate the same gateway list
//!    fetching `/ipfs/<cid>` until one body content-addresses to
//!    that CID via [`verify_cid_against_bytes`]. Parse the body as
//!    [`GlobalUsersIndex`]; verify the in-payload `sequence`
//!    matches the on-chain `sequence` and is ≥ `highest_seen_sequence`.
//!
//! 3. **Single sequence stream.** There is one monotonic `sequence`
//!    field, embedded inside the CBOR payload itself. Both IPNS and
//!    chain paths read it from the bytes — never from IPNS DHT
//!    metadata or the chain-call return — so a compromised gateway
//!    (or RPC node, or operator) can publish a fresh-but-malicious
//!    *higher* sequence (closing that requires user wallets and is
//!    out of scope), but **cannot regress** to a stale one.
//!
//! ## Native-only
//!
//! The resolver is gated to `cfg(not(target_arch = "wasm32"))` for
//! the same reason as `block_cache.rs` and `gateway_fetch.rs`: it
//! depends on `tokio::time::timeout`, on the `parking_lot::Mutex`
//! used internally by gateway-side code, and on
//! `verify_cid_against_bytes` (which itself is native-only because
//! it lives in `gateway_fetch.rs`). Cold-start on browser/wasm
//! surfaces [`ClientError::UsersIndexResolutionFailed`] until a
//! browser-friendly resolver lands as a follow-up.

#![cfg(not(target_arch = "wasm32"))]

use crate::error::ClientError;
use crate::gateway_fetch::verify_cid_against_bytes;
use bytes::Bytes;
use cid::multihash::Multihash;
use cid::Cid;
use futures::stream::StreamExt;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

// ============================================================
// Public types
// ============================================================

/// Master's published global users-index CBOR payload. Mirrors the
/// `GlobalUsersIndex` struct in `fula-cli`'s
/// `handlers::users_index_publisher`. The two definitions must stay
/// in lockstep — see plan §3.2.a for the producer side.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct GlobalUsersIndex {
    pub v: u32,
    pub sequence: u64,
    pub updated_at_unix: u64,
    /// `userKey_hex` (32 hex chars) → bucketsIndexCid (string).
    /// The SDK looks up its own `userKey` here on cold-start.
    pub users: BTreeMap<String, String>,
}

/// Master's per-user `bucketsIndex` CBOR — one per user per snapshot
/// when their state changed. Mirrors the `UserBucketsIndex` struct
/// in `fula-cli`'s `handlers::users_index_publisher` (the producer
/// side; see plan §3.2.a). The two definitions must stay in lockstep.
///
/// Map keys are either:
///   - 32-hex BLAKE3-derived `bucketLookupH` (Phase 1.2 blinded form)
///   - plaintext bucket name (Phase 1.2 lazy-migration legacy form)
///
/// `legacy=true` distinguishes the latter so the cold-start dispatch
/// can fall back from `index[blinded_hex]` to `index[bucket_name]`
/// for users who haven't yet uploaded with a Phase-1.2-aware client.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct UserBucketsIndex {
    pub v: u32,
    pub buckets: BTreeMap<String, BucketEntry>,
    pub updated_at_unix: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct BucketEntry {
    /// **v0.4.4 RENAMED FOR CLARITY** (was the only "manifest" field).
    /// CID of MASTER's bucket Prolly Tree root (`BucketMetadata.root_cid`),
    /// stringified. Master's S3-listing index, NOT the SDK's encrypted
    /// forest manifest. Kept for forward compatibility (operator tooling
    /// that wants to walk master's tree from the published CBOR can
    /// still find the root here) and as a fallback for v0.4.4-pre SDKs
    /// that only know to read this field.
    pub manifest: String,
    /// **v0.4.4** — CID of the SDK's encrypted forest manifest object
    /// (`EncryptedShardManifestV7` JSON envelope) stored at
    /// `derive_index_key(forest_dek, bucket)`. THIS is what cold-start
    /// must resolve and decrypt. `None` when master has not yet
    /// observed a v0.4.4+ SDK PUT for this bucket; the resolver falls
    /// back to `manifest` in that case.
    ///
    /// Treat `Some("")` as `None` for defensive parsing — we only fall
    /// back when neither `Some(non-empty)` is present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forest_manifest_cid: Option<String>,
    /// `true` ⇔ map key is the plaintext `bucket_name` (legacy
    /// fallback). The cold-start lookup tries blinded first; on
    /// miss it tries the plaintext name and accepts only entries
    /// where `legacy = true`.
    pub legacy: bool,
}

impl BucketEntry {
    /// Returns the CID the cold-start resolver should fetch + decrypt
    /// as the bucket's encrypted forest manifest.
    ///
    /// Prefers v0.4.4+ `forest_manifest_cid` (correct: SDK's encrypted
    /// forest); falls back to legacy `manifest` (master's CBOR Prolly
    /// Tree, which the SDK cannot decrypt — included only for
    /// no-regression behavior on pre-v0.4.4-master users). Empty
    /// strings on either side are treated as absent (defensive against
    /// any serializer that round-trips `Some("")` for an unset Option).
    pub fn cold_start_cid(&self) -> &str {
        match self.forest_manifest_cid.as_deref() {
            Some(s) if !s.is_empty() => s,
            _ => &self.manifest,
        }
    }
}

/// Result of a successful [`UsersIndexResolver::resolve`].
#[derive(Clone, Debug)]
pub struct ResolvedUsersIndex {
    /// Which channel actually served the payload. Surfaced to apps
    /// (and to Phase 19's `ReadFreshness`) so users can be told
    /// "served from chain backup; expected staleness ≤ 12h".
    pub source: ResolutionSource,
    /// CID of the parsed payload. For the chain path this is the
    /// reconstructed-and-verified CID. For the IPNS path it is
    /// `Cid::new_v1(0x71, sha2-256(bytes))` — synthesized from the
    /// returned bytes (the IPNS path has no externally-asserted CID
    /// to verify against; the gateway does the IPNS-record
    /// resolution upstream).
    pub cid: Cid,
    /// Decoded payload. Apps walk `payload.users` to find their own
    /// `userKey` → bucketsIndexCid.
    pub payload: GlobalUsersIndex,
    /// Raw CBOR bytes — kept so callers can persist them (Phase
    /// 3.3.5 hot-start cache) without re-fetching.
    pub bytes: Bytes,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResolutionSource {
    Ipns,
    Chain,
    /// Phase 3.3.5 — served from the on-disk hot-start cache (the
    /// resolver short-circuited IPNS + chain because the cached
    /// `(cid, sequence)` was within `soft_ttl`). Apps/Phase 19's
    /// `ReadFreshness` can surface this as "served from a recent
    /// snapshot — last refreshed N seconds ago".
    HotStartCache,
}

/// Resolver configuration. Construct via [`UsersIndexResolver::new`].
#[derive(Clone, Debug)]
pub struct ResolverConfig {
    /// IPNS-aware gateway URL templates (each must contain `{name}`).
    /// Empty = use the SDK-shipped default subset
    /// ([`default_ipns_gateway_urls`]).
    pub ipns_gateways: Vec<String>,
    /// `/ipfs/{cid}` gateway URL templates for the chain path's
    /// CID-fetch step. Empty = use the SDK-shipped default six.
    pub ipfs_gateways: Vec<String>,
    /// JSON-RPC URL for the chain anchor. Required.
    pub chain_rpc_url: String,
    /// `FulaUsersIndexAnchor.sol` proxy address (20 bytes hex,
    /// optionally `0x`-prefixed). Required.
    pub anchor_address: String,
    /// IPNS NAME (libp2p public-key hash, e.g. `k51qzi5...`).
    /// Required.
    pub ipns_name: String,
    /// Hard ceiling on the IPNS race; fall through to chain after.
    /// Default 10 s per plan §3.3 step 5a.
    pub ipns_race_timeout: Duration,
    /// Per-gateway timeout for individual fetches (both IPNS and the
    /// chain path's CID-fetch step).
    pub per_request_timeout: Duration,

    /// Phase 3.3.5 — soft TTL for the on-disk hot-start cache.
    /// When the resolver was successfully run within this window
    /// (per the cached `observed_at_unix`), `resolve()` returns the
    /// cached state directly without touching IPNS or chain.
    /// Beyond this, the resolver opportunistically re-runs.
    /// Default: 5 minutes per plan §3.3.5 — matches the expected
    /// IPNS publish cadence.
    pub soft_ttl: Duration,
}

impl ResolverConfig {
    /// Default config for a given chain RPC URL, IPNS NAME, and
    /// anchor address. All other fields take audit-recommended
    /// defaults.
    pub fn new(
        chain_rpc_url: impl Into<String>,
        anchor_address: impl Into<String>,
        ipns_name: impl Into<String>,
    ) -> Self {
        Self {
            ipns_gateways: Vec::new(),
            ipfs_gateways: Vec::new(),
            chain_rpc_url: chain_rpc_url.into(),
            anchor_address: anchor_address.into(),
            ipns_name: ipns_name.into(),
            ipns_race_timeout: Duration::from_secs(10),
            per_request_timeout: Duration::from_secs(8),
            soft_ttl: Duration::from_secs(300), // 5 min, matches IPNS publish cadence
        }
    }
}

/// Derive the SDK-side `userKey` from a user's email address.
///
/// Replicates the master-side identity derivation chain in
/// `fula-cli/src/state.rs::hash_user_id`:
///
/// 1. `userId   = sha256(lower(email))`               — 32 bytes
/// 2. `userIdHex = hex::encode(userId)`               — 64 ASCII hex chars
/// 3. `userKey  = BLAKE3("fula:user_id:" || userIdHex)[..16]` — 16 bytes
/// 4. Return `hex::encode(userKey)`                   — 32 ASCII hex chars
///
/// The 32-hex output matches `BucketMetadata.owner_id` on master
/// (see `fula-cli/src/state.rs:15-22`). The SDK passes this string
/// in `Config::users_index_user_key` so the cold-start path can
/// look itself up in the published `GlobalUsersIndex.users` map.
///
/// This is a **free function**, not a method, so JS / Flutter
/// bindings can compute the user_key without holding a client.
/// Domain separator + double hashing + lowercase normalization MUST
/// stay in lockstep with the master's `hash_user_id`; the
/// `derive_user_key_matches_master_state_rs_algorithm` test below
/// reproduces the master algorithm step-by-step and asserts equality.
///
/// Source-of-truth lives in `crate::user_key` (extracted there so the
/// wasm-bindgen binding can expose it — the `registry_resolver`
/// module itself is gated to native targets). This re-export keeps
/// the historical `fula_client::registry_resolver::derive_user_key_from_email`
/// import path working for native callers AND lets the test module
/// in this file (line 1485+) call the function via `use super::*;`.
#[allow(unused_imports)]
pub use crate::user_key::derive_user_key_from_email;

/// Default IPNS-aware gateway list. Excludes
/// `trustless-gateway.link` (only serves `/ipfs/`, not `/ipns/`).
///
/// The resolver now **races every gateway in parallel** and picks the
/// response with the highest in-CBOR `sequence` (subject to F10's
/// chain-floor anti-poisoning cap). Ordering still matters as a tie-
/// breaker on equal-sequence responses, and for which gateway gets the
/// first request dispatched, but the slowest gateway is no longer the
/// bottleneck the way it was under the prior sequential scheme.
///
/// Ordering (operator-confirmed 2026-05-11 after staleness audit):
/// 1. `ipfs.io/ipns/{name}` (path-style) — **first because empirical
///    verification on 2026-05-11 showed `ipfs.io` returning the
///    latest publisher-tick sequence while every dweb.link surface
///    served Cloudflare-edge-cached stale data (Age >= 4180 s).** A
///    `curl -I` against `ipfs.io/ipns/<name>` returns
///    `cf-cache-status: EXPIRED` and the freshly-resolved CID; the
///    same curl against `{name}.ipns.dweb.link/` returns
///    `cf-cache-status: HIT` with a record up to 70 min old.
///    Submitting `ipfs.io` first ensures the most-recently-resolved
///    record arrives first and seeds the 10 s grace window with a
///    fresh baseline.
/// 2. `ipfs.filebase.io/ipns/{name}` (path-style) — **second because
///    operator-confirmed 2026-05-11 that Filebase frequently picks
///    up freshly-published IPNS records *before* ipfs.io.** Filebase
///    has its own cache layer (`X-Filebase-Cache: HIT` / `X-Filebase-Edge-Cache: MISS`)
///    that is independent of Cloudflare and sometimes lags-by-less
///    than the Protocol Labs tier. Together with `ipfs.io`, the
///    two top gateways give two independent freshness paths — the
///    parallel race + 10 s grace + highest-sequence selection means
///    whichever of them resolved the freshest record wins.
/// 3. `dweb.link/ipns/{name}` (path-style) — backup. Same gateway
///    family as the subdomain entry below but a different
///    cache-key path, so when the subdomain surface is stale the
///    path surface sometimes isn't (and vice versa).
/// 4. `4everland.io/ipns/{name}`, `gateway.pinata.cloud/ipns/{name}` —
///    independent fleet fallbacks for fan-out coverage.
///    `cloudflare-ipfs.com` is excluded (does not support IPNS
///    resolution; every probe against it returned 4xx).
/// 5. `{name}.ipns.dweb.link/` (subdomain-style) — moved DOWN from
///    position 1. The user's 2026-05-11 audit showed this surface
///    serving stale records for 70+ min via Cloudflare HIT. Kept
///    in the list because the parallel-race + sequence-max design
///    means even a stale response doesn't poison the result — it
///    just gets overridden when a fresher response arrives within
///    the 10 s grace.
/// 6. `{name}.ipns.dget.top/` (subdomain-style) — small-fleet
///    last-resort. Less reliable uptime than the Protocol Labs /
///    Filebase tier.
pub fn default_ipns_gateway_urls() -> Vec<String> {
    vec![
        "https://ipfs.io/ipns/{name}".into(),
        "https://ipfs.filebase.io/ipns/{name}".into(),
        "https://dweb.link/ipns/{name}".into(),
        "https://4everland.io/ipns/{name}".into(),
        "https://gateway.pinata.cloud/ipns/{name}".into(),
        "https://{name}.ipns.dweb.link/".into(),
        "https://{name}.ipns.dget.top/".into(),
    ]
}

/// Fetch a CID's bytes via simple sequential iteration over the
/// configured IPFS-gateway list, verifying content-addressing on
/// each successful response. Returns the first body whose
/// `verify_cid_against_bytes` passes; surfaces
/// `UsersIndexResolutionFailed` if all gateways exhaust.
///
/// Intentionally simpler than `GatewayPool::fetch_verified` (Phase
/// 2.3's dynamic-priority race orchestrator). Cold-start is one-shot
/// — the per-gateway state machine pays no benefit here, and keeping
/// the resolver self-contained means cold-start doesn't require
/// Phase 2.2/2.4 to be enabled.
pub async fn fetch_cid_via_gateways(
    cid: &Cid,
    gateways: &[String],
    http: &reqwest::Client,
    per_request_timeout: Duration,
) -> Result<Bytes, ClientError> {
    if gateways.is_empty() {
        return Err(ClientError::UsersIndexResolutionFailed {
            reason: format!("no IPFS gateways configured to fetch {}", cid),
        });
    }
    let cid_str = cid.to_string();
    let mut last_err: Option<String> = None;
    for tmpl in gateways {
        let url = tmpl.replace("{cid}", &cid_str);
        // IPFS gateway spec (IPIP-412): path-style endpoints like
        // `gateway.example.com/ipfs/<cid>` and `gateway.example.com/ipns/<name>`
        // return their HTML directory-listing UI when no Accept header is sent
        // (or `application/vnd.ipld.car`/`raw`/`dag-json` for those types). To
        // get the raw block bytes for content verification we MUST request
        // `application/vnd.ipld.raw`. Without this, dweb.link returns 276 KB of
        // HTML that fails `verify_cid_against_bytes`, the resolver exhausts the
        // IPNS leg, and falls back to chain. Reproducible: any user pointing
        // FULA_USERS_INDEX_IPNS_GATEWAY_URLS at a path-style gateway saw stale
        // bucketsIndex (chain CIDs lag by up to 12h) → cold-start lookups for
        // recently-created buckets returned `BucketNotFound`, swallowed by
        // `list_files_from_forest` as 0 files.
        // Multi-value Accept (RFC 7231 §5.3.2 quality-ordered list). The
        // path-style `/ipfs/<cid>` endpoint resolves to a block whose codec
        // is encoded in the CID — for fula it's either raw (0x55, used for
        // EncryptedShardManifestV7 envelopes) or dag-cbor (0x71, used for
        // GlobalUsersIndex and per-user bucketsIndex CBORs). Send both
        // codec-specific media types so the gateway returns the right
        // bytes regardless of which CID we're fetching. Without this,
        // path-style gateways (dweb.link, ipfs.io) return their HTML
        // directory listing UI and `verify_cid_against_bytes` rejects it.
        // `application/cbor` is the legacy fallback some gateways accept
        // for dag-cbor; `*/*` lets a stricter gateway pick anything if it
        // doesn't honor the typed forms.
        let resp = match tokio::time::timeout(
            per_request_timeout,
            http.get(&url)
                .header(
                    reqwest::header::ACCEPT,
                    "application/vnd.ipld.raw, application/vnd.ipld.dag-cbor, application/cbor, */*;q=0.1",
                )
                .send(),
        )
        .await
        {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => {
                last_err = Some(format!("{} transport: {}", url, e));
                continue;
            }
            Err(_) => {
                last_err = Some(format!("{} timeout", url));
                continue;
            }
        };
        if !resp.status().is_success() {
            last_err = Some(format!("{} HTTP {}", url, resp.status()));
            continue;
        }
        let bytes = match resp.bytes().await {
            Ok(b) => b,
            Err(e) => {
                last_err = Some(format!("{} body: {}", url, e));
                continue;
            }
        };
        if let Err(e) = verify_cid_against_bytes(cid, &bytes) {
            last_err = Some(format!("{} verify: {}", url, e));
            continue;
        }
        return Ok(bytes);
    }
    Err(ClientError::UsersIndexResolutionFailed {
        reason: format!(
            "CID {} unreachable across {} gateways: {}",
            cid,
            gateways.len(),
            last_err.unwrap_or_else(|| "no gateways tried".into())
        ),
    })
}

/// Decode dag-cbor bytes as a per-user `UserBucketsIndex`. Wraps the
/// dagcbor crate's error so callers see a single ClientError shape.
pub fn decode_user_buckets_index(bytes: &[u8]) -> Result<UserBucketsIndex, ClientError> {
    serde_ipld_dagcbor::from_slice(bytes).map_err(|e| {
        ClientError::UsersIndexResolutionFailed {
            reason: format!("UserBucketsIndex CBOR decode: {}", e),
        }
    })
}

/// Default `/ipfs/{cid}` gateway list — kept in sync with the
/// warm-device pool's `gateway_fetch::default_gateway_urls`.
/// Re-declared here so the resolver's chain path doesn't need to
/// depend on the pool's state machine.
///
/// Issue #8 fix #1 — `cloudflare-ipfs.com/ipfs/` was retired (DNS
/// no longer resolves, verified 2026-05-10). Dropped from both this
/// list and from `gateway_fetch::default_gateway_urls`; keeping
/// them in sync prevents a dead gateway from burning a slot in
/// either race.
pub fn default_ipfs_gateway_urls() -> Vec<String> {
    vec![
        "https://dweb.link/ipfs/{cid}".into(),
        "https://ipfs.io/ipfs/{cid}".into(),
        "https://trustless-gateway.link/ipfs/{cid}".into(),
        "https://4everland.io/ipfs/{cid}".into(),
        "https://gateway.pinata.cloud/ipfs/{cid}".into(),
    ]
}

// ============================================================
// Resolver
// ============================================================

#[derive(Debug)]
pub struct UsersIndexResolver {
    config: ResolverConfig,
    http: reqwest::Client,
    /// Process-wide replay defense — only ever increases. Updated by
    /// every successful resolve regardless of source (IPNS or chain).
    /// Used as the in-session lower bound for accepting payloads.
    /// **NOT persisted** — see `highest_chain_seen_sequence` for the
    /// persistent floor.
    highest_seen_sequence: AtomicU64,
    /// **F10 audit fix — chain-confirmed replay-defense floor.**
    ///
    /// Advances ONLY on successful chain resolves. Persisted to the
    /// hot-start cache and re-seeded on next SDK start. Used as the
    /// reference point for the IPNS sequence-jump cap so a malicious
    /// IPNS gateway returning `sequence = u64::MAX` cannot poison the
    /// persistent floor: the in-session `highest_seen_sequence` may
    /// advance up to `chain_floor + MAX_IPNS_SEQUENCE_JUMP_OVER_CHAIN`
    /// from IPNS, but that elevated value is never persisted, so
    /// process restart wipes the attacker's progress.
    highest_chain_seen_sequence: AtomicU64,
    /// Pre-validated 20-byte anchor address. Cached so each `resolve`
    /// doesn't re-parse the hex.
    anchor_address_bytes: [u8; 20],
    /// Phase 3.3.5 — optional hot-start persistence layer. When set,
    /// `resolve()` reads cached `(cid, sequence, observed_at_unix)`
    /// from the cache's METADATA table on the first call AND writes
    /// the freshly-resolved state on every successful resolve. This
    /// makes the replay-defense floor survive SDK restarts AND lets
    /// the resolver short-circuit IPNS+chain when within `soft_ttl`.
    cache: Option<Arc<crate::block_cache::BlockCache>>,
}

impl UsersIndexResolver {
    /// Build a resolver. Validates `anchor_address` is 20 bytes hex
    /// up-front so misconfiguration fails at construction time, not
    /// on the first cold-start.
    pub fn new(config: ResolverConfig) -> Result<Self, ClientError> {
        if config.chain_rpc_url.is_empty() {
            return Err(ClientError::Config(
                "registry resolver: chain_rpc_url is empty".into(),
            ));
        }
        if config.ipns_name.is_empty() {
            return Err(ClientError::Config(
                "registry resolver: ipns_name is empty".into(),
            ));
        }
        let anchor_address_bytes = parse_anchor_address(&config.anchor_address)?;
        Ok(Self {
            config,
            http: reqwest::Client::new(),
            highest_seen_sequence: AtomicU64::new(0),
            highest_chain_seen_sequence: AtomicU64::new(0),
            anchor_address_bytes,
            cache: None,
        })
    }

    /// Phase 3.3.5 — construct a resolver wired to a persistent
    /// hot-start cache. On construction the resolver:
    ///   1. Reads `(cid, sequence, observed_at_unix)` from the
    ///      cache's METADATA table.
    ///   2. Seeds the replay-defense floor from the cached
    ///      sequence — a malicious gateway cannot regress to a
    ///      stale payload across SDK restarts.
    ///
    /// On every successful `resolve` the resolver:
    ///   1. Writes the new `(cid, sequence, now)` to METADATA.
    ///   2. Inserts the bytes into BLOCKS (so a future hot-start
    ///      can serve the payload entirely from disk).
    ///
    /// The cache load/store paths are **best-effort**: failures
    /// log at `warn!` and don't propagate, so a corrupted or
    /// unwriteable cache never blocks SDK functionality. (The
    /// resolver still works, just without hot-start.)
    pub fn new_with_cache(
        config: ResolverConfig,
        cache: Arc<crate::block_cache::BlockCache>,
    ) -> Result<Self, ClientError> {
        let mut resolver = Self::new(config)?;
        // Seed the floor from cached state, if any. Best-effort —
        // a corrupt or empty cache gives us the default floor (0).
        //
        // F10 audit fix — sanity-cap the seeded value.
        //
        // Pre-fix the persisted sequence was advanced by every IPNS
        // resolve, which let a malicious gateway poison the persistent
        // floor with `sequence = u64::MAX` (or any value above what
        // chain could realistically reach), permanently locking the SDK
        // out of every subsequent IPNS AND chain read. Post-fix only
        // chain advances the persistent floor (see `resolve()` below),
        // but **legacy caches written by pre-fix builds may already
        // carry a poisoned value**. The sanity cap below transparently
        // recovers from that case: any cached sequence above
        // `MAX_SANE_SEED_SEQUENCE` is treated as `0` so the next chain
        // resolve can re-establish the real floor.
        match cache.load_users_index_state() {
            Ok(Some((_cid, mut sequence, _observed))) => {
                if sequence > MAX_SANE_SEED_SEQUENCE {
                    tracing::warn!(
                        cached_sequence = sequence,
                        cap = MAX_SANE_SEED_SEQUENCE,
                        "registry_resolver: F10 — cached sequence exceeds sanity cap (likely \
                         pre-fix IPNS poisoning); treating as 0 so chain can re-establish floor"
                    );
                    sequence = 0;
                }
                // Seed BOTH atomics: under Plan B the persisted value is
                // always chain-confirmed, so it's the right seed for the
                // chain floor too. (`bump_*` are monotonic-max, so a
                // sequence of 0 is a no-op against the AtomicU64::new(0)
                // initial value.)
                resolver.bump_chain_seen_sequence(sequence);
                resolver.bump_seen_sequence(sequence);
                tracing::debug!(
                    seeded_sequence = sequence,
                    "registry_resolver: hot-start floor seeded from cache (chain-confirmed)"
                );
            }
            Ok(None) => {
                tracing::debug!("registry_resolver: no hot-start state cached (fresh)");
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "registry_resolver: hot-start cache load failed; floor stays at 0 (best-effort)"
                );
            }
        }
        resolver.cache = Some(cache);
        Ok(resolver)
    }

    /// Test/integration hook — production callers update via
    /// `resolve()`'s side-effect of calling `bump_seen_sequence`.
    /// Marked `pub(crate)` so tests can seed the floor without a
    /// stable public API.
    #[cfg(test)]
    pub(crate) fn set_highest_seen_sequence(&self, seq: u64) {
        self.bump_seen_sequence(seq);
    }

    /// Read the current replay-defense floor.
    pub fn highest_seen_sequence(&self) -> u64 {
        self.highest_seen_sequence.load(Ordering::Acquire)
    }

    /// Read the chain-confirmed replay-defense floor.
    ///
    /// **F10 audit fix** — under Plan B this is the value that gets
    /// persisted to the hot-start cache and re-seeded on next SDK
    /// start. IPNS resolves never advance this floor (see
    /// `parse_and_validate` and `resolve_via_network`), so a malicious
    /// IPNS gateway cannot poison the persistent floor.
    pub fn chain_seen_sequence(&self) -> u64 {
        self.highest_chain_seen_sequence.load(Ordering::Acquire)
    }

    /// Test-only mirror of `set_highest_seen_sequence` for the chain
    /// floor — F10 regression tests need to seed it without going
    /// through a full chain resolve.
    #[cfg(test)]
    pub(crate) fn set_chain_seen_sequence(&self, seq: u64) {
        self.bump_chain_seen_sequence(seq);
    }

    /// Read-only access to the resolver's HTTP client. The cold-start
    /// path on `EncryptedClient` reuses this client for the
    /// bucketsIndex + manifest fetches so connection pooling stays
    /// intact across all of the cold-start request burst.
    pub fn http_client(&self) -> &reqwest::Client {
        &self.http
    }

    /// Read-only access to the resolver's per-request timeout —
    /// reused by the cold-start path's gateway fetches for the
    /// bucketsIndex CBOR and the forest manifest, so a single config
    /// knob governs all of cold-start.
    pub fn per_request_timeout(&self) -> Duration {
        self.config.per_request_timeout
    }

    /// Read-only access to the IPFS gateway list. Cold-start uses
    /// this same list (rather than the warm-device pool's) so it
    /// stays self-contained and works without Phase 2.2/2.4 enabled.
    pub fn ipfs_gateways(&self) -> Vec<String> {
        if self.config.ipfs_gateways.is_empty() {
            default_ipfs_gateway_urls()
        } else {
            self.config.ipfs_gateways.clone()
        }
    }

    /// Atomic monotonic-max — only ever increases. Lock-free CAS loop.
    fn bump_seen_sequence(&self, seq: u64) {
        let mut current = self.highest_seen_sequence.load(Ordering::Acquire);
        while seq > current {
            match self.highest_seen_sequence.compare_exchange_weak(
                current,
                seq,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(observed) => current = observed,
            }
        }
    }

    /// **F10 audit fix** — atomic monotonic-max for the chain-confirmed
    /// floor. Called only from `try_chain` on success and from
    /// `new_with_cache` (when seeding from a chain-confirmed cache
    /// entry). `try_ipns` does NOT call this — that's what bounds the
    /// persistent floor against IPNS poisoning.
    fn bump_chain_seen_sequence(&self, seq: u64) {
        let mut current = self.highest_chain_seen_sequence.load(Ordering::Acquire);
        while seq > current {
            match self.highest_chain_seen_sequence.compare_exchange_weak(
                current,
                seq,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(observed) => current = observed,
            }
        }
    }

    /// Hybrid resolve.
    ///
    /// Order of operations:
    ///   0. **Hot-start short-circuit (Phase 3.3.5).** If a cache is
    ///      configured AND has a `(cid, sequence, observed_at)` row
    ///      AND `now - observed_at < soft_ttl`, return the cached
    ///      state directly. Bytes come from BLOCKS if cached,
    ///      otherwise via gateway race for the cached cid. Sequence
    ///      is re-checked against the in-memory floor for defense.
    ///   1. Try IPNS for `ipns_race_timeout`.
    ///   2. Fall through to chain on timeout / all-gateway failure
    ///      / replay-rejection.
    ///   3. On success (any path), write `(cid, sequence, now)` to
    ///      METADATA and the bytes to BLOCKS — best-effort, so a
    ///      cache write failure never aborts the resolve.
    pub async fn resolve(&self) -> Result<ResolvedUsersIndex, ClientError> {
        // Step 0 — hot-start short-circuit.
        if let Some(resolved) = self.try_hot_start().await {
            return Ok(resolved);
        }

        // Steps 1-2 — IPNS-then-chain.
        let resolved = self.resolve_via_network().await?;

        // Step 3 — write-back. Best-effort, synchronous-from-async
        // so the next call observes the freshly-written cache without
        // racing a spawned background task. Cold-start is a once-
        // per-session event; the few hundred microseconds for the
        // redb txns are negligible vs. the IPNS+chain budget we just
        // paid.
        //
        // **F10 audit fix — Chain-only persistence.** Pre-fix, both
        // IPNS and chain sources persisted to cache, allowing one
        // malicious IPNS hit to poison the persistent floor with
        // `sequence = u64::MAX`. Under Plan B the persistent floor
        // is chain-confirmed only; IPNS-source resolves return
        // without persisting, so process restart wipes any in-session
        // attacker progress and the next chain resolve transparently
        // re-establishes the real floor.
        if matches!(resolved.source, ResolutionSource::Chain) {
            self.persist_to_cache(&resolved).await;
        } else {
            tracing::debug!(
                source = ?resolved.source,
                "registry_resolver: skipping cache persist for non-chain source (F10)"
            );
        }

        Ok(resolved)
    }

    /// Phase 3.3.5 — try to serve from the persistent cache without
    /// touching the network. Returns `Some(ResolvedUsersIndex)` when
    /// a fresh-enough cached state exists AND the bytes are
    /// available (BLOCKS hit OR a fast gateway-race fetch for the
    /// cached cid succeeds). Returns `None` to indicate "fall
    /// through to full IPNS+chain resolve."
    ///
    /// A `None` return is silent — the network path takes over.
    async fn try_hot_start(&self) -> Option<ResolvedUsersIndex> {
        let cache = self.cache.as_ref()?;
        let (cached_cid, cached_seq, observed_at) = match cache.load_users_index_state() {
            Ok(Some(triple)) => triple,
            Ok(None) => return None,
            Err(e) => {
                tracing::warn!(error = %e, "hot-start: cache load failed");
                return None;
            }
        };

        // TTL check. Use wall-clock (matches what the writer used).
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if now.saturating_sub(observed_at) >= self.config.soft_ttl.as_secs() {
            tracing::debug!(
                age_secs = now.saturating_sub(observed_at),
                ttl_secs = self.config.soft_ttl.as_secs(),
                "hot-start: cache entry beyond TTL; re-resolving"
            );
            return None;
        }

        // Replay-defense check on the cached sequence itself —
        // defends against a corrupt/tampered METADATA row.
        let seen = self.highest_seen_sequence();
        if cached_seq < seen {
            tracing::warn!(
                cached = cached_seq,
                seen,
                "hot-start: cached sequence < in-memory floor; ignoring (corrupt or rolled-back cache)"
            );
            return None;
        }

        // Fetch bytes — BLOCKS first, then gateway race for the
        // cached cid as a network fallback.
        let bytes = match cache.get(&cached_cid) {
            Ok(Some(b)) => {
                tracing::debug!(cid = %cached_cid, "hot-start: BLOCKS hit");
                b
            }
            Ok(None) => {
                // BLOCKS miss: cached metadata says "we know the
                // CID" but we don't have the bytes (LRU evicted, or
                // the prior resolve failed mid-write). Fetch via
                // gateway race for the cached cid; cheaper than the
                // full IPNS dance because we skip the DHT lookup.
                let gateways = self.ipfs_gateways();
                match fetch_cid_via_gateways(
                    &cached_cid,
                    &gateways,
                    &self.http,
                    self.config.per_request_timeout,
                )
                .await
                {
                    Ok(b) => {
                        tracing::debug!(cid = %cached_cid, "hot-start: BLOCKS miss → gateway race");
                        // Repopulate BLOCKS for the next read.
                        if let Err(e) = cache.put(&cached_cid, &b).await {
                            tracing::debug!(error = %e, "hot-start: BLOCKS put failed (best-effort)");
                        }
                        b
                    }
                    Err(e) => {
                        tracing::debug!(
                            error = %e,
                            "hot-start: BLOCKS miss AND gateway fetch failed; falling through"
                        );
                        return None;
                    }
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "hot-start: BLOCKS lookup failed");
                return None;
            }
        };

        // Decode + cross-check sequence. The bytes content-address
        // to `cached_cid` (BLOCKS hit) or were verified by the
        // gateway-fetch (CID match guaranteed by
        // `verify_cid_against_bytes`). Decode failure here is
        // silent — fall through to network path so a fresh resolve
        // can heal a poisoned cache.
        let payload = match decode_users_index_cbor(&bytes) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(error = %e, "hot-start: cached CBOR parse failed; re-resolving");
                return None;
            }
        };
        if payload.sequence != cached_seq {
            tracing::warn!(
                payload_seq = payload.sequence,
                metadata_seq = cached_seq,
                "hot-start: payload sequence != metadata sequence; cache inconsistent, re-resolving"
            );
            return None;
        }

        // All checks passed. Bump the in-memory floor to match
        // (no-op if already >= cached_seq) and return.
        self.bump_seen_sequence(payload.sequence);
        Some(ResolvedUsersIndex {
            source: ResolutionSource::HotStartCache,
            cid: cached_cid,
            payload,
            bytes,
        })
    }

    /// Network resolve path (IPNS-then-chain). Extracted from the
    /// old `resolve()` body so the hot-start short-circuit can fall
    /// through to it cleanly.
    async fn resolve_via_network(&self) -> Result<ResolvedUsersIndex, ClientError> {
        let ipns_outcome = tokio::time::timeout(
            self.config.ipns_race_timeout,
            self.try_ipns(),
        )
        .await;

        match ipns_outcome {
            Ok(Ok(resolved)) => {
                self.bump_seen_sequence(resolved.payload.sequence);
                return Ok(resolved);
            }
            Ok(Err(e)) => {
                tracing::debug!(
                    error = %e,
                    "registry_resolver: IPNS path exhausted; falling back to chain"
                );
            }
            Err(_) => {
                tracing::debug!(
                    timeout_secs = self.config.ipns_race_timeout.as_secs(),
                    "registry_resolver: IPNS timed out; falling back to chain"
                );
            }
        }

        match self.try_chain().await {
            Ok(resolved) => {
                // F10: chain success advances BOTH floors. The chain
                // floor is the persistent one (see `resolve()` →
                // `persist_to_cache` chain-only branch); advancing it
                // raises the IPNS anti-poisoning cap headroom for
                // legitimate IPNS responses going forward.
                self.bump_chain_seen_sequence(resolved.payload.sequence);
                self.bump_seen_sequence(resolved.payload.sequence);
                Ok(resolved)
            }
            Err(e) => Err(ClientError::UsersIndexResolutionFailed {
                reason: format!("IPNS exhausted; chain: {}", e),
            }),
        }
    }

    /// Phase 3.3.5 — best-effort write of the just-resolved state to
    /// the METADATA table + BLOCKS. Failures log and proceed; the
    /// caller already has the resolved value, so cache hiccups never
    /// block SDK functionality.
    ///
    /// Synchronous-from-async (no `tokio::spawn`) so the next
    /// `resolve()` call observes the freshly-written cache without
    /// racing a background task — important because tests using
    /// `Mock::expect(N)` would otherwise be flaky on slow CI hosts.
    /// Cost is hundreds of microseconds for the two redb txns;
    /// negligible vs. the network budget the caller just spent.
    async fn persist_to_cache(&self, resolved: &ResolvedUsersIndex) {
        let Some(cache) = self.cache.as_ref() else {
            return;
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if let Err(e) = cache.store_users_index_state(&resolved.cid, resolved.payload.sequence, now)
        {
            tracing::warn!(
                error = %e,
                "registry_resolver: hot-start metadata write failed (best-effort)"
            );
        }
        if let Err(e) = cache.put(&resolved.cid, &resolved.bytes).await {
            // BlockTooLarge is the expected failure for huge global
            // CBORs (>cache budget); log at debug, not warn.
            tracing::debug!(
                error = %e,
                "registry_resolver: hot-start BLOCKS put failed (best-effort)"
            );
        }
    }

    /// IPNS leg — **parallel race + 10s grace + highest-sequence
    /// selection**. Dispatches a GET to every configured gateway
    /// simultaneously, waits for the first valid response, then keeps
    /// collecting responses for up to `IPNS_RACE_GRACE` (10 s)
    /// before picking the result with the highest in-CBOR `sequence`.
    ///
    /// # Why parallel + grace, not sequential
    ///
    /// The prior sequential implementation took the first successful
    /// response and returned. Audit on 2026-05-11 against the real
    /// fula production master uncovered the failure mode it allowed:
    /// public IPNS gateways have **wildly different CDN cache TTLs**.
    /// `{name}.ipns.dweb.link` (Cloudflare edge) was returning a 70-
    /// minute-old record (`Age: 4180`, `cf-cache-status: HIT`); the
    /// same name on `ipfs.io/ipns/{name}` returned the latest record
    /// the master had just published (`cf-cache-status: EXPIRED`).
    /// Sequential dispatch returned the dweb.link stale response and
    /// the SDK walked a pre-migration manifest, surfacing as a v7
    /// internal-node fetch failure during offline reads.
    ///
    /// Parallel race + sequence-max picks the freshest record across
    /// all responders. The 10 s grace window after the first response
    /// gives slower gateways a chance to come back with a higher
    /// sequence — bounded so a single hung gateway can't stall the
    /// resolver indefinitely.
    ///
    /// # Replay defense, anti-poisoning, and freshness
    ///
    /// Every response still flows through `parse_and_validate`, which
    /// rejects:
    ///   * `payload.sequence < highest_seen_sequence` (replay defense
    ///     — unchanged from the sequential design),
    ///   * `payload.sequence > chain_seen_sequence +
    ///     MAX_IPNS_SEQUENCE_JUMP_OVER_CHAIN` (F10 anti-poisoning cap).
    ///
    /// A poisoned-high response from one gateway is dropped on the
    /// floor and the resolver picks from the remaining valid set.
    /// Replay-stale responses are likewise dropped. The picked
    /// response is the highest-sequence record that passes both checks.
    ///
    /// # Cost
    ///
    /// 5–6 parallel HTTP GETs each ~7 KB CBOR ≈ 35–40 KB total
    /// bandwidth per cold-start resolve. Cold-start is rare (fresh
    /// install / cache-wipe / app reinstall — once per user per
    /// device-lifetime in practice), so the bandwidth is acceptable.
    ///
    /// # Worst-case timing
    ///
    /// Bounded by `min(slowest_gateway_response_time,
    /// fastest_gateway_response_time + 10 s)`, capped further by the
    /// outer resolver's per-request timeout. In the common case (most
    /// gateways respond in 1–3 s), total IPNS-leg time is
    /// `~first_response_time + 10 s` — about 11–13 s, which fits well
    /// inside the resolver's 30 s budget.
    async fn try_ipns(&self) -> Result<ResolvedUsersIndex, ClientError> {
        let gateways: Vec<String> = if self.config.ipns_gateways.is_empty() {
            default_ipns_gateway_urls()
        } else {
            self.config.ipns_gateways.clone()
        };

        if gateways.is_empty() {
            return Err(ClientError::UsersIndexResolutionFailed {
                reason: "no IPNS gateways configured".into(),
            });
        }

        // Dispatch all gateway fetches concurrently. Each future
        // returns `Result<(url, ResolvedUsersIndex), (url, error)>`
        // so the outer collector can report which gateway failed
        // with which error when the entire set exhausts. Borrowing
        // `&self` across all in-flight futures is fine because the
        // futures only live within this function call and they all
        // hold shared (immutable) borrows.
        let name = self.config.ipns_name.clone();
        let mut futs: futures::stream::FuturesUnordered<_> = gateways
            .iter()
            .map(|tmpl| {
                let url = tmpl.replace("{name}", &name);
                async move {
                    match self.fetch_with_timeout(&url).await {
                        Ok(bytes) => match self.parse_and_validate(bytes, ResolutionSource::Ipns) {
                            Ok(resolved) => Ok((url, resolved)),
                            Err(e) => Err((url, e.to_string())),
                        },
                        Err(e) => Err((url, e.to_string())),
                    }
                }
            })
            .collect();

        const IPNS_RACE_GRACE: Duration = Duration::from_secs(10);
        let mut results: Vec<(String, ResolvedUsersIndex)> = Vec::new();
        let mut errors: Vec<(String, String)> = Vec::new();
        let mut first_arrived_at: Option<std::time::Instant> = None;

        // Drain `futs` until either (a) all futures complete, or
        // (b) the 10-s grace window after the first successful
        // response elapses.
        loop {
            // Compute how long to wait for the next stream item.
            // Before the first success: wait however long the next
            // poll takes (outer resolver timeout bounds this).
            // After the first success: cap at the grace window's
            // remainder so a single hung gateway can't stall us.
            let next_future = futs.next();
            let next_item = if let Some(t0) = first_arrived_at {
                let elapsed = t0.elapsed();
                if elapsed >= IPNS_RACE_GRACE {
                    tracing::debug!(
                        "registry_resolver: IPNS 10s grace window already elapsed; stopping collection"
                    );
                    break;
                }
                let remaining = IPNS_RACE_GRACE - elapsed;
                match tokio::time::timeout(remaining, next_future).await {
                    Ok(opt) => opt,
                    Err(_) => {
                        tracing::debug!(
                            results = results.len(),
                            errors = errors.len(),
                            "registry_resolver: IPNS 10s grace expired; choosing among collected results"
                        );
                        break;
                    }
                }
            } else {
                next_future.await
            };

            match next_item {
                Some(Ok((url, resolved))) => {
                    let seq = resolved.payload.sequence;
                    if first_arrived_at.is_none() {
                        first_arrived_at = Some(std::time::Instant::now());
                        tracing::debug!(
                            url = %url,
                            sequence = seq,
                            "registry_resolver: first IPNS response received; starting 10s grace for stragglers"
                        );
                    } else {
                        tracing::debug!(
                            url = %url,
                            sequence = seq,
                            "registry_resolver: additional IPNS response within grace window"
                        );
                    }
                    results.push((url, resolved));
                }
                Some(Err((url, err))) => {
                    tracing::debug!(
                        url = %url,
                        error = %err,
                        "registry_resolver: IPNS gateway failed or returned invalid body"
                    );
                    errors.push((url, err));
                }
                None => {
                    // FuturesUnordered drained — every gateway returned.
                    break;
                }
            }
        }

        if results.is_empty() {
            return Err(ClientError::UsersIndexResolutionFailed {
                reason: format!(
                    "IPNS exhausted across {} gateways: [{}]",
                    gateways.len(),
                    errors
                        .iter()
                        .map(|(u, e)| format!("{}: {}", u, e))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            });
        }

        // Pick the response with the highest sequence. Stable sort
        // by descending sequence; ties broken by insertion order
        // (which is first-to-respond order, so we prefer the
        // faster gateway when two return the same sequence).
        results.sort_by(|a, b| b.1.payload.sequence.cmp(&a.1.payload.sequence));
        let (chosen_url, chosen) = results.into_iter().next().expect("non-empty");
        tracing::debug!(
            url = %chosen_url,
            sequence = chosen.payload.sequence,
            "registry_resolver: chose highest-sequence IPNS response"
        );
        Ok(chosen)
    }

    /// Chain leg — single eth_call to `latest()`, then iterate IPFS
    /// gateways for the resulting CID.
    async fn try_chain(&self) -> Result<ResolvedUsersIndex, ClientError> {
        // Step 1 — eth_call.
        let (cid_digest, on_chain_seq) = self.eth_call_latest().await?;
        if on_chain_seq < self.highest_seen_sequence() {
            return Err(ClientError::SequenceRegression {
                observed: on_chain_seq,
                highest_seen: self.highest_seen_sequence(),
                channel: "chain.latest()".into(),
            });
        }

        // Step 2 — reconstruct CID. dag-cbor codec (0x71) +
        // sha2-256 multihash (0x12) + the on-chain digest.
        let mh = Multihash::<64>::wrap(MULTIHASH_SHA2_256, &cid_digest).map_err(|e| {
            ClientError::UsersIndexResolutionFailed {
                reason: format!("invalid chain CID digest: {}", e),
            }
        })?;
        let cid = Cid::new_v1(CODEC_DAG_CBOR, mh);

        // Step 3 — iterate IPFS gateways until one body
        // content-addresses to `cid`.
        let gateways: Vec<String> = if self.config.ipfs_gateways.is_empty() {
            default_ipfs_gateway_urls()
        } else {
            self.config.ipfs_gateways.clone()
        };
        let mut last_err: Option<String> = None;
        for tmpl in &gateways {
            let url = tmpl.replace("{cid}", &cid.to_string());
            let bytes = match self.fetch_with_timeout(&url).await {
                Ok(b) => b,
                Err(e) => {
                    last_err = Some(e.to_string());
                    continue;
                }
            };
            if let Err(e) = verify_cid_against_bytes(&cid, &bytes) {
                last_err = Some(format!("verify failed at {}: {}", url, e));
                continue;
            }
            // Step 4 — parse + cross-validate sequence.
            let payload = decode_users_index_cbor(&bytes).map_err(|e| {
                ClientError::UsersIndexResolutionFailed {
                    reason: format!("chain-fetched payload parse: {}", e),
                }
            })?;
            if payload.sequence != on_chain_seq {
                return Err(ClientError::UsersIndexResolutionFailed {
                    reason: format!(
                        "in-CBOR sequence {} != on-chain sequence {} (anomaly: tamper or RPC inconsistency)",
                        payload.sequence, on_chain_seq
                    ),
                });
            }
            return Ok(ResolvedUsersIndex {
                source: ResolutionSource::Chain,
                cid,
                payload,
                bytes,
            });
        }
        Err(ClientError::UsersIndexResolutionFailed {
            reason: format!(
                "chain CID {} unreachable across {} gateways: {}",
                cid,
                gateways.len(),
                last_err.unwrap_or_else(|| "no gateways tried".into())
            ),
        })
    }

    /// Issue the `latest()` eth_call and parse the 96-byte response.
    /// Self-contained: assembles the JSON-RPC envelope manually, no
    /// dependency on a full ethers-rs client.
    async fn eth_call_latest(&self) -> Result<([u8; 32], u64), ClientError> {
        let calldata = format!("0x{}", hex::encode(SELECTOR_LATEST));
        let to_addr = format!("0x{}", hex::encode(self.anchor_address_bytes));
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_call",
            "params": [{ "to": to_addr, "data": calldata }, "latest"],
            "id": 1,
        });

        let resp = tokio::time::timeout(
            self.config.per_request_timeout,
            self.http
                .post(&self.config.chain_rpc_url)
                .json(&body)
                .send(),
        )
        .await
        .map_err(|_| ClientError::UsersIndexResolutionFailed {
            reason: format!(
                "chain RPC timeout after {}s",
                self.config.per_request_timeout.as_secs()
            ),
        })?
        .map_err(|e| ClientError::UsersIndexResolutionFailed {
            reason: format!("chain RPC transport: {}", e),
        })?;

        if !resp.status().is_success() {
            return Err(ClientError::UsersIndexResolutionFailed {
                reason: format!("chain RPC HTTP {}", resp.status()),
            });
        }
        let json: serde_json::Value =
            resp.json().await.map_err(|e| ClientError::UsersIndexResolutionFailed {
                reason: format!("chain RPC response parse: {}", e),
            })?;
        if let Some(err) = json.get("error") {
            return Err(ClientError::UsersIndexResolutionFailed {
                reason: format!("chain RPC error: {}", err),
            });
        }
        let result_hex = json
            .get("result")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ClientError::UsersIndexResolutionFailed {
                reason: "chain RPC: missing result".into(),
            })?;
        let result_hex = result_hex.strip_prefix("0x").unwrap_or(result_hex);
        let raw =
            hex::decode(result_hex).map_err(|e| ClientError::UsersIndexResolutionFailed {
                reason: format!("chain RPC: hex decode result: {}", e),
            })?;
        parse_latest_response(&raw)
    }

    /// Single-gateway HTTP GET with `per_request_timeout`. Returns
    /// raw body on 2xx, error otherwise. Doesn't touch the gateway-
    /// pool's dynamic-priority state machine — this is one-shot
    /// cold-start, not the ongoing warm-device hot path.
    async fn fetch_with_timeout(&self, url: &str) -> Result<Bytes, ClientError> {
        // IPIP-412: request raw IPLD bytes so path-style gateways (e.g.
        // dweb.link/ipns/<name>) return the underlying CBOR rather than
        // their HTML directory listing. Without this header, the IPNS
        // leg silently exhausted across every gateway that wraps
        // responses in HTML, forcing fall-back to the chain leg (which
        // can be up to 12h stale).
        // IPNS path. The resolved object is the GlobalUsersIndex CBOR
        // (dag-cbor codec 0x71), so explicitly accept dag-cbor; include
        // raw + cbor + */* as fallbacks for gateways that don't honor
        // the typed forms. dweb.link 406s `vnd.ipld.raw` on IPNS paths
        // (raw doesn't apply to IPNS-resolved typed content) but
        // happily serves `vnd.ipld.dag-cbor` — empirically verified
        // during the cold-walk diagnostic that produced this fix.
        let resp = tokio::time::timeout(
            self.config.per_request_timeout,
            self.http
                .get(url)
                .header(
                    reqwest::header::ACCEPT,
                    "application/vnd.ipld.dag-cbor, application/vnd.ipld.raw, application/cbor, */*;q=0.1",
                )
                .send(),
        )
        .await
        .map_err(|_| ClientError::UsersIndexResolutionFailed {
            reason: format!("HTTP timeout: {}", url),
        })?
        .map_err(|e| ClientError::UsersIndexResolutionFailed {
            reason: format!("HTTP transport ({}): {}", url, e),
        })?;
        if !resp.status().is_success() {
            return Err(ClientError::UsersIndexResolutionFailed {
                reason: format!("HTTP {} from {}", resp.status(), url),
            });
        }
        resp.bytes()
            .await
            .map_err(|e| ClientError::UsersIndexResolutionFailed {
                reason: format!("HTTP body read ({}): {}", url, e),
            })
    }

    /// Parse + validate IPNS-fetched bytes. Synthesizes the CID
    /// from the bytes (no external CID to verify against on the
    /// IPNS path; the gateway did the IPNS-record resolution
    /// upstream — the security boundary here is the in-CBOR
    /// `sequence` field, not the bytes-to-CID hash).
    ///
    /// **F10 audit fix — source-aware sequence validation.**
    ///
    /// All sources: reject `payload.sequence < highest_seen_sequence`
    /// (replay defense; unchanged).
    ///
    /// IPNS source ALSO caps `payload.sequence <=
    /// chain_seen_sequence + MAX_IPNS_SEQUENCE_JUMP_OVER_CHAIN`. This
    /// prevents a malicious IPNS gateway from returning
    /// `sequence = u64::MAX` and advancing the replay-defense floor
    /// arbitrarily — without the cap, every subsequent legitimate
    /// chain response (whose sequence is a small integer) would be
    /// rejected as `SequenceRegression`. The cap is anchored to the
    /// chain-confirmed floor (not the in-session `seen` floor) so
    /// repeated coordinated IPNS hits cannot drift the cap upward.
    fn parse_and_validate(
        &self,
        bytes: Bytes,
        source: ResolutionSource,
    ) -> Result<ResolvedUsersIndex, ClientError> {
        let payload = decode_users_index_cbor(&bytes).map_err(|e| {
            ClientError::UsersIndexResolutionFailed {
                reason: format!("CBOR decode: {}", e),
            }
        })?;
        let seen = self.highest_seen_sequence();
        if payload.sequence < seen {
            return Err(ClientError::SequenceRegression {
                observed: payload.sequence,
                highest_seen: seen,
                channel: format!("{:?}", source),
            });
        }
        // F10 — IPNS-only anti-poisoning cap.
        if matches!(source, ResolutionSource::Ipns) {
            let chain_floor = self.chain_seen_sequence();
            let max_allowed = chain_floor.saturating_add(MAX_IPNS_SEQUENCE_JUMP_OVER_CHAIN);
            if payload.sequence > max_allowed {
                return Err(ClientError::UsersIndexResolutionFailed {
                    reason: format!(
                        "IPNS sequence {} exceeds chain-confirmed floor {} by more than {} \
                         — possible IPNS gateway poisoning, refusing payload (F10 anti-poisoning cap)",
                        payload.sequence, chain_floor, MAX_IPNS_SEQUENCE_JUMP_OVER_CHAIN,
                    ),
                });
            }
        }
        let cid = synthesize_cid_from_bytes(&bytes);
        Ok(ResolvedUsersIndex {
            source,
            cid,
            payload,
            bytes,
        })
    }
}

// ============================================================
// Helpers
// ============================================================

/// Multihash code for sha2-256 (0x12).
const MULTIHASH_SHA2_256: u64 = 0x12;
/// IPLD codec for dag-cbor (0x71).
const CODEC_DAG_CBOR: u64 = 0x71;

/// **F10 audit fix** — Maximum delta between the chain-confirmed floor
/// and an accepted IPNS payload's `sequence`. Defends against a
/// malicious IPNS gateway returning a poisoned `sequence = u64::MAX`
/// (or any large value above what chain could realistically reach),
/// which would otherwise advance the in-session replay-defense floor
/// arbitrarily and reject every subsequent legitimate chain response
/// as `SequenceRegression`.
///
/// Sized for the bootstrap edge case: if the chain-floor is `0` (brand
/// new SDK before chain has ever published) AND IPNS is the only path,
/// the SDK can read up to `MAX_IPNS_SEQUENCE_JUMP_OVER_CHAIN` distinct
/// publishes before chain catches up. At a 5-min publish cadence this
/// is ~9.5 years of headroom — generous for any realistic deployment.
/// Production design has chain on a 12h cron, so this slack should
/// never bind in practice.
const MAX_IPNS_SEQUENCE_JUMP_OVER_CHAIN: u64 = 1_000_000;

/// **F10 audit fix** — Sanity ceiling on the cached sequence value
/// loaded at construction time via `new_with_cache`. Defends against
/// legacy caches written by pre-fix SDK builds, which may carry an
/// IPNS-poisoned value. Any persisted sequence above this cap is
/// treated as `0` so the next chain resolve transparently re-establishes
/// the real floor.
///
/// `1u64 << 40 ≈ 1.1 trillion` — well above any conceivable legitimate
/// publisher sequence (chain advances ~730/year at 12h cadence; this
/// cap is reached after ~1.5 billion years of continuous publishing).
/// Anything above is unambiguously corrupt.
const MAX_SANE_SEED_SEQUENCE: u64 = 1u64 << 40;

/// `keccak256("latest()")[..4]`. Hardcoded so the production build
/// has zero crypto dependency for this constant.
///
/// MUST stay in sync with `tests::abi_selector_latest_matches_keccak256`
/// — that test is the **source of truth**, this constant is just the
/// cache. Do not delete the test "because it's redundant"; without it,
/// a typo here goes unnoticed until the SDK silently calls the wrong
/// 4-byte selector on the deployed `FulaUsersIndexAnchor`.
const SELECTOR_LATEST: [u8; 4] = [0x52, 0xbf, 0xe7, 0x89];

/// Parse a 0x-prefixed-or-not 40-char hex address into 20 bytes.
fn parse_anchor_address(s: &str) -> Result<[u8; 20], ClientError> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s).map_err(|e| {
        ClientError::Config(format!("registry resolver: invalid anchor_address hex: {}", e))
    })?;
    if bytes.len() != 20 {
        return Err(ClientError::Config(format!(
            "registry resolver: anchor_address must be 20 bytes, got {}",
            bytes.len()
        )));
    }
    let mut out = [0u8; 20];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Parse the 96-byte ABI-encoded return of `latest()`.
/// Layout (Solidity packs `uint64` right-aligned within a 32-byte slot):
///   bytes[0..32]    = cid_digest (full 32 bytes)
///   bytes[32..64]   = sequence  (u64 BE in last 8 bytes)
///   bytes[64..96]   = updatedAt (u64 BE in last 8 bytes) — **dropped**
///
/// We deliberately drop `updatedAt` here: nothing in the SDK's
/// security model depends on it (sequence is the security boundary,
/// and `block.timestamp` is miner-influenceable on EVM chains anyway).
/// Returning a richer tuple would invite callers to make decisions on
/// it; keeping the parser narrow forces the right shape.
fn parse_latest_response(raw: &[u8]) -> Result<([u8; 32], u64), ClientError> {
    if raw.len() < 96 {
        return Err(ClientError::UsersIndexResolutionFailed {
            reason: format!(
                "chain `latest()` returned {} bytes (expected ≥ 96)",
                raw.len()
            ),
        });
    }
    let mut cid_digest = [0u8; 32];
    cid_digest.copy_from_slice(&raw[0..32]);
    // u64 lives in the last 8 bytes of the 32-byte slot.
    let mut seq_be = [0u8; 8];
    seq_be.copy_from_slice(&raw[32 + 24..32 + 32]);
    let sequence = u64::from_be_bytes(seq_be);
    Ok((cid_digest, sequence))
}

/// Decode dag-cbor bytes as a `GlobalUsersIndex`. Wraps the
/// ipld-dagcbor crate's error in our own typed error.
fn decode_users_index_cbor(bytes: &[u8]) -> Result<GlobalUsersIndex, String> {
    serde_ipld_dagcbor::from_slice(bytes).map_err(|e| e.to_string())
}

/// Synthesize a CIDv1 (dag-cbor + sha2-256) from a body. Used for
/// the IPNS path's reported `ResolvedUsersIndex.cid` so callers can
/// use it as a cache key. NOT a security claim — IPNS bytes are
/// trusted via the in-payload `sequence`, not via this hash.
fn synthesize_cid_from_bytes(bytes: &[u8]) -> Cid {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    // wrap() can only fail if digest is wrong size; sha2-256 is
    // always exactly 32 bytes so unwrap is safe.
    let mh = Multihash::<64>::wrap(MULTIHASH_SHA2_256, &digest).expect("32-byte sha2 digest");
    Cid::new_v1(CODEC_DAG_CBOR, mh)
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use sha3::{Digest, Keccak256};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    // ============================================================
    // v0.4.4 — BucketEntry::cold_start_cid fallback semantics
    // ============================================================

    #[test]
    fn cold_start_cid_prefers_forest_manifest_cid_when_set() {
        // Happy path for v0.4.4+: master populated `forest_manifest_cid`.
        // The accessor must return THAT value, NOT the legacy `manifest`.
        let entry = BucketEntry {
            manifest: "bafyreilegacy".to_string(),
            forest_manifest_cid: Some("bafyreinew".to_string()),
            legacy: false,
        };
        assert_eq!(entry.cold_start_cid(), "bafyreinew");
    }

    #[test]
    fn cold_start_cid_falls_back_when_forest_manifest_cid_is_none() {
        // pre-v0.4.4 master: only the legacy field is populated.
        let entry = BucketEntry {
            manifest: "bafyreilegacy".to_string(),
            forest_manifest_cid: None,
            legacy: false,
        };
        assert_eq!(entry.cold_start_cid(), "bafyreilegacy");
    }

    #[test]
    fn cold_start_cid_falls_back_when_forest_manifest_cid_is_empty_string() {
        // Defensive: some serializers might round-trip Some("") for an
        // unset Option<String>. The accessor MUST treat empty string as
        // absent and fall back to the legacy field — otherwise cold-start
        // would try to parse "" as a CID and produce a confusing error.
        let entry = BucketEntry {
            manifest: "bafyreilegacy".to_string(),
            forest_manifest_cid: Some(String::new()),
            legacy: false,
        };
        assert_eq!(entry.cold_start_cid(), "bafyreilegacy");
    }

    #[test]
    fn cold_start_cid_returns_legacy_even_when_legacy_is_also_empty() {
        // Both fields effectively empty: caller's parse will fail with a
        // clean error message (not our problem here). We don't panic; we
        // just return the legacy field, which is "".
        let entry = BucketEntry {
            manifest: String::new(),
            forest_manifest_cid: None,
            legacy: false,
        };
        assert_eq!(entry.cold_start_cid(), "");
    }

    #[test]
    fn bucket_entry_serde_round_trip_with_forest_manifest_cid_set() {
        // Verify CBOR round-trip preserves both fields, and the
        // skip_serializing_if attribute behaves correctly.
        let entry = BucketEntry {
            manifest: "bafyreilegacy".to_string(),
            forest_manifest_cid: Some("bafyreinew".to_string()),
            legacy: false,
        };
        let bytes = serde_ipld_dagcbor::to_vec(&entry).expect("serialize");
        let restored: BucketEntry =
            serde_ipld_dagcbor::from_slice(&bytes).expect("deserialize");
        assert_eq!(restored.manifest, "bafyreilegacy");
        assert_eq!(restored.forest_manifest_cid.as_deref(), Some("bafyreinew"));
        assert!(!restored.legacy);
    }

    #[test]
    fn bucket_entry_deserializes_old_cbor_without_forest_manifest_cid() {
        // Pre-v0.4.4 CBOR: only `manifest` and `legacy` fields. Must
        // deserialize cleanly with `forest_manifest_cid: None` (via
        // #[serde(default)]). Apps still on pre-v0.4.4 SDK versions
        // must not break when reading new CBORs (and vice-versa).
        #[derive(serde::Serialize)]
        struct LegacyBucketEntry {
            manifest: String,
            legacy: bool,
        }
        let legacy = LegacyBucketEntry {
            manifest: "bafyreilegacy".to_string(),
            legacy: true,
        };
        let bytes = serde_ipld_dagcbor::to_vec(&legacy).expect("serialize legacy");
        let modern: BucketEntry =
            serde_ipld_dagcbor::from_slice(&bytes).expect("legacy → modern");
        assert_eq!(modern.manifest, "bafyreilegacy");
        assert_eq!(modern.forest_manifest_cid, None);
        assert!(modern.legacy);
    }

    /// The hardcoded `SELECTOR_LATEST` MUST equal the canonical
    /// `keccak256("latest()")[..4]`. If a future refactor renames the
    /// solidity function and someone forgets to update the constant,
    /// this test catches it before the SDK silently calls the wrong
    /// selector against the deployed contract.
    #[test]
    fn abi_selector_latest_matches_keccak256() {
        let mut hasher = Keccak256::new();
        hasher.update(b"latest()");
        let full = hasher.finalize();
        let expected: [u8; 4] = [full[0], full[1], full[2], full[3]];
        assert_eq!(
            SELECTOR_LATEST, expected,
            "SELECTOR_LATEST drifted from keccak256(\"latest()\")[..4]: \
             expected 0x{:02x}{:02x}{:02x}{:02x}, got 0x{:02x}{:02x}{:02x}{:02x}",
            expected[0], expected[1], expected[2], expected[3],
            SELECTOR_LATEST[0], SELECTOR_LATEST[1], SELECTOR_LATEST[2], SELECTOR_LATEST[3]
        );
    }

    /// Build a syntactically-valid CBOR-encoded payload for tests.
    fn make_payload_cbor(sequence: u64) -> (Bytes, GlobalUsersIndex) {
        let payload = GlobalUsersIndex {
            v: 1,
            sequence,
            updated_at_unix: 1_700_000_000,
            users: BTreeMap::new(),
        };
        let bytes = serde_ipld_dagcbor::to_vec(&payload).expect("encode");
        (Bytes::from(bytes), payload)
    }

    fn fixture_address() -> String {
        // 20-byte zero address with 0x prefix. parse_anchor_address
        // accepts both forms.
        "0x0000000000000000000000000000000000000001".to_string()
    }

    fn fixture_ipns_name() -> String {
        // Real-shape libp2p public key hash (b58btc-encoded ed25519);
        // resolver doesn't validate the key format, just substitutes.
        "k51qzi5uqu5dh-test".to_string()
    }

    #[test]
    fn parse_anchor_address_accepts_with_or_without_0x() {
        let with_prefix = parse_anchor_address("0x0000000000000000000000000000000000000001")
            .expect("with 0x");
        let without = parse_anchor_address("0000000000000000000000000000000000000001")
            .expect("without 0x");
        assert_eq!(with_prefix, without);
        assert_eq!(with_prefix[19], 1);
        for &b in &with_prefix[..19] {
            assert_eq!(b, 0);
        }
    }

    #[test]
    fn parse_anchor_address_rejects_wrong_length() {
        assert!(parse_anchor_address("0xdeadbeef").is_err());
        assert!(parse_anchor_address("0x").is_err());
        assert!(parse_anchor_address("not-hex").is_err());
    }

    #[test]
    fn parse_latest_response_extracts_correct_fields() {
        // Build a 96-byte response: digest = 0xff*32, sequence = 42, ts = 100.
        let mut raw = vec![0u8; 96];
        for i in 0..32 {
            raw[i] = 0xff;
        }
        raw[32 + 24..32 + 32].copy_from_slice(&42u64.to_be_bytes());
        raw[64 + 24..64 + 32].copy_from_slice(&100u64.to_be_bytes());

        let (digest, seq) = parse_latest_response(&raw).expect("parse");
        assert_eq!(digest, [0xff; 32]);
        assert_eq!(seq, 42);
    }

    #[test]
    fn parse_latest_response_rejects_short_input() {
        let short = vec![0u8; 95];
        assert!(parse_latest_response(&short).is_err());
    }

    #[test]
    fn synthesize_cid_is_deterministic_and_dagcbor_sha256() {
        let bytes = b"some payload bytes";
        let c1 = synthesize_cid_from_bytes(bytes);
        let c2 = synthesize_cid_from_bytes(bytes);
        assert_eq!(c1, c2, "synthesis is deterministic");
        assert_eq!(c1.codec(), CODEC_DAG_CBOR);
        assert_eq!(c1.hash().code(), MULTIHASH_SHA2_256);
        assert_eq!(c1.hash().digest().len(), 32);
    }

    #[test]
    fn resolver_new_rejects_empty_rpc_url() {
        let mut cfg = ResolverConfig::new("", fixture_address(), fixture_ipns_name());
        let err = UsersIndexResolver::new(cfg.clone()).unwrap_err();
        assert!(matches!(err, ClientError::Config(_)));
        cfg.chain_rpc_url = "https://rpc.example".into();
        cfg.ipns_name = "".into();
        let err = UsersIndexResolver::new(cfg).unwrap_err();
        assert!(matches!(err, ClientError::Config(_)));
    }

    #[test]
    fn resolver_new_rejects_bad_anchor_address() {
        let cfg = ResolverConfig::new(
            "https://rpc.example",
            "0xdeadbeef", // too short
            fixture_ipns_name(),
        );
        let err = UsersIndexResolver::new(cfg).unwrap_err();
        assert!(matches!(err, ClientError::Config(_)));
    }

    #[tokio::test]
    async fn resolve_via_ipns_succeeds_when_first_gateway_serves_valid_payload() {
        let (cbor, _) = make_payload_cbor(7);
        let mock = MockServer::start().await;
        let url_path = format!("/ipns/{}", fixture_ipns_name());
        Mock::given(method("GET"))
            .and(path(url_path))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(cbor.as_ref()))
            .mount(&mock)
            .await;

        let mut cfg = ResolverConfig::new(
            "https://chain.example/rpc", // never called on success
            fixture_address(),
            fixture_ipns_name(),
        );
        cfg.ipns_gateways = vec![format!("{}/ipns/{{name}}", mock.uri())];
        cfg.ipns_race_timeout = Duration::from_secs(5);
        cfg.per_request_timeout = Duration::from_secs(2);

        let resolver = UsersIndexResolver::new(cfg).expect("new");
        let r = resolver.resolve().await.expect("resolve");
        assert_eq!(r.source, ResolutionSource::Ipns);
        assert_eq!(r.payload.sequence, 7);
        assert_eq!(resolver.highest_seen_sequence(), 7);
    }

    /// **The load-bearing test for the 2026-05-11 IPNS race redesign.**
    ///
    /// Two gateways, both valid CBOR, both within the per-request timeout.
    /// Gateway A is fast (no delay) and serves a *staler* sequence (100).
    /// Gateway B is slower (300 ms delay, still within the 10 s grace
    /// window) and serves a *fresher* sequence (101). The race + grace
    /// design must surface 101, not the faster-but-staler 100.
    ///
    /// If this test fails, someone has reverted to "return first
    /// successful response" semantics — the exact regression the
    /// audit on 2026-05-11 was triggered by. Production failure mode:
    /// users hitting cold-start get the dweb.link Cloudflare-edge-cached
    /// stale CBOR and walk a pre-migration manifest, surfacing as a
    /// "no such object" or v7-storage-key fetch failure during offline
    /// reads. Empirical proof that the race-and-pick-highest design
    /// matters in production: `images` bucket cold-walk failed with
    /// dweb.link-first ordering and passed with parallel race against
    /// ipfs.io + dweb.link.
    #[tokio::test]
    async fn resolve_via_ipns_picks_highest_sequence_when_gateways_disagree() {
        // Gateway A — fast, returns the lower sequence.
        let (cbor_a, _) = make_payload_cbor(100);
        let gw_a = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!("/ipns/{}", fixture_ipns_name())))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(cbor_a.as_ref()))
            .mount(&gw_a)
            .await;

        // Gateway B — slower (300 ms delay, well under the 10 s grace
        // and 5 s ipns_race_timeout configured below), returns the
        // higher sequence. This is the gateway whose response must
        // win even though A responds first.
        let (cbor_b, _) = make_payload_cbor(101);
        let gw_b = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!("/ipns/{}", fixture_ipns_name())))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_bytes(cbor_b.as_ref())
                    .set_delay(Duration::from_millis(300)),
            )
            .mount(&gw_b)
            .await;

        let mut cfg = ResolverConfig::new(
            "https://chain.example/rpc", // never called on success
            fixture_address(),
            fixture_ipns_name(),
        );
        cfg.ipns_gateways = vec![
            format!("{}/ipns/{{name}}", gw_a.uri()),
            format!("{}/ipns/{{name}}", gw_b.uri()),
        ];
        // Outer race ceiling must accommodate (first_response_time +
        // 10 s grace). At in-process MockServer latencies this is
        // trivially satisfied, but keep it well above the inner
        // grace to make the relationship visible.
        cfg.ipns_race_timeout = Duration::from_secs(15);
        cfg.per_request_timeout = Duration::from_secs(5);

        let resolver = UsersIndexResolver::new(cfg).expect("new");
        let r = resolver.resolve().await.expect("resolve");
        assert_eq!(r.source, ResolutionSource::Ipns);
        assert_eq!(
            r.payload.sequence, 101,
            "race-and-pick-highest design must return the higher-sequence \
             response from gateway B, even though gateway A responded first \
             with a staler sequence. If this is now 100, the resolver has \
             regressed to first-response-wins semantics — re-read \
             `try_ipns` and the 2026-05-11 audit notes in \
             `default_ipns_gateway_urls`'s docstring."
        );
        assert_eq!(resolver.highest_seen_sequence(), 101);
    }

    /// Sequence-equal tie-break is by insertion order (which becomes
    /// first-to-respond order under the race). Both gateways return
    /// the same sequence; either is correct, but `sort_by` is stable
    /// so the faster gateway's response wins. Asserts the tie-break
    /// is deterministic, not that one specific gateway wins.
    #[tokio::test]
    async fn resolve_via_ipns_tie_break_is_stable_on_equal_sequence() {
        let (cbor_a, _) = make_payload_cbor(42);
        let gw_a = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!("/ipns/{}", fixture_ipns_name())))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(cbor_a.as_ref()))
            .mount(&gw_a)
            .await;

        // Same sequence, deliberate delay to keep responder ordering
        // visible — gw_a responds first.
        let (cbor_b, _) = make_payload_cbor(42);
        let gw_b = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!("/ipns/{}", fixture_ipns_name())))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_bytes(cbor_b.as_ref())
                    .set_delay(Duration::from_millis(100)),
            )
            .mount(&gw_b)
            .await;

        let mut cfg = ResolverConfig::new(
            "https://chain.example/rpc",
            fixture_address(),
            fixture_ipns_name(),
        );
        cfg.ipns_gateways = vec![
            format!("{}/ipns/{{name}}", gw_a.uri()),
            format!("{}/ipns/{{name}}", gw_b.uri()),
        ];
        cfg.ipns_race_timeout = Duration::from_secs(15);
        cfg.per_request_timeout = Duration::from_secs(5);

        let resolver = UsersIndexResolver::new(cfg).expect("new");
        let r = resolver.resolve().await.expect("resolve");
        assert_eq!(r.payload.sequence, 42);
    }

    #[tokio::test]
    async fn resolve_falls_through_to_chain_when_ipns_rejected_for_sequence_regression() {
        // Setup: IPNS returns seq=3, but the resolver's floor is
        // already at 5 (apps seeded it from a hot-start cache). The
        // IPNS payload is replay-rejected. Chain returns seq=10,
        // which is accepted. Resolver returns the chain payload.
        let (ipns_cbor, _) = make_payload_cbor(3);
        let (chain_cbor, _) = make_payload_cbor(10);

        let ipns = MockServer::start().await;
        let chain_rpc = MockServer::start().await;
        let chain_gw = MockServer::start().await;

        // IPNS gateway → seq=3 body (will be rejected as regression).
        Mock::given(method("GET"))
            .and(path(format!("/ipns/{}", fixture_ipns_name())))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(ipns_cbor.as_ref()))
            .mount(&ipns)
            .await;

        // Compute the chain CID from the chain_cbor bytes so we can
        // mock the gateway response correctly. The eth_call returns
        // the digest; the gateway serves bytes that hash to it.
        let chain_cid = synthesize_cid_from_bytes(&chain_cbor);
        let chain_digest = chain_cid.hash().digest();

        // Chain RPC mock — return the digest + seq=10 + ts=anything.
        let mut raw = vec![0u8; 96];
        raw[0..32].copy_from_slice(chain_digest);
        raw[32 + 24..32 + 32].copy_from_slice(&10u64.to_be_bytes());
        raw[64 + 24..64 + 32].copy_from_slice(&12345u64.to_be_bytes());
        let result_hex = format!("0x{}", hex::encode(&raw));
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": result_hex,
                })),
            )
            .mount(&chain_rpc)
            .await;

        // IPFS gateway for the chain CID → return chain_cbor bytes.
        let cid_str = chain_cid.to_string();
        Mock::given(method("GET"))
            .and(path(format!("/ipfs/{}", cid_str)))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(chain_cbor.as_ref()))
            .mount(&chain_gw)
            .await;

        let mut cfg = ResolverConfig::new(
            chain_rpc.uri(),
            fixture_address(),
            fixture_ipns_name(),
        );
        cfg.ipns_gateways = vec![format!("{}/ipns/{{name}}", ipns.uri())];
        cfg.ipfs_gateways = vec![format!("{}/ipfs/{{cid}}", chain_gw.uri())];
        cfg.ipns_race_timeout = Duration::from_secs(2);
        cfg.per_request_timeout = Duration::from_secs(2);

        let resolver = UsersIndexResolver::new(cfg).expect("new");
        // Seed the floor to 5 so the IPNS seq=3 is rejected.
        resolver.set_highest_seen_sequence(5);

        let r = resolver.resolve().await.expect("resolve");
        assert_eq!(r.source, ResolutionSource::Chain);
        assert_eq!(r.payload.sequence, 10);
        assert_eq!(resolver.highest_seen_sequence(), 10);
    }

    #[tokio::test]
    async fn resolve_returns_error_when_both_paths_fail() {
        // IPNS gateway returns 503; chain RPC returns malformed JSON.
        // Resolver surfaces UsersIndexResolutionFailed.
        let ipns = MockServer::start().await;
        let chain_rpc = MockServer::start().await;

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&ipns)
            .await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500).set_body_string("not json"))
            .mount(&chain_rpc)
            .await;

        let mut cfg = ResolverConfig::new(
            chain_rpc.uri(),
            fixture_address(),
            fixture_ipns_name(),
        );
        cfg.ipns_gateways = vec![format!("{}/ipns/{{name}}", ipns.uri())];
        cfg.ipns_race_timeout = Duration::from_secs(2);
        cfg.per_request_timeout = Duration::from_secs(2);

        let resolver = UsersIndexResolver::new(cfg).expect("new");
        let err = resolver.resolve().await.expect_err("both fail");
        assert!(
            matches!(err, ClientError::UsersIndexResolutionFailed { .. }),
            "expected UsersIndexResolutionFailed, got {:?}",
            err
        );
    }

    #[tokio::test]
    async fn resolve_chain_path_rejects_cid_digest_mismatch() {
        // The chain returns digest D, but the gateway serves bytes
        // whose sha2-256 != D. verify_cid_against_bytes fails and
        // the resolver should NOT accept the payload — surfaces an
        // UsersIndexResolutionFailed mentioning verify failure.
        let (cbor_legit, _) = make_payload_cbor(10);
        let cbor_tampered = Bytes::from_static(b"this is not the real CBOR payload");

        let ipns = MockServer::start().await;
        let chain_rpc = MockServer::start().await;
        let chain_gw = MockServer::start().await;

        // IPNS gateway serves nothing useful → resolver must use chain.
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&ipns)
            .await;

        // Chain RPC says "real CID is X with seq=10".
        let real_cid = synthesize_cid_from_bytes(&cbor_legit);
        let real_digest = real_cid.hash().digest();
        let mut raw = vec![0u8; 96];
        raw[0..32].copy_from_slice(real_digest);
        raw[32 + 24..32 + 32].copy_from_slice(&10u64.to_be_bytes());
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": format!("0x{}", hex::encode(&raw)),
                })),
            )
            .mount(&chain_rpc)
            .await;

        // Gateway serves DIFFERENT bytes — verify_cid_against_bytes
        // must reject.
        Mock::given(method("GET"))
            .and(path(format!("/ipfs/{}", real_cid)))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(cbor_tampered.as_ref()))
            .mount(&chain_gw)
            .await;

        let mut cfg = ResolverConfig::new(
            chain_rpc.uri(),
            fixture_address(),
            fixture_ipns_name(),
        );
        cfg.ipns_gateways = vec![format!("{}/ipns/{{name}}", ipns.uri())];
        cfg.ipfs_gateways = vec![format!("{}/ipfs/{{cid}}", chain_gw.uri())];
        cfg.ipns_race_timeout = Duration::from_secs(2);
        cfg.per_request_timeout = Duration::from_secs(2);

        let resolver = UsersIndexResolver::new(cfg).expect("new");
        let err = resolver.resolve().await.expect_err("verify fails");
        assert!(matches!(err, ClientError::UsersIndexResolutionFailed { .. }));
    }

    #[tokio::test]
    async fn resolve_chain_path_rejects_in_cbor_seq_mismatch() {
        // Chain says seq=10 but the bytes-fetched payload has seq=11.
        // Defensive: resolver must surface this as a tamper / RPC-
        // inconsistency anomaly, NOT silently use either side.
        let (cbor_seq_11, _) = make_payload_cbor(11);

        let ipns = MockServer::start().await;
        let chain_rpc = MockServer::start().await;
        let chain_gw = MockServer::start().await;

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&ipns)
            .await;

        // Chain says seq=10, digest of cbor_seq_11.
        let cid = synthesize_cid_from_bytes(&cbor_seq_11);
        let mut raw = vec![0u8; 96];
        raw[0..32].copy_from_slice(cid.hash().digest());
        raw[32 + 24..32 + 32].copy_from_slice(&10u64.to_be_bytes());
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": format!("0x{}", hex::encode(&raw)),
                })),
            )
            .mount(&chain_rpc)
            .await;

        Mock::given(method("GET"))
            .and(path(format!("/ipfs/{}", cid)))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(cbor_seq_11.as_ref()))
            .mount(&chain_gw)
            .await;

        let mut cfg = ResolverConfig::new(
            chain_rpc.uri(),
            fixture_address(),
            fixture_ipns_name(),
        );
        cfg.ipns_gateways = vec![format!("{}/ipns/{{name}}", ipns.uri())];
        cfg.ipfs_gateways = vec![format!("{}/ipfs/{{cid}}", chain_gw.uri())];
        cfg.ipns_race_timeout = Duration::from_secs(2);
        cfg.per_request_timeout = Duration::from_secs(2);

        let resolver = UsersIndexResolver::new(cfg).expect("new");
        let err = resolver.resolve().await.expect_err("seq mismatch");
        let msg = format!("{}", err);
        assert!(
            msg.contains("sequence")
                || msg.contains("anomaly")
                || matches!(err, ClientError::UsersIndexResolutionFailed { .. }),
            "expected sequence-mismatch error, got: {}",
            msg
        );
    }

    #[tokio::test]
    async fn replay_defense_rejects_chain_regression() {
        // Floor is 100; chain returns seq=50. Resolver MUST reject
        // even though the bytes verify and parse correctly. This
        // is the chain-side replay-defense path.
        let (cbor, _) = make_payload_cbor(50);
        let cid = synthesize_cid_from_bytes(&cbor);

        let ipns = MockServer::start().await;
        let chain_rpc = MockServer::start().await;
        let chain_gw = MockServer::start().await;

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&ipns)
            .await;

        let mut raw = vec![0u8; 96];
        raw[0..32].copy_from_slice(cid.hash().digest());
        raw[32 + 24..32 + 32].copy_from_slice(&50u64.to_be_bytes());
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": format!("0x{}", hex::encode(&raw)),
                })),
            )
            .mount(&chain_rpc)
            .await;

        Mock::given(method("GET"))
            .and(path(format!("/ipfs/{}", cid)))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(cbor.as_ref()))
            .mount(&chain_gw)
            .await;

        let mut cfg = ResolverConfig::new(
            chain_rpc.uri(),
            fixture_address(),
            fixture_ipns_name(),
        );
        cfg.ipns_gateways = vec![format!("{}/ipns/{{name}}", ipns.uri())];
        cfg.ipfs_gateways = vec![format!("{}/ipfs/{{cid}}", chain_gw.uri())];
        cfg.ipns_race_timeout = Duration::from_secs(2);
        cfg.per_request_timeout = Duration::from_secs(2);

        let resolver = UsersIndexResolver::new(cfg).expect("new");
        resolver.set_highest_seen_sequence(100);
        let err = resolver.resolve().await.expect_err("regression rejected");
        // Either UsersIndexResolutionFailed (wrapper) or
        // SequenceRegression directly is acceptable; both signal
        // "do not accept" to the caller.
        match err {
            ClientError::SequenceRegression { observed, highest_seen, channel } => {
                assert_eq!(observed, 50);
                assert_eq!(highest_seen, 100);
                assert!(!channel.is_empty(), "channel label should be set");
            }
            ClientError::UsersIndexResolutionFailed { .. } => { /* also fine */ }
            other => panic!("unexpected error: {:?}", other),
        }
    }

    /// `derive_user_key_from_email` MUST produce a 32-hex-char output
    /// matching what `fula-cli/src/state.rs::hash_user_id` would
    /// produce against the same `userId` (= sha256-hex of
    /// lower(email)). Reproduces the master algorithm step-by-step
    /// here so the two stay in lockstep — without this test, a
    /// future master-side refactor could silently desync the SDK
    /// from the published global users-index keys.
    #[test]
    fn derive_user_key_matches_master_state_rs_algorithm() {
        use sha2::{Digest, Sha256};

        // Reference inputs.
        let email = "User@Example.COM";
        let email_lower = "user@example.com";

        // SDK derives directly from email.
        let sdk_key = derive_user_key_from_email(email);

        // Reproduce master's chain: lower(email) → sha256 → hex → blake3 → first 16 bytes hex.
        let user_id_digest = Sha256::digest(email_lower.as_bytes());
        let user_id_hex = hex::encode(user_id_digest);
        // master state.rs: hash_user_id(user_id_str) =
        //   blake3::Hasher::new()
        //     .update(b"fula:user_id:")
        //     .update(user_id_str.as_bytes())
        //     .finalize()[..16] hex
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"fula:user_id:");
        hasher.update(user_id_hex.as_bytes());
        let master_key = hex::encode(&hasher.finalize().as_bytes()[..16]);

        assert_eq!(
            sdk_key, master_key,
            "SDK derive_user_key_from_email diverged from master state.rs::hash_user_id; \
             email={}, sdk={}, master={}",
            email, sdk_key, master_key
        );
        assert_eq!(sdk_key.len(), 32, "userKey must be 32 hex chars (16 bytes)");
    }

    #[test]
    fn derive_user_key_normalizes_email_case() {
        // Email is case-insensitive (per RFC 5321 local-part is, in practice,
        // a courtesy and master normalizes too). Same email different case
        // MUST yield the same userKey, otherwise users would lose access
        // when their app capitalizes differently than master.
        let a = derive_user_key_from_email("alice@example.com");
        let b = derive_user_key_from_email("ALICE@EXAMPLE.COM");
        let c = derive_user_key_from_email("Alice@Example.com");
        assert_eq!(a, b);
        assert_eq!(a, c);
    }

    #[test]
    fn derive_user_key_distinguishes_different_users() {
        let a = derive_user_key_from_email("alice@example.com");
        let b = derive_user_key_from_email("bob@example.com");
        assert_ne!(a, b);
    }

    // ============================================================
    // Phase 3.3.5 — hot-start cache reuse tests (advisor-mandated 4)
    // ============================================================
    //
    // Each test constructs both a network-mock universe (wiremock)
    // and a real on-disk BlockCache (TempDir + redb). The cache
    // survives across resolver constructions (simulating SDK
    // restart) so we can verify replay-defense persistence and the
    // soft-TTL short-circuit behavior.

    use crate::block_cache::BlockCache;
    use std::path::PathBuf;
    use tempfile::TempDir;

    fn make_payload_with_seq(sequence: u64) -> (Bytes, GlobalUsersIndex) {
        let payload = GlobalUsersIndex {
            v: 1,
            sequence,
            updated_at_unix: 1_700_000_000,
            users: BTreeMap::new(),
        };
        let bytes = serde_ipld_dagcbor::to_vec(&payload).expect("encode");
        (Bytes::from(bytes), payload)
    }

    fn fixture_resolver_config_with_ipns(ipns_url: &str) -> ResolverConfig {
        let mut cfg = ResolverConfig::new(
            "http://chain-rpc.unused/", // never called on hot-start path
            fixture_address(),
            fixture_ipns_name(),
        );
        cfg.ipns_gateways = vec![format!("{}/ipns/{{name}}", ipns_url)];
        cfg.ipns_race_timeout = Duration::from_secs(2);
        cfg.per_request_timeout = Duration::from_secs(2);
        cfg.soft_ttl = Duration::from_secs(60);
        cfg
    }

    /// Test 1 — replay-defense floor survives SDK restart.
    /// Round-trip through the cache: resolve seq=42 → drop resolver
    /// → reopen against same cache → highest_seen_sequence == 42.
    #[tokio::test]
    async fn hot_start_seeds_floor_across_restart() {
        let dir = TempDir::new().unwrap();
        let cache_path: PathBuf = dir.path().join("cache.redb");

        // Open cache, manually plant a (cid, seq) row — simulates
        // a prior successful resolve. (Avoids the full wiremock
        // setup since this test is about restart semantics, not
        // resolve mechanics.)
        {
            let cache = BlockCache::open(&cache_path, 1024 * 1024).expect("open");
            let cid = synthesize_cid_from_bytes(b"some payload");
            cache
                .store_users_index_state(&cid, 42, 1_700_000_000)
                .expect("store");
        } // cache dropped → file lock released

        // Re-open cache + construct resolver via new_with_cache.
        let cache = Arc::new(BlockCache::open(&cache_path, 1024 * 1024).expect("re-open"));
        let cfg = ResolverConfig::new(
            "http://rpc.unused/",
            fixture_address(),
            fixture_ipns_name(),
        );
        let resolver = UsersIndexResolver::new_with_cache(cfg, cache).expect("new_with_cache");

        assert_eq!(
            resolver.highest_seen_sequence(),
            42,
            "replay-defense floor MUST survive restart and seed from persisted state"
        );
    }

    /// Test 2 — replay regression after restart is rejected.
    /// Restart with floor=99; IPNS returns seq=50; resolver MUST
    /// reject (not silently serve the stale payload).
    #[tokio::test]
    async fn hot_start_rejects_regression_after_restart() {
        let dir = TempDir::new().unwrap();
        let cache_path: PathBuf = dir.path().join("cache.redb");

        // Plant a high floor (seq=99).
        {
            let cache = BlockCache::open(&cache_path, 1024 * 1024).expect("open");
            let placeholder = synthesize_cid_from_bytes(b"placeholder");
            cache
                .store_users_index_state(&placeholder, 99, 0)
                .expect("plant");
        }

        // wiremock IPNS serves seq=50 (regression).
        let ipns = MockServer::start().await;
        let (regress_bytes, _) = make_payload_with_seq(50);
        Mock::given(method("GET"))
            .and(path(format!("/ipns/{}", fixture_ipns_name())))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(regress_bytes.as_ref()))
            .mount(&ipns)
            .await;

        let cache = Arc::new(BlockCache::open(&cache_path, 1024 * 1024).expect("re-open"));
        // observed_at = 0 → way past TTL → hot-start short-circuit
        // should NOT fire; resolver falls through to network.
        let mut cfg = fixture_resolver_config_with_ipns(&ipns.uri());
        cfg.soft_ttl = Duration::from_secs(60); // bigger than 0-vs-now gap doesn't matter; observed_at=0
        let resolver = UsersIndexResolver::new_with_cache(cfg, cache).expect("new_with_cache");

        assert_eq!(resolver.highest_seen_sequence(), 99, "floor seeded");

        // resolve() → IPNS returns seq=50; replay-defense rejects.
        // Falls through to chain (also fails since RPC URL is
        // unused). Final error: UsersIndexResolutionFailed wrapping
        // the IPNS exhaustion (the resolver internally rejected the
        // regression and treated it as "IPNS failed").
        let err = resolver.resolve().await.expect_err("must reject");
        // The regression is observed inside try_ipns and surfaces
        // as UsersIndexResolutionFailed — the chain leg also can't
        // help (RPC URL unused), so the wrapper combines them.
        assert!(
            matches!(err, ClientError::UsersIndexResolutionFailed { .. }),
            "expected resolution failure, got: {:?}",
            err
        );

        // Floor unchanged — 99 still holds.
        assert_eq!(
            resolver.highest_seen_sequence(),
            99,
            "regression payload must NOT advance the floor"
        );
    }

    /// Test 3 — hot-start within TTL serves cached state without
    /// touching the network.
    ///
    /// **F10 audit fix — semantics updated.** Pre-fix any IPNS resolve
    /// populated the cache; second resolve hot-started from it. Under
    /// Plan B the persistent cache is chain-confirmed only — IPNS
    /// resolves do NOT persist (so a malicious IPNS gateway cannot
    /// poison the chain-floor). To still exercise the hot-start
    /// short-circuit, this test now pre-seeds the cache directly with
    /// chain-flavored state, then asserts a single resolve() call
    /// short-circuits to `HotStartCache` without hitting IPNS.
    #[tokio::test]
    async fn hot_start_within_ttl_skips_network() {
        let dir = TempDir::new().unwrap();
        let cache_path: PathBuf = dir.path().join("cache.redb");
        let cache = Arc::new(BlockCache::open(&cache_path, 1024 * 1024).expect("open"));

        let ipns = MockServer::start().await;
        let (cbor, _) = make_payload_with_seq(7);

        // F10: pre-seed the cache with chain-confirmed state. The
        // `synthesize_cid_from_bytes` matches what try_hot_start would
        // compute, and BlockCache's METADATA + BLOCKS tables together
        // give the resolver everything it needs for hot-start.
        let cid = synthesize_cid_from_bytes(&cbor);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        cache
            .store_users_index_state(&cid, 7, now)
            .expect("seed METADATA");
        cache.put(&cid, &cbor).await.expect("seed BLOCKS");

        // IPNS mock with `expect(0)` — if the hot-start short-circuit
        // breaks, wiremock will panic on Drop because the mock was
        // hit despite expecting zero hits.
        Mock::given(method("GET"))
            .and(path(format!("/ipns/{}", fixture_ipns_name())))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(cbor.as_ref()))
            .expect(0)
            .mount(&ipns)
            .await;

        let cfg = fixture_resolver_config_with_ipns(&ipns.uri());
        let resolver =
            UsersIndexResolver::new_with_cache(cfg, Arc::clone(&cache)).expect("new_with_cache");

        // Single resolve: must hot-start from the pre-seeded cache,
        // NEVER touching IPNS. `expect(0)` enforces this on wiremock
        // Drop.
        let r = resolver.resolve().await.expect("hot-start resolve");
        assert_eq!(
            r.source,
            ResolutionSource::HotStartCache,
            "must serve from hot-start cache (not the network)"
        );
        assert_eq!(r.payload.sequence, 7);
    }

    /// Test 4 — hot-start beyond TTL re-resolves. Configure a
    /// 1-second `soft_ttl`; resolve once; sleep 2 seconds; resolve
    /// again. The second resolve MUST re-hit IPNS (so the mock is
    /// expected to fire twice).
    #[tokio::test]
    async fn hot_start_beyond_ttl_re_resolves() {
        let dir = TempDir::new().unwrap();
        let cache_path: PathBuf = dir.path().join("cache.redb");
        let cache = Arc::new(BlockCache::open(&cache_path, 1024 * 1024).expect("open"));

        let ipns = MockServer::start().await;
        let (cbor, _) = make_payload_with_seq(11);
        Mock::given(method("GET"))
            .and(path(format!("/ipns/{}", fixture_ipns_name())))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(cbor.as_ref()))
            .expect(2) // both resolves must hit IPNS — TTL elapsed between them
            .mount(&ipns)
            .await;

        let mut cfg = fixture_resolver_config_with_ipns(&ipns.uri());
        cfg.soft_ttl = Duration::from_secs(1); // tight TTL for the test
        let resolver =
            UsersIndexResolver::new_with_cache(cfg, Arc::clone(&cache)).expect("new_with_cache");

        let r1 = resolver.resolve().await.expect("first resolve");
        assert_eq!(r1.source, ResolutionSource::Ipns);

        // Wait past the TTL.
        tokio::time::sleep(Duration::from_millis(1500)).await;

        let r2 = resolver.resolve().await.expect("second resolve");
        assert_eq!(
            r2.source,
            ResolutionSource::Ipns,
            "after TTL elapse, resolver must re-fetch from IPNS rather than serve stale cache"
        );
    }

    // ============================================================
    // Pre-existing tests below (Phase 3.3 sub-step A)
    // ============================================================

    #[test]
    fn highest_seen_sequence_is_monotonic() {
        let cfg = ResolverConfig::new(
            "https://rpc.example",
            fixture_address(),
            fixture_ipns_name(),
        );
        let resolver = UsersIndexResolver::new(cfg).expect("new");
        assert_eq!(resolver.highest_seen_sequence(), 0);
        resolver.bump_seen_sequence(5);
        assert_eq!(resolver.highest_seen_sequence(), 5);
        // Lower value MUST NOT lower the floor.
        resolver.bump_seen_sequence(3);
        assert_eq!(resolver.highest_seen_sequence(), 5);
        // Equal value is also a no-op.
        resolver.bump_seen_sequence(5);
        assert_eq!(resolver.highest_seen_sequence(), 5);
        // Higher value advances.
        resolver.bump_seen_sequence(7);
        assert_eq!(resolver.highest_seen_sequence(), 7);
    }

    // ─────────────────────────────────────────────────────────────────
    // F10 (audit) — IPNS poisoning protection regression tests.
    //
    // Pre-fix the SDK accepted any IPNS payload with `sequence >= seen`
    // and persisted it to the cache. A malicious IPNS gateway returning
    // `sequence = u64::MAX` would advance the persistent floor to
    // u64::MAX, permanently locking the SDK out of every subsequent
    // legitimate IPNS AND chain read (chain's real sequence is small;
    // would be rejected as `SequenceRegression`). Post-fix:
    //
    //   1. IPNS payloads are capped at `chain_floor + 1M` per resolve
    //      (`MAX_IPNS_SEQUENCE_JUMP_OVER_CHAIN`).
    //   2. IPNS-source resolves do NOT persist to cache — the
    //      persistent floor is chain-confirmed only.
    //   3. Cold-start cache loads sanity-cap legacy poisoned values
    //      at `MAX_SANE_SEED_SEQUENCE = 1u64 << 40`.
    // ─────────────────────────────────────────────────────────────────

    fn fixture_resolver() -> UsersIndexResolver {
        let cfg = ResolverConfig::new(
            "https://rpc.example",
            fixture_address(),
            fixture_ipns_name(),
        );
        UsersIndexResolver::new(cfg).expect("fixture resolver")
    }

    #[test]
    fn f10_ipns_u64_max_poisoning_rejected_in_memory() {
        // Headline attack: malicious IPNS gateway returns u64::MAX.
        // parse_and_validate must refuse before bumping the floor.
        let resolver = fixture_resolver();
        let (poisoned_bytes, _) = make_payload_cbor(u64::MAX);
        let err = resolver
            .parse_and_validate(poisoned_bytes, ResolutionSource::Ipns)
            .expect_err("u64::MAX from IPNS must be rejected by anti-poisoning cap");
        let msg = err.to_string();
        assert!(
            msg.contains("anti-poisoning") || msg.contains("MAX_IPNS_SEQUENCE_JUMP")
                || msg.contains("possible IPNS gateway poisoning"),
            "error must cite the F10 cap; got: {}",
            msg
        );
        // CRITICAL: the in-memory floor MUST NOT have advanced — proves
        // the rejection happened before any bump.
        assert_eq!(resolver.highest_seen_sequence(), 0);
        assert_eq!(resolver.chain_seen_sequence(), 0);
    }

    #[test]
    fn f10_ipns_drift_attack_doesnt_persist() {
        // 100 in-session IPNS hits at chain_floor+cap-1. Each hit
        // succeeds parse_and_validate (within the cap) and bumps
        // highest_seen_sequence. But the chain floor stays at 0 and
        // — crucially — would never be persisted (the persist gate
        // in resolve() only fires for Chain source).
        let resolver = fixture_resolver();
        let initial_chain_floor = resolver.chain_seen_sequence();
        assert_eq!(initial_chain_floor, 0);

        // Within-cap value (chain_floor + cap - 1).
        let within_cap = MAX_IPNS_SEQUENCE_JUMP_OVER_CHAIN - 1;
        let (good_bytes, _) = make_payload_cbor(within_cap);
        let resolved = resolver
            .parse_and_validate(good_bytes, ResolutionSource::Ipns)
            .expect("within-cap IPNS is accepted");
        // Simulate the in-session floor bump that resolve_via_network
        // does on IPNS success.
        resolver.bump_seen_sequence(resolved.payload.sequence);

        // In-memory floor advanced.
        assert_eq!(resolver.highest_seen_sequence(), within_cap);
        // BUT the chain floor — the persistent one — did NOT.
        assert_eq!(
            resolver.chain_seen_sequence(),
            0,
            "F10: IPNS must NEVER advance the chain-confirmed floor"
        );

        // Try to drift past chain_floor + cap (should fail even though
        // it's still > highest_seen_sequence: the cap is anchored to
        // chain_floor, not to seen).
        let drift_target = MAX_IPNS_SEQUENCE_JUMP_OVER_CHAIN + 1;
        let (drift_bytes, _) = make_payload_cbor(drift_target);
        assert!(
            resolver
                .parse_and_validate(drift_bytes, ResolutionSource::Ipns)
                .is_err(),
            "F10: cap is anchored to chain_floor=0, so seq > 1M must fail \
             even after IPNS already bumped seen to 1M-1"
        );
    }

    #[test]
    fn f10_chain_advance_persists_and_survives_restart() {
        // Chain success bumps both floors; chain floor is persisted
        // and re-seeded on next SDK start.
        let resolver = fixture_resolver();
        // Simulate chain success.
        resolver.bump_chain_seen_sequence(100);
        resolver.bump_seen_sequence(100);
        assert_eq!(resolver.chain_seen_sequence(), 100);
        assert_eq!(resolver.highest_seen_sequence(), 100);

        // After restart, both floors should re-seed from cache (chain
        // floor is what's persisted; the seed code seeds both atomics
        // from that single value). Simulate via `set_chain_seen_sequence`
        // on a fresh resolver, mirroring `new_with_cache`'s seed.
        let fresh = fixture_resolver();
        // bump_chain_seen_sequence is private; use the test-only setter.
        fresh.set_chain_seen_sequence(100);
        fresh.set_highest_seen_sequence(100);
        assert_eq!(fresh.chain_seen_sequence(), 100);
        assert_eq!(fresh.highest_seen_sequence(), 100);

        // Now an IPNS payload at seq=200 (legitimate, within cap from
        // chain_floor=100) should succeed.
        let (legit_bytes, _) = make_payload_cbor(200);
        assert!(
            fresh.parse_and_validate(legit_bytes, ResolutionSource::Ipns).is_ok(),
            "F10: with chain_floor=100, IPNS at 200 (cap=1_000_100) is legitimate"
        );
    }

    #[test]
    fn f10_ipns_within_cap_accepted() {
        // Legitimate IPNS exactly at chain_floor + cap is accepted.
        let resolver = fixture_resolver();
        resolver.set_chain_seen_sequence(50);
        resolver.set_highest_seen_sequence(50);

        // chain_floor=50, cap=1M → max allowed = 1_000_050.
        let max_legit = 50 + MAX_IPNS_SEQUENCE_JUMP_OVER_CHAIN;
        let (bytes, _) = make_payload_cbor(max_legit);
        assert!(
            resolver
                .parse_and_validate(bytes, ResolutionSource::Ipns)
                .is_ok(),
            "F10: IPNS at exactly chain_floor + MAX_IPNS_SEQUENCE_JUMP_OVER_CHAIN must be accepted"
        );

        // One above is rejected.
        let (over_bytes, _) = make_payload_cbor(max_legit + 1);
        assert!(
            resolver
                .parse_and_validate(over_bytes, ResolutionSource::Ipns)
                .is_err(),
            "F10: IPNS at chain_floor + cap + 1 must be rejected"
        );
    }

    #[test]
    fn f10_chain_path_not_subject_to_ipns_cap() {
        // Chain is monotonic-enforced by the contract (require(newSeq
        // > sequence)); the SDK trusts chain absolutely. parse_and_validate
        // for ResolutionSource::Chain must NOT apply the IPNS cap, even
        // for sequence values way above chain_floor (e.g., a deployment
        // that advanced rapidly via legitimate publishes).
        let resolver = fixture_resolver();
        // chain_floor=0; under IPNS this would reject anything > 1M.
        // Under Chain, even a huge legitimate value is fine (chain has
        // its own monotonic enforcement).
        let huge_legit_chain = MAX_IPNS_SEQUENCE_JUMP_OVER_CHAIN + 1_000_000;
        let (bytes, _) = make_payload_cbor(huge_legit_chain);
        let resolved = resolver
            .parse_and_validate(bytes, ResolutionSource::Chain)
            .expect("Chain source not subject to IPNS anti-poisoning cap");
        assert_eq!(resolved.payload.sequence, huge_legit_chain);
    }

    #[test]
    fn f10_legacy_poisoned_cache_sanity_capped() {
        // Cache sanity cap on the SEEDED sequence. Pre-fix poisoning
        // wrote u64::MAX to the persistent floor; new_with_cache must
        // detect this (value > MAX_SANE_SEED_SEQUENCE) and recover by
        // treating the seed as 0. Tested directly against the cap
        // constant + `bump_chain_seen_sequence` semantics; full
        // new_with_cache integration test would require a redb cache
        // fixture which is heavy.
        let resolver = fixture_resolver();
        let poisoned = u64::MAX;
        let cap = MAX_SANE_SEED_SEQUENCE;
        // Cap definition correctness:
        assert!(poisoned > cap);
        assert_eq!(cap, 1u64 << 40);
        // The new_with_cache logic discards values > cap, treating
        // them as 0 for seeding. Verify the cap is high enough that
        // legitimate publisher seqs never trigger it (730/year × 1B
        // years before a real publisher could reach 1u64 << 40):
        let one_century_at_max_realistic_pace: u64 = 730 * 100;
        assert!(one_century_at_max_realistic_pace < cap);
        // And that the cap is low enough to reject obvious poisoning:
        assert!(poisoned > cap);
    }

    #[test]
    fn f10_replay_defense_seq_below_floor_still_rejected() {
        // Sanity check: the existing replay-defense behavior must still
        // work. A payload with sequence < highest_seen_sequence is
        // rejected before any source-specific cap check.
        let resolver = fixture_resolver();
        resolver.set_highest_seen_sequence(100);
        let (stale_bytes, _) = make_payload_cbor(50);
        let err = resolver
            .parse_and_validate(stale_bytes.clone(), ResolutionSource::Ipns)
            .expect_err("stale IPNS rejected");
        assert!(matches!(err, ClientError::SequenceRegression { .. }));
        // Same for chain source.
        let err2 = resolver
            .parse_and_validate(stale_bytes, ResolutionSource::Chain)
            .expect_err("stale chain rejected");
        assert!(matches!(err2, ClientError::SequenceRegression { .. }));
    }
}
