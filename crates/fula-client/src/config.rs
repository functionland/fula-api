//! Client configuration

use std::path::PathBuf;
use std::time::Duration;

use crate::health_gate::HealthCallback;

/// Client configuration
///
/// Note: `Config` is `Clone` but the `health_callback` shares the
/// underlying `Arc<dyn Fn>` across clones — there's exactly one
/// callback closure per logical SDK construction, fired by every
/// `FulaClient` clone derived from this config.
#[derive(Clone)]
pub struct Config {
    /// Gateway endpoint URL
    pub endpoint: String,
    /// Access token (JWT)
    pub access_token: Option<String>,
    /// Request timeout
    pub timeout: Duration,
    /// Enable client-side encryption
    pub encryption_enabled: bool,
    /// User agent string
    pub user_agent: String,
    /// Maximum retry attempts
    pub max_retries: u32,
    /// Multipart upload threshold (bytes)
    pub multipart_threshold: u64,
    /// Multipart chunk size (bytes)
    pub multipart_chunk_size: u64,
    /// Per-chunk download timeout (F10).
    ///
    /// Applied to every individual chunk fetched by the windowed chunked-download
    /// engine. Guards against a slow server that trickles bytes below the global
    /// reqwest dead-connection threshold and stalls a download for minutes. Only
    /// active on native targets; wasm inherits the fetch default.
    pub per_chunk_download_timeout: Duration,
    /// Maximum plaintext size a buffered download will accept (F8).
    ///
    /// Applied *before* any network I/O by the buffered chunked-download engine.
    /// If the chunked metadata declares a `total_size` larger than this ceiling,
    /// the buffered path returns an error instead of allocating the buffer. This
    /// exists because the buffered engine holds the entire decrypted file in RAM
    /// until `finalize_and_verify` passes, then emits to the caller's writer —
    /// a disaster-recovery tradeoff that prefers a loud error over an unbounded
    /// allocation. The streaming variant (`..._to_writer`) has no such ceiling.
    ///
    /// Note: the ceiling bounds allocation under an honest manifest. A forged
    /// `total_size` that lies about the real payload is caught by the
    /// mid-stream per-chunk AEAD + size check in the engine itself, so the
    /// ceiling is an allocation guard, not a security boundary.
    pub buffered_download_max_bytes: u64,

    /// Phase 2.1 of master-independent reads: enable the master health
    /// gate. Off by default (backward-compat). When on, the SDK observes
    /// request outcomes and short-circuits with `MasterUnreachable` after
    /// two consecutive failures, instead of paying the per-read timeout.
    pub health_gate_enabled: bool,

    /// TTL of the `Down` state when `health_gate_enabled = true`. After
    /// this duration elapses, the next request is allowed through as a
    /// probe (without resetting state — only an observed success resets).
    pub health_gate_ttl: Duration,

    /// Phase 2.2 of master-independent reads: enable the on-disk LRU
    /// block cache. Off by default. Native-only — `wasm32` ignores
    /// this flag (the redb-backed cache cannot open in browsers).
    /// When enabled, master-up reads observe and persist the
    /// `(bucket, key) → cid` mapping the offline path needs.
    pub block_cache_enabled: bool,

    /// Filesystem path for the block-cache redb database. `None` means
    /// "use the platform default" (resolved at SDK init via the
    /// `dirs` crate's `data_local_dir()`). Operators can override
    /// this for tests or non-standard deployments. Native-only.
    pub block_cache_path: Option<PathBuf>,

    /// Maximum on-disk bytes for the block cache. Defaults to 256 MiB
    /// per plan §2.2. The cache evicts to 80 % of this watermark when
    /// `put` would push it past `max_bytes`. Native-only.
    pub block_cache_max_bytes: u64,

    /// Phase 2.4 of master-independent reads: enable falling back to
    /// public IPFS gateways when master is unreachable AND the SDK has
    /// already cached the requested object's CID via Phase 2.2's
    /// `(bucket, key) → cid` table. Off by default; flip on AFTER
    /// Phase 2.2 has had time to populate the cache during master-up
    /// reads. Native-only — `wasm32` returns `MasterUnreachable`
    /// instead of falling back (no gateway-race plumbing in the
    /// browser target).
    pub gateway_fallback_enabled: bool,

    /// Custom gateway URL templates. Each must contain the literal
    /// `{cid}` token, which the SDK substitutes per fetch. Empty =
    /// use the SDK-shipped default list of six gateways
    /// (`gateway_fetch::default_gateway_urls()`). Native-only.
    pub gateway_fallback_urls: Vec<String>,

    /// Number of gateways the SDK races in parallel for any single
    /// CID. Default 3 per plan §2.3 (cancels in-flight losers via
    /// `Drop` of the spawned futures). Capped at the gateway-pool
    /// length. Native-only.
    pub gateway_race_concurrency: usize,

    // ============================================================
    // Phase 3.3 — cold-start hybrid resolver
    // ============================================================
    //
    // The resolver is "configured" iff ALL of:
    //   - `users_index_chain_rpc_url` is non-empty
    //   - `users_index_anchor_address` is non-empty
    //   - `users_index_ipns_name` is non-empty
    //   - `users_index_user_key` is `Some`
    //
    // are populated. Field presence is the single source of truth —
    // there is no separate `enabled` bool. To disable cold-start an
    // operator clears any one of the four fields; the SDK degrades
    // to "warm-cache only" automatically. This eliminates the
    // surprise of "I flipped the master switch but it's still off
    // because I forgot field N" — an audit-driven simplification.

    /// JSON-RPC URL for the chain anchor (Base or SKALE). One of
    /// the four required fields for the cold-start resolver.
    pub users_index_chain_rpc_url: String,

    /// `FulaUsersIndexAnchor.sol` proxy address (20 bytes hex,
    /// optionally `0x`-prefixed). Required when the resolver is
    /// enabled.
    pub users_index_anchor_address: String,

    /// IPNS NAME (libp2p public-key hash, e.g. `k51qzi5...`) under
    /// which the master publishes the users-index. Required when
    /// the resolver is enabled.
    pub users_index_ipns_name: String,

    /// 32-hex-char `userKey` (= `BLAKE3("fula:user_id:" || sha256(lower(email)))[..16]`).
    /// Computed once at sign-in via `registry_resolver::derive_user_key_from_email`
    /// and passed in here; the SDK does not store the raw email. Required when
    /// the resolver is enabled.
    pub users_index_user_key: Option<String>,

    /// IPNS-aware gateway URL templates the resolver races against
    /// (each must contain `{name}`). Empty Vec = use the SDK-shipped
    /// defaults (Cloudflare, dweb.link, ipfs.io, 4everland, Pinata —
    /// `trustless-gateway.link` is excluded since it serves only
    /// `/ipfs/`). Operators can override e.g. for staging tests
    /// against wiremock or to add a private IPNS-aware gateway.
    pub users_index_ipns_gateway_urls: Vec<String>,

    /// `/ipfs/{cid}` gateway URL templates the resolver uses for
    /// fetching the chain-anchored CID's bytes AND the cold-start
    /// path uses for fetching the per-user `bucketsIndex` and forest
    /// manifest CBORs. Empty Vec = use the SDK-shipped six-gateway
    /// default. Independent of `gateway_fallback_urls` (which serves
    /// the warm-device offline path) so cold-start works without
    /// Phase 2.2/2.4 enabled.
    pub users_index_ipfs_gateway_urls: Vec<String>,

    /// Walkable-v8 (W.9.3) — emit CID hints in HAMT internal-node
    /// pointers, manifest pages, dir-index, and forest file-index
    /// entries from master's PUT-response ETag (= `BLAKE3(ciphertext)`
    /// raw-codec). Off by default during the v0.6.x rollout window so
    /// every write stays byte-identical to v0.5 behaviour and old SDKs
    /// can keep reading newly-written buckets.
    ///
    /// When `true`:
    ///   * `S3BlobBackend::put` parses the master-returned ETag as a
    ///     `Cid` and surfaces it in `BlobPutResult.cid`. The HAMT cascade
    ///     then emits `PointerWire::LinkV2 { storage_key, cid }` for any
    ///     re-persisted child node (legacy `Stored` siblings stay as
    ///     `Link`).
    ///   * Phase 1.5 (page commits), Phase 1.6 (dir-index commit), and
    ///     forest file-index PUTs parse the response ETag and stamp it
    ///     into `PageRef.cid`, `ManifestRoot.dir_index_cid`, and
    ///     `ForestFileEntry.storage_cid` respectively.
    ///   * Each parsed CID is **self-verified** locally before being
    ///     stamped: `BLAKE3(ciphertext)` is recomputed and compared to
    ///     the master-returned CID. On mismatch the SDK soft-fails to
    ///     `None` (logging the divergence at warn level, rate-limited
    ///     per (bucket,key) per session) so a compromised master cannot
    ///     redirect future offline walkers to attacker-controlled IPFS
    ///     bytes.
    ///
    /// When `false`: all CID-stamping fields stay `None` — readers
    /// fall through to the legacy storage-key path. Wire-format
    /// unchanged; old SDKs read newly-written buckets byte-identically
    /// to v0.5.
    ///
    /// **Default flipped to `true` on 2026-05-09 (#89)**: per the user's
    /// rollout plan ("when we roll out everyone will update"), this
    /// bypasses the W.10 step 5 80%-adoption gate. Pre-v0.6 SDKs reading
    /// newly-written buckets surface `WireVersionUnsupported` (#81 typed
    /// variant). Set to `false` explicitly to opt out per-client (e.g.,
    /// targeted regressions or backward-compat tests).
    pub walkable_v8_writer_enabled: bool,

    /// Phase 19 — optional health-status callback. When set, the SDK
    /// invokes this closure on every Up↔Down transition of the
    /// master health gate (`MasterHealthEvent::Online` /
    /// `OfflineFallbackActive`) plus on cold-start failure
    /// (`SeverelyDegraded`). Apps wire this to surface offline UI
    /// affordances. Default `None` = silent (gate works, just no
    /// transparency callback). Native-only — `Arc<dyn Fn>` doesn't
    /// cross FRB / wasm-bindgen cleanly, so wasm/Flutter surface
    /// these via the typed error variants instead.
    pub health_callback: Option<HealthCallback>,
}

// `Config` derives `Clone` but not `Debug` because `HealthCallback`
// is `Arc<dyn Fn>` which has no `Debug`. Hand-roll a `Debug` impl
// that omits the callback (printing "Some(<callback>)" or "None"),
// preserving the Phase 1.x behavior where Config could be logged.
impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("endpoint", &self.endpoint)
            .field("access_token", &self.access_token.as_deref().map(|_| "<redacted>"))
            .field("timeout", &self.timeout)
            .field("encryption_enabled", &self.encryption_enabled)
            .field("user_agent", &self.user_agent)
            .field("max_retries", &self.max_retries)
            .field("multipart_threshold", &self.multipart_threshold)
            .field("multipart_chunk_size", &self.multipart_chunk_size)
            .field("per_chunk_download_timeout", &self.per_chunk_download_timeout)
            .field("buffered_download_max_bytes", &self.buffered_download_max_bytes)
            .field("health_gate_enabled", &self.health_gate_enabled)
            .field("health_gate_ttl", &self.health_gate_ttl)
            .field("block_cache_enabled", &self.block_cache_enabled)
            .field("block_cache_path", &self.block_cache_path)
            .field("block_cache_max_bytes", &self.block_cache_max_bytes)
            .field("gateway_fallback_enabled", &self.gateway_fallback_enabled)
            .field("gateway_fallback_urls", &self.gateway_fallback_urls)
            .field("gateway_race_concurrency", &self.gateway_race_concurrency)
            .field("users_index_chain_rpc_url", &self.users_index_chain_rpc_url)
            .field("users_index_anchor_address", &self.users_index_anchor_address)
            .field("users_index_ipns_name", &self.users_index_ipns_name)
            // Per-user routing key (`BLAKE3("fula:user_id:" || sha256(email))[..16]`).
            // Stable per-account, used to route the cold-start resolver to a
            // specific user's bucketsIndex CBOR. Not a secret, but a persistent
            // user-identity correlator — redacted to match the `access_token`
            // pattern above and avoid linking log lines to a specific user.
            .field(
                "users_index_user_key",
                &self.users_index_user_key.as_ref().map(|_| "<redacted>"),
            )
            .field("users_index_ipns_gateway_urls", &self.users_index_ipns_gateway_urls)
            .field("users_index_ipfs_gateway_urls", &self.users_index_ipfs_gateway_urls)
            .field("walkable_v8_writer_enabled", &self.walkable_v8_writer_enabled)
            .field(
                "health_callback",
                &self.health_callback.as_ref().map(|_| "<callback>"),
            )
            .finish()
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            endpoint: "http://localhost:9000".to_string(),
            access_token: None,
            timeout: Duration::from_secs(30),
            encryption_enabled: false,
            user_agent: format!("fula-client/{}", env!("CARGO_PKG_VERSION")),
            max_retries: 3,
            multipart_threshold: 100 * 1024 * 1024, // 100 MB
            multipart_chunk_size: 256 * 1024,       // 256 KB (must be < 1MB for IPFS)
            per_chunk_download_timeout: Duration::from_secs(300), // 5 min
            buffered_download_max_bytes: 256 * 1024 * 1024,       // 256 MB
            health_gate_enabled: false, // backward-compat: off by default
            health_gate_ttl: Duration::from_secs(30),
            // Phase 2.2 / 2.4 — off by default for backward-compat.
            // SDK consumers must opt in explicitly; existing apps see
            // byte-identical behavior to pre-Phase-2 builds.
            block_cache_enabled: false,
            block_cache_path: None,
            block_cache_max_bytes: 256 * 1024 * 1024, // 256 MiB
            gateway_fallback_enabled: false,
            gateway_fallback_urls: Vec::new(),
            gateway_race_concurrency: 3,
            // Phase 3.3 — resolver disabled by default (every required
            // field is empty/None; field-presence is the single
            // source of truth — see config-block doc above).
            users_index_chain_rpc_url: String::new(),
            users_index_anchor_address: String::new(),
            users_index_ipns_name: String::new(),
            users_index_user_key: None,
            users_index_ipns_gateway_urls: Vec::new(),
            users_index_ipfs_gateway_urls: Vec::new(),
            // Walkable-v8 (W.9.3) — writer is opt-in during the v0.6.x
            // rollout. Default `false` keeps writes byte-identical to
            // v0.5 so old SDKs can keep reading newly-written buckets.
            // #89 (2026-05-09): default flipped from `false` to `true`
            // per user decision — every new-format-capable client emits
            // walkable-v8 wire bytes by default. Operators must hold off
            // flipping master-side gates until SDK adoption reaches the
            // % they're comfortable with for the pre-v0.6 reader cost.
            walkable_v8_writer_enabled: true,
            // Phase 19 — no callback by default (silent gate).
            health_callback: None,
        }
    }
}

impl Config {
    /// Create a new config with the given endpoint
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            ..Default::default()
        }
    }

    /// Set the access token
    pub fn with_token(mut self, token: impl Into<String>) -> Self {
        self.access_token = Some(token.into());
        self
    }

    /// Enable encryption
    pub fn with_encryption(mut self) -> Self {
        self.encryption_enabled = true;
        self
    }

    /// Set timeout
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Phase 19 — set the health-status callback. The closure is shared
    /// across `Config` clones via `Arc<dyn Fn>`; constructing once and
    /// cloning the config gives every derived `FulaClient` the same
    /// callback wiring.
    pub fn with_health_callback(mut self, callback: HealthCallback) -> Self {
        self.health_callback = Some(callback);
        self
    }

    /// Build the base URL for API requests
    pub fn base_url(&self) -> &str {
        &self.endpoint
    }
}
