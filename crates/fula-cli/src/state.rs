//! Application state

use crate::config::GatewayConfig;
use crate::multipart::MultipartManager;
use blake3::Hasher;
use fula_blockstore::{
    ClusterClient, ClusterConfig, ClusterFallbackConfig, FlexibleBlockStore, IpfsBlockStore,
    IpfsConfig, IpfsPinningBlockStore, IpfsPinningConfig, MemoryBlockStore,
};
use fula_core::BucketManager;
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};

/// Hash a user ID for privacy (Security audit fix A3)
/// This prevents exposing raw user IDs (e.g., email addresses) in stored metadata
pub fn hash_user_id(user_id: &str) -> String {
    let mut hasher = Hasher::new();
    hasher.update(b"fula:user_id:");  // Domain separation
    hasher.update(user_id.as_bytes());
    let hash = hasher.finalize();
    // Use first 16 bytes (128 bits) encoded as hex for reasonable uniqueness
    hex::encode(&hash.as_bytes()[..16])
}

/// Application state shared across handlers
pub struct AppState {
    /// Gateway configuration
    pub config: GatewayConfig,
    /// Block store (IPFS with pinning or memory fallback)
    pub block_store: Arc<FlexibleBlockStore>,
    /// Bucket manager
    pub bucket_manager: Arc<BucketManager<FlexibleBlockStore>>,
    /// Multipart upload manager
    pub multipart_manager: Arc<MultipartManager>,
    /// In-memory advisory lock store used to serialize v1 -> v7 forest
    /// migrations across devices. TTL-bounded; process-local only.
    pub lock_store: crate::handlers::locks::LockStore,
    /// Phase 3.2 master-side users-index publisher. `None` when the
    /// `FULA_USERS_INDEX_PUBLISHER_ENABLED` env flag is unset (default).
    /// When `None`, the `/_internal/users-index-state` endpoint
    /// returns 503; existing S3 handlers behave byte-identically to
    /// pre-Phase-3 deploys.
    pub users_index_publisher: Option<
        Arc<crate::handlers::users_index_publisher::UsersIndexPublisher<FlexibleBlockStore>>,
    >,
    /// W.9.6 — durable pin queue. `Some` when `pin_queue_path` is
    /// configured (production deploy). `None` when unset (tests,
    /// minimal dev configs); in that case the PUT handler falls
    /// back to the legacy fire-and-forget pin path. The drainer
    /// task is spawned by `server::run_server` if this is `Some`.
    pub pin_queue: Option<Arc<crate::pin_queue::PinQueue>>,
    /// Per-user signed-entry store for the encrypted bucketsIndex
    /// architecture (Phase 2 of the E2E plan). `Some` when the
    /// `entries_store_path` config field is set (or always-present
    /// in-memory store); `None` to fail-closed the new endpoints
    /// with 503 in deployments that haven't opted in yet. Strictly
    /// additive — when `None`, all existing routes and the legacy
    /// `users[]` plaintext publisher path behave byte-identically
    /// to pre-Phase-2 deploys.
    pub entries_store: Option<Arc<crate::entries_store::EntriesStore>>,
    /// Local-retain-until-replicated GC-safety context. `Some` when the feature
    /// is enabled (`local_retain_path` + cluster configured, not memory store).
    /// The PUT handler uses it to pin each block locally + enqueue; the verifier
    /// task (spawned in `server::run_server`) drops local pins once the cluster
    /// confirms replication. `None` = feature off (tests / dev / cluster down).
    pub local_retain: Option<Arc<crate::local_retain::LocalRetainContext>>,
    /// Per-bucket "last confirmed-pinned index node set" store (P0 index
    /// gc-safety). `Some` when `local_retain_path` is configured. The PUT
    /// handler diffs against it to pin only newly-appeared index nodes (and pin
    /// ALL when absent — rollout-safe). `None` = feature off.
    pub index_pin_set: Option<Arc<crate::index_pin_set::IndexPinSet>>,
    /// Read-only Postgres pool to the pinning DB, used ONLY by the GC-recovery
    /// endpoints (`/api/v1/buckets/{b}/resolve-keys`, `/api/v1/blocks/{cid}`) to
    /// resolve storage_key→CID and gate block fetches. `Some` when
    /// `FULA_PINS_DATABASE_URL` is set; `None` (default) → those endpoints 503.
    /// No other code path touches it; lazily connected.
    pub pins_db: Option<sqlx::PgPool>,
}

impl AppState {
    /// Create a new application state
    pub async fn new(config: GatewayConfig) -> anyhow::Result<Self> {
        // Initialize block store based on configuration
        let inner = if config.use_memory_store {
            info!("Using in-memory block store (data will not persist)");
            FlexibleBlockStore::Memory(MemoryBlockStore::new())
        } else {
            // Try to connect to IPFS with optional pinning service
            match Self::create_ipfs_store(&config).await {
                Ok(store) => {
                    info!("Connected to IPFS at {}", config.ipfs_url);
                    if config.pinning_service_endpoint.is_some() {
                        info!("Pinning service configured");
                    }
                    FlexibleBlockStore::IpfsPinning(store)
                }
                Err(e) => {
                    warn!(
                        "Failed to connect to IPFS ({}), falling back to in-memory storage",
                        e
                    );
                    FlexibleBlockStore::Memory(MemoryBlockStore::new())
                }
            }
        };

        // Wrap with the cluster-aware read fallback (inside the LRU cache,
        // around the IPFS store) when enabled. No-op for the memory store, when
        // disabled, or when the cluster is unreachable at startup.
        let inner = Self::maybe_wrap_cluster_fallback(inner, &config).await;

        // Optionally wrap in an LRU block cache
        let block_store = if config.block_cache_mb > 0 {
            info!("LRU block cache enabled ({} MB)", config.block_cache_mb);
            Arc::new(inner.with_cache_mb(config.block_cache_mb))
        } else {
            Arc::new(inner)
        };

        // Log storage mode
        if block_store.is_persistent() {
            info!("✓ Storage mode: IPFS (persistent)");
        } else {
            warn!("⚠ Storage mode: In-memory (NOT persistent - for development only)");
        }

        // Initialize bucket manager with persistence if configured
        let bucket_manager = if let Some(ref registry_path) = config.registry_cid_path {
            info!("Bucket registry persistence enabled at: {}", registry_path);
            Arc::new(BucketManager::with_persistence(
                Arc::clone(&block_store),
                registry_path,
            ))
        } else {
            info!("Bucket registry persistence disabled (no registry_cid_path configured)");
            Arc::new(BucketManager::new(Arc::clone(&block_store)))
        };

        // Load existing bucket registry from IPFS if available
        match bucket_manager.load_registry().await {
            Ok(count) if count > 0 => {
                info!("✓ Loaded {} bucket(s) from persistent registry", count);
            }
            Ok(_) => {
                info!("Starting with empty bucket registry");
            }
            Err(e) => {
                // CRITICAL: Don't continue with empty registry if load failed!
                // This prevents overwriting the CID file with an empty registry.
                return Err(anyhow::anyhow!(
                    "Failed to load bucket registry: {}. \
                     Refusing to start to prevent data loss. \
                     Ensure IPFS is running and the registry block is available, \
                     then restart the gateway.",
                    e
                ));
            }
        }

        // Initialize multipart manager. Audit F-A5 / issue #13: apply
        // per-user concurrent-multipart cap so a single authenticated
        // user cannot accumulate unbounded session state.
        let multipart_manager = {
            let mut mgr = MultipartManager::new(config.multipart_expiry_secs);
            if let Some(cap) = config.multipart_per_user_cap {
                mgr = mgr.with_per_user_cap(cap);
                info!(per_user_cap = cap, "multipart per-user cap enforced");
            } else {
                warn!(
                    "multipart per-user cap disabled (multipart_per_user_cap=None); \
                     a single authenticated user can accumulate unbounded session state"
                );
            }
            Arc::new(mgr)
        };

        // Initialize empty lock store. The sweeper is spawned by `server::run_server`
        // after AppState is wrapped in an Arc.
        let lock_store = crate::handlers::locks::LockStore::new();

        // Phase 2 entries store is built BEFORE the publisher so the
        // publisher can hold a reference and emit `users_enc` at every
        // tick (Phase 3 of the E2E plan). Backward compat: when
        // `entries_store_path` is unset, the store is empty in-memory;
        // when EVERY user lacks an entry, the published CBOR's
        // `users_enc` field is empty and serializes away thanks to
        // `skip_serializing_if`, leaving the wire-format byte-identical
        // to pre-Phase-3 deployments.
        let entries_store = {
            let path = config
                .entries_store_path
                .as_ref()
                .map(std::path::PathBuf::from);
            match crate::entries_store::EntriesStore::open(path) {
                Ok(s) => {
                    info!(entries = s.len(), "entries store ready");
                    Some(Arc::new(s))
                }
                Err(e) => {
                    warn!(
                        error = %e,
                        "entries store failed to open; per-user signed-entry endpoints will return 503 this run"
                    );
                    None
                }
            }
        };

        // Phase 3.2 users-index publisher — env-flag-gated so day-one
        // deploys behave byte-identically to pre-Phase-3 builds.
        // Operators flip `FULA_USERS_INDEX_PUBLISHER_ENABLED=1` after
        // canary verification.
        let users_index_publisher = build_users_index_publisher(
            &config,
            Arc::clone(&bucket_manager),
            Arc::clone(&block_store),
            entries_store.clone(),
        );

        // W.9.6 durable pin queue — opens the redb file at the
        // configured path. The drainer is spawned in
        // `server::run_server`; this constructor only opens the file
        // (or surfaces an open error so the operator sees it
        // immediately, before any PUT can land). When the path is
        // unset the queue stays `None` and the PUT handler falls
        // back to fire-and-forget — supported for tests + minimal
        // dev configs, NOT recommended for production.
        let pin_queue = match &config.pin_queue_path {
            Some(path) => match crate::pin_queue::PinQueue::open(path) {
                Ok(q) => {
                    info!("✓ Pin queue (W.9.6) opened at {}", path);
                    Some(Arc::new(q))
                }
                Err(e) => {
                    warn!(
                        "Failed to open pin queue at {} ({}); falling back to \
                         fire-and-forget pinning. Pin retries / crash recovery \
                         are DISABLED for this run.",
                        path, e
                    );
                    None
                }
            },
            None => {
                warn!(
                    "pin_queue_path is not configured; pinning falls back to \
                     fire-and-forget (legacy v0.5 behavior). Set \
                     `pin_queue_path` in the gateway config to enable \
                     durable retry / crash recovery."
                );
                None
            }
        };

        // Local-retain-until-replicated GC-safety. Degrades to `None` (feature
        // off) on any setup failure so it never blocks startup.
        let local_retain = Self::maybe_build_local_retain(&config).await;
        // Per-bucket pinned-index-node set (the gc-safety diff baseline).
        let index_pin_set = Self::maybe_build_index_pin_set(&config);

        // Read-only pins-DB pool for the GC-recovery endpoints (resolve-keys /
        // block-by-cid). Prefer the individual POSTGRES_* vars (no URL-encoding
        // pitfalls); fall back to a full FULA_PINS_DATABASE_URL. Neither set →
        // those two endpoints 503 and every existing route is byte-identical.
        // Strictly additive; lazily connected.
        let pins_db: Option<sqlx::PgPool> = {
            use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
            let env_nonempty = |k: &str| std::env::var(k).ok().filter(|s| !s.trim().is_empty());
            if let (Some(host), Some(db), Some(user)) = (
                env_nonempty("POSTGRES_HOST"),
                env_nonempty("POSTGRES_DB"),
                env_nonempty("POSTGRES_USER"),
            ) {
                let port = env_nonempty("POSTGRES_PORT")
                    .and_then(|s| s.parse::<u16>().ok())
                    .unwrap_or(5432);
                let pass = std::env::var("POSTGRES_PASSWORD").unwrap_or_default();
                let opts = PgConnectOptions::new()
                    .host(&host)
                    .port(port)
                    .database(&db)
                    .username(&user)
                    .password(&pass);
                info!(host = %host, port, db = %db, "✓ Pins-DB pool ready (POSTGRES_* env; recovery endpoints enabled)");
                Some(
                    PgPoolOptions::new()
                        .max_connections(5)
                        .acquire_timeout(Duration::from_secs(10))
                        .connect_lazy_with(opts),
                )
            } else if let Some(url) = env_nonempty("FULA_PINS_DATABASE_URL") {
                match PgPoolOptions::new()
                    .max_connections(5)
                    .acquire_timeout(Duration::from_secs(10))
                    .connect_lazy(&url)
                {
                    Ok(pool) => {
                        info!("✓ Pins-DB pool ready (FULA_PINS_DATABASE_URL; recovery endpoints enabled)");
                        Some(pool)
                    }
                    Err(e) => {
                        warn!(error = %e, "pins-DB URL invalid; recovery endpoints will 503 this run");
                        None
                    }
                }
            } else {
                info!("pins-DB not configured (set POSTGRES_HOST/DB/USER, or FULA_PINS_DATABASE_URL); recovery resolve-keys/block endpoints disabled (503)");
                None
            }
        };

        Ok(Self {
            config,
            block_store,
            bucket_manager,
            multipart_manager,
            lock_store,
            users_index_publisher,
            pin_queue,
            entries_store,
            local_retain,
            index_pin_set,
            pins_db,
        })
    }

    /// Create IPFS block store with optional pinning service endpoint
    /// Note: The pinning service token is provided per-request (from user's JWT),
    /// not at startup. Only the endpoint is configured at the server level.
    async fn create_ipfs_store(config: &GatewayConfig) -> anyhow::Result<IpfsPinningBlockStore> {
        let mut ipfs_config = IpfsPinningConfig::with_ipfs(&config.ipfs_url);

        // Store the pinning service endpoint if configured
        // The token will be provided per-request from the user's JWT
        if let Some(endpoint) = &config.pinning_service_endpoint {
            ipfs_config = ipfs_config.with_pinning_endpoint(endpoint);
        }

        let store = IpfsPinningBlockStore::new(ipfs_config).await?;
        Ok(store)
    }

    /// Wrap the IPFS store with the cluster-aware read fallback when enabled.
    /// Degrades to the unwrapped store (today's behavior) for the memory store,
    /// when explicitly disabled, or when the cluster API is unreachable at
    /// startup (the proactive-peering task may still run and recover reads).
    async fn maybe_wrap_cluster_fallback(
        inner: FlexibleBlockStore,
        config: &GatewayConfig,
    ) -> FlexibleBlockStore {
        let enabled = config.cluster_fallback_enabled.unwrap_or_else(|| {
            !config.use_memory_store && !config.cluster_url.trim().is_empty()
        });
        if !enabled || !matches!(inner, FlexibleBlockStore::IpfsPinning(_)) {
            return inner;
        }

        // A dedicated bounded kubo handle for the fallback's offline/online/swarm
        // calls (per-request timeouts override the client default).
        let ipfs = match IpfsBlockStore::new_unverified(IpfsConfig::with_url(&config.ipfs_url)) {
            Ok(handle) => handle,
            Err(e) => {
                warn!(error = %e, "cluster-fallback: kubo client build failed; fallback disabled");
                return inner;
            }
        };

        // Short-timeout cluster client; degrade if the cluster is down now.
        let cluster_cfg = ClusterConfig {
            timeout: Duration::from_secs(5),
            ..ClusterConfig::with_url(&config.cluster_url)
        };
        let cluster = match ClusterClient::new(cluster_cfg).await {
            Ok(c) => c,
            Err(e) => {
                warn!(
                    error = %e,
                    cluster_url = %config.cluster_url,
                    "cluster-fallback: cluster unreachable at startup; fallback disabled (peering may still run)"
                );
                return inner;
            }
        };

        // Read budget is env-tunable so a too-slow / too-fast lost-block 410 can
        // be adjusted in prod without a rebuild. Seconds; falls back to the
        // (fast-failure) defaults when unset/unparseable.
        let env_secs = |name: &str, default: std::time::Duration| -> std::time::Duration {
            std::env::var(name)
                .ok()
                .and_then(|v| v.trim().parse::<u64>().ok())
                .map(std::time::Duration::from_secs)
                .unwrap_or(default)
        };
        let fb_defaults = ClusterFallbackConfig::default();
        let fb_cfg = ClusterFallbackConfig {
            max_holders: config.cluster_fallback_max_holders.max(1),
            online_fast_timeout: env_secs(
                "FULA_READ_FAST_TIMEOUT_SECS",
                fb_defaults.online_fast_timeout,
            ),
            online_slow_timeout: env_secs(
                "FULA_READ_SLOW_TIMEOUT_SECS",
                fb_defaults.online_slow_timeout,
            ),
            file_download_timeout: env_secs(
                "FULA_READ_FILE_TIMEOUT_SECS",
                fb_defaults.file_download_timeout,
            ),
            ..fb_defaults
        };
        info!(
            cluster_url = %config.cluster_url,
            max_holders = config.cluster_fallback_max_holders,
            "✓ Cluster-aware read fallback enabled"
        );
        inner.with_cluster_fallback(ipfs, cluster, fb_cfg)
    }

    /// Build the local-retain-until-replicated context when enabled. Degrades
    /// to `None` (feature off) on any setup failure so it never blocks startup.
    async fn maybe_build_local_retain(
        config: &GatewayConfig,
    ) -> Option<Arc<crate::local_retain::LocalRetainContext>> {
        let enabled = config.local_retain_enabled.unwrap_or_else(|| {
            config.local_retain_path.is_some()
                && !config.use_memory_store
                && !config.cluster_url.trim().is_empty()
        });
        if !enabled {
            return None;
        }
        let path = config.local_retain_path.as_ref()?;

        let queue = match crate::local_retain_queue::LocalRetainQueue::open(path) {
            Ok(q) => q,
            Err(e) => {
                warn!(error = %e, path = %path, "local-retain: failed to open backlog; feature disabled");
                return None;
            }
        };
        let kubo = match IpfsBlockStore::new_unverified(IpfsConfig::with_url(&config.ipfs_url)) {
            Ok(h) => h,
            Err(e) => {
                warn!(error = %e, "local-retain: kubo client build failed; feature disabled");
                return None;
            }
        };
        let cluster_cfg = ClusterConfig {
            timeout: Duration::from_secs(10),
            ..ClusterConfig::with_url(&config.cluster_url)
        };
        // Capture the min-replication target before the config is consumed.
        let min_repl = cluster_cfg.replication.min.max(1) as usize;
        let cluster = match ClusterClient::new(cluster_cfg).await {
            Ok(c) => c,
            Err(e) => {
                warn!(error = %e, cluster_url = %config.cluster_url, "local-retain: cluster unreachable at startup; feature disabled");
                return None;
            }
        };
        let master_peer_id = match cluster.peer_info().await {
            Ok(info) => info.id,
            Err(e) => {
                warn!(error = %e, "local-retain: could not read master cluster peer id; feature disabled");
                return None;
            }
        };
        info!(
            path = %path,
            min_repl = min_repl,
            master_peer_id = %master_peer_id,
            "✓ Local-retain-until-replicated enabled (ipfs repo gc is now safe)"
        );
        Some(Arc::new(crate::local_retain::LocalRetainContext::new(
            queue,
            kubo,
            cluster,
            master_peer_id,
            min_repl,
        )))
    }

    /// Open the per-bucket pinned-index-node-set store when the gc-safety
    /// feature is configured. Derives its path next to the local-retain backlog
    /// (`local_retain_path`'s directory). Degrades to `None` on any failure so
    /// it never blocks startup; the index-node pinning in the PUT handler is
    /// then a no-op.
    fn maybe_build_index_pin_set(
        config: &GatewayConfig,
    ) -> Option<Arc<crate::index_pin_set::IndexPinSet>> {
        let base = config.local_retain_path.as_ref()?;
        let path = std::path::Path::new(base)
            .parent()
            .map(|p| p.join("index_pin_set.redb"))
            .unwrap_or_else(|| std::path::PathBuf::from("index_pin_set.redb"));
        match crate::index_pin_set::IndexPinSet::open(&path) {
            Ok(s) => {
                info!(path = %path.display(), "✓ Index-node pin-set store opened (P0 index gc-safety)");
                Some(Arc::new(s))
            }
            Err(e) => {
                warn!(error = %e, "index-pin-set: failed to open store; index-node pinning disabled");
                None
            }
        }
    }
}

/// User session information
#[derive(Clone, Debug)]
pub struct UserSession {
    /// **DO NOT PERSIST OR LOG.** Raw JWT `sub` claim, as-is.
    ///
    /// For pre-migration-011 users this is plaintext email
    /// (e.g., `"ehsan@fx.land"`); for post-migration users it's
    /// `sha256(email)` hex. Either way, treating it as PII is the
    /// only safe contract — never store this value anywhere
    /// external (object metadata, registry CBORs, IPFS pins,
    /// trace logs, metrics, HTTP responses). Use
    /// [`Self::hashed_user_id`] (the canonical opaque form
    /// `BLAKE3("fula:user_id:" || user_id)[..16]` hex) for any
    /// persisted, logged, or externally-observable identifier.
    /// The only legitimate uses of this raw value are:
    /// (1) computing `hashed_user_id` at session construction
    /// (already done in [`Self::new`]), and (2) forwarding the
    /// JWT itself (via [`Self::jwt_token`]) to the pinning
    /// service for token-based auth.
    pub user_id: String,
    /// Hashed user ID for storage (Security audit fix A3).
    /// **This is the canonical opaque identifier**: 16-byte
    /// BLAKE3 over `"fula:user_id:" || user_id`, hex-encoded.
    /// Use this anywhere a user identifier is persisted, logged,
    /// returned to a peer, or used as a map/index key.
    pub hashed_user_id: String,
    /// Display name
    pub display_name: Option<String>,
    /// Scopes
    pub scopes: Vec<String>,
    /// Expiration time
    pub expires_at: chrono::DateTime<chrono::Utc>,
    /// Raw JWT token for forwarding to pinning service
    pub jwt_token: String,
}

impl UserSession {
    /// Create a new user session with automatic ID hashing
    pub fn new(user_id: String, display_name: Option<String>, scopes: Vec<String>, expires_at: chrono::DateTime<chrono::Utc>, jwt_token: String) -> Self {
        let hashed_user_id = hash_user_id(&user_id);
        Self {
            user_id,
            hashed_user_id,
            display_name,
            scopes,
            expires_at,
            jwt_token,
        }
    }

    /// Check if the session has expired
    pub fn is_expired(&self) -> bool {
        chrono::Utc::now() > self.expires_at
    }

    /// Check if user has a scope
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.iter().any(|s| s == scope || s == "*")
    }

    /// Check if user can read
    pub fn can_read(&self) -> bool {
        self.has_scope("storage:read") || self.has_scope("storage:*")
    }

    /// Check if user can write
    pub fn can_write(&self) -> bool {
        self.has_scope("storage:write") || self.has_scope("storage:*")
    }

    /// Check if user is admin
    pub fn is_admin(&self) -> bool {
        self.has_scope("admin") || self.has_scope("*")
    }

    /// Check if user can access a bucket (owner or admin)
    /// Security audit fix A3: Uses hashed user ID for comparison
    pub fn can_access_bucket(&self, bucket_owner_id: &str) -> bool {
        self.hashed_user_id == bucket_owner_id || self.is_admin()
    }
}

/// Phase 3.2 users-index publisher constructor — env-flag-gated.
///
/// Returns `None` when `FULA_USERS_INDEX_PUBLISHER_ENABLED` is unset
/// or "0"/"false". When enabled:
///
/// | Env var                                     | Default                                                    |
/// |---------------------------------------------|------------------------------------------------------------|
/// | `FULA_USERS_INDEX_STATE_PATH`               | `/var/lib/fula-gateway/users_index_state.txt`              |
/// | `FULA_USERS_INDEX_FLUSH_INTERVAL_SECS`      | 300                                                        |
/// | `FULA_USERS_INDEX_INTERNAL_TOKEN`           | (none → endpoints fail-closed with 503)                    |
/// | `FULA_USERS_INDEX_IPNS_KEY_NAME`            | `fula-users-index`                                         |
/// | `FULA_USERS_INDEX_IPNS_LIFETIME_SECS`       | 129600 (36h)                                               |
/// | `FULA_USERS_INDEX_IPNS_TTL_SECS`            | 900 (15m)                                                  |
/// | `FULA_USERS_INDEX_IPNS_DISABLED`            | unset → IPNS enabled                                       |
/// | `FULA_USERS_INDEX_FIRST_PUBLISH_PINS_PER_S` | 100                                                        |
fn build_users_index_publisher(
    config: &GatewayConfig,
    bucket_manager: Arc<BucketManager<FlexibleBlockStore>>,
    block_store: Arc<FlexibleBlockStore>,
    entries_store: Option<Arc<crate::entries_store::EntriesStore>>,
) -> Option<Arc<crate::handlers::users_index_publisher::UsersIndexPublisher<FlexibleBlockStore>>> {
    use crate::handlers::users_index_publisher::{
        IpnsPublisher, PublisherConfig, UsersIndexPublisher,
    };
    use std::time::Duration;

    let enabled = std::env::var("FULA_USERS_INDEX_PUBLISHER_ENABLED")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if !enabled {
        info!("users-index publisher: disabled (FULA_USERS_INDEX_PUBLISHER_ENABLED unset)");
        return None;
    }

    let state_file_path = std::env::var("FULA_USERS_INDEX_STATE_PATH")
        .unwrap_or_else(|_| "/var/lib/fula-gateway/users_index_state.txt".to_string())
        .into();
    let flush_interval = Duration::from_secs(
        std::env::var("FULA_USERS_INDEX_FLUSH_INTERVAL_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(300),
    );
    let ipns_lifetime = Duration::from_secs(
        std::env::var("FULA_USERS_INDEX_IPNS_LIFETIME_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(36 * 3600),
    );
    let ipns_ttl = Duration::from_secs(
        std::env::var("FULA_USERS_INDEX_IPNS_TTL_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(15 * 60),
    );
    let ipns_key_name = std::env::var("FULA_USERS_INDEX_IPNS_KEY_NAME")
        .unwrap_or_else(|_| "fula-users-index".to_string());
    let internal_token = std::env::var("FULA_USERS_INDEX_INTERNAL_TOKEN").ok().filter(|s| !s.is_empty());
    let first_publish_max_pins_per_sec = std::env::var("FULA_USERS_INDEX_FIRST_PUBLISH_PINS_PER_S")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(100);

    let pub_config = PublisherConfig {
        flush_interval,
        first_publish_max_pins_per_sec,
        ipns_lifetime,
        ipns_ttl,
        ipns_key_name: ipns_key_name.clone(),
        state_file_path,
        ipfs_api_url: config.ipfs_url.clone(),
        internal_token: internal_token.clone(),
    };

    let ipns_disabled = std::env::var("FULA_USERS_INDEX_IPNS_DISABLED")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let ipns = if ipns_disabled {
        warn!("users-index publisher: IPNS disabled (FULA_USERS_INDEX_IPNS_DISABLED=1) — chain backup is the only publish channel");
        None
    } else {
        Some(IpnsPublisher::new(config.ipfs_url.clone()))
    };

    match UsersIndexPublisher::open_with_ipns_and_entries(
        pub_config,
        bucket_manager,
        block_store,
        ipns,
        entries_store,
    ) {
        Ok(p) => {
            info!(
                flush_interval_secs = flush_interval.as_secs(),
                ipns_key_name = %ipns_key_name,
                internal_token_set = internal_token.is_some(),
                "users-index publisher: enabled"
            );
            Some(Arc::new(p))
        }
        Err(e) => {
            warn!(
                error = %e,
                "users-index publisher: failed to open state file; publisher disabled for this run"
            );
            None
        }
    }
}

/// Admin session information
#[derive(Clone, Debug)]
pub struct AdminSession {
    /// Admin ID (from JWT sub claim)
    pub admin_id: String,
    /// Expiration time
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

impl AdminSession {
    /// Create a new admin session
    pub fn new(admin_id: String, expires_at: chrono::DateTime<chrono::Utc>) -> Self {
        Self {
            admin_id,
            expires_at,
        }
    }

    /// Check if the session has expired
    pub fn is_expired(&self) -> bool {
        chrono::Utc::now() > self.expires_at
    }
}
