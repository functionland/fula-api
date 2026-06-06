//! Gateway configuration

use serde::{Deserialize, Serialize};

/// Gateway server configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GatewayConfig {
    /// Host to bind to
    pub host: String,
    /// Port to listen on
    pub port: u16,
    /// IPFS API URL
    pub ipfs_url: String,
    /// IPFS Cluster API URL (legacy, prefer pinning_service_endpoint)
    pub cluster_url: String,
    /// IPFS Pinning Service API endpoint (standard spec)
    /// Note: The token is provided per-request from the user's JWT, not configured here.
    pub pinning_service_endpoint: Option<String>,
    /// Use in-memory storage (for testing/development)
    pub use_memory_store: bool,
    /// JWT secret for authentication
    pub jwt_secret: Option<String>,
    /// Enable authentication
    pub auth_enabled: bool,
    /// Rate limit (requests per second per user)
    pub rate_limit_rps: u32,
    /// Maximum request body size (bytes)
    pub max_body_size: usize,
    /// Maximum multipart upload size (bytes)
    pub max_upload_size: u64,
    /// Multipart upload expiry (seconds). Sessions whose
    /// `last_activity_at` is older than this are reaped by the
    /// background sweeper. Last-activity-based so slow legitimate
    /// uploads survive long pauses between parts. See audit F-A5 /
    /// issue #13.
    pub multipart_expiry_secs: u64,
    /// Maximum concurrent in-flight multipart uploads per user.
    /// `None` = unbounded (legacy). Production deploys set this to
    /// bound a single authenticated user from accumulating session
    /// state. Slots are released on complete / abort / reap.
    /// See audit F-A5 / issue #13.
    #[serde(default = "default_multipart_per_user_cap")]
    pub multipart_per_user_cap: Option<usize>,
    /// How often the multipart-reaper sweeps the in-memory upload
    /// store, in seconds. See audit F-A5 / issue #13.
    #[serde(default = "default_multipart_reaper_interval_secs")]
    pub multipart_reaper_interval_secs: u64,
    /// Enable CORS
    pub cors_enabled: bool,
    /// CORS allowed origins
    pub cors_origins: Vec<String>,
    /// Path to store bucket registry CID for persistence
    pub registry_cid_path: Option<String>,
    /// Storage API URL for balance/quota checking before uploads
    pub storage_api_url: Option<String>,
    /// Admin JWT secret for admin API authentication (separate from user JWT)
    pub admin_jwt_secret: Option<String>,
    /// Enable admin API endpoints
    pub admin_api_enabled: bool,
    /// LRU block cache capacity in MB. 0 disables the cache.
    #[serde(default = "default_block_cache_mb")]
    pub block_cache_mb: usize,
    /// W.9.6 — durable pin queue file path. When `Some`, every PUT
    /// enqueues its master-cluster + user-external pin requests to
    /// this redb-backed queue and a background drainer dispatches
    /// them with bounded concurrency + exp backoff retry. Survives
    /// master crashes — pending pins resume on the next startup.
    ///
    /// When `None` (default for tests / minimal configs), the PUT
    /// handler falls back to the legacy fire-and-forget pin path
    /// (no retry, no crash safety). Production deploys MUST set
    /// this; the fallback exists only to keep unit tests + dev
    /// deployments lightweight.
    #[serde(default)]
    pub pin_queue_path: Option<String>,
    /// Phase 2 E2E plan — JSON file path for the per-user signed-entry
    /// store. When `Some`, master accepts encrypted bucketsIndex
    /// entries via the new `/api/v1/users-index/entry` endpoint and
    /// persists them here. When `None`, the new endpoints return 503
    /// and master falls back to today's legacy `users[]` publisher
    /// path for ALL users — strictly byte-identical to pre-Phase-2
    /// behavior. Backward-compatible default.
    #[serde(default)]
    pub entries_store_path: Option<String>,

    /// Cluster-aware read fallback (see `fula_blockstore::cluster_fallback`).
    /// `None` = auto: enabled when `cluster_url` is set and not using the
    /// in-memory store. `Some(false)` is the kill-switch (exact prior behavior).
    #[serde(default)]
    pub cluster_fallback_enabled: Option<bool>,
    /// Proactive peering task: keep the gateway kubo connected to the fleet so
    /// bitswap stays fast. `None` = auto (same condition as the fallback).
    #[serde(default)]
    pub cluster_peering_enabled: Option<bool>,
    /// How often the peering task refreshes the fleet peer list + reconnects.
    #[serde(default = "default_cluster_peering_interval_secs")]
    pub cluster_peering_interval_secs: u64,
    /// Max holder peers to connect to per read miss in the fallback.
    #[serde(default = "default_cluster_fallback_max_holders")]
    pub cluster_fallback_max_holders: usize,

    /// Local-retain-until-replicated GC-safety. When enabled, every uploaded
    /// block is pinned LOCALLY on the master's kubo (so `ipfs repo gc` cannot
    /// reclaim it) and recorded in this redb backlog; a verifier drops the
    /// local pin only once the cluster confirms replication to >= min-repl
    /// non-master holders. Makes `ipfs repo gc` always safe.
    #[serde(default = "default_local_retain_path")]
    pub local_retain_path: Option<String>,
    /// `None` = auto (enabled when `local_retain_path` + `cluster_url` are set
    /// and not the in-memory store). `Some(false)` is the kill-switch.
    #[serde(default)]
    pub local_retain_enabled: Option<bool>,
    /// How often the local-retain verifier polls cluster replication status.
    #[serde(default = "default_local_retain_interval_secs")]
    pub local_retain_interval_secs: u64,
    /// One-time startup backfill: seed the backlog with the blocks already in
    /// the master's local store so the verifier protects pre-existing
    /// un-replicated data too. `None`/`Some(true)` = on, `Some(false)` = off.
    /// Throttled + background; can be disabled on very large datastores.
    #[serde(default)]
    pub local_retain_backfill: Option<bool>,

    /// GC-recovery READ-FALLBACK: on an object-GET index miss (404/410), resolve
    /// the storage_key→CID from the cluster pinset mirror and serve the block
    /// straight from the cluster. Miss-path only (healthy reads untouched). A
    /// background job mirrors the cluster pinset into the `recovery_key_cid`
    /// table. `None` = auto (on when the pins DB + `cluster_url` are configured,
    /// not the in-memory store). `Some(false)` is the kill switch (exact prior
    /// behavior — a gc-orphaned key just returns 404/410 as before).
    #[serde(default)]
    pub recovery_read_fallback_enabled: Option<bool>,
    /// How often the recovery reconcile job refreshes the cluster→CID mirror.
    #[serde(default = "default_recovery_reconcile_interval_secs")]
    pub recovery_reconcile_interval_secs: u64,
}

fn default_recovery_reconcile_interval_secs() -> u64 {
    600 // 10 minutes
}

fn default_local_retain_path() -> Option<String> {
    Some("/var/lib/fula-gateway/local_retain.redb".to_string())
}

fn default_local_retain_interval_secs() -> u64 {
    60
}

fn default_cluster_peering_interval_secs() -> u64 {
    90
}

fn default_cluster_fallback_max_holders() -> usize {
    5
}

fn default_block_cache_mb() -> usize {
    256
}

fn default_multipart_per_user_cap() -> Option<usize> {
    Some(8)
}

fn default_multipart_reaper_interval_secs() -> u64 {
    600 // 10 minutes
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            host: "0.0.0.0".to_string(),
            port: 9000,
            ipfs_url: "http://localhost:5001".to_string(),
            cluster_url: "http://localhost:9094".to_string(),
            pinning_service_endpoint: None,
            use_memory_store: false,
            jwt_secret: None,
            auth_enabled: true,
            rate_limit_rps: 100,
            max_body_size: 5 * 1024 * 1024 * 1024, // 5 GB
            max_upload_size: 5 * 1024 * 1024 * 1024 * 1024, // 5 TB
            multipart_expiry_secs: 24 * 60 * 60, // 24 hours
            multipart_per_user_cap: default_multipart_per_user_cap(),
            multipart_reaper_interval_secs: default_multipart_reaper_interval_secs(),
            cors_enabled: true,
            cors_origins: vec!["*".to_string()],
            registry_cid_path: Some("/var/lib/fula-gateway/registry.cid".to_string()),
            storage_api_url: None,
            admin_jwt_secret: None,
            admin_api_enabled: false,
            block_cache_mb: default_block_cache_mb(),
            pin_queue_path: Some("/var/lib/fula-gateway/pin_queue.redb".to_string()),
            entries_store_path: None,
            cluster_fallback_enabled: None,
            cluster_peering_enabled: None,
            cluster_peering_interval_secs: default_cluster_peering_interval_secs(),
            cluster_fallback_max_holders: default_cluster_fallback_max_holders(),
            local_retain_path: default_local_retain_path(),
            local_retain_enabled: None,
            local_retain_interval_secs: default_local_retain_interval_secs(),
            local_retain_backfill: None,
            recovery_read_fallback_enabled: None,
            recovery_reconcile_interval_secs: default_recovery_reconcile_interval_secs(),
        }
    }
}

impl GatewayConfig {
    /// Get the bind address
    pub fn bind_addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}
