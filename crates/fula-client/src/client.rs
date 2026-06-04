//! Main client implementation

use crate::{
    Config, ClientError, Result,
    health_gate::{HealthGate, GateDecision},
    types::*,
};
use bytes::Bytes;
use reqwest::{Client, Response, header};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, instrument};
// `warn` is only used by the native-only offline-fallback wrapper —
// gate the import so wasm builds don't emit `unused_imports`.
#[cfg(not(target_arch = "wasm32"))]
use tracing::warn;

#[cfg(not(target_arch = "wasm32"))]
use crate::{
    block_cache::BlockCache,
    gateway_fetch::GatewayPool,
    registry_resolver::{ResolverConfig, UsersIndexResolver},
};

/// Fula storage client
#[derive(Clone)]
pub struct FulaClient {
    config: Config,
    http: Client,
    /// Phase 2.1 of master-independent reads. `Some` when
    /// `Config::health_gate_enabled = true`; shared across all clones via
    /// `Arc` so a failure observed in one task immediately silences the
    /// rest. `None` when the feature is off — request path then runs
    /// exactly as before (backward-compat).
    health_gate: Option<Arc<HealthGate>>,

    /// Phase 2.2 / 2.4. `Some` when `Config::block_cache_enabled = true`
    /// AND the configured path opens successfully. Native-only — wasm
    /// builds compile without this field. Used by the offline-fallback
    /// wrapper to record `(bucket, key) → cid` and to short-circuit
    /// repeated reads of the same content via the BLOCKS table.
    #[cfg(not(target_arch = "wasm32"))]
    block_cache: Option<Arc<BlockCache>>,

    /// Phase 2.3 / 2.4. `Some` when `Config::gateway_fallback_enabled
    /// = true` AND `block_cache_enabled = true` (the cache is a
    /// prerequisite — without it the fallback has no CID to fetch).
    /// Native-only.
    #[cfg(not(target_arch = "wasm32"))]
    gateway_pool: Option<Arc<GatewayPool>>,

    /// Phase 3.3. `Some` when `Config::users_index_resolver_enabled
    /// = true` AND all four resolver fields (chain_rpc_url,
    /// anchor_address, ipns_name, user_key) are populated. The
    /// EncryptedClient cold-start path uses this to discover the
    /// per-user `bucketsIndexCid` when KEY_TO_CID misses.
    /// Native-only — cold-start is a no-op on wasm until a
    /// browser-friendly resolver lands.
    #[cfg(not(target_arch = "wasm32"))]
    users_index_resolver: Option<Arc<UsersIndexResolver>>,
}

impl FulaClient {
    /// Create a new client with the given configuration
    pub fn new(config: Config) -> Result<Self> {
        let mut headers = header::HeaderMap::new();
        headers.insert(
            header::USER_AGENT,
            config.user_agent.parse().unwrap(),
        );

        let builder = Client::builder()
            .default_headers(headers);

        // Timeout is not supported on WASM
        #[cfg(not(target_arch = "wasm32"))]
        let builder = builder.timeout(config.timeout);

        let http = builder.build().map_err(ClientError::Http)?;

        let health_gate = if config.health_gate_enabled {
            // Phase 19 — wire the optional health callback into the
            // gate. With_callback fires `Online` / `OfflineFallbackActive`
            // on Up↔Down transitions; without one the gate behaves
            // identically to pre-Phase-19 builds (silent).
            let gate = match config.health_callback.as_ref() {
                Some(cb) => HealthGate::with_callback(config.health_gate_ttl, Arc::clone(cb)),
                None => HealthGate::new(config.health_gate_ttl),
            };
            Some(Arc::new(gate))
        } else {
            None
        };

        // Phase 2.2 / 2.4 — block cache + gateway pool. Native-only.
        // Construction failures degrade gracefully to "no cache /
        // no fallback" rather than failing SDK init outright; the
        // operator's other workflows (master-up reads) keep working.
        #[cfg(not(target_arch = "wasm32"))]
        let block_cache = if config.block_cache_enabled {
            match build_block_cache(&config) {
                Ok(cache) => Some(Arc::new(cache)),
                Err(e) => {
                    warn!(
                        error = %e,
                        "block_cache: failed to open; offline fallback disabled for this session"
                    );
                    None
                }
            }
        } else {
            None
        };

        // Issue #8 fix #4 — gateway_pool no longer cascades to None
        // when block_cache is None.
        //
        // Old behavior: `gateway_fallback_enabled && block_cache.is_some()`.
        // If the redb cache file failed to open (e.g., another
        // EncryptedClient instance briefly held the lock during a
        // FxFiles reinit), block_cache became None — and gateway_pool
        // ALSO became None. The entire offline-fallback path was dead
        // for the session, surfaced only by an easy-to-miss `warn!`
        // line.
        //
        // New behavior: `gateway_fallback_enabled` alone gates the
        // pool. The cid-hint variant of the offline fallback
        // (`try_offline_fallback_with_cid_hint`) holds the CID
        // externally (from the just-decrypted parent's `LinkV2`
        // pointer or from `page_ref.cid`) — it does NOT need a cache
        // to source the CID, only to (best-effort) memoize the
        // fetched bytes. Letting the pool survive a cache-open
        // failure means walkable-v8 offline reads still work in the
        // degraded mode.
        //
        // The no-hint variant (`try_offline_fallback`) still requires
        // a cache to translate `(bucket, key) → cid`; if cache is
        // None there, it cleanly returns master_error without
        // attempting the race.
        #[cfg(not(target_arch = "wasm32"))]
        let gateway_pool = if config.gateway_fallback_enabled {
            let pool = if config.gateway_fallback_urls.is_empty() {
                GatewayPool::default_pool()
            } else {
                GatewayPool::with_gateways(
                    config.gateway_fallback_urls.clone(),
                    config.gateway_race_concurrency.max(1),
                )
            };
            Some(Arc::new(pool))
        } else {
            None
        };

        // Phase 3.3 — cold-start hybrid resolver. Configured iff
        // ALL four required fields are populated (no separate
        // `enabled` bool — field presence is the single source of
        // truth, per the audit-driven simplification documented on
        // Config). Fails closed: any missing field → resolver stays
        // None and cold-start surfaces UsersIndexResolutionFailed
        // at the call site rather than imploding SDK init.
        #[cfg(not(target_arch = "wasm32"))]
        let users_index_resolver = if !config.users_index_chain_rpc_url.is_empty()
            && !config.users_index_anchor_address.is_empty()
            && !config.users_index_ipns_name.is_empty()
            && config.users_index_user_key.is_some()
        {
            let mut resolver_cfg = ResolverConfig::new(
                config.users_index_chain_rpc_url.clone(),
                config.users_index_anchor_address.clone(),
                config.users_index_ipns_name.clone(),
            );
            // Phase 3.3 gateway overrides — empty Vec = use defaults.
            // Operators (and tests) can pin custom gateways here.
            if !config.users_index_ipns_gateway_urls.is_empty() {
                resolver_cfg.ipns_gateways = config.users_index_ipns_gateway_urls.clone();
            }
            if !config.users_index_ipfs_gateway_urls.is_empty() {
                resolver_cfg.ipfs_gateways = config.users_index_ipfs_gateway_urls.clone();
            }
            // Phase 3.3.5 — wire the BlockCache into the resolver
            // when both are configured. The cache enables hot-start
            // (replay-defense floor seeded across restarts; full
            // network round-trip skipped within `soft_ttl`). When
            // BlockCache is disabled, the resolver still works —
            // just without the on-disk persistence layer.
            let resolver_result = match block_cache.as_ref() {
                Some(cache) => UsersIndexResolver::new_with_cache(resolver_cfg, Arc::clone(cache)),
                None => UsersIndexResolver::new(resolver_cfg),
            };
            match resolver_result {
                Ok(r) => Some(Arc::new(r)),
                Err(e) => {
                    warn!(
                        error = %e,
                        "users_index_resolver: construction failed; cold-start unavailable for this session"
                    );
                    None
                }
            }
        } else {
            None
        };

        Ok(Self {
            config,
            http,
            health_gate,
            #[cfg(not(target_arch = "wasm32"))]
            block_cache,
            #[cfg(not(target_arch = "wasm32"))]
            gateway_pool,
            #[cfg(not(target_arch = "wasm32"))]
            users_index_resolver,
        })
    }

    /// Phase 3.3 — accessor for the cold-start hybrid resolver.
    /// Returns `Some` only when all four resolver config fields are
    /// populated (`users_index_resolver_enabled = true` plus
    /// `chain_rpc_url`, `anchor_address`, `ipns_name`, `user_key`)
    /// AND construction succeeded. Native-only.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn users_index_resolver(&self) -> Option<&Arc<UsersIndexResolver>> {
        self.users_index_resolver.as_ref()
    }

    /// Phase 2.2 — accessor for the on-disk block cache. Returns
    /// `Some` when the cache is enabled AND opened successfully.
    /// Native-only. Used by the cold-start path to populate
    /// `KEY_TO_CID` after resolving the manifest CID.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn block_cache(&self) -> Option<&Arc<BlockCache>> {
        self.block_cache.as_ref()
    }

    /// Phase 2.3 — accessor for the gateway pool. Returns `Some` when
    /// the pool is enabled AND `block_cache` is also enabled (the
    /// pair is required for the offline-fallback path to fetch
    /// CID-addressed bytes). Native-only.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn gateway_pool(&self) -> Option<&Arc<GatewayPool>> {
        self.gateway_pool.as_ref()
    }

    /// Create with default configuration
    pub fn default_local() -> Result<Self> {
        Self::new(Config::default())
    }

    /// Create with endpoint URL
    pub fn with_endpoint(endpoint: &str) -> Result<Self> {
        Self::new(Config::new(endpoint))
    }

    /// Get the configuration
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Phase 19 — fire a `MasterHealthEvent` through the configured
    /// health callback (if any). No-op when no callback is set.
    /// Panic-safe: a buggy app callback that panics is swallowed and
    /// logged at warn (same protection the gate uses internally).
    ///
    /// Used by the cold-start failure path in `EncryptedClient` to
    /// emit `SeverelyDegraded` when both IPNS and chain channels
    /// have exhausted; the health gate itself never emits
    /// `SeverelyDegraded` because it can't authoritatively detect
    /// "both down" without trying.
    ///
    /// Native-only: cold-start (the only consumer) is gated to
    /// `cfg(not(target_arch = "wasm32"))`.
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn fire_health_event(&self, event: crate::health_gate::MasterHealthEvent) {
        if let Some(cb) = self.config.health_callback.as_ref() {
            let cb = Arc::clone(cb);
            let event_clone = event.clone();
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                cb(event_clone);
            }));
            if result.is_err() {
                tracing::warn!(
                    event = ?event,
                    "health_callback panicked (cold-start path); SDK proceeding"
                );
            }
        }
    }

    /// Access the pooled HTTP client for internal modules (e.g. multipart
    /// helpers) that need to issue raw requests. Exposing this keeps
    /// connection pooling and configured timeouts intact instead of minting
    /// a fresh `reqwest::Client` per call. (NEW-F3.)
    pub(crate) fn http_client(&self) -> &Client {
        &self.http
    }

    // ==================== Bucket Operations ====================

    /// List all buckets.
    ///
    /// Issue #8 fix #2 — when master is reachable, the XML response
    /// body is mirrored into the local BlockCache's METADATA table so
    /// a subsequent master-down call (DNS error, connection refused,
    /// health-gate short-circuit, etc.) can serve from cache instead
    /// of propagating the network error.
    ///
    /// **Per-JWT scoping.** Each user's cached XML lives under a row
    /// keyed by `sha256(access_token)[..16]` so a shared cache file
    /// cannot leak one account's bucket list to another. JWT rotation
    /// invalidates the cache (new token → new scope key); the next
    /// master-up call re-populates.
    ///
    /// **No access token configured (anonymous client).** Caching is
    /// disabled — the scope key would be empty and a non-anonymous
    /// caller could collide with it.
    ///
    /// Backward compatibility: master-up behavior is byte-identical
    /// to pre-fix. The cache write is best-effort (a redb error logs
    /// at `debug` and is dropped).
    #[instrument(skip(self))]
    pub async fn list_buckets(&self) -> Result<ListBucketsResult> {
        let response = match self.request("GET", "/", None, None, None).await {
            Ok(r) => r,
            #[cfg(not(target_arch = "wasm32"))]
            Err(e) if is_master_unreachable_error(&e) => {
                // Master is unreachable. Try the cached XML body for
                // THIS user's scope.
                if let (Some(cache), Some(scope)) = (&self.block_cache, self.list_buckets_cache_scope()) {
                    match cache.load_list_buckets_xml(&scope) {
                        Ok(Some((xml, _observed_at))) => {
                            debug!("list_buckets: master unreachable; serving from cache");
                            return parse_list_buckets_response(&xml);
                        }
                        Ok(None) => {
                            debug!("list_buckets: master unreachable; no cached entry for this JWT");
                        }
                        Err(cache_err) => {
                            debug!(
                                error = %cache_err,
                                "list_buckets: master unreachable AND cache read failed"
                            );
                        }
                    }
                }
                return Err(e);
            }
            Err(e) => return Err(e),
        };
        let text = response.text().await?;
        let parsed = parse_list_buckets_response(&text)?;

        // Master-up success: mirror the body into the cache for
        // future offline reads, scoped to this JWT. Best-effort.
        #[cfg(not(target_arch = "wasm32"))]
        if let (Some(cache), Some(scope)) = (&self.block_cache, self.list_buckets_cache_scope()) {
            let observed_at = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            if let Err(e) = cache.store_list_buckets_xml(&scope, &text, observed_at) {
                debug!(
                    error = %e,
                    "list_buckets: cache write failed (best-effort; master fetch already succeeded)"
                );
            }
        }

        Ok(parsed)
    }

    /// Issue #8 fix #2 — derive the per-JWT scope key for the
    /// list-buckets cache.
    ///
    /// `sha256(access_token)[..16]` (32 hex chars). Returns `None`
    /// when no access token is configured (anonymous clients don't
    /// cache list_buckets responses; they can still serve cached
    /// reads via the cid-hint path which has its own integrity story).
    ///
    /// Security note: the cache key is derived from the bearer token
    /// rather than the OAuth-derived stable user_id because the
    /// stable id is in `EncryptionConfig` (not on `FulaClient`).
    /// JWT rotation does invalidate the cache as a side effect,
    /// which is acceptable — a fresh master-up call re-populates in
    /// seconds. The threat we're closing is cross-account
    /// pollution on shared cache files, which the JWT-bound key
    /// prevents whether or not it's rotation-stable.
    #[cfg(not(target_arch = "wasm32"))]
    fn list_buckets_cache_scope(&self) -> Option<String> {
        use sha2::{Digest, Sha256};
        let token = self.config.access_token.as_deref()?;
        if token.is_empty() {
            return None;
        }
        let digest = Sha256::digest(token.as_bytes());
        // 16 hex chars = 8 bytes of entropy. Plenty against accidental
        // collision; not a security-critical derivation.
        Some(hex::encode(&digest[..8]))
    }

    /// Create a bucket
    #[instrument(skip(self))]
    pub async fn create_bucket(&self, bucket: &str) -> Result<()> {
        let path = format!("/{}", bucket);
        self.request("PUT", &path, None, None, None).await?;
        Ok(())
    }

    /// Delete a bucket
    #[instrument(skip(self))]
    pub async fn delete_bucket(&self, bucket: &str) -> Result<()> {
        let path = format!("/{}", bucket);
        self.request("DELETE", &path, None, None, None).await?;
        Ok(())
    }

    /// Check if a bucket exists
    #[instrument(skip(self))]
    pub async fn bucket_exists(&self, bucket: &str) -> Result<bool> {
        let path = format!("/{}", bucket);
        match self.request("HEAD", &path, None, None, None).await {
            Ok(_) => Ok(true),
            Err(ref e) if e.is_not_found() => Ok(false),
            Err(e) => Err(e),
        }
    }

    // ==================== Object Operations ====================

    /// List objects in a bucket
    #[instrument(skip(self))]
    pub async fn list_objects(
        &self,
        bucket: &str,
        options: Option<ListObjectsOptions>,
    ) -> Result<ListObjectsResult> {
        let opts = options.unwrap_or_default();
        let mut query = vec![("list-type", "2".to_string())];
        
        if let Some(prefix) = &opts.prefix {
            query.push(("prefix", prefix.clone()));
        }
        if let Some(delimiter) = &opts.delimiter {
            query.push(("delimiter", delimiter.clone()));
        }
        if let Some(max_keys) = opts.max_keys {
            query.push(("max-keys", max_keys.to_string()));
        }
        if let Some(token) = &opts.continuation_token {
            query.push(("continuation-token", token.clone()));
        }
        if let Some(start_after) = &opts.start_after {
            query.push(("start-after", start_after.clone()));
        }

        let path = format!("/{}", bucket);
        let response = self.request("GET", &path, Some(&query), None, None).await?;
        let text = response.text().await?;
        parse_list_objects_response(&text, bucket)
    }

    /// Put an object
    #[instrument(skip(self, data))]
    pub async fn put_object(
        &self,
        bucket: &str,
        key: &str,
        data: impl Into<Bytes>,
    ) -> Result<PutObjectResult> {
        self.put_object_with_metadata(bucket, key, data, None).await
    }

    /// Put an object with metadata
    #[instrument(skip(self, data))]
    pub async fn put_object_with_metadata(
        &self,
        bucket: &str,
        key: &str,
        data: impl Into<Bytes>,
        metadata: Option<ObjectMetadata>,
    ) -> Result<PutObjectResult> {
        let path = format!("/{}/{}", bucket, key);
        let data = data.into();

        let mut headers = HashMap::new();
        if let Some(meta) = metadata {
            if let Some(ct) = meta.content_type {
                headers.insert("Content-Type".to_string(), ct);
            }
            for (k, v) in meta.user_metadata {
                headers.insert(format!("x-amz-meta-{}", k), v);
            }
        }

        // Clone `data` for the post-PUT cache warm. `Bytes` is
        // refcounted (Arc<u8>) so this is O(1). The PUT consumes its
        // Bytes; the clone gives us bytes for `cache.put(&cid, &bytes)`
        // after we've confirmed the PUT succeeded.
        #[cfg(not(target_arch = "wasm32"))]
        let body_for_cache = data.clone();

        let response = self.request("PUT", &path, None, Some(headers), Some(data)).await?;

        let etag = response
            .headers()
            .get("ETag")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim_matches('"').to_string())
            .unwrap_or_default();

        // Issue #8 fix #3 — warm the local BLOCKS cache with the
        // just-PUT bytes so a subsequent offline read can serve them
        // without depending on a follow-up master-up read or on
        // public-IPFS-DHT propagation of the freshly-pinned CID.
        #[cfg(not(target_arch = "wasm32"))]
        self.warm_block_cache_after_put(bucket, key, &etag, &body_for_cache).await;

        Ok(PutObjectResult {
            etag,
            version_id: None,
        })
    }

    /// Put an object with metadata and optional If-Match / If-None-Match guards.
    ///
    /// Used by conditional-write paths (e.g. forest flush) to detect concurrent
    /// modification. On ETag mismatch the server returns 412, which surfaces as
    /// `ClientError::ConcurrentModification`.
    #[instrument(skip(self, data))]
    pub async fn put_object_with_metadata_conditional(
        &self,
        bucket: &str,
        key: &str,
        data: impl Into<Bytes>,
        metadata: Option<ObjectMetadata>,
        if_match: Option<&str>,
        if_none_match: Option<&str>,
    ) -> Result<PutObjectResult> {
        let path = format!("/{}/{}", bucket, key);
        let data = data.into();

        let mut headers = HashMap::new();
        if let Some(meta) = metadata {
            if let Some(ct) = meta.content_type {
                headers.insert("Content-Type".to_string(), ct);
            }
            for (k, v) in meta.user_metadata {
                headers.insert(format!("x-amz-meta-{}", k), v);
            }
        }
        if let Some(etag) = if_match {
            headers.insert("If-Match".to_string(), format!("\"{}\"", etag.trim_matches('"')));
        }
        if let Some(etag) = if_none_match {
            let val = if etag == "*" { "*".to_string() } else { format!("\"{}\"", etag.trim_matches('"')) };
            headers.insert("If-None-Match".to_string(), val);
        }

        // Clone for the post-PUT cache warm (see put_object_with_metadata).
        #[cfg(not(target_arch = "wasm32"))]
        let body_for_cache = data.clone();

        let response = self.request("PUT", &path, None, Some(headers), Some(data)).await?;

        let etag = response
            .headers()
            .get("ETag")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim_matches('"').to_string())
            .unwrap_or_default();

        // Issue #8 fix #3 — warm BLOCKS for manifest pages, dir-index
        // commits, and the Phase-2 root commit. These all flow through
        // `put_object_with_metadata_conditional` directly (NOT through
        // S3BlobBackend), so without warming here the offline path
        // cannot serve them after a write.
        #[cfg(not(target_arch = "wasm32"))]
        self.warm_block_cache_after_put(bucket, key, &etag, &body_for_cache).await;

        Ok(PutObjectResult { etag, version_id: None })
    }

    /// Put an object with pinning credentials
    /// 
    /// This uploads the object and also pins it to a remote pinning service.
    /// 
    /// # Arguments
    /// * `bucket` - Bucket name
    /// * `key` - Object key
    /// * `data` - Object data
    /// * `pinning_service` - Pinning service endpoint (e.g., "https://api.pinata.cloud/psa")
    /// * `pinning_token` - JWT token for the pinning service
    #[instrument(skip(self, data, pinning_token))]
    pub async fn put_object_with_pinning(
        &self,
        bucket: &str,
        key: &str,
        data: impl Into<Bytes>,
        pinning_service: &str,
        pinning_token: &str,
    ) -> Result<PutObjectResult> {
        let path = format!("/{}/{}", bucket, key);
        let data = data.into();

        let mut headers = HashMap::new();
        headers.insert("X-Pinning-Service".to_string(), pinning_service.to_string());
        headers.insert("X-Pinning-Token".to_string(), pinning_token.to_string());

        #[cfg(not(target_arch = "wasm32"))]
        let body_for_cache = data.clone();

        let response = self.request("PUT", &path, None, Some(headers), Some(data)).await?;

        let etag = response
            .headers()
            .get("ETag")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim_matches('"').to_string())
            .unwrap_or_default();

        #[cfg(not(target_arch = "wasm32"))]
        self.warm_block_cache_after_put(bucket, key, &etag, &body_for_cache).await;

        Ok(PutObjectResult {
            etag,
            version_id: None,
        })
    }

    /// Put an object with metadata AND pinning credentials
    /// 
    /// Combines encrypted metadata with remote pinning support.
    #[instrument(skip(self, data, pinning_token))]
    pub async fn put_object_with_metadata_and_pinning(
        &self,
        bucket: &str,
        key: &str,
        data: impl Into<Bytes>,
        metadata: Option<ObjectMetadata>,
        pinning_service: &str,
        pinning_token: &str,
    ) -> Result<PutObjectResult> {
        let path = format!("/{}/{}", bucket, key);
        let data = data.into();

        let mut headers = HashMap::new();

        // Add metadata headers
        if let Some(meta) = metadata {
            if let Some(ct) = meta.content_type {
                headers.insert("Content-Type".to_string(), ct);
            }
            for (k, v) in meta.user_metadata {
                headers.insert(format!("x-amz-meta-{}", k), v);
            }
        }

        // Add pinning headers
        headers.insert("X-Pinning-Service".to_string(), pinning_service.to_string());
        headers.insert("X-Pinning-Token".to_string(), pinning_token.to_string());

        // Clone for the post-PUT cache warm (see put_object_with_metadata).
        #[cfg(not(target_arch = "wasm32"))]
        let body_for_cache = data.clone();

        let response = self.request("PUT", &path, None, Some(headers), Some(data)).await?;

        let etag = response
            .headers()
            .get("ETag")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim_matches('"').to_string())
            .unwrap_or_default();

        // Issue #8 fix #3 — warm BLOCKS for chunked uploads and any
        // other path that routes through the pinning variant.
        #[cfg(not(target_arch = "wasm32"))]
        self.warm_block_cache_after_put(bucket, key, &etag, &body_for_cache).await;

        Ok(PutObjectResult {
            etag,
            version_id: None,
        })
    }

    /// Issue #8 fix #3 — best-effort cache warm-up after a successful
    /// PUT.
    ///
    /// Background: every encrypted write the SDK makes is also a
    /// content-addressed pin. Pre-fix, those bytes lived only on
    /// master (and master's downstream IPFS-cluster pin chain) —
    /// the SDK's LOCAL `BlockCache` was populated exclusively by
    /// successful master-UP READS. So the user-reported flow
    /// "upload → reinit to offline → read" would walk through:
    /// `request()` → health-gate `MasterUnreachable` short-circuit
    /// → `try_offline_fallback*` → `cache.get(cid)` → MISS (writes
    /// never populated BLOCKS) → gateway race → 404 (DHT propagation
    /// hadn't reached public gateways yet for the freshly-pinned
    /// CID) → propagate `Master unreachable`. See issue #8 for the
    /// full trace.
    ///
    /// Fix: every `put_object_*` method on `FulaClient` (and
    /// `S3BlobBackend::put` for HAMT internal nodes) calls this
    /// helper after a successful PUT. The helper:
    ///
    /// 1. No-ops when `walkable_v8_writer_enabled` is off (write
    ///    semantics stay byte-identical to v0.5).
    /// 2. No-ops when `block_cache` is None (offline-fallback
    ///    infrastructure not configured).
    /// 3. Tries to parse the master ETag as a CID. Master v0.4.4+
    ///    returns `BLAKE3(body)` as the ETag string. On parse
    ///    failure (legacy master, malformed response) the warm
    ///    silently skips — the PUT itself already succeeded.
    /// 4. Best-effort `cache.put(&cid, body)` + `cache.record_key_cid`.
    ///    Failures (e.g., `BlockTooLarge` for a single body bigger
    ///    than the entire cache budget) log at debug and proceed —
    ///    the bytes are stored on master either way.
    ///
    /// Threat model: the helper writes ciphertext-as-given to the
    /// local cache. The bytes are content-addressed by the parsed
    /// CID; a malicious master that returned a wrong-CID ETag
    /// would corrupt the SDK's own KEY_TO_CID mapping but cannot
    /// inject foreign bytes via this path (the BLOCKS row is keyed
    /// by the CID the SDK *parsed*, not the CID the bytes
    /// content-address to). Subsequent offline reads through
    /// `try_offline_fallback_with_cid_hint` would re-verify the
    /// CID against the bytes via `verify_cid_against_bytes` if
    /// they came from a gateway race — but a cache HIT skips that
    /// check by design (we trust local cache contents). The
    /// upgrade story: when `walkable_v8` is on, the same flag also
    /// runs `verify_etag_matches_ciphertext` in `S3BlobBackend::put`
    /// before stamping a `LinkV2.cid` — that's the authoritative
    /// self-verify. This helper relies on that gate being on for
    /// trustworthy cache writes.
    #[cfg(not(target_arch = "wasm32"))]
    async fn warm_block_cache_after_put(
        &self,
        bucket: &str,
        key: &str,
        etag: &str,
        body: &Bytes,
    ) {
        // Walkable-v8 writer disabled → master might not return a
        // parseable CID ETag (legacy v0.5 master, multipart upload
        // returning an aggregate ETag, etc.). Skip entirely so write
        // semantics stay byte-identical to v0.5.
        if !self.config.walkable_v8_writer_enabled {
            return;
        }
        let cache = match &self.block_cache {
            Some(c) => c,
            None => return,
        };
        if etag.is_empty() {
            return;
        }
        // SECURITY: Self-verify the master-attested CID against
        // `BLAKE3(body)` BEFORE caching. Same gate `S3BlobBackend::put`
        // uses for `LinkV2.cid` stamping (see encryption.rs:438-450).
        // Without this check, a malicious or buggy master could return
        // an arbitrary CID as the ETag and the cache row would be
        // keyed by an attacker-influenced value, weakening the trust
        // chain that the cid-hint variant of `try_offline_fallback`
        // relies on (it skips `verify_cid_against_bytes` on BLOCKS
        // hits, deliberately, because BLOCKS contents are SDK-internal).
        //
        // On mismatch, `verify_etag_matches_ciphertext` returns None
        // with a rate-limited per-`(bucket, path)` warn — same
        // soft-fail-to-None policy that S3BlobBackend::put already
        // uses for its `LinkV2.cid` stamping.
        let cid = match crate::walkable_v8::verify_etag_matches_ciphertext(
            etag, body, bucket, key,
        ) {
            Some(c) => c,
            None => return,
        };
        // Best-effort writes. A BlockTooLarge error (single body
        // bigger than the entire cache budget) is the only expected
        // failure mode; everything else (redb I/O, lock contention)
        // is treated identically — log at debug, proceed.
        if let Err(e) = cache.put(&cid, body).await {
            debug!(
                error = %e,
                cid = %cid,
                bucket = %bucket,
                key = %key,
                "warm_block_cache_after_put: BLOCKS put failed (best-effort; PUT already succeeded)"
            );
        }
        if let Err(e) = cache.record_key_cid(bucket, key, &cid) {
            debug!(
                error = %e,
                cid = %cid,
                bucket = %bucket,
                key = %key,
                "warm_block_cache_after_put: KEY_TO_CID record failed (best-effort)"
            );
        }
    }

    /// Get an object
    #[instrument(skip(self))]
    pub async fn get_object(&self, bucket: &str, key: &str) -> Result<Bytes> {
        let result = self.get_object_with_metadata(bucket, key).await?;
        Ok(result.data)
    }

    /// Get an object with metadata
    #[instrument(skip(self))]
    pub async fn get_object_with_metadata(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<GetObjectResult> {
        let path = format!("/{}/{}", bucket, key);
        let response = self.request("GET", &path, None, None, None).await?;

        let headers = response.headers();
        let etag = headers
            .get("ETag")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim_matches('"').to_string())
            .unwrap_or_default();

        let content_type = headers
            .get("Content-Type")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let content_length = headers
            .get("Content-Length")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        let mut metadata = HashMap::new();
        for (name, value) in headers.iter() {
            if let Some(key) = name.as_str().strip_prefix("x-amz-meta-") {
                if let Ok(v) = value.to_str() {
                    metadata.insert(key.to_string(), v.to_string());
                }
            }
        }

        let data = response.bytes().await?;

        Ok(GetObjectResult {
            data,
            etag,
            content_type,
            content_length,
            last_modified: None,
            metadata,
        })
    }

    /// Phase 2.4 — `get_object` with offline fallback to public IPFS
    /// gateways when master is unreachable.
    ///
    /// Behavior matrix:
    ///
    /// | State                                  | Behavior                                                    | source                       | freshness               |
    /// |----------------------------------------|-------------------------------------------------------------|------------------------------|-------------------------|
    /// | flags off                              | Identical to `get_object_with_metadata` (backward-compat). | `Master`                     | `Live`                  |
    /// | flags on, master up, master responds   | Serve master bytes; populate KEY_TO_CID + BLOCKS.           | `Master`                     | `Live`                  |
    /// | flags on, master down, KEY_TO_CID hit  | Race the gateway pool for the cached CID; verify; populate. | `Gateway(url)` or `LocalCache` | `Cached { observed_at }` |
    /// | flags on, master down, KEY_TO_CID miss | Return `MasterUnreachable` (cold-start; Phase 3.3 territory).| n/a                          | n/a                     |
    /// | wasm32 target                          | Always delegates to `get_object_with_metadata` (no cache /  | `Master`                     | `Live`                  |
    /// |                                        | gateway race plumbing on web).                              |                              |                         |
    ///
    /// Etag rewrite: when the bytes come from the gateway race the
    /// returned `OfflineGetResult.inner.etag` is set to `cid.to_string()`
    /// so downstream callers (e.g., `load_forest_internal`) see the
    /// same ETag-as-CID convention master uses on the fast path.
    ///
    /// **Known offline-path difference (Phase 2.4 v1):** when bytes
    /// come from the gateway race or BLOCKS cache, the returned
    /// `inner.metadata` is **empty** and `content_type` is `None`.
    /// Master-up responses still surface `x-amz-meta-*` headers in
    /// `metadata`. Encrypted-SDK callers never read user-metadata, so
    /// this is invisible to them; app-level callers that depend on
    /// user-metadata should treat the offline path as metadata-stripped.
    ///
    /// **Phase 19 — return type changed to `OfflineGetResult`.** The
    /// extra fields `source: ReadSource` and `freshness: ReadFreshness`
    /// let apps surface "you're offline; reading from cache" UI without
    /// observing internal state. Existing callers extract `.inner.data`
    /// / `.inner.etag` to access the bytes (one-line change).
    ///
    /// **Breaking change vs. Phase 2.4:** the previous `Result<GetObjectResult>`
    /// signature is gone. Audit (2026-05-02) established no external
    /// SDK consumers — Phase 2.4 GET-path wiring (task #15) is still
    /// pending — so today's blast radius is zero. Document this in
    /// the next release note so the Phase 2.4 wiring lands with the
    /// new signature and doesn't accidentally inherit a backward-compat
    /// expectation. Internal callers (S3BlobBackend, encrypted
    /// cold-start) are already updated; their bytes are accessed via
    /// `result.inner.data`.
    #[cfg(not(target_arch = "wasm32"))]
    #[instrument(skip(self))]
    pub async fn get_object_with_offline_fallback(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<OfflineGetResult> {
        // Fast path — if neither flag is on, this is byte-identical
        // to the existing call. The new method costs nothing in
        // existing deployments.
        if self.block_cache.is_none() && self.gateway_pool.is_none() {
            let inner = self.get_object_with_metadata(bucket, key).await?;
            return Ok(OfflineGetResult {
                inner,
                source: ReadSource::Master,
                freshness: ReadFreshness::Live,
            });
        }

        let cache = self.block_cache.clone();

        // Master attempt. If health gate already says Down, request()
        // short-circuits before touching the network. Otherwise we
        // hit master normally.
        match self.get_object_with_metadata(bucket, key).await {
            Ok(result) => {
                // Master-up success path: record the CID side-effect.
                // Skip if etag is empty (defensive: every master
                // response should have one, but a future endpoint
                // change shouldn't break the wrapper).
                if let Some(cache) = &cache {
                    if !result.etag.is_empty() {
                        if let Ok(cid) = result.etag.parse::<cid::Cid>() {
                            // Both writes are best-effort: a redb error
                            // logs and proceeds (the master read already
                            // succeeded, so the user gets their bytes).
                            if let Err(e) = cache.record_key_cid(bucket, key, &cid) {
                                debug!(
                                    error = %e,
                                    "block_cache: record_key_cid failed (best-effort; master fetch already succeeded)"
                                );
                            }
                            // Cache the bytes themselves so a subsequent
                            // master-down read can serve them without
                            // any network round-trip at all.
                            if let Err(e) = cache.put(&cid, &result.data).await {
                                // BlockTooLarge is expected for huge
                                // objects (>cache budget); not a bug.
                                debug!(
                                    error = %e,
                                    "block_cache: put failed (best-effort)"
                                );
                            }
                        }
                    }
                }
                Ok(OfflineGetResult {
                    inner: result,
                    source: ReadSource::Master,
                    freshness: ReadFreshness::Live,
                })
            }
            Err(e) if is_master_unreachable_error(&e) => {
                // Master-down: try the offline path. Requires the
                // cache + pool to be set AND a prior master-up read
                // for this `(bucket, key)` to have populated KEY_TO_CID.
                self.try_offline_fallback(bucket, key, e).await
            }
            // Non-master-down errors (4xx, auth failures, etc.)
            // propagate without any fallback attempt — they're not
            // about availability.
            Err(e) => Err(e),
        }
    }

    /// Wasm version: no offline fallback infrastructure exists on
    /// browsers (block_cache + gateway_fetch are gated out). Delegate
    /// to the regular method so call sites can use one name across
    /// targets without additional `cfg` gates of their own.
    #[cfg(target_arch = "wasm32")]
    pub async fn get_object_with_offline_fallback(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<OfflineGetResult> {
        let inner = self.get_object_with_metadata(bucket, key).await?;
        Ok(OfflineGetResult {
            inner,
            source: ReadSource::Master,
            freshness: ReadFreshness::Live,
        })
    }

    /// Cold-cache cold-start variant of [`get_object_with_offline_fallback`].
    ///
    /// Same master-up fast path — when master responds, this method is
    /// byte-identical in latency and behavior. The CID hint is consulted
    /// only on the master-down branch, so a healthy deployment pays
    /// nothing for it. The hint lets a freshly-installed device fetch
    /// objects whose CID it just learned from a parent structure (e.g.,
    /// a manifest root just decrypted from IPNS) without the prior
    /// master-up read that warm-cache fallback requires.
    ///
    /// Privacy: the hint is a content-addressed CID; it leaves the
    /// device only as part of the gateway race for that exact CID, the
    /// same shape of network traffic that's already part of the
    /// warm-cache offline path. No new identifier or PII reaches the
    /// network, and the AEAD ciphertext stored at the CID is unchanged.
    #[cfg(not(target_arch = "wasm32"))]
    #[instrument(skip(self, cid_hint))]
    pub async fn get_object_with_offline_fallback_known_cid(
        &self,
        bucket: &str,
        key: &str,
        cid_hint: &cid::Cid,
    ) -> Result<OfflineGetResult> {
        // Generic cid-hint entry point. A 404/NoSuchKey from a reachable
        // master propagates UNCHANGED (a missing object is a real miss,
        // not an offline condition); only master-unreachable consults the
        // hint. This strict invariant is covered by
        // `test_cid_hint_master_4xx_propagates_without_fallback` — do not
        // weaken it. Callers that must recover a gc-orphaned object on a
        // 404 (forest infra + the encrypted-download path) use
        // `get_object_with_recovery_known_cid` instead.
        self.get_object_with_offline_fallback_known_cid_inner(bucket, key, cid_hint, false)
            .await
    }

    /// Gc-orphan-recovery variant of
    /// [`get_object_with_offline_fallback_known_cid`] (issue #24, extended
    /// to the encrypted-download path).
    ///
    /// Identical to the generic method EXCEPT it ALSO engages the verified
    /// gateway race when a reachable master returns a 404/NoSuchKey —
    /// recovering an object whose gateway storage-key → CID index entry was
    /// destroyed by a server-side `ipfs repo gc` while the block itself
    /// still exists in IPFS by CID.
    ///
    /// Used by callers that fetch a MANIFEST/INDEX-REFERENCED object with an
    /// authoritative, freshly-decrypted CID: forest infrastructure (HAMT
    /// nodes + manifest pages) AND the encrypted-download path (the
    /// single-block file object via `forest_entry.storage_cid`, and data
    /// chunks via `chunked_meta.chunk_cid`). For all of these a 404 means
    /// "index entry gc'd", not "object deleted" — deletion is a hard index
    /// removal (`delete_object_flat`: "an orphaned blob is recoverable, a
    /// dangling ref is not"), so a still-referenced object is live. The
    /// fetched bytes are content-verified against the supplied CID inside
    /// the gateway race (`fetch_verified` → `verify_cid_against_bytes`), so
    /// recovery can only ever return the exact block the manifest/index
    /// points at — the CID is the capability — and if the block is truly
    /// gone the race fails and the original 404 propagates (genuine loss
    /// stays a hard error; chunks are additionally Bao-verified during
    /// assembly). The generic method keeps the strict propagate-404
    /// invariant so the dir-index sentinel (404 → `Ok(None)`) and any
    /// future non-recovering caller can never silently inherit hide-404
    /// behavior.
    #[cfg(not(target_arch = "wasm32"))]
    #[instrument(skip(self, cid_hint))]
    pub async fn get_object_with_recovery_known_cid(
        &self,
        bucket: &str,
        key: &str,
        cid_hint: &cid::Cid,
    ) -> Result<OfflineGetResult> {
        self.get_object_with_offline_fallback_known_cid_inner(bucket, key, cid_hint, true)
            .await
    }

    /// Shared implementation of the two cid-hint entry points above.
    /// `recover_on_not_found` gates the gc-orphan-recovery behavior: `true`
    /// routes a 404/NoSuchKey from a reachable master into the verified
    /// gateway race (forest nodes/pages + download objects/chunks); `false`
    /// propagates the 404 unchanged (generic objects + the dir-index
    /// sentinel). The master-up success path and the master-unreachable
    /// branch are identical for both.
    #[cfg(not(target_arch = "wasm32"))]
    async fn get_object_with_offline_fallback_known_cid_inner(
        &self,
        bucket: &str,
        key: &str,
        cid_hint: &cid::Cid,
        recover_on_not_found: bool,
    ) -> Result<OfflineGetResult> {
        // Fast path mirror of get_object_with_offline_fallback — flags
        // off means no hint consumption, identical latency.
        if self.block_cache.is_none() && self.gateway_pool.is_none() {
            let inner = self.get_object_with_metadata(bucket, key).await?;
            return Ok(OfflineGetResult {
                inner,
                source: ReadSource::Master,
                freshness: ReadFreshness::Live,
            });
        }

        let cache = self.block_cache.clone();

        match self.get_object_with_metadata(bucket, key).await {
            Ok(result) => {
                // Master-up success: populate KEY_TO_CID + BLOCKS so
                // the next read of this object can skip the network
                // entirely. Identical bookkeeping to the no-hint
                // wrapper above; the hint isn't needed when master
                // responded.
                if let Some(cache) = &cache {
                    if !result.etag.is_empty() {
                        if let Ok(cid) = result.etag.parse::<cid::Cid>() {
                            if let Err(e) = cache.record_key_cid(bucket, key, &cid) {
                                debug!(
                                    error = %e,
                                    "block_cache: record_key_cid failed (best-effort; master fetch already succeeded)"
                                );
                            }
                            if let Err(e) = cache.put(&cid, &result.data).await {
                                debug!(
                                    error = %e,
                                    "block_cache: put failed (best-effort)"
                                );
                            }
                        }
                    }
                }
                Ok(OfflineGetResult {
                    inner: result,
                    source: ReadSource::Master,
                    freshness: ReadFreshness::Live,
                })
            }
            // Gc-orphan recovery (`recover_on_not_found`) ALSO recovers on a
            // NoSuchKey/404 from a REACHABLE master — the object's gateway
            // storage-key→CID index entry was gc-orphaned while the block
            // still exists by CID. We match the shared `is_not_found()`
            // (which also covers NoSuchBucket) rather than a narrower
            // object-only predicate on purpose: every recovering caller
            // (forest `S3BlobBackend::get_with_cid_hint` + `load_manifest_pages`,
            // and the download path's index-object + chunk fetches) is reached
            // only AFTER the bucket's manifest/forest decrypted, so a
            // NoSuchBucket cannot occur here, and the gateway race is
            // content-verified against the manifest-supplied CID regardless of
            // which not-found shape triggered it (caller scope verified at
            // source during review).
            Err(e)
                if is_master_unreachable_error(&e)
                    || (recover_on_not_found && e.is_not_found()) =>
            {
                // Surface gc-orphan recovery: a silent recover would hide
                // ongoing gateway-index rot. Fires only on the reachable-
                // master not-found path, not the normal master-unreachable
                // case (which is the expected offline-mode flow).
                if recover_on_not_found && !is_master_unreachable_error(&e) {
                    warn!(
                        bucket = %bucket,
                        key = %key,
                        cid = %cid_hint,
                        "gc-orphaned object recovered: not-found from reachable \
                         master — gateway storage-key->CID index entry likely \
                         gc'd; recovering the block via verified gateway race by \
                         CID. Repeated occurrences mean the gateway index needs \
                         re-pin (a forest node/page, or a file index-object/chunk)."
                    );
                }
                self.try_offline_fallback_with_cid_hint(bucket, key, cid_hint, e)
                    .await
            }
            Err(e) => Err(e),
        }
    }

    /// Phase 2.4 fallback step. Looks up the cached CID for the
    /// requested `(bucket, key)`; if absent, returns the original
    /// `MasterUnreachable` error (cold-start case — Phase 3.3 catches
    /// it). If present, races the gateway pool for that CID; on
    /// verification success, populates BLOCKS and returns a synthesized
    /// `OfflineGetResult` with `source = LocalCache` (BLOCKS hit) or
    /// `source = Gateway(url_template)` (gateway race), and
    /// `freshness = Cached { observed_at }`. On any gateway-side
    /// failure, propagates the original master-down error so the
    /// caller sees a stable error type regardless of which channel
    /// ultimately failed.
    #[cfg(not(target_arch = "wasm32"))]
    async fn try_offline_fallback(
        &self,
        bucket: &str,
        key: &str,
        master_error: ClientError,
    ) -> Result<OfflineGetResult> {
        let (cache, pool) = match (&self.block_cache, &self.gateway_pool) {
            (Some(c), Some(p)) => (c.clone(), p.clone()),
            _ => return Err(master_error),
        };

        // Step 1 — translate (bucket, key) → CID via the warm-cache
        // table populated during prior master-up reads. Cold-start
        // misses return MasterUnreachable so the app can show
        // "offline mode unavailable for this object yet".
        let cid = match cache.lookup_cid(bucket, key) {
            Ok(Some(cid)) => cid,
            Ok(None) => {
                debug!(
                    bucket = %bucket, key = %key,
                    "offline fallback: no cached CID for this object (cold-start; needs Phase 3.3)"
                );
                return Err(master_error);
            }
            Err(e) => {
                warn!(error = %e, "offline fallback: lookup_cid failed");
                return Err(master_error);
            }
        };

        // Step 2 — BLOCKS hit short-circuits the network entirely.
        // Cheap: a single redb read.
        if let Ok(Some(bytes)) = cache.get(&cid) {
            debug!(cid = %cid, "offline fallback: BLOCKS hit");
            let observed_at = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);
            return Ok(OfflineGetResult {
                inner: GetObjectResult {
                    content_length: bytes.len() as u64,
                    data: bytes,
                    etag: cid.to_string(),
                    content_type: None,
                    last_modified: None,
                    metadata: HashMap::new(),
                },
                source: ReadSource::LocalCache,
                freshness: ReadFreshness::Cached { observed_at },
            });
        }

        // Step 3 — race the gateway pool. fetch_verified handles the
        // CID verification (verify_cid_against_bytes) internally;
        // bytes returned here are guaranteed to content-address to
        // the requested CID. The accompanying URL template records
        // which gateway won the race for transparency surfacing.
        match pool.fetch_verified_with_source(&cid, &self.http).await {
            Ok((bytes, gateway_url)) => {
                debug!(cid = %cid, gateway = %gateway_url, "offline fallback: gateway race succeeded");
                // Populate BLOCKS so the next read of this object
                // serves entirely locally. BlockTooLarge is the only
                // expected failure (huge objects); fall through and
                // still return the bytes to the caller.
                if let Err(e) = cache.put(&cid, &bytes).await {
                    debug!(error = %e, "offline fallback: BLOCKS put failed (best-effort)");
                }
                let observed_at = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(0);
                Ok(OfflineGetResult {
                    inner: GetObjectResult {
                        content_length: bytes.len() as u64,
                        data: bytes,
                        etag: cid.to_string(),
                        content_type: None,
                        last_modified: None,
                        metadata: HashMap::new(),
                    },
                    source: ReadSource::Gateway(gateway_url),
                    freshness: ReadFreshness::Cached { observed_at },
                })
            }
            Err(e) => {
                warn!(
                    cid = %cid,
                    error = %e,
                    "offline fallback: gateway race failed"
                );
                // Propagate the original master error rather than the
                // gateway error — callers expect a single failure type
                // for "the object is unreachable" and the gateway-race
                // error is a secondary signal.
                Err(master_error)
            }
        }
    }

    /// Cold-cache variant of [`try_offline_fallback`]. The caller has
    /// already learned the object's CID (typically by decrypting a
    /// just-fetched manifest root that points at it) and supplies it
    /// directly, skipping the KEY_TO_CID lookup that the warm-cache
    /// path depends on. BLOCKS-hit short-circuit and gateway-race
    /// verification are otherwise identical, and the post-fetch cache
    /// populate restores the warm-cache invariant for subsequent reads.
    #[cfg(not(target_arch = "wasm32"))]
    async fn try_offline_fallback_with_cid_hint(
        &self,
        bucket: &str,
        key: &str,
        cid: &cid::Cid,
        master_error: ClientError,
    ) -> Result<OfflineGetResult> {
        // Issue #8 fix #4 — the cid-hint variant works even when
        // block_cache is None. The CID is supplied externally (from
        // a just-decrypted parent's `LinkV2` pointer or from
        // `page_ref.cid`), so we can race the gateway pool directly.
        // Cache, when present, is used for BLOCKS short-circuit + post-
        // fetch memoization; absent, those become no-ops.
        let pool = match &self.gateway_pool {
            Some(p) => p.clone(),
            None => return Err(master_error),
        };
        let cache = self.block_cache.clone();

        // BLOCKS hit — same short-circuit as warm-cache fallback. A
        // prior cold-start that raced this exact CID populated the
        // cache, so a follow-up read serves with no network at all.
        if let Some(c) = &cache {
            if let Ok(Some(bytes)) = c.get(cid) {
                debug!(cid = %cid, "offline fallback (cid-hint): BLOCKS hit");
                // Best-effort warm-cache backfill: if this is the
                // first time we've seen this `(bucket, key)`, record
                // the mapping so the next read can use the no-hint
                // warm path too.
                if let Err(e) = c.record_key_cid(bucket, key, cid) {
                    debug!(
                        error = %e,
                        "block_cache: record_key_cid failed (best-effort)"
                    );
                }
                let observed_at = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(0);
                return Ok(OfflineGetResult {
                    inner: GetObjectResult {
                        content_length: bytes.len() as u64,
                        data: bytes,
                        etag: cid.to_string(),
                        content_type: None,
                        last_modified: None,
                        metadata: HashMap::new(),
                    },
                    source: ReadSource::LocalCache,
                    freshness: ReadFreshness::Cached { observed_at },
                });
            }
        }

        // Gateway race using the supplied CID. fetch_verified verifies
        // the bytes content-address to the requested CID, so a
        // malicious or buggy gateway cannot inject foreign bytes
        // here any more than it can on the warm-cache path.
        match pool.fetch_verified_with_source(cid, &self.http).await {
            Ok((bytes, gateway_url)) => {
                debug!(
                    cid = %cid,
                    gateway = %gateway_url,
                    "offline fallback (cid-hint): gateway race succeeded"
                );
                // Populate BLOCKS + KEY_TO_CID when a cache is present
                // so subsequent reads skip the network. Best-effort —
                // a redb error doesn't break this fetch, and an absent
                // cache just means we re-race on the next read.
                if let Some(c) = &cache {
                    if let Err(e) = c.put(cid, &bytes).await {
                        debug!(
                            error = %e,
                            "block_cache: put failed (best-effort)"
                        );
                    }
                    if let Err(e) = c.record_key_cid(bucket, key, cid) {
                        debug!(
                            error = %e,
                            "block_cache: record_key_cid failed (best-effort)"
                        );
                    }
                }
                let observed_at = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(0);
                Ok(OfflineGetResult {
                    inner: GetObjectResult {
                        content_length: bytes.len() as u64,
                        data: bytes,
                        etag: cid.to_string(),
                        content_type: None,
                        last_modified: None,
                        metadata: HashMap::new(),
                    },
                    source: ReadSource::Gateway(gateway_url),
                    freshness: ReadFreshness::Cached { observed_at },
                })
            }
            Err(e) => {
                warn!(
                    cid = %cid,
                    error = %e,
                    "offline fallback (cid-hint): gateway race failed"
                );
                Err(master_error)
            }
        }
    }

    /// Check if an object exists
    #[instrument(skip(self))]
    pub async fn object_exists(&self, bucket: &str, key: &str) -> Result<bool> {
        match self.head_object(bucket, key).await {
            Ok(_) => Ok(true),
            Err(ref e) if e.is_not_found() => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Head an object (get metadata without content)
    #[instrument(skip(self))]
    pub async fn head_object(&self, bucket: &str, key: &str) -> Result<HeadObjectResult> {
        let path = format!("/{}/{}", bucket, key);
        let response = self.request("HEAD", &path, None, None, None).await?;
        
        let headers = response.headers();
        let etag = headers
            .get("ETag")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim_matches('"').to_string())
            .unwrap_or_default();
        
        let content_type = headers
            .get("Content-Type")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        
        let content_length = headers
            .get("Content-Length")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        let mut metadata = HashMap::new();
        for (name, value) in headers.iter() {
            if let Some(key) = name.as_str().strip_prefix("x-amz-meta-") {
                if let Ok(v) = value.to_str() {
                    metadata.insert(key.to_string(), v.to_string());
                }
            }
        }

        Ok(HeadObjectResult {
            etag,
            content_type,
            content_length,
            last_modified: None,
            metadata,
        })
    }

    /// Delete an object
    #[instrument(skip(self))]
    pub async fn delete_object(&self, bucket: &str, key: &str) -> Result<()> {
        let path = format!("/{}/{}", bucket, key);
        self.request("DELETE", &path, None, None, None).await?;
        Ok(())
    }

    /// Copy an object
    #[instrument(skip(self))]
    pub async fn copy_object(
        &self,
        source_bucket: &str,
        source_key: &str,
        dest_bucket: &str,
        dest_key: &str,
    ) -> Result<CopyObjectResult> {
        let path = format!("/{}/{}", dest_bucket, dest_key);
        let copy_source = format!("/{}/{}", source_bucket, source_key);
        
        let mut headers = HashMap::new();
        headers.insert("x-amz-copy-source".to_string(), copy_source);

        let response = self.request("PUT", &path, None, Some(headers), None).await?;
        let text = response.text().await?;
        parse_copy_object_response(&text)
    }

    // ==================== Helper Methods ====================

    async fn request(
        &self,
        method: &str,
        path: &str,
        query: Option<&[(&str, String)]>,
        headers: Option<HashMap<String, String>>,
        body: Option<Bytes>,
    ) -> Result<Response> {
        // Phase 2.1: consult the health gate before sending. When Down +
        // within TTL, short-circuit with MasterUnreachable so the caller
        // doesn't pay the per-read timeout. When the TTL has elapsed the
        // gate auto-allows a probe through.
        if let Some(gate) = &self.health_gate {
            if let GateDecision::ShortCircuit { down_for_secs } = gate.decide() {
                debug!(
                    method = %method,
                    path = %path,
                    "health gate Down → short-circuiting (down_for_secs={})",
                    down_for_secs
                );
                return Err(ClientError::MasterUnreachable { down_for_secs });
            }
        }

        let url = format!("{}{}", self.config.endpoint, path);

        let mut req = match method {
            "GET" => self.http.get(&url),
            "PUT" => self.http.put(&url),
            "POST" => self.http.post(&url),
            "DELETE" => self.http.delete(&url),
            "HEAD" => self.http.head(&url),
            _ => return Err(ClientError::Config(format!("Unknown method: {}", method))),
        };

        // The master health gate answers "can I READ from the master?", so only
        // read methods (GET/HEAD) may TRIP it. A failed WRITE (PUT/POST/DELETE)
        // is a write-specific condition — e.g. the master accepted the request
        // but couldn't durably pin the block (local-retain fatal-pin → 5xx) —
        // and must NOT black out the whole app for reads that still work. A
        // *successful* response of any method still proves reachability, so it
        // clears the gate unconditionally (`record_success` below).
        let read_method = matches!(method, "GET" | "HEAD");

        // Add query parameters
        if let Some(q) = query {
            req = req.query(q);
        }

        // Add authorization
        if let Some(token) = &self.config.access_token {
            req = req.header("Authorization", format!("Bearer {}", token));
        }

        // Add custom headers
        if let Some(hdrs) = headers {
            for (k, v) in hdrs {
                req = req.header(&k, v);
            }
        }

        // Add body
        if let Some(data) = body {
            req = req.body(data);
        }

        debug!("Sending {} request to {}", method, url);
        let response = match req.send().await {
            Ok(r) => r,
            Err(e) => {
                // Connection-level error (refused, RST, DNS, timeout). For a
                // READ this is a master-down signal; for a WRITE we leave the
                // gate untouched — a write timeout (e.g. a slow fatal pin) must
                // not flip the app offline for reads that still work.
                if let Some(gate) = &self.health_gate {
                    if read_method {
                        gate.record_failure();
                    }
                }
                return Err(ClientError::Http(e));
            }
        };

        // Check for errors
        let status = response.status();

        // Phase 2.1: classify the response status for the health gate.
        //   5xx on a READ  → master-side read failure → record_failure
        //   5xx on a WRITE → write-specific (e.g. durability/pin) → gate untouched
        //   4xx → request-level (auth, not-found, precondition, etc.); NOT
        //         a master-down signal — the server responded, the request
        //         was just bad. Don't touch the gate.
        //   2xx/3xx (any method) → success → record_success (also clears any prior Down)
        if let Some(gate) = &self.health_gate {
            if status.is_server_error() {
                if read_method {
                    gate.record_failure();
                }
            } else if status.is_success() {
                gate.record_success();
            }
        }

        if !status.is_success() {
            // 412 Precondition Failed surfaces as ConcurrentModification so
            // callers using If-Match / If-None-Match can retry distinctly.
            if status.as_u16() == 412 {
                let _ = response.text().await;
                return Err(ClientError::ConcurrentModification(
                    "precondition failed (ETag mismatch)".to_string()
                ));
            }

            // 409 on a /locks/ endpoint means the migration lock is held.
            // We narrowly gate on the path so non-lock 409s (e.g. S3
            // BucketAlreadyExists) continue to surface as S3 errors.
            if status.as_u16() == 409 && path.starts_with("/locks/") {
                let body = response.text().await.unwrap_or_default();
                let expires_at = serde_json::from_str::<serde_json::Value>(&body)
                    .ok()
                    .and_then(|v| v.get("expires_at").and_then(|e| e.as_i64()))
                    .unwrap_or(0);
                // Strip the "/locks/" prefix to recover the bucket name, and
                // drop any trailing "/heartbeat" segment.
                let bucket = path
                    .trim_start_matches("/locks/")
                    .split('/')
                    .next()
                    .unwrap_or("")
                    .to_string();
                return Err(ClientError::MigrationLockHeld { bucket, expires_at });
            }

            // S3-compat: error code lives in the `x-amz-error-code` header
            // for HEAD responses (which carry no body) AND duplicated for
            // every error response by our master (see fula-cli error.rs).
            //
            // Prefer the XML body's `<Message>` when present (it carries
            // the master-side context, e.g., "bucket already exists: foo")
            // and fall back to the header + a generic message only when
            // the body is empty (HEAD response). The prior implementation
            // unconditionally substituted `"Object not found"` whenever
            // the header was present, swallowing every real error message
            // and producing the famous "BucketAlreadyExists / Object not
            // found" mismatch (filed in the 2026-05 E2E run).
            let error_code_header = response
                .headers()
                .get("x-amz-error-code")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());

            let text = response.text().await.unwrap_or_default();

            if !text.is_empty() {
                return Err(ClientError::from_s3_xml(&text, status.as_u16()));
            }

            if let Some(code) = error_code_header {
                return Err(ClientError::S3Error {
                    code,
                    // Empty body (typically HEAD) — synthesize a minimal
                    // message from the HTTP status.
                    message: status.canonical_reason().unwrap_or("error").to_string(),
                    request_id: None,
                });
            }

            return Err(ClientError::from_s3_xml(&text, status.as_u16()));
        }

        Ok(response)
    }
}

/// Handle returned from `acquire_migration_lock`. Carries the token needed
/// to release the lock or refresh its TTL.
#[derive(Debug, Clone)]
pub struct MigrationLockHandle {
    pub token: String,
    pub expires_at_ms: i64,
}

impl FulaClient {
    /// Acquire the server-side migration advisory lock for `bucket`.
    ///
    /// Returns the holder's token on success. On 409, returns
    /// `ClientError::MigrationLockHeld { bucket, expires_at }` — the caller
    /// should interpret this as "another device is migrating" and fall back
    /// to a read-only path.
    #[instrument(skip(self))]
    pub async fn acquire_migration_lock(&self, bucket: &str) -> Result<MigrationLockHandle> {
        let path = format!("/locks/{}", bucket);
        let response = self.request("POST", &path, None, None, None).await?;
        let text = response.text().await?;
        let v: serde_json::Value = serde_json::from_str(&text)
            .map_err(|e| ClientError::InvalidResponse(format!("lock acquire: {}", e)))?;
        let token = v.get("token").and_then(|t| t.as_str())
            .ok_or_else(|| ClientError::InvalidResponse("lock acquire: missing token".into()))?
            .to_string();
        let expires_at_ms = v.get("expires_at").and_then(|e| e.as_i64())
            .ok_or_else(|| ClientError::InvalidResponse("lock acquire: missing expires_at".into()))?;
        Ok(MigrationLockHandle { token, expires_at_ms })
    }

    /// Release the migration lock for `bucket`. Requires the token returned
    /// from `acquire_migration_lock`. Idempotent: a 404 (already released)
    /// is treated as success.
    #[instrument(skip(self, token))]
    pub async fn release_migration_lock(&self, bucket: &str, token: &str) -> Result<()> {
        let path = format!("/locks/{}", bucket);
        let mut headers = HashMap::new();
        headers.insert("x-fula-lock-token".to_string(), token.to_string());
        match self.request("DELETE", &path, None, Some(headers), None).await {
            Ok(_) => Ok(()),
            Err(e) if e.is_not_found() => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Refresh the TTL on the migration lock for `bucket`. Returns the new
    /// `expires_at_ms`. Callers should run this on a ~30s cadence so the
    /// 60s server TTL never lapses mid-migration.
    #[instrument(skip(self, token))]
    pub async fn heartbeat_migration_lock(&self, bucket: &str, token: &str) -> Result<i64> {
        let path = format!("/locks/{}/heartbeat", bucket);
        let mut headers = HashMap::new();
        headers.insert("x-fula-lock-token".to_string(), token.to_string());
        let response = self.request("POST", &path, None, Some(headers), None).await?;
        let text = response.text().await?;
        let v: serde_json::Value = serde_json::from_str(&text)
            .map_err(|e| ClientError::InvalidResponse(format!("lock heartbeat: {}", e)))?;
        v.get("expires_at").and_then(|e| e.as_i64())
            .ok_or_else(|| ClientError::InvalidResponse("lock heartbeat: missing expires_at".into()))
    }
}

/// Phase 2.4 — classify which error variants represent "master is
/// unreachable" for the purpose of triggering the gateway-race
/// fallback. Tightly scoped to:
///   - explicit `MasterUnreachable` from the health gate short-circuit,
///   - connection-level `Http` errors (DNS, RST, refused, timeout —
///     reqwest::Error wraps these),
///   - 5xx server errors (master is up but failing).
///
/// 4xx (auth, not-found, precondition-failed, etc.) do NOT count: the
/// server responded correctly, the request was just refused. Falling
/// back to gateway race in those cases would mask real bugs.
///
/// Native-only because the only caller (`try_offline_fallback`) is
/// gated to `cfg(not(target_arch = "wasm32"))`. Defining it here
/// without gates would yield a dead-code warning on wasm builds.
/// Walk an error's source chain looking for an `std::io::Error` whose
/// `kind` indicates a network-tier transport failure. Used by
/// [`is_master_unreachable_error`] as a fallback when
/// `reqwest::Error::is_connect` doesn't see through hyper-util's
/// wrapper layer (the reqwest-0.12 + hyper-1 chain is
/// `reqwest::Error → hyper_util::Error → std::io::Error`, not
/// `reqwest::Error → hyper::Error → std::io::Error`).
///
/// Strictly limited to network-tier io kinds. URL-build / body-encoding
/// errors don't surface a network io::Error in their chain, so this
/// check preserves the audit-follow-up invariant that bad-input
/// errors must NOT classify as master-unreachable.
#[cfg(not(target_arch = "wasm32"))]
fn source_chain_has_network_io_error<E: std::error::Error + 'static>(err: &E) -> bool {
    use std::io::ErrorKind;
    // First pass: typed ErrorKind matches on any io::Error in the chain.
    // Cheap and platform-agnostic — covers the named transport variants.
    let mut source: Option<&dyn std::error::Error> = err.source();
    let mut chain_text = String::new();
    while let Some(s) = source {
        // Accumulate the chain's Display strings for the second-pass
        // pattern check below. One walk, no rebuild.
        if !chain_text.is_empty() {
            chain_text.push_str(" :: ");
        }
        chain_text.push_str(&s.to_string());
        if let Some(io_err) = s.downcast_ref::<std::io::Error>() {
            // Only network-tier kinds. Notably excludes:
            //   - InvalidInput / InvalidData (parse / encode bugs)
            //   - PermissionDenied / NotFound (filesystem)
            //   - WouldBlock (non-blocking-io noise)
            if matches!(
                io_err.kind(),
                ErrorKind::ConnectionRefused
                    | ErrorKind::ConnectionReset
                    | ErrorKind::ConnectionAborted
                    | ErrorKind::NotConnected
                    | ErrorKind::TimedOut
                    | ErrorKind::AddrNotAvailable
                    | ErrorKind::BrokenPipe
                    | ErrorKind::HostUnreachable
                    | ErrorKind::NetworkUnreachable
                    | ErrorKind::NetworkDown
            ) {
                return true;
            }
        }
        source = s.source();
    }

    // Cross-platform DNS-resolution failure: io::Error::kind() is
    // `Uncategorized` (Windows GetAddrInfo OS code 11001 / 11002 / 11003 /
    // 11004) or `Other` (some libc-backed Linux paths), with no
    // ErrorKind variant for "host not found". hyper_util's wrapper
    // adds the literal text "dns error" before the underlying io
    // failure — gate on that string so we don't over-classify
    // unrelated `Uncategorized` io errors as master-unreachable.
    chain_text.contains("dns error")
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn is_master_unreachable_error(e: &ClientError) -> bool {
    match e {
        ClientError::MasterUnreachable { .. } => true,
        // reqwest::Error: cover the common transport failures. We
        // can't easily distinguish "DNS down" from "connection RST"
        // without inspecting the inner — for our purposes both are
        // "master is unreachable".
        ClientError::Http(re) => {
            // `is_connect()` exists on native reqwest but not on the
            // wasm32 build — guard it. On wasm the offline path is a
            // no-op anyway (gated out at the call site), so the
            // narrower native-only classification suffices.
            //
            // We DELIBERATELY do NOT include `is_request()` (audit
            // follow-up): that variant covers body-build errors,
            // redirect-loops, URL parsing — half are app bugs (bad
            // bucket name, malformed header) that the fallback would
            // mask. Limit to connect/timeout/5xx — the trio that
            // genuinely means "master is unreachable right now".
            #[cfg(not(target_arch = "wasm32"))]
            let is_connect = re.is_connect();
            #[cfg(target_arch = "wasm32")]
            let is_connect = false;

            // Source-chain fallback: in reqwest 0.12 with hyper-util,
            // `is_connect()` walks the source chain looking for
            // `hyper::Error`, but the actual chain on a real failure
            // is `reqwest::Error → hyper_util::client::legacy::Error
            // → std::io::Error(ConnectionRefused/TimedOut/etc.)` —
            // hyper::Error is no longer in the middle. Without this
            // fallback, real connection-refused / DNS-fail errors
            // bypass the offline path. Limited to genuinely-network
            // io kinds; URL-build / redirect-loop / body-encoding
            // errors don't surface a network-tier io::Error in
            // their source chain so the audit-follow-up
            // (`test_master_unreachable_classifier_excludes_request_build_errors`)
            // still passes.
            let has_io_connect_error = source_chain_has_network_io_error(re);

            is_connect
                || has_io_connect_error
                || re.is_timeout()
                || matches!(re.status(), Some(s) if s.is_server_error())
        }
        ClientError::S3Error { code, .. } => {
            // 5xx surfaces as S3Error with a status-derived code.
            code.starts_with("HTTP5") || code == "InternalError" || code == "ServiceUnavailable"
                || code == "SlowDown"
        }
        _ => false,
    }
}

// ==================== Phase 2.4 helpers ====================

/// Resolve the on-disk path for the block cache. Honors
/// `Config::block_cache_path` if set; otherwise falls back to the
/// platform's local data directory under `fula/cache/blocks.redb`.
/// Native-only; the function is not compiled into the wasm target
/// because BlockCache itself isn't.
#[cfg(not(target_arch = "wasm32"))]
fn resolve_block_cache_path(config: &Config) -> std::path::PathBuf {
    if let Some(p) = &config.block_cache_path {
        return p.clone();
    }
    // dirs::data_local_dir() returns the platform-conventional cache
    // root: ~/.local/share on Linux, ~/Library/Application Support on
    // macOS, %LOCALAPPDATA% on Windows. Falls back to ./fula-cache if
    // dirs cannot resolve a home directory (extremely rare; common in
    // CI containers without HOME set).
    let base = dirs::data_local_dir().unwrap_or_else(|| std::path::PathBuf::from("."));
    base.join("fula").join("cache").join("blocks.redb")
}

/// Open the BlockCache for `config`. Returns the typed
/// BlockCacheError on any failure so the caller can decide whether
/// to disable the offline path or surface it.
#[cfg(not(target_arch = "wasm32"))]
fn build_block_cache(config: &Config) -> std::result::Result<BlockCache, crate::block_cache::BlockCacheError> {
    let path = resolve_block_cache_path(config);
    BlockCache::open(path, config.block_cache_max_bytes)
}

// ==================== Response Parsers ====================

fn parse_list_buckets_response(xml: &str) -> Result<ListBucketsResult> {
    // Simple XML parsing
    let owner_id = extract_xml_value(xml, "ID").unwrap_or_default();
    let owner_display_name = extract_xml_value(xml, "DisplayName").unwrap_or_default();
    
    let mut buckets = Vec::new();
    let mut pos = 0;
    while let Some(start) = xml[pos..].find("<Bucket>") {
        let start = pos + start;
        if let Some(end) = xml[start..].find("</Bucket>") {
            let bucket_xml = &xml[start..start + end + 9];
            if let (Some(name), Some(date)) = (
                extract_xml_value(bucket_xml, "Name"),
                extract_xml_value(bucket_xml, "CreationDate"),
            ) {
                buckets.push(Bucket {
                    name,
                    creation_date: chrono::DateTime::parse_from_rfc3339(&date)
                        .map(|d| d.with_timezone(&chrono::Utc))
                        .unwrap_or_else(|_| chrono::Utc::now()),
                });
            }
            pos = start + end + 9;
        } else {
            break;
        }
    }

    Ok(ListBucketsResult {
        owner_id,
        owner_display_name,
        buckets,
    })
}

fn parse_list_objects_response(xml: &str, bucket: &str) -> Result<ListObjectsResult> {
    let prefix = extract_xml_value(xml, "Prefix").unwrap_or_default();
    let is_truncated = extract_xml_value(xml, "IsTruncated")
        .map(|s| s == "true")
        .unwrap_or(false);
    let next_token = extract_xml_value(xml, "NextContinuationToken");

    let mut objects = Vec::new();
    let mut pos = 0;
    while let Some(start) = xml[pos..].find("<Contents>") {
        let start = pos + start;
        if let Some(end) = xml[start..].find("</Contents>") {
            let obj_xml = &xml[start..start + end + 11];
            if let Some(key) = extract_xml_value(obj_xml, "Key") {
                objects.push(Object {
                    key,
                    last_modified: extract_xml_value(obj_xml, "LastModified")
                        .and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).ok())
                        .map(|d| d.with_timezone(&chrono::Utc))
                        .unwrap_or_else(chrono::Utc::now),
                    etag: extract_xml_value(obj_xml, "ETag")
                        .map(|s| s.trim_matches('"').to_string())
                        .unwrap_or_default(),
                    size: extract_xml_value(obj_xml, "Size")
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(0),
                    storage_class: extract_xml_value(obj_xml, "StorageClass")
                        .unwrap_or_else(|| "STANDARD".to_string()),
                });
            }
            pos = start + end + 11;
        } else {
            break;
        }
    }

    let mut common_prefixes = Vec::new();
    pos = 0;
    while let Some(start) = xml[pos..].find("<CommonPrefixes>") {
        let start = pos + start;
        if let Some(end) = xml[start..].find("</CommonPrefixes>") {
            let prefix_xml = &xml[start..start + end + 17];
            if let Some(p) = extract_xml_value(prefix_xml, "Prefix") {
                common_prefixes.push(p);
            }
            pos = start + end + 17;
        } else {
            break;
        }
    }

    Ok(ListObjectsResult {
        name: bucket.to_string(),
        prefix,
        objects,
        common_prefixes,
        is_truncated,
        next_continuation_token: next_token,
    })
}

fn parse_copy_object_response(xml: &str) -> Result<CopyObjectResult> {
    let etag = extract_xml_value(xml, "ETag")
        .map(|s| s.trim_matches('"').to_string())
        .unwrap_or_default();
    
    let last_modified = extract_xml_value(xml, "LastModified")
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).ok())
        .map(|d| d.with_timezone(&chrono::Utc))
        .unwrap_or_else(chrono::Utc::now);

    Ok(CopyObjectResult { etag, last_modified })
}

fn extract_xml_value(xml: &str, element: &str) -> Option<String> {
    let start_tag = format!("<{}>", element);
    let end_tag = format!("</{}>", element);
    
    let start = xml.find(&start_tag)? + start_tag.len();
    let end = xml.find(&end_tag)?;
    
    if start < end {
        Some(xml[start..end].to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_list_buckets() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
    <Owner>
        <ID>user123</ID>
        <DisplayName>Test User</DisplayName>
    </Owner>
    <Buckets>
        <Bucket>
            <Name>bucket1</Name>
            <CreationDate>2024-01-01T00:00:00.000Z</CreationDate>
        </Bucket>
    </Buckets>
</ListAllMyBucketsResult>"#;

        let result = parse_list_buckets_response(xml).unwrap();
        assert_eq!(result.owner_id, "user123");
        assert_eq!(result.buckets.len(), 1);
        assert_eq!(result.buckets[0].name, "bucket1");
    }

    // ============================================================
    // Phase 2.4 — offline-fallback wrapper helper-fn tests
    // ============================================================
    //
    // The integration tests for the full wrapper (master + gateway
    // wiremock combo) live in `phase_2_4_offline_tests` below. These
    // smaller unit tests cover the classification helper that decides
    // when to attempt the offline path, without spinning up a server.

    #[test]
    fn test_master_unreachable_classifier_explicit_variant() {
        let e = ClientError::MasterUnreachable { down_for_secs: 5 };
        assert!(is_master_unreachable_error(&e));
    }

    #[test]
    fn test_master_unreachable_classifier_5xx_s3_codes() {
        // 5xx surfaces as S3Error with a code derived from the body
        // or the status line. All these forms must be classified as
        // master-unreachable so the offline path triggers.
        for code in &["HTTP500", "HTTP502", "HTTP503", "InternalError", "ServiceUnavailable", "SlowDown"] {
            let e = ClientError::S3Error {
                code: (*code).into(),
                message: "x".into(),
                request_id: None,
            };
            assert!(is_master_unreachable_error(&e), "code={} should classify as master-unreachable", code);
        }
    }

    #[test]
    fn test_master_unreachable_classifier_excludes_4xx() {
        // 4xx must NOT trigger fallback — server responded, request
        // was simply refused. Falling back here would mask real auth
        // / not-found issues.
        for code in &["NoSuchKey", "NoSuchBucket", "AccessDenied", "PreconditionFailed", "HTTP404", "HTTP403"] {
            let e = ClientError::S3Error {
                code: (*code).into(),
                message: "x".into(),
                request_id: None,
            };
            assert!(!is_master_unreachable_error(&e), "code={} must NOT classify as master-unreachable", code);
        }
    }

    #[test]
    fn test_master_unreachable_classifier_excludes_other_variants() {
        // Encryption / config / NotFound / etc. are not master-down.
        let e = ClientError::Config("bad".into());
        assert!(!is_master_unreachable_error(&e));
        let e = ClientError::BucketNotFound("b".into());
        assert!(!is_master_unreachable_error(&e));
        let e = ClientError::ConcurrentModification("etag mismatch".into());
        assert!(!is_master_unreachable_error(&e));
    }

    /// Real connection-refused errors must classify as master-unreachable.
    /// The reqwest 0.12 + hyper-util chain wraps the underlying
    /// `std::io::Error(ConnectionRefused)` under
    /// `hyper_util::client::legacy::Error → ConnectError → io::Error`.
    /// `reqwest::Error::is_connect()` only walks the chain looking for
    /// `hyper::Error`, which is no longer in the middle, so we extend
    /// the classifier with a source-chain `io::Error::kind()` probe
    /// (`source_chain_has_network_io_error`). Without that fallback,
    /// real offline scenarios bypass the warm-cache fallback entirely.
    #[tokio::test]
    async fn test_master_unreachable_classifier_catches_real_connection_refused() {
        let http = reqwest::Client::new();
        // 127.0.0.1:1 is a privileged port; nothing listens.
        let req_err = http
            .get("http://127.0.0.1:1/probe")
            .send()
            .await
            .expect_err("connection must be refused");
        let wrapped = ClientError::Http(req_err);
        assert!(
            is_master_unreachable_error(&wrapped),
            "real connection-refused error MUST classify as master-unreachable; \
             without this the SDK's warm-cache offline fallback never fires. \
             Error chain: {wrapped:#?}"
        );
    }

    /// Cold-start cold-cache regression test: a DNS-failing master URL
    /// (the operator's "I'm offline" simulation in the e2e test) must
    /// classify as master-unreachable so the gateway-race fallback runs.
    /// On Windows the DNS error surfaces as `io::ErrorKind::Uncategorized`
    /// with no typed variant — without the chain-string check we'd miss it.
    #[tokio::test]
    async fn test_master_unreachable_classifier_catches_dns_resolution_failure() {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap();
        // A guaranteed-nonexistent hostname forces DNS resolution to fail
        // on every platform. `.invalid` is the IETF-reserved TLD for
        // tests that must never resolve (RFC 6761).
        let req_err = http
            .get("https://this-host-does-not-exist.invalid/probe")
            .send()
            .await
            .expect_err("DNS lookup must fail");
        let wrapped = ClientError::Http(req_err);
        assert!(
            is_master_unreachable_error(&wrapped),
            "DNS-failing hostname MUST classify as master-unreachable; \
             without this the cold-cache cold-start path can't reach \
             the gateway-race fallback. Error chain: {wrapped:#?}"
        );
    }

    /// Audit follow-up: request-build errors (URL parsing, malformed
    /// headers, body-encoding) must NOT classify as master-unreachable.
    /// Including `re.is_request()` would mask "I gave the SDK a bad
    /// bucket name" by silently falling back to the gateway race.
    /// Construct a request-build error by passing an invalid URL.
    #[tokio::test]
    async fn test_master_unreachable_classifier_excludes_request_build_errors() {
        let http = reqwest::Client::new();
        // Building a request to a malformed URL fails at request-build
        // time, before any network I/O. reqwest classifies this as
        // is_builder() / is_request() — NOT is_connect() / is_timeout().
        let result = http.get("ht!tp://bad").build();
        let req_err = match result {
            Err(e) => e,
            Ok(_) => {
                // If reqwest happened to accept this URL, try sending
                // it; the send will fail with a different request error.
                http.get("ht!tp://bad").send().await.unwrap_err()
            }
        };
        let wrapped = ClientError::Http(req_err);
        assert!(
            !is_master_unreachable_error(&wrapped),
            "request-build / URL-parse errors must NOT classify as master-unreachable"
        );
    }

    // Resolve-block-cache-path is native-only (uses dirs crate).
    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn test_resolve_block_cache_path_uses_explicit_when_set() {
        let mut config = Config::default();
        config.block_cache_path = Some(std::path::PathBuf::from("/tmp/explicit/blocks.redb"));
        let p = resolve_block_cache_path(&config);
        assert_eq!(p, std::path::PathBuf::from("/tmp/explicit/blocks.redb"));
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn test_resolve_block_cache_path_uses_platform_default_when_unset() {
        let config = Config::default();
        let p = resolve_block_cache_path(&config);
        // The exact path depends on the host OS, but it must end in
        // the documented "fula/cache/blocks.redb" suffix.
        let s = p.to_string_lossy().replace('\\', "/");
        assert!(
            s.ends_with("fula/cache/blocks.redb"),
            "expected platform default to end with 'fula/cache/blocks.redb', got: {}",
            s
        );
    }
}

// ============================================================
// Phase 2.4 — offline-fallback integration tests (wiremock)
// ============================================================
//
// These tests spin up:
//   1. A wiremock master at 127.0.0.1:<random>
//   2. A wiremock gateway at 127.0.0.1:<random>/ipfs/{cid}
//
// They exercise the wrapper end-to-end:
//   - flags off → no cache, no fallback, byte-identical to old behavior
//   - master up → cache populated (KEY_TO_CID + BLOCKS)
//   - master down + cache hit → gateway race serves bytes
//   - master down + cache miss → MasterUnreachable surfaces
//   - master 5xx → fallback triggers
//   - master 4xx → fallback does NOT trigger (auth/not-found preserved)
//
// Native-only: wiremock + block_cache aren't compiled into wasm builds.

#[cfg(not(target_arch = "wasm32"))]
#[cfg(test)]
mod phase_2_4_offline_tests {
    use super::*;
    use crate::block_cache::BlockCache;
    use cid::Cid;
    use cid::multihash::Multihash;
    use sha2::Digest;
    use std::time::Duration;
    use tempfile::TempDir;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Compute the CID master would set as ETag for the given
    /// payload. Master uses CIDv1 + raw codec + sha2-256 multihash
    /// for direct S3-PUT objects (per `object.rs:103-105` and
    /// `cid_utils::create_cid`). For tests we mirror that exactly so
    /// `verify_cid_against_bytes` will pass.
    fn cid_for_bytes(data: &[u8]) -> Cid {
        let digest = sha2::Sha256::digest(data);
        let mh = Multihash::<64>::wrap(0x12 /* sha2-256 */, &digest).unwrap();
        Cid::new_v1(0x55 /* raw */, mh)
    }

    /// Helper: build a FulaClient pointed at `master_url` with
    /// `gateway_url` in its fallback list. Cache lives in `cache_path`.
    fn build_client(
        master_url: &str,
        cache_path: &std::path::Path,
        gateway_url_template: &str,
    ) -> FulaClient {
        let mut config = Config::new(master_url);
        config.timeout = Duration::from_secs(2);
        config.block_cache_enabled = true;
        config.block_cache_path = Some(cache_path.to_path_buf());
        config.block_cache_max_bytes = 1024 * 1024;
        config.gateway_fallback_enabled = true;
        config.gateway_fallback_urls = vec![gateway_url_template.to_string()];
        config.gateway_race_concurrency = 1;
        // Health gate off — these tests construct the master-down
        // signal via 5xx responses or a stopped wiremock; gate
        // semantics are exercised separately in health_gate.rs.
        config.health_gate_enabled = false;
        FulaClient::new(config).expect("client")
    }

    /// Local-retain fatal-pin guard (server-side `retain()` returns 5xx when a
    /// block can't be durably pinned). A WRITE that 5xx's must NOT trip the
    /// read-health gate and black out the whole app, whereas two READ 5xx's
    /// still must. The gate answers "can I READ the master?" — a write failure
    /// doesn't speak to that.
    #[tokio::test]
    async fn write_5xx_does_not_trip_health_gate_but_read_5xx_does() {
        let master = MockServer::start().await;
        Mock::given(method("PUT"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&master)
            .await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&master)
            .await;

        let mut config = Config::new(master.uri());
        config.timeout = Duration::from_secs(2);
        config.health_gate_enabled = true;
        let client = FulaClient::new(config).expect("client");
        let gate = client.health_gate.as_ref().expect("gate enabled");

        // Two WRITE failures (PUT via create_bucket) must leave the gate Allow.
        let _ = client.create_bucket("b1").await;
        let _ = client.create_bucket("b2").await;
        assert_eq!(
            gate.decide(),
            GateDecision::Allow,
            "write 5xx must not trip the read-health gate"
        );

        // Two READ failures (GET via get_object) must trip it.
        let _ = client.get_object("bucket", "key").await;
        let _ = client.get_object("bucket", "key").await;
        assert!(
            matches!(gate.decide(), GateDecision::ShortCircuit { .. }),
            "two read 5xx must trip the read-health gate"
        );
    }

    #[tokio::test]
    async fn test_flags_off_byte_identical_to_get_object_with_metadata() {
        // Backward-compat: if neither flag is set, the wrapper must
        // delegate to get_object_with_metadata with no observable
        // difference (no extra cache writes, no extra network calls).
        let master = MockServer::start().await;
        let body = b"some bytes";
        let cid = cid_for_bytes(body);
        Mock::given(method("GET"))
            .and(path("/bucket/key.txt"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("ETag", format!("\"{}\"", cid))
                    .set_body_bytes(body.as_slice()),
            )
            .expect(1)
            .mount(&master)
            .await;

        let mut config = Config::new(master.uri());
        // Both flags OFF — backward-compat scenario.
        config.block_cache_enabled = false;
        config.gateway_fallback_enabled = false;
        let client = FulaClient::new(config).expect("client");

        let r = client
            .get_object_with_offline_fallback("bucket", "key.txt")
            .await
            .expect("get");
        // Phase 19: result is OfflineGetResult; bytes/etag on .inner.
        assert_eq!(r.inner.data.as_ref(), body);
        assert_eq!(r.inner.etag, cid.to_string());
        assert_eq!(r.source, ReadSource::Master);
        assert_eq!(r.freshness, ReadFreshness::Live);
    }

    #[tokio::test]
    async fn test_master_up_populates_key_to_cid_and_blocks() {
        let master = MockServer::start().await;
        let body = b"payload bytes for cache";
        let cid = cid_for_bytes(body);
        Mock::given(method("GET"))
            .and(path("/bucket/file.bin"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("ETag", format!("\"{}\"", cid))
                    .set_body_bytes(body.as_slice()),
            )
            .mount(&master)
            .await;

        let dir = TempDir::new().unwrap();
        let cache_path = dir.path().join("cache.redb");
        let client = build_client(
            &master.uri(),
            &cache_path,
            "http://unused.invalid/ipfs/{cid}",
        );

        let r = client
            .get_object_with_offline_fallback("bucket", "file.bin")
            .await
            .expect("get");
        assert_eq!(r.inner.data.as_ref(), body);
        assert_eq!(r.source, ReadSource::Master);
        assert_eq!(r.freshness, ReadFreshness::Live);

        // Drop the client (and its BlockCache Arc) so we can re-open
        // the on-disk file for inspection. redb holds an exclusive
        // file lock; AlreadyOpen otherwise.
        drop(client);

        // Cache must have been populated as a side-effect.
        let cache = BlockCache::open(&cache_path, 1024 * 1024).expect("re-open cache");
        let looked_up = cache.lookup_cid("bucket", "file.bin").expect("lookup").expect("hit");
        assert_eq!(looked_up, cid, "KEY_TO_CID must record the master's etag");
        let bytes = cache.get(&cid).expect("get").expect("BLOCKS hit");
        assert_eq!(bytes.as_ref(), body, "BLOCKS table must hold the payload");
    }

    #[tokio::test]
    async fn test_master_down_with_cached_cid_falls_back_to_gateway() {
        // Phase: warm-up against master, then simulate master-down
        // and verify the gateway race fills in.
        let master = MockServer::start().await;
        let gateway = MockServer::start().await;
        let body = b"served by gateway after master goes dark";
        let cid = cid_for_bytes(body);

        // Master serves the file ONCE, populating the cache.
        Mock::given(method("GET"))
            .and(path("/bucket/file.txt"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("ETag", format!("\"{}\"", cid))
                    .set_body_bytes(body.as_slice()),
            )
            .up_to_n_times(1)
            .mount(&master)
            .await;
        // Subsequent master requests fail with 503.
        Mock::given(method("GET"))
            .and(path("/bucket/file.txt"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&master)
            .await;

        // Gateway always serves the same bytes.
        let gateway_path = format!("/ipfs/{}", cid);
        Mock::given(method("GET"))
            .and(path(gateway_path.clone()))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(body.as_slice()))
            .mount(&gateway)
            .await;

        let dir = TempDir::new().unwrap();
        let cache_path = dir.path().join("cache.redb");
        let gateway_template = format!("{}/ipfs/{{cid}}", gateway.uri());
        let client = build_client(&master.uri(), &cache_path, &gateway_template);

        // Read 1: master up — populates cache.
        let r1 = client
            .get_object_with_offline_fallback("bucket", "file.txt")
            .await
            .expect("master read");
        assert_eq!(r1.inner.data.as_ref(), body);
        assert_eq!(r1.source, ReadSource::Master);

        // Drop the in-process BLOCKS entry to force the gateway race
        // (otherwise step 2 would short-circuit on a BLOCKS hit and
        // we wouldn't be testing the fallback path).
        // We do this by opening a fresh client without the populated
        // cache — but actually keeping the same on-disk cache is what
        // we want; just clear BLOCKS while keeping KEY_TO_CID.
        // Simpler: we test against a SECOND client that re-uses the
        // same cache file; since BLOCKS is populated by step 1, we'd
        // expect a BLOCKS hit on read 2. So we'll first open a client
        // with a different cache path (no warm-up), then manually
        // call record_key_cid → that simulates "warm KEY_TO_CID, cold
        // BLOCKS" which is the realistic scenario after a long enough
        // outage.
        let dir2 = TempDir::new().unwrap();
        let cache_path2 = dir2.path().join("cache2.redb");
        let cache2 = BlockCache::open(&cache_path2, 1024 * 1024).expect("open");
        cache2.record_key_cid("bucket", "file.txt", &cid).expect("seed mapping");
        drop(cache2);

        let client2 = build_client(&master.uri(), &cache_path2, &gateway_template);
        let r2 = client2
            .get_object_with_offline_fallback("bucket", "file.txt")
            .await
            .expect("offline path read");
        assert_eq!(r2.inner.data.as_ref(), body, "gateway must have served the bytes");
        assert_eq!(r2.inner.etag, cid.to_string(), "synthesized etag = cid");
        // Phase 19: gateway-served bytes get a Gateway(url) source +
        // Cached freshness. The URL template should match the
        // configured gateway template (NOT the per-CID-substituted URL).
        match &r2.source {
            ReadSource::Gateway(url) => {
                assert_eq!(url, &gateway_template, "source URL = configured gateway template");
            }
            other => panic!("expected ReadSource::Gateway, got {:?}", other),
        }
        match r2.freshness {
            ReadFreshness::Cached { .. } => { /* ok */ }
            other => panic!("expected ReadFreshness::Cached, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_master_down_no_cached_cid_returns_master_unreachable() {
        // Cold-start case: SDK has never read this object before, so
        // KEY_TO_CID has no entry. Wrapper must surface the original
        // master-down error rather than swallow it — Phase 3.3 will
        // pick it up later.
        let master = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/bucket/never-read.txt"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&master)
            .await;

        let dir = TempDir::new().unwrap();
        let cache_path = dir.path().join("cache.redb");
        let client = build_client(
            &master.uri(),
            &cache_path,
            "http://unused.invalid/ipfs/{cid}",
        );

        let result = client
            .get_object_with_offline_fallback("bucket", "never-read.txt")
            .await;
        assert!(result.is_err(), "no cached CID → must propagate master-down");
        let err = result.unwrap_err();
        // Either the explicit MasterUnreachable variant (if health
        // gate were involved) or an S3Error with HTTP503 code is
        // acceptable here. The point is: NOT Ok, and NOT silently
        // swallowed.
        assert!(
            is_master_unreachable_error(&err),
            "error must classify as master-unreachable: {:?}",
            err
        );
    }

    #[tokio::test]
    async fn test_master_4xx_does_not_trigger_fallback() {
        // 4xx (auth, not-found) surfaces as S3Error and MUST propagate
        // unchanged. The fallback path would mask real bugs (e.g.,
        // a typo in the bucket name yielding NoSuchBucket).
        let master = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/bucket/missing.txt"))
            .respond_with(
                ResponseTemplate::new(404)
                    .set_body_string(r#"<Error><Code>NoSuchKey</Code><Message>not here</Message></Error>"#),
            )
            .mount(&master)
            .await;

        let dir = TempDir::new().unwrap();
        let cache_path = dir.path().join("cache.redb");
        let client = build_client(
            &master.uri(),
            &cache_path,
            "http://unused.invalid/ipfs/{cid}",
        );

        let err = client
            .get_object_with_offline_fallback("bucket", "missing.txt")
            .await
            .expect_err("404 propagates");
        assert!(err.is_not_found(), "expected NotFound, got: {:?}", err);
        assert!(
            !is_master_unreachable_error(&err),
            "4xx must NOT classify as master-unreachable"
        );
    }

    #[tokio::test]
    async fn test_master_down_gateway_failure_propagates_original_error() {
        // If the offline path tries to fetch via the gateway race AND
        // the race exhausts (all gateways down), the wrapper must
        // surface the ORIGINAL master-down error so callers see a
        // single failure type. The gateway-side error is already
        // logged at warn level (operators can debug from logs).
        let master = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/bucket/x.txt"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&master)
            .await;

        // Gateway always 500s — race will exhaust.
        let gateway = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&gateway)
            .await;

        let dir = TempDir::new().unwrap();
        let cache_path = dir.path().join("cache.redb");
        let body = b"would have been served";
        let cid = cid_for_bytes(body);
        let cache = BlockCache::open(&cache_path, 1024 * 1024).expect("open");
        cache.record_key_cid("bucket", "x.txt", &cid).expect("seed");
        drop(cache);

        let gateway_template = format!("{}/ipfs/{{cid}}", gateway.uri());
        let client = build_client(&master.uri(), &cache_path, &gateway_template);

        let err = client
            .get_object_with_offline_fallback("bucket", "x.txt")
            .await
            .expect_err("both channels failed");
        assert!(
            is_master_unreachable_error(&err),
            "must surface master-unreachable, not a gateway-specific error"
        );
    }

    // ============================================================
    // Phase 19 — transparency surfaces on the offline path
    // ============================================================

    #[tokio::test]
    async fn test_phase19_blocks_hit_carries_local_cache_source() {
        // Advisor-mandated test #3: when BLOCKS already holds the
        // bytes (e.g., from a prior master-up read), the offline path
        // serves them from local cache and the result carries
        // `ReadSource::LocalCache` + `ReadFreshness::Cached`. No
        // network round-trip happens at all.
        let master = MockServer::start().await;
        // Master is unreachable (every request 503s).
        Mock::given(method("GET"))
            .and(path("/bucket/cached.txt"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&master)
            .await;

        let body = b"already cached locally";
        let cid = cid_for_bytes(body);

        // Pre-populate BOTH KEY_TO_CID and BLOCKS so the offline
        // fallback's BLOCKS hit short-circuits before any gateway
        // race attempt.
        let dir = TempDir::new().unwrap();
        let cache_path = dir.path().join("cache.redb");
        let cache = BlockCache::open(&cache_path, 1024 * 1024).expect("open cache");
        cache.record_key_cid("bucket", "cached.txt", &cid).expect("seed key→cid");
        cache.put(&cid, body).await.expect("seed BLOCKS");
        drop(cache);

        // Use a gateway URL that would FAIL if the gateway race were
        // even attempted — proves the BLOCKS hit short-circuited.
        let gateway_template = "http://gateway-must-not-be-called.invalid/ipfs/{cid}";
        let client = build_client(&master.uri(), &cache_path, gateway_template);

        let r = client
            .get_object_with_offline_fallback("bucket", "cached.txt")
            .await
            .expect("BLOCKS hit serves bytes");

        assert_eq!(r.inner.data.as_ref(), body);
        assert_eq!(r.inner.etag, cid.to_string(), "synthesized etag = cid");
        assert_eq!(r.source, ReadSource::LocalCache, "BLOCKS hit → LocalCache");
        match r.freshness {
            ReadFreshness::Cached { observed_at } => {
                assert!(observed_at > 0, "Cached.observed_at must be set");
            }
            other => panic!("expected ReadFreshness::Cached, got {:?}", other),
        }
    }

    // ============================================================
    // #31 — cold-cache cold-start CID-hint variant
    // ============================================================

    #[tokio::test]
    async fn test_cid_hint_master_up_path_unchanged() {
        // The master-up branch must be byte-identical to the no-hint
        // wrapper: master responds, we serve master bytes, populate
        // KEY_TO_CID + BLOCKS as side effects, never touch the gateway.
        let master = MockServer::start().await;
        let body = b"served by master";
        let cid = cid_for_bytes(body);
        Mock::given(method("GET"))
            .and(path("/bucket/file.bin"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("ETag", format!("\"{}\"", cid))
                    .set_body_bytes(body.as_slice()),
            )
            .expect(1)
            .mount(&master)
            .await;

        let dir = TempDir::new().unwrap();
        let cache_path = dir.path().join("cache.redb");
        let client = build_client(
            &master.uri(),
            &cache_path,
            "http://must-not-be-called.invalid/ipfs/{cid}",
        );

        let r = client
            .get_object_with_offline_fallback_known_cid("bucket", "file.bin", &cid)
            .await
            .expect("master-up read");
        assert_eq!(r.inner.data.as_ref(), body);
        assert_eq!(r.source, ReadSource::Master);
        assert_eq!(r.freshness, ReadFreshness::Live);

        drop(client);
        let cache = BlockCache::open(&cache_path, 1024 * 1024).expect("re-open");
        let looked_up = cache.lookup_cid("bucket", "file.bin").expect("lookup").expect("hit");
        assert_eq!(looked_up, cid, "master-up path still populates KEY_TO_CID");
        let bytes = cache.get(&cid).expect("get").expect("BLOCKS hit");
        assert_eq!(bytes.as_ref(), body, "BLOCKS populated from master read");
    }

    #[tokio::test]
    async fn test_cid_hint_cold_cache_master_down_serves_from_gateway() {
        // The actual cold-start regression test: cache is empty, master
        // is down, but the SDK has just decrypted a manifest root that
        // points at this CID. The hint variant must race the gateway
        // and return the verified bytes.
        let master = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/bucket/page.bin"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&master)
            .await;

        let gateway = MockServer::start().await;
        let body = b"manifest page bytes from gateway";
        let cid = cid_for_bytes(body);
        Mock::given(method("GET"))
            .and(path(format!("/ipfs/{}", cid)))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(body.as_slice()))
            .mount(&gateway)
            .await;

        let dir = TempDir::new().unwrap();
        let cache_path = dir.path().join("cache.redb");
        let gateway_template = format!("{}/ipfs/{{cid}}", gateway.uri());
        let client = build_client(&master.uri(), &cache_path, &gateway_template);

        // CRITICAL: no prior master-up read for this (bucket, key) —
        // KEY_TO_CID is empty. Without the hint variant this would
        // surface MasterUnreachable.
        let r = client
            .get_object_with_offline_fallback_known_cid("bucket", "page.bin", &cid)
            .await
            .expect("cold-cache cold-start succeeds with hint");
        assert_eq!(r.inner.data.as_ref(), body);
        assert_eq!(r.inner.etag, cid.to_string());
        match &r.source {
            ReadSource::Gateway(url) => {
                assert_eq!(url, &gateway_template, "served from gateway template");
            }
            other => panic!("expected Gateway source, got {:?}", other),
        }
        match r.freshness {
            ReadFreshness::Cached { observed_at } => {
                assert!(observed_at > 0);
            }
            other => panic!("expected Cached freshness, got {:?}", other),
        }

        // Cache is now warm — the next read can use either path.
        drop(client);
        let cache = BlockCache::open(&cache_path, 1024 * 1024).expect("re-open");
        let looked_up = cache.lookup_cid("bucket", "page.bin").expect("lookup").expect("hit");
        assert_eq!(looked_up, cid, "warm-cache invariant restored after cold-start");
        let bytes = cache.get(&cid).expect("get").expect("BLOCKS hit");
        assert_eq!(bytes.as_ref(), body, "BLOCKS populated from gateway");
    }

    #[tokio::test]
    async fn test_cid_hint_blocks_hit_short_circuits_network() {
        // BLOCKS already holds the bytes — no gateway round-trip.
        let master = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/bucket/page.bin"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&master)
            .await;

        let body = b"already cached";
        let cid = cid_for_bytes(body);

        let dir = TempDir::new().unwrap();
        let cache_path = dir.path().join("cache.redb");
        let cache = BlockCache::open(&cache_path, 1024 * 1024).expect("open cache");
        cache.put(&cid, body).await.expect("seed BLOCKS");
        drop(cache);

        let gateway_template = "http://must-not-be-called.invalid/ipfs/{cid}";
        let client = build_client(&master.uri(), &cache_path, gateway_template);

        let r = client
            .get_object_with_offline_fallback_known_cid("bucket", "page.bin", &cid)
            .await
            .expect("BLOCKS hit serves bytes");
        assert_eq!(r.inner.data.as_ref(), body);
        assert_eq!(r.source, ReadSource::LocalCache);

        // Best-effort KEY_TO_CID backfill: the BLOCKS-hit path also
        // records the mapping so the no-hint warm-cache path serves on
        // subsequent reads.
        drop(client);
        let cache = BlockCache::open(&cache_path, 1024 * 1024).expect("re-open");
        let looked_up = cache.lookup_cid("bucket", "page.bin").expect("lookup").expect("hit");
        assert_eq!(looked_up, cid, "BLOCKS-hit path backfills KEY_TO_CID");
    }

    #[tokio::test]
    async fn test_cid_hint_gateway_failure_propagates_master_error() {
        // Master 503 + every gateway 500 → original master-down error
        // surfaces, mirroring the no-hint wrapper's behavior.
        let master = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/bucket/page.bin"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&master)
            .await;

        let gateway = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&gateway)
            .await;

        let dir = TempDir::new().unwrap();
        let cache_path = dir.path().join("cache.redb");
        let gateway_template = format!("{}/ipfs/{{cid}}", gateway.uri());
        let client = build_client(&master.uri(), &cache_path, &gateway_template);

        let body = b"would have been served";
        let cid = cid_for_bytes(body);
        let err = client
            .get_object_with_offline_fallback_known_cid("bucket", "page.bin", &cid)
            .await
            .expect_err("both channels failed");
        assert!(
            is_master_unreachable_error(&err),
            "must surface master-unreachable, not a gateway-specific error"
        );
    }

    #[tokio::test]
    async fn test_cid_hint_master_4xx_propagates_without_fallback() {
        // 4xx propagates unchanged — same invariant as the no-hint
        // wrapper. We must never hide a NoSuchKey behind a gateway
        // race success.
        let master = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/bucket/missing.bin"))
            .respond_with(
                ResponseTemplate::new(404)
                    .set_body_string(r#"<Error><Code>NoSuchKey</Code><Message>not here</Message></Error>"#),
            )
            .mount(&master)
            .await;

        let body = b"if this were served, we'd be hiding a real bug";
        let cid = cid_for_bytes(body);

        let dir = TempDir::new().unwrap();
        let cache_path = dir.path().join("cache.redb");
        let client = build_client(
            &master.uri(),
            &cache_path,
            "http://must-not-be-called.invalid/ipfs/{cid}",
        );

        let err = client
            .get_object_with_offline_fallback_known_cid("bucket", "missing.bin", &cid)
            .await
            .expect_err("404 propagates");
        assert!(err.is_not_found(), "expected NotFound, got: {:?}", err);
        assert!(
            !is_master_unreachable_error(&err),
            "4xx must NOT classify as master-unreachable"
        );
    }
}
