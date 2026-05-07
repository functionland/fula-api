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

        // GatewayPool requires block_cache as a hard prereq: without
        // a cached `(bucket, key) → cid` mapping the fallback path has
        // no CID to fetch. If the cache failed to open we silently
        // disable gateway fallback too.
        #[cfg(not(target_arch = "wasm32"))]
        let gateway_pool = if config.gateway_fallback_enabled && block_cache.is_some() {
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

    /// List all buckets
    #[instrument(skip(self))]
    pub async fn list_buckets(&self) -> Result<ListBucketsResult> {
        let response = self.request("GET", "/", None, None, None).await?;
        let text = response.text().await?;
        parse_list_buckets_response(&text)
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

        let response = self.request("PUT", &path, None, Some(headers), Some(data)).await?;
        
        let etag = response
            .headers()
            .get("ETag")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim_matches('"').to_string())
            .unwrap_or_default();

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

        let response = self.request("PUT", &path, None, Some(headers), Some(data)).await?;

        let etag = response
            .headers()
            .get("ETag")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim_matches('"').to_string())
            .unwrap_or_default();

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

        let response = self.request("PUT", &path, None, Some(headers), Some(data)).await?;
        
        let etag = response
            .headers()
            .get("ETag")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim_matches('"').to_string())
            .unwrap_or_default();

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

        let response = self.request("PUT", &path, None, Some(headers), Some(data)).await?;
        
        let etag = response
            .headers()
            .get("ETag")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim_matches('"').to_string())
            .unwrap_or_default();

        Ok(PutObjectResult {
            etag,
            version_id: None,
        })
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
                // Connection-level error (refused, RST, DNS, timeout). Treat
                // as a master-down signal for the gate's purposes. Returning
                // the original error preserves caller diagnostics.
                if let Some(gate) = &self.health_gate {
                    gate.record_failure();
                }
                return Err(ClientError::Http(e));
            }
        };

        // Check for errors
        let status = response.status();

        // Phase 2.1: classify the response status for the health gate.
        //   5xx → master-side failure → record_failure
        //   4xx → request-level (auth, not-found, precondition, etc.); NOT
        //         a master-down signal — the server responded, the request
        //         was just bad. Don't touch the gate.
        //   2xx/3xx → success → record_success (also clears any prior Down)
        if let Some(gate) = &self.health_gate {
            if status.is_server_error() {
                gate.record_failure();
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

            // For HEAD requests, S3 returns error code in x-amz-error-code header
            // since there's no response body
            let error_code = response
                .headers()
                .get("x-amz-error-code")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());

            let text = response.text().await.unwrap_or_default();

            // If we have an error code header, use it; otherwise parse XML or use status
            if let Some(code) = error_code {
                return Err(ClientError::S3Error {
                    code,
                    message: "Object not found".to_string(),
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
    let mut source: Option<&dyn std::error::Error> = err.source();
    while let Some(s) = source {
        if let Some(io_err) = s.downcast_ref::<std::io::Error>() {
            // Only network-tier kinds. Notably excludes:
            //   - InvalidInput / InvalidData (parse / encode bugs)
            //   - PermissionDenied / NotFound (filesystem)
            //   - WouldBlock (non-blocking-io noise)
            return matches!(
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
            );
        }
        source = s.source();
    }
    false
}

#[cfg(not(target_arch = "wasm32"))]
fn is_master_unreachable_error(e: &ClientError) -> bool {
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
    use std::sync::Arc;
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
}
