//! Multi-gateway race + CID verification (Phase 2.3 of master-independent reads).
//!
//! When master is unreachable (per the [`crate::health_gate`]), Phase 2.4
//! routes reads through this module: race fetches against several public
//! IPFS gateways with dynamic priority, verify each response's bytes
//! against the requested CID's multihash, return the first verified hit.
//!
//! # Default gateway list (post-Step-0)
//!
//! Six gateways in quality-priority order. **`ipfs.cloud.fx.land/gateway/`
//! is intentionally NOT in the default list** — Step 0 verification on
//! 2026-05-01 found it returns HTTP 500 with `{"error":"Error fetching
//! content from IPFS"}` for dag-cbor (codec 0x71) CIDs while serving
//! raw codec correctly. Forest manifest pages and bucket Prolly Tree
//! roots — the metadata SDK cold-start needs — are dag-cbor. Including
//! it in the race would burn a slot returning 500s for half of all
//! requests. Re-add it via `Config::gateway_fallback_urls` once the
//! gateway-side codec bug is fixed (one-line config change, no code
//! change).
//!
//! # CID verification
//!
//! Every fetched body is re-hashed against the multihash declared in
//! the requested CID. We support standard IPFS multihash codes:
//!
//! - `0x1e` (BLAKE3)   — used by encrypted SDK chunk uploads via
//!   `block/put?mhtype=blake3` (`fula-blockstore::ipfs::put_block_raw`)
//! - `0x12` (SHA2-256) — used by IPFS UnixFS chunked uploads
//!   (`block/put` default; `add?cid-version=1`)
//!
//! Any other multihash code → [`VerifyError::UnsupportedHashCode`]. We
//! deliberately do NOT support `cid_utils::create_cid`'s quirky
//! `sha2_256(blake3(data))` scheme because that path is only used by
//! the in-memory `MemoryBlockStore` (test backend) and never produces
//! CIDs that round-trip to public IPFS gateways.
//!
//! # Backward compatibility
//!
//! Phase 2.3 is purely additive new infrastructure. No callers exist
//! yet — Phase 2.4 wires this into [`crate::encryption`]'s GET path.
//! Existing reads against a healthy master continue to behave exactly
//! as before.

#![cfg(not(target_arch = "wasm32"))]

use bytes::Bytes;
use cid::Cid;
use parking_lot::Mutex;
use std::time::{Duration, Instant};

/// IPFS multihash code for BLAKE3-256.
const MULTIHASH_BLAKE3: u64 = 0x1e;
/// IPFS multihash code for SHA2-256.
const MULTIHASH_SHA2_256: u64 = 0x12;

/// Default decay time-constant. After `TAU`, a penalty of 1.0 decays
/// to ~0.37; after `3 * TAU` (~3 minutes for default 60s) it's at ~5%.
/// Configurable per `effective_priority` call so tests can use a much
/// shorter TAU without sleeping for minutes.
pub(crate) const DEFAULT_DECAY_TAU: Duration = Duration::from_secs(60);

/// Cooldown after a CID-verification failure. A gateway returning
/// content that fails CID verification is "returned wrong bytes" —
/// a strong-signal event. Penalty alone (decay TAU=60s) returns to
/// ~5% in 3 min, which is too fast to trust again. Cooldown enforces
/// a hard 5-min skip period before the gateway can re-enter the race.
pub(crate) const VERIFY_FAILURE_COOLDOWN: Duration = Duration::from_secs(300);

/// Default per-gateway request timeout. The default reqwest timeout
/// (30s) is too generous for K=3 racing; if Cloudflare hangs, we want
/// the race to give up on it within 10s and let dweb.link's faster
/// response win.
pub(crate) const DEFAULT_FETCH_TIMEOUT: Duration = Duration::from_secs(10);

/// Default ordered list of public gateway URL templates. Lower index =
/// higher base priority. Phase 2.3 races the top K (default 3) of these
/// in parallel; Phase 2.4 will use this directly.
///
/// Each template uses a literal `{cid}` placeholder that gets substituted
/// with the requested CID's `to_string()` form. All six gateways speak
/// standard `/ipfs/<cid>` URL conventions.
pub fn default_gateway_urls() -> Vec<String> {
    vec![
        "https://cloudflare-ipfs.com/ipfs/{cid}".to_string(),
        "https://dweb.link/ipfs/{cid}".to_string(),
        "https://ipfs.io/ipfs/{cid}".to_string(),
        "https://trustless-gateway.link/ipfs/{cid}".to_string(),
        "https://4everland.io/ipfs/{cid}".to_string(),
        "https://gateway.pinata.cloud/ipfs/{cid}".to_string(),
    ]
}

/// Errors specific to gateway-fetched body verification.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum VerifyError {
    /// The CID's multihash code is one we don't know how to verify.
    /// Returned for codes other than BLAKE3 (0x1e) and SHA2-256 (0x12).
    #[error("unsupported multihash code: 0x{code:x}")]
    UnsupportedHashCode { code: u64 },

    /// The fetched bytes hash to a different digest than the CID's
    /// multihash. Possible causes: gateway returned wrong content,
    /// in-flight tampering, or the gateway has the wrong block under
    /// this CID (shouldn't happen since CIDs are content-addressed).
    #[error("digest mismatch (CID hash code 0x{code:x})")]
    DigestMismatch { code: u64 },
}

/// Re-hash `data` using the algorithm declared in `cid`'s multihash and
/// compare against the CID's digest. Returns `Ok(())` if the bytes
/// content-address to the CID, otherwise [`VerifyError`].
///
/// This is the security boundary: a successful return means the bytes
/// are exactly what the CID claims they are. Callers MUST refuse to
/// hand the bytes to downstream consumers if this fails.
pub fn verify_cid_against_bytes(cid: &Cid, data: &[u8]) -> Result<(), VerifyError> {
    let mh = cid.hash();
    let code = mh.code();
    let expected_digest = mh.digest();
    match code {
        MULTIHASH_BLAKE3 => {
            let actual = blake3::hash(data);
            if actual.as_bytes().as_slice() == expected_digest {
                Ok(())
            } else {
                Err(VerifyError::DigestMismatch { code })
            }
        }
        MULTIHASH_SHA2_256 => {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(data);
            let actual = hasher.finalize();
            if actual.as_slice() == expected_digest {
                Ok(())
            } else {
                Err(VerifyError::DigestMismatch { code })
            }
        }
        other => Err(VerifyError::UnsupportedHashCode { code: other }),
    }
}

// ============================================================
// Gateway pool data structures (Checkpoint A skeleton).
// Behavior (penalty math, decay, fetch, race) lands in subsequent
// checkpoints.
// ============================================================

/// Per-gateway runtime state. Penalty + cooldown + last-observed
/// timestamp drive the dynamic priority calculation in Checkpoint B.
#[derive(Debug)]
pub(crate) struct GatewayState {
    /// 0.0 = healthy, 1.0 = fully sidelined. Decays toward 0 over time.
    pub(crate) penalty: f32,
    /// Bumped on each failure; reset on each success. Used by the
    /// circuit-breaker open rule (Checkpoint C).
    pub(crate) consecutive_failures: u32,
    /// When the last priority observation / state mutation happened.
    /// Used to compute decay lazily on the next read.
    pub(crate) last_observed_at: Instant,
    /// Hard skip until this instant if Some — set on HTTP 429 with a
    /// `Retry-After` header. Bypasses penalty math entirely while in
    /// effect.
    pub(crate) cooldown_until: Option<Instant>,
}

impl GatewayState {
    fn fresh() -> Self {
        Self {
            penalty: 0.0,
            consecutive_failures: 0,
            last_observed_at: Instant::now(),
            cooldown_until: None,
        }
    }
}

/// One entry in the gateway pool. Cheap-clone via `Arc` (Checkpoint C
/// will wrap `GatewayPool` in `Arc` so all SDK clones share state).
#[derive(Debug)]
pub(crate) struct Gateway {
    /// URL template containing `{cid}` placeholder.
    pub(crate) url_template: String,
    /// Index in the configured list (0 = highest base priority).
    pub(crate) base_priority: u8,
    pub(crate) state: Mutex<GatewayState>,
}

impl Gateway {
    fn new(url_template: String, base_priority: u8) -> Self {
        Self {
            url_template,
            base_priority,
            state: Mutex::new(GatewayState::fresh()),
        }
    }

    /// Substitute the `{cid}` placeholder with the requested CID's
    /// canonical string form.
    pub(crate) fn url_for(&self, cid: &Cid) -> String {
        self.url_template
            .replace("{cid}", &cid.to_string())
    }

    /// Record a successful fetch + verify. Halves the penalty and
    /// resets the consecutive-failure counter.
    pub(crate) fn record_success(&self) {
        let mut s = self.state.lock();
        s.penalty *= 0.5;
        s.consecutive_failures = 0;
        s.last_observed_at = Instant::now();
    }

    /// Record a transient failure (5xx, timeout, connection error).
    /// Bumps penalty by 0.3 (capped at 1.0) and increments the
    /// consecutive-failure counter.
    pub(crate) fn record_transient_failure(&self) {
        let mut s = self.state.lock();
        s.penalty = (s.penalty + 0.3).min(1.0);
        s.consecutive_failures = s.consecutive_failures.saturating_add(1);
        s.last_observed_at = Instant::now();
    }

    /// Record a CID-verification failure. Strong-signal event — the
    /// gateway returned bytes that don't content-address to the CID.
    /// Sets penalty to 1.0 AND a 5-minute cooldown. Cooldown is the
    /// primary defense (skips this gateway from the race entirely);
    /// penalty=1.0 is the diagnostic signal that recovers via decay
    /// after cooldown lifts.
    pub(crate) fn record_verify_failure(&self) {
        let mut s = self.state.lock();
        s.penalty = 1.0;
        s.consecutive_failures = s.consecutive_failures.saturating_add(1);
        s.last_observed_at = Instant::now();
        s.cooldown_until = Some(Instant::now() + VERIFY_FAILURE_COOLDOWN);
    }

    /// Record an HTTP 429 with `Retry-After` header. Sets cooldown
    /// without changing penalty — rate limits are a load-shedding
    /// signal, not a quality issue.
    pub(crate) fn record_rate_limit(&self, retry_after: Duration) {
        let mut s = self.state.lock();
        s.cooldown_until = Some(Instant::now() + retry_after);
    }

    /// Compute the effective priority at `now` using the given decay
    /// time-constant. Lower = higher priority (matches sort order).
    ///
    /// **Pure** — does NOT mutate state. Decay is computed lazily
    /// from `(penalty, last_observed_at)`. Only events
    /// (`record_success` / `record_transient_failure` / etc.) update
    /// `last_observed_at`. This makes decay a function of
    /// time-since-last-event, which is the property we want.
    pub(crate) fn effective_priority(&self, now: Instant, tau: Duration) -> f32 {
        let (penalty, last_obs) = {
            let s = self.state.lock();
            (s.penalty, s.last_observed_at)
        };
        let elapsed = now.saturating_duration_since(last_obs).as_secs_f32();
        let tau_secs = tau.as_secs_f32().max(0.001);
        let decayed = penalty * (-elapsed / tau_secs).exp();
        self.base_priority as f32 + decayed * 3.0
    }

    /// True iff the gateway is in an active cooldown window. Phase 2.3
    /// Checkpoint C will use this to filter cooldowned gateways out of
    /// the race candidate set entirely (rather than letting them
    /// participate as f32::INFINITY losers).
    pub(crate) fn is_in_cooldown(&self, now: Instant) -> bool {
        let s = self.state.lock();
        s.cooldown_until.map_or(false, |until| now < until)
    }
}

/// Outcome of a single-gateway fetch+verify attempt.
#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    /// 5xx, request timeout, connection-level error. Caller bumps
    /// the gateway's penalty.
    #[error("transient gateway failure: {0}")]
    Transient(String),

    /// HTTP 429 with `Retry-After` parsed. Caller sets cooldown_until
    /// = now + retry_after; no penalty change.
    #[error("rate limited (retry after {retry_after_secs}s)")]
    RateLimited { retry_after_secs: u64 },

    /// HTTP 404 / 410. Request-level outcome — gateway responded
    /// correctly, content just isn't there. No penalty change.
    #[error("content not found at gateway")]
    NotFound,

    /// Gateway returned bytes that don't hash to the requested CID's
    /// multihash. Caller calls `record_verify_failure` (penalty=1.0
    /// + 5-min cooldown).
    #[error("CID verification failed: {0}")]
    VerifyFailed(#[from] VerifyError),
}

/// Fetch a single CID from one specific gateway with timeout + CID
/// verification. Used by the race in Checkpoint C; testable directly.
///
/// On HTTP 200: reads body, verifies via `verify_cid_against_bytes`.
/// On HTTP 429: parses `Retry-After` (decimal-seconds form; falls
///   back to a 60-second default if the header is missing/unparseable).
/// On HTTP 4xx (other than 429) and 5xx: surfaces as the appropriate
///   `FetchError` variant.
///
/// Note: this function does NOT call any of the gateway's `record_*`
/// methods. The race orchestrator (Checkpoint C) does that based on
/// the returned `FetchError` variant. Keeping the side-effects in
/// the orchestrator makes per-gateway behavior easier to test.
pub(crate) async fn fetch_one(
    gateway: &Gateway,
    cid: &Cid,
    http: &reqwest::Client,
    timeout: Duration,
) -> Result<Bytes, FetchError> {
    let url = gateway.url_for(cid);
    let resp = http
        .get(&url)
        .timeout(timeout)
        .send()
        .await
        .map_err(|e| FetchError::Transient(format!("send: {}", e)))?;

    let status = resp.status();

    if status.is_success() {
        let body = resp
            .bytes()
            .await
            .map_err(|e| FetchError::Transient(format!("body read: {}", e)))?;
        verify_cid_against_bytes(cid, &body)?;
        Ok(body)
    } else if status.as_u16() == 429 {
        // Retry-After: HTTP/1.1 spec allows either delta-seconds or
        // an HTTP-date. Most public gateways emit delta-seconds. Fall
        // back to a 60-second default for missing/unparseable headers
        // so we don't loop hot against a rate-limiter.
        let retry_after_secs = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.trim().parse::<u64>().ok())
            .unwrap_or(60);
        Err(FetchError::RateLimited { retry_after_secs })
    } else if status.as_u16() == 404 || status.as_u16() == 410 {
        Err(FetchError::NotFound)
    } else {
        Err(FetchError::Transient(format!("HTTP {}", status.as_u16())))
    }
}

/// A pool of gateways racing the same CID fetch. Constructed once per
/// `FulaClient` and shared across all clones via `Arc` (Checkpoint C).
#[derive(Debug)]
pub struct GatewayPool {
    pub(crate) gateways: Vec<Gateway>,
    /// How many gateways to race in parallel for a single CID. Default
    /// 3 — caches the median Cloudflare-occasional-blip without paying
    /// the latency cost of a single sequential request, while not
    /// wasting bandwidth on K-1 cancelled losers.
    pub(crate) race_concurrency: usize,
}

impl GatewayPool {
    /// Construct a pool with the default 6-gateway list and race
    /// concurrency K=3. Use this in production unless an operator has
    /// overridden via [`Config::gateway_fallback_urls`](crate::Config).
    pub fn default_pool() -> Self {
        let gateways = default_gateway_urls()
            .into_iter()
            .enumerate()
            .map(|(i, url)| Gateway::new(url, i as u8))
            .collect();
        Self {
            gateways,
            race_concurrency: 3,
        }
    }

    /// Construct a pool from explicit URL templates. Use this for tests
    /// (against `wiremock`) or operator overrides.
    pub fn with_gateways(urls: Vec<String>, race_concurrency: usize) -> Self {
        let gateways = urls
            .into_iter()
            .enumerate()
            .map(|(i, url)| Gateway::new(url, i as u8))
            .collect();
        Self {
            gateways,
            race_concurrency,
        }
    }

    /// Number of gateways in the pool.
    pub fn len(&self) -> usize {
        self.gateways.len()
    }

    /// True if no gateways are configured (effectively disables
    /// gateway-race fallback).
    pub fn is_empty(&self) -> bool {
        self.gateways.is_empty()
    }

    /// Select gateways eligible to race RIGHT NOW. Filters out
    /// cooldowned gateways entirely (rather than letting them
    /// participate as f32::INFINITY losers — a sentinel-value hack),
    /// sorts the remaining by effective priority ascending (lower =
    /// faster path), and takes the top `race_concurrency`.
    ///
    /// PERF: this calls `effective_priority` twice per gateway during
    /// sort comparisons (O(n log n) calls total). For the default 6
    /// gateways, that's ~30 evaluations — acceptable. If the pool
    /// grows past ~20 gateways, swap to `sort_by_cached_key` with a
    /// `Reverse(NotNan)` wrapper or pre-compute `(priority, gateway)`
    /// tuples and sort those.
    ///
    /// Returns an empty `Vec` if every gateway is in cooldown.
    /// Callers (`fetch_verified`) interpret empty as
    /// [`GatewayPoolError::AllUnavailable`] — a "try later" signal,
    /// distinct from [`GatewayPoolError::AllFailed`] (racers ran but
    /// all returned errors).
    pub(crate) fn select_for_race(&self, now: Instant) -> Vec<&Gateway> {
        let mut alive: Vec<&Gateway> = self
            .gateways
            .iter()
            .filter(|g| !g.is_in_cooldown(now))
            .collect();
        alive.sort_by(|a, b| {
            a.effective_priority(now, DEFAULT_DECAY_TAU)
                .total_cmp(&b.effective_priority(now, DEFAULT_DECAY_TAU))
        });
        alive.truncate(self.race_concurrency);
        alive
    }

    /// Fetch a CID by racing the top-K eligible gateways in parallel.
    /// Returns the first verified body. Cancels in-flight losers via
    /// `Drop` of the spawned futures (reqwest cancels the underlying
    /// HTTP request on `Response::drop`, releasing the socket).
    ///
    /// Per-racer outcomes update the racer's penalty/cooldown state
    /// via the orchestrator (here) — `fetch_one` itself is pure.
    ///
    /// PERF: each settled future synchronously locks the per-gateway
    /// `parking_lot::Mutex` to update penalty/cooldown. Two
    /// simultaneous `fetch_verified` calls hitting the same gateway
    /// will briefly contend on that lock. Negligible for v1; revisit
    /// if profiling shows lock contention under heavy parallel-race
    /// load.
    pub async fn fetch_verified(
        &self,
        cid: &Cid,
        http: &reqwest::Client,
    ) -> Result<Bytes, GatewayPoolError> {
        use futures::stream::FuturesUnordered;
        use futures::StreamExt;

        let now = Instant::now();
        let candidates = self.select_for_race(now);
        if candidates.is_empty() {
            return Err(GatewayPoolError::AllUnavailable);
        }

        // Spawn one future per candidate. Each future returns a tuple
        // (gateway_index_in_pool, fetch_result) so the post-race state
        // mutation can apply to the right gateway.
        let mut in_flight: FuturesUnordered<_> = candidates
            .iter()
            .enumerate()
            .map(|(i, g)| {
                let g_ref = *g;
                async move {
                    let r = fetch_one(g_ref, cid, http, DEFAULT_FETCH_TIMEOUT).await;
                    (i, g_ref, r)
                }
            })
            .collect();

        let mut errors: Vec<String> = Vec::new();

        while let Some((_idx, g, result)) = in_flight.next().await {
            match result {
                Ok(body) => {
                    g.record_success();
                    // Drop in_flight to cancel remaining racers.
                    drop(in_flight);
                    return Ok(body);
                }
                Err(FetchError::Transient(msg)) => {
                    g.record_transient_failure();
                    errors.push(format!("transient: {}", msg));
                }
                Err(FetchError::RateLimited { retry_after_secs }) => {
                    g.record_rate_limit(Duration::from_secs(retry_after_secs));
                    errors.push(format!("rate-limited (retry {}s)", retry_after_secs));
                }
                Err(FetchError::NotFound) => {
                    // Request-level outcome — no penalty change. But
                    // a 404 from this gateway means the content isn't
                    // there; collect for diagnostic, race continues.
                    errors.push("not-found".to_string());
                }
                Err(FetchError::VerifyFailed(ve)) => {
                    g.record_verify_failure();
                    errors.push(format!("verify-failed: {}", ve));
                }
            }
        }

        Err(GatewayPoolError::AllFailed { errors })
    }
}

/// Outcome of a multi-gateway race. Distinct from `FetchError`
/// because the race aggregates per-gateway results.
#[derive(Debug, thiserror::Error)]
pub enum GatewayPoolError {
    /// Every gateway in the pool is currently in a cooldown window
    /// (recent rate-limit or verify-failure). This is a "try again
    /// later" signal — short-term unavailable, not a failure of the
    /// content itself.
    #[error("all gateways are in cooldown; retry later")]
    AllUnavailable,

    /// All eligible gateways were raced and all returned errors
    /// (transient, rate-limited, not-found, or verify-failed).
    /// `errors` lists the per-racer outcomes for diagnostic logging.
    #[error("all gateway racers failed: {errors:?}")]
    AllFailed { errors: Vec<String> },
}

#[cfg(test)]
mod tests {
    use super::*;
    use cid::multihash::Multihash;
    use sha2::{Digest, Sha256};

    /// Build a raw-codec CID with a BLAKE3 multihash over `data`. This
    /// matches what `block/put?mhtype=blake3` produces (the encrypted
    /// SDK chunk-upload path).
    fn cid_blake3(data: &[u8]) -> Cid {
        let h = blake3::hash(data);
        let mh = Multihash::<64>::wrap(MULTIHASH_BLAKE3, h.as_bytes()).unwrap();
        Cid::new_v1(0x55 /* raw */, mh)
    }

    /// Build a dag-cbor CID with a SHA2-256 multihash over `data`. This
    /// matches what `block/put` (default) and `add?cid-version=1`
    /// produce.
    fn cid_sha2(data: &[u8]) -> Cid {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let digest = hasher.finalize();
        let mh = Multihash::<64>::wrap(MULTIHASH_SHA2_256, digest.as_slice()).unwrap();
        Cid::new_v1(0x71 /* dag-cbor */, mh)
    }

    // ============================================================
    // default_gateway_urls
    // ============================================================

    #[test]
    fn test_default_gateway_urls_list_is_six_entries() {
        let urls = default_gateway_urls();
        assert_eq!(urls.len(), 6);
    }

    #[test]
    fn test_default_gateway_urls_does_not_include_fula_gateway() {
        // Step-0 finding (2026-05-01): ipfs.cloud.fx.land/gateway/
        // returns 500 on dag-cbor codec. Default list MUST NOT include
        // it until that codec bug is fixed.
        let urls = default_gateway_urls();
        for url in &urls {
            assert!(
                !url.contains("ipfs.cloud.fx.land"),
                "fula gateway must not be in default list (dag-cbor codec bug); found: {}",
                url
            );
        }
    }

    #[test]
    fn test_default_gateway_urls_quality_order() {
        // Cloudflare is slot 0 (lowest latency, generous rate limits).
        // Pinata is the last fallback. Verify the published quality
        // order so a reorder is a deliberate change.
        let urls = default_gateway_urls();
        assert!(urls[0].contains("cloudflare-ipfs.com"));
        assert!(urls[1].contains("dweb.link"));
        assert!(urls[2].contains("ipfs.io"));
        assert!(urls[3].contains("trustless-gateway.link"));
        assert!(urls[4].contains("4everland.io"));
        assert!(urls[5].contains("gateway.pinata.cloud"));
    }

    #[test]
    fn test_default_gateway_urls_have_cid_placeholder() {
        for url in default_gateway_urls() {
            assert!(
                url.contains("{cid}"),
                "url must have {{cid}} placeholder: {}",
                url
            );
        }
    }

    // ============================================================
    // verify_cid_against_bytes
    // ============================================================

    #[test]
    fn test_verify_blake3_match_passes() {
        // The encrypted SDK's chunk-upload path produces blake3+raw
        // CIDs. Verification of correct bytes against such a CID must
        // pass.
        let data = b"hello blake3 world";
        let cid = cid_blake3(data);
        verify_cid_against_bytes(&cid, data).expect("blake3 verify on matching bytes");
    }

    #[test]
    fn test_verify_blake3_mismatch_rejects() {
        // Tampered bytes must be rejected with DigestMismatch.
        let original = b"original content";
        let cid = cid_blake3(original);

        let tampered = b"tampered content";
        match verify_cid_against_bytes(&cid, tampered) {
            Err(VerifyError::DigestMismatch { code }) => {
                assert_eq!(code, MULTIHASH_BLAKE3);
            }
            other => panic!("expected DigestMismatch, got {:?}", other),
        }
    }

    #[test]
    fn test_verify_sha2_match_passes() {
        // IPFS UnixFS / standard `block/put` paths produce sha2-256
        // multihash CIDs. Verification of correct bytes must pass.
        let data = b"hello sha2 world";
        let cid = cid_sha2(data);
        verify_cid_against_bytes(&cid, data).expect("sha2 verify on matching bytes");
    }

    #[test]
    fn test_verify_sha2_mismatch_rejects() {
        let original = b"sha2 original";
        let cid = cid_sha2(original);
        let tampered = b"sha2 tampered";
        match verify_cid_against_bytes(&cid, tampered) {
            Err(VerifyError::DigestMismatch { code }) => {
                assert_eq!(code, MULTIHASH_SHA2_256);
            }
            other => panic!("expected DigestMismatch, got {:?}", other),
        }
    }

    #[test]
    fn test_verify_unsupported_hash_code_rejects() {
        // SHA3-256 (code 0x16) is NOT in our supported set. Even if
        // the bytes "match" via sha2/blake3, we must refuse rather
        // than fake a verification we can't actually perform.
        let data = b"sha3 test";
        // Build a CID with an arbitrary code we don't support.
        let mh = Multihash::<64>::wrap(0x16 /* sha3-256 */, &[0u8; 32]).unwrap();
        let cid = Cid::new_v1(0x55, mh);
        match verify_cid_against_bytes(&cid, data) {
            Err(VerifyError::UnsupportedHashCode { code }) => {
                assert_eq!(code, 0x16);
            }
            other => panic!("expected UnsupportedHashCode, got {:?}", other),
        }
    }

    #[test]
    fn test_verify_empty_data_against_empty_blake3() {
        // Edge case: empty body. blake3("") has a well-defined digest;
        // verification must work on length-0 inputs without panic.
        let cid = cid_blake3(b"");
        verify_cid_against_bytes(&cid, b"").expect("empty bytes verify");
    }

    // ============================================================
    // GatewayPool skeleton (Checkpoint A — structure only)
    // ============================================================

    #[test]
    fn test_default_pool_has_six_gateways() {
        let pool = GatewayPool::default_pool();
        assert_eq!(pool.len(), 6);
        assert_eq!(pool.race_concurrency, 3);
    }

    #[test]
    fn test_pool_with_gateways_sets_concurrency() {
        let pool = GatewayPool::with_gateways(
            vec!["https://test1.example/ipfs/{cid}".to_string()],
            2,
        );
        assert_eq!(pool.len(), 1);
        assert_eq!(pool.race_concurrency, 2);
    }

    #[test]
    fn test_pool_assigns_base_priority_by_index() {
        let pool = GatewayPool::default_pool();
        for (i, g) in pool.gateways.iter().enumerate() {
            assert_eq!(g.base_priority as usize, i);
        }
    }

    #[test]
    fn test_gateway_url_for_substitutes_cid() {
        let g = Gateway::new("https://example.test/ipfs/{cid}".to_string(), 0);
        let cid = cid_blake3(b"x");
        let url = g.url_for(&cid);
        assert!(url.contains(&cid.to_string()));
        assert!(!url.contains("{cid}"));
    }

    #[test]
    fn test_gateway_state_starts_healthy() {
        let g = Gateway::new("https://x/{cid}".to_string(), 0);
        let s = g.state.lock();
        assert_eq!(s.penalty, 0.0);
        assert_eq!(s.consecutive_failures, 0);
        assert!(s.cooldown_until.is_none());
    }

    // ============================================================
    // Checkpoint B: per-gateway penalty math + cooldown
    // ============================================================

    #[test]
    fn test_record_success_halves_penalty_and_resets_counter() {
        let g = Gateway::new("https://x/{cid}".to_string(), 0);
        // Pre-condition: simulate an existing penalty
        {
            let mut s = g.state.lock();
            s.penalty = 0.6;
            s.consecutive_failures = 3;
        }
        g.record_success();
        let s = g.state.lock();
        assert!((s.penalty - 0.3).abs() < f32::EPSILON, "penalty must be halved");
        assert_eq!(s.consecutive_failures, 0);
    }

    #[test]
    fn test_record_transient_failure_caps_at_one() {
        let g = Gateway::new("https://x/{cid}".to_string(), 0);
        // Five consecutive failures must cap penalty at exactly 1.0
        // (3 * 0.3 = 0.9, then +0.3 → 1.0; further +0.3 stays at 1.0).
        for _ in 0..5 {
            g.record_transient_failure();
        }
        let s = g.state.lock();
        assert!(s.penalty <= 1.0 + f32::EPSILON, "penalty must cap at 1.0");
        assert!(s.penalty > 0.99, "penalty must reach 1.0 after 5 failures");
        assert_eq!(s.consecutive_failures, 5);
    }

    #[test]
    fn test_record_verify_failure_pegs_penalty_and_sets_cooldown() {
        let g = Gateway::new("https://x/{cid}".to_string(), 0);
        let before = Instant::now();
        g.record_verify_failure();
        let s = g.state.lock();
        assert_eq!(s.penalty, 1.0);
        let cd = s.cooldown_until.expect("cooldown must be set");
        // Cooldown should be ~5 minutes from now.
        let target = before + VERIFY_FAILURE_COOLDOWN;
        // Allow slack for the time elapsed during the test.
        assert!(cd >= target - Duration::from_secs(1));
        assert!(cd <= target + Duration::from_secs(2));
    }

    #[test]
    fn test_record_rate_limit_sets_cooldown_only() {
        // Rate-limit cooldown must NOT change penalty (load-shedding,
        // not a quality issue).
        let g = Gateway::new("https://x/{cid}".to_string(), 0);
        let pre_penalty = g.state.lock().penalty;
        g.record_rate_limit(Duration::from_secs(30));
        let s = g.state.lock();
        assert_eq!(s.penalty, pre_penalty, "rate limit must not change penalty");
        assert!(s.cooldown_until.is_some());
    }

    #[test]
    fn test_is_in_cooldown_transitions_through_expiry() {
        let g = Gateway::new("https://x/{cid}".to_string(), 0);
        // Fresh: not in cooldown.
        assert!(!g.is_in_cooldown(Instant::now()));

        g.record_rate_limit(Duration::from_millis(50));
        assert!(g.is_in_cooldown(Instant::now()), "must be in cooldown immediately after rate-limit");

        std::thread::sleep(Duration::from_millis(80));
        assert!(
            !g.is_in_cooldown(Instant::now()),
            "cooldown must auto-expire after the retry-after duration"
        );
    }

    #[test]
    fn test_effective_priority_reflects_decayed_penalty() {
        // With a fast TAU (100ms), penalty=1.0 should decay to ~0.37
        // after 1 TAU and ~0.05 after 3 TAUs.
        let g = Gateway::new("https://x/{cid}".to_string(), 2);
        // Force penalty to 1.0 directly so we have a known starting
        // point (record_transient_failure also bumps last_observed_at,
        // which we want to set to "just now" anyway).
        g.record_transient_failure();
        g.record_transient_failure();
        g.record_transient_failure();
        g.record_transient_failure();
        let now = Instant::now();
        let tau = Duration::from_millis(100);

        // Immediately after, penalty ~1.0, so effective_priority
        // ≈ base_priority + 1.0 * 3.0 = 5.0.
        let pri_now = g.effective_priority(now, tau);
        assert!(
            pri_now > 4.5 && pri_now < 5.5,
            "expected ~5.0 (base 2 + penalty*3), got {}",
            pri_now
        );

        // After 1 TAU: decay factor exp(-1) ≈ 0.368. Penalty ≈ 0.368,
        // effective ≈ 2.0 + 1.1 = ~3.1.
        let one_tau_later = now + tau;
        let pri_after = g.effective_priority(one_tau_later, tau);
        assert!(
            pri_after > 2.8 && pri_after < 3.3,
            "expected ~3.1 (base 2 + 0.37*3), got {}",
            pri_after
        );

        // After 5 TAUs: decay factor exp(-5) ≈ 0.0067. Penalty essentially
        // gone, effective ≈ base_priority = 2.0.
        let five_tau_later = now + tau * 5;
        let pri_far_later = g.effective_priority(five_tau_later, tau);
        assert!(
            pri_far_later >= 2.0 && pri_far_later < 2.1,
            "expected ~2.0 after 5 TAUs of decay, got {}",
            pri_far_later
        );
    }

    #[test]
    fn test_effective_priority_does_not_mutate_state() {
        // Decay-on-read is pure. Calling effective_priority multiple
        // times must NOT advance last_observed_at — that's what makes
        // decay a function of time-since-last-event, not
        // time-since-last-read.
        let g = Gateway::new("https://x/{cid}".to_string(), 0);
        g.record_transient_failure();
        let pre_obs = g.state.lock().last_observed_at;
        let pre_pen = g.state.lock().penalty;

        let _ = g.effective_priority(Instant::now() + Duration::from_secs(1), Duration::from_secs(60));
        let _ = g.effective_priority(Instant::now() + Duration::from_secs(2), Duration::from_secs(60));

        let post_obs = g.state.lock().last_observed_at;
        let post_pen = g.state.lock().penalty;

        assert_eq!(pre_obs, post_obs, "last_observed_at must not change on read");
        assert_eq!(pre_pen, post_pen, "penalty must not change on read");
    }

    // ============================================================
    // Checkpoint B: fetch_one against wiremock
    // ============================================================

    #[tokio::test]
    async fn test_fetch_one_success_with_matching_bytes() {
        use wiremock::matchers::{method, path_regex};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let data = b"hello fetch_one";
        let cid = cid_blake3(data);

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex(r"/ipfs/.+"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(data.as_ref()))
            .mount(&server)
            .await;

        let gw = Gateway::new(format!("{}/ipfs/{{cid}}", server.uri()), 0);
        let http = reqwest::Client::new();
        let body = fetch_one(&gw, &cid, &http, Duration::from_secs(5))
            .await
            .expect("fetch_one ok");
        assert_eq!(body.as_ref(), data);
    }

    #[tokio::test]
    async fn test_fetch_one_tampered_bytes_rejected() {
        // The gateway returns bytes that DON'T hash to the requested
        // CID. fetch_one must reject with VerifyFailed — the security
        // boundary that defends against malicious or buggy gateways.
        use wiremock::matchers::{method, path_regex};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let cid_data = b"original content";
        let cid = cid_blake3(cid_data);
        let tampered = b"tampered content";

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex(r"/ipfs/.+"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(tampered.as_ref()))
            .mount(&server)
            .await;

        let gw = Gateway::new(format!("{}/ipfs/{{cid}}", server.uri()), 0);
        let http = reqwest::Client::new();
        match fetch_one(&gw, &cid, &http, Duration::from_secs(5)).await {
            Err(FetchError::VerifyFailed(VerifyError::DigestMismatch { .. })) => { /* ok */ }
            other => panic!("expected VerifyFailed/DigestMismatch, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_fetch_one_404_returns_not_found() {
        use wiremock::matchers::{method, path_regex};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let cid = cid_blake3(b"some content");

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex(r"/ipfs/.+"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let gw = Gateway::new(format!("{}/ipfs/{{cid}}", server.uri()), 0);
        let http = reqwest::Client::new();
        match fetch_one(&gw, &cid, &http, Duration::from_secs(5)).await {
            Err(FetchError::NotFound) => { /* ok */ }
            other => panic!("expected NotFound, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_fetch_one_503_returns_transient() {
        use wiremock::matchers::{method, path_regex};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let cid = cid_blake3(b"some content");

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex(r"/ipfs/.+"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;

        let gw = Gateway::new(format!("{}/ipfs/{{cid}}", server.uri()), 0);
        let http = reqwest::Client::new();
        match fetch_one(&gw, &cid, &http, Duration::from_secs(5)).await {
            Err(FetchError::Transient(_)) => { /* ok */ }
            other => panic!("expected Transient, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_fetch_one_429_with_retry_after_returns_rate_limited() {
        use wiremock::matchers::{method, path_regex};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let cid = cid_blake3(b"some content");

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex(r"/ipfs/.+"))
            .respond_with(ResponseTemplate::new(429).insert_header("Retry-After", "42"))
            .mount(&server)
            .await;

        let gw = Gateway::new(format!("{}/ipfs/{{cid}}", server.uri()), 0);
        let http = reqwest::Client::new();
        match fetch_one(&gw, &cid, &http, Duration::from_secs(5)).await {
            Err(FetchError::RateLimited { retry_after_secs }) => {
                assert_eq!(retry_after_secs, 42, "must parse Retry-After header");
            }
            other => panic!("expected RateLimited, got {:?}", other),
        }
    }

    // ============================================================
    // Checkpoint C: race orchestration + circuit breaker
    // ============================================================

    #[test]
    fn test_select_for_race_filters_cooldowned() {
        // 3 gateways. Put gateway 1 in cooldown. select_for_race
        // returns gateways 0 and 2 only.
        let pool = GatewayPool::with_gateways(
            vec![
                "https://g0/{cid}".to_string(),
                "https://g1/{cid}".to_string(),
                "https://g2/{cid}".to_string(),
            ],
            3,
        );
        pool.gateways[1].record_rate_limit(Duration::from_secs(60));

        let alive = pool.select_for_race(Instant::now());
        assert_eq!(alive.len(), 2);
        assert!(alive.iter().any(|g| g.url_template.contains("g0")));
        assert!(alive.iter().any(|g| g.url_template.contains("g2")));
        assert!(!alive.iter().any(|g| g.url_template.contains("g1")));
    }

    #[test]
    fn test_select_for_race_takes_top_k_by_priority() {
        // 6 gateways with K=2. select_for_race returns the 2 with
        // lowest effective priority (= highest quality), which for
        // a fresh pool is just gateways 0 and 1 (base_priority 0, 1).
        let pool = GatewayPool::with_gateways(
            vec![
                "https://g0/{cid}".to_string(),
                "https://g1/{cid}".to_string(),
                "https://g2/{cid}".to_string(),
                "https://g3/{cid}".to_string(),
                "https://g4/{cid}".to_string(),
                "https://g5/{cid}".to_string(),
            ],
            2,
        );
        let racers = pool.select_for_race(Instant::now());
        assert_eq!(racers.len(), 2);
        assert_eq!(racers[0].base_priority, 0);
        assert_eq!(racers[1].base_priority, 1);
    }

    #[test]
    fn test_select_for_race_penalty_demotes_gateway() {
        // Pile penalty on the top-priority gateway. After enough
        // failures, its effective priority should fall below the
        // next ones, and select_for_race should pick the others
        // first.
        let pool = GatewayPool::with_gateways(
            vec![
                "https://g0/{cid}".to_string(),
                "https://g1/{cid}".to_string(),
                "https://g2/{cid}".to_string(),
            ],
            2,
        );
        // 4 transient failures on g0 → penalty caps near 1.0,
        // effective priority ≈ 0 + 1.0*3 = 3.0.
        // g1 base = 1, g2 base = 2.
        for _ in 0..4 {
            pool.gateways[0].record_transient_failure();
        }
        let racers = pool.select_for_race(Instant::now());
        // The first two slots should be g1 and g2 (priorities 1 and 2),
        // ahead of the penalized g0 (effective ~3.0).
        assert_eq!(racers.len(), 2);
        assert!(
            racers[0].url_template.contains("g1") || racers[0].url_template.contains("g2"),
            "penalized g0 must not be top of race; got {}",
            racers[0].url_template
        );
    }

    #[test]
    fn test_select_for_race_empty_when_all_cooled_down() {
        let pool = GatewayPool::with_gateways(
            vec!["https://g0/{cid}".to_string(), "https://g1/{cid}".to_string()],
            3,
        );
        for g in &pool.gateways {
            g.record_rate_limit(Duration::from_secs(60));
        }
        let alive = pool.select_for_race(Instant::now());
        assert!(alive.is_empty());
    }

    #[tokio::test]
    async fn test_fetch_verified_first_gateway_wins() {
        use wiremock::matchers::{method, path_regex};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let data = b"race-winner-content";
        let cid = cid_blake3(data);

        // Two mock gateways: one fast 200, one slow 200.
        let server_fast = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex(r"/ipfs/.+"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(data.as_ref()))
            .mount(&server_fast)
            .await;

        let server_slow = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex(r"/ipfs/.+"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_bytes(data.as_ref())
                    .set_delay(Duration::from_secs(2)),
            )
            .mount(&server_slow)
            .await;

        let pool = GatewayPool::with_gateways(
            vec![
                format!("{}/ipfs/{{cid}}", server_fast.uri()),
                format!("{}/ipfs/{{cid}}", server_slow.uri()),
            ],
            2,
        );
        let http = reqwest::Client::new();

        let body = pool.fetch_verified(&cid, &http).await.expect("race ok");
        assert_eq!(body.as_ref(), data);
    }

    #[tokio::test]
    async fn test_fetch_verified_falls_through_failed_gateway_to_succeeding_one() {
        use wiremock::matchers::{method, path_regex};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let data = b"second-gateway-saves-the-day";
        let cid = cid_blake3(data);

        // First gateway always returns 503 (fast); second returns 200
        // with matching bytes (slightly delayed) — this 150ms delay
        // is for race-DETERMINISM in the test, not realism. Without
        // it, both responses are instant and the FuturesUnordered
        // arrival order is timing-dependent: when 200 wins the wire,
        // the 503 future is cancelled by `drop(in_flight)` before its
        // `record_transient_failure` can run, and the test's
        // assert-on-503-penalty-bump becomes flaky.
        let server_503 = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex(r"/ipfs/.+"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server_503)
            .await;

        let server_ok = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex(r"/ipfs/.+"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_bytes(data.as_ref())
                    .set_delay(Duration::from_millis(150)),
            )
            .mount(&server_ok)
            .await;

        let pool = GatewayPool::with_gateways(
            vec![
                format!("{}/ipfs/{{cid}}", server_503.uri()),
                format!("{}/ipfs/{{cid}}", server_ok.uri()),
            ],
            2,
        );
        let http = reqwest::Client::new();

        let body = pool.fetch_verified(&cid, &http).await.expect("fallback ok");
        assert_eq!(body.as_ref(), data);

        // The 503 gateway should have its penalty bumped.
        let s = pool.gateways[0].state.lock();
        assert!(s.penalty > 0.0, "503 gateway must be penalized");
        assert_eq!(s.consecutive_failures, 1);
    }

    #[tokio::test]
    async fn test_fetch_verified_all_failed_returns_aggregate_error() {
        use wiremock::matchers::{method, path_regex};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let cid = cid_blake3(b"unreachable");

        let server_a = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex(r"/ipfs/.+"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server_a)
            .await;
        let server_b = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex(r"/ipfs/.+"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server_b)
            .await;

        let pool = GatewayPool::with_gateways(
            vec![
                format!("{}/ipfs/{{cid}}", server_a.uri()),
                format!("{}/ipfs/{{cid}}", server_b.uri()),
            ],
            2,
        );
        let http = reqwest::Client::new();

        match pool.fetch_verified(&cid, &http).await {
            Err(GatewayPoolError::AllFailed { errors }) => {
                assert_eq!(errors.len(), 2, "must aggregate per-gateway errors");
            }
            other => panic!("expected AllFailed, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_fetch_verified_all_unavailable_when_pool_in_cooldown() {
        let pool = GatewayPool::with_gateways(
            vec!["http://test.invalid/ipfs/{cid}".to_string()],
            1,
        );
        pool.gateways[0].record_rate_limit(Duration::from_secs(60));

        let cid = cid_blake3(b"x");
        let http = reqwest::Client::new();
        match pool.fetch_verified(&cid, &http).await {
            Err(GatewayPoolError::AllUnavailable) => { /* ok */ }
            other => panic!("expected AllUnavailable, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_fetch_verified_tampered_response_records_verify_failure() {
        // Race a gateway that returns tampered bytes alone — the race
        // must fail (no verified body), AND the gateway's state must
        // record a verify failure (penalty=1.0, cooldown set).
        use wiremock::matchers::{method, path_regex};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let cid_data = b"original";
        let cid = cid_blake3(cid_data);
        let tampered = b"NOT THE SAME";

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex(r"/ipfs/.+"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(tampered.as_ref()))
            .mount(&server)
            .await;

        let pool = GatewayPool::with_gateways(
            vec![format!("{}/ipfs/{{cid}}", server.uri())],
            1,
        );
        let http = reqwest::Client::new();
        let result = pool.fetch_verified(&cid, &http).await;
        assert!(matches!(result, Err(GatewayPoolError::AllFailed { .. })));

        // Critical security assertion: the gateway is now in cooldown,
        // so a future race won't include it for ~5 min.
        let s = pool.gateways[0].state.lock();
        assert_eq!(s.penalty, 1.0, "verify failure pegs penalty at 1.0");
        assert!(s.cooldown_until.is_some(), "verify failure sets cooldown");
        let cooldown_remaining = s
            .cooldown_until
            .unwrap()
            .saturating_duration_since(Instant::now());
        assert!(
            cooldown_remaining > Duration::from_secs(290)
                && cooldown_remaining <= VERIFY_FAILURE_COOLDOWN + Duration::from_secs(1),
            "cooldown should be ~5 min; got {:?}",
            cooldown_remaining
        );
    }

    #[tokio::test]
    async fn test_fetch_one_429_without_retry_after_uses_default() {
        // Some gateways return 429 without a Retry-After header.
        // We must not treat that as a parseable 0-second retry —
        // the default 60s ensures we don't loop hot.
        use wiremock::matchers::{method, path_regex};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let cid = cid_blake3(b"some content");

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex(r"/ipfs/.+"))
            .respond_with(ResponseTemplate::new(429))
            .mount(&server)
            .await;

        let gw = Gateway::new(format!("{}/ipfs/{{cid}}", server.uri()), 0);
        let http = reqwest::Client::new();
        match fetch_one(&gw, &cid, &http, Duration::from_secs(5)).await {
            Err(FetchError::RateLimited { retry_after_secs }) => {
                assert_eq!(retry_after_secs, 60, "missing header → 60s default");
            }
            other => panic!("expected RateLimited, got {:?}", other),
        }
    }
}
