//! # `quota` — fail-fast credit/quota pre-check + per-session write rate limit (P10)
//!
//! Two cheap guards that run **before** the expensive encrypt+upload in
//! [`crate::store::store_file`], so the AI does not burn CPU (encryption) and
//! bandwidth on a write the gateway will reject anyway, and so a runaway AI
//! cannot spam writes:
//!
//! 1. [`QuotaDecision`] — a fail-fast **pre-flight quota check** that calls the
//!    SAME credit endpoint the gateway itself calls before storing
//!    (`GET {storage_api_url}/api/v1/storage`, `Authorization: Bearer {jwt}` →
//!    `{ "canUpload": bool }`). If the user is clearly over quota we return
//!    [`QuotaDecision::Denied`] and `store_file` fails fast with
//!    [`crate::store::StoreError::QuotaExceeded`] — no encryption, no upload.
//! 2. [`TokenBucket`] — a per-session, in-memory **token-bucket rate limiter**
//!    over WRITE ops. The MCP is stateless (one connection = one session), so
//!    one bucket per [`crate::capability::CapabilityBundle`] is exactly "per AI
//!    session." Over-limit → [`crate::store::StoreError::RateLimited`].
//!
//! ## Why the quota pre-check FAILS OPEN (the load-bearing decision)
//!
//! The pre-check is an **optimization + UX signal, NOT the security boundary.**
//! The gateway re-checks quota on the actual PUT (it calls `check_can_upload`
//! before storing and rejects an over-quota write with the S3 code
//! `AccountProblem`; see `fula-cli/src/{pinning,handlers/object}.rs`). So if our
//! pre-check cannot reach the credit service — endpoint unconfigured, network
//! error, timeout, non-2xx, or unparseable body — the correct behavior is to
//! **allow the write to proceed** and let the gateway be the authority. A check
//! outage then degrades to "the PUT may fail later with a clean
//! [`QuotaExceeded`](crate::store::StoreError::QuotaExceeded)" — NOT "every
//! write is blocked." Failing *closed* would turn a transient credit-service
//! blip into a total write outage even though the real upload path still works.
//! This mirrors the gateway's own helper, which returns `Ok(true)` (allow) on
//! every error path. Only an explicit `canUpload == false` denies.
//!
//! Because a silently-failed-open check is byte-identical to a real pass on a
//! happy path, the decision is **3-state** ([`QuotaDecision::Allowed`] /
//! [`Denied`](QuotaDecision::Denied) /
//! [`SkippedFailOpen`](QuotaDecision::SkippedFailOpen)) rather than a bare bool,
//! so tests and the audit log can tell "we checked and it passed" apart from
//! "we never managed to check." Both non-Denied variants proceed to the upload.
//!
//! ## Why rate-limit here when the gateway already does?
//!
//! The gateway ALSO rate-limits per user (a `governor` keyed limiter that
//! rejects with the S3 code `SlowDown`; see `fula-cli/src/middleware.rs`). This
//! bucket is an **additional courtesy / spam guard at the MCP boundary**, not
//! the only enforcement: it throttles a runaway model locally (before any
//! network round-trip) and is per-session, whereas the gateway's is the
//! authoritative per-user limit. A gateway `SlowDown` surfaced from the PUT is
//! mapped to [`RateLimited`](crate::store::StoreError::RateLimited) too, so the
//! model gets one clean signal whichever limiter trips.
//!
//! ## Ordering inside `store_file` (security-relevant)
//!
//! Both guards run **after** [`assert_in_scope`](crate::capability::CapabilityBundle::assert_in_scope),
//! never before: an unauthorized / out-of-scope attempt must be rejected by the
//! authority check first, so it can neither drain the session's write-token
//! budget (a local denial-of-service against legitimate writes) nor use the
//! quota response as an account-status oracle. The order is:
//! classify → build key → `assert_in_scope` → consume a write token → quota
//! pre-check → encrypt + upload.

use std::sync::Mutex;
use std::time::{Duration, Instant};

/// The default token-bucket capacity (max burst of write ops) when the bundle
/// does not override it. Generous on purpose: normal AI sessions store a handful
/// of files; this only ever throttles a pathological runaway. The gateway's
/// per-user limiter remains the authoritative cap. (Two back-to-back stores —
/// e.g. the P5 e2e — must never trip the default; a burst test overrides this to
/// a tiny value to demonstrate blocking.)
pub const DEFAULT_WRITE_BURST: u32 = 20;

/// The default sustained refill rate (write tokens per second) when the bundle
/// does not override it. At 1/s a session that pauses ~1s between writes is never
/// throttled; only a tight write loop that outruns this for a sustained burst
/// beyond the capacity is.
pub const DEFAULT_WRITE_REFILL_PER_SEC: f64 = 1.0;

/// Environment variable overriding the write-bucket capacity (burst).
pub const ENV_WRITE_BURST: &str = "FULA_MCP_WRITE_BURST";

/// Environment variable overriding the write-bucket refill rate (tokens/sec).
pub const ENV_WRITE_REFILL_PER_SEC: &str = "FULA_MCP_WRITE_REFILL_PER_SEC";

// ────────────────────────────── injectable clock ──────────────────────────────

/// A monotonic time source the [`TokenBucket`] reads, abstracted so tests can
/// drive refill deterministically with NO real sleeps.
///
/// Production uses [`SystemClock`] (real [`Instant::now`]); tests use a manual
/// clock they advance by an explicit [`Duration`]. The only operation the bucket
/// needs is "how long since this earlier instant" — expressed as a base
/// [`Instant`] plus an advanceable offset, because [`Instant`] has no public
/// arbitrary constructor (you cannot fabricate one; you can only offset a real
/// one).
pub trait Clock: Send + Sync {
    /// The current instant. Must be monotonic non-decreasing.
    fn now(&self) -> Instant;
}

/// The real, monotonic system clock ([`Instant::now`]).
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

/// A test clock: a fixed base [`Instant`] plus an offset the test advances. Never
/// moves backward. Lets the offline tests prove "denies after N, refills after
/// time T" precisely and instantly.
#[derive(Debug)]
pub struct ManualClock {
    base: Instant,
    offset: Mutex<Duration>,
}

impl ManualClock {
    /// A manual clock anchored at the real `now` with zero offset.
    pub fn new() -> Self {
        Self {
            base: Instant::now(),
            offset: Mutex::new(Duration::ZERO),
        }
    }

    /// Advance the clock by `delta` (monotonic; cannot go backward).
    pub fn advance(&self, delta: Duration) {
        let mut off = self.offset.lock().expect("manual clock poisoned");
        *off += delta;
    }
}

impl Default for ManualClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for ManualClock {
    fn now(&self) -> Instant {
        let off = *self.offset.lock().expect("manual clock poisoned");
        self.base + off
    }
}

// ────────────────────────────── token bucket ──────────────────────────────────

/// Mutable bucket state, guarded by a `std::sync::Mutex`. The critical section is
/// tiny and fully synchronous (lock → refill → consume-or-deny → unlock); it is
/// NEVER held across an `.await`, so a std mutex (not a tokio one) is correct and
/// cheap.
#[derive(Debug)]
struct BucketState {
    /// Tokens currently available (fractional so sub-second refill is exact).
    /// Always clamped to `[0, capacity]`.
    tokens: f64,
    /// The last instant we refilled to.
    last: Instant,
}

/// A classic token-bucket rate limiter over a single resource (here: WRITE ops
/// for one MCP session).
///
/// `capacity` is the bucket size (the maximum burst); `refill_per_sec` is the
/// sustained token-replenish rate. Each [`try_consume`](Self::try_consume) lazily
/// refills based on elapsed time, then takes one token if available. It is
/// independently constructible (not only via the bundle) so the offline tests can
/// drive it directly with a [`ManualClock`].
pub struct TokenBucket {
    capacity: f64,
    refill_per_sec: f64,
    state: Mutex<BucketState>,
    clock: Box<dyn Clock>,
}

impl std::fmt::Debug for TokenBucket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // No secrets here, but keep it terse and avoid printing the clock trait
        // object (which has no Debug).
        f.debug_struct("TokenBucket")
            .field("capacity", &self.capacity)
            .field("refill_per_sec", &self.refill_per_sec)
            .finish()
    }
}

impl TokenBucket {
    /// Build a bucket with the real system clock. `capacity` is floored at 1 (a
    /// zero-capacity bucket could never admit any write, which is never the
    /// intent for a courtesy limiter); `refill_per_sec` is floored at a tiny
    /// positive value so the bucket always eventually refills. Starts FULL (a
    /// fresh session may burst up to `capacity` immediately).
    pub fn new(capacity: u32, refill_per_sec: f64) -> Self {
        Self::with_clock(capacity, refill_per_sec, Box::new(SystemClock))
    }

    /// Build a bucket with an injected clock (the test seam).
    pub fn with_clock(capacity: u32, refill_per_sec: f64, clock: Box<dyn Clock>) -> Self {
        let capacity = capacity.max(1) as f64;
        // Floor the refill at a small positive rate: a non-positive rate would
        // wedge the bucket permanently empty after the first burst.
        let refill_per_sec = if refill_per_sec.is_finite() && refill_per_sec > 0.0 {
            refill_per_sec
        } else {
            DEFAULT_WRITE_REFILL_PER_SEC
        };
        let now = clock.now();
        Self {
            capacity,
            refill_per_sec,
            state: Mutex::new(BucketState {
                tokens: capacity, // start full
                last: now,
            }),
            clock,
        }
    }

    /// Try to take one token. Returns `true` if a write may proceed, `false` if
    /// the bucket is empty (rate-limited). Fully synchronous: no `.await`, so the
    /// guard is dropped before any async work in the caller.
    pub fn try_consume(&self) -> bool {
        self.try_consume_n(1.0)
    }

    /// Try to take `n` tokens (used as `try_consume(1)` in production; the
    /// parametric form keeps refill math testable).
    fn try_consume_n(&self, n: f64) -> bool {
        let now = self.clock.now();
        let mut st = self.state.lock().expect("token bucket poisoned");

        // Lazily refill by elapsed time. `Instant::saturating_duration_since`
        // yields ZERO if `now` is not after `last` (it never is, but this also
        // makes a backward-moving clock safe — elapsed is treated as zero).
        let elapsed = now.saturating_duration_since(st.last).as_secs_f64();
        if elapsed > 0.0 {
            st.tokens = (st.tokens + elapsed * self.refill_per_sec).min(self.capacity);
            st.last = now;
        }

        if st.tokens >= n {
            st.tokens -= n;
            true
        } else {
            false
        }
    }

    /// The configured capacity (burst). Exposed for tests / introspection.
    pub fn capacity(&self) -> u32 {
        self.capacity as u32
    }
}

// ────────────────────────────── quota pre-check ───────────────────────────────

/// The outcome of the pre-flight quota check.
///
/// Deliberately 3-state (not a bool): a check that we could not actually perform
/// ([`SkippedFailOpen`](Self::SkippedFailOpen)) is NOT the same as a check that
/// ran and passed ([`Allowed`](Self::Allowed)) — conflating them would let a
/// field-name / auth / endpoint bug masquerade as a healthy pass in a happy-path
/// e2e. Only [`Denied`](Self::Denied) blocks the write; both other variants
/// proceed (fail-open).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuotaDecision {
    /// The credit service was reached and reports the user CAN upload
    /// (`canUpload == true`). Proceed.
    Allowed,
    /// The credit service was reached and reports the user CANNOT upload
    /// (`canUpload == false`) — over quota / insufficient credits. Fail fast.
    Denied,
    /// The check could not be performed (no URL configured, no JWT, transport
    /// error, timeout, non-2xx status, or unparseable body). FAIL OPEN: proceed
    /// and let the gateway enforce on the real PUT. `reason` is a BOUNDED,
    /// non-secret label (never a URL, JWT, or raw error body) for the audit log.
    SkippedFailOpen(FailOpenReason),
}

impl QuotaDecision {
    /// Does this decision allow the write to proceed? True for everything except
    /// [`Denied`](Self::Denied) (the fail-open posture).
    pub fn allows(&self) -> bool {
        !matches!(self, QuotaDecision::Denied)
    }

    /// A bounded, secret-free label for the audit stream.
    pub fn audit_label(&self) -> &'static str {
        match self {
            QuotaDecision::Allowed => "quota_allowed",
            QuotaDecision::Denied => "quota_denied",
            QuotaDecision::SkippedFailOpen(_) => "quota_skipped_failopen",
        }
    }
}

/// Why a quota check was skipped (fail-open). A bounded enum — NEVER carries a
/// URL, JWT, object key, or raw gateway error body, so it is safe to log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailOpenReason {
    /// No `storage_api_url` configured in the bundle — quota checking is off
    /// (exactly the gateway's `None → Ok(true)` behavior).
    NotConfigured,
    /// No JWT available to authenticate the check.
    NoToken,
    /// The HTTP request failed to send / timed out / DNS, etc. (transport).
    Transport,
    /// The endpoint returned a non-2xx status.
    HttpStatus,
    /// The 2xx body could not be parsed into the expected shape (e.g. the
    /// `canUpload` field was absent or the JSON was malformed).
    Decode,
}

impl FailOpenReason {
    /// A bounded, secret-free label for the audit stream.
    pub fn label(self) -> &'static str {
        match self {
            FailOpenReason::NotConfigured => "not_configured",
            FailOpenReason::NoToken => "no_token",
            FailOpenReason::Transport => "transport_error",
            FailOpenReason::HttpStatus => "http_status",
            FailOpenReason::Decode => "decode_error",
        }
    }
}

/// The credit-service response shape. We mirror the gateway, which deserializes
/// only `canUpload` and ignores the rest (`isSuspended`, `currentStorageBytes`,
/// `freeTierBytes`, `message`, …).
///
/// `can_upload` is **required and not defaulted** ON PURPOSE: a body that is
/// missing the field (e.g. a renamed field or a wrong endpoint) then FAILS to
/// deserialize → [`FailOpenReason::Decode`] → fail-open, which is the safe
/// degradation. Defaulting it would make a missing field silently `false` →
/// fail-CLOSED, the opposite of the design. The `serde(alias)` tolerates the
/// snake_case spelling some backends emit (the Rust gateway + the public API use
/// `canUpload`; a Go backend variant uses `can_upload`), so either name parses,
/// but NEITHER present is a decode failure (→ fail-open), not a false `false`.
#[derive(Debug, serde::Deserialize)]
struct StorageStatus {
    #[serde(rename = "canUpload", alias = "can_upload")]
    can_upload: bool,
}

/// The raw outcome of *attempting* the quota HTTP call, handed to the pure
/// [`decide`] so every branch is unit-testable with no network. The async
/// wrapper ([`check_quota_http`]) produces one of these; `decide` turns it into a
/// [`QuotaDecision`]. This split is what keeps the fail-open logic deterministic
/// and dependency-light to test (no `wiremock` dev-dep needed).
#[derive(Debug)]
pub enum QuotaProbe {
    /// The request completed; carries the HTTP status code and the response body
    /// bytes (only inspected on 2xx).
    Response { status: u16, body: Vec<u8> },
    /// The request could not be sent / timed out / transport failure.
    TransportError,
    /// No `storage_api_url` was configured — the check is off.
    NotConfigured,
    /// No JWT available to authenticate.
    NoToken,
}

/// PURE decision function: map a [`QuotaProbe`] to a [`QuotaDecision`]. Zero
/// network, zero I/O — the whole fail-open policy lives here so every branch
/// (allowed / denied / each fail-open reason) is a plain unit test.
///
/// - `NotConfigured` / `NoToken` → fail-open with the matching reason.
/// - `TransportError` → fail-open ([`FailOpenReason::Transport`]).
/// - a non-2xx `Response` → fail-open ([`FailOpenReason::HttpStatus`]).
/// - a 2xx `Response` whose body does not parse / lacks `canUpload` → fail-open
///   ([`FailOpenReason::Decode`]).
/// - a 2xx `Response` parsed as `canUpload: true` → [`Allowed`](QuotaDecision::Allowed).
/// - a 2xx `Response` parsed as `canUpload: false` → [`Denied`](QuotaDecision::Denied)
///   (the ONLY blocking outcome).
pub fn decide(probe: QuotaProbe) -> QuotaDecision {
    match probe {
        QuotaProbe::NotConfigured => {
            QuotaDecision::SkippedFailOpen(FailOpenReason::NotConfigured)
        }
        QuotaProbe::NoToken => QuotaDecision::SkippedFailOpen(FailOpenReason::NoToken),
        QuotaProbe::TransportError => {
            QuotaDecision::SkippedFailOpen(FailOpenReason::Transport)
        }
        QuotaProbe::Response { status, body } => {
            if !(200..300).contains(&status) {
                return QuotaDecision::SkippedFailOpen(FailOpenReason::HttpStatus);
            }
            match serde_json::from_slice::<StorageStatus>(&body) {
                Ok(s) if s.can_upload => QuotaDecision::Allowed,
                Ok(_) => QuotaDecision::Denied,
                Err(_) => QuotaDecision::SkippedFailOpen(FailOpenReason::Decode),
            }
        }
    }
}

/// The default per-request timeout for the quota pre-check. SHORT on purpose:
/// this is a fail-fast UX optimization, not a required auth step, so it must not
/// eat the write's latency budget. The gateway uses 5s for its own copy; we use a
/// slightly tighter 5s ceiling and fail-open the moment it elapses.
const QUOTA_TIMEOUT: Duration = Duration::from_secs(5);

/// Perform the quota pre-check over HTTP and return the [`QuotaProbe`].
///
/// Builds `GET {storage_api_url}/api/v1/storage` with `Authorization: Bearer
/// {jwt}` and a short timeout, exactly as the gateway's own `check_can_upload`
/// does. Any send/timeout failure becomes [`QuotaProbe::TransportError`]; a
/// completed request becomes [`QuotaProbe::Response`]. This function performs NO
/// policy — it only gathers the probe; [`decide`] owns the fail-open logic.
///
/// `storage_api_url` / `jwt` are passed in (rather than read from a global) so
/// the bundle can supply its private fields without exposing them.
pub async fn check_quota_http(storage_api_url: Option<&str>, jwt: Option<&str>) -> QuotaProbe {
    let base = match storage_api_url {
        Some(u) if !u.is_empty() => u,
        _ => return QuotaProbe::NotConfigured,
    };
    let token = match jwt {
        Some(t) if !t.is_empty() => t,
        _ => return QuotaProbe::NoToken,
    };

    let url = format!("{}/api/v1/storage", base.trim_end_matches('/'));
    let client = match reqwest::Client::builder().timeout(QUOTA_TIMEOUT).build() {
        Ok(c) => c,
        Err(_) => return QuotaProbe::TransportError,
    };

    match client
        .get(&url)
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
    {
        Ok(resp) => {
            let status = resp.status().as_u16();
            // Read the body for 2xx parsing; on a read failure fall back to an
            // empty body, which `decide` treats as a decode failure (fail-open).
            let body = resp.bytes().await.map(|b| b.to_vec()).unwrap_or_default();
            QuotaProbe::Response { status, body }
        }
        Err(_) => QuotaProbe::TransportError,
    }
}

/// Convenience: gather the probe over HTTP and apply [`decide`] in one call.
pub async fn check_quota(storage_api_url: Option<&str>, jwt: Option<&str>) -> QuotaDecision {
    decide(check_quota_http(storage_api_url, jwt).await)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── token bucket: deterministic refill via the manual clock ───────────────

    #[test]
    fn bucket_allows_up_to_capacity_then_denies() {
        // A fresh bucket starts full; capacity writes pass, the next is denied.
        let clock = ManualClock::new();
        // Hold a handle to advance later by building the bucket around a clock we
        // also keep a reference to. We box a clone-free clock by moving a second
        // ManualClock; instead, drive time through the bucket's own clock by
        // constructing the clock here and advancing via a shared Arc-like.
        let bucket = TokenBucket::with_clock(3, 1.0, Box::new(clock));
        assert!(bucket.try_consume(), "1st write within capacity");
        assert!(bucket.try_consume(), "2nd write within capacity");
        assert!(bucket.try_consume(), "3rd write within capacity");
        assert!(!bucket.try_consume(), "4th write over capacity → denied");
    }

    // A clock we can both inject AND advance from the test needs shared
    // ownership. The bucket takes `Box<dyn Clock>`, so we use a small Arc shim
    // that implements Clock by delegating to an inner ManualClock.
    use std::sync::Arc;

    struct SharedClock(Arc<ManualClock>);
    impl Clock for SharedClock {
        fn now(&self) -> Instant {
            self.0.now()
        }
    }

    #[test]
    fn bucket_refills_over_time() {
        let manual = Arc::new(ManualClock::new());
        let bucket = TokenBucket::with_clock(2, 1.0, Box::new(SharedClock(manual.clone())));

        // Drain the bucket.
        assert!(bucket.try_consume());
        assert!(bucket.try_consume());
        assert!(!bucket.try_consume(), "drained → denied");

        // No time has passed → still denied.
        assert!(!bucket.try_consume(), "no refill without time");

        // Advance 1s at 1 token/s → exactly one token back.
        manual.advance(Duration::from_secs(1));
        assert!(bucket.try_consume(), "1s refilled one token");
        assert!(!bucket.try_consume(), "only one token refilled");

        // Advance well beyond capacity → clamps at capacity (not unbounded).
        manual.advance(Duration::from_secs(100));
        assert!(bucket.try_consume(), "refilled token 1 (clamped)");
        assert!(bucket.try_consume(), "refilled token 2 (clamped)");
        assert!(
            !bucket.try_consume(),
            "refill clamps at capacity=2, not 102 tokens"
        );
    }

    #[test]
    fn bucket_capacity_floored_at_one() {
        // A zero capacity is nonsensical for a courtesy limiter; floor at 1 so at
        // least one write can always proceed.
        let bucket = TokenBucket::new(0, 1.0);
        assert_eq!(bucket.capacity(), 1);
        assert!(bucket.try_consume(), "floored capacity still admits one");
        assert!(!bucket.try_consume());
    }

    #[test]
    fn bucket_nonpositive_refill_is_floored() {
        // A non-positive / non-finite refill must not wedge the bucket empty
        // forever; it is floored to the default positive rate.
        let manual = Arc::new(ManualClock::new());
        let bucket = TokenBucket::with_clock(1, 0.0, Box::new(SharedClock(manual.clone())));
        assert!(bucket.try_consume());
        assert!(!bucket.try_consume());
        manual.advance(Duration::from_secs(2));
        assert!(
            bucket.try_consume(),
            "floored refill (DEFAULT rate) replenished after time"
        );
    }

    // ── quota decide(): every fail-open branch + the two real outcomes ────────

    fn body(json: &str) -> Vec<u8> {
        json.as_bytes().to_vec()
    }

    #[test]
    fn decide_allows_on_can_upload_true_camelcase() {
        let d = decide(QuotaProbe::Response {
            status: 200,
            body: body(r#"{"canUpload": true, "balanceFula": 5.0}"#),
        });
        assert_eq!(d, QuotaDecision::Allowed);
        assert!(d.allows());
    }

    #[test]
    fn decide_allows_on_can_upload_true_snakecase_alias() {
        // The serde alias must accept the snake_case spelling too.
        let d = decide(QuotaProbe::Response {
            status: 200,
            body: body(r#"{"can_upload": true}"#),
        });
        assert_eq!(d, QuotaDecision::Allowed);
    }

    #[test]
    fn decide_denies_only_on_explicit_false() {
        let d = decide(QuotaProbe::Response {
            status: 200,
            body: body(r#"{"canUpload": false, "message": "Insufficient credits"}"#),
        });
        assert_eq!(d, QuotaDecision::Denied);
        assert!(!d.allows(), "Denied is the ONLY blocking outcome");
    }

    #[test]
    fn decide_fails_open_on_non_2xx() {
        for status in [401u16, 403, 404, 429, 500, 503] {
            let d = decide(QuotaProbe::Response {
                status,
                body: body(r#"{"canUpload": false}"#), // body irrelevant on non-2xx
            });
            assert_eq!(
                d,
                QuotaDecision::SkippedFailOpen(FailOpenReason::HttpStatus),
                "status {status} must fail-open, never deny"
            );
            assert!(d.allows());
        }
    }

    #[test]
    fn decide_fails_open_on_missing_field_not_false() {
        // CRUX of the fail-open-not-closed design: a 2xx body WITHOUT canUpload
        // (renamed field / wrong endpoint) must FAIL OPEN (decode error), NOT be
        // read as `false`. This is why the field is required, not defaulted.
        let d = decide(QuotaProbe::Response {
            status: 200,
            body: body(r#"{"isSuspended": false, "balanceFula": 1.0}"#),
        });
        assert_eq!(d, QuotaDecision::SkippedFailOpen(FailOpenReason::Decode));
        assert!(d.allows(), "missing field → fail-OPEN, never a silent deny");
    }

    #[test]
    fn decide_fails_open_on_malformed_json() {
        let d = decide(QuotaProbe::Response {
            status: 200,
            body: body("not json at all"),
        });
        assert_eq!(d, QuotaDecision::SkippedFailOpen(FailOpenReason::Decode));
    }

    #[test]
    fn decide_fails_open_on_transport_error() {
        let d = decide(QuotaProbe::TransportError);
        assert_eq!(d, QuotaDecision::SkippedFailOpen(FailOpenReason::Transport));
        assert!(d.allows());
    }

    #[test]
    fn decide_fails_open_when_unconfigured_or_no_token() {
        assert_eq!(
            decide(QuotaProbe::NotConfigured),
            QuotaDecision::SkippedFailOpen(FailOpenReason::NotConfigured)
        );
        assert_eq!(
            decide(QuotaProbe::NoToken),
            QuotaDecision::SkippedFailOpen(FailOpenReason::NoToken)
        );
    }

    #[tokio::test]
    async fn check_quota_unconfigured_url_fails_open_without_network() {
        // No URL → NotConfigured, no network touched (offline-safe).
        let d = check_quota(None, Some("jwt")).await;
        assert_eq!(
            d,
            QuotaDecision::SkippedFailOpen(FailOpenReason::NotConfigured)
        );
        // Empty URL is treated the same.
        let d2 = check_quota(Some(""), Some("jwt")).await;
        assert_eq!(
            d2,
            QuotaDecision::SkippedFailOpen(FailOpenReason::NotConfigured)
        );
    }

    #[tokio::test]
    async fn check_quota_no_token_fails_open_without_network() {
        // URL but no token → NoToken, no network touched.
        let d = check_quota(Some("https://credit.example"), None).await;
        assert_eq!(d, QuotaDecision::SkippedFailOpen(FailOpenReason::NoToken));
        let d2 = check_quota(Some("https://credit.example"), Some("")).await;
        assert_eq!(d2, QuotaDecision::SkippedFailOpen(FailOpenReason::NoToken));
    }

    #[test]
    fn audit_labels_are_bounded_and_secret_free() {
        // Every label is a static string with no placeholder / secret marker.
        for d in [
            QuotaDecision::Allowed,
            QuotaDecision::Denied,
            QuotaDecision::SkippedFailOpen(FailOpenReason::Transport),
        ] {
            let l = d.audit_label();
            assert!(!l.is_empty() && !l.contains('{') && !l.contains("jwt"));
        }
        for r in [
            FailOpenReason::NotConfigured,
            FailOpenReason::NoToken,
            FailOpenReason::Transport,
            FailOpenReason::HttpStatus,
            FailOpenReason::Decode,
        ] {
            assert!(!r.label().is_empty());
        }
    }
}
