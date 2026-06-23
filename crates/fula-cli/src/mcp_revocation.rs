//! MCP-token `jti` revocation deny-list (P12, step 5).
//!
//! A scoped MCP token (`token_use == "mcp_s3"`) is short-lived and STATELESS —
//! the issuer never stores it. The only server-side revocation state is a list
//! of revoked `jti`s (issued by `pinning-webui`'s revoke endpoint, see
//! `mcpTokens.ts::resolveRevocationTarget`). This module mirrors that list into
//! memory and lets the auth path reject a token whose `jti` is on it.
//!
//! It is a deliberate sibling of [`crate::revocation`] (the F3 key deny-list),
//! sharing its shape: an in-memory `HashSet<String>` swapped wholesale by a
//! background refresher, a [`McpRevocationSource`] trait seam so tests inject a
//! mock with no live HTTP, and a fetch source modelled on
//! `pinning.rs::check_can_upload`.
//!
//! ## Fail policy (asymmetric — the key difference from F3)
//! - **Known-revoked jti ⇒ always denied**, for every verb. That's the plain
//!   membership check ([`ensure_jti_not_revoked`]) wired into the middleware;
//!   no action context is needed (a revoked token is revoked for read AND
//!   write).
//! - **Source enabled but UNREACHABLE** ⇒ fail-**CLOSED on writes**, fail-open
//!   on reads. A momentary inability to confirm a token is still valid must not
//!   let a possibly-revoked agent keep WRITING; reads degrade open (consistent
//!   with the rest of the gateway's read-availability bias). This decision is
//!   [`revocation_decision`] — a pure function unit-tested with a mock; the
//!   per-action wiring is deferred to the test-server deploy (see below).
//!
//! ## Default OFF / deferred live polling
//! Gated on `FULA_MCP_REVOCATION_ENABLED` (+ a configured
//! `FULA_MCP_REVOCATION_ENDPOINT`). When off, [`ensure_jti_not_revoked`] is a
//! no-op and auth is byte-identical to pre-P12. The background HTTP poller
//! ([`spawn_if_enabled`]) is implemented but defaults OFF; turning it on (and
//! wiring the per-action unreachable-fail-closed-on-write path into handlers)
//! is deferred to the test-server deploy — the SCOPE enforcement (steps 1-4) is
//! the must-have and does not depend on it.
//!
//! Match key: the token's `jti` claim verbatim (the issuer's `jti` is a uuid v4
//! string; compared as-is, never normalized).

use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tracing::{debug, info, warn};

use crate::state::AppState;
use crate::{ApiError, S3ErrorCode};

/// Observability counters (jti deny-list).
pub static MCP_REVOCATION_DENIED_TOTAL: AtomicU64 = AtomicU64::new(0);
pub static MCP_REVOCATION_REFRESH_OK: AtomicU64 = AtomicU64::new(0);
pub static MCP_REVOCATION_REFRESH_FAIL: AtomicU64 = AtomicU64::new(0);

/// Observability counters (L1b connection deny-list — sibling of the jti
/// counters above, keyed on the connection pubkey instead of the jti).
pub static MCP_CONNECTION_REVOCATION_DENIED_TOTAL: AtomicU64 = AtomicU64::new(0);
pub static MCP_CONNECTION_REVOCATION_REFRESH_OK: AtomicU64 = AtomicU64::new(0);
pub static MCP_CONNECTION_REVOCATION_REFRESH_FAIL: AtomicU64 = AtomicU64::new(0);

/// `true` when the env master switch is set (`1`/`true`). The feature is only
/// actually live when this AND an endpoint are both present (see [`enabled`]).
pub fn env_enabled() -> bool {
    std::env::var("FULA_MCP_REVOCATION_ENABLED")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// The configured revocation endpoint (`FULA_MCP_REVOCATION_ENDPOINT`), if any.
pub fn endpoint() -> Option<String> {
    std::env::var("FULA_MCP_REVOCATION_ENDPOINT")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Is the MCP jti deny-list live? Requires the env switch AND an endpoint. When
/// `false`, [`ensure_jti_not_revoked`] is a no-op.
pub fn enabled() -> bool {
    env_enabled() && endpoint().is_some()
}

/// In-memory revoked-jti set, swapped wholesale by the background refresher.
/// Same swap-on-tick idiom as [`crate::revocation::RevocationState`].
pub struct McpRevocationState {
    set: parking_lot::RwLock<Arc<HashSet<String>>>,
}

impl Default for McpRevocationState {
    fn default() -> Self {
        Self::empty()
    }
}

impl McpRevocationState {
    /// An empty deny-list = allow everything (the safe startup state).
    pub fn empty() -> Self {
        Self {
            set: parking_lot::RwLock::new(Arc::new(HashSet::new())),
        }
    }

    /// Replace the deny-list with a freshly-loaded set.
    pub fn swap(&self, new: HashSet<String>) {
        *self.set.write() = Arc::new(new);
    }

    /// Is this `jti` explicitly revoked?
    pub fn is_revoked(&self, jti: &str) -> bool {
        let snapshot = { self.set.read().clone() };
        snapshot.contains(jti)
    }

    /// Current deny-list size (monitoring).
    pub fn len(&self) -> usize {
        self.set.read().len()
    }

    /// Companion to `len` for clippy; empty = allow-all.
    pub fn is_empty(&self) -> bool {
        self.set.read().is_empty()
    }
}

/// Plain membership deny — reject a token whose `jti` is on the deny-list.
/// `None` state (feature off) → always `Ok`. `None` jti (token has no jti) →
/// `Ok` (a token without a jti can't be on the list; storage tokens have none).
/// Decoupled from `AppState` so it's directly unit-testable. This is the
/// every-verb check wired into the middleware; the unreachable-source
/// fail-closed-on-write nuance is [`revocation_decision`] (deferred wiring).
pub fn ensure_jti_not_revoked(
    revocation: Option<&McpRevocationState>,
    jti: Option<&str>,
) -> Result<(), ApiError> {
    match (revocation, jti) {
        (Some(rev), Some(jti)) if rev.is_revoked(jti) => {
            MCP_REVOCATION_DENIED_TOTAL.fetch_add(1, Ordering::Relaxed);
            Err(ApiError::s3(
                S3ErrorCode::InvalidToken,
                "MCP token has been revoked",
            ))
        }
        _ => Ok(()),
    }
}

/// The intended S3 action class for the asymmetric (read vs write) fail policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationAction {
    Read,
    Write,
}

/// Liveness of the deny-list when a request is being decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceHealth {
    /// Feature off — no MCP revocation in play.
    Disabled,
    /// Enabled and the in-memory set is fresh (a refresh has succeeded).
    Fresh,
    /// Enabled but the source could not be reached / has never loaded.
    Unreachable,
}

/// The decision a request should get, BEFORE the plain membership check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationDecision {
    /// Proceed to the membership check (and then normal handling).
    Allow,
    /// Deny now — the source is enabled-but-unreachable and this is a write, so
    /// we fail closed rather than risk honoring a possibly-revoked token.
    DenyFailClosed,
}

/// Pure decision function for the enabled-but-unreachable case (P12 step 5).
///
/// - `Disabled`            ⇒ `Allow` (feature off).
/// - `Fresh`               ⇒ `Allow` (membership check is authoritative).
/// - `Unreachable` + Read  ⇒ `Allow` (reads degrade open).
/// - `Unreachable` + Write ⇒ `DenyFailClosed` (writes fail closed).
///
/// Unit-tested with a mock; the per-action wiring into handlers is deferred to
/// the test-server deploy (live HTTP polling defaults OFF).
pub fn revocation_decision(health: SourceHealth, action: RevocationAction) -> RevocationDecision {
    match (health, action) {
        (SourceHealth::Disabled, _) => RevocationDecision::Allow,
        (SourceHealth::Fresh, _) => RevocationDecision::Allow,
        (SourceHealth::Unreachable, RevocationAction::Read) => RevocationDecision::Allow,
        (SourceHealth::Unreachable, RevocationAction::Write) => RevocationDecision::DenyFailClosed,
    }
}

/// Where the revoked-jti set comes from. `Err` ⇒ keep the previous set (never
/// wipe on a transient failure). The trait seam lets tests inject an in-memory
/// source with no HTTP.
#[async_trait::async_trait]
pub trait McpRevocationSource: Send + Sync {
    async fn revoked_jtis(&self) -> anyhow::Result<HashSet<String>>;
}

/// Shape of the revoke endpoint's JSON body. Tolerant: only the `jtis` array is
/// read; any other fields are ignored.
#[derive(Debug, serde::Deserialize)]
struct RevokedJtisBody {
    #[serde(default)]
    jtis: Vec<String>,
}

/// Production source: an HTTP `GET {endpoint}` returning the revoked-jti list.
/// Modelled on `pinning.rs::check_can_upload` (short timeout, JSON body).
pub struct HttpMcpRevocationSource {
    endpoint: String,
    client: reqwest::Client,
}

impl HttpMcpRevocationSource {
    pub fn new(endpoint: String) -> Self {
        Self {
            endpoint,
            client: reqwest::Client::new(),
        }
    }
}

#[async_trait::async_trait]
impl McpRevocationSource for HttpMcpRevocationSource {
    async fn revoked_jtis(&self) -> anyhow::Result<HashSet<String>> {
        let resp = self
            .client
            .get(&self.endpoint)
            .timeout(Duration::from_secs(5))
            .send()
            .await?;
        if !resp.status().is_success() {
            anyhow::bail!("mcp revocation endpoint returned {}", resp.status());
        }
        let body: RevokedJtisBody = resp.json().await?;
        Ok(body.jtis.into_iter().filter(|s| !s.is_empty()).collect())
    }
}

/// One refresh: swap on success, keep the previous set on error.
async fn refresh_once(src: &dyn McpRevocationSource, state: &McpRevocationState) {
    match src.revoked_jtis().await {
        Ok(set) => {
            let n = set.len();
            state.swap(set);
            MCP_REVOCATION_REFRESH_OK.fetch_add(1, Ordering::Relaxed);
            debug!(revoked = n, "mcp revocation deny-list refreshed");
        }
        Err(e) => {
            MCP_REVOCATION_REFRESH_FAIL.fetch_add(1, Ordering::Relaxed);
            warn!(error = %e, "mcp revocation deny-list refresh failed; keeping previous set");
        }
    }
}

/// Background loop: reload the deny-list every `interval`.
pub async fn run_refresh_loop(
    src: Arc<dyn McpRevocationSource>,
    state: Arc<McpRevocationState>,
    interval: Duration,
) {
    info!(
        interval_secs = interval.as_secs(),
        "mcp revocation deny-list refresher running"
    );
    loop {
        refresh_once(src.as_ref(), &state).await;
        tokio::time::sleep(interval).await;
    }
}

/// Spawn the refresh loop iff the feature is enabled. Safe no-op otherwise.
/// NOTE: live polling defaults OFF; flipping it on is deferred to the
/// test-server deploy.
pub fn spawn_if_enabled(state: &Arc<AppState>) {
    if !enabled() {
        return;
    }
    let Some(rev) = state.mcp_revocation.clone() else {
        return;
    };
    let Some(ep) = endpoint() else {
        return;
    };
    let interval = Duration::from_secs(
        std::env::var("FULA_MCP_REVOCATION_REFRESH_SECS")
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .unwrap_or(30)
            .max(5),
    );
    let src: Arc<dyn McpRevocationSource> = Arc::new(HttpMcpRevocationSource::new(ep));
    tokio::spawn(async move {
        run_refresh_loop(src, rev, interval).await;
    });
    info!("✓ MCP revocation deny-list refresher started (honors jti revocation)");
}

// ═══════════════════════════════════════════════════════════════════════════
// L1b — CONNECTION-LEVEL revocation deny-list (sibling of the jti deny-list)
// ═══════════════════════════════════════════════════════════════════════════
//
// A connection-bound MCP token carries a `cnf.mcp_pub_b64` claim (the MCP
// connection's X25519 public key, base64). pinning-webui can revoke a whole
// CONNECTION (independent of any individual token's jti) by publishing its
// pubkey on a "revoked connections" feed. This block mirrors the jti seam
// above EXACTLY — same swap-on-tick in-memory `HashSet<String>`, same trait
// seam for tests, same FAIL-OPEN refresh (keep the previous set on error) —
// but is keyed on the connection pubkey and parses `{ revoked_pubkeys: [...] }`.
//
// Fail policy: PLAIN MEMBERSHIP only (a known-revoked pubkey is denied for
// every verb) and FAIL-OPEN on a source outage (an unreachable endpoint keeps
// the previous set; it never wipes revocations and never locks connections
// out). This deliberately does NOT carry the jti seam's deferred
// `revocation_decision`/`SourceHealth` asymmetric-write scaffolding — that was
// never wired into the middleware and L1b's contract is plain fail-open.
//
// Default OFF: gated on `FULA_MCP_CONNECTION_REVOCATION_ENABLED` +
// `FULA_MCP_CONNECTION_REVOCATION_ENDPOINT`. When off, the AppState field is
// `None` and [`ensure_connection_not_revoked`] is a no-op — auth is
// byte-identical to pre-L1b.

/// `true` when the connection-revocation master switch is set (`1`/`true`).
/// Live only when this AND an endpoint are both present (see [`connection_enabled`]).
pub fn connection_env_enabled() -> bool {
    std::env::var("FULA_MCP_CONNECTION_REVOCATION_ENABLED")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// The configured connection-revocation endpoint
/// (`FULA_MCP_CONNECTION_REVOCATION_ENDPOINT`), if any.
pub fn connection_endpoint() -> Option<String> {
    std::env::var("FULA_MCP_CONNECTION_REVOCATION_ENDPOINT")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Is the connection deny-list live? Requires the env switch AND an endpoint.
/// When `false`, [`ensure_connection_not_revoked`] is a no-op.
pub fn connection_enabled() -> bool {
    connection_env_enabled() && connection_endpoint().is_some()
}

/// In-memory revoked-connection-pubkey set, swapped wholesale by the background
/// refresher. Same swap-on-tick idiom as [`McpRevocationState`].
pub struct McpConnectionRevocationState {
    set: parking_lot::RwLock<Arc<HashSet<String>>>,
}

impl Default for McpConnectionRevocationState {
    fn default() -> Self {
        Self::empty()
    }
}

impl McpConnectionRevocationState {
    /// An empty deny-list = allow every connection (the safe startup state).
    pub fn empty() -> Self {
        Self {
            set: parking_lot::RwLock::new(Arc::new(HashSet::new())),
        }
    }

    /// Replace the deny-list with a freshly-loaded set.
    pub fn swap(&self, new: HashSet<String>) {
        *self.set.write() = Arc::new(new);
    }

    /// Is this connection pubkey explicitly revoked? Compared verbatim — the
    /// issuer normalizes the pubkey on both mint and verify, so the token's
    /// `cnf.mcp_pub_b64` and the feed's entries are already canonical.
    pub fn is_revoked(&self, pubkey: &str) -> bool {
        let snapshot = { self.set.read().clone() };
        snapshot.contains(pubkey)
    }

    /// Current deny-list size (monitoring).
    pub fn len(&self) -> usize {
        self.set.read().len()
    }

    /// Companion to `len` for clippy; empty = allow-all.
    pub fn is_empty(&self) -> bool {
        self.set.read().is_empty()
    }
}

/// Plain membership deny — reject a token whose connection pubkey is on the
/// deny-list. `None` state (feature off) → always `Ok`. `None` pubkey (token
/// has no `cnf` — every storage token and unbound MCP token) → `Ok`. This is
/// the non-MCP-token invariant: a token without a connection binding can never
/// be on the connection deny-list, so it is never denied here regardless of how
/// large the revoked set is. Decoupled from `AppState` so it is directly
/// unit-testable. Mirrors [`ensure_jti_not_revoked`].
pub fn ensure_connection_not_revoked(
    revocation: Option<&McpConnectionRevocationState>,
    pubkey: Option<&str>,
) -> Result<(), ApiError> {
    match (revocation, pubkey) {
        (Some(rev), Some(pubkey)) if rev.is_revoked(pubkey) => {
            MCP_CONNECTION_REVOCATION_DENIED_TOTAL.fetch_add(1, Ordering::Relaxed);
            Err(ApiError::s3(
                S3ErrorCode::InvalidToken,
                "Connection has been revoked",
            ))
        }
        _ => Ok(()),
    }
}

/// Where the revoked-connection-pubkey set comes from. `Err` ⇒ keep the
/// previous set (never wipe on a transient failure). The trait seam lets tests
/// inject an in-memory source with no HTTP. Mirrors [`McpRevocationSource`].
#[async_trait::async_trait]
pub trait McpConnectionRevocationSource: Send + Sync {
    async fn revoked_pubkeys(&self) -> anyhow::Result<HashSet<String>>;
}

/// Shape of the revoked-connections feed's JSON body. Tolerant: only the
/// `revoked_pubkeys` array is read; any other fields are ignored.
#[derive(Debug, serde::Deserialize)]
struct RevokedPubkeysBody {
    #[serde(default)]
    revoked_pubkeys: Vec<String>,
}

/// Production source: an HTTP `GET {endpoint}` returning the revoked-connection
/// pubkey list. Mirrors [`HttpMcpRevocationSource`] but additionally sends an
/// `Authorization: Bearer {FULA_MCP_REVOCATION_INTERNAL_TOKEN}` header when that
/// (jti-family) internal token is configured, so the feed can be auth-gated.
pub struct HttpConnectionRevocationSource {
    endpoint: String,
    internal_token: Option<String>,
    client: reqwest::Client,
}

impl HttpConnectionRevocationSource {
    pub fn new(endpoint: String) -> Self {
        let internal_token = std::env::var("FULA_MCP_REVOCATION_INTERNAL_TOKEN")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        Self {
            endpoint,
            internal_token,
            client: reqwest::Client::new(),
        }
    }
}

#[async_trait::async_trait]
impl McpConnectionRevocationSource for HttpConnectionRevocationSource {
    async fn revoked_pubkeys(&self) -> anyhow::Result<HashSet<String>> {
        let mut req = self
            .client
            .get(&self.endpoint)
            .timeout(Duration::from_secs(5));
        if let Some(token) = &self.internal_token {
            req = req.bearer_auth(token);
        }
        let resp = req.send().await?;
        if !resp.status().is_success() {
            anyhow::bail!(
                "mcp connection revocation endpoint returned {}",
                resp.status()
            );
        }
        let body: RevokedPubkeysBody = resp.json().await?;
        Ok(body
            .revoked_pubkeys
            .into_iter()
            .filter(|s| !s.is_empty())
            .collect())
    }
}

/// One refresh: swap on success, keep the previous set on error (fail-open).
async fn refresh_connections_once(
    src: &dyn McpConnectionRevocationSource,
    state: &McpConnectionRevocationState,
) {
    match src.revoked_pubkeys().await {
        Ok(set) => {
            let n = set.len();
            state.swap(set);
            MCP_CONNECTION_REVOCATION_REFRESH_OK.fetch_add(1, Ordering::Relaxed);
            debug!(revoked = n, "mcp connection revocation deny-list refreshed");
        }
        Err(e) => {
            MCP_CONNECTION_REVOCATION_REFRESH_FAIL.fetch_add(1, Ordering::Relaxed);
            warn!(error = %e, "mcp connection revocation deny-list refresh failed; keeping previous set");
        }
    }
}

/// Background loop: reload the connection deny-list every `interval`.
pub async fn run_connection_refresh_loop(
    src: Arc<dyn McpConnectionRevocationSource>,
    state: Arc<McpConnectionRevocationState>,
    interval: Duration,
) {
    info!(
        interval_secs = interval.as_secs(),
        "mcp connection revocation deny-list refresher running"
    );
    loop {
        refresh_connections_once(src.as_ref(), &state).await;
        tokio::time::sleep(interval).await;
    }
}

/// Spawn the connection-revocation refresh loop iff the feature is enabled.
/// Safe no-op otherwise. Mirrors [`spawn_if_enabled`]; live polling defaults
/// OFF (gated on the L1b env switch + endpoint).
pub fn spawn_if_enabled_connections(state: &Arc<AppState>) {
    if !connection_enabled() {
        return;
    }
    let Some(rev) = state.mcp_connection_revocation.clone() else {
        return;
    };
    let Some(ep) = connection_endpoint() else {
        return;
    };
    let interval = Duration::from_secs(
        std::env::var("FULA_MCP_CONNECTION_REVOCATION_REFRESH_SECS")
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .unwrap_or(30)
            .max(5),
    );
    let src: Arc<dyn McpConnectionRevocationSource> =
        Arc::new(HttpConnectionRevocationSource::new(ep));
    tokio::spawn(async move {
        run_connection_refresh_loop(src, rev, interval).await;
    });
    info!("✓ MCP connection revocation deny-list refresher started (honors connection revocation)");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_denylist_allows_everything() {
        let st = McpRevocationState::empty();
        assert!(!st.is_revoked("any-jti"));
        assert!(st.is_empty());
    }

    #[test]
    fn revoked_jti_detected_others_allowed() {
        let st = McpRevocationState::empty();
        let mut set = HashSet::new();
        set.insert("revoked-jti-123".to_string());
        st.swap(set);
        assert!(st.is_revoked("revoked-jti-123"));
        assert!(!st.is_revoked("other-jti"));
    }

    #[test]
    fn ensure_none_source_is_always_ok() {
        // Feature off → every token passes.
        assert!(ensure_jti_not_revoked(None, Some("anything")).is_ok());
        assert!(ensure_jti_not_revoked(None, None).is_ok());
    }

    #[test]
    fn ensure_denies_only_revoked_jti() {
        let st = McpRevocationState::empty();
        let mut set = HashSet::new();
        set.insert("bad-jti".to_string());
        st.swap(set);
        // A token with no jti can't be on the list.
        assert!(ensure_jti_not_revoked(Some(&st), None).is_ok());
        // A valid jti passes; the revoked one is denied.
        assert!(ensure_jti_not_revoked(Some(&st), Some("good-jti")).is_ok());
        assert!(ensure_jti_not_revoked(Some(&st), Some("bad-jti")).is_err());
    }

    #[test]
    fn decision_disabled_always_allows() {
        assert_eq!(
            revocation_decision(SourceHealth::Disabled, RevocationAction::Write),
            RevocationDecision::Allow
        );
        assert_eq!(
            revocation_decision(SourceHealth::Disabled, RevocationAction::Read),
            RevocationDecision::Allow
        );
    }

    #[test]
    fn decision_fresh_always_allows() {
        // When fresh, the membership check is authoritative; this gate allows.
        assert_eq!(
            revocation_decision(SourceHealth::Fresh, RevocationAction::Write),
            RevocationDecision::Allow
        );
        assert_eq!(
            revocation_decision(SourceHealth::Fresh, RevocationAction::Read),
            RevocationDecision::Allow
        );
    }

    #[test]
    fn decision_unreachable_fails_closed_on_write_open_on_read() {
        // The asymmetric policy: a write under an unreachable source is denied;
        // a read degrades open.
        assert_eq!(
            revocation_decision(SourceHealth::Unreachable, RevocationAction::Write),
            RevocationDecision::DenyFailClosed
        );
        assert_eq!(
            revocation_decision(SourceHealth::Unreachable, RevocationAction::Read),
            RevocationDecision::Allow
        );
    }

    // ── Mock source: refresh loads then keeps previous set on error ──────────
    struct StaticSource(HashSet<String>);
    #[async_trait::async_trait]
    impl McpRevocationSource for StaticSource {
        async fn revoked_jtis(&self) -> anyhow::Result<HashSet<String>> {
            Ok(self.0.clone())
        }
    }

    struct FailingSource;
    #[async_trait::async_trait]
    impl McpRevocationSource for FailingSource {
        async fn revoked_jtis(&self) -> anyhow::Result<HashSet<String>> {
            anyhow::bail!("simulated source failure")
        }
    }

    #[tokio::test]
    async fn refresh_loads_then_keeps_previous_on_error() {
        let st = McpRevocationState::empty();
        let mut set = HashSet::new();
        set.insert("jti-to-revoke".to_string());

        refresh_once(&StaticSource(set), &st).await;
        assert!(st.is_revoked("jti-to-revoke"));

        // A failing refresh must NOT wipe the deny-list.
        refresh_once(&FailingSource, &st).await;
        assert!(st.is_revoked("jti-to-revoke"));
    }

    #[tokio::test]
    async fn refresh_can_clear_a_jti_when_unrevoked() {
        let st = McpRevocationState::empty();
        let mut set = HashSet::new();
        set.insert("jti".to_string());
        refresh_once(&StaticSource(set), &st).await;
        assert!(st.is_revoked("jti"));
        refresh_once(&StaticSource(HashSet::new()), &st).await;
        assert!(!st.is_revoked("jti"));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // L1b — CONNECTION-LEVEL revocation tests (mirror the jti tests above).
    //
    // Pure-function + mock-source only: NO `std::env::set_var` and NO asserts on
    // the global `AtomicU64` counters, both of which are process-global and race
    // at default test parallelism (a flaky global-state test was caught that way
    // before). The `is_revoked`/`ensure_*`/refresh logic is fully exercisable
    // without touching env or the network.
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn connection_empty_denylist_allows_everything() {
        let st = McpConnectionRevocationState::empty();
        assert!(!st.is_revoked("any-pubkey"));
        assert!(st.is_empty());
    }

    #[test]
    fn connection_revoked_pubkey_detected_others_allowed() {
        let st = McpConnectionRevocationState::empty();
        let mut set = HashSet::new();
        set.insert("revoked-pubkey-AAA".to_string());
        st.swap(set);
        assert!(st.is_revoked("revoked-pubkey-AAA"));
        assert!(!st.is_revoked("other-pubkey"));
    }

    #[test]
    fn ensure_connection_none_source_is_always_ok() {
        // Feature off (None state) → every token passes, with or without a pubkey.
        assert!(ensure_connection_not_revoked(None, Some("anything")).is_ok());
        assert!(ensure_connection_not_revoked(None, None).is_ok());
    }

    #[test]
    fn ensure_connection_denies_only_revoked_pubkey() {
        let st = McpConnectionRevocationState::empty();
        let mut set = HashSet::new();
        set.insert("bad-pubkey".to_string());
        st.swap(set);
        // A token with no cnf (storage token / unbound MCP token) can't be on the
        // list → allowed. THIS IS THE NON-MCP-TOKEN INVARIANT.
        assert!(ensure_connection_not_revoked(Some(&st), None).is_ok());
        // A bound token with a non-revoked pubkey passes; the revoked one denies.
        assert!(ensure_connection_not_revoked(Some(&st), Some("good-pubkey")).is_ok());
        let err = ensure_connection_not_revoked(Some(&st), Some("bad-pubkey"))
            .expect_err("a revoked connection pubkey must be denied");
        // Surfaces as an InvalidToken (mirrors the jti deny).
        assert!(matches!(err.error_code(), S3ErrorCode::InvalidToken));
    }

    #[test]
    fn ensure_connection_non_mcp_token_unaffected_even_with_huge_revoked_set() {
        // Hardened restatement of the invariant: even with a large revoked set,
        // a token that carries NO cnf (pubkey == None) is NEVER denied.
        let st = McpConnectionRevocationState::empty();
        let set: HashSet<String> = (0..10_000).map(|i| format!("revoked-{i}")).collect();
        st.swap(set);
        assert!(
            ensure_connection_not_revoked(Some(&st), None).is_ok(),
            "a storage token (no cnf → no pubkey) must never be denied"
        );
    }

    #[test]
    fn connection_body_parses_revoked_pubkeys_array() {
        // The feed contract: `{ "revoked_pubkeys": [...] }`. Parsed directly
        // (no network), mirroring how the jti side avoids real HTTP.
        let json = r#"{ "revoked_pubkeys": ["pk-1", "pk-2", "pk-3"] }"#;
        let body: RevokedPubkeysBody = serde_json::from_str(json).expect("body parses");
        assert_eq!(body.revoked_pubkeys.len(), 3);
        assert!(body.revoked_pubkeys.contains(&"pk-2".to_string()));

        // Tolerant: extra fields ignored, missing array defaults to empty.
        let extra = r#"{ "revoked_pubkeys": ["pk-1"], "generated_at": 123, "note": "x" }"#;
        let body: RevokedPubkeysBody = serde_json::from_str(extra).expect("tolerant parse");
        assert_eq!(body.revoked_pubkeys, vec!["pk-1".to_string()]);
        let empty: RevokedPubkeysBody = serde_json::from_str("{}").expect("absent array → empty");
        assert!(empty.revoked_pubkeys.is_empty());
    }

    // ── Mock source: refresh loads then keeps previous set on error ──────────
    struct StaticConnectionSource(HashSet<String>);
    #[async_trait::async_trait]
    impl McpConnectionRevocationSource for StaticConnectionSource {
        async fn revoked_pubkeys(&self) -> anyhow::Result<HashSet<String>> {
            Ok(self.0.clone())
        }
    }

    struct FailingConnectionSource;
    #[async_trait::async_trait]
    impl McpConnectionRevocationSource for FailingConnectionSource {
        async fn revoked_pubkeys(&self) -> anyhow::Result<HashSet<String>> {
            anyhow::bail!("simulated connection source failure")
        }
    }

    #[tokio::test]
    async fn connection_refresh_loads_then_keeps_previous_on_error() {
        // FAIL-OPEN: a failing refresh must NOT wipe the deny-list.
        let st = McpConnectionRevocationState::empty();
        let mut set = HashSet::new();
        set.insert("pubkey-to-revoke".to_string());

        refresh_connections_once(&StaticConnectionSource(set), &st).await;
        assert!(st.is_revoked("pubkey-to-revoke"));

        refresh_connections_once(&FailingConnectionSource, &st).await;
        assert!(
            st.is_revoked("pubkey-to-revoke"),
            "a fetch error must keep the previous revoked set (fail-open)"
        );
    }

    #[tokio::test]
    async fn connection_refresh_can_clear_a_pubkey_when_unrevoked() {
        let st = McpConnectionRevocationState::empty();
        let mut set = HashSet::new();
        set.insert("pubkey".to_string());
        refresh_connections_once(&StaticConnectionSource(set), &st).await;
        assert!(st.is_revoked("pubkey"));
        refresh_connections_once(&StaticConnectionSource(HashSet::new()), &st).await;
        assert!(!st.is_revoked("pubkey"));
    }
}
