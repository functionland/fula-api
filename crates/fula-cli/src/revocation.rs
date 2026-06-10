//! JWT revocation deny-list for the auth path (audit finding F3).
//!
//! `fula-api` validates JWTs cryptographically only; it never consulted the
//! issuer's key store, so a key the user MANUALLY revoked in the WebUI
//! (`api_keys.is_deleted = 1`) kept working at this gateway forever. JWTs
//! intentionally carry no `exp` — revocation is by manual key deletion — so the
//! ONLY way to honor a revoke here is to check the issuer's deny flag. This
//! module does exactly that, and nothing else (no expiry, no token lifetime
//! changes).
//!
//! It mirrors the set of explicitly-revoked key hashes
//! (`SELECT key_hash FROM api_keys WHERE is_deleted = 1`) into memory on a
//! background timer, and `auth_middleware` rejects a token whose
//! `sha256_hex(raw_jwt)` is in that set.
//!
//! Design properties — chosen to honor the hard constraint "never lock out a
//! valid user, never lose access":
//! - **Deny-list, not allow-list.** A token is rejected ONLY if its hash is an
//!   explicit `is_deleted = 1` row. Anything not in the set — a currently-valid
//!   token, a legacy token, a token from any other issuer — is ALWAYS allowed.
//!   A valid user can never be wrongly locked out.
//! - **Fail-open.** Before the first refresh, on a refresh error, or when the
//!   pins DB is unreachable, the set is empty/stale → allow-all → byte-identical
//!   to today. A DB outage never denies anyone.
//! - **Default OFF.** Gated on `FULA_REVOCATION_CHECK_ENABLED` AND a configured
//!   pins DB. When off, `ensure_not_revoked` is a no-op.
//! - **No per-request DB hit.** The check is an in-memory `HashSet` lookup; the
//!   DB is read once per refresh interval on the existing read-only pins pool,
//!   so the forest-walk burst path (hundreds–thousands of GETs/sec) is unaffected.
//!
//! Match key: lowercase hex SHA-256 of the FULL JWT string, matching the
//! issuer's `hashToken` (`pinning-webui/server/database/postgres.ts`:
//! `createHash('sha256').update(token).digest('hex')`) and the
//! `api_keys.key_hash` column. The token is hashed exactly as received — never
//! trimmed, normalized, or re-cased.
//!
//! Env knobs:
//! | Var                              | Default | Meaning                                         |
//! |----------------------------------|---------|-------------------------------------------------|
//! | `FULA_REVOCATION_CHECK_ENABLED`  | `false` | Master switch (also needs a pins DB configured) |
//! | `FULA_REVOCATION_REFRESH_SECS`   | `30`    | Deny-list reload interval (floored at 5)        |
//! | `FULA_REVOCATION_WINDOW_DAYS`    | `0`     | `0` = load ALL revoked hashes; N = only revoked in the last N days |

use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use sqlx::{PgPool, Row};
use tracing::{debug, info, warn};

use crate::state::AppState;
use crate::{ApiError, S3ErrorCode};

/// Observability counters (read via logs / a future metrics endpoint).
pub static REVOCATION_DENIED_TOTAL: AtomicU64 = AtomicU64::new(0);
pub static REVOCATION_REFRESH_OK: AtomicU64 = AtomicU64::new(0);
pub static REVOCATION_REFRESH_FAIL: AtomicU64 = AtomicU64::new(0);

/// `true` when the env master switch is set (`1`/`true`). The feature is only
/// actually live when this AND a pins DB are both present (see [`enabled`]).
pub fn env_enabled() -> bool {
    std::env::var("FULA_REVOCATION_CHECK_ENABLED")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// Is the revocation deny-list live? Requires the env switch AND a pins DB pool
/// (the same read-only pool the GC-recovery endpoints use). When `false`,
/// `ensure_not_revoked` is a no-op and auth behaves byte-identically to before.
pub fn enabled(state: &AppState) -> bool {
    env_enabled() && state.pins_db.is_some()
}

/// Lowercase hex SHA-256 of the raw token, matching the issuer's `key_hash`.
fn sha256_hex(token: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

/// In-memory revoked-hash set, swapped wholesale by the background refresher.
/// `parking_lot::RwLock<Arc<…>>` mirrors the swap-on-tick idiom already used by
/// the users-index publisher: the request path takes a cheap read lock to
/// `contains`, the refresher takes one write lock per interval to swap a fresh
/// `Arc`.
pub struct RevocationState {
    set: parking_lot::RwLock<Arc<HashSet<String>>>,
}

impl RevocationState {
    /// An empty deny-list = allow everything (the safe startup state, before the
    /// first refresh has run).
    pub fn empty() -> Self {
        Self {
            set: parking_lot::RwLock::new(Arc::new(HashSet::new())),
        }
    }

    /// Replace the deny-list with a freshly-loaded set.
    pub fn swap(&self, new: HashSet<String>) {
        *self.set.write() = Arc::new(new);
    }

    /// Is this raw JWT explicitly revoked? Snapshots the `Arc` under the read
    /// lock and drops the guard immediately, so the critical section is just a
    /// pointer clone — the hash + membership test run lock-free on the snapshot.
    pub fn is_revoked(&self, token: &str) -> bool {
        let snapshot = { self.set.read().clone() };
        let h = sha256_hex(token);
        snapshot.contains(&h)
    }

    /// Current deny-list size (monitoring).
    pub fn len(&self) -> usize {
        self.set.read().len()
    }

    /// Required companion to `len` for clippy; an empty deny-list = allow-all.
    pub fn is_empty(&self) -> bool {
        self.set.read().is_empty()
    }
}

/// Reject `token` only if the deny-list is present AND the token is in it.
/// `None` (feature off) → always `Ok`. Decoupled from `AppState` so it is
/// directly unit-testable.
pub fn ensure_not_revoked(
    revocation: Option<&RevocationState>,
    token: &str,
) -> Result<(), ApiError> {
    match revocation {
        None => Ok(()),
        Some(rev) => {
            if rev.is_revoked(token) {
                REVOCATION_DENIED_TOTAL.fetch_add(1, Ordering::Relaxed);
                Err(ApiError::s3(
                    S3ErrorCode::InvalidToken,
                    "Token has been revoked",
                ))
            } else {
                Ok(())
            }
        }
    }
}

/// Where the revoked-hash set comes from. `Err` => keep the previous set (never
/// wipe the deny-list on a transient failure). The trait seam lets tests inject
/// an in-memory source with no database.
#[async_trait::async_trait]
pub trait RevocationSource: Send + Sync {
    async fn revoked_hashes(&self) -> anyhow::Result<HashSet<String>>;
}

/// Production source: the shared pinning Postgres `api_keys` table. `key_hash`
/// is the issuer's lowercase-hex SHA-256 of the JWT; `is_deleted = 1` marks a
/// manually-revoked key (schema: `migrations/postgres/001_initial_schema.sql`
/// + `013_api_key_hash.sql`).
pub struct PgRevocationSource {
    pool: PgPool,
    /// `0` = load every revoked hash; `N` = only keys revoked in the last N days.
    window_days: u64,
}

impl PgRevocationSource {
    pub fn new(pool: PgPool, window_days: u64) -> Self {
        Self { pool, window_days }
    }
}

#[async_trait::async_trait]
impl RevocationSource for PgRevocationSource {
    async fn revoked_hashes(&self) -> anyhow::Result<HashSet<String>> {
        // `key_hash IS NOT NULL` skips genuinely-legacy rows whose hash basis
        // differs from sha256(full_jwt) — deny-list-safe: such a key simply
        // isn't denied (never a valid key wrongly denied).
        let rows = if self.window_days == 0 {
            sqlx::query(
                "SELECT key_hash FROM api_keys WHERE is_deleted = 1 AND key_hash IS NOT NULL",
            )
            .fetch_all(&self.pool)
            .await?
        } else {
            sqlx::query(
                "SELECT key_hash FROM api_keys \
                 WHERE is_deleted = 1 AND key_hash IS NOT NULL \
                 AND deleted_at > now() - make_interval(days => $1)",
            )
            .bind(self.window_days as i32)
            .fetch_all(&self.pool)
            .await?
        };
        let mut set = HashSet::with_capacity(rows.len());
        for row in rows {
            if let Ok(h) = row.try_get::<String, _>("key_hash") {
                if !h.is_empty() {
                    // Stored lowercase by the issuer; lowercase defensively so a
                    // mixed-case row can never silently fail to match.
                    set.insert(h.to_lowercase());
                }
            }
        }
        Ok(set)
    }
}

/// One refresh: swap on success, keep the previous set on error.
async fn refresh_once(src: &dyn RevocationSource, state: &RevocationState) {
    match src.revoked_hashes().await {
        Ok(set) => {
            let n = set.len();
            state.swap(set);
            REVOCATION_REFRESH_OK.fetch_add(1, Ordering::Relaxed);
            debug!(revoked = n, "revocation deny-list refreshed");
        }
        Err(e) => {
            REVOCATION_REFRESH_FAIL.fetch_add(1, Ordering::Relaxed);
            warn!(error = %e, "revocation deny-list refresh failed; keeping previous set (fail-open)");
        }
    }
}

/// Background loop: reload the deny-list every `interval`. Best-effort; a failed
/// cycle logs and retries next tick without disturbing the in-memory set.
pub async fn run_refresh_loop(
    src: Arc<dyn RevocationSource>,
    state: Arc<RevocationState>,
    interval: Duration,
) {
    info!(
        interval_secs = interval.as_secs(),
        "revocation deny-list refresher running"
    );
    loop {
        refresh_once(src.as_ref(), &state).await;
        tokio::time::sleep(interval).await;
    }
}

/// Spawn the refresh loop iff the feature is enabled. Safe no-op otherwise.
/// Called from both server entry points (next to the other background tasks).
pub fn spawn_if_enabled(state: &Arc<AppState>) {
    if !enabled(state) {
        return;
    }
    let Some(pool) = state.pins_db.clone() else {
        return;
    };
    let Some(rev) = state.revocation.clone() else {
        return;
    };
    let window_days = std::env::var("FULA_REVOCATION_WINDOW_DAYS")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(0);
    let interval = Duration::from_secs(
        std::env::var("FULA_REVOCATION_REFRESH_SECS")
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .unwrap_or(30)
            .max(5),
    );
    let src: Arc<dyn RevocationSource> = Arc::new(PgRevocationSource::new(pool, window_days));
    tokio::spawn(async move {
        run_refresh_loop(src, rev, interval).await;
    });
    info!(
        window_days,
        "✓ Revocation deny-list refresher started (honors manual key revocation)"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_hex_matches_known_vector() {
        // echo -n hello | sha256sum
        assert_eq!(
            sha256_hex("hello"),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn empty_denylist_allows_everything() {
        let st = RevocationState::empty();
        assert!(!st.is_revoked("any.jwt.token"));
        assert!(st.is_empty());
    }

    #[test]
    fn revoked_hash_is_detected_others_allowed() {
        let st = RevocationState::empty();
        let token = "eyJ.fake.jwt";
        let mut set = HashSet::new();
        set.insert(sha256_hex(token));
        st.swap(set);
        assert!(st.is_revoked(token));
        assert!(!st.is_revoked("some.other.token"));
    }

    #[test]
    fn ensure_not_revoked_none_source_is_always_ok() {
        // Feature off → every token passes (byte-identical to pre-fix behavior).
        assert!(ensure_not_revoked(None, "anything").is_ok());
    }

    #[test]
    fn ensure_not_revoked_denies_only_revoked() {
        let st = RevocationState::empty();
        let mut set = HashSet::new();
        set.insert(sha256_hex("revoked.jwt"));
        st.swap(set);
        assert!(ensure_not_revoked(Some(&st), "valid.jwt").is_ok());
        assert!(ensure_not_revoked(Some(&st), "revoked.jwt").is_err());
    }

    struct StaticSource(HashSet<String>);
    #[async_trait::async_trait]
    impl RevocationSource for StaticSource {
        async fn revoked_hashes(&self) -> anyhow::Result<HashSet<String>> {
            Ok(self.0.clone())
        }
    }

    struct FailingSource;
    #[async_trait::async_trait]
    impl RevocationSource for FailingSource {
        async fn revoked_hashes(&self) -> anyhow::Result<HashSet<String>> {
            anyhow::bail!("simulated DB failure")
        }
    }

    #[tokio::test]
    async fn refresh_loads_then_keeps_previous_set_on_error() {
        let st = RevocationState::empty();
        let token = "tok.to.revoke";
        let mut set = HashSet::new();
        set.insert(sha256_hex(token));

        // First refresh loads the revoked hash.
        refresh_once(&StaticSource(set), &st).await;
        assert!(st.is_revoked(token));

        // A failing refresh must NOT wipe the deny-list (fail-safe).
        refresh_once(&FailingSource, &st).await;
        assert!(st.is_revoked(token));
    }

    #[tokio::test]
    async fn refresh_can_clear_a_hash_when_unrevoked() {
        // If a key is later un-revoked (or the window drops it), the next
        // successful refresh removes it — a previously-denied token is allowed
        // again. Confirms swaps are wholesale, not additive.
        let st = RevocationState::empty();
        let token = "tok";
        let mut set = HashSet::new();
        set.insert(sha256_hex(token));
        refresh_once(&StaticSource(set), &st).await;
        assert!(st.is_revoked(token));
        refresh_once(&StaticSource(HashSet::new()), &st).await;
        assert!(!st.is_revoked(token));
    }
}
