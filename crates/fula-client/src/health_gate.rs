//! Master health gate (Phase 2.1 of master-independent reads).
//!
//! Lock-free, lazy-probed state machine that tracks whether the master S3
//! endpoint is reachable. The SDK consults the gate inside its HTTP request
//! path: when the gate is `Up`, requests proceed normally; when `Down`,
//! requests short-circuit with `Error::MasterUnreachable` for the configured
//! TTL, avoiding the per-read timeout tax that would otherwise degrade the
//! fast path under any flaky network.
//!
//! ## Design
//!
//! - **Lazy probing.** No eager init probe (which would waste a roundtrip on
//!   every SDK construction when master is up — the common case). Failures
//!   are observed inside normal traffic; once the gate trips, periodic
//!   "probe" attempts are allowed through after the TTL expires.
//!
//! - **2-consecutive-failure threshold.** A single 5xx on a single bucket is
//!   not a master-down signal — it's a request-level issue. The gate only
//!   trips after **two** consecutive failures across any requests. This
//!   prevents one transient error from sidelining the whole client.
//!
//! - **Lock-free atomic state.** `state_ms` is an `AtomicU64` representing
//!   either `0` (Up) or the unix-millis when the gate flipped Down.
//!   `consecutive_failures` is an `AtomicU32`. No `Mutex` / `RwLock`
//!   contention even when 50 in-flight requests all fail simultaneously.
//!
//! - **Phase 2.1 ships the gate; Phase 2.4 wires it into a fallback to the
//!   gateway race.** Standalone, the gate just turns "3-second-timeout per
//!   read" into "fast-fail with `MasterUnreachable`" when Down.

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Threshold for flipping from `Up` to `Down`. One transient 5xx on a single
/// bucket isn't the same as "master is unreachable" — only two consecutive
/// signals trip the gate.
const CONSECUTIVE_FAILURE_THRESHOLD: u32 = 2;

/// State machine for master reachability.
///
/// `state_ms == 0`  → currently `Up`.
/// `state_ms != 0`  → flipped `Down` at this unix-millis timestamp.
///
/// Cheap to clone via `Arc`; shared across all `FulaClient` clones so a
/// failure observed in one task immediately silences the rest.
pub struct HealthGate {
    state_ms: AtomicU64,
    consecutive_failures: AtomicU32,
    ttl: Duration,
}

impl HealthGate {
    /// Create a new gate with the given TTL. Starts in the `Up` state.
    pub fn new(ttl: Duration) -> Self {
        Self {
            state_ms: AtomicU64::new(0),
            consecutive_failures: AtomicU32::new(0),
            ttl,
        }
    }

    /// Decide whether a request to master should be sent or short-circuited.
    ///
    /// Returns:
    /// - `GateDecision::Allow` — gate is `Up`, OR `Down` but `now > since + ttl`
    ///   (the TTL elapsed; this request is the next "probe").
    /// - `GateDecision::ShortCircuit { down_for_secs }` — gate is `Down` and
    ///   within the TTL; caller should fail fast with `MasterUnreachable`.
    pub fn decide(&self) -> GateDecision {
        let down_at = self.state_ms.load(Ordering::Acquire);
        if down_at == 0 {
            return GateDecision::Allow;
        }
        let now = now_ms();
        let elapsed = now.saturating_sub(down_at);
        if elapsed >= self.ttl.as_millis() as u64 {
            // TTL elapsed — let this request through as a probe. Don't
            // reset the gate yet; reset only on observed success.
            GateDecision::Allow
        } else {
            GateDecision::ShortCircuit {
                down_for_secs: elapsed / 1000,
            }
        }
    }

    /// Record a successful master interaction. Resets the failure counter
    /// and clears the `Down` timestamp (gate returns to `Up`).
    pub fn record_success(&self) {
        self.consecutive_failures.store(0, Ordering::Release);
        self.state_ms.store(0, Ordering::Release);
    }

    /// Record a master-side failure (connection refused / RST / 5xx /
    /// request timeout). Increments the consecutive-failure counter; once
    /// the threshold is reached, flips the gate to `Down(now)`.
    ///
    /// 4xx responses are NOT failures for gate purposes — they're
    /// request-level issues, not master-down signals.
    pub fn record_failure(&self) {
        let prior = self.consecutive_failures.fetch_add(1, Ordering::AcqRel);
        if prior + 1 >= CONSECUTIVE_FAILURE_THRESHOLD {
            // Threshold crossed (or exceeded). Flip to `Down` if not already.
            // Only update timestamp on the first transition this window so
            // that repeated failures don't keep extending the TTL.
            let _ = self.state_ms.compare_exchange(
                0,
                now_ms(),
                Ordering::AcqRel,
                Ordering::Acquire,
            );
        }
    }
}

/// Decision returned by `HealthGate::decide`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateDecision {
    /// Caller should send the request to master normally.
    Allow,
    /// Caller should fail fast with `Error::MasterUnreachable`.
    ShortCircuit { down_for_secs: u64 },
}

/// Current unix-time in milliseconds. Wall-clock based (so SystemTime
/// adjustments can shift the gate's perceived "since" — acceptable here
/// since we only compare durations, and a clock jump is at worst a slight
/// TTL anomaly).
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_state_is_up() {
        // A freshly-constructed gate must be `Up`. Lazy probing means we
        // never assume master is down without observation.
        let gate = HealthGate::new(Duration::from_secs(30));
        assert_eq!(gate.decide(), GateDecision::Allow);
    }

    #[test]
    fn test_one_failure_does_not_trip() {
        // S1 from advisor: a single failure must NOT sideline the gate.
        // One-off 5xx on a bucket-level operation is not "master is down."
        let gate = HealthGate::new(Duration::from_secs(30));
        gate.record_failure();
        assert_eq!(
            gate.decide(),
            GateDecision::Allow,
            "one failure must not flip the gate"
        );
    }

    #[test]
    fn test_two_consecutive_failures_trip_to_down() {
        // CONSECUTIVE_FAILURE_THRESHOLD = 2. Two consecutive failures
        // (across any requests) flip the gate.
        let gate = HealthGate::new(Duration::from_secs(30));
        gate.record_failure();
        gate.record_failure();
        match gate.decide() {
            GateDecision::ShortCircuit { down_for_secs: _ } => { /* ok */ }
            other => panic!("expected ShortCircuit, got {:?}", other),
        }
    }

    #[test]
    fn test_success_resets_consecutive_counter() {
        // A success between failures must reset the counter so a second
        // failure (after the success) doesn't pile on with the first.
        let gate = HealthGate::new(Duration::from_secs(30));
        gate.record_failure();
        gate.record_success();
        gate.record_failure();
        // Only ONE failure since the last success — must not be down.
        assert_eq!(gate.decide(), GateDecision::Allow);
    }

    #[test]
    fn test_success_clears_down_state() {
        // When the gate is Down and a probe (after TTL or first attempt
        // that gets through) succeeds, the gate must return to Up.
        let gate = HealthGate::new(Duration::from_secs(30));
        gate.record_failure();
        gate.record_failure();
        assert!(matches!(gate.decide(), GateDecision::ShortCircuit { .. }));
        gate.record_success();
        assert_eq!(gate.decide(), GateDecision::Allow);
    }

    #[test]
    fn test_down_state_expires_after_ttl() {
        // After TTL elapses, the gate allows the next request through
        // as a probe (without resetting state — only success resets).
        // Use a very short TTL to keep the test fast.
        let gate = HealthGate::new(Duration::from_millis(50));
        gate.record_failure();
        gate.record_failure();
        assert!(matches!(gate.decide(), GateDecision::ShortCircuit { .. }));

        std::thread::sleep(Duration::from_millis(80));

        assert_eq!(
            gate.decide(),
            GateDecision::Allow,
            "after TTL, next decide() must allow a probe"
        );
        // State is still Down until a probe succeeds (verify by observing
        // that consecutive_failures hasn't auto-reset).
        let down_at = gate.state_ms.load(Ordering::Acquire);
        assert!(down_at > 0, "state remains Down until success observed");
    }

    #[test]
    fn test_concurrent_failures_idempotent() {
        // Two threads recording failures concurrently must not produce
        // unexpected state. Even with N concurrent failures, the gate is
        // either Up (if total < threshold) or Down (if >= threshold).
        use std::sync::Arc;
        let gate = Arc::new(HealthGate::new(Duration::from_secs(30)));

        let mut handles = Vec::new();
        for _ in 0..8 {
            let g = gate.clone();
            handles.push(std::thread::spawn(move || g.record_failure()));
        }
        for h in handles {
            h.join().unwrap();
        }
        // 8 failures > threshold(2), so gate must be Down.
        assert!(matches!(gate.decide(), GateDecision::ShortCircuit { .. }));
    }
}
