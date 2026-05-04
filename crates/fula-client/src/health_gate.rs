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
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Phase 19 transparency surface — events the SDK emits when its
/// view of master-server reachability changes. Apps wire a
/// [`HealthCallback`] via [`Config::health_callback`] and surface
/// the transitions to users (e.g., "you're offline; reading from
/// IPFS gateway"). The default behavior with no callback set is
/// byte-identical to pre-Phase-19 builds — the gate still works,
/// just silently.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MasterHealthEvent {
    /// Master S3 is reachable; reads use the fast path.
    Online,

    /// Master S3 is unreachable; SDK is falling back to IPFS
    /// gateways (Phase 2.4) or cold-start resolver (Phase 3.3).
    /// `reason` is human-readable for logging — not for end-user
    /// display (use a localized string from your UI layer).
    OfflineFallbackActive { reason: String },

    /// Both master S3 AND the chain RPC are unreachable. Cold-
    /// start reads will fail; warm reads (via cached `(bucket,
    /// key) → cid`) still work via gateways. Apps should disable
    /// "open new bucket" / "first-read" UI affordances when this
    /// fires. **Emitted only from the cold-start failure path**
    /// (the resolver), NOT from periodic health-gate observation —
    /// the SDK can't authoritatively detect "both down" without
    /// trying.
    SeverelyDegraded { reason: String },
}

/// A callback the SDK invokes on every `MasterHealthEvent`
/// transition. `Arc<dyn Fn + Send + Sync>` so the closure can be
/// shared across all clones of `FulaClient` and called from any
/// task. Transitions are deduplicated — a single Down→Up flip fires
/// exactly one `Online` event, not one per request.
pub type HealthCallback = Arc<dyn Fn(MasterHealthEvent) + Send + Sync + 'static>;

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
    /// Phase 19 — optional transparency callback. `Some` when
    /// `Config::health_callback` was set on `FulaClient::new`.
    /// Fires `Online` / `OfflineFallbackActive` on Up↔Down state
    /// transitions, with deduplication so back-to-back events
    /// don't double-fire.
    callback: Option<HealthCallback>,
}

impl HealthGate {
    /// Create a new gate with the given TTL. Starts in the `Up` state.
    /// No callback registered.
    pub fn new(ttl: Duration) -> Self {
        Self {
            state_ms: AtomicU64::new(0),
            consecutive_failures: AtomicU32::new(0),
            ttl,
            callback: None,
        }
    }

    /// Phase 19 — construct a gate with a transparency callback.
    /// The callback fires once on each Up↔Down transition; consecutive
    /// failures within an already-Down state do NOT re-fire.
    pub fn with_callback(ttl: Duration, callback: HealthCallback) -> Self {
        Self {
            state_ms: AtomicU64::new(0),
            consecutive_failures: AtomicU32::new(0),
            ttl,
            callback: Some(callback),
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
    ///
    /// Phase 19: fires `MasterHealthEvent::Online` exactly when the gate
    /// flips from Down→Up. A success while already Up is a no-op.
    pub fn record_success(&self) {
        self.consecutive_failures.store(0, Ordering::Release);
        let was_down = self.state_ms.swap(0, Ordering::AcqRel) != 0;
        if was_down {
            self.fire_event(MasterHealthEvent::Online);
        }
    }

    /// Record a master-side failure (connection refused / RST / 5xx /
    /// request timeout). Increments the consecutive-failure counter; once
    /// the threshold is reached, flips the gate to `Down(now)`.
    ///
    /// 4xx responses are NOT failures for gate purposes — they're
    /// request-level issues, not master-down signals.
    ///
    /// Phase 19: fires `MasterHealthEvent::OfflineFallbackActive` exactly
    /// once on the Up→Down transition. Subsequent failures while already
    /// Down do NOT re-fire (the `compare_exchange` filters duplicates).
    pub fn record_failure(&self) {
        let prior = self.consecutive_failures.fetch_add(1, Ordering::AcqRel);
        if prior + 1 >= CONSECUTIVE_FAILURE_THRESHOLD {
            // Threshold crossed (or exceeded). Flip to `Down` if not already.
            // Only update timestamp on the first transition this window so
            // that repeated failures don't keep extending the TTL.
            let now = now_ms();
            let prev = self
                .state_ms
                .compare_exchange(0, now, Ordering::AcqRel, Ordering::Acquire);
            // `Ok(_)` means we successfully transitioned Up→Down — fire
            // the event once. `Err(_)` means already Down (timestamp
            // non-zero), no transition.
            if prev.is_ok() {
                self.fire_event(MasterHealthEvent::OfflineFallbackActive {
                    reason: format!(
                        "{} consecutive master failures observed",
                        prior + 1
                    ),
                });
            }
        }
    }

    /// Phase 19 helper — invoke the registered callback if present.
    /// Swallows panics inside the callback so a buggy app handler
    /// can't crash the SDK request path.
    fn fire_event(&self, event: MasterHealthEvent) {
        if let Some(cb) = self.callback.as_ref() {
            let cb = Arc::clone(cb);
            // Clone the event for the closure; original is dropped after.
            let event_clone = event.clone();
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                cb(event_clone);
            }));
            if result.is_err() {
                tracing::warn!(
                    event = ?event,
                    "health_callback panicked; SDK proceeding (callback panics are swallowed by design)"
                );
            }
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

    // ============================================================
    // Phase 19 — transparency callback wiring
    // ============================================================

    /// Helper: build a callback that pushes events into a Mutex<Vec>.
    /// Returns the callback Arc + a clone of the same Vec for assertions.
    fn capturing_callback() -> (
        HealthCallback,
        std::sync::Arc<std::sync::Mutex<Vec<MasterHealthEvent>>>,
    ) {
        let captured: std::sync::Arc<std::sync::Mutex<Vec<MasterHealthEvent>>> =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let captured_for_cb = std::sync::Arc::clone(&captured);
        let cb: HealthCallback = std::sync::Arc::new(move |ev| {
            captured_for_cb.lock().unwrap().push(ev);
        });
        (cb, captured)
    }

    #[test]
    fn test_phase19_two_failures_fire_offline_event_single_failure_silent() {
        // Advisor-mandated test #1: a single failure must NOT fire the
        // callback (the gate stays Up). The second failure that crosses
        // the threshold fires `OfflineFallbackActive` exactly once.
        let (cb, captured) = capturing_callback();
        let gate = HealthGate::with_callback(Duration::from_secs(30), cb);

        gate.record_failure();
        // After one failure: gate still Up, no callback fired.
        assert_eq!(
            captured.lock().unwrap().len(),
            0,
            "single failure must not fire callback"
        );

        gate.record_failure();
        // After two failures: gate flipped Down, exactly one event fired.
        let events = captured.lock().unwrap().clone();
        assert_eq!(events.len(), 1, "expected exactly one event, got: {:?}", events);
        match &events[0] {
            MasterHealthEvent::OfflineFallbackActive { reason } => {
                assert!(
                    reason.contains("2 consecutive"),
                    "reason should mention failure count: {}",
                    reason
                );
            }
            other => panic!("expected OfflineFallbackActive, got {:?}", other),
        }

        // Further failures while already Down must NOT re-fire the event
        // (compare_exchange filters the no-transition case).
        gate.record_failure();
        gate.record_failure();
        assert_eq!(
            captured.lock().unwrap().len(),
            1,
            "additional failures while Down must not re-fire OfflineFallbackActive"
        );
    }

    #[test]
    fn test_phase19_success_after_down_fires_online() {
        // Advisor-mandated test #2: when the gate is Down and a probe
        // succeeds, the callback observes `Online` exactly once.
        let (cb, captured) = capturing_callback();
        let gate = HealthGate::with_callback(Duration::from_secs(30), cb);

        // Trip the gate.
        gate.record_failure();
        gate.record_failure();
        // One OfflineFallbackActive event so far.
        assert_eq!(captured.lock().unwrap().len(), 1);

        // Success — flips Down→Up; fires Online.
        gate.record_success();
        let events = captured.lock().unwrap().clone();
        assert_eq!(events.len(), 2, "expected OfflineFallbackActive + Online");
        assert!(matches!(events[1], MasterHealthEvent::Online));

        // A second success while already Up must NOT re-fire Online.
        gate.record_success();
        assert_eq!(
            captured.lock().unwrap().len(),
            2,
            "redundant success while Up must not re-fire Online"
        );
    }

    #[test]
    fn test_phase19_callback_panic_does_not_crash_caller() {
        // A buggy app callback that panics must NOT crash the SDK.
        // `fire_event` wraps the call in `catch_unwind` and proceeds.
        let cb: HealthCallback = std::sync::Arc::new(|_ev| {
            panic!("simulated app-level panic");
        });
        let gate = HealthGate::with_callback(Duration::from_secs(30), cb);

        // These calls would propagate the panic if catch_unwind weren't
        // wrapping the callback. The test passes by NOT panicking.
        gate.record_failure();
        gate.record_failure();
        gate.record_success();

        // And the gate state itself remains correct: a success after a
        // Down state returns to Up.
        assert_eq!(gate.decide(), GateDecision::Allow);
    }

    #[test]
    fn test_phase19_no_callback_means_silent() {
        // A gate constructed via `new` (no callback) must work
        // identically to pre-Phase-19 builds: state machine works,
        // no events are produced anywhere.
        let gate = HealthGate::new(Duration::from_secs(30));
        gate.record_failure();
        gate.record_failure();
        gate.record_success();
        // No assertion on event capture — there's no captured Vec.
        // The fact that we constructed the gate with `new` (no
        // callback wiring) and reached this line proves the silent
        // path works. Verify final state is sane.
        assert_eq!(gate.decide(), GateDecision::Allow);
    }
}
