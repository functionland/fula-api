//! RAII helpers that flip the `test-fault-injection` atomics in
//! `fula-client/src/encryption.rs` for the scope of a single test.
//!
//! Background: the two crash points inside `migrate_v1_to_v7_internal` are
//! only visible from inside the `fula-client` crate — integration tests live
//! in a separate binary. To make them observable from the outside, the crate
//! exposes two public `AtomicBool`s under the `test-fault-injection` feature
//! (enabled by the workspace root's `[dev-dependencies]` block). This module
//! wraps the "set flag / clear flag" pattern in an RAII scope so a test can
//! do:
//!
//! ```ignore
//! let _fault = FaultScope::crash_after_phase_a();
//! let outcome = client.migrate_to_sharded(bucket).await;
//! // flag cleared automatically on drop
//! ```
//!
//! The integration-test build always activates `test-fault-injection` via
//! the workspace root's `[dev-dependencies]`, so `fula_client::test_faults`
//! is always in scope when this module is compiled. Production builds of
//! `fula-client` never pull this module (it lives under `tests/`).

use fula_client::test_faults;
use std::sync::atomic::Ordering;

/// RAII guard that sets one of the migration crash-injection flags and
/// clears it on drop. Only one flag can be active at a time in practice,
/// but the guards compose (each independently clears its own flag).
pub struct FaultScope {
    kind: FaultKind,
}

#[derive(Clone, Copy, Debug)]
enum FaultKind {
    PhaseA,
    PhaseBBeforeCacheSwap,
    OrphanCleanupMainFail,
    BypassOrphanCleanupRefcheck,
}

impl FaultScope {
    /// Simulate a crash AFTER Phase A's `flush_dirty` writes HAMT node blobs
    /// but BEFORE Phase B's manifest PUT fires. The migration returns
    /// `DeferredTransientError`; the server's v1 `index_key` is untouched;
    /// orphan `__fula_forest_v7_nodes/*` blobs exist on the backend.
    pub fn crash_after_phase_a() -> Self {
        test_faults::CRASH_AFTER_PHASE_A_FLUSH.store(true, Ordering::SeqCst);
        Self { kind: FaultKind::PhaseA }
    }

    /// Simulate a crash AFTER Phase B's conditional PUT succeeds (server now
    /// serves v7 at `index_key`) but BEFORE the in-process cache swap /
    /// `persist_manifest_version` call. The next session's cold load must
    /// detect v7 directly from the server.
    pub fn crash_after_phase_b_before_cache_swap() -> Self {
        test_faults::CRASH_AFTER_PHASE_B_PUT_BEFORE_CACHE_SWAP.store(true, Ordering::SeqCst);
        Self { kind: FaultKind::PhaseBBeforeCacheSwap }
    }

    /// Force the main-object delete inside `cleanup_orphaned_storage` to
    /// report failure without touching the network. Used to verify that
    /// failed orphan cleanups are persisted to the F7 retry queue.
    pub fn orphan_cleanup_main_fail() -> Self {
        test_faults::FORCE_ORPHAN_CLEANUP_MAIN_FAIL.store(true, Ordering::SeqCst);
        Self { kind: FaultKind::OrphanCleanupMainFail }
    }

    /// Bypass the `storage_key_still_referenced` short-circuit inside
    /// `cleanup_orphaned_storage` so the cleanup path runs even on v7
    /// (which currently returns `true` unconditionally from the refcount
    /// check). Used only by F7 tests to exercise the queue.
    pub fn bypass_orphan_cleanup_refcheck() -> Self {
        test_faults::BYPASS_ORPHAN_CLEANUP_REFCHECK.store(true, Ordering::SeqCst);
        Self { kind: FaultKind::BypassOrphanCleanupRefcheck }
    }
}

impl Drop for FaultScope {
    fn drop(&mut self) {
        match self.kind {
            FaultKind::PhaseA => {
                test_faults::CRASH_AFTER_PHASE_A_FLUSH.store(false, Ordering::SeqCst);
            }
            FaultKind::PhaseBBeforeCacheSwap => {
                test_faults::CRASH_AFTER_PHASE_B_PUT_BEFORE_CACHE_SWAP.store(false, Ordering::SeqCst);
            }
            FaultKind::OrphanCleanupMainFail => {
                test_faults::FORCE_ORPHAN_CLEANUP_MAIN_FAIL.store(false, Ordering::SeqCst);
            }
            FaultKind::BypassOrphanCleanupRefcheck => {
                test_faults::BYPASS_ORPHAN_CLEANUP_REFCHECK.store(false, Ordering::SeqCst);
            }
        }
    }
}
