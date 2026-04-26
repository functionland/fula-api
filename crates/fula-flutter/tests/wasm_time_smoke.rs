//! WASM regression tests for the v1→v7 forest migration time-API panic.
//!
//! Background: `std::time::Instant::now()` and `std::time::SystemTime::now()`
//! compile cleanly on `wasm32-unknown-unknown` but panic at runtime with
//! "time not implemented on this platform". The migration code path used both
//! at module level (un-gated by `cfg(not(target_arch = "wasm32"))`), so any
//! browser user listing a v1-format bucket panicked the WASM module.
//!
//! These tests exercise the public surface of the time wiring so a regression
//! that drops `web-time` from `fula-client`'s deps, removes the `wasmbind`
//! feature on chrono, or re-introduces a raw stdlib time call inside an
//! ungated code path will fail CI's `wasm-pack test` step instead of
//! reaching production.
//!
//! Run with: `wasm-pack test --headless --firefox crates/fula-flutter`

#![cfg(target_arch = "wasm32")]

use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

/// Validates that `web_time::Instant::now()` — the replacement for
/// `std::time::Instant::now()` at `fula-client/src/encryption.rs:3600` — wires
/// through to `performance.now()` without panicking.
#[wasm_bindgen_test]
fn web_time_instant_now_does_not_panic() {
    let _ = web_time::Instant::now();
}

/// Validates that `fula_crypto::time::now_timestamp()` — the wrapper used at
/// `fula-crypto/src/private_forest.rs:292, 368, 1125, 1350` — returns a
/// plausible Unix timestamp from the JS Date API on WASM.
#[wasm_bindgen_test]
fn fula_crypto_now_timestamp_returns_current_seconds() {
    let ts = fula_crypto::time::now_timestamp();
    assert!(
        ts > 1_700_000_000,
        "expected a post-2023 Unix timestamp, got {ts}",
    );
}

/// Constructs a `PrivateForest` via the public `with_format` constructor
/// (`fula-crypto/src/private_forest.rs:287`). Before the fix, that constructor
/// called `std::time::SystemTime::now().duration_since(...)` at line 292 and
/// panicked under WASM. The fix routes through `crate::time::now_timestamp()`;
/// this test catches a regression that re-introduces the raw stdlib call.
#[wasm_bindgen_test]
fn private_forest_with_format_does_not_panic_on_wasm() {
    use fula_crypto::{ForestFormat, PrivateForest};
    let _ = PrivateForest::with_format(ForestFormat::FlatMapV1);
}
