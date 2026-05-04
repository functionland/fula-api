//! WASM-compatible time utilities
//!
//! This module provides time functions that work in both native and WASM environments.
//! In WASM, `std::time::SystemTime` is not available, so we use `js_sys::Date::now()` instead.

/// Get current Unix timestamp in seconds (WASM-compatible)
///
/// Returns the current time as seconds since the Unix epoch.
/// Works in both native Rust and WASM environments.
#[cfg(target_arch = "wasm32")]
pub fn now_timestamp() -> i64 {
    (js_sys::Date::now() / 1000.0) as i64
}

/// Get current Unix timestamp in seconds (native)
#[cfg(not(target_arch = "wasm32"))]
pub fn now_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// Get current Unix timestamp in milliseconds (WASM-compatible)
///
/// Returns the current time as milliseconds since the Unix epoch.
/// Companion to `now_timestamp` for callers that need millisecond
/// resolution (e.g., the master health gate's TTL bookkeeping where
/// sub-second precision matters across rapid Up↔Down transitions).
/// Works in both native Rust and WASM environments.
#[cfg(target_arch = "wasm32")]
pub fn now_millis() -> u64 {
    js_sys::Date::now() as u64
}

/// Get current Unix timestamp in milliseconds (native)
#[cfg(not(target_arch = "wasm32"))]
pub fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_now_timestamp_reasonable() {
        let ts = now_timestamp();
        // Should be after Jan 1, 2020 (timestamp: 1577836800)
        assert!(ts > 1577836800, "Timestamp should be after 2020");
        // Should be before Jan 1, 2100 (timestamp: 4102444800)
        assert!(ts < 4102444800, "Timestamp should be before 2100");
    }

    #[test]
    fn test_now_millis_reasonable() {
        let ms = now_millis();
        // Should be after Jan 1, 2020 in ms (1577836800000)
        assert!(ms > 1_577_836_800_000, "ms timestamp should be after 2020");
        // Should be before Jan 1, 2100 in ms
        assert!(ms < 4_102_444_800_000, "ms timestamp should be before 2100");
    }

    #[test]
    fn test_now_millis_matches_seconds_within_tolerance() {
        // Sanity: the millis helper agrees with the seconds helper to
        // the second. Catches an accidental scaling bug.
        let ms = now_millis();
        let s = now_timestamp() as u64;
        let derived_s = ms / 1000;
        assert!(
            derived_s.abs_diff(s) <= 1,
            "now_millis()/1000 ({derived_s}) and now_timestamp() ({s}) must agree to within 1s",
        );
    }
}
