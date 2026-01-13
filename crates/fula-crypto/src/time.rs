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
}
