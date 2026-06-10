//! Operational metrics exposed to the binding layer.
//!
//! F11: process-wide WAL append-failure count. The WAL is the crash-recovery
//! log for in-memory forest upserts; when `wal::append` fails, the in-memory
//! dirty state has outrun its on-disk record. This counter rises on every
//! such failure so Flutter apps can wire it into their telemetry pipeline
//! alongside `tracing` logs.

/// Monotonic count of WAL append failures since process start.
///
/// Process-wide (not per-client). Not reset. Returns 0 on WASM where the
/// WAL module does not compile â€” a uniform shape across platforms simplifies
/// shared Dart code that monitors both mobile and web.
#[cfg(not(target_arch = "wasm32"))]
pub async fn wal_append_failure_count() -> u64 {
    fula_client::wal_append_failure_count()
}

#[cfg(target_arch = "wasm32")]
pub async fn wal_append_failure_count() -> u64 {
    0
}

/// Monotonic count of flush-forest retry backoff sleeps observed since
/// process start (M-2).
///
/// Incremented each time the `flush_forest` retry loop sleeps on a 412
/// concurrent-modification race before re-attempting. Process-wide.
/// Returns 0 on WASM where `flush_forest` does a single attempt with no
/// retry/backoff.
#[cfg(not(target_arch = "wasm32"))]
pub async fn flush_backoff_count() -> u64 {
    fula_client::flush_backoff_count()
}

#[cfg(target_arch = "wasm32")]
pub async fn flush_backoff_count() -> u64 {
    0
}

/// Monotonic count of WAL groups discarded on load due to partial-group
/// truncation (M-4).
///
/// A transactional multi-entry op written via the internal `append_group`
/// path is applied all-or-none on replay: if any member is missing at load
/// time (power-loss between writes and the trailing fsync, MAC corruption,
/// index collision), every surviving member is dropped and this counter
/// increments once per discarded group. Returns 0 on WASM where the WAL is
/// compiled out.
#[cfg(not(target_arch = "wasm32"))]
pub async fn wal_truncated_groups_count() -> u64 {
    fula_client::wal_truncated_groups_count()
}

#[cfg(target_arch = "wasm32")]
pub async fn wal_truncated_groups_count() -> u64 {
    0
}
