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
/// WAL module does not compile — a uniform shape across platforms simplifies
/// shared Dart code that monitors both mobile and web.
#[cfg(not(target_arch = "wasm32"))]
pub fn wal_append_failure_count() -> u64 {
    fula_client::wal_append_failure_count()
}

#[cfg(target_arch = "wasm32")]
pub fn wal_append_failure_count() -> u64 {
    0
}
