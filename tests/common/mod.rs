//! Shared helpers for the workspace-level integration tests.
//!
//! Each integration test binary that needs these helpers pulls them in with:
//! ```ignore
//! mod common;
//! use common::*;
//! ```
//!
//! The helpers were previously duplicated across `api_tests.rs`,
//! `v7_hamt_tests.rs`, `audit3_wal_rotation_tests.rs`, and
//! `conditional_write_tests.rs`. Existing duplicates remain in place so this
//! change is additive — tests may migrate in a follow-up.

#![allow(dead_code)] // Not every test binary uses every helper.

use fula_cli::{AppState, GatewayConfig, routes};
use fula_client::{Config, EncryptedClient, EncryptionConfig};
use std::sync::Arc;
use tokio::net::TcpListener;

pub mod v1_seed;
pub mod fault_injection;

/// Spawn an in-process gateway backed by the in-memory store. Returns the
/// base URL the test client should target. Every call binds a fresh ephemeral
/// port, so tests can run in parallel without colliding.
pub async fn spawn_server() -> String {
    let mut config = GatewayConfig::default();
    config.host = "127.0.0.1".to_string();
    config.port = 0;
    config.auth_enabled = false;
    config.use_memory_store = true;
    config.registry_cid_path = None;
    config.jwt_secret = Some("test-secret-common".to_string());
    // Tests frequently burst thousands of puts through a single client; the
    // 100 rps default otherwise triggers SlowDown and masks real behaviour.
    config.rate_limit_rps = 1_000_000;

    let state = Arc::new(AppState::new(config.clone()).await.unwrap());
    let app = routes::create_router(state);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    format!("http://{}", addr)
}

/// Build an `EncryptedClient` pointing at `endpoint` with the supplied
/// encryption config.
pub fn make_client(endpoint: &str, encryption: EncryptionConfig) -> EncryptedClient {
    let config = Config::new(endpoint).with_encryption();
    EncryptedClient::new(config, encryption).expect("encrypted client")
}

/// Mutex-serialized env-var override with RAII restore on drop.
///
/// `cargo test` runs tests in parallel within a single binary. Several tests
/// need to swap `FULA_STATE_DIR` (or other env vars) for the duration of a
/// single test, but `std::env::set_var` / `remove_var` are process-global.
/// Every `EnvGuard::set` acquires a global mutex before mutating the env, so
/// only one test at a time owns a given variable's value.
pub struct EnvGuard {
    key: &'static str,
    prior: Option<std::ffi::OsString>,
    _lock: std::sync::MutexGuard<'static, ()>,
}

impl EnvGuard {
    pub fn set(key: &'static str, value: &std::path::Path) -> Self {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let lock = LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let prior = std::env::var_os(key);
        std::env::set_var(key, value);
        Self { key, prior, _lock: lock }
    }

    /// Like `set`, but for arbitrary string values rather than paths. Used
    /// by the heartbeat-interval override test.
    pub fn set_str(key: &'static str, value: &str) -> Self {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let lock = LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let prior = std::env::var_os(key);
        std::env::set_var(key, value);
        Self { key, prior, _lock: lock }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        match self.prior.take() {
            Some(v) => std::env::set_var(self.key, v),
            None => std::env::remove_var(self.key),
        }
    }
}
