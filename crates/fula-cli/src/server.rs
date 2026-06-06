//! Server startup and lifecycle

use crate::handlers::{locks, users_index_publisher};
use crate::{AppState, GatewayConfig, routes};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::info;

/// Run the gateway server
pub async fn run_server(config: GatewayConfig) -> anyhow::Result<()> {
    // Create application state
    let state = Arc::new(AppState::new(config.clone()).await?);

    // Spawn the migration-lock TTL sweeper. Holds a cheap clone of the store;
    // lives for the lifetime of the process.
    locks::start_sweeper(state.lock_store.clone());

    // Proactive peering: keep the gateway kubo connected to the fleet so
    // bitswap serves reads fast. No-op when disabled / not configured.
    crate::peering::spawn_if_enabled(&config);

    // Local-retain-until-replicated verifier: drop each block's local pin once
    // the cluster confirms it's replicated to >= min-repl non-master holders,
    // so `ipfs repo gc` on the master can never delete an un-replicated block.
    // No-op when the feature is disabled (`state.local_retain` is `None`).
    if let Some(lr) = state.local_retain.clone() {
        crate::local_retain::spawn_verifier(
            lr.clone(),
            std::time::Duration::from_secs(state.config.local_retain_interval_secs.max(15)),
        );
        // One-time, throttled, background backfill of pre-existing local blocks
        // (default on; `--no-local-retain-backfill` to skip on huge datastores).
        if state.config.local_retain_backfill.unwrap_or(true) {
            tokio::spawn(async move { lr.backfill().await });
        }
    }

    // P0 index-node gc-safety backfill: pin every existing bucket's index nodes
    // (the per-PUT path only covers a bucket on its next write, so idle buckets
    // would stay gc-exposed). Throttled, best-effort; run before re-enabling
    // `ipfs repo gc`. No-op when the gc-safety feature is off.
    if state.local_retain.is_some() && state.config.local_retain_backfill.unwrap_or(true) {
        tokio::spawn(crate::index_pin_backfill::run_index_pin_backfill(Arc::clone(
            &state,
        )));
    }

    // Audit F-A5 / issue #13: spawn the multipart-upload reaper. Drops
    // abandoned in-memory upload sessions whose `last_activity_at` is
    // older than `multipart_expiry_secs`. Does NOT touch the blockstore
    // — orphan chunks are left to operator IPFS GC (deletion would be
    // unsafe in a content-addressed store due to CID dedup).
    crate::multipart::start_reaper(
        Arc::clone(&state.multipart_manager),
        state.config.multipart_reaper_interval_secs,
    );

    // Phase 3.2 — spawn the users-index publisher loop iff the env
    // flag enabled the publisher at AppState construction time. When
    // disabled, this is a no-op and nothing about S3 routing changes.
    if let Some(publisher) = state.users_index_publisher.clone() {
        users_index_publisher::start_publisher_loop(publisher);
    }

    // W.9.6 — spawn the pin-queue drainer iff the queue was opened
    // at AppState construction time. When the queue is None, this is
    // a no-op and the PUT handler falls back to fire-and-forget pins
    // (legacy v0.5 behavior). On runtime shutdown the tokio runtime
    // aborts the spawned task; pending records survive the next
    // master restart via redb durability (this is the load-bearing
    // crash-safety property — the queue is the source of truth, not
    // the drainer's in-flight state).
    //
    // We `mem::forget` both the JoinHandle and the cancel oneshot:
    // the drainer is a process-lifetime task. A future graceful-
    // shutdown wiring would replace this with a registry of cancel
    // tokens that `run_server_with_shutdown` drains during its
    // tokio-runtime-shutdown grace period. For now, abrupt cancel
    // is safe because pin RPCs are idempotent at cluster — a
    // partially-completed pin gets retried on next startup, no harm.
    if let Some(queue) = state.pin_queue.clone() {
        let dispatcher: Arc<dyn crate::pin_drainer::PinDispatcher> = Arc::new(
            crate::pin_drainer::LivePinDispatcher::new(Arc::clone(&state.block_store)),
        );
        let (handle, cancel) = crate::pin_drainer::spawn_drainer_loop(
            queue,
            dispatcher,
            crate::pin_drainer::DrainerConfig::default(),
        );
        std::mem::forget(handle);
        std::mem::forget(cancel);
        info!("✓ Pin drainer (W.9.6) started");
    }

    // GC-recovery read-fallback: a background job mirrors the cluster pinset
    // (storage_key→CID) into `recovery_key_cid` so an object-GET index miss can
    // resolve the key from the cluster and serve the block (turning a gc-orphan
    // 404/410 into a 200). No-op when disabled (kill switch / no pins DB / no
    // cluster URL / memory store). Healthy reads are never affected.
    crate::recovery_fallback::spawn_reconcile_if_enabled(&state);

    // Create router
    let app = routes::create_router(state);

    // Bind to address
    let addr = config.bind_addr();
    let listener = TcpListener::bind(&addr).await?;

    info!("🚀 Fula Gateway listening on http://{}", addr);
    info!("📦 S3-compatible API ready for requests");

    // Run the server with ConnectInfo to enable client IP extraction
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await?;

    Ok(())
}

/// Run server with graceful shutdown
pub async fn run_server_with_shutdown(
    config: GatewayConfig,
    shutdown_signal: impl std::future::Future<Output = ()> + Send + 'static,
) -> anyhow::Result<()> {
    let state = Arc::new(AppState::new(config.clone()).await?);

    locks::start_sweeper(state.lock_store.clone());

    // Proactive peering: keep the gateway kubo connected to the fleet so
    // bitswap serves reads fast. No-op when disabled / not configured.
    crate::peering::spawn_if_enabled(&config);

    // Local-retain-until-replicated verifier: drop each block's local pin once
    // the cluster confirms it's replicated to >= min-repl non-master holders,
    // so `ipfs repo gc` on the master can never delete an un-replicated block.
    // No-op when the feature is disabled (`state.local_retain` is `None`).
    if let Some(lr) = state.local_retain.clone() {
        crate::local_retain::spawn_verifier(
            lr.clone(),
            std::time::Duration::from_secs(state.config.local_retain_interval_secs.max(15)),
        );
        // One-time, throttled, background backfill of pre-existing local blocks
        // (default on; `--no-local-retain-backfill` to skip on huge datastores).
        if state.config.local_retain_backfill.unwrap_or(true) {
            tokio::spawn(async move { lr.backfill().await });
        }
    }

    // P0 index-node gc-safety backfill: pin every existing bucket's index nodes
    // (the per-PUT path only covers a bucket on its next write, so idle buckets
    // would stay gc-exposed). Throttled, best-effort; run before re-enabling
    // `ipfs repo gc`. No-op when the gc-safety feature is off.
    if state.local_retain.is_some() && state.config.local_retain_backfill.unwrap_or(true) {
        tokio::spawn(crate::index_pin_backfill::run_index_pin_backfill(Arc::clone(
            &state,
        )));
    }

    // Phase 3.2 — spawn the users-index publisher loop iff the env
    // flag enabled the publisher at AppState construction time. When
    // disabled, this is a no-op and nothing about S3 routing changes.
    if let Some(publisher) = state.users_index_publisher.clone() {
        users_index_publisher::start_publisher_loop(publisher);
    }

    // W.9.6 — spawn the pin-queue drainer iff the queue was opened
    // at AppState construction time. When the queue is None, this is
    // a no-op and the PUT handler falls back to fire-and-forget pins
    // (legacy v0.5 behavior). On runtime shutdown the tokio runtime
    // aborts the spawned task; pending records survive the next
    // master restart via redb durability (this is the load-bearing
    // crash-safety property — the queue is the source of truth, not
    // the drainer's in-flight state).
    //
    // We `mem::forget` both the JoinHandle and the cancel oneshot:
    // the drainer is a process-lifetime task. A future graceful-
    // shutdown wiring would replace this with a registry of cancel
    // tokens that `run_server_with_shutdown` drains during its
    // tokio-runtime-shutdown grace period. For now, abrupt cancel
    // is safe because pin RPCs are idempotent at cluster — a
    // partially-completed pin gets retried on next startup, no harm.
    if let Some(queue) = state.pin_queue.clone() {
        let dispatcher: Arc<dyn crate::pin_drainer::PinDispatcher> = Arc::new(
            crate::pin_drainer::LivePinDispatcher::new(Arc::clone(&state.block_store)),
        );
        let (handle, cancel) = crate::pin_drainer::spawn_drainer_loop(
            queue,
            dispatcher,
            crate::pin_drainer::DrainerConfig::default(),
        );
        std::mem::forget(handle);
        std::mem::forget(cancel);
        info!("✓ Pin drainer (W.9.6) started");
    }

    // GC-recovery read-fallback: a background job mirrors the cluster pinset
    // (storage_key→CID) into `recovery_key_cid` so an object-GET index miss can
    // resolve the key from the cluster and serve the block (turning a gc-orphan
    // 404/410 into a 200). No-op when disabled (kill switch / no pins DB / no
    // cluster URL / memory store). Healthy reads are never affected.
    crate::recovery_fallback::spawn_reconcile_if_enabled(&state);

    let app = routes::create_router(state);

    let addr = config.bind_addr();
    let listener = TcpListener::bind(&addr).await?;

    info!("🚀 Fula Gateway listening on http://{}", addr);

    // Run the server with ConnectInfo to enable client IP extraction
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(shutdown_signal)
        .await?;

    info!("👋 Gateway shutdown complete");

    Ok(())
}
