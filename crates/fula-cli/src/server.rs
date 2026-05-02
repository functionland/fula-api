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

    // Phase 3.2 — spawn the users-index publisher loop iff the env
    // flag enabled the publisher at AppState construction time. When
    // disabled, this is a no-op and nothing about S3 routing changes.
    if let Some(publisher) = state.users_index_publisher.clone() {
        users_index_publisher::start_publisher_loop(publisher);
    }

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

    // Phase 3.2 — spawn the users-index publisher loop iff the env
    // flag enabled the publisher at AppState construction time. When
    // disabled, this is a no-op and nothing about S3 routing changes.
    if let Some(publisher) = state.users_index_publisher.clone() {
        users_index_publisher::start_publisher_loop(publisher);
    }

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
