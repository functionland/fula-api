//! Server startup and lifecycle

use crate::{AppState, GatewayConfig, routes};
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::info;

/// Run the gateway server
pub async fn run_server(config: GatewayConfig) -> anyhow::Result<()> {
    // Create application state
    let state = Arc::new(AppState::new(config.clone()).await?);

    // Create router
    let app = routes::create_router(state);

    // Bind to address
    let addr = config.bind_addr();
    let listener = TcpListener::bind(&addr).await?;

    info!("🚀 Fula Gateway listening on http://{}", addr);
    info!("📦 S3-compatible API ready for requests");

    // Run the server
    axum::serve(listener, app).await?;

    Ok(())
}

/// Run server with graceful shutdown
pub async fn run_server_with_shutdown(
    config: GatewayConfig,
    shutdown_signal: impl std::future::Future<Output = ()> + Send + 'static,
) -> anyhow::Result<()> {
    let state = Arc::new(AppState::new(config.clone()).await?);
    let app = routes::create_router(state);

    let addr = config.bind_addr();
    let listener = TcpListener::bind(&addr).await?;

    info!("🚀 Fula Gateway listening on http://{}", addr);

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal)
        .await?;

    info!("👋 Gateway shutdown complete");

    Ok(())
}
