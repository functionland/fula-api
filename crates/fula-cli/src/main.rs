//! Fula Gateway - S3-compatible storage gateway

use clap::Parser;
use fula_cli::{GatewayConfig, run_server};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Parser, Debug)]
#[command(name = "fula-gateway")]
#[command(about = "S3-compatible gateway for Fula decentralized storage")]
#[command(version)]
struct Args {
    /// Host to bind to
    #[arg(short = 'H', long, default_value = "0.0.0.0", env = "FULA_HOST")]
    host: String,

    /// Port to listen on
    #[arg(short, long, default_value = "9000", env = "FULA_PORT")]
    port: u16,

    /// IPFS API URL
    #[arg(long, default_value = "http://localhost:5001", env = "IPFS_API_URL")]
    ipfs_url: String,

    /// IPFS Cluster API URL (legacy)
    #[arg(long, default_value = "http://localhost:9094", env = "CLUSTER_API_URL")]
    cluster_url: String,

    /// IPFS Pinning Service API endpoint (e.g., https://api.pinata.cloud/psa)
    /// Note: The token is provided per-request from the user's JWT, not configured here.
    #[arg(long, env = "PINNING_SERVICE_ENDPOINT")]
    pinning_service_endpoint: Option<String>,

    /// Storage API URL for balance/quota checking (e.g., https://cloud.fx.land)
    #[arg(long, env = "STORAGE_API_URL")]
    storage_api_url: Option<String>,

    /// Use in-memory storage (for testing, data will not persist)
    #[arg(long, env = "FULA_MEMORY_STORE")]
    memory_store: bool,

    /// Enable debug logging
    #[arg(short, long, env = "FULA_DEBUG")]
    debug: bool,

    /// JWT secret for token validation
    #[arg(long, env = "JWT_SECRET")]
    jwt_secret: Option<String>,

    /// Disable authentication (for development only!)
    #[arg(long, env = "FULA_NO_AUTH")]
    no_auth: bool,

    /// Admin JWT secret for admin API authentication (separate from user JWT)
    #[arg(long, env = "ADMIN_JWT_SECRET")]
    admin_jwt_secret: Option<String>,

    /// Enable admin API endpoints
    #[arg(long, env = "FULA_ADMIN_API")]
    admin_api: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load .env file if present
    dotenvy::dotenv().ok();

    // Parse arguments
    let args = Args::parse();

    // Setup logging
    let log_level = if args.debug { "debug" } else { "info" };
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| format!("fula_cli={},tower_http=debug", log_level).into()))
        .with(tracing_subscriber::fmt::layer())
        .init();

    tracing::info!(
        "Starting Fula Gateway on {}:{}",
        args.host,
        args.port
    );
    tracing::info!("IPFS API: {}", args.ipfs_url);
    
    if let Some(ref endpoint) = args.pinning_service_endpoint {
        tracing::info!("Pinning Service: {}", endpoint);
    } else {
        tracing::info!("Cluster API: {}", args.cluster_url);
    }

    if let Some(ref storage_url) = args.storage_api_url {
        tracing::info!("Storage API (balance check): {}", storage_url);
    }

    if args.memory_store {
        tracing::warn!("⚠️  Using in-memory storage - data will NOT persist!");
    }

    if args.no_auth {
        tracing::warn!("⚠️  Authentication is DISABLED - for development only!");
    }

    if args.admin_api {
        if args.admin_jwt_secret.is_some() {
            tracing::info!("Admin API: enabled");
        } else {
            tracing::warn!("⚠️  Admin API enabled but ADMIN_JWT_SECRET not set - admin endpoints will reject all requests");
        }
    }

    // Build configuration
    let config = GatewayConfig {
        host: args.host,
        port: args.port,
        ipfs_url: args.ipfs_url,
        cluster_url: args.cluster_url,
        pinning_service_endpoint: args.pinning_service_endpoint,
        storage_api_url: args.storage_api_url,
        use_memory_store: args.memory_store,
        jwt_secret: args.jwt_secret,
        auth_enabled: !args.no_auth,
        admin_jwt_secret: args.admin_jwt_secret,
        admin_api_enabled: args.admin_api,
        ..Default::default()
    };

    // Run the server
    run_server(config).await
}
