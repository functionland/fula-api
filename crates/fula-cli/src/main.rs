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

    /// LRU block cache size in MB (0 disables the cache)
    #[arg(long, default_value = "256", env = "FULA_BLOCK_CACHE_MB")]
    block_cache_mb: usize,

    /// Per-user sustained rate limit (requests/second; token refill rate).
    #[arg(long, default_value = "1000", env = "FULA_RATE_LIMIT_RPS")]
    rate_limit_rps: u32,

    /// Per-user rate-limit burst capacity (token-bucket size). A client "list"
    /// of a bucket is a client-side forest walk = hundreds of structural
    /// `__fula_forest_v7_nodes/<h>` GETs in a sub-second burst, so this must
    /// comfortably exceed a bucket's node count or listings 429 mid-walk and
    /// time out. Tune up (no rebuild) for very large buckets.
    #[arg(long, default_value = "10000", env = "FULA_RATE_LIMIT_BURST")]
    rate_limit_burst: u32,

    /// Disable the cluster-aware read fallback (kill-switch; exact prior behavior)
    #[arg(long, env = "FULA_NO_CLUSTER_FALLBACK")]
    no_cluster_fallback: bool,

    /// Disable the proactive peering task (keeps the gateway kubo connected to the fleet)
    #[arg(long, env = "FULA_NO_CLUSTER_PEERING")]
    no_cluster_peering: bool,

    /// Disable local-retain-until-replicated GC-safety (kill-switch). When off,
    /// uploaded blocks are NOT held locally until the cluster replicates them —
    /// `ipfs repo gc` can again delete un-replicated blocks.
    #[arg(long, env = "FULA_NO_LOCAL_RETAIN")]
    no_local_retain: bool,

    /// Disable the one-time startup backfill of pre-existing local blocks into
    /// the local-retain backlog (the ongoing per-upload protection still runs).
    #[arg(long, env = "FULA_NO_LOCAL_RETAIN_BACKFILL")]
    no_local_retain_backfill: bool,

    /// Phase 2 (decentralized ingress): accept empty-body chunk PUTs carrying
    /// x-amz-meta-fula-remote-cid (bytes pre-stored on a fula-ingest node).
    /// Advertised to clients via GET /fula/capabilities. Default OFF.
    #[arg(long, env = "FULA_REMOTE_CID_PUT")]
    remote_cid_put: bool,
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
        rate_limit_rps: args.rate_limit_rps,
        rate_limit_burst: args.rate_limit_burst,
        admin_jwt_secret: args.admin_jwt_secret,
        admin_api_enabled: args.admin_api,
        block_cache_mb: args.block_cache_mb,
        cluster_fallback_enabled: if args.no_cluster_fallback { Some(false) } else { None },
        cluster_peering_enabled: if args.no_cluster_peering { Some(false) } else { None },
        local_retain_enabled: if args.no_local_retain { Some(false) } else { None },
        local_retain_backfill: if args.no_local_retain_backfill { Some(false) } else { None },
        remote_cid_put_enabled: args.remote_cid_put,
        ..Default::default()
    };

    // Run the server
    run_server(config).await
}
