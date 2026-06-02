//! Proactive peering: keep the gateway's kubo connected to every cluster IPFS
//! peer so bitswap can fetch any block fast (the durable half of the
//! cluster-aware read story; the per-request locate in
//! `fula_blockstore::cluster_fallback` is the targeted fallback).
//!
//! Periodically pulls the fleet peer list from the cluster API and hands each
//! peer to kubo's `swarm/peering/add` subsystem, which then *maintains* and
//! auto-reconnects the connection natively. Best-effort and self-healing —
//! tolerates the cluster or kubo being down and retries next cycle.

use crate::config::GatewayConfig;
use fula_blockstore::{ClusterClient, ClusterConfig, IpfsBlockStore, IpfsConfig};
use futures::StreamExt;
use std::time::Duration;
use tracing::{debug, info, warn};

/// Per-`swarm/peering/add` timeout (it just registers the peer with kubo; the
/// actual dial is maintained asynchronously by kubo, so this returns fast).
const PEERING_ADD_TIMEOUT: Duration = Duration::from_secs(5);
/// Cluster API timeout for the periodic `list_peers`.
const CLUSTER_TIMEOUT: Duration = Duration::from_secs(10);
/// Max concurrent `swarm/peering/add` calls per cycle.
const MAX_CONCURRENT: usize = 16;

/// Spawn the background peering loop when enabled. Returns immediately.
///
/// Enabled when `cluster_peering_enabled` is `Some(true)`, or `None` (auto) and
/// a real IPFS store + cluster URL are configured. `Some(false)` disables it.
pub fn spawn_if_enabled(config: &GatewayConfig) {
    let enabled = config.cluster_peering_enabled.unwrap_or_else(|| {
        !config.use_memory_store && !config.cluster_url.trim().is_empty()
    });
    if !enabled {
        return;
    }

    let cluster_url = config.cluster_url.clone();
    let ipfs_url = config.ipfs_url.clone();
    let interval = Duration::from_secs(config.cluster_peering_interval_secs.max(15));

    info!(
        interval_secs = config.cluster_peering_interval_secs,
        cluster_url = %cluster_url,
        "Cluster proactive-peering task enabled"
    );

    tokio::spawn(async move {
        run_loop(cluster_url, ipfs_url, interval).await;
    });
}

async fn run_loop(cluster_url: String, ipfs_url: String, interval: Duration) {
    let ipfs = match IpfsBlockStore::new_unverified(IpfsConfig::with_url(&ipfs_url)) {
        Ok(handle) => handle,
        Err(e) => {
            warn!(error = %e, "peering: failed to build kubo client; peering disabled");
            return;
        }
    };
    let cluster_cfg = ClusterConfig {
        timeout: CLUSTER_TIMEOUT,
        ..ClusterConfig::with_url(&cluster_url)
    };

    loop {
        peer_once(&ipfs, &cluster_cfg).await;
        tokio::time::sleep(interval).await;
    }
}

async fn peer_once(ipfs: &IpfsBlockStore, cluster_cfg: &ClusterConfig) {
    // Rebuild each cycle so a cluster that was down at startup is picked up
    // once it comes back (ClusterClient::new verifies the connection cheaply).
    let cluster = match ClusterClient::new(cluster_cfg.clone()).await {
        Ok(c) => c,
        Err(e) => {
            debug!(error = %e, "peering: cluster unreachable this cycle");
            return;
        }
    };
    let peers = match cluster.list_peers().await {
        Ok(p) => p,
        Err(e) => {
            debug!(error = %e, "peering: list_peers failed this cycle");
            return;
        }
    };

    let mut addrs: Vec<String> = Vec::new();
    for peer in &peers {
        if let Some(ipfs_info) = &peer.ipfs {
            if let (Some(id), Some(list)) = (&ipfs_info.id, &ipfs_info.addresses) {
                for addr in list {
                    if is_dialable(addr) {
                        addrs.push(format!("{}/p2p/{}", addr, id));
                    }
                }
            }
        }
    }

    let total = addrs.len();
    if total == 0 {
        return;
    }

    let connected = futures::stream::iter(addrs)
        .map(|addr| {
            let ipfs = ipfs.clone();
            async move { ipfs.swarm_peering_add(&addr, PEERING_ADD_TIMEOUT).await }
        })
        .buffer_unordered(MAX_CONCURRENT)
        .filter(|ok| futures::future::ready(*ok))
        .count()
        .await;

    debug!(
        peers = peers.len(),
        addrs = total,
        connected,
        "peering: refreshed fleet peering"
    );
}

/// Skip loopback / unspecified multiaddrs; keep public + LAN + relay addresses.
fn is_dialable(addr: &str) -> bool {
    !addr.contains("/127.0.0.1/")
        && !addr.contains("/::1/")
        && !addr.contains("/0.0.0.0/")
        && !addr.contains("/::/")
}
