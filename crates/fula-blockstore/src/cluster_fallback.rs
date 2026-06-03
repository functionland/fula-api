//! Cluster-aware read fallback for the gateway block store.
//!
//! ## Why
//! The gateway stores blocks on its local kubo (incidentally, unpinned) and
//! pins them to the ipfs-cluster (replicated across the fleet). When the local
//! copies are garbage-collected, plain `block/get`/`cat` blind-bitswaps and
//! stalls to the 30s client timeout. This layer makes reads fast and bounded:
//!
//!   1. **Instant local probe** (`offline=true`) — classifies local-hit vs miss
//!      in milliseconds, never paying the 30s bitswap timeout.
//!   2. **Short bounded online fetch** — a peered holder (kept connected by the
//!      proactive-peering task) answers in well under a second.
//!   3. **Targeted cluster fallback** — on miss, ask the cluster *which* peers
//!      hold the exact CID (`get_pin_status` → `list_peers` for their kubo
//!      multiaddrs), `swarm/connect` them, then do one bounded online fetch.
//!
//! It implements **both** `get_block` and `get_ipld` (separate code paths in
//! kubo) and **delegates every other method** unchanged, so it cannot change
//! CIDs, encryption, pinning, or any write/upload behaviour. Content is
//! CID-verified by kubo regardless of which peer serves it.

use crate::cluster::{ClusterClient, ClusterPeerInfo, PinInfo};
use crate::ipfs::IpfsBlockStore;
use crate::ipfs_pinning::FlexibleBlockStore;
use crate::{BlockStore, BlockStoreError, PinStore, Result};
use async_trait::async_trait;
use bytes::Bytes;
use cid::Cid;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;
use tracing::debug;

/// dag-pb codec — a UnixFS file root that `cat` reassembles from chunks. A
/// bounded `cat` is a whole-download timeout (it buffers the full object), so
/// these must NOT use the short small-block probe.
const DAG_PB_CODEC: u64 = 0x70;

/// Tunables for the cluster-aware read fallback. All durations bound a single
/// sub-step; the read path is `offline → online_fast → (locate+connect) →
/// online_slow`, so the worst case is their sum and is kept under the gateway's
/// outer request timeout (and never worse than today's 30s for an actually
/// unreachable block).
#[derive(Clone, Debug)]
pub struct ClusterFallbackConfig {
    /// Local-only probe (`offline=true`) — should return near-instantly.
    pub offline_timeout: Duration,
    /// First online attempt for SMALL blocks (raw/dag-cbor index + object
    /// blocks); a peered holder answers fast, so a cold block falls through to
    /// the cluster locate quickly. NOT used for dag-pb files.
    pub online_fast_timeout: Duration,
    /// Online retry for SMALL blocks after connecting to located holders.
    pub online_slow_timeout: Duration,
    /// Generous total budget for a dag-pb FILE download (`cat` buffers the
    /// whole object), matching the gateway's prior single-attempt behaviour.
    pub file_download_timeout: Duration,
    /// Per cluster API call (`get_pin_status` / `list_peers`).
    pub status_timeout: Duration,
    /// Per `swarm/connect`.
    pub connect_timeout: Duration,
    /// TTL for the cached `list_peers()` map.
    pub peers_ttl: Duration,
    /// Max holder peers to connect to per miss.
    pub max_holders: usize,
    /// Max dialable addresses to try per holder (bounds connect fanout).
    pub max_addrs_per_holder: usize,
    /// Global cap on concurrent `swarm/connect` operations.
    pub max_concurrent_connects: usize,
}

impl Default for ClusterFallbackConfig {
    fn default() -> Self {
        // Tuned for FAST failure on a genuinely-unavailable block: peering keeps
        // live holders connected so a real fetch answers in <1s, so a lost small
        // block now fails in roughly offline(instant miss) + fast 2 + status 3 +
        // slow 4 ≈ 6–8s instead of ~18s. All three online timeouts are env-
        // overridable at the gateway (`FULA_READ_{FAST,SLOW,FILE}_TIMEOUT_SECS`)
        // so this can be tuned in prod without a rebuild. dag-pb FILES skip the
        // short steps and get one generous `cat` (file_download_timeout).
        Self {
            offline_timeout: Duration::from_secs(2),
            online_fast_timeout: Duration::from_secs(2),
            online_slow_timeout: Duration::from_secs(4),
            file_download_timeout: Duration::from_secs(30),
            status_timeout: Duration::from_secs(3),
            connect_timeout: Duration::from_secs(3),
            peers_ttl: Duration::from_secs(60),
            max_holders: 5,
            max_addrs_per_holder: 4,
            max_concurrent_connects: 16,
        }
    }
}

/// Read layer that wraps an inner `FlexibleBlockStore` (the normal IPFS+pinning
/// store) and adds the bounded/peered/cluster-locate fallback to `get_block`
/// and `get_ipld`. Every other operation delegates straight to `inner`.
pub struct ClusterFallbackBlockStore {
    /// The normal store — used verbatim for puts, pins, deletes, stats.
    inner: Box<FlexibleBlockStore>,
    /// A direct handle to the same kubo for the bounded/offline/swarm calls
    /// (the LRU cache, if any, wraps *us* from the outside).
    ipfs: IpfsBlockStore,
    cluster: ClusterClient,
    cfg: ClusterFallbackConfig,
    peers_cache: parking_lot::Mutex<Option<(Instant, Arc<Vec<ClusterPeerInfo>>)>>,
    connect_sema: Arc<Semaphore>,
}

impl ClusterFallbackBlockStore {
    pub fn new(
        inner: Box<FlexibleBlockStore>,
        ipfs: IpfsBlockStore,
        cluster: ClusterClient,
        cfg: ClusterFallbackConfig,
    ) -> Self {
        let connect_sema = Arc::new(Semaphore::new(cfg.max_concurrent_connects.max(1)));
        Self {
            inner,
            ipfs,
            cluster,
            cfg,
            peers_cache: parking_lot::Mutex::new(None),
            connect_sema,
        }
    }

    /// Recurse into the wrapped store for persistence reporting.
    pub fn inner_is_persistent(&self) -> bool {
        self.inner.is_persistent()
    }

    /// `get_block` with the bounded/peered/cluster-locate fallback.
    async fn get_block_fallback(&self, cid: &Cid) -> Result<Bytes> {
        // 1. Instant local-only probe (small blocks and file roots alike). A
        //    clean HTTP miss (`NotFound`) means the daemon is up and the block
        //    just isn't local; a transport error means the daemon may be down.
        let responsive = match self.ipfs.get_block_offline(cid, self.cfg.offline_timeout).await {
            Ok(bytes) => return Ok(bytes),
            Err(BlockStoreError::NotFound(_)) => true,
            Err(e) => {
                debug!(cid = %cid, error = %e, "cluster-fallback: offline probe errored (daemon may be down)");
                false
            }
        };

        // dag-pb roots are UnixFS FILES: `cat` buffers the whole object, so a
        // short timeout would cap the *download* (not probe connectivity). Give
        // them one generous streamed fetch — peering keeps the holder connected;
        // running them through the short small-block probe below would wrongly
        // time out any file that takes more than `online_fast_timeout` to stream.
        if cid.codec() == DAG_PB_CODEC {
            return self
                .ipfs
                .get_block_online_bounded(cid, self.cfg.file_download_timeout)
                .await
                .map_err(|e| classify_exhaustion(cid, responsive, e));
        }

        // Small blocks (raw / dag-cbor index + object blocks): a peered holder
        // answers fast; otherwise locate the holders, connect, and retry.
        if let Ok(bytes) = self.ipfs.get_block_online_bounded(cid, self.cfg.online_fast_timeout).await {
            return Ok(bytes);
        }
        self.ensure_holders_connected(cid).await;
        self.ipfs
            .get_block_online_bounded(cid, self.cfg.online_slow_timeout)
            .await
            .map_err(|e| classify_exhaustion(cid, responsive, e))
    }

    /// `get_ipld` with the same three-step fallback (raw single-block path).
    async fn get_ipld_fallback<T: serde::de::DeserializeOwned>(&self, cid: &Cid) -> Result<T> {
        let bytes = self.get_ipld_bytes_fallback(cid).await?;
        serde_ipld_dagcbor::from_slice(&bytes)
            .map_err(|e| BlockStoreError::Deserialization(e.to_string()))
    }

    async fn get_ipld_bytes_fallback(&self, cid: &Cid) -> Result<Bytes> {
        let responsive = match self.ipfs.get_raw_block_offline(cid, self.cfg.offline_timeout).await {
            Ok(bytes) => return Ok(bytes),
            Err(BlockStoreError::NotFound(_)) => true,
            Err(e) => {
                debug!(cid = %cid, error = %e, "cluster-fallback: ipld offline probe errored (daemon may be down)");
                false
            }
        };
        if let Ok(bytes) = self.ipfs.get_raw_block_online_bounded(cid, self.cfg.online_fast_timeout).await {
            return Ok(bytes);
        }
        self.ensure_holders_connected(cid).await;
        self.ipfs
            .get_raw_block_online_bounded(cid, self.cfg.online_slow_timeout)
            .await
            .map_err(|e| classify_exhaustion(cid, responsive, e))
    }

    /// Best-effort: ask the cluster which peers hold `cid` and `swarm/connect`
    /// the gateway kubo to them, so the subsequent bitswap fetch is from a live
    /// connection. Never errors; degrades to a no-op when the cluster is
    /// unreachable, the CID isn't tracked, or no dialable addrs are known.
    async fn ensure_holders_connected(&self, cid: &Cid) {
        // Note: sequential re-reads of the same CID are absorbed by the LRU
        // cache that wraps this layer from the outside, and cross-block
        // amortization across a tree traversal comes from step-2 succeeding
        // once a holder is connected — so no per-CID de-dup cache is needed
        // here. Connects are idempotent (kubo dedups) and capped by the
        // semaphore, so concurrent misses can't storm.

        // Which cluster peers hold it?
        let holders = match tokio::time::timeout(
            self.cfg.status_timeout,
            self.cluster.get_pin_status(cid),
        )
        .await
        {
            Ok(Ok(info)) => holder_peer_ids(&info),
            Ok(Err(e)) => {
                debug!(cid = %cid, error = %e, "cluster-fallback: get_pin_status failed");
                return;
            }
            Err(_) => {
                debug!(cid = %cid, "cluster-fallback: get_pin_status timed out");
                return;
            }
        };
        if holders.is_empty() {
            return;
        }

        // Map cluster-peer-id -> kubo dialable multiaddrs (cached peer list).
        let peers = match self.cached_list_peers().await {
            Some(p) => p,
            None => return,
        };
        let mut addrs: Vec<String> = Vec::new();
        for holder in holders.iter().take(self.cfg.max_holders) {
            if let Some(peer) = peers.iter().find(|p| &p.id == holder) {
                if let Some(ipfs) = &peer.ipfs {
                    if let (Some(id), Some(list)) = (&ipfs.id, &ipfs.addresses) {
                        for addr in list
                            .iter()
                            .filter(|a| is_dialable(a))
                            .take(self.cfg.max_addrs_per_holder)
                        {
                            addrs.push(format!("{}/p2p/{}", addr, id));
                        }
                    }
                }
            }
        }
        if addrs.is_empty() {
            return;
        }

        debug!(cid = %cid, holders = holders.len(), addrs = addrs.len(), "cluster-fallback: connecting to holders");

        // Connect concurrently, best-effort, capped by the semaphore.
        let futures_iter = addrs.into_iter().map(|addr| {
            let ipfs = self.ipfs.clone();
            let sema = Arc::clone(&self.connect_sema);
            let timeout = self.cfg.connect_timeout;
            async move {
                let _permit = sema.acquire_owned().await.ok();
                ipfs.swarm_connect(&addr, timeout).await
            }
        });
        let _ = futures::future::join_all(futures_iter).await;
    }

    /// `list_peers()` with a short TTL cache; falls back to a stale cached copy
    /// if a refresh fails, so a transient cluster blip doesn't disable locating.
    async fn cached_list_peers(&self) -> Option<Arc<Vec<ClusterPeerInfo>>> {
        let now = Instant::now();
        {
            let guard = self.peers_cache.lock();
            if let Some((stamped, peers)) = guard.as_ref() {
                if now.duration_since(*stamped) < self.cfg.peers_ttl {
                    return Some(Arc::clone(peers));
                }
            }
        }
        match tokio::time::timeout(self.cfg.status_timeout, self.cluster.list_peers()).await {
            Ok(Ok(peers)) => {
                let arc = Arc::new(peers);
                *self.peers_cache.lock() = Some((now, Arc::clone(&arc)));
                Some(arc)
            }
            _ => self.peers_cache.lock().as_ref().map(|(_, p)| Arc::clone(p)),
        }
    }
}

/// Map the final bounded-fetch error to `Unavailable` (→ HTTP 410) when the
/// local daemon was responsive (the offline probe was a clean HTTP miss) and
/// the failure is a *retrieval* failure (`Timeout`/`NotFound`) — i.e. the block
/// is genuinely unavailable, not the daemon being down. Infrastructure errors
/// (`Connection`/`IpfsApi`/…) and the not-responsive case pass through unchanged
/// so they stay 5xx and the client SDK's health gate still trips on real
/// master/kubo outages.
fn classify_exhaustion(cid: &Cid, responsive: bool, e: BlockStoreError) -> BlockStoreError {
    if responsive
        && matches!(
            e,
            BlockStoreError::Timeout { .. } | BlockStoreError::NotFound(_)
        )
    {
        BlockStoreError::Unavailable(*cid)
    } else {
        e
    }
}

/// Cluster peers that report `pinned` for a CID (fall back to `allocations`).
fn holder_peer_ids(info: &PinInfo) -> Vec<String> {
    if let Some(map) = &info.peer_map {
        let pinned: Vec<String> = map
            .iter()
            .filter(|(_, status)| status.status.eq_ignore_ascii_case("pinned"))
            .map(|(id, _)| id.clone())
            .collect();
        if !pinned.is_empty() {
            return pinned;
        }
    }
    info.allocations.clone().unwrap_or_default()
}

/// Skip loopback / unspecified multiaddrs (dialing them from the gateway is
/// pointless); keep public + private-LAN + relay (`p2p-circuit`) addresses.
fn is_dialable(addr: &str) -> bool {
    !addr.contains("/127.0.0.1/")
        && !addr.contains("/::1/")
        && !addr.contains("/0.0.0.0/")
        && !addr.contains("/::/")
}

#[async_trait]
impl BlockStore for ClusterFallbackBlockStore {
    async fn put_block(&self, data: &[u8]) -> Result<Cid> {
        self.inner.as_ref().put_block(data).await
    }

    async fn get_block(&self, cid: &Cid) -> Result<Bytes> {
        self.get_block_fallback(cid).await
    }

    async fn has_block(&self, cid: &Cid) -> Result<bool> {
        self.inner.as_ref().has_block(cid).await
    }

    async fn delete_block(&self, cid: &Cid) -> Result<()> {
        self.inner.as_ref().delete_block(cid).await
    }

    async fn block_size(&self, cid: &Cid) -> Result<u64> {
        self.inner.as_ref().block_size(cid).await
    }

    async fn put_ipld<T: serde::Serialize + Send + Sync>(&self, data: &T) -> Result<Cid> {
        self.inner.as_ref().put_ipld(data).await
    }

    async fn get_ipld<T: serde::de::DeserializeOwned>(&self, cid: &Cid) -> Result<T> {
        self.get_ipld_fallback(cid).await
    }
}

#[async_trait]
impl PinStore for ClusterFallbackBlockStore {
    async fn pin(&self, cid: &Cid, name: Option<&str>) -> Result<()> {
        self.inner.as_ref().pin(cid, name).await
    }

    async fn pin_with_token(&self, cid: &Cid, name: Option<&str>, token: &str) -> Result<()> {
        self.inner.as_ref().pin_with_token(cid, name, token).await
    }

    async fn unpin(&self, cid: &Cid) -> Result<()> {
        self.inner.as_ref().unpin(cid).await
    }

    async fn is_pinned(&self, cid: &Cid) -> Result<bool> {
        self.inner.as_ref().is_pinned(cid).await
    }

    async fn list_pins(&self) -> Result<Vec<Cid>> {
        self.inner.as_ref().list_pins().await
    }

    async fn pin_status(&self, cid: &Cid) -> Result<crate::PinStatus> {
        self.inner.as_ref().pin_status(cid).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster::{PeerPinStatus, PinInfo};
    use crate::memory::MemoryBlockStore;
    use crate::{ClusterConfig, IpfsConfig};
    use httpmock::prelude::*;
    use serde_json::json;
    use std::collections::HashMap;

    const RAW_CID: &str = "bafkreigh2akiscaildc6v5q2xg34x5sqo5djznnha64x4jn3fjvu3j6jci";

    async fn build(kubo_url: &str, cluster_url: &str) -> ClusterFallbackBlockStore {
        let ipfs = IpfsBlockStore::new_unverified(IpfsConfig::with_url(kubo_url)).unwrap();
        let cluster = ClusterClient::new(ClusterConfig::with_url(cluster_url))
            .await
            .unwrap();
        let inner = Box::new(FlexibleBlockStore::Memory(MemoryBlockStore::new()));
        ClusterFallbackBlockStore::new(inner, ipfs, cluster, ClusterFallbackConfig::default())
    }

    #[test]
    fn is_dialable_filters_loopback_and_unspecified() {
        assert!(is_dialable("/ip4/5.6.7.8/tcp/4001"));
        assert!(is_dialable("/ip4/192.168.1.2/tcp/4001")); // LAN kept
        assert!(!is_dialable("/ip4/127.0.0.1/tcp/4001"));
        assert!(!is_dialable("/ip6/::1/tcp/4001"));
        assert!(!is_dialable("/ip4/0.0.0.0/tcp/4001"));
    }

    #[test]
    fn classify_exhaustion_maps_only_responsive_retrieval_failures() {
        let cid: Cid = RAW_CID.parse().unwrap();
        // Daemon responsive (clean offline miss) + a *retrieval* failure → the
        // block is genuinely unavailable → Unavailable (gateway maps to 410).
        assert!(matches!(
            classify_exhaustion(&cid, true, BlockStoreError::Timeout { seconds: 12 }),
            BlockStoreError::Unavailable(_)
        ));
        assert!(matches!(
            classify_exhaustion(&cid, true, BlockStoreError::NotFound(cid)),
            BlockStoreError::Unavailable(_)
        ));
        // Responsive but an *infrastructure* failure (kubo erroring / unreachable)
        // → pass through unchanged → stays 5xx so the health gate still trips.
        assert!(matches!(
            classify_exhaustion(&cid, true, BlockStoreError::Connection("x".into())),
            BlockStoreError::Connection(_)
        ));
        assert!(matches!(
            classify_exhaustion(&cid, true, BlockStoreError::IpfsApi("x".into())),
            BlockStoreError::IpfsApi(_)
        ));
        // Daemon NOT responsive (probe failed → maybe down) → pass through even a
        // Timeout, so a real master outage is NOT masked as a per-file 410.
        assert!(matches!(
            classify_exhaustion(&cid, false, BlockStoreError::Timeout { seconds: 12 }),
            BlockStoreError::Timeout { .. }
        ));
    }

    #[test]
    fn holder_peer_ids_prefers_pinned_then_allocations() {
        let mut map = HashMap::new();
        map.insert(
            "a".to_string(),
            PeerPinStatus { peername: None, status: "pinned".into(), timestamp: None, error: None },
        );
        map.insert(
            "b".to_string(),
            PeerPinStatus { peername: None, status: "pinning".into(), timestamp: None, error: None },
        );
        let info = PinInfo {
            cid: RAW_CID.into(),
            name: None,
            allocations: Some(vec!["x".into()]),
            origins: None,
            created: None,
            metadata: None,
            peer_map: Some(map),
        };
        assert_eq!(holder_peer_ids(&info), vec!["a".to_string()]);

        // No peer_map → fall back to allocations.
        let info2 = PinInfo {
            cid: RAW_CID.into(),
            name: None,
            allocations: Some(vec!["x".into(), "y".into()]),
            origins: None,
            created: None,
            metadata: None,
            peer_map: None,
        };
        let mut holders = holder_peer_ids(&info2);
        holders.sort();
        assert_eq!(holders, vec!["x".to_string(), "y".to_string()]);
    }

    #[tokio::test]
    async fn local_hit_returns_without_touching_cluster() {
        let kubo = MockServer::start_async().await;
        let cluster = MockServer::start_async().await;
        cluster
            .mock_async(|when, then| {
                when.method(GET).path("/id");
                then.status(200).body("{}");
            })
            .await;
        let pins = cluster
            .mock_async(|when, then| {
                when.method(GET).path(format!("/pins/{}", RAW_CID));
                then.status(200).json_body(json!({ "cid": RAW_CID }));
            })
            .await;
        let block_get = kubo
            .mock_async(|when, then| {
                when.method(POST).path("/api/v0/block/get");
                then.status(200).body("hello");
            })
            .await;

        let store = build(&kubo.base_url(), &cluster.base_url()).await;
        let cid: Cid = RAW_CID.parse().unwrap();
        let data = store.get_block(&cid).await.expect("get block");

        assert_eq!(&data[..], b"hello");
        block_get.assert_hits_async(1).await; // only the offline probe
        pins.assert_hits_async(0).await; // cluster never consulted on a local hit
    }

    #[tokio::test]
    async fn hard_miss_triggers_cluster_locate_and_connect() {
        let kubo = MockServer::start_async().await;
        let cluster = MockServer::start_async().await;
        cluster
            .mock_async(|when, then| {
                when.method(GET).path("/id");
                then.status(200).body("{}");
            })
            .await;
        // Every block/get (offline probe, online-fast, online-slow) fails.
        kubo.mock_async(|when, then| {
            when.method(POST).path("/api/v0/block/get");
            then.status(500).body("nope");
        })
        .await;
        let pins = cluster
            .mock_async(|when, then| {
                when.method(GET).path(format!("/pins/{}", RAW_CID));
                then.status(200).json_body(json!({
                    "cid": RAW_CID,
                    "peer_map": { "clusterA": { "status": "pinned" } }
                }));
            })
            .await;
        let peers = cluster
            .mock_async(|when, then| {
                when.method(GET).path("/peers");
                then.status(200).json_body(json!([{
                    "id": "clusterA",
                    "addresses": [],
                    "ipfs": { "id": "12D3KooTEST", "addresses": ["/ip4/5.6.7.8/tcp/4001"] }
                }]));
            })
            .await;
        let connect = kubo
            .mock_async(|when, then| {
                when.method(POST).path("/api/v0/swarm/connect");
                then.status(200).body("{}");
            })
            .await;

        let store = build(&kubo.base_url(), &cluster.base_url()).await;
        let cid: Cid = RAW_CID.parse().unwrap();
        let result = store.get_block(&cid).await;

        assert!(result.is_err(), "all fetches fail → error");
        pins.assert_hits_async(1).await;
        peers.assert_hits_async(1).await;
        connect.assert_hits_async(1).await; // connected to the located holder
    }

    #[tokio::test]
    async fn get_ipld_local_hit_decodes() {
        let kubo = MockServer::start_async().await;
        let cluster = MockServer::start_async().await;
        cluster
            .mock_async(|when, then| {
                when.method(GET).path("/id");
                then.status(200).body("{}");
            })
            .await;
        let body = serde_ipld_dagcbor::to_vec(&42u64).unwrap();
        kubo.mock_async(move |when, then| {
            when.method(POST).path("/api/v0/block/get");
            then.status(200).body(body.clone());
        })
        .await;

        let store = build(&kubo.base_url(), &cluster.base_url()).await;
        let cid: Cid = RAW_CID.parse().unwrap();
        let value: u64 = store.get_ipld(&cid).await.expect("get ipld");
        assert_eq!(value, 42);
    }
}
