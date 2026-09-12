//! IPFS Cluster client for pinning and replication management

use crate::{BlockStoreError, Result};
use cid::Cid;
use reqwest::{Client, multipart};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::instrument;

/// Configuration for IPFS Cluster connection
#[derive(Clone, Debug)]
pub struct ClusterConfig {
    /// Cluster API URL (e.g., "http://localhost:9094")
    pub api_url: String,
    /// Request timeout
    pub timeout: Duration,
    /// Basic auth credentials (optional)
    pub basic_auth: Option<(String, String)>,
    /// Replication settings
    pub replication: ReplicationFactor,
}

impl Default for ClusterConfig {
    fn default() -> Self {
        Self {
            api_url: "http://localhost:9094".to_string(),
            timeout: Duration::from_secs(60),
            basic_auth: None,
            replication: ReplicationFactor::default(),
        }
    }
}

impl ClusterConfig {
    /// Create with a custom API URL
    pub fn with_url(api_url: impl Into<String>) -> Self {
        Self {
            api_url: api_url.into(),
            ..Default::default()
        }
    }

    /// Set basic auth credentials
    pub fn with_auth(mut self, username: impl Into<String>, password: impl Into<String>) -> Self {
        self.basic_auth = Some((username.into(), password.into()));
        self
    }
}

/// Replication factor settings
#[derive(Clone, Copy, Debug)]
pub struct ReplicationFactor {
    /// Minimum number of replicas
    pub min: i32,
    /// Maximum number of replicas (-1 for all peers)
    pub max: i32,
}

impl Default for ReplicationFactor {
    fn default() -> Self {
        Self { min: 2, max: 3 }
    }
}

impl ReplicationFactor {
    /// Create with specific min/max
    pub fn new(min: i32, max: i32) -> Self {
        Self { min, max }
    }

    /// Replicate to all peers
    pub fn all() -> Self {
        Self { min: -1, max: -1 }
    }
}

/// Pin status in the cluster
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PinStatus {
    /// Pin is being processed
    Pinning,
    /// Pin is complete
    Pinned,
    /// Pin failed
    Error,
    /// Pin is queued
    Queued,
    /// Unpin in progress
    Unpinning,
    /// Not pinned
    Unpinned,
    /// Status unknown
    Unknown,
}

impl Default for PinStatus {
    fn default() -> Self {
        Self::Unknown
    }
}

/// Locate the next COMPLETE newline-delimited line in `buf` starting at `from`.
///
/// Returns `(start, end, next_from)` where `buf[start..end]` is the line with
/// its terminator stripped (CRLF as well as bare LF), and `next_from` is where
/// scanning should resume. `None` means no complete line remains — the tail is
/// a partial line that must wait for more bytes.
///
/// Split out from the streaming reader because this is the part that is easy to
/// get subtly wrong: a line that straddles two network chunks, a `\r` that ends
/// up alone at a chunk boundary, an empty line, or a final line with no
/// terminator at all. Pure and allocation-free so it can be tested directly.
fn next_ndjson_line(buf: &[u8], from: usize) -> Option<(usize, usize, usize)> {
    if from >= buf.len() {
        return None;
    }
    let offset = buf[from..].iter().position(|&b| b == b'\n')?;
    let end = from + offset;
    let trimmed = if end > from && buf[end - 1] == b'\r' {
        end - 1
    } else {
        end
    };
    Some((from, trimmed, end + 1))
}

/// IPFS Cluster client
#[derive(Clone)]
pub struct ClusterClient {
    client: Client,
    config: ClusterConfig,
}

impl ClusterClient {
    /// Create a new cluster client
    pub async fn new(config: ClusterConfig) -> Result<Self> {
        // Disable idle connection pooling for the same reason as
        // `IpfsBlockStore::build_client`: a stale pooled keep-alive connection
        // to the cluster API blocks the next request until the timeout. A fresh
        // connection per request avoids reusing a dead socket.
        let builder = Client::builder()
            .timeout(config.timeout)
            .pool_max_idle_per_host(0);

        let client = builder
            .build()
            .map_err(|e| BlockStoreError::Connection(e.to_string()))?;

        let cluster = Self { client, config };
        cluster.verify_connection().await?;
        Ok(cluster)
    }

    /// Create with default config
    pub async fn default_local() -> Result<Self> {
        Self::new(ClusterConfig::default()).await
    }

    /// Verify connection to cluster
    pub async fn verify_connection(&self) -> Result<()> {
        let url = format!("{}/id", self.config.api_url);
        let mut req = self.client.get(&url);
        
        if let Some((user, pass)) = &self.config.basic_auth {
            req = req.basic_auth(user, Some(pass));
        }

        req.send()
            .await
            .map_err(|e| BlockStoreError::Connection(format!("Failed to connect to cluster: {}", e)))?;
        Ok(())
    }

    /// Get cluster peer info
    pub async fn peer_info(&self) -> Result<ClusterPeerInfo> {
        let url = format!("{}/id", self.config.api_url);
        let mut req = self.client.get(&url);
        
        if let Some((user, pass)) = &self.config.basic_auth {
            req = req.basic_auth(user, Some(pass));
        }

        let response = req.send().await?;
        
        if !response.status().is_success() {
            return Err(BlockStoreError::ClusterApi(format!(
                "Failed to get peer info: {}",
                response.status()
            )));
        }

        response
            .json()
            .await
            .map_err(|e| BlockStoreError::ClusterApi(e.to_string()))
    }

    /// List all peers in the cluster
    pub async fn list_peers(&self) -> Result<Vec<ClusterPeerInfo>> {
        let url = format!("{}/peers", self.config.api_url);
        let mut req = self.client.get(&url);
        
        if let Some((user, pass)) = &self.config.basic_auth {
            req = req.basic_auth(user, Some(pass));
        }

        let response = req.send().await?;
        
        if !response.status().is_success() {
            return Err(BlockStoreError::ClusterApi(format!(
                "Failed to list peers: {}",
                response.status()
            )));
        }

        // ipfs-cluster streams `/peers` as newline-delimited JSON (one peer
        // object per line), NOT a single JSON array — so `.json()` fails with
        // "error decoding response body". Accept both shapes: try an array
        // first, then parse line-by-line, tolerating the occasional
        // unparseable peer so one bad entry can't kill peering/locate.
        let text = response.text().await?;
        if let Ok(arr) = serde_json::from_str::<Vec<ClusterPeerInfo>>(&text) {
            return Ok(arr);
        }
        let mut peers = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            match serde_json::from_str::<ClusterPeerInfo>(line) {
                Ok(peer) => peers.push(peer),
                Err(e) => {
                    tracing::debug!(error = %e, "list_peers: skipping unparseable peer line")
                }
            }
        }
        Ok(peers)
    }

    /// Pin a CID in the cluster with the configured replication factor.
    #[instrument(skip(self))]
    pub async fn pin_cid(&self, cid: &Cid, name: Option<&str>) -> Result<PinInfo> {
        self.pin_cid_with_replication(
            cid,
            name,
            self.config.replication.min,
            self.config.replication.max,
        )
        .await
    }

    /// Pin a CID in the cluster with an EXPLICIT replication factor, overriding
    /// the configured default for this one pin. Used for the small but
    /// resilience-critical users-index objects (global root + per-user
    /// bucketsIndex), which warrant wider replication than ordinary data blocks
    /// so they survive the master going down. Other pins keep the configured
    /// factor (they call `pin_cid`).
    #[instrument(skip(self))]
    pub async fn pin_cid_with_replication(
        &self,
        cid: &Cid,
        name: Option<&str>,
        replication_min: i32,
        replication_max: i32,
    ) -> Result<PinInfo> {
        let mut url = format!(
            "{}/pins/{}?replication-min={}&replication-max={}",
            self.config.api_url, cid, replication_min, replication_max
        );

        if let Some(n) = name {
            url.push_str(&format!("&name={}", urlencoding::encode(n)));
        }

        let mut req = self.client.post(&url);

        if let Some((user, pass)) = &self.config.basic_auth {
            req = req.basic_auth(user, Some(pass));
        }

        let response = req.send().await?;

        if !response.status().is_success() {
            let error = response.text().await.unwrap_or_default();
            return Err(BlockStoreError::PinFailed(format!(
                "Failed to pin {}: {}",
                cid, error
            )));
        }

        response
            .json()
            .await
            .map_err(|e| BlockStoreError::ClusterApi(e.to_string()))
    }

    /// Unpin a CID from the cluster
    #[instrument(skip(self))]
    pub async fn unpin_cid(&self, cid: &Cid) -> Result<PinInfo> {
        let url = format!("{}/pins/{}", self.config.api_url, cid);
        let mut req = self.client.delete(&url);
        
        if let Some((user, pass)) = &self.config.basic_auth {
            req = req.basic_auth(user, Some(pass));
        }

        let response = req.send().await?;
        
        if !response.status().is_success() {
            let error = response.text().await.unwrap_or_default();
            return Err(BlockStoreError::UnpinFailed(format!(
                "Failed to unpin {}: {}",
                cid, error
            )));
        }

        response
            .json()
            .await
            .map_err(|e| BlockStoreError::ClusterApi(e.to_string()))
    }

    /// Get pin status for a CID
    pub async fn get_pin_status(&self, cid: &Cid) -> Result<PinInfo> {
        let url = format!("{}/pins/{}", self.config.api_url, cid);
        let mut req = self.client.get(&url);
        
        if let Some((user, pass)) = &self.config.basic_auth {
            req = req.basic_auth(user, Some(pass));
        }

        let response = req.send().await?;
        
        if !response.status().is_success() {
            if response.status().as_u16() == 404 {
                return Err(BlockStoreError::NotFound(*cid));
            }
            let error = response.text().await.unwrap_or_default();
            return Err(BlockStoreError::ClusterApi(format!(
                "Failed to get pin status: {}",
                error
            )));
        }

        response
            .json()
            .await
            .map_err(|e| BlockStoreError::ClusterApi(e.to_string()))
    }

    /// Count cluster peers that report status **exactly `"pinned"`** for `cid`,
    /// excluding `exclude_peer` (the master's own cluster peer id).
    ///
    /// Used by the local-retain verifier to decide a block is durably
    /// replicated *elsewhere* so the master can drop its local copy. Counts
    /// ONLY confirmed `"pinned"` — never `"pinning"`/`"queued"`/`"error"`, and
    /// never the `allocations` fallback — so the unpin decision can't fire
    /// before real replication. The safety invariant of the whole mechanism
    /// rides on this method: it must under-count, never over-count.
    pub async fn pinned_holder_count(&self, cid: &Cid, exclude_peer: &str) -> Result<usize> {
        let info = self.get_pin_status(cid).await?;
        Ok(info
            .peer_map
            .as_ref()
            .map(|m| {
                m.iter()
                    .filter(|(id, st)| {
                        id.as_str() != exclude_peer && st.status.eq_ignore_ascii_case("pinned")
                    })
                    .count()
            })
            .unwrap_or(0))
    }

    /// List all pins
    pub async fn list_pins(&self) -> Result<Vec<PinInfo>> {
        let url = format!("{}/pins", self.config.api_url);
        let mut req = self.client.get(&url);
        
        if let Some((user, pass)) = &self.config.basic_auth {
            req = req.basic_auth(user, Some(pass));
        }

        let response = req.send().await?;
        
        if !response.status().is_success() {
            let error = response.text().await.unwrap_or_default();
            return Err(BlockStoreError::ClusterApi(format!(
                "Failed to list pins: {}",
                error
            )));
        }

        // The response is newline-delimited JSON
        let text = response.text().await?;
        let mut pins = Vec::new();
        
        for line in text.lines() {
            if !line.is_empty() {
                let pin: PinInfo = serde_json::from_str(line)
                    .map_err(|e| BlockStoreError::ClusterApi(e.to_string()))?;
                pins.push(pin);
            }
        }

        Ok(pins)
    }

    /// List all pin ALLOCATIONS (the pinset definitions: cid + name + holder
    /// peers). Much faster than [`Self::list_pins`] for large pinsets —
    /// `GET /pins` aggregates per-peer status across the whole cluster (slow at
    /// 100k+ pins), whereas `GET /allocations` returns just the pin specs.
    #[deprecated(
        note = "buffers the ENTIRE pinset (1.17 GiB / 2.1M pins in production) as one String \
                plus a Vec, which ratchets RSS until the container is OOM-killed. \
                Use `for_each_allocation_batch`, which streams."
    )]
    pub async fn list_allocations(&self) -> Result<Vec<PinAllocation>> {
        let url = format!("{}/allocations", self.config.api_url);
        let mut req = self.client.get(&url);

        if let Some((user, pass)) = &self.config.basic_auth {
            req = req.basic_auth(user, Some(pass));
        }

        let response = req.send().await?;

        if !response.status().is_success() {
            let error = response.text().await.unwrap_or_default();
            return Err(BlockStoreError::ClusterApi(format!(
                "Failed to list allocations: {}",
                error
            )));
        }

        // Newline-delimited JSON, one pin spec per line. Unknown fields
        // (replication factors, allocations, timestamps, …) are ignored by
        // serde so each line parses cheaply into just cid + name.
        let text = response.text().await?;
        let mut out = Vec::new();
        for line in text.lines() {
            if !line.is_empty() {
                let p: PinAllocation = serde_json::from_str(line)
                    .map_err(|e| BlockStoreError::ClusterApi(e.to_string()))?;
                out.push(p);
            }
        }

        Ok(out)
    }

    /// Maximum length of a single NDJSON line before we refuse to keep
    /// buffering. A well-formed pin spec is a few hundred bytes; anything
    /// approaching this means the response is not what we think it is, and
    /// buffering it unbounded is how a parser becomes a memory bug.
    const MAX_ALLOCATION_LINE_BYTES: usize = 1024 * 1024;

    /// Stream `/allocations` in fixed-size batches instead of materialising it.
    ///
    /// [`ClusterClient::list_allocations`] buffers the ENTIRE newline-delimited
    /// body as one `String` and then a `Vec` of every pin. On the production
    /// cluster that body is **1.17 GiB across 2.1M pins**, so each call briefly
    /// holds well over a gigabyte — and because the allocator does not hand
    /// freed arenas back to the OS, RSS ratchets upward every cycle until the
    /// container hits its memory cap and is OOM-killed. Measured on the live
    /// host: a kill every ~25 minutes, i.e. every couple of reconcile passes.
    ///
    /// This keeps only the current batch plus one partial line alive, so peak
    /// memory is a few hundred KB however large the pinset grows. Returns the
    /// number of pin specs streamed.
    pub async fn for_each_allocation_batch<F, Fut>(
        &self,
        batch_size: usize,
        mut on_batch: F,
    ) -> Result<usize>
    where
        F: FnMut(Vec<PinAllocation>) -> Fut,
        Fut: std::future::Future<Output = std::result::Result<(), String>>,
    {
        use futures::StreamExt;

        let batch_size = batch_size.max(1);
        let url = format!("{}/allocations", self.config.api_url);
        let mut req = self.client.get(&url);
        if let Some((user, pass)) = &self.config.basic_auth {
            req = req.basic_auth(user, Some(pass));
        }

        let response = req.send().await?;
        if !response.status().is_success() {
            let error = response.text().await.unwrap_or_default();
            return Err(BlockStoreError::ClusterApi(format!(
                "Failed to list allocations: {}",
                error
            )));
        }

        // Unknown fields are ignored by serde, so a line costs only cid + name.
        fn parse_line(line: &[u8]) -> Result<Option<PinAllocation>> {
            if line.is_empty() {
                return Ok(None);
            }
            serde_json::from_slice::<PinAllocation>(line)
                .map(Some)
                .map_err(|e| BlockStoreError::ClusterApi(e.to_string()))
        }

        let mut stream = response.bytes_stream();
        let mut pending: Vec<u8> = Vec::new();
        let mut batch: Vec<PinAllocation> = Vec::with_capacity(batch_size);
        let mut total = 0usize;

        while let Some(chunk) = stream.next().await {
            pending.extend_from_slice(&chunk?);

            let mut start = 0usize;
            while let Some((line_start, line_end, next)) = next_ndjson_line(&pending, start) {
                if let Some(pin) = parse_line(&pending[line_start..line_end])? {
                    batch.push(pin);
                    total += 1;
                    if batch.len() >= batch_size {
                        on_batch(std::mem::take(&mut batch))
                            .await
                            .map_err(BlockStoreError::ClusterApi)?;
                        batch.reserve(batch_size);
                    }
                }
                start = next;
            }
            pending.drain(..start);

            if pending.len() > Self::MAX_ALLOCATION_LINE_BYTES {
                return Err(BlockStoreError::ClusterApi(format!(
                    "allocations stream: single line exceeded {} bytes",
                    Self::MAX_ALLOCATION_LINE_BYTES
                )));
            }
        }

        // A final line with no trailing newline.
        let tail = std::mem::take(&mut pending);
        let tail_slice = if tail.last() == Some(&b'\r') {
            &tail[..tail.len() - 1]
        } else {
            &tail[..]
        };
        if let Some(pin) = parse_line(tail_slice)? {
            batch.push(pin);
            total += 1;
        }
        if !batch.is_empty() {
            on_batch(batch).await.map_err(BlockStoreError::ClusterApi)?;
        }

        Ok(total)
    }

    /// Add and pin data in one operation
    #[instrument(skip(self, data), fields(size = data.len()))]
    pub async fn add_and_pin(&self, data: &[u8], name: Option<&str>) -> Result<AddPinResponse> {
        let mut url = format!(
            "{}/add?replication-min={}&replication-max={}&cid-version=1",
            self.config.api_url,
            self.config.replication.min,
            self.config.replication.max
        );

        if let Some(n) = name {
            url.push_str(&format!("&name={}", urlencoding::encode(n)));
        }

        let part = multipart::Part::bytes(data.to_vec())
            .file_name("data")
            .mime_str("application/octet-stream")
            .map_err(|e| BlockStoreError::ClusterApi(e.to_string()))?;

        let form = multipart::Form::new().part("file", part);

        let mut req = self.client.post(&url).multipart(form);
        
        if let Some((user, pass)) = &self.config.basic_auth {
            req = req.basic_auth(user, Some(pass));
        }

        let response = req.send().await?;
        
        if !response.status().is_success() {
            let error = response.text().await.unwrap_or_default();
            return Err(BlockStoreError::ClusterApi(format!(
                "Failed to add and pin: {}",
                error
            )));
        }

        response
            .json()
            .await
            .map_err(|e| BlockStoreError::ClusterApi(e.to_string()))
    }

    /// Recover a pin (re-trigger pinning on failed peers)
    pub async fn recover_pin(&self, cid: &Cid) -> Result<PinInfo> {
        let url = format!("{}/pins/{}/recover", self.config.api_url, cid);
        let mut req = self.client.post(&url);
        
        if let Some((user, pass)) = &self.config.basic_auth {
            req = req.basic_auth(user, Some(pass));
        }

        let response = req.send().await?;
        
        if !response.status().is_success() {
            let error = response.text().await.unwrap_or_default();
            return Err(BlockStoreError::ClusterApi(format!(
                "Failed to recover pin: {}",
                error
            )));
        }

        response
            .json()
            .await
            .map_err(|e| BlockStoreError::ClusterApi(e.to_string()))
    }
}

/// Cluster peer information
#[derive(Clone, Debug, Deserialize)]
pub struct ClusterPeerInfo {
    pub id: String,
    pub addresses: Vec<String>,
    pub cluster_peers: Option<Vec<String>>,
    pub cluster_peers_addresses: Option<Vec<String>>,
    pub version: Option<String>,
    pub commit: Option<String>,
    pub peername: Option<String>,
    #[serde(default)]
    pub ipfs: Option<IpfsPeerInfo>,
}

/// IPFS peer info within cluster
#[derive(Clone, Debug, Deserialize)]
pub struct IpfsPeerInfo {
    pub id: Option<String>,
    pub addresses: Option<Vec<String>>,
}

/// Pin information
#[derive(Clone, Debug, Deserialize)]
pub struct PinInfo {
    pub cid: String,
    pub name: Option<String>,
    pub allocations: Option<Vec<String>>,
    pub origins: Option<Vec<String>>,
    pub created: Option<String>,
    pub metadata: Option<serde_json::Value>,
    pub peer_map: Option<std::collections::HashMap<String, PeerPinStatus>>,
}

/// A single pin allocation spec from `GET /allocations` (the pinset
/// definition). Only the fields the recovery mirror needs are kept; serde
/// ignores the rest (replication factors, holder peers, timestamps, …).
#[derive(Clone, Debug, Deserialize)]
pub struct PinAllocation {
    /// Content CID (base32 string).
    pub cid: String,
    /// Pin name — the storage_key / `object:<bucket>/<key>` set at upload.
    #[serde(default)]
    pub name: Option<String>,
}

/// Per-peer pin status
#[derive(Clone, Debug, Deserialize)]
pub struct PeerPinStatus {
    pub peername: Option<String>,
    pub status: String,
    pub timestamp: Option<String>,
    pub error: Option<String>,
}

/// Response from add and pin
#[derive(Clone, Debug, Deserialize)]
pub struct AddPinResponse {
    pub name: String,
    pub cid: String,
    pub size: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = ClusterConfig::default();
        assert_eq!(config.api_url, "http://localhost:9094");
        assert!(config.basic_auth.is_none());
    }

    /// Collect every complete line the way the streaming reader does, so these
    /// exercise the real loop shape rather than a re-implementation.
    fn drain(buf: &mut Vec<u8>) -> Vec<String> {
        let mut out = Vec::new();
        let mut start = 0usize;
        while let Some((s, e, next)) = next_ndjson_line(buf, start) {
            out.push(String::from_utf8_lossy(&buf[s..e]).into_owned());
            start = next;
        }
        buf.drain(..start);
        out
    }

    #[test]
    fn ndjson_splits_plain_lines_and_keeps_the_partial_tail() {
        let mut buf = b"{\"a\":1}\n{\"b\":2}\n{\"c\"".to_vec();
        assert_eq!(drain(&mut buf), vec!["{\"a\":1}", "{\"b\":2}"]);
        // The incomplete third line must survive for the next chunk.
        assert_eq!(buf, b"{\"c\"".to_vec());
    }

    #[test]
    fn ndjson_reassembles_a_line_split_across_chunks() {
        // The failure mode that matters: a pin spec straddling two network
        // chunks must not be dropped or truncated.
        let mut buf = Vec::new();
        buf.extend_from_slice(b"{\"cid\":\"bafy");
        assert!(drain(&mut buf).is_empty(), "no complete line yet");
        buf.extend_from_slice(b"aaa\",\"name\":\"k\"}\n");
        assert_eq!(drain(&mut buf), vec!["{\"cid\":\"bafyaaa\",\"name\":\"k\"}"]);
        assert!(buf.is_empty());
    }

    #[test]
    fn ndjson_handles_crlf_including_a_lone_cr_at_a_chunk_boundary() {
        let mut buf = b"{\"a\":1}\r\n{\"b\":2}\r".to_vec();
        assert_eq!(drain(&mut buf), vec!["{\"a\":1}"]);
        // The dangling \r belongs to an unterminated line; it must be kept.
        assert_eq!(buf, b"{\"b\":2}\r".to_vec());
        buf.extend_from_slice(b"\n");
        assert_eq!(drain(&mut buf), vec!["{\"b\":2}"]);
    }

    #[test]
    fn ndjson_yields_empty_lines_for_the_caller_to_skip() {
        // Blank lines are legal filler in NDJSON; the reader skips them when
        // parsing, but the splitter must still advance past them.
        let mut buf = b"\n{\"a\":1}\n\n".to_vec();
        assert_eq!(drain(&mut buf), vec!["", "{\"a\":1}", ""]);
        assert!(buf.is_empty());
    }

    #[test]
    fn ndjson_reports_nothing_for_an_unterminated_final_line() {
        // The reader handles this tail explicitly after the stream ends;
        // the splitter must NOT hand it over early.
        let mut buf = b"{\"a\":1}".to_vec();
        assert!(drain(&mut buf).is_empty());
        assert_eq!(buf, b"{\"a\":1}".to_vec());
    }

    #[test]
    fn ndjson_is_byte_exact_across_every_possible_chunk_split() {
        // Feed the same payload one byte at a time and assert we recover the
        // identical set of lines — the property that makes chunk boundaries
        // irrelevant.
        let payload = b"{\"cid\":\"a\",\"name\":\"x\"}\n{\"cid\":\"b\",\"name\":\"y\"}\n{\"cid\":\"c\",\"name\":\"z\"}\n";
        let mut buf = Vec::new();
        let mut got = Vec::new();
        for byte in payload.iter() {
            buf.push(*byte);
            got.extend(drain(&mut buf));
        }
        assert_eq!(
            got,
            vec![
                "{\"cid\":\"a\",\"name\":\"x\"}",
                "{\"cid\":\"b\",\"name\":\"y\"}",
                "{\"cid\":\"c\",\"name\":\"z\"}",
            ]
        );
        assert!(buf.is_empty(), "nothing left pending");
    }

    #[test]
    fn ndjson_parses_a_real_allocation_line_into_cid_and_name() {
        // Unknown fields (allocations, replication factors, timestamps) must
        // be ignored so a line costs only cid + name.
        let line = br#"{"cid":"bafkr4ictest","name":"website-assets/foo.jpg","allocations":["12D3Koo"],"replication_factor_min":2,"replication_factor_max":3,"created":"2026-09-12T00:00:00Z"}"#;
        let pin: PinAllocation = serde_json::from_slice(line).expect("parses");
        assert_eq!(pin.cid, "bafkr4ictest");
        assert_eq!(pin.name.as_deref(), Some("website-assets/foo.jpg"));
    }

    #[test]
    fn test_config_with_auth() {
        let config = ClusterConfig::with_url("http://cluster:9094")
            .with_auth("user", "pass");
        assert_eq!(config.basic_auth, Some(("user".to_string(), "pass".to_string())));
    }

    #[test]
    fn test_replication_factor() {
        let default = ReplicationFactor::default();
        assert_eq!(default.min, 2);
        assert_eq!(default.max, 3);

        let all = ReplicationFactor::all();
        assert_eq!(all.min, -1);
        assert_eq!(all.max, -1);
    }

    #[test]
    fn test_pin_status_default() {
        let status = PinStatus::default();
        assert_eq!(status, PinStatus::Unknown);
    }

    #[tokio::test]
    async fn list_peers_parses_ndjson_stream() {
        use httpmock::prelude::*;
        use serde_json::json;

        let server = MockServer::start_async().await;
        server
            .mock_async(|when, then| {
                when.method(GET).path("/id");
                then.status(200).body("{}");
            })
            .await;

        // ipfs-cluster `/peers` shape: one peer object per line (NDJSON), each
        // carrying the kubo daemon under `ipfs`.
        let line1 = json!({
            "id": "clusterA", "addresses": [],
            "ipfs": { "id": "kuboA", "addresses": ["/ip4/1.2.3.4/tcp/4001"] }
        })
        .to_string();
        let line2 = json!({
            "id": "clusterB", "addresses": [],
            "ipfs": { "id": "kuboB", "addresses": ["/ip4/5.6.7.8/tcp/4001"] }
        })
        .to_string();
        let ndjson = format!("{}\n{}\n", line1, line2);
        server
            .mock_async(move |when, then| {
                when.method(GET).path("/peers");
                then.status(200).body(ndjson.clone());
            })
            .await;

        let client = ClusterClient::new(ClusterConfig::with_url(server.base_url()))
            .await
            .unwrap();
        let peers = client.list_peers().await.unwrap();

        assert_eq!(peers.len(), 2);
        assert_eq!(peers[0].ipfs.as_ref().unwrap().id.as_deref(), Some("kuboA"));
        assert_eq!(
            peers[1].ipfs.as_ref().unwrap().addresses.as_ref().unwrap()[0],
            "/ip4/5.6.7.8/tcp/4001"
        );
    }

    async fn allocations_server(body: String) -> httpmock::MockServer {
        use httpmock::prelude::*;
        let server = MockServer::start_async().await;
        server
            .mock_async(|when, then| {
                when.method(GET).path("/id");
                then.status(200).body("{}");
            })
            .await;
        server
            .mock_async(move |when, then| {
                when.method(GET).path("/allocations");
                then.status(200).body(body.clone());
            })
            .await;
        server
    }

    fn alloc_line(cid: &str, name: &str) -> String {
        serde_json::json!({
            "cid": cid,
            "name": name,
            "allocations": ["12D3KooWtest"],
            "replication_factor_min": 2,
            "replication_factor_max": 3,
        })
        .to_string()
    }

    #[tokio::test]
    async fn for_each_allocation_batch_batches_and_streams_everything() {
        // 2500 pins at a batch size of 1000 → 1000 / 1000 / 500, and every pin
        // accounted for. The production pinset is 2.1M, so the batching is the
        // whole point: only one batch is ever resident.
        let body: String = (0..2500)
            .map(|i| format!("{}\n", alloc_line(&format!("bafy{i}"), &format!("key/{i}"))))
            .collect();
        let server = allocations_server(body).await;
        let client = ClusterClient::new(ClusterConfig::with_url(server.base_url()))
            .await
            .unwrap();

        let mut sizes = Vec::new();
        let mut seen = Vec::new();
        let total = client
            .for_each_allocation_batch(1000, |batch| {
                sizes.push(batch.len());
                for p in &batch {
                    seen.push(p.cid.clone());
                }
                async { Ok(()) }
            })
            .await
            .unwrap();

        assert_eq!(total, 2500);
        assert_eq!(sizes, vec![1000, 1000, 500]);
        assert_eq!(seen.len(), 2500);
        assert_eq!(seen[0], "bafy0");
        assert_eq!(seen[2499], "bafy2499");
    }

    #[tokio::test]
    async fn for_each_allocation_batch_skips_blank_lines_and_a_missing_final_newline() {
        let body = format!(
            "{}\n\n{}",
            alloc_line("bafyA", "a"),
            alloc_line("bafyB", "b") // no trailing newline
        );
        let server = allocations_server(body).await;
        let client = ClusterClient::new(ClusterConfig::with_url(server.base_url()))
            .await
            .unwrap();

        let mut seen = Vec::new();
        let total = client
            .for_each_allocation_batch(1000, |batch| {
                for p in &batch {
                    seen.push(p.cid.clone());
                }
                async { Ok(()) }
            })
            .await
            .unwrap();

        assert_eq!(total, 2, "blank line skipped, unterminated last line kept");
        assert_eq!(seen, vec!["bafyA".to_string(), "bafyB".to_string()]);
    }

    #[tokio::test]
    async fn for_each_allocation_batch_aborts_when_the_callback_fails() {
        // A DB failure mid-stream must stop the sweep and surface, not be
        // silently swallowed while the remaining batches keep writing.
        let body: String = (0..3000)
            .map(|i| format!("{}\n", alloc_line(&format!("bafy{i}"), &format!("k{i}"))))
            .collect();
        let server = allocations_server(body).await;
        let client = ClusterClient::new(ClusterConfig::with_url(server.base_url()))
            .await
            .unwrap();

        let mut calls = 0usize;
        let err = client
            .for_each_allocation_batch(1000, |_batch| {
                calls += 1;
                let fail = calls == 2;
                async move {
                    if fail {
                        Err("upsert failed: boom".to_string())
                    } else {
                        Ok(())
                    }
                }
            })
            .await
            .unwrap_err();

        assert!(format!("{err}").contains("boom"), "got: {err}");
        assert_eq!(calls, 2, "stopped at the failing batch");
    }

    #[tokio::test]
    async fn for_each_allocation_batch_reports_an_http_error() {
        use httpmock::prelude::*;
        let server = MockServer::start_async().await;
        server
            .mock_async(|when, then| {
                when.method(GET).path("/id");
                then.status(200).body("{}");
            })
            .await;
        server
            .mock_async(|when, then| {
                when.method(GET).path("/allocations");
                then.status(500).body("cluster exploded");
            })
            .await;

        let client = ClusterClient::new(ClusterConfig::with_url(server.base_url()))
            .await
            .unwrap();
        let err = client
            .for_each_allocation_batch(1000, |_b| async { Ok(()) })
            .await
            .unwrap_err();
        assert!(format!("{err}").contains("Failed to list allocations"), "got: {err}");
    }
}
