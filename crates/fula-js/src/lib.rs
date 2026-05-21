//! # Fula JS
//!
//! JavaScript/TypeScript SDK for Fula decentralized storage.
//!
//! This crate provides WASM bindings for browser-based applications
//! using wasm-bindgen. It wraps the fula-client and fula-crypto crates
//! with a clean JavaScript API.
//!
//! ## Usage
//!
//! ```javascript
//! import init, { createEncryptedClient, getDecrypted, deriveKey } from '@functionland/fula-client';
//!
//! await init();
//!
//! const secretKey = deriveKey('my-app-v1', new TextEncoder().encode(userId + email));
//! const client = await createEncryptedClient(
//!   { endpoint: 'https://gateway:9000', accessToken: jwt },
//!   { secretKey, obfuscationMode: 'flatNamespace' }
//! );
//!
//! const data = await getDecrypted(client, 'bucket', '/path/to/file');
//! ```

use wasm_bindgen::prelude::*;
use serde::{Serialize, Deserialize};
use std::sync::Arc;
use bytes::Bytes;

// Use async_lock for WASM (no tokio)
use futures::lock::Mutex;

// ============================================================================
// Initialization
// ============================================================================

/// Initialize the WASM module. Call this before any other functions.
#[wasm_bindgen(start)]
pub fn init() {
    console_error_panic_hook::set_once();
}

// ============================================================================
// Configuration Types (JS <-> Rust via serde)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsFulaConfig {
    /// Gateway endpoint URL (e.g., "https://gateway:9000")
    pub endpoint: String,
    /// JWT access token for authentication
    pub access_token: Option<String>,
    /// Request timeout in seconds (default: 30)
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,

    // ============================================================
    // Phase 2.1 — master-down detection (functional on wasm/web)
    // ============================================================
    /// Enable the SDK's master health gate. Off by default
    /// (backward-compat). When on, two consecutive failed master
    /// requests trip the gate and short-circuit subsequent reads
    /// with a `MASTER_UNREACHABLE` error. **Functional on wasm/web.**
    #[serde(default)]
    pub health_gate_enabled: bool,

    /// TTL of the `Down` state when `healthGateEnabled = true`.
    /// After this duration elapses, the next request is allowed
    /// through as a probe. Default: 30 seconds.
    #[serde(default = "default_health_gate_ttl")]
    pub health_gate_ttl_seconds: u64,

    // ============================================================
    // Phase 2.2 / 2.3 / 2.4 — block cache + gateway race
    // ============================================================
    //
    // These fields are NATIVE-ONLY at runtime. The underlying
    // `fula_client::Config` carries them across all builds, but on
    // the wasm32 target the SDK gates out the `redb`-backed cache
    // and the parking_lot-based gateway pool, so setting these
    // flags has no effect in browsers.
    //
    // We expose them anyway for **API symmetry** with `fula-flutter`:
    // a TypeScript app sharing config types between mobile and web
    // builds can construct one config object and have it accepted
    // by both. On web the offline path silently no-ops; on native
    // (Tauri / Electron-with-Rust / Node-via-N-API integrations) the
    // path activates as documented for fula-flutter.

    /// Enable the on-disk LRU block cache. **Native-only at runtime.**
    /// On wasm/web this flag is silently inert.
    #[serde(default)]
    pub block_cache_enabled: bool,

    /// Filesystem path for the block-cache redb database. Empty
    /// string = use platform default. **Native-only at runtime.**
    #[serde(default)]
    pub block_cache_path: String,

    /// Maximum on-disk bytes for the block cache. Default: 256 MiB.
    /// **Native-only at runtime.**
    #[serde(default = "default_block_cache_max_bytes")]
    pub block_cache_max_bytes: u64,

    /// Enable falling back to public IPFS gateways when master is
    /// unreachable. **Native-only at runtime.** Requires
    /// `blockCacheEnabled = true` to populate the `(bucket,key) → cid`
    /// lookup table the offline race needs.
    #[serde(default)]
    pub gateway_fallback_enabled: bool,

    /// Custom gateway URL templates. Each must contain the literal
    /// `{cid}` token. Empty Vec = use the SDK-shipped default list
    /// of six gateways (Cloudflare, dweb.link, ipfs.io,
    /// trustless-gateway.link, 4everland.io, gateway.pinata.cloud).
    /// **Native-only at runtime.**
    #[serde(default)]
    pub gateway_fallback_urls: Vec<String>,

    /// Number of gateways the SDK races in parallel. Default: 3.
    /// **Native-only at runtime.**
    #[serde(default = "default_gateway_race_concurrency")]
    pub gateway_race_concurrency: u32,

    // ============================================================
    // Phase 3.3 — cold-start hybrid resolver (native-only at runtime)
    // ============================================================
    //
    // The cold-start resolver itself is gated to native targets in
    // `fula-client` (the JSON-RPC eth_call + IPNS gateway race rely
    // on `reqwest` + `parking_lot` paths that aren't compiled on
    // wasm32). These fields are accepted on wasm for **API symmetry**
    // — a TS app sharing a config object across mobile + web can
    // pass them through unconditionally; the wasm build silently
    // disables cold-start. Apps that need offline reads on the web
    // still get Phase 2.1 (health gate + typed `MASTER_UNREACHABLE`
    // error); cold-start cross-device support is mobile-only today.

    /// JSON-RPC URL for the chain anchor (Base or SKALE). Empty =
    /// disabled. **Native-only at runtime.**
    #[serde(default)]
    pub users_index_chain_rpc_url: String,

    /// `FulaUsersIndexAnchor.sol` proxy address (20 bytes hex,
    /// optionally `0x`-prefixed). Empty = disabled. **Native-only
    /// at runtime.**
    #[serde(default)]
    pub users_index_anchor_address: String,

    /// IPNS NAME (libp2p public-key hash, e.g. `k51qzi5...`).
    /// Empty = disabled. **Native-only at runtime.**
    #[serde(default)]
    pub users_index_ipns_name: String,

    /// 32-hex-char `userKey` derived from the user's email via
    /// [`derive_user_key_from_email`]. Empty = disabled.
    /// **Native-only at runtime.**
    #[serde(default)]
    pub users_index_user_key: String,

    /// IPNS-aware gateway URL templates (each must contain `{name}`).
    /// Empty Vec = use SDK-shipped defaults. **Native-only at runtime.**
    #[serde(default)]
    pub users_index_ipns_gateway_urls: Vec<String>,

    /// `/ipfs/{cid}` gateway URL templates (each must contain `{cid}`).
    /// Empty Vec = use SDK-shipped 6-gateway default. **Native-only
    /// at runtime.**
    #[serde(default)]
    pub users_index_ipfs_gateway_urls: Vec<String>,

    // ============================================================
    // Walkable-v8 (W.9.3) — encrypted-tree CID stamping
    // ============================================================
    /// Emit walkable-v8 CID hints in HAMT internal-node pointers,
    /// manifest pages, dir-index, and forest file-index entries from
    /// master's PUT-response ETag (= `BLAKE3(ciphertext)` raw-codec).
    ///
    /// **#89 (2026-05-09): default flipped to `true`** per user
    /// decision ("when we roll out everyone will update"), mirroring
    /// `fula_client::Config::default()` and `FulaConfig::default()`
    /// (cross-platform parity is non-negotiable). Pre-v0.6 SDKs
    /// reading newly-written buckets surface `WireVersionUnsupported`
    /// (#81 typed variant; mapped to `WIRE_VERSION_UNSUPPORTED` JS
    /// error code via `client_error_to_js_error`).
    ///
    /// Each parsed CID is **self-verified** locally before being
    /// stamped: the SDK recomputes `BLAKE3(ciphertext)` and compares
    /// to the master-returned CID. On mismatch the SDK soft-fails to
    /// `None` (logging at warn, rate-limited per (bucket,key) per
    /// session) so a compromised master cannot redirect future
    /// offline walkers to attacker-controlled IPFS bytes.
    ///
    /// **Cross-platform.** Works identically on the wasm32 web target
    /// and on any native `fula_client::Config` consumer. Offline
    /// reading via these hints lands in W.9.4; today the writer just
    /// records them for a future reader.
    /// `#[serde(default = "default_walkable_v8_writer_enabled")]` so
    /// JSON omitting the field gets the post-#89 default of `true`.
    /// `#[serde(default)]` would fall back to `bool::default()` which
    /// is `false` and would silently drift from the Rust-side defaults.
    #[serde(default = "default_walkable_v8_writer_enabled")]
    pub walkable_v8_writer_enabled: bool,

    /// E2E plan Phase 5 — 32-byte AEAD key for encrypting the
    /// per-user bucketsIndex envelope (`K_index` in the plan; derived
    /// client-side from `KEK_seed` via BLAKE3). Empty `Vec` is
    /// treated as `None` and leaves the legacy plaintext path active
    /// (Mode A behavior preserved). Non-empty must be exactly 32
    /// bytes; the SDK validates and falls back to `None` on length
    /// mismatch.
    ///
    /// **Note**: on the wasm32 web target the `users_index_writer`
    /// module is not compiled (`#[cfg(not(target_arch = "wasm32"))]`),
    /// so this field is currently inert in fula-js. The field exists
    /// here for wire-format parity with `FulaConfig` (cross-platform
    /// parity is non-negotiable) and to keep the JSON config shape
    /// identical between native FxFiles and browser webui.
    #[serde(default)]
    pub encrypted_user_buckets_index_key: Vec<u8>,

    /// E2E plan Phase 5 — 32-byte Ed25519 seed for signing the
    /// global-CBOR per-user entry (`K_entry_seed` in the plan).
    /// Empty `Vec` leaves the signed-entry writer inert. Must be
    /// exactly 32 bytes when non-empty.
    ///
    /// Same wasm-inert caveat as `encrypted_user_buckets_index_key`
    /// — field present for cross-platform parity, currently no-op on
    /// the web target.
    #[serde(default)]
    pub user_entry_signing_seed: Vec<u8>,
}

fn default_timeout() -> u64 { 30 }
fn default_walkable_v8_writer_enabled() -> bool { true }
fn default_health_gate_ttl() -> u64 { 30 }
fn default_block_cache_max_bytes() -> u64 { 256 * 1024 * 1024 }
fn default_gateway_race_concurrency() -> u32 { 3 }

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsEncryptionConfig {
    /// 32-byte secret key (base64 encoded or Uint8Array). If null, generates new key.
    pub secret_key: Option<Vec<u8>>,
    /// Enable metadata privacy (obfuscate file names). Default: true
    #[serde(default = "default_true")]
    pub enable_metadata_privacy: bool,
    /// Obfuscation mode: "flatNamespace", "deterministic", "random", "preserveStructure"
    #[serde(default = "default_obfuscation")]
    pub obfuscation_mode: String,
}

fn default_true() -> bool { true }
fn default_obfuscation() -> String { "flatNamespace".to_string() }

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsListOptions {
    pub prefix: Option<String>,
    pub delimiter: Option<String>,
    pub max_keys: Option<u32>,
    pub continuation_token: Option<String>,
}

// ============================================================================
// Result Types (returned to JS)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsPutResult {
    pub etag: String,
    pub version_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsFileMetadata {
    pub storage_key: String,
    pub original_key: String,
    pub size: u64,
    pub content_type: Option<String>,
    pub created_at: Option<i64>,
    pub modified_at: Option<i64>,
    pub is_encrypted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsBucketInfo {
    pub name: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsDirectoryEntry {
    pub name: String,
    pub is_directory: bool,
    pub files: Vec<JsFileMetadata>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsDirectoryListing {
    pub bucket: String,
    pub prefix: Option<String>,
    pub entries: Vec<JsDirectoryEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsSharePermissions {
    pub can_read: bool,
    pub can_write: bool,
    pub expires_at: Option<i64>,
}

// ============================================================================
// Phase 19 — transparency types
// ============================================================================
//
// All three are `serde`-tagged enums / structs so JS sees an idiomatic
// shape:
//   ReadSource:   { kind: "Master" }
//                 { kind: "LocalCache" }
//                 { kind: "Gateway", url: "https://ipfs.io/ipfs/{cid}" }
//   ReadFreshness: { kind: "Live" }
//                  { kind: "Cached", observedAt: 1234567890 }
//                  { kind: "StaleByDesign", snapshotAgeSecs: 60 }
//                  { kind: "StaleByOutage", snapshotAgeSecs: 7200 }
//   MasterHealthEvent: same `kind` discriminant
// Apps `switch` on `result.source.kind` to drive UI.

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "kind")]
pub enum JsReadSource {
    Master,
    LocalCache,
    Gateway { url: String },
}

impl From<fula_client::ReadSource> for JsReadSource {
    fn from(s: fula_client::ReadSource) -> Self {
        match s {
            fula_client::ReadSource::Master => JsReadSource::Master,
            fula_client::ReadSource::LocalCache => JsReadSource::LocalCache,
            fula_client::ReadSource::Gateway(url) => JsReadSource::Gateway { url },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "kind")]
pub enum JsReadFreshness {
    Live,
    #[serde(rename_all = "camelCase")]
    Cached { observed_at: u64 },
    #[serde(rename_all = "camelCase")]
    StaleByDesign { snapshot_age_secs: u64 },
    #[serde(rename_all = "camelCase")]
    StaleByOutage { snapshot_age_secs: u64 },
}

impl From<fula_client::ReadFreshness> for JsReadFreshness {
    fn from(f: fula_client::ReadFreshness) -> Self {
        match f {
            fula_client::ReadFreshness::Live => JsReadFreshness::Live,
            fula_client::ReadFreshness::Cached { observed_at } => {
                JsReadFreshness::Cached { observed_at }
            }
            fula_client::ReadFreshness::StaleByDesign { snapshot_age_secs } => {
                JsReadFreshness::StaleByDesign { snapshot_age_secs }
            }
            fula_client::ReadFreshness::StaleByOutage { snapshot_age_secs } => {
                JsReadFreshness::StaleByOutage { snapshot_age_secs }
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsOfflineGetResult {
    /// Object data (bytes).
    pub data: Vec<u8>,
    /// ETag (CID string when bytes came from gateway race / cache;
    /// master-issued ETag when bytes came from master).
    pub etag: String,
    /// Content type if known (always `None` on offline-fallback paths
    /// today; master-served reads carry the response Content-Type).
    pub content_type: Option<String>,
    /// Object size in bytes.
    pub size: u64,
    /// Last-modified timestamp (Unix epoch seconds) if master served
    /// the bytes; 0 on offline-fallback paths.
    pub last_modified: i64,
    /// Where the bytes ultimately came from.
    pub source: JsReadSource,
    /// How fresh the bytes are.
    pub freshness: JsReadFreshness,
}

impl From<fula_client::OfflineGetResult> for JsOfflineGetResult {
    fn from(r: fula_client::OfflineGetResult) -> Self {
        let inner = r.inner;
        Self {
            data: inner.data.to_vec(),
            etag: inner.etag,
            content_type: inner.content_type,
            size: inner.content_length,
            last_modified: inner.last_modified.map(|d| d.timestamp()).unwrap_or(0),
            source: r.source.into(),
            freshness: r.freshness.into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", tag = "kind")]
pub enum JsMasterHealthEvent {
    Online,
    OfflineFallbackActive { reason: String },
    SeverelyDegraded { reason: String },
}

impl From<fula_client::MasterHealthEvent> for JsMasterHealthEvent {
    fn from(e: fula_client::MasterHealthEvent) -> Self {
        match e {
            fula_client::MasterHealthEvent::Online => JsMasterHealthEvent::Online,
            fula_client::MasterHealthEvent::OfflineFallbackActive { reason } => {
                JsMasterHealthEvent::OfflineFallbackActive { reason }
            }
            fula_client::MasterHealthEvent::SeverelyDegraded { reason } => {
                JsMasterHealthEvent::SeverelyDegraded { reason }
            }
        }
    }
}

// ============================================================================
// Client Handles (opaque types exposed to JS)
// ============================================================================

/// Phase 19 — wasm dispatcher capturing `MasterHealthEvent`
/// transitions for polling consumers. The Rust callback set on the
/// inner `Config::health_callback` pushes events here; JS apps drain
/// via `pollMasterHealthEvents` or read latest via
/// `getLastMasterHealthEvent`.
///
/// Buffer is bounded at 64 entries — apps that fall further behind
/// drop the oldest events (latest state is what UI cares about).
struct WasmHealthEventDispatcher {
    buffer: std::sync::Mutex<std::collections::VecDeque<JsMasterHealthEvent>>,
    last_event: std::sync::Mutex<Option<JsMasterHealthEvent>>,
}

const WASM_MAX_BUFFERED_EVENTS: usize = 64;

impl WasmHealthEventDispatcher {
    fn new() -> Self {
        Self {
            buffer: std::sync::Mutex::new(std::collections::VecDeque::new()),
            last_event: std::sync::Mutex::new(None),
        }
    }

    /// Called from the `health_callback` set on the inner Config.
    /// Captures the event for both polling drain + latest-state read.
    fn dispatch(&self, event: fula_client::MasterHealthEvent) {
        let app_event: JsMasterHealthEvent = event.into();
        if let Ok(mut last) = self.last_event.lock() {
            *last = Some(app_event.clone());
        }
        if let Ok(mut buf) = self.buffer.lock() {
            if buf.len() >= WASM_MAX_BUFFERED_EVENTS {
                buf.pop_front();
            }
            buf.push_back(app_event);
        }
    }

    fn drain_events(&self) -> Vec<JsMasterHealthEvent> {
        self.buffer
            .lock()
            .map(|mut buf| buf.drain(..).collect())
            .unwrap_or_default()
    }

    fn last_event(&self) -> Option<JsMasterHealthEvent> {
        self.last_event.lock().ok().and_then(|guard| guard.clone())
    }
}

/// Handle to an encrypted Fula client
#[wasm_bindgen]
pub struct EncryptedClient {
    inner: Arc<Mutex<fula_client::EncryptedClient>>,
    /// Phase 19 — per-client health-event dispatcher. Always present
    /// so apps can poll regardless of whether they wired
    /// `healthGateEnabled = true`. When the gate is off, the buffer
    /// stays empty (no events fire); polling returns `[]`.
    health_dispatcher: Arc<WasmHealthEventDispatcher>,
}

/// Handle to an accepted share for accessing shared files
#[wasm_bindgen]
pub struct AcceptedShare {
    inner: fula_crypto::AcceptedShare,
}

// ============================================================================
// Client Creation
// ============================================================================

/// Create an encrypted client for secure storage operations
///
/// @param config - Client configuration (endpoint, accessToken, etc.)
/// @param encryption - Encryption configuration (secretKey, obfuscationMode, etc.)
/// @returns EncryptedClient handle
#[wasm_bindgen(js_name = createEncryptedClient)]
pub async fn create_encrypted_client(
    config: JsValue,
    encryption: JsValue,
) -> Result<EncryptedClient, JsError> {
    let config: JsFulaConfig = serde_wasm_bindgen::from_value(config)
        .map_err(|e| JsError::new(&format!("Invalid config: {}", e)))?;
    let encryption: JsEncryptionConfig = serde_wasm_bindgen::from_value(encryption)
        .map_err(|e| JsError::new(&format!("Invalid encryption config: {}", e)))?;

    // Phase 19 dispatcher — created per client so events from one
    // EncryptedClient never leak to another's poll buffer.
    let dispatcher = Arc::new(WasmHealthEventDispatcher::new());
    // Build client config (callback wired to dispatcher).
    let client_config = build_inner_config(config, &dispatcher);

    // Build encryption config.
    //
    // `encryption.secret_key` is REQUIRED. fula derives every per-user identity
    // (X25519 keypair, content_encryption_key, userKey, bucket_lookup_h) from a
    // stable OAuth-derived seed; falling back to a random keypair (pre-0.7
    // behavior) silently locks the user out of every blob they previously
    // wrote. Surface the misconfiguration as a clean error instead.
    let secret_key = encryption
        .secret_key
        .as_ref()
        .ok_or_else(|| {
            JsError::new(
                "encryption.secretKey is required: derive a stable 32-byte SecretKey from \
                 your OAuth-stable seed (e.g. Argon2id(provider:rawSub:email)) and pass it \
                 via JsEncryptionConfig.secretKey. A random keypair would lock the user out \
                 of all previously-uploaded data on the next session restart.",
            )
        })?;
    if secret_key.len() != 32 {
        return Err(JsError::new("Secret key must be exactly 32 bytes"));
    }
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(secret_key);
    let secret = fula_crypto::SecretKey::from_bytes(&key_bytes)
        .map_err(|e| JsError::new(&format!("Invalid secret key: {}", e)))?;
    let enc_config = fula_client::EncryptionConfig::from_secret_key(secret);

    let enc_config = enc_config.with_metadata_privacy(encryption.enable_metadata_privacy);
    #[allow(deprecated)]
    let enc_config = match encryption.obfuscation_mode.as_str() {
        "deterministic" => enc_config.with_obfuscation_mode(fula_client::KeyObfuscation::DeterministicHash),
        "random" => enc_config.with_obfuscation_mode(fula_client::KeyObfuscation::RandomUuid),
        "preserveStructure" => enc_config.with_obfuscation_mode(fula_client::KeyObfuscation::PreserveStructure),
        _ => enc_config.with_obfuscation_mode(fula_client::KeyObfuscation::FlatNamespace), // Default
    };

    let client = fula_client::EncryptedClient::new(client_config, enc_config)
        .map_err(|e| client_error_to_js_error("create_client_failed", e))?;

    Ok(EncryptedClient {
        inner: Arc::new(Mutex::new(client)),
        health_dispatcher: dispatcher,
    })
}

// ============================================================================
// Phase 2.x helpers
// ============================================================================

/// Translate a Dart-flavoured `JsFulaConfig` into the underlying
/// `fula_client::Config`, plumbing every Phase 1.2 / 2.x / 3.3 / 19
/// field through. Used by every JS client constructor — adding a new
/// field means changing this function only.
///
/// `dispatcher` is the per-client Phase 19 dispatcher; the callback
/// wired into `Config::health_callback` forwards each transition to
/// it so JS apps can poll via `pollMasterHealthEvents`.
///
/// Note on wasm32: the block_cache + gateway_fallback + cold-start
/// resolver fields are silently inert at runtime (the underlying SDK
/// gates out the redb-backed cache, parking_lot-based pool, and
/// reqwest-based resolver). They're still plumbed through so a single
/// shared config struct works across native + web targets.
fn build_inner_config(
    config: JsFulaConfig,
    dispatcher: &Arc<WasmHealthEventDispatcher>,
) -> fula_client::Config {
    let mut inner = fula_client::Config::new(&config.endpoint)
        .with_timeout(std::time::Duration::from_secs(config.timeout_seconds));

    if let Some(token) = config.access_token {
        inner = inner.with_token(token);
    }

    // Phase 2.1 — health gate (functional on wasm).
    inner.health_gate_enabled = config.health_gate_enabled;
    inner.health_gate_ttl =
        std::time::Duration::from_secs(config.health_gate_ttl_seconds);

    // Phase 19 — wire forwarding callback into the gate. The callback
    // is `Arc<dyn Fn>` which lives entirely in Rust; it never crosses
    // the wasm-bindgen boundary (the wasm boundary is between Rust
    // and JS — the Arc<dyn Fn> stays inside Rust). HealthGate fires
    // it from `record_success` / `record_failure` regardless of target.
    let dispatcher_for_cb = Arc::clone(dispatcher);
    let cb: fula_client::HealthCallback = Arc::new(move |ev| {
        dispatcher_for_cb.dispatch(ev);
    });
    inner.health_callback = Some(cb);

    // Phase 2.2 — block cache (native-only at runtime; plumbed for symmetry).
    inner.block_cache_enabled = config.block_cache_enabled;
    inner.block_cache_path = if config.block_cache_path.is_empty() {
        None
    } else {
        Some(std::path::PathBuf::from(config.block_cache_path))
    };
    inner.block_cache_max_bytes = config.block_cache_max_bytes;

    // Phase 2.3 / 2.4 — gateway race (native-only at runtime).
    inner.gateway_fallback_enabled = config.gateway_fallback_enabled;
    inner.gateway_fallback_urls = config.gateway_fallback_urls;
    inner.gateway_race_concurrency = config.gateway_race_concurrency as usize;

    // Phase 3.3 — cold-start hybrid resolver (native-only at runtime;
    // plumbed for symmetry). Empty strings → resolver disabled (the
    // four required fields are all string-empty in JsFulaConfig's
    // Default impl-equivalent via `#[serde(default)]`).
    inner.users_index_chain_rpc_url = config.users_index_chain_rpc_url;
    inner.users_index_anchor_address = config.users_index_anchor_address;
    inner.users_index_ipns_name = config.users_index_ipns_name;
    inner.users_index_user_key = if config.users_index_user_key.is_empty() {
        None
    } else {
        Some(config.users_index_user_key)
    };
    inner.users_index_ipns_gateway_urls = config.users_index_ipns_gateway_urls;
    inner.users_index_ipfs_gateway_urls = config.users_index_ipfs_gateway_urls;

    // Walkable-v8 (W.9.3) — writer flag. Cross-platform: works on the
    // wasm32 web target identically to native. Default `false` keeps
    // writes byte-identical to v0.5; flipping `true` activates the
    // v8 wire surface. See `walkable_v8_writer_enabled` in
    // `JsFulaConfig` for the full self-verify rationale.
    inner.walkable_v8_writer_enabled = config.walkable_v8_writer_enabled;

    // E2E plan Phase 5 — encrypted bucketsIndex keys (plumbed for
    // cross-platform parity with `fula_client::Config` and
    // `FulaConfig` even though `users_index_writer` is not compiled
    // for the wasm32 target). Length-validated; falls back to `None`
    // on mismatch so a misconfigured webui doesn't break.
    inner.encrypted_user_buckets_index_key =
        if config.encrypted_user_buckets_index_key.len() == 32 {
            Some(config.encrypted_user_buckets_index_key)
        } else {
            None
        };
    inner.user_entry_signing_seed = if config.user_entry_signing_seed.len() == 32 {
        Some(config.user_entry_signing_seed)
    } else {
        None
    };

    inner
}

/// Convert a `fula_client::ClientError` into a `JsError` whose
/// message is a JSON object carrying a stable error `code` plus
/// any structured fields. JS callers can `JSON.parse(err.message)`
/// to dispatch on the code and surface it to UI logic — e.g.,
/// "show offline indicator" on `MASTER_UNREACHABLE` rather than
/// just a generic "download failed".
///
/// The set of codes is stable across native and wasm so apps can
/// share an error-handling layer.
fn client_error_to_js_error(operation: &str, e: fula_client::ClientError) -> JsError {
    use fula_client::ClientError;

    // Compose stable code + human-readable message.
    let (code, structured) = match &e {
        ClientError::MasterUnreachable { down_for_secs } => (
            "MASTER_UNREACHABLE",
            serde_json::json!({ "downForSecs": down_for_secs }),
        ),
        ClientError::BlockTooLarge { size, budget } => (
            "BLOCK_TOO_LARGE",
            serde_json::json!({ "size": size, "budget": budget }),
        ),
        ClientError::BlockCache(_) => ("BLOCK_CACHE_ERROR", serde_json::json!(null)),
        ClientError::UsersIndexResolutionFailed { reason } => (
            "USERS_INDEX_RESOLUTION_FAILED",
            serde_json::json!({ "reason": reason }),
        ),
        ClientError::SequenceRegression { observed, highest_seen, channel } => (
            "SEQUENCE_REGRESSION",
            serde_json::json!({
                "observed": observed,
                "highestSeen": highest_seen,
                "channel": channel,
            }),
        ),
        ClientError::NotFound { bucket, key } => (
            "NOT_FOUND",
            serde_json::json!({ "bucket": bucket, "key": key }),
        ),
        ClientError::BucketNotFound(name) => (
            "BUCKET_NOT_FOUND",
            serde_json::json!({ "name": name }),
        ),
        ClientError::AccessDenied(_) => ("ACCESS_DENIED", serde_json::json!(null)),
        ClientError::ConcurrentModification(_)
        | ClientError::ConcurrentModificationExhausted { .. } => {
            ("CONCURRENT_MODIFICATION", serde_json::json!(null))
        }
        ClientError::MigrationLockHeld { bucket, expires_at } => (
            "MIGRATION_LOCK_HELD",
            serde_json::json!({ "bucket": bucket, "expiresAt": expires_at }),
        ),
        ClientError::Encryption(_) => ("ENCRYPTION", serde_json::json!(null)),
        // #81 (2026-05-09) — typed wire-version-skew variant. Without
        // this arm the variant falls through to the `_` wildcard and
        // surfaces as "INTERNAL", defeating the telemetry-stability
        // purpose of the typed variant. Mirrors fula-flutter's
        // `error_code()` returning "WIRE_VERSION_UNSUPPORTED".
        ClientError::WireVersionUnsupported {
            context,
            postcard_error,
        } => (
            "WIRE_VERSION_UNSUPPORTED",
            serde_json::json!({
                "context": context,
                "postcardError": postcard_error,
            }),
        ),
        ClientError::Http(_) => ("HTTP", serde_json::json!(null)),
        _ => ("INTERNAL", serde_json::json!(null)),
    };

    let payload = serde_json::json!({
        "code": code,
        "operation": operation,
        "message": e.to_string(),
        "data": structured,
    });
    JsError::new(&payload.to_string())
}

// ============================================================================
// Encrypted Operations
// ============================================================================

/// Upload encrypted data
///
/// @param client - EncryptedClient handle
/// @param bucket - Bucket name
/// @param key - Object key (path)
/// @param data - Data to upload (Uint8Array)
/// @returns PutResult with etag
#[wasm_bindgen(js_name = putEncrypted)]
pub async fn put_encrypted(
    client: &EncryptedClient,
    bucket: &str,
    key: &str,
    data: &[u8],
) -> Result<JsValue, JsError> {
    let guard = client.inner.lock().await;
    let result = guard.put_object_encrypted(bucket, key, Bytes::from(data.to_vec()))
        .await
        .map_err(|e| JsError::new(&format!("Upload failed: {}", e)))?;

    let js_result = JsPutResult {
        etag: result.etag,
        version_id: result.version_id,
    };
    serde_wasm_bindgen::to_value(&js_result)
        .map_err(|e| JsError::new(&format!("Serialization error: {}", e)))
}

/// Upload encrypted data with content type
#[wasm_bindgen(js_name = putEncryptedWithType)]
pub async fn put_encrypted_with_type(
    client: &EncryptedClient,
    bucket: &str,
    key: &str,
    data: &[u8],
    content_type: &str,
) -> Result<JsValue, JsError> {
    let guard = client.inner.lock().await;
    let result = guard.put_object_encrypted_with_type(bucket, key, Bytes::from(data.to_vec()), Some(content_type))
        .await
        .map_err(|e| JsError::new(&format!("Upload failed: {}", e)))?;

    let js_result = JsPutResult {
        etag: result.etag,
        version_id: result.version_id,
    };
    serde_wasm_bindgen::to_value(&js_result)
        .map_err(|e| JsError::new(&format!("Serialization error: {}", e)))
}

/// Download and decrypt data by original key
///
/// @param client - EncryptedClient handle
/// @param bucket - Bucket name
/// @param key - Original object key (path)
/// @returns Decrypted data as Uint8Array
///
/// Errors surface as `JsError` whose `message` is a JSON-encoded
/// `{ code, operation, message, data }` object — `code` is one of
/// the stable codes documented on `client_error_to_js_error`. Apps
/// should `JSON.parse(err.message)` to dispatch on `code` (e.g.,
/// `"MASTER_UNREACHABLE"` is the Phase 2.1 signal that the SDK's
/// health gate has tripped — surface an offline UI rather than a
/// generic "download failed").
#[wasm_bindgen(js_name = getDecrypted)]
pub async fn get_decrypted(
    client: &EncryptedClient,
    bucket: &str,
    key: &str,
) -> Result<Vec<u8>, JsError> {
    let guard = client.inner.lock().await;
    let data = guard.get_object_decrypted(bucket, key)
        .await
        .map_err(|e| client_error_to_js_error("get_decrypted", e))?;
    Ok(data.to_vec())
}

/// Download and decrypt data by storage key
///
/// Same structured-error contract as `getDecrypted`.
#[wasm_bindgen(js_name = getDecryptedByStorageKey)]
pub async fn get_decrypted_by_storage_key(
    client: &EncryptedClient,
    bucket: &str,
    storage_key: &str,
) -> Result<Vec<u8>, JsError> {
    let guard = client.inner.lock().await;
    let data = guard.get_object_decrypted_by_storage_key(bucket, storage_key)
        .await
        .map_err(|e| client_error_to_js_error("get_decrypted_by_storage_key", e))?;
    Ok(data.to_vec())
}

/// Delete an encrypted object
#[wasm_bindgen(js_name = deleteEncrypted)]
pub async fn delete_encrypted(
    client: &EncryptedClient,
    bucket: &str,
    key: &str,
) -> Result<(), JsError> {
    let guard = client.inner.lock().await;
    guard.delete_object(bucket, key)
        .await
        .map_err(|e| JsError::new(&format!("Delete failed: {}", e)))?;
    Ok(())
}

/// List objects with decrypted metadata
///
/// @param client - EncryptedClient handle
/// @param bucket - Bucket name
/// @param options - List options (prefix, maxKeys, etc.)
/// @returns Array of FileMetadata
#[wasm_bindgen(js_name = listDecrypted)]
pub async fn list_decrypted(
    client: &EncryptedClient,
    bucket: &str,
    options: JsValue,
) -> Result<JsValue, JsError> {
    let options: Option<JsListOptions> = if options.is_null() || options.is_undefined() {
        None
    } else {
        Some(serde_wasm_bindgen::from_value(options)
            .map_err(|e| JsError::new(&format!("Invalid options: {}", e)))?)
    };

    let list_opts = options.map(|o| fula_client::ListObjectsOptions {
        prefix: o.prefix,
        delimiter: o.delimiter,
        max_keys: o.max_keys.map(|n| n as usize),
        continuation_token: o.continuation_token,
        start_after: None,
    });

    let guard = client.inner.lock().await;
    let result = guard.list_objects_decrypted(bucket, list_opts)
        .await
        .map_err(|e| JsError::new(&format!("List failed: {}", e)))?;

    let js_result: Vec<JsFileMetadata> = result.into_iter().map(|m| JsFileMetadata {
        storage_key: m.storage_key,
        original_key: m.original_key,
        size: m.original_size,
        content_type: m.content_type,
        created_at: m.created_at,
        modified_at: m.modified_at,
        is_encrypted: m.is_encrypted,
    }).collect();

    serde_wasm_bindgen::to_value(&js_result)
        .map_err(|e| JsError::new(&format!("Serialization error: {}", e)))
}

/// List directory structure
#[wasm_bindgen(js_name = listDirectory)]
pub async fn list_directory(
    client: &EncryptedClient,
    bucket: &str,
    prefix: Option<String>,
) -> Result<JsValue, JsError> {
    let guard = client.inner.lock().await;
    let result = guard.list_directory(bucket, prefix.as_deref())
        .await
        .map_err(|e| JsError::new(&format!("List failed: {}", e)))?;

    let entries: Vec<JsDirectoryEntry> = result.directories
        .into_iter()
        .map(|(name, files)| JsDirectoryEntry {
            name,
            is_directory: true,
            files: files.into_iter().map(|f| JsFileMetadata {
                storage_key: f.storage_key,
                original_key: f.original_key,
                size: f.original_size,
                content_type: f.content_type,
                created_at: f.created_at,
                modified_at: f.modified_at,
                is_encrypted: f.is_encrypted,
            }).collect(),
        })
        .collect();

    let js_result = JsDirectoryListing {
        bucket: result.bucket,
        prefix: result.prefix,
        entries,
    };

    serde_wasm_bindgen::to_value(&js_result)
        .map_err(|e| JsError::new(&format!("Serialization error: {}", e)))
}

// ============================================================================
// Bucket Operations
// ============================================================================

/// List all buckets
#[wasm_bindgen(js_name = listBuckets)]
pub async fn list_buckets(client: &EncryptedClient) -> Result<JsValue, JsError> {
    let guard = client.inner.lock().await;
    let result = guard.list_buckets()
        .await
        .map_err(|e| JsError::new(&format!("List buckets failed: {}", e)))?;

    let js_result: Vec<JsBucketInfo> = result.buckets.into_iter().map(|b| JsBucketInfo {
        name: b.name,
        created_at: b.creation_date.timestamp(),
    }).collect();

    serde_wasm_bindgen::to_value(&js_result)
        .map_err(|e| JsError::new(&format!("Serialization error: {}", e)))
}

/// Create a bucket
#[wasm_bindgen(js_name = createBucket)]
pub async fn create_bucket(client: &EncryptedClient, name: &str) -> Result<(), JsError> {
    let guard = client.inner.lock().await;
    guard.create_bucket(name)
        .await
        .map_err(|e| JsError::new(&format!("Create bucket failed: {}", e)))?;
    Ok(())
}

/// Delete a bucket
#[wasm_bindgen(js_name = deleteBucket)]
pub async fn delete_bucket(client: &EncryptedClient, name: &str) -> Result<(), JsError> {
    let guard = client.inner.lock().await;
    guard.delete_bucket(name)
        .await
        .map_err(|e| JsError::new(&format!("Delete bucket failed: {}", e)))?;
    Ok(())
}

// ============================================================================
// Key Management
// ============================================================================

/// Export the secret key for backup (32 bytes)
///
/// Store this securely - it's the master encryption key!
#[wasm_bindgen(js_name = exportSecretKey)]
pub async fn export_secret_key(client: &EncryptedClient) -> Vec<u8> {
    let guard = client.inner.lock().await;
    guard.encryption_config().export_secret_key().as_bytes().to_vec()
}

/// Get the public key for sharing (32 bytes)
#[wasm_bindgen(js_name = getPublicKey)]
pub async fn get_public_key(client: &EncryptedClient) -> Vec<u8> {
    let guard = client.inner.lock().await;
    guard.encryption_config().public_key().as_bytes().to_vec()
}

/// Derive a 32-byte key from context and input using Argon2id (memory-hard KDF)
///
/// Use this to derive encryption keys from Google credentials with brute-force resistance:
/// ```javascript
/// const key = deriveKey('fula-files-v1', new TextEncoder().encode(`google:${userId}:${email}`));
/// ```
///
/// Parameters:
/// - Memory: 64 MiB
/// - Iterations: 3
/// - Parallelism: 1 (for cross-platform consistency)
///
/// @param context - Context string used as salt (e.g., "fula-files-v1")
/// @param input - Input bytes (e.g., UTF-8 encoded credentials)
/// @returns 32-byte derived key
#[wasm_bindgen(js_name = deriveKey)]
pub fn derive_key(context: &str, input: &[u8]) -> Vec<u8> {
    fula_crypto::hashing::derive_key_argon2id(context, input).to_vec()
}

/// Derive a 32-byte sub-key from a high-entropy parent key using
/// BLAKE3's keyed-derivation mode.
///
/// Mirrors the native FFI helper exposed in `fula-flutter`. Used by
/// the E2E plan Phase 5 to derive `K_index` and `K_entry_seed` from
/// the user's `KEK_seed` (= the existing Argon2id output). BLAKE3-
/// derive is the right primitive here: input is already key-strength,
/// so no need for memory-hardness again, and the output is
/// byte-identical to the Rust side's
/// `fula_crypto::derive_user_buckets_index_key` and
/// `fula_crypto::derive_entry_signing_seed`, which use the same
/// `blake3::Hasher::new_derive_key(context)`.
///
/// Distinct from [`deriveKey`] (Argon2id, memory-hard, for stretching
/// a user-typed passphrase into a master key).
///
/// ```javascript
/// // Derive K_index from the user's existing KEK_seed (output of deriveKey):
/// const kIndex = blake3DeriveKey('fula:user-buckets-index:v1', kekSeed);
/// ```
///
/// @param context - Domain-separation tag (e.g., "fula:user-buckets-index:v1")
/// @param input - Parent key bytes (32 bytes of `KEK_seed`)
/// @returns 32-byte derived sub-key
#[wasm_bindgen(js_name = blake3DeriveKey)]
pub fn blake3_derive_key(context: &str, input: &[u8]) -> Vec<u8> {
    fula_crypto::hashing::derive_key(context, input).as_bytes().to_vec()
}

/// Derive X25519 public key from private key bytes
///
/// **IMPORTANT**: Use this function to ensure compatibility between
/// Flutter/Native and Web/WASM clients when sharing files.
///
/// This ensures both sender and receiver derive the exact same public key
/// from the same private key bytes, avoiding cryptographic mismatches.
///
/// @param secretKeyBytes - 32-byte X25519 private key (Uint8Array)
/// @returns 32-byte X25519 public key (Uint8Array)
#[wasm_bindgen(js_name = derivePublicKeyFromSecret)]
pub fn derive_public_key_from_secret(secret_key_bytes: &[u8]) -> Result<Vec<u8>, JsError> {
    if secret_key_bytes.len() != 32 {
        return Err(JsError::new(&format!(
            "Secret key must be exactly 32 bytes, got {}", secret_key_bytes.len()
        )));
    }

    let mut arr = [0u8; 32];
    arr.copy_from_slice(secret_key_bytes);

    let secret = fula_crypto::SecretKey::from_bytes(&arr)
        .map_err(|e| JsError::new(&format!("Invalid secret key: {}", e)))?;
    let public = secret.public_key();

    Ok(public.as_bytes().to_vec())
}

// ============================================================================
// Seed-as-identity primitives (Mode B / Mode C sign-in)
// ============================================================================
//
// These mirror the FxFiles FFI surface for cross-platform parity. The
// `effective_user_id` is the JWT `sub` for seed-derived users; the
// signing seed feeds Ed25519 challenge-response auth against the
// pinning-service issuer endpoints.
//
// All three derivations live in `fula_crypto::effective_user_id`:
//   - `compute_effective_user_id_mode_b(provider, oauth_sub, seed) -> [u8; 16]`
//   - `compute_effective_user_id_mode_c(seed) -> [u8; 16]`
//   - `derive_signing_seed_from_seed(seed) -> [u8; 32]`
//
// Sign/public-key helpers are co-located there too so all the Ed25519
// material is in one module.

/// Compute the Mode B (OAuth + seed) `effective_user_id`.
///
/// 16 raw bytes. Hex-encode for the JWT `sub` / issuer payload.
///
/// `provider` is canonical (`"google"` or `"apple"`). `oauth_sub` is the
/// OAuth provider's opaque `sub` claim — passed through as bytes, NOT
/// NFC-normalized (OAuth identifiers are opaque). `seed` is the user's
/// passphrase — NFC-normalized inside.
#[wasm_bindgen(js_name = computeEffectiveUserIdModeB)]
pub fn compute_effective_user_id_mode_b(
    provider: &str,
    oauth_sub: &str,
    seed: &str,
) -> Vec<u8> {
    fula_crypto::effective_user_id::compute_effective_user_id_mode_b(
        provider, oauth_sub, seed,
    )
    .to_vec()
}

/// Compute the Mode C (seed-only) `effective_user_id`. 16 raw bytes.
///
/// `seed` is NFC-normalized inside. Two callers with identical seeds
/// produce identical user-ids — by design. Use a high-entropy seed.
#[wasm_bindgen(js_name = computeEffectiveUserIdModeC)]
pub fn compute_effective_user_id_mode_c(seed: &str) -> Vec<u8> {
    fula_crypto::effective_user_id::compute_effective_user_id_mode_c(seed).to_vec()
}

/// Derive the 32-byte Ed25519 signing seed from the user's passphrase.
///
/// Domain-separated from `computeEffectiveUserId*` so leaking the
/// 16-byte user-id does not compromise the signing key (and vice versa).
/// Pass the result to `ed25519Sign` / `ed25519PublicKey`.
#[wasm_bindgen(js_name = deriveSigningSeed)]
pub fn derive_signing_seed(seed: &str) -> Vec<u8> {
    fula_crypto::effective_user_id::derive_signing_seed_from_seed(seed).to_vec()
}

/// Sign `message` with the Ed25519 keypair derived from `signing_seed`
/// (the 32-byte output of `deriveSigningSeed`).
///
/// Returns a 64-byte detached signature. Used to prove seed possession
/// when responding to the issuer's challenge nonce on `/auth/sign-in` /
/// `/auth/register-mode-{b,c}`.
#[wasm_bindgen(js_name = ed25519Sign)]
pub fn ed25519_sign(signing_seed: &[u8], message: &[u8]) -> Result<Vec<u8>, JsError> {
    if signing_seed.len() != 32 {
        return Err(JsError::new(&format!(
            "signing_seed must be exactly 32 bytes, got {}",
            signing_seed.len()
        )));
    }
    let mut seed_arr = [0u8; 32];
    seed_arr.copy_from_slice(signing_seed);
    Ok(
        fula_crypto::effective_user_id::sign_with_signing_seed(&seed_arr, message)
            .to_vec(),
    )
}

/// Derive the Ed25519 public verifying key from the 32-byte signing seed.
///
/// Returns 32 raw bytes — what the issuer stores at registration and
/// uses to verify subsequent sign-in signatures.
#[wasm_bindgen(js_name = ed25519PublicKey)]
pub fn ed25519_public_key(signing_seed: &[u8]) -> Result<Vec<u8>, JsError> {
    if signing_seed.len() != 32 {
        return Err(JsError::new(&format!(
            "signing_seed must be exactly 32 bytes, got {}",
            signing_seed.len()
        )));
    }
    let mut seed_arr = [0u8; 32];
    seed_arr.copy_from_slice(signing_seed);
    Ok(
        fula_crypto::effective_user_id::public_key_from_signing_seed(&seed_arr)
            .to_vec(),
    )
}

// ============================================================================
// Sharing
// ============================================================================

/// Accept a share token and get an AcceptedShare for accessing shared files
///
/// @param client - EncryptedClient handle
/// @param token_json - JSON string containing the ShareToken
/// @returns AcceptedShare handle
#[wasm_bindgen(js_name = acceptShare)]
pub async fn accept_share(
    client: &EncryptedClient,
    token_json: &str,
) -> Result<AcceptedShare, JsError> {
    let token: fula_crypto::ShareToken = serde_json::from_str(token_json)
        .map_err(|e| JsError::new(&format!("Invalid share token JSON: {}", e)))?;

    let guard = client.inner.lock().await;
    let accepted = guard.accept_share(&token)
        .map_err(|e| JsError::new(&format!("Failed to accept share: {}", e)))?;

    Ok(AcceptedShare { inner: accepted })
}

/// Get a shared file using an accepted share
///
/// @param client - EncryptedClient handle
/// @param bucket - Bucket name
/// @param storage_key - Storage key of the shared file
/// @param original_key - Original (unobfuscated) file path for path scope validation
/// @param share - AcceptedShare handle
/// @returns Decrypted data as Uint8Array
#[wasm_bindgen(js_name = getWithShare)]
pub async fn get_with_share(
    client: &EncryptedClient,
    bucket: &str,
    storage_key: &str,
    original_key: &str,
    share: &AcceptedShare,
) -> Result<Vec<u8>, JsError> {
    let guard = client.inner.lock().await;
    let data = guard.get_object_with_share(bucket, storage_key, original_key, &share.inner)
        .await
        .map_err(|e| JsError::new(&format!("Failed to get shared file: {}", e)))?;
    Ok(data.to_vec())
}

/// Get a shared file directly using a share token JSON
///
/// @param client - EncryptedClient handle
/// @param bucket - Bucket name
/// @param storage_key - Storage key of the shared file
/// @param original_key - Original (unobfuscated) file path for path scope validation
/// @param token_json - JSON string containing the ShareToken
/// @returns Decrypted data as Uint8Array
#[wasm_bindgen(js_name = getWithToken)]
pub async fn get_with_token(
    client: &EncryptedClient,
    bucket: &str,
    storage_key: &str,
    original_key: &str,
    token_json: &str,
) -> Result<Vec<u8>, JsError> {
    let token: fula_crypto::ShareToken = serde_json::from_str(token_json)
        .map_err(|e| JsError::new(&format!("Invalid share token JSON: {}", e)))?;

    let guard = client.inner.lock().await;
    let data = guard.get_object_with_token(bucket, storage_key, original_key, &token)
        .await
        .map_err(|e| JsError::new(&format!("Failed to get shared file: {}", e)))?;
    Ok(data.to_vec())
}

/// Get share permissions
#[wasm_bindgen(js_name = getSharePermissions)]
pub fn get_share_permissions(share: &AcceptedShare) -> Result<JsValue, JsError> {
    let perms = JsSharePermissions {
        can_read: share.inner.permissions.can_read,
        can_write: share.inner.permissions.can_write,
        expires_at: share.inner.expires_at,
    };
    serde_wasm_bindgen::to_value(&perms)
        .map_err(|e| JsError::new(&format!("Serialization error: {}", e)))
}

/// Check if a share is still valid (not expired)
#[wasm_bindgen(js_name = isShareValid)]
pub fn is_share_valid(share: &AcceptedShare) -> bool {
    share.inner.is_valid()
}

// ============================================================================
// Utility Functions
// ============================================================================

/// Check if client uses FlatNamespace mode
#[wasm_bindgen(js_name = isFlatNamespace)]
pub async fn is_flat_namespace(client: &EncryptedClient) -> bool {
    let guard = client.inner.lock().await;
    guard.is_flat_namespace()
}

// ============================================================================
// Phase 3.3 — userKey derivation
// ============================================================================

/// **PREFERRED** — derive the canonical fula `userKey` directly from a
/// JWT `sub` claim. Mirrors `fula_client::derive_user_key_from_jwt_sub`
/// and matches master's `state.rs::hash_user_id` byte-for-byte: the
/// JWT sub bytes feed straight into `BLAKE3.derive_key`, no
/// transformation.
///
/// Works correctly for BOTH pre-migration-011 users (sub = plaintext
/// email) and post-migration users (sub = sha256(email).hex()). Apps
/// should cache the JWT sub at sign-in and pass it here whenever
/// (re-)setting `users_index_user_key`. The SDK never sees the raw
/// email.
///
/// Use this in preference to `deriveUserKeyFromEmail` — the email
/// variant is broken for pre-migration users.
#[wasm_bindgen(js_name = deriveUserKeyFromJwtSub)]
pub fn derive_user_key_from_jwt_sub(jwt_sub: String) -> String {
    fula_client::derive_user_key_from_jwt_sub(&jwt_sub)
}

/// **DEPRECATED — broken for pre-migration-011 users.** Use
/// `deriveUserKeyFromJwtSub` instead.
///
/// Computes the userKey by first applying `sha256(email.lowercase())`
/// before BLAKE3. This happens to match master ONLY for
/// post-migration users whose JWT sub is itself `sha256(email).hex()`.
/// For pre-migration users whose JWT sub is plaintext email, master's
/// derivation skips the sha256 step and the two values diverge —
/// silent cold-start failure.
///
/// On wasm32 the cold-start RESOLVER isn't wired (depends on reqwest
/// + parking_lot which aren't compiled for browsers), so this helper
/// remains exposed for API symmetry with the native binding.
#[wasm_bindgen(js_name = deriveUserKeyFromEmail)]
pub fn derive_user_key_from_email(email: String) -> String {
    fula_client::derive_user_key_from_email(&email)
}

// ============================================================================
// Phase 19 — get_object_with_offline_fallback + transparency polling
// ============================================================================

/// Phase 19 GET wrapper that returns transparency fields alongside
/// the bytes. Mirrors `fula-flutter`'s `getObjectWithOfflineFallback`.
/// On wasm32 the offline fallback infrastructure is gated out (no
/// block cache, no gateway race), so this delegates to the
/// master-only `get_object_with_metadata` path; the returned shape
/// always carries `source = Master, freshness = Live`. Exposed for
/// API symmetry with the Flutter binding.
///
/// @param client - EncryptedClient (the underlying wraps a FulaClient too)
/// @param bucket - Bucket name
/// @param key    - Object key
/// @returns      - JSON object matching `JsOfflineGetResult`
///                 (`data: number[]`, `etag: string`, `source: {kind: ...}`,
///                  `freshness: {kind: ...}`, ...)
#[wasm_bindgen(js_name = getObjectWithOfflineFallback)]
pub async fn get_object_with_offline_fallback(
    client: &EncryptedClient,
    bucket: String,
    key: String,
) -> Result<JsValue, JsError> {
    let guard = client.inner.lock().await;
    // The `EncryptedClient` doesn't expose `get_object_with_offline_fallback`
    // directly; it's on the underlying `FulaClient`. Reach in via
    // `inner()`.
    let result = guard
        .inner()
        .get_object_with_offline_fallback(&bucket, &key)
        .await
        .map_err(|e| client_error_to_js_error("get_offline_fallback_failed", e))?;
    let js_result: JsOfflineGetResult = result.into();
    serde_wasm_bindgen::to_value(&js_result)
        .map_err(|e| JsError::new(&format!("serialize OfflineGetResult: {}", e)))
}

/// Drain every `MasterHealthEvent` observed since the last call to
/// this function. Returns events in the order they fired (oldest
/// first); after draining the buffer is empty.
///
/// JS apps poll this on a timer (or on UI rebuilds) and update an
/// online/offline indicator. Internal buffer bounded at 64 entries —
/// if an app falls behind, oldest events drop first, latest state is
/// preserved. For latest-only consumers, see `getLastMasterHealthEvent`.
///
/// Returned shape: `Array<{kind: 'Online'} | {kind: 'OfflineFallbackActive', reason: string} | {kind: 'SeverelyDegraded', reason: string}>`.
#[wasm_bindgen(js_name = pollMasterHealthEvents)]
pub fn poll_master_health_events(client: &EncryptedClient) -> Result<JsValue, JsError> {
    let events = client.health_dispatcher.drain_events();
    serde_wasm_bindgen::to_value(&events)
        .map_err(|e| JsError::new(&format!("serialize health events: {}", e)))
}

/// Read the most recent `MasterHealthEvent` observed by the SDK
/// without draining the buffer. Returns `null` if no transition has
/// happened yet (master has been Up the whole session). Useful for
/// apps that build UI state from a single field on mount.
///
/// Returned shape: same as a single element from `pollMasterHealthEvents`,
/// or `null`.
#[wasm_bindgen(js_name = getLastMasterHealthEvent)]
pub fn get_last_master_health_event(client: &EncryptedClient) -> Result<JsValue, JsError> {
    let last = client.health_dispatcher.last_event();
    serde_wasm_bindgen::to_value(&last)
        .map_err(|e| JsError::new(&format!("serialize last health event: {}", e)))
}

/// Get SDK version
#[wasm_bindgen(js_name = getVersion)]
pub fn get_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

// ============================================================================
// HPKE Test Functions (for cross-platform verification)
// ============================================================================

/// Encrypt a DEK using HPKE with the given public key
///
/// This simulates what FxFiles does when encrypting a file.
/// Returns JSON string containing the EncryptedData (wrapped DEK).
///
/// @param publicKeyBytes - 32-byte X25519 public key
/// @param dekBytes - 32-byte DEK to encrypt
/// @returns JSON string with {version, encapsulated_key, ciphertext}
#[wasm_bindgen(js_name = testHpkeEncryptDek)]
pub fn test_hpke_encrypt_dek(
    public_key_bytes: &[u8],
    dek_bytes: &[u8],
) -> Result<String, JsError> {
    if public_key_bytes.len() != 32 {
        return Err(JsError::new(&format!(
            "Public key must be 32 bytes, got {}", public_key_bytes.len()
        )));
    }
    if dek_bytes.len() != 32 {
        return Err(JsError::new(&format!(
            "DEK must be 32 bytes, got {}", dek_bytes.len()
        )));
    }

    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(public_key_bytes);
    let public_key = fula_crypto::PublicKey::from_bytes(&pk_arr)
        .map_err(|e| JsError::new(&format!("Invalid public key: {}", e)))?;

    let mut dek_arr = [0u8; 32];
    dek_arr.copy_from_slice(dek_bytes);
    let dek = fula_crypto::keys::DekKey::from_bytes(&dek_arr)
        .map_err(|e| JsError::new(&format!("Invalid DEK: {}", e)))?;

    let encryptor = fula_crypto::hpke::Encryptor::new(&public_key);
    let wrapped = encryptor.encrypt_dek(&dek)
        .map_err(|e| JsError::new(&format!("HPKE encryption failed: {}", e)))?;

    serde_json::to_string(&wrapped)
        .map_err(|e| JsError::new(&format!("JSON serialization failed: {}", e)))
}

/// Decrypt a wrapped DEK using HPKE with the given secret key
///
/// This simulates what WebUI WASM should do when decrypting a file.
///
/// @param secretKeyBytes - 32-byte X25519 secret key
/// @param wrappedDekJson - JSON string from testHpkeEncryptDek
/// @returns 32-byte decrypted DEK
#[wasm_bindgen(js_name = testHpkeDecryptDek)]
pub fn test_hpke_decrypt_dek(
    secret_key_bytes: &[u8],
    wrapped_dek_json: &str,
) -> Result<Vec<u8>, JsError> {
    if secret_key_bytes.len() != 32 {
        return Err(JsError::new(&format!(
            "Secret key must be 32 bytes, got {}", secret_key_bytes.len()
        )));
    }

    let mut sk_arr = [0u8; 32];
    sk_arr.copy_from_slice(secret_key_bytes);
    let secret = fula_crypto::SecretKey::from_bytes(&sk_arr)
        .map_err(|e| JsError::new(&format!("Invalid secret key: {}", e)))?;

    let key_manager = fula_crypto::keys::KeyManager::from_secret_key(secret);
    let wrapped: fula_crypto::hpke::EncryptedData = serde_json::from_str(wrapped_dek_json)
        .map_err(|e| JsError::new(&format!("Invalid wrapped DEK JSON: {}", e)))?;

    let decryptor = fula_crypto::hpke::Decryptor::new(key_manager.keypair());
    let dek = decryptor.decrypt_dek(&wrapped)
        .map_err(|e| JsError::new(&format!("HPKE decryption failed: {}", e)))?;

    Ok(dek.as_bytes().to_vec())
}

/// AES-256-GCM encrypt data with a DEK
///
/// @param dekBytes - 32-byte DEK
/// @param plaintext - Data to encrypt
/// @returns JSON string with {nonce, ciphertext} (both base64 encoded)
#[wasm_bindgen(js_name = testAesGcmEncrypt)]
pub fn test_aes_gcm_encrypt(
    dek_bytes: &[u8],
    plaintext: &[u8],
) -> Result<String, JsError> {
    if dek_bytes.len() != 32 {
        return Err(JsError::new(&format!(
            "DEK must be 32 bytes, got {}", dek_bytes.len()
        )));
    }

    let mut dek_arr = [0u8; 32];
    dek_arr.copy_from_slice(dek_bytes);
    let dek = fula_crypto::keys::DekKey::from_bytes(&dek_arr)
        .map_err(|e| JsError::new(&format!("Invalid DEK: {}", e)))?;

    let nonce = fula_crypto::symmetric::Nonce::generate();
    let aead = fula_crypto::symmetric::Aead::new_default(&dek);
    let ciphertext = aead.encrypt(&nonce, plaintext)
        .map_err(|e| JsError::new(&format!("AES-GCM encryption failed: {}", e)))?;

    use base64::Engine;
    let result = serde_json::json!({
        "nonce": base64::engine::general_purpose::STANDARD.encode(nonce.as_bytes()),
        "ciphertext": base64::engine::general_purpose::STANDARD.encode(&ciphertext),
    });

    serde_json::to_string(&result)
        .map_err(|e| JsError::new(&format!("JSON serialization failed: {}", e)))
}

/// AES-256-GCM decrypt data with a DEK
///
/// @param dekBytes - 32-byte DEK
/// @param nonceBase64 - Base64 encoded 12-byte nonce
/// @param ciphertextBase64 - Base64 encoded ciphertext
/// @returns Decrypted plaintext
#[wasm_bindgen(js_name = testAesGcmDecrypt)]
pub fn test_aes_gcm_decrypt(
    dek_bytes: &[u8],
    nonce_base64: &str,
    ciphertext_base64: &str,
) -> Result<Vec<u8>, JsError> {
    if dek_bytes.len() != 32 {
        return Err(JsError::new(&format!(
            "DEK must be 32 bytes, got {}", dek_bytes.len()
        )));
    }

    use base64::Engine;
    let nonce_bytes = base64::engine::general_purpose::STANDARD.decode(nonce_base64)
        .map_err(|e| JsError::new(&format!("Invalid nonce base64: {}", e)))?;
    let ciphertext = base64::engine::general_purpose::STANDARD.decode(ciphertext_base64)
        .map_err(|e| JsError::new(&format!("Invalid ciphertext base64: {}", e)))?;

    let mut dek_arr = [0u8; 32];
    dek_arr.copy_from_slice(dek_bytes);
    let dek = fula_crypto::keys::DekKey::from_bytes(&dek_arr)
        .map_err(|e| JsError::new(&format!("Invalid DEK: {}", e)))?;

    let nonce = fula_crypto::symmetric::Nonce::from_bytes(&nonce_bytes)
        .map_err(|e| JsError::new(&format!("Invalid nonce: {}", e)))?;
    let aead = fula_crypto::symmetric::Aead::new_default(&dek);
    let plaintext = aead.decrypt(&nonce, &ciphertext)
        .map_err(|e| JsError::new(&format!("AES-GCM decryption failed: {}", e)))?;

    Ok(plaintext)
}

/// Full encryption round-trip test
///
/// This tests the EXACT flow: derive key -> encrypt DEK with HPKE -> encrypt data with AES-GCM
/// then decrypt in reverse order. If this works, the WASM crypto is correct.
///
/// @param context - Key derivation context (e.g., "fula-files-v1")
/// @param input - Key derivation input (e.g., credentials)
/// @param plaintext - Data to encrypt and decrypt
/// @returns Original plaintext if successful (proves round-trip works)
#[wasm_bindgen(js_name = testFullEncryptionRoundtrip)]
pub fn test_full_encryption_roundtrip(
    context: &str,
    input: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, JsError> {
    // Step 1: Derive key using Argon2id
    let secret_bytes = fula_crypto::hashing::derive_key_argon2id(context, input);

    // Step 2: Create keypair
    let secret = fula_crypto::SecretKey::from_bytes(&secret_bytes)
        .map_err(|e| JsError::new(&format!("Invalid derived key: {}", e)))?;
    let public = secret.public_key();

    // Step 3: Generate random DEK
    let dek = fula_crypto::keys::DekKey::generate();

    // Step 4: Encrypt DEK with HPKE (simulating FxFiles upload)
    let encryptor = fula_crypto::hpke::Encryptor::new(&public);
    let wrapped_dek = encryptor.encrypt_dek(&dek)
        .map_err(|e| JsError::new(&format!("HPKE DEK encryption failed: {}", e)))?;

    // Step 5: Encrypt plaintext with AES-GCM
    let nonce = fula_crypto::symmetric::Nonce::generate();
    let aead = fula_crypto::symmetric::Aead::new_default(&dek);
    let ciphertext = aead.encrypt(&nonce, plaintext)
        .map_err(|e| JsError::new(&format!("AES-GCM encryption failed: {}", e)))?;

    // --- Simulating WebUI decryption ---

    // Step 6: Derive key again (same as WebUI would do)
    let secret_bytes_2 = fula_crypto::hashing::derive_key_argon2id(context, input);
    let secret_2 = fula_crypto::SecretKey::from_bytes(&secret_bytes_2)
        .map_err(|e| JsError::new(&format!("Invalid derived key on decrypt: {}", e)))?;

    // Step 7: Decrypt DEK with HPKE (simulating WebUI WASM)
    let key_manager = fula_crypto::keys::KeyManager::from_secret_key(secret_2);
    let decryptor = fula_crypto::hpke::Decryptor::new(key_manager.keypair());
    let decrypted_dek = decryptor.decrypt_dek(&wrapped_dek)
        .map_err(|e| JsError::new(&format!("HPKE DEK decryption failed: {}", e)))?;

    // Step 8: Decrypt plaintext with AES-GCM
    let aead_decrypt = fula_crypto::symmetric::Aead::new_default(&decrypted_dek);
    let decrypted = aead_decrypt.decrypt(&nonce, &ciphertext)
        .map_err(|e| JsError::new(&format!("AES-GCM decryption failed: {}", e)))?;

    Ok(decrypted)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[wasm_bindgen_test]
    fn test_derive_key_argon2id() {
        // Test Argon2id key derivation
        let key1 = derive_key("fula-files-v1", b"google:123:user@test.com");
        let key2 = derive_key("fula-files-v1", b"google:456:other@test.com");
        let key3 = derive_key("fula-files-v1", b"google:123:user@test.com");

        assert_eq!(key1.len(), 32);
        assert_ne!(key1, key2); // Different input -> different key
        assert_eq!(key1, key3); // Same input -> same key (deterministic)
    }

    #[wasm_bindgen_test]
    fn test_version() {
        let version = get_version();
        assert!(!version.is_empty());
    }
}
