//! # Capability bundle — the MCP's in-memory, per-session collaboration authority
//!
//! The MCP server (the "AI") is a **stateless proxy**: it persists NO user data
//! beyond its own long-lived X25519 identity key. Every piece of capability
//! material is **injected per session** (via `FULA_MCP_CAPABILITY`) and held **in
//! memory only** — never logged.
//!
//! ## The collaboration bundle (Method 2)
//!
//! A [`CapabilityBundle`] binds the MCP to exactly ONE collaboration **group**:
//!
//! 1. **`webui_base`** + **`group_id`** — the base URL and UUID for the group's
//!    `/api/collab/{group_id}/*` endpoints (see [`crate::collab`]).
//! 2. **`manifest_bucket`** / **`manifest_key`** — where the group's encrypted
//!    manifest lives (informational; the manifest is fetched by `group_id`).
//! 3. **`wrapped_link_secret`** — a [`ShareToken`] (serialized JSON) wrapping the
//!    group's 32-byte **link secret** for the MCP's OWN X25519 public key. The MCP
//!    loads/generates its identity LOCALLY ([`crate::identity::McpIdentity`]) and
//!    unwraps the link secret ONCE at construction. The link secret is what
//!    derives the manifest key and every collab-file key, and the link *keypair*
//!    (derived from it) accepts the owner's per-file `fula` share tokens. Holding
//!    the recovered secret (zeroized on drop) for the process lifetime avoids
//!    re-running HPKE per op; it is no more sensitive than the keys it derives.
//! 4. **`collab_write_token`** (optional) — a group-scoped Bearer for the WRITE
//!    endpoints (`PUT manifest-sync`, `POST upload`). Re-mintable via the optional
//!    `refresh_token` + `refresh_url` (mirrors the connection-JWT refresh). Absent
//!    ⇒ the MCP is read-only for this session.
//!
//! There is NO `ai/`-prefix scope gate anymore: authorization is "the file is in
//! THIS group's manifest" (the bundle is per-group), so an op simply operates over
//! the group it was handed.
//!
//! ## Security properties
//!
//! - **No secret in logs.** The bundle does not derive [`Debug`] automatically;
//!   the hand-written impl redacts the link secret, the write token, and the
//!   refresh token. The recovered link secret is wrapped in [`Zeroizing`] so it is
//!   wiped on drop. The MCP identity's secret never enters the bundle (only its
//!   public key / FULA id are retained).
//! - **No bearer leak.** `webui_base`, `refresh_url`, and `storage_api_url` are
//!   validated HTTPS-or-loopback at parse time, so the write/refresh Bearer is
//!   never sent to an unintended origin.
//!
//! ## Bundle wire format (injected at startup; NEVER persisted)
//!
//! ```json
//! {
//!   "webui_base": "https://cloud.fx.land",
//!   "group_id": "1b9d…uuid",
//!   "manifest_bucket": "fula-metadata",
//!   "manifest_key": "manifests/1b9d….json",
//!   "wrapped_link_secret": "<serde_json string of a fula ShareToken>",
//!   "identity_path": "/optional/path/to/mcp_identity.key",
//!   "collab_write_token": "<optional group-scoped Bearer>",
//!   "refresh_token": "<optional, re-mints the write token>",
//!   "refresh_url": "<optional, https or loopback>",
//!   "storage_api_url": "<optional credit host for the quota pre-check>",
//!   "user_id": "<optional, informational>",
//!   "timeout_secs": 60
//! }
//! ```
//!
//! Load it with [`CapabilityBundle::from_json`] / [`CapabilityBundle::from_env`].

use std::path::PathBuf;
use std::time::Duration;

use fula_crypto::{KekKeyPair, SecretKey, ShareToken};
use serde::Deserialize;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::identity::McpIdentity;
use crate::quota::{
    check_quota, QuotaDecision, TokenBucket, DEFAULT_WRITE_BURST, DEFAULT_WRITE_REFILL_PER_SEC,
    ENV_WRITE_BURST, ENV_WRITE_REFILL_PER_SEC,
};

/// The default HTTP request timeout when the bundle does not specify one.
const DEFAULT_TIMEOUT_SECS: u64 = 60;

/// Environment variable that carries the capability bundle JSON.
pub const ENV_CAPABILITY: &str = "FULA_MCP_CAPABILITY";

/// Environment variable that, if set, overrides the bundle's `collab_write_token`
/// (so the group-scoped write Bearer can be injected out-of-band from the rest of
/// the bundle, the same way the legacy JWT could be).
pub const ENV_WRITE_TOKEN_OVERRIDE: &str = "FULA_MCP_COLLAB_WRITE_TOKEN";

/// Environment variable that, if set, overrides the bundle's `storage_api_url`
/// (the credit/quota host the write pre-check calls).
pub const ENV_STORAGE_API_URL: &str = "FULA_MCP_STORAGE_API_URL";

/// Environment variable that, if set, overrides where the MCP persists its X25519
/// identity (otherwise `identity_path`, otherwise a per-user default).
pub const ENV_IDENTITY_PATH: &str = "FULA_MCP_IDENTITY_PATH";

/// Validate a URL that will carry a Bearer token (the collab write token or the
/// refresh token). Require `https://`, with the sole exception of an explicit
/// `http://localhost` / `http://127.0.0.1` / `http://[::1]` for local/dev. Any
/// other scheme (or an `http://` non-loopback host) is rejected so a bearer token
/// is never sent to an unintended origin.
fn validate_https_or_loopback(field: &'static str, url: &str) -> Result<(), CapabilityError> {
    // Parse the URL rather than prefix-match the string: a prefix check admits
    // `http://localhost.evil.com`, the `http://localhost@evil.com` userinfo trick,
    // and IPv6-mapped / decimal-IP loopback spoofs, ALL of which would leak the
    // Bearer (including the long-lived refresh token) to an attacker origin over
    // cleartext. reqwest re-exports the `url` crate, so no new dependency.
    let parsed = reqwest::Url::parse(url.trim()).map_err(|_| CapabilityError::InvalidUrl {
        field,
        reason: "is not a valid absolute URL",
    })?;
    let ok = match parsed.scheme() {
        "https" => true,
        // http:// permitted ONLY for an EXACT loopback host.
        "http" => matches!(
            parsed.host_str(),
            Some("localhost") | Some("127.0.0.1") | Some("[::1]") | Some("::1")
        ),
        _ => false,
    };
    if ok {
        Ok(())
    } else {
        Err(CapabilityError::InvalidUrl {
            field,
            reason: "must be https:// (or http:// only for an exact localhost / 127.0.0.1 / \
                     [::1] host) so a bearer token is never sent to an unintended origin",
        })
    }
}

/// A stable per-user path for the MCP's X25519 identity secret, used when neither
/// the bundle's `identity_path` nor [`ENV_IDENTITY_PATH`] is set.
///
/// The path MUST be stable across runs: if it changes, [`McpIdentity::load_or_generate`]
/// mints a fresh key and the wrapped link secret (addressed to the prior public
/// key) can no longer be unwrapped. We prefer the OS per-user cache dir
/// (`%LOCALAPPDATA%` on Windows, `$XDG_CACHE_HOME` or `$HOME/.cache` on Unix) and
/// fall back to the temp dir only as a last resort.
fn default_identity_path() -> PathBuf {
    let base = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("XDG_CACHE_HOME").map(PathBuf::from))
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache")))
        .unwrap_or_else(std::env::temp_dir);
    base.join("fula-mcp").join("mcp_identity.key")
}

/// Errors surfaced by the capability layer.
#[derive(Debug, Error)]
pub enum CapabilityError {
    /// The injected bundle JSON was malformed or missing required fields.
    #[error("malformed capability bundle: {0}")]
    Malformed(String),

    /// A required environment variable was not set.
    #[error("environment variable `{0}` is not set")]
    MissingEnv(&'static str),

    /// A URL field that must not leak a bearer token failed validation.
    #[error("invalid `{field}`: {reason}")]
    InvalidUrl {
        /// Which field failed (`webui_base` / `refresh_url` / `storage_api_url`).
        field: &'static str,
        /// Why it was rejected.
        reason: &'static str,
    },

    /// A required string field was empty.
    #[error("capability bundle field `{0}` must not be empty")]
    EmptyField(&'static str),

    /// Loading or generating the MCP's local identity key failed.
    #[error("MCP identity load/generate failed: {0}")]
    Identity(String),

    /// The `wrapped_link_secret` was not a valid serialized `ShareToken`.
    #[error("wrapped_link_secret is not a valid share token: {0}")]
    InvalidShareToken(String),

    /// The wrapped link secret could not be recovered with the MCP's identity —
    /// it is not addressed to this MCP's public key (re-authorize the connection,
    /// or check that `identity_path` points at the SAME key the owner authorized).
    #[error("link secret recovery failed (identity mismatch — re-authorize this MCP): {0}")]
    LinkSecretRecovery(String),

    /// The reqwest HTTP client could not be built.
    #[error("failed to build HTTP client: {0}")]
    HttpClient(String),
}

/// On-the-wire JSON shape of the collaboration bundle. Deserialized, consumed, and
/// dropped at construction — only the typed [`CapabilityBundle`] survives.
#[derive(Deserialize)]
struct CapabilityBundleJson {
    /// Base URL for the `/api/collab/*` endpoints (e.g. `https://cloud.fx.land`).
    webui_base: String,
    /// The collaboration group UUID.
    group_id: String,
    /// Bucket the group's manifest lives in (informational).
    manifest_bucket: String,
    /// Key of the group's manifest in the bucket (informational).
    manifest_key: String,
    /// A `fula_crypto::sharing::ShareToken` (serde_json STRING) wrapping the
    /// 32-byte link secret for the MCP's own X25519 public key.
    wrapped_link_secret: String,
    /// Optional path where the MCP persists its X25519 identity secret. Defaults to
    /// [`ENV_IDENTITY_PATH`] then a per-user path ([`default_identity_path`]).
    #[serde(default)]
    identity_path: Option<String>,
    /// Optional group-scoped Bearer for the WRITE endpoints. Absent ⇒ read-only.
    #[serde(default)]
    collab_write_token: Option<String>,
    /// Optional long-lived token to re-mint `collab_write_token` on a 401/403.
    #[serde(default)]
    refresh_token: Option<String>,
    /// Optional explicit URL that re-mints the write token (validated
    /// HTTPS-or-loopback). The `refresh_token` is POSTed here.
    #[serde(default)]
    refresh_url: Option<String>,
    /// Optional client timeout (seconds). Defaults to [`DEFAULT_TIMEOUT_SECS`].
    #[serde(default)]
    timeout_secs: Option<u64>,
    /// Optional credit/quota host for the write pre-check. Absent ⇒ quota check OFF.
    #[serde(default)]
    storage_api_url: Option<String>,
    /// Optional informational `userId` (not load-bearing for any authority check).
    #[serde(default)]
    user_id: Option<String>,
    /// Optional override for the write-rate-limit burst (token-bucket capacity).
    #[serde(default)]
    write_burst: Option<u32>,
    /// Optional override for the write-rate-limit refill (tokens/sec).
    #[serde(default)]
    write_refill_per_sec: Option<f64>,
}

/// The MCP's in-memory, per-session collaboration bundle. Holds the recovered link
/// secret + write token; never written to disk, never logged (redacting [`Debug`]).
pub struct CapabilityBundle {
    webui_base: String,
    group_id: String,
    manifest_bucket: String,
    manifest_key: String,
    /// The recovered 32-byte group link secret (zeroized on drop). Derives the
    /// manifest key, every collab-file key, and the link keypair for owner shares.
    link_secret: Zeroizing<[u8; 32]>,
    /// The MCP identity's X25519 public key, base64 (standard). Stamped as a
    /// file's `addedByPublicKey` when the AI writes into the manifest.
    mcp_public_b64: String,
    /// The MCP identity's `FULA-…` share id — the string the owner authorized.
    mcp_fula_id: String,
    /// The shared HTTP client (timeout-configured), reused across ops.
    http: reqwest::Client,
    /// Group-scoped write Bearer, behind interior mutability so a refresh can swap
    /// it in place while the bundle is shared `&self` behind an `Arc`. `None` ⇒
    /// the session is read-only.
    collab_write_token: std::sync::RwLock<Option<String>>,
    /// Long-lived token to re-mint `collab_write_token` (a SECRET). `None` ⇒ no
    /// write-token refresh.
    refresh_token: Option<String>,
    /// Endpoint that re-mints the write token (validated HTTPS-or-loopback).
    refresh_url: Option<String>,
    /// Credit/quota host for the write pre-check, if configured.
    storage_api_url: Option<String>,
    /// Informational owner `userId`.
    user_id: Option<String>,
    /// Per-session WRITE rate limiter (built once; limits across calls).
    write_bucket: TokenBucket,
}

impl std::fmt::Debug for CapabilityBundle {
    /// Redacting debug — NEVER prints the link secret, the write token, or the
    /// refresh token.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CapabilityBundle")
            .field("webui_base", &self.webui_base)
            .field("group_id", &self.group_id)
            .field("manifest_bucket", &self.manifest_bucket)
            .field("manifest_key", &self.manifest_key)
            .field("link_secret", &"<redacted>")
            .field("mcp_public_b64", &self.mcp_public_b64)
            .field("mcp_fula_id", &self.mcp_fula_id)
            .field(
                "collab_write_token",
                &self
                    .collab_write_token
                    .read()
                    .ok()
                    .and_then(|g| g.as_ref().map(|_| "<redacted>")),
            )
            .field("refresh_token", &self.refresh_token.as_ref().map(|_| "<redacted>"))
            .field("refresh_url", &self.refresh_url)
            .field("storage_api_url", &self.storage_api_url)
            .field("user_id", &self.user_id)
            .finish()
    }
}

impl CapabilityBundle {
    /// Parse a bundle from its injected JSON form: load the MCP identity, unwrap the
    /// link secret once, validate URLs, and build the HTTP client.
    ///
    /// # Errors
    /// See [`CapabilityError`] — malformed JSON, an empty required field, a bad URL,
    /// an identity load failure, an invalid share token, or a link-secret recovery
    /// failure (identity mismatch).
    pub fn from_json(json: &str) -> Result<Self, CapabilityError> {
        let parsed: CapabilityBundleJson =
            serde_json::from_str(json).map_err(|e| CapabilityError::Malformed(e.to_string()))?;
        Self::from_parsed(parsed)
    }

    fn from_parsed(parsed: CapabilityBundleJson) -> Result<Self, CapabilityError> {
        // Required non-empty fields.
        if parsed.webui_base.trim().is_empty() {
            return Err(CapabilityError::EmptyField("webui_base"));
        }
        if parsed.group_id.trim().is_empty() {
            return Err(CapabilityError::EmptyField("group_id"));
        }
        validate_https_or_loopback("webui_base", &parsed.webui_base)?;

        // Resolve the identity path: env override > bundle field > per-user default.
        let identity_path = std::env::var_os(ENV_IDENTITY_PATH)
            .map(PathBuf::from)
            .or_else(|| {
                parsed
                    .identity_path
                    .as_ref()
                    .filter(|s| !s.trim().is_empty())
                    .map(PathBuf::from)
            })
            .unwrap_or_else(default_identity_path);

        // Load (or first-run generate) the MCP's persistent X25519 identity.
        let identity = McpIdentity::load_or_generate(&identity_path)
            .map_err(|e| CapabilityError::Identity(e.to_string()))?;

        // Parse the wrapped link-secret share token, then recover the link secret
        // with the MCP's own identity. A failure here means the token is not
        // addressed to THIS identity (wrong/rotated key) — surface it as a clear
        // re-authorize hint, never a panic.
        let token: ShareToken = serde_json::from_str(parsed.wrapped_link_secret.trim())
            .map_err(|e| CapabilityError::InvalidShareToken(e.to_string()))?;
        let link_secret = identity
            .accept_link_secret(&token)
            .map_err(|e| CapabilityError::LinkSecretRecovery(e.to_string()))?;

        let mcp_public_b64 = identity.public_key_b64();
        let mcp_fula_id = identity.fula_id();
        // `identity` (and its secret) drops here — only the public id + the
        // recovered link secret survive into the bundle.

        let timeout = Duration::from_secs(parsed.timeout_secs.unwrap_or(DEFAULT_TIMEOUT_SECS).max(1));

        // Validate the optional credit/quota host (a bearer is sent there).
        let storage_api_url = match parsed.storage_api_url.filter(|s| !s.trim().is_empty()) {
            Some(u) => {
                validate_https_or_loopback("storage_api_url", &u)?;
                Some(u)
            }
            None => None,
        };

        // Validate the optional write-token refresh URL (the refresh token is
        // POSTed there).
        let refresh_url = match parsed.refresh_url.filter(|s| !s.trim().is_empty()) {
            Some(u) => {
                validate_https_or_loopback("refresh_url", &u)?;
                Some(u)
            }
            None => None,
        };
        let refresh_token = parsed.refresh_token.filter(|s| !s.is_empty());
        let collab_write_token = parsed.collab_write_token.filter(|s| !s.is_empty());

        let http = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|e| CapabilityError::HttpClient(e.to_string()))?;

        let write_bucket = TokenBucket::new(
            parsed.write_burst.unwrap_or(DEFAULT_WRITE_BURST),
            parsed
                .write_refill_per_sec
                .unwrap_or(DEFAULT_WRITE_REFILL_PER_SEC),
        );

        Ok(CapabilityBundle {
            webui_base: parsed.webui_base.trim_end_matches('/').to_string(),
            group_id: parsed.group_id,
            manifest_bucket: parsed.manifest_bucket,
            manifest_key: parsed.manifest_key,
            link_secret: Zeroizing::new(link_secret),
            mcp_public_b64,
            mcp_fula_id,
            http,
            collab_write_token: std::sync::RwLock::new(collab_write_token),
            refresh_token,
            refresh_url,
            storage_api_url,
            user_id: parsed.user_id.filter(|s| !s.is_empty()),
            write_bucket,
        })
    }

    /// Construct a bundle from environment variables.
    ///
    /// Reads the JSON blob from [`ENV_CAPABILITY`], then applies out-of-band
    /// overrides (each only when set and non-empty): [`ENV_WRITE_TOKEN_OVERRIDE`]
    /// replaces `collab_write_token`, [`ENV_STORAGE_API_URL`] replaces the quota
    /// host, and [`ENV_WRITE_BURST`] / [`ENV_WRITE_REFILL_PER_SEC`] rebuild the
    /// write rate limiter.
    ///
    /// # Errors
    /// [`CapabilityError::MissingEnv`] if [`ENV_CAPABILITY`] is unset, plus any
    /// parse/validation error from [`CapabilityBundle::from_json`].
    pub fn from_env() -> Result<Self, CapabilityError> {
        let json =
            std::env::var(ENV_CAPABILITY).map_err(|_| CapabilityError::MissingEnv(ENV_CAPABILITY))?;
        let mut bundle = Self::from_json(&json)?;

        if let Ok(tok) = std::env::var(ENV_WRITE_TOKEN_OVERRIDE) {
            if !tok.is_empty() {
                bundle.set_collab_write_token(tok);
            }
        }
        if let Ok(url) = std::env::var(ENV_STORAGE_API_URL) {
            if !url.is_empty() {
                validate_https_or_loopback("storage_api_url", &url)?;
                bundle.storage_api_url = Some(url);
            }
        }
        let env_burst = std::env::var(ENV_WRITE_BURST).ok().and_then(|s| s.parse::<u32>().ok());
        let env_refill = std::env::var(ENV_WRITE_REFILL_PER_SEC)
            .ok()
            .and_then(|s| s.parse::<f64>().ok());
        if env_burst.is_some() || env_refill.is_some() {
            bundle.write_bucket = TokenBucket::new(
                env_burst.unwrap_or_else(|| bundle.write_bucket.capacity()),
                env_refill.unwrap_or(DEFAULT_WRITE_REFILL_PER_SEC),
            );
        }
        Ok(bundle)
    }

    /// The base URL for the group's `/api/collab/*` endpoints (no trailing slash).
    pub fn webui_base(&self) -> &str {
        &self.webui_base
    }

    /// The collaboration group UUID.
    pub fn group_id(&self) -> &str {
        &self.group_id
    }

    /// The bucket the group's manifest lives in (informational; used as the default
    /// `bucket` stamped on collab files the AI writes).
    pub fn manifest_bucket(&self) -> &str {
        &self.manifest_bucket
    }

    /// The key of the group's manifest in the bucket (informational).
    pub fn manifest_key(&self) -> &str {
        &self.manifest_key
    }

    /// The recovered 32-byte group link secret. Used to derive the manifest key
    /// (`enc1_*`), every collab-file key (`collab_file_*`), and the link keypair.
    pub fn link_secret(&self) -> &[u8] {
        &self.link_secret[..]
    }

    /// Build the **link keypair** — the X25519 keypair derived from the link
    /// secret. It is the recipient of the owner's per-file `fula` share tokens, so
    /// any group member (anyone holding the link secret) can accept them.
    ///
    /// # Errors
    /// [`CapabilityError::LinkSecretRecovery`] if the 32 bytes do not form a valid
    /// secret key (unreachable for a well-formed link secret).
    pub fn link_keypair(&self) -> Result<KekKeyPair, CapabilityError> {
        let secret = SecretKey::from_bytes(&self.link_secret[..])
            .map_err(|e| CapabilityError::LinkSecretRecovery(e.to_string()))?;
        Ok(KekKeyPair::from_secret_key(secret))
    }

    /// The MCP identity's X25519 public key (standard base64) — stamped as a file's
    /// `addedByPublicKey` when the AI writes into the manifest.
    pub fn mcp_public_b64(&self) -> &str {
        &self.mcp_public_b64
    }

    /// The MCP identity's `FULA-…` share id (the string the owner authorized).
    pub fn mcp_fula_id(&self) -> &str {
        &self.mcp_fula_id
    }

    /// The shared, timeout-configured HTTP client.
    pub fn http(&self) -> &reqwest::Client {
        &self.http
    }

    /// A clone of the current group-scoped write Bearer, if the session has one.
    /// `None` ⇒ the session is read-only (writes return a clear "not configured"
    /// error before any network I/O).
    pub fn collab_write_token(&self) -> Option<String> {
        self.collab_write_token
            .read()
            .expect("collab_write_token lock poisoned")
            .clone()
    }

    /// Swap in a freshly re-minted write Bearer (after a 401/403 refresh), in place,
    /// behind the shared `&self`. The lock is held only for the brief replace.
    pub fn set_collab_write_token(&self, new: String) {
        *self
            .collab_write_token
            .write()
            .expect("collab_write_token lock poisoned") = Some(new);
    }

    /// The long-lived token to re-mint the write Bearer, if configured (a SECRET —
    /// callers pass it to the refresh helper but MUST NEVER log it).
    pub fn refresh_token(&self) -> Option<&str> {
        self.refresh_token.as_deref()
    }

    /// The endpoint that re-mints the write Bearer, if configured.
    pub fn refresh_url(&self) -> Option<&str> {
        self.refresh_url.as_deref()
    }

    /// The configured credit/quota host, if any. `None` ⇒ the quota pre-check is
    /// OFF (fail-open).
    pub fn storage_api_url(&self) -> Option<&str> {
        self.storage_api_url.as_deref()
    }

    /// The informational owner `userId`, if supplied.
    pub fn user_id(&self) -> Option<&str> {
        self.user_id.as_deref()
    }

    /// Run the fail-fast quota pre-check, sending the write Bearer to the credit
    /// host. Only [`QuotaDecision::Denied`] should block a write; every other
    /// outcome (including fail-open) proceeds. No `storage_api_url` ⇒ a no-network
    /// `SkippedFailOpen`.
    pub async fn check_quota(&self) -> QuotaDecision {
        let token = self.collab_write_token();
        check_quota(self.storage_api_url.as_deref(), token.as_deref()).await
    }

    /// Take one WRITE token from the per-session rate limiter. `true` ⇒ proceed;
    /// `false` ⇒ over the local write-rate limit. Call AFTER input validation so a
    /// rejected write cannot drain the budget.
    pub fn try_consume_write_token(&self) -> bool {
        self.write_bucket.try_consume()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fula_crypto::{DekKey, sharing::ShareBuilder, KekKeyPair};

    /// Build a bundle JSON with a wrapped link secret addressed to `mcp_pubkey`.
    fn bundle_json(
        owner: &KekKeyPair,
        mcp_pubkey: &fula_crypto::PublicKey,
        link_secret: &[u8; 32],
        identity_path: &str,
        write_token: Option<&str>,
    ) -> String {
        let dek = DekKey::from_bytes(link_secret).unwrap();
        let token = ShareBuilder::new(owner, mcp_pubkey, &dek)
            .path_scope("/collab/group-1")
            .build()
            .unwrap();
        let wrapped = serde_json::to_string(&token).unwrap();
        let wt = match write_token {
            Some(t) => format!(r#","collab_write_token":"{t}""#),
            None => String::new(),
        };
        format!(
            r#"{{"webui_base":"https://cloud.fx.land","group_id":"group-1","manifest_bucket":"fula-metadata","manifest_key":"m/group-1.json","wrapped_link_secret":{wrapped:?},"identity_path":{identity_path:?}{wt}}}"#
        )
    }

    fn temp_identity_path(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "fula_mcp_cap_test_{}_{}_{:?}",
            tag,
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("mcp_identity.key")
    }

    #[test]
    fn validate_url_accepts_https_and_exact_loopback_rejects_spoofs() {
        // Accept: https anywhere, and http ONLY for an exact loopback host.
        for ok in [
            "https://cloud.fx.land",
            "https://cloud.fx.land/api/x?y=1",
            "http://localhost:8787/cap",
            "http://127.0.0.1:9000",
            "http://[::1]:3000/refresh",
            // Decimal-encoded 127.0.0.1: the url crate normalizes the host to
            // 127.0.0.1, so this IS loopback (the user's own machine) — correctly
            // accepted. A naive prefix check would have wrongly rejected it.
            "http://2130706433/",
        ] {
            assert!(validate_https_or_loopback("f", ok).is_ok(), "should accept {ok}");
        }
        // Reject: cleartext non-loopback + the loopback-spoof family that a prefix
        // check would have admitted (subdomain, userinfo trick, scheme).
        for bad in [
            "http://evil.com",
            "http://localhost.evil.com",
            "http://localhost@evil.com",
            "http://localhost:80@evil.com",
            "http://127.0.0.1.evil.com",
            "ftp://localhost/x",
            "file:///etc/passwd",
            "not-a-url",
        ] {
            assert!(
                validate_https_or_loopback("f", bad).is_err(),
                "should REJECT {bad}"
            );
        }
    }

    #[test]
    fn from_json_recovers_link_secret_and_exposes_group() {
        let id_path = temp_identity_path("recover");
        let _ = std::fs::remove_file(&id_path);
        // First-run: generate the identity by loading once.
        let identity = McpIdentity::load_or_generate(&id_path).unwrap();
        let owner = KekKeyPair::generate();
        let link_secret = [0x11u8; 32];
        let json = bundle_json(
            &owner,
            identity.public_key(),
            &link_secret,
            id_path.to_str().unwrap(),
            Some("write-tok-abc"),
        );

        let bundle = CapabilityBundle::from_json(&json).unwrap();
        assert_eq!(bundle.group_id(), "group-1");
        assert_eq!(bundle.webui_base(), "https://cloud.fx.land");
        assert_eq!(bundle.manifest_bucket(), "fula-metadata");
        assert_eq!(bundle.link_secret(), &link_secret[..]);
        assert_eq!(bundle.collab_write_token().as_deref(), Some("write-tok-abc"));
        assert_eq!(bundle.mcp_public_b64(), identity.public_key_b64());
        // The link keypair derives deterministically from the link secret.
        let kp = bundle.link_keypair().unwrap();
        let expected = KekKeyPair::from_secret_key(SecretKey::from_bytes(&link_secret).unwrap());
        assert_eq!(kp.public_key().as_bytes(), expected.public_key().as_bytes());

        let _ = std::fs::remove_file(&id_path);
        let _ = std::fs::remove_dir(id_path.parent().unwrap());
    }

    #[test]
    fn wrong_identity_cannot_recover_link_secret() {
        // A bundle wrapped for a DIFFERENT identity must fail with a clear error,
        // not a panic — this is the "re-authorize" path.
        let id_path = temp_identity_path("wrong");
        let _ = std::fs::remove_file(&id_path);
        let _ours = McpIdentity::load_or_generate(&id_path).unwrap();
        let owner = KekKeyPair::generate();
        let stranger = McpIdentity::generate();
        let json = bundle_json(
            &owner,
            stranger.public_key(), // wrapped for someone else
            &[0x22u8; 32],
            id_path.to_str().unwrap(),
            None,
        );
        let err = CapabilityBundle::from_json(&json).unwrap_err();
        assert!(matches!(err, CapabilityError::LinkSecretRecovery(_)));
        let _ = std::fs::remove_file(&id_path);
        let _ = std::fs::remove_dir(id_path.parent().unwrap());
    }

    #[test]
    fn read_only_bundle_has_no_write_token() {
        let id_path = temp_identity_path("readonly");
        let _ = std::fs::remove_file(&id_path);
        let identity = McpIdentity::load_or_generate(&id_path).unwrap();
        let owner = KekKeyPair::generate();
        let json = bundle_json(
            &owner,
            identity.public_key(),
            &[0x33u8; 32],
            id_path.to_str().unwrap(),
            None,
        );
        let bundle = CapabilityBundle::from_json(&json).unwrap();
        assert!(bundle.collab_write_token().is_none());
        // A refresh can swap one in later.
        bundle.set_collab_write_token("fresh".to_string());
        assert_eq!(bundle.collab_write_token().as_deref(), Some("fresh"));
        let _ = std::fs::remove_file(&id_path);
        let _ = std::fs::remove_dir(id_path.parent().unwrap());
    }

    #[test]
    fn rejects_non_https_webui_base() {
        let json = r#"{"webui_base":"http://evil.example","group_id":"g","manifest_bucket":"b","manifest_key":"k","wrapped_link_secret":"{}"}"#;
        let err = CapabilityBundle::from_json(json).unwrap_err();
        assert!(matches!(err, CapabilityError::InvalidUrl { field: "webui_base", .. }));
    }
}
