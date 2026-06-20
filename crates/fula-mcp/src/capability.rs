//! # Capability bundle — the MCP's in-memory, per-session authority
//!
//! Phase 3 of the stateless-MCP line. The MCP server (the "AI") is a **stateless
//! proxy**: it persists NO user data. Every piece of capability material is
//! **injected per session** and held **in memory only** — never written to disk,
//! never logged.
//!
//! ## The connection bundle
//!
//! A [`CapabilityBundle`] carries exactly four things (resolved in P1/P2):
//!
//! 1. A **scoped gateway JWT** + S3 endpoint. The token's PUT/GET authority is
//!    limited (by the gateway) to AI-workspace buckets. Gateway-side enforcement
//!    is a later phase; here we just carry the token and hand it to the client.
//! 2. A **dedicated AI-workspace encryption secret** — a 32-byte secret that is
//!    **NOT** the user's master KEK. The AI builds an [`EncryptedClient`] from it
//!    to read/write its OWN workspace buckets. FxFiles also knows this secret, so
//!    it can read the workspace directly; the AI cannot read the user's real
//!    files, because those use a different, never-shared secret.
//! 3. The MCP's **own X25519 keypair**. Used to ACCEPT `owner -> MCP` grant share
//!    tokens — the path by which the owner explicitly hands the AI read access to
//!    a specific real file.
//! 4. The **owner's X25519 public key**. Used to MINT `AI -> owner` share tokens
//!    when the AI writes a workspace file, wrapping the per-file content DEK to
//!    the owner so the owner can read what the AI wrote (the P2 "inverse share"
//!    pattern, which needs no new crypto and no forest-format change).
//!
//! Plus a list of **grants** ([`Capability`]) — the positive, scoped
//! read/write/delete authorities this session holds. The workspace itself is a
//! grant; owner-granted real-file prefixes are grants too. [`assert_in_scope`]
//! checks an access against this list and is the security boundary that closes
//! the P2 substring-prefix footgun.
//!
//! [`assert_in_scope`]: CapabilityBundle::assert_in_scope
//!
//! ## Security properties
//!
//! - **No secret on disk, no secret in logs.** The bundle deliberately does not
//!   (and cannot) derive [`Debug`] — [`SecretKey`] has no `Debug`. The
//!   hand-written [`Debug`] impl redacts every secret. Intermediate decoded key
//!   bytes are zeroized immediately after the typed key is constructed; the
//!   typed keys ([`SecretKey`]) are `ZeroizeOnDrop`.
//! - **Scope is a security boundary, not a hint.** [`CapabilityBundle::assert_in_scope`]
//!   matches on canonicalized path *segments*, so a grant of `ai/note` does not
//!   admit `ai/notebook`, and a grant of `a` does not admit `ai/foo`. It also
//!   enforces the requested [`Permission`] against the covering grant.
//!
//! ## Bundle wire format (injected at startup; NEVER persisted)
//!
//! A single JSON object (see [`CapabilityBundleJson`]). Example:
//!
//! ```json
//! {
//!   "endpoint": "https://gateway.example",
//!   "jwt": "<scoped gateway JWT>",
//!   "workspace_secret_b64": "<base64 of 32-byte workspace secret>",
//!   "mcp_secret_b64": "<base64 of 32-byte MCP X25519 secret>",
//!   "owner_public_b64": "<base64 of 32-byte owner X25519 public key>",
//!   "grants": [
//!     { "scope": "ai/", "permissions": { "can_read": true, "can_write": true, "can_delete": true } }
//!   ]
//! }
//! ```
//!
//! Load it with [`CapabilityBundle::from_json`] (or [`CapabilityBundle::from_env`]
//! reading `FULA_MCP_CAPABILITY` for the JSON and `FULA_MCP_JWT` to override the
//! token out-of-band). The JSON is consumed and dropped immediately; only the
//! in-memory typed bundle survives.

use std::time::Duration;

use base64::Engine as _;
use fula_client::{Config, EncryptedClient, EncryptionConfig};
use fula_crypto::{
    AcceptedShare, DekKey, KekKeyPair, PublicKey, SecretKey, SharePermissions, ShareBuilder,
    ShareRecipient, ShareToken,
};
use serde::Deserialize;
use thiserror::Error;
use zeroize::Zeroize;

/// The default S3 client request timeout when the bundle does not specify one.
const DEFAULT_TIMEOUT_SECS: u64 = 60;

/// Environment variable that carries the capability bundle JSON.
pub const ENV_CAPABILITY: &str = "FULA_MCP_CAPABILITY";

/// Environment variable that, if set, overrides the bundle's `jwt` field. Lets an
/// operator inject the short-lived token out-of-band from the rest of the bundle.
pub const ENV_JWT_OVERRIDE: &str = "FULA_MCP_JWT";

/// The access a caller needs for a given key. Maps onto [`SharePermissions`].
///
/// These are *positive* permissions checked against a covering grant; there are
/// no deny rules (the grant list is allow-only).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Permission {
    /// Read an object (GET).
    Read,
    /// Create or overwrite an object (PUT).
    Write,
    /// Delete an object (DELETE).
    Delete,
}

impl Permission {
    /// Is this permission granted by `perms`?
    fn granted_by(self, perms: &SharePermissions) -> bool {
        match self {
            Permission::Read => perms.can_read,
            Permission::Write => perms.can_write,
            Permission::Delete => perms.can_delete,
        }
    }
}

/// Errors surfaced by the capability layer.
#[derive(Debug, Error)]
pub enum CapabilityError {
    /// The injected bundle JSON was malformed or missing required fields.
    #[error("malformed capability bundle: {0}")]
    Malformed(String),

    /// A base64 secret/key field did not decode to the required length.
    #[error("invalid key material in bundle field `{field}`: {reason}")]
    InvalidKeyMaterial {
        /// Which JSON field failed.
        field: &'static str,
        /// Why it failed (length / decode).
        reason: String,
    },

    /// A required environment variable was not set.
    #[error("environment variable `{0}` is not set")]
    MissingEnv(&'static str),

    /// A path/key/scope failed canonicalization (empty, traversal, etc.).
    #[error("invalid path `{path}`: {reason}")]
    InvalidPath {
        /// The offending path.
        path: String,
        /// Why it is invalid.
        reason: &'static str,
    },

    /// The key is outside every granted scope (or no grant has the needed
    /// permission). This is the access-DENIED outcome.
    #[error("access denied: `{key}` not within any granted scope with `{needed:?}` permission")]
    OutOfScope {
        /// The key that was checked.
        key: String,
        /// The permission that was required.
        needed: Permission,
    },

    /// Building the underlying encrypted client failed.
    #[error("failed to build workspace client: {0}")]
    Client(String),

    /// Minting or accepting a share token failed.
    #[error("share operation failed: {0}")]
    Share(String),
}

/// One positive, scoped authority the session holds.
///
/// `scope` is a path *prefix* (e.g. `ai/` or `ai/notes`); `permissions` is the
/// read/write/delete it grants under that prefix.
#[derive(Clone, Deserialize)]
pub struct Capability {
    /// The path-prefix scope this capability covers (canonicalized at check time).
    pub scope: String,
    /// What the holder may do under `scope`.
    pub permissions: SharePermissions,
}

impl std::fmt::Debug for Capability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Capability")
            .field("scope", &self.scope)
            .field("permissions", &self.permissions)
            .finish()
    }
}

/// The MCP's in-memory, per-session capability bundle.
///
/// Constructed from an injected JSON blob via [`CapabilityBundle::from_json`] /
/// [`CapabilityBundle::from_env`]. Holds secret key material; it is never written
/// to disk and never logged (see the redacting [`Debug`] impl).
pub struct CapabilityBundle {
    /// S3 / gateway endpoint URL.
    endpoint: String,
    /// Scoped gateway JWT (bearer token). Carried verbatim; treated as a secret.
    jwt: String,
    /// Client request timeout.
    timeout: Duration,
    /// The dedicated AI-workspace encryption secret (NOT the user's master KEK).
    workspace_secret: SecretKey,
    /// The MCP's own X25519 keypair (accepts owner -> MCP grants; signs AI -> owner
    /// shares once token signing lands).
    mcp_keypair: KekKeyPair,
    /// The owner's X25519 public key (recipient of AI -> owner shares).
    owner_public: PublicKey,
    /// The positive scoped grants this session holds.
    grants: Vec<Capability>,
}

/// On-the-wire JSON shape of the bundle. Deserialized, consumed, and dropped at
/// construction — only the typed [`CapabilityBundle`] survives in memory.
///
/// This type is intentionally NOT public API beyond documentation: callers go
/// through [`CapabilityBundle::from_json`].
#[derive(Deserialize)]
struct CapabilityBundleJson {
    endpoint: String,
    jwt: String,
    /// Base64 of the 32-byte AI-workspace encryption secret.
    workspace_secret_b64: String,
    /// Base64 of the 32-byte MCP X25519 secret key.
    mcp_secret_b64: String,
    /// Base64 of the 32-byte owner X25519 public key.
    owner_public_b64: String,
    /// Optional client timeout (seconds). Defaults to [`DEFAULT_TIMEOUT_SECS`].
    #[serde(default)]
    timeout_secs: Option<u64>,
    /// The positive scoped grants.
    #[serde(default)]
    grants: Vec<Capability>,
}

impl std::fmt::Debug for CapabilityBundle {
    /// Redacting debug — NEVER prints any secret (workspace secret, MCP secret,
    /// or JWT). Only non-sensitive shape is shown.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CapabilityBundle")
            .field("endpoint", &self.endpoint)
            .field("jwt", &"<redacted>")
            .field("timeout", &self.timeout)
            .field("workspace_secret", &"<redacted>")
            .field("mcp_secret", &"<redacted>")
            // Public key is, by definition, public — safe to show.
            .field("mcp_public", &self.mcp_keypair.public_key())
            .field("owner_public", &self.owner_public)
            .field("grants", &self.grants)
            .finish()
    }
}

/// Decode a base64 field into a fixed 32-byte array, zeroizing the intermediate
/// decoded `Vec` on the way out. The returned array is the caller's to wrap into
/// a typed key (and then drop/zeroize per that type's policy).
fn decode_secret_32(field: &'static str, b64: &str) -> Result<[u8; 32], CapabilityError> {
    let mut raw = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .map_err(|e| CapabilityError::InvalidKeyMaterial {
            field,
            reason: format!("base64 decode failed: {e}"),
        })?;
    if raw.len() != 32 {
        // Wipe whatever we decoded before erroring out.
        raw.zeroize();
        return Err(CapabilityError::InvalidKeyMaterial {
            field,
            reason: format!("expected 32 bytes, got {}", raw.len()),
        });
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    raw.zeroize();
    Ok(out)
}

impl CapabilityBundle {
    /// Parse a bundle from its injected JSON form.
    ///
    /// The JSON string is parsed into [`CapabilityBundleJson`], the secret fields
    /// are decoded into typed keys (intermediate bytes zeroized), and the JSON
    /// struct is dropped. Nothing touches the disk.
    ///
    /// # Errors
    /// - [`CapabilityError::Malformed`] if the JSON is invalid or missing fields.
    /// - [`CapabilityError::InvalidKeyMaterial`] if a secret/key field is not a
    ///   valid base64 32-byte value.
    pub fn from_json(json: &str) -> Result<Self, CapabilityError> {
        let parsed: CapabilityBundleJson = serde_json::from_str(json)
            .map_err(|e| CapabilityError::Malformed(e.to_string()))?;
        Self::from_parsed(parsed)
    }

    /// Build from the deserialized JSON struct, decoding key material and wiping
    /// the base64 intermediates. `parsed` is consumed; its base64 secret strings
    /// are zeroized before it drops.
    fn from_parsed(mut parsed: CapabilityBundleJson) -> Result<Self, CapabilityError> {
        // Decode workspace secret.
        let mut ws_bytes = decode_secret_32("workspace_secret_b64", &parsed.workspace_secret_b64)?;
        let workspace_secret = SecretKey::from_bytes(&ws_bytes).map_err(|e| {
            CapabilityError::InvalidKeyMaterial {
                field: "workspace_secret_b64",
                reason: e.to_string(),
            }
        })?;
        ws_bytes.zeroize();

        // Decode MCP secret -> keypair.
        let mut mcp_bytes = decode_secret_32("mcp_secret_b64", &parsed.mcp_secret_b64)?;
        let mcp_secret = SecretKey::from_bytes(&mcp_bytes).map_err(|e| {
            CapabilityError::InvalidKeyMaterial {
                field: "mcp_secret_b64",
                reason: e.to_string(),
            }
        })?;
        mcp_bytes.zeroize();
        let mcp_keypair = KekKeyPair::from_secret_key(mcp_secret);

        // Decode owner public key (NOT a secret, but length-validated).
        let owner_bytes = decode_secret_32("owner_public_b64", &parsed.owner_public_b64)?;
        let owner_public =
            PublicKey::from_bytes(&owner_bytes).map_err(|e| CapabilityError::InvalidKeyMaterial {
                field: "owner_public_b64",
                reason: e.to_string(),
            })?;

        let timeout =
            Duration::from_secs(parsed.timeout_secs.unwrap_or(DEFAULT_TIMEOUT_SECS).max(1));

        let bundle = CapabilityBundle {
            endpoint: std::mem::take(&mut parsed.endpoint),
            jwt: std::mem::take(&mut parsed.jwt),
            timeout,
            workspace_secret,
            mcp_keypair,
            owner_public,
            grants: std::mem::take(&mut parsed.grants),
        };

        // Best-effort wipe of the base64 secret strings in the parsed struct
        // before it drops (the typed keys above are the authoritative copies).
        parsed.workspace_secret_b64.zeroize();
        parsed.mcp_secret_b64.zeroize();

        Ok(bundle)
    }

    /// Construct a bundle from environment variables.
    ///
    /// Reads the JSON blob from [`ENV_CAPABILITY`]. If [`ENV_JWT_OVERRIDE`] is
    /// set and non-empty, it replaces the bundle's `jwt` (so the short-lived
    /// token can be injected separately from the rest of the bundle).
    ///
    /// # Errors
    /// [`CapabilityError::MissingEnv`] if [`ENV_CAPABILITY`] is unset, plus any
    /// parse error from [`CapabilityBundle::from_json`].
    pub fn from_env() -> Result<Self, CapabilityError> {
        let json =
            std::env::var(ENV_CAPABILITY).map_err(|_| CapabilityError::MissingEnv(ENV_CAPABILITY))?;
        let mut bundle = Self::from_json(&json)?;
        if let Ok(jwt) = std::env::var(ENV_JWT_OVERRIDE) {
            if !jwt.is_empty() {
                bundle.jwt = jwt;
            }
        }
        Ok(bundle)
    }

    /// The configured gateway endpoint.
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// The MCP's own X25519 public key (safe to share; e.g. so the owner can mint
    /// `owner -> MCP` grants addressed to it).
    pub fn mcp_public_key(&self) -> &PublicKey {
        self.mcp_keypair.public_key()
    }

    /// The owner's X25519 public key (recipient of `AI -> owner` shares).
    pub fn owner_public_key(&self) -> &PublicKey {
        &self.owner_public
    }

    /// The positive scoped grants this session holds.
    pub fn grants(&self) -> &[Capability] {
        &self.grants
    }

    /// Build the AI-workspace [`EncryptedClient`] from the workspace secret +
    /// scoped JWT + endpoint.
    ///
    /// This is the client the AI uses to read/write its OWN workspace buckets.
    /// It is encrypted under the *dedicated workspace secret*, NOT the user's
    /// master KEK, so it can never decrypt the user's real files.
    ///
    /// # Errors
    /// [`CapabilityError::Client`] if the underlying client cannot be built.
    pub fn workspace_client(&self) -> Result<EncryptedClient, CapabilityError> {
        let config = Config::new(self.endpoint.clone())
            .with_token(self.jwt.clone())
            .with_encryption()
            .with_timeout(self.timeout);
        // `EncryptionConfig::from_secret_key` takes the secret by value; clone the
        // in-memory copy so the bundle retains ownership of its workspace secret.
        let encryption = EncryptionConfig::from_secret_key(self.workspace_secret.clone());
        EncryptedClient::new(config, encryption).map_err(|e| CapabilityError::Client(e.to_string()))
    }

    /// Accept an `owner -> MCP` grant share token using the MCP's own keypair.
    ///
    /// The owner mints a [`ShareToken`] addressed to [`Self::mcp_public_key`]
    /// (wrapping a real file's content/folder DEK); this recovers the DEK + scope
    /// so the AI can read that specific granted file. The strict v5
    /// [`ShareRecipient::accept_share`] rejects any token not addressed to this
    /// keypair (and any pre-v5 token).
    ///
    /// # Errors
    /// [`CapabilityError::Share`] if the token is not addressed to the MCP, is
    /// expired, or is otherwise invalid.
    pub fn accept_grant(&self, token: &ShareToken) -> Result<AcceptedShare, CapabilityError> {
        ShareRecipient::new(&self.mcp_keypair)
            .accept_share(token)
            .map_err(|e| CapabilityError::Share(e.to_string()))
    }

    /// Mint an `AI -> owner` share token: wrap a per-file content `dek` to the
    /// **owner's** public key so the owner can read a file the AI wrote into the
    /// workspace.
    ///
    /// Mirrors the proven P2 pattern exactly: the token carries the `path_scope`,
    /// the single-block `nonce` (base64) and/or `chunked_metadata` (JSON), and
    /// `encryption_version = 4` (AAD-bound content). The sender keypair is the
    /// MCP's own (`mcp_keypair`) so the share is attributable to the MCP when
    /// token signing lands. Permissions are read-write (the AI authored the file
    /// under its scope, and the owner consuming it gets read-write semantics, as
    /// in P2).
    ///
    /// `nonce_b64` and `chunked_metadata` are mutually-shaped: pass `nonce_b64`
    /// for a single-block (v4) object, `chunked_metadata` for a chunked one. At
    /// least conceptually one is present; both may be `None` for a degenerate
    /// empty object, matching the builder's optionality.
    ///
    /// # Errors
    /// [`CapabilityError::Share`] if the token cannot be built.
    #[allow(clippy::too_many_arguments)]
    pub fn mint_owner_share(
        &self,
        dek: &DekKey,
        path_scope: &str,
        nonce_b64: Option<&str>,
        chunked_metadata: Option<&str>,
        expires_in_secs: Option<i64>,
    ) -> Result<ShareToken, CapabilityError> {
        let mut builder = ShareBuilder::new(&self.mcp_keypair, &self.owner_public, dek)
            .path_scope(path_scope)
            .read_write()
            .encryption_version(4);
        if let Some(n) = nonce_b64 {
            builder = builder.nonce(n.to_string());
        }
        if let Some(m) = chunked_metadata {
            builder = builder.chunked_metadata(m.to_string());
        }
        if let Some(secs) = expires_in_secs {
            builder = builder.expires_in(secs);
        }
        builder
            .build()
            .map_err(|e| CapabilityError::Share(e.to_string()))
    }

    /// Assert that `key` is within `scope` AND that the covering grant permits
    /// `needed`. This is the security boundary that replaces the P2
    /// substring-prefix footgun.
    ///
    /// `scope` names the grant the caller intends to use (e.g. `"ai/"`). The
    /// check is twofold:
    ///
    /// 1. **Geometry** — `key` must be inside `scope` by *path segment* boundary
    ///    (see [`Self::key_in_scope`]). A scope of `ai/note` does NOT admit
    ///    `ai/notebook`; a scope of `a` does NOT admit `ai/foo`. Exact equality
    ///    is admitted (a single-object grant).
    /// 2. **Authority** — the bundle must actually hold a grant whose canonical
    ///    scope equals the canonical `scope`, and that grant must include the
    ///    `needed` permission. A caller cannot conjure authority by passing a
    ///    `scope` the bundle never granted (e.g. `""` or `"/"`), and cannot
    ///    upgrade Read to Write/Delete it was not given.
    ///
    /// # Errors
    /// - [`CapabilityError::InvalidPath`] if `key` or `scope` fails
    ///   canonicalization (empty, or contains a `.`/`..` traversal segment).
    /// - [`CapabilityError::OutOfScope`] if `key` is not inside `scope`, the
    ///   bundle holds no matching grant, or the grant lacks `needed`.
    pub fn assert_in_scope(
        &self,
        key: &str,
        scope: &str,
        needed: Permission,
    ) -> Result<(), CapabilityError> {
        // Canonicalize. The KEY is checked STRICTLY (no empty/leading/trailing/
        // doubled slash, no traversal): a key that passes is already in canonical
        // textual form, so the SAME string the caller blesses here is the one it
        // must hand to the storage client. Storage keys are hashed verbatim by
        // `generate_flat_key(logical_path, …)`, so `ai//foo` and `ai/foo` are
        // DIFFERENT objects — were we to canonicalize the key leniently, the
        // blessed form could diverge from the stored form (a scope-broadening
        // aliasing bug). The SCOPE is an authorization *pattern* that never
        // reaches storage, so it is normalized leniently (the task requires both
        // `ai/` and `ai` to work).
        let key_segs = canonicalize_key(key)?;
        let scope_segs = canonicalize_scope(scope)?;

        // (1) Geometry: key must be inside the requested scope by segment prefix.
        if !key_in_scope(&key_segs, &scope_segs) {
            return Err(CapabilityError::OutOfScope {
                key: key.to_string(),
                needed,
            });
        }

        // (2) Authority: the bundle must hold a grant whose canonical scope
        //     EQUALS the requested scope, with the needed permission. We match on
        //     equality (not "grant covers scope") so the caller-named scope is
        //     itself an authorized grant — a caller cannot widen authority by
        //     naming a broader scope than it was granted.
        let authorized = self.grants.iter().any(|g| {
            match canonicalize_scope(&g.scope) {
                Ok(g_segs) => g_segs == scope_segs && needed.granted_by(&g.permissions),
                // A malformed grant scope never authorizes anything.
                Err(_) => false,
            }
        });

        if !authorized {
            return Err(CapabilityError::OutOfScope {
                key: key.to_string(),
                needed,
            });
        }

        Ok(())
    }

    /// Convenience: assert `key` is permitted for `needed` under ANY grant the
    /// bundle holds (most-permissive-wins over the positive grant list).
    ///
    /// Unlike [`Self::assert_in_scope`], the caller need not name the scope; this
    /// scans every grant and succeeds if any one canonically covers `key` with
    /// the `needed` permission. Useful for an enforcement wrapper that just asks
    /// "may I touch this key at all?".
    ///
    /// # Errors
    /// - [`CapabilityError::InvalidPath`] if `key` fails canonicalization.
    /// - [`CapabilityError::OutOfScope`] if no grant covers `key` with `needed`.
    pub fn assert_key_allowed(
        &self,
        key: &str,
        needed: Permission,
    ) -> Result<(), CapabilityError> {
        let key_segs = canonicalize_key(key)?;
        let ok = self.grants.iter().any(|g| match canonicalize_scope(&g.scope) {
            Ok(g_segs) => key_in_scope(&key_segs, &g_segs) && needed.granted_by(&g.permissions),
            Err(_) => false,
        });
        if ok {
            Ok(())
        } else {
            Err(CapabilityError::OutOfScope {
                key: key.to_string(),
                needed,
            })
        }
    }
}

/// Reject bytes that are dangerous in any path position (key or scope).
///
/// Only NUL is rejected here. Percent (`%`) is intentionally NOT rejected: the
/// logical path is fed verbatim into `generate_flat_key`
/// (`blake3 …update(original_path.as_bytes())` — see
/// `fula-crypto::private_forest::generate_flat_key`), and never placed into a URL
/// that a layer would percent-decode. So `%` is just an ordinary byte here, and a
/// legitimate AI filename like `q3-50%-off.txt` must not be falsely denied. NUL
/// is rejected as pure upside (it can corrupt logging / FFI / tooling downstream).
fn reject_dangerous_bytes(path: &str) -> Result<(), CapabilityError> {
    if path.contains('\0') {
        return Err(CapabilityError::InvalidPath {
            path: path.to_string(),
            reason: "contains NUL byte",
        });
    }
    Ok(())
}

/// Canonicalize a **storage key** into path segments — STRICT.
///
/// A key is the identifier that reaches storage: `put_object_flat`/
/// `get_object_flat` hash it verbatim via `generate_flat_key`, so two textually
/// different keys (`ai/foo` vs `ai//foo` vs `/ai/foo`) are DIFFERENT objects.
/// Because [`assert_in_scope`] returns only `Result<()>` (it cannot hand back a
/// rewritten key), the *only* way to guarantee the key the check blesses is the
/// key storage uses is to **reject any non-canonical key** here. A key that
/// passes is already in canonical form and must be used verbatim by the caller.
///
/// Rejects: an empty key, a leading `/`, a trailing `/`, any doubled `//`
/// (i.e. ANY empty segment), and any `.`/`..` traversal segment. Matching is
/// **case-sensitive**; `\` is an ordinary byte (kept safe by exact segment
/// equality, not treated as a separator).
///
/// [`assert_in_scope`]: CapabilityBundle::assert_in_scope
///
/// # Errors
/// [`CapabilityError::InvalidPath`] for an empty key, any empty segment
/// (leading/trailing/doubled slash), a `.`/`..` segment, or a NUL byte.
fn canonicalize_key(key: &str) -> Result<Vec<&str>, CapabilityError> {
    reject_dangerous_bytes(key)?;
    if key.is_empty() {
        return Err(CapabilityError::InvalidPath {
            path: key.to_string(),
            reason: "empty key",
        });
    }
    let segs: Vec<&str> = key.split('/').collect();
    for seg in &segs {
        if seg.is_empty() {
            return Err(CapabilityError::InvalidPath {
                path: key.to_string(),
                reason: "non-canonical key: empty segment (leading, trailing, or doubled '/')",
            });
        }
        if *seg == "." || *seg == ".." {
            return Err(CapabilityError::InvalidPath {
                path: key.to_string(),
                reason: "contains a '.' or '..' path-traversal segment",
            });
        }
    }
    Ok(segs)
}

/// Canonicalize an authorization **scope** into path segments — LENIENT.
///
/// A scope is a *pattern* used only to authorize; it NEVER reaches storage, so
/// normalizing it cannot cause a check-vs-store mismatch. The task requires both
/// `ai/` and `ai` to grant the `ai/` subtree, so empty segments (leading/
/// trailing/doubled slash) are DROPPED. `.`/`..` are still rejected (a scope has
/// nothing to resolve them against), as is an empty result and NUL.
///
/// # Errors
/// [`CapabilityError::InvalidPath`] for an empty canonical form (e.g. `""` or
/// `"/"`), a `.`/`..` segment, or a NUL byte.
fn canonicalize_scope(scope: &str) -> Result<Vec<&str>, CapabilityError> {
    reject_dangerous_bytes(scope)?;
    let mut segs = Vec::new();
    for seg in scope.split('/') {
        if seg.is_empty() {
            continue; // drop leading/trailing/doubled slash
        }
        if seg == "." || seg == ".." {
            return Err(CapabilityError::InvalidPath {
                path: scope.to_string(),
                reason: "contains a '.' or '..' path-traversal segment",
            });
        }
        segs.push(seg);
    }
    if segs.is_empty() {
        return Err(CapabilityError::InvalidPath {
            path: scope.to_string(),
            reason: "scope is empty after canonicalization (no path segments)",
        });
    }
    Ok(segs)
}

/// Is `key` inside `scope` by path-segment prefix?
///
/// True iff `key`'s segment list starts with `scope`'s segment list, compared
/// element-by-element. Equal lists prefix each other, so an exact key == scope
/// match is admitted (single-object grant). This is the segment-boundary check
/// that closes the substring-prefix footgun: `["ai","note"]` does NOT prefix
/// `["ai","notebook"]`, and `["a"]` does NOT prefix `["ai","foo"]`.
fn key_in_scope(key_segs: &[&str], scope_segs: &[&str]) -> bool {
    key_segs.starts_with(scope_segs)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── canonicalize / key_in_scope: the security crux ─────────────────────

    #[test]
    fn scope_canon_drops_empty_and_normalizes_slashes() {
        // Scope is lenient: leading/trailing/doubled slashes are dropped so both
        // `ai/` and `ai` name the same subtree.
        assert_eq!(canonicalize_scope("ai/foo").unwrap(), vec!["ai", "foo"]);
        assert_eq!(canonicalize_scope("ai/").unwrap(), vec!["ai"]);
        assert_eq!(canonicalize_scope("/ai").unwrap(), vec!["ai"]);
        assert_eq!(canonicalize_scope("ai//foo").unwrap(), vec!["ai", "foo"]);
        assert_eq!(canonicalize_scope("/ai/foo/").unwrap(), vec!["ai", "foo"]);
        assert_eq!(canonicalize_scope("ai").unwrap(), vec!["ai"]);
    }

    #[test]
    fn key_canon_is_strict_about_non_canonical_forms() {
        // A key is the stored identifier; it must already be canonical so the
        // checked string == the stored string. Non-canonical forms are REJECTED
        // (not silently normalized) to prevent a check-vs-store aliasing gap.
        assert_eq!(canonicalize_key("ai/foo").unwrap(), vec!["ai", "foo"]);
        assert_eq!(
            canonicalize_key("ai/notes/x.txt").unwrap(),
            vec!["ai", "notes", "x.txt"]
        );
        // The lenient cases that scope accepts are HARD ERRORS for a key.
        assert!(canonicalize_key("ai/").is_err(), "trailing slash key rejected");
        assert!(canonicalize_key("/ai").is_err(), "leading slash key rejected");
        assert!(canonicalize_key("ai//foo").is_err(), "doubled slash key rejected");
        assert!(canonicalize_key("ai/foo/").is_err());
        // Percent is a legitimate key byte (no decode layer) — must be ALLOWED.
        assert_eq!(
            canonicalize_key("ai/q3-50%-off.txt").unwrap(),
            vec!["ai", "q3-50%-off.txt"]
        );
    }

    #[test]
    fn canon_rejects_empty_traversal_and_nul() {
        // Empty / traversal / NUL rejected for BOTH key and scope.
        for bad in ["", "/", "//", "ai/../etc", "../etc", "ai/./foo", ".", ".."] {
            assert!(canonicalize_scope(bad).is_err(), "scope must reject {bad:?}");
        }
        for bad in ["", "ai/../etc", "../etc", "ai/./foo", ".", ".."] {
            assert!(canonicalize_key(bad).is_err(), "key must reject {bad:?}");
        }
        assert!(canonicalize_key("ai/\0/foo").is_err()); // NUL
        assert!(canonicalize_scope("ai/\0/foo").is_err()); // NUL
    }

    #[test]
    fn segment_prefix_closes_the_p2_footgun() {
        // The exact footgun P2 flagged: a substring check would admit these; a
        // segment check must NOT.
        let note = canonicalize_scope("ai/note").unwrap();
        let notebook = canonicalize_key("ai/notebook.txt").unwrap();
        assert!(
            !key_in_scope(&notebook, &note),
            "scope 'ai/note' must NOT admit 'ai/notebook.txt'"
        );

        // First-segment substring footgun: scope "a" must not admit "ai/foo".
        let a = canonicalize_scope("a").unwrap();
        let ai_foo = canonicalize_key("ai/foo").unwrap();
        assert!(
            !key_in_scope(&ai_foo, &a),
            "scope 'a' must NOT admit 'ai/foo'"
        );
    }

    #[test]
    fn segment_prefix_admits_real_children_and_exact() {
        let ai = canonicalize_scope("ai/").unwrap();
        assert!(key_in_scope(&canonicalize_key("ai/foo").unwrap(), &ai));
        assert!(key_in_scope(&canonicalize_key("ai/foo/bar.txt").unwrap(), &ai));
        // Bare scope (no trailing slash) admits its children too.
        let ai_bare = canonicalize_scope("ai").unwrap();
        assert!(key_in_scope(&canonicalize_key("ai/foo.txt").unwrap(), &ai_bare));
        // Exact match (single-object grant): key == scope segments.
        let exact_key = canonicalize_key("ai/notes/x.txt").unwrap();
        let exact_scope = canonicalize_scope("ai/notes/x.txt").unwrap();
        assert!(key_in_scope(&exact_key, &exact_scope));
        // A parent key is NOT inside a deeper scope.
        let deep = canonicalize_scope("ai/notes/").unwrap();
        assert!(!key_in_scope(&canonicalize_key("ai/x.txt").unwrap(), &deep));
    }

    #[test]
    fn case_sensitive_matching() {
        let ai = canonicalize_scope("ai/").unwrap();
        assert!(
            !key_in_scope(&canonicalize_key("AI/foo").unwrap(), &ai),
            "matching must be case-sensitive: 'AI/foo' is not under 'ai/'"
        );
    }

    // ── assert_in_scope: geometry + authority together ─────────────────────

    /// A bundle with deterministic dummy material and the given grants.
    fn bundle_with_grants(grants: Vec<Capability>) -> CapabilityBundle {
        let ws = [7u8; 32];
        let mcp = [9u8; 32];
        let owner_secret = SecretKey::from_bytes(&[11u8; 32]).unwrap();
        let owner_public = owner_secret.public_key();
        CapabilityBundle {
            endpoint: "https://gw.example".to_string(),
            jwt: "test-jwt".to_string(),
            timeout: Duration::from_secs(60),
            workspace_secret: SecretKey::from_bytes(&ws).unwrap(),
            mcp_keypair: KekKeyPair::from_secret_key(SecretKey::from_bytes(&mcp).unwrap()),
            owner_public,
            grants,
        }
    }

    fn grant(scope: &str, perms: SharePermissions) -> Capability {
        Capability {
            scope: scope.to_string(),
            permissions: perms,
        }
    }

    #[test]
    fn assert_in_scope_admits_child_with_permission() {
        let b = bundle_with_grants(vec![grant("ai/", SharePermissions::read_write())]);
        assert!(b
            .assert_in_scope("ai/notes/x.txt", "ai/", Permission::Read)
            .is_ok());
        assert!(b
            .assert_in_scope("ai/notes/x.txt", "ai/", Permission::Write)
            .is_ok());
    }

    #[test]
    fn assert_in_scope_denies_sibling_footgun() {
        // Grant is "ai/note" (no trailing slash). "ai/notebook.txt" must be denied.
        let b = bundle_with_grants(vec![grant("ai/note", SharePermissions::read_write())]);
        let err = b
            .assert_in_scope("ai/notebook.txt", "ai/note", Permission::Read)
            .unwrap_err();
        assert!(matches!(err, CapabilityError::OutOfScope { .. }));
    }

    #[test]
    fn assert_in_scope_denies_first_segment_substring() {
        // Grant "a"; "ai/foo" must be denied (substring would wrongly admit).
        let b = bundle_with_grants(vec![grant("a", SharePermissions::full())]);
        let err = b
            .assert_in_scope("ai/foo", "a", Permission::Read)
            .unwrap_err();
        assert!(matches!(err, CapabilityError::OutOfScope { .. }));
    }

    #[test]
    fn assert_in_scope_enforces_permission() {
        // Read-only grant: Write and Delete must be denied even though geometry ok.
        let b = bundle_with_grants(vec![grant("ai/", SharePermissions::read_only())]);
        assert!(b
            .assert_in_scope("ai/x.txt", "ai/", Permission::Read)
            .is_ok());
        assert!(matches!(
            b.assert_in_scope("ai/x.txt", "ai/", Permission::Write)
                .unwrap_err(),
            CapabilityError::OutOfScope { .. }
        ));
        assert!(matches!(
            b.assert_in_scope("ai/x.txt", "ai/", Permission::Delete)
                .unwrap_err(),
            CapabilityError::OutOfScope { .. }
        ));
    }

    #[test]
    fn assert_in_scope_rejects_unauthorized_scope_name() {
        // Caller names a scope the bundle never granted -> denied, even if the
        // geometry of key-vs-scope would pass. This is the "can't conjure
        // authority by passing scope='' or a broader scope" guard.
        let b = bundle_with_grants(vec![grant("ai/", SharePermissions::full())]);
        // scope "" canonicalizes to an error (invalid path).
        assert!(matches!(
            b.assert_in_scope("ai/x", "", Permission::Read).unwrap_err(),
            CapabilityError::InvalidPath { .. }
        ));
        // A syntactically-valid but ungranted scope: key is geometrically inside
        // "ai/notes" but the bundle only granted "ai/" — naming "ai/notes" as the
        // authority must fail because there is no grant whose scope == "ai/notes".
        assert!(matches!(
            b.assert_in_scope("ai/notes/x", "ai/notes", Permission::Read)
                .unwrap_err(),
            CapabilityError::OutOfScope { .. }
        ));
    }

    #[test]
    fn assert_in_scope_rejects_traversal_key() {
        let b = bundle_with_grants(vec![grant("ai/", SharePermissions::full())]);
        assert!(matches!(
            b.assert_in_scope("ai/../secret", "ai/", Permission::Read)
                .unwrap_err(),
            CapabilityError::InvalidPath { .. }
        ));
    }

    #[test]
    fn assert_key_allowed_scans_all_grants() {
        let b = bundle_with_grants(vec![
            grant("ai/", SharePermissions::read_only()),
            grant("shared/reports/", SharePermissions::read_write()),
        ]);
        // Covered by the first grant (read).
        assert!(b.assert_key_allowed("ai/x.txt", Permission::Read).is_ok());
        // Write under ai/ denied (read-only), but write under shared/reports ok.
        assert!(b.assert_key_allowed("ai/x.txt", Permission::Write).is_err());
        assert!(b
            .assert_key_allowed("shared/reports/q1.pdf", Permission::Write)
            .is_ok());
        // Nothing grants delete.
        assert!(b
            .assert_key_allowed("ai/x.txt", Permission::Delete)
            .is_err());
        // Outside every grant.
        assert!(b.assert_key_allowed("other/x", Permission::Read).is_err());
    }

    // ── bundle parse + redaction ───────────────────────────────────────────

    fn sample_bundle_json() -> String {
        let ws = base64::engine::general_purpose::STANDARD.encode([1u8; 32]);
        let mcp = base64::engine::general_purpose::STANDARD.encode([2u8; 32]);
        let owner_pub = SecretKey::from_bytes(&[3u8; 32]).unwrap().public_key();
        let owner = base64::engine::general_purpose::STANDARD.encode(owner_pub.as_bytes());
        format!(
            r#"{{
              "endpoint": "https://gw.example",
              "jwt": "super-secret-jwt-value",
              "workspace_secret_b64": "{ws}",
              "mcp_secret_b64": "{mcp}",
              "owner_public_b64": "{owner}",
              "grants": [
                {{ "scope": "ai/", "permissions": {{ "can_read": true, "can_write": true, "can_delete": false }} }}
              ]
            }}"#
        )
    }

    #[test]
    fn bundle_parses_with_expected_fields() {
        let b = CapabilityBundle::from_json(&sample_bundle_json()).unwrap();
        assert_eq!(b.endpoint(), "https://gw.example");
        assert_eq!(b.grants().len(), 1);
        assert_eq!(b.grants()[0].scope, "ai/");
        assert!(b.grants()[0].permissions.can_write);
        assert!(!b.grants()[0].permissions.can_delete);
        // The MCP public key must be the X25519 derivation of [2u8;32].
        let expected_mcp_pub = SecretKey::from_bytes(&[2u8; 32]).unwrap().public_key();
        assert_eq!(b.mcp_public_key().as_bytes(), expected_mcp_pub.as_bytes());
        // The owner public key must round-trip.
        let expected_owner_pub = SecretKey::from_bytes(&[3u8; 32]).unwrap().public_key();
        assert_eq!(b.owner_public_key().as_bytes(), expected_owner_pub.as_bytes());
    }

    #[test]
    fn malformed_bundle_errors_cleanly() {
        // Not JSON.
        assert!(matches!(
            CapabilityBundle::from_json("not json").unwrap_err(),
            CapabilityError::Malformed(_)
        ));
        // Missing required field (jwt).
        let missing = r#"{ "endpoint": "x", "workspace_secret_b64": "AA", "mcp_secret_b64": "AA", "owner_public_b64": "AA" }"#;
        assert!(matches!(
            CapabilityBundle::from_json(missing).unwrap_err(),
            CapabilityError::Malformed(_)
        ));
        // Wrong-length secret (valid base64 but not 32 bytes).
        let short_secret = base64::engine::general_purpose::STANDARD.encode([0u8; 16]);
        let owner_pub = base64::engine::general_purpose::STANDARD
            .encode(SecretKey::from_bytes(&[3u8; 32]).unwrap().public_key().as_bytes());
        let bad = format!(
            r#"{{ "endpoint": "x", "jwt": "j", "workspace_secret_b64": "{short_secret}", "mcp_secret_b64": "{short_secret}", "owner_public_b64": "{owner_pub}" }}"#
        );
        assert!(matches!(
            CapabilityBundle::from_json(&bad).unwrap_err(),
            CapabilityError::InvalidKeyMaterial { .. }
        ));
    }

    #[test]
    fn debug_never_prints_secrets() {
        let json = sample_bundle_json();
        let b = CapabilityBundle::from_json(&json).unwrap();
        let dbg = format!("{b:?}");
        // The JWT must not appear.
        assert!(
            !dbg.contains("super-secret-jwt-value"),
            "Debug output leaked the JWT: {dbg}"
        );
        // Neither secret's base64 must appear.
        let ws_b64 = base64::engine::general_purpose::STANDARD.encode([1u8; 32]);
        let mcp_b64 = base64::engine::general_purpose::STANDARD.encode([2u8; 32]);
        assert!(!dbg.contains(&ws_b64), "Debug leaked workspace secret: {dbg}");
        assert!(!dbg.contains(&mcp_b64), "Debug leaked MCP secret: {dbg}");
        // Redaction marker present; endpoint (non-secret) is fine to show.
        assert!(dbg.contains("<redacted>"));
        assert!(dbg.contains("https://gw.example"));
    }

    // ── share round-trips (accept_grant / mint_owner_share) ────────────────

    #[test]
    fn accept_grant_round_trip_and_wrong_key_rejected() {
        // Owner mints a grant to the MCP's pubkey; the MCP accepts and recovers
        // the DEK. A bundle with a DIFFERENT MCP key must NOT be able to accept.
        let owner = KekKeyPair::from_secret_key(SecretKey::from_bytes(&[11u8; 32]).unwrap());

        // Bundle whose MCP keypair is [9u8;32].
        let b = bundle_with_grants(vec![]);
        let mcp_pub = b.mcp_public_key().clone();

        let dek = DekKey::generate();
        // Owner mints a v5 token addressed to the MCP's public key.
        let token = ShareBuilder::new(&owner, &mcp_pub, &dek)
            .path_scope("photos/2026/")
            .read_only()
            .build()
            .unwrap();

        let accepted = b.accept_grant(&token).unwrap();
        assert_eq!(accepted.dek.as_bytes(), dek.as_bytes());
        assert_eq!(accepted.path_scope, "photos/2026/");

        // A different bundle (different MCP key) cannot accept the same token.
        let other = CapabilityBundle {
            mcp_keypair: KekKeyPair::from_secret_key(SecretKey::from_bytes(&[42u8; 32]).unwrap()),
            ..bundle_with_grants(vec![])
        };
        assert!(other.accept_grant(&token).is_err());
    }

    #[test]
    fn mint_owner_share_round_trip() {
        use fula_crypto::{Aead, Nonce};

        // The MCP mints a share to the owner; the owner accepts and decrypts the
        // AI-written content byte-identically. Mirrors P2's pattern.
        let owner = KekKeyPair::from_secret_key(SecretKey::from_bytes(&[11u8; 32]).unwrap());
        // Bundle's owner_public is derived from [11u8;32] (see bundle_with_grants).
        let b = bundle_with_grants(vec![grant("ai/", SharePermissions::read_write())]);

        let logical_path = "ai/notes/summary.txt";
        let plaintext = b"AI-written content that must round-trip to the owner.";
        let dek = DekKey::generate();

        // Encrypt with the v4 single-block format the upload path uses.
        let storage_key = fula_crypto::generate_flat_key(logical_path, &dek, b"salt");
        let aad = format!("fula:v4:content:{storage_key}").into_bytes();
        let nonce = Nonce::generate();
        let ciphertext = Aead::new_default(&dek)
            .encrypt_with_aad(&nonce, plaintext, &aad)
            .unwrap();

        let nonce_b64 = base64::engine::general_purpose::STANDARD.encode(nonce.as_bytes());
        let token = b
            .mint_owner_share(&dek, logical_path, Some(&nonce_b64), None, Some(3600))
            .unwrap();

        // Owner accepts and decrypts.
        let accepted = ShareRecipient::new(&owner).accept_share(&token).unwrap();
        assert_eq!(accepted.dek.as_bytes(), dek.as_bytes());
        assert_eq!(accepted.encryption_version, Some(4));
        let recovered_nonce = {
            let raw = base64::engine::general_purpose::STANDARD
                .decode(accepted.nonce.as_ref().unwrap())
                .unwrap();
            Nonce::from_bytes(&raw).unwrap()
        };
        let decrypted = Aead::new_default(&accepted.dek)
            .decrypt_with_aad(&recovered_nonce, &ciphertext, &aad)
            .unwrap();
        assert_eq!(decrypted.as_slice(), plaintext.as_slice());
    }

    #[test]
    fn mint_owner_share_wrong_recipient_cannot_open() {
        // The share is wrapped to the owner only; a stranger cannot open it.
        let b = bundle_with_grants(vec![grant("ai/", SharePermissions::read_write())]);
        let dek = DekKey::generate();
        let token = b
            .mint_owner_share(&dek, "ai/secret.txt", None, None, None)
            .unwrap();
        let stranger = KekKeyPair::generate();
        assert!(ShareRecipient::new(&stranger).accept_share(&token).is_err());
    }
}
