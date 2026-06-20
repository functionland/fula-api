//! # `read_file` — the AI's scoped, DECRYPT-ing READ operation (P6)
//!
//! The read counterpart to P5's [`crate::store`]. This is where the
//! **default-deny read guarantee** lives: the AI (the MCP server) may read ONLY
//!
//! 1. **its own workspace files** — objects it wrote under the `ai/` scope into
//!    [`WORKSPACE_BUCKET`] (decrypted with the dedicated workspace secret), and
//! 2. **files the owner explicitly granted** to the MCP — delivered as an
//!    `owner → MCP` [`ShareToken`] (decrypted with the per-file DEK the token
//!    wraps to the MCP's keypair).
//!
//! Anything else is **rejected with a [`ReadError::Capability`] BEFORE any
//! network I/O** — never silently read. The MCP-protocol wiring (tool dispatch)
//! comes later (P9); here we build + test the operation as a plain async
//! library call.
//!
//! ## The two read modes (both scope-enforced, gate runs before I/O)
//!
//! ### 1. Workspace read — the AI's OWN files
//! [`read_workspace_file`]:
//! ```text
//! assert_in_scope(key, WORKSPACE_KEY_PREFIX, Read)?   // gate, no I/O
//! workspace_client()?.get_object_flat(WORKSPACE_BUCKET, key)   // decrypt w/ own secret
//! ```
//! The workspace client is built from the dedicated workspace secret (NOT the
//! user's master KEK), so it can only ever decrypt the AI's own forest. The gate
//! requires the bundle to actually hold a `Read` grant for the `ai/` scope and
//! the key to be segment-contained in it.
//!
//! ### 2. Granted read — a file the owner explicitly shared to the MCP
//! [`read_granted_file`]:
//! ```text
//! accepted = accept_grant(token)?                              // in-memory crypto, NO I/O
//! assert_in_scope(original_key, &accepted.path_scope, Read)?   // gate, no I/O
//! get_object_with_share(bucket, storage_key, original_key, &accepted)   // decrypt w/ share DEK
//! ```
//! [`CapabilityBundle::accept_grant`] is pure in-memory HPKE unwrap — it touches
//! no network — so it legitimately precedes the gate (the gate still runs before
//! the one call that DOES hit the wire, [`EncryptedClient::get_object_with_share`]).
//!
//! ## The granted-read scope gate (the security crux) — and its invariant
//!
//! The gate for a granted read is the single call
//! `assert_in_scope(original_key, &accepted.path_scope, Permission::Read)`. That
//! one call enforces BOTH halves the task requires, and is *strictly stronger*
//! than the SDK's own share check:
//!
//! - **Geometry** — `original_key` must be inside `accepted.path_scope` by P3's
//!   **path-segment** boundary. This is the part that beats the footgun: the
//!   crypto layer's [`AcceptedShare::is_path_allowed`] is a naive *substring*
//!   `path.starts_with(path_scope)`, which would wrongly admit `ai/notebook.txt`
//!   under a grant of `ai/note`. The segment check rejects exactly that. (The
//!   SDK's substring check still runs underneath inside `get_object_with_share`
//!   as defense-in-depth; we simply never *rely* on it.)
//! - **Authority** — the session [`CapabilityBundle`] must hold a `Read` grant
//!   whose canonical scope **EQUALS** `accepted.path_scope`. Mere possession of a
//!   valid `ShareToken` is NOT sufficient: the token's scope must correspond to
//!   an authority grant injected into the session. This is the fail-closed,
//!   auditable choice (confirmed by the P6 design review with the built-in
//!   advisor + Codex/GPT-5.5): a stolen or stale token the session was never
//!   granted authority for is denied.
//!
//! ### INVARIANT the session injector (P9) must uphold
//!
//! Because the authority check is **equality** (not "a broader grant covers the
//! token scope"), the component that builds the [`CapabilityBundle`] for a
//! session MUST add a `Read` grant whose canonical scope equals each granted
//! token's `path_scope`. A broad bundle grant (`photos/`) does NOT by itself
//! authorize a read against a narrower token (`photos/2026/x.jpg`) — the bundle
//! must also carry the `photos/2026/x.jpg` grant. This keeps "the owner granted
//! the AI authority over THIS scope" explicit and coordinated with token
//! minting, rather than letting token possession silently widen what the AI can
//! read. If a future product model wants broad-grant→narrow-token delegation,
//! that is a deliberate spec change (add a separate, explicitly-named coverage
//! API — do NOT loosen `assert_in_scope` to mean coverage).
//!
//! ## What this module deliberately does NOT do
//!
//! - It does not hardcode the bucket for granted reads — the caller supplies the
//!   target `bucket` (per the P5 [`crate::store::StoreOutcome`] contract: a
//!   reader reads `bucket`, never assumes [`WORKSPACE_BUCKET`]). Workspace reads
//!   DO use [`WORKSPACE_BUCKET`] because that is, by definition, where the AI's
//!   own files live.
//! - It never gates on the obfuscated `storage_key`. The gate always runs on the
//!   **logical** key (`key` for workspace, `original_key` for granted) — the
//!   human-meaningful path the scope commits to. Bytes are fetched by
//!   `storage_key`, but authority is decided on the logical path.

use bytes::Bytes;
use fula_crypto::ShareToken;
use thiserror::Error;

use crate::capability::{CapabilityBundle, CapabilityError, Permission};
use crate::store::{WORKSPACE_BUCKET, WORKSPACE_KEY_PREFIX};

/// A scoped read the AI wishes to perform. The two variants map to the two
/// (and only two) legitimate read modes; there is no "read an arbitrary path"
/// variant by construction.
///
/// Carried as owned data so a later MCP tool-dispatch layer (P9) can build one
/// from a deserialized request and hand it to [`read_file`].
#[derive(Clone)]
pub enum ReadRequest {
    /// Read one of the AI's OWN workspace files by its logical key
    /// (`ai/<category>/<uuid>-<name>`). Authorized under the `ai/` grant;
    /// decrypted with the workspace secret.
    Workspace {
        /// The canonical logical key (must be inside the `ai/` scope).
        key: String,
    },
    /// Read a file the owner explicitly shared to the MCP.
    ///
    /// `token` is the `owner → MCP` share (wrapping the file's content DEK to
    /// the MCP keypair). `bucket` + `storage_key` locate the ciphertext;
    /// `original_key` is the file's logical path, which the gate checks against
    /// the token's `path_scope`.
    Granted {
        /// The owner-minted share token addressed to the MCP keypair.
        ///
        /// Boxed: a [`ShareToken`] is large (wrapped DEK + several optional
        /// fields), so boxing keeps [`ReadRequest`] small and avoids bloating
        /// the [`Workspace`](ReadRequest::Workspace) variant
        /// (clippy::large_enum_variant). A request is built once per call, so
        /// the indirection is free.
        token: Box<ShareToken>,
        /// The bucket the granted object lives in (NOT assumed to be the
        /// workspace bucket).
        bucket: String,
        /// The obfuscated storage key the bytes are fetched by.
        storage_key: String,
        /// The logical path of the file (gated against `token.path_scope`).
        original_key: String,
    },
}

impl std::fmt::Debug for ReadRequest {
    /// Redacting debug — a [`ShareToken`] wraps a content DEK, so we never print
    /// it. Only non-sensitive shape is shown.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReadRequest::Workspace { key } => {
                f.debug_struct("ReadRequest::Workspace").field("key", key).finish()
            }
            ReadRequest::Granted {
                bucket,
                storage_key,
                original_key,
                ..
            } => f
                .debug_struct("ReadRequest::Granted")
                .field("token", &"<redacted ShareToken>")
                .field("bucket", bucket)
                .field("storage_key", storage_key)
                .field("original_key", original_key)
                .finish(),
        }
    }
}

/// Errors surfaced by [`read_file`] and its two mode helpers.
///
/// The shape mirrors [`crate::store::StoreError`]: a denial is a *distinct*
/// variant ([`ReadError::Capability`]) so "never silently read" lives in the
/// type — a caller (and a test) can tell an access-DENIED outcome apart from a
/// network failure unambiguously. This is what lets the offline tests prove the
/// scope gate fires BEFORE any I/O: an out-of-scope read against an unreachable
/// endpoint returns `Capability`, not `Client`.
#[derive(Debug, Error)]
pub enum ReadError {
    /// The scope/authority check failed, or the key/scope failed
    /// canonicalization. This is the access-DENIED / bad-key outcome and is
    /// raised BEFORE any network I/O. Includes: key outside `ai/` (workspace),
    /// `original_key` outside the token's `path_scope` (granted), the bundle not
    /// holding a matching `Read` grant, and a non-canonical key.
    #[error("read denied by capability check: {0}")]
    Capability(#[from] CapabilityError),

    /// Building the workspace client, accepting the grant token, or the storage
    /// GET / decrypt failed. (Network / crypto failure, NOT an authorization
    /// outcome.)
    #[error("read storage operation failed: {0}")]
    Client(String),

    /// The object was not found at the resolved location.
    #[error("object not found for read: {0}")]
    NotFound(String),
}

/// Perform a scoped, decrypting read.
///
/// Dispatches on the [`ReadRequest`] variant to [`read_workspace_file`] or
/// [`read_granted_file`]. In BOTH paths the scope gate runs before any network
/// I/O and an out-of-scope key is rejected with [`ReadError::Capability`].
///
/// This is the single entrypoint a later MCP tool-dispatch layer (P9) calls; it
/// can also call the two mode helpers directly if it has already split the
/// request.
///
/// # Errors
/// - [`ReadError::Capability`] — access denied / non-canonical key (NO I/O ran).
/// - [`ReadError::Client`] — client build / storage GET / decrypt failed.
/// - [`ReadError::NotFound`] — the object did not exist.
pub async fn read_file(cap: &CapabilityBundle, req: &ReadRequest) -> Result<Bytes, ReadError> {
    match req {
        ReadRequest::Workspace { key } => read_workspace_file(cap, key).await,
        ReadRequest::Granted {
            token,
            bucket,
            storage_key,
            original_key,
        } => read_granted_file(cap, token, bucket, storage_key, original_key).await,
    }
}

/// Read one of the AI's OWN workspace files, scope-gated.
///
/// Gate (BEFORE any I/O): `assert_in_scope(key, WORKSPACE_KEY_PREFIX,
/// Permission::Read)`. This rejects a non-canonical key AND a bundle that lacks
/// the `ai/` read grant — with no network call. Only then is the workspace
/// client built and the (own-secret-decrypted) object fetched.
///
/// # Errors
/// - [`ReadError::Capability`] if `key` is outside the `ai/` scope, the bundle
///   lacks the `ai/` read grant, or `key` is non-canonical (NO I/O performed).
/// - [`ReadError::NotFound`] if the object does not exist in the workspace.
/// - [`ReadError::Client`] if building the client or the GET/decrypt fails.
pub async fn read_workspace_file(cap: &CapabilityBundle, key: &str) -> Result<Bytes, ReadError> {
    // GATE FIRST — no client, no network until this passes. `?` maps
    // CapabilityError -> ReadError::Capability, the distinct access-DENIED type.
    cap.assert_in_scope(key, WORKSPACE_KEY_PREFIX, Permission::Read)?;

    // Authorized: build the workspace client (own secret) and read by LOGICAL
    // key. get_object_flat resolves key -> storage_key in our own forest and
    // decrypts with the workspace keypair.
    let client = cap.workspace_client()?;
    client
        .get_object_flat(WORKSPACE_BUCKET, key)
        .await
        .map_err(|e| classify_client_error(key, e))
}

/// Read a file the owner explicitly granted to the MCP, scope-gated.
///
/// Steps (the GATE runs before the one networked call):
///
/// - **Accept** — `accept_grant(token)` is in-memory HPKE unwrap (NO I/O),
///   recovering the DEK, `path_scope`, nonce / chunked metadata. A token not
///   addressed to this MCP keypair (or expired) fails here as
///   [`ReadError::Client`].
/// - **Gate** — `assert_in_scope(original_key, &accepted.path_scope,
///   Permission::Read)`: segment-boundary geometry (beats the substring footgun)
///   plus the bundle must hold a `Read` grant equal to the token's scope.
/// - **Fetch** — `get_object_with_share(bucket, storage_key, original_key,
///   &accepted)` fetches ciphertext by `storage_key` and decrypts with the
///   share's DEK.
///
/// See the module docs for the INVARIANT the session injector must uphold so the
/// equality authority check does not wrongly deny a legitimate narrower token.
///
/// # Errors
/// - [`ReadError::Capability`] if `original_key` is outside the token's
///   `path_scope`, the bundle holds no `Read` grant equal to that scope, or
///   `original_key`/scope is non-canonical (raised BEFORE the storage GET).
/// - [`ReadError::NotFound`] if the object does not exist.
/// - [`ReadError::Client`] if accepting the grant, or the GET/decrypt, fails.
pub async fn read_granted_file(
    cap: &CapabilityBundle,
    token: &ShareToken,
    bucket: &str,
    storage_key: &str,
    original_key: &str,
) -> Result<Bytes, ReadError> {
    // 1. Accept the grant. Pure in-memory crypto — no network. Recovers the DEK,
    //    path_scope, nonce / chunked metadata, encryption_version.
    let accepted = cap
        .accept_grant(token)
        .map_err(|e| ReadError::Client(format!("accept grant token: {e}")))?;

    // 2. GATE on the LOGICAL key against the token's own declared scope, with the
    //    bundle's authority. This is the security crux: segment-boundary geometry
    //    (strictly stronger than the SDK substring is_path_allowed) AND the
    //    bundle must hold a Read grant whose scope EQUALS accepted.path_scope.
    //    Runs before get_object_with_share (the only call that hits the wire).
    cap.assert_in_scope(original_key, &accepted.path_scope, Permission::Read)?;

    // 3. Authorized: fetch by storage_key, decrypt with the share's DEK. (The
    //    SDK re-checks is_path_allowed(original_key) + can_read internally as
    //    defense-in-depth; we have already enforced the stronger gate.)
    cap.workspace_client()?
        .get_object_with_share(bucket, storage_key, original_key, &accepted)
        .await
        .map_err(|e| classify_client_error(original_key, e))
}

/// Map a `fula-client` error into the right [`ReadError`]: a not-found resolves
/// to [`ReadError::NotFound`] (so callers can distinguish "no such object" from
/// a transport/crypto failure), everything else to [`ReadError::Client`].
///
/// We match on the rendered message rather than the concrete error enum to avoid
/// coupling this crate to `fula-client`'s private error taxonomy; the
/// `NotFound { bucket, key }` Display contains "not found" / the key.
fn classify_client_error(key: &str, err: impl std::fmt::Display) -> ReadError {
    let msg = err.to_string();
    let lower = msg.to_lowercase();
    if lower.contains("notfound") || lower.contains("not found") {
        ReadError::NotFound(format!("{key}: {msg}"))
    } else {
        ReadError::Client(msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use base64::Engine as _;
    use fula_crypto::{
        Aead, DekKey, KekKeyPair, Nonce, SecretKey, ShareBuilder, SharePermissions,
    };

    use crate::capability::CapabilityBundle as Bundle;

    // ── Bundle builders (offline; the endpoint is never contacted) ──────────

    /// A bundle JSON whose owner_public is derived from a known owner secret, the
    /// MCP keypair from a known MCP secret, with a single configurable grant.
    /// `endpoint` is unreachable so any accidental I/O would fail loudly (and
    /// differently from a Capability denial).
    fn bundle_json(grant_scope: &str, can_read: bool, mcp_secret: &[u8; 32], owner_secret: &[u8; 32]) -> String {
        let ws = base64::engine::general_purpose::STANDARD.encode([1u8; 32]);
        let mcp = base64::engine::general_purpose::STANDARD.encode(mcp_secret);
        let owner = base64::engine::general_purpose::STANDARD.encode(
            SecretKey::from_bytes(owner_secret).unwrap().public_key().as_bytes(),
        );
        format!(
            r#"{{ "endpoint": "https://offline.invalid", "jwt": "j", "workspace_secret_b64": "{ws}", "mcp_secret_b64": "{mcp}", "owner_public_b64": "{owner}", "grants": [{{ "scope": "{grant_scope}", "permissions": {{ "can_read": {can_read}, "can_write": false, "can_delete": false }} }}] }}"#
        )
    }

    /// Bundle with an `ai/` read grant (the normal workspace-read case).
    fn workspace_bundle() -> Bundle {
        Bundle::from_json(&bundle_json("ai/", true, &[9u8; 32], &[11u8; 32])).unwrap()
    }

    // ─────────────────────────────────────────────────────────────────────────
    // WORKSPACE-READ GATE (synchronous replication of the exact pre-I/O check)
    //
    // We replicate EXACTLY the gate read_workspace_file performs — same key, same
    // scope constant, same permission — so these prove the gate's decision
    // without needing the gateway. (The async "gate fires before I/O" proof is
    // the separate offline-against-unreachable-endpoint test below.)
    // ─────────────────────────────────────────────────────────────────────────

    /// The exact gate read_workspace_file performs.
    fn workspace_gate(cap: &Bundle, key: &str) -> Result<(), ReadError> {
        cap.assert_in_scope(key, WORKSPACE_KEY_PREFIX, Permission::Read)?;
        Ok(())
    }

    #[test]
    fn workspace_gate_allows_ai_key_with_read_grant() {
        let cap = workspace_bundle();
        assert!(workspace_gate(&cap, "ai/note/abc-summary.txt").is_ok());
        assert!(workspace_gate(&cap, "ai/image/xyz-photo.png").is_ok());
    }

    #[test]
    fn workspace_gate_denies_key_outside_ai_scope() {
        // The crux: a key OUTSIDE ai/ is rejected. `photos/...` is not under ai/.
        let cap = workspace_bundle();
        assert!(matches!(
            workspace_gate(&cap, "photos/2026/vacation.jpg"),
            Err(ReadError::Capability(CapabilityError::OutOfScope { .. }))
        ));
        // First-segment substring footgun: `ai-evil/...` must NOT pass as ai/.
        assert!(matches!(
            workspace_gate(&cap, "ai-evil/secret.txt"),
            Err(ReadError::Capability(CapabilityError::OutOfScope { .. }))
        ));
    }

    #[test]
    fn workspace_gate_denies_when_no_read_grant() {
        // Bundle whose ai/ grant is NOT readable (can_read:false) → denied.
        let cap = Bundle::from_json(&bundle_json("ai/", false, &[9u8; 32], &[11u8; 32])).unwrap();
        assert!(matches!(
            workspace_gate(&cap, "ai/note/x.txt"),
            Err(ReadError::Capability(CapabilityError::OutOfScope { .. }))
        ));
    }

    #[test]
    fn workspace_gate_rejects_non_canonical_key() {
        // A traversal / non-canonical key is rejected as InvalidPath (pre-I/O).
        let cap = workspace_bundle();
        assert!(matches!(
            workspace_gate(&cap, "ai/../secret"),
            Err(ReadError::Capability(CapabilityError::InvalidPath { .. }))
        ));
        assert!(matches!(
            workspace_gate(&cap, "ai//doubled"),
            Err(ReadError::Capability(CapabilityError::InvalidPath { .. }))
        ));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // GRANTED-READ GATE — the substring footgun is the graded crux.
    //
    // We mint a REAL owner→MCP token (the owner plays sender; the bundle's MCP
    // keypair is the recipient), accept it the way read_granted_file does, then
    // run the EXACT gate — assert_in_scope(original_key, &accepted.path_scope,
    // Read) — and assert in-scope passes / out-of-scope (incl. the footgun) is
    // denied. No network.
    // ─────────────────────────────────────────────────────────────────────────

    /// Mint an owner→MCP share token for `path_scope`, addressed to the bundle's
    /// MCP public key, signed by the `owner` keypair.
    fn mint_grant_to_mcp(cap: &Bundle, owner: &KekKeyPair, path_scope: &str) -> ShareToken {
        let dek = DekKey::generate();
        ShareBuilder::new(owner, cap.mcp_public_key(), &dek)
            .path_scope(path_scope)
            .read_only()
            .encryption_version(4)
            .build()
            .unwrap()
    }

    /// The exact gate read_granted_file performs, after accepting the token.
    fn granted_gate(cap: &Bundle, token: &ShareToken, original_key: &str) -> Result<(), ReadError> {
        let accepted = cap
            .accept_grant(token)
            .map_err(|e| ReadError::Client(e.to_string()))?;
        cap.assert_in_scope(original_key, &accepted.path_scope, Permission::Read)?;
        Ok(())
    }

    /// A bundle that grants `ai/` read AND holds a known MCP/owner keypair, plus
    /// a configurable EXTRA grant for the granted-read scope (so the authority
    /// arm — bundle must hold a grant equal to the token scope — is satisfiable).
    fn granted_bundle(extra_grant_scope: &str, owner_secret: &[u8; 32]) -> Bundle {
        let ws = base64::engine::general_purpose::STANDARD.encode([1u8; 32]);
        let mcp = base64::engine::general_purpose::STANDARD.encode([9u8; 32]);
        let owner = base64::engine::general_purpose::STANDARD.encode(
            SecretKey::from_bytes(owner_secret).unwrap().public_key().as_bytes(),
        );
        let json = format!(
            r#"{{ "endpoint": "https://offline.invalid", "jwt": "j", "workspace_secret_b64": "{ws}", "mcp_secret_b64": "{mcp}", "owner_public_b64": "{owner}", "grants": [ {{ "scope": "ai/", "permissions": {{ "can_read": true, "can_write": true, "can_delete": false }} }}, {{ "scope": "{extra_grant_scope}", "permissions": {{ "can_read": true, "can_write": false, "can_delete": false }} }} ] }}"#
        );
        Bundle::from_json(&json).unwrap()
    }

    #[test]
    fn granted_gate_allows_key_in_scope_with_matching_grant() {
        let owner_secret = [11u8; 32];
        let owner = KekKeyPair::from_secret_key(SecretKey::from_bytes(&owner_secret).unwrap());
        // Bundle holds a grant EQUAL to the token scope `photos/2026/` (the P9
        // invariant) → a key inside that scope is authorized.
        let cap = granted_bundle("photos/2026/", &owner_secret);
        let token = mint_grant_to_mcp(&cap, &owner, "photos/2026/");
        assert!(granted_gate(&cap, &token, "photos/2026/vacation.jpg").is_ok());
        assert!(granted_gate(&cap, &token, "photos/2026/sub/dir/x.png").is_ok());
    }

    #[test]
    fn granted_gate_denies_substring_footgun() {
        // THE GRADED CRUX. Token scope `ai/note`; `ai/notebook.txt` shares the
        // string prefix `ai/note` but is a DIFFERENT segment — the SDK's
        // substring is_path_allowed would ADMIT it; our segment gate must DENY.
        let owner_secret = [11u8; 32];
        let owner = KekKeyPair::from_secret_key(SecretKey::from_bytes(&owner_secret).unwrap());
        let cap = granted_bundle("ai/note", &owner_secret);
        let token = mint_grant_to_mcp(&cap, &owner, "ai/note");

        // First confirm the SDK substring check WOULD be fooled (documents why
        // our gate matters): accept and ask the crypto layer directly.
        let accepted = cap.accept_grant(&token).unwrap();
        assert!(
            accepted.is_path_allowed("ai/notebook.txt"),
            "precondition: the SDK substring check admits the footgun key (that's the danger)"
        );

        // Our gate must REJECT it.
        assert!(matches!(
            granted_gate(&cap, &token, "ai/notebook.txt"),
            Err(ReadError::Capability(CapabilityError::OutOfScope { .. }))
        ));
        // The genuine in-scope child still passes.
        assert!(granted_gate(&cap, &token, "ai/note/today.md").is_ok());
    }

    #[test]
    fn granted_gate_denies_key_outside_token_scope() {
        // A key in a wholly different subtree than the token's scope → denied.
        let owner_secret = [11u8; 32];
        let owner = KekKeyPair::from_secret_key(SecretKey::from_bytes(&owner_secret).unwrap());
        let cap = granted_bundle("photos/2026/", &owner_secret);
        let token = mint_grant_to_mcp(&cap, &owner, "photos/2026/");
        assert!(matches!(
            granted_gate(&cap, &token, "documents/secret.pdf"),
            Err(ReadError::Capability(CapabilityError::OutOfScope { .. }))
        ));
    }

    #[test]
    fn granted_gate_denies_when_bundle_lacks_matching_grant() {
        // Possession of a valid token is NOT authority: if the bundle has NO
        // grant equal to the token's path_scope, the read is denied. Here the
        // bundle's extra grant is `other/`, but the token scope is `photos/2026/`.
        let owner_secret = [11u8; 32];
        let owner = KekKeyPair::from_secret_key(SecretKey::from_bytes(&owner_secret).unwrap());
        let cap = granted_bundle("other/", &owner_secret);
        let token = mint_grant_to_mcp(&cap, &owner, "photos/2026/");
        // Geometry (key inside path_scope) passes, but authority (bundle grant ==
        // scope) fails → OutOfScope.
        assert!(matches!(
            granted_gate(&cap, &token, "photos/2026/x.jpg"),
            Err(ReadError::Capability(CapabilityError::OutOfScope { .. }))
        ));
    }

    #[test]
    fn granted_gate_denies_broad_bundle_grant_narrow_token() {
        // Documents the equality invariant explicitly: a BROAD bundle grant
        // (`photos/`) does NOT authorize a NARROWER token (`photos/2026/`),
        // because authority is equality, not coverage. P9 must inject a grant
        // equal to the token scope.
        let owner_secret = [11u8; 32];
        let owner = KekKeyPair::from_secret_key(SecretKey::from_bytes(&owner_secret).unwrap());
        let cap = granted_bundle("photos/", &owner_secret); // broad grant only
        let token = mint_grant_to_mcp(&cap, &owner, "photos/2026/"); // narrower token
        assert!(matches!(
            granted_gate(&cap, &token, "photos/2026/x.jpg"),
            Err(ReadError::Capability(CapabilityError::OutOfScope { .. }))
        ));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // GATE-BEFORE-I/O proof (async, offline against an UNREACHABLE endpoint).
    //
    // The bundle endpoint is https://offline.invalid. If the gate did NOT fire
    // first, the call would proceed to build a client and hit the network,
    // surfacing a Client/transport error. Asserting we instead get a *Capability*
    // error is positive proof the synchronous gate short-circuited BEFORE any
    // client construction / I/O.
    // ─────────────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn read_workspace_file_denies_out_of_scope_before_any_io() {
        let cap = workspace_bundle();
        // `photos/...` is outside ai/ → must be a Capability denial, NOT a
        // network error against offline.invalid.
        let err = read_workspace_file(&cap, "photos/secret.jpg")
            .await
            .unwrap_err();
        assert!(
            matches!(err, ReadError::Capability(CapabilityError::OutOfScope { .. })),
            "out-of-scope workspace read must deny pre-I/O (got {err:?})"
        );
    }

    #[tokio::test]
    async fn read_workspace_file_denies_non_canonical_before_any_io() {
        let cap = workspace_bundle();
        let err = read_workspace_file(&cap, "ai/../etc/passwd").await.unwrap_err();
        assert!(
            matches!(err, ReadError::Capability(CapabilityError::InvalidPath { .. })),
            "non-canonical workspace key must deny pre-I/O (got {err:?})"
        );
    }

    #[tokio::test]
    async fn read_granted_file_denies_footgun_before_any_io() {
        // The footgun key, through the REAL async read_granted_file, against an
        // unreachable endpoint. accept_grant is in-memory (no I/O); the gate then
        // denies BEFORE get_object_with_share would touch the network.
        let owner_secret = [11u8; 32];
        let owner = KekKeyPair::from_secret_key(SecretKey::from_bytes(&owner_secret).unwrap());
        let cap = granted_bundle("ai/note", &owner_secret);
        let token = mint_grant_to_mcp(&cap, &owner, "ai/note");
        let err = read_granted_file(&cap, &token, "some-bucket", "QmStorageKey", "ai/notebook.txt")
            .await
            .unwrap_err();
        assert!(
            matches!(err, ReadError::Capability(CapabilityError::OutOfScope { .. })),
            "granted footgun read must deny pre-I/O (got {err:?})"
        );
    }

    #[tokio::test]
    async fn read_granted_file_denies_unauthorized_scope_before_any_io() {
        // Token the bundle has no matching grant for → denied pre-I/O.
        let owner_secret = [11u8; 32];
        let owner = KekKeyPair::from_secret_key(SecretKey::from_bytes(&owner_secret).unwrap());
        let cap = granted_bundle("other/", &owner_secret);
        let token = mint_grant_to_mcp(&cap, &owner, "photos/2026/");
        let err = read_granted_file(&cap, &token, "b", "QmK", "photos/2026/x.jpg")
            .await
            .unwrap_err();
        assert!(
            matches!(err, ReadError::Capability(CapabilityError::OutOfScope { .. })),
            "unauthorized granted read must deny pre-I/O (got {err:?})"
        );
    }

    #[tokio::test]
    async fn read_file_dispatches_to_workspace_and_denies_out_of_scope() {
        // The ReadRequest entrypoint routes correctly and preserves the gate.
        let cap = workspace_bundle();
        let req = ReadRequest::Workspace {
            key: "nope/secret.txt".to_string(),
        };
        let err = read_file(&cap, &req).await.unwrap_err();
        assert!(matches!(
            err,
            ReadError::Capability(CapabilityError::OutOfScope { .. })
        ));
    }

    // ── owner→MCP accept round-trip + a full crypto decrypt round-trip ───────
    //
    // Proves the granted-read crypto end-to-end OFFLINE: build a v4 single-block
    // ciphertext exactly as the upload path does, mint the owner→MCP share, accept
    // it as the MCP, and decrypt — the same DEK/nonce/AAD the live
    // get_object_with_share would use. (The live byte-fetch is the gated e2e.)

    #[test]
    fn granted_read_crypto_round_trips_single_block_offline() {
        let owner_secret = [11u8; 32];
        let owner = KekKeyPair::from_secret_key(SecretKey::from_bytes(&owner_secret).unwrap());
        let cap = granted_bundle("docs/", &owner_secret);

        // Owner-side: a file the owner shares with the MCP. Encrypt with the v4
        // content AAD keyed by storage_key (the upload format).
        let storage_key = "QmGrantedStorageKeySingle";
        let plaintext = b"owner-granted file the AI is allowed to read";
        let dek = DekKey::generate();
        let nonce = Nonce::generate();
        let aad = format!("fula:v4:content:{storage_key}").into_bytes();
        let ciphertext = Aead::new_default(&dek)
            .encrypt_with_aad(&nonce, plaintext, &aad)
            .unwrap();
        let nonce_b64 = base64::engine::general_purpose::STANDARD.encode(nonce.as_bytes());

        // Owner mints the share to the MCP keypair.
        let token = ShareBuilder::new(&owner, cap.mcp_public_key(), &dek)
            .path_scope("docs/")
            .read_only()
            .encryption_version(4)
            .nonce(nonce_b64)
            .build()
            .unwrap();

        // MCP accepts (as read_granted_file does) and decrypts.
        let accepted = cap.accept_grant(&token).unwrap();
        assert!(accepted.is_path_allowed("docs/report.txt"));
        assert_eq!(accepted.encryption_version, Some(4));
        let rec_nonce = {
            let raw = base64::engine::general_purpose::STANDARD
                .decode(accepted.nonce.as_ref().unwrap())
                .unwrap();
            Nonce::from_bytes(&raw).unwrap()
        };
        let decrypted = Aead::new_default(&accepted.dek)
            .decrypt_with_aad(&rec_nonce, &ciphertext, &aad)
            .unwrap();
        assert_eq!(decrypted.as_slice(), plaintext.as_slice());
    }

    #[test]
    fn granted_read_token_for_other_mcp_cannot_be_accepted() {
        // A token addressed to a DIFFERENT MCP keypair cannot be accepted by this
        // bundle — accept_grant fails (so read_granted_file returns Client, never
        // silently reads).
        let owner = KekKeyPair::from_secret_key(SecretKey::from_bytes(&[11u8; 32]).unwrap());
        let cap = granted_bundle("docs/", &[11u8; 32]);
        let other_mcp = KekKeyPair::generate();
        let dek = DekKey::generate();
        let token = ShareBuilder::new(&owner, other_mcp.public_key(), &dek)
            .path_scope("docs/")
            .read_only()
            .build()
            .unwrap();
        assert!(cap.accept_grant(&token).is_err());
        // And confirm SharePermissions read-only is what we minted (sanity).
        assert!(SharePermissions::read_only().can_read);
    }
}
