Fula Storage API – Security Audit Report
=======================================

Project: functionland/fula-api
Date: 2025-12-08
Auditor: Cascade (automated analysis)

1. Scope and Executive Summary
------------------------------

**Scope.** This review covers the current `fula-api` repository, with focus on:

- `fula-crypto`: crypto primitives and key management.
- `fula-client`: client SDK and client-side encryption flows.
- `fula-cli`: S3-compatible gateway, HTTP surfaces, auth, and metadata handling.
- `fula-blockstore`: IPFS/blockstore and pinning integrations.
- `fula-core`: bucket/object metadata and indexing.
- Public docs (`docs/openAPI.yaml`, `Decentralized S3-Compatible Storage Plan.md`).

**Goal.** Assess whether the system is suitable for **public deployment as a decentralized S3-compatible API for storing private data**, with data encrypted client-side and stored on IPFS.

### Overall Assessment

- **Cryptography and client-side encryption:**
  - Uses modern primitives: **AES-256-GCM / ChaCha20-Poly1305**, **RFC 9180 HPKE (X25519-HKDF-SHA256 + ChaCha20-Poly1305)**, and **BLAKE3**.
  - **Per-object DEKs** (data encryption keys) and a **root KEK keypair** (X25519) per user.
  - Nonces are random, keys are random, crypto APIs are used correctly and defensively, and there are extensive tests, including tampering and misuse scenarios.
  - Metadata privacy is handled thoughtfully via **PrivateMetadata** and **PrivateForest** with **FlatNamespace** mode for structure hiding.
  - For users who **actually use the `EncryptedClient`**, confidentiality and integrity of file contents and sensitive metadata are **strong**.

- **Gateway/API & auth:**
  - S3-compatible HTTP layer is reasonably hardened: JWT-based auth, per-user scopes, per-user rate limiting, and ownership checks for buckets/objects.
  - However, there are some important **configuration-dependent risks**:
    - Authentication can be disabled (`--no-auth` / `FULA_NO_AUTH=true`) exposing a fully open S3 gateway.
    - JWT issuer/audience validation exists in code but is **not wired to configuration**; currently only signature + expiry are enforced.
    - Buckets store `owner_id` as the raw JWT `sub` (not hashed) despite comments promising hashing, which is a **privacy concern**.

- **Storage & IPFS/pinning:**
  - IPFS integration is designed for untrusted storage nodes; actual plaintext secrecy is pushed entirely to the client.
  - Remote pinning credentials are **per-request**, not persisted, and logging avoids leaking token values.

- **Key conclusion:**
  - For **private data**, the system is secure **if and only if** all sensitive data is uploaded via the **encrypted SDK (`EncryptedClient` / FlatNamespace)** and operational configuration is correct (auth enabled, JWT secret strong, CORS restricted, no dev flags in production).
  - The main residual risks are **operational misconfiguration**, **unencrypted S3 clients**, and some moderate **privacy/discovery issues** around user identifiers and CORS.

2. Threat Model
----------------

### Assets

- **File contents** (user data – expected to be private).
- **File metadata**: names, paths, content types, sizes, timestamps, custom metadata.
- **Encryption keys**: per-user KEK (X25519 keypair), per-object DEKs.
- **Authentication material**: JWT access tokens, pinning service tokens.

### Actors

- **Legitimate clients** using `fula-client` or generic S3 tools.
- **Gateway operator**: runs `fula-cli` S3 gateway and IPFS nodes.
- **Storage nodes / IPFS network**: honest-but-curious or potentially malicious.
- **External attackers** on the network.
- **Compromised browser/JS origins** abusing bearer tokens if CORS is too open.

### Security Goals

- **Confidentiality:** Storage nodes and gateway operators cannot read private file contents or sensitive metadata when client-side encryption is used.
- **Integrity:** Clients can detect tampering with ciphertext and with HPKE-wrapped keys.
- **Authentication & authorization:** Only properly authenticated users can access/modify their buckets and objects.
- **Multi-tenant isolation:** Buckets and objects are scoped to owners; one tenant cannot read or delete another tenant’s data.
- **Key protection:** KEKs and DEKs are never exposed server-side; compromise of gateway/storage does not directly reveal keys.

3. Cryptographic Architecture Analysis
--------------------------------------

### 3.1 Key Management (fula-crypto/src/keys.rs)

- **KEK (Key Encryption Key):**
  - `SecretKey` is a 32-byte X25519 secret.
  - `PublicKey` is derived via `x25519_dalek`.
  - `KekKeyPair` holds both `SecretKey` and `PublicKey`.
  - `KeyManager` holds a single root `KekKeyPair` + version.

- **DEKs (Data Encryption Keys):**
  - `DekKey` is a 32-byte random key, generated with `OsRng`.
  - `KeyManager::generate_dek()` returns a new random DEK per file/object.

- **Path-based keys:**
  - `KeyManager::derive_path_key(path: &str)` uses `derive_key("fula-path-key-v1", secret || path)` to derive a deterministic DEK-like key from the root secret plus a path string.
  - Used for **stor­age-key obfuscation** and `PrivateForest` encryption, not for content encryption.

- **Security assessment:**
  - Random key generation and sizes are appropriate (256-bit keys).
  - `SecretKey` and `DekKey` are `Zeroize`/`ZeroizeOnDrop`, reducing leakage on drop.
  - Path-derivation is domain-separated and avoids reusing DEKs for content.

### 3.2 Symmetric Encryption (fula-crypto/src/symmetric.rs)

- **Algorithms:**
  - Default: **AES-256-GCM** (`AeadCipher::Aes256Gcm`).
  - Optional: **ChaCha20-Poly1305**.
  - Nonces are 96-bit random (`Nonce::generate()` uses `OsRng`).

- **API usage pattern:**
  - `Aead::new_default(&DekKey)` uses the configured cipher and key bytes.
  - `encrypt(&Nonce, plaintext)` and `decrypt(&Nonce, ciphertext)` directly map to the AEAD primitives.
  - Convenience functions `encrypt` and `decrypt` generate a random nonce and return `(nonce, ciphertext)`.

- **Tests:**
  - Extensive tests cover:
    - Roundtrips for both AES-GCM and ChaCha20-Poly1305.
    - Tampering with ciphertext and auth tag.
    - Wrong key/wrong nonce failures.
    - Truncated/appended ciphertext failures.
    - Nonce uniqueness (1000 nonces with no collisions).
    - Large messages and all-byte-values tests.

- **Security assessment:**
  - AEAD is used correctly with random nonces and per-object DEKs.
  - Probability of nonce reuse under the same DEK is negligible and further mitigated by per-object DEKs.
  - Tests explicitly verify failure on tampering and misuse -> high confidence in correctness.

### 3.3 HPKE & DEK Wrapping (fula-crypto/src/hpke.rs)

- **Suite:** RFC 9180 HPKE
  - KEM: `X25519HkdfSha256`.
  - KDF: `HkdfSha256`.
  - AEAD: `ChaCha20Poly1305` for the HPKE payload.

- **Usage:**
  - `Encryptor::encrypt_dek(&DekKey)` wraps a DEK for a recipient’s public key.
  - `Decryptor::decrypt_dek(&EncryptedData)` unwraps the DEK given the recipient’s secret key.
  - AAD is used for **context binding**:
    - Default data AAD: `"fula:v2:default"`.
    - DEK wrapping AAD: `"fula:v2:dek-wrap"`.

- **Security features:**
  - Ephemeral keys and AAD ensure semantic security and bind ciphertexts to specific contexts (e.g., “DEK wrap” vs generic message).
  - Tests cover:
    - Roundtrip correctness.
    - Wrong key failures.
    - Multi-recipient wrapping.
    - Tampering with ciphertext and encapsulated key.
    - Semantic security (same plaintext → different ciphertexts and different encapsulated keys).
    - AAD binding (wrong AAD fails).

- **Security assessment:**
  - Proper, standards-based HPKE with strong defenses against common misuse.
  - The HPKE layer appears **robust** and safe for DEK wrapping and sharing.

### 3.4 Client-Side Encryption Flow (fula-client/src/encryption.rs)

Key flow for `EncryptedClient::put_object_encrypted_with_type`:

1. Generate a per-object **DEK**: `KeyManager::generate_dek()`.
2. Generate a random **nonce**.
3. Encrypt plaintext with AEAD: `AES-256-GCM(DEK, nonce)`.
4. Wrap DEK with HPKE for the owner’s public key: `Encryptor::encrypt_dek(&dek)`.
5. If metadata privacy is enabled:
   - Build `PrivateMetadata` with original key/path, size, and content type.
   - Encrypt it with the **per-file DEK** into `EncryptedPrivateMetadata`.
   - Derive a **path DEK** via `KeyManager::derive_path_key(key)`.
   - Compute an **obfuscated storage key** via `obfuscate_key(key, path_dek, obfuscation_mode)`.
6. Construct JSON **encryption metadata**:
   - `version` = 2 (crypto format version).
   - `algorithm` = `"AES-256-GCM"`.
   - `nonce` = base64-encoded.
   - `wrapped_key` = serialized HPKE `EncryptedData`.
   - `metadata_privacy` flag.
   - Optional `private_metadata` = encrypted blob of original metadata.
7. Store the ciphertext via the S3-compatible gateway, attaching user metadata:
   - `x-fula-encrypted = "true"`.
   - `x-fula-encryption = <JSON metadata>`.
   - Content-Type visible to server is forced to generic `application/octet-stream`.

Decryption (`get_object_decrypted_*`):

1. Fetch object bytes and metadata from gateway.
2. If `x-fula-encrypted != "true"`, return plaintext as-is.
3. Parse `x-fula-encryption` JSON.
4. Decode nonce and wrapped DEK.
5. Use local `KeyManager`/`SecretKey` via HPKE decryptor to unwrap the DEK.
6. Decrypt ciphertext with AEAD.
7. If present, decrypt `private_metadata` to restore original path, size, type, and user metadata.

**Security properties:**

- Encryption and decryption are **entirely client-side**; server sees only ciphertext and opaque metadata.
- Server and IPFS nodes **never see any KEKs/DEKs**.
- Metadata privacy is enforced by:
  - Obfuscating storage keys (especially in `FlatNamespace` mode).
  - Encrypting original filenames, sizes, and content types.

### 3.5 FlatNamespace & PrivateForest

- `FlatNamespace` mode (`EncryptionConfig::new_flat_namespace`) is designed for **maximum privacy**:
  - Storage keys look like random hashes (e.g., CID-style), with **no prefixes or structure hints**.
  - Logical directory structure is stored in an encrypted **PrivateForest** index.

- `PrivateForest` handling:
  - Forest encryption key is derived with `derive_path_key("forest:{bucket}")`.
  - An index key is derived via `derive_index_key(forest_dek, bucket)`.
  - Encrypted forest is stored as a normal object (with metadata `x-fula-forest = true`).
  - Forest maps **user-facing paths** → **obfuscated storage keys**.

- Security impact:
  - Server and IPFS nodes see only opaque storage keys and a single forest object; they cannot infer folder structure or filenames.
  - Forest content (paths, tree structure) is encrypted; only clients with the KEK can read it.

**Conclusion:** For users who opt into `FlatNamespace` and encrypted client, both content and structure are well protected.

4. Gateway, Authentication, and Authorization
--------------------------------------------

### 4.1 Authentication (fula-cli/src/auth.rs, middleware.rs, main.rs)

- **JWT-based auth**:
  - Tokens are expected in `Authorization: Bearer <token>`.
  - `validate_token` verifies:
    - Signature with HS256 and a configured shared secret (`JWT_SECRET`).
    - `exp` (expiry) with a default leeway (60s).
  - Optional issuer/audience fields:
    - `JwtValidationConfig` supports checking `iss` and `aud`, but the current middleware always calls `validate_token` with **default config**, which does **not** enforce `iss`/`aud`.

- **Session & scopes:**
  - `Claims.scope` is a space-separated list like `"storage:read storage:write"`.
  - `UserSession` exposes `can_read()`, `can_write()`, `is_admin()`, and `can_access_bucket(owner_id)`.

- **Auth middleware (`auth_middleware`)**:
  - If `config.auth_enabled == false` (i.e., `--no-auth` / `FULA_NO_AUTH=true`), middleware injects a **dev session** with `user_id = "dev-user"`, full `storage:*` scope, and 1-year expiry.
  - If auth is enabled:
    - Absence of `Authorization` header → `AccessDenied` (no anonymous access).
    - Invalid or expired token → `InvalidToken`.

- **Configuration:**
  - `GatewayConfig.auth_enabled` is set as `!no_auth` in `main.rs`.
  - `JWT_SECRET` is required when auth is enabled.

**Security assessment:**

- JWT validation is mostly correct (signature + expiration) and uses a well-known library.
- **Issuer (`iss`) and audience (`aud`) claims are not presently enforced**, even though the code supports doing so.
- HS256 implies **symmetric** secret; if the secret is leaked or reused across systems, arbitrary tokens can be forged.
- The `dev_session` configuration is claramente flagged as **DEVELOPMENT ONLY**, but operational discipline is required to avoid deploying with auth disabled.

### 4.2 Authorization and Multi-Tenant Isolation

- **Bucket operations:**
  - `create_bucket` sets owner via `Owner::new(&session.user_id)`.
  - `delete_bucket` checks that `metadata.owner_id == session.user_id` or `session.has_scope("admin")`.
  - `list_objects`, `get_object`, `put_object`, `delete_object`, and `copy_object` all verify bucket ownership via `session.can_access_bucket(&bucket.metadata().owner_id)`.

- **Object-level decisions:**
  - Access is governed by **bucket ownership + scope** (`can_read` / `can_write`).
  - There is no per-object ACL or policy language yet (consistent with project’s current scope).

- **Privacy note on `owner_id`:**
  - `BucketMetadata.owner_id` is documented as “hashed” in comments, but code uses the **raw `session.user_id`**.
  - If `sub` (subject) is an email or stable user identifier, bucket metadata in IPFS and logs will expose it.

**Security assessment:**

- Cross-tenant read/write isolation is implemented and enforced at bucket level.
- Ownership checks are present in all relevant handlers.
- The mismatch between documentation (“hashed user ID”) and implementation (plain `sub`) is a **privacy issue**, not a direct integrity break.

### 4.3 Rate Limiting and DoS Controls

- `middleware::rate_limit_middleware` enforces per-user **requests-per-second** with `governor`.
- Limit is configured via `GatewayConfig.rate_limit_rps` (default 100 RPS per user).
- If auth is disabled (`dev_session`), all requests share the same user id (`"dev-user"`), so the rate-limiter still applies but to the whole instance.

**Security assessment:**

- Basic protection against abusive clients is present.
- Additional infra-level protection (reverse proxy, IP-based limiting, etc.) is still recommended for an internet-facing deployment.

### 4.4 CORS and Browser Security

- `create_cors_layer` builds a CORS policy using `GatewayConfig.cors_origins`.
- If `cors_origins` contains `"*"`, all origins are allowed (development behavior).
- Default `GatewayConfig` sets `cors_enabled = true` and `cors_origins = ["*"]`.
- The layer allows common S3 headers and methods and exposes standard S3 response headers.

**Security assessment:**

- Mechanism for **restrictive CORS** is present, but **default is permissive** (`"*"`).
- In production, if user browsers hold bearer tokens and CORS remains `*`, any malicious website can issue cross-origin XHR/fetch calls to the gateway with those tokens. This is a typical web auth risk and must be mitigated by tightening CORS and using proper OAuth flows.

### 4.5 Logging

- Logging middleware records method, URI, status, and duration only; it does **not** log Authorization headers or JWTs.
- Pinning credentials (`X-Pinning-Token`) are intentionally not logged (only presence/absence of headers is logged).

**Security assessment:**

- Logging is reasonably privacy-preserving; secrets/tokens are not logged.

5. Blockstore, IPFS, and Pinning
---------------------------------

### 5.1 Blockstore Abstraction (fula-blockstore)

- `BlockStore` trait provides `put_block`, `get_block`, `delete_block`, `put_ipld`, `get_ipld`, etc.
- Default block size, chunking, and CID generation use content-addressing and BLAKE3 (see `cid_utils`, not deeply re-audited here but consistent with docs).

### 5.2 IPFS + Pinning Service Store (ipfs_pinning.rs)

- `IpfsPinningBlockStore` wraps:
  - `IpfsBlockStore` for raw block operations.
  - Optional `PinningServiceClient` for remote pinning services.

- Writes:
  - Write data to IPFS, optionally cache in-memory.
  - Try to pin via remote service or local `ipfs pin add`.
  - Pinning failures are logged as warnings but **do not abort** the main write; data may become non-persistent.

- Reads:
  - Prefer cache; otherwise fetch from IPFS via CID.

- Remote pinning:
  - `PinningServiceClient` uses the standard IPFS Pinning Service API (`Ipfs-pinning-API.md`).
  - IPFS pinning credentials (endpoint + token) can be configured globally via env or per-request via headers.

### 5.3 Per-User Pinning (fula-cli/src/pinning.rs)

- `pin_for_user(headers, cid, object_key)`:
  - Extracts `X-Pinning-Service`, `X-Pinning-Token`, and optional `X-Pinning-Name` from request headers.
  - Logs only presence of headers, not values.
  - Spawns a background task that uses these credentials to pin the CID on behalf of the user.
  - Errors are logged but do not impact the main S3 request.

**Security assessment:**

- IPFS and pinning layers treat **CIDs as public** and ciphertext as opaque.
- Remote pinning credentials are per-request and explicitly not persisted.
- Logging strategy avoids accidental credential leakage.
- Failure to pin primarily impacts **availability/persistence**, not confidentiality.

6. Suitability for Private Data
-------------------------------

### 6.1 When Security Properties Hold

Confidentiality and privacy properties are **strong** when all of the following are true:

1. **Clients use encrypted flows**:
   - Use `EncryptedClient` (or equivalent SDK logic) for all sensitive data.
   - Prefer `FlatNamespace` mode to hide directory structure and filenames.

2. **Keys are kept entirely client-side**:
   - The KEK secret (`SecretKey`) is never uploaded or logged.
   - Users back up keys securely (lost keys = irrevocably lost data).

3. **Gateway is correctly configured**:
   - `FULA_NO_AUTH` / `--no-auth` is **never** used in production.
   - `JWT_SECRET` is long and random, and kept secret.
   - CORS is restricted to trusted origins (`cors_origins` does **not** contain `"*"` in production).
   - IPFS nodes are treated as untrusted storage only.

Under these conditions, even a fully compromised IPFS node or gateway operator cannot decrypt user data or infer directory structure for encrypted buckets.

### 6.2 When Security Properties Degrade

- **Plain S3 clients (no encryption):**
  - If users upload sensitive data via AWS CLI or any non-encrypting S3 client, the gateway will store **plaintext** in IPFS.
  - The system does not enforce that `x-fula-encrypted = true` for writes.

- **Misconfigured gateway:**
  - If auth is disabled, the API becomes a public writable S3 gateway, subject only to rate limiting.
  - If `JWT_SECRET` is weak or shared widely, attackers can forge tokens.
  - If CORS is `*` and apps store bearer tokens in browser-accessible storage, any website can issue authenticated calls from that browser.

- **Metadata privacy gaps:**
  - Even with encryption, some metadata (bucket names, ciphertext sizes, timestamps) remains visible to the gateway and appears in IPFS Prolly tree structures.
  - Bucket owner ids (`owner_id`) are stored as **raw `sub`** values, not hashed, which leaks stable identifiers.

7. Findings and Recommendations
--------------------------------

Below, findings are labeled with a rough severity: [High], [Medium], [Low].

### 7.1 Crypto and Client-Side Encryption

- **Finding C1 [Low/Info]:** Crypto primitives and usage are solid.
  - AES-256-GCM/ChaCha20-Poly1305, X25519 HPKE, BLAKE3, and Bao (streaming) are state-of-the-art and used correctly.
  - Extensive unit tests cover tampering, misuse, and edge cases.

  **Recommendation C1:**
  - Continue to treat **fula-crypto** as the single source of crypto primitives.
  - Any new features (e.g., sharing, rotation) should be implemented via these existing, well-tested modules.

- **Finding C2 [Medium]:** No enforcement that data is encrypted.
  - Gateway handles both encrypted and unencrypted objects identically; encryption is a **client convention**.
  - For applications requiring strict confidentiality, use of `EncryptedClient` must be enforced externally (docs, client libraries, or policy), or unencrypted uploads are possible.

  **Recommendation C2:**
  - For a “secure cluster” deployment, consider adding a **gateway mode** that:
    - Rejects writes to certain buckets unless `x-fula-encrypted = true` and valid encryption metadata is present.
    - Optionally, segregates “public” and “private” buckets.
  - At minimum, document clearly that **private data must be uploaded via the encrypted SDK**, not via raw S3 tools.

### 7.2 Authentication and Authorization

- **Finding A1 [High]:** `--no-auth` / `FULA_NO_AUTH` disables all authentication.
  - When `auth_enabled = false`, the gateway creates a long-lived dev session with full `storage:*` permission for every request.
  - This is appropriate for local development but catastrophic if used in production.

  **Recommendation A1:**
  - Add **safety rails** around `--no-auth`, such as:
    - Warning and/or refusal to start when `--no-auth` is combined with a non-localhost `host` or `debug=false`.
    - Distinct Docker images/config profiles for `DEV` vs `PROD` that make non-authenticated mode impossible in production.

- **Finding A2 [Medium]:** JWT `iss` and `aud` are not enforced.
  - `JwtValidationConfig` supports issuer/audience checks, but `auth_middleware` always uses default config without setting them.
  - This means any JWT signed with the **same HS256 secret** is accepted, regardless of issuer/audience.

  **Recommendation A2:**
  - Wire environment variables (e.g., `OAUTH_ISSUER`, `OAUTH_AUDIENCE`) into a `JwtValidationConfig` instance and use `validate_token_with_config` in `auth_middleware`.
  - For production, consider supporting **asymmetric JWT validation** (RS256/ES256 via JWKS) to avoid sharing HS256 secrets across systems.

- **Finding A3 [Medium]:** Bucket owner IDs are not hashed as documented.
  - `BucketMetadata.owner_id` comments state “hashed sub claim,” but code uses `session.user_id` directly.
  - Exposes raw user identifiers (e.g., email-like subjects) in bucket metadata and any logs using those values.

  **Recommendation A3:**
  - Use `hash_user_id` when setting `Owner` / `BucketMetadata.owner_id`.
  - Perform a **one-time migration strategy** or accept that existing buckets remain with non-hashed IDs.
  - Update docs and openAPI to reflect actual behavior if migration is not feasible.

### 7.3 CORS and Web-Client Risk

- **Finding W1 [Medium]:** Default CORS is permissive (`*`).
  - `GatewayConfig` defaults to `cors_origins = ["*"]`, which is fine for development but too open for production.
  - Browser-based applications holding bearer tokens are at risk if a malicious origin can make CORS-authorized requests.

  **Recommendation W1:**
  - Provide production config examples where:
    - `cors_enabled = true` but `cors_origins` is a **finite list of trusted front-end URLs**.
    - Wildcard `*` is only present in sample `.env` for development.
  - Optionally, add runtime checks that log warnings when `cors_origins` contains `*` while `auth_enabled = true`.

### 7.4 Metadata Privacy and Observability

- **Finding M1 [Low/Info]:** Some metadata remains visible.
  - Even with encryption, bucket names, encrypted object sizes, and timestamps are visible to the gateway.
  - This is generally acceptable given the threat model but should be documented.

  **Recommendation M1:**
  - Document clearly that **traffic patterns and volume, bucket names, and approximate data sizes** are not hidden from the gateway operator.
  - For highly sensitive use cases, recommend using non-identifying bucket names and padding strategies at the client level.

- **Finding M2 [Low]:** Pinning names may expose object keys for unencrypted clients.
  - For unencrypted S3 clients, `object_key` may be used as a human-readable `name` in pinning services.
  - For encrypted clients with FlatNamespace, this name is obfuscated storage key, so no issue.

  **Recommendation M2:**
  - For privacy-sensitive deployments, recommend that unencrypted clients **avoid meaningful object keys** if also using pinning services, or enforce encryption.

### 7.5 Multi-Part Upload Implementation

- **Finding U1 [Low/Functional]:** Multipart implementation is intentionally simplified.
  - `complete_multipart_upload` currently uses only the first part’s CID for final `ObjectMetadata` and treats the rest logically.
  - Comments note that “in a real implementation, we'd create a DAG linking all parts.”
  - This is more of a **completeness/integrity** concern for very large files than a fresh security flaw.

  **Recommendation U1:**
  - Implement the full DAG-based multipart assembly as described in the architecture document.
  - Verify part lists and ETags thoroughly and ensure final CID covers all parts.

8. Operational Hardening Checklist
----------------------------------

For **public production deployments** intended to store private data, the following configuration is recommended:

1. **Enable strong auth:**
   - Do **not** use `--no-auth` or `FULA_NO_AUTH=true`.
   - Set a long, random `JWT_SECRET`.
   - Enforce `OAUTH_ISSUER` and `OAUTH_AUDIENCE` via `JwtValidationConfig`.

2. **Lock down CORS:**
   - Set `cors_enabled = true`.
   - Replace `"*"` in `cors_origins` with a list of trusted front-end URLs.

3. **Encourage/require encrypted clients:**
   - Provide SDKs that default to `EncryptedClient` + FlatNamespace.
   - For “private buckets,” consider having a future gateway mode that rejects non-encrypted writes.

4. **Logging and monitoring:**
   - Keep logging of sensitive values disabled (as currently implemented).
   - Consider adding audit logs of security-relevant events (auth failures, bucket ownership violations) to an immutable store (e.g., IPFS-based log archive).

5. **Infrastructure:**
   - Place the gateway behind a standard reverse proxy (nginx/Traefik) with TLS termination, additional rate limits, and DoS protections.
   - Treat IPFS nodes as untrusted storage; separate them from control-plane networks.

9. Summary
----------

The `fula-api` codebase presents a **strongly designed cryptographic foundation** and a **thoughtful client-side encryption model** suitable for storing private data on untrusted, decentralized infrastructure. When used with the encrypted client SDK, particularly in FlatNamespace mode, it provides robust confidentiality and metadata privacy: storage nodes and gateway operators cannot decrypt files or infer directory structure.

The primary remaining risks are **configuration and usage**:

- Running the gateway with auth disabled.
- Accepting tokens without issuer/audience constraints.
- Allowing browser-based access with wide-open CORS.
- Using plain S3 clients for sensitive data instead of the encrypted SDK.

Addressing the recommendations in this report—particularly around auth wiring, CORS defaults, hashed owner IDs, and a “require-encryption” mode for private buckets—will significantly strengthen the system’s security posture for public use as a decentralized, S3-compatible backend for private data.
