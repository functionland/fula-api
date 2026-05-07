# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.3] - 2026-05-07

**Hotfix release.** Fixes a silent cold-start failure for pre-migration-011 users (legacy users whose JWT `sub` claim is plaintext email rather than `sha256(email).hex()`). Without this fix, those users get a "user has not written yet" error when trying to read their own data offline, even though they have written. Apps should call the new `deriveUserKeyFromJwtSub` function whenever they have access to the JWT (which they do at sign-in).

### Fixed

- **Cold-start userKey derivation now matches master byte-for-byte for ALL users.** Master's `crates/fula-cli/src/state.rs::hash_user_id` does `BLAKE3.derive_key("fula:user_id:", claims.sub.as_bytes())[..16]` — no transformation of the JWT sub. The previous SDK-side `derive_user_key_from_email` always pre-hashed with `sha256(email)` first, which matches master ONLY for post-migration-011 users (whose `claims.sub` already IS `sha256(email).hex()`). For pre-migration users like the production account `ehsan@fx.land` (whose `claims.sub` is the plaintext email), the SDK's `sha256` step diverged from master's. Master stored the user's `bucketsIndexCid` under userKey `4da2c0616b1d39660f9f94e145fbce4f` (BLAKE3 over plaintext email); the SDK looked up `d2df90894e237aa4ef50618e514e0e37` (BLAKE3 over `sha256(email).hex()`). Lookup missed; cold-start failed silently with a misleading "user has not written yet" error.
- **Fix:** new `derive_user_key_from_jwt_sub(jwt_sub)` in `crates/fula-client/src/user_key.rs` mirrors master's algorithm exactly — feeds the JWT sub into BLAKE3 with no transformation. Apps call it at sign-in (the JWT is right there), passing the sub through unchanged. Works for both pre-migration and post-migration users without branching. The legacy `derive_user_key_from_email` is kept for source compatibility but is now documented as broken for pre-migration users.

### Added

- **`fula_client::derive_user_key_from_jwt_sub` (pure / cross-target)** — preferred userKey derivation. 32-hex output, stable per OAuth identity, matches master.
- **fula-flutter Dart binding `deriveUserKeyFromJwtSub`** at `crates/fula-flutter/src/api/client.rs` — generated automatically by FRB.
- **fula-js wasm-bindgen binding `deriveUserKeyFromJwtSub`** at `crates/fula-js/src/lib.rs:1075-1077` — exposed as `deriveUserKeyFromJwtSub` in JS.
- **Pinned regression tests** in `crates/fula-client/src/user_key.rs::tests`:
  - `derive_user_key_from_jwt_sub_matches_master_for_plaintext_email_sub` — asserts `derive_user_key_from_jwt_sub("ehsan@fx.land") == "4da2c0616b1d39660f9f94e145fbce4f"` (the actual value in master's published CBOR).
  - `derive_user_key_from_jwt_sub_matches_legacy_for_sha256_email_sub` — asserts the new function on a sha256-hex sub equals the old function on the original email.
  - `derive_user_key_from_email_pinned_value` — asserts the legacy function's broken-for-legacy-users return value (`d2df90...`) so future refactors can't silently change the algorithm.
  - `derive_user_key_from_jwt_sub_empty_does_not_panic` — defense against edge-case input.

### Migration guide for apps

If your app calls `deriveUserKeyFromEmail(email)` today, switch to `deriveUserKeyFromJwtSub(jwt_sub)` where `jwt_sub` is the `sub` claim from the JWT your auth flow already received. Pre-migration users will start being able to cold-start; post-migration users see no behavior change.

JWT sub extraction is one-line in most languages — for Dart, see the example `_extractJwtSub` helper in FxFiles' `fula_api_service.dart`. The fula_client SDK does NOT need the JWT or the email — only the sub string.

If your app cannot get the JWT sub at the call site, keep using `deriveUserKeyFromEmail` with the caveat that pre-migration users won't be able to cold-start. The legacy function is NOT going to be removed.

### Known limitations

- **Already-cached state on device** still has the wrong userKey baked in if the app cached the userKey from a previous session. Apps should clear any cached userKey on first run after upgrading to v0.4.3 OR re-derive on every init (cheap operation). FxFiles re-derives on every `FulaApiService.initialize` call so no special migration is needed there.
- **Master-side `state.rs::hash_user_id`** still has the underlying inconsistency (task #24 in the master-independent-reads plan). This SDK fix is a workaround that aligns the SDK to master's existing behavior — it does NOT unify the two `hash_user_id` functions inside fula-cli. That cleanup is tracked separately.

### Operational

- **No master changes required.** Strictly an SDK-side fix.
- **No data migration required.** Cold-start lookups now hit the right key; existing data is preserved untouched.
- **No coordinated rollout required.** v0.4.2 master + v0.4.3 SDK works. v0.4.3 master (when bumped to match) + v0.4.2 SDK still works for post-migration users; pre-migration users see the same broken behavior they had before until the SDK is upgraded.

## [0.4.2] - 2026-05-07

**Security release.** Includes a high-severity PII leak fix and an admin sweep tool to remediate already-leaked data. Operators who deployed v0.4.0 or v0.4.1 with the Phase 3.2 users-index publisher enabled (i.e., `FULA_USERS_INDEX_PUBLISHER_ENABLED=1`) MUST follow the runbook in `crates/fula-cli/src/handlers/admin.rs::pii_sweep`. Apps using fula-client 0.4.0/0.4.1 are not affected directly — this is a master-side fix.

### Security

- **CRITICAL: Per-object `tags.owner_id` leaked the raw JWT `sub` claim into bucket Prolly Tree leaves.** For pre-migration-011 (legacy) users this is plaintext email; for post-migration users it's `sha256(email)` hex (still enumerable). The leaves are content-addressed and pinned to IPFS; the Phase 3.2 publisher then exposed each affected bucket's `root_cid` as the `manifest` field of a publicly-fetchable per-user `bucketsIndex` CBOR. Fixed at `crates/fula-cli/src/handlers/object.rs:127` and `crates/fula-cli/src/handlers/multipart.rs:210` — both now use `session.hashed_user_id` (canonical 16-byte BLAKE3-derived opaque form, matching `BucketMetadata.owner_id` and the COPY handler at line 694). Verified safe for download, decryption, share-token issuance, and access control (per-object `owner_id` is metadata only; bucket-level `can_access_bucket` already uses the hashed form).
- **HIGH: Rate-limit middleware keyed on raw JWT sub.** `crates/fula-cli/src/middleware.rs:175` now uses `session.hashed_user_id`. In-memory only, but if metrics are exported (Prometheus, etc.) the raw form would leak.
- **HIGH: Admin tracing logged raw JWT sub.** `crates/fula-cli/src/middleware.rs:144-157` (admin-auth log line) and `crates/fula-cli/src/handlers/admin.rs:97-101, 146-150, 176-178` (admin handler entry/no-buckets logs) now compute the BLAKE3-hashed form before logging. Note: HTTP response bodies for admin endpoints still echo the raw URL parameter `user_id` (admin-supplied; admin auth gates this); tightening the response is a separate API change.
- **Documented `UserSession.user_id` as PII.** `crates/fula-cli/src/state.rs:170-186` doc-comment now explicitly warns: never persist, never log, never return externally; use `hashed_user_id` instead. The two legitimate consumers (computing `hashed_user_id` at session construction, forwarding the raw JWT to the pinning service) are called out.
- **NEW: `POST /admin/pii-sweep` endpoint.** Admin-authenticated rewrite tool. Walks every bucket's Prolly Tree, identifies objects whose `owner_id` differs from the canonical `BucketMetadata.owner_id`, rewrites them in-memory, and atomically flushes a fresh root_cid per bucket via the existing `flush()` mechanism. Idempotent, dry-run by default (`?dry_run=true`), per-bucket detail report. Holds the same `bucket_write_lock(hashed_user_id, bucket_name)` the regular PUT handler holds, so concurrent uploads serialize naturally without losing user writes. Crash-safe: rewritten buckets are committed atomically; pending buckets stay at pre-sweep state for the next run. See `handlers::admin::pii_sweep` for full runbook including IMPORTANT note that the sweep does NOT clean up cluster pins of old root_cids (operator must run `ipfs-cluster-ctl pin rm` for each `details[].old_root_cid`) and that chain-anchor `Published` event history is permanent (no mitigation short of contract redeployment, which is out of scope).

## [0.4.1] - 2026-05-06

Follow-up release that closes correctness gaps found while validating v0.4.0's offline-reads end-to-end against a live master. **Strictly additive at the API level** — no signature changes, no Dart/JS code changes required in apps; just rebuild against the new SDK.

### Fixed

- **Offline path no longer masks failures as empty forests.** `load_forest_internal` previously caught every error via a wildcard `Err(_)` arm and silently created an empty v7 forest, so a master-unreachable read returned 0 files instead of surfacing the outage. Narrowed to `Err(e) if e.is_not_found()` for the genuine "new bucket" path; every other error now propagates correctly. Apps see real errors during outages instead of empty buckets. (`encryption.rs:2569`)
- **Connection-refused / DNS-failure errors now correctly classify as master-unreachable.** `is_master_unreachable_error` only looked at `reqwest::Error::is_connect()`, which fails to detect connect errors through the reqwest 0.12 + hyper-util wrapper chain. Added a source-chain `std::io::Error` walker that catches `ConnectionRefused / TimedOut / NetworkUnreachable / HostUnreachable / ConnectionReset / ConnectionAborted / NotConnected / AddrNotAvailable / BrokenPipe / NetworkDown`. Without this fix, real offline scenarios bypassed the warm-cache fallback entirely. (`client.rs::source_chain_has_network_io_error`)
- **v7 sharded-HAMT manifest pages now use the offline-fallback wrapper.** `load_manifest_pages` was fetching every page via raw `get_object`, bypassing the warm cache. Master-down reads of sharded buckets failed even with cache + gateway flags on. Routed through `get_object_with_offline_fallback`. Same security model — page bytes are AEAD envelopes decrypted with `forest_dek` after fetch; cache stores only ciphertext keyed by content-addressed CID. (`encryption.rs:3744-3783`)
- **v7 directory-index also uses the offline-fallback wrapper.** Same root cause as manifest pages; same fix. `NotFound` short-circuits to "rebuild from forest" unchanged. (`encryption.rs:3807-3856`)
- **Encrypted offline DOWNLOAD now works for single-object AND chunked files.** The encrypted SDK's read path required HTTP `x-fula-encryption` user-metadata to decrypt — a header that gateways don't preserve and the warm cache didn't capture. The read path (`get_object_decrypted_by_storage_key`) now falls back to the forest entry's `user_metadata` when the HTTP header is absent, and the upload path stashes the encryption-metadata JSON onto `forest_entry.user_metadata` so future reads are self-describing. The forest blob is AEAD-encrypted with `forest_dek` (derived from the user's KEK), so the metadata travels privately. AEAD AAD on every chunk binds bytes to their `storage_key`, defeating key-substitution attacks. Forward-only: existing pre-v0.4.1 uploads still need master to be reachable until they're re-uploaded once. (`encryption.rs:put_object_flat_deferred`, `encryption.rs:get_object_decrypted_by_storage_key`)
- **Per-chunk fetches in the chunked-download engine route through `get_object_with_offline_fallback`.** Chunks themselves carry no per-chunk metadata (DEK from the index, nonce derived from chunk_index), so warm-cache hits are sufficient. Bao streaming verifier still catches truncation/tampering regardless of which channel served the bytes. Files >768 KB (the chunked threshold) now decrypt fully offline. (`encryption.rs:download_chunks_windowed_to_writer`)
- **`FulaUsersIndexAnchor` Solidity contract: `initialize` now also accepts an `initialOperator` argument** that's granted `CONTRACT_OPERATOR_ROLE` at deploy with the same `ROLE_CHANGE_DELAY` timelock as owner/admin. Removes the operational dead-time of the day-one AddRole governance round-trip while preserving the multi-sig discipline for every subsequent operator change. Audit-driven; documented in the deploy script.
- **Phase 1.2 `bucket_lookup_h` header now rides on every Phase 1.5 page PUT and Phase 1.6 dir-index PUT, not only the Phase 2 manifest-root commit.** Buckets that flush rarely — or where `flush_forest` is deferred — now migrate from `legacy=true` to `legacy=false` on the first chunked upload that dirties any manifest page, instead of waiting for an explicit `flushForest` call to fire Phase 2. Master's `populate_lookup_h_if_missing` is idempotent (`bucket.rs:1017-1041`), so the same hex from multiple PUTs in one flush is a no-op after the first. The lookup-h hex is now hoisted out of the Phase 1.5 dirty-pages loop (computed once per flush, reused across page PUTs, dir-index PUT, and root PUT). No security delta — same per-bucket, per-user blinded value derived from the user's MetadataKey. (`encryption.rs:3463-3552, 3586-3587, 3660-3673`)

### Added

- **`BlockCache` and `BlockCacheError` re-exported at `fula_client` crate root** (`pub use block_cache::{BlockCache, BlockCacheError}`), gated to native targets. Lets integration tests and operator diagnostic tooling probe cache state without crossing internal-module-path boundaries. The cache itself stores only AEAD-encrypted ciphertext keyed by content-addressed CID — no plaintext, no encryption keys.
- **`FileMetadata.userMetadata` is now boundary-filtered** before returning to apps: keys starting with `x-fula-` are stripped. Internal SDK plumbing (notably `x-fula-encryption` carrying the HPKE-wrapped DEK) no longer leaks into UI surfaces like "Properties" dialogs or custom-tag screens. App-set keys are returned unchanged.
- **End-to-end integration test (`tests/offline_e2e.rs`).** Three variants — single-object (256 B), chunked (1.5 MB straddling the 768 KB threshold), and a legacy alias. Each phase: upload → fresh-client read against real master (populates warm cache) → bogus-master client (proves cache-served decrypt). Gated `#[ignore]`; opt in with `FULA_JWT` + `FULA_S3` env vars. Validates every fix above against live infrastructure.

### Changed

- **`get_object_decrypted_by_storage_key` routes through `get_object_with_offline_fallback`.** Same signature, same master-up behavior; transparently picks up warm-cache offline support. The cache hook on success populates `KEY_TO_CID` + `BLOCKS` for both index objects and chunks.
- **Forest entries written by v0.4.1 carry encryption metadata in `user_metadata`** (`x-fula-encrypted`, `x-fula-encryption` JSON, optionally `x-fula-chunked`). Same JSON the master gets in HTTP user-metadata, but stored privately inside the AEAD-encrypted forest blob. Apps that want to read these can grep their own forest entries; the boundary filter (above) hides them from the public `FileMetadata.userMetadata` map.
- **`load_forest_internal` errors are no longer self-healing into empty state.** Combined with the discriminator fix above, transient outages now propagate to the caller instead of silently caching empty. The next call after master returns re-fetches from scratch (cache stays empty on the failure path).

### Bindings

- **No public API changes.** `fula-flutter` and `fula-js` continue to expose the same Dart / TypeScript surfaces as v0.4.0. Apps just need to bump the dependency version and rebuild. The bug fixes above land automatically.
- **`fula-flutter`**: regenerated `frb_generated.rs` from CI on tag push (no manual codegen needed). The Dart binding `getObjectWithOfflineFallback` now backs encrypted offline reads via the path through `get_object_decrypted_by_storage_key`.
- **`fula-js`**: same — wasm-bindgen surface unchanged; the upstream Rust fixes apply transparently.

### Operational

- **Master deploy is unchanged.** All v0.4.1 changes are SDK-side. Master operators keep their existing `FULA_BUCKET_LOOKUP_H_ENABLED`, `FULA_USERS_INDEX_PUBLISHER_ENABLED`, etc. settings.
- **Mixed-version coexistence.** A v0.4.0 master + v0.4.1 client works (master ignores client-side improvements). A v0.4.1 master + v0.4.0 client also works (master changes are forward-compatible with old SDKs).

### Known Limitations

- **Encrypted offline DOWNLOAD is forward-only.** Files uploaded by an SDK older than v0.4.1 don't carry encryption metadata in their forest entries, so reading them while the master is unreachable still fails (clean error: "Missing encryption metadata in headers AND forest entry — re-upload via the new SDK to enable offline reads"). Re-upload migrates lazily; on master-up, every re-upload populates the forest entry. No explicit migration step is required for end users.
- **Sibling encrypted-read paths not yet routed through offline-fallback.** `get_object_decrypted_to_writer_by_storage_key`, `get_object_decrypted_buffered_to_writer_by_storage_key`, and `get_object_with_private_metadata` still use direct master fetch. FxFiles doesn't call these (uses `getFlat` only) but they're tracked for a follow-up release if other apps need the streaming-decrypt offline path.

### Migration Guide

- **No code changes.** Bump `fula_client` (Dart) / `fula-js` (npm) / `fula-client` (Rust) to `0.4.1`, rebuild, redistribute.
- **No data migration.** Existing forests, existing buckets, existing chain entries — all readable as-is.
- **Re-upload existing files** if you want offline-encrypted reads to cover them too. New uploads are self-describing immediately.

## [0.4.0] - 2026-05-04

### Added

- **Master-independent reads (Phase 2 + 3 + 19).** When the master gateway is unreachable, the SDK now transparently falls back to public IPFS gateways AND, on a fresh device install, can cold-start by resolving a globally-published users-index from IPNS or the chain anchor — without a client wallet. End users keep reading their own files even during master outages.

  - **Phase 2.1 — Master health gate.** Lock-free `AtomicU64` state machine that observes request outcomes and short-circuits with `MasterUnreachable` after two consecutive failures, instead of paying the per-read timeout tax. New `FulaConfig` fields: `healthGateEnabled`, `healthGateTtlSeconds`. Functional on every target including web. Default OFF for backward-compat.
  - **Phase 2.2 — Persistent block cache.** redb-backed LRU cache (default 256 MiB) of fetched encrypted blocks keyed by CID. Populated transparently during master-up reads; serves repeat reads without any network hit during master outages. New fields: `blockCacheEnabled`, `blockCachePath`, `blockCacheMaxBytes`. Native-only at runtime; the flags are accepted on web for config symmetry but inert.
  - **Phase 2.3 — Multi-gateway race + dynamic priority + CID verification.** Six default public IPFS gateways raced K-at-a-time (default K=3) with per-gateway penalty/cooldown state. Every fetched block is re-hashed against the requested CID's multihash (BLAKE3 or SHA2-256) before being trusted. New fields: `gatewayFallbackEnabled`, `gatewayFallbackUrls`, `gatewayRaceConcurrency`. Native-only.
  - **Phase 2.4 — Wired warm-device offline GET.** New `getObjectWithOfflineFallback` returns `OfflineGetResult` with bytes + transparency. Master-up reads serve normally; master-down reads fall through to the gateway race using the cached `(bucket, key) → cid` mapping. Cold-start (cache miss) propagates `MasterUnreachable` for the resolver to handle.
  - **Phase 3.2 — Master-side users-index publisher.** Master gateway now periodically (every 5 min by default) builds per-user `bucketsIndex` CBORs + a global users-index CBOR, pins them via cluster, publishes to IPNS, and a 12h cron in `mainnet-rewards-server` submits the same CID to a `FulaUsersIndexAnchor` contract on Base/SKALE. Two chain writes per day, fixed forever, gas-defensive against future Base pricing. Server-side change; SDK consumes via Phase 3.3.
  - **Phase 3.3 — Cold-start hybrid resolver (IPNS-first → chain-fallback).** New `FulaConfig` fields: `usersIndexChainRpcUrl`, `usersIndexAnchorAddress`, `usersIndexIpnsName`, `usersIndexUserKey`, `usersIndexIpnsGatewayUrls`, `usersIndexIpfsGatewayUrls`. New free function `deriveUserKeyFromEmail(email)` — apps call once at sign-in to derive the userKey; SDK never sees the raw email. Resolver activates iff all four required fields are populated; fresh-install fresh-master-down reads now succeed. Native-only at runtime; web surfaces typed `UsersIndexResolutionFailed` errors.
  - **Phase 19 — Transparency surfaces.** `OfflineGetResult { inner, source: ReadSource, freshness: ReadFreshness }`, `MasterHealthEvent` enum (`Online | OfflineFallbackActive | SeverelyDegraded`). New polling APIs `pollMasterHealthEvents(client)` and `getLastMasterHealthEvent(client)` so apps can drive online/offline UI affordances. The Rust core also exposes a closure-based `HealthCallback`; the FRB and wasm-bindgen bindings expose the polling form for cross-target ergonomics.

### Changed

- **`getObjectWithOfflineFallback` return type** is now `OfflineGetResult` (was `GetObjectResult`). Master-up reads return `source: Master, freshness: Live` so existing callers that only read `.inner.data` need a one-character change. The pre-existing `getObjectWithMetadata` is unchanged.
- **`PublishNowResponse`** (master-side admin endpoint) gains a `failed_users` field exposing the per-user-error-tolerance count from `TickOutcome`.
- **Per-user error tolerance in master publisher.** A single user's CBOR pin failure no longer aborts the whole tick; succeeded users still get published, failed users keep their prior CID, and they retry on the next tick. `TickOutcome` gains `failed_users: usize`.

### Bindings

- **fula-flutter (Dart)** — every Phase 2.x / 3.3 / 19 surface plumbed: 6 new Phase 3.3 config fields + 2 new types (`OfflineGetResult`, `MasterHealthEvent`) + 2 new enum types (`FulaReadSource`, `FulaReadFreshness`) + free function `deriveUserKeyFromEmail` + method `getObjectWithOfflineFallback` + polling `pollMasterHealthEvents` / `getLastMasterHealthEvent` (+ encrypted-handle variants). Generated Dart bindings + `frb_generated.rs` are regenerated by CI on tag push.
- **fula-js (wasm-bindgen / TypeScript)** — same surfaces exposed via serde-tagged JS objects. Cross-target `deriveUserKeyFromEmail` extracted from `registry_resolver` to a wasm-friendly `user_key` module so JS apps can compute the userKey on web.
- **Error mapping** — both bindings cover the new `UsersIndexResolutionFailed`, `SequenceRegression`, `BlockTooLarge`, and `BlockCacheError` variants.

### Operational

- **New admin endpoints** for triggering an immediate publisher tick / chain anchor submit without waiting up to 12h:
  - `fula-cli`: `POST /_internal/publish-now` (already existed; response now includes `failed_users`)
  - `mainnet-rewards-server`: `POST /admin/users-index-anchor/trigger` (new) — bearer-protected, fail-closed 503, 409 on contention
  - `pinning-webui`: new admin tab "Fula Publisher" with two buttons proxying through `/api/admin/fula/publish-now` and `/api/admin/fula/anchor-now`
- **Master deploy is backward-compat**: every new server-side path is gated by an env flag default-OFF. Old fula-clients (running pre-0.4.0 SDK) continue to work byte-identically against an 0.4.0 master.

### Migration Guide

- **Existing apps reading bytes**: change `result.data` → `result.inner.data` if you're using `getObjectWithOfflineFallback`. `getObjectWithMetadata` callers unchanged.
- **To enable warm-device offline reads**: set `healthGateEnabled = true`, `blockCacheEnabled = true`, `gatewayFallbackEnabled = true` on `FulaConfig`. Native-only; safe to set on web (silently inert).
- **To enable cold-start (fresh device install while master is down)**: in addition to the warm-device flags, populate `usersIndexChainRpcUrl`, `usersIndexAnchorAddress`, `usersIndexIpnsName` (operator-supplied at deploy), and `usersIndexUserKey` (computed via `deriveUserKeyFromEmail(email)` at sign-in). Native-only at runtime.
- **No data migration required.** Existing on-chain / IPFS / S3 data remains readable through every new code path AND through the existing master path.

## [0.3.0] - 2026-04-01

Internal SDK refactors and incremental fixes between v0.2.18 and v0.4.0; see git history for the full set. The user-facing API additions are consolidated under v0.4.0 above.

## [0.2.18] - 2026-01-13

### Fixed

- **Android 16KB page size support for Android 15+ (API 35)**
  - Native libraries (.so files) now compiled with 16KB page alignment
  - Added `-Wl,-z,max-page-size=16384` linker flag to all Android targets in CI
  - Apps can now target Android 15 without Google Play warnings

## [0.2.17] - 2026-01-13

### Fixed

- **CRITICAL: Share tokens missing encryption nonce - decryption produces garbage**
  - Share tokens only contained wrapped DEK but not the nonce needed for decryption
  - Web UI proxy doesn't forward S3 metadata headers (`x-fula-encryption`)
  - Without the nonce, decryption "succeeds" but produces garbage data
  - **Fix**: Share tokens now include `nonce` (for single-block files) and `chunked_metadata` (for chunked files)
  - Recipients can now decrypt using just the share token without needing S3 metadata headers

### Changed

- `ShareToken` struct now includes optional `nonce` and `chunked_metadata` fields
- `ShareBuilder` has new `.nonce()` and `.chunked_metadata()` builder methods
- `AcceptedShare` now carries nonce and chunked metadata through to decryption
- `get_object_with_share` uses nonce from share token if available, falls back to S3 headers for backwards compatibility
- Share token version bumped to 3

### Migration Guide for FxFiles

Share tokens created with v0.2.17+ will automatically include the nonce.
No code changes needed - just rebuild FxFiles with the new fula_client SDK.

Old share tokens (without nonce) will continue to work if the proxy forwards S3 headers correctly.

## [0.2.16] - 2026-01-13

### Fixed

- **CRITICAL: Share decryption fails for chunked files (files > 768KB)**
  - `get_object_with_share` was using single-block decryption for all files
  - Chunked files store each chunk with its own nonce in `{storage_key}.chunks/{index}`
  - Share flow was ignoring chunked file metadata and trying to decrypt assembled bytes as single block
  - **Result**: Large shared files (images, videos) returned garbage data instead of correct content
  - **Fix**: `get_object_with_share` now checks `x-fula-chunked` metadata and uses `ChunkedDecoder` with per-chunk nonces when needed

### Technical Details

- Added `get_object_chunked_with_share()` internal method for chunked file handling in share flow
- Downloads each chunk from `{storage_key}.chunks/{index}`, decrypts with chunk-specific nonce
- Concatenates decrypted chunks and returns complete plaintext
- Works identically to normal `get_object_decrypted_by_storage_key()` but uses share's DEK

## [0.2.15] - 2026-01-13

### Fixed

- **CRITICAL: flutter_rust_bridge content hash mismatch in CI**
  - `build-android` and `build-ios` jobs were building native libraries from committed `frb_generated.rs`
  - `generate-bindings` job was creating fresh `frb_generated.dart` with different content hash
  - This caused "Content hash on Dart side is different from Rust side" error
  - **Fix**: Both Android and iOS build jobs now run `flutter_rust_bridge_codegen generate` before building

- **CRITICAL: X25519 public key derivation mismatch between Dart and Rust**
  - When sharing files via public links, FxFiles was using Dart's `cryptography` package to derive X25519 public keys
  - The Web UI uses Rust (via WASM) to derive public keys from the same private key bytes
  - Different implementations may produce different public keys from the same private key seed
  - This caused HPKE key wrapping to fail: the share token encrypted DEK for Dart's public key, but the web UI derived a different public key from the private key in the URL
  - **Fix**: Added `derivePublicKeyFromSecret()` function to both Flutter and JS/WASM bindings
  - **Required FxFiles change**: Use `derivePublicKeyFromSecret(secretKeyBytes)` instead of Dart's native X25519 derivation

### Added

- `derivePublicKeyFromSecret(Vec<u8>)` - Flutter API function to derive X25519 public key from private key bytes using Rust's x25519_dalek
- `derivePublicKeyFromSecret(Uint8Array)` - JS/WASM function for the same purpose
- Comprehensive tests verifying end-to-end share flow compatibility

### Migration Guide for FxFiles

Replace this Dart code:
```dart
final x25519 = X25519();
final keyPair = await x25519.newKeyPair();
final publicKeyBytes = Uint8List.fromList((await keyPair.extractPublicKey()).bytes);
final privateKeyBytes = await keyPair.extractPrivateKeyBytes();
```

With this:
```dart
import 'dart:math';

// Generate random 32 bytes
final privateKeyBytes = Uint8List(32);
Random.secure().nextBytes(privateKeyBytes);

// Derive public key using Rust (ensures cross-platform compatibility)
final publicKeyBytes = await derivePublicKeyFromSecret(privateKeyBytes);
```

## [0.2.12] - 2026-01-13

### Fixed

- **CRITICAL: Share token DEK mismatch bug**: Fixed share tokens using derived DEK instead of actual uploaded DEK
  - In FlatNamespace mode, files are encrypted with random DEKs stored in metadata
  - Share token creation was incorrectly deriving DEK from path instead of fetching actual DEK from metadata
  - This caused all shared files to fail decryption on recipient side (garbage output)
  - Fix: `create_share_token` and `create_share_token_with_mode` now fetch wrapped DEK from object metadata

### Changed

- **API Breaking Change**: `createShareToken` and `createShareTokenWithMode` now require `bucket` parameter
  - Flutter: `createShareToken(bucket: 'mybucket', storageKey: '...', ...)`
  - This is needed to fetch object metadata containing the actual DEK

### Added

- Comprehensive sharing tests verifying:
  - Share token uses correct (uploaded) DEK
  - Different files have different random DEKs (isolation)
  - Sharing one file does not expose other files
  - Wrong recipient cannot decrypt share tokens
  - Path scope enforcement
  - Expiration handling

## [0.2.11] - 2026-01-13

### Fixed

- **WASM time compatibility bug**: Fixed `time not implemented on this platform` panic when validating share tokens in browser
- Added centralized `time::now_timestamp()` function using `js_sys::Date::now()` for WASM and `std::time::SystemTime` for native

### Changed

- Updated `fula-crypto` to use WASM-compatible time functions in sharing, inbox, private_metadata, and subtree_keys modules

## [0.2.10] - 2026-01-12

### Added

- New `@functionland/fula-client` npm package with high-level JavaScript APIs
- WASM bindings using wasm-bindgen (replaces low-level flutter_rust_bridge exports)
- Cross-platform key derivation compatibility between Flutter and JavaScript
- Functions: `createEncryptedClient`, `getDecrypted`, `putEncrypted`, `deriveKey`, `acceptShare`, `getWithShare`

### Changed

- GitHub Actions workflows updated to build and publish fula-js npm package

## [0.2.9] - 2026-01-11

### Changed

- Bumped version to 0.2.9

## [0.2.8] - 2026-01-11

### Changed

- Minimum Flutter version raised to 3.38.0 (Dart 3.10.x)
- Minimum Dart SDK raised to 3.8.0 (required for freezed ^3.2.0)
- CI/CD workflows updated to use Flutter 3.38.0 stable
- Web plugin updated to use `package:web` and `dart:js_interop` (replacing deprecated `dart:html` and `dart:js`)

## [0.2.7] - 2026-01-11

### Changed

- Minimum Flutter version raised to 3.27.0 (Dart 3.6.0 required for freezed 3.x)
- Minimum Dart SDK raised to 3.6.0
- CI/CD workflows updated to use Flutter 3.27.0

## [0.2.6] - 2026-01-11

### Changed

- Updated `freezed_annotation` to ^3.1.0 for compatibility with other packages
- Updated `freezed` to ^3.2.0
- Updated `flutter_lints` to ^5.0.0
- Updated `ffigen` to ^14.0.0

## [0.2.5] - 2026-01-11

### Changed

- Release workflow now triggers on tag push (v*) for pub.dev OIDC compatibility
- Simplified release process: just push a tag to publish everywhere

### Fixed

- pub.dev OIDC authentication now works (requires tag context, not branch)

## [0.2.3] - 2026-01-11

### Changed

- iOS binaries now downloaded from GitHub Releases during pod install
- This reduces pub.dev package size from 160MB to ~12MB

### Fixed

- Strip debug symbols from native libraries to reduce package size
- Fixed Android NDK compiler configuration (CC/AR environment variables)
- Disabled wasm-opt to fix bulk memory operations error

## [0.2.1] - 2026-01-11

### Added

- GitHub Actions CI workflow for automated testing
- GitHub Actions release workflow for publishing to pub.dev and npm
- iOS XCFramework support for device and simulator builds

### Changed

- Switched from parking_lot to tokio::sync for async-safe locks
- Made async runtime conditional: tokio on native, async-lock on WASM
- Updated iOS podspec to use XCFramework instead of static library
- Improved flutter_rust_bridge compatibility with anyhow::Result

### Fixed

- WASM build now compiles correctly without tokio OS-specific dependencies
- Android namespace updated from fula_flutter to fula_client
- Fixed flutter_rust_bridge codegen configuration

## [0.2.0] - 2026-01-10

### Added

- **FlatNamespace obfuscation mode** - Complete structure hiding for maximum privacy
- **PreserveStructure obfuscation mode** - Keep folder paths, hash filenames only
- All 4 obfuscation modes now available: `flatNamespace`, `deterministic`, `random`, `preserveStructure`

### Changed

- Minimum SDK version raised to 3.3.0 (required for inline-class feature)
- Minimum Flutter version raised to 3.19.0
- FlatNamespace is now the recommended default for new projects

### Fixed

- Documentation updated to match actual API signatures

## [0.1.0] - 2024-01-09

### Added

- Initial release of fula_client Flutter SDK
- Client-side encryption with AES-256-GCM
- Metadata privacy with configurable obfuscation modes
- Secure file sharing with capability-based tokens
- Key rotation support
- Flat namespace API for file system-like access
- Android support via FFI
- Web support via WASM
- Multipart upload support for large files

### Security

- HPKE (Hybrid Public Key Encryption) for key exchange
- BLAKE3 for fast, secure hashing
- X25519 for elliptic curve Diffie-Hellman

## [Unreleased]

### Planned

- iOS support
- Desktop support (Windows, macOS, Linux)
- Offline-first sync capabilities
- Background upload/download
