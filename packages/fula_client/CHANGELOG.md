# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.6.20] - 2026-08-23

### Fixed

- **The bridge no longer serialises every call behind one lock.**
  `EncryptedClientHandle` wrapped the client in a single
  `Arc<RwLock<EncryptedClient>>` -- not per-bucket. `loadForest` took the
  EXCLUSIVE guard and held it across the whole network fetch, so ONE slow or
  damaged bucket blocked every other call in the app, including reads of
  healthy buckets. A Dart-side `.timeout()` could not rescue it: the binding
  exposes no cancel handle for `loadForest`, so the Rust future kept running
  and kept the guard after the caller gave up. The lock is removed rather than
  made per-bucket -- `EncryptedClient` has no `&mut self` methods, and the
  SDK already owns per-bucket locking (`forest_cache`, `migration_locks`,
  `bucket_write_mutex`).

- **Web builds now honour `timeoutSeconds`.** `reqwest`'s client-level
  timeout is a no-op on `wasm32`, so the browser ran with NO request timeout
  at all and a stalled fetch could hang for the lifetime of the tab. The wasm
  build now sets the timeout per-request, which reqwest enforces with an
  `AbortController`. A browser timeout surfaces as an ordinary transport
  error, identical in shape to native.

### Known issue

- Key rotation (`rewrapObject` / `rotateBucket`) is no longer serialised
  against uploads by the removed bridge lock. `rewrap_object_dek` is a
  GET-modify-PUT that takes no per-bucket lock, so an upload landing between
  its GET and PUT is overwritten by the re-encrypted old data. Fix is
  `If-Match`/ETag optimistic concurrency inside `rewrap_object_dek`;
  tracked separately.
## [0.6.12] - 2026-06-16

## [0.6.11] - 2026-06-16

## [0.6.10] - 2026-06-16

## [0.6.9] - 2026-06-12

### Added

- **`invalidateForestCache` / `invalidateAllForestCaches` bindings
  ([#36](https://github.com/functionland/fula-api/issues/36)).** The
  encrypted client caches each bucket's forest for the client lifetime,
  so a long-lived session never observed another device's uploads —
  listings and downloads kept resolving against the session-stale index.
  The escape hatch (`EncryptedClient::invalidate_forest_cache`) existed
  in the Rust core but was unreachable from Dart and JS. Both bindings
  now expose it: call on refresh / tab-resume / reconnect / cache-
  revalidation paths, then re-list — the next forest operation reloads
  from storage and sees cross-device writes, with no client rebuild.
  Dirty-safe per the existing core contract: a forest with pending
  (unsaved) local changes is NOT evicted; flush first, then invalidate.
  Exposed identically in `fula-flutter` (Dart: `invalidateForestCache`,
  `invalidateAllForestCaches`) and `fula-js` (same names) for
  cross-platform parity; CI now guards the npm `.d.ts` exports.

## [0.6.8] - 2026-06-12

### Fixed

- **Forest write amplification on sequential uploads
  ([#34](https://github.com/functionland/fula-api/issues/34)).** Every
  `put_object_flat` (and any other per-file flush) re-uploaded the entire
  ever-touched portion of the bucket's HAMT index instead of just the
  changed path, because nodes persisted by a flush were never marked
  clean in memory. Sequential bulk uploads into one directory therefore
  cost O(N²) total index traffic (measured: 1,630 index PUTs / 12.2 MB
  to store 150 × 4 KB files; per-upload latency grew 1.0 s → 3.8 s as the
  bucket filled). Flushes now write back a `Sealed` pointer state after
  each successful node PUT: a flush uploads only the shard root plus the
  path(s) mutated since the previous flush, so per-upload cost is flat
  regardless of bucket size (same workload now: 384 PUTs / 3.5 MB, ~3
  node PUTs per upload at any bucket size). The persisted format is
  byte-identical to previous releases — existing buckets are read and
  written exactly as before, and older SDKs interoperate unchanged.
  Applies to all platforms (Android, iOS, Windows, web/wasm, fula-js)
  since the fix lives in the shared `fula-crypto` core.

## [0.6.7] - 2026-06-10

### Fixed

- **Flutter Web actually works now.** Three fixes that together make
  `flutter build web` + browser runtime functional for apps depending on
  this package:
  - `lib/fula_client_web.dart` registrant stub added — the pubspec's
    `web:` plugin block named a file that only existed under `web/`, so
    Flutter's generated web plugin registrant failed to resolve and every
    consumer's web build broke at compile time.
  - **All bridge fns are now `async` on the Rust side.** flutter_rust_bridge
    dispatches sync fns to its Web-Worker pool on wasm32, which panics
    (`fail to create WorkerPool`) unless the site is cross-origin-isolated —
    impossible on plain static hosts like GitHub Pages. Async fns run on the
    JS event loop instead. No Dart signature changes (everything was already
    `Future`-typed) and no native behavior change.
  - `flutter_rust_bridge` Dart dependency pinned to exactly `2.11.1` and the
    release CI now installs the same pinned codegen in every job, so the
    published bindings, native binaries, and the new wasm bundle are
    hash-consistent by construction (0.6.6 shipped pub bindings from a
    different codegen run than the repo tree, so a wasm built from source
    was rejected at `RustLib.init()`).

### Added

- **`flutter-wasm-pkg.zip` release asset** — wasm-pack `--target no-modules`
  build of `crates/fula-flutter` (`pkg/fula_flutter.js` +
  `pkg/fula_flutter_bg.wasm`) for Flutter Web apps to ship under `web/pkg/`,
  plus a `VERSION` stamp for CI guards. Measured in headless Chrome from a
  plain static server: `RustLib.init()` ~224 ms, Argon2id `deriveKey`
  ~261 ms.

## [0.6.2] - 2026-05-23

### Fixed
- **#24 — Fixed 404 breaks.**

## [0.6.2] - 2026-05-23

### Fixed

- **#23 — `uploadLargeFileResumable` now durably persists the forest to master.** Previously, the resumable chunked upload path (`put_object_encrypted_resumable_with_cancel` and `resume_upload_with_cancel`) registered the new entry only in the in-memory cache + on-disk WAL after chunks landed; the master-side flush sequence (`save_sharded_hamt_forest`/`save_monolithic_forest` → `Persisting bucket registry to IPFS` → `Bucket root CID enqueued for durable pin (W.9.6)` → IPNS update) never fired. A fresh client load — post app restart, post storage clear, fresh device — pulled the pre-upload forest and the file was missing despite the upload returning a valid etag. Symmetric with `put_object_flat`'s established "register + flush" pattern; the resumable path was added in v0.6.0 (issues #16/#17/#18) but the flush step was inadvertently omitted. Fix is one line inside `finalize_and_register_resumed_upload` (`crates/fula-client/src/encryption.rs`): call `self.flush_forest_locked(bucket)` after `register_encrypted_chunked_upload_in_forest`, before manifest deletion. Uses the `_locked` variant because both callers already hold `bucket_write_mutex` (issue #16); `flush_forest`'s public variant would deadlock on tokio's non-reentrant mutex. Manifest deletion moved after the flush so crash-safety extends to flush failure (manifest stays on disk for `resume_upload` retry).
- Fixed a race condition in rust tests multi gateway.

### Added

- **Regression test `resumable_forest_persistence`** (`crates/fula-client/tests/resumable_forest_persistence.rs`) — integration test that uploads via the resumable path, drops the client entirely (including in-memory cache + on-disk WAL via separate tempdirs), creates a fresh client against the same master with no inherited state, and asserts the file appears in `list_files_from_forest` + downloads to the same bytes. Without the #23 fix this test fails at the fresh-client list assertion. Marked `#[ignore]`; opt-in via `FULA_JWT` + `FULA_S3` envvars (same convention as `offline_e2e`).

## [0.6.1] - 2026-05-09

**Walkable‑v8 writer flag flipped to default‑on (#89).** This is a wire‑format default flip, not a feature add. v0.6.0 shipped the entire walkable‑v8 stack (writer cascade, reader cid‑hint dispatch, durable pin queue, dual cross‑platform parity) but kept the writer flag default‑off so the v0.6.x rollout window could let pre‑v0.6 SDK readers continue reading newly‑written buckets byte‑identically. Per operator decision (*"that is ok. turn it on globally as when we roll out everyone will update"*), every new fula‑client / fula‑flutter / fula‑js Config now defaults `walkable_v8_writer_enabled = true`. **This deliberately bypasses the v0.6.0 rollout matrix's Phase B 4–8‑week SDK‑adoption gate** — the operator's coordinated single‑update rollout shape replaces the staged adoption window the v0.6.0 plan assumed; see `docs/wnfs-comparison.md` §9 + the project memory note `project_walkable_v8_default_on.md` for the authorization trail. Buckets written by v0.6.1+ SDKs emit `PointerWire::LinkV2` everywhere the cascade fires; pre‑v0.6 SDK readers encountering a `LinkV2` blob surface the typed `ClientError::WireVersionUnsupported { context, postcard_error }` variant cleanly (no data corruption), with parallel `FulaError::WireVersionUnsupported` on fula‑flutter (Dart `error_code() == "WIRE_VERSION_UNSUPPORTED"`) and the matching `"WIRE_VERSION_UNSUPPORTED"` JS error code on fula‑js — operators filtering error telemetry should match on these typed variants, not the underlying postcard message string. Operators relying on the v0.5‑readable wire form must now hold the flag down explicitly via `cfg.walkable_v8_writer_enabled = false`.

### Changed

- **`fula-client` `Config::default()`** — `walkable_v8_writer_enabled` now defaults to `true`. Existing tests that constructed a default Config to exercise the v7 path now pass through the v8 writer cascade; the only test that asserted "default‑off" semantics was renamed to `put_with_explicit_writer_disabled_returns_cid_none` (in `crates/fula-client/tests/s3_blob_backend_returns_cid.rs`) and explicitly sets `cfg.walkable_v8_writer_enabled = false` to keep covering the disabled‑writer path. The fula-flutter test `fula_config_default_phase_2_x_fields_are_off` was updated to assert default‑on for this field with a load‑bearing comment that flipping back is now a deliberate operator action.
- **`fula-flutter` `FulaConfig::default()`** — mirrors fula-client (cross‑platform alignment is non‑negotiable per the project memory rule). The published v0.6.1 Dart package on pub.dev exposes `walkableV8WriterEnabled` correctly: the release workflow `.github/workflows/flutter-release.yml` runs `flutter_rust_bridge_codegen generate` (line 67, plus line 136 and 209 in the Android / iOS native-build jobs) on every tag push, so the FRB-generated codecs in the shipped artifact are always in sync with the current Rust struct. The repo-checked-in `crates/fula-flutter/src/frb_generated.rs` is not auto-regenerated on commit and may lag behind the live Rust types — that's the in-scope state of #87 — but it does not affect what FxFiles or any other downstream consumer sees from the published SDK. Apps updating to v0.6.1 from pub.dev get the new field with full Dart-side rollback capability (set `walkableV8WriterEnabled: false` to opt out of the new default).
- **`fula-js` `JsConfig`** — the `walkable_v8_writer_enabled` field's `#[serde(default)]` was replaced with `#[serde(default = "default_walkable_v8_writer_enabled")]` plus a new `fn default_walkable_v8_writer_enabled() -> bool { true }` to defend against the silent‑drift trap where `bool::default() = false` would have masked the flip on the JS surface. Verified against `serde_wasm_bindgen::from_value` (the JS→Rust deserialization entry point at `crates/fula-js/src/lib.rs:499`); the custom default fires for any JS caller passing a config object without the field.
- **`docs/wnfs-comparison.md` §9** — W.9.3 status line updated to reflect the v0.6.1 flip; the "default off during the v0.6.x rollout" caveat is now a v0.6.0‑specific historical note.

### Operational impact

| Scenario | Behavior under v0.6.1 |
|---|---|
| New SDK install, app does not override `walkable_v8_writer_enabled` | New writes emit `LinkV2`. Buckets become offline‑walkable on first flush. ✅ |
| New SDK install, app explicitly sets `walkable_v8_writer_enabled = false` | New writes emit legacy `Link`. Pre‑v0.6 readable. Same behavior as v0.6.0 default. |
| Pre‑v0.6 SDK reading a v0.6.1‑written bucket | Surfaces typed `WireVersionUnsupported` on the `LinkV2` portions of the tree. v7 portions (siblings of mutations that haven't cascaded yet) read normally. **Lazy migration is per‑shard, not per‑bucket** — a single write only re‑stamps the touched shard's HAMT path; siblings in other shards stay v7 until the next write that lands in their shard. Operators verifying offline‑walk against legacy buckets need to write to enough directories to cover every populated shard before the entire bucket is v8‑only. |
| Rollback to v0.6.0 default semantics | Config flag flip: app sets `walkable_v8_writer_enabled = false` and re‑deploys. New writes resume `Link`. Already‑written `LinkV2` data stays readable by any v0.6+ SDK; pre‑v0.6 readers see the typed error on those nodes. |

### Added (#88 — direct W.8.4 validation)

- **`fula_crypto::wnfs_hamt::CountingBlobBackend<B>`** — `BlobBackend` wrapper that atomically counts every `put`, `get`, and `get_with_cid_hint` call (including a discriminator counter for `cid_hint.is_some()`). Gated on `cfg(any(test, feature = "test-fault-injection"))` so it costs nothing in production builds. Cross‑platform (native + wasm32 trait variants). Used by the two new parity tests below to validate the v0.6.0 plan §W.8.4 claim *"v8 adds zero new master RPCs vs v7"* — pre‑#88 the claim was "suggestive but not proven" via throughput equivalence; post‑#88 it is byte‑equality direct evidence.
- **`walkable_v8_rpc_count_parity_writes_match_v7`** (`crates/fula-crypto/src/sharded_hamt_forest.rs`) — runs identical write workload (32 upserts + flush) through `CountingBlobBackend<InMemoryBackend>` (v7 path, `BlobPutResult::none()`) and `CountingBlobBackend<CidCapturingBackend>` (v8 path, `BlobPutResult { cid: Some(_) }`); asserts `puts` and `gets` counts match byte‑for‑byte. A drift in either direction is a load‑bearing W.8.4 regression.
- **`walkable_v8_rpc_count_parity_reader_uses_cid_hints_under_v8_only`** — write 64 entries, reload from manifest, walk via `list_all_files`. Asserts `gets_with_hint` is identical between v7 and v8 (same call sites; only the argument differs) AND `gets_with_some_hint == 0` under v7 (no `LinkV2` → no CID hints flow) AND `gets_with_some_hint > 0` under v8 (the discriminator that proves the v8 wiring is live, not just stamping bytes nobody reads).

### Verified before release

- **fula-client lib tests**: 187/187 passing; integration test `s3_blob_backend_returns_cid::put_with_explicit_writer_disabled_returns_cid_none` exercises the explicit‑false path (renamed from `put_default_off_returns_cid_none_*`).
- **fula-flutter lib tests**: 8/8 passing (the inverted `fula_config_default_phase_2_x_fields_are_off` assertion is the gold‑standard regression guard for this flip).
- **fula-crypto lib tests**: 326/326 passing (324 pre‑existing + 2 new W.8.4 parity tests from #88); no behavior change at this layer (the wire format is unchanged from v0.6.0).
- **wasm32 cross‑platform check**: `cargo check --target wasm32-unknown-unknown` clean for both `-p fula-client` and `-p fula-js`. No new warnings introduced.
- **Test‑semantic audit**: the helpers in `crates/fula-client/tests/offline_e2e.rs::build_client` and `build_client_with_cold_start` now mirror the post‑#89 FxFiles config under default‑on; this is intentional (the helper docstring states "Mirror FxFiles config"). Walkable‑v8 reader tests (`walkable_v8_offline_walk.rs`) explicitly note that the reader path is not gated on the writer flag, so the default flip does not affect their coverage. `blob_backend_retries_transient.rs` exercises raw `BlobBackend::get/put` retry logic, not the cascade — unaffected.

### Limitations (unchanged from v0.6.0)

All v0.6.0 limitations apply unchanged. Specifically, `put_object_chunked` (public unencrypted‑debug API) still doesn't engage v8 offline reads (#51), and resumable/streaming chunk‑CID stamping was closed under #80 in v0.6.0.

## [0.6.0] - 2026-05-09

**Walkable encrypted HAMT release.** Closes the offline-tree-walk gap **for production-encrypted chunked files** (the dominant FxFiles content shape — every photo / video / PDF > 768 KB written via `put_object_encrypted_with_type`). The encrypted HAMT now carries content-addressed CIDs alongside the existing master-S3 storage keys at every layer (HAMT internal nodes, manifest pages, dir-index, file-index, per-chunk), so a key-holder can walk the entire tree via public IPFS gateways without contacting master. Privacy is preserved: keyless observers still see only opaque ciphertexts and learn nothing about tree shape, file count, or graph topology. Default-off in the SDK so old SDKs can keep reading newly-written buckets byte-identically; flip the flag after the v0.6.x adoption window. The public unencrypted-debug `put_object_chunked` path still needs the redesign tracked in #51 (see Limitations).

### Wire format (additive, backward-compatible)

All new fields are `Option<Cid>` / `Vec<Option<Cid>>` with `#[serde(default, skip_serializing_if = ...)]`. Pre-v0.6.0 SDKs reading new buckets see unknown fields and ignore them; new SDKs reading pre-v0.6.0 data see `None` everywhere and fall back to the legacy storage-key path. No migration tooling required. Pre-v0.6.0 SDKs encountering a `PointerWire::LinkV2` blob (only emitted when the writer flag is on AND a v0.6+ SDK wrote that node) surface postcard's "unknown variant" decode error and refuse to read that node rather than corrupting state — the postcard enum-variant tag is the forward-incompatibility boundary. Operators filtering error telemetry should match on the typed `ClientError::WireVersionUnsupported { context, postcard_error }` variant (#81 — landed 2026-05-09). The variant fires from `Node::load_with_cid_hint` whenever postcard's variant-tag-decode hits an unknown variant; the parallel `FulaError::WireVersionUnsupported` is plumbed through fula-flutter's `error_code()` returns `"WIRE_VERSION_UNSUPPORTED"`. Pre-#81 telemetry filters that pattern-matched on the postcard error message string still work; the typed variant is the stable handle going forward.

### Added

#### Wire format extensions (`fula-crypto`)

- **`PointerWire::LinkV2 { storage_key, cid }`** — new HAMT pointer variant carrying both addresses. Postcard tag `2` (legacy `Values` = 0, `Link` = 1). Test pinned: `pointer_wire_link_v2_roundtrip`, `legacy_v7_decoder_errors_on_v8_link_v2_blob`, `mixed_link_and_link_v2_in_one_parent_round_trips`.
- **`ManifestRoot.shards[i].root_cid: Option<Cid>`** — per-shard HAMT-root CID hint, populated by the writer cascade.
- **`ManifestRoot.page_index[*].cid: Option<Cid>` (PageRef field)** — manifest-page CID hint.
- **`ManifestRoot.dir_index_cid: Option<Cid>`** — dir-index blob CID hint (dir_index_etag and dir_index_seq stay; cid is added).
- **`ForestFileEntry.storage_cid: Option<Cid>`** — file-index object CID hint, stamped by the SDK after the encrypted-content PUT returns.
- **`ChunkedFileMetadata.chunk_cids: Vec<Option<Cid>>`** — per-chunk CID hints, parallel to `chunk_nonces`. Empty Vec = legacy. When non-empty, length must equal `num_chunks`. Test pinned: `chunk_cids_round_trip_via_json`, `legacy_chunked_metadata_without_chunk_cids_field_deserializes_to_none`, `chunk_cids_empty_round_trips_via_json` (verifies field is OFF the wire when empty).
- **`BlobBackend::get_with_cid_hint(path, Option<&Cid>)`** — new trait method (default impl delegates to `get`). Lets the offline reader forward the CID it learned from a parent's `LinkV2` plaintext down to the storage layer.
- **`HamtNodeStore::get_node_with_cid_hint(&StorageKey, Option<&Cid>)`** — same shape at the HAMT abstraction.
- **`Node::load_with_cid_hint(key, Option<&Cid>, store)`** — sibling of `load`; the resolve dispatcher used by `ChildPtr::resolve_owned`.

#### SDK API surface (`fula-client`)

- **`Config::walkable_v8_writer_enabled: bool`** (default `false`) — opt-in flag for the writer cascade. When `true`, every PUT through `S3BlobBackend` parses master's response ETag, self-verifies it against `BLAKE3(ciphertext)` recomputed locally, and stamps the verified CID into the appropriate Option<Cid> field. Default-off for the v0.6.x rollout window so old SDKs can keep reading newly-written buckets without seeing `LinkV2` pointers.
- **`walkable_v8` module** (`crates/fula-client/src/walkable_v8.rs`) — new internal module with two helpers:
  - `local_blake3_raw_cid(bytes) -> Cid` — computes the CID master would emit for `bytes` (v1 raw-codec BLAKE3-multihash).
  - `verify_etag_against_expected_cid(etag, expected, bucket, path) -> Option<Cid>` — soft-fails to `None` on mismatch with a rate-limited `tracing::warn!` (deduplicated per `(bucket, path)` per session via a process-wide `DashSet`). The mismatch dedup defends against a chronically-misconfigured proxy flooding production logs.
- **Reader cid-hint dispatch** — `ChildPtr::resolve_owned` for `StoredV2` variant now forwards the CID hint through `Node::load_with_cid_hint` → `HamtNodeStore::get_node_with_cid_hint` → `BlobBackend::get_with_cid_hint`. On `S3BlobBackend` the `Some(cid)` path routes through `FulaClient::get_object_with_offline_fallback_known_cid` (the cold-cache gateway-race entry already shipped in Phase 2.4 / v0.4.0). The reader path is **not gated on the writer flag** — the wire format itself is the gate. Buckets written entirely under v7 produce no `LinkV2` entries, so no `cid_hint` ever reaches the storage layer; lazy migration on next write.
- **Per-chunk reader dispatch** — windowed (`download_chunks_windowed_to_writer`), buffered, and ranged (`get_object_range`) chunked-download paths all check `chunked_meta.chunk_cid(i)` per chunk and route `Some` through the cold-cache cid-hint variant. Without this, even after the W.9.4 HAMT walker reaches the file index, the chunks themselves remained unreachable when master was down — that's the gap #32 closed.
- **Cross-platform parity** — `fula-flutter::FulaConfig::walkable_v8_writer_enabled` and `fula-js::JsConfig::walkable_v8_writer_enabled` plumb the flag through FRB and wasm-bindgen respectively. Both targets compile clean; flipping the flag is a single toggle on every platform fula-client ships against.

#### Master-side pin durability (`fula-cli`)

- **`PinQueue` module** (`crates/fula-cli/src/pin_queue.rs`) — redb-backed durable pin queue. Closes task #23. Records keyed by `(cid_bytes ‖ target_byte)` carry `target` (`MasterCluster` or `UserExternal`), `pin_name`, `bearer_token`, `pinning_endpoint`, `attempts`, `next_due_unix_ms`, `dead`, `enqueued_at_unix_ms`. Operations: `enqueue` (idempotent), `pop_due` (per-row corrupt-blob tolerance — one bad postcard record cannot wedge the drainer), `mark_succeeded`, `mark_failed` (exp backoff 500 ms → 5 min cap with 10 % jitter, max 8 attempts then dead-letter), `purge_corrupt_record` (raw-key delete for unparseable rows), `pending_count`, `dead_count`. Crash-safe: every `enqueue` is a redb commit before returning Ok.
- **`pin_drainer` module** (`crates/fula-cli/src/pin_drainer.rs`) — background worker. `drain_once(queue, dispatcher, config)` does ONE batch via bounded semaphore (default 32 concurrent in-flight pins). `spawn_drainer_loop` runs forever with 1-second idle poll. `LivePinDispatcher` wires `BlockStore::pin_with_token` (master cluster) + `PinningServiceClient::add_pin` (user external).
- **`AppState.pin_queue: Option<Arc<PinQueue>>`** — opens redb at `config.pin_queue_path` (defaults to `/var/lib/fula-gateway/pin_queue.redb`). When `None` (path unset), the PUT and multipart handlers fall back to the legacy fire-and-forget `tokio::spawn`-and-forget pin path so existing tests + minimal dev configs still work. Production deployments MUST set `pin_queue_path`.
- **`server::run_server` spawns the drainer** on startup if `pin_queue.is_some()`. On a clean restart, pending records survive via redb durability; the drainer picks them up on the next tick. Verified by the `crash_recovery_drains_persisted_pins_after_restart` integration test (100 pins enqueued, queue dropped mid-batch, fresh drainer reopens at the same path, every CID eventually pinned).
- **PUT and multipart handler integration** (`crates/fula-cli/src/handlers/object.rs`, `multipart.rs`) — three pin records per encrypted upload: per-object CID (with `v8-node:` / `forest-meta:` / `object:` name prefix per path class for operator `pin ls` triage), bucket-root CID, and user-external CID. Each enqueue has a fire-and-forget fallback when the redb commit itself fails so a user's PUT cannot fail because of a transient queue write error.

#### Configuration knobs

- **`pin_queue_path: Option<String>`** in `GatewayConfig` (default `/var/lib/fula-gateway/pin_queue.redb`).

### Operational rollout (env-flag-gated, instant rollback)

| Phase | Action | Observable change |
|---|---|---|
| **A** | Cut and ship v0.6.0 SDK to apps. **Walkable-v8 writer flag stays OFF in app config.** | None observable. SDK now contains the writer cascade + reader cid-hint dispatch, but the writer flag default-off keeps every PUT byte-identical to v0.5. |
| **B** | Wait 4–8 weeks for v0.6.0 SDK adoption to reach 80%+ of monthly actives. Watch error telemetry for postcard "unknown variant" decode errors from HAMT-node loads — should stay zero (no v0.6 writes are happening yet). | None observable. |
| **C** | Deploy v0.6.0 master with `pin_queue_path` configured. Pin queue starts surviving crashes; existing PUT semantics unchanged. | Operators see the new `pin_queue.redb` file. `dead_count` should stay 0 in healthy clusters. |
| **D** | Operator flips app-side `walkable_v8_writer_enabled = true` for v0.6+ users (or default it to true in a v0.6.1 SDK push). New writes start emitting `PointerWire::LinkV2` and stamping CID hints. **Reader-side walkable-v8 lights up automatically when reading these new buckets.** | New buckets opened by v0.6+ readers walk via public gateways when master is down. No change for v0.5 readers reading new buckets — they error cleanly with `WireVersionUnsupported` for the LinkV2 portions of the tree, but read v7 portions normally. |
| **E** | Monitor 1–2 week soak. Watch error telemetry for postcard "unknown variant" decode errors from v0.5 SDKs hitting v0.6-written buckets — expected to be zero by step B's 80% threshold but track to confirm. | Telemetry stable. |
| **Rollback at any step** | Flip `walkable_v8_writer_enabled = false` and ship a config push. New writes resume v7 wire format. Already-written v0.6 data stays v0.6 — but readable by any v0.6+ SDK, so no permanent damage. Users on v0.5 SDK who hit a v0.6-written bucket get a postcard "unknown variant" decode error from the HAMT-node load path and can be guided to update. | New writes stop emitting LinkV2 immediately. Existing v0.6-written nodes stay readable by v0.6+ SDKs. |

### Compatibility matrix

| SDK version | Master version | Writer flag | Reader behavior |
|---|---|---|---|
| pre-v0.6 | pre-v0.6 | n/a | Legacy v7 — works as today. No walkable-v8 anywhere. |
| pre-v0.6 | v0.6 | n/a | Legacy v7 — pin queue is transparent to old SDKs; reads/writes unchanged. |
| v0.6 | pre-v0.6 | OFF | v0.5-byte-identical. Pre-v0.6 master sees no new headers / behavior. |
| v0.6 | v0.6 | OFF | v0.5-byte-identical for writes. Reader cid-hint dispatch is dormant (no LinkV2 entries exist yet). |
| **v0.6** | **v0.6** | **ON** | **Full walkable-v8.** Writer stamps all CID layers; reader walks via gateway race when master is unreachable. ✅ |
| pre-v0.6 reading a v0.6-written bucket (writer flag had been ON) | any | n/a | Reads v7 portions of the tree normally; surfaces a postcard "unknown variant" decode error from the HAMT-node load path for any LinkV2 it encounters (no data corruption). Online reads via master continue working byte-identically. |
| v0.6 reading a pre-v0.6 bucket | any | n/a | Reads as legacy v7 (no LinkV2 anywhere). Lazy migration: as soon as the user writes anything that triggers a flush, that subtree's nodes upgrade to LinkV2 on the next persist. |

### Limitations (operator-facing — must-read before flipping the writer flag)

- **~~Single-directory cliff at ~60-100k files (#72)~~ — RESOLVED 2026-05-09.** See "Fixed" section below; the cliff no longer applies. New users with 100k+ files in a single folder can flip the writer flag without restriction.
- **Public `put_object_chunked` debug API doesn't stamp `storage_cid` (#51 still pending).** This API writes a literal `b"CHUNKED"` marker as the index-object body and carries the encryption metadata in the HTTP `x-fula-encryption` user-metadata header. Stamping the CID would produce a useless cross-file-collision CID (every file's body is the same 7-byte marker), so #32 explicitly skipped this path. **FxFiles users on the production encrypted chunked path (`put_object_encrypted_with_type` → `put_object_chunked_internal`) DO get full per-chunk walkability via #32** — the gap is limited to the public unencrypted-debug `put_object_chunked` API, which is rarely used in production. Track the redesign in #51.
- **chunk_cids privacy posture: plaintext, by design.** Per-chunk CID hints (`ChunkedFileMetadata.chunk_cids`) are serialized into the index object's `chunked` JSON field alongside `chunk_nonces`, `root_hash`, `num_chunks`, `total_size`, `chunk_size`. Only the `wrapped_key` and `private_metadata` siblings are AEAD-encrypted; the `chunked` block is **plaintext-readable** by anyone who can fetch the index object. **This is not a privacy regression**: every existing field in the same plaintext block was already plaintext-readable at the same level pre-v0.6.0. An attacker with the index body could already enumerate child storage paths via `chunk_key(storage_key, i)` and fetch the same encrypted chunk bytes via gateway. The hints simply make legitimate offline reads cheaper for the same content already addressable. Future security audits reviewing the threat model should treat `chunk_cids` as joining an existing public set, not introducing a new leak.
- **Resumable + streaming upload paths don't stamp per-chunk CIDs (#80).** `put_object_encrypted_resumable` and `put_object_encrypted_streaming` write chunks but never call `populate_chunk_cids` on the metadata. Files uploaded via these paths fall back to the warm-cache offline path (still works, just doesn't engage cold-cache gateway race for fresh devices). Lower priority than the main path because resumable + streaming are less commonly used. Tracked as #80.
- **No retry budget for permanently-dead pins.** When a pin record graduates to the dead-letter state after 8 attempts, it stays in the queue for operator audit (visible via `dead_count()`) but never auto-retries. Operators need to inspect dead records and clear them manually. A future internal endpoint to surface the dead-letter list is tracked as part of #67.
- **`put_object_chunked_internal` index PUT body uses `walkable_v8` flag at TWO read sites within the same function.** Cosmetic (the field is `Copy`-shadowable and reads consistent values within a single call), but a future refactor that introduces flag mutability mid-call would need to consolidate the two reads. Not a current correctness issue.

### Fixed

- **`walkable_v8_manifest_block_size` integration test now exercises full v7 cascade (#75).** Pre-#75 the test called `put_object_encrypted` (which doesn't touch the forest) and reported only 1000 file-blob PUTs — the v7 manifest-page / dir-index / Phase 2 root commits the test was filed to validate never fired. Post-#75 the test calls `put_object_flat_deferred` (forest-aware), which on a 404-GET catch-all bootstraps a fresh v7 `ShardedHamtPrivateForest` per `encryption.rs:2847-2867`, and `flush_forest` then drives Phase 1.5/1.6/2 commits via `save_sharded_hamt_forest` (`encryption.rs:3723+`). Empirical: 1152 PUTs total (1000 file blobs + ~152 forest blobs); largest blob a HAMT internal-node at ~26.8 KiB — well under the 1 MiB W.8.3 hard ceiling. New positive assertion `hamt_node_max > 0` catches future regressions where the call site changes back to a forest-bypassing path. **Note**: original task scope was "pre-load wiremock with a fake-but-decryptable v7 manifest" (~200 LOC); empirical investigation showed the SDK already bootstraps fresh-v7 on 404, so the actual fix was a one-line call-site change. Test-only / dev-tooling change.
- **Plan W.8.2 wire-format-overhead claim updated with empirical data (#74).** The original plan predicted "5-20% relative growth" for v8's LinkV2 pointer overhead vs v7's Link. The walkable_v8_scale bench's new v7-vs-v8 baseline comparator (added #74) measured **2.2-4.6% growth across N=1k/10k/50k × 16/256-shard configurations** — meaningfully BELOW the lower bound of the prediction. The original prediction for "~32 internal nodes at 1k entries on 16-shard" was empirically **~135** (HAMT_VALUES_BUCKET_SIZE=3 makes the cascade deeper than the prediction assumed). Plan W.8.4's "no extra round trips" claim is consistent with v7-vs-v8 throughput within measurement noise (~5% at N=10k) — suggestive but not proven; tracked separately as #88 for direct round-trip-count instrumentation. **Operational implication**: v8 wire-format overhead is meaningfully cheaper than the original plan suggested; storage-cost projections based on the W.8.2 prediction can be revised down. Bench-only / dev-tooling change; no SDK or production code change.
- **Typed `WireVersionUnsupported` error variant for telemetry stability (#81).** Pre-#81, postcard "unknown variant" decode errors (the v0.6 walkable-v8 forward-incompatibility surface — old SDKs reading new `PointerWire::LinkV2` blobs) surfaced as the generic `CryptoError::Serialization("decode hamt node: ...")` wrapped in `ClientError::Encryption(...)`. Telemetry filters had to substring-match the brittle postcard error message. Now the typed `ClientError::WireVersionUnsupported { context, postcard_error }` variant fires for unknown-variant decode failures specifically, with parallel `FulaError::WireVersionUnsupported` exposed through fula-flutter (Dart-side `error_code() == "WIRE_VERSION_UNSUPPORTED"`). Cross-platform: native + wasm32 verified clean. Implementation classifies postcard errors at the boundary — `DeserializeBadEnum` and `SerdeDeCustom` (postcard 1.x's surface for unknown enum tags) map to the typed variant; other postcard errors stay generic. Master-side and SDK-side change.
- **User-external unpins now durable (#66).** DELETE-handler's `unpin_for_user` was fire-and-forget — failed unpins silently leaked pin slots on the user's external pinning service (e.g., quota slowly fills until manual cleanup). Migrated to the durable pin queue with new `PinKind { Add, Remove }` semantics. The "latest intent wins" idempotency rule (`(cid, target)` collapses pin+unpin into one record per key, conflicting kind overwrites) handles the upload→delete→re-upload race by construction: even if drainer order isn't preserved, the most recent user intent wins. Dispatch maps 404 ("pin already removed") to success. Master-local unpin (`object.rs:955`) stays sync best-effort per #66's minimal-scope advisor brief — failure mode is "kubo briefly down" and the next user write re-aligns state via the bucket-root pin queue. **Operator-impacting**: bumps the pin queue's redb table from `pin_queue_v1` to `pin_queue_v2` on first open; pre-#66 in-flight pin records are dropped (records lacked the new `kind` field). Lazy re-enqueue happens as users touch affected objects. **If `pending_count > 1000`** at upgrade time (e.g., kubo was down for an extended period and the queue backed up), let the drainer flush before deploying — dropped records that were ALREADY failing won't auto-re-enqueue; only freshly-touched CIDs will. Cluster GC eventually reaps any genuinely orphaned blobs regardless. No data loss (master S3 + cluster still hold the blobs). Master-side change only; no SDK / fula-flutter / fula-js / wasm impact.
- **PII-sweep bucket-root pins now survive operator cancel/restart of a slow sweep (#65).** Previously the fire-and-forget `tokio::spawn`'d pin in `admin.rs` lost in-flight pins whenever the operator killed `curl` mid-sweep (the symptom most operators have hit: re-running `admin-pii-sweep.sh` to drain remaining buckets silently lost pins for the buckets the prior run rewrote). With the durable pin queue (W.9.6), enqueued pin records persist in redb; the drainer resumes them after process restart or curl disconnect. End-to-end-equivalent under steady-state (`bearer_token: None` → empty-string short-circuit → `pin_cid()`), strictly better under cancel/restart. Master-side change only; no SDK or cross-platform impact.
- **Single-directory 1 MiB cliff resolved (#72).** Previously a directory containing ~60-100k+ files in flat layout produced a `ForestDirectoryEntry` blob exceeding the 1 MiB IPFS gateway limit (verified 1.66 MiB at 100k entries via the W.9.7 stress test); offline walks failed for affected buckets. Root cause: `ForestDirectoryEntry.files: Vec<String>` accumulated one filename per `upsert_file`, growing linearly. Fix: stop populating `dir.files` on v7 writes; the `ShardedHamtPrivateForest::list_directory` and `list_subtree` methods now walk the HAMT for `F:` entries directly (using dir-local routing — single shard for `list_directory`). `dir.files` remains in the wire format for backward-read compat with legacy buckets; on new buckets it stays empty regardless of file count. Verified end-to-end: 100k files in `/single-dir/` now produces a tiny Dir blob and a max-blob size well under 1 MiB. **Behavior change for direct fula-crypto consumers**: `forest.list_subtree(prefix)` cost is now O(N total entries) instead of O(K under prefix) — acceptable per advisor, the method was not on any hot path. The fula-client SDK API surface (`EncryptedClient::list_directory`, `list_files`) is unaffected: those already used the HAMT-walk path.
- **Resumable + streaming uploads now appear in the encrypted forest (#82).** Previously `put_object_encrypted_resumable`, `put_object_encrypted_streaming`, and `resume_upload` PUT chunks + index to S3 + IPFS but never called `forest_cache.upsert_file` — the file landed durably on master but was invisible to offline forest walks (Phase 2.4 / cold-start). All three paths now register a `ForestFileEntry` after the index PUT succeeds, mirroring the upsert dance in `put_object_encrypted_with_type`. **Behavior change for callers**: these three functions now call `ensure_forest_loaded(bucket)` upfront, so a master-down state surfaces as `Err` BEFORE any chunk is uploaded — replacing the prior silent-success-with-invisible-file mode. Apps that depended on chunks-uploading-while-master-is-down will see honest failures; that's the desired end state. Crash-safety: the resumable manifest file on disk is now deleted only AFTER both the index PUT and forest registration succeed (previously deleted right after the index PUT — a register failure would lose the resumable artifact).

### Threat-model preservation (changes vs. v0.5)

The walkable-v8 wire format does not weaken any existing privacy or integrity property:

- **Three-layer integrity for every offline-fetched node** — gateway content-address verify (`verify_cid_against_bytes` on every gateway response, byte-identical to native IPLD's property), AEAD decrypt with `(bucket, shard_idx)` AAD, plaintext-vs-claimed-storage-key recompute. The third layer specifically defends against a malicious parent claiming `LinkV2 { storage_key: A, cid: hash_of_real_node_B }` — under such a parent the gateway returns valid bytes for cid_B, AEAD passes (legitimate ciphertext under shared bucket DEK), but the recompute layer rejects because plaintext_B addresses B, not the requested A.
- **Self-verify at write time** — the SDK rehashes its own ciphertext locally before stamping the master-attested CID. Mismatches soft-fail to `None`, so a compromised master cannot redirect future offline walkers to attacker-controlled IPFS bytes.
- **Writer flag default-off keeps the option in operator hands** — until the flag flips on, no `LinkV2` ever lands on disk, and the bucket's wire format is byte-identical to v0.5. Rolling back is a config flip, not a data migration.
- **Privacy strictly improves vs. stock WNFS** at the tree-structure level — keyless observers cannot enumerate the HAMT shape, count entries, see leaf CIDs, or diff snapshots, because all of that information lives behind AEAD.

For full architectural detail see `docs/wnfs-comparison.md` §9 and `docs/website/security.html#walkable-hamt`.

### Verified before release

- **~670 unit + integration tests passing** across fula-crypto (~320 in-module incl. 4 chunk_cids round-trip + 5 walkable-v8 reader + 4 W.9.7 block-size), fula-client (187 lib + 26 integration spread across 7 test files), fula-flutter (8), fula-cli (129 incl. 9 pin-queue + 7 pin-drainer + 1 BLOCKER-3 corrupt-blob regression).
- **9 `#[ignore]`-gated stress tests** (1k regular, 100k/1M operator-run release-mode) — 100k re-run completed in 19.49s release-mode, max blob 17.1 KiB, well under both ceilings.
- **Cross-platform clean compile**: native (fula-crypto + fula-client + fula-flutter + fula-cli) and wasm32 (fula-client + fula-js).
- **Two parallel independent reviewers per W.9.x subtask** per the dual-advisor memory rule (W.9.3, W.9.4, W.9.6, W.9.7, W.9.4-A2 / #32). Every BLOCKER and IMPORTANT finding addressed before declaring the subtask done.

## [0.4.4] - 2026-05-07

**Hotfix release.** Fixes a fundamental cold-start bug: the publisher was emitting MASTER's bucket Prolly Tree CID (CBOR) as the `manifest` field, but the SDK's cold-start needs the SDK's encrypted forest manifest CID (JSON envelope). Result: cold-start (offline reads on a fresh device or when master is unreachable) failed for ALL users with `serde_json` "expected value at line 1 column 1" — CBOR bytes fed into a JSON parser. Cold-start has actually never worked end-to-end against real published data; the bug only manifested once production users tested offline reads.

### Fixed

- **`bucketsIndex` CBOR's `BucketEntry` now exposes BOTH master's Prolly Tree CID (legacy `manifest` field, kept for forward compatibility) AND the SDK's encrypted forest manifest CID (new `forest_manifest_cid` field).** Cold-start prefers the new field; falls back to the legacy field when the new field is absent (defensive: also treats `Some("")` as absent). Old SDKs reading the new CBOR see an unknown field and ignore it (`#[serde(default, skip_serializing_if = "Option::is_none")]`); old buckets without `forest_manifest_cid` populated continue to fail cold-start (no regression vs. v0.4.3-and-prior). New SDKs reading old CBORs fall back to `manifest` (no regression).

### Added

- **`BucketMetadata.forest_manifest_cid: Option<String>`** — master tracks the latest encrypted forest manifest CID per bucket. Distinct from `root_cid` (master's S3-listing index, used internally by master and pinned for IPFS availability). `#[serde(default)]` ensures pre-v0.4.4 registry CBORs deserialize without migration. Fully populated and unit-tested via `test_forest_manifest_cid_round_trip_with_lookup_h_set` in `crates/fula-core/src/metadata.rs`.
- **`BucketManager::populate_forest_manifest_cid(user_id, bucket_name, cid)`** at `crates/fula-core/src/bucket.rs` — REPLACE-LATEST semantics, structurally identical to `populate_bucket_lookup_h`. Idempotent on identical CID input (no extra registry-persist churn). Sets the dirty flag only when the value actually changes.
- **Master sentinel header** `x-amz-meta-fula-forest-manifest: 1` on the SDK's Phase 2 manifest root commit (encryption.rs save_sharded_hamt_forest, save_forest, v1→v7 migration). Master sees the sentinel, takes its own server-computed CID for that PUT (the etag), and stores it on `BucketMetadata.forest_manifest_cid`. SDK does NOT need to recompute and send the CID — server is the source of truth for content-addressing.
- **Master env flag** `FULA_FOREST_MANIFEST_CID_ENABLED=0|1` (default 0) gating header consumption — enables independent rollout of master vs SDK.
- **`BucketEntry.cold_start_cid()` accessor** in `crates/fula-client/src/registry_resolver.rs` — encapsulates the prefer-new-field-fall-back-to-legacy logic in one place. Empty-string defensive parsing.
- **`fula-forest-manifest`** added to `FULA_CONTROL_HEADERS` (`crates/fula-cli/src/handlers/object.rs`) so the sentinel is consumed by handler logic and never persisted as object metadata.

### Operational rollout (env-flag-gated, instant rollback)

| Phase | Action | Observable change |
|---|---|---|
| **A** | Ship v0.4.4 SDK to apps. SDK starts sending `x-amz-meta-fula-forest-manifest: 1` on Phase 2 root PUTs. Pre-v0.4.4 master ignores the header (it's just an `x-amz-meta-*`). | None observable. |
| **B** | Deploy v0.4.4 master with `FULA_FOREST_MANIFEST_CID_ENABLED=0` (default). | None observable. |
| **C** | Operator flips `FULA_FOREST_MANIFEST_CID_ENABLED=1`, restarts gateway. | Master starts populating `BucketMetadata.forest_manifest_cid` on every Phase 2 commit from a v0.4.4+ SDK. Look for log line `"Populated forest_manifest_cid (v0.4.4)"`. Next publisher tick emits the new CID in the per-user CBOR. Cold-start works. |
| **Rollback** | Set flag to 0, restart. | Next publisher tick re-emits without `forest_manifest_cid`. SDK falls back to `manifest` (broken cold-start, no regression vs. pre-v0.4.4). |

### Compatibility matrix

| SDK | Master | Master flag | Cold-start works? |
|---|---|---|---|
| pre-v0.4.4 | pre-v0.4.4 | n/a | No (the original bug). |
| pre-v0.4.4 | v0.4.4 | OFF | No (no behavior change). |
| pre-v0.4.4 | v0.4.4 | ON | No (pre-v0.4.4 SDK doesn't send sentinel; `forest_manifest_cid` stays `None`; SDK falls back to broken `manifest`). |
| v0.4.4 | pre-v0.4.4 | n/a | No (master ignores sentinel; field never populated). Fall back to broken `manifest`. |
| v0.4.4 | v0.4.4 | OFF | No (master discards sentinel due to env flag). |
| **v0.4.4** | **v0.4.4** | **ON** | **Yes** ✅ — first regression-free cold-start in fula history. |

### Why the legacy `manifest` field is kept (per operator request)

Master never reads its own published CBOR back for recovery (verified by audit — master uses on-disk `registry_cid_path` only). The legacy `manifest` field thus has exactly one consumer today (the SDK cold-start, which currently fails on it). However, the operator requested keeping it for forward compatibility: if any future tooling wants to walk master's Prolly Tree from the published CBOR (e.g., for disaster-recovery diagnostics, third-party indexing, or audit), the root_cid is still there. The cost is one extra string per bucket per user (~46 bytes); the benefit is zero data corruption risk on rollback.

### Limitations

- **Cold-start works only for users who have done at least ONE Phase 2 root commit AFTER master was upgraded to v0.4.4 with the flag on.** Users who have only pre-v0.4.4 data (legacy bucket forests with no fresh root commit) need to re-PUT or re-flush to populate `forest_manifest_cid`. Same lazy-migration property as Phase 1.2's `bucket_lookup_h`.
- **Empty-bucket users still can't cold-start** — without a Phase 2 commit, there's nothing to populate. Cold-start fails cleanly with a `UsersIndexResolutionFailed` error referring to the bucket name.

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
