# Web Streaming + Resumable Large-File Upload — Plan

Status: **PLAN (not started)** · Owner: SDK (`fula-api`) + FxFiles web · Created 2026-06-18
Delivery: **one `fula-api` PR delivered in phases P1–P5** (streaming AND resume together),
then a separate FxFiles consumer PR (P6, needs the published SDK).
Build on branch `feat/wasm-resumable-upload` (groundwork commit `468543e` already lifts
`UploadManifest`/`ManifestChunk` onto wasm + un-gates `decrypt_resumable_private_meta`).

---

## 0. Problem & goal

Large files OOM low-RAM web tabs. Root cause: the wasm upload path materializes the
**entire ciphertext** before the first PUT (`fula-client/src/encryption.rs:7325`,
`put_object_chunked_internal` → `encoder.update(data)` → `all_chunks` Vec → `buffer_unordered`).
Peak memory ≈ 2× file size. The interim "surface the failure" UX shipped (FxFiles v1.11.4.6,
PR #59); **this plan removes the cap** so multi-hundred-MB / GB files upload from a 1–2 GB phone.

Goal: stream the file through the encrypt+PUT loop so **peak memory is independent of file
size**, AND make the upload **resumable** after interruption — under hard guarantees:

| Requirement (user) | Where addressed |
|---|---|
| 1. No silent corruption / chunk mixup | §4 INV-4, §3 AAD binding, download-side `bao_root`+`content_hash` verify; tests §8 |
| 2. Properly unit + e2e tested | §8 (round-trip, interrupt→resume, mixup-detector, nonce-reuse guard, e2e) |
| 3. Smooth error handling, no corruption on interruption | §2 two-pass atomicity, §6 error matrix, per-chunk idempotent retry |
| 4. Resume + security + no unattended ghost nodes | §2 resume, §4 INV-1/2/3/6/7, §5 orphan lifecycle |

---

## 1. Verified facts (the design rests on these — re-confirm if the SDK changes)

- **BAO root + `content_hash` are computed over PLAINTEXT**, not ciphertext
  (`fula-crypto/src/chunked.rs:313-317`: `bao_encoder.update(data)` + `content_hasher.update(data)`
  where `data` is the plaintext). ⇒ **Pass 1 needs no encryption.**
- `ChunkedEncoder::content_hash_hex()` = `blake3(plaintext)` (`chunked.rs:325`). ⇒ cheap resume-verify.
- Per-chunk nonce is **random** (`Nonce::generate()`, `chunked.rs:366`). ⇒ must persist; reuse only after content-verify.
- AAD = `"fula:v4:chunk:{storage_key}:{index}"` (`chunked.rs:371`). ⇒ cryptographic anti-mixup binding.
- Chunks are **pinned per-chunk on PUT** (`encryption.rs:7411`, `put_object_with_metadata_and_pinning`).
  ⇒ abandoned uploads leave *pinned* orphans → active cleanup required (§5).
- Per-chunk PUT **retry already exists** (`encryption.rs:7403`, `retry_idempotent(4, …)`, FxFiles #50). ⇒ reuse in pass 2.
- Post-PUT **CID verify exists** (`encryption.rs:7447`, walkable_v8 `verify_etag_against_expected_cid`). ⇒ wire into the "uploaded" flag.
- Native already has **file-based resumable** (`UploadManifest`, stored-nonce reuse, BAO root check, WAL),
  all `#[cfg(not(wasm32))]`. wasm mirrors it **minus filesystem + WAL**.
- **Gateway auto-GC is OFF** (one-off manual GC only — see memory `project_fula_v7_migration_gone_fix`).
  This is a *load-bearing assumption* for §5; the orphan design must not silently depend on it (and doesn't — it cleans actively).

**Security design validated by independent adversarial review (Codex / GPT-5.5):** the nonce-reuse
argument is sound *iff* §4's invariants are enforced; the dangerous edge is reuse ordering on resume (INV-1).

---

## 2. Architecture — two-pass, where the upload pass *is* the resume path

A page reload loses the browser `Blob` reference (browsers won't persist file handles; iOS Safari
has no File System Access API). So **in-session** resume (network blip, no reload) is seamless;
**cross-reload** resume requires the user to re-select the same file, gated by INV-1.

```
ChunkSource (Dart Blob.slice → bytes, pulled lazily by Rust)   ── §10 de-risk first (P1)
        │
   PASS 1 — plan/commit  (hash-only, NO encryption; ~1 chunk in memory)
        │  chunk plaintext → generate nonce/chunk → feed BAO + content_hash
        │  finalize → root_hash + content_hash + nonces[]
        │  ⇒ commit immutable manifest (§3). Interrupted? nothing uploaded → RESTART pass 1.
        ▼
   PASS 2 — upload  (re-encrypt with STORED nonce; ~concurrency×chunk in memory)
        │  for each not-yet-uploaded chunk i: AES-GCM(dek, nonce_i, plaintext_i, AAD=.../i)
        │  deterministic ⇒ identical ciphertext ⇒ idempotent content-addressed PUT (retry per chunk)
        │  post-PUT CID verify → mark uploaded[i]; poll ManifestHandle → Dart persists to IndexedDB
        │  Interrupted? manifest has uploaded[] → RESUME pass 2 (reuse stored nonces, INV-1).
        ▼
   FINALIZE — write index/metadata (header_safe, 0.6.13) + forest entry. COMMIT POINT.
```

**Fresh upload = pass 1 + pass 2-from-0. Resume = reuse manifest + pass 2-from-K.**
Resume never re-runs BAO mid-stream → no fragile blake3-state serialization.
Pass 2's re-encrypt-from-stored-nonce is *exactly* the existing native resume logic, applied to a Blob source.

**Why two-pass (not single-pass):** because BAO is over plaintext, pass 1 is nearly free, so two-pass
buys a clean separation of *sequential* BAO/commit from *concurrent, idempotent* upload — far easier to
prove correct than entangling a sequential BAO advance with out-of-order concurrent PUTs. (Single-pass
was considered and rejected on this basis, not on a false "avoids blake3 serialization" claim.)

**Concurrency:** 2–4 in-flight chunks on low-end (`WebDeviceClass.lowEnd`), up to 16 on desktop.

---

## 3. The manifest (split: immutable commitment + mutable progress)

Persisted to **IndexedDB by Dart** (the SDK exposes the bytes via a pollable `ManifestHandle`, mirroring
`ProgressHandle`/`CancelHandle` — see memory `reference_fula_frb_polling_not_streamsink`). **No raw DEK is ever persisted** — only `wrapped_dek`.

**Immutable commitment block** (frozen the instant pass 1 finalizes; the *only* thing that gates nonce reuse):
`algorithm_version`, `storage_key`, `bucket`, `total_size`, `chunk_size`, `num_chunks`
(`== ceil(total_size/chunk_size)`), `nonces[]` (len `== num_chunks`, base64), `bao_root`,
`content_hash`, `wrapped_dek`, `kek_version`, `upload_id`, `created_at`.

**Mutable progress block:** `uploaded[]` (per-chunk flag = "PUT succeeded AND post-PUT CID verified"),
optional `chunk_cids[]` (offline-walk hints, recomputed in pass 2).

---

## 4. Security & integrity invariants (HARD — each maps to a test in §8)

- **INV-1 (nonce-reuse gate — the catastrophic one).** No stored nonce may encrypt until the byte
  stream is *proven identical* to the manifest. **Cross-reload: fully recompute `content_hash` +
  `total_size` + `num_chunks` and match the manifest BEFORE any AES-GCM call.** Never interleave
  hashing with encrypting. (In-session reuse is safe because the `Blob` is the same immutable source.)
- **INV-2 (atomic commit).** Pass 1 publishes the commitment block only after *all* its fields are
  finalized from one stream; reject if `nonces.length != num_chunks` or `num_chunks != ceil(total_size/chunk_size)`.
- **INV-3 (per-chunk precondition).** Before encrypting chunk `i`: `0 ≤ i < num_chunks`; `nonce[i]`
  present and 96-bit; AAD uses `manifest.storage_key` and exact `i`; slice offset `== i*chunk_size`;
  slice length `== min(chunk_size, total_size - offset)`. Reject extra/short/zero-length reads.
- **INV-4 (anti-mixup).** AAD binds ciphertext to `(storage_key, index)`; each chunk has its own S3 key;
  progress is indexed by `chunk_index` (not completion order). Download verifies `bao_root` + `content_hash`
  ⇒ any scramble/truncation **fails loudly, never silently wrong**.
- **INV-5 (empty / tiny files).** Define explicitly: `num_chunks = 0`, no nonces, no AES-GCM chunks; single-chunk and partial-final-chunk paths covered by tests.
- **INV-6 (concurrent writer).** A **per-`storage_key` lock** (Web Locks API `navigator.locks`, with an
  IndexedDB lease + TTL fallback for older browsers) prevents two tabs writing the same chunk keys with
  *different* DEKs (→ mixed object). Residual mixed state is **caught by download verify** (not silent, not
  a key leak). *Alternative considered (Codex):* `upload_id`-scoped temporary chunk keys + atomic promote at
  finalize — more robust but changes the chunk-key scheme (touches reads + native); **deferred** unless cross-tab proves real.
- **INV-7 (manifest integrity).** Pass 2 revalidates the manifest's internal consistency before use and
  unwraps only the expected `wrapped_dek`/`kek_version`. *Optional defense-in-depth:* MAC the manifest under
  a KEK-derived key to detect IndexedDB tampering/rollback (can't recover the DEK regardless, since it's wrapped).
- **INV-8 (stable DEK across resume).** Reuse `wrapped_dek` from the manifest, re-unwrap via the user's KEK; never mint a new DEK on resume.

---

## 5. Orphan / ghost-node lifecycle (requirement 4)

Decision: **keep per-chunk pinning** (so chunks survive mid-upload regardless of the gateway's GC config —
no dependence on auto-GC being off) **+ active cleanup**, so every uploaded chunk ends in exactly one of:

- **(a) referenced** by a finalized file (finalize writes index/forest; pinned chunks are reachable), or
- **(b) deleted on cancel** — the existing cancel compensating-delete (unpin + delete uploaded chunks) + drop manifest, or
- **(c) deleted by the startup sweep** — on app start, scan IndexedDB manifests; any `created_at` older than
  TTL (e.g. 24–48 h) and not completed → unpin + delete its uploaded chunk keys (identifiable via `upload_id`), then drop the manifest.

⇒ **no unattended ghost nodes**, and no reliance on server GC.

---

## 6. Error-handling matrix (requirement 3)

| Event | Behavior |
|---|---|
| Transient chunk PUT fail (`ERR_CONNECTION_CLOSED`/5xx) | per-chunk `retry_idempotent` (exists, `encryption.rs:7403`). **Never restart the whole upload** (the original bug). |
| Index/metadata PUT fail (large header) | `header_safe` strip + retry (0.6.13, exists). |
| Network drop mid-upload (in-session, Blob retained) | pause; resume pass 2 on reconnect. |
| Tab close / reload | manifest in IndexedDB; cross-reload resume = re-pick + INV-1 verify + pass 2. |
| Pass 1 fail | restart pass 1 (nothing committed or uploaded). |
| Finalize fail | retry finalize (idempotent; chunks already present + pinned). |
| Post-PUT CID verify mismatch | do **not** mark uploaded; re-PUT that chunk. |
| User cancel | compensating-delete + drop manifest (§5b). |
| Different file on resume (INV-1 mismatch) | refuse; discard manifest; fresh upload with new nonces. |

---

## 7. Phasing — one `fula-api` PR; each phase compiles native + wasm and has a test gate

- **P1 — ChunkSource + FRB pull-callback (de-risk the boundary first).**
  Rust `ChunkSource` trait (`async fn chunk(index,offset,len) -> Bytes`); FRB binding so Dart passes a
  `Blob.slice → arrayBuffer → bytes` callback. **Gate:** Rust pulls N slices via the Dart callback and
  reassembles `== original`, on wasm. *If the async Rust→Dart callback proves brittle on wasm, fall back to
  the PUSH model* (Dart feeds chunks into a stateful handle) — this phase picks the one that works.
  Files: `fula-flutter/src/api/forest.rs`, new `chunk_source` module, `fula-client` trait.

- **P2 — Plan-mode encoder + streaming fresh upload (the OOM fix; no resume yet).**
  `fula-crypto`: add a `ChunkedEncoder` **plan mode** (generate nonce + feed BAO + `content_hash`, **skip AEAD**)
  sharing the chunking/nonce/BAO code with the real path. `fula-client`: `put_object_flat_streaming_wasm`
  (pass 1 + pass 2 + finalize) using `ChunkSource`, bounded concurrency, cancel, `header_safe`.
  **Gates:** (a) plan-mode parity — `root_hash`/`content_hash`/`num_chunks` identical to the full encoder for
  the same input; (b) round-trip byte-exact for a multi-chunk file; (c) parity vs the whole-buffer path.
  **Milestone: large uploads work, memory-bounded.**

- **P3 — Manifest + resume.**
  `UploadManifest` commitment/progress split (extends `468543e`); `ManifestHandle` (pollable); resume entrypoint
  enforcing **INV-1** (content-verify before nonce reuse). **Gates:** interrupt@K → resume → byte-exact;
  nonce-reuse guard (changed file → refuse); empty / single-chunk / partial-final (INV-5).

- **P4 — Orphan lifecycle + error hardening + concurrent-writer lock.**
  Cancel compensating-delete; startup sweep (§5c); per-`storage_key` lock (INV-6); wire post-PUT CID verify
  into the `uploaded[]` flag. **Gates:** cancel deletes chunks; abandoned sweep deletes orphans; concurrent
  same-key writer rejected; torn-manifest rejected (INV-2).

- **P5 — FRB surface + version + full suite + review → publish.**
  Wire `put_flat_streaming` + resume + `ManifestHandle` into FRB; bump workspace version (**0.7.0** — significant
  feature); `cargo check` native + wasm + flutter; full test suite; final adversarial review of the resume +
  concurrent-writer code (codex). User publishes to pub.dev + the wasm release asset.

- **P6 — FxFiles consumer PR (separate repo, post-publish).**
  Re-pin `fula_client`; `tools/sync-wasm-pkg.ps1` for `web/pkg`; `WebUploadManager`: Blob `ChunkSource`,
  manifest → IndexedDB, resume on failure/reload, Sync Queue resumable rows, device-class concurrency; version
  bump; deploy. **Web e2e gate** (real browser, low-RAM device-class override): 200 MB+ upload (no OOM),
  interrupt → resume → exact, cancel cleans up.

---

## 8. Test plan (requirements 1, 2, 3)

- **fula-crypto unit:** plan-mode parity (root/content_hash/nonce-count); empty/single/partial-final chunking; AAD binding.
- **fula-client unit:** round-trip byte-exact; interrupt→resume byte-exact; **nonce-reuse guard** (changed
  content → refuse, INV-1); **mixup-detector** (deliberately swap a chunk → download fails, INV-4);
  concurrent-writer rejected (INV-6); cancel → chunks deleted; abandoned sweep → orphans deleted;
  **manifest atomicity** (torn/short manifest rejected, INV-2/3).
- **fula-client e2e** (real server, gated like existing `*_e2e.rs`): large multi-chunk upload → download exact;
  mid-flight interrupt → resume → exact; cross-reload (simulated: drop in-memory state, reload manifest, re-feed source).
- **FxFiles web e2e (P6):** real browser on a low-RAM profile; 200 MB+ no-OOM; interrupt→resume; cancel cleanup.

---

## 9. Memory budget

- Pass 1: 1 chunk buffer + BAO/blake3 hashers (negligible).
- Pass 2: `concurrency × (plaintext slice + ciphertext)` ≈ `2 × C × chunk_size`. C=3, chunk=4 MB ⇒ **~24 MB,
  independent of file size** (vs current ~2× file size). 2 GB on a 1 GB phone becomes feasible.

---

## 10. Open verification items (resolve at P1/P2 start)

1. **FRB async Rust→Dart callback on wasm** — confirm it works (P1 *is* this de-risk); fallback = push model.
2. **Plan-mode parity** — prove `root_hash` identical before relying on pass-1/pass-2 determinism.
3. **`chunk_size` is fixed & manifest-bound across SDK versions** — INV-2/INV-3 determinism depends on it
   (add `algorithm_version` to the manifest and refuse resume across incompatible versions).

---

## 11. Non-goals / deferred

- File System Access API persistent handles (cross-reload resume without re-pick) — iOS Safari unsupported.
- `upload_id`-staging chunk keys instead of a per-key lock (INV-6 alt) — bigger change (key scheme + reads); deferred.
- Native path changes — native already has file-based resumable; this work is wasm/web. The fula-crypto
  plan-mode is shared but purely additive.
