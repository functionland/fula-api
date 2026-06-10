# fula-client / fula-crypto — Client-Side Encryption Audit

**Date:** 2026-06-09
**Scope:** `crates/fula-crypto/src/**` and `crates/fula-client/src/**` (~45k LOC)
**Method:** Full read of the crypto primitives + client integration, four parallel
sub-agent deep-dives (raw-client transport, persistence/identity, sharing/rotation,
forest scalability), and three independent external advisors (Gemini, Cursor/Composer,
GPT-5.5). Severities reconciled across all sources.

---

## TL;DR

The core cryptographic engineering is **good**: modern AEADs, RFC 9180 HPKE, AAD
binding on nearly every surface, Merkle content-addressing of the metadata tree,
per-download integrity verification, careful redaction of secrets in `Debug`. The
gaps are not in the primitives — they are at the **edges**: identity/PII derivation,
the trust-no-server promise vs. advisory enforcement, local data-at-rest, transport,
and metadata-write scalability.

### Highest-priority issues

| # | Severity | Dimension | Issue |
|---|----------|-----------|-------|
| P1 | **High** | Privacy | Global users-index is keyed by an unsalted fast hash of the email → offline "is `<email>` a user?" oracle, world-readable on public gateways |
| P2 | **High** | Security | "Revocation" never re-encrypts; a revoked share-recipient keeps a working DEK forever; `rotate_subtree` returns no work-list |
| P3 | **High** | Security | No HTTPS enforcement — bearer JWT sent to any `http://` host; default endpoint is `http://localhost:9000` |
| P4 | **High** | Privacy | Mode-A key derivation: X25519 master secret = Argon2id(*constant* salt, `provider:sub:email`) — derivable from semi-public identity (deployment-dependent; prod uses a random seed) |
| P5 | **High** | Scalability | Directory-index 1 MiB cliff (~30k dirs) hard-blocks new writes; the sharded fix (`EncryptedDirectoryIndexV8`) exists but has **no production call sites** |
| P6 | **High** | Scalability/Speed | Per-bucket `tokio::sync::RwLock` write lock is held across network I/O — all uploads to one bucket serialize end-to-end |
| P7 | **Med** | Security | Cold-start read never calls `verify_entry_signature` → a malicious gateway can serve a rolled-back (but AEAD-valid) index; amplifies P2 |
| P8 | **Med** | Security | Local WAL + list-buckets cache store filenames/paths/metadata as **plaintext** on disk, no `0600` perms |
| P9 | **Med** | Security | Share read/write/delete permissions are advisory (AAD-bound but the DEK = full capability); contradicts "trust-no-server" |
| P10 | **Med** | Security | Dead `Config.encryption_enabled` flag — `with_encryption()` is a no-op; encryption is opt-in only by choosing `EncryptedClient` (fail-open footgun) |
| P11 | **Med** | Scalability | Every new-file upload re-encrypts + re-PUTs the **entire** directory index (O(D) bytes); no GC of orphaned HAMT nodes |
| P12 | **Med** | Security | Rotation `WrappedKeyInfo` DEKs not bound to `object_path`/`kek_version` (the one place AAD-binding discipline was skipped) |

### What's genuinely solid (don't change)
- Per-file random 256-bit DEK; random 96-bit nonces; **per-file DEK keeps the nonce
  birthday-bound irrelevant** for content.
- v4 content AAD `fula:v4:content:{storage_key}` + per-chunk AAD with index → chunk
  swap/reorder/cross-file substitution all fail closed (tested).
- v7 HAMT nodes: 3 enforced integrity layers (AEAD-with-AAD, recompute
  content-address == requested key, gateway CID verify). **Merkle content-addressing
  blocks node-level subtree grafting** — the only residual rollback is whole-manifest.
- Metadata v1→v2, forest v1/v2→v4, manifest→v7 all **fail closed on downgrade**
  (`decrypt()` rejects `version >= 4`; cross-format rollback guard in `load_forest`).
- HPKE AAD binding for shares/subtree-shares/inbox is length-prefixed and rejects
  pre-v5 tokens (no downgrade oracle). Inbox uses HPKE **Auth** mode (sender-authenticated).
- Secrets redacted in `Debug` throughout; `DekKey`/`SecretKey`/`HybridSecretKey` are
  `ZeroizeOnDrop`.

---

## 1. PRIVACY (PII)

### P1 — [High] Email-enumerable global users-index
`user_key.rs:66-97`, published as map keys at `registry_resolver.rs:81-83`.
`userKey = hex(BLAKE3("fula:user_id:" || jwt_sub)[..16])` where `jwt_sub` is the
plaintext email (pre-migration) or `sha256(email)` (post-migration). No per-user salt,
no memory-hard KDF. The complete set of `userKey` values is published to public
IPNS/IPFS gateways and fetched unauthenticated (`registry_resolver.rs:357-367`). Anyone
who pulls the index can test any candidate email for membership offline at hash-speed.
All three advisors rated this High; it is **world-readable by design**, making it a
permanent public membership oracle (GDPR/CCPA-relevant for email PII).

*Honest fix note:* you cannot simply "add a salt" — the key must be deterministically
re-derivable by other clients for lookup. Real options: (a) require a capability/secret
to fetch a user's entry (private-set-intersection style), (b) switch the SDK↔master
identity hash to Argon2id to raise per-guess cost from ns to ~tens of ms (must change in
lockstep with master's `hash_user_id`), or (c) make the index non-enumerable.

### P4 — [High, deployment-dependent] Mode-A identity-derived master key
`hashing.rs:228-258` (`derive_key_argon2id`, salt = the *context* string, a constant).
In the legacy "Mode A" provisioning path the X25519 master secret is
`Argon2id("fula-files-v1", "google:{sub}:{email}")`. Argon2 (64 MiB/3 iter) protects
*low-entropy* inputs against bulk brute-force; it adds **zero** security when the input
is a known/guessable identity string — an attacker needs **one** evaluation per target.
The later "Mode B" fix (`derive_key_argon2id_with_salt`) adds a per-user random salt
precisely because, per its own doc, the master key was otherwise "derivable from public
identity attributes alone."

**Mitigation in practice:** production FxFiles provisions a random 32-byte base64 root
secret and uses it directly (`examples/audio_client_recovery_e2e.rs:148-158`); Argon2-
over-identity is a fallback. The server cannot *force* the fallback (mode is chosen
client-side by what credential the app supplies). So live exposure depends on whether any
real users were ever provisioned via Mode A. **Recommendation:** treat as High at the
SDK level — gate or remove the identity-derived path, and audit your user base for any
Mode-A accounts; for any that exist, rotate to a random-seed identity.

### P8 — [Medium] Plaintext metadata at rest on the client
- WAL (`wal.rs:91-136, 253-267`): `WalEntry::Insert` records a full `ForestFileEntry`
  (real `path`, `storage_key`, `size`, `content_type`, `content_hash`, `user_metadata`)
  as **plaintext JSON**, protected only by a BLAKE3 keyed MAC (integrity, *not*
  confidentiality). This locally defeats the exact metadata-hiding the forest design
  works to provide against the server.
- list-buckets cache (`block_cache.rs:585-630`): raw S3 ListBuckets XML stored verbatim
  (plaintext bucket names for Mode-A users).
- No `0600`/`0700` perms anywhere (`wal.rs:260`, `orphan_queue.rs:115`,
  `block_cache.rs:249`) — default umask, world-readable on multi-user Unix / shared CI.
  (Block *payloads* themselves are ciphertext — that part is fine.)

**Fix:** AEAD-encrypt the WAL body under `derive_path_key("forest-wal-enc:{bucket}")`,
encrypt/minimize the cached XML, and set `0600` on all state files (`OpenOptionsExt::mode`).

### Privacy residuals (Info)
- **Length/shape side-channels** (all advisors): object sizes, the 768 KB chunk
  boundary, chunk count, HAMT fan-out, and "which subtree changed" all leak to the
  server despite filename obfuscation. Inherent to the storage model; consider size-
  bucketed padding for metadata objects if directory-cardinality privacy matters.
- **Harvest-now-decrypt-later:** ciphertext is permanently, publicly replicated, but the
  default content path is classical HPKE (`CRYPTO_VERSION = 2`) even though a hybrid
  X25519+ML-KEM-768 KEM is implemented. For a permanent public store, HNDL is a more
  realistic concern than for ephemeral TLS — consider making the hybrid path the default
  for long-lived data, or document the exposure.

---

## 2. SECURITY

### P2 — [High] Revocation never re-encrypts; cached DEK retains access
`subtree_keys.rs:407-451` (`rotate_subtree`), `sharing.rs:642-649` (`revoke_share`).
A share hands the recipient the actual symmetric DEK (`AcceptedShare.dek`). `revoke_share`
only `retain()`s an in-memory token list; `validate_access → Revoked` is an advisory
server check. The one cryptographic remedy, `rotate_subtree`, generates a new DEK but
**does not re-encrypt existing content and does not enumerate what needs re-encrypting** —
`SubtreeRotationResult` carries no file list, and the doc comment at `subtree_keys.rs:412`
references a "paths that need re-encryption" field **that does not exist**. Net: a revoked
recipient keeps a working DEK for everything shared before rotation. This is the canonical
limitation of envelope sharing — acceptable *if disclosed*, but here the API actively
implies revocation works. **Fix:** provide a real `reencrypt_subtree` pass (or at minimum
return the object set needing re-wrap), correct the doc, and state revocation is
forward-only.

### P3 — [High] No HTTPS enforcement for the bearer JWT
`client.rs:1503` builds `url = config.endpoint + path`; the `Authorization: Bearer`
header is attached regardless of scheme (`client.rs:1529-1531`, and every multipart
helper). Nothing rejects `http://` for non-loopback hosts; the default endpoint is
`http://localhost:9000` (`config.rs:294`). A misconfigured non-localhost `http://`
endpoint sends a replayable bearer credential (and, for the raw client, plaintext data)
in cleartext. **Fix:** reject `http://` for non-loopback hosts (allow
localhost/127.0.0.1/[::1] for dev) or require an explicit `allow_insecure_http` opt-in.

### P7 — [Medium] Cold-start read trusts an unsigned index (rollback / equivocation)
Consumer at `encryption.rs:4168-4196` looks the user up in the **unsigned plaintext**
`users[]` map and never calls `verify_entry_signature` — even though the SDK builds the
Ed25519 signed-entry apparatus (`user_entry.rs`) for exactly this purpose, and `users_enc`
is never read on the client path. Content stays AEAD-safe (no plaintext forgery), but a
malicious gateway/RPC can serve a **fresh-but-forged or rolled-back** index
(`registry_resolver.rs:1360-1419` validates only an in-payload monotonic `sequence`,
which is per-global-index, not per-bucket). The in-memory sequence cache that catches
replay is lost on restart, so cold start is the exposed window.

This is the lock built but never installed on the door. Combined with P2/P9 it becomes
the scariest cluster (all advisors flagged this): a gateway serves a **pre-revocation**
index → restores a revoked party's DEK access → nothing re-encrypts. **Fix:** on cold
start, prefer `users_enc[userKey]`, verify the Ed25519 signature against a TOFU-pinned
`entry_pubkey_from_kek`, decrypt with AAD, and pin a per-bucket monotonic version.

### P9 — [Medium] Share permissions are advisory, not cryptographic
`hpke.rs:591-622`, `sharing.rs:778-793`. read/write/delete bits are bound into AAD
(tamper-evident) but possession of the symmetric DEK *is* the capability to both decrypt
and produce valid ciphertext — a "read-only" share still delivers the DEK. Enforcement
depends on a trusted gateway, which contradicts the trust-no-server thesis the module
markets ("permission-based access control", `sharing.rs:6`). **Fix:** document
permissions as gateway-enforced hints; for cryptographic write-gating, wire the existing
Ed25519 apparatus into signed-write authorization. (Snapshot-mode binding, `sharing.rs:97`,
has the same advisory-vs-enforced gap.)

### P10 — [Medium] Dead `encryption_enabled` flag (fail-open footgun)
`config.rs:23, 297, 362-365`. The flag is **never read** anywhere; `with_encryption()`
has no effect. Encryption is available only by choosing the `EncryptedClient` type over
the raw `FulaClient`, and the crate-root doc example demonstrates the **plaintext** path
(`lib.rs:30`). `Config::new(url).with_encryption()` + `FulaClient` silently uploads
plaintext. **Fix:** either make `FulaClient::new` error when `encryption_enabled = true`
(fail-closed), or delete the flag, or rename the raw client `UnencryptedFulaClient`.

### P12 — [Medium] Rotation DEKs not bound to object/version
`rotation.rs:139, 244` use bare `encrypt_dek`/`decrypt_dek` (constant AAD
`fula:v2:dek-wrap`) with `object_path` and `kek_version` sitting unauthenticated alongside.
A storage-side adversary can move file A's wrapped DEK onto file B's `WrappedKeyInfo`; it
unwraps cleanly (no confidentiality break, but the content AEAD then fails → confusion/DoS,
and it removes the integrity binding the rest of the crate is careful to provide). **Fix:**
use `encrypt_dek_with_context` binding a canonical `(object_path, kek_version)`, mirroring
the share/subtree paths.

### Security residuals
- **[Low] Inbox spam + replay** (`inbox.rs:208-257`): Auth mode proves the sender holds
  *some* keypair, not that they're authorized to write to this recipient; anyone with the
  (public) recipient pk can drop unlimited entries. Envelope AAD binds only the recipient
  hash (not entry id/timestamp), so a captured entry replays under a fresh id. TTL is
  client-side only.
- **[Low] SecretLink** (`secret_link.rs:81-246`): the fragment payload is base64url JSON
  with no AEAD and (in the Rust struct) no unwrap secret. If a downstream client appends
  the ephemeral `sk` to the URL fragment (as the Dart side appears to), fragment privacy
  becomes load-bearing and the "never sent to servers" framing understates exposure
  (browser history, in-page JS, extensions). Decide the model and document leak vectors.
- **[Low] Rotated KEK is random, not seed-derived** (`rotation.rs:105-108`) → a fresh
  device re-derives the *original* KEK from the seed and (post-`clear_previous`) cannot
  decrypt anything re-wrapped under the rotated KEK. Derive rotated KEKs from
  `seed || rotation_epoch`, or document that rotation needs durable out-of-band backup.
- **[Low] Legacy no-AAD subtree wraps** (`subtree_keys.rs:111-135`) still accepted
  (fail-closed for new data; residual risk only for genuinely-legacy v0 blobs).
- **[Info] HPKE_INFO constant** `fula-storage-v2` reused across all purposes
  (`hpke.rs:242`); domain separation lives in AAD, which RFC 9180 augments with mode
  binding in the key schedule — acceptable, but per-purpose `info` would be cleaner.
- **[Info] Key commitment:** AES-GCM/ChaCha20-Poly1305 are not key-committing. Under this
  trust-no-server model the advisors found no practical partitioning-oracle: shares are
  single-recipient HPKE, and content is additionally bound by the forest `content_hash`.
  Worth a note only if a multi-recipient wrapped-DEK blob or a cross-user
  decrypt-success oracle is ever introduced.
- **[Info] Verbatim-path DEK derivation** (`keys.rs:309-318`): `secret || path` with no
  length prefix is safe (key is fixed 32 B), but the path is hashed verbatim with no NFC /
  separator canonicalization — see Robustness §5.

---

## 3. SCALABILITY (thousands→millions of files)

Current default is **v7 sharded HAMT** (new buckets born v7 with 16 shards;
`compute_initial_shard_count = clamp(next_pow2(N/5000), 16, 65536)`). Per-upload cost is
**O(log₁₆(N/shards))** node reads + writes + O(1) page + O(1) root — genuinely
logarithmic and well-engineered. The scaling problems are the **non-logarithmic terms**:

### P5 — [High] Directory-index 1 MiB hard cliff blocks writes (~30k directories)
`private_forest.rs:1979-1993`. `EncryptedDirectoryIndex::encrypt` hard-fails at ≥1 MiB
serialized; ~30k directories trips it ("only NEW writes are blocked; existing data stays
readable"). The sharded replacement `EncryptedDirectoryIndexV8` (16 hash-prefix shards)
exists and round-trips in tests but has **zero production call sites** — Phase 1.6 and the
migration path both still call the v7 single-blob encrypt (`encryption.rs:4623, 5993`).
The "auto-shard at ~80% of cap" described in comments is not implemented. **A bucket with
tens of thousands of folders becomes permanently un-writable.** Fix: wire `encrypt_sharded`
into the client write path and add a per-shard size guard.

### P6 — [High] Global per-bucket write lock held across network I/O
The forest is `Arc<tokio::sync::RwLock<ShardedHamtPrivateForest>>`; every upload takes
`forest_arc.write().await` and runs `get_file` + `upsert_file` (which await HAMT node
GETs/PUTs over the network) **inside** the guard (`encryption.rs:6530-6543`), and
`flush_dirty` PUTs all nodes under the same guard (`encryption.rs:4415-4425`). Parallel
uploads to one bucket serialize end-to-end including their round-trips; readers are blocked
while a writer holds the lock. Per-shard read locks help concurrent *readers*, and
cross-client races are handled by conditional PUTs + 412-retry + WAL replay — but
single-client write throughput to a hot bucket is round-trip-bound and serial. Fix: shrink
the critical section (resolve/encrypt outside the lock; hold it only for the in-memory
swap), or pipeline node PUTs before taking the commit lock.

### P11 — [Medium] Write amplification + no GC
- Every new-file upload sets `dir_index_dirty` (`sharded_hamt_forest.rs:1153-1155`) and
  re-encrypts + re-PUTs the **whole** directory index — O(D) bytes (~0.7 MB at 20k dirs)
  per single file added, on top of approaching the P5 cliff.
- Orphaned HAMT node blobs from copy-on-write are **never collected** ("out-of-band GC
  sweep (future work)", `encryption.rs:4382-4384`) → ~O(log N) dead blobs leaked per
  upload forever (~5 GB residual at 1M entries in the scale test).

### Scalability residuals
- **[Medium] `list_directory` is O(shard), not O(children)** (`sharded_hamt_forest.rs:1431-1467`):
  a full `flat_map` walk of the owning shard, ≈ 1/16 of the whole bucket at default
  sharding, with **no read-side node memoization** — repeated listings re-fetch every
  node. A 10k-child folder ≈ 250–500 node GETs+decrypts per listing. Recursive surfaces
  (`list_all_files`, `extract_subtree`, `find_by_storage_key`) are full-bucket O(N) scans.
- **[Low] No dynamic reshard:** shard count is frozen at creation. A bucket born <80k
  files stays at 16 shards forever, so per-shard listing cost grows with N.
- **[Med] Flush failure leaves partial state by contract** (`sharded_hamt_forest.rs:1901-1907`)
  — the caller must discard the in-memory forest; seq guards prevent stale-etag clobber.
- **[Low] orphan_queue O(n²)** (`orphan_queue.rs:101,133`): full-file `read_to_string` +
  reparse on every append (WAL already got the streaming-load fix; orphan queue did not).

---

## 4. SPEED of encryption / decryption

**The symmetric crypto is not the bottleneck.** AES-256-GCM runs on AES-NI and
BLAKE3/Bao at ~1 GB/s SIMD; both are benchmarked (`benches/crypto_benchmarks.rs`,
1 KiB/64 KiB/1 MiB). Per-file work is dominated by network round-trips, not cipher cost.

Observations:
- **Walkable-v8 self-verify** adds one BLAKE3 pass (~µs) per PUT ciphertext, pre-computed
  before the PUT to avoid a second pass — negligible.
- **Buffered download peak memory** (`chunked.rs:441` / `ChunkedDecoder::finalize`) is ~2×
  file size; the streaming `decrypt_chunk_streaming` / windowed writer paths bound peak to
  ~`window_size × chunk_size`. Good that both exist; make sure large-file call sites use
  the streaming path.
- **[Low] Release of unverified plaintext (streaming path):** the windowed decoder writes
  each chunk's plaintext to the caller's writer **before** the Bao root hash is verified at
  finalize (`encryption.rs:1857-1859`, explicitly documented). Per-chunk AEAD still holds,
  so individual chunks are authentic, but truncation/reorder is only caught at the end —
  by which point partial plaintext was already emitted. The buffered variant (F8,
  `get_object_decrypted_buffered_to_writer`) closes this for disaster-recovery consumers.
  Single-block files are fully verified before return (AEAD tag + post-decrypt
  `content_hash`).
- **Argon2id at 64 MiB/3 iter** (~50–100 ms) runs once per session at key derivation —
  fine, and correctly memory-hard.

---

## 5. ERROR-PRONE / BREAKING POINTS

- **[High] Key-derivation drift = permanent data loss.** Two userKey functions
  (`derive_user_key_from_jwt_sub` vs `derive_user_key_from_email`) and two master-key modes
  (random seed vs Argon2-over-identity). Picking the wrong one yields a different identity:
  the SDK looks up the wrong index / derives the wrong forest DEK and **every decrypt
  fails** with an AEAD error (this exact bug is pinned in `user_key.rs` tests for a
  pre-migration user). This is the single most likely operational failure.
- **[High] Path canonicalization not applied by the crate** (`keys.rs:267-308`): paths feed
  DEK/storage-key derivation **verbatim** — no NFC normalization, no separator coercion.
  `photos\cat.jpg` (Windows) vs `photos/cat.jpg` (mac), or NFC vs NFD `café`, derive
  *different* keys → the same logical file is unreadable on a second device. A
  `canonicalize_path` helper exists but is **opt-in** and doesn't do NFC. Callers must
  canonicalize identically on every read and write, forever.
- **[Low] NFC vs NFKC mismatch** (`effective_user_id.rs:98,121,146`): code applies `.nfc()`
  but docs/tests say "NFKC". They diverge for compatibility characters (ligatures,
  full-width) → two visually-equal passphrases derive different identities. Decide one and
  make code+docs+tests agree.
- **[Med] Cross-session replay floor is opt-in** (`encryption.rs:1124-1151`): the
  monotonic-sequence replay guard lives in an in-memory cache lost on restart; cross-session
  protection requires the app to persist and restore a "sequence floor" itself. Without it,
  cold start accepts an older valid manifest (ties into P7).
- **[Info] Resumable-upload nonce safety:** chunk nonces are fresh-random per chunk under a
  fresh per-file DEK, so resume/retry cannot reuse a (key, nonce) pair — verified safe. (The
  one thing to never introduce here is a counter-nonce that resets on crash.)
- **[Info] `getrandom` panics** in several `generate()` paths if OS entropy is unavailable
  (`symmetric.rs:38`, `keys.rs:29`, `hpke.rs:46`); `try_*` fallible variants exist — prefer
  them on constrained/early-boot/WASM targets.

---

## Prioritized recommendations

1. **P3 (cheap, high impact):** reject non-loopback `http://` in `Config`/`FulaClient::new`.
2. **P10 (cheap):** make `encryption_enabled = true` on a raw `FulaClient` a hard error, or
   delete the flag. Banner `FulaClient` as the raw transport in docs.
3. **P5 (correctness blocker at scale):** wire `EncryptedDirectoryIndexV8::encrypt_sharded`
   into the client write/migration path before any user reaches ~30k directories.
4. **P2 + P7 + P9 cluster:** wire `verify_entry_signature` into cold-start, add per-bucket
   version pinning, implement a real `reencrypt_subtree`, and correct the revocation/
   permission/snapshot docs to say "advisory / gateway-enforced." This is the trust-no-server
   gap that several findings share.
5. **P1 / P4 (privacy):** move the identity hash to Argon2id (lockstep with master) and
   audit for any Mode-A users; gate/remove the identity-derived master-key path.
6. **P8:** AEAD-encrypt the WAL body and set `0600` on all state files.
7. **P6 / P11 (throughput):** shrink the per-bucket write critical section and ship the
   orphan-node GC sweep + dir-index sharding to bound storage and per-upload bytes.
8. **Robustness:** make path canonicalization (separator + NFC) mandatory inside the SDK
   boundary, and resolve the NFC/NFKC doc-vs-code mismatch.

*Confidence: the crypto-primitive findings are verified against source with file:line
citations. Mode-A (P4) severity is deployment-dependent — confirm whether any production
users were provisioned via the identity-derived path. The scalability numbers are from the
code's own scale benches and structural analysis, not a live load test.*
