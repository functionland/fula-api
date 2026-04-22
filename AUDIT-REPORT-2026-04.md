# Fula API Encryption Audit Report

**Date:** 2026-04-16  
**Scope:** `fula-client/src/encryption.rs`, `fula-crypto/src/*`  
**Method:** Line-by-line code path audit (not comment/doc review)  
**Audited paths:**
1. encrypt → upload → list folder → download → decrypt
2. share send → share receive
3. collaborate share → collaborate accept

---

## Path Coverage

### Path 1: encrypt → upload → list folder → download → decrypt

| Step | Location | What happens |
|------|----------|-------------|
| Generate DEK | `encryption.rs:1629` | `key_manager.generate_dek()` — random 256-bit AES key |
| Derive storage key | `encryption.rs:1632-1641` | `forest.generate_key(key, &dek)` → `generate_flat_key(path, dek, salt)` (`private_forest.rs:80-89`) — BLAKE3 KDF produces `Qm<hex>` |
| Encrypt (small file) | `encryption.rs:1673-1677` | AES-256-GCM with random nonce, AAD = `fula:v4:content:<storage_key>` |
| Encrypt (chunked) | `encryption.rs:1660-1670` → `put_object_chunked_internal:1756-1892` | Split at 256KB, each chunk: random nonce + AES-GCM + AAD `fula:v4:chunk:<storage_key>:<index>` (`chunked.rs:244-268`) |
| Wrap DEK | `encryption.rs:1644-1646` | HPKE encrypt DEK for owner's public key (X25519+ChaCha20Poly1305) |
| Upload | `encryption.rs:1696-1712` | PUT to S3 with `x-fula-encrypted: true`, `x-fula-encryption: {JSON metadata}` |
| Update forest | `encryption.rs:1718-1750` | `forest.upsert_file(entry)` — insert/replace in in-memory forest, mark dirty |
| Flush forest | `encryption.rs:2367-2452` | Serialize forest → AES-GCM encrypt (`private_forest.rs:600-612`) → PUT to S3 |
| List folder | `encryption.rs` `list_objects_decrypted` | `load_forest()` (`encryption.rs:1121-1204`) → filter by prefix → return entries with decrypted metadata |
| Download | `encryption.rs:466-541` `get_object_decrypted_by_storage_key` | Fetch from S3 → parse `x-fula-encryption` JSON → HPKE unwrap DEK (`hpke.rs` Decryptor) |
| Decrypt (single) | `encryption.rs:506-518` | AES-GCM decrypt with version-aware AAD (`v4`: with AAD, `<v4`: without) |
| Decrypt (chunked) | `encryption.rs:3346-3420` `get_object_chunked` | Sequential loop: fetch each `_chunk_N` → AES-GCM decrypt per chunk → concatenate |
| Verify integrity | `chunked.rs:575-660` `VerifiedStreamingDecoder` | Bao hash verification per 1KiB block (`streaming.rs:191-248`) + root hash check |

### Path 2: share send → share receive

| Step | Location | What happens |
|------|----------|-------------|
| **Send side** | | |
| Create ShareBuilder | `sharing.rs:302-431` | Owner provides: `&owner_keypair`, `recipient.public_key()`, `&dek`, path_scope, expiry, permissions |
| Wrap DEK for recipient | `sharing.rs:414-415` | `Encryptor::new(recipient_pk).encrypt_dek(&dek)` — HPKE encrypts DEK for recipient's X25519 public key |
| Build ShareToken | `sharing.rs:417-431` | Token = `{id, wrapped_key, path_scope, expires_at, permissions, mode, nonce, chunked_metadata, encryption_version}` |
| Attach encryption info | `sharing.rs:354-393` | `.with_nonce()` embeds the content nonce; `.with_chunked_metadata()` embeds chunk layout — allows recipient to decrypt without S3 metadata headers |
| **Receive side** | | |
| Accept share | `sharing.rs:574-593` `ShareRecipient.accept_share()` | Check expiry → `Decryptor::from_secret_key(&sk).decrypt_dek(&token.wrapped_key)` → returns `AcceptedShare{dek, path_scope, permissions, nonce, chunked_metadata}` |
| Validate access | `encryption.rs:2800-2821` `get_object_with_share()` | Check `is_valid()` (expiry), `is_path_allowed(original_key)` (scope), `can_read` (permission) |
| Decrypt with token nonce | `encryption.rs:2830-2853` | If token has nonce: fetch raw data → AES-GCM decrypt with share's DEK, version-aware AAD |
| Decrypt chunked with token | `encryption.rs:2825-2828` | If token has `chunked_metadata`: call `get_object_chunked_with_share_token()` — uses chunk layout from token |
| Fallback: S3 metadata | `encryption.rs:2855-2916` | Old tokens without embedded nonce/chunks: fetch S3 headers → parse `x-fula-encryption` → decrypt using share's DEK |

**Security properties verified:**
- DEK is wrapped per-recipient (HPKE, `sharing.rs:414-415`); no raw key in token
- Path scope enforced before any data fetch (`encryption.rs:2808-2814`)
- Expiry checked at both accept (`sharing.rs:576-578`) and use (`encryption.rs:2801-2804`)
- Snapshot mode can bind to specific content hash/size/timestamp (`sharing.rs:54-95`)

### Path 3: collaborate share → collaborate accept

| Step | Location | What happens |
|------|----------|-------------|
| **Share side** | | |
| Build share envelope | `inbox.rs:445-614` `ShareEnvelopeBuilder` | Fluent API: set owner, recipient, DEK, path, permissions, expiry |
| Create ShareToken | `inbox.rs` → `sharing.rs:402-431` | Same as Path 2: HPKE-wrap DEK for recipient |
| Create ShareEnvelope | `inbox.rs:550-570` | Envelope = `{token, sender_public_key, bucket, message, created_at}` |
| Create InboxEntry | `inbox.rs:573-602` | `InboxEntry::create(envelope, recipient_pk)`: serialize envelope → HPKE encrypt for recipient → set `recipient_id = BLAKE3(recipient_pk)[..16]` |
| Store inbox entry | Client stores at `inbox/<recipient_hash>/<entry_id>` | Encrypted blob; server sees only the recipient hash prefix, not content |
| **Accept side** | | |
| Load inbox | Client fetches entries at `inbox/<own_hash>/` | List + download encrypted inbox entries |
| Verify recipient | `inbox.rs:362-363` `accept_entry()` | `entry.is_for_recipient(recipient_keypair.public_key())` — BLAKE3 hash match (128 bits) |
| Decrypt envelope | `inbox.rs:367` | `entry.decrypt(recipient_keypair.secret_key())` — HPKE decrypt |
| Extract token | Envelope contains `ShareToken` | Same structure as Path 2 |
| Accept token | `sharing.rs:574-593` `ShareRecipient.accept_share()` | Same as Path 2: check expiry → HPKE decrypt DEK → return `AcceptedShare` |
| Use share | `encryption.rs:2793-2917` | Same as Path 2's receive side |

**Security properties verified:**
- Recipient ownership verified via `is_for_recipient()` before ANY mutation (`inbox.rs:362-363`, `378-382`, `395-397`, `412-414`)
- Envelope encrypted end-to-end; server sees only `recipient_id` hash
- Cross-user isolation: tests in `inbox.rs:750-900` verify entries for user A are inaccessible to user B
- Dismiss/remove also verify recipient (`inbox.rs:395-414`)

---

## Category 1: Scalability of Files Per User

### F-1.1 — Hard ceiling at ~2.56M files per bucket

**Location:** `private_forest.rs:687-691` (`compute_initial_shard_count`), `private_forest.rs:59` (`MAX_SHARDS=256`), `private_forest.rs:60` (`RESHARD_THRESHOLD=10000`)

The sharded forest caps at `MAX_SHARDS(256) × RESHARD_THRESHOLD(10000) = 2,560,000` files. After this, `should_reshard()` returns `false` and shards grow without bound.

- **By design?** Partially. The constants are tunable, but MAX_SHARDS=256 is hard-coded and tied to the single-byte shard routing (`hash.as_bytes()[0] as usize % num_shards` at line 679). Raising MAX_SHARDS above 256 requires changing to a multi-byte shard key.
- **Backward compatible?** Yes — existing data unaffected. Raising limits is a forward-only change; old forests stay valid.

### F-1.2 — `find_by_storage_key` is O(n) scan

**Location:** `private_forest.rs:437-460` (monolithic), `private_forest.rs:1204-1240` (sharded)

Reverse lookup (storage key → original path) iterates every file entry. In the sharded variant, it loads *every* shard from S3 to scan. Used during `get_object_decrypted` when called with a storage key.

- **By design?** Yes — the forest is indexed by original path, not by storage key. A reverse index would add complexity.
- **Backward compatible?** N/A (behavioral, no data change needed).

### F-1.3 — `list_subdirs` is O(total files) in sharded mode

**Location:** `private_forest.rs:1181-1202` (`list_subdirs` → `reconstruct_directories`)

`reconstruct_directories()` iterates ALL file entries across ALL shards to rebuild the directory tree. For 100K+ files, this is expensive — every `list_objects_decrypted` call for a subfolder triggers this.

- **By design?** Yes — the shard key is a hash of the file path, not the directory. There is no directory-level index.
- **Backward compatible?** N/A.

### F-1.4 — Monolithic → sharded auto-migration threshold

**Location:** `encryption.rs:2410-2430` (inside `flush_forest`)

Auto-migration from monolithic (v1/v2) to sharded (v3) triggers at 5,000 files. During migration, the entire forest is re-encrypted and re-uploaded as 16+ shard objects in a single flush. This is a heavy operation that could timeout on slow connections.

- **By design?** Yes — one-time migration cost. The threshold is reasonable.
- **Backward compatible?** Yes — old monolithic forests remain readable; migration is transparent.

---

## Category 2: Security of Encryption & Sharing

### F-2.1 — Forest/shard encryption has no AAD (rollback/replay attack) — MEDIUM

**Location:** `private_forest.rs:600-612` (`EncryptedForest::encrypt`), `private_forest.rs:822-835` (`EncryptedShardManifest::encrypt`), `private_forest.rs:875-888` (`EncryptedForestShard::encrypt`)

All three use `Aead::encrypt` with no Additional Authenticated Data. The encryption key is derived from `dek + bucket`, so cross-user/cross-bucket swaps are prevented. However, a malicious storage server can replay a *stale but validly encrypted* forest blob — the client would silently decrypt and see an old snapshot of the file tree (deleted files reappear, renames revert).

- **By design?** No. This is a gap. The content encryption path (v4) correctly binds AAD to `fula:v4:content:<storage_key>`. Forest encryption should bind to a monotonic counter or version tag.
- **Backward compatible?** Adding AAD to forest encryption is a **breaking change** for existing forests. Would require a version bump (v4 forest format) with fallback decryption for v1-v3.

### F-2.2 — `HpkeConfig.aead` field is ignored

**Location:** `hpke.rs` — the `aead` field on `HpkeConfig` exists but the actual AEAD algorithm is hardcoded to ChaCha20Poly1305 in the HPKE suite construction.

A caller setting `config.aead = AeadAlgorithm::Aes256Gcm` would believe they selected AES-GCM, but ChaCha20Poly1305 is always used. This is a correctness trap, not a vulnerability (ChaCha20Poly1305 is secure).

- **By design?** Partially — HPKE RFC 9180 specifies the full suite as a unit. The field exists for future flexibility but is misleading.
- **Backward compatible?** N/A — no data format change.

### F-2.3 — Share token `encryption_version` may be `None` for pre-v4 data

**Location:** `sharing.rs` — `ShareToken` struct, `encryption_version: Option<u8>` field

When a share token is created for content encrypted before v4, the version can be `None`. The recipient path in `get_object_with_share` (`encryption.rs:2793-2917`) handles this by falling back to no-AAD decryption. This is correct behavior but means pre-v4 shared content lacks AAD binding.

- **By design?** Yes — backward compatibility with pre-v4 encrypted content.
- **Backward compatible?** Yes — old tokens continue to work.

### F-2.4 — Bao `track_chunk` deprecated but still callable

**Location:** `streaming.rs:176` (`track_chunk`)

`track_chunk()` only counts bytes without verifying hashes. It is properly marked `#[deprecated]` with a note to use `verify_chunk()` instead. No live call sites use it — `VerifiedStreamingDecoder` in `chunked.rs` calls `verify_chunk()`.

- **By design?** Yes — retained for API compat, correctly deprecated.
- **Backward compatible?** N/A.

### F-2.5 — Subtree key resolution is sound

**Location:** `subtree_keys.rs:224-243` (`resolve_dek`)

Subtree key resolution finds the most-specific matching prefix via linear scan of `subtree_keys` HashMap. Falls back to master DEK when no subtree matches. The `SubtreeShareBuilder` (`subtree_keys.rs:419-503`) wraps the subtree DEK for the recipient using HPKE (same pattern as per-file shares). `SubtreeShareRecipient.accept_share()` (`subtree_keys.rs:518-533`) checks expiry before decrypting.

One note: `resolve_dek()` does a linear scan of all subtree prefixes (O(n) where n = number of subtree keys). This is fine for typical use (few subtrees) but would degrade with many hundreds of subtree keys.

- **Status:** No security issue. Subtree rotation (`subtree_keys.rs:268-300`) correctly increments version and generates a fresh DEK.

### F-2.6 — Secret links keep key material in URL fragment

**Location:** `secret_link.rs:30-100`

Secret links embed the full `ShareToken` (including wrapped DEK) in the URL fragment (`#<base64url payload>`). The fragment is never sent to the server per RFC 3986 — the server only sees the `opaque_id` in the path. The payload uses base64url-no-pad encoding (`secret_link.rs:213-215`), verified by tests (`secret_link.rs:515-527`).

`SecretLink::parse()` (`secret_link.rs:159-209`) validates the URL has a fragment and correct path prefix before decoding. No XSS or injection risk — the payload is decoded as JSON, not evaluated.

- **Status:** No issue. The design correctly keeps key material client-side.

### F-2.7 — Inbox recipient verification is sound

**Location:** `inbox.rs` — all mutable operations (`mark_read`, `dismiss_entry`, `remove_entry`, `accept_entry`) verify `entry.is_for_recipient(&recipient_id)` before modification.

`is_for_recipient` uses `BLAKE3(recipient_public_key)[..16]` — 128 bits of collision resistance, adequate for recipient binding.

- **Status:** No issue found. The collaborate path (ShareEnvelopeBuilder → InboxEntry → ShareInbox.accept_entry → ShareRecipient.accept_share) is correctly isolated per-recipient.

---

## Category 3: Privacy of Uploaded Data

### F-3.1 — Entire old upload orphaned on file overwrite — MEDIUM

**Location:** `encryption.rs:1614-1753` (`put_object_flat_deferred`)

**Mechanism:** Each upload generates a **new random DEK** (`encryption.rs:1629`). The storage key is derived from `BLAKE3-KDF(dek || salt, original_path)` (`private_forest.rs:80-89`). Since the DEK is different each time, the storage key is **different on every overwrite of the same path**. The flow:
1. Generate new DEK (line 1629) → new storage key (lines 1632-1641)
2. Encrypt and upload to the new storage key (lines 1660-1712)
3. `forest.upsert_file()` replaces the forest entry with the new storage key (lines 1718-1750)

**Result:** The old storage key — and ALL its chunk objects (`<old_key>_chunk_0`, `_chunk_1`, etc.) — remain in S3 with no reference. The old DEK is lost (the forest entry that held it is overwritten), making the orphaned data unrecoverable. Every file overwrite leaks the entire old upload as orphaned S3 objects.

- **By design?** No — this is a gap. The per-upload random DEK is correct for security (prevents DEK reuse), but the function should look up and delete the old storage key before overwriting the forest entry.
- **Backward compatible?** Yes — adding a pre-overwrite cleanup step affects only new overwrites. Existing orphaned objects from past overwrites would need a separate garbage-collection sweep (scan S3 for objects not referenced by the current forest).

### F-3.2 — Forest object size leaks approximate file count

**Location:** `private_forest.rs:600-612` (monolithic), `private_forest.rs:822-835` (sharded manifest)

The encrypted forest/manifest object size is proportional to the number of files. A storage server can observe the forest object growing and estimate how many files a user has, even though individual file names and paths are encrypted.

For sharded forests, the number of shard objects (16, 32, 64, ...) directly reveals the approximate file count range (since resharding thresholds are public knowledge).

- **By design?** Accepted tradeoff. Padding the forest to fixed sizes would be expensive and complex.
- **Backward compatible?** N/A.

### F-3.3 — FlatNamespace key derivation is sound

**Location:** `private_forest.rs:69-93` (`generate_flat_key`), `private_metadata.rs:233-244`

Storage keys are derived as `BLAKE3-KDF(dek || salt, original_key)` with domain `fula/flat-namespace/key/v1`, output formatted as `Qm<44 hex chars>`. The empty salt in `obfuscate_key()` is documented (audit comment M-001 at `private_metadata.rs:237-241`) — cross-bucket correlation is prevented because each user has a unique DEK.

- **Status:** No issue. The derivation provides proper domain separation and determinism within a user's scope.

### F-3.4 — Metadata privacy is well-implemented

**Location:** `private_metadata.rs:126-151`

`EncryptedPrivateMetadata` encrypts the full `PrivateMetadata` struct (original filename, size, timestamps, content type, user metadata) with the per-file DEK using AES-256-GCM. The server sees only the obfuscated storage key and ciphertext size.

- **Status:** No issue.

---

## Category 4: Speed of Upload/Download

### F-4.1 — `get_object_chunked` downloads sequentially — MEDIUM

**Location:** `encryption.rs:3346-3420` (`get_object_chunked`)

This function downloads chunks in a sequential `for` loop — one HTTP request at a time. It is a **live code path** called from:
- `fula-flutter/src/api/chunked.rs:44`
- `encryption.rs:514` (main decrypt path)
- `encryption.rs:2827` (share flow)

A parallel path exists (`download_chunks_windowed_to_writer` at `encryption.rs:606-676` with semaphore of 16), but it is NOT used in the primary `get_object_decrypted_by_storage_key` flow when the caller hasn't opted in via the writer-based API.

- **By design?** No — the parallel windowed downloader exists but isn't wired into the main download path. Likely an incremental development artifact.
- **Backward compatible?** Yes — changing download concurrency is transparent to stored data.

### F-4.2 — `list_objects_decrypted` issues sequential HEAD requests

**Location:** `encryption.rs` — the list flow loads the forest, enumerates matching entries, then for each file calls the S3 API to get metadata. These calls happen sequentially.

For a folder with hundreds of files, this means hundreds of sequential HTTP round-trips.

- **By design?** Partially — S3 LIST returns metadata inline, but the encrypted metadata is stored in a custom header requiring a HEAD per object. Could be batched or cached.
- **Backward compatible?** Yes.

### F-4.3 — `rotate_bucket` rewraps keys sequentially

**Location:** `encryption.rs:3117-3168`

Key rotation lists all objects, then iterates sequentially: fetch metadata → unwrap DEK with old KEK → rewrap with new KEK → update metadata. For a bucket with thousands of objects, this is very slow and has no parallelism.

- **By design?** Partially — sequential processing is simpler and avoids rate limiting, but a semaphore-bounded parallel approach (like upload chunking) would be safer and faster.
- **Backward compatible?** Yes.

### F-4.4 — Upload parallelism is good

**Location:** `encryption.rs:1756-1892` (`put_object_chunked_internal`)

Chunk uploads use a semaphore of 16 concurrent uploads with `tokio::spawn` + `JoinSet`. This is well-implemented.

- **Status:** No issue.

---

## Category 5: Scalability of Users

### F-5.1 — Users are well-isolated

Each user has:
- Independent X25519 keypair (KEK)
- Independent per-file DEKs
- Independent forest (encrypted index) in their own bucket
- No shared mutable state between users

The `EncryptedClient` uses `DashMap` for in-memory forest caching (keyed by bucket), and `tokio::sync::RwLock` for migration locks — both are per-process, not cross-user.

- **Status:** No scalability issue found. User count scales independently of per-user data.

### F-5.2 — Sharing does not create cross-user coupling

**Location:** `inbox.rs`, `sharing.rs`

Share tokens contain a wrapped DEK (encrypted for the recipient's public key). The recipient decrypts independently — no shared lock, no shared index, no back-channel to the sender.

Inbox entries are stored at a path derived from the recipient's public key hash. Multiple senders can write to the same inbox prefix, but each entry is independently encrypted.

- **Status:** No issue.

---

## Category 6: Scalability of Folders & Subfolders

### F-6.1 — No inherent folder depth limit, but performance degrades

**Location:** `private_forest.rs:385-425` (`ensure_directory`)

Directory creation is recursive: for `/a/b/c/d/file.txt`, it creates entries for `/a/`, `/a/b/`, `/a/b/c/`, `/a/b/c/d/`. Each is an `upsert` into the forest. This is correct but means:
- Deep nesting creates many directory entries in the forest
- `list_subdirs` (F-1.3) must scan all entries to reconstruct the tree

There is no folder-count limit, but very deep or very wide directory trees degrade listing performance linearly.

- **By design?** Yes — flat file-based indexing avoids the complexity of a tree-structured index.
- **Backward compatible?** N/A.

### F-6.2 — Shard routing ignores directory locality

**Location:** `private_forest.rs:675-682` (`shard_for_path`)

Shard assignment uses `BLAKE3(path)[0] % num_shards`. Files in the same directory are distributed across different shards. Listing a directory requires loading *all* shards (since any shard may contain files from any directory).

A directory-prefix-based sharding scheme would allow loading only relevant shards for a given folder listing.

- **By design?** Yes — uniform distribution prevents hot shards. The tradeoff is listing performance.
- **Backward compatible?** Changing shard routing requires a full reshard migration (supported by `reshard()` but it changes all shard assignments).

### F-6.3 — HAMT auto-migration at 1,000 files

**Location:** `private_forest.rs:349-382` (`upsert_file`)

The monolithic forest auto-migrates from `FlatMapV1` (BTreeMap) to `HamtV2` (hash array mapped trie) at 1,000 files. This is a good optimization — HAMT provides O(log32 n) lookups vs O(log n) for BTreeMap, and more importantly enables future partial-tree loading.

- **Status:** No issue — this is well-designed.

---

## Category 7: Error Recovery & Disaster Recovery

### F-7.1 — Crash between upload and forest flush = orphaned data — MEDIUM

**Location:** `encryption.rs:1614-1753` (`put_object_flat_deferred`), `encryption.rs:2367-2452` (`flush_forest`)

The deferred-save pattern works as:
1. Upload encrypted object to S3 ✓
2. Update in-memory forest cache (mark dirty) ✓
3. Later: `flush_forest` saves encrypted forest to S3

If the process crashes between steps 2 and 3, the uploaded object exists in S3 but the forest doesn't reference it. The data is:
- **Irrecoverable** — without the forest entry, the original path and DEK are lost
- **Storage-leaking** — the orphaned object persists in S3

There is no write-ahead log (WAL), no journaling, and no recovery mechanism.

- **By design?** The deferred pattern is intentional for performance (batching forest writes). The lack of recovery tooling is a gap.
- **Backward compatible?** Adding a WAL or immediate-flush option would not affect existing data.

### F-7.2 — Key rotation partial failure = mixed encryption state

**Location:** `encryption.rs:3117-3168` (`rotate_bucket`)

If `rotate_bucket` fails midway (network error, process crash), some objects have DEKs wrapped with the new KEK and some with the old. There is no tracking of which objects were re-wrapped, so:
- Recovery requires re-scanning all objects to determine their KEK version
- Both old and new KEKs must be retained until rotation completes
- There is no resume capability

- **By design?** No — this is a robustness gap. A rotation journal (tracking progress) would allow safe resume.
- **Backward compatible?** Yes — adding rotation tracking doesn't affect existing data.

### F-7.3 — Reshard doesn't clean old shard objects

**Location:** `private_forest.rs:1244-1289` (`reshard`)

When resharding (e.g., from 16 to 32 shards), new shard objects are written with a new `shard_salt`, but old shard objects remain in S3. These are:
- Encrypted with the same forest DEK (so they could theoretically be decrypted)
- Referenced by no manifest (the new manifest points to new shard keys)
- Never cleaned up

- **By design?** Partially — leaving old shards avoids deletion failures blocking resharding. But there's no deferred cleanup either.
- **Backward compatible?** Yes — adding post-reshard cleanup is additive.

### F-7.4 — No integrity check on forest load (beyond AES-GCM auth tag)

**Location:** `encryption.rs:1121-1204` (`load_forest`), `private_forest.rs:614-637` (`EncryptedForest::decrypt`)

AES-GCM's authentication tag ensures the ciphertext wasn't tampered with, but there's no versioning or sequence check. Combined with F-2.1 (no AAD), a replayed old forest blob will pass AES-GCM verification.

- **By design?** No — this compounds F-2.1. A monotonic version counter stored inside the encrypted forest (and verified after decryption) would detect replay.
- **Backward compatible?** Adding an internal version counter is backward compatible if the absence of a counter is treated as "version 0" during migration.

### F-7.5 — Concurrent `flush_forest` is safe but last-writer-wins

**Location:** `encryption.rs:2367-2452` (`flush_forest`)

`flush_forest` takes a read lock on the forest cache, checks dirty flag, serializes, encrypts, and uploads. Two concurrent flushes of the same forest can race — both read the same dirty state, both upload, and the last S3 PUT wins. No S3 conditional write (If-None-Match) is used.

In practice, this is unlikely with single-client usage but could cause silent data loss with multiple client instances using the same bucket.

- **By design?** Single-client assumption is implicit but not enforced.
- **Backward compatible?** N/A.

---

## Summary Table

| ID | Category | Severity | By Design? | Backward Compatible? |
|----|----------|----------|------------|---------------------|
| F-1.1 | Scalability/files | Low | Partially | Yes |
| F-1.2 | Scalability/files | Low | Yes | N/A |
| F-1.3 | Scalability/files | Medium | Yes | N/A |
| F-1.4 | Scalability/files | Info | Yes | Yes |
| F-2.1 | Security | Medium | No | **Breaking** for forest |
| F-2.2 | Security | Low | Partially | N/A |
| F-2.3 | Security | Info | Yes | Yes |
| F-2.4 | Security | Info | Yes | N/A |
| F-2.5 | Security | None | N/A | N/A |
| F-2.6 | Security | None | N/A | N/A |
| F-2.7 | Security | None | N/A | N/A |
| F-3.1 | Privacy | Medium | No | Yes |
| F-3.2 | Privacy | Low | Accepted | N/A |
| F-3.3 | Privacy | None | N/A | N/A |
| F-3.4 | Privacy | None | N/A | N/A |
| F-4.1 | Speed | Medium | No | Yes |
| F-4.2 | Speed | Low | Partially | Yes |
| F-4.3 | Speed | Low | Partially | Yes |
| F-4.4 | Speed | None | N/A | N/A |
| F-5.1 | Users | None | N/A | N/A |
| F-5.2 | Users | None | N/A | N/A |
| F-6.1 | Folders | Low | Yes | N/A |
| F-6.2 | Folders | Low | Yes | Reshard needed |
| F-6.3 | Folders | None | N/A | N/A |
| F-7.1 | Recovery | Medium | Partially | Yes |
| F-7.2 | Recovery | Medium | No | Yes |
| F-7.3 | Recovery | Low | Partially | Yes |
| F-7.4 | Recovery | Medium | No | Yes |
| F-7.5 | Recovery | Low | Implicit | N/A |

---

## Recommended Priority Fixes

**High priority (security/correctness):**
1. **F-2.1** — Add AAD to forest/shard encryption (version-gated, with v3 fallback decryption)
2. **F-3.1** — In `put_object_flat_deferred`, look up and delete old storage key (+ chunk objects) before upserting the forest entry
3. **F-7.1** — Add immediate-flush option or write-ahead log for critical uploads

**Medium priority (performance):**
4. **F-4.1** — Wire `download_chunks_windowed_to_writer` into the main `get_object_decrypted_by_storage_key` path
5. **F-7.2** — Add rotation progress journal for resumable key rotation

**Lower priority (scalability):**
6. **F-1.1** — Plan for multi-byte shard routing when approaching 256 shard limit
7. **F-1.3 / F-6.2** — Consider directory-aware shard routing or a separate directory index

---

## Remediation Status (2026-04-16)

| ID | Status | Notes |
|----|--------|-------|
| F-2.1 + F-7.4 | **Fixed** | New formats: `EncryptedForest` v4 (monolithic-AAD), `EncryptedShardManifest` v5 (sharded-AAD, legacy routing), v6 (sharded-AAD, directory-aware routing); `EncryptedForestShard` v2. AAD is `fula:forest:v4:<bucket>:<seq>`, `fula:manifest:v{5,6}:<bucket>:<seq>`, `fula:shard:v2:<bucket>:<shard_index>:<seq>`. Manifest-seq + per-shard-seq (`shard_sequences` vouched inside v5/v6 manifest plaintext) close replay holes including cold-start-before-cache shard replay. Distinct v5/v6 AAD prefixes prevent cross-version downgrade at AEAD verification; `cached_prior_manifest_version` gate additionally rejects v5 once v6 has been observed for a bucket. Legacy v1/v2/v3 remain decryptable for backward compatibility. |
| F-2.2 | **Fixed** | Marked `HpkeConfig.aead` field as deprecated; `Default` now returns `ChaCha20Poly1305` to match actual behavior. |
| F-3.1 | **Fixed** | `put_object_flat_deferred` and `put_object_chunked_internal` capture the prior storage key before upsert; post-save cleanup deletes chunk objects + main object + IPFS pin (refcount-checked via in-forest scan). |
| F-NEW | **Fixed** | `delete_object_flat` runs the same refcount-safe cleanup helper; server-side `delete_object` handler unpins IPFS after refcount check. |
| F-4.1 | **Fixed** | `get_object_chunked` now calls `download_chunks_windowed_to_writer` (same parallel helper used by the main path); pre-v3 `ChunkedDecoder::new` path preserved via format dispatch. |
| F-4.2 | **Fixed** | `list_objects_decrypted` uses `futures::stream::for_each_concurrent` at `MAX_CONCURRENT_HEADS=16`. No caching (per scope guidance). |
| F-4.3 | **Fixed** | `rotate_bucket` uses `for_each_concurrent` at `MAX_CONCURRENT_REWRAPS=8`; `RotationReport` collected via `Arc<Mutex<_>>`. |
| F-6.2 | **Fixed** | `ShardedV6` (manifest v6, format `sharded-v6`) routes by parent directory (`BLAKE3-KDF(dek‖parent_dir‖salt)[0..2] % num_shards`). All files under one directory land in one shard — locality without new metadata leak (shard IDs remain `QmXXXX`-opaque because DEK+salt are mixed). Auto-migration v1/v2→v6 on next flush when file count ≥ `SHARDED_MIGRATION_THRESHOLD`; v3/v5→v6 on next flush regardless of count (one-time reshard, old shard blobs best-effort deleted after new manifest is written). |
| F-1.3 | **Partial / deferred** | v6 routing gives `list_directory(dir)` one-shard locality (big win), but `list_subdirs(dir)` still iterates all loaded shards to rebuild the directory tree — subdirs of a given dir may live in any shard, which v6 routing does not localize. A dedicated directory index (~50 bytes/dir, maintained on upsert/remove with refcount) would deliver the advertised "O(files in that dir)" bound; deferred here to avoid adding bug surface in refcount maintenance. Tracked for a follow-up fix. |
| F-7.1 | **Fixed** | New `put_object_flat_immediate` variant that flushes per-call; background auto-flush task in `EncryptedClient` runs every `AUTO_FLUSH_INTERVAL_SECS`. Existing `put_object_flat_deferred` unchanged. |
| F-7.2 | **Fixed** | `RotationReport` gained an optional `journal_path`; on resume, rewraps already listed as complete (by matching current object `kek_version`) are skipped; journal is deleted on clean completion. |
| F-7.3 | **Fixed** | After a reshard (in both flush-forest and v6 auto-migration paths), old shard keys computed from the prior salt are deleted best-effort once the new manifest is written. |
| F-7.5 | **Fixed** | `save_sharded_forest` and monolithic `save_forest` now use conditional PUT with the prior ETag; 412 → `ClientError::ConcurrentModification`, which evicts the cache and asks the caller to reload + retry. `delete_object_flat` on sharded buckets routes through `flush_forest` so v3/v5→v6 auto-migration also fires on delete-only flows. Server-side: PUT now honors RFC 7232 `If-Match` / `If-None-Match` and returns 412 via `S3ErrorCode::PreconditionFailed` (`crates/fula-cli/src/handlers/object.rs`); the client's retry-on-412 loop is now wired end-to-end. |
| F-1.1, F-1.2, F-1.4 | No change | Per scope; raising the cap and adding a storage-key reverse index are tracked for future work. |
| F-2.3 / F-3.2 / F-4.4 / F-5.x / F-6.1 / F-6.3 | No change | Per scope — no action required. |

**Format-version matrix:**

| Format name | Type | Version tag | Writes produced by this client | Reads still supported |
|-------------|------|-------------|-------------------------------|-----------------------|
| Monolithic (no AAD) | Forest | 1, 2 | No | **Yes** (legacy fallback) |
| Monolithic (AAD) | Forest | 4 | Yes | Yes |
| Sharded (no AAD) | Manifest | 3 | No | **Yes** (auto-migrates to v6 on next flush) |
| Sharded (AAD, legacy routing) | Manifest | 5 | Only during a save that precedes the v3/v5→v6 auto-migration — the subsequent flush writes v6 | **Yes** (auto-migrates to v6 on next flush) |
| Sharded (AAD, directory-aware routing) | Manifest | 6 | **Yes** (new default) | Yes |
| Shard (no AAD) | Shard blob | 1 | No | **Yes** (legacy fallback) |
| Shard (AAD) | Shard blob | 2 | Yes | Yes |

A client that has observed manifest v6 for a bucket will refuse a subsequent v5 response for that bucket (rollback guard backed by `cached_prior_manifest_version`).
