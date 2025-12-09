# Feature Additions Inspired by WNFS and Peergos

This document captures a set of concrete feature ideas to further enhance Fula while **preserving its current advantages** (simple object model, low backend round‑trips, HPKE‑based sharing, single encrypted `PrivateForest` per bucket).

For each idea we describe:

- **What it is**
- **Practical advantages for Fula**
- **High‑level implementation steps** (where in Fula this would live)
- **Reference implementations** in WNFS or Peergos to study

---

## ✅ 1. Async/Offline Sharing on Top of HPKE + ShareToken + Inbox — **IMPLEMENTED**

### What it is

Introduce an **asynchronous, store‑and‑forward sharing workflow** where a sharer writes encrypted share descriptors into a recipient’s "inbox" in storage. The recipient can later discover and accept these shares without the sharer or gateway being online at the same time.

Fula keeps:

- HPKE‑based `ShareToken` format
- Single encrypted `PrivateForest` per bucket
- Low number of backend requests per normal read/write

### Practical advantage for Fula

- **Offline and cross‑device sharing:** recipients can pick up new shares later, similar to how WNFS does with exchange directories.
- **Better user experience:** enables "send now, recipient opens later" semantics with no online coordination.
- **Preserves current performance model:** normal reads/writes remain simple object ops; async sharing adds small metadata objects only.

### High‑level implementation steps (in Fula)

- **Define an inbox location**
  - Decide on a per‑user or per‑bucket inbox convention, e.g.:
    - A dedicated bucket such as `inbox/<user-id>` managed by `EncryptedClient`.
    - Or a prefix like `".fula/inbox/"` in an existing bucket.
  - Represent inbox entries either:
    - In `PrivateForest` (recommended, for privacy), or
    - As separate encrypted objects whose locations are themselves in the forest.

- **Extend `ShareToken` usage**
  - Keep `ShareToken` as the payload for rights:
    - HPKE‑wrapped DEK, `path_scope`, expiry, permissions, etc.
  - Define a small **`ShareEnvelope`** structure containing:
    - The `ShareToken`
    - Optional sharer identity / display name
    - Optional message/label

- **Sharer flow (writer API in `EncryptedClient`)**
  - New methods, e.g.:
    - `enqueue_share_for_recipient(recipient_id, envelope)`
  - Steps:
    1. Construct `ShareToken` (existing API).
    2. Wrap it in `ShareEnvelope`.
    3. Serialize and encrypt `ShareEnvelope` under a per‑recipient inbox key (could be path‑derived from recipient’s public info or HPKE to recipient).
    4. Write an inbox entry in recipient’s inbox location via `PrivateForest` and `put_object_flat`.

- **Recipient flow (reader API in `EncryptedClient`)**
  - New methods, e.g.:
    - `list_incoming_shares()`
    - `accept_incoming_share(envelope_id)`
  - Steps:
    1. Use `load_forest` and inbox prefix to list new inbox entries.
    2. Download and decrypt each envelope.
    3. Extract `ShareToken` and feed into existing `accept_share()` / `get_object_with_token()` flows.

- **Security and revocation**
  - Clarify how long inbox entries live and how they are pruned.
  - Re‑use existing `ShareToken` expiry and permissions checks.

### Reference implementations to study

- **WNFS**
  - `wnfs/src/private/share.rs`
    - `share.rs::sharer::share::<K: ExchangeKey>` – how sharers write encrypted `AccessKey`s into a forest.
    - `share.rs::recipient::receive_share` – how recipients locate and decrypt shares.
  - `wnfs/src/private/keys/access.rs`
    - `AccessKey` structure and representation of capabilities.

- **Fula (current)**
  - `crates/fula-crypto/src/sharing.rs`
    - `ShareToken`, `SharePermissions`, validation helpers.
  - `crates/fula-client/src/encryption.rs`
    - `get_object_with_share()`, `accept_share()`, `get_object_with_token()`.
  - `crates/fula-crypto/src/private_forest.rs`
    - How `PrivateForest` stores index entries and how to integrate an inbox namespace.

**Implementation:** `crates/fula-crypto/src/inbox.rs`
- `ShareEnvelope` - Container for ShareToken + metadata (label, message, sharer info)
- `InboxEntry` - HPKE-encrypted envelope stored in recipient's inbox
- `InboxEntryStatus` - Pending, Read, Accepted, Dismissed, Expired
- `ShareInbox` - Manager for inbox operations (enqueue, list, accept, dismiss)
- `ShareEnvelopeBuilder` - Fluent API for creating envelopes
- `INBOX_PREFIX` = `"/.fula/inbox/"` - Storage location convention
- 10 unit tests for complete workflow
- Documentation added to `docs/website/security.html`

---

## ✅ 2. Snapshot vs Temporal Share Modes (WNFS‑Style Semantics) — **IMPLEMENTED**

### What it is

Add a **mode flag** to `ShareToken` that distinguishes between:

- **Snapshot shares** – allow read access only to the *current* version of an object or subtree at the time of sharing.
- **Temporal shares** – allow continuous access to the *latest* version under a path as it evolves.

### Practical advantage for Fula

- **Finer control over what recipients see over time**:
  - Share "this exact file as it is now" vs "this folder and any future updates".
- **Clearer expectations and auditability**:
  - Easier to reason about what a long‑lived share does, especially for compliance.

### High‑level implementation steps (in Fula)

- **Extend `ShareToken`**
  - Add a new enum or flag, e.g. `ShareMode` with variants `Snapshot` and `Temporal`.
  - Extend `SharePermissions` or add a new field, e.g. `mode: ShareMode`.

- **Define how snapshot semantics are checked**
  - For `Snapshot` mode, bind the share to a specific object state. Options:
    - Include a **content hash** (e.g. BLAKE3) of the file in `ShareToken`.
    - Or include a **storage key + size + modification timestamp** triple.
  - In `get_object_with_share()`:
    - After locating the object for `path_scope`, verify that the metadata still matches the snapshot data.
    - If it does not match, either reject or require an explicit override.

- **Preserve Temporal semantics as default**
  - Existing behavior (`path_scope` + permissions) becomes `Temporal`.
  - Only new snapshot shares set the stricter checks.

### Reference implementations to study

- **WNFS**
  - `wnfs/src/private/keys/access.rs`
    - `AccessKey` enum: `Temporal(TemporalAccessKey)` vs `Snapshot(SnapshotAccessKey)`.
    - How snapshot vs temporal references are constructed and used.
  - `wnfs/src/private/share.rs`
    - How shared capabilities are created and consumed with temporal vs snapshot semantics.

- **Fula (current)**
  - `crates/fula-crypto/src/sharing.rs`
    - Current `ShareToken` definition and helpers.
  - `crates/fula-client/src/encryption.rs`
    - `get_object_with_share()`, `get_object_with_token()` – ideal place to enforce snapshot checks.

---

## 3. Shallow Cryptree‑Style Subtree Keys for Better Revocation

### What it is

Adopt a **shallow Cryptree‑inspired key hierarchy**: allocate separate DEKs for major subtrees (folders) so that:

- Sharing a folder only exposes the subtree key.
- Revoking that share only requires re‑keying the subtree, not the whole bucket.

This is a **shallow** tree (e.g. one level per top‑level folder or per application namespace), not a deep Cryptree on every directory.

### Practical advantage for Fula

- **Improved revocation:** if a share is leaked, you can rotate keys for just that subtree instead of rotating the entire bucket.
- **Least privilege:** a subtree share cannot be escalated into access to unrelated data.
- **Low overhead:** still keep a single `PrivateForest` object and the same basic object layout.

### High‑level implementation steps (in Fula)

- **Extend `FolderShareManager` and key management**
  - Introduce the notion of **subtree DEKs** for key prefixes (e.g. `/appA/*`, `/appB/*`).
  - Store subtree DEK metadata inside `PrivateForest` (e.g. in directory entries) so the mapping from path prefix → DEK is encrypted.

- **On write (`put_object_flat` / `put_object_encrypted`)**
  - Determine which subtree DEK applies based on path.
  - Use that DEK for content encryption and for encrypting `PrivateMetadata`.

- **On subtree share**
  - `FolderShareManager` issues a `ShareToken` referring to the subtree key instead of per‑file DEKs.

- **On subtree revocation**
  - Add a helper to **re‑key** one subtree:
    - Generate a new subtree DEK.
    - Re‑encrypt only files under that subtree (or rewrap DEKs if you keep an extra layer).
    - Update `PrivateForest` entries.

### Reference implementations to study

- **Peergos**
  - `book.peergos.org/security/cryptree.html`
    - Conceptual description of Cryptree (tree of symmetric keys).
  - `E:\GitHub\Peergos\src\peergos\shared\user\fs\cryptree\` (Java package)
    - `CryptreeNode` and related classes – how key hierarchies are represented.

- **Fula (current)**
  - `crates/fula-crypto/src/sharing.rs`
    - `FolderShareManager` and how folder DEKs are handled today.
  - `crates/fula-crypto/src/private_forest.rs`
    - `ForestFileEntry`, directory entries – where subtree key metadata can be stored.
  - `crates/fula-client/src/encryption.rs`
    - `put_object_flat`, `list_directory_from_forest` – integration points for subtree DEKs.

---

## 4. Secret‑Link URL Patterns (Key Material Only in Fragment)

### What it is

Refine Fula’s share links so that **all sensitive key material is kept in the URL fragment (`#...`)**, which is never sent to the server, while the path and token identifier seen by the server remains opaque.

### Practical advantage for Fula

- **Stronger guarantee that gateways never see key material**, even for shared links.
- Cleaner integration with browsers and web apps:
  - Frontend router parses the fragment and passes keys only to the client library.
- Easy to reason about from a threat‑model and privacy perspective.

### High‑level implementation steps (in Fula)

- **Define a share URL format**
  - For example:
    - `https://gateway.example/fula/share/<opaque-id>#<base64url-encoded-client-payload>`
  - Server (gateway) sees:
    - `/fula/share/<opaque-id>` only.
  - Client payload in fragment contains:
    - Serialized+encoded `ShareToken`, or
    - An HPKE‑encrypted envelope from which `ShareToken` is derived.

- **Gateway behavior**
  - Resolve `<opaque-id>` to minimal server‑side info (e.g. logging, rate limits, optional revocation list) but **not** to DEKs.
  - Delegate actual decryption to the client using the payload from the fragment.

- **Client behavior (`fula-client`)**
  - Provide helpers to:
    - Parse share URLs.
    - Decode fragment payload into `ShareToken` or equivalent structure.
    - Call `get_object_with_token()` as today.

### Reference implementations to study

- **Peergos**
  - `README.md` section on links
    - Describes links like `https://demo.peergos.net/#KEY_MATERIAL`.
  - Peergos web UI / client code paths that parse the URL fragment and reconstruct capabilities.

- **Fula (current)**
  - `crates/fula-crypto/src/sharing.rs`
    - `ShareToken` format – what needs to live in the fragment.
  - Any existing HTTP/API layer that exposes shares – where to plug in URL composition and parsing.

---

## 5. Document Multi‑Device and Threat Model (WNFS‑Style Docs)

### What it is

Produce explicit documentation (similar to WNFS’s book) describing:

- Supported **threat models** (malicious storage, network attacker, compromised client).
- **Multi‑device** key management story:
  - How device keys, user KEKs, and rotation interact.
  - How sharing and revocation work across devices.

### Practical advantage for Fula

- **Clarity for integrators and auditors**:
  - Reduces misuse risk (e.g. accidentally using non‑private obfuscation modes in sensitive environments).
- **Guides future changes**:
  - Easier to reason about the impact of new features (like async sharing or subtree keys).

### High‑level implementation steps (in Fula)

- **Threat‑model document** (new or extended under `docs/`)
  - Enumerate adversaries:
    - Malicious storage / pinning providers.
    - Passive/active network attackers.
    - Compromised or stolen client devices.
  - For each Fula feature (metadata privacy, sharing, rotation, streaming) state:
    - What is protected.
    - What still leaks (access patterns, sizes, etc.).

- **Multi‑device key management section**
  - Define recommended patterns:
    - One `KeyManager` per user identity vs per device.
    - How to back up and restore `SecretKey`.
    - How `kek_version` and `rotate_bucket()` behave when a device is lost.

### Reference implementations to study

- **WNFS**
  - `book.wnfs.io` (if available) or WNFS docs in `rs-wnfs` repo – overall design and threat model descriptions.
  - WNFS documentation of shared‑private‑data and accumulators.

- **Fula (current)**
  - `docs/wnfs-comparison.md`
    - Already contains a lot of narrative; can be distilled into a threat‑model doc.
  - Any existing docs under `docs/` that describe security assumptions.

This docuemnt should be integrated into current docs/website
---

## 6. Optional Coarse Forest Sharding for Extreme Scale

### What it is

Introduce an **optional** mode for very large, high‑churn deployments where a single `PrivateForest` per bucket becomes too big or too hot to rewrite. Instead of a single index object, you maintain a **small number of forest objects**, partitioned by coarse criteria (e.g. tenant, top‑level prefix).

This is much coarser than WNFS/Peergos’s full per‑node HAMT/CHAMP sharding, and is only intended for extreme cases.

### Practical advantage for Fula

- **Better scaling for huge multi‑tenant buckets** while:
  - Keeping Fula’s **low round‑trip count** (few large objects instead of many tiny ones).
  - Avoiding full rewrite of a single gigantic forest object on every update.

### High‑level implementation steps (in Fula)

- **Partitioning strategy**
  - Define a mapping from logical prefix to forest partition, for example:
    - One forest per tenant/user ID.
    - One forest per first path segment (`/a/*`, `/b/*`, ...), for very large namespaces.

- **Update `PrivateForest` loading/saving**
  - Extend `EncryptedClient::load_forest` / `save_forest` to:
    - Accept a partition identifier.
    - Derive a distinct forest index key per partition (e.g. using `derive_index_key` with partition in the context).

- **Client logic**
  - For most users and buckets, keep the current **single‑forest** behavior.
  - For configured high‑scale buckets, compute the partition from the path and operate on the appropriate forest object.

### Reference implementations to study

- **WNFS**
  - `wnfs/src/private/forest/hamt.rs`
    - How `HamtForest` breaks the forest into many nodes and stores them via the blockstore.
  - `diff`/`merge` logic for large forests.

- **Peergos**
  - `README.md` and architecture docs
    - Description of Merkle‑CHAMP and storage of encrypted chunks under random labels.

- **Fula (current)**
  - `crates/fula-crypto/src/private_forest.rs`
    - `ForestFormat`, `EncryptedForest`, and current single‑object storage.
  - `crates/fula-client/src/encryption.rs`
    - `load_forest`, `save_forest` – where partition awareness would be introduced.

---

This document is intended as a **design backlog** of features to consider. Each item can be implemented independently, and most (1–5) can be added without changing the core storage layout or sacrificing Fula’s existing performance advantages.

# Practical order of implementation

## ✅ 4 – Secret‑link URL patterns — **IMPLEMENTED**
Small, self‑contained, improves guarantees without touching storage.

**Implementation:** `crates/fula-crypto/src/secret_link.rs`
- `SecretLink` - Create and parse share links with key material in URL fragment
- `SecretLinkBuilder` - Fluent API with label and metadata support
- 14 unit tests covering all functionality
- Documentation added to `docs/website/security.html`

## ✅ 2 – Snapshot vs temporal share modes — **IMPLEMENTED**
Clarifies sharing semantics; only touches ShareToken + client logic.

**Implementation:** `crates/fula-crypto/src/sharing.rs`
- `ShareMode` enum with `Temporal` (default) and `Snapshot` variants
- `SnapshotBinding` struct with content_hash, size, modified_at
- `ShareBuilder.snapshot()` and `ShareBuilder.snapshot_with()` methods
- `ShareToken.verify_snapshot()` and `ShareToken.is_snapshot_valid()` helpers
- 12 unit tests for snapshot/temporal functionality
- Documentation added to `docs/website/security.html`

## ✅ 5 – Multi‑device and threat‑model docs — **IMPLEMENTED**
Locks down assumptions and guides later changes.

**Implementation:** `docs/THREAT_MODEL.md` + `docs/website/security.html`
- Comprehensive threat model document with adversary analysis
- Multi-device key management patterns (shared identity, per-device keys)
- Key backup and recovery strategies
- Device loss handling procedures
- Comparison with WNFS security model
- Multi-device section added to security.html

## ✅ 3 – Shallow subtree keys (Cryptree‑inspired) — **IMPLEMENTED**
Internal key‑model improvement; more work but still local.

**Implementation:** `crates/fula-crypto/src/subtree_keys.rs`
- `SubtreeKeyManager` - Manages the key hierarchy with master + subtree DEKs
- `EncryptedSubtreeDek` - Encrypted subtree DEK stored in directory entries
- `SubtreeShareToken` / `SubtreeShareBuilder` - Share subtrees with recipients
- `SubtreeRotationResult` - Rotate subtree keys for revocation
- DEK resolution: most specific subtree prefix match, falls back to master
- 14 unit tests for all functionality
- `ForestDirectoryEntry.subtree_dek` field added for storage
- Documentation added to `docs/website/security.html`

## 6 – Coarse forest sharding (only if needed)
Only if you actually see huge buckets / hot forests.

## 1 – Async/offline sharing (inbox)
Last, since it has the broadest surface and can benefit from the clearer semantics of #2, #3, and #5.
