# WNFS vs Fula Encryption Comparison

> **Scope.** This document compares the client‑side encryption and privacy mechanisms in:
>
> - `fula-api` (this repository), specifically `crates/fula-client` and `crates/fula-crypto`.
> - `rs-wnfs` (`E:\GitHub\rs-wnfs`), specifically the private filesystem implementation under `wnfs/src/private`.
>
> Focus areas:
> - Sharing capability
> - Key rotation
> - Security and privacy
> - Speed for large files / deep folder trees
> - Future‑proofing

All observations and examples below are based on *current code* in these repos, not on design intent alone.

---

## 1. Architecture Overview

### 1.1 Fula (fula-api) Encryption Architecture

**Main components (from `crates/fula-crypto` and `crates/fula-client`):**

- `symmetric.rs`
  - AEAD: **AES‑256‑GCM** (default) and **ChaCha20‑Poly1305**.
  - `DekKey` is a 32‑byte symmetric key.
  - 12‑byte random nonces, random per encryption.

- `hpke.rs`
  - Implements **RFC 9180 HPKE**:
    - KEM: `X25519HkdfSha256`.
    - KDF: `HkdfSha256`.
    - AEAD: `ChaCha20Poly1305`.
  - `Encryptor::encrypt_dek` / `Decryptor::decrypt_dek` wrap and unwrap `DekKey`s with AAD binding:
    - DEK wrapping AAD: `"fula:v2:dek-wrap"`.
    - General AAD: caller‑supplied (e.g. includes bucket/key context in tests).
  - `encrypt_for_multiple` supports multi‑recipient DEK wrapping.

- `keys.rs`
  - `DekKey`: 256‑bit content key (symmetric).
  - `SecretKey` / `PublicKey`: X25519 keypair.
  - `KekKeyPair`: root **KEK** (Key Encryption Key) pair for a user.
  - `KeyManager`:
    - Generates random per‑file DEKs.
    - Derives **path‑specific keys** using BLAKE3 (`derive_path_key("fula-path-key-v1", secret || path)`).
    - Tracks a `version` for KEK rotation.

- `private_metadata.rs`
  - `PrivateMetadata` holds sensitive metadata:
    - Original path / key.
    - Actual size.
    - Content type.
    - Creation / modification timestamps.
    - User metadata + optional content hash.
  - `EncryptedPrivateMetadata`:
    - JSON‑serializes `PrivateMetadata` and encrypts it with **AES‑GCM under the per‑file DEK**.
  - `KeyObfuscation` controls how visible storage keys look:
    - `DeterministicHash`: BLAKE3 over `DEK || path`, prefix `e/…`.
    - `RandomUuid`: random ID each upload.
    - `PreserveStructure`: keep directory path, hash only filename.
    - `FlatNamespace`: CID‑like `Qm…` keys via `private_forest::generate_flat_key` (no structural hints).

- `private_forest.rs`
  - Implements **PrivateForest**: an encrypted directory/index structure:
    - `PrivateForest` holds:
      - Either a flat `files: HashMap<String, ForestFileEntry>` (small forests) or a HAMT‑backed `files_hamt: HamtIndex<ForestFileEntry>` for large forests.
      - `directories: HashMap<String, ForestDirectoryEntry>` with direct children.
      - Random `salt` used when generating flat storage keys.
    - Format versioning via `ForestFormat`:
      - `FlatMapV1` (original) and `HamtV2` (HAMT with auto‑migration past a file‑count threshold).
    - `ForestFileEntry::from_metadata` is derived from `PrivateMetadata` and `storage_key`.
  - Storage keys:
    - `generate_flat_key(original_path, dek, salt)` → CID‑like `Qm…` string (no `/` or plaintext hints).
    - `derive_index_key(dek, bucket)` → deterministic CID‑like key for the forest index object itself.
  - `EncryptedForest` JSON‑serializes `PrivateForest`, then encrypts with AES‑GCM under a **forest DEK**:
    - Forest DEK is derived from the root secret via `KeyManager::derive_path_key("forest:<bucket>")`.

- `sharing.rs`
  - `ShareToken`:
    - Contains a **wrapped DEK** (`EncryptedData` from HPKE), `path_scope` (prefix), `expires_at`, `created_at`, `permissions` (`SharePermissions`), and version.
  - `FolderShareManager`:
    - Maintains per‑folder `DekKey`s and a list of active `ShareToken`s.
    - Supports creation, listing, revocation, and validation of folder shares.
  - `ShareRecipient`:
    - Uses recipient's X25519 secret key to unwrap `ShareToken.wrapped_key` via HPKE.
    - Yields an `AcceptedShare` with the folder DEK and permissions.
  - **Gateway integration** (in `EncryptedClient`):
    - `get_object_with_share()` validates expiry, path scope, and permissions before decrypting.
    - `accept_share()` and `get_object_with_token()` provide convenience methods.
    - Sharing is **fully wired into gateway flows** for read operations.

- `rotation.rs`
  - `KeyRotationManager`:
    - Keeps `current_keypair` and optional `previous_keypair`, with versions.
    - Can `rotate_kek()`, `wrap_dek`, `unwrap_dek`, and `rewrap_dek` old→new.
  - `FileSystemRotation`:
    - Tracks `WrappedKeyInfo` per object path.
    - Supports batch and full key rotation across many DEKs without re‑encrypting file contents.
  - **Gateway integration** (in `EncryptedClient`):
    - Object metadata now includes `kek_version` field for tracking which KEK was used.
    - `get_object_kek_version()` reads KEK version from object metadata.
    - `rewrap_object_dek()` re‑wraps a single object's DEK without re‑encrypting content.
    - `rotate_bucket()` rotates all objects in a bucket, returning a `RotationReport`.
    - Key rotation is **fully integrated into the live object metadata and gateway workflows**.

- `streaming.rs` / `hashing.rs` / `chunked.rs`
  - BLAKE3 based hashing and Bao‑style verified streaming: `BaoEncoder`, `BaoDecoder`, `BaoOutboard`.
  - `chunked.rs` implements chunked file encryption metadata (`ChunkedFileMetadata`), `ChunkedEncoder`, `ChunkedDecoder`, and verified streaming decoders.
  - Provides integrity‑checked streaming, chunked upload, and partial reads, and is **now integrated into `EncryptedClient`'s large‑file path**.

- `crates/fula-client/src/encryption.rs`
  - `EncryptionConfig`:
    - Wraps `Arc<KeyManager>` and metadata privacy settings.
    - Default: **metadata privacy enabled + `FlatNamespace` obfuscation**.
  - `EncryptedClient`:
    - Write path (`put_object_encrypted[_with_type]`):
      1. Generate per‑file DEK.
      2. Encrypt payload with AES‑GCM + random nonce.
      3. HPKE‑wrap DEK for owner (X25519 public key).
      4. If metadata privacy:
         - Build `PrivateMetadata`, encrypt with DEK.
         - Compute storage key:
           - Non‑Flat modes: `obfuscate_key(original_path, derive_path_key(path))`.
           - FlatNamespace: via `PrivateForest::generate_key` (CID‑like).
         - Store encrypted private metadata JSON in `x-fula-encryption.private_metadata`.
      5. Upload ciphertext under obfuscated storage key, with `x-fula-encrypted: true` and JSON `x-fula-encryption` metadata.
      6. Optionally send to a remote **IPFS pinning service** using `PinningCredentials`.
    - Read path (`get_object_decrypted[ _by_storage_key ]`):
      - If metadata privacy: recompute storage key from original path using `derive_path_key + obfuscate_key` or via `PrivateForest` in FlatNamespace mode.
      - Fetch object, parse `x-fula-encryption` JSON, HPKE‑unwrap DEK, AES‑GCM decrypt data.
      - Optionally decrypt `EncryptedPrivateMetadata` for original path, size, timestamps, and user metadata.
    - Streaming path for large files (`put_object_chunked`, `get_object_chunked`, `get_object_range`):
      - Splits large files into AES‑GCM‑encrypted chunks uploaded as separate objects under `<storage_key>.chunks/<index>`.
      - Uses an HPKE‑wrapped DEK stored in a small index object under the obfuscated storage key with `x-fula-chunked: true` and version 3 metadata.
      - Supports partial reads and Bao‑verified streaming via chunked metadata and `ChunkedDecoder`/`VerifiedStreamingDecoder`.
    - PrivateForest integration:
      - `load_forest` / `save_forest` transparently maintain a per‑bucket encrypted index object (`x-fula-forest: true`) storing either a flat map or a HAMT‑backed index (with automatic migration for large forests).
      - `put_object_flat`, `list_directory_from_forest`, `get_forest_subtree`, `delete_object_flat` provide complete structure hiding at the server.

**Summary:**

- Strong, modern crypto primitives (AES‑GCM, ChaCha20‑Poly1305, HPKE over X25519, BLAKE3).
- Object‑centric design well suited for gateways and IPFS pinning.
- PrivateForest + FlatNamespace already closely mirrors WNFS‑style structure hiding.
- **Sharing is fully integrated** into `EncryptedClient` with path‑scoped, permission‑checked, expiry‑validated access via `ShareToken`.
- **Key rotation is fully integrated** with `kek_version` in object metadata and `rotate_bucket()` for bulk re‑wrapping.
- **Streaming encryption for large files is now integrated** via chunked uploads, partial reads, and Bao‑verified streaming, while preserving S3/IPFS compatibility.

---

### 1.2 WNFS (rs-wnfs) Encryption Architecture

**Main components (from `wnfs/src/private`):**

- `node/keys.rs`
  - `SnapshotKey([u8; 32])`:
    - Encrypts **node content** (files and relevant data) using **XChaCha20‑Poly1305**.
    - Nonce: 24‑byte `XNonce`, random per encryption.
    - `encrypt` prepends nonce to ciphertext; `decrypt` splits and verifies.
    - Also supports in‑place encryption/decryption for advanced usages.
  - `TemporalKey([u8; 32])`:
    - Derived from a per‑node **skip‑ratchet `Ratchet`**: `TemporalKey::new(&ratchet)` using BLAKE3 `derive_key` with domain separation (`TEMPORAL_KEY_DSI`).
    - Used with **AES‑KWP (AES key wrap with padding)** for authenticated deterministic encryption of high‑entropy materials (headers, keys, etc.).
    - `key_wrap_encrypt` / `key_wrap_decrypt` use `aes_kw::KekAes256`.
  - Derivation constants (domain separation strings):
    - `REVISION_SEGMENT_DSI`: derives a **revision segment** to add to a node’s name per revision.
    - `HIDING_SEGMENT_DSI`: derives a **hiding segment** from content key to obfuscate content base names.
    - `BLOCK_SEGMENT_DSI`: derives per‑block segments for file content blocks.
    - `TEMPORAL_KEY_DSI`, `SNAPSHOT_KEY_DSI`: for key derivation.

- `node/header.rs`
  - `PrivateNodeHeader` holds secret per‑node state:
    - `inumber: NameSegment` – node identity.
    - `ratchet: Ratchet` – per‑node forward‑secrecy state.
    - `name: Name` – private accumulator‑based name of the node.
  - Revision management:
    - `advance_ratchet` increments the ratchet for new revisions.
    - `derive_temporal_key` → `TemporalKey` (per revision).
    - `derive_revision_segment` and `get_revision_name` produce a revision‑specific name.
    - `derive_revision_ref` uses forest’s accumulator and BLAKE3 to derive a label (`HashOutput`) plus `TemporalKey` for this revision.
  - Encryption / decryption:
    - `store`:
      - Serialize a `PrivateNodeHeaderSerializable` containing the inumber, ratchet, and accumulated name.
      - AES‑KWP encrypt with `TemporalKey`.
      - Store ciphertext in blockstore as raw block (CID).
    - `load`:
      - Fetch ciphertext by CID, AES‑KWP decrypt with `TemporalKey`.
      - Validate consistency between deserialized accumulated name and optional parent name (guard against mountpoint mismatches).
  - `seek_unmerged_heads` / `get_multivalue` enable **multi‑head revision discovery**, necessary for conflict resolution and merges.

- `private/encrypted.rs`
  - Generic `Encrypted<T>` wrapper:
    - Stores ciphertext bytes, plus a lazy `OnceCell<T>` cache.
    - `from_value(value, temporal_key)` → DAG‑CBOR encode + AES‑KWP encrypt under `TemporalKey`.
    - `from_ciphertext(ciphertext)` for lazy, on‑demand decryption.
    - `resolve_value(temporal_key)` decrypts and caches.
  - Used throughout to protect node headers and other high‑entropy structures.

- `forest/hamt.rs` + `forest/traits.rs`
  - `HamtForest` implements `PrivateForest` using a **HAMT keyed by name accumulators**:
    - Key type: `NameAccumulator` from `wnfs_nameaccumulator`.
    - Value type: `Ciphertexts(BTreeSet<Cid>)` – links to ciphertexts of private nodes.
    - Backed by `Hamt<NameAccumulator, Ciphertexts, blake3::Hasher>`.
  - Security:
    - Uses a **cryptographic accumulator** (`AccumulatorSetup`) presumably based on RSA‑2048 challenge modulus.
    - Names are **accumulated** and hashed via BLAKE3 for lookups (`blake3::Hasher::hash(&forest.get_accumulated_name(name))`).
    - Server only sees HAMT nodes and CIDs; it cannot derive filesystem structure from key material alone.
  - Functionality:
    - `put_encrypted`, `get_encrypted`, `remove_encrypted` insert / retrieve / remove ciphertext CIDs keyed by accumulated names.
    - `diff` and `merge` allow forest merges with per‑key union of multivalues.
    - Implements `Storable` so the forest itself is serialized/deserialized via the blockstore.

- `keys/access.rs`
  - `AccessKey` enum:
    - `Temporal(TemporalAccessKey)` or `Snapshot(SnapshotAccessKey)`.
    - Each contains:
      - `label: HashOutput` – forest label (hash of accumulated name).
      - `content_cid: Cid` – pointer to encrypted node content.
      - `temporal_key` or `snapshot_key`.
  - Methods:
    - `AccessKey::to_bytes` / `parse` via DAG‑CBOR.
    - `get_label`, `get_temporal_key`, `get_snapshot_key`, `get_content_cid`.
    - `derive_private_ref` builds a `PrivateRef` from a temporal access key.

- `keys/exchange.rs`
  - Abstracts **RSA‑based exchange keys** via traits:
    - `ExchangeKey`:
      - `from_modulus(modulus: &[u8]) -> Future<Output=Result<Self>>`.
      - `encrypt(&self, data: &[u8]) -> Future<Output=Result<Vec<u8>>>`.
    - `PrivateKey`:
      - `decrypt(&self, ciphertext: &[u8]) -> Future<Output=Result<Vec<u8>>>`.
  - Test‑only `RsaPublicKey`/`RsaPrivateKey` implementation:
    - 2048‑bit RSA, exponent 65537, OAEP + SHA‑256.
  - This underpins **asynchronous sharing** via the shared‑private‑data extension.

- `share.rs`
  - Implements the **Shared Private Data Extension**:
    - Goal: asynchronous, store‑and‑forward sharing via public exchange directories.
  - `sharer` module:
    - `share::<K: ExchangeKey>`:
      - Fetches recipients’ exchange public keys (moduli) from their public exchange tree (`PublicLink` pointing to a `PublicDirectory`).
      - For each key:
        - Encrypts serialized `AccessKey` with RSA OAEP using `K::encrypt`.
        - Computes a **share label** under sharer’s private forest: `create_share_name(share_count, sharer_did, recipient_exchange_modulus, forest)`.
        - Stores ciphertext as a raw block (`CODEC_RAW`) and inserts its CID into the private forest at that label.
    - `create_share_name`:
      - Derives a `Name` from: sharer DID, recipient exchange key modulus, and share counter; each hashed into `NameSegment`s.
  - `recipient` module:
    - `find_latest_share_counter` scans for the highest populated share label.
    - `receive_share`:
      - Derives label from sharer DID + recipient exchange key.
      - Reads encrypted `AccessKey` CID from sharer’s private forest.
      - Decrypts with recipient’s RSA private key (`PrivateKey::decrypt`).
      - Deserializes `AccessKey` and converts to `PrivateRef`.
      - Loads `PrivateNode` from sharer’s forest via that `PrivateRef`.

**Summary:**

- Per‑node **ratchet + temporal/snapshot key hierarchy** gives fine‑grained forward secrecy and snapshot‑only sharing.
- HAMT + name accumulator forest offers a powerful, privacy‑preserving index suitable for complex private filesystems.
- Asynchronous shared‑data extension builds on public exchange directories and RSA exchange keys to provide offline/queued sharing.
- Design is oriented around a **general private filesystem** (WNFS), not just object storage.

---

### 1.3 Peergos Encryption Architecture

**Main aspects (from the `Peergos` repo and Peergos documentation):**

- **Stack and deployment model**
  - Peergos is a peer-to-peer encrypted global filesystem and social platform built on **IPFS**.
  - Each user has at least one Peergos server (including an IPFS instance) which stores their encrypted data, mutable pointers, and pending follow requests.
  - Servers and underlying storage (IPFS or S3-compatible services) are treated as **untrusted**; all encryption and verification happen client-side.

- **Content and key encryption**
  - Strong symmetric encryption is performed on the client using **TweetNaCl/libsodium** primitives (XSalsa20-Poly1305 style authenticated encryption).
  - Files are split into ~**5 MiB chunks**, each encrypted independently; two random symmetric keys are generated for every file or directory (explicitly **not convergent encryption**).
  - Login security uses **scrypt** (username + password + salt) to derive a login keypair and symmetric key; encrypted login data then yields identity keypair, social keypair, and root filesystem capability.

- **Data layout and index**
  - Data under a user’s public key is organized as a **Merkle-CHAMP** (hash array mapped trie) of encrypted chunks under random labels.
  - There are no visible cross-links in the storage layout; the server cannot infer file sizes or directory structure from labels alone.

- **Access control and sharing (Cryptree)**
  - Read access is controlled by **Cryptree**, a tree of symmetric keys where possession of a parent key allows decryption of all descendant keys.
  - This enables fine-grained, capability-style access: a capability to a directory gives access to that directory and all descendants.
  - Sharing with other users leverages the social/friend network: once user B follows user A, A can share files or folders with B by granting capabilities.
  - Secret links encode key material in the URL fragment (`#KEY_MATERIAL`), so even the Peergos server never sees the decryption keys.

- **Metadata and social-graph privacy**
  - Peergos encrypts or obfuscates file properties including **names, modification times, MIME types, thumbnails, and directory structure**; without keys, directories are indistinguishable from small files.
  - Friend/follow requests are cryptographically blinded so the server cannot learn the friendship graph; once onion routing is deployed, network observers should also be unable to reconstruct it.

**Summary:**

- Peergos provides a **complete private filesystem + social layer** on top of IPFS with strong end-to-end encryption.
- Cryptree and Merkle-CHAMP structures give fine-grained capabilities and scalable indexing, while hiding metadata and social relationships from servers.
- The design is closer to WNFS (a general private filesystem) than to a pure object-storage gateway like Fula.

---

## 2. Comparative Feature Table

Scores are **1–10**, where 10 is best given typical modern requirements. Scores are relative and assume an attacker controlling the storage provider and network, but not the client device.

| Dimension | Fula (fula-api) | Score | WNFS (rs-wnfs) | Score | Peergos | Score |
| --- | --- | --- | --- | --- | --- | --- |
| **Content encryption primitive** | AES‑256‑GCM (default) or ChaCha20‑Poly1305 under random 256‑bit DEKs. Well‑vetted AEAD with good test coverage (tampering, nonce uniqueness, AAD). | **9** | XChaCha20‑Poly1305 under 256‑bit `SnapshotKey`s; long nonces reduce misuse risk. Also thoroughly tested and modern. | **9** | TweetNaCl/libsodium authenticated encryption (XSalsa20‑Poly1305 style) applied on the client; files are split into independent ~5 MiB chunks, each encrypted with fresh symmetric keys. Mature and widely used primitives. | **9** |
| **Key wrapping / KEK layer** | RFC 9180 HPKE (X25519‑HKDF‑SHA256 + ChaCha20‑Poly1305), AAD‑bound and with multi‑recipient support. Very strong and future‑proof. | **9–10** | AES‑KWP (AES key wrap with padding) under `TemporalKey`s, plus RSA‑OAEP for sharing. AES‑KWP is sound for high‑entropy inputs; RSA‑OAEP is solid but older and less agile than HPKE. | **8** | Cryptree uses a tree of symmetric keys where capabilities carry the necessary keys to decrypt descendants; public-key crypto (Curve25519) is used for identity and login, but there is no distinct HPKE/KWP-style wrapping layer. Strong in practice, but less standardized/agile than HPKE. | **8–9** |
| **Per‑object / per‑node keys** | Per‑object random DEKs, plus BLAKE3 path‑derived DEKs for obfuscation and forest index encryption. Simpler than WNFS ratchets, but adequate for object storage. | **8** | Per‑node **ratchet** → `TemporalKey` → `SnapshotKey`. Every node has its own ratchet state across revisions, giving strong forward secrecy per object and revision. | **9–10** | Two random symmetric keys per file or directory and a Cryptree key hierarchy give each subtree its own key material. Holders of a parent capability can decrypt all descendants; compromise is generally localized to that subtree rather than the entire account. | **9** |
| **Metadata privacy (names, sizes, timestamps)** | `PrivateMetadata` is encrypted with DEK; storage keys are obfuscated (`DeterministicHash`, `RandomUuid`, `PreserveStructure`, or `FlatNamespace` via PrivateForest). Default config provides **complete structure hiding** (FlatNamespace) with encrypted forest index; plaintext sizes & metadata never exposed when privacy is enabled. | **9** | Names are cryptographic `Name`s accumulated and hashed; headers contain inumber and ratchet, encrypted with AES‑KWP. Forest is HAMT keyed by accumulators; server *never* sees plaintext paths or structure. Metadata is strongly hidden; the design is very mature. | **9–10** | Peergos encrypts or obfuscates file properties including names, modification times, MIME types, thumbnails, and directory structure; chunks are stored under random labels so servers cannot deduce file sizes or distinguish files from directories. | **9–10** |
| **Structure hiding / directory privacy** | In FlatNamespace mode, server sees only CID‑like keys for files and forest index; all path structure is encoded in **encrypted `PrivateForest`**. Non‑flat modes can intentionally trade privacy for compatibility (e.g. `PreserveStructure`). | **9** (FlatNamespace) | HAMT forest + name accumulator from the start: all private trees are effectively structure‑hidden; directory structure only exists in encrypted blocks and accumulator state. Very strong by design. | **9–10** | A Merkle‑CHAMP of encrypted chunks under random labels gives strong structure hiding: directories and files both look like small encrypted nodes without cross‑links visible to the server; social graph information is also hidden from storage. | **9–10** |
| **Sharing capability – primitives** | HPKE wrapping of DEKs; `ShareToken` and `FolderShareManager` provide path‑scoped shares with expiry and permissions. **Fully integrated** into `EncryptedClient` via `get_object_with_share()`, `accept_share()`, and `get_object_with_token()`. | **9** | `AccessKey` + RSA‑based `ExchangeKey` + `share.rs` implement asynchronous, store‑and‑forward sharing: sharer writes encrypted access keys to their private forest; recipient scans for them and decrypts. This is **fully wired** into the filesystem model. | **9** | Cryptree capabilities and the social/friend layer provide sharing: once B follows A, A can grant capabilities to files/folders; secret links encode key material after `#` so servers never see decryption keys. Sharing is strongly integrated into the filesystem and social model. | **9** |
| **Sharing – granularity & expressiveness** | Folder‑level sharing via `FolderShareManager` (path prefix + permissions) and per‑file shares. `EncryptedClient` enforces expiry, path scope, and permissions (`can_read`, `can_write`, `can_delete`) at gateway level. Asynchronous/offline sharing semantics could be borrowed from WNFS for enhanced workflows. | **9** | Can share arbitrary private subtrees by exporting `AccessKey`s / `PrivateRef`s; ratchets allow carefully scoped read rights (snapshot vs temporal). Exchange keys are organized per device in public dirs. Better‑specified semantics for multi‑device, offline sharing. | **9–10** | Cryptree allows granting capabilities to arbitrary subtrees (directories or files), with the ability to issue public, secret, or friend-based shares. Very expressive, though revocation still requires re‑keying affected subtrees. | **9** |
| **Key rotation – mechanism** | `KeyRotationManager` + `FileSystemRotation` support KEK rotation and DEK re‑wrapping without re‑encrypting content. **Fully integrated**: object metadata includes `kek_version`, and `EncryptedClient` provides `rewrap_object_dek()` and `rotate_bucket()` for live rotation. | **9** | Ratchet progression inherently provides forward secrecy and "rotation" at node‑revision granularity; there is no central KEK to rotate, but you can rotate private roots and re‑derive structures. Rotation is per‑node/per‑revision, not via a single KEK, which is good for compromise isolation but heavier to orchestrate for "all data" rotations. | **8–9** | Cryptree supports subtree re‑keying by walking and rewriting keys, giving localized recovery from compromise. There is no single KEK layer, so global rotation is heavier operationally, but compromise impact is generally limited to affected subtrees. | **8** |
| **Security & privacy against storage provider** | With FlatNamespace + PrivateForest, provider sees: random‑looking keys, ciphertext sizes, and encrypted index objects flagged only by metadata. AAD usage in HPKE and optional AAD in AEADs defend against context‑swap attacks. Very strong metadata privacy; main leakage is access pattern and ciphertext length. | **9** | WNFS was designed specifically against a very strong storage adversary: accumulators, ratchets, per‑revision labels, HAMT, etc. The provider sees only HAMT nodes and CIDs; neither structure nor evolution of revisions is easy to infer beyond coarse access patterns and object sizes. | **9–10** | Peergos assumes untrusted servers and blockstores: all data and metadata are encrypted client-side; file properties, directory structure, and even much of the social graph are hidden or blinded. Storage nodes see random labels and ciphertext, learning only coarse access patterns and total storage. | **9–10** |
| **Security & privacy in multi‑user sharing** | Multi‑recipient HPKE wrapping and `ShareToken`s with path scopes and permissions. `EncryptedClient` now enforces these via `get_object_with_share()`. Asynchronous sharing protocol (store‑and‑forward) not yet implemented; could borrow from WNFS. | **9** | Multi‑user sharing protocol is **explicitly specified** (shared‑private‑data extension): sharer and recipient roles, exchange directories, share counters, and how `AccessKey`s are created and consumed. Semantics and limitations are clearly laid out in code and spec. | **9** | Peergos protects both shared content and the social graph: follow requests are blinded, capabilities are end-to-end encrypted, and secret links keep keys in URL fragments. Multi-user sharing is strong, though—like WNFS and Fula—true revocation requires re‑keying. | **9** |
| **Performance – large files** | Chunked/streaming encryption via `put_object_chunked`, `get_object_chunked`, and `get_object_range`. Large files are split into AES‑GCM‑encrypted chunks with a small index object, supporting partial reads and Bao‑verified streaming with O(chunk_size) memory and S3/IPFS‑compatible layout. | **9** | WNFS stores file content as blocks in the blockstore and encrypts them with `SnapshotKey`. Block‑level encryption + blockstore streaming scales well to large files, though it adds overhead in many small encrypted blocks. The design is more naturally suited to very big files. | **8–9** | Peergos encrypts files in independent ~5 MiB chunks; this yields good streaming performance on a user’s own server with relatively few chunks per file, but coarser granularity than Fula/WNFS for very fine-grained partial reads. IPFS traffic is moderate because data is typically served from the home server’s IPFS node. | **8–9** |
| **Performance – deep / wide trees** | FlatNamespace + `PrivateForest` now support `ForestFormat::HamtV2` with a HAMT‑backed file index and automatic migration past a file‑count threshold. Tree operations (lookup/insert/remove) scale roughly O(log N), but the forest is still stored as a single encrypted index object per bucket, so very large forests still require fetching that object. | **8** | `HamtForest` is explicitly designed for large forests: HAMT structure, accumulator caching, and streaming store operations. Tree operations scale roughly `O(log N)` in number of nodes, and the forest can be diffed and merged efficiently. | **9** | The Merkle‑CHAMP underlying Peergos is also HAMT-like and scales well to large trees and multi-tenant spaces; directory operations touch only the nodes along the path but can involve multiple storage lookups. This is well-suited to a model where each user has a nearby Peergos+IPFS server. | **9** |
| **Implementation complexity** | Fewer moving parts: single `PrivateForest` structure, straightforward KEK/DEK separation, HPKE, and AES‑GCM. Easier to reason about and integrate into an IPFS gateway. | **8** | Significantly more complex: accumulators, ratchets, HAMT, multivalue heads, async sharing, etc. Very powerful but harder to integrate correctly without following the spec very closely. | **7** | Also complex: Cryptree, Merkle‑CHAMP storage, multi-keypair model (login, identity, social), a PKI log, social graph and messaging, sync, FUSE/WebDAV, etc. Peergos is a full application platform, not just a crypto library. | **7** |
| **Future‑proofing (algorithm agility, extensibility)** | HPKE and BLAKE3 are **very modern** choices. The design already abstracts AEAD algorithm (`AeadCipher`) and HPKE config. PrivateForest and rotation modules leave room for upgrading algorithms and formats by bumping version fields. | **9** | WNFS uses robust primitives (XChaCha20‑Poly1305, BLAKE3, AES‑KWP) and separates many concerns cleanly (forest traits, key derivation DSIs). However, some pieces (RSA‑2048 accumulators, RSA OAEP for sharing) are not as flexible/modern as HPKE. Upgrading those would require protocol migrations. | **8** | Peergos uses well-established primitives (scrypt KDF, NaCl/Curve25519, XSalsa20‑Poly1305) and a capability/cryptree model. There is no HPKE or accumulator setup to migrate, but the rich social and filesystem semantics make large-scale protocol changes non-trivial. | **8** |

**Very rough overall scores (for the current codebases):**

- **Fula encryption subsystem:** **9.0 / 10**
  - Strong primitives and a design tailored to an IPFS/S3‑like gateway.
  - Metadata privacy and structure hiding excellent in FlatNamespace mode.
  - Sharing is now **fully integrated** with permission‑checked, expiry‑validated, path‑scoped access.
  - Key rotation is now **fully integrated** with `kek_version` in object metadata and bulk rotation via `rotate_bucket()`.
  - Remaining gap: asynchronous offline sharing protocol and per‑node ratchet‑style forward secrecy; streaming and HAMT‑style indexing are now implemented.

- **WNFS private filesystem:** **9.2 / 10**
  - Extremely strong model for a general private filesystem, with rich sharing and revision semantics.
  - More complex and opinionated; less directly suited as a drop‑in for a generic pinning gateway but excellent as a filesystem abstraction.

- **Peergos private filesystem + social layer:** **~9.0 / 10**
  - End-to-end encrypted global filesystem and social platform with strong metadata and social-graph privacy.
  - Cryptree and Merkle‑CHAMP provide fine-grained capabilities and scalable indexing, at the cost of considerable implementation complexity.
  - Well-suited to users running their own Peergos server or relying on hosted Peergos instances, less so as a thin library for an external gateway.

---

## 3. Dimension‑by‑Dimension Analysis

### 3.1 Sharing Capability

#### Fula

- **Primitives:**
  - HPKE for multi‑recipient DEK wrapping (`encrypt_for_multiple`).
  - `ShareToken` encapsulating a wrapped DEK, path scope, expiry, and permissions.
  - `FolderShareManager` for managing folder DEKs and associated shares.
  - `ShareRecipient` to unwrap and validate shares.
- **Strengths:**
  - Uses HPKE/X25519, which supports clean multi‑recipient workflows and potential integration with KEM‑based identity schemes.
  - Path‑scoped `ShareToken` with explicit permissions is a good starting point for access control semantics.
- **Gateway integration (now complete):**
  - `get_object_with_share()` validates expiry, path scope, and permissions before decrypting.
  - `accept_share()` and `get_object_with_token()` provide convenience methods.
  - Permissions (`can_read`, `can_write`, `can_delete`) are enforced at read time.
- **Remaining gaps:**
  - No explicit multi‑device story (e.g. device keys, revocation) at the filesystem level.
  - Asynchronous/offline sharing protocol (store‑and‑forward) not yet implemented; could borrow design ideas from WNFS.

#### WNFS

- **Primitives:**
  - `AccessKey` (temporal/snapshot) as the central capability to a private node.
  - RSA‑based `ExchangeKey`/`PrivateKey` abstraction.
  - `share.rs` implements the shared‑private‑data extension:
    - Sharer uses recipients’ exchange directories (public) to find their public keys.
    - For each recipient, sharer encrypts `AccessKey` and writes it into sharer’s private forest under a share label.
    - Recipient searches for share labels, fetches encrypted access key CID, decrypts with own private key, and obtains `AccessKey`.
- **Strengths:**
  - Clearly specified, asynchronous sharing using store‑and‑forward semantics.
  - Works across offline peers and heterogeneous devices.
  - `AccessKey` abstraction is well‑designed: label + CID + key; can be temporal (future revisions) or snapshot (current revision only).
- **Gaps / tradeoffs:**
  - Uses RSA‑OAEP for exchange; large enough and secure, but less agile and more heavyweight than HPKE.
  - Complexity is higher; integrators must respect name‑accumulator, device, and counter semantics.

#### Peergos

- **Primitives:**
  - Capability‑based sharing built on **Cryptree**: a tree of symmetric keys where a parent key decrypts all descendants.
  - Multiple keypairs (login, identity, social) and a PKI log; follow requests are blinded.
  - Secret links encode key material in the URL fragment (`#KEY_MATERIAL`), so even the Peergos server never sees decryption keys.
- **Strengths:**
  - Very natural end‑user sharing semantics (friends, follow requests, public/secret links) with strong cryptographic underpinnings.
  - Fine‑grained subtree capabilities: you can share a directory or file subtree without exposing unrelated data.
- **Gaps / tradeoffs:**
  - Revocation, as in Fula and WNFS, ultimately requires re‑keying affected subtrees.
  - There is no separate, formally specified shared‑private‑data extension like WNFS’s; semantics are defined by the Cryptree capability model and social layer.

**Verdict:**

- All three systems now have **strong, capability‑based sharing** integrated into their core models.
- **WNFS** has the most clearly specified **asynchronous, offline store‑and‑forward protocol** (exchange directories, share counters, explicit roles).
- **Peergos** offers the richest **end‑user sharing experience** (social graph, friend requests, secret links) with strong crypto, but fewer low‑level protocol details published than WNFS.
- **Fula** excels at **synchronous gateway‑based sharing** with modern HPKE primitives and a simple object model; you can still borrow WNFS‑style ideas to add offline semantics.

### 3.2 Key Rotation

#### Fula

- KEK/DEK separation is explicit:
  - `KeyManager` holds a KEK keypair and generates DEKs.
  - `rotation.rs` can rewrap DEKs for a new KEK without touching ciphertext.
- `FileSystemRotation` can:
  - Track `WrappedKeyInfo` per path.
  - Incrementally rotate subsets of files or all files.
  - Cleanly drop old KEKs when rotation completes, enforcing forward secrecy at the KEK level.
- **Gateway integration (now complete):**
  - Object metadata now includes `kek_version` field for tracking which KEK was used.
  - `get_object_kek_version()` reads KEK version from object metadata.
  - `rewrap_object_dek()` re‑wraps a single object's DEK without re‑encrypting content.
  - `rotate_bucket()` rotates all objects in a bucket, returning a `RotationReport` with progress tracking.

#### WNFS

- No explicit KEK layer; instead, each node has a **per‑node ratchet** (`Ratchet`):
  - `TemporalKey` is derived from ratchet state and applied via AES‑KWP.
  - `SnapshotKey` is derived from `TemporalKey` and used to encrypt content.
- Rotating keys is equivalent to:
  - Advancing ratchets or re‑rooting the filesystem.
  - Migrating to new accumulator or blockstore if needed.
- **Security advantage:**
  - Compromise of a `TemporalKey`/`SnapshotKey` generally affects only a specific node/revision, not the entire filesystem.
  - Ratchet comparison and `seek_unmerged_heads` logic allow recovery and merges even after branching revisions.
- **Operational tradeoff:**
  - There is no simple “rotate single KEK and rewrap everything” knob; rotations are tied to evolving ratchet state and can be more complex to coordinate globally.

#### Peergos

- **Cryptree‑centric rotation:**
  - Each file or directory has its own symmetric keys in the Cryptree hierarchy.
  - You can rotate keys for a subtree by re‑encrypting child keys and updating capabilities, limiting blast radius to that subtree.
- **Login and identity keys:**
  - Login keys are derived from `scrypt(username, password, salt)`; login data then yields identity and social keypairs.
  - Changing password or re‑provisioning devices affects login‑level protection; content keys remain protected by Cryptree.
- **Tradeoffs:**
  - Like WNFS, there is no single KEK to flip; global rotation across all data is heavier and requires walking the Cryptree.
  - Compromise is generally localized (per capability or subtree) rather than catastrophic for the whole account.

**Verdict:**

- **Fula** now has a **simple, operationally friendly KEK/DEK rotation** story with `kek_version` in metadata and `rotate_bucket()` for bulk re‑wrapping.
- **WNFS** and **Peergos** both favor **fine‑grained, per‑subtree or per‑node rotation** via ratchets or Cryptree, which improves compromise isolation but makes "rotate everything" operations more complex.
- For **global KEK rotation** after a detected breach, Fula is easiest to operate; for **localized forward secrecy and least‑privilege capabilities**, WNFS and Peergos provide stronger granularity.

### 3.3 Security and Privacy

#### Fula

- Strong primitives:
  - AES‑GCM / ChaCha20‑Poly1305, HPKE (X25519), BLAKE3, Bao.
  - Extensive tests for tampering, nonce uniqueness, AAD binding, etc.
- Metadata privacy:
  - `PrivateMetadata` encrypts filenames, real sizes, timestamps, content type, user metadata, and content hash.
  - `x-fula-encryption` hides everything except ciphertext size and boolean flags.
  - FlatNamespace mode ensures storage keys leak no path structure; only the presence of an index object (`x-fula-forest`) is visible.
- Threats addressed:
  - Malicious storage nodes modifying or truncating ciphertext (detected by AEADs).
  - Storage nodes trying to infer filenames/structure by key prefixes (prevented by FlatNamespace and PrivateForest).
  - Key reuse and context swap attacks (mitigated by random nonces and HPKE AAD binding).
- Remaining leakages:
  - Access patterns (which objects when, and how often) are visible.
  - Ciphertext size and approximate logical size (although real size can be hidden in private metadata if carefully used).

#### WNFS

- Strong primitives as well:
  - XChaCha20‑Poly1305, AES‑KWP, BLAKE3, RSA‑OAEP, name accumulators.
  - Extensive tests, property tests (proptests) for snapshot key encryption/decryption.
- Privacy characteristics:
  - Names are accumulators over hashed name segments; no direct leakage of paths.
  - Revision labels are derived with DSIs from ratchet data; structure over time is hidden beyond access patterns.
  - Private headers and previous pointers are encrypted via AES‑KWP; multi‑head semantics do not leak structure beyond ciphertext existence.
- Additional benefits:
  - Sharing via `AccessKey` and `PrivateRef` is tightly integrated with the same privacy model.
  - Forest diffing and merging operate on hashed names and do not re‑expose paths.
- Remaining leakages:
  - Similar to Fula: access patterns, ciphertext sizes, and the presence of certain types of blocks (HAMT vs content vs header) can be inferred.

#### Peergos

- **Primitives and threat model:**
  - Uses NaCl/Curve25519, XSalsa20‑Poly1305 AEAD, and scrypt for login‑level key derivation.
  - Treats servers, IPFS, and underlying blockstores as untrusted; all encryption and verification are done on the client.
- **Metadata and structure privacy:**
  - Encrypts or obfuscates file and directory names, modification times, MIME types, thumbnails, and directory structure.
  - Stores chunks under random labels in a Merkle‑CHAMP, so the server cannot tell file vs directory or infer file size.
- **Social‑graph privacy:**
  - Follow requests are cryptographically blinded so the server cannot see who is following whom.
  - Planned onion routing aims to hide friendship graphs even from network observers.
- **Leakage:**
  - Similar to Fula and WNFS, remaining leakages are access patterns and coarse ciphertext sizes.

**Verdict:**

- **All three systems provide strong confidentiality and integrity** against the storage provider when used as designed.
- **WNFS** and **Peergos** are more fully specified at the general filesystem and social‑graph level, with carefully designed metadata‑hiding structures.
- **Fula** reaches essentially similar privacy goals for an object‑centric gateway (FlatNamespace + PrivateForest) in a simpler, easier‑to‑integrate form.

### 3.4 Speed for Large Files and Deep Folder Trees

#### Fula

- **Large files:**
  - `EncryptedClient` now supports chunked/streaming encryption via `put_object_chunked`, `get_object_chunked`, and `get_object_range`.
  - Large files are split into AES‑GCM‑encrypted chunks (default 256KB), each stored as a separate object; a small index object under the obfuscated storage key contains HPKE‑wrapped DEK, chunk metadata, and Bao root hash.
  - Memory usage is O(chunk_size) and partial reads only download needed chunks; Bao‑based streaming verification detects corruption during download.
- **Deep/wide trees:**
  - In FlatNamespace mode, **one encrypted PrivateForest object per bucket** still holds all path and directory metadata, but the internal file index can now be HAMT‑backed (`ForestFormat::HamtV2`) for large forests.
  - Listing or walking the tree still requires fetching and decrypting the index object, but internal operations (upserts/lookups) scale better for very large file sets.
  - For huge, multi‑tenant deployments, sharding forests across buckets or further splitting index objects may still be desirable.

#### WNFS

- **Large files:**
  - Files are broken into blocks, each stored as a separate CID in the blockstore and encrypted with `SnapshotKey`.
  - This design supports streaming and partial reads naturally, with decryption per block.
  - Overhead: more round trips and metadata per file, but less memory pressure and better scalability to very large contents.
- **Deep/wide trees:**
  - `HamtForest` is designed for very large forests: HAMT plus accumulator caching, asymptotically good performance for lookups and updates.
  - `diff` and `merge` allow efficient synchronization and conflict resolution in distributed scenarios.

#### Peergos

- **Large files:**
  - Files are encrypted client‑side in independent ~5 MiB chunks using NaCl AEAD, then stored under random labels in the Merkle‑CHAMP.
  - Streaming and partial reads are supported at chunk granularity; memory usage is O(chunk_size), but partial reads are coarser than Fula’s 256KB chunks or WNFS’s smaller blocks.
- **Deep/wide trees:**
  - The underlying Merkle‑CHAMP is HAMT‑like and scales well to very large trees and multi‑tenant spaces.
  - Operations along a path touch only a handful of CHAMP nodes, but each node may require a separate storage lookup.

#### Round‑trip patterns (receiver ↔ storage engine)

- **Fula (gateway ↔ IPFS/S3):**
  - Listing: typically 1 `get` of the encrypted `PrivateForest` index per bucket (cacheable), then purely in‑memory directory walks on the gateway.
  - Read small non‑chunked file: 1 `get` for the object.
  - Read large chunked file: 1 `get` for the small index object + `N` `get`s for the needed chunks, where `N` is proportional to the requested ranges.
- **WNFS (client ↔ blockstore/IPFS):**
  - Listing: several `get`s to traverse `HamtForest` and fetch the directory node (and optionally child headers).
  - Read file: `get`s for HAMT path + directory/file headers + one or more content blocks.
  - Round‑trips per operation are higher, but each block is small and well‑suited to local blockstores.
- **Peergos (Peergos server ↔ IPFS/backing store):**
  - Listing: a few `get`s along the Merkle‑CHAMP path to the directory node and its metadata.
  - Read file: CHAMP path lookups + several chunk fetches (~5 MiB each by default).
  - In typical deployments the Peergos server and its IPFS node are co‑located, so latency for these additional requests is acceptable, but the raw count of back‑and‑forths is still higher than Fula’s single‑object model.

**Verdict:**

- For a **gateway that mainly deals with object‑level put/get** operations to a remote IPFS or S3‑compatible backend, **Fula’s** chunked/streaming support and single‑index‑object forest minimize the number of back‑and‑forths while still supporting partial reads.
- For **very large, deeply nested private filesystems** with many concurrent writers and revisions and richer sync semantics, **WNFS** and **Peergos** benefit from fully sharded HAMT/CHAMP structures at the cost of more individual storage requests per operation.
- In Peergos’s typical "user has their own server" deployment, extra storage round‑trips are mostly local and hidden from the end user, whereas in a thin gateway in front of a remote IPFS cluster, Fula’s lower storage round‑trip count is a practical advantage.

### 3.5 Future‑Proofing

#### Fula

- Uses HPKE and BLAKE3, both designed with algorithm agility and modern cryptographic standards in mind.
- Versioning exists in multiple places (`CRYPTO_VERSION`, `EncryptedPrivateMetadata.version`, `EncryptedForest.version`, HPKE versioning comments), enabling format evolution.
- The KEK/DEK + rotation design will make it feasible to migrate to new KEK types or HPKE suites with minimal disruption to stored ciphertext.

#### WNFS

- Extensively uses DSIs (domain separation identifiers) and typed traits (`PrivateForest`, `ExchangeKey`, `PrivateKey`), which eases future changes.
- However:
  - Accumulator setup currently relies on RSA‑2048 challenge modulus or trusted RSA generation; moving to a different accumulator scheme will likely be a substantial migration.
  - RSA‑based exchange for shared‑private‑data is more cumbersome to upgrade than HPKE‑based designs.

#### Peergos

- Uses well‑established primitives (scrypt KDF, NaCl/Curve25519, XSalsa20‑Poly1305) and a capability/cryptree model instead of HPKE or RSA accumulators.
- There is no global accumulator setup to migrate, but:
  - The rich application semantics (filesystem, social graph, messaging, sync, FUSE/WebDAV) make protocol migrations more complex from an application perspective.
  - Changing core structures like Cryptree or Merkle‑CHAMP would require careful data migration and client updates.

**Verdict:**

- **Fula** has a modest advantage in future‑proofing for a gateway use case due to its **HPKE‑centric**, modular crypto and explicit versioning of formats.
- **WNFS** is still upgradable but will need carefully planned migrations for accumulators and RSA components.
- **Peergos** sits between them: it avoids accumulators and HPKE, relying on long‑lived, battle‑tested primitives, but its broader application surface makes upgrades more involved from an ecosystem point of view.

### 3.6 Encrypted Folder Listing for File Managers

This section focuses on the common "file manager" use case: **listing files in an encrypted folder with names, sizes, timestamps, and content types, without reading or decrypting full file contents.**

#### Fula

- **PrivateForest as a pre‑computed index**
  - `PrivateForest` stores a per‑bucket index of files and directories:
    - `ForestFileEntry` contains original path, storage key, size, content type, timestamps, user metadata, and optional content hash.
  - The entire forest is wrapped in `EncryptedForest` and encrypted once with a forest DEK derived from `KeyManager::derive_path_key("forest:<bucket>")`.
  - The server sees only an opaque forest object (`x-fula-forest: true`) and flat storage keys; all human‑readable paths live inside the encrypted forest.
- **Listing behavior**
  - `EncryptedClient::load_forest` downloads and decrypts the forest index **once** per bucket.
  - `list_directory_from_forest` and `list_files_from_forest` then perform **in‑memory lookups** to produce `DirectoryListing` and `FileMetadata` structs:
    - `original_key`, `original_size`, `content_type`, `created_at`, `modified_at`, `user_metadata`, `is_encrypted`.
  - To render a file manager view (names, icons, sizes, dates), the client only needs to:
    1. Fetch and decrypt the forest index object.
    2. Never touch individual file ciphertexts until the user actually opens a file.
- **Implications**
  - **Pros:**
    - Very fast after the first forest load; directory listings are just hash‑map lookups.
    - Ideal for UI patterns like "load all files in this bucket and sort/filter client‑side".
  - **Cons:**
    - For extremely large buckets (millions of files), the forest index itself can become large; listing any directory requires fetching and decrypting the entire index.

#### WNFS

- **Per‑node metadata and forest indirection**
  - WNFS separates **metadata nodes** from content blocks:
    - Private directories and files are represented as `PrivateNode`s with headers encrypted under `TemporalKey` (AES‑KWP) and content under `SnapshotKey` (XChaCha20‑Poly1305).
    - The `HamtForest` maps name accumulators to ciphertext CIDs for these private nodes.
  - To list a directory, the client:
    1. Uses `HamtForest` to resolve the directory's name accumulator into one or more CIDs.
    2. Fetches and AES‑KWP decrypts the directory node header to obtain child entries (names → `PrivateRef`s).
    3. Optionally fetches child file headers to obtain per‑file metadata (size, timestamps, etc.), **without decrypting file content blocks**.
- **Listing behavior**
  - Listing is localized: only the directory node and relevant HAMT nodes (and perhaps child headers) are loaded and decrypted.
  - For very large trees, this avoids loading a global index; the amount of data touched is proportional to the size of the directory subtree being viewed.
- **Implications**
  - **Pros:**
    - Scales well to very large forests; listing a small directory only touches a small subset of the tree.
    - Clean separation between metadata nodes and content blocks ensures file content is never decrypted during pure listing.
  - **Cons:**
    - Listing a large directory can require multiple blockstore fetches and many small decryption operations (one per node/header).
    - More complex data structures (HAMT + accumulators + ratchets) make implementation and caching more involved.

#### Peergos

- **Cryptree + Merkle‑CHAMP for listing**
  - Peergos also separates metadata and content using Cryptree capabilities and a Merkle‑CHAMP index of encrypted nodes.
  - Directory nodes contain encrypted child metadata (names, types, timestamps, etc.), while content chunks are separate encrypted blobs.
- **Listing behavior**
  - To list a directory, the Peergos client/server walks the Merkle‑CHAMP path to the directory node and decrypts its metadata, without touching file content chunks.
  - As with WNFS, only the directory node and a few CHAMP nodes need to be loaded; file contents remain untouched until the user opens a file.
- **Implications**
  - **Pros:**
    - Scales well to large trees and multi‑tenant spaces; directory listings touch only a small subset of the structure.
    - Strong metadata privacy, including thumbnails and file properties, while supporting rich UI views.
  - **Cons:**
    - More underlying storage lookups per listing than Fula’s single‑index‑object model (though often local to the Peergos server’s IPFS node).

**Verdict:**

- **Fula, WNFS, and Peergos all support metadata‑only listing of encrypted folders** for file‑manager‑style UIs, without decrypting file contents.
- **Fula** optimizes for the gateway/object‑storage model:
  - A single encrypted `PrivateForest` index per bucket gives very fast listings after an initial download/decrypt, especially for small–medium buckets, and minimizes storage round‑trips.
- **WNFS** and **Peergos** optimize for very large, evolving private filesystems:
  - `HamtForest` and Merkle‑CHAMP with per‑node headers let you list only the subtrees you care about, with work proportional to directory size rather than global tree size, at the cost of more fine‑grained storage operations per listing.

---

## 4. Missing or Weaker Features in Fula Compared to WNFS

From a security & feature perspective, the following WNFS capabilities are not (yet) fully present in Fula:

- **1. Asynchronous, offline sharing protocol (store‑and‑forward)**
  - WNFS: complete shared‑private‑data extension, including public exchange directories, share counters, and recipient workflows for offline/queued sharing.
  - Fula: synchronous gateway‑based sharing is now fully integrated (`get_object_with_share()`), but asynchronous offline sharing is not yet implemented. This can be added by borrowing ideas from WNFS.

- **2. Per‑node ratchet‑based forward secrecy**
  - WNFS: each private node has its own `Ratchet` → `TemporalKey` → `SnapshotKey`; compromise of one node's key doesn't expose others.
  - Fula: per‑object DEKs and path‑derived keys are good, but there is no explicit per‑object ratchet notion; forward secrecy relies primarily on KEK rotation and DEK randomness.

- **3. Scalable forest structure for extremely large trees**
  - WNFS: HAMT forest scales gracefully to millions of entries, with diff/merge operations.
  - Fula: `PrivateForest` now supports a HAMT‑backed index (`ForestFormat::HamtV2`) with O(log N) operations, but is still stored as a single encrypted index object per bucket. For extremely large, multi‑tenant trees, WNFS’s fully sharded `HamtForest` remains more scalable.

- **4. Snapshot vs temporal access semantics**
  - WNFS: explicit distinction between `TemporalAccessKey` (future revisions) and `SnapshotAccessKey` (current revision only).
  - Fula: no built‑in notion of "snapshot" vs "temporal" access; the semantics of shares are primarily path‑scoped, not revision‑scoped.

**Previously missing, now addressed:**

- ✅ **Sharing integration**: `get_object_with_share()`, `accept_share()`, and `get_object_with_token()` now fully enforce expiry, path scope, and permissions.
- ✅ **Key rotation integration**: object metadata now includes `kek_version`; `rewrap_object_dek()` and `rotate_bucket()` provide complete rotation workflows.
- ✅ **Streaming encryption for large files**: `put_object_chunked`, `get_object_chunked`, and `get_object_range` implement chunked uploads, partial reads, and Bao‑verified streaming.
- ✅ **HAMT‑backed forest index**: `PrivateForest` now supports `ForestFormat::HamtV2` with `HamtIndex`, auto‑migrated for large forests.

---

## 5. Recommendations for Fula

From a security‑auditor perspective, the following steps would close most of the remaining gaps and may *exceed* WNFS in some areas for an IPFS pinning gateway:

1. ✅ **~~Integrate KEK versioning into object metadata~~** — **DONE**
   - `kek_version` is now included in `x-fula-encryption` JSON.
   - `rewrap_object_dek()` and `rotate_bucket()` provide complete rotation workflows.

2. ✅ **~~Define and implement a concrete sharing protocol using `ShareToken`~~** — **DONE**
   - `get_object_with_share()` validates expiry, path scope, and permissions before decrypting.
   - `accept_share()` and `get_object_with_token()` provide convenience methods.
   - Permissions (`can_read`, `can_write`, `can_delete`) are now enforced at gateway level.

3. ✅ **~~Expose a streaming encrypted upload/download API~~** — **DONE**
   - `put_object_chunked`, `get_object_chunked`, and `get_object_range` provide chunked encryption, partial reads, and Bao‑verified streaming for large files.

4. **Implement asynchronous offline sharing protocol** (remaining)
   - Borrow from WNFS's shared‑private‑data extension for store‑and‑forward sharing semantics.
   - Allows sharing with offline recipients or across heterogeneous devices.

5. **Clarify multi‑device and multi‑user key management** (remaining)
   - Decide how device keys, user KEKs, and rotation are managed (e.g. one `KeyManager` per user identity, separate keys per device, etc.).
   - Provide a stable format for exporting/importing the `SecretKey` that backs `KeyManager::from_secret_key`.

6. ✅ **~~Scale PrivateForest for large deployments~~** (partially DONE)
   - `ForestFormat::HamtV2` and `HamtIndex` provide a HAMT‑backed file index with automatic migration for large forests.
   - Further improvements (e.g., sharding the forest index across multiple objects) can be explored for extreme multi‑tenant scales.

7. **Document threat models and guarantees explicitly** (optional)
   - Borrow from WNFS documentation style: specify attacker models (malicious storage, malicious peer, compromised client), and list what each feature guarantees (and what it doesn't).
   - Helps integrators use the crypto correctly and avoid misconfiguration (e.g. choosing non‑private obfuscation modes in sensitive environments).

---

## 6. Which Implementation Is “Better” for Your Use Case?

**For a gateway with encryption in front of an IPFS pinning service:**

- Fula’s design is **better aligned with your stated goal**:
  - Direct support for S3‑compatible APIs and remote pinning endpoints.
  - Simple, object‑centric encryption model with powerful metadata privacy.
  - HPKE‑based sharing is more naturally integrated into modern ecosystems.
- WNFS is overkill if you only need a secure object store; its complexity makes sense when you need a *full private filesystem* with offline sharing and revisioned directories.

**For a general private filesystem (multi‑device, offline‑capable, rich sharing):**

- WNFS currently has the edge:
  - More complete protocols for sharing and revision management.
  - Well‑designed data structures (HAMT, accumulators, ratchets) for large, evolving trees.
  - Clear semantics for snapshot vs temporal access.

**Overall judgment from a security expert perspective:**

- **Fula**: very strong foundation with modern algorithm choices (HPKE, BLAKE3) and excellent metadata privacy. Sharing and rotation are now **fully integrated**. **Score: ~9.0/10.**
- **WNFS**: more conceptually complete as a private filesystem with rich sharing and revision semantics; slightly older crypto choices in some areas but still robust. **Score: ~9.2/10.**

For your **encrypted IPFS pinning gateway**, I would recommend **keep Fula as the core**, and **adopt specific design ideas from WNFS** (asynchronous offline sharing protocol, per‑node ratchets for fine‑grained forward secrecy, and possibly HAMT‑like forest structures for very large deployments) rather than trying to drop WNFS in wholesale.


---

## 7. Executive Summary Table

| Aspect | Fula (fula-api) | WNFS (rs-wnfs) | Peergos | Recommended Choice for IPFS Pinning Gateway |
| --- | --- | --- | --- | --- |
| **Primary goal / fit** | Encrypted object storage in front of S3/IPFS + pinning services and remote pinning endpoints. | General private filesystem with rich revisioning and offline sharing. | End‑to‑end encrypted global filesystem and social platform built on IPFS, with its own server stack. | **Fula** as core (best match to a thin encryption gateway in front of IPFS/S3). |
| **Crypto primitives** | AES‑256‑GCM / ChaCha20‑Poly1305, HPKE (X25519), BLAKE3, Bao. Very modern and HPKE‑centric. | XChaCha20‑Poly1305, AES‑KWP, BLAKE3, RSA‑OAEP, accumulators. Strong but slightly older in sharing layer. | NaCl/Curve25519, XSalsa20‑Poly1305, scrypt. Robust and widely deployed but without HPKE or accumulator components. | For a gateway, **Fula** has the best balance of modern primitives and integration simplicity. |
| **Metadata & structure privacy** | Encrypted `PrivateMetadata` + `KeyObfuscation`; FlatNamespace + `PrivateForest` hides folder structure from the server. | Name accumulators + HAMT; per‑node headers encrypted with AES‑KWP; directory structure fully hidden. | Encrypts names, modification times, MIME types, thumbnails, and directory structure; random labels in Merkle‑CHAMP hide file sizes and types. | All three are strong; **Fula** is already very good, while **WNFS** and **Peergos** are more fully explored for general filesystems. |
| **Sharing** | HPKE‑wrapped `ShareToken`s, folder‑scoped, with expiry & permissions; **fully integrated** via `get_object_with_share()`. Async/offline flows not yet specified. | `AccessKey` + RSA exchange keys + shared‑private‑data extension for asynchronous, offline sharing. | Cryptree capabilities, blinded friend requests, and secret links (`#KEY_MATERIAL`) for rich user‑level sharing. | For **gateway sharing**, **Fula** is now complete; for **offline protocols**, look to **WNFS**, and for end‑user social flows, **Peergos**. |
| **Key rotation / forward secrecy** | KEK/DEK with `KeyRotationManager` and `FileSystemRotation`; **fully integrated** with `kek_version` in metadata and `rotate_bucket()`. | Per‑node ratchet → `TemporalKey` → `SnapshotKey`; strong forward secrecy at node/revision level. | Cryptree supports subtree re‑keying; login/identity keys can change without re‑encrypting all content. | For **global KEK rotation**, **Fula** is simplest; for **per‑subtree/node forward secrecy**, **WNFS** and **Peergos** are stronger. |
| **Performance – large files** | Chunked/streaming encryption with `put_object_chunked`, `get_object_chunked`, and `get_object_range`; O(chunk_size) memory, partial reads only download needed chunks, S3/IPFS‑friendly layout. | Block‑level encrypted content; excellent for very large files and partial reads, at cost of more blockstore operations. | ~5 MiB encrypted chunks give good throughput from a user’s own server; coarser partial reads than Fula/WNFS but fewer chunks per file. | For a remote IPFS/S3 backend, **Fula** is now comparable to WNFS on large‑file handling with a simpler object API. |
| **Performance – large / deep trees** | Single encrypted `PrivateForest` index per bucket, with optional HAMT‑backed index (`ForestFormat::HamtV2`) for large forests; still one index object per bucket. | HAMT‑based `HamtForest`; scales well to very large private trees and sync scenarios with diff/merge. | Merkle‑CHAMP (HAMT‑like) under each user; scales well to deep and wide trees, especially when each user has their own Peergos server. | For huge multi‑tenant trees in a shared backend, borrow HAMT ideas from **WNFS**/Peergos; Fula’s HAMT‑backed forest improves scaling but still uses a single index object per bucket. |
| **Round‑trips to storage engine (per typical op)** | Low: 1 `get` for forest index (cacheable) + 1 `get` per small file or per needed chunk; ideal when the gateway talks to a remote IPFS/S3 cluster. | Higher: multiple `get`s for HAMT nodes, headers, and blocks per operation; best when client is close to the blockstore. | Higher: multiple `get`s for Merkle‑CHAMP nodes and chunks, typically from a user‑local Peergos+IPFS server. | For minimizing back‑and‑forth between gateway and a remote IPFS/S3 backend, **Fula** clearly wins. |
| **Future‑proofing** | HPKE, BLAKE3, explicit versioning; easier migration to new suites and formats for a gateway. | DSIs and traits help, but accumulators and RSA exchange keys are heavier to migrate. | Uses long‑lived, well‑understood primitives; changes to Cryptree or CHAMP are possible but more invasive at the app level. | **Fula** has a slight edge for gateway deployments; **WNFS** and **Peergos** are upgradeable but with heavier protocol migrations. |
| **Overall security score (this audit)** | ~**9.0 / 10** – strong primitives and design; sharing and rotation now **fully integrated**. | ~**9.2 / 10** – very complete private filesystem model, especially for sharing and revisions. | ~**9.0 / 10** – strong end‑to‑end crypto, excellent metadata and social‑graph privacy, higher complexity. | For a **pinning gateway**, use **Fula** as core and selectively adopt ideas from **WNFS** and **Peergos** where needed. |

---

## 8. Central Authority Reliance for Encryption

This section focuses **only on encryption, decryption, and cryptographic features** — not on IPFS or pinning service availability. The question is: **which features break if a central authority (server, gateway, or trusted third party) is unavailable or compromised?**

### 8.1 Fula

| Feature | Central Authority Required? | Notes |
| --- | --- | --- |
| **Key generation** | ❌ No | `KeyManager::new()` generates keys locally using OS randomness. No server involved. |
| **Content encryption** | ❌ No | AES‑GCM / ChaCha20‑Poly1305 encryption happens entirely on the client. |
| **DEK wrapping (HPKE)** | ❌ No | HPKE wrapping uses local X25519 keys; no trusted third party needed. |
| **Metadata encryption** | ❌ No | `PrivateMetadata` is encrypted locally with the per‑file DEK. |
| **PrivateForest index** | ❌ No | The forest is encrypted locally and stored as a normal object; no special server logic. |
| **Decryption (owner)** | ❌ No | Owner uses local `SecretKey` to HPKE‑unwrap DEK and decrypt content. |
| **Sharing (create ShareToken)** | ❌ No | Sharer wraps DEK for recipient's public key locally; no server mediation. |
| **Sharing (accept ShareToken)** | ❌ No | Recipient decrypts `ShareToken.wrapped_key` locally with own private key. |
| **Share validation (expiry, scope, permissions)** | ⚠️ Partial | If enforced at gateway, relies on gateway; if enforced in client, no central authority. Current implementation enforces in `EncryptedClient` (client‑side). |
| **Share revocation** | ⚠️ Partial | `FolderShareManager::revoke_share()` removes share from local state. If shares are distributed (e.g., via URL), revocation requires re‑keying the folder to truly prevent access. |
| **Key rotation** | ❌ No | `KeyRotationManager` and `rotate_bucket()` operate locally; no trusted server. |
| **Key escrow / recovery** | N/A | Not implemented. User is responsible for backing up `SecretKey`. |
| **Trust assumptions** | Client device | Assumes the client device is not compromised. No trust required in storage provider or gateway for confidentiality. |

**Summary for Fula:**

- **All encryption, decryption, and key management are fully client‑side.** No central authority is required for core crypto operations.
- Share revocation is **weak** without re‑keying: revoking a share from `FolderShareManager` only affects local state. A recipient who already has the `ShareToken` can continue to decrypt unless the folder's DEK is rotated.
- The gateway is only a transport layer for encrypted blobs; it never sees plaintext keys or data.

---

### 8.2 WNFS

| Feature | Central Authority Required? | Notes |
| --- | --- | --- |
| **Key generation** | ❌ No | Keys are generated locally (per‑node ratchets, `TemporalKey`, `SnapshotKey`). |
| **Content encryption** | ❌ No | XChaCha20‑Poly1305 encryption is client‑side. |
| **Key wrapping (AES‑KWP)** | ❌ No | AES key wrap uses local `TemporalKey`; no server involved. |
| **Name accumulator** | ⚠️ Setup | The `AccumulatorSetup` (RSA modulus) must be generated once, ideally via trusted setup or MPC. After setup, no central authority is needed for accumulation. |
| **HamtForest storage** | ❌ No | HAMT nodes are stored as CIDs in a content‑addressed blockstore; no server logic. |
| **Decryption (owner)** | ❌ No | Owner derives keys from ratchet state and decrypts locally. |
| **Sharing (sharer side)** | ❌ No | Sharer encrypts `AccessKey` with recipient's RSA public key locally and stores in own private forest. |
| **Sharing (recipient side)** | ❌ No | Recipient scans sharer's forest for share labels and decrypts with own RSA private key locally. |
| **Share revocation** | ⚠️ Weak | Similar to Fula: once an `AccessKey` is shared, the recipient can access the data. Revocation requires re‑keying (ratchet advancement) and re‑encrypting affected nodes. |
| **Exchange key discovery** | ⚠️ Public directory | Recipients' RSA public keys are stored in public exchange directories. These directories must be accessible, but are not a trusted authority — they are content‑addressed. |
| **Key rotation (ratchet)** | ❌ No | Ratchet advancement is local; no server involvement. |
| **Trust assumptions** | Client device + initial accumulator setup | Assumes client device is not compromised. Accumulator setup requires a one‑time trusted process. |

**Summary for WNFS:**

- **All encryption, decryption, and key management are fully client‑side.** No ongoing central authority is required.
- **Accumulator setup** is a one‑time trust requirement: the RSA modulus must be generated securely (e.g., via MPC or trusted party). After setup, the system is decentralized.
- **Exchange key discovery** uses public directories (content‑addressed), not a trusted server.
- Share revocation is **weak** without ratchet advancement: once an `AccessKey` is shared, revocation requires re‑keying.

---

### 8.3 Comparison Table

| Aspect | Fula | WNFS | Notes |
| --- | --- | --- | --- |
| **Key generation** | Fully local | Fully local | Both use local randomness. |
| **Encryption / decryption** | Fully local | Fully local | No server sees plaintext. |
| **Key wrapping** | HPKE (local) | AES‑KWP (local) | Both client‑side. |
| **Sharing (create)** | HPKE for recipient (local) | RSA OAEP for recipient (local) | Both client‑side. |
| **Sharing (accept)** | Recipient decrypts locally | Recipient decrypts locally | No server mediation. |
| **Share revocation** | Weak (re‑key folder DEK) | Weak (ratchet advancement) | Both require re‑keying to truly revoke. |
| **Key rotation** | `rotate_bucket()` (local) | Ratchet advancement (local) | Both client‑side. |
| **Trust setup** | None | One‑time accumulator setup | WNFS requires trusted RSA modulus generation. |
| **Exchange key discovery** | Out of scope (bring your own) | Public directories (content‑addressed) | WNFS has a specified mechanism. |
| **Features that break without authority** | None (for encryption) | None (for encryption, post‑setup) | Both are fully decentralized for core crypto. |

---

### 8.4 Verdict on Central Authority Reliance

**Both Fula and WNFS are designed for decentralized, client‑side encryption with no ongoing reliance on a central authority for core cryptographic operations.**

Key differences:

- **WNFS** requires a **one‑time trusted accumulator setup** (RSA modulus generation). After that, all operations are decentralized.
- **Fula** has **no trusted setup requirement** — keys are generated locally with no special ceremony.
- Both systems have **weak revocation semantics**: once a share is granted, true revocation requires re‑keying the shared data. This is inherent to capability‑based systems.
- **Exchange key discovery** is explicitly specified in WNFS (via public directories); Fula leaves this to the integrator.

For an IPFS pinning gateway use case:

- **Fula's simpler model** (no trusted setup, HPKE for sharing) is easier to deploy in a decentralized manner.
- If asynchronous offline sharing with public exchange directories is needed, **borrow the WNFS model** for discovery while keeping Fula's HPKE wrapping for the actual key exchange.
