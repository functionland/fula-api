# Security Audit: fula-client Encryption -- March 2026

**Audit Date:** 2026-03-06
**Scope:** fula-client client-side encryption (encryption.rs) and fula-crypto cryptographic primitives
**Auditor:** Automated deep review
**Previous Audit:** FULA-AUDIT-005 (February 2026)

---

## 1. Executive Summary

**Core Conclusion: An attacker CANNOT decrypt files without knowledge of the master private key (X25519).** No cryptographic bypass was found. The encryption architecture is sound and correctly implemented.

The audit covered the full encryption path in fula-client and all cryptographic primitives in fula-crypto:

- `crates/fula-client/src/encryption.rs` -- client-side encryption orchestration
- `crates/fula-crypto/src/symmetric.rs` -- AES-256-GCM / ChaCha20Poly1305
- `crates/fula-crypto/src/hpke.rs` -- RFC 9180 HPKE key encapsulation
- `crates/fula-crypto/src/sharing.rs` -- share token and snapshot binding
- `crates/fula-crypto/src/rotation.rs` -- KEK rotation manager
- `crates/fula-crypto/src/chunked.rs` -- chunked encryption for large files
- `crates/fula-crypto/src/private_metadata.rs` -- encrypted metadata
- `crates/fula-crypto/src/private_forest.rs` -- encrypted directory index
- `crates/fula-crypto/src/subtree_keys.rs` -- hierarchical DEK encryption

**Findings:** 6 total (2 MEDIUM, 3 LOW, 1 INFORMATIONAL). None enable decryption bypass.

---

## 2. Architecture Overview

### 2.1 Key Hierarchy (3-Tier)

```
Master Key (X25519 keypair)
    |
    +-- HPKE (X25519-HKDF-SHA256 + ChaCha20Poly1305)
    |       wraps per-file DEKs with AAD "fula:v2:dek-wrap"
    |
    +-- Per-file DEK (256-bit, random via OsRng)
            |
            +-- AES-256-GCM encrypts file content
                (random 12-byte nonce per operation)
```

### 2.2 Encryption Flow (Upload)

1. Generate random 256-bit DEK via `KeyManager::generate_dek()`
2. Generate random 12-byte nonce via `Nonce::generate()` (OsRng)
3. Encrypt file content: `Aead::new_default(&dek).encrypt(&nonce, &data)` (AES-256-GCM)
4. Wrap DEK via HPKE: `Encryptor::encrypt_dek(&dek)` with AAD `fula:v2:dek-wrap`
5. Store ciphertext + wrapped DEK + nonce in object metadata

### 2.3 Decryption Flow (Download)

1. Read `x-fula-encrypted` header to confirm encryption
2. Parse encryption metadata (wrapped DEK, nonce, algorithm)
3. Unwrap DEK via HPKE: `Decryptor::decrypt_dek(&wrapped_dek)` using master private key
4. Decrypt content: `Aead::new_default(&dek).encrypt(&nonce, &ciphertext)`

### 2.4 Additional Layers

- **Metadata Privacy:** `PrivateForest` + `EncryptedPrivateMetadata` hide filenames and directory structure (encrypted with their own DEKs under the same HPKE scheme)
- **Sharing:** DEK is re-encrypted for recipient's public key via HPKE; no content re-encryption needed
- **Key Rotation:** `KeyRotationManager::rotate_kek()` re-wraps existing DEKs under a new keypair without re-encrypting content
- **Chunked Encryption:** Large files split into chunks, each encrypted with the same DEK but unique random nonces (`chunked.rs:244-248`)

---

## 3. Core Conclusion: Why the Master Private Key Is Required

Every file's content is encrypted with AES-256-GCM using a random 256-bit DEK. The DEK is only stored wrapped by HPKE (X25519-HKDF-SHA256 + ChaCha20Poly1305 with AAD). Recovering the DEK requires performing HPKE decapsulation, which requires the X25519 private key.

**No bypass exists because:**

1. **AES-256-GCM is computationally infeasible to break** without the DEK (128-bit security level)
2. **HPKE wrapping binds the DEK to the master key** -- the wrapped DEK cannot be unwrapped without the X25519 private key
3. **Each file uses a unique random DEK** -- compromising one DEK does not reveal others
4. **Nonces are randomly generated via OsRng** -- no nonce reuse risk from deterministic derivation
5. **AAD on DEK wrapping** (`fula:v2:dek-wrap`) prevents repurposing HPKE ciphertexts across contexts
6. **Key material is zeroized on drop** -- `DekKey`, `SecretKey`, and `Aead` all implement `Zeroize`/`ZeroizeOnDrop`

---

## 4. Findings

### F-001: No AAD on Content Encryption [MEDIUM]

**Status:** Deferred (carried forward from FULA-AUDIT-005 C-002)

**Description:** All content encryption calls use `aead.encrypt(&nonce, &data)` without Associated Authenticated Data (AAD). The `encrypt_with_aad()` method exists in symmetric.rs:157 but is never used for content encryption.

**Affected Code:**
- `crates/fula-client/src/encryption.rs:214` -- single-object upload
- `crates/fula-client/src/encryption.rs:932` -- chunked upload fallback
- `crates/fula-crypto/src/chunked.rs:248` -- chunk encryption (ChunkedEncryptor)
- `crates/fula-crypto/src/chunked.rs:461` -- chunk encryption (StreamingChunkedEncryptor)
- `crates/fula-crypto/src/private_metadata.rs:134` -- metadata encryption
- `crates/fula-crypto/src/private_forest.rs:596` -- forest encryption
- `crates/fula-crypto/src/subtree_keys.rs:74` -- subtree DEK encryption

**Contrast:** HPKE DEK wrapping correctly uses AAD (`hpke.rs:261-262`): `self.encrypt_with_aad(dek.as_bytes(), b"fula:v2:dek-wrap")`

**Impact:** Without AAD, ciphertext is not cryptographically bound to its context (e.g., storage key, bucket, chunk index). A malicious server could swap ciphertext blocks between objects or reorder chunks without detection during AES-GCM decryption. This does NOT enable decryption without the key, but undermines integrity guarantees.

**Recommendation:** Add AAD to all `aead.encrypt()` calls binding ciphertext to its context. For file content: `bucket + storage_key`. For chunks: `bucket + storage_key + chunk_index`. This is a breaking change requiring a version bump in encryption metadata.

---

### F-002: Unencrypted Fallback Path in EncryptedClient [MEDIUM]

**Description:** When `EncryptedClient` retrieves an object, it checks for the `x-fula-encrypted` metadata header. If absent, raw data is returned without decryption and without warning.

**Affected Code:**
- `crates/fula-client/src/encryption.rs:341-342` -- `get_object()`: returns raw bytes if not encrypted
- `crates/fula-client/src/encryption.rs:449-457` -- `get_object_decrypted()`: returns raw data wrapped in `DecryptedObjectInfo`
- `crates/fula-client/src/encryption.rs:600-607` -- `head_object_decrypted()`: returns metadata with `is_encrypted: false`

**Impact:** If a malicious storage server strips the `x-fula-encrypted` header and returns plaintext, the client silently accepts it. While this doesn't enable decryption (the server would need the plaintext to substitute), it creates a downgrade vector: an attacker who intercepts a file before encryption could replace the encrypted version on the server, strip the header, and the client would accept the substitution without complaint.

**Recommendation:** Add configuration option `require_encryption: bool` (default `true` on `EncryptedClient`) that rejects objects without encryption headers. Log a warning when unencrypted fallback is used.

---

### F-003: Memory Residency of Sensitive Data [LOW]

**Description:** Some sensitive data structures remain in memory longer than necessary without explicit zeroization.

**Affected Code:**
- `crates/fula-client/src/encryption.rs:149` -- `forest_cache: RwLock<HashMap<String, PrivateForest>>` caches decrypted forest indexes in memory for the lifetime of the `EncryptedClient`
- `crates/fula-client/src/config.rs:11` -- `access_token: Option<String>` stores bearer token as a plain `String` (not zeroized on drop)

**Impact:** If an attacker gains memory read access (e.g., via a memory dump, core dump, or cold boot attack), cached forest data reveals file names and directory structure. The bearer token could be extracted for unauthorized API access. Note: the core cryptographic keys (`DekKey`, `SecretKey`, `Aead`) correctly use `Zeroize`/`ZeroizeOnDrop`.

**Recommendation:**
- Wrap `access_token` in `secrecy::SecretString` or a `Zeroizing<String>` wrapper
- Consider adding a TTL or explicit `clear_cache()` method to the forest cache
- Document the threat model assumption that process memory is trusted

---

### F-004: Share Token Transport Security Is Application Responsibility [INFORMATIONAL]

**Description:** When a file is shared via `ShareToken`, the token contains the DEK re-encrypted for the recipient's public key. The token itself is a serialized data structure that must be transmitted to the recipient. The fula-crypto library does not enforce any transport security for this token.

**Impact:** If share tokens are transmitted over an insecure channel, an eavesdropper who also possesses the recipient's private key can decrypt the shared file. This is by design -- transport security is the application's responsibility -- but it should be documented.

**Recommendation:** Add documentation noting that share tokens must be transmitted over authenticated, encrypted channels (e.g., TLS, end-to-end encrypted messaging).

---

### F-005: Non-Constant-Time Hash Comparison in Snapshot Verification [LOW]

**Description:** Snapshot binding verification uses standard `==` comparison on content hashes, which is not constant-time.

**Affected Code:**
- `crates/fula-crypto/src/sharing.rs:99` -- `self.content_hash == current_hash`
- `crates/fula-crypto/src/sharing.rs:116` -- `self.content_hash == current_hash`

**Impact:** A timing side-channel could theoretically allow an attacker to determine how many leading bytes of a content hash match. Since these are content hashes (not secrets), the practical risk is very low -- an attacker who can measure timing with sufficient precision likely already has more direct attack vectors. However, it violates the principle of constant-time comparison for security-sensitive values.

**Recommendation:** Use `subtle::ConstantTimeEq` or `ring::constant_time::verify_slices_are_equal` for hash comparisons. Low priority given the non-secret nature of content hashes.

---

### F-006: Debug Logging Includes Storage Keys [LOW]

**Description:** Error handling in the file listing path logs storage keys in warning messages.

**Affected Code:**
- `crates/fula-client/src/encryption.rs:696` -- `tracing::warn!("Failed to get metadata for {}: {:?}", obj.key, e)`

**Impact:** When metadata privacy (`FlatNamespace`) is enabled, storage keys are opaque random identifiers, so this is not a direct information leak. However, if metadata privacy is disabled, storage keys contain the original file path, which would be logged in plaintext. In either case, correlating log entries with storage operations could provide metadata to an attacker with log access.

**Recommendation:** Redact or truncate storage keys in log messages, or gate verbose logging behind a debug flag. At minimum, do not log the full key when metadata privacy is enabled.

---

## 5. Attack Model Analysis

### 5.1 Malicious Storage Server

**Can:**
- Read encrypted ciphertext and wrapped DEKs
- Observe access patterns, object sizes, and timing
- Swap or reorder encrypted chunks (see F-001)
- Strip encryption headers to trigger fallback (see F-002)
- Delete or corrupt objects

**Cannot:**
- Decrypt file content (requires master private key for HPKE decapsulation)
- Recover DEKs from wrapped form (HPKE with ChaCha20Poly1305)
- Forge valid ciphertext (AES-256-GCM authentication tag)

### 5.2 Malicious Share Recipient

**Can:**
- Decrypt files explicitly shared with them (by design)
- Read shared file content and metadata

**Cannot:**
- Access files not shared with them (each share re-encrypts under recipient's key)
- Derive the owner's master private key from a share token
- Access other files using a share token's DEK (DEKs are per-file)

### 5.3 Man-in-the-Middle (Network)

**Can:**
- Observe encrypted traffic (if TLS is compromised)
- Perform traffic analysis on object sizes and timing

**Cannot:**
- Decrypt content (client-side encryption happens before network transmission)
- Modify ciphertext without detection (AES-GCM authentication)

### 5.4 Memory Access Attacker

**Can:**
- Extract cached forest data revealing file structure (see F-003)
- Extract bearer tokens from process memory (see F-003)
- Potentially read DEKs during active encryption/decryption operations

**Cannot:**
- Recover DEKs after operations complete (Zeroize/ZeroizeOnDrop)
- Recover the master secret key after the Decryptor is dropped

---

## 6. Verified Secure Properties

The following cryptographic properties were confirmed as correctly implemented:

1. **Per-file random DEKs** -- each file gets a unique 256-bit key from OsRng (`encryption.rs:209`)
2. **Random nonce generation** -- 12-byte nonces via OsRng, no reuse risk (`symmetric.rs:236-240`)
3. **HPKE with AAD for DEK wrapping** -- AAD `fula:v2:dek-wrap` binds context (`hpke.rs:261-262`)
4. **Key zeroization** -- `DekKey` and `SecretKey` derive `Zeroize + ZeroizeOnDrop`; `Aead` has manual `Drop` impl
5. **Intermediate DEK bytes zeroized** -- `decrypt_dek()` wraps intermediate bytes in `Zeroizing<Vec<u8>>`
6. **No key reuse across rotations** -- `KeyRotationManager::rotate_kek()` rejects double rotation
7. **HPKE follows RFC 9180** -- X25519-HKDF-SHA256 + ChaCha20Poly1305 (version 2)
8. **Chunked encryption uses unique nonces per chunk** -- random nonce per chunk, not derived (`chunked.rs:244`)
9. **Forest cache uses `tokio::sync::RwLock`** -- no poisoning concern (unlike `std::sync::RwLock`)
10. **Fallible constructors available** -- `try_generate()` on `DekKey`, `SecretKey`, `Nonce`, `HybridSecretKey`; `try_encapsulate()` in hybrid KEM
11. **Path key derivation is safe** -- unframed concat is safe because the secret key is always 32 bytes (fixed-length prefix)
12. **`BaoDecoder::track_chunk()` correctly named** -- does not imply verification; only `verify_all()` performs actual verification

---

## 7. Relationship to FULA-AUDIT-005

| FULA-AUDIT-005 ID | Status | This Audit |
|--------------------|--------|------------|
| C-001 | Fixed | Confirmed |
| C-002 (AAD for content encryption) | Deferred | Carried forward as F-001 |
| C-003 | Fixed | Confirmed |
| C-004 | Fixed | Confirmed |
| C-005 | Fixed | Confirmed |
| C-006 | Fixed | Confirmed |
| C-007 (x-fula-forest tag) | Deferred | Still deferred (requires coordinated fix) |
| C-008 | Fixed | Confirmed |
| C-009 | Fixed | Confirmed |
| C-010 | Fixed | Confirmed |
| C-012 | Fixed | Confirmed |
| C-013 | Fixed | Confirmed |

All previously fixed items (C-001, C-003-C-006, C-008-C-010, C-012-C-013) were verified as correctly implemented. The two deferred items (C-002, C-007) remain open.

---

## 8. Recommendations Summary

**Priority order:**

| Priority | Finding | Action | Breaking Change? |
|----------|---------|--------|------------------|
| 1 | F-001 (AAD on content) | Add AAD to all `aead.encrypt()` calls | Yes -- requires metadata version bump |
| 2 | F-002 (Unencrypted fallback) | Add `require_encryption` config option | No |
| 3 | F-003 (Memory residency) | Wrap token in `SecretString`; add cache TTL | No |
| 4 | F-006 (Debug logging) | Redact storage keys in log messages | No |
| 5 | F-005 (Timing on hashes) | Use constant-time comparison | No |
| 6 | F-004 (Share transport) | Document transport security requirement | No |

F-001 is the highest-impact finding but requires a breaking change (new encryption metadata version). Consider bundling with any other breaking changes in a major version release. F-002 through F-006 can be addressed incrementally without breaking compatibility.

---

*End of audit report.*
