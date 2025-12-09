# Fula Threat Model & Multi-Device Key Management

> **Scope.** This document provides a comprehensive threat model for Fula's encryption system,
> including multi-device key management patterns. It is inspired by WNFS's documentation approach.

---

## Table of Contents

1. [Overview](#1-overview)
2. [Security Goals](#2-security-goals)
3. [Adversary Model](#3-adversary-model)
4. [Protection Analysis by Feature](#4-protection-analysis-by-feature)
5. [What Leaks](#5-what-leaks)
6. [Multi-Device Key Management](#6-multi-device-key-management)
7. [Sharing and Revocation](#7-sharing-and-revocation)
8. [Key Recovery](#8-key-recovery)
9. [Recommended Security Practices](#9-recommended-security-practices)
10. [Comparison with WNFS](#10-comparison-with-wnfs)

---

## 1. Overview

Fula provides client-side encryption for decentralized storage. The core principle is:

> **The storage layer (gateways, IPFS nodes, pinning services) should NEVER have access to plaintext data or encryption keys.**

### Architecture Summary

```
┌─────────────────────────────────────────────────────────────────┐
│                        CLIENT (Trusted)                         │
│  ┌─────────────┐   ┌─────────────┐   ┌─────────────────────┐   │
│  │ Secret Key  │   │ KeyManager  │   │ EncryptedClient SDK │   │
│  │ (User KEK)  │──▶│ (DEK mgmt)  │──▶│   (encrypt/decrypt) │   │
│  └─────────────┘   └─────────────┘   └─────────────────────┘   │
└────────────────────────────────┬────────────────────────────────┘
                                 │ TLS (encrypted transport)
                                 ▼
┌─────────────────────────────────────────────────────────────────┐
│                     GATEWAY (Untrusted)                         │
│  Sees: bucket names, encrypted blobs, timestamps, sizes         │
│  Does NOT see: plaintext, keys, file names, structure           │
└────────────────────────────────┬────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────┐
│                   STORAGE (Untrusted)                           │
│  IPFS nodes, pinning services, S3-compatible storage            │
│  Sees: encrypted content-addressed blobs                        │
└─────────────────────────────────────────────────────────────────┘
```

---

## 2. Security Goals

### Primary Goals

| Goal | Description | Implementation |
|------|-------------|----------------|
| **Confidentiality** | Only authorized users can read data | AES-256-GCM/ChaCha20 + per-file DEKs |
| **Integrity** | Detect any tampering with data | AEAD authentication tags |
| **Metadata Privacy** | Hide file names, structure, sizes | FlatNamespace mode + encrypted PrivateForest |
| **Forward Secrecy** | Past data protected if current key compromised | Ephemeral keys in HPKE key wrapping |
| **Key Isolation** | Compromise of one file's key doesn't affect others | Unique DEK per file |

### Secondary Goals

| Goal | Description | Implementation |
|------|-------------|----------------|
| **Efficient Rotation** | Change keys without re-encrypting data | Re-wrap DEKs only (FileSystemRotation) |
| **Selective Sharing** | Share specific files/folders without master key | ShareToken with HPKE-wrapped DEKs |
| **Revocation** | Remove access from previously shared users | FolderShareManager revocation |
| **Auditability** | Track who has access to what | ShareToken creation timestamps |

---

## 3. Adversary Model

### 3.1 Malicious Storage Provider

**Description:** The IPFS nodes, pinning services, or S3-compatible storage are adversarial.

**Capabilities:**
- Can read all stored data (encrypted blobs)
- Can observe access patterns (when data is read/written)
- Can observe data sizes
- Can refuse to store or serve data (DoS)
- Can modify stored data

**What is Protected:**
- ✅ File contents (encrypted with AES-256-GCM)
- ✅ File names and paths (FlatNamespace mode)
- ✅ Directory structure (encrypted PrivateForest)
- ✅ Integrity (AEAD tags detect modification)

**What Leaks:**
- ⚠️ Encrypted file sizes (approximate)
- ⚠️ Number of files (blobs)
- ⚠️ Access patterns (when blobs are read)
- ⚠️ Creation/modification timestamps

### 3.2 Malicious Gateway Operator

**Description:** The Fula gateway server is adversarial.

**Capabilities:**
- Can observe all API requests
- Can see bucket names and storage keys
- Can see request timing and frequency
- Can see client IP addresses
- Can see encrypted request/response bodies

**What is Protected:**
- ✅ File contents (never decrypted at gateway)
- ✅ Encryption keys (HPKE wrapping happens client-side)
- ✅ File names (FlatNamespace mode)
- ✅ User IDs (hashed before storage)

**What Leaks:**
- ⚠️ Bucket names (S3 API requirement)
- ⚠️ Storage keys (opaque CID-like strings in FlatNamespace)
- ⚠️ Request patterns and timing
- ⚠️ Approximate data sizes

### 3.3 Network Attacker (Passive)

**Description:** An attacker who can observe network traffic.

**Capabilities:**
- Can see encrypted TLS traffic
- Can observe traffic metadata (timing, sizes, endpoints)

**What is Protected:**
- ✅ All data in transit (TLS encryption)
- ✅ Request contents

**What Leaks:**
- ⚠️ Communication patterns (when you access Fula)
- ⚠️ Traffic volume (how much data transferred)
- ⚠️ Gateway endpoint (server addresses)

### 3.4 Network Attacker (Active)

**Description:** A man-in-the-middle attacker.

**Capabilities:**
- All passive capabilities
- Can inject, modify, or drop packets

**What is Protected:**
- ✅ Data integrity (TLS + AEAD prevents undetected modification)
- ✅ Data confidentiality (TLS encryption)
- ✅ Replay attacks (TLS + nonces)

**What Leaks:**
- ⚠️ Communication patterns
- ⚠️ Availability (attacker can DoS)

### 3.5 Compromised Client Device

**Description:** An attacker gains access to the user's device.

**Capabilities:**
- Can read memory and disk
- Can extract secret keys
- Can impersonate the user

**What is Protected:**
- ✅ Files encrypted with different user's keys
- ✅ Past data (if keys have been rotated and old keys deleted)

**What Leaks:**
- ❌ Current user's secret key
- ❌ All data accessible with that key
- ❌ Shared data from other users

### 3.6 Stolen or Lost Device

**Description:** Physical loss of a device.

**Capabilities:**
- Can attempt offline attacks on stored keys
- Can access unencrypted local data

**What is Protected:**
- ✅ Remote data (if device key is revoked)
- ✅ Data encrypted with per-device keys (if rotated)

**What Leaks:**
- ⚠️ Locally cached data
- ⚠️ Keys stored insecurely

**Mitigation:**
- Use device full-disk encryption
- Key rotation after device loss
- Per-device keys (see Multi-Device section)

---

## 4. Protection Analysis by Feature

### 4.1 File Encryption

| Component | Protected By | Against |
|-----------|--------------|---------|
| File content | AES-256-GCM with unique DEK | All adversaries except compromised client |
| File integrity | AEAD authentication tag | Storage/network tampering |
| DEK confidentiality | HPKE wrapping with user KEK | Key extraction |

**Security Level:** AES-256-GCM provides 256-bit security. X25519 provides ~128-bit security.

### 4.2 Metadata Privacy (PrivateForest)

| Component | Protected By | Against |
|-----------|--------------|---------|
| File names | Encrypted in PrivateForest | Storage/gateway observation |
| Directory structure | Encrypted PrivateForest index | Structure inference |
| File sizes | ⚠️ Partially hidden (encrypted size visible) | Limited protection |
| Timestamps | ⚠️ S3 timestamps visible | Not protected |

**FlatNamespace Mode:**
- Storage keys are CID-like (`Qm...`) with no structural hints
- Directory paths are NOT encoded in storage keys
- Server cannot distinguish files from different directories

### 4.3 Sharing (ShareToken)

| Component | Protected By | Against |
|-----------|--------------|---------|
| Shared DEK | HPKE encryption for recipient | Non-recipients |
| Path scope | Encoded in token, validated client-side | Scope expansion |
| Expiration | Timestamp validation | Access after expiry |
| Permissions | Encoded in token | Unauthorized write/delete |
| Snapshot integrity | Content hash binding (Snapshot mode) | Content tampering |

**Secret Links:**
- Key material in URL fragment (never sent to server)
- Gateway only sees opaque ID
- Supports revocation via server-side check

### 4.4 Key Rotation

| Component | Protected By | Against |
|-----------|--------------|---------|
| Forward secrecy | New KEK generated | Future key compromise |
| Old data | DEKs re-wrapped with new KEK | Old key compromise |
| Efficiency | Only DEK wrappers updated | Performance degradation |

---

## 5. What Leaks

This section explicitly documents what information is NOT protected.

### 5.1 To Storage Providers

| Information | Reason | Mitigation |
|-------------|--------|------------|
| Blob count | Required for storage | None (inherent) |
| Blob sizes | Required for storage | Padding (not implemented) |
| Access patterns | Required for retrieval | Mix networks, caching |
| Content hashes (CIDs) | Content addressing | Encrypted content |

### 5.2 To Gateway Operators

| Information | Reason | Mitigation |
|-------------|--------|------------|
| Bucket names | S3 API compatibility | Use random bucket names |
| Request timing | Network protocol | Batching, random delays |
| Client IPs | Network protocol | VPN/Tor |
| User ID hashes | Account management | Already hashed |

### 5.3 To Network Observers

| Information | Reason | Mitigation |
|-------------|--------|------------|
| Traffic volume | Network protocol | Mix networks |
| Connection timing | Network protocol | Always-on connections |
| Gateway endpoints | Network protocol | Multiple gateways |

---

## 6. Multi-Device Key Management

### 6.1 Key Hierarchy

```
User Identity (Master Secret)
       │
       ▼
┌─────────────────┐
│  User KEK       │  ← X25519 keypair, derived from master secret
│  (KekKeyPair)   │
└────────┬────────┘
         │
         ├──────────────────────────────────────────┐
         │                                          │
         ▼                                          ▼
┌─────────────────┐                     ┌─────────────────┐
│  Device A Keys  │                     │  Device B Keys  │
│  (derived)      │                     │  (derived)      │
└────────┬────────┘                     └────────┬────────┘
         │                                       │
         ▼                                       ▼
┌─────────────────┐                     ┌─────────────────┐
│  Per-file DEKs  │                     │  Per-file DEKs  │
│  (wrapped)      │                     │  (wrapped)      │
└─────────────────┘                     └─────────────────┘
```

### 6.2 Recommended Patterns

#### Pattern A: Single Identity, Multiple Devices (Simple)

**Use Case:** Personal user with phone, laptop, tablet.

```rust
// All devices share the same KeyManager/KEK
// Master secret stored securely and backed up

// Device setup
let master_secret = SecretKey::from_bytes(backed_up_secret)?;
let keypair = KekKeyPair::from_secret(master_secret);
let key_manager = KeyManager::new(&keypair);

// All devices use same key_manager
// Files encrypted on one device readable on others
```

**Pros:**
- Simple to implement
- Seamless multi-device access

**Cons:**
- Single point of failure (master secret)
- All devices equally trusted
- No device-specific revocation

#### Pattern B: Per-Device Keys with Shared Access (Recommended)

**Use Case:** Enterprise or security-conscious users.

```rust
// Each device has its own KEK
// Shared files are explicitly granted via ShareToken

// Device A (primary)
let device_a_keypair = KekKeyPair::generate();
let device_a_manager = KeyManager::new(&device_a_keypair);

// Device B (secondary)
let device_b_keypair = KekKeyPair::generate();

// Grant Device B access to specific folders
let share = ShareBuilder::new(
    &device_a_keypair,
    device_b_keypair.public_key(),
    &folder_dek
)
    .path_scope("/shared/")
    .build()?;

// Device B accepts share
let recipient = ShareRecipient::new(&device_b_keypair);
let accepted = recipient.accept_share(&share)?;
```

**Pros:**
- Device-specific revocation
- Granular access control
- Compromised device has limited blast radius

**Cons:**
- More complex setup
- Requires explicit sharing between devices
- More key management overhead

#### Pattern C: Hierarchical Keys with Device Sub-Keys

**Use Case:** Organizations with device management.

```rust
// Master KEK derives device-specific KEKs
// BLAKE3 derivation with device identifier

let master_keypair = KekKeyPair::generate();

// Derive device-specific keys
fn derive_device_key(master: &SecretKey, device_id: &str) -> SecretKey {
    let derived = KeyManager::derive_path_key(
        master.as_bytes(),
        &format!("device:{}", device_id)
    );
    SecretKey::from_bytes(&derived).unwrap()
}

let device_a_secret = derive_device_key(master_keypair.secret_key(), "laptop-001");
let device_b_secret = derive_device_key(master_keypair.secret_key(), "phone-002");
```

**Pros:**
- Centralized master key
- Reproducible device keys
- Can revoke and re-derive

**Cons:**
- Master key compromise affects all devices
- Requires secure device ID management

### 6.3 Key Backup and Recovery

#### Recommended Backup Strategy

```
┌─────────────────────────────────────────────────────────┐
│                    BACKUP STRATEGY                       │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  Master Secret (32 bytes)                               │
│     │                                                    │
│     ├──▶ Paper backup (BIP39 mnemonic)                  │
│     │    - 24 words, stored offline                     │
│     │    - Multiple geographic locations                │
│     │                                                    │
│     ├──▶ Hardware security module (HSM)                 │
│     │    - YubiKey, Ledger, etc.                        │
│     │                                                    │
│     └──▶ Encrypted cloud backup                         │
│          - Password-protected                            │
│          - Different provider than data storage         │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

#### Recovery Procedure

```rust
// From BIP39 mnemonic
let mnemonic = "word1 word2 word3 ... word24";
let seed = bip39_to_seed(mnemonic)?;
let master_secret = SecretKey::from_bytes(&seed[0..32])?;
let keypair = KekKeyPair::from_secret(master_secret);

// Verify by checking public key matches
assert_eq!(keypair.public_key(), expected_public_key);

// Restore KeyManager
let key_manager = KeyManager::new(&keypair);
```

### 6.4 Device Loss Handling

When a device is lost or stolen:

1. **Immediate:** Rotate KEK on remaining devices
2. **Re-wrap:** Use `FileSystemRotation` to re-wrap all DEKs
3. **Revoke:** Remove device from any shared access
4. **Audit:** Review what data the device had access to

```rust
// On remaining device
let mut fs_rotation = FileSystemRotation::new(current_keypair)
    .with_batch_size(100);

// Rotate to new KEK
let new_public_key = fs_rotation.rotate();

// Process all files
while !fs_rotation.is_rotation_complete() {
    let result = fs_rotation.rotate_batch();
    println!("Rotated {} files", result.rotated_count);
}

// Old device's wrapped keys are now useless
```

---

## 7. Sharing and Revocation

### 7.1 Share Lifecycle

```
┌──────────┐   create    ┌──────────┐   transmit   ┌──────────┐
│  Owner   │ ──────────▶ │  Share   │ ───────────▶ │ Recipient│
│          │             │  Token   │              │          │
└──────────┘             └──────────┘              └──────────┘
                              │
                              │ validate
                              ▼
                        ┌──────────┐
                        │  Access  │ ──▶ Read/Write/Delete
                        │  Granted │     (per permissions)
                        └──────────┘
```

### 7.2 Revocation Strategies

#### Time-Based Expiration

```rust
let share = ShareBuilder::new(&owner, recipient.public_key(), &dek)
    .expires_in(3600)  // 1 hour
    .build()?;
```

#### Active Revocation

```rust
let mut manager = FolderShareManager::new(&owner);
manager.create_share("/photos/", recipient.public_key(), &dek, 3600)?;

// Later, revoke
manager.revoke_share("/photos/", recipient.public_key());

// Or revoke all shares
manager.revoke_all_shares();
```

#### Re-Encryption (Nuclear Option)

For complete revocation:
1. Generate new DEK for the folder
2. Re-encrypt all content
3. Update PrivateForest
4. Create new shares for authorized users only

### 7.3 Snapshot vs Temporal Shares

| Mode | Access To | Use Case |
|------|-----------|----------|
| **Temporal** (default) | Latest version | Collaboration, shared folders |
| **Snapshot** | Specific version only | Audit trails, legal holds |

```rust
// Temporal - access evolves with content
let temporal = ShareBuilder::new(&owner, recipient.public_key(), &dek)
    .temporal()
    .build()?;

// Snapshot - frozen to specific state
let snapshot = ShareBuilder::new(&owner, recipient.public_key(), &dek)
    .snapshot_with(content_hash, size, modified_at)
    .build()?;
```

---

## 8. Key Recovery

### 8.1 Recovery Matrix

| Scenario | Recovery Method | Data Loss |
|----------|-----------------|-----------|
| Lost device (backup exists) | Restore from backup | None |
| Lost device (no backup) | Cannot recover | All data |
| Compromised device (detected) | Rotate + restore | None (if rotated in time) |
| Compromised device (delayed) | Rotate + audit | Potentially exposed |
| Forgotten password | Use recovery key/mnemonic | None (if recovery exists) |

### 8.2 Recovery Key Generation

```rust
use rand::RngCore;

// Generate 256-bit master entropy
let mut entropy = [0u8; 32];
rand::rngs::OsRng.fill_bytes(&mut entropy);

// Convert to BIP39 mnemonic (24 words)
let mnemonic = bip39::Mnemonic::from_entropy(&entropy)?;
println!("Recovery phrase: {}", mnemonic.to_string());

// Derive keypair
let seed = mnemonic.to_seed("");
let master_secret = SecretKey::from_bytes(&seed[0..32])?;
let keypair = KekKeyPair::from_secret(master_secret);
```

---

## 9. Recommended Security Practices

### 9.1 For Individual Users

| Practice | Priority | Reason |
|----------|----------|--------|
| Use FlatNamespace mode | **High** | Hides file structure |
| Back up master secret | **High** | Prevent data loss |
| Enable full-disk encryption | **High** | Protect keys at rest |
| Rotate keys annually | Medium | Limit exposure window |
| Use unique bucket names | Medium | Prevent correlation |

### 9.2 For Enterprise Deployments

| Practice | Priority | Reason |
|----------|----------|--------|
| Per-device keys | **High** | Granular revocation |
| HSM for master keys | **High** | Hardware security |
| Audit logging | **High** | Compliance |
| Automatic key rotation | Medium | Policy enforcement |
| Split-knowledge backup | Medium | Prevent insider threat |

### 9.3 For Developers Integrating Fula

| Practice | Priority | Reason |
|----------|----------|--------|
| Never log keys or DEKs | **Critical** | Key exposure |
| Clear keys from memory | **High** | Memory attacks |
| Validate all share tokens | **High** | Prevent bypasses |
| Use authenticated encryption | **High** | Integrity + confidentiality |
| Test key rotation flows | Medium | Ensure recovery works |

---

## 10. Comparison with WNFS

| Aspect | Fula | WNFS |
|--------|------|------|
| **Encryption** | AES-256-GCM + HPKE | AES-256-GCM + custom key derivation |
| **Key Wrapping** | RFC 9180 HPKE | Custom ratcheting protocol |
| **Structure Hiding** | FlatNamespace mode | Name accumulators |
| **Sharing** | ShareToken with path scope | AccessKey (Temporal/Snapshot) |
| **Storage** | S3-compatible | Content-addressed (IPFS) |
| **Index** | PrivateForest (flat or HAMT) | HamtForest |
| **Key Rotation** | DEK re-wrapping | Key ratcheting |
| **Forward Secrecy** | HPKE ephemeral keys | Ratchet protocol |

### Key Differences

1. **Fula prioritizes S3 compatibility** - Works with existing infrastructure
2. **WNFS prioritizes IPFS native** - Deeper content-addressing integration
3. **Fula uses standard HPKE** - RFC 9180 compliant, auditable
4. **WNFS uses custom ratcheting** - More features, more complexity

---

## References

- [RFC 9180 - Hybrid Public Key Encryption](https://www.rfc-editor.org/rfc/rfc9180)
- [WNFS Specification](https://github.com/wnfs-wg/spec)
- [AEAD (RFC 5116)](https://www.rfc-editor.org/rfc/rfc5116)
- [X25519 (RFC 7748)](https://www.rfc-editor.org/rfc/rfc7748)
- [BLAKE3 Hash Function](https://github.com/BLAKE3-team/BLAKE3)

---

*Document Version: 1.0 | Last Updated: December 2024*
