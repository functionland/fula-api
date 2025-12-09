# Security Audit Report: Fula API Encryption & S3 Compatibility
**Date:** December 8, 2024
**Target:** Fula API (fula-crypto, fula-client, fula-cli)
**Auditor:** Cascade AI

## 1. Executive Summary

This report presents the findings of a security audit conducted on the `fula-api` encryption mechanism and its S3-compatible API implementation. The audit focused on the cryptographic primitives, key management, client-side encryption logic, and the security controls of the S3 gateway.

**Overall Assessment:** The encryption mechanism is robust, utilizing modern, standard algorithms (HPKE, AES-GCM, ChaCha20-Poly1305) and following best practices for key management (key wrapping, zeroization, nonce generation). The S3 API implementation provides good authorization controls but currently lacks support for AWS Signature V4, relying instead on JWT Bearer tokens, which impacts compatibility with standard S3 clients.

## 2. Encryption Mechanism Audit

The encryption logic is primarily implemented in `fula-crypto` and utilized by `fula-client`. It follows a "Trust-No-One" architecture where data is encrypted client-side before transmission.

### 2.1 Cryptographic Primitives
- **Algorithms:** The system correctly uses industry-standard authenticated encryption algorithms:
  - **AES-256-GCM**
  - **ChaCha20-Poly1305**
- **Key Exchange:** Uses **HPKE (RFC 9180)** with `X25519-HKDF-SHA256` for KEM and `HKDF-SHA256` for KDF. This is a modern and secure choice.
- **Randomness:** Uses `OsRng` via `rand_core` for key and nonce generation, ensuring cryptographically secure implementation.

### 2.2 Key Management
- **DEK/KEK Architecture:**
  - A unique **Data Encryption Key (DEK)** is generated for every file.
  - The DEK is wrapped (encrypted) using the user's public key (KEK) via HPKE.
  - This limits the impact of a compromised file key to a single file.
- **Key Protection:** The `zeroize` crate is used to clear sensitive keys from memory when they are dropped, protecting against memory dump attacks.
- **Key Derivation:** Path-dependent keys are derived securely using a root secret, enabling deterministic regeneration of keys for metadata privacy without storing them explicitly.

### 2.3 Metadata Privacy
- **Obfuscation:** The system supports a "FlatNamespace" mode where file paths are obfuscated using `blake3` hashing with a path-derived secret key. This effectively hides the directory structure and filenames from the storage provider while preventing dictionary attacks (since the hash is keyed with a user secret).
- **Private Metadata:** Original filenames, sizes, and timestamps are encrypted into a `PrivateMetadata` structure and stored alongside the file.

### 2.4 Findings
- **Strength:** Implementation of AAD (Additional Authenticated Data) binding in `fula-crypto` prevents ciphertext context swapping attacks.
- **Strength:** Use of ephemeral keys in HPKE ensures forward secrecy for the session keys.
- **Observation:** `x-fula-encryption` metadata (containing the wrapped key and nonce) is stored in the bucket metadata. While the key itself is encrypted, the presence of this metadata confirms the file is encrypted.

## 3. S3 API Audit

The S3 API is implemented in `fula-cli`, acting as a gateway to the underlying IPFS blockstore.

### 3.1 Authentication
- **Current Implementation:** The API uses **JWT Bearer Tokens** in the `Authorization` header.
- **Issue:** Standard S3 clients (AWS CLI, SDKs) use **AWS Signature V4** (HMAC-SHA256 based on request canonicalization).
- **Impact:** The current implementation is **not compatible** with standard S3 tools without modification or a custom client. It forces users to use the `fula-client` or manually construct HTTP requests with JWTs.
- **Recommendation:** Implement AWS Signature V4 validation middleware to ensure true S3 compatibility and enable use of standard ecosystem tools.

### 3.2 Authorization
- **Scope-Based Access:** The system implements fine-grained scopes (`storage:read`, `storage:write`) within the JWTs.
- **Bucket Ownership:** Critical operations (`put_object`, `get_object`, `delete_object`) verify that the authenticated user owns the bucket before proceeding. This prevents unauthorized access to other users' data.
- **Privacy:** User IDs are hashed before being stored as bucket owners, enhancing privacy.

### 3.3 Security Controls
- **Rate Limiting:** Implemented via `governor`, keyed by user ID. This protects against DoS attacks.
- **Input Validation:** Bucket names and object keys are validated against S3 standards (length, allowed characters).
- **CORS:** Configurable CORS support. A warning is logged if `*` is used, alerting administrators to potential risks.
- **Checksums:** Validates `Content-MD5` headers if provided, ensuring data integrity during upload.

## 4. Vulnerabilities & Loopholes

### 4.1 High: Lack of AWS Signature V4 Support
**Description:** The API rejects requests without a Bearer token, meaning it does not support the standard authentication mechanism for S3.
**Risk:** Low security risk (JWT is secure), but High operational/compatibility risk. It breaks the promise of "S3-compatible" for standard clients.
**Mitigation:** Implement a middleware that parses the `Authorization` header for `AWS4-HMAC-SHA256` and validates the signature against the user's secret key (which would need to be stored or derived).

### 4.2 Medium: No Server-Side Encryption Enforcement
**Description:** The encryption is entirely client-side. The server accepts any binary data sent to `PUT /bucket/key`.
**Risk:** If a user uses a standard HTTP client (assuming they have a JWT) and uploads a file without running it through `fula-client`'s encryption logic, the file will be stored in **plaintext** on IPFS.
**Mitigation:**
- **Option A:** Enforce the presence of `x-fula-encrypted: true` header and validate the metadata structure on the server (though the server cannot validate the ciphertext itself without the key).
- **Option B:** Implement Server-Side Encryption (SSE-S3 or SSE-C) where the server handles encryption. However, this contradicts the "Trust-No-One" model.
- **Recommended:** Clearly document that encryption is the client's responsibility and potentially reject objects missing the specific encryption metadata headers if strict policy is desired.

### 4.3 Low: Metadata Visibility
**Description:** While file content and names are encrypted, the *structure* of the encrypted data (ciphertext size, approximate number of files) remains visible to the storage node.
**Risk:** Traffic analysis could potentially infer file types or activities based on size and access patterns.
**Mitigation:** Padding ciphertext to fixed block sizes (e.g., Padme) could reduce size leakage, though it incurs storage overhead.

## 5. Conclusion

The `fula-api` demonstrates a high standard of cryptographic engineering. The decision to use HPKE and separate DEK/KEK architecture provides a robust foundation for secure, decentralized storage. The primary area for improvement lies in the S3 API layer, specifically regarding authentication compatibility. By implementing AWS Signature V4, the API would achieve true interoperability with the S3 ecosystem while maintaining its strong security posture.

**Final Verdict:** **SECURE**, with recommendations for improved compatibility and enforcement.
