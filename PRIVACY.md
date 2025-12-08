# Privacy Policy & Data Protection

## Overview

Fula API is designed with privacy as a core principle. This document explains what data is encrypted, what remains visible, and potential privacy considerations.

## What Is Encrypted

When using the **Encrypted Client SDK** (recommended for private data):

| Data Type | Encryption Status | Details |
|-----------|------------------|---------|
| **File Content** | ✅ Encrypted | AES-256-GCM or ChaCha20-Poly1305 with per-file DEKs |
| **File Names** | ✅ Encrypted | Stored using cryptographic flat keys (no structure hints) |
| **Directory Structure** | ✅ Hidden | FlatNamespace mode prevents structure inference |
| **File Metadata** | ✅ Encrypted | Content-type, custom headers encrypted |
| **DEKs (Data Encryption Keys)** | ✅ Encrypted | Wrapped with RFC 9180 HPKE using user's KEK |
| **User IDs** | ✅ Hashed | BLAKE3 hashed before storage (audit fix A3) |

## What Is NOT Encrypted

The following metadata **remains visible** to gateway operators and storage nodes:

| Data Type | Visibility | Reason |
|-----------|-----------|--------|
| **Bucket Names** | Visible | Required for S3 API compatibility |
| **Object Sizes** | Approximate | Encrypted size visible (includes AEAD overhead) |
| **Timestamps** | Visible | Created/modified times for S3 compliance |
| **Request Patterns** | Visible | Upload/download timing and frequency |
| **IP Addresses** | Visible | Network-level information |
| **Data Volume** | Visible | Total storage used per bucket |

## Privacy Recommendations

### For Maximum Privacy

1. **Use non-identifying bucket names**
   - ❌ Bad: `john-doe-medical-records`
   - ✅ Good: `b7f4a2e8-9c1d-4b3a-8f5e-1a2b3c4d5e6f`

2. **Use the Encrypted Client SDK**
   - Never upload sensitive data via raw S3 tools
   - Always use `EncryptedClient` with FlatNamespace mode

3. **Consider padding strategies**
   - If file sizes could reveal information, pad files to standard sizes
   - Example: Pad all files to nearest 1MB boundary

4. **Randomize access patterns**
   - If access timing is sensitive, add random delays
   - Batch uploads/downloads when possible

5. **Use dedicated buckets**
   - Don't mix sensitive and non-sensitive data
   - Use separate buckets for different data classifications

## Threat Model

### Protected Against

- ✅ **Storage Node Operators** - Cannot decrypt file contents
- ✅ **Gateway Operators** - Cannot read encrypted data (with encrypted client)
- ✅ **Network Observers** - TLS protects data in transit
- ✅ **Database Breaches** - All content encrypted client-side
- ✅ **User ID Enumeration** - IDs are hashed before storage

### NOT Protected Against

- ⚠️ **Traffic Analysis** - Request patterns visible to gateway
- ⚠️ **Metadata Correlation** - Bucket names and sizes may reveal information
- ⚠️ **Timing Attacks** - Upload/download times observable
- ⚠️ **Device Compromise** - Keys on compromised devices are vulnerable

## Legal Considerations

This software provides technical privacy protections. However:

1. **No Warranty**: Privacy features are provided "as-is"
2. **User Responsibility**: Users must evaluate if protections meet their requirements
3. **Jurisdiction**: Privacy laws vary by location
4. **Compliance**: Users are responsible for regulatory compliance (GDPR, HIPAA, etc.)

## Data Retention

- **Encrypted Content**: Stored on IPFS until explicitly deleted
- **Metadata**: Retained in gateway database until bucket deletion
- **Logs**: Configurable retention (default: no sensitive data logged)
- **IPFS Note**: Due to IPFS content-addressing, data may persist on other nodes

## Security Audit Status

This implementation has been security audited. Key findings addressed:

- ✅ User IDs hashed for privacy (Finding A3)
- ✅ RFC 9180 HPKE for key wrapping (Finding #4)
- ✅ AAD binding prevents ciphertext swapping (Finding #5)
- ✅ No sensitive data in logs (Finding #2)

## Contact

For privacy concerns or security issues, please contact the project maintainers.

---

*Last Updated: December 2024*
