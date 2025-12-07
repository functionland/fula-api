Decentralized S3-Compatible Storage Engine: Master Technical Implementation Plan (Revised Edition)
1. Executive Summary
1.1 Architectural Vision and Strategic Imperative
The transition from centralized cloud storage architectures to decentralized, peer-to-peer (P2P) networks represents a fundamental shift in data sovereignty, resilience, and availability. However, this transition is frequently impeded by a lack of interoperability with the entrenched standards of the current cloud ecosystem—specifically, the Amazon Simple Storage Service (S3) API. The objective of this revised Technical Implementation Plan is to define the architecture, engineering specifications, and operational procedures for a Decentralized S3-Compatible Storage Engine. This system is designed to function not merely as a proxy, but as a robust, distributed storage backend that strictly adheres to S3 API semantics while leveraging the immutable, content-addressed nature of the InterPlanetary File System (IPFS) and the resilience of IPFS Cluster.

The core architectural innovation remains the hybridization of a high-performance, stateless Gateway Layer with a decentralized persistence layer underpinned by Prolly Trees (Probabilistic B-Trees) and Conflict-free Replicated Data Types (CRDTs). This approach resolves the historical performance bottlenecks associated with listing large directories in Distributed Hash Tables (DHTs) by implementing verifiable, structurally shared indices that offer O(log n) lookup performance. Furthermore, the system integrates a "Trust-No-One" security model using Hybrid Public Key Encryption (HPKE) for asynchronous, decentralized file sharing and BLAKE3/Bao for verified streaming, ensuring that data integrity and confidentiality are cryptographically guaranteed independent of the storage provider. This revised plan enhances the original by shifting encryption fully to client-side operations, minimizing central server dependencies (with feasibility analysis for GitHub Pages), justifying programming language choices, providing a timeline-free numbered execution plan, detailing production-ready priorities, and incorporating all required benefits such as co-working, sharing with expiry, key rotation, and offline conflict resolution—without losing strengths like detailed S3 API specs, resilience runbooks, and Prolly Tree integration.

1.2 System Objectives and Success Metrics
The implementation is guided by five distinct technical objectives, each with rigorous success criteria:

Objective | Technical Goal | Success Criteria
--- | --- | ---
Strict S3 Compatibility | Replicate S3 API behaviors, including XML schemas and error codes, to support existing SDKs (boto3, AWS JS SDK). | Pass 100% of the minio/mint compatibility suite; accurate XML responses for ListObjectsV2, MultipartUpload, etc.
Verifiable Indexing | Implement Prolly Trees to manage bucket indices, enabling verifiable syncing and efficient delta updates. | O(log n) read/write latency for index operations; verifiable Merkle proofs for directory listings.
Resilient Persistence | Leverage IPFS Cluster with CRDT consensus for data replication and partition tolerance. | Zero data loss with replication factor R=3 during 33% node failure; automatic recovery from split-brain scenarios.
Secure Transport | Integrate BLAKE3 and Bao for streaming verification and HPKE for encrypted sharing. | Detect 100% of bit-flip errors during streaming; sub-second encryption/decryption overhead for GB-scale files.
Real-Time Collaboration | Utilize CRDTs for metadata management to allow concurrent, conflict-free updates. | Deterministic convergence of metadata updates from partitioned nodes using Observe-Remove Sets.

2. System Architecture and Component Design
The architecture is composed of four distinct, loosely coupled layers: the Gateway Layer, the Metadata Layer, the Storage Layer, and the Coordination Layer. This separation of concerns allows for independent scaling of compute (Gateway) and storage (IPFS Cluster), mirroring the elasticity of centralized cloud services while maintaining decentralized principles. Enhancements minimize central dependencies by making gateways optional and storing all authoritative state in IPFS.

2.1 Layer 1: The Gateway Layer
The Gateway Layer serves as the primary interface for client applications. It is a stateless, horizontally scalable HTTP server that translates standard S3 HTTP verbs into complex InterPlanetary Linked Data (IPLD) Directed Acyclic Graph (DAG) manipulations. To enhance decentralization, gateways are optional proxies; advanced clients can interact directly with IPFS via provided SDKs.

- Request Ingestion: The Gateway parses incoming HTTP requests, validating headers (Authorization, x-amz-date, Content-MD5) against S3 specifications.
- Protocol Translation: It converts S3 object keys (e.g., bucket/folder/file.jpg) into IPFS Content Identifiers (CIDs) via the Metadata Layer.
- Stream Processing: For PutObject operations, the Gateway acts as a streaming processor, calculating BLAKE3 hashes and generating Bao trees on the fly before chunking data to the Storage Layer.
- Response Formatting: It constructs strictly compliant XML responses, ensuring that namespaces (xmlns="http://s3.amazonaws.com/doc/2006-03-01/") and error codes map correctly to client expectations.
- Enhancements: Rate limiting (100 requests/second per user via token bucket algorithm, configurable); DDoS mitigation (integrate with optional proxies like Cloudflare or built-in IPFS rate limits + CAPTCHA for high-traffic endpoints); TLS certificate management (automated via Let's Encrypt with certbot renewal scripts in Docker configs).

2.1.1 Rate limiting Implementation example

```
use governor::{Quota, RateLimiter};
use std::num::NonZeroU32;

// Per-user rate limiter (Token Bucket)
pub struct RateLimitMiddleware {
    limiter: RateLimiter<String>,
}

impl RateLimitMiddleware {
    pub fn new() -> Self {
        let quota = Quota::per_second(NonZeroU32::new(100).unwrap());
        Self {
            limiter: RateLimiter::keyed(quota),
        }
    }
    
    pub async fn check(&self, user_id: &str) -> Result<(), RateLimitError> {
        self.limiter.check_key(user_id).map_err(|_| {
            RateLimitError {
                code: "SlowDown",
                retry_after: 1, // seconds
            }
        })
    }
}

// Integration with Axum
async fn rate_limit_handler(
    State(limiter): State<RateLimitMiddleware>,
    headers: HeaderMap,
    next: Next,
) -> Response {
    let user_id = extract_jwt_sub(&headers).unwrap_or_default();
    match limiter.check(&user_id).await {
        Ok(_) => next.run(request).await,
        Err(e) => {
            let xml = format!(
                r#"<?xml version="1.0"?>
                <Error>
                  <Code>{}</Code>
                  <Message>Please reduce your request rate</Message>
                </Error>"#,
                e.code
            );
            (StatusCode::TOO_MANY_REQUESTS, xml).into_response()
        }
    }
}
```


2.2 Layer 2: The Metadata Layer (Hybrid Architecture)
To achieve the low latency required by the S3 protocol (where ListObjects is expected to return in milliseconds) while maintaining decentralization, the system employs a hybrid metadata architecture, enhanced for minimal central storage.

- Hot Index (In-Memory Cache with Redis Fallback): An in-memory cache (with optional Redis for multi-gateway sync via pub/sub) acts as a read-through cache for bucket states, multipart upload parts, and user permissions. This allows for complex queries required for features like prefix filtering and delimiter grouping in ListObjectsV2. Only ephemeral data (e.g., multipart states expiring after 24 hours) is stored; no PII or keys.
- Cold/Immutable Index (Prolly Trees): The authoritative state of every bucket is stored as a Prolly Tree in IPFS. This Merkle-based B-Tree structure allows for efficient comparison and synchronization. Periodically, the cache is "flushed" to the Prolly Tree, generating a new Root CID that represents the bucket's state at that version.
- Synchronization: Gateways subscribe to IPFS PubSub topics to listen for updates to Prolly Tree roots. When a root changes (e.g., a write via another Gateway), the local cache is invalidated and updated via a diff of the Prolly Trees.
- Enhancements: Support for millions of nested files/folders without speed loss (tune Prolly Tree node size to 4KB, use HAMT fallbacks for deep nesting; O(log n) operations ensure no computation increase); offline work (clients cache local diffs, sync on reconnect via PubSub); automatic conflict resolution/merge (CRDTs for metadata, LWW or manual forks for content).

2.3 Layer 3: The Storage Layer (IPFS Cluster)
The persistent storage of raw data blocks is handled by a swarm of IPFS nodes managed by IPFS Cluster.

- Data Distribution: Files are chunked into 256KB blocks (standard IPFS chunking) or larger blocks for performance optimization, then DAG-ified. Automatic deduplication via CIDs.
- Pinning Strategy: The IPFS Cluster acts as the "Pinset Manager." It ensures that every block referenced by the Prolly Trees is pinned on a configurable number of nodes (R_min=2, R_max=3).
- Consensus: The storage layer utilizes a CRDT-based consensus mechanism for the cluster state. This ensures that the cluster remains available for writes even during network partitions, prioritizing availability (AP in CAP theorem) which aligns with the "eventual consistency" model of S3.
- Enhancements: Large file support (>5GB via multipart, failure recovery with part-level resumes); streaming data (Bao for verified streams); co-working on files (CRDTs like Yjs over PubSub for editable content, LWW for binaries); moving/copying/removing files (update Prolly Tree paths without re-encryption via structural sharing); adding files without full tree re-encryption (encrypt new nodes individually, O(log n) updates).

2.4 Layer 4: The Coordination Layer
This layer manages identity, access control, and peer discovery.

- Identity Provider (IdP): An external OAuth 2.0 provider handles user authentication. The Gateway validates JWTs and maps sub (subject) claims to internal User IDs (hashed for minimal storage).
- Peer Discovery: Libp2p DHT and PubSub mechanisms are used for Gateways to discover Storage Nodes and broadcast index updates.
- Enhancements: Minimal central info (no keys stored); if central server lost, new gateways bootstrap from IPNS bucket roots; GitHub Pages feasibility (use for static SDK docs/OpenAPI specs; not for dynamic APIs due to no compute—gateways run via Docker, anyone can deploy without risk via read-only defaults and signed updates).

2.5 Programming Language Selection
Rust is selected as the primary language for the core implementation, with wrappers for cross-platform support. Justification: Rust offers memory safety (critical for handling encrypted streams without leaks), high performance (zero-cost abstractions for O(1) hashing with BLAKE3), and excellent cross-platform capabilities (compiles to Wasm for web/JavaScript, native binaries for Windows/Mac/Linux, JNI for Android, Swift bindings for iOS). Its ecosystem includes key crates (prollytree for indexing, hpke for encryption, bao-tree for streaming, crdt-lite for consensus). Alternatives like Go lack strong Wasm maturity for web/mobile; Rust enables unified SDKs for all developers (e.g., mobile apps via FFI, web via Wasm-bindgen). Provide SDK wrappers: Rust core, with NPM for web, Maven for Android, CocoaPods for iOS, NuGet for Windows.

3. The Indexing Layer: Prolly Trees and Verifiable Listings
The most significant technical challenge in decentralized storage is the "Listing Problem." Standard IPFS directories (UnixFS) are structured as linked lists or Hash Array Mapped Tries (HAMTs). While efficient for retrieval by hash, they perform poorly for sequential iteration (listing keys) and diffing. To solve this, we implement Prolly Trees using the Rust prollytree crate ecosystem.

3.1 Prolly Tree Data Structure
A Prolly Tree (Probabilistic B-Tree) is a hybrid data structure that combines the properties of B-Trees and Merkle Trees.
- Probabilistic Balancing: Unlike standard B-Trees which split nodes based on a fixed number of elements, Prolly Trees split nodes based on a rolling hash (e.g., Rabin Fingerprint or Buzhash) of the entry content. If the hash of a key-value pair matches a specific pattern (e.g., the lower N bits are zero), a boundary is created.
- Structural Sharing: Because boundaries are content-defined, inserting a new key into a Prolly Tree only affects the path from the leaf to the root. Neighboring nodes and subtrees remain identical (same CID), allowing for massive deduplication between bucket versions.
- Ordering: Keys are sorted lexicographically, allowing for efficient range queries (ListObjects with prefix and start-after).

3.2 Rust Implementation and Integration
The implementation utilizes the prollytree crate, customized for IPLD storage backends.

3.2.1 Node Schema
Each node in the Prolly Tree is serialized as a DAG-CBOR block containing:
- entries: A list of (Key, Value) pairs.
- children: A list of CIDs pointing to child nodes (if not a leaf).
- is_leaf: Boolean flag.

The Value stored in the tree is a rich metadata struct:

```rust
struct ObjectMetadata {
    cid: Cid,               // The raw data root
    size: u64,              // File size in bytes
    etag: String,           // S3 ETag (usually MD5)
    last_modified: i64,     // Unix timestamp
    storage_class: String,  // e.g., STANDARD, IA
    user_metadata: HashMap<String, String>, // x-amz-meta-* headers
    encryption_info: Option<EncryptionMetadata>, // For client-side HPKE details (e.g., encapsulated_key)
}
```

3.2.2 Indexing Workflow
- Ingest: When a PutObject completes, the Gateway constructs the ObjectMetadata.
- Load: The Gateway loads the current Bucket Root CID from the cache (or IPFS if cache miss).
- Mutate: The prollytree library performs the insert/update operation, generating new CIDs for the affected path.
- Flush: The new Root CID is calculated.
- Broadcast: The new Root CID is published to the bucket-updates PubSub topic and updated in the cache.

3.3 Merging and Conflict Resolution
In a distributed system, two Gateways might update the same bucket concurrently. Prolly Trees support efficient 3-way merging.
- Scenario: Gateway A updates Root R_base → R_A. Gateway B updates R_base → R_B.
- Detection: When Gateway A receives R_B via PubSub, it detects a divergence from its local state.
- Merge Function: Calculate the diff between R_A and R_base. Calculate the diff between R_B and R_base. Apply both sets of changes.
- Collision Handling: If both modified the same key, apply Last-Write-Wins (LWW) based on the last_modified timestamp in the ObjectMetadata struct. For co-working, use CRDTs (e.g., Yjs) for mergeable content.

4. S3 Compatibility Specification: API & Schemas
To ensure seamless integration with the existing ecosystem, the Gateway must strictly adhere to the S3 XML response schemas. Deviations here are the primary cause of SDK failures (e.g., boto3 throwing parsing errors). Definitive S3 API operation list with priorities:

Priority | Operation | Description
--- | --- | ---
1 (Blocker) | PutObject, GetObject, DeleteObject, ListObjectsV2, CreateBucket, DeleteBucket | Core storage ops; must support client-side encryption metadata.
1 (Blocker) | HeadObject, CopyObject | Metadata retrieval and efficient copies via CID sharing.
2 (Critical) | CreateMultipartUpload, UploadPart, CompleteMultipartUpload, AbortMultipartUpload | Large file handling with resumes.
2 (Critical) | ListMultipartUploads, ListParts | State inspection.
3 (Important) | GetObjectTagging, PutObjectTagging, PutBucketPolicy | Metadata and access control.

4.1 ListObjectsV2 Implementation
The ListObjectsV2 operation is critical for browsing content. It must emulate hierarchical directories using the CommonPrefixes element.

4.1.1 Request Handling
The Gateway translates S3 parameters to Prolly Tree queries:
- prefix: Limits the Prolly Tree cursor to keys starting with this string.
- start-after / continuation-token: Seeks the cursor to the specific key before beginning iteration.
- delimiter: (Usually /) Used to group keys. The Prolly Tree iteration logic must "skip" over keys sharing the same prefix after the delimiter, aggregating them into a single CommonPrefix result.

4.1.2 XML Response Schema
The response must use the namespace http://s3.amazonaws.com/doc/2006-03-01/.
Response Example (Success):

```xml
<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
    <Name>distributed-bucket-01</Name>
    <Prefix>photos/</Prefix>
    <KeyCount>3</KeyCount>
    <MaxKeys>1000</MaxKeys>
    <IsTruncated>false</IsTruncated>
    <Contents>
        <Key>photos/beach.jpg</Key>
        <LastModified>2025-12-07T01:42:00.000Z</LastModified>
        <ETag>"b2419b1e3fd45d596ee22bdf62aaaa2f"</ETag>
        <Size>2048576</Size>
        <StorageClass>STANDARD</StorageClass>
        <Owner>
            <ID>79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be</ID>
            <DisplayName>owner-name</DisplayName>
        </Owner>
    </Contents>
    <CommonPrefixes>
        <Prefix>photos/2024/</Prefix>
    </CommonPrefixes>
    <CommonPrefixes>
        <Prefix>photos/2025/</Prefix>
    </CommonPrefixes>
</ListBucketResult>
```

Key Implementation Note: The ETag returned is the stored MD5 hash. If the file was uploaded via a non-S3 path (direct IPFS add), the Gateway might compute a placeholder ETag or strictly enforce MD5 calculation on ingest.

4.2 Multipart Upload (MPU) Persistence
Multipart uploads require state persistence across multiple stateless HTTP requests. The Gateway uses an in-memory cache (with Redis fallback) to track this ephemeral state before the final merge into the Prolly Tree.

4.2.1 Database Schema for MPU
The schema must track the global upload state and the individual parts. Exact column definitions:

```sql
CREATE TABLE multipart_uploads (
    upload_id VARCHAR(255) PRIMARY KEY,
    bucket_name VARCHAR(255) NOT NULL,
    object_key TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    metadata JSONB, -- Stores content-type, user-metadata
    owner_id VARCHAR(255) NOT NULL, -- Hashed JWT sub
    acl JSONB,
    INDEX bucket_index (bucket_name), -- For fast queries by bucket
    FOREIGN KEY (owner_id) REFERENCES users(owner_id) ON DELETE CASCADE -- If users table exists for minimal auth mapping
);

CREATE TABLE upload_parts (
    upload_id VARCHAR(255) NOT NULL,
    part_number INT NOT NULL,
    etag VARCHAR(255) NOT NULL,
    size BIGINT NOT NULL,
    cid VARCHAR(255) NOT NULL, -- IPFS CID for this part
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    checksum_blake3 VARCHAR(255), -- For integrity
    PRIMARY KEY (upload_id, part_number),
    FOREIGN KEY (upload_id) REFERENCES multipart_uploads(upload_id) ON DELETE CASCADE,
    INDEX upload_index (upload_id) -- For fast part listing
);
```

Migration scripts (using Diesel in Rust):
- Initial: CREATE TABLES as above.
- Update example: ALTER TABLE upload_parts ADD COLUMN checksum_sha256 VARCHAR(255) IF NOT EXISTS;

4.2.2 CompleteMultipartUpload Logic
Upon receiving the POST request to complete the upload:
- Verification: The Gateway fetches all parts from upload_parts matching the upload_id, sorted by part_number. It verifies that the list of parts and ETags provided in the client's XML body matches the records.
- DAG Construction: Instead of concatenating binaries (which is expensive), the Gateway creates a new IPLD Node (likely a UnixFS file node) that links to the CIDs of the individual parts. This "concatenation by reference" is instant.
- Indexing: The new Root CID is inserted into the Prolly Tree.
- Cleanup: The record is removed from multipart_uploads.
Response Example:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<CompleteMultipartUploadResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
    <Location>https://gateway.decentralized.net/bucket/key</Location>
    <Bucket>bucket-name</Bucket>
    <Key>object-key</Key>
    <ETag>"3858f62230ac3c915f300c664312c11f-9"</ETag>
</CompleteMultipartUploadResult>
```

4.3 CopyObject Implementation
The CopyObject operation allows creating a new object from an existing one. In a content-addressed system, this is highly efficient.
- Logic: The Gateway looks up the source key in the Prolly Tree, retrieves the ObjectMetadata, and inserts a new key pointing to the same CID (no re-encryption needed).
- Response: The response must return the CopyObjectResult with the LastModified time of the new object and the ETag of the content.
Response Example:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<CopyObjectResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
    <LastModified>2025-12-07T02:00:00Z</LastModified>
    <ETag>"9b2cf535f27731c974343645a3985328"</ETag>
</CopyObjectResult>
```

4.4 DeleteObjects Implementation
S3 supports batch deletion with two modes: Verbose and Quiet.
- Logic: "Deletion" in this system is defined as removing the key from the Prolly Tree index (supports subfolders). The actual data blocks on IPFS are not immediately removed. They become "unpinned" (if no other key references them) and are eventually garbage collected by the IPFS Cluster's GC process.
- Verbose Mode: Returns a list of all deleted keys.
- Quiet Mode: Returns only errors.
Response Example (Verbose):

```xml
<?xml version="1.0" encoding="UTF-8"?>
<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
    <Deleted>
        <Key>sample.txt</Key>
        <VersionId>version-id-if-enabled</VersionId>
    </Deleted>
    <Deleted>
        <Key>image.png</Key>
    </Deleted>
    <Error>
        <Key>locked-file.txt</Key>
        <Code>AccessDenied</Code>
        <Message>Access Denied</Message>
    </Error>
</DeleteResult>
```

4.5 Error Handling and Code Mapping
The Gateway must map internal distributed systems errors to standard S3 Error Codes to ensure client retry logic functions correctly. Specifications include:

Internal System Event | S3 Error Code | HTTP Status | Meaning
--- | --- | --- | ---
Prolly Tree key lookup failure | NoSuchKey | 404 | Object not found.
Bucket name already exists in global namespace | BucketAlreadyExists | 409 | Namespace collision.
IPFS Cluster pin: allocation failed | InternalError | 500 | Storage backend full or unavailable.
Upload size > 5GB (single PUT) | EntityTooLarge | 400 | Constraints check.
OAuth token invalid/expired | InvalidToken | 400 | Authentication failure.
Access Control check failure | AccessDenied | 403 | Authorization failure.
Concurrent update conflict (rare) | OperationAborted | 409 | Write conflict.

5. Security Architecture
The security model assumes that storage nodes are "honest-but-curious" or potentially untrusted. Therefore, data privacy and integrity must be enforced by the client before data persists to the network. No central authority or holder for keys; if user loses key, data is irrecoverable (user responsibility).

5.1 Authentication: OAuth 2.0 Integration
The system decouples identity management from storage operations. The Gateway functions as an OAuth 2.0 Resource Server.
- Protocol: Supports standard OAuth 2.0 flows (Authorization Code for users, Client Credentials for machines).
- Token Validation: Gateway receives Authorization: Bearer <token>. Validates signature using the IdP's JWKS (JSON Web Key Set). Checks claims: iss (issuer), exp (expiration), and custom scopes like storage:read, storage:write.
- User Mapping: The sub (subject) claim in the JWT is hashed to generate the internal OwnerID used in the Prolly Tree and cache.
- Enhancements: Audit logging for compliance (signed logs stored in IPFS, e.g., JWT events); penetration testing plan (external audit post-MVP using tools like OWASP ZAP).

5.2 Encryption: Client-Side Hybrid Public Key Encryption (HPKE)
To enable the "Inbox Pattern"—where users can drop files for others without prior key negotiation—we implement HPKE (RFC 9180) fully on the client-side. The main private key never leaves the uploader's device; no keys sent to or stored on the gateway/server.

- Key Management Architecture (KEK/DEK): Clients generate Data Encryption Keys (DEK) locally for file content (AES-256-GCM). Key Encryption Keys (KEK) use HPKE for wrapping DEKs. Users publish HPKE public keys via IPNS (decentralized, no gateway involvement).
- Encryption Flow (Client-Side): Client generates random 256-bit DEK. Encrypts data with DEK. Fetches recipient's public key from IPNS. Uses HPKE to encapsulate DEK, producing Shared_Secret and Encapsulated_Key. Uploads ciphertext + Encapsulated_Key (as x-amz-meta-hpke-enc) to gateway, which stores blindly.
- Decryption Flow: Recipient client authenticates via OAuth, downloads ciphertext + metadata, uses private key to decapsulate DEK, decrypts locally.
- Enhancements: Key rotation (client re-encrypts affected subtrees via Prolly diffs if compromised, updates root CID); sharing files/subfolders (generate links with embedded temporal keys expiring via time-bound ratchets; permissions via signed capabilities—read/write without root access via isolated sub-roots); no central recovery.

5.3 Verified Streaming: BLAKE3 & Bao
In a P2P network, data integrity is paramount. Standard S3 relies on TLS for transit security, but decentralized reads fetch blocks from potentially untrusted peers. We utilize Bao, an implementation of BLAKE3 verified streaming.
- The Mechanism: BLAKE3 is a Merkle Tree-based hash function. Bao allows encoding a file such that the hash of the root allows verification of any slice of the file without downloading the whole.
- Outboard Encoding: When a file is uploaded (client-side), the client computes the Bao tree. This "outboard" data (the tree hashes) is stored as a separate IPFS block, linked in the object metadata.
- Streaming Logic: Client requests bytes 0-1MB of a 10GB file. Gateway retrieves the data blocks for that range. Gateway retrieves the Bao tree nodes required to prove those blocks belong to the root hash. Gateway sends the verified stream.
- Benefit: If a storage node serves a corrupted block, the verification fails immediately at the Gateway or Client level, preventing the propagation of corrupt data.

6. Resilience and Operations: IPFS Cluster
6.1 Cluster Configuration and Persistence
We employ IPFS Cluster to manage the persistence of data across the swarm.
- Replication Factors: replication_factor_min: 2 (Data must exist on at least 2 nodes). replication_factor_max: 3 (Target 3 copies for redundancy).
- Consensus: We select CRDT (Conflict-free Replicated Data Type) mode for the cluster state. CRDTs allow the cluster to accept pins even during network partitions, prioritizing availability. Raft is rejected due to its brittleness in dynamic P2P environments where nodes may churn.
- Datastore: The underlying IPFS nodes use BadgerDS for optimized key-value storage of blocks, which provides better performance than FlatFS for large datasets.
- Enhancements: Follower node offline during replication (auto-repin via CRDT; data retrieved from other replicas); IPFS block retrieval timeouts (configurable 10s default, retry 3x); HAMT Forest corruption (rebuild from last good Prolly root via Merkle proofs); concurrent write conflicts (optimistic locking with CID checks, LWW resolution); large file upload failure recovery (resume from cache state).

6.2 Operational Runbooks
Runbook A: Node Failure and Recovery
- Scenario: A storage node (Node-3) crashes or suffers disk failure.
- Detection: Prometheus metrics (ipfs_cluster_peer_status) report OFFLINE.
- Procedure: Assessment: Check if replication_factor_min is compromised. If R_current < R_min for any pin, the cluster is in a degraded state. Recovery: Provision a new node (Node-4). Bootstrap ipfs-cluster-service with the cluster secret. Join the cluster: ipfs-cluster-ctl peer add <Node-4-ID>. The CRDT consensus will automatically sync the Pinset to the new node. IPFS Cluster will trigger "Repin" operations to satisfy replication factors, copying data to Node-4.

Runbook B: Split-Brain Resolution
- Scenario: Network partition creates two sub-clusters (A and B). Users pin files to both.
- Resolution: Network Heal: Connectivity is restored. CRDT Merge: The CRDTs from partition A and B automatically merge. The Pinset becomes the union of Set A and Set B. Conflict Audit: If an "Unpin" operation happened in Partition A while a "Pin" for the same CID happened in Partition B, CRDT logic (Observe-Remove Set) typically prioritizes the "Add" (Pin). A manual audit log check can verify if this intent was correct.

Runbook C: Garbage Collection (GC)
- Scenario: Disk usage is high.
- Procedure: Cluster GC: Run ipfs-cluster-ctl ipfs gc. This triggers the IPFS daemon GC on all peers but protects pinned items. Unpinning: To delete data, explicitly run ipfs-cluster-ctl pin rm <cid>. Safety: Standard IPFS GC is strictly controlled by the Cluster to prevent accidental data loss.

7. Real-Time Collaboration and Conflict Resolution
Standard file systems lock files during edits. A decentralized system must handle concurrent edits without locks.
7.1 Metadata Conflicts: CRDTs
For bucket metadata (ACLs, Tags, Custom Headers), we use Yjs or Loro (a Rust CRDT library).
- Data Structure: Bucket metadata is treated as a specialized CRDT Map.
- Scenario: User A sets Tag:Project = X. User B sets Tag:Status = Active.
- Resolution: The CRDT merges these operations commutatively. The result is a map containing both tags. No "conflict error" is shown to the user.

7.2 Binary Content Conflicts: Last-Write-Wins (LWW)
For the actual file content (the object key), merging binary data (like a JPEG) is impossible automatically. We use Last-Write-Wins.
- Clock Synchronization: Gateways rely on NTP.
- Logic: Update A: key="report.pdf", cid="Qm...", ts=1000. Update B: key="report.pdf", cid="Qm...", ts=1005. Result: Update B wins. The Prolly Tree updates the key to point to Update B's CID.
- Versioning: If S3 Versioning is enabled, both are kept as distinct versions (ver-1, ver-2). The "Current" pointer simply moves to the latest timestamp.

8. Execution Plan and Testing Specifications
8.1 Development Phases (Timeline-Free, Numbered Steps)
1. **Create Technical Requirements Document (TRD)**: Expand on gaps (e.g., encryption details, DB schema). Technical: Review all user requirements, draft in Markdown with sections on benefits (dedup, streaming, etc.). Process: Iterate based on original plan enhancements. Deliverable: Complete TRD document. Success Criteria: Covers all requirements, peer-reviewed by 2 developers; validates against S3 specs.
2. **Design and Review Database Schema**: Define exact tables/columns/keys/indexes/migrations as in 4.2.1. Technical: Use Postgres; ensure minimal data (ephemeral only). Process: Draft SQL, run EXPLAIN for performance. Deliverable: SQL schema files + migration scripts (Diesel). Success Criteria: No PII, indexes improve query speed by 50%; reviewed for security/completeness.
3. **Create OpenAPI 3.0 Specification**: Define all prioritized S3 endpoints (e.g., /<bucket>/{object} for PUT/GET) with XML schemas, auth, errors. Technical: Use Swagger/OpenAPI tools in Rust. Process: Generate from code stubs. Deliverable: YAML/JSON spec file. Success Criteria: Generates valid SDK stubs (e.g., for Rust/Wasm); passes validation against S3 docs.
4. **Prototype the BlockStore Implementation**: Build IPFS block handling with client-side encryption. Technical: Rust crate for chunking/encrypting/decrypting blocks (hpke crate), integrate Bao/BLAKE3. Process: Test with 1GB file upload/download. Deliverable: Prototype repo with code/tests. Success Criteria: Handles dedup/streaming/large files; unit tests (90% coverage) pass for integrity/encryption.
5. **Build a Minimal Working Example**: Implement PutObject + GetObject for a single bucket. Technical: Setup Gateway + IPFS test cluster (3 nodes) + client SDK. Process: End-to-end flow with encryption/sharing. Deliverable: Docker-compose setup with demo script. Success Criteria: Works with boto3 SDK; client-side encrypt/decrypt verified; no central key exposure.
6. **Implement Authentication/Authorization**: Integrate OAuth 2.0 with JWT validation. Technical: Rust middleware (actix-web/axum). Process: Add scopes for read/write. Deliverable: Auth module. Success Criteria: Invalid tokens rejected; integration tests pass.
7. **Add KEK/DEK Key Management and Encryption**: Client-side HPKE with SDK wrappers. Technical: Provide libsodium/Wasm bindings. Process: Test sharing/rotation/offline. Deliverable: Encryption SDK. Success Criteria: Keys never leave client; rotation re-encrypts minimally.
8. **Implement Multipart Upload and Monitoring**: Detailed spec as in 4.2; add Prometheus for observability. Technical: Cache integration. Process: Handle resumes/timeouts. Deliverable: MPU code. Success Criteria: 5GB upload resumes after failure.
9. **Develop Testing Strategy and Security Hardening**: Unit (90% coverage with cargo test), integration (minio/mint for S3 compat), load (k6 for 500 concurrent 1GB uploads), chaos (Chaos Mesh for 30% node failures). Technical: Checklist: OWASP top 10, audit logs in IPFS. Process: Run pen tests. Deliverable: Test suites/scripts. Success Criteria: All tests pass; no vulnerabilities found.
10. **Finalize API Documentation and Polish**: Generate from OpenAPI; add edge case handling (e.g., concurrent writes). Technical: Docs site on GitHub Pages. Process: Full system integration. Deliverable: Complete repo/docs. Success Criteria: System sustains 100MB/s throughput; all benefits (sharing, offline, etc.) demoed.

8.2 Testing Specifications
We use k6 for performance testing and Chaos Mesh for resilience testing.
8.2.1 Load Testing with k6
Script for testing Multipart Upload throughput:

```javascript
import { AWSConfig, S3Client } from 'https://jslib.k6.io/aws/0.14.0/s3.js';
import { check } from 'k6';

const s3 = new S3Client(new AWSConfig({
    region: 'us-east-1',
    accessKeyId: 'test',
    secretAccessKey: 'test',
    endpoint: 'http://gateway:9000'
}));

export default async function () {
    const bucket = 'load-test';
    const key = `file-${Math.random()}.bin`;
    
    // 1. Initiate MPU
    const mpu = await s3.createMultipartUpload(bucket, key);
    check(mpu, { 'init 200': (r) => r && r.uploadId });

    // 2. Upload Part
    const part = await s3.uploadPart(bucket, key, mpu.uploadId, 1, 'x'.repeat(5 * 1024 * 1024));
    check(part, { 'part upload 200': (r) => r.status === 200 });
    
    // 3. Complete
    const complete = await s3.completeMultipartUpload(bucket, key, mpu.uploadId,);
    check(complete, { 'complete 200': (r) => r.status === 200 });
}
```

8.2.2 Fault Injection with Chaos Mesh
We define a Chaos Mesh experiment to simulate network latency between the Gateway and IPFS Cluster.

```yaml
apiVersion: chaos-mesh.org/v1alpha1
kind: NetworkChaos
metadata:
  name: cluster-latency
spec:
  action: delay
  mode: all
  selector:
    namespaces:
      - ipfs-cluster
  delay:
    latency: "100ms"
    correlation: "100"
    jitter: "0ms"
  duration: "5m"
```

Success Criteria: The Gateway should handle the latency gracefully (e.g., increased response time) without crashing or corrupting data. Retries should eventually succeed.

8.3 Success Criteria Checklist
[ ] S3 Compliance: minio/mint test suite passes > 95% of tests.
[ ] Listing Performance: ListObjectsV2 returns 1,000 keys in < 200ms (via Prolly Tree).
[ ] Recovery: Cluster recovers full replication after 1 node kill command.
[ ] Security: Encrypted files cannot be opened without the HPKE private key.
[ ] Throughput: System sustains 100MB/s write throughput per Gateway node.

9. Conclusion
This revised Master Technical Implementation Plan outlines a rigorous path to building a storage engine that marries the reliability and ubiquity of the S3 API with the resilience and sovereignty of decentralized networks. By leveraging Prolly Trees for indexing, IPFS Cluster for persistence, and client-side HPKE/Bao for security, the proposed architecture eliminates the traditional trade-offs between performance and decentralization. The detailed schemas, API specifications, operational runbooks, and enhanced features (e.g., client-side encryption, minimal centralization) provided herein serve as the definitive blueprint for engineering teams to execute this vision with precision and confidence.

Works cited (updated as of December 07, 2025):
- prollytree - Rust - Docs.rs, https://docs.rs/prollytree
- Lab note #034 Incremental insertion into Prolly Trees - Interjected Future, https://interjectedfuture.com/lab-note-034-incremental-insertion-into-prolly-trees/
- oconnor663/bao: an implementation of BLAKE3 verified streaming - GitHub, https://github.com/oconnor663/bao
- Hybrid Public Key Encryption (HPKE) - PyCryptodome's documentation, https://pycryptodome.readthedocs.io/en/latest/src/protocol/hpke.html
- ListObjectsV2 - Amazon Simple Storage Service, https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListObjectsV2.html
- Error responses - Amazon Simple Storage Service, https://docs.aws.amazon.com/AmazonS3/latest/API/ErrorResponses.html
- prollytree - crates.io: Rust Package Registry, https://crates.io/crates/prollytree
- Data, backups and recovery - Pinset orchestration for IPFS, https://ipfscluster.io/documentation/guides/backups/
- How CRDTs and Rust are revolutionizing distributed systems and local-first applications, https://kerkour.com/rust-crdt
- crdt-lite - crates.io: Rust Package Registry, https://crates.io/crates/crdt-lite
- CompleteMultipartUpload - Amazon Simple Storage Service, https://docs.aws.amazon.com/AmazonS3/latest/API/API_CompleteMultipartUpload.html
- DeleteObjects - Amazon Simple Storage Service - AWS Documentation, https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteObjects.html
- Tracking a multipart upload with the AWS SDKs - Amazon Simple Storage Service, https://docs.aws.amazon.com/AmazonS3/latest/userguide/track-mpu.html
- Streaming Postgres query data to AWS S3 using Multipart upload in Java | by sannith vitta, https://medium.com/@sannithrcks/streaming-postgres-query-data-to-aws-s3-using-multipart-upload-in-java-047fc35a39d0
- Download and setup - Pinset orchestration for IPFS - IPFS Cluster, https://ipfscluster.io/documentation/deployment/setup/
- Replication factor not getting recovered - IPFS Forums, https://discuss.ipfs.tech/t/replication-factor-not-getting-recovered/11989
- API Gateway OAuth 2.0 Authentication Flows - Oracle Help Center, https://docs.oracle.com/cd/E39820_01/doc.11121/gateway_docs/content/oauth_flows.html
- Prolly Trees - Dolt Documentation - DoltHub, https://docs.dolthub.com/architecture/storage-engine/prolly-tree
- Configure Last Writer Conflict Detection & Resolution - SQL Server | Microsoft Learn, https://learn.microsoft.com/en-us/sql/relational-databases/replication/transactional/peer-to-peer/configure-last-writer?view=sql-server-ver17
- Conflict Resolution - Riak Documentation, https://docs.riak.com/riak/kv/latest/developing/usage/conflict-resolution/index.html
- list-objects-v2 — AWS CLI 2.32.11 Command Reference, https://docs.aws.amazon.com/cli/latest/reference/s3api/list-objects-v2.html
- Uploading and copying objects using multipart upload in Amazon S3 - AWS Documentation, https://docs.aws.amazon.com/AmazonS3/latest/userguide/mpuoverview.html
- S3::CompleteMultipartUploadCommand - AWS SDK for JavaScript v3, https://docs.aws.amazon.com/goto/SdkForJavaScriptV3/s3-2006-03-01/CompleteMultipartUpload
- CopyObject - Amazon Simple Storage Service - AWS Documentation, https://docs.aws.amazon.com/AmazonS3/latest/API/API_CopyObject.html
- copy-object — AWS CLI 2.32.11 Command Reference, https://docs.aws.amazon.com/cli/latest/reference/s3api/copy-object.html
- S3::DeleteObjectsCommand - AWS SDK for JavaScript v3, https://docs.aws.amazon.com/goto/SdkForJavaScriptV3/s3-2006-03-01/DeleteObjects
- How to Choose the Right OAuth 2.0 Flow - A Complete Guide | Curity, https://curity.io/resources/learn/choose-oauth-flow/
- RFC 9180 - Hybrid Public Key Encryption - IETF Datatracker, https://datatracker.ietf.org/doc/rfc9180/
- bao_tree - Rust - Docs.rs, https://docs.rs/bao-tree/latest/bao_tree/
- yjs/yjs: Shared data types for building collaborative software - GitHub, https://github.com/yjs/yjs
- Yjs vs Loro (new CRDT lib) - Show, https://discuss.yjs.dev/t/yjs-vs-loro-new-crdt-lib/2567
- Retaining multiple versions of objects with S3 Versioning - Amazon Simple Storage Service, https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html
- AWS S3 Delete Marker: What it is and How it works? - Learn AWS, https://www.learnaws.org/2022/10/04/aws-s3-delete-marker/
- S3MultipartUpload | Grafana k6 documentation, https://grafana.com/docs/k6/latest/javascript-api/jslib/aws/s3client/s3multipartupload/
- Upload files to AWS S3 in k6 - QAInsights, https://qainsights.com/upload-files-to-aws-s3-in-k6/
- Simulate File I/O Faults - Chaos Mesh, https://chaos-mesh.org/docs/simulate-io-chaos-on-kubernetes/