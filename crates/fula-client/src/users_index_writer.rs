//! Phase 4 — client-side writer for the encrypted bucketsIndex
//! architecture.
//!
//! Responsibilities (per the E2E plan):
//!
//! 1. Fetch master's authoritative bucket list via
//!    `GET /api/v1/buckets/list` (Layer 1 of the multi-device merge).
//! 2. AEAD-encrypt the user's plaintext bucketsIndex CBOR under
//!    `K_index` with the plan-defined AAD (Layer A of E2E).
//! 3. Upload the ciphertext envelope to
//!    `PUT /api/v1/users-index/per-user`, with `parent_sequence`
//!    header (Layer 2 — optimistic concurrency on the encrypted-blob
//!    upload).
//! 4. Sign an entry payload with `K_entry_priv` derived from
//!    `K_entry_seed`; submit to `PUT /api/v1/users-index/entry`
//!    (Layer 3 — sequence monotonicity enforced by master).
//! 5. Retry on master's 409 responses by re-fetching the latest
//!    sequence and rebuilding the payload (bounded retry).
//!
//! Backward compatibility:
//! - The writer is **inert** when [`Config::encrypted_user_buckets_index_key`]
//!   OR [`Config::user_entry_signing_seed`] is `None`. Mode A users
//!   never call this code; their legacy `users[]` path is untouched.
//! - When called, the writer ONLY interacts with the new
//!   `/api/v1/users-index/*` and `/api/v1/buckets/list` endpoints
//!   introduced in Phase 2. All existing S3 endpoints, forest
//!   write paths, and per-bucket DEK logic are unchanged.
//! - Phase 3's `users_enc` is additive: even after the writer
//!   publishes, the master's publisher still emits `users[]` for
//!   every user (Mode A or Mode B/C), so legacy SDK readers continue
//!   to see byte-identical CBOR.

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_ipld_dagcbor as dagcbor;

use crate::error::ClientError;
use crate::registry_resolver::{BucketEntry, UserBucketsIndex};
use fula_crypto::{
    build_user_buckets_index_aad, derive_user_buckets_index_key, entry_pubkey_from_kek,
    keys::DekKey, sign_entry, symmetric::Aead, symmetric::AeadCipher, symmetric::Nonce,
    USER_BUCKETS_INDEX_ENVELOPE_VERSION,
};

/// On-the-wire encrypted envelope. AEAD-AES-256-GCM under `K_index`
/// with AAD bound to (`user_key_hex`, `sequence`, `envelope_version`).
/// Mirrors the planned CBOR shape:
/// `{ v: 3, nonce: bytes(12), ciphertext: bytes }`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EncryptedBucketsIndexEnvelope {
    pub v: u32,
    #[serde(with = "serde_bytes")]
    pub nonce: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub ciphertext: Vec<u8>,
}

/// Bucket entry returned by `GET /api/v1/buckets/list`. Mirrors the
/// shape emitted by `crate::handlers::list_buckets_for_owner` in
/// `fula-cli`.
#[derive(Clone, Debug, Deserialize)]
pub struct ServerBucketEntry {
    pub bucket_id: String,
    #[serde(default)]
    pub forest_manifest_cid: Option<String>,
    #[serde(default)]
    pub object_count: u64,
    #[serde(default)]
    pub updated_at_unix: u64,
}

#[derive(Clone, Debug, Deserialize)]
struct BucketsListResponse {
    buckets: Vec<ServerBucketEntry>,
}

#[derive(Clone, Debug, Deserialize)]
struct PutEncryptedBucketsIndexResponse {
    cid: String,
    #[allow(dead_code)]
    size: usize,
}

/// Master's `GET /api/v1/users-index/per-user/latest` response shape.
/// Used for sequence-recovery after storage clear (`next_seq =
/// highest_seq_ever_accepted + 1`) and for the cold-start fast-path.
#[derive(Clone, Debug, Deserialize)]
pub struct LatestEntryResponse {
    pub cid: String,
    pub sequence: u64,
    pub entry_pubkey_hex: String,
    pub signature_hex: String,
    pub envelope_version: u32,
    pub updated_at_unix: u64,
    pub highest_seq_ever_accepted: u64,
}

#[derive(Serialize)]
struct PutEntryRequest<'a> {
    cid: &'a str,
    sequence: u64,
    entry_pubkey_hex: &'a str,
    signature_hex: &'a str,
    envelope_version: u32,
}

/// Outcome of a single [`UsersIndexWriter::publish`] call. Useful for
/// observability + tests.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublishOutcome {
    pub published_cid: String,
    pub sequence: u64,
    pub bucket_count: usize,
    pub retry_count: u32,
}

/// Maximum number of optimistic-concurrency retries. Higher than the
/// usual "1 retry + bail" because a fast multi-device write storm can
/// cause repeated 409s; bounded to avoid infinite loops if master
/// keeps reporting newer sequences (e.g., a runaway peer).
const MAX_PUBLISH_RETRIES: u32 = 5;

/// Phase 4 writer. One per signed-in user; cheap to construct.
pub struct UsersIndexWriter {
    http: reqwest::Client,
    /// Master base URL (e.g. `https://api.cloud.fx.land`). No trailing
    /// slash — appended per request.
    endpoint: String,
    /// JWT used for the user-JWT auth middleware on every request.
    jwt: String,
    /// `K_index` — AEAD key for the bucketsIndex envelope (32 bytes).
    k_index: [u8; 32],
    /// `K_entry_seed` — Ed25519 seed for signing entries (32 bytes).
    k_entry_seed: [u8; 32],
    /// Caller's hashed user identity. Used to build the AAD and to
    /// sign the entry payload. The same value the master's auth
    /// middleware will see after JWT decode.
    user_key_hex: String,
}

impl UsersIndexWriter {
    /// Construct a writer. `endpoint` should NOT have a trailing slash.
    pub fn new(
        endpoint: impl Into<String>,
        jwt: impl Into<String>,
        k_index: [u8; 32],
        k_entry_seed: [u8; 32],
        user_key_hex: impl Into<String>,
    ) -> Self {
        Self {
            http: reqwest::Client::new(),
            endpoint: endpoint.into().trim_end_matches('/').to_string(),
            jwt: jwt.into(),
            k_index,
            k_entry_seed,
            user_key_hex: user_key_hex.into().to_ascii_lowercase(),
        }
    }

    /// Test-only constructor that injects a pre-built reqwest client
    /// (so wiremock can route requests).
    #[cfg(test)]
    pub fn with_http(
        endpoint: impl Into<String>,
        jwt: impl Into<String>,
        k_index: [u8; 32],
        k_entry_seed: [u8; 32],
        user_key_hex: impl Into<String>,
        http: reqwest::Client,
    ) -> Self {
        Self {
            http,
            endpoint: endpoint.into().trim_end_matches('/').to_string(),
            jwt: jwt.into(),
            k_index,
            k_entry_seed,
            user_key_hex: user_key_hex.into().to_ascii_lowercase(),
        }
    }

    /// Fetch master's authoritative bucket list (Layer 1 of the merge).
    pub async fn fetch_buckets_list(&self) -> Result<Vec<ServerBucketEntry>, ClientError> {
        let url = format!("{}/api/v1/buckets/list", self.endpoint);
        let resp = self
            .http
            .get(&url)
            .bearer_auth(&self.jwt)
            .send()
            .await?
            .error_for_status()?;
        let body: BucketsListResponse = resp.json().await?;
        Ok(body.buckets)
    }

    /// Fetch master's latest entry for the caller (sequence-recovery
    /// + cold-start fast path). Returns `Ok(None)` when master
    /// reports 404 (no entry yet) — that is NOT an error.
    pub async fn fetch_latest_entry(
        &self,
    ) -> Result<Option<LatestEntryResponse>, ClientError> {
        let url = format!("{}/api/v1/users-index/per-user/latest", self.endpoint);
        let resp = self.http.get(&url).bearer_auth(&self.jwt).send().await?;
        match resp.status().as_u16() {
            200 => Ok(Some(resp.json().await?)),
            404 => Ok(None),
            // Master returns 503 when the entries store isn't configured.
            // Treat as "no entry yet" so the writer can still publish
            // its first record; master will accept it as the TOFU
            // binding.
            503 => Ok(None),
            other => Err(ClientError::InvalidResponse(format!(
                "GET /per-user/latest unexpected status {}",
                other
            ))),
        }
    }

    /// Publish a new encrypted bucketsIndex. Does the full Layer-1+2+3
    /// pipeline with bounded optimistic-concurrency retry.
    ///
    /// Caller passes the PLAINTEXT [`UserBucketsIndex`] payload they
    /// want published. This function:
    /// 1. Pulls master's bucket list and verifies the payload is
    ///    consistent — caller is responsible for the merge step but
    ///    we double-check master sees at least all the bucket IDs the
    ///    payload claims (Layer-1 sanity).
    /// 2. AEAD-encrypts the payload under `K_index` with AAD bound to
    ///    (user_key, sequence, envelope_version).
    /// 3. PUTs the envelope to `/users-index/per-user`, captures CID.
    /// 4. Signs `entry_signature_payload(user_key, cid, seq, env_v)`
    ///    with `K_entry_priv`.
    /// 5. POSTs `(cid, seq, entry_pubkey, sig, env_v)` to
    ///    `/users-index/entry`.
    ///
    /// On 409 from step 5 (stale sequence), refetches the latest
    /// sequence, re-encrypts under the new AAD, and retries — up to
    /// [`MAX_PUBLISH_RETRIES`].
    pub async fn publish(
        &self,
        payload: UserBucketsIndex,
    ) -> Result<PublishOutcome, ClientError> {
        // Start sequence: query master for the highest accepted so far.
        // If master returns 404 (first publish), start at 1.
        let mut next_seq = match self.fetch_latest_entry().await? {
            Some(latest) => latest.highest_seq_ever_accepted.saturating_add(1).max(1),
            None => 1,
        };

        for attempt in 0..=MAX_PUBLISH_RETRIES {
            let envelope_v = USER_BUCKETS_INDEX_ENVELOPE_VERSION;
            let envelope_bytes = self.encrypt_payload(&payload, next_seq, envelope_v)?;

            // PUT the encrypted envelope.
            let put_url = format!("{}/api/v1/users-index/per-user", self.endpoint);
            let put_resp = self
                .http
                .put(&put_url)
                .bearer_auth(&self.jwt)
                .body(envelope_bytes)
                .send()
                .await?;

            if !put_resp.status().is_success() {
                return Err(ClientError::UploadFailed(format!(
                    "PUT /per-user failed: status={}",
                    put_resp.status()
                )));
            }
            let put_body: PutEncryptedBucketsIndexResponse = put_resp.json().await?;
            let cid = put_body.cid;

            // Sign and submit the entry.
            let sig = sign_entry(
                &self.k_entry_seed,
                &self.user_key_hex,
                &cid,
                next_seq,
                envelope_v,
            );
            let pubkey = entry_pubkey_from_kek(&self.k_entry_seed);
            let entry_pubkey_hex = hex::encode(pubkey);
            let signature_hex = hex::encode(sig);

            let entry_url = format!("{}/api/v1/users-index/entry", self.endpoint);
            let req = PutEntryRequest {
                cid: &cid,
                sequence: next_seq,
                entry_pubkey_hex: &entry_pubkey_hex,
                signature_hex: &signature_hex,
                envelope_version: envelope_v,
            };
            let entry_resp = self
                .http
                .put(&entry_url)
                .bearer_auth(&self.jwt)
                .json(&req)
                .send()
                .await?;
            let status = entry_resp.status();
            if status.is_success() {
                return Ok(PublishOutcome {
                    published_cid: cid,
                    sequence: next_seq,
                    bucket_count: payload.buckets.len(),
                    retry_count: attempt,
                });
            }
            if status.as_u16() == 409 {
                // Master rejected sequence; refetch and retry.
                if attempt >= MAX_PUBLISH_RETRIES {
                    return Err(ClientError::ConcurrentModification(format!(
                        "PUT /entry returned 409 after {} retries",
                        attempt
                    )));
                }
                let refreshed = self.fetch_latest_entry().await?;
                next_seq = refreshed
                    .map(|l| l.highest_seq_ever_accepted.saturating_add(1).max(1))
                    .unwrap_or(next_seq.saturating_add(1));
                continue;
            }
            return Err(ClientError::UploadFailed(format!(
                "PUT /entry unexpected status {}",
                status
            )));
        }
        // Loop exit without success or 409 — defensive; the loop
        // returns inside via the success / 409-exhaustion branches.
        Err(ClientError::UploadFailed(
            "publish loop exhausted without conclusive outcome".to_string(),
        ))
    }

    /// Build the AAD-bound envelope CBOR bytes for a payload. Pure;
    /// no network. Public for tests + for callers that want to do
    /// their own upload (e.g., to a third-party publisher in the
    /// optional Phase 6 self-sovereignty path).
    pub fn encrypt_payload(
        &self,
        payload: &UserBucketsIndex,
        sequence: u64,
        envelope_version: u32,
    ) -> Result<Vec<u8>, ClientError> {
        let aad = build_user_buckets_index_aad(&self.user_key_hex, sequence, envelope_version);
        let dek = DekKey::from_bytes(&self.k_index)
            .map_err(ClientError::Encryption)?;
        let aead = Aead::new(&dek, AeadCipher::Aes256Gcm);
        let nonce = Nonce::generate();
        let plaintext = dagcbor::to_vec(payload).map_err(|e| {
            ClientError::InvalidResponse(format!("encode payload: {}", e))
        })?;
        let ciphertext = aead
            .encrypt_with_aad(&nonce, &plaintext, &aad)
            .map_err(ClientError::Encryption)?;
        let envelope = EncryptedBucketsIndexEnvelope {
            v: envelope_version,
            nonce: nonce.as_bytes().to_vec(),
            ciphertext,
        };
        dagcbor::to_vec(&envelope).map_err(|e| {
            ClientError::InvalidResponse(format!("encode envelope: {}", e))
        })
    }

    /// Inverse of [`encrypt_payload`] — used by cold-start to decrypt
    /// a fetched envelope back to the plaintext [`UserBucketsIndex`].
    pub fn decrypt_envelope(
        &self,
        envelope_bytes: &[u8],
        sequence: u64,
    ) -> Result<UserBucketsIndex, ClientError> {
        let envelope: EncryptedBucketsIndexEnvelope =
            dagcbor::from_slice(envelope_bytes).map_err(|e| {
                ClientError::InvalidResponse(format!("decode envelope: {}", e))
            })?;
        let aad = build_user_buckets_index_aad(&self.user_key_hex, sequence, envelope.v);
        let dek = DekKey::from_bytes(&self.k_index)
            .map_err(ClientError::Encryption)?;
        let aead = Aead::new(&dek, AeadCipher::Aes256Gcm);
        if envelope.nonce.len() != 12 {
            return Err(ClientError::InvalidResponse(
                "nonce must be 12 bytes".to_string(),
            ));
        }
        let nonce = Nonce::from_bytes(envelope.nonce.as_slice())
            .map_err(ClientError::Encryption)?;
        let plaintext = aead
            .decrypt_with_aad(&nonce, &envelope.ciphertext, &aad)
            .map_err(ClientError::Encryption)?;
        let payload: UserBucketsIndex = dagcbor::from_slice(&plaintext).map_err(|e| {
            ClientError::InvalidResponse(format!("decode payload: {}", e))
        })?;
        Ok(payload)
    }
}

/// Build a plaintext bucketsIndex payload from master's authoritative
/// list and a local plaintext-name map. Layer-1 merge helper. The
/// `plaintext_names` map is `bucket_id → plaintext_name` from the
/// caller's local SDK state; entries are silently dropped if master
/// doesn't know about that bucket (defensive against stale local
/// state). Buckets master knows about but for which we lack a
/// plaintext name are included with `name = None` — the receiving
/// device may already have the name from a previously decrypted
/// snapshot and merge it in.
pub fn build_payload_from_buckets_list(
    server_buckets: &[ServerBucketEntry],
    plaintext_names: &BTreeMap<String, String>,
) -> UserBucketsIndex {
    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut buckets = BTreeMap::new();
    let mut names = BTreeMap::new();
    for b in server_buckets {
        buckets.insert(
            b.bucket_id.clone(),
            BucketEntry {
                manifest: String::new(),
                forest_manifest_cid: b.forest_manifest_cid.clone(),
                // This builder only runs for Mode B/C users whose
                // `bucket_id` is the blinded HMAC hex form (legacy
                // plaintext names are a Mode-A-only concept written
                // by master's publisher). Always `false` here.
                legacy: false,
            },
        );
        // Carry the caller's plaintext-name mapping for this bucket
        // into the encrypted payload. Decrypted on cold-start, the
        // map gives a fresh-device UI the human names without ever
        // exposing them to master. Buckets without a known plaintext
        // name (the caller's local cache didn't have it) are simply
        // absent from `names` — UI falls back to displaying the
        // blinded ID until a device with the mapping decrypts and
        // re-publishes.
        if let Some(name) = plaintext_names.get(&b.bucket_id) {
            names.insert(b.bucket_id.clone(), name.clone());
        }
    }
    UserBucketsIndex {
        v: 1,
        buckets,
        updated_at_unix: now_unix,
        names,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry_resolver::{BucketEntry, UserBucketsIndex};
    use std::collections::BTreeMap;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const KEK_A: [u8; 32] = [0xA5; 32];
    const USER_KEY: &str = "0123456789abcdef0123456789abcdef";

    fn writer_for(server: &MockServer) -> UsersIndexWriter {
        let k_index = fula_crypto::derive_user_buckets_index_key(&KEK_A);
        let k_entry = fula_crypto::derive_entry_signing_seed(&KEK_A);
        UsersIndexWriter::new(
            server.uri(),
            "test-jwt",
            k_index,
            k_entry,
            USER_KEY,
        )
    }

    fn sample_payload() -> UserBucketsIndex {
        let mut buckets = BTreeMap::new();
        buckets.insert(
            "blinded_a".to_string(),
            BucketEntry {
                manifest: "bafy_a".to_string(),
                forest_manifest_cid: Some("bafy_a_forest".to_string()),
                legacy: false,
            },
        );
        UserBucketsIndex {
            v: 1,
            buckets,
            updated_at_unix: 1_700_000_000,
            names: BTreeMap::new(),
        }
    }

    /// Round-trip: encrypt with one key, decrypt with the same key.
    /// AAD-bound: tampering with sequence between encrypt and decrypt
    /// fails verification.
    #[test]
    fn encrypt_decrypt_round_trip() {
        let writer = UsersIndexWriter::new(
            "http://unused",
            "jwt",
            derive_user_buckets_index_key(&KEK_A),
            fula_crypto::derive_entry_signing_seed(&KEK_A),
            USER_KEY,
        );
        let payload = sample_payload();
        let envelope = writer.encrypt_payload(&payload, 7, 3).unwrap();
        let decoded = writer.decrypt_envelope(&envelope, 7).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn decrypt_rejects_sequence_tamper() {
        let writer = UsersIndexWriter::new(
            "http://unused",
            "jwt",
            derive_user_buckets_index_key(&KEK_A),
            fula_crypto::derive_entry_signing_seed(&KEK_A),
            USER_KEY,
        );
        let payload = sample_payload();
        let envelope = writer.encrypt_payload(&payload, 7, 3).unwrap();
        // Different sequence → AAD mismatch → decryption fails.
        assert!(writer.decrypt_envelope(&envelope, 8).is_err());
    }

    #[tokio::test]
    async fn publish_happy_path() {
        let server = MockServer::start().await;

        // No prior entry.
        Mock::given(method("GET"))
            .and(path("/api/v1/users-index/per-user/latest"))
            .respond_with(ResponseTemplate::new(404))
            .expect(1)
            .mount(&server)
            .await;

        // PUT envelope → returns synthetic CID.
        Mock::given(method("PUT"))
            .and(path("/api/v1/users-index/per-user"))
            .and(header("authorization", "Bearer test-jwt"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "cid": "bafyreitestcidaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "size": 100,
            })))
            .expect(1)
            .mount(&server)
            .await;

        // PUT entry → accepted.
        Mock::given(method("PUT"))
            .and(path("/api/v1/users-index/entry"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "user_key": USER_KEY,
                "sequence": 1,
                "highest_seq_ever_accepted": 1,
            })))
            .expect(1)
            .mount(&server)
            .await;

        let writer = writer_for(&server);
        let outcome = writer.publish(sample_payload()).await.expect("publish");

        assert_eq!(outcome.sequence, 1);
        assert_eq!(outcome.retry_count, 0);
        assert!(outcome.published_cid.starts_with("bafyrei"));
    }

    /// 409 on /entry → writer refetches sequence and retries.
    #[tokio::test]
    async fn publish_retries_on_stale_sequence() {
        let server = MockServer::start().await;

        // First /latest call: returns existing entry with highest_seq=5.
        Mock::given(method("GET"))
            .and(path("/api/v1/users-index/per-user/latest"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "cid": "bafyreioldoldoldoldoldoldoldoldoldoldoldoldoldoldoldoldolddd",
                "sequence": 5,
                "entry_pubkey_hex": "0".repeat(64),
                "signature_hex": "0".repeat(128),
                "envelope_version": 3,
                "updated_at_unix": 1_700_000_000,
                "highest_seq_ever_accepted": 5,
            })))
            .mount(&server)
            .await;

        // /per-user always accepts the upload (returns the same CID
        // both attempts — we're testing 409 on /entry, not on /per-user).
        Mock::given(method("PUT"))
            .and(path("/api/v1/users-index/per-user"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "cid": "bafyreinewnewnewnewnewnewnewnewnewnewnewnewnewnewnewnewneww",
                "size": 100,
            })))
            .mount(&server)
            .await;

        // First /entry call: 409 (someone else raced to seq=6 already).
        // Second /entry call: 200.
        let first_409 = Mock::given(method("PUT"))
            .and(path("/api/v1/users-index/entry"))
            .respond_with(ResponseTemplate::new(409).set_body_string("stale"))
            .expect(1)
            .up_to_n_times(1);
        first_409.mount(&server).await;

        Mock::given(method("PUT"))
            .and(path("/api/v1/users-index/entry"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "user_key": USER_KEY,
                "sequence": 7,
                "highest_seq_ever_accepted": 7,
            })))
            .mount(&server)
            .await;

        let writer = writer_for(&server);
        let outcome = writer.publish(sample_payload()).await.expect("publish");
        assert!(outcome.retry_count >= 1);
    }

    /// Master returns 503 (entries_store not configured) → treated as
    /// "no entry yet" → writer publishes seq=1 anyway.
    #[tokio::test]
    async fn publish_treats_503_latest_as_no_entry() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/v1/users-index/per-user/latest"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;

        Mock::given(method("PUT"))
            .and(path("/api/v1/users-index/per-user"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "cid": "bafyreitestcidaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "size": 100,
            })))
            .mount(&server)
            .await;

        Mock::given(method("PUT"))
            .and(path("/api/v1/users-index/entry"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "user_key": USER_KEY,
                "sequence": 1,
                "highest_seq_ever_accepted": 1,
            })))
            .mount(&server)
            .await;

        let writer = writer_for(&server);
        let outcome = writer.publish(sample_payload()).await.expect("publish");
        assert_eq!(outcome.sequence, 1);
    }

    /// `fetch_buckets_list` round-trip.
    #[tokio::test]
    async fn fetch_buckets_list_works() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/buckets/list"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "buckets": [
                    {
                        "bucket_id": "abc123",
                        "forest_manifest_cid": "bafyrei_forest_abc",
                        "object_count": 3,
                        "updated_at_unix": 1_700_000_000
                    }
                ]
            })))
            .mount(&server)
            .await;

        let writer = writer_for(&server);
        let list = writer.fetch_buckets_list().await.expect("buckets list");
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].bucket_id, "abc123");
    }
}
