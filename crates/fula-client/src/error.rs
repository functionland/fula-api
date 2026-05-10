//! Client error types

use thiserror::Error;

/// Result type alias
pub type Result<T> = std::result::Result<T, ClientError>;

/// Client errors
#[derive(Error, Debug)]
pub enum ClientError {
    /// HTTP request error
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// S3 API error
    #[error("S3 error ({code}): {message}")]
    S3Error {
        code: String,
        message: String,
        request_id: Option<String>,
    },

    /// Invalid configuration
    #[error("Configuration error: {0}")]
    Config(String),

    /// Encryption error. **#81**: the `#[from]` was replaced by a
    /// custom `From<CryptoError>` impl below so we can branch on
    /// `CryptoError::WireVersionUnsupported` and surface it as the
    /// typed `ClientError::WireVersionUnsupported` variant rather
    /// than burying it inside the generic `Encryption(...)` wrapper.
    #[error("Encryption error: {0}")]
    Encryption(fula_crypto::CryptoError),

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// XML parsing error
    #[error("XML parsing error: {0}")]
    XmlParse(String),

    /// Invalid response
    #[error("Invalid response: {0}")]
    InvalidResponse(String),

    /// Object not found
    #[error("Object not found: {bucket}/{key}")]
    NotFound { bucket: String, key: String },

    /// Bucket not found
    #[error("Bucket not found: {0}")]
    BucketNotFound(String),

    /// Access denied
    #[error("Access denied: {0}")]
    AccessDenied(String),

    /// Upload failed
    #[error("Upload failed: {0}")]
    UploadFailed(String),

    /// Download failed
    #[error("Download failed: {0}")]
    DownloadFailed(String),

    /// Concurrent modification detected (412 Precondition Failed / ETag mismatch).
    ///
    /// Returned by conditional writes (e.g. forest flush with If-Match) when another
    /// writer has updated the same object since it was loaded. Callers should reload
    /// and retry.
    #[error("Concurrent modification: {0}")]
    ConcurrentModification(String),

    /// Concurrent forest flush could not be reconciled within the retry budget.
    ///
    /// Raised by `save_forest` / `save_sharded_forest` when repeated optimistic-merge
    /// retries continue to lose 412 races. The WAL at `wal_path` still holds the
    /// unreconciled operations — either delete it to drop the work or invoke flush
    /// again later. (NEW-7.2.)
    #[error("Concurrent modification unresolved after {retries} retries: bucket={bucket}, pending ops={unresolved_ops}, wal={wal_path}")]
    ConcurrentModificationExhausted {
        bucket: String,
        retries: usize,
        unresolved_ops: usize,
        wal_path: String,
    },

    /// Another rotation is already running against the same journal path.
    ///
    /// `rotate_bucket_with_journal` acquires an exclusive OS file lock on the
    /// journal so two processes (or threads) cannot garble the append log.
    /// (NEW-L.4.)
    #[error("Rotation already in progress for bucket: {bucket}")]
    RotationInProgress { bucket: String },

    /// Server-side advisory migration lock is already held by another device
    /// or by a prior session whose TTL has not yet expired.
    ///
    /// Returned by `POST /locks/{bucket}` with a 409 response. The caller should
    /// fall back to read-only v1 access for this session; the next session will
    /// re-enter the load-time migration path.
    #[error("Migration lock held for bucket {bucket} (expires at {expires_at} ms)")]
    MigrationLockHeld { bucket: String, expires_at: i64 },

    /// Phase 2.1 of master-independent reads: the SDK's health gate
    /// observed master is unreachable and short-circuited the request.
    /// Phase 2.4 will catch this variant and trigger the gateway-race
    /// fallback. Standalone (Phase 2.1 only), this turns "wait 3s for
    /// timeout" into "fast-fail with a clear signal."
    #[error("Master unreachable (health gate; down for ~{down_for_secs}s)")]
    MasterUnreachable { down_for_secs: u64 },

    /// Phase 2.2 of master-independent reads: a single block exceeds the
    /// configured `block_cache_max_bytes` budget and cannot be cached.
    ///
    /// **Native-only signal in practice.** `BlockCache` itself is
    /// compiled out on `wasm32`; this variant is defined unconditionally
    /// so the enum shape stays stable across native and web builds, and
    /// so consumers (fula-flutter, app integrators) can write a single
    /// exhaustive match arm without `#[cfg]` gates of their own.
    /// Triggering it on wasm would require a manual construction —
    /// the SDK never raises it there.
    ///
    /// Apps should surface this to the user with guidance to raise the
    /// `block_cache_max_bytes` config or skip the cache for this object.
    #[error("Block exceeds cache budget: size={size}, budget={budget}")]
    BlockTooLarge { size: u64, budget: u64 },

    /// Phase 2.2 of master-independent reads: catch-all for the
    /// persistent block cache's I/O / storage / commit errors.
    ///
    /// Stringified at the SDK boundary so app code doesn't need to depend
    /// on `redb` or its concrete error type. Native-only in practice
    /// (same reasoning as `BlockTooLarge` above); kept unconditional for
    /// enum-shape stability.
    #[error("Block cache error: {0}")]
    BlockCache(String),

    /// Phase 3.3 of master-independent reads: cold-start hybrid
    /// resolver could not resolve the master-published global
    /// users-index CID through any channel (IPNS exhausted AND
    /// chain failed / was unreachable / had no entry / sequence-
    /// regressed). Fresh-device cold-start is unrecoverable until
    /// at least one channel returns; the app should surface
    /// "offline mode unavailable for this device yet".
    ///
    /// Defined unconditionally so the enum shape stays stable
    /// across native and wasm. The native resolver lives in
    /// `registry_resolver.rs`; the wasm cold-start path always
    /// raises this variant until a browser-friendly resolver lands.
    #[error("users-index resolution failed: {reason}")]
    UsersIndexResolutionFailed { reason: String },

    /// Phase 3.3 replay defense: the resolver observed a payload
    /// whose embedded `sequence` is strictly less than what the SDK
    /// has previously seen and persisted. A compromised gateway,
    /// RPC node, or operator could try to serve a stale (but
    /// otherwise valid-looking) payload to roll back the user's
    /// view; this variant is the SDK's refusal to honor that.
    ///
    /// Apps should NOT retry — every retry from the same source
    /// would fail identically. Surface as "your master appears to
    /// be serving stale state; contact support" or equivalent.
    /// `channel` is a free-form label identifying which path
    /// observed the regression (e.g. `"chain.latest()"`,
    /// `"Ipns"`, `"Chain"`). Named `channel` rather than `source`
    /// because thiserror gives the latter special meaning
    /// (it expects an `std::error::Error` impl).
    #[error("sequence regression in {channel}: observed={observed}, highest seen={highest_seen}")]
    SequenceRegression {
        observed: u64,
        highest_seen: u64,
        channel: String,
    },

    /// **#81 (2026-05-09)** — the SDK encountered a wire format with
    /// an unknown enum variant tag (e.g. v0.5 SDK reading a v0.6
    /// walkable-v8 `LinkV2` blob). Surfaced as a typed variant so
    /// operators can filter telemetry on it directly rather than
    /// substring-matching the postcard error class buried inside
    /// `Encryption(CryptoError::Serialization(...))`.
    ///
    /// `context` describes WHERE the unknown variant was encountered
    /// (e.g. "decode hamt node"). `postcard_error` is postcard's
    /// own stringification for diagnostic depth.
    ///
    /// Apps should surface as "this bucket needs FxFiles vX.Y or
    /// later" — the bucket data itself is intact, the SDK just
    /// can't decode the new wire format.
    #[error("wire format version unsupported (need newer SDK): {context}: {postcard_error}")]
    WireVersionUnsupported {
        context: String,
        postcard_error: String,
    },

    /// **D6 audit fix** — a multipart upload would require more than
    /// the S3 hard limit of 10,000 parts at the configured
    /// `multipart_chunk_size`. Surfaced as a typed pre-condition error
    /// before any HTTP traffic, so callers see a clear actionable
    /// signal ("increase chunk size to N bytes") instead of an opaque
    /// S3 error at part #10001.
    ///
    /// `computed_parts` is what the upload would need at the current
    /// chunk size; `max` is the S3-enforced ceiling (10,000); the
    /// `suggested_chunk_size` is the smallest chunk size that fits the
    /// file under the cap.
    #[error(
        "multipart upload requires {computed_parts} parts which exceeds the S3 limit \
         of {max}; increase multipart_chunk_size to at least {suggested_chunk_size} bytes"
    )]
    PartCountExceeded {
        computed_parts: u64,
        max: u64,
        suggested_chunk_size: u64,
    },
}

/// **#81** — custom `From<CryptoError>` (replaces the prior `#[from]`
/// macro on the `Encryption` variant) so that
/// [`CryptoError::WireVersionUnsupported`] surfaces as the typed
/// [`ClientError::WireVersionUnsupported`] variant rather than being
/// wrapped in the generic `Encryption(...)` arm. Every other
/// `CryptoError` variant routes through `Encryption` as before —
/// `?` semantics at all existing call sites are byte-identical.
impl From<fula_crypto::CryptoError> for ClientError {
    fn from(err: fula_crypto::CryptoError) -> Self {
        match err {
            fula_crypto::CryptoError::WireVersionUnsupported {
                context,
                postcard_error,
            } => ClientError::WireVersionUnsupported {
                context,
                postcard_error,
            },
            other => ClientError::Encryption(other),
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl From<crate::block_cache::BlockCacheError> for ClientError {
    fn from(err: crate::block_cache::BlockCacheError) -> Self {
        use crate::block_cache::BlockCacheError;
        match err {
            BlockCacheError::BlockTooLarge { size, budget } => {
                ClientError::BlockTooLarge { size, budget }
            }
            // Catch-all: stringify the rest so app code doesn't have to
            // pattern-match on redb internals. Adds zero deps to the
            // public SDK surface.
            other => ClientError::BlockCache(other.to_string()),
        }
    }
}

impl ClientError {
    /// Parse an S3 error from XML response
    pub fn from_s3_xml(xml: &str, status: u16) -> Self {
        // Simple XML parsing for error responses
        let code = extract_xml_element(xml, "Code").unwrap_or_else(|| format!("HTTP{}", status));
        let message = extract_xml_element(xml, "Message").unwrap_or_else(|| "Unknown error".to_string());
        let request_id = extract_xml_element(xml, "RequestId");

        Self::S3Error {
            code,
            message,
            request_id,
        }
    }

    /// Check if this is a "not found" error
    pub fn is_not_found(&self) -> bool {
        matches!(self, Self::NotFound { .. } | Self::BucketNotFound(_))
            || matches!(self, Self::S3Error { code, .. } 
                if code == "NoSuchKey" || code == "NoSuchBucket" || code == "HTTP404" || code == "404")
    }

    /// Check if this is an access denied error
    pub fn is_access_denied(&self) -> bool {
        matches!(self, Self::AccessDenied(_))
            || matches!(self, Self::S3Error { code, .. } if code == "AccessDenied")
    }

    /// Check if this is a concurrent-modification / precondition-failed error.
    pub fn is_concurrent_modification(&self) -> bool {
        matches!(self, Self::ConcurrentModification(_))
            || matches!(self, Self::ConcurrentModificationExhausted { .. })
            || matches!(self, Self::S3Error { code, .. }
                if code == "PreconditionFailed" || code == "HTTP412" || code == "412")
    }

    /// Check if this is a block-cache error (budget exceeded or storage
    /// failure). Useful for app integrators that want to retry without
    /// the cache (e.g., directly via the gateway-race path).
    pub fn is_cache_error(&self) -> bool {
        matches!(self, Self::BlockTooLarge { .. } | Self::BlockCache(_))
    }
}

fn extract_xml_element(xml: &str, element: &str) -> Option<String> {
    let start_tag = format!("<{}>", element);
    let end_tag = format!("</{}>", element);
    
    let start = xml.find(&start_tag)? + start_tag.len();
    let end = xml.find(&end_tag)?;
    
    if start < end {
        Some(xml[start..end].to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_s3_error() {
        let xml = r#"<?xml version="1.0"?>
<Error>
    <Code>NoSuchKey</Code>
    <Message>The specified key does not exist.</Message>
    <RequestId>abc123</RequestId>
</Error>"#;

        let error = ClientError::from_s3_xml(xml, 404);
        
        match error {
            ClientError::S3Error { code, message, request_id } => {
                assert_eq!(code, "NoSuchKey");
                assert_eq!(message, "The specified key does not exist.");
                assert_eq!(request_id, Some("abc123".to_string()));
            }
            _ => panic!("Expected S3Error"),
        }
    }
}
