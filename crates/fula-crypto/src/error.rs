//! Error types for the fula-crypto crate

use thiserror::Error;

/// Result type alias using `CryptoError`
pub type Result<T> = std::result::Result<T, CryptoError>;

/// Errors that can occur during cryptographic operations
#[derive(Error, Debug)]
pub enum CryptoError {
    /// Key generation failed
    #[error("key generation failed: {0}")]
    KeyGeneration(String),

    /// Encryption failed
    #[error("encryption failed: {0}")]
    Encryption(String),

    /// Decryption failed
    #[error("decryption failed: {0}")]
    Decryption(String),

    /// Invalid key format or length
    #[error("invalid key: {0}")]
    InvalidKey(String),

    /// Invalid ciphertext format
    #[error("invalid ciphertext: {0}")]
    InvalidCiphertext(String),

    /// Signature verification failed
    #[error("signature verification failed")]
    SignatureVerification,

    /// Hash verification failed
    #[error("hash verification failed: expected {expected}, got {actual}")]
    HashMismatch { expected: String, actual: String },

    /// Post-decrypt content hash mismatch against a forest-entry-bound
    /// BLAKE3 digest (detects whole-file substitution under HPKE-to-self).
    #[error("integrity check failed: {0}")]
    IntegrityMismatch(String),

    /// Blob version advertises a lower format version than the forest entry's
    /// `min_version` pin allows. Blocks downgrade-to-no-AAD attacks.
    #[error("version downgrade rejected: got {got}, required >= {required}")]
    VersionDowngrade { got: u8, required: u8 },

    /// Bao verification failed
    #[error("bao verification failed: {0}")]
    BaoVerification(String),

    /// Invalid nonce
    #[error("invalid nonce: {0}")]
    InvalidNonce(String),

    /// Data too large for operation
    #[error("data too large: {size} bytes exceeds maximum {max} bytes")]
    DataTooLarge { size: u64, max: u64 },

    /// Invalid chunk size
    #[error("invalid chunk size: {0}")]
    InvalidChunkSize(usize),

    /// IO error
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// Serialization error
    #[error("serialization error: {0}")]
    Serialization(String),

    /// Base64 decode error
    #[error("base64 decode error: {0}")]
    Base64Decode(#[from] base64::DecodeError),

    /// Hex decode error
    #[error("hex decode error: {0}")]
    HexDecode(#[from] hex::FromHexError),

    /// Share token expired
    #[error("share token expired")]
    ShareExpired,

    /// Access denied
    #[error("access denied: {0}")]
    AccessDenied(String),

    /// Invalid format (for parsing URLs, links, etc.)
    #[error("invalid format: {0}")]
    InvalidFormat(String),

    /// HAMT-level error (traversal, canonicalization, integrity check, etc.)
    #[error("hamt error: {0}")]
    Hamt(String),

    /// Storage-backend error surfaced through the `BlobBackend` seam.
    ///
    /// `fula-crypto` owns the trait but never reaches the network itself;
    /// concrete backends (e.g. S3 in `fula-client`) map their transport
    /// failures into this variant so the trait signature can stay fully
    /// within `fula-crypto::Result`.
    #[error("storage backend error: {0}")]
    Storage(String),

    /// **#81 (2026-05-09)** — postcard decoded an enum variant tag the
    /// reader doesn't know. Hit on the read path when an old SDK
    /// (e.g. v0.5) encounters a blob written under a forward-incompatible
    /// wire format (e.g. walkable-v8's `PointerWire::LinkV2` variant
    /// tag 2). Distinguishes "you need to upgrade your SDK to read
    /// this bucket" from generic serialization corruption — operators
    /// can filter telemetry on the typed variant rather than
    /// substring-matching postcard's error class.
    ///
    /// `context` describes WHERE the unknown variant was hit (e.g.
    /// "decode hamt node"); `postcard_error` carries postcard's own
    /// error stringification for diagnostic depth.
    #[error("wire format version unsupported (need newer SDK): {context}: {postcard_error}")]
    WireVersionUnsupported {
        context: String,
        postcard_error: String,
    },
}

impl CryptoError {
    /// **#81 (2026-05-09)** — classify a postcard decode error. Maps
    /// postcard's `DeserializeBadEnum` (= "unknown enum variant tag,
    /// likely from a newer wire format") to the typed
    /// [`CryptoError::WireVersionUnsupported`] variant for stable
    /// telemetry handling. All other postcard errors fall through to
    /// the generic [`CryptoError::Serialization`] variant — they
    /// represent genuine codec failures, not version skew.
    ///
    /// Centralised here (rather than inline at call sites) so adding
    /// future detection sites is a one-liner. Detection currently
    /// applied at:
    ///   - `wnfs_hamt::node::Node::load`
    ///   - `wnfs_hamt::node::Node::load_with_cid_hint`
    pub fn classify_postcard_decode(err: postcard::Error, context: impl Into<String>) -> Self {
        let context = context.into();
        let postcard_error = err.to_string();
        // Postcard 1.x quirk: unknown enum variant tags during
        // serde-driven deserialization can surface via EITHER
        // `DeserializeBadEnum` (postcard's direct enum-tag-out-of-
        // range path) OR `SerdeDeCustom` (when serde's inner
        // `Error::custom("unknown variant ...")` is reached during
        // postcard's variant-discriminant decode). Empirically — see
        // the `unknown_variant_tag_maps_to_wire_version_unsupported`
        // unit test below — postcard 1.1.3 routes `LinkV2`-style
        // unknown-variant blobs through `SerdeDeCustom`, NOT
        // `DeserializeBadEnum`. Without matching `SerdeDeCustom` here
        // the typed variant would never fire in production.
        //
        // Trade-off: `SerdeDeCustom` is generic. Any other serde
        // error (e.g. malformed payload that triggers a custom
        // serde error during decode) would also map here. For our
        // controlled wire types (HAMT nodes, manifest pages,
        // ChunkedFileMetadata) the only realistic path to
        // `SerdeDeCustom` IS wire-version skew; non-skew corruption
        // tends to surface as `DeserializeUnexpectedEnd` or
        // `DeserializeBadEncoding` instead. Acceptable conflation
        // for telemetry — the variant message includes the postcard
        // error stringification so operators get diagnostic depth.
        match err {
            postcard::Error::DeserializeBadEnum | postcard::Error::SerdeDeCustom => {
                CryptoError::WireVersionUnsupported {
                    context,
                    postcard_error,
                }
            }
            _ => CryptoError::Serialization(format!("{context}: {postcard_error}")),
        }
    }
}

#[cfg(test)]
mod classify_postcard_decode_tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    /// **#81** — feed postcard bytes for a v2-only enum to a v1 reader
    /// that doesn't know variant tag 1 (Value). Postcard returns
    /// `DeserializeBadEnum`, which `classify_postcard_decode` maps to
    /// `WireVersionUnsupported`. This is the load-bearing assertion:
    /// the typed variant fires for unknown-variant errors specifically,
    /// not for any old postcard error.
    #[test]
    fn unknown_variant_tag_maps_to_wire_version_unsupported() {
        #[derive(Serialize)]
        enum V2Writer {
            #[allow(dead_code)]
            A,
            B(u32),
        }
        #[derive(Deserialize, Debug)]
        enum V1Reader {
            #[allow(dead_code)]
            A,
        }

        // Encode V2's Variant 1 (B) — V1 reader doesn't know tag 1.
        let bytes = postcard::to_allocvec(&V2Writer::B(42)).expect("encode");
        let err = postcard::from_bytes::<V1Reader>(&bytes).expect_err("must fail");
        let mapped = CryptoError::classify_postcard_decode(err, "test ctx");
        match mapped {
            CryptoError::WireVersionUnsupported {
                context,
                postcard_error,
            } => {
                assert_eq!(context, "test ctx");
                assert!(
                    !postcard_error.is_empty(),
                    "postcard error stringified for telemetry depth"
                );
            }
            other => panic!("expected WireVersionUnsupported, got: {other:?}"),
        }
    }

    /// Other postcard decode failures (e.g. truncated input) remain
    /// generic `Serialization` errors — the typed variant is reserved
    /// for genuine wire-version skew.
    #[test]
    fn truncated_input_stays_as_serialization_error() {
        #[derive(Deserialize, Debug)]
        struct NeedsTwoFields {
            #[allow(dead_code)]
            a: u32,
            #[allow(dead_code)]
            b: u32,
        }
        // Encode only one u32 — postcard hits DeserializeUnexpectedEnd.
        let bytes = postcard::to_allocvec(&7u32).expect("encode");
        let err = postcard::from_bytes::<NeedsTwoFields>(&bytes).expect_err("must fail");
        let mapped = CryptoError::classify_postcard_decode(err, "trunc ctx");
        match mapped {
            CryptoError::Serialization(msg) => {
                assert!(
                    msg.contains("trunc ctx"),
                    "context propagated into serialization message: {msg}"
                );
            }
            other => panic!(
                "expected Serialization for truncated input (NOT WireVersionUnsupported), got: {other:?}"
            ),
        }
    }
}
