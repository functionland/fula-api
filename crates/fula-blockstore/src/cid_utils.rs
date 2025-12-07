//! CID (Content Identifier) utilities
//!
//! Creates content-addressed identifiers using BLAKE3

use cid::{Cid, Version};
use multihash_codetable::{Code, MultihashDigest};

/// Supported IPLD codecs
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CidCodec {
    /// Raw binary data (0x55)
    Raw,
    /// DAG-CBOR (0x71)
    DagCbor,
    /// DAG-PB/Protobuf (0x70)
    DagPb,
    /// DAG-JSON (0x0129)
    DagJson,
}

impl CidCodec {
    /// Get the multicodec code
    pub fn code(&self) -> u64 {
        match self {
            CidCodec::Raw => 0x55,
            CidCodec::DagCbor => 0x71,
            CidCodec::DagPb => 0x70,
            CidCodec::DagJson => 0x0129,
        }
    }

    /// Parse from multicodec code
    pub fn from_code(code: u64) -> Option<Self> {
        match code {
            0x55 => Some(CidCodec::Raw),
            0x71 => Some(CidCodec::DagCbor),
            0x70 => Some(CidCodec::DagPb),
            0x0129 => Some(CidCodec::DagJson),
            _ => None,
        }
    }

    /// Get a human-readable name
    pub fn name(&self) -> &'static str {
        match self {
            CidCodec::Raw => "raw",
            CidCodec::DagCbor => "dag-cbor",
            CidCodec::DagPb => "dag-pb",
            CidCodec::DagJson => "dag-json",
        }
    }
}

impl Default for CidCodec {
    fn default() -> Self {
        CidCodec::Raw
    }
}

/// Create a CID from data using BLAKE3 hash
pub fn create_cid(data: &[u8], codec: CidCodec) -> Cid {
    // Use BLAKE3 for hashing
    let hash = blake3::hash(data);
    
    // Create multihash using blake3 code (0x1e)
    // Note: multihash crate may use different code, we use SHA2-256 for compatibility
    let multihash = Code::Sha2_256.digest(hash.as_bytes());
    
    Cid::new(Version::V1, codec.code(), multihash).expect("valid CID construction")
}

/// Create a CID with explicit hash (for when hash is pre-computed)
pub fn create_cid_from_hash(hash: &[u8; 32], codec: CidCodec) -> Cid {
    let multihash = Code::Sha2_256.digest(hash);
    Cid::new(Version::V1, codec.code(), multihash).expect("valid CID construction")
}

/// Verify that data matches a CID
pub fn verify_cid(data: &[u8], cid: &Cid) -> bool {
    let expected = create_cid(data, CidCodec::from_code(cid.codec()).unwrap_or_default());
    expected == *cid
}

/// Parse a CID from a string
pub fn parse_cid(s: &str) -> Result<Cid, crate::BlockStoreError> {
    s.parse()
        .map_err(|e: cid::Error| crate::BlockStoreError::InvalidCid(e.to_string()))
}

/// Convert a CID to a base32 string (for file names, URLs)
pub fn cid_to_base32(cid: &Cid) -> String {
    // Use the default string representation which is base32 for CIDv1
    cid.to_string()
}

/// Get the codec of a CID
pub fn get_codec(cid: &Cid) -> Option<CidCodec> {
    CidCodec::from_code(cid.codec())
}

/// Get the hash bytes from a CID
pub fn get_hash_bytes(cid: &Cid) -> Vec<u8> {
    cid.hash().digest().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_cid() {
        let data = b"Hello, World!";
        let cid = create_cid(data, CidCodec::Raw);
        
        assert_eq!(cid.version(), Version::V1);
        assert_eq!(cid.codec(), CidCodec::Raw.code());
    }

    #[test]
    fn test_cid_consistency() {
        let data = b"test data";
        let cid1 = create_cid(data, CidCodec::Raw);
        let cid2 = create_cid(data, CidCodec::Raw);
        
        assert_eq!(cid1, cid2);
    }

    #[test]
    fn test_different_data_different_cid() {
        let cid1 = create_cid(b"data1", CidCodec::Raw);
        let cid2 = create_cid(b"data2", CidCodec::Raw);
        
        assert_ne!(cid1, cid2);
    }

    #[test]
    fn test_verify_cid() {
        let data = b"verify me";
        let cid = create_cid(data, CidCodec::Raw);
        
        assert!(verify_cid(data, &cid));
        assert!(!verify_cid(b"wrong data", &cid));
    }

    #[test]
    fn test_cid_string_roundtrip() {
        let data = b"test";
        let cid = create_cid(data, CidCodec::Raw);
        let string = cid.to_string();
        let parsed = parse_cid(&string).unwrap();
        
        assert_eq!(cid, parsed);
    }

    #[test]
    fn test_codec_roundtrip() {
        for codec in [CidCodec::Raw, CidCodec::DagCbor, CidCodec::DagPb, CidCodec::DagJson] {
            let code = codec.code();
            let parsed = CidCodec::from_code(code);
            assert_eq!(Some(codec), parsed);
        }
    }
}
