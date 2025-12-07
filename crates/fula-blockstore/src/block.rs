//! Block types and operations

use cid::Cid;
use bytes::Bytes;
use serde::{Deserialize, Serialize};

/// A block of data with its CID
#[derive(Clone, Debug)]
pub struct Block {
    /// The content identifier
    pub cid: Cid,
    /// The raw data
    pub data: Bytes,
}

impl Block {
    /// Create a new block
    pub fn new(cid: Cid, data: Bytes) -> Self {
        Self { cid, data }
    }

    /// Create a block from raw bytes (computes CID)
    pub fn from_data(data: impl Into<Bytes>) -> Self {
        let data = data.into();
        let cid = crate::cid_utils::create_cid(&data, crate::cid_utils::CidCodec::Raw);
        Self { cid, data }
    }

    /// Get the size of the block
    pub fn size(&self) -> usize {
        self.data.len()
    }

    /// Check if the block is empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Get the data as a slice
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }
}

/// Block data variants
#[derive(Clone, Debug)]
pub enum BlockData {
    /// Raw binary data
    Raw(Bytes),
    /// DAG-CBOR encoded data
    DagCbor(Bytes),
    /// DAG-PB (Protobuf) encoded data
    DagPb(Bytes),
    /// DAG-JSON encoded data
    DagJson(Bytes),
}

impl BlockData {
    /// Get the codec for this data type
    pub fn codec(&self) -> crate::cid_utils::CidCodec {
        match self {
            BlockData::Raw(_) => crate::cid_utils::CidCodec::Raw,
            BlockData::DagCbor(_) => crate::cid_utils::CidCodec::DagCbor,
            BlockData::DagPb(_) => crate::cid_utils::CidCodec::DagPb,
            BlockData::DagJson(_) => crate::cid_utils::CidCodec::DagJson,
        }
    }

    /// Get the raw bytes
    pub fn bytes(&self) -> &Bytes {
        match self {
            BlockData::Raw(b) | BlockData::DagCbor(b) | BlockData::DagPb(b) | BlockData::DagJson(b) => b,
        }
    }

    /// Convert to raw bytes
    pub fn into_bytes(self) -> Bytes {
        match self {
            BlockData::Raw(b) | BlockData::DagCbor(b) | BlockData::DagPb(b) | BlockData::DagJson(b) => b,
        }
    }
}

/// A reference to a block (CID without data)
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BlockRef {
    /// The content identifier
    #[serde(with = "cid_serde")]
    pub cid: Cid,
    /// Optional size hint
    pub size: Option<u64>,
}

impl BlockRef {
    /// Create a new block reference
    pub fn new(cid: Cid) -> Self {
        Self { cid, size: None }
    }

    /// Create with size hint
    pub fn with_size(cid: Cid, size: u64) -> Self {
        Self { cid, size: Some(size) }
    }
}

impl From<Cid> for BlockRef {
    fn from(cid: Cid) -> Self {
        Self::new(cid)
    }
}

impl From<BlockRef> for Cid {
    fn from(block_ref: BlockRef) -> Self {
        block_ref.cid
    }
}

/// Helper for serializing CIDs
mod cid_serde {
    use cid::Cid;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(cid: &Cid, s: S) -> Result<S::Ok, S::Error> {
        cid.to_string().serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Cid, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// A link in a DAG structure
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DagLink {
    /// The name of the link
    pub name: String,
    /// The CID being linked to
    #[serde(with = "cid_serde")]
    pub cid: Cid,
    /// Size of the linked data
    pub size: u64,
}

impl DagLink {
    /// Create a new DAG link
    pub fn new(name: impl Into<String>, cid: Cid, size: u64) -> Self {
        Self {
            name: name.into(),
            cid,
            size,
        }
    }
}

/// A DAG node with links
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DagNode {
    /// The data in this node
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
    /// Links to other nodes
    pub links: Vec<DagLink>,
}

impl DagNode {
    /// Create an empty DAG node
    pub fn new() -> Self {
        Self {
            data: Vec::new(),
            links: Vec::new(),
        }
    }

    /// Create with data
    pub fn with_data(data: Vec<u8>) -> Self {
        Self {
            data,
            links: Vec::new(),
        }
    }

    /// Add a link
    pub fn add_link(&mut self, link: DagLink) {
        self.links.push(link);
    }

    /// Get total size including linked data
    pub fn total_size(&self) -> u64 {
        let data_size = self.data.len() as u64;
        let links_size: u64 = self.links.iter().map(|l| l.size).sum();
        data_size + links_size
    }
}

impl Default for DagNode {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_from_data() {
        let data = b"Hello, World!";
        let block = Block::from_data(data.as_slice());
        assert_eq!(block.size(), data.len());
        assert!(!block.is_empty());
    }

    #[test]
    fn test_block_ref_serialization() {
        let block = Block::from_data(b"test".as_slice());
        let block_ref = BlockRef::with_size(block.cid, block.size() as u64);
        
        let json = serde_json::to_string(&block_ref).unwrap();
        let deserialized: BlockRef = serde_json::from_str(&json).unwrap();
        
        assert_eq!(block_ref.cid, deserialized.cid);
        assert_eq!(block_ref.size, deserialized.size);
    }

    #[test]
    fn test_dag_node() {
        let mut node = DagNode::with_data(b"root data".to_vec());
        let child_block = Block::from_data(b"child data".as_slice());
        
        node.add_link(DagLink::new("child", child_block.cid, child_block.size() as u64));
        
        assert_eq!(node.links.len(), 1);
        assert_eq!(node.total_size(), 9 + 10); // "root data" + "child data"
    }
}
