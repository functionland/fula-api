//! Hash utilities for Prolly Tree boundaries

use fula_crypto::hashing::{Blake3Hash, HASH_BYTE_SIZE, HashOutput};
use serde::{Deserialize, Serialize};

/// Number of nibbles in a hash
pub const MAX_HASH_NIBBLE_LENGTH: usize = HASH_BYTE_SIZE * 2;

/// A cursor for traversing hash nibbles
#[derive(Clone, Debug)]
pub struct HashNibbles<'a> {
    /// The hash digest
    pub digest: &'a HashOutput,
    /// Current cursor position (nibble index)
    cursor: usize,
}

impl<'a> HashNibbles<'a> {
    /// Create a new nibble cursor
    pub fn new(digest: &'a HashOutput) -> Self {
        Self { digest, cursor: 0 }
    }

    /// Get the current nibble and advance
    pub fn next(&mut self) -> Option<u8> {
        if self.cursor >= MAX_HASH_NIBBLE_LENGTH {
            return None;
        }
        let nibble = self.get_nibble(self.cursor);
        self.cursor += 1;
        Some(nibble)
    }

    /// Peek at the current nibble without advancing
    pub fn peek(&self) -> Option<u8> {
        if self.cursor >= MAX_HASH_NIBBLE_LENGTH {
            return None;
        }
        Some(self.get_nibble(self.cursor))
    }

    /// Get a nibble at a specific index
    fn get_nibble(&self, index: usize) -> u8 {
        let byte_index = index / 2;
        let byte = self.digest[byte_index];
        if index % 2 == 0 {
            (byte >> 4) & 0x0F
        } else {
            byte & 0x0F
        }
    }

    /// Get the current cursor position
    pub fn position(&self) -> usize {
        self.cursor
    }

    /// Skip N nibbles
    pub fn skip(&mut self, n: usize) {
        self.cursor = (self.cursor + n).min(MAX_HASH_NIBBLE_LENGTH);
    }

    /// Check if we've exhausted all nibbles
    pub fn is_exhausted(&self) -> bool {
        self.cursor >= MAX_HASH_NIBBLE_LENGTH
    }
}

/// A hash prefix for locating nodes in the tree
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct HashPrefix {
    /// The hash digest
    pub digest: HashOutput,
    /// Length in nibbles
    length: u8,
}

impl HashPrefix {
    /// Create a prefix with a specific length
    pub fn with_length(digest: HashOutput, length: u8) -> Self {
        Self { digest, length }
    }

    /// Create from a full hash
    pub fn from_hash(hash: &Blake3Hash) -> Self {
        Self {
            digest: *hash.as_bytes(),
            length: MAX_HASH_NIBBLE_LENGTH as u8,
        }
    }

    /// Get the length in nibbles
    pub fn len(&self) -> usize {
        self.length as usize
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.length == 0
    }

    /// Create a nibbles cursor
    pub fn nibbles(&self) -> HashNibbles<'_> {
        HashNibbles::new(&self.digest)
    }

    /// Check if this prefix matches another
    pub fn matches(&self, other: &HashPrefix) -> bool {
        let len = self.length.min(other.length) as usize;
        for i in 0..len {
            let byte_idx = i / 2;
            if i % 2 == 0 {
                let mask = 0xF0;
                if (self.digest[byte_idx] & mask) != (other.digest[byte_idx] & mask) {
                    return false;
                }
            } else {
                let mask = 0x0F;
                if (self.digest[byte_idx] & mask) != (other.digest[byte_idx] & mask) {
                    return false;
                }
            }
        }
        true
    }

    /// Extend the prefix with one nibble
    pub fn extend(&mut self, nibble: u8) {
        let idx = self.length as usize;
        let byte_idx = idx / 2;
        if idx % 2 == 0 {
            self.digest[byte_idx] = (self.digest[byte_idx] & 0x0F) | ((nibble & 0x0F) << 4);
        } else {
            self.digest[byte_idx] = (self.digest[byte_idx] & 0xF0) | (nibble & 0x0F);
        }
        self.length += 1;
    }
}

/// Hasher for determining node boundaries
pub struct BoundaryHasher {
    /// Number of trailing zero bits required for boundary
    boundary_bits: u8,
    /// Mask for boundary detection
    boundary_mask: u32,
}

impl BoundaryHasher {
    /// Create a new boundary hasher
    pub fn new(boundary_bits: u8) -> Self {
        let boundary_mask = (1u32 << boundary_bits) - 1;
        Self {
            boundary_bits,
            boundary_mask,
        }
    }

    /// Check if a key-value pair creates a boundary
    pub fn is_boundary(&self, key: &[u8], value: &[u8]) -> bool {
        // Use a rolling hash of key + value
        let mut data = Vec::with_capacity(key.len() + value.len());
        data.extend_from_slice(key);
        data.extend_from_slice(value);
        
        let hash = fula_crypto::hashing::hash(&data);
        let hash_bytes = hash.as_bytes();
        
        // Check if lower bits are zero (boundary condition)
        let lower_bits = u32::from_le_bytes([
            hash_bytes[0],
            hash_bytes[1],
            hash_bytes[2],
            hash_bytes[3],
        ]);
        
        (lower_bits & self.boundary_mask) == 0
    }

    /// Get the expected average node size
    pub fn expected_node_size(&self) -> usize {
        1 << self.boundary_bits
    }
}

impl Default for BoundaryHasher {
    fn default() -> Self {
        Self::new(super::DEFAULT_BOUNDARY_BITS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_nibbles() {
        let hash = [0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x9A,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let mut nibbles = HashNibbles::new(&hash);
        
        assert_eq!(nibbles.next(), Some(0x0A));
        assert_eq!(nibbles.next(), Some(0x0B));
        assert_eq!(nibbles.next(), Some(0x0C));
        assert_eq!(nibbles.next(), Some(0x0D));
    }

    #[test]
    fn test_hash_prefix_matching() {
        let hash1 = [0xAB, 0xCD, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let hash2 = [0xAB, 0xCE, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

        let prefix1 = HashPrefix::with_length(hash1, 3); // ABC
        let prefix2 = HashPrefix::with_length(hash2, 3); // ABC
        
        assert!(prefix1.matches(&prefix2));
    }

    #[test]
    fn test_boundary_hasher() {
        let hasher = BoundaryHasher::new(4);
        assert_eq!(hasher.expected_node_size(), 16);
        
        // Test some boundaries
        let mut boundary_count = 0;
        for i in 0..1000 {
            let key = format!("key{}", i);
            let value = format!("value{}", i);
            if hasher.is_boundary(key.as_bytes(), value.as_bytes()) {
                boundary_count += 1;
            }
        }
        
        // Should be roughly 1000/16 = ~62 boundaries
        assert!(boundary_count > 30 && boundary_count < 120);
    }
}
