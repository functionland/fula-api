// Vendored and stripped from rs-wnfs/wnfs-hamt/src/hash.rs (Apache-2.0). See NOTICE.
//
// Only `HashNibbles` is carried over. `HashPrefix` and its iterator serve
// the `get_node_at` / `diff` code paths that are deferred to phase 2.

use crate::hashing::{HASH_BYTE_SIZE, HashOutput};
use crate::{CryptoError, Result};
use std::fmt::Debug;

/// The maximum number of nibbles in a `HashOutput`.
pub const MAX_HASH_NIBBLE_LENGTH: usize = HASH_BYTE_SIZE * 2;

/// A cursor over the nibbles (4-bit half-bytes) of a `HashOutput`.
///
/// The HAMT traversal consumes one nibble per level of descent; `HashNibbles`
/// remembers where the cursor is so that recursive descents pick up from the
/// right depth without rehashing.
#[derive(Clone)]
pub struct HashNibbles<'a> {
    pub digest: &'a HashOutput,
    cursor: usize,
}

impl<'a> HashNibbles<'a> {
    /// Create a new cursor starting at the top of the digest.
    pub fn new(digest: &'a HashOutput) -> HashNibbles<'a> {
        Self::with_cursor(digest, 0)
    }

    /// Create a cursor at an arbitrary nibble position.
    pub fn with_cursor(digest: &'a HashOutput, cursor: usize) -> HashNibbles<'a> {
        Self { digest, cursor }
    }

    /// Consume the next nibble, returning an error if the cursor has been
    /// exhausted. Used by HAMT descent code that *must* have more nibbles
    /// to make progress.
    pub fn try_next(&mut self) -> Result<usize> {
        self.next()
            .map(|n| n as usize)
            .ok_or_else(|| CryptoError::Hamt("hash cursor out of bounds".into()))
    }

    #[inline]
    pub fn get_cursor(&self) -> usize {
        self.cursor
    }
}

impl Iterator for HashNibbles<'_> {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        if self.cursor >= MAX_HASH_NIBBLE_LENGTH {
            return None;
        }

        let byte = self.digest[self.cursor / 2];
        let byte = if self.cursor % 2 == 0 {
            byte >> 4
        } else {
            byte & 0b0000_1111
        };

        self.cursor += 1;
        Some(byte)
    }
}

impl Debug for HashNibbles<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut s = String::with_capacity(MAX_HASH_NIBBLE_LENGTH);
        for nibble in HashNibbles::with_cursor(self.digest, 0) {
            s.push_str(&format!("{nibble:1X}"));
        }
        f.debug_struct("HashNibbles")
            .field("hash", &s)
            .field("cursor", &self.cursor)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_traverses_all_nibbles_and_stops() {
        let key = {
            let mut bytes = [0u8; HASH_BYTE_SIZE];
            bytes[0] = 0b1000_1100;
            bytes[1] = 0b1010_1010;
            bytes[2] = 0b1011_1111;
            bytes[3] = 0b1111_1101;
            bytes
        };

        let nibbles = &mut HashNibbles::new(&key);
        let expected = [
            0b1000, 0b1100, 0b1010, 0b1010, 0b1011, 0b1111, 0b1111, 0b1101,
        ];
        for (got, exp) in nibbles.zip(expected.into_iter()) {
            assert_eq!(exp, got);
        }
        let _ = nibbles
            .take(MAX_HASH_NIBBLE_LENGTH - expected.len())
            .collect::<Vec<_>>();
        assert_eq!(nibbles.next(), None);
    }

    #[test]
    fn try_next_errors_when_exhausted() {
        let key = [0u8; HASH_BYTE_SIZE];
        let mut nibbles = HashNibbles::with_cursor(&key, MAX_HASH_NIBBLE_LENGTH);
        assert!(nibbles.try_next().is_err());
    }
}
