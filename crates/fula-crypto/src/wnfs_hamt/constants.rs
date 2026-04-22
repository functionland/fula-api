// Vendored from rs-wnfs/wnfs-hamt/src/constants.rs (Apache-2.0). See NOTICE.

/// The number of bits used per level of the HAMT. At each level the bitmask is
/// `2^HAMT_BITMASK_BIT_SIZE` bits wide; with the value 16 each node can hold up
/// to 16 children or value buckets, and each traversal step consumes one
/// nibble (4 bits) of the key hash.
pub const HAMT_BITMASK_BIT_SIZE: usize = 16;

/// Number of bytes in the bitmask (16 bits = 2 bytes).
pub const HAMT_BITMASK_BYTE_SIZE: usize = 2;

/// Maximum number of key-value pairs stored inline in a single `Pointer::Values`
/// bucket before the bucket is split into a `Pointer::Link` subtree.
pub const HAMT_VALUES_BUCKET_SIZE: usize = 3;
