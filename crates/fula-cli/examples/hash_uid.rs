//! Compute hash_user_id(arg) = BLAKE3("fula:user_id:"||arg)[..16] hex — the
//! gateway's bucket-key prefix / owner_id. Used to check which JWT-sub a
//! bucket's owner_id corresponds to (email vs sha256(email)).
use blake3::Hasher;

fn main() {
    for arg in std::env::args().skip(1) {
        let mut h = Hasher::new();
        h.update(b"fula:user_id:");
        h.update(arg.as_bytes());
        println!("{} -> {}", arg, hex::encode(&h.finalize().as_bytes()[..16]));
    }
}
