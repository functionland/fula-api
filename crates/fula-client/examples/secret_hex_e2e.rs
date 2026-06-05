//! TEMP: derive and print FULA_SECRET_HEX (the 64-hex root secret recover_walk
//! needs) from the same KEK the app uses. NOT COMMITTED (reads creds from env).
//!
//!   $env:FULA_KEK_INPUT="google:<sub>:<email>"
//!   cargo run -p fula-client --example secret_hex_e2e

fn main() {
    let kek = std::env::var("FULA_KEK_INPUT").expect("set FULA_KEK_INPUT");
    let secret = fula_crypto::hashing::derive_key_argon2id("fula-files-v1", kek.as_bytes());
    let h: String = secret.iter().map(|b| format!("{:02x}", b)).collect();
    println!("FULA_SECRET_HEX={}", h);
    println!("len={}", secret.len());
}
