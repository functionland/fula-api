//! One-shot helper: derive FULA_TEST_SECRET from FULA_TEST_PROVIDER +
//! FULA_TEST_OAUTH_SUB + FULA_TEST_EMAIL using the same Argon2id call
//! FxFiles + the e2e tests use (`fula-files-v1` domain).
//!
//! Outputs the base64-encoded 32-byte key on stdout so a parent shell
//! can capture it into `FULA_TEST_SECRET`.

use base64::Engine as _;

fn main() {
    let provider = std::env::var("FULA_TEST_PROVIDER").expect("FULA_TEST_PROVIDER not set");
    let sub = std::env::var("FULA_TEST_OAUTH_SUB").expect("FULA_TEST_OAUTH_SUB not set");
    let email = std::env::var("FULA_TEST_EMAIL").expect("FULA_TEST_EMAIL not set");
    let input = format!("{}:{}:{}", provider, sub, email);
    let key = fula_crypto::hashing::derive_key_argon2id("fula-files-v1", input.as_bytes());
    let b64 = base64::engine::general_purpose::STANDARD.encode(&key);
    println!("{}", b64);
}
