//! FM-4 (Phase 2.5) — portable identity: EIP-712 wallet-signature auth.
//!
//! Federated masters must authenticate the SAME user identically without
//! sharing master-local secrets. A wallet signature is self-certifying:
//! any master can verify it offline (no JWT secret, no session table), so
//! one identity works everywhere — and it is the same wallet the staking /
//! MasterRegistry phases key on.
//!
//! Token format (sent as the Bearer value; the prefix routes it):
//!
//!   fula-eip712.<base64url(payload-json)>.<base64url(65-byte rsv signature)>
//!
//! payload JSON: {"wallet":"0x..","iat":<unix>,"exp":<unix>}
//!
//! The signature is an EIP-712 typed signature over:
//!   domain  = { name: "Fula Gateway", version: "1" }        (chain-agnostic)
//!   message = FulaAuth { wallet: address, iat: uint256, exp: uint256 }
//!
//! Verification: recover the secp256k1 signer from the digest, require it to
//! equal `payload.wallet`, require `iat - 300 ≤ now ≤ exp` and a lifetime of
//! at most 24 h. The resulting session's user id IS the lowercase wallet
//! address — every master derives the same hashed user id from it.
//!
//! Scope: fixed to `storage:*`. Replay within the validity window is
//! accepted (bearer-token semantics, same as a JWT); short `exp` is the
//! mitigation, and the existing revocation deny-list applies to the raw
//! token string unchanged.
//!
//! Additive: the legacy JWT/session path is untouched; this path only
//! activates behind `FULA_EIP712_AUTH` AND the `fula-eip712.` prefix.
//!
//! Known v0 limitation (documented in #32): per-PUT registry pinning
//! forwards the bearer to the pinning service, which only knows ITS issued
//! sessions — an EIP-712 bearer 401s there, so registry persistence
//! requires the pinning service to accept this scheme too (follow-up).
//! Storage-only Stage-B operators (no pinning service) are unaffected.

use crate::error::ApiError;
use crate::state::UserSession;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use serde::Deserialize;
use sha3::{Digest, Keccak256};

pub const TOKEN_PREFIX: &str = "fula-eip712.";

/// Maximum allowed token lifetime (exp - iat).
const MAX_LIFETIME_SECS: i64 = 24 * 60 * 60;
/// Allowed clock skew on `iat`.
const IAT_SKEW_SECS: i64 = 300;

#[derive(Debug, Deserialize)]
struct Eip712Payload {
    wallet: String,
    iat: i64,
    exp: i64,
}

fn keccak(data: &[u8]) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(data);
    h.finalize().into()
}

/// keccak256("EIP712Domain(string name,string version)") with our values.
fn domain_separator() -> [u8; 32] {
    let type_hash = keccak(b"EIP712Domain(string name,string version)");
    let name_hash = keccak(b"Fula Gateway");
    let version_hash = keccak(b"1");
    let mut enc = Vec::with_capacity(96);
    enc.extend_from_slice(&type_hash);
    enc.extend_from_slice(&name_hash);
    enc.extend_from_slice(&version_hash);
    keccak(&enc)
}

/// keccak256(typeHash ‖ wallet-as-uint256 ‖ iat ‖ exp)
fn struct_hash(wallet: &[u8; 20], iat: i64, exp: i64) -> [u8; 32] {
    let type_hash = keccak(b"FulaAuth(address wallet,uint256 iat,uint256 exp)");
    let mut enc = Vec::with_capacity(128);
    enc.extend_from_slice(&type_hash);
    let mut addr32 = [0u8; 32];
    addr32[12..].copy_from_slice(wallet);
    enc.extend_from_slice(&addr32);
    let mut int32 = [0u8; 32];
    int32[24..].copy_from_slice(&(iat as u64).to_be_bytes());
    enc.extend_from_slice(&int32);
    let mut exp32 = [0u8; 32];
    exp32[24..].copy_from_slice(&(exp as u64).to_be_bytes());
    enc.extend_from_slice(&exp32);
    keccak(&enc)
}

/// The EIP-712 signing digest: keccak256(0x1901 ‖ domainSeparator ‖ structHash).
pub fn signing_digest(wallet: &[u8; 20], iat: i64, exp: i64) -> [u8; 32] {
    let mut enc = Vec::with_capacity(66);
    enc.extend_from_slice(&[0x19, 0x01]);
    enc.extend_from_slice(&domain_separator());
    enc.extend_from_slice(&struct_hash(wallet, iat, exp));
    keccak(&enc)
}

fn parse_wallet(s: &str) -> Result<[u8; 20], ApiError> {
    let hexpart = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(hexpart)
        .map_err(|_| bad("wallet is not valid hex"))?;
    bytes
        .try_into()
        .map_err(|_| bad("wallet must be 20 bytes"))
}

fn bad(msg: &str) -> ApiError {
    ApiError::s3(crate::error::S3ErrorCode::InvalidToken, msg)
}

/// Verify a `fula-eip712.` bearer and mint the portable session.
pub fn verify_eip712_token(token: &str) -> Result<UserSession, ApiError> {
    let rest = token
        .strip_prefix(TOKEN_PREFIX)
        .ok_or_else(|| bad("not an eip712 token"))?;
    let (payload_b64, sig_b64) = rest
        .split_once('.')
        .ok_or_else(|| bad("malformed eip712 token (need payload.signature)"))?;

    let payload_bytes = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|_| bad("payload is not base64url"))?;
    let payload: Eip712Payload =
        serde_json::from_slice(&payload_bytes).map_err(|_| bad("payload is not valid JSON"))?;

    let now = chrono::Utc::now().timestamp();
    if payload.exp <= now {
        return Err(bad("eip712 token expired"));
    }
    if payload.iat > now + IAT_SKEW_SECS {
        return Err(bad("eip712 token iat is in the future"));
    }
    if payload.exp - payload.iat > MAX_LIFETIME_SECS {
        return Err(bad("eip712 token lifetime exceeds 24h"));
    }

    let wallet = parse_wallet(&payload.wallet)?;
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(sig_b64)
        .map_err(|_| bad("signature is not base64url"))?;
    if sig_bytes.len() != 65 {
        return Err(bad("signature must be 65 bytes (r‖s‖v)"));
    }
    let v = sig_bytes[64];
    let rec_id = RecoveryId::try_from(match v {
        0 | 1 => v,
        27 | 28 => v - 27,
        _ => return Err(bad("invalid recovery id")),
    })
    .map_err(|_| bad("invalid recovery id"))?;
    let signature =
        Signature::from_slice(&sig_bytes[..64]).map_err(|_| bad("invalid signature bytes"))?;

    let digest = signing_digest(&wallet, payload.iat, payload.exp);
    let recovered = VerifyingKey::recover_from_prehash(&digest, &signature, rec_id)
        .map_err(|_| bad("signature recovery failed"))?;

    // Ethereum address = last 20 bytes of keccak256(uncompressed pubkey[1..]).
    let pub_uncompressed = recovered.to_encoded_point(false);
    let addr_hash = keccak(&pub_uncompressed.as_bytes()[1..]);
    let recovered_addr: [u8; 20] = addr_hash[12..].try_into().expect("20 bytes");

    if recovered_addr != wallet {
        return Err(bad("signature does not match the claimed wallet"));
    }

    let wallet_lower = format!("0x{}", hex::encode(wallet));
    let expires_at = chrono::DateTime::from_timestamp(payload.exp, 0)
        .unwrap_or_else(|| chrono::Utc::now() + chrono::Duration::hours(1));

    Ok(UserSession::new(
        wallet_lower,
        None,
        vec!["storage:*".to_string()],
        expires_at,
        token.to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::SigningKey;

    fn test_key() -> SigningKey {
        SigningKey::from_slice(&[0x42u8; 32]).expect("static test key")
    }

    fn addr_of(key: &SigningKey) -> [u8; 20] {
        let pubkey = key.verifying_key().to_encoded_point(false);
        let h = keccak(&pubkey.as_bytes()[1..]);
        h[12..].try_into().unwrap()
    }

    fn mint(key: &SigningKey, wallet: [u8; 20], iat: i64, exp: i64) -> String {
        let digest = signing_digest(&wallet, iat, exp);
        let (sig, rec) = key.sign_prehash_recoverable(&digest).unwrap();
        let mut sig65 = sig.to_bytes().to_vec();
        sig65.push(rec.to_byte());
        let payload = serde_json::json!({
            "wallet": format!("0x{}", hex::encode(wallet)),
            "iat": iat,
            "exp": exp,
        });
        format!(
            "{}{}.{}",
            TOKEN_PREFIX,
            URL_SAFE_NO_PAD.encode(payload.to_string()),
            URL_SAFE_NO_PAD.encode(sig65)
        )
    }

    #[test]
    fn valid_signature_yields_portable_wallet_session() {
        let key = test_key();
        let wallet = addr_of(&key);
        let now = chrono::Utc::now().timestamp();
        let token = mint(&key, wallet, now - 10, now + 3600);

        let session = verify_eip712_token(&token).expect("valid token");
        assert_eq!(session.user_id, format!("0x{}", hex::encode(wallet)));
        assert!(session.can_write(), "storage:* must grant write");
    }

    #[test]
    fn wrong_wallet_claim_is_rejected() {
        let key = test_key();
        let now = chrono::Utc::now().timestamp();
        // Sign for OUR address but claim a different wallet in the payload.
        let claimed = [0x11u8; 20];
        let digest = signing_digest(&claimed, now - 10, now + 3600);
        let (sig, rec) = key.sign_prehash_recoverable(&digest).unwrap();
        let mut sig65 = sig.to_bytes().to_vec();
        sig65.push(rec.to_byte());
        let payload = serde_json::json!({
            "wallet": format!("0x{}", hex::encode(claimed)),
            "iat": now - 10,
            "exp": now + 3600,
        });
        let token = format!(
            "{}{}.{}",
            TOKEN_PREFIX,
            URL_SAFE_NO_PAD.encode(payload.to_string()),
            URL_SAFE_NO_PAD.encode(sig65)
        );
        assert!(verify_eip712_token(&token).is_err());
    }

    #[test]
    fn tampered_payload_is_rejected() {
        let key = test_key();
        let wallet = addr_of(&key);
        let now = chrono::Utc::now().timestamp();
        let token = mint(&key, wallet, now - 10, now + 3600);
        // Re-encode with a longer exp but the ORIGINAL signature.
        let parts: Vec<&str> = token.trim_start_matches(TOKEN_PREFIX).split('.').collect();
        let forged_payload = serde_json::json!({
            "wallet": format!("0x{}", hex::encode(wallet)),
            "iat": now - 10,
            "exp": now + 7200,
        });
        let forged = format!(
            "{}{}.{}",
            TOKEN_PREFIX,
            URL_SAFE_NO_PAD.encode(forged_payload.to_string()),
            parts[1]
        );
        assert!(verify_eip712_token(&forged).is_err());
    }

    #[test]
    fn expired_and_overlong_tokens_are_rejected() {
        let key = test_key();
        let wallet = addr_of(&key);
        let now = chrono::Utc::now().timestamp();
        assert!(verify_eip712_token(&mint(&key, wallet, now - 7200, now - 3600)).is_err());
        assert!(verify_eip712_token(&mint(&key, wallet, now, now + 90_000)).is_err());
    }

    #[test]
    fn same_token_verifies_identically_with_no_local_state() {
        // The portability property: verification uses NOTHING but the token —
        // two "masters" (two verify calls with no shared setup) agree.
        let key = test_key();
        let wallet = addr_of(&key);
        let now = chrono::Utc::now().timestamp();
        let token = mint(&key, wallet, now - 10, now + 600);
        let a = verify_eip712_token(&token).unwrap();
        let b = verify_eip712_token(&token).unwrap();
        assert_eq!(a.user_id, b.user_id);
        assert_eq!(a.hashed_user_id, b.hashed_user_id);
    }
}
