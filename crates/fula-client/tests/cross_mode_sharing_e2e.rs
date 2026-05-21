//! Cross-mode sharing + collaboration crypto round-trip tests.
//!
//! Covers every (owner_mode, recipient_mode) pair across all three
//! Phase F-A1 / F-A3 sign-up modes (A, B, C) for:
//!
//!   * **Direct share** (FxFiles "share with specific person", Type 3).
//!     Owner wraps DEK to recipient's curve25519 pubkey via HPKE; recipient
//!     unwraps with their derived KEK.
//!   * **Public-link share** (Type 1) — same HPKE flow but the recipient
//!     pubkey is an ephemeral keypair generated at share-creation time
//!     and embedded in the URL. From the SDK's perspective this is just
//!     a share to a random pubkey; the differentiator is FxFiles UI
//!     packaging.
//!   * **Password-link share** (Type 2) — Type 1 + an additional
//!     password-derived AEAD wrap on the URL fragment. The PASSWORD
//!     layer is mode-agnostic by construction (it's just Argon2id +
//!     AES-256-GCM applied to bytes); validated by a single dedicated
//!     round-trip test.
//!   * **Two-way collaboration** (`FolderShareManager`) — folder DEK
//!     shared with member's pubkey, owner can also revoke. Each (owner,
//!     member) mode pair exercises the HPKE wrap with a folder-scoped
//!     `path_scope` + write permissions.
//!
//! ## What these tests prove
//!
//! 1. **Mode is a derivation detail, not a crypto-layer concern.** The
//!    master KEK is `[u8; 32]` regardless of how it was derived. Once
//!    you have the KEK, the curve25519 keypair and HPKE wrap/unwrap
//!    behave identically. These tests empirically confirm that property
//!    by mixing modes on either end of every share.
//!
//! 2. **Cross-mode sharing works at the crypto layer.** A Mode A owner
//!    can share with a Mode B recipient; a Mode C owner can share with
//!    a Mode A recipient; etc. All 9 combos validated for direct shares
//!    + 9 for collab.
//!
//! 3. **The password-wrap layer is mode-orthogonal.** It operates on
//!    the URL fragment bytes, not the master KEK, so a single test
//!    suffices to validate Type 2.
//!
//! ## What these tests DO NOT prove
//!
//! These are PURE CRYPTO ROUND-TRIPS — no master interaction.
//!
//! What's NOT covered here:
//!   * Cross-account network fetch via `get_object_with_share` — the
//!     production SDK uses the recipient's JWT to GET the ciphertext
//!     from master, which scopes by namespace. Recipient cannot fetch
//!     owner's `storage_key` from owner's bucket via master with their
//!     own JWT (returns NoSuchBucket). This is a SEPARATE architectural
//!     question raised during the 2026-05-21 E2E sweep — see the
//!     `share_round_trip_e2e` failure note in `sharing_e2e.rs`. Whether
//!     production sharing actually traverses master, or fetches by CID
//!     via public IPFS gateways, is an open question.
//!
//! ## Running
//!
//! No network, no env vars, no credentials. Runs in stock `cargo test`.

use fula_crypto::{
    hpke::SharePermissions,
    keys::{DekKey, KekKeyPair, PublicKey, SecretKey},
    sharing::{FolderShareManager, ShareBuilder, ShareRecipient},
    Aead, Nonce,
};
use unicode_normalization::UnicodeNormalization as _;

// ════════════════════════════════════════════════════════════════════════════
// Mode-derivation helpers (mirror auth_service.dart byte-for-byte)
// ════════════════════════════════════════════════════════════════════════════

/// Sign-up mode. Identifies HOW the master KEK is derived. Once derived,
/// downstream crypto (HPKE share wrap, AEAD, signing) is mode-agnostic.
#[derive(Debug, Clone, Copy)]
enum Mode {
    A, // OAuth-only: `provider:userId:email` → Argon2id "fula-files-v1"
    B, // OAuth+seed: canonical_kek_input_mode_b → Argon2id "fula-files-v2-mode-b"
    C, // Seed-only:  canonical_kek_input_mode_c → Argon2id "fula-files-v2-mode-c"
}

impl Mode {
    fn label(self) -> &'static str {
        match self {
            Mode::A => "A",
            Mode::B => "B",
            Mode::C => "C",
        }
    }
}

fn canonical_kek_input_mode_b(provider: &str, sub: &str, seed: &str) -> Vec<u8> {
    let provider_b = provider.as_bytes();
    let sub_b = sub.as_bytes();
    let seed_norm: String = seed.nfc().collect();
    let seed_b = seed_norm.as_bytes();
    let mut out = Vec::with_capacity(12 + provider_b.len() + sub_b.len() + seed_b.len());
    out.extend_from_slice(&(provider_b.len() as u32).to_le_bytes());
    out.extend_from_slice(provider_b);
    out.extend_from_slice(&(sub_b.len() as u32).to_le_bytes());
    out.extend_from_slice(sub_b);
    out.extend_from_slice(&(seed_b.len() as u32).to_le_bytes());
    out.extend_from_slice(seed_b);
    out
}

fn canonical_kek_input_mode_c(seed: &str) -> Vec<u8> {
    let seed_norm: String = seed.nfc().collect();
    let seed_b = seed_norm.as_bytes();
    let mut out = Vec::with_capacity(4 + seed_b.len());
    out.extend_from_slice(&(seed_b.len() as u32).to_le_bytes());
    out.extend_from_slice(seed_b);
    out
}

/// Per-mode synthetic identity used by these tests. The actual byte
/// values are arbitrary — what matters is that owner and recipient
/// produce DISTINCT KEKs (so HPKE wrap to recipient's pubkey can't be
/// trivially "unwrapped" by owner's keypair).
struct Identity {
    label: &'static str,
    mode: Mode,
    provider: &'static str,
    oauth_sub: &'static str,
    email: &'static str,
    seed: &'static str,
}

const ALICE_A: Identity = Identity {
    label: "alice-A",
    mode: Mode::A,
    provider: "google",
    oauth_sub: "100000000000000000001",
    email: "alice@example.com",
    seed: "",
};
const BOB_A: Identity = Identity {
    label: "bob-A",
    mode: Mode::A,
    provider: "google",
    oauth_sub: "200000000000000000002",
    email: "bob@example.com",
    seed: "",
};
const ALICE_B: Identity = Identity {
    label: "alice-B",
    mode: Mode::B,
    provider: "google",
    oauth_sub: "100000000000000000001",
    email: "alice@example.com",
    seed: "alice-mode-b-passphrase-2026",
};
const BOB_B: Identity = Identity {
    label: "bob-B",
    mode: Mode::B,
    provider: "google",
    oauth_sub: "200000000000000000002",
    email: "bob@example.com",
    seed: "bob-mode-b-passphrase-2026",
};
const ALICE_C: Identity = Identity {
    label: "alice-C",
    mode: Mode::C,
    provider: "",
    oauth_sub: "",
    email: "",
    seed: "alice-twelve-word-seed-phrase-here-please-verify-abc-def-mode-c",
};
const BOB_C: Identity = Identity {
    label: "bob-C",
    mode: Mode::C,
    provider: "",
    oauth_sub: "",
    email: "",
    seed: "bob-twelve-word-seed-phrase-here-please-verify-xyz-uvw-mode-c",
};

fn derive_kek(id: &Identity) -> [u8; 32] {
    match id.mode {
        Mode::A => {
            let input = format!("{}:{}:{}", id.provider, id.oauth_sub, id.email);
            fula_crypto::hashing::derive_key_argon2id("fula-files-v1", input.as_bytes())
        }
        Mode::B => {
            let input = canonical_kek_input_mode_b(id.provider, id.oauth_sub, id.seed);
            fula_crypto::hashing::derive_key_argon2id("fula-files-v2-mode-b", &input)
        }
        Mode::C => {
            let input = canonical_kek_input_mode_c(id.seed);
            fula_crypto::hashing::derive_key_argon2id("fula-files-v2-mode-c", &input)
        }
    }
}

fn keypair_from_identity(id: &Identity) -> KekKeyPair {
    let kek = derive_kek(id);
    let secret = SecretKey::from_bytes(&kek).expect("secret from kek bytes");
    KekKeyPair::from_secret_key(secret)
}

fn pubkey_from_identity(id: &Identity) -> PublicKey {
    keypair_from_identity(id).public_key().clone()
}

// ════════════════════════════════════════════════════════════════════════════
// Shared round-trip helper for direct (Type 3) share
// ════════════════════════════════════════════════════════════════════════════

/// Cryptographic round-trip:
///   1. Owner has a DEK for some file.
///   2. Owner builds a share token via `ShareBuilder` addressed to
///      recipient's pubkey.
///   3. Token is serialized to JSON (the on-wire format).
///   4. Recipient parses the JSON.
///   5. Recipient `accept_share()`s — internally unwraps the DEK with
///      their KekKeyPair's private key.
///   6. We extract the unwrapped DEK from the accepted-share state
///      and assert it equals what the owner started with.
fn run_direct_share_round_trip(owner: &Identity, recipient: &Identity) {
    let owner_kp = keypair_from_identity(owner);
    let recipient_kp = keypair_from_identity(recipient);

    // Sanity: distinct identities derive distinct keypairs.
    assert_ne!(
        owner_kp.public_key().as_bytes(),
        recipient_kp.public_key().as_bytes(),
        "{} and {} must derive distinct keypairs",
        owner.label,
        recipient.label,
    );

    let dek = DekKey::generate();
    let storage_key = "Qmabc123abc123abc123abc123abc123abc123";

    let token = ShareBuilder::new(&owner_kp, recipient_kp.public_key(), &dek)
        .path_scope(storage_key)
        .read_only()
        .build()
        .expect("ShareBuilder.build");

    // Round-trip through JSON like the FFI does.
    let token_json = serde_json::to_string(&token).expect("ShareToken to JSON");
    let parsed: fula_crypto::sharing::ShareToken =
        serde_json::from_str(&token_json).expect("ShareToken from JSON");

    // Recipient accepts using their own keypair via the production
    // `ShareRecipient::accept_share` (validates expiry, version, AAD
    // binding, then unwraps the DEK).
    let recipient = ShareRecipient::new(&recipient_kp);
    let accepted = recipient
        .accept_share(&parsed)
        .expect("recipient must be able to accept this token");

    assert_eq!(
        accepted.dek.as_bytes(),
        dek.as_bytes(),
        "unwrapped DEK must equal owner's original DEK ({}→{})",
        owner.label,
        recipient_id_label(recipient_kp.public_key()),
    );
    assert!(
        accepted.permissions.can_read,
        "share built with .read_only() must grant read permission",
    );
    assert!(
        accepted.is_path_allowed(storage_key),
        "share's path_scope must permit the original storage_key",
    );
}

fn recipient_id_label(pk: &PublicKey) -> String {
    hex::encode(&pk.as_bytes()[..4])
}

// ════════════════════════════════════════════════════════════════════════════
// DIRECT SHARE (Type 3) — 9 cross-mode tests
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn share_direct_mode_a_to_a() { run_direct_share_round_trip(&ALICE_A, &BOB_A); }
#[test]
fn share_direct_mode_a_to_b() { run_direct_share_round_trip(&ALICE_A, &BOB_B); }
#[test]
fn share_direct_mode_a_to_c() { run_direct_share_round_trip(&ALICE_A, &BOB_C); }
#[test]
fn share_direct_mode_b_to_a() { run_direct_share_round_trip(&ALICE_B, &BOB_A); }
#[test]
fn share_direct_mode_b_to_b() { run_direct_share_round_trip(&ALICE_B, &BOB_B); }
#[test]
fn share_direct_mode_b_to_c() { run_direct_share_round_trip(&ALICE_B, &BOB_C); }
#[test]
fn share_direct_mode_c_to_a() { run_direct_share_round_trip(&ALICE_C, &BOB_A); }
#[test]
fn share_direct_mode_c_to_b() { run_direct_share_round_trip(&ALICE_C, &BOB_B); }
#[test]
fn share_direct_mode_c_to_c() { run_direct_share_round_trip(&ALICE_C, &BOB_C); }

// ════════════════════════════════════════════════════════════════════════════
// PUBLIC-LINK SHARE (Type 1) — ephemeral recipient keypair
// ════════════════════════════════════════════════════════════════════════════

/// Mirrors the public-link flow: owner generates an ephemeral keypair
/// per share, wraps DEK to the ephemeral pubkey, embeds the ephemeral
/// private key in the URL fragment. Any user with the URL can unwrap.
fn run_public_link_round_trip(owner: &Identity) {
    let owner_kp = keypair_from_identity(owner);
    let dek = DekKey::generate();
    let storage_key = "Qmpubliclinktarget0000000000000000000";

    // Ephemeral keypair — what FxFiles' Type 1 URL generator does.
    // The "recipient" in this flow has no fula account; they just have
    // the ephemeral private key from the URL.
    let ephemeral_kp = KekKeyPair::generate();
    let token = ShareBuilder::new(&owner_kp, ephemeral_kp.public_key(), &dek)
        .path_scope(storage_key)
        .read_only()
        .build()
        .expect("public link token build");

    // Anyone with the ephemeral private key can unwrap.
    let token_json = serde_json::to_string(&token).expect("to JSON");
    let parsed: fula_crypto::sharing::ShareToken =
        serde_json::from_str(&token_json).expect("from JSON");
    let recipient = ShareRecipient::new(&ephemeral_kp);
    let accepted = recipient.accept_share(&parsed).expect("accept");
    assert_eq!(accepted.dek.as_bytes(), dek.as_bytes());
}

#[test]
fn share_public_link_mode_a() { run_public_link_round_trip(&ALICE_A); }
#[test]
fn share_public_link_mode_b() { run_public_link_round_trip(&ALICE_B); }
#[test]
fn share_public_link_mode_c() { run_public_link_round_trip(&ALICE_C); }

// ════════════════════════════════════════════════════════════════════════════
// PASSWORD-LINK SHARE (Type 2) — Type 1 + Argon2id-AEAD on the URL fragment
// ════════════════════════════════════════════════════════════════════════════

/// Type 2's password-wrap layer is mode-agnostic — it operates on the
/// URL fragment bytes (which carry the ephemeral private key + share
/// token JSON), not on the master KEK. A single round-trip suffices.
///
/// We use Argon2id with a fixed context to derive a wrap key from the
/// password, then AEAD-wrap the URL payload. The reverse path
/// decrypts under the same derivation. Mode of either party is
/// irrelevant — that's the property being asserted.
#[test]
fn share_password_wrap_round_trip() {
    let password = "correct horse battery staple";

    // Step 1: derive a DEK-equivalent wrap key from the password via
    // Argon2id (memory-hard) and wrap it into a DekKey for the SDK's
    // Aead primitive.
    let wrap_key_bytes = fula_crypto::hashing::derive_key_argon2id(
        "fula:share-link-password:v1",
        password.as_bytes(),
    );
    let wrap_key = DekKey::from_bytes(&wrap_key_bytes).expect("DekKey from 32 bytes");
    let aead = Aead::new_default(&wrap_key);

    // Step 2: build a synthetic URL payload (would be ephemeral_priv +
    // share token JSON in production).
    let synthetic_payload = b"FAKE_EPHEMERAL_PRIV_AND_TOKEN_JSON".to_vec();
    let aad = b"fula:share-link-password:v1";

    // Step 3: AEAD-wrap with a fresh random nonce.
    let nonce = Nonce::generate();
    let ciphertext = aead
        .encrypt_with_aad(&nonce, &synthetic_payload, aad)
        .expect("AEAD encrypt");

    // Step 4: reverse — re-derive wrap key from password, unwrap.
    let unwrap_key_bytes = fula_crypto::hashing::derive_key_argon2id(
        "fula:share-link-password:v1",
        password.as_bytes(),
    );
    assert_eq!(
        wrap_key_bytes, unwrap_key_bytes,
        "Argon2id must be deterministic"
    );
    let unwrap_key = DekKey::from_bytes(&unwrap_key_bytes).unwrap();
    let unwrap_aead = Aead::new_default(&unwrap_key);
    let recovered = unwrap_aead
        .decrypt_with_aad(&nonce, &ciphertext, aad)
        .expect("AEAD decrypt with correct password");

    assert_eq!(recovered, synthetic_payload);
}

/// Wrong-password must fail to decrypt.
#[test]
fn share_password_wrap_wrong_password_fails() {
    let right_password = "correct horse battery staple";
    let wrong_password = "Tr0ub4dor&3";

    let right_key_bytes = fula_crypto::hashing::derive_key_argon2id(
        "fula:share-link-password:v1",
        right_password.as_bytes(),
    );
    let wrong_key_bytes = fula_crypto::hashing::derive_key_argon2id(
        "fula:share-link-password:v1",
        wrong_password.as_bytes(),
    );
    assert_ne!(right_key_bytes, wrong_key_bytes);

    let right_key = DekKey::from_bytes(&right_key_bytes).unwrap();
    let wrong_key = DekKey::from_bytes(&wrong_key_bytes).unwrap();
    let right_aead = Aead::new_default(&right_key);
    let wrong_aead = Aead::new_default(&wrong_key);
    let aad = b"fula:share-link-password:v1";

    let nonce = Nonce::generate();
    let ciphertext = right_aead
        .encrypt_with_aad(&nonce, b"secret payload", aad)
        .unwrap();

    let result = wrong_aead.decrypt_with_aad(&nonce, &ciphertext, aad);
    assert!(result.is_err(), "wrong password must fail to decrypt");
}

// ════════════════════════════════════════════════════════════════════════════
// COLLABORATION (FolderShareManager) — 9 cross-mode tests
// ════════════════════════════════════════════════════════════════════════════

/// Two-way collab uses `FolderShareManager` to wrap a folder DEK to
/// each member's pubkey with read+write permissions. Same HPKE
/// primitive, just folder-scoped path + explicit permissions.
fn run_collab_round_trip(owner: &Identity, member: &Identity) {
    let owner_kp = keypair_from_identity(owner);
    let member_kp = keypair_from_identity(member);

    assert_ne!(
        owner_kp.public_key().as_bytes(),
        member_kp.public_key().as_bytes(),
        "owner {} and member {} must be distinct identities",
        owner.label,
        member.label,
    );

    let folder_path = "/.fula/collab/test-group-2026/manifest.json";
    let folder_dek = DekKey::generate();

    let mut mgr = FolderShareManager::new();
    mgr.register_folder(folder_path, folder_dek.clone());

    let perms = SharePermissions::read_write();

    let share = mgr
        .create_share(
            &owner_kp,
            folder_path,
            member_kp.public_key(),
            None, // no expiry
            perms.clone(),
        )
        .expect("create_share");

    // Round-trip through JSON.
    let json = serde_json::to_string(&share).unwrap();
    let parsed: fula_crypto::sharing::ShareToken = serde_json::from_str(&json).unwrap();

    // Member accepts → unwraps DEK with their secret via the
    // production ShareRecipient path.
    let recipient = ShareRecipient::new(&member_kp);
    let accepted = recipient
        .accept_share(&parsed)
        .expect("member must be able to accept collab share");
    assert_eq!(accepted.dek.as_bytes(), folder_dek.as_bytes());

    // Permissions survive the JSON round-trip.
    assert!(accepted.permissions.can_read, "collab member must have read");
    assert!(accepted.permissions.can_write, "collab member must have write");

    // Path scope check — member's access is bounded to the manifest path.
    assert!(accepted.is_path_allowed(folder_path));

    // Revoke cleanly. (Doesn't affect already-accepted-and-unwrapped
    // DEK on the member's side — same as production: revocation is
    // future-oriented.)
    assert!(
        mgr.revoke_share(folder_path, &share.id),
        "revoke must succeed for a known share id"
    );
    assert_eq!(mgr.list_shares(folder_path).len(), 0);
}

#[test]
fn collab_mode_a_to_a() { run_collab_round_trip(&ALICE_A, &BOB_A); }
#[test]
fn collab_mode_a_to_b() { run_collab_round_trip(&ALICE_A, &BOB_B); }
#[test]
fn collab_mode_a_to_c() { run_collab_round_trip(&ALICE_A, &BOB_C); }
#[test]
fn collab_mode_b_to_a() { run_collab_round_trip(&ALICE_B, &BOB_A); }
#[test]
fn collab_mode_b_to_b() { run_collab_round_trip(&ALICE_B, &BOB_B); }
#[test]
fn collab_mode_b_to_c() { run_collab_round_trip(&ALICE_B, &BOB_C); }
#[test]
fn collab_mode_c_to_a() { run_collab_round_trip(&ALICE_C, &BOB_A); }
#[test]
fn collab_mode_c_to_b() { run_collab_round_trip(&ALICE_C, &BOB_B); }
#[test]
fn collab_mode_c_to_c() { run_collab_round_trip(&ALICE_C, &BOB_C); }

// ════════════════════════════════════════════════════════════════════════════
// NEGATIVE-CONTROL TESTS — wrong recipient must NOT unwrap
// ════════════════════════════════════════════════════════════════════════════

/// A share wrapped to Bob must not be unwrappable by Carol — across
/// any mode combination.
#[test]
fn share_wrong_recipient_fails_a_to_b_not_c() {
    let owner_kp = keypair_from_identity(&ALICE_A);
    let bob_kp = keypair_from_identity(&BOB_B);
    let carol_kp = keypair_from_identity(&BOB_C);

    let dek = DekKey::generate();
    let token = ShareBuilder::new(&owner_kp, bob_kp.public_key(), &dek)
        .path_scope("Qmtarget")
        .read_only()
        .build()
        .unwrap();

    let token_json = serde_json::to_string(&token).unwrap();
    let parsed: fula_crypto::sharing::ShareToken =
        serde_json::from_str(&token_json).unwrap();

    // Carol's decryptor MUST fail.
    // Carol attempts to accept via the production path — must fail.
    let carol_recipient = ShareRecipient::new(&carol_kp);
    assert!(
        carol_recipient.accept_share(&parsed).is_err(),
        "wrong recipient must fail to accept the share"
    );
}

/// Same test but with the negative-control recipient in Mode A (rules
/// out any "Mode B/C is broken" false positive).
#[test]
fn share_wrong_recipient_fails_c_to_a_not_b() {
    let owner_kp = keypair_from_identity(&ALICE_C);
    let target_kp = keypair_from_identity(&BOB_A);
    let wrong_kp = keypair_from_identity(&BOB_B);

    let dek = DekKey::generate();
    let token = ShareBuilder::new(&owner_kp, target_kp.public_key(), &dek)
        .path_scope("Qmtarget")
        .read_only()
        .build()
        .unwrap();

    let token_json = serde_json::to_string(&token).unwrap();
    let parsed: fula_crypto::sharing::ShareToken =
        serde_json::from_str(&token_json).unwrap();

    let wrong_recipient = ShareRecipient::new(&wrong_kp);
    assert!(
        wrong_recipient.accept_share(&parsed).is_err(),
        "wrong recipient must fail to accept the share"
    );
}

// ════════════════════════════════════════════════════════════════════════════
// EXPIRY + REVOCATION + PERMISSIONS — generic crypto property tests
// ════════════════════════════════════════════════════════════════════════════

/// An expired share must not validate, even if the crypto round-trips
/// cleanly. (Belt-and-suspenders: the SDK's `is_valid()` check fires
/// before the unwrap on the production path.)
#[test]
fn share_expired_token_is_invalid() {
    let owner_kp = keypair_from_identity(&ALICE_A);
    let recipient_kp = keypair_from_identity(&BOB_C);

    let dek = DekKey::generate();
    let token = ShareBuilder::new(&owner_kp, recipient_kp.public_key(), &dek)
        .path_scope("Qmtarget")
        .read_only()
        .expires_at(1_000_000_000) // year 2001 — clearly past
        .build()
        .unwrap();

    let token_json = serde_json::to_string(&token).unwrap();
    let parsed: fula_crypto::sharing::ShareToken =
        serde_json::from_str(&token_json).unwrap();

    assert!(parsed.is_expired(), "token from year 2001 must be expired in 2026");
}

/// Read-only permissions must NOT include write.
#[test]
fn share_read_only_does_not_grant_write() {
    let owner_kp = keypair_from_identity(&ALICE_B);
    let recipient_kp = keypair_from_identity(&BOB_C);

    let dek = DekKey::generate();
    let token = ShareBuilder::new(&owner_kp, recipient_kp.public_key(), &dek)
        .path_scope("Qmtarget")
        .read_only()
        .build()
        .unwrap();

    assert!(token.permissions.can_read);
    assert!(!token.permissions.can_write);
}
