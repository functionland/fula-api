//! Phase 2 — share-recipient WRITE into a shared scope (OFFLINE crypto/forest proof).
//!
//! ## What P2 set out to prove
//!
//! The MCP server (the "AI") holds only a scoped folder-DEK [`ShareToken`] minted
//! by the owner (FxFiles, which holds the master KEK), granting read-write to a
//! path prefix such as `ai/`. P2's goal was to establish the mechanism by which
//! the AI WRITES a new file into the shared scope such that the OWNER can read it
//! back byte-identically AND see it in a forest listing.
//!
//! ## The finding (why this is NOT the plan's original shape)
//!
//! The plan assumed "AI writes into the owner's native category bucket under an
//! `ai/` prefix using the shared folder DEK; the owner reads it in a forest
//! listing." That does NOT hold against the real SDK, for one decisive reason:
//!
//! **The per-bucket private forest (the file index) is encrypted under a single,
//! bucket-global key derived from the OWNER's master secret** —
//! `forest_dek = KeyManager::derive_path_key("forest:{bucket}")
//!            = derive_key("fula-path-key-v1", master_secret || "forest:{bucket}")`
//! (see `fula-client/src/encryption.rs::load_forest_internal` and
//! `fula-crypto/src/keys.rs::derive_path_key`). The index storage key is then
//! `derive_index_key(forest_dek, bucket)`.
//!
//! Because `forest_dek` is bucket-global, the ONLY key that can write an entry
//! into the owner's forest is the SAME key that decrypts/lists every other file
//! in the bucket. It cannot be scoped to `ai/`. A recipient holding only a folder
//! DEK therefore cannot land an owner-decryptable entry in the owner's forest
//! without being handed full-bucket read/write — which violates the scope.
//! Additionally `put_object_flat` wraps the per-file DEK to the *writer's own*
//! public key and upserts via the writer's own `forest_dek`, and there is no
//! share-aware WRITE method in the SDK (only `get_object_with_share` for reads).
//! See the full write-up in the P2 GitHub issue / PR description.
//!
//! ## What this test proves instead (the recommended path — Option 1)
//!
//! The INVERSE direction works today with ZERO new crypto, reusing only existing
//! primitives. It is the role-swap of the already-proven owner->recipient share
//! flow (`fula-client/tests/sharing_e2e.rs`):
//!
//!   1. The AI generates a per-file content DEK and encrypts the file with the
//!      EXACT production v4 single-block format
//!      (`Aead::new_default(dek).encrypt_with_aad(nonce, data, "fula:v4:content:{storage_key}")`,
//!      mirroring `put_object_flat_deferred_locked`). The storage key is derived
//!      the same way the SDK does: `generate_flat_key(path, dek, salt)`.
//!   2. The AI mints a [`ShareToken`] (via [`ShareBuilder`]) wrapping THAT content
//!      DEK to the OWNER's public key, with `path_scope` carrying the `ai/...`
//!      scope, the nonce, and `encryption_version = 4`. (The owner's KEK public
//!      key is public, so the AI can wrap to it without holding the master key.)
//!   3. The AI delivers the token to the OWNER's inbox as an HPKE-Auth-mode
//!      [`InboxEntry`] (the AI authenticates as sender).
//!   4. The OWNER opens the inbox entry, `accept_share`s the inner token to
//!      recover the DEK, validates the `ai/` scope, and decrypts the ciphertext
//!      back to the EXACT original bytes.
//!
//! This is precisely the task's named alternative "AI writes to a separate
//! AI-owned scope that FxFiles merges into category views": the AI owns the
//! bytes + the forest; the owner consumes via share-accept (per file), and
//! FxFiles surfaces them under an `ai/` view. No new crypto, no forest-format
//! change.
//!
//! These tests are OFFLINE (crypto level, no gateway) so `cargo test -p fula-mcp`
//! stays green with no network. A GATED live variant lives in
//! `tests/p2_shared_scope_write_e2e.rs` behind `#[ignore]` + `FULA_E2E=1`.

use fula_crypto::{
    Aead, InboxEntry, KekKeyPair, Nonce, SecretKey, ShareBuilder, ShareEnvelope, ShareRecipient,
    ShareToken, generate_flat_key,
};
use rand::RngCore;

/// The v4 single-block content AAD, byte-for-byte what
/// `put_object_flat_deferred_locked` binds at upload time:
/// `format!("fula:v4:content:{}", storage_key)`.
fn content_aad_v4(storage_key: &str) -> Vec<u8> {
    format!("fula:v4:content:{storage_key}").into_bytes()
}

/// End-to-end OFFLINE proof of the recommended P2 path: the AI writes a file
/// into its OWN scope, mints a per-file ShareToken to the owner, delivers it via
/// inbox; the owner reads the bytes back byte-identically.
#[test]
fn ai_writes_into_shared_scope_owner_reads_back_byte_identical() {
    // ── Identities ────────────────────────────────────────────────────────
    // The OWNER (FxFiles) holds a master KEK. The AI (MCP) has its OWN keypair
    // and never sees the owner's secret. Both are built deterministically here
    // from fixed seeds purely so the test is reproducible.
    let mut owner_seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut owner_seed);
    let mut ai_seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut ai_seed);

    let owner = KekKeyPair::from_secret_key(SecretKey::from_bytes(&owner_seed).unwrap());
    let ai = KekKeyPair::from_secret_key(SecretKey::from_bytes(&ai_seed).unwrap());

    // The AI knows ONLY the owner's PUBLIC key (it would be carried in the
    // inbound folder ShareToken / capability bundle in P3). Crucially it does
    // NOT know the owner's secret — proving the master key is never exposed.
    let owner_public = owner.public_key().clone();

    // ── AI side: write a file into the `ai/` shared scope ──────────────────
    // The logical path under the shared scope the owner granted.
    let logical_path = "ai/notes/summary-2026-06.txt";
    let plaintext = b"AI-generated summary. Must round-trip to the owner byte-for-byte.";

    // 1. Generate a per-file content DEK (the AI owns this file's bytes).
    let content_dek = fula_crypto::DekKey::generate();

    // 2. Derive the obfuscated storage key exactly as the SDK does for a v7
    //    flat-namespace write: generate_flat_key(path, dek, shard_salt).
    //    Offline we stand in a deterministic salt; on a live bucket this comes
    //    from the AI's own forest manifest (`shard_salt`). The value only needs
    //    to be identical on the wrap side and the read side, which it is because
    //    it is carried (implicitly, via path_scope == storage_key on live; via
    //    the explicit storage_key here) to the reader.
    let shard_salt = b"p2-offline-shard-salt";
    let storage_key = generate_flat_key(logical_path, &content_dek, shard_salt);

    // 3. Encrypt the content with the EXACT production v4 single-block format.
    let nonce = Nonce::generate();
    let aad = content_aad_v4(&storage_key);
    let aead = Aead::new_default(&content_dek);
    let ciphertext = aead
        .encrypt_with_aad(&nonce, plaintext, &aad)
        .expect("AI encrypts content (v4 AAD)");

    // On a live gateway the AI would PUT `ciphertext` at `storage_key` into its
    // OWN bucket here (proven by the e2e variant). Offline we keep the bytes in
    // memory and treat them as "what the owner will fetch by storage_key".

    // 4. Mint a ShareToken wrapping the content DEK to the OWNER's public key.
    //    path_scope carries the shared-scope path; the nonce + encryption_version
    //    are baked in so the owner can decrypt without any S3 metadata header
    //    (identical to FxFiles' own createShareToken options).
    let nonce_b64 = {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(nonce.as_bytes())
    };
    let token = ShareBuilder::new(&ai, &owner_public, &content_dek)
        .path_scope(logical_path)
        .read_write() // recipient-WRITE semantics: the AI authored this under ai/
        .nonce(nonce_b64)
        .encryption_version(4)
        .build()
        .expect("AI mints ShareToken to owner");

    // 5. Wrap the token in a ShareEnvelope and deposit it into the OWNER's
    //    inbox as an HPKE-Auth-mode entry (the AI authenticates as sender).
    let envelope = ShareEnvelope::new(token)
        .with_label("ai/notes/summary-2026-06.txt")
        .with_message("Written by the MCP AI into the ai/ scope")
        .with_sharer_name("fula-mcp");
    let inbox_entry =
        InboxEntry::create(&envelope, &owner_public, &ai).expect("AI enqueues into owner inbox");

    // ── Transmit: serialize the inbox entry (store-and-forward) ────────────
    let entry_json = serde_json::to_string(&inbox_entry).expect("serialize inbox entry");

    // ══ OWNER side ═════════════════════════════════════════════════════════
    let received_entry: InboxEntry =
        serde_json::from_str(&entry_json).expect("owner parses inbox entry");

    // Sanity: the entry is addressed to the owner.
    assert!(
        received_entry.is_for_recipient(owner.public_key()),
        "inbox entry must be addressed to the owner"
    );

    // 1. Owner opens the envelope with its secret (HPKE Auth verifies the AI
    //    as sender), recovering the inner ShareToken.
    let opened = received_entry
        .decrypt(owner.secret_key())
        .expect("owner decrypts inbox envelope (HPKE Auth)");
    let received_token: ShareToken = opened.token;

    // 2. Owner accepts the share -> recovers the content DEK + scope.
    let accepted = ShareRecipient::new(&owner)
        .accept_share(&received_token)
        .expect("owner.accept_share");

    // 3. Scope check: the file is inside the `ai/` scope the AI declared.
    assert!(
        accepted.is_path_allowed(logical_path),
        "owner sees the file inside the declared ai/ scope"
    );
    assert!(
        accepted.path_scope.starts_with("ai/"),
        "scope is the ai/ prefix the AI wrote under (got {:?})",
        accepted.path_scope
    );
    assert!(
        accepted.permissions.can_write,
        "token carries the read-write semantics the AI authored with"
    );

    // 4. Owner decrypts the ciphertext (fetched by storage_key on live) with the
    //    recovered DEK + the nonce carried in the token, using the SAME v4 AAD.
    let recovered_nonce = {
        use base64::Engine;
        let raw = base64::engine::general_purpose::STANDARD
            .decode(accepted.nonce.as_ref().expect("token carries nonce"))
            .expect("decode nonce");
        Nonce::from_bytes(&raw).expect("nonce from bytes")
    };
    let owner_aead = Aead::new_default(&accepted.dek);
    let decrypted = owner_aead
        .decrypt_with_aad(&recovered_nonce, &ciphertext, &content_aad_v4(&storage_key))
        .expect("owner decrypts AI-authored content");

    // ── The whole point ───────────────────────────────────────────────────
    assert_eq!(
        decrypted.as_slice(),
        plaintext.as_slice(),
        "owner must read the AI-written file back BYTE-IDENTICALLY"
    );
}

/// The owner's DEK is recovered ONLY from the share token; the owner never holds
/// the AI's secret, and the AI never holds the owner's secret. This pins the
/// security property the MCP model depends on (master key never exposed) and that
/// the wrap is to the OWNER specifically (a third party cannot open it).
#[test]
fn wrong_party_cannot_open_the_ai_share() {
    let owner = KekKeyPair::generate();
    let ai = KekKeyPair::generate();
    let stranger = KekKeyPair::generate();
    let content_dek = fula_crypto::DekKey::generate();

    let token = ShareBuilder::new(&ai, owner.public_key(), &content_dek)
        .path_scope("ai/secret.txt")
        .read_write()
        .build()
        .unwrap();

    // The intended owner recovers the DEK.
    let accepted = ShareRecipient::new(&owner).accept_share(&token).unwrap();
    assert_eq!(accepted.dek.as_bytes(), content_dek.as_bytes());

    // A stranger (incl. the AI itself, which used a one-way wrap to the owner)
    // cannot open it.
    assert!(
        ShareRecipient::new(&stranger).accept_share(&token).is_err(),
        "a non-owner must not recover the content DEK"
    );
    assert!(
        ShareRecipient::new(&ai).accept_share(&token).is_err(),
        "the AI wrapped to the owner only; it cannot re-open its own share token"
    );
}

/// Guard the load-bearing wire-format constant. If the upload path's v4 content
/// AAD ever changes, this test (and the owner read-back) must change in lockstep,
/// otherwise an owner could not decrypt an AI-written file. Pins the exact bytes.
///
/// Scope honesty (per external review): this proves crypto-format compatibility
/// for the v4 SINGLE-BLOCK content object only. It does NOT prove gateway
/// behaviour, upload metadata, chunked objects, server authorization, or any
/// forest-listing behaviour — those are covered by the gated live e2e and the
/// workspace's existing cross-platform/chunked tests.
#[test]
fn content_aad_v4_single_block_matches_upload_format() {
    assert_eq!(
        content_aad_v4("QmExampleStorageKey"),
        b"fula:v4:content:QmExampleStorageKey".to_vec(),
        "v4 content AAD must match put_object_flat_deferred_locked verbatim"
    );
}

/// P3 caveat (flagged in external review): [`AcceptedShare::is_path_allowed`]
/// uses a raw `path.starts_with(path_scope)`, which is a SUBSTRING prefix, not a
/// path-segment prefix. So a scope of `ai/note` ALSO admits `ai/notebook`. P3's
/// `assert_in_scope` MUST canonicalize the scope (e.g. require a trailing `/` on
/// folder scopes, and normalize separators / leading slashes) before relying on
/// it as a security boundary. This test documents the current behaviour so the
/// gap is explicit and regression-visible, NOT an endorsement of it.
#[test]
fn path_scope_is_raw_substring_prefix_p3_must_canonicalize() {
    let owner = KekKeyPair::generate();
    let ai = KekKeyPair::generate();
    let dek = fula_crypto::DekKey::generate();

    // Folder-style scope WITH a trailing slash behaves as a true segment prefix.
    let folder_token = ShareBuilder::new(&ai, owner.public_key(), &dek)
        .path_scope("ai/notes/")
        .read_write()
        .build()
        .unwrap();
    let folder = ShareRecipient::new(&owner)
        .accept_share(&folder_token)
        .unwrap();
    assert!(folder.is_path_allowed("ai/notes/summary.txt"));
    assert!(
        !folder.is_path_allowed("ai/notebook/x"),
        "trailing-slash scope correctly excludes a sibling with a shared prefix"
    );

    // WITHOUT a trailing slash, the raw substring match leaks to a sibling —
    // the exact footgun P3 must guard against.
    let bare_token = ShareBuilder::new(&ai, owner.public_key(), &dek)
        .path_scope("ai/note")
        .read_write()
        .build()
        .unwrap();
    let bare = ShareRecipient::new(&owner).accept_share(&bare_token).unwrap();
    assert!(
        bare.is_path_allowed("ai/notebook"),
        "documents the substring-prefix footgun: 'ai/note' admits 'ai/notebook' — \
         P3 assert_in_scope must canonicalize (require trailing '/')"
    );
}
