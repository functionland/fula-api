//! # Cross-implementation KAT: Method-2 RECIPIENT bindings
//!
//! This is the correctness GATE for the recipient-side bindings that let the
//! hosted Cloudflare Worker (wasm) consume a Method-2 collaboration share. It
//! exercises the EXACT shared `fula_crypto::sharing` core fns that the `fula-js`
//! wasm bindings (`unwrapSecretForRecipient` / `describeSharedFile` /
//! `decryptSharedFileSingleBlock` / `decryptSharedFileChunked`) call, so a green
//! KAT here means a token produced by FxFiles (the A6 `wrap_secret_for_recipient`
//! producer) or an owner file written by FxFiles/web is byte-for-byte readable by
//! the Worker — and ONLY by the addressed recipient.
//!
//! These are real KNOWN-ANSWER tests, not vacuous round-trips: every case pins
//! FIXED inputs (recipient secret bytes, link secret, file DEK, nonce, storage
//! key, plaintext) and asserts the recovered bytes equal a LITERAL expected
//! value. Because AES-GCM ciphertext never equals its plaintext, a decrypt that
//! merely echoed its input would FAIL these assertions. (Token `id`/`created_at`
//! are random, so the token JSON itself is non-deterministic — hence we pin the
//! recovered PLAINTEXT, not the token bytes, exactly as the design review
//! prescribed.)

use base64::Engine as _;
use fula_crypto::sharing::{
    decrypt_shared_file_chunked, decrypt_shared_file_single_block, describe_shared_file,
    unwrap_secret_for_recipient, wrap_secret_for_recipient, ShareBuilder,
};
use fula_crypto::{Aead, ChunkedEncoder, DekKey, KekKeyPair, Nonce, PublicKey, SecretKey, ShareToken};

// ── Fixed KAT vectors ────────────────────────────────────────────────────────

/// The recipient's (Worker's) X25519 secret key — fixed so the recipient side is
/// fully deterministic.
const RECIPIENT_SK: [u8; 32] = [0x55u8; 32];

/// A DIFFERENT recipient's secret key (the "stranger" who must NOT decrypt).
const STRANGER_SK: [u8; 32] = [0x66u8; 32];

/// The link secret a producer wraps for the recipient (`0x00..=0x1f`). This is
/// the literal the unwrap must recover verbatim.
const LINK_SECRET: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];

/// The owner file's DEK (fixed), carried encrypted inside the share token.
const FILE_DEK: [u8; 32] = [0xa7u8; 32];

/// A fixed 12-byte AES-GCM nonce for the single-block vectors.
const FILE_NONCE: [u8; 12] = [0x24u8; 12];

/// Serialize -> deserialize a token, mirroring the JSON wire form the wasm
/// bindings receive.
fn over_the_wire(token: &ShareToken) -> ShareToken {
    let json = serde_json::to_string(token).expect("serialize token to JSON");
    serde_json::from_str(&json).expect("deserialize token from JSON")
}

fn recipient_pub() -> PublicKey {
    SecretKey::from_bytes(&RECIPIENT_SK).unwrap().public_key()
}

// ════════════════════════════════════════════════════════════════════════════
// 1. Link-secret unwrap (consumer half of `wrapSecretForRecipient`)
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn kat_unwrap_recovers_exact_link_secret() {
    let recipient_pub = recipient_pub();

    // PRODUCER: the A6 shared core fn FxFiles / the Worker producer calls.
    let token = wrap_secret_for_recipient(
        &LINK_SECRET,
        recipient_pub.as_bytes(),
        Some("/collab/group-kat"),
        Some(3600),
    )
    .expect("wrap must succeed for valid 32-byte inputs");
    let token = over_the_wire(&token);
    assert_eq!(token.version, 5, "must be a strict v5 token");

    // CONSUMER: the EXACT shared core fn the `unwrapSecretForRecipient` binding
    // calls — recovers the EXACT fixed link secret.
    let recovered = unwrap_secret_for_recipient(&RECIPIENT_SK, &token)
        .expect("the addressed recipient must recover its secret");
    assert_eq!(
        recovered, LINK_SECRET,
        "recovered link secret must equal the fixed 0x00..=0x1f vector"
    );

    // A DIFFERENT recipient must NOT recover it (v5 recipient-pk AAD binding).
    assert!(
        unwrap_secret_for_recipient(&STRANGER_SK, &token).is_err(),
        "a non-addressed recipient must be rejected"
    );

    // Bad key length fails closed.
    assert!(unwrap_secret_for_recipient(&[0u8; 31], &token).is_err());
    assert!(unwrap_secret_for_recipient(&[0u8; 33], &token).is_err());
}

#[test]
fn kat_unwrap_rejects_tampered_and_expired() {
    let recipient_pub = recipient_pub();
    let token = wrap_secret_for_recipient(
        &LINK_SECRET,
        recipient_pub.as_bytes(),
        Some("/collab/group-original"),
        Some(3600),
    )
    .expect("wrap must succeed");

    // Baseline: pristine token is accepted.
    assert_eq!(
        unwrap_secret_for_recipient(&RECIPIENT_SK, &over_the_wire(&token)).unwrap(),
        LINK_SECRET
    );

    // Mutated path_scope -> generic auth failure (v5 AAD binds every field).
    {
        let mut t = over_the_wire(&token);
        t.path_scope = "/collab/group-WIDENED".to_string();
        assert!(unwrap_secret_for_recipient(&RECIPIENT_SK, &t).is_err());
    }
    // Stretched expiry -> generic auth failure.
    {
        let mut t = over_the_wire(&token);
        t.expires_at = Some(t.expires_at.unwrap() + 86_400 * 365);
        assert!(unwrap_secret_for_recipient(&RECIPIENT_SK, &t).is_err());
    }
    // Born-expired token (expires_in = -3600) -> rejected fail-closed.
    let expired = wrap_secret_for_recipient(&LINK_SECRET, recipient_pub.as_bytes(), None, Some(-3600))
        .expect("wrap itself succeeds even for a past expiry");
    assert!(unwrap_secret_for_recipient(&RECIPIENT_SK, &over_the_wire(&expired)).is_err());
}

// ════════════════════════════════════════════════════════════════════════════
// 2. Owner-file decrypt — SINGLE BLOCK
// ════════════════════════════════════════════════════════════════════════════

/// Build a single-block owner-file share token addressed to `recipient_pub`,
/// carrying the fixed `FILE_DEK` + the given inline nonce and encryption version.
fn build_single_block_token(
    recipient_pub: &PublicKey,
    storage_key: &str,
    nonce_b64: String,
    enc_version: Option<u8>,
) -> ShareToken {
    let owner = KekKeyPair::generate(); // ephemeral; accept never inspects the sender
    let dek = DekKey::from_bytes(&FILE_DEK).unwrap();
    let mut builder = ShareBuilder::new(&owner, recipient_pub, &dek)
        .path_scope(storage_key)
        .nonce(nonce_b64);
    if let Some(v) = enc_version {
        builder = builder.encryption_version(v);
    }
    builder.build().unwrap()
}

#[test]
fn kat_owner_single_block_v4_decrypts_to_exact_plaintext() {
    let recipient_pub = recipient_pub();
    let storage_key = "obfs-kat-single-001";
    // The known-answer plaintext (includes NUL + high bytes so it can't be UTF-8
    // coincidence).
    let plaintext: &[u8] = b"KAT owner single-block exact plaintext \x00\x01\xff\xfe";

    // Producer encrypts with the v4 AAD `fula:v4:content:{storage_key}`.
    let dek = DekKey::from_bytes(&FILE_DEK).unwrap();
    let nonce = Nonce::from_bytes(&FILE_NONCE).unwrap();
    let aad = format!("fula:v4:content:{storage_key}");
    let ciphertext = Aead::new_default(&dek)
        .encrypt_with_aad(&nonce, plaintext, aad.as_bytes())
        .unwrap();
    let nonce_b64 = base64::engine::general_purpose::STANDARD.encode(FILE_NONCE);

    let token = over_the_wire(&build_single_block_token(
        &recipient_pub,
        storage_key,
        nonce_b64,
        Some(4),
    ));

    // The binding core recovers the EXACT fixed plaintext.
    let out =
        decrypt_shared_file_single_block(&RECIPIENT_SK, &token, storage_key, &ciphertext).unwrap();
    assert_eq!(out.as_slice(), plaintext, "must recover the exact KAT plaintext");

    // Wrong storage_key (AAD mismatch) fails closed.
    assert!(
        decrypt_shared_file_single_block(&RECIPIENT_SK, &token, "obfs-WRONG", &ciphertext).is_err(),
        "a wrong storage_key (AAD) must fail authentication"
    );
    // Wrong recipient fails closed.
    assert!(
        decrypt_shared_file_single_block(&STRANGER_SK, &token, storage_key, &ciphertext).is_err(),
        "a non-addressed recipient must be rejected"
    );
    // Routing a single-block share through the chunked path fails closed.
    assert!(
        decrypt_shared_file_chunked(&RECIPIENT_SK, &token, storage_key, vec![ciphertext.clone()])
            .is_err(),
        "single-block share must not decrypt via the chunked path"
    );
}

#[test]
fn kat_owner_single_block_version_gate_tristate() {
    let recipient_pub = recipient_pub();
    let storage_key = "obfs-kat-single-version";
    let plaintext: &[u8] = b"version-gate KAT \x00\x10\x20";
    let dek = DekKey::from_bytes(&FILE_DEK).unwrap();
    let nonce = Nonce::from_bytes(&FILE_NONCE).unwrap();
    let nonce_b64 = base64::engine::general_purpose::STANDARD.encode(FILE_NONCE);
    let aad = format!("fula:v4:content:{storage_key}");

    let ct_with_aad = Aead::new_default(&dek)
        .encrypt_with_aad(&nonce, plaintext, aad.as_bytes())
        .unwrap();
    let ct_no_aad = Aead::new_default(&dek).encrypt(&nonce, plaintext).unwrap();

    // Some(>=4): AAD-bound ciphertext decrypts.
    let t4 = over_the_wire(&build_single_block_token(
        &recipient_pub,
        storage_key,
        nonce_b64.clone(),
        Some(4),
    ));
    assert_eq!(
        decrypt_shared_file_single_block(&RECIPIENT_SK, &t4, storage_key, &ct_with_aad).unwrap(),
        plaintext
    );

    // Some(<4): legacy, NO AAD.
    let t2 = over_the_wire(&build_single_block_token(
        &recipient_pub,
        storage_key,
        nonce_b64.clone(),
        Some(2),
    ));
    assert_eq!(
        decrypt_shared_file_single_block(&RECIPIENT_SK, &t2, storage_key, &ct_no_aad).unwrap(),
        plaintext
    );

    // None: try-AAD-then-plaintext fallback — a no-AAD ciphertext still decrypts.
    let tnone = over_the_wire(&build_single_block_token(
        &recipient_pub,
        storage_key,
        nonce_b64,
        None,
    ));
    assert_eq!(
        decrypt_shared_file_single_block(&RECIPIENT_SK, &tnone, storage_key, &ct_no_aad).unwrap(),
        plaintext
    );
}

// ════════════════════════════════════════════════════════════════════════════
// 3. Owner-file decrypt — CHUNKED (streaming-v2)
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn kat_owner_chunked_streaming_v2_decrypts_and_count_mismatch_fails() {
    let recipient_pub = recipient_pub();
    let storage_key = "obfs-kat-chunk-001";
    let payload = vec![0xc3u8; 200_000]; // > one 64 KiB chunk ⇒ multi-chunk

    // Producer chunk-encodes with the v4 chunk AAD prefix.
    let dek = DekKey::from_bytes(&FILE_DEK).unwrap();
    let prefix = format!("fula:v4:chunk:{storage_key}");
    let mut enc =
        ChunkedEncoder::with_aad_and_chunk_size(dek.clone(), prefix.into_bytes(), 64 * 1024);
    let mut indexed: Vec<(u32, Vec<u8>)> = enc
        .update(&payload)
        .unwrap()
        .into_iter()
        .map(|c| (c.index, c.ciphertext.to_vec()))
        .collect();
    let (final_chunk, meta, _ob) = enc.finalize().unwrap();
    if let Some(c) = final_chunk {
        indexed.push((c.index, c.ciphertext.to_vec()));
    }
    assert!(meta.num_chunks > 1, "test must be multi-chunk");
    assert_eq!(meta.format, "streaming-v2");

    let token = over_the_wire(
        &ShareBuilder::new(&KekKeyPair::generate(), &recipient_pub, &dek)
            .path_scope(storage_key)
            .chunked_metadata(serde_json::to_string(&meta).unwrap())
            .encryption_version(4)
            .build()
            .unwrap(),
    );

    // Ordered chunk ciphertexts (index == position) the Worker would have fetched.
    let mut ordered = indexed.clone();
    ordered.sort_by_key(|(i, _)| *i);
    let chunks: Vec<Vec<u8>> = ordered.into_iter().map(|(_, ct)| ct).collect();

    let out =
        decrypt_shared_file_chunked(&RECIPIENT_SK, &token, storage_key, chunks.clone()).unwrap();
    assert_eq!(out, payload, "chunked decrypt must recover the exact payload");

    // Chunk-count mismatch (drop the last chunk) fails closed BEFORE any decrypt.
    let mut short = chunks.clone();
    short.pop();
    assert!(
        decrypt_shared_file_chunked(&RECIPIENT_SK, &token, storage_key, short).is_err(),
        "a chunk-count mismatch must fail closed"
    );

    // Wrong recipient fails closed.
    assert!(decrypt_shared_file_chunked(&STRANGER_SK, &token, storage_key, chunks.clone()).is_err());

    // Routing a chunked share through the single-block path fails closed.
    assert!(
        decrypt_shared_file_single_block(&RECIPIENT_SK, &token, storage_key, &chunks[0]).is_err(),
        "chunked share must not decrypt via the single-block path"
    );
}

// ════════════════════════════════════════════════════════════════════════════
// 4. describeSharedFile framing (non-secret)
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn kat_describe_reports_framing_without_leaking_secrets() {
    let recipient_pub = recipient_pub();

    // Single-block share -> { chunked: false, num_chunks: 1, encryption_version: Some(4) }.
    let nonce_b64 = base64::engine::general_purpose::STANDARD.encode(FILE_NONCE);
    let single = over_the_wire(&build_single_block_token(
        &recipient_pub,
        "obfs-desc-single",
        nonce_b64,
        Some(4),
    ));
    let f = describe_shared_file(&RECIPIENT_SK, &single).unwrap();
    assert!(!f.chunked);
    assert_eq!(f.num_chunks, 1);
    assert_eq!(f.encryption_version, Some(4));

    // Chunked share -> { chunked: true, num_chunks: N>1, encryption_version: Some(4) }.
    let storage_key = "obfs-desc-chunk";
    let payload = vec![0x9bu8; 200_000];
    let dek = DekKey::from_bytes(&FILE_DEK).unwrap();
    let prefix = format!("fula:v4:chunk:{storage_key}");
    let mut enc =
        ChunkedEncoder::with_aad_and_chunk_size(dek.clone(), prefix.into_bytes(), 64 * 1024);
    let _ = enc.update(&payload).unwrap();
    let (_final, meta, _ob) = enc.finalize().unwrap();
    let chunked = over_the_wire(
        &ShareBuilder::new(&KekKeyPair::generate(), &recipient_pub, &dek)
            .path_scope(storage_key)
            .chunked_metadata(serde_json::to_string(&meta).unwrap())
            .encryption_version(4)
            .build()
            .unwrap(),
    );
    let f = describe_shared_file(&RECIPIENT_SK, &chunked).unwrap();
    assert!(f.chunked);
    assert_eq!(f.num_chunks, meta.num_chunks);
    assert!(f.num_chunks > 1);

    // A stranger cannot even read the framing (it requires accepting the share).
    assert!(describe_shared_file(&STRANGER_SK, &chunked).is_err());
}

// ════════════════════════════════════════════════════════════════════════════
// 5. Version-downgrade guard (security): encryption_version is bound in the v5 AAD
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn kat_owner_single_block_rejects_version_downgrade() {
    let recipient_pub = recipient_pub();
    let storage_key = "obfs-kat-downgrade";
    let plaintext: &[u8] = b"downgrade-guard KAT payload \x00\xff";
    let dek = DekKey::from_bytes(&FILE_DEK).unwrap();
    let nonce = Nonce::from_bytes(&FILE_NONCE).unwrap();
    let nonce_b64 = base64::engine::general_purpose::STANDARD.encode(FILE_NONCE);
    let aad = format!("fula:v4:content:{storage_key}");
    let ciphertext = Aead::new_default(&dek)
        .encrypt_with_aad(&nonce, plaintext, aad.as_bytes())
        .unwrap();

    // A pristine Some(4) token decrypts.
    let good = over_the_wire(&build_single_block_token(
        &recipient_pub,
        storage_key,
        nonce_b64,
        Some(4),
    ));
    assert_eq!(
        decrypt_shared_file_single_block(&RECIPIENT_SK, &good, storage_key, &ciphertext).unwrap(),
        plaintext
    );

    // Downgrade Some(4) -> None on the wire: encryption_version is bound in the v5 AAD,
    // so acceptance fails (the no-AAD decrypt arm is NEVER reached).
    {
        let mut t = over_the_wire(&good);
        t.encryption_version = None;
        assert!(
            decrypt_shared_file_single_block(&RECIPIENT_SK, &t, storage_key, &ciphertext).is_err(),
            "Some(4)->None downgrade must be rejected (version is in the v5 AAD)"
        );
        assert!(unwrap_secret_for_recipient(&RECIPIENT_SK, &t).is_err());
    }
    // Downgrade Some(4) -> Some(2) likewise rejected.
    {
        let mut t = over_the_wire(&good);
        t.encryption_version = Some(2);
        assert!(
            decrypt_shared_file_single_block(&RECIPIENT_SK, &t, storage_key, &ciphertext).is_err(),
            "Some(4)->Some(2) downgrade must be rejected"
        );
    }
}

// ════════════════════════════════════════════════════════════════════════════
// 6. Edge cases: empty plaintext + single-chunk chunked
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn kat_owner_single_block_empty_plaintext() {
    let recipient_pub = recipient_pub();
    let storage_key = "obfs-kat-empty";
    let dek = DekKey::from_bytes(&FILE_DEK).unwrap();
    let nonce = Nonce::from_bytes(&FILE_NONCE).unwrap();
    let nonce_b64 = base64::engine::general_purpose::STANDARD.encode(FILE_NONCE);
    let aad = format!("fula:v4:content:{storage_key}");
    let ciphertext = Aead::new_default(&dek)
        .encrypt_with_aad(&nonce, b"", aad.as_bytes())
        .unwrap();
    let token = over_the_wire(&build_single_block_token(
        &recipient_pub,
        storage_key,
        nonce_b64,
        Some(4),
    ));
    // Empty plaintext round-trips (the AEAD tag is still verified).
    assert_eq!(
        decrypt_shared_file_single_block(&RECIPIENT_SK, &token, storage_key, &ciphertext).unwrap(),
        b""
    );
    // Tag enforcement holds even for empty plaintext: a wrong storage_key (AAD) fails.
    assert!(
        decrypt_shared_file_single_block(&RECIPIENT_SK, &token, "obfs-WRONG", &ciphertext).is_err()
    );
}

#[test]
fn kat_owner_chunked_single_chunk_uses_per_chunk_aad() {
    let recipient_pub = recipient_pub();
    let storage_key = "obfs-kat-1chunk";
    let payload = vec![0x4du8; 1000]; // < 64 KiB ⇒ exactly one chunk
    let dek = DekKey::from_bytes(&FILE_DEK).unwrap();
    let prefix = format!("fula:v4:chunk:{storage_key}");
    let mut enc =
        ChunkedEncoder::with_aad_and_chunk_size(dek.clone(), prefix.into_bytes(), 64 * 1024);
    let mut indexed: Vec<(u32, Vec<u8>)> = enc
        .update(&payload)
        .unwrap()
        .into_iter()
        .map(|c| (c.index, c.ciphertext.to_vec()))
        .collect();
    let (final_chunk, meta, _ob) = enc.finalize().unwrap();
    if let Some(c) = final_chunk {
        indexed.push((c.index, c.ciphertext.to_vec()));
    }
    assert_eq!(meta.num_chunks, 1, "test must be exactly one chunk");
    let token = over_the_wire(
        &ShareBuilder::new(&KekKeyPair::generate(), &recipient_pub, &dek)
            .path_scope(storage_key)
            .chunked_metadata(serde_json::to_string(&meta).unwrap())
            .encryption_version(4)
            .build()
            .unwrap(),
    );
    let mut ordered = indexed.clone();
    ordered.sort_by_key(|(i, _)| *i);
    let chunks: Vec<Vec<u8>> = ordered.into_iter().map(|(_, ct)| ct).collect();
    let out = decrypt_shared_file_chunked(&RECIPIENT_SK, &token, storage_key, chunks).unwrap();
    assert_eq!(out, payload, "single-chunk chunked must use per-chunk AAD and round-trip");
}
