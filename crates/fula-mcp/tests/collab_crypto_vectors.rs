//! # Cross-implementation byte-exact gate for the collab crypto
//!
//! These vectors were produced by RUNNING the REAL FxFiles Dart code
//! (`lib/core/services/share_link_builder.dart` + the inline
//! `CollaborationService.deriveCollabFileKey`) via a one-shot
//! `tool/emit_collab_vectors.dart` harness (since deleted — FxFiles is left
//! clean). The Dart side self-round-tripped (`dartSelfRoundTripOk: true`).
//!
//! Fixed inputs:
//! - `linkSecret` = bytes `0x00..=0x1f`
//! - `scopeId`    = `"group-123"`
//! - `fileId`     = `"file-abc"`
//! - manifest map = `{"id":"group-123","name":"Legal Docs","version":2,"files":[]}`
//! - file payload = UTF-8 of `"hello collab file -- vector payload 0123456789"`
//!
//! The gate proves: (a) the Rust HKDF key derivation matches Dart bit-for-bit;
//! (b) Rust DECRYPTS the real Dart `ENC1:` envelope to the original manifest
//! JSON; (c) Rust DECRYPTS the real Dart collab-file blob to the original
//! payload; (d) Rust encrypt→decrypt round-trips and emits the exact
//! `nonce(12)||ct||tag(16)` layout. The reverse direction (Dart decrypts a
//! Rust-produced blob — the production manifest WRITE path) was verified
//! out-of-band with the `emit_rust_vectors_for_dart_bidirectional_check` test
//! output fed back through the live Dart harness before it was deleted.

use base64::Engine as _;
use fula_mcp::manifest::{
    collab_file_decrypt, collab_file_encrypt, derive_collab_file_key, derive_manifest_key,
    enc1_decrypt, enc1_encrypt, CollaborationFile, CollaborationGroup, ManifestError,
};

// ── Captured Dart vectors ───────────────────────────────────────────────────

const LINK_SECRET_HEX: &str =
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const SCOPE_ID: &str = "group-123";
const FILE_ID: &str = "file-abc";

/// `shareManifestDeriveKey(linkSecret, "group-123")`, hex.
const MANIFEST_KEY_HEX: &str =
    "c61b4a389061c98516da26d7a2523eeed9be71f40707ab2931656ecf8c1851eb";
/// `deriveCollabFileKey(linkSecret, "file-abc")`, hex.
const COLLAB_FILE_KEY_HEX: &str =
    "5c6984465336c7453df0a1116079b94f88d6461cfbeb47c5000d51ef1f31f9f4";

/// Exact `jsonEncode(manifest)` the Dart side encrypted.
const MANIFEST_JSON: &str = r#"{"id":"group-123","name":"Legal Docs","version":2,"files":[]}"#;
/// `shareManifestEncrypt(manifest, linkSecret, "group-123")` (random nonce, so
/// this particular ciphertext is a one-time capture; only its DECRYPTION is
/// asserted).
const ENC1: &str = "ENC1:FJ762am0rSrOYe5PZUliAok3O/r8QzSNERKNWEBPwohm20cHx14bsOgPI/qEZrXIsHpbbZ0L2i+WNeg115SAmu/0Cx5poYunZ5rlxI/pLB7DRXXX9FmVHLg=";

/// Hex of the fixed collab-file payload.
const FILE_PAYLOAD_HEX: &str =
    "68656c6c6f20636f6c6c61622066696c65202d2d20766563746f72207061796c6f61642030313233343536373839";
/// `base64(sharePasswordEncrypt(payload, deriveCollabFileKey(...)))` (random
/// nonce; only its DECRYPTION is asserted).
const FILE_BLOB_B64: &str = "mlwW2gu24BpsUpiLD1ltCTzsKcC7INT5RqudVUv/glAWHN7Sg4LSlrqaHzxm7XDKanwoQ0TrYv5ysISMoERQ4RkDg/+16jzcR7c=";

/// `jsonEncode(CollaborationGroup(...).toJson())` from the real Dart model — the
/// authority for the serde struct field names, key order, and conditional
/// omission rules.
const GROUP_JSON: &str = r#"{"id":"group-123","name":"Legal Docs","ownerPublicKey":"T1dORVJQVUI=","manifestBucket":"fula-metadata","manifestKey":"manifests/group-123.json","createdAt":"2026-01-01T00:00:00.000Z","expiresAt":"2026-06-01T00:00:00.000Z","isRevoked":false,"files":[{"id":"f-1","fileName":"contract.pdf","contentType":"application/pdf","bucket":"fula-collab","storageKey":"bafy-contract","pathScope":"/legal/contract.pdf","addedByPublicKey":"QUJDRA==","addedAt":"2026-01-02T03:04:05.000Z","fileSize":12345,"encType":"fula","shareTokenJson":"{\"id\":\"tok1\"}"},{"id":"f-2","fileName":"note.txt","bucket":"fula-collab","storageKey":"bafy-note","addedByPublicKey":"WFlaWg==","addedAt":"2026-01-03T00:00:00.000Z","fileSize":7,"encType":"collab"}],"removedFileIds":["f-removed-1"],"version":3,"updatedAt":"2026-01-04T00:00:00.000Z"}"#;

fn link_secret() -> Vec<u8> {
    hex::decode(LINK_SECRET_HEX).unwrap()
}

// ── (a) Key derivation matches Dart bit-for-bit ─────────────────────────────

#[test]
fn derive_keys_match_dart_vectors() {
    let secret = link_secret();
    assert_eq!(
        hex::encode(derive_manifest_key(&secret, SCOPE_ID)),
        MANIFEST_KEY_HEX,
        "manifest key must match the Dart HKDF output"
    );
    assert_eq!(
        hex::encode(derive_collab_file_key(&secret, FILE_ID)),
        COLLAB_FILE_KEY_HEX,
        "collab-file key must match the Dart HKDF output"
    );
}

// ── (b) Rust decrypts the real Dart ENC1 envelope ───────────────────────────

#[test]
fn enc1_decrypt_of_dart_vector_yields_manifest_json() {
    let plaintext = enc1_decrypt(ENC1, &link_secret(), SCOPE_ID).unwrap();
    assert_eq!(plaintext, MANIFEST_JSON.as_bytes());
}

// ── (c) Rust decrypts the real Dart collab-file blob ────────────────────────

#[test]
fn collab_file_decrypt_of_dart_vector_yields_payload() {
    let blob = base64::engine::general_purpose::STANDARD
        .decode(FILE_BLOB_B64)
        .unwrap();
    let plaintext = collab_file_decrypt(&blob, &link_secret(), FILE_ID).unwrap();
    assert_eq!(hex::encode(&plaintext), FILE_PAYLOAD_HEX);
}

// ── (d) Rust round-trips + correct on-wire layout ───────────────────────────

#[test]
fn rust_enc1_round_trips_with_correct_layout() {
    let secret = link_secret();
    let manifest = MANIFEST_JSON.as_bytes();

    let enc1 = enc1_encrypt(manifest, &secret, SCOPE_ID);
    assert!(enc1.starts_with("ENC1:"));
    assert_eq!(enc1_decrypt(&enc1, &secret, SCOPE_ID).unwrap(), manifest);

    // Structural: decoded blob is exactly nonce(12) || ciphertext || tag(16).
    let blob = base64::engine::general_purpose::STANDARD
        .decode(enc1.strip_prefix("ENC1:").unwrap())
        .unwrap();
    assert_eq!(blob.len(), 12 + manifest.len() + 16);

    // Domain separation: the SAME ciphertext under a different scope must fail.
    assert!(enc1_decrypt(&enc1, &secret, "other-scope").is_err());
}

#[test]
fn rust_collab_file_round_trips_with_correct_layout() {
    let secret = link_secret();
    let payload = hex::decode(FILE_PAYLOAD_HEX).unwrap();

    let blob = collab_file_encrypt(&payload, &secret, FILE_ID);
    assert_eq!(blob.len(), 12 + payload.len() + 16);
    assert_eq!(collab_file_decrypt(&blob, &secret, FILE_ID).unwrap(), payload);

    // Domain separation: a different file id must not decrypt.
    assert!(collab_file_decrypt(&blob, &secret, "other-file").is_err());
}

#[test]
fn enc1_decrypt_rejects_missing_prefix() {
    let err = enc1_decrypt("not-an-envelope", &link_secret(), SCOPE_ID).unwrap_err();
    assert!(matches!(err, ManifestError::MissingEnc1Prefix));
}

#[test]
fn collab_file_decrypt_rejects_short_blob() {
    let err = collab_file_decrypt(&[0u8; 10], &link_secret(), FILE_ID).unwrap_err();
    assert!(matches!(err, ManifestError::TooShort { .. }));
}

// ── Bidirectional emitter (run with `--nocapture`) ──────────────────────────
//
// Prints a Rust-produced ENC1 envelope + collab-file blob for the FIXED inputs
// so a one-shot Dart verifier can confirm the PRODUCTION WRITE direction (Dart
// decrypts what Rust encrypts). Harmless as a normal test — just emits two lines.

#[test]
fn emit_rust_vectors_for_dart_bidirectional_check() {
    let secret = link_secret();
    let enc1 = enc1_encrypt(MANIFEST_JSON.as_bytes(), &secret, SCOPE_ID);
    let payload = hex::decode(FILE_PAYLOAD_HEX).unwrap();
    let blob = collab_file_encrypt(&payload, &secret, FILE_ID);
    let blob_b64 = base64::engine::general_purpose::STANDARD.encode(&blob);
    println!("RUST_BIDIR_ENC1={enc1}");
    println!("RUST_BIDIR_FILEBLOB_B64={blob_b64}");

    // Self round-trip — also keeps this emitter from being an assertion-free test.
    // (The printed values were fed back through the live Dart harness once to
    // prove Dart decrypts Rust output = `BIDIR_OK`, before the harness was deleted.)
    assert_eq!(
        enc1_decrypt(&enc1, &secret, SCOPE_ID).unwrap(),
        MANIFEST_JSON.as_bytes()
    );
    assert_eq!(collab_file_decrypt(&blob, &secret, FILE_ID).unwrap(), payload);
}

// ── Manifest model fidelity (serde structs vs the Dart toJson) ──────────────

#[test]
fn group_json_round_trips_byte_exact_with_dart() {
    let group: CollaborationGroup = serde_json::from_str(GROUP_JSON).unwrap();

    // Field + conditional-omission spot checks.
    assert_eq!(group.id, "group-123");
    assert_eq!(group.manifest_bucket, "fula-metadata");
    assert_eq!(group.expires_at.as_deref(), Some("2026-06-01T00:00:00.000Z"));
    assert!(!group.is_revoked);
    assert_eq!(group.version, 3);
    assert_eq!(group.removed_file_ids, vec!["f-removed-1".to_string()]);
    assert_eq!(group.files.len(), 2);

    let f1 = &group.files[0];
    assert_eq!(f1.content_type.as_deref(), Some("application/pdf"));
    assert_eq!(f1.path_scope.as_deref(), Some("/legal/contract.pdf"));
    assert_eq!(f1.enc_type, "fula");
    assert_eq!(f1.share_token_json.as_deref(), Some(r#"{"id":"tok1"}"#));

    let f2 = &group.files[1];
    assert_eq!(f2.content_type, None);
    assert_eq!(f2.path_scope, None);
    assert_eq!(f2.share_token_json, None);
    assert_eq!(f2.enc_type, "collab");

    // Byte-exact re-serialization == Dart's jsonEncode(group.toJson()).
    assert_eq!(serde_json::to_string(&group).unwrap(), GROUP_JSON);
}

#[test]
fn empty_collections_serialize_like_dart() {
    // `files` and `isRevoked` are ALWAYS emitted (even when empty/false);
    // `removedFileIds` is SKIPPED when empty; `expiresAt` is SKIPPED when None —
    // matching Dart `CollaborationGroup.toJson`. (The `group_json` vector covers
    // the populated case; this locks the omission/always-emit edges.)
    let g = group("G", 1, vec![], &[], false, None);
    let json = serde_json::to_string(&g).unwrap();
    assert!(json.contains(r#""files":[]"#), "files must always be emitted: {json}");
    assert!(
        json.contains(r#""isRevoked":false"#),
        "isRevoked must always be emitted: {json}"
    );
    assert!(
        !json.contains("removedFileIds"),
        "empty removedFileIds must be omitted: {json}"
    );
    assert!(
        !json.contains("expiresAt"),
        "None expiresAt must be omitted: {json}"
    );
}

#[test]
fn fromjson_defaults_mirror_dart() {
    // Missing encType defaults to "fula".
    let f: CollaborationFile = serde_json::from_str(
        r#"{"id":"x","fileName":"n","bucket":"b","storageKey":"s","addedByPublicKey":"p","addedAt":"t","fileSize":1}"#,
    )
    .unwrap();
    assert_eq!(f.enc_type, "fula");

    // Missing manifestBucket/version/isRevoked/files/removedFileIds default like Dart.
    let g: CollaborationGroup = serde_json::from_str(
        r#"{"id":"i","name":"n","ownerPublicKey":"o","manifestKey":"k","createdAt":"c","updatedAt":"u"}"#,
    )
    .unwrap();
    assert_eq!(g.manifest_bucket, "fula-metadata");
    assert_eq!(g.version, 1);
    assert!(!g.is_revoked);
    assert!(g.files.is_empty());
    assert!(g.removed_file_ids.is_empty());
}

// ── merge_with (CRDT) ───────────────────────────────────────────────────────

fn file(id: &str, added_at: &str) -> CollaborationFile {
    CollaborationFile {
        id: id.to_string(),
        file_name: format!("{id}.txt"),
        content_type: None,
        bucket: "b".to_string(),
        storage_key: format!("sk-{id}"),
        path_scope: None,
        added_by_public_key: "pk".to_string(),
        added_at: added_at.to_string(),
        file_size: 1,
        enc_type: "collab".to_string(),
        share_token_json: None,
    }
}

#[allow(clippy::too_many_arguments)]
fn group(
    id: &str,
    version: i64,
    files: Vec<CollaborationFile>,
    tombstones: &[&str],
    revoked: bool,
    expiry: Option<&str>,
) -> CollaborationGroup {
    CollaborationGroup {
        id: id.to_string(),
        name: format!("name-{id}"),
        owner_public_key: "owner".to_string(),
        manifest_bucket: "fula-metadata".to_string(),
        manifest_key: "mk".to_string(),
        created_at: "2026-01-01T00:00:00.000".to_string(),
        expires_at: expiry.map(str::to_string),
        is_revoked: revoked,
        files,
        removed_file_ids: tombstones.iter().map(|s| s.to_string()).collect(),
        version,
        updated_at: "2026-01-01T00:00:00.000".to_string(),
    }
}

#[test]
fn merge_unions_files_tombstones_and_picks_higher_version_base() {
    let a = group(
        "A",
        2,
        vec![
            file("f1", "2026-01-02T00:00:00.000"),
            file("f2", "2026-01-03T00:00:00.000"),
        ],
        &["t1"],
        false,
        Some("2026-12-01T00:00:00.000"),
    );
    let b = group(
        "B",
        5,
        vec![
            file("f2", "2026-09-09T00:00:00.000"), // conflict: A wins
            file("f3", "2026-01-01T00:00:00.000"),
        ],
        &["t2"],
        false,
        Some("2026-06-01T00:00:00.000"),
    );

    let merged = a.merge_with(&b, "2026-02-02T02:02:02.000");

    assert_eq!(merged.version, 6, "version = max(2,5)+1");
    // Higher-version side (B) supplies the scalar base fields.
    assert_eq!(merged.id, "B");
    assert_eq!(merged.name, "name-B");
    // Tombstone union, self-first insertion order.
    assert_eq!(
        merged.removed_file_ids,
        vec!["t1".to_string(), "t2".to_string()]
    );
    // Files sorted by addedAt: f3 (01-01), f1 (01-02), f2 (01-03 from A, not B's 09-09).
    let ids: Vec<&str> = merged.files.iter().map(|f| f.id.as_str()).collect();
    assert_eq!(ids, vec!["f3", "f1", "f2"]);
    let f2 = merged.files.iter().find(|f| f.id == "f2").unwrap();
    assert_eq!(f2.added_at, "2026-01-03T00:00:00.000", "self wins on id conflict");
    // Injected wall-clock.
    assert_eq!(merged.updated_at, "2026-02-02T02:02:02.000");
    // Shrink-only expiry: B's June < A's December.
    assert_eq!(merged.expires_at.as_deref(), Some("2026-06-01T00:00:00.000"));
}

#[test]
fn merge_drops_tombstoned_files() {
    let a = group(
        "A",
        1,
        vec![
            file("f1", "2026-01-02T00:00:00.000"),
            file("keep", "2026-01-05T00:00:00.000"),
        ],
        &[],
        false,
        None,
    );
    let b = group("B", 1, vec![], &["f1"], false, None);

    let merged = a.merge_with(&b, "2026-01-09T00:00:00.000");
    let ids: Vec<&str> = merged.files.iter().map(|f| f.id.as_str()).collect();
    assert_eq!(ids, vec!["keep"], "f1 is tombstoned by B and must be dropped");
    assert_eq!(merged.removed_file_ids, vec!["f1".to_string()]);
}

#[test]
fn merge_revocation_is_monotonic() {
    let revoked = group("A", 1, vec![], &[], true, None);
    let live = group("B", 9, vec![], &[], false, None); // higher version, NOT revoked

    // Revoked on either side ⇒ revoked, regardless of which side has higher version.
    assert!(revoked.merge_with(&live, "now").is_revoked);
    assert!(live.merge_with(&revoked, "now").is_revoked);
}

#[test]
fn merge_expiry_only_shrinks_even_against_higher_version() {
    // Stale higher-version copy with a FAR expiry vs a low-version NEAR expiry.
    let stale_far = group("A", 10, vec![], &[], false, Some("2027-01-01T00:00:00.000"));
    let fresh_near = group("B", 1, vec![], &[], false, Some("2026-03-01T00:00:00.000"));
    assert_eq!(
        stale_far.merge_with(&fresh_near, "now").expires_at.as_deref(),
        Some("2026-03-01T00:00:00.000"),
        "higher version must NOT extend a shortened expiry"
    );

    // A present expiry always wins over None (no-expiry = least restrictive).
    let no_expiry = group("C", 1, vec![], &[], false, None);
    assert_eq!(
        stale_far.merge_with(&no_expiry, "now").expires_at.as_deref(),
        Some("2027-01-01T00:00:00.000")
    );
    assert_eq!(
        no_expiry.merge_with(&stale_far, "now").expires_at.as_deref(),
        Some("2027-01-01T00:00:00.000")
    );
}

#[test]
fn merge_expiry_compares_naive_across_mixed_z_and_fraction_widths() {
    // Mixed 'Z'/no-'Z' and fractional widths must still compare chronologically
    // (naive wall-clock), so shrink-only holds: March < June regardless of suffix.
    let june = group("A", 1, vec![], &[], false, Some("2026-06-01T00:00:00.000"));
    let march_z = group("B", 1, vec![], &[], false, Some("2026-03-01T00:00:00.000Z"));
    assert_eq!(
        june.merge_with(&march_z, "now").expires_at.as_deref(),
        Some("2026-03-01T00:00:00.000Z")
    );

    // Same instant, different fractional widths ⇒ EQUAL. Dart's `isBefore?a:b`
    // tie-break returns the OTHER side's string, so the merged expiry is
    // byte-identical to Dart: `self.merge_with(other)` keeps `other`'s string.
    let short_frac = group("C", 1, vec![], &[], false, Some("2026-05-01T00:00:00.0"));
    let long_frac = group("D", 1, vec![], &[], false, Some("2026-05-01T00:00:00.000000"));
    assert_eq!(
        short_frac.merge_with(&long_frac, "now").expires_at.as_deref(),
        Some("2026-05-01T00:00:00.000000"),
        "tie -> other's string (Dart isBefore?a:b)"
    );
    assert_eq!(
        long_frac.merge_with(&short_frac, "now").expires_at.as_deref(),
        Some("2026-05-01T00:00:00.0")
    );
}

#[test]
fn merge_expiry_fails_closed_on_unparseable_input() {
    // A malformed expiry string must NEVER win via lexicographic compare and
    // extend the access window: the side that is a REAL instant is kept. (Trusted
    // producers never emit this; it is defense-in-depth — Dart would itself throw
    // on `DateTime.parse(garbage)`.)
    let real = group("A", 1, vec![], &[], false, Some("2025-01-01T00:00:00.000"));
    // '0' (0x30) lexicographically sorts BEFORE '2', so a naive lex compare would
    // wrongly treat this garbage as the "earlier"/winning expiry.
    let garbage = group("B", 1, vec![], &[], false, Some("0-not-a-real-date"));
    assert_eq!(
        real.merge_with(&garbage, "now").expires_at.as_deref(),
        Some("2025-01-01T00:00:00.000")
    );
    assert_eq!(
        garbage.merge_with(&real, "now").expires_at.as_deref(),
        Some("2025-01-01T00:00:00.000")
    );
}
