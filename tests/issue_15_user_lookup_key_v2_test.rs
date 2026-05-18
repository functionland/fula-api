//! Issue #15 — client-derived userKey_v2 for the global users-index.
//!
//! Today: the global users-index CBOR maps `BLAKE3("fula:user_id:" || user_id)[..16]`
//! → `bucketsIndexCid`. Both are server-derived from public attributes,
//! so anyone with the published CBOR can enumerate Fula users by
//! hashing target emails / subs.
//!
//! After the fix:
//! - `fula_crypto::hashing::compute_user_lookup_key_v2(user_id, kek_pub)`
//!   produces `BLAKE3("fula:user-lookup-v2:" || user_id || kek_pub)[..16]`,
//!   client-derived (server doesn't have `kek_pub`).
//! - `GlobalUsersIndex` gains an additive `users_v2` field — Mode B users'
//!   client-supplied v2 lookup keys. Default empty so the CBOR byte-shape
//!   is identical to today when no Mode B users exist.
//!
//! These tests compile only against the post-fix API. On current `main`
//! they fail to compile, which is the intended "failing-first" signal.

use fula_cli::handlers::users_index_publisher::{
    build_global_users_index_v2, GlobalUsersIndex,
};
use fula_crypto::hashing::compute_user_lookup_key_v2;
use std::collections::BTreeMap;

#[test]
fn user_lookup_key_v2_is_deterministic() {
    let user_id = b"alice@example.com";
    let kek_pub = [0x42u8; 32];
    let k1 = compute_user_lookup_key_v2(user_id, &kek_pub);
    let k2 = compute_user_lookup_key_v2(user_id, &kek_pub);
    assert_eq!(k1, k2);
    assert_eq!(k1.len(), 16, "16 bytes (128 bits) per spec");
}

#[test]
fn user_lookup_key_v2_distinct_user_ids_distinct_keys() {
    let kek_pub = [0x42u8; 32];
    let k_alice = compute_user_lookup_key_v2(b"alice@example.com", &kek_pub);
    let k_bob = compute_user_lookup_key_v2(b"bob@example.com", &kek_pub);
    assert_ne!(k_alice, k_bob);
}

#[test]
fn user_lookup_key_v2_distinct_kek_pubs_distinct_keys() {
    // Load-bearing for the F-A3 fix: this is what makes Mode A vs
    // Mode B users produce different lookup keys for the same
    // user_id — Mode A's KEK is identity-derived, Mode B's is salted
    // + seeded.
    let user_id = b"alice@example.com";
    let kek_pub_a = [0xAAu8; 32];
    let kek_pub_b = [0xBBu8; 32];
    let k_a = compute_user_lookup_key_v2(user_id, &kek_pub_a);
    let k_b = compute_user_lookup_key_v2(user_id, &kek_pub_b);
    assert_ne!(k_a, k_b);
}

#[test]
fn user_lookup_key_v2_domain_separation_from_legacy() {
    // The new key MUST NOT collide with the legacy hash_user_id (v1)
    // even for byte-equivalent inputs. The domain prefix
    // "fula:user-lookup-v2:" guarantees this.
    let user_id = b"alice@example.com";
    let kek_pub = [0u8; 32];
    let v2 = compute_user_lookup_key_v2(user_id, &kek_pub);
    // Legacy v1: BLAKE3("fula:user_id:" || user_id)[..16]
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"fula:user_id:");
    hasher.update(user_id);
    let v1 = {
        let h = hasher.finalize();
        let mut out = [0u8; 16];
        out.copy_from_slice(&h.as_bytes()[..16]);
        out
    };
    assert_ne!(v1, v2, "v1 and v2 must be domain-separated");
}

#[test]
fn global_users_index_v2_empty_is_back_compat() {
    // A CBOR with empty `users_v2` should produce a byte-equivalent
    // encoding to the legacy schema thanks to `skip_serializing_if`.
    let mut entries_v1: BTreeMap<String, cid::Cid> = BTreeMap::new();
    let dummy_cid: cid::Cid = "QmYzfL2k4XAWWBfSk8N3qHRgUcDoNcMqdo2pCnFkmJEHpa"
        .parse()
        .unwrap();
    entries_v1.insert("aabbccdd00112233aabbccdd00112233".to_string(), dummy_cid);

    let global_v2 =
        build_global_users_index_v2(&entries_v1, &BTreeMap::new(), /* sequence */ 1, /* now */ 0);

    // Mirror the OLD shape — same fields the audit finding cites.
    assert_eq!(global_v2.users.len(), 1);
    assert!(global_v2.users_v2.is_empty());

    // Round-trip dag-cbor and re-parse with the SAME schema (additive).
    let bytes =
        serde_ipld_dagcbor::to_vec(&global_v2).expect("serialize");
    let parsed: GlobalUsersIndex = serde_ipld_dagcbor::from_slice(&bytes).expect("parse");
    assert_eq!(parsed.users.len(), 1);
    assert!(parsed.users_v2.is_empty());
}

#[test]
fn global_users_index_v2_populated_round_trips() {
    let mut v1 = BTreeMap::new();
    let mut v2 = BTreeMap::new();
    let cid_a: cid::Cid = "QmYzfL2k4XAWWBfSk8N3qHRgUcDoNcMqdo2pCnFkmJEHpa"
        .parse()
        .unwrap();
    let cid_b: cid::Cid = "QmTzfL2k4XAWWBfSk8N3qHRgUcDoNcMqdo2pCnFkmJEHpb"
        .parse()
        .unwrap();
    v1.insert("aaaa00000000000000000000000000aa".to_string(), cid_a);
    v2.insert("ffffeeeeddddccccbbbbaaaa99998888".to_string(), cid_b);

    let global = build_global_users_index_v2(&v1, &v2, /* sequence */ 5, /* now */ 1700000000);
    assert_eq!(global.users.len(), 1);
    assert_eq!(global.users_v2.len(), 1);
    assert_eq!(global.sequence, 5);

    let bytes = serde_ipld_dagcbor::to_vec(&global).expect("serialize");
    let parsed: GlobalUsersIndex = serde_ipld_dagcbor::from_slice(&bytes).expect("parse");
    assert_eq!(parsed, global);
}
