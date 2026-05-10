//! Walkable-v8 (W.9.3) — SDK self-verification of master-attested CIDs.
//!
//! Master returns each PUT's content-address as the response `ETag` header
//! (= `BLAKE3(ciphertext)` raw-codec, computed by kubo's
//! `block/put?cid-codec=raw&mhtype=blake3`; see
//! `crates/fula-cli/src/handlers/object.rs:103-137`). Walkable-v8 stamps
//! that CID into HAMT internal-node pointers, manifest pages, dir-index,
//! and forest file-index entries so an offline reader can fetch the same
//! ciphertext via a public IPFS gateway without going through master.
//!
//! Trusting the master to attest the CID without checking would let a
//! compromised master redirect future offline walkers to attacker-
//! controlled IPFS bytes (the gateway-side `verify_cid_against_bytes`
//! step would still hash-match, because the attacker chose a CID that
//! addresses *their* bytes). The fix is a one-line local re-hash and a
//! soft-fail-to-`None` on mismatch — the PUT itself succeeded, the
//! offline-walk hint just isn't trustworthy, and the legacy storage-key
//! path covers reads regardless.
//!
//! Mismatch logging is rate-limited per `(bucket, path)` per session via
//! a `DashSet` so a misconfigured proxy that chronically wraps etags
//! cannot flood production logs — the first occurrence of each path is
//! the load-bearing one.

use cid::Cid;
use cid::multihash::Multihash;
use dashmap::DashSet;
use std::sync::OnceLock;

/// BLAKE3 multihash code (per IANA / multiformats), matching kubo's
/// `mhtype=blake3` setting and master's `crates/fula-cli/src/handlers/object.rs:103-137`.
const MULTIHASH_BLAKE3: u64 = 0x1e;

/// Raw codec, matching master's `cid-codec=raw` setting for object
/// bodies. CID v1 + raw codec + BLAKE3 multihash is the canonical
/// content-address for every encrypted blob fula stores.
const CODEC_RAW: u64 = 0x55;

/// Process-wide deduplication of self-verify mismatch warnings. A real
/// production master never returns the wrong CID; if it does, we want a
/// loud signal once per `(bucket, path)` for triage. Without dedup a
/// chronically-misconfigured proxy could flood logs at PUT rate (every
/// retry, every chunk, every page).
fn mismatch_dedup() -> &'static DashSet<String> {
    static DEDUP: OnceLock<DashSet<String>> = OnceLock::new();
    DEDUP.get_or_init(DashSet::new)
}

/// Locally compute the v1 raw-codec BLAKE3-multihash CID of `ciphertext`
/// — the same CID kubo computes under `block/put?cid-codec=raw&mhtype=blake3`
/// for the same bytes.
///
/// Pure / no I/O / no allocation beyond the CID itself. ~1 GB/s on
/// commodity hardware via the `blake3` SIMD-accelerated implementation.
pub(crate) fn local_blake3_raw_cid(ciphertext: &[u8]) -> Cid {
    let h = blake3::hash(ciphertext);
    let mh = Multihash::<64>::wrap(MULTIHASH_BLAKE3, h.as_bytes())
        .expect("32-byte BLAKE3 digest fits in Multihash<64>");
    Cid::new_v1(CODEC_RAW, mh)
}

/// Resolve the cid-hint for a manifest-anchored fetch (W.9.4) given the
/// two sources of CID information that can appear in a `ManifestRoot`:
///
///   * `explicit_cid`: an `Option<Cid>` field stamped by the W.9.3
///     writer after self-verifying it against `BLAKE3(blob)`. When
///     present this is the trustworthy source — it survived the
///     SDK-side mismatch check, so the value is **at-most** what
///     `BLAKE3(blob)` actually was (master cannot have lied about it
///     without the writer dropping the field).
///   * `etag`: a string from S3 / master's PUT response. When master
///     emits `cid.to_string()` as the etag (current convention) the
///     etag-parse path produces a usable CID; when master's etag
///     format ever drifts (a future reconfig, a misbehaving proxy
///     that quotes the etag, etc.), this fallback degrades to None
///     and the offline path skips the gateway race.
///
/// Returns `Some(cid)` if either source produced one, with the
/// **explicit field winning when both are present** so a future where
/// master's etag format drifts (or a deliberate test that supplies a
/// non-CID etag) still routes through the explicit field. `None` when
/// neither source produces a CID — caller falls through to the no-hint
/// offline path (which itself has a warm-cache lookup).
///
/// Pure function. Unit-tested below to pin the precedence ordering so
/// a future refactor that reverses the `or_else` chain (etag-first)
/// would surface as a test failure.
pub(crate) fn cid_hint_from_manifest_field_or_etag(
    explicit_cid: Option<&Cid>,
    etag: Option<&str>,
) -> Option<Cid> {
    explicit_cid
        .cloned()
        .or_else(|| etag.and_then(|s| s.parse::<Cid>().ok()))
}

/// Walkable-v8 self-verification, expected-CID variant.
///
/// Compare the master-returned `etag` against an `expected` CID the
/// caller has already computed (typically via `local_blake3_raw_cid`
/// over the bytes the SDK sent). Returns `Some(cid)` only on equality.
///
/// Use this variant at writer sites where the caller already had to
/// produce the body buffer for the PUT — pre-computing `expected` from
/// the borrowed body avoids a second pass over the bytes after the PUT
/// has consumed them into a `Bytes` value.
///
/// Soft-fail semantics:
///   * `etag` doesn't parse as a CID → returns `None`.
///   * `etag` parses but disagrees with `expected` → emits one
///     `tracing::warn!` per `(bucket, path)` per session and returns
///     `None`. **Load-bearing safety property**: defends against a
///     compromised master attesting attacker-chosen CIDs that would
///     mislead future offline walkers, even though every
///     gateway-fetched block is content-verified.
///   * `etag` parses and matches → returns `Some(cid)`.
///
/// `bucket` and `path` are used solely for the mismatch warn log's
/// structured fields and for the `(bucket, path)`-keyed dedup — they
/// have no effect on the returned value.
pub(crate) fn verify_etag_against_expected_cid(
    etag: &str,
    expected: Cid,
    bucket: &str,
    path: &str,
) -> Option<Cid> {
    let parsed = match etag.parse::<Cid>() {
        Ok(c) => c,
        Err(e) => {
            // Operator-triage hint at debug level. Production master
            // never emits an unparseable etag (kubo's `block/put` returns
            // `cid.to_string()` straight per `crates/fula-cli/src/handlers/
            // object.rs:103-137`), so this firing in the wild typically
            // signals a misconfigured proxy stripping or wrapping the
            // header. Debug (not warn) so a chronic config issue can't
            // flood structured-log pipelines, but the signal is present
            // for anyone tailing.
            tracing::debug!(
                bucket = %bucket,
                path = %path,
                etag,
                error = %e,
                "walkable-v8 self-verify: master ETag did not parse as a CID; \
                 walkable-v8 hint will be None for this object"
            );
            return None;
        }
    };
    if parsed == expected {
        return Some(parsed);
    }
    // Use NUL as the separator: S3 bucket names cannot contain NUL and
    // S3 object keys cannot contain NUL (per AWS spec — keys are
    // arbitrary UTF-8 but `\x00` is reserved). NUL therefore yields an
    // unambiguous key for every (bucket, path) pair, defending the
    // dedup against a future caller that might pass a path containing
    // `/` and accidentally collide with a sibling (bucket, path).
    let dedup_key = format!("{bucket}\0{path}");
    if mismatch_dedup().insert(dedup_key) {
        tracing::warn!(
            bucket = %bucket,
            path = %path,
            expected = %expected,
            master_returned = %parsed,
            "walkable-v8 self-verify: master-attested CID disagrees with \
             locally-computed BLAKE3(ciphertext); soft-failing to None so \
             readers fall back to the storage-key path. Recurrence for the \
             same (bucket, path) is suppressed for the rest of this session."
        );
    }
    None
}

/// Walkable-v8 self-verification, body-bytes variant.
///
/// Convenience wrapper for sites that still hold the ciphertext when
/// they want to verify (e.g. `S3BlobBackend::put`'s retry loop, where
/// the body was cloned for retry). Computes `BLAKE3(ciphertext)`
/// internally and forwards to [`verify_etag_against_expected_cid`].
///
/// At sites that have already pre-computed the expected CID before the
/// PUT (every encryption.rs writer site under W.9.3-D), prefer
/// [`verify_etag_against_expected_cid`] directly to avoid a second
/// pass over the body after the PUT.
pub(crate) fn verify_etag_matches_ciphertext(
    etag: &str,
    ciphertext: &[u8],
    bucket: &str,
    path: &str,
) -> Option<Cid> {
    let expected = local_blake3_raw_cid(ciphertext);
    verify_etag_against_expected_cid(etag, expected, bucket, path)
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;

    fn make_ct(seed: u8, len: usize) -> Vec<u8> {
        (0..len).map(|i| seed.wrapping_add(i as u8)).collect()
    }

    #[test]
    fn local_blake3_raw_cid_is_deterministic_and_blake3_raw() {
        let ct = make_ct(0x10, 256);
        let cid1 = local_blake3_raw_cid(&ct);
        let cid2 = local_blake3_raw_cid(&ct);
        assert_eq!(cid1, cid2, "deterministic: same bytes → same CID");
        assert_eq!(cid1.codec(), CODEC_RAW, "codec must be raw 0x55");
        assert_eq!(cid1.hash().code(), MULTIHASH_BLAKE3, "multihash code 0x1e");
    }

    #[test]
    fn verify_etag_matches_returns_some_on_correct_etag() {
        let ct = make_ct(0x42, 128);
        let expected = local_blake3_raw_cid(&ct);
        let etag = expected.to_string();
        let result = verify_etag_matches_ciphertext(&etag, &ct, "bkt", "obj/key");
        assert_eq!(
            result,
            Some(expected),
            "matching etag must surface as Some(cid)"
        );
    }

    #[test]
    fn verify_etag_matches_returns_none_on_unparseable_etag() {
        let ct = make_ct(0x42, 64);
        let result = verify_etag_matches_ciphertext("not-a-cid-just-noise", &ct, "bkt", "k");
        assert!(
            result.is_none(),
            "unparseable etag soft-fails to None — PUT succeeded, only the \
             offline-walk hint is missing"
        );
    }

    #[test]
    fn verify_etag_matches_returns_none_on_master_mismatch() {
        let real_ct = make_ct(0x42, 64);
        let other_ct = make_ct(0x43, 64);
        let other_cid = local_blake3_raw_cid(&other_ct);
        // Pass an etag for a DIFFERENT body — simulates a master that
        // (e.g., due to compromise) attests a CID that doesn't address
        // what we sent. SDK must reject and soft-fail.
        let result = verify_etag_matches_ciphertext(
            &other_cid.to_string(),
            &real_ct,
            "bkt-mismatch",
            "k-mismatch",
        );
        assert!(
            result.is_none(),
            "master-attested CID disagreeing with local hash must soft-fail \
             — defends against a compromised master redirecting future \
             offline walkers to attacker-controlled IPFS bytes"
        );
    }

    #[test]
    fn cid_hint_prefers_explicit_field_over_etag_parse() {
        // W.9.4: this precedence is load-bearing. The W.9.3 writer
        // self-verifies `explicit_cid` against `BLAKE3(blob)` before
        // stamping; the etag string is only-as-trustworthy as master's
        // current convention of emitting `cid.to_string()`. If a
        // future master change ships a different etag format (or a
        // misbehaving proxy mangles it), the explicit field MUST still
        // win so cold-start offline-walks keep functioning.
        let cid_a = local_blake3_raw_cid(b"plaintext-A");
        let cid_b = local_blake3_raw_cid(b"plaintext-B");
        assert_ne!(cid_a, cid_b);

        // 1) Both populated, with disagreeing values: explicit wins.
        let resolved = cid_hint_from_manifest_field_or_etag(
            Some(&cid_a),
            Some(&cid_b.to_string()),
        );
        assert_eq!(
            resolved,
            Some(cid_a),
            "explicit cid field MUST win when present, even if etag also \
             parses as a different cid — defends against a future master \
             whose etag drifts from the W.9.3 self-verified field"
        );

        // 2) Only etag populated: etag-parse fallback fires.
        let resolved =
            cid_hint_from_manifest_field_or_etag(None, Some(&cid_a.to_string()));
        assert_eq!(
            resolved,
            Some(cid_a),
            "etag-parse fallback must work for pre-W.9.3 buckets that \
             lack the explicit cid field"
        );

        // 3) Only explicit populated: explicit returned.
        let resolved = cid_hint_from_manifest_field_or_etag(Some(&cid_a), None);
        assert_eq!(resolved, Some(cid_a));

        // 4) Etag is non-CID (a future master drift, or a quoted etag
        //    that escaped the trim, etc.): explicit field still wins.
        let resolved = cid_hint_from_manifest_field_or_etag(
            Some(&cid_a),
            Some("not-a-cid-just-some-string"),
        );
        assert_eq!(
            resolved,
            Some(cid_a),
            "non-CID etag must NOT poison the explicit-field path — the \
             explicit field is independent and remains usable"
        );

        // 5) Both None: no hint.
        let resolved = cid_hint_from_manifest_field_or_etag(None, None);
        assert_eq!(resolved, None);

        // 6) Etag is unparseable AND explicit is None: still None
        //    (no fabricated cid).
        let resolved = cid_hint_from_manifest_field_or_etag(None, Some("bogus"));
        assert_eq!(resolved, None);
    }

    #[test]
    fn verify_etag_matches_dedup_suppresses_repeat_mismatch_warns() {
        // The dedup is a process-wide DashSet, so we use a unique
        // (bucket, path) per test to avoid cross-test contamination.
        let real = make_ct(0x77, 32);
        let other = make_ct(0x78, 32);
        let bad = local_blake3_raw_cid(&other).to_string();
        // Two consecutive calls with the SAME (bucket, path) — the
        // second insert into the dedup set returns false, so the
        // warn-log path is skipped (we can't observe `tracing::warn!`
        // directly here, but we can observe the dedup state).
        let key = format!("{}\0{}", "bkt-dedup-unique", "k-dedup-unique");
        let dedup = mismatch_dedup();
        // Pre-condition: key absent.
        assert!(!dedup.contains(&key), "fresh dedup state for this key");
        let r1 = verify_etag_matches_ciphertext(&bad, &real, "bkt-dedup-unique", "k-dedup-unique");
        let r2 = verify_etag_matches_ciphertext(&bad, &real, "bkt-dedup-unique", "k-dedup-unique");
        assert!(r1.is_none() && r2.is_none(), "both calls soft-fail");
        assert!(
            dedup.contains(&key),
            "dedup key persisted after first warn-emitting call"
        );
        // Different path — must still log (own dedup slot).
        let other_key = format!("{}\0{}", "bkt-dedup-unique", "k-dedup-other");
        assert!(!dedup.contains(&other_key));
        let _ = verify_etag_matches_ciphertext(
            &bad,
            &real,
            "bkt-dedup-unique",
            "k-dedup-other",
        );
        assert!(
            dedup.contains(&other_key),
            "different path gets its own dedup slot — first occurrence \
             still logged"
        );
    }
}
