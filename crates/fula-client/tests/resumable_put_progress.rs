//! Chunk-granular upload progress on the NATIVE resumable paths.
//!
//! The web path (`put_object_flat_with_progress`) is covered by
//! `chunk_put_progress.rs`. These tests exercise the separate (mirrored)
//! native chunk loops:
//!   * `put_object_encrypted_resumable_with_cancel_and_progress` (fresh)
//!   * `resume_upload_with_cancel_and_progress` (resume)
//! The resume test is the important one: it proves the progress counter is
//! **seeded with the already-uploaded chunk count**, so the bar continues
//! from where an interrupted attempt stopped and still reaches 100% even
//! though only the *remaining* chunks are re-uploaded.

#![cfg(not(target_arch = "wasm32"))]

use bytes::Bytes;
use cid::multihash::Multihash;
use cid::Cid;
use fula_client::{Config, EncryptedClient, EncryptionConfig};
use fula_crypto::keys::SecretKey;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tempfile::TempDir;
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

fn blake3_raw_cid(data: &[u8]) -> Cid {
    let h = blake3::hash(data);
    let mh = Multihash::<64>::wrap(0x1e, h.as_bytes()).expect("blake3 multihash wrap");
    Cid::new_v1(0x55, mh)
}

/// 200 + matching ETag so the W.9.3/W.9.4 self-verify accepts the PUT.
fn ok_with_etag(req: &Request) -> ResponseTemplate {
    ResponseTemplate::new(200).insert_header("ETag", blake3_raw_cid(&req.body).to_string())
}

/// Every PUT succeeds (fresh-path test).
struct EtagResponder;
impl Respond for EtagResponder {
    fn respond(&self, req: &Request) -> ResponseTemplate {
        ok_with_etag(req)
    }
}

/// Two-phase PUT responder for the resume test, with NO dependency on the
/// (encoder-determined) chunk count:
///   * While `phase2 == false`: the first `ok_budget` PUTs succeed and the
///     rest fail with a NON-transient 403 (so the SDK doesn't retry them).
///     A phase-1 upload therefore lands EXACTLY `ok_budget` chunks and then
///     errors, leaving a real partial manifest on disk.
///   * Once the test flips `phase2 = true`: every PUT succeeds, so the
///     resume re-uploads the remaining chunks + finalize + forest flush.
struct PhasedResponder {
    seen: AtomicUsize,
    phase2: Arc<AtomicBool>,
    ok_budget: usize,
}
impl Respond for PhasedResponder {
    fn respond(&self, req: &Request) -> ResponseTemplate {
        if self.phase2.load(Ordering::Acquire) {
            return ok_with_etag(req);
        }
        let n = self.seen.fetch_add(1, Ordering::SeqCst);
        if n < self.ok_budget {
            ok_with_etag(req)
        } else {
            ResponseTemplate::new(403)
        }
    }
}

fn make_client(uri: &str, secret: SecretKey) -> EncryptedClient {
    let mut config = Config::new(uri).with_token("test-jwt");
    config.walkable_v8_writer_enabled = true;
    EncryptedClient::new(config, EncryptionConfig::from_secret_key(secret))
        .expect("EncryptedClient::new")
}

type Events = Arc<Mutex<Vec<(u64, u64)>>>;
fn progress_collector() -> (Events, Arc<dyn Fn(u64, u64) + Send + Sync>) {
    let events: Events = Arc::new(Mutex::new(Vec::new()));
    let ev = events.clone();
    let cb: Arc<dyn Fn(u64, u64) + Send + Sync> = Arc::new(move |done, tot| {
        ev.lock().unwrap().push((done, tot));
    });
    (events, cb)
}

/// Fresh resumable upload reports cumulative progress reaching 100%.
#[tokio::test]
async fn resumable_fresh_reports_cumulative_progress() {
    let server = MockServer::start().await;
    Mock::given(method("PUT")).respond_with(EtagResponder).mount(&server).await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;
    Mock::given(method("HEAD"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let client = make_client(&server.uri(), SecretKey::generate());
    // 2 MiB > CHUNKED_THRESHOLD (768 KB) ⇒ multiple chunks ⇒ multiple events.
    let data = vec![0xABu8; 2 * 1024 * 1024];
    let total = data.len() as u64;

    let manifest_dir = TempDir::new().expect("manifest tempdir");
    let manifest_path = manifest_dir.path().join("fresh.manifest");

    let (events, cb) = progress_collector();
    client
        .put_object_encrypted_resumable_with_cancel_and_progress(
            "videos-v8",
            "/fresh.mp4",
            Bytes::from(data),
            Some("video/mp4"),
            &manifest_path,
            None,     // no cancel
            Some(cb), // progress
        )
        .await
        .expect("fresh resumable upload must succeed");

    let evs = events.lock().unwrap().clone();
    assert!(!evs.is_empty(), "progress must be reported at least once");
    assert!(
        evs.iter().all(|(_, t)| *t == total),
        "every event's total must equal the file size ({total})"
    );
    for (done, _) in &evs {
        assert!(*done <= total, "cumulative bytes must not exceed total");
    }
    // buffer/spawn completion order != push order, so assert the MAX reached
    // total (not the last-pushed).
    let max_done = evs.iter().map(|(d, _)| *d).max().unwrap();
    assert_eq!(max_done, total, "fresh progress must reach 100% (max == total)");
}

/// Resume seeds the cumulative counter with already-uploaded chunks, so the
/// bar continues from where it stopped and still reaches 100%.
#[tokio::test]
async fn resume_reports_seeded_cumulative_progress() {
    let secret = SecretKey::generate();
    let data = vec![0xCDu8; 2 * 1024 * 1024];
    let total = data.len() as u64;

    let manifest_dir = TempDir::new().expect("manifest tempdir");
    let manifest_path = manifest_dir.path().join("resume.manifest");

    let phase2 = Arc::new(AtomicBool::new(false));
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .respond_with(PhasedResponder {
            seen: AtomicUsize::new(0),
            phase2: phase2.clone(),
            ok_budget: 1, // exactly one chunk lands in phase 1
        })
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;
    Mock::given(method("HEAD"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let client = make_client(&server.uri(), secret);

    // ── Phase 1: only one chunk is allowed to land, the rest 403 ⇒ the
    //    upload fails and a real partial manifest persists.
    let phase1 = client
        .put_object_encrypted_resumable_with_cancel(
            "videos-v8",
            "/resume.mp4",
            Bytes::from(data.clone()),
            Some("video/mp4"),
            &manifest_path,
            None,
        )
        .await;
    assert!(phase1.is_err(), "phase 1 must fail (only one chunk allowed through)");
    assert!(
        manifest_path.exists(),
        "a partial manifest must persist after the failed attempt"
    );

    // ── Phase 2: let everything through; resume re-uploads ONLY the
    //    remaining chunks. A correctly seeded counter still reaches `total`.
    phase2.store(true, Ordering::Release);

    let (events, cb) = progress_collector();
    client
        .resume_upload_with_cancel_and_progress(&manifest_path, &data, None, Some(cb))
        .await
        .expect("resume must succeed");

    let evs = events.lock().unwrap().clone();
    assert!(!evs.is_empty(), "resume must report progress for re-uploaded chunks");
    assert!(
        evs.iter().all(|(_, t)| *t == total),
        "every event's total must equal the file size ({total})"
    );
    let min_done = evs.iter().map(|(d, _)| *d).min().unwrap();
    let max_done = evs.iter().map(|(d, _)| *d).max().unwrap();
    assert!(min_done > 0, "a seeded counter never emits a zero-based event");
    // DECISIVE seed proof: phase 1 already landed one chunk, so the resume
    // re-uploads strictly fewer than N chunks. An UNSEEDED counter could
    // only reach (remaining/N)·total < total. Reaching `total` is possible
    // ONLY if the counter was seeded with the already-uploaded chunk count.
    assert_eq!(
        max_done, total,
        "seeded resume progress must reach 100% (max == total)"
    );
}
