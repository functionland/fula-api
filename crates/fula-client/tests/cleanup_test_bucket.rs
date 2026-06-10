//! Reusable best-effort cleanup for e2e test buckets left on a real account.
//!
//! S3 `DELETE /{bucket}` only succeeds on an EMPTY bucket, and a forest bucket
//! retains internal objects a logical `delete_object_flat` never touches:
//! the dir-index shard objects, the manifest root + page objects, and the
//! content-addressed forest HAMT node objects (`__fula_forest_v7_nodes/<cid>`,
//! not enumerable by a derived key). This test lists EVERY raw object in the
//! bucket (paginated) via the low-level `FulaClient`, deletes each, then drops
//! the bucket — so a `-v8` (or any) e2e bucket can be fully removed.
//!
//! ## Running (PowerShell, from repo root)
//! ```powershell
//! $env:FULA_S3 = "https://s3.cloud.fx.land"
//! $env:FULA_JWT = "<jwt>"
//! $env:FULA_CLEANUP_BUCKET = "dirv8-e2e-1781063026-v8"
//! cargo test -p fula-client --test cleanup_test_bucket -- --ignored --nocapture
//! ```
//!
//! Required env: `FULA_S3`, `FULA_JWT`, `FULA_CLEANUP_BUCKET`.

#![cfg(not(target_arch = "wasm32"))]

use fula_client::{Config, FulaClient, ListObjectsOptions};

fn read_required_env(var: &str) -> Option<String> {
    match std::env::var(var) {
        Ok(v) if !v.is_empty() => Some(v),
        _ => {
            eprintln!("[cleanup] {} not set — skipping.", var);
            None
        }
    }
}

#[tokio::test]
#[ignore]
async fn cleanup_named_test_bucket() {
    let s3 = match read_required_env("FULA_S3") {
        Some(v) => v,
        None => return,
    };
    let jwt = match read_required_env("FULA_JWT") {
        Some(v) => v,
        None => return,
    };
    let bucket = match read_required_env("FULA_CLEANUP_BUCKET") {
        Some(v) => v,
        None => return,
    };

    // Guard rail: refuse to nuke anything that doesn't look like an e2e bucket,
    // so a mistyped FULA_CLEANUP_BUCKET can't wipe a real bucket like `images`.
    assert!(
        bucket.contains("e2e") || bucket.contains("test") || bucket.ends_with("-v8"),
        "refusing to clean '{}' — name must contain 'e2e'/'test' or end with '-v8' \
         (safety guard against wiping a real bucket)",
        bucket
    );

    let raw = FulaClient::new(Config::new(&s3).with_token(&jwt)).expect("raw FulaClient::new");

    // Page through ALL raw objects.
    let mut all_keys: Vec<String> = Vec::new();
    let mut token: Option<String> = None;
    loop {
        let opts = ListObjectsOptions {
            max_keys: Some(1000),
            continuation_token: token.clone(),
            ..Default::default()
        };
        let res = raw
            .list_objects(&bucket, Some(opts))
            .await
            .unwrap_or_else(|e| panic!("list_objects('{bucket}'): {e:?}"));
        for o in res.objects {
            all_keys.push(o.key);
        }
        if res.is_truncated {
            token = res.next_continuation_token;
            if token.is_none() {
                break; // defensive: truncated but no token
            }
        } else {
            break;
        }
    }
    eprintln!("[cleanup] '{}' holds {} raw objects", bucket, all_keys.len());

    let mut deleted = 0usize;
    let mut failed = 0usize;
    for k in &all_keys {
        match raw.delete_object(&bucket, k).await {
            Ok(_) => deleted += 1,
            Err(e) => {
                failed += 1;
                eprintln!("[cleanup]   delete_object {k} failed: {e:?}");
            }
        }
    }
    eprintln!("[cleanup] deleted {}/{} objects ({} failed)", deleted, all_keys.len(), failed);

    match raw.delete_bucket(&bucket).await {
        Ok(_) => eprintln!("[cleanup] delete_bucket('{}') OK — bucket removed", bucket),
        Err(e) => eprintln!(
            "[cleanup] delete_bucket('{}') failed: {:?} (objects may remain; re-run, or the \
             master may not allow bucket DELETE for this account)",
            bucket, e
        ),
    }
}
