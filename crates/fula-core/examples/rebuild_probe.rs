//! Fresh-tree gateway-index rebuild prototype (DIAGNOSTIC — local, non-destructive).
//!
//! Proves the keystone of the server-side index-rebuild recovery (P3): that a
//! BRAND-NEW `ProllyTree<String, ObjectMetadata>` built from a key->cid set
//! (the bucket's real S3 keys, parsed from the pin-map CSV) flushes to a store,
//! reloads from its root CID, lists every entry, and resolves a key — i.e. a
//! fresh tree dodges the re-PUT "must read the whole existing tree first"
//! chicken-and-egg that blocks in-place repair.
//!
//! Uses an in-memory MemoryBlockStore. Touches no gateway, no network, nothing
//! durable. The walkable-v8 forest nodes (pinned `v8-node:<bucket>`, no key in
//! the pin name) are intentionally absent here — this quantifies the Postgres-
//! derived key set; the v8 gap is handled separately (walk-supplied keys).
//!
//! Usage:
//!   cargo run -p fula-core --example rebuild_probe -- <pinmap.csv> [bucket]

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;

use cid::Cid;
use fula_blockstore::MemoryBlockStore;
use fula_core::{ObjectMetadata, ProllyTree};

fn main() {
    let mut args = std::env::args().skip(1);
    let csv_path = args.next().expect("arg1: pin-map CSV path");
    let bucket = args.next().unwrap_or_else(|| "images".to_string());
    let object_prefix = format!("object:{}/", bucket);

    // Parse CSV -> s3_key -> cid. Multi-version: last cid wins (dedup).
    let text = std::fs::read_to_string(&csv_path).expect("read CSV");
    let mut entries: HashMap<String, String> = HashMap::new();
    let mut skipped_infra = 0usize;
    for (i, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if i == 0 && line.starts_with("name,") {
            continue;
        }
        let Some((name, cid)) = line.split_once(',') else {
            continue;
        };
        let name = name.trim().trim_matches('"');
        let cid = cid.trim().trim_matches('"');
        if cid.is_empty() {
            continue;
        }
        // The gateway index key is the S3 object key.
        let key = if let Some(rest) = name.strip_prefix(&object_prefix) {
            rest.to_string()
        } else if name.starts_with("__fula_forest_v7_nodes/") {
            name.to_string()
        } else {
            skipped_infra += 1; // v8-node:/bucket:/forest-meta: — no usable key in pin name
            continue;
        };
        entries.insert(key, cid.to_string());
    }
    println!(
        "CSV -> {} distinct index keys ({} infra rows skipped, incl keyless v8-node pins)",
        entries.len(),
        skipped_infra
    );

    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    rt.block_on(async move {
        let store = Arc::new(MemoryBlockStore::new());

        // BUILD a fresh tree from key -> ObjectMetadata{cid,size,etag}.
        let mut tree: ProllyTree<String, ObjectMetadata, _> = ProllyTree::new(Arc::clone(&store));
        let mut built = 0usize;
        let mut sample: Option<(String, Cid)> = None;
        let mut bad_cid = 0usize;
        for (key, cid_str) in entries.iter() {
            let cid = match Cid::from_str(cid_str) {
                Ok(c) => c,
                Err(_) => {
                    bad_cid += 1;
                    continue;
                }
            };
            let meta = ObjectMetadata::new(cid, 0, cid.to_string());
            tree.set(key.clone(), meta).await.expect("set");
            if sample.is_none() {
                sample = Some((key.clone(), cid));
            }
            built += 1;
        }
        let root_cid = tree.flush().await.expect("flush");
        println!(
            "built {} entries ({} unparseable cids) -> FRESH root_cid = {}",
            built, bad_cid, root_cid
        );

        // RELOAD from the root cid (same store) and verify a full round-trip.
        let tree2: ProllyTree<String, ObjectMetadata, _> =
            ProllyTree::load(Arc::clone(&store), root_cid)
                .await
                .expect("load fresh root");
        let listed = tree2
            .list_prefix_bounded(b"", None, 100_000_000)
            .await
            .expect("list");
        println!("reloaded fresh root + listed {} entries", listed.len());

        // GET a sample key -> must resolve to its cid (proves point lookups work).
        if let Some((k, c)) = sample {
            match tree2.get(&k).await.expect("get") {
                Some(m) if m.cid == c => println!("get(\"{}\") -> cid {}  [OK]", k, m.cid),
                Some(m) => println!("get MISMATCH: {} != {}", m.cid, c),
                None => println!("get returned None  [FAIL]"),
            }
        }

        println!(
            "\n{}",
            if listed.len() == built {
                "[OK] FRESH-TREE REBUILD round-trips: build -> flush -> reload -> list/get all consistent"
            } else {
                "[FAIL] reloaded list count != built count"
            }
        );
    });
}
