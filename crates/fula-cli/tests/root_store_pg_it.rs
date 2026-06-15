//! FM-1 (Phase 2.5) — PgRootStore integration test against a REAL Postgres.
//!
//! Proves the shared bucket-root arbiter that makes concurrent federated
//! masters safe behaves correctly against the actual database + migration 020
//! `bucket_roots` table — the exact CAS two live gateways perform on flush.
//!
//! Skips cleanly when POSTGRES_* is unset (local dev); the Phase 2.5 drill
//! runs it on the test master's stack DB.
//!
//! Run: POSTGRES_HOST=127.0.0.1 POSTGRES_DB=pinning_service \
//!      POSTGRES_USER=pinning_user POSTGRES_PASSWORD=… \
//!      cargo test -p fula-cli --test root_store_pg_it -- --ignored --nocapture

#![cfg(not(target_arch = "wasm32"))]

use cid::Cid;
use fula_core::root_pointer::{CasOutcome, RootPointerStore};
use fula_cli::root_store_pg::PgRootStore;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

fn cid_of(b: &[u8]) -> Cid {
    let h = blake3::hash(b);
    let mh = cid::multihash::Multihash::<64>::wrap(0x1e, h.as_bytes()).unwrap();
    Cid::new_v1(0x55, mh)
}

async fn pool_or_skip() -> Option<sqlx::PgPool> {
    let env = |k: &str| std::env::var(k).ok().filter(|s| !s.trim().is_empty());
    let (host, db, user) = (env("POSTGRES_HOST")?, env("POSTGRES_DB")?, env("POSTGRES_USER")?);
    let port = env("POSTGRES_PORT").and_then(|s| s.parse().ok()).unwrap_or(5432u16);
    let pass = std::env::var("POSTGRES_PASSWORD").unwrap_or_default();
    let opts = PgConnectOptions::new().host(&host).port(port).database(&db).username(&user).password(&pass);
    match PgPoolOptions::new().max_connections(4).connect_with(opts).await {
        Ok(p) => Some(p),
        Err(e) => {
            eprintln!("SKIP: cannot reach Postgres: {e}");
            None
        }
    }
}

#[tokio::test]
#[ignore]
async fn pg_cas_arbitrates_the_two_master_race() {
    let Some(pool) = pool_or_skip().await else { return };
    let owner = "p25-it-owner";
    let bucket = format!("p25-it-bkt-{}", std::process::id());
    // Clean any prior row for a deterministic run.
    let _ = sqlx::query("DELETE FROM bucket_roots WHERE owner_id = $1 AND bucket = $2")
        .bind(owner).bind(&bucket).execute(&pool).await;

    let store = PgRootStore::new(pool.clone());
    let (a, b, c) = (cid_of(b"r-a"), cid_of(b"r-b"), cid_of(b"r-c"));

    // First flush claims the slot (no row yet — expected==new is the bootstrap).
    assert_eq!(store.cas_root(owner, &bucket, &a, &b).await.unwrap(), CasOutcome::Won);
    assert_eq!(store.get_root(owner, &bucket).await.unwrap(), Some(b), "shared root is now B");

    // Master #2 built on the STALE root A → must conflict, reporting current=B.
    match store.cas_root(owner, &bucket, &a, &c).await.unwrap() {
        CasOutcome::Conflict { current } => assert_eq!(current, Some(b)),
        other => panic!("stale flush must conflict, got {other:?}"),
    }
    // The pointer is unchanged by the losing CAS.
    assert_eq!(store.get_root(owner, &bucket).await.unwrap(), Some(b));

    // Loser reopens at the shared root B and retries → wins.
    assert_eq!(store.cas_root(owner, &bucket, &b, &c).await.unwrap(), CasOutcome::Won);
    assert_eq!(store.get_root(owner, &bucket).await.unwrap(), Some(c));

    // version incremented across the two winning CASes (claim=1, then +1).
    let version: i64 = sqlx::query_scalar("SELECT version FROM bucket_roots WHERE owner_id=$1 AND bucket=$2")
        .bind(owner).bind(&bucket).fetch_one(&pool).await.unwrap();
    assert_eq!(version, 2, "two winning CASes ⇒ version 2");

    let _ = sqlx::query("DELETE FROM bucket_roots WHERE owner_id = $1 AND bucket = $2")
        .bind(owner).bind(&bucket).execute(&pool).await;
}

/// Concurrency: fire N tasks that all build on the SAME root; EXACTLY ONE may
/// win — the rest must conflict. This is the real two-master race, collapsed
/// into one process hitting the real Postgres.
#[tokio::test]
#[ignore]
async fn pg_cas_admits_exactly_one_concurrent_winner() {
    let Some(pool) = pool_or_skip().await else { return };
    let owner = "p25-it-owner";
    let bucket = format!("p25-it-conc-{}", std::process::id());
    let _ = sqlx::query("DELETE FROM bucket_roots WHERE owner_id=$1 AND bucket=$2")
        .bind(owner).bind(&bucket).execute(&pool).await;

    let base = cid_of(b"base");
    // Establish the base root.
    PgRootStore::new(pool.clone()).cas_root(owner, &bucket, &base, &base).await.unwrap();

    // 8 racers, each proposing a distinct new root from `base`.
    let mut handles = Vec::new();
    for i in 0..8u8 {
        let pool = pool.clone();
        let bucket = bucket.clone();
        let base = base;
        handles.push(tokio::spawn(async move {
            let store = PgRootStore::new(pool);
            let new = cid_of(&[i; 8]);
            store.cas_root(owner, &bucket, &base, &new).await.unwrap()
        }));
    }
    let mut wins = 0;
    for h in handles {
        if matches!(h.await.unwrap(), CasOutcome::Won) {
            wins += 1;
        }
    }
    assert_eq!(wins, 1, "exactly one concurrent CAS from the same base may win");

    let _ = sqlx::query("DELETE FROM bucket_roots WHERE owner_id=$1 AND bucket=$2")
        .bind(owner).bind(&bucket).execute(&pool).await;
}
