//! FM-1 (Phase 2.5, federated masters) — shared bucket-root arbitration.
//!
//! With more than one gateway serving writes, the per-bucket root pointer
//! must live somewhere ALL masters can compare-and-swap, or concurrent
//! flushes silently drop each other's objects (the in-process
//! `bucket_write_locks` only serialize within one process). This trait is
//! that arbiter, deliberately storage-agnostic: fula-core never learns what
//! backs it (fula-cli injects a Postgres implementation — the Stage-A
//! masters already share one database — and later phases may swap in a
//! chain-backed store without touching this crate).
//!
//! Wiring (when the operator enables the flag):
//!   * `Bucket::flush()` CASes `(owner, bucket): old_root -> new_root`
//!     BEFORE publishing the new root to the in-process metadata cache.
//!     A lost race surfaces as `CoreError::PreconditionFailed` — the same
//!     retryable contract as conditional writes, which client SDKs
//!     already handle.
//!   * `BucketManager::open_bucket_for_user()` consults `get_root` so a
//!     bucket modified by ANOTHER master is opened at the shared root,
//!     not this process's stale cache.
//!
//! Disabled (no store injected — the default): behavior is byte-identical
//! to today's single-master code.

use crate::error::Result;
use async_trait::async_trait;
use cid::Cid;

/// Outcome of a compare-and-swap on the shared root pointer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CasOutcome {
    /// This master won: the shared pointer now holds the new root.
    Won,
    /// Another master moved the pointer first. `current` is the root the
    /// shared store holds now (None if the row vanished — treat as retry).
    Conflict { current: Option<Cid> },
}

/// Shared, multi-master-visible bucket-root pointer store.
#[async_trait]
pub trait RootPointerStore: Send + Sync {
    /// Atomically set `(owner_id, bucket)` to `new` iff the stored root is
    /// `expected` (or no row exists yet — first flush claims the slot).
    async fn cas_root(
        &self,
        owner_id: &str,
        bucket: &str,
        expected: &Cid,
        new: &Cid,
    ) -> Result<CasOutcome>;

    /// The shared root for `(owner_id, bucket)`, if any master has flushed.
    async fn get_root(&self, owner_id: &str, bucket: &str) -> Result<Option<Cid>>;
}

#[cfg(test)]
mod tests {
    use super::test_support::InMemoryRootStore;
    use super::*;

    fn cid_of(b: &[u8]) -> Cid {
        let h = blake3::hash(b);
        let mh = cid::multihash::Multihash::<64>::wrap(0x1e, h.as_bytes()).unwrap();
        Cid::new_v1(0x55, mh)
    }

    /// The exact two-master race: both open at root A; master 1 flushes A→B
    /// and wins; master 2 flushes A→C and MUST conflict (its write would
    /// silently drop master 1's objects otherwise).
    #[tokio::test]
    async fn second_master_building_on_a_stale_root_loses_the_cas() {
        let store = InMemoryRootStore::default();
        let (a, b, c) = (cid_of(b"root-a"), cid_of(b"root-b"), cid_of(b"root-c"));

        assert_eq!(
            store.cas_root("owner", "bkt", &a, &b).await.unwrap(),
            CasOutcome::Won,
            "first flush claims the slot"
        );
        match store.cas_root("owner", "bkt", &a, &c).await.unwrap() {
            CasOutcome::Conflict { current } => assert_eq!(current, Some(b)),
            other => panic!("stale flush must conflict, got {other:?}"),
        }
        // The loser reopens at the shared root and retries — now it wins.
        assert_eq!(
            store.cas_root("owner", "bkt", &b, &c).await.unwrap(),
            CasOutcome::Won
        );
        assert_eq!(store.get_root("owner", "bkt").await.unwrap(), Some(c));
    }

    #[tokio::test]
    async fn buckets_and_owners_are_isolated() {
        let store = InMemoryRootStore::default();
        let (a, b) = (cid_of(b"a"), cid_of(b"b"));
        store.cas_root("o1", "bkt", &a, &b).await.unwrap();
        assert_eq!(store.get_root("o2", "bkt").await.unwrap(), None);
        assert_eq!(store.get_root("o1", "other").await.unwrap(), None);
    }
}

#[cfg(test)]
pub mod test_support {
    //! In-memory store for unit tests: two Buckets sharing one of these
    //! reproduce the cross-master race deterministically.
    use super::*;
    use dashmap::DashMap;
    use std::sync::Arc;

    #[derive(Default, Clone)]
    pub struct InMemoryRootStore {
        inner: Arc<DashMap<(String, String), Cid>>,
    }

    #[async_trait]
    impl RootPointerStore for InMemoryRootStore {
        async fn cas_root(
            &self,
            owner_id: &str,
            bucket: &str,
            expected: &Cid,
            new: &Cid,
        ) -> Result<CasOutcome> {
            let key = (owner_id.to_string(), bucket.to_string());
            let mut entry = self.inner.entry(key).or_insert(*expected);
            if *entry.value() == *expected {
                *entry.value_mut() = *new;
                Ok(CasOutcome::Won)
            } else {
                Ok(CasOutcome::Conflict {
                    current: Some(*entry.value()),
                })
            }
        }

        async fn get_root(&self, owner_id: &str, bucket: &str) -> Result<Option<Cid>> {
            Ok(self
                .inner
                .get(&(owner_id.to_string(), bucket.to_string()))
                .map(|e| *e.value()))
        }
    }
}
