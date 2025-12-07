//! Benchmarks for Prolly Tree operations

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use fula_core::prolly::{ProllyTree, ProllyConfig};
use fula_blockstore::memory::MemoryBlockStore;
use std::sync::Arc;

fn create_tree() -> (ProllyTree, Arc<MemoryBlockStore>) {
    let store = Arc::new(MemoryBlockStore::new());
    let config = ProllyConfig::default();
    let tree = ProllyTree::new(config);
    (tree, store)
}

fn bench_insert(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    
    let mut group = c.benchmark_group("prolly_insert");
    
    for size in [10, 100, 1000].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            b.iter(|| {
                rt.block_on(async {
                    let (mut tree, store) = create_tree();
                    for i in 0..size {
                        let key = format!("key-{:08}", i);
                        let value = format!("value-{}", i).into_bytes();
                        tree.insert(key.as_bytes(), &value, store.as_ref()).await.unwrap();
                    }
                    black_box(tree)
                })
            });
        });
    }
    
    group.finish();
}

fn bench_lookup(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    
    // Pre-populate tree
    let (mut tree, store) = create_tree();
    rt.block_on(async {
        for i in 0..1000 {
            let key = format!("key-{:08}", i);
            let value = format!("value-{}", i).into_bytes();
            tree.insert(key.as_bytes(), &value, store.as_ref()).await.unwrap();
        }
    });
    
    let mut group = c.benchmark_group("prolly_lookup");
    
    group.bench_function("existing_key", |b| {
        b.iter(|| {
            rt.block_on(async {
                let result = tree.get(b"key-00000500", store.as_ref()).await.unwrap();
                black_box(result)
            })
        });
    });
    
    group.bench_function("missing_key", |b| {
        b.iter(|| {
            rt.block_on(async {
                let result = tree.get(b"nonexistent", store.as_ref()).await.unwrap();
                black_box(result)
            })
        });
    });
    
    group.finish();
}

fn bench_range_scan(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    
    // Pre-populate tree
    let (mut tree, store) = create_tree();
    rt.block_on(async {
        for i in 0..1000 {
            let key = format!("key-{:08}", i);
            let value = format!("value-{}", i).into_bytes();
            tree.insert(key.as_bytes(), &value, store.as_ref()).await.unwrap();
        }
    });
    
    let mut group = c.benchmark_group("prolly_range");
    
    for range_size in [10, 100, 500].iter() {
        group.bench_with_input(
            BenchmarkId::new("scan", range_size),
            range_size,
            |b, &range_size| {
                let start = b"key-00000100";
                let end = format!("key-{:08}", 100 + range_size);
                b.iter(|| {
                    rt.block_on(async {
                        let result = tree.range(start, end.as_bytes(), store.as_ref()).await.unwrap();
                        black_box(result)
                    })
                });
            },
        );
    }
    
    group.finish();
}

fn bench_delete(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    
    c.bench_function("prolly_delete", |b| {
        b.iter(|| {
            rt.block_on(async {
                let (mut tree, store) = create_tree();
                
                // Insert
                for i in 0..100 {
                    let key = format!("key-{:08}", i);
                    let value = format!("value-{}", i).into_bytes();
                    tree.insert(key.as_bytes(), &value, store.as_ref()).await.unwrap();
                }
                
                // Delete
                for i in 0..100 {
                    let key = format!("key-{:08}", i);
                    tree.delete(key.as_bytes(), store.as_ref()).await.unwrap();
                }
                
                black_box(tree)
            })
        });
    });
}

criterion_group!(
    benches,
    bench_insert,
    bench_lookup,
    bench_range_scan,
    bench_delete,
);

criterion_main!(benches);
