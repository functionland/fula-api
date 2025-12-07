//! Benchmarks for BlockStore operations

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};
use fula_blockstore::{BlockStore, memory::MemoryBlockStore};
use fula_blockstore::chunking::Chunker;

fn generate_data(size: usize) -> Vec<u8> {
    (0..size).map(|i| (i % 256) as u8).collect()
}

fn bench_put_block(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    
    let mut group = c.benchmark_group("blockstore_put");
    
    for size in [1024, 64 * 1024, 256 * 1024, 1024 * 1024].iter() {
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            let data = generate_data(size);
            b.iter(|| {
                rt.block_on(async {
                    let store = MemoryBlockStore::new();
                    let cid = store.put_block(&data).await.unwrap();
                    black_box(cid)
                })
            });
        });
    }
    
    group.finish();
}

fn bench_get_block(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    
    let mut group = c.benchmark_group("blockstore_get");
    
    for size in [1024, 64 * 1024, 256 * 1024].iter() {
        let data = generate_data(*size);
        let store = MemoryBlockStore::new();
        let cid = rt.block_on(async { store.put_block(&data).await.unwrap() });
        
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| {
                rt.block_on(async {
                    let result = store.get_block(&cid).await.unwrap();
                    black_box(result)
                })
            });
        });
    }
    
    group.finish();
}

fn bench_chunking(c: &mut Criterion) {
    let mut group = c.benchmark_group("chunking");
    
    for size in [64 * 1024, 256 * 1024, 1024 * 1024, 4 * 1024 * 1024].iter() {
        let data = generate_data(*size);
        
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::new("fixed", size), size, |b, _| {
            b.iter(|| {
                let chunker = Chunker::fixed(256 * 1024);
                let chunks: Vec<_> = chunker.chunk(&data).collect();
                black_box(chunks)
            });
        });
    }
    
    group.finish();
}

fn bench_has_block(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    
    let store = MemoryBlockStore::new();
    let data = generate_data(64 * 1024);
    let cid = rt.block_on(async { store.put_block(&data).await.unwrap() });
    
    let mut group = c.benchmark_group("blockstore_has");
    
    group.bench_function("existing", |b| {
        b.iter(|| {
            rt.block_on(async {
                let result = store.has_block(&cid).await.unwrap();
                black_box(result)
            })
        });
    });
    
    // Create a fake CID for non-existing block
    let fake_data = b"nonexistent";
    let fake_cid = rt.block_on(async {
        let temp_store = MemoryBlockStore::new();
        temp_store.put_block(fake_data).await.unwrap()
    });
    
    group.bench_function("missing", |b| {
        b.iter(|| {
            rt.block_on(async {
                let result = store.has_block(&fake_cid).await.unwrap();
                black_box(result)
            })
        });
    });
    
    group.finish();
}

criterion_group!(
    benches,
    bench_put_block,
    bench_get_block,
    bench_chunking,
    bench_has_block,
);

criterion_main!(benches);
