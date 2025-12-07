//! Benchmarks for fula-crypto

use criterion::{criterion_group, criterion_main, Criterion, Throughput, BenchmarkId};
use fula_crypto::{
    hashing::{hash, IncrementalHasher, md5_hash},
    keys::{DekKey, KekKeyPair},
    symmetric::{encrypt, decrypt, Aead, AeadCipher, Nonce},
    hpke::{Encryptor, Decryptor},
    streaming::{encode as bao_encode, verify as bao_verify},
};

fn bench_hashing(c: &mut Criterion) {
    let mut group = c.benchmark_group("hashing");
    
    for size in [1024, 64 * 1024, 1024 * 1024].iter() {
        let data = vec![0u8; *size];
        group.throughput(Throughput::Bytes(*size as u64));
        
        group.bench_with_input(
            BenchmarkId::new("blake3", size),
            &data,
            |b, data| b.iter(|| hash(data)),
        );
        
        group.bench_with_input(
            BenchmarkId::new("md5", size),
            &data,
            |b, data| b.iter(|| md5_hash(data)),
        );
    }
    
    group.finish();
}

fn bench_symmetric(c: &mut Criterion) {
    let mut group = c.benchmark_group("symmetric");
    let key = DekKey::generate();
    
    for size in [1024, 64 * 1024, 1024 * 1024].iter() {
        let data = vec![0u8; *size];
        group.throughput(Throughput::Bytes(*size as u64));
        
        group.bench_with_input(
            BenchmarkId::new("aes-256-gcm-encrypt", size),
            &data,
            |b, data| b.iter(|| encrypt(&key, data).unwrap()),
        );
        
        let (nonce, ciphertext) = encrypt(&key, &data).unwrap();
        group.bench_with_input(
            BenchmarkId::new("aes-256-gcm-decrypt", size),
            &(&nonce, &ciphertext),
            |b, (nonce, ciphertext)| b.iter(|| decrypt(&key, nonce, ciphertext).unwrap()),
        );
        
        let chacha_aead = Aead::new(&key, AeadCipher::ChaCha20Poly1305);
        let nonce = Nonce::generate();
        group.bench_with_input(
            BenchmarkId::new("chacha20-poly1305-encrypt", size),
            &data,
            |b, data| b.iter(|| chacha_aead.encrypt(&nonce, data).unwrap()),
        );
    }
    
    group.finish();
}

fn bench_hpke(c: &mut Criterion) {
    let mut group = c.benchmark_group("hpke");
    let keypair = KekKeyPair::generate();
    let encryptor = Encryptor::new(keypair.public_key());
    let decryptor = Decryptor::new(&keypair);
    
    for size in [32, 1024, 64 * 1024].iter() {
        let data = vec![0u8; *size];
        group.throughput(Throughput::Bytes(*size as u64));
        
        group.bench_with_input(
            BenchmarkId::new("encrypt", size),
            &data,
            |b, data| b.iter(|| encryptor.encrypt(data).unwrap()),
        );
        
        let encrypted = encryptor.encrypt(&data).unwrap();
        group.bench_with_input(
            BenchmarkId::new("decrypt", size),
            &encrypted,
            |b, encrypted| b.iter(|| decryptor.decrypt(encrypted).unwrap()),
        );
    }
    
    group.finish();
}

fn bench_bao(c: &mut Criterion) {
    let mut group = c.benchmark_group("bao");
    
    for size in [64 * 1024, 1024 * 1024, 10 * 1024 * 1024].iter() {
        let data = vec![0u8; *size];
        group.throughput(Throughput::Bytes(*size as u64));
        
        group.bench_with_input(
            BenchmarkId::new("encode", size),
            &data,
            |b, data| b.iter(|| bao_encode(data)),
        );
        
        let outboard = bao_encode(&data);
        group.bench_with_input(
            BenchmarkId::new("verify", size),
            &(&data, &outboard),
            |b, (data, outboard)| b.iter(|| bao_verify(data, outboard).unwrap()),
        );
    }
    
    group.finish();
}

criterion_group!(benches, bench_hashing, bench_symmetric, bench_hpke, bench_bao);
criterion_main!(benches);
