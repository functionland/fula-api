//! Phase 1 — OFFLINE crypto round-trip (MUST pass, no network).
//!
//! Proves the `fula-mcp` crate can reuse `fula_crypto`'s chunked content
//! encryption primitive — the SAME primitive `fula_client` drives internally
//! when it chunks a large object — to encrypt+chunk and then decrypt+reassemble
//! a buffer byte-identically.
//!
//! Scope honesty: this exercises the *content-encryption + chunking* layer
//! (`ChunkedEncoder`/`ChunkedDecoder`), which is the part that determines the
//! on-the-wire chunk bytes + the `ChunkedFileMetadata` shape. It does NOT
//! exercise HPKE DEK-wrapping, storage-key obfuscation, or the forest index —
//! those are validated end-to-end by the gated `e2e_roundtrip` test against a
//! real gateway.

use fula_crypto::{ChunkedDecoder, ChunkedEncoder, DekKey, EncryptedChunk, should_use_chunked};
use rand::RngCore;

/// Encrypt+chunk `plaintext` with a fresh DEK, then decrypt+reassemble with the
/// same DEK, and return the recovered bytes alongside the number of chunks the
/// encoder produced.
///
/// This mirrors how a caller drives the primitive: feed all input to `update`,
/// then `finalize` to flush the trailing partial chunk + obtain the metadata.
/// The union of (chunks returned by `update`) + (the `Option` from `finalize`)
/// is exactly indices `0..num_chunks` with no gaps or duplicates — `update`
/// only *returns* a chunk when it emits it, and `finalize` emits only the
/// remaining buffer.
fn chunked_roundtrip(plaintext: &[u8]) -> (Vec<u8>, u32) {
    let dek = DekKey::generate();

    // --- Encode side --------------------------------------------------------
    let mut encoder = ChunkedEncoder::new(dek.clone());
    // Feed the whole buffer at once; collect every full chunk it emits.
    let mut chunks: Vec<EncryptedChunk> = encoder
        .update(plaintext)
        .expect("encoder.update must succeed on valid input");
    // Flush the trailing partial chunk (if any) and take the metadata.
    let (last_chunk, metadata, _outboard) =
        encoder.finalize().expect("encoder.finalize must succeed");
    if let Some(c) = last_chunk {
        chunks.push(c);
    }

    // Sanity: the metadata's declared chunk count matches what we collected.
    assert_eq!(
        metadata.num_chunks as usize,
        chunks.len(),
        "collected chunk count must equal metadata.num_chunks"
    );
    assert_eq!(
        metadata.total_size,
        plaintext.len() as u64,
        "metadata.total_size must equal the original length"
    );

    // --- Decode side --------------------------------------------------------
    // Feed every chunk by its own index; the decoder looks up the matching
    // nonce from the metadata, so index alignment is what makes this work.
    let mut decoder = ChunkedDecoder::new(dek, metadata.clone());
    for chunk in &chunks {
        decoder
            .decrypt_chunk(chunk.index, &chunk.ciphertext)
            .expect("decrypt_chunk must succeed for a correctly-keyed chunk");
    }
    let recovered = decoder
        .finalize()
        .expect("decoder.finalize must succeed once all chunks are present");

    (recovered.to_vec(), metadata.num_chunks)
}

/// ~1 MB random payload: exceeds the 768 KB chunked threshold, so it splits
/// into multiple 256 KB chunks (4 full + a partial). This is the dominant
/// FxFiles content shape (photos / PDFs / video).
#[test]
fn roundtrip_1mb_multichunk() {
    let mut data = vec![0u8; 1024 * 1024];
    rand::thread_rng().fill_bytes(&mut data);

    assert!(
        should_use_chunked(data.len()),
        "1MB must be above the chunked threshold"
    );

    let (recovered, num_chunks) = chunked_roundtrip(&data);

    assert_eq!(recovered, data, "1MB round-trip must be byte-identical");
    // 1 MiB / 256 KiB = exactly 4 chunks (the last chunk fills exactly).
    assert!(
        num_chunks >= 4,
        "expected multiple chunks for a 1MB payload, got {num_chunks}"
    );
}

/// Small single-block payload (~100 KB): below the 256 KB chunk size AND below
/// the 768 KB threshold, so the encoder emits exactly one chunk (flushed by
/// `finalize`). Exercises the single-block path through the same primitive.
#[test]
fn roundtrip_small_single_block() {
    let mut data = vec![0u8; 100 * 1024];
    rand::thread_rng().fill_bytes(&mut data);

    assert!(
        !should_use_chunked(data.len()),
        "100KB must be below the chunked threshold"
    );

    let (recovered, num_chunks) = chunked_roundtrip(&data);

    assert_eq!(recovered, data, "small round-trip must be byte-identical");
    assert_eq!(num_chunks, 1, "a sub-chunk-size payload must yield one chunk");
}

/// Edge case: empty input. Guards the boundary where `update` emits nothing and
/// `finalize` has an empty buffer (zero chunks). Reassembly must give back the
/// empty buffer, not error.
#[test]
fn roundtrip_empty_input() {
    let data: Vec<u8> = Vec::new();
    let (recovered, num_chunks) = chunked_roundtrip(&data);
    assert_eq!(recovered, data, "empty round-trip must yield empty output");
    assert_eq!(num_chunks, 0, "empty input must yield zero chunks");
}
