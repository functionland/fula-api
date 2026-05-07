# WASM Compatibility

This document describes the modifications made to `fula-crypto` and `fula-client` crates to enable WebAssembly (WASM) compilation for Flutter Web and other browser-based applications.

## Overview

The Fula SDK now supports compilation to `wasm32-unknown-unknown` target, enabling:
- Flutter Web applications via flutter_rust_bridge
- Browser-based JavaScript/TypeScript applications via wasm-bindgen
- Any WASM runtime (Node.js, Deno, edge workers)

## Key Changes

### 1. Post-Quantum Cryptography Library Migration

**Before:** `pqcrypto-mlkem` (C bindings via pqcrypto)
**After:** `libcrux-ml-kem` (Pure Rust implementation)

The `pqcrypto-mlkem` crate depends on C code that cannot compile to WASM. We migrated to `libcrux-ml-kem`, a formally verified pure-Rust implementation of ML-KEM (Kyber) that compiles cleanly to WASM.

```toml
# fula-crypto/Cargo.toml
[dependencies]
# Post-quantum KEM - pure Rust, WASM compatible
libcrux-ml-kem = { version = "0.0.2-alpha.3", default-features = false }
```

**Security Note:** libcrux-ml-kem is developed by Cryspen and has been formally verified using the F* proof assistant. It provides the same ML-KEM-768 security level as the previous library.

### 2. Random Number Generation

**Before:** `OsRng` from the `rand` crate
**After:** `getrandom` with WASM support

`OsRng` relies on OS-specific system calls that don't exist in WASM. We replaced it with `getrandom`, which:
- Uses `crypto.getRandomValues()` in browsers
- Uses OS entropy on native platforms
- Provides cryptographically secure randomness on all platforms

```toml
# fula-crypto/Cargo.toml
[dependencies]
getrandom = "0.2"

[target.'cfg(target_arch = "wasm32")'.dependencies]
getrandom = { version = "0.2", features = ["js"] }
```

**Usage in code:**
```rust
// Before
use rand::rngs::OsRng;
let key = SomeKey::generate(&mut OsRng);

// After
fn generate_random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes).expect("getrandom failed");
    bytes
}
```

### 3. Async Runtime (tokio)

**Before:** tokio always required
**After:** tokio optional, only for native builds

WASM doesn't support tokio's multi-threaded runtime. We made tokio optional:

```toml
# fula-client/Cargo.toml
[features]
default = ["tokio-runtime"]
tokio-runtime = ["tokio"]

[dependencies]
tokio = { version = "1", features = ["rt-multi-thread", "sync"], optional = true }

[target.'cfg(target_arch = "wasm32")'.dependencies]
wasm-bindgen-futures = "0.4"
```

For WASM, async operations use `wasm-bindgen-futures` which integrates with the browser's JavaScript event loop.

### 4. Conditional Compilation

The crates use `cfg` attributes for platform-specific code:

```rust
// Native-only code
#[cfg(not(target_arch = "wasm32"))]
fn native_only_function() {
    // Uses tokio, file I/O, etc.
}

// WASM-only code
#[cfg(target_arch = "wasm32")]
fn wasm_only_function() {
    // Uses wasm-bindgen, web APIs, etc.
}
```

### 5. Feature Flags

Both crates expose feature flags for WASM builds:

```toml
# fula-crypto/Cargo.toml
[features]
default = []
wasm = []

# fula-client/Cargo.toml
[features]
default = ["tokio-runtime"]
tokio-runtime = ["tokio"]
```

**WASM builds use:**
```bash
cargo build --target wasm32-unknown-unknown \
  -p fula-crypto --no-default-features --features wasm \
  -p fula-client --no-default-features
```

## Cargo.toml Configuration

### fula-crypto

```toml
[package]
name = "fula-crypto"

[features]
default = []
wasm = []

[dependencies]
# Core crypto - all WASM compatible
chacha20poly1305 = "0.10"
hkdf = "0.12"
sha2 = "0.10"
x25519-dalek = { version = "2", features = ["static_secrets"] }
ed25519-dalek = { version = "2", features = ["rand_core"] }

# Post-quantum - pure Rust
libcrux-ml-kem = { version = "0.0.2-alpha.3", default-features = false }

# Random - with WASM support
getrandom = "0.2"

[target.'cfg(target_arch = "wasm32")'.dependencies]
getrandom = { version = "0.2", features = ["js"] }
```

### fula-client

```toml
[package]
name = "fula-client"

[features]
default = ["tokio-runtime"]
tokio-runtime = ["tokio"]

[dependencies]
fula-crypto = { path = "../fula-crypto" }

# HTTP client - WASM compatible
reqwest = { version = "0.12", default-features = false, features = ["json"] }

[target.'cfg(not(target_arch = "wasm32"))'.dependencies]
tokio = { version = "1", features = ["rt-multi-thread", "sync"], optional = true }
reqwest = { version = "0.12", features = ["native-tls"] }

[target.'cfg(target_arch = "wasm32")'.dependencies]
reqwest = { version = "0.12", features = ["wasm-bindgen"] }
wasm-bindgen-futures = "0.4"
```

## Building for WASM

### Prerequisites

```bash
# Install WASM target
rustup target add wasm32-unknown-unknown

# Optional: Install wasm-pack for npm packaging
cargo install wasm-pack
```

### Build Commands

```bash
# Build fula-crypto for WASM
cargo build -p fula-crypto --target wasm32-unknown-unknown \
  --no-default-features --features wasm

# Build fula-client for WASM
cargo build -p fula-client --target wasm32-unknown-unknown \
  --no-default-features

# Build fula-flutter for WASM (includes both)
cargo build -p fula-flutter --target wasm32-unknown-unknown
```

### Verification

```bash
# Verify WASM compilation succeeds
cargo check -p fula-crypto --target wasm32-unknown-unknown \
  --no-default-features --features wasm

cargo check -p fula-client --target wasm32-unknown-unknown \
  --no-default-features
```

## Testing

### Native Tests
```bash
cargo test -p fula-crypto
cargo test -p fula-client
cargo test -p fula-flutter
```

### WASM Tests
WASM-specific tests use `wasm-bindgen-test`:

```bash
# Install wasm-pack
cargo install wasm-pack

# Run WASM tests in headless browser
cd crates/fula-flutter
wasm-pack test --headless --chrome

# Or run in Node.js
wasm-pack test --node
```

## API Differences

The API surface is identical between native and WASM builds. However:

1. **File I/O:** Not available in WASM. Use `Uint8Array`/`Vec<u8>` for data.
2. **Multithreading:** WASM is single-threaded. Async operations use the event loop.
3. **Timing:** High-resolution timers may be limited in WASM for security reasons.

## Master-Independent Reads (v0.4.0+) — what works on wasm

v0.4.0 introduced the offline-read story (Phase 2.1 / 2.2 / 2.3 / 2.4 / 3.3 / 19). The full surface is exposed in **both** `fula-flutter` and `fula-js` bindings for API symmetry, but several layers are **inert at runtime on wasm32** because their dependencies (redb, `parking_lot`-based gateway pool, reqwest-with-tls, `std::time::SystemTime`) don't compile cleanly in browsers.

> **v0.4.1 update.** v0.4.1 closes correctness gaps in the same offline-reads stack (encrypted offline DOWNLOAD for single-object + chunked files, widened connection-error classifier, v7 sharded-HAMT manifest pages and dir-index now route through the offline-fallback wrapper). All v0.4.1 changes are **SDK-side only** — no new dependencies, no new wasm-specific gates. The wasm-functional vs. wasm-inert split below is unchanged from v0.4.0; the v0.4.1 fixes apply on whichever platforms the underlying surface was already functional. In practice that means: native targets pick up the encrypted-offline-download fix; wasm targets continue to pass through to master with the same behavior they had in v0.4.0 (block_cache + gateway_fallback are still inert on wasm).

### Functional on wasm32

| Surface | Notes |
|---|---|
| **Health gate (Phase 2.1)** | `health_gate_enabled` + `health_gate_ttl` work. Internal `now_ms()` routes through `fula_crypto::time::now_millis()` which uses `js_sys::Date::now()` on wasm32 (the `clippy::disallowed_methods` config in `.github/clippy-wasm/clippy.toml` bans `std::time::SystemTime::now` to catch regressions at lint time). Two consecutive request failures still trip the gate; reads short-circuit with `MasterUnreachable` instead of paying the timeout tax. |
| **Transparency polling (Phase 19)** | `pollMasterHealthEvents()` and `getLastMasterHealthEvent()` work. The dispatcher captures every transition fired by the in-Rust health gate. On wasm32 the gate fires for the same conditions as native (failed master requests), so apps see the same event stream. `MasterHealthEvent::SeverelyDegraded` is only emitted by the cold-start resolver, which is native-only — on wasm you'll see `Online` / `OfflineFallbackActive` only. |
| **`derive_user_key_from_email`** | Pure `sha256` + `blake3` + `hex` — no native-only deps. Apps can compute the userKey on web for cross-platform identity flows (e.g., compute on a desktop Tauri app, replicate on a web companion using the same email + algorithm). |
| **`get_object_with_offline_fallback`** | Compiles and runs on wasm32. With block_cache + gateway_fallback inert (see below), the wasm path always returns `source: Master, freshness: Live` — i.e., it's effectively `get_object_with_metadata` wrapped in the `OfflineGetResult` shape. Apps can consume the result identically across native + web. |

### Inert on wasm32 (fields accepted, runtime no-op)

| Surface | Why inert | Effect |
|---|---|---|
| **Block cache (Phase 2.2)** | `redb` is a native-only embedded KV (mmap + file locks). The whole `crates/fula-client/src/block_cache.rs` file is gated `#![cfg(not(target_arch = "wasm32"))]`. | Setting `block_cache_enabled = true` on wasm is silently ignored. The SDK never persists block bytes and never observes the `(bucket, key) → cid` map needed by the gateway-race fallback. |
| **Gateway race (Phase 2.3 / 2.4)** | Depends on the block cache (for the `(bucket, key) → cid` lookup table) AND on `parking_lot`'s native-only mutex behavior in the gateway-state ring. Whole `gateway_fetch.rs` is gated. | Setting `gateway_fallback_enabled = true` on wasm is silently ignored. Master-down reads on web surface as `MasterUnreachable` errors instead of falling through to a public gateway. |
| **Cold-start hybrid resolver (Phase 3.3)** | `registry_resolver.rs` is gated `#![cfg(not(target_arch = "wasm32"))]` because it depends on `reqwest` with native-tls, `parking_lot`, and `serde_ipld_dagcbor` paths that the wasm build chain doesn't currently support. | Setting `users_index_*` fields on wasm is silently ignored. Cold-start GETs (master-down + cache miss) surface `UsersIndexResolutionFailed`. |

### Why expose inert flags at all

The fields are accepted on every target so a TypeScript app sharing a config struct between mobile (where everything works) and web (where some flags are silently inert) can construct one config object without per-platform branches. On web, the offline path simply degrades to "no offline path" — typed errors come back instead of fallback paths firing. Apps that want web-side offline reads today should rely on browser caching (HTTP-level service workers) until the wasm-side gateway race lands in a future release.

### Adding new wasm-incompatible API to fula-client

When adding a new SDK surface that depends on `std::time::SystemTime::now`, `std::time::Instant::now`, file I/O, or any other native-only call:

1. **Either** gate the function with `#[cfg(not(target_arch = "wasm32"))]` so it's excluded from wasm builds entirely.
2. **Or** route the call through `fula_crypto::time::now_timestamp()` / `now_millis()` (or `web_time::Instant::now()` for monotonic timing).

The CI's `test-wasm` job loads `.github/clippy-wasm/clippy.toml` via `CLIPPY_CONF_DIR` and runs `cargo clippy --target wasm32-unknown-unknown -D clippy::disallowed-methods`. This catches `SystemTime::now` / `Instant::now` regressions before merge. Native clippy ignores the config.

## Performance Considerations

1. **Crypto operations:** libcrux-ml-kem is optimized but may be ~10-20% slower than native C in WASM.
2. **Large files:** Consider chunked uploads to avoid memory pressure in WASM.
3. **Startup time:** WASM modules have initialization overhead; consider lazy loading.

## Security Considerations

1. **Memory safety:** Rust's memory safety guarantees apply in WASM.
2. **Side channels:** Constant-time operations are preserved in WASM.
3. **Randomness:** `crypto.getRandomValues()` provides cryptographic randomness in browsers.
4. **Key storage:** In browsers, use IndexedDB with encryption for key storage (not localStorage).

## Browser Compatibility

Minimum browser versions for WASM:
- Chrome 57+
- Firefox 52+
- Safari 11+
- Edge 16+

For older browsers, consider polyfills or fallback to server-side encryption.

## Troubleshooting

### "getrandom not supported"
Ensure the `js` feature is enabled for getrandom in WASM builds:
```toml
[target.'cfg(target_arch = "wasm32")'.dependencies]
getrandom = { version = "0.2", features = ["js"] }
```

### "tokio runtime not found"
Building for WASM should not include tokio. Check your feature flags:
```bash
cargo build --target wasm32-unknown-unknown --no-default-features
```

### "undefined import: __wbindgen_*"
Ensure wasm-bindgen is properly configured and the JavaScript glue code is loaded before the WASM module.

### Large WASM bundle size
Use `wasm-opt` to optimize:
```bash
wasm-opt -O3 -o optimized.wasm input.wasm
```

Or enable LTO in release builds:
```toml
[profile.release]
lto = true
```
