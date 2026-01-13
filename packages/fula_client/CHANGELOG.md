# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.17] - 2026-01-13

### Fixed

- **CRITICAL: Share tokens missing encryption nonce - decryption produces garbage**
  - Share tokens only contained wrapped DEK but not the nonce needed for decryption
  - Web UI proxy doesn't forward S3 metadata headers (`x-fula-encryption`)
  - Without the nonce, decryption "succeeds" but produces garbage data
  - **Fix**: Share tokens now include `nonce` (for single-block files) and `chunked_metadata` (for chunked files)
  - Recipients can now decrypt using just the share token without needing S3 metadata headers

### Changed

- `ShareToken` struct now includes optional `nonce` and `chunked_metadata` fields
- `ShareBuilder` has new `.nonce()` and `.chunked_metadata()` builder methods
- `AcceptedShare` now carries nonce and chunked metadata through to decryption
- `get_object_with_share` uses nonce from share token if available, falls back to S3 headers for backwards compatibility
- Share token version bumped to 3

### Migration Guide for FxFiles

Share tokens created with v0.2.17+ will automatically include the nonce.
No code changes needed - just rebuild FxFiles with the new fula_client SDK.

Old share tokens (without nonce) will continue to work if the proxy forwards S3 headers correctly.

## [0.2.16] - 2026-01-13

### Fixed

- **CRITICAL: Share decryption fails for chunked files (files > 768KB)**
  - `get_object_with_share` was using single-block decryption for all files
  - Chunked files store each chunk with its own nonce in `{storage_key}.chunks/{index}`
  - Share flow was ignoring chunked file metadata and trying to decrypt assembled bytes as single block
  - **Result**: Large shared files (images, videos) returned garbage data instead of correct content
  - **Fix**: `get_object_with_share` now checks `x-fula-chunked` metadata and uses `ChunkedDecoder` with per-chunk nonces when needed

### Technical Details

- Added `get_object_chunked_with_share()` internal method for chunked file handling in share flow
- Downloads each chunk from `{storage_key}.chunks/{index}`, decrypts with chunk-specific nonce
- Concatenates decrypted chunks and returns complete plaintext
- Works identically to normal `get_object_decrypted_by_storage_key()` but uses share's DEK

## [0.2.15] - 2026-01-13

### Fixed

- **CRITICAL: flutter_rust_bridge content hash mismatch in CI**
  - `build-android` and `build-ios` jobs were building native libraries from committed `frb_generated.rs`
  - `generate-bindings` job was creating fresh `frb_generated.dart` with different content hash
  - This caused "Content hash on Dart side is different from Rust side" error
  - **Fix**: Both Android and iOS build jobs now run `flutter_rust_bridge_codegen generate` before building

- **CRITICAL: X25519 public key derivation mismatch between Dart and Rust**
  - When sharing files via public links, FxFiles was using Dart's `cryptography` package to derive X25519 public keys
  - The Web UI uses Rust (via WASM) to derive public keys from the same private key bytes
  - Different implementations may produce different public keys from the same private key seed
  - This caused HPKE key wrapping to fail: the share token encrypted DEK for Dart's public key, but the web UI derived a different public key from the private key in the URL
  - **Fix**: Added `derivePublicKeyFromSecret()` function to both Flutter and JS/WASM bindings
  - **Required FxFiles change**: Use `derivePublicKeyFromSecret(secretKeyBytes)` instead of Dart's native X25519 derivation

### Added

- `derivePublicKeyFromSecret(Vec<u8>)` - Flutter API function to derive X25519 public key from private key bytes using Rust's x25519_dalek
- `derivePublicKeyFromSecret(Uint8Array)` - JS/WASM function for the same purpose
- Comprehensive tests verifying end-to-end share flow compatibility

### Migration Guide for FxFiles

Replace this Dart code:
```dart
final x25519 = X25519();
final keyPair = await x25519.newKeyPair();
final publicKeyBytes = Uint8List.fromList((await keyPair.extractPublicKey()).bytes);
final privateKeyBytes = await keyPair.extractPrivateKeyBytes();
```

With this:
```dart
import 'dart:math';

// Generate random 32 bytes
final privateKeyBytes = Uint8List(32);
Random.secure().nextBytes(privateKeyBytes);

// Derive public key using Rust (ensures cross-platform compatibility)
final publicKeyBytes = await derivePublicKeyFromSecret(privateKeyBytes);
```

## [0.2.12] - 2026-01-13

### Fixed

- **CRITICAL: Share token DEK mismatch bug**: Fixed share tokens using derived DEK instead of actual uploaded DEK
  - In FlatNamespace mode, files are encrypted with random DEKs stored in metadata
  - Share token creation was incorrectly deriving DEK from path instead of fetching actual DEK from metadata
  - This caused all shared files to fail decryption on recipient side (garbage output)
  - Fix: `create_share_token` and `create_share_token_with_mode` now fetch wrapped DEK from object metadata

### Changed

- **API Breaking Change**: `createShareToken` and `createShareTokenWithMode` now require `bucket` parameter
  - Flutter: `createShareToken(bucket: 'mybucket', storageKey: '...', ...)`
  - This is needed to fetch object metadata containing the actual DEK

### Added

- Comprehensive sharing tests verifying:
  - Share token uses correct (uploaded) DEK
  - Different files have different random DEKs (isolation)
  - Sharing one file does not expose other files
  - Wrong recipient cannot decrypt share tokens
  - Path scope enforcement
  - Expiration handling

## [0.2.11] - 2026-01-13

### Fixed

- **WASM time compatibility bug**: Fixed `time not implemented on this platform` panic when validating share tokens in browser
- Added centralized `time::now_timestamp()` function using `js_sys::Date::now()` for WASM and `std::time::SystemTime` for native

### Changed

- Updated `fula-crypto` to use WASM-compatible time functions in sharing, inbox, private_metadata, and subtree_keys modules

## [0.2.10] - 2026-01-12

### Added

- New `@functionland/fula-client` npm package with high-level JavaScript APIs
- WASM bindings using wasm-bindgen (replaces low-level flutter_rust_bridge exports)
- Cross-platform key derivation compatibility between Flutter and JavaScript
- Functions: `createEncryptedClient`, `getDecrypted`, `putEncrypted`, `deriveKey`, `acceptShare`, `getWithShare`

### Changed

- GitHub Actions workflows updated to build and publish fula-js npm package

## [0.2.9] - 2026-01-11

### Changed

- Bumped version to 0.2.9

## [0.2.8] - 2026-01-11

### Changed

- Minimum Flutter version raised to 3.38.0 (Dart 3.10.x)
- Minimum Dart SDK raised to 3.8.0 (required for freezed ^3.2.0)
- CI/CD workflows updated to use Flutter 3.38.0 stable
- Web plugin updated to use `package:web` and `dart:js_interop` (replacing deprecated `dart:html` and `dart:js`)

## [0.2.7] - 2026-01-11

### Changed

- Minimum Flutter version raised to 3.27.0 (Dart 3.6.0 required for freezed 3.x)
- Minimum Dart SDK raised to 3.6.0
- CI/CD workflows updated to use Flutter 3.27.0

## [0.2.6] - 2026-01-11

### Changed

- Updated `freezed_annotation` to ^3.1.0 for compatibility with other packages
- Updated `freezed` to ^3.2.0
- Updated `flutter_lints` to ^5.0.0
- Updated `ffigen` to ^14.0.0

## [0.2.5] - 2026-01-11

### Changed

- Release workflow now triggers on tag push (v*) for pub.dev OIDC compatibility
- Simplified release process: just push a tag to publish everywhere

### Fixed

- pub.dev OIDC authentication now works (requires tag context, not branch)

## [0.2.3] - 2026-01-11

### Changed

- iOS binaries now downloaded from GitHub Releases during pod install
- This reduces pub.dev package size from 160MB to ~12MB

### Fixed

- Strip debug symbols from native libraries to reduce package size
- Fixed Android NDK compiler configuration (CC/AR environment variables)
- Disabled wasm-opt to fix bulk memory operations error

## [0.2.1] - 2026-01-11

### Added

- GitHub Actions CI workflow for automated testing
- GitHub Actions release workflow for publishing to pub.dev and npm
- iOS XCFramework support for device and simulator builds

### Changed

- Switched from parking_lot to tokio::sync for async-safe locks
- Made async runtime conditional: tokio on native, async-lock on WASM
- Updated iOS podspec to use XCFramework instead of static library
- Improved flutter_rust_bridge compatibility with anyhow::Result

### Fixed

- WASM build now compiles correctly without tokio OS-specific dependencies
- Android namespace updated from fula_flutter to fula_client
- Fixed flutter_rust_bridge codegen configuration

## [0.2.0] - 2026-01-10

### Added

- **FlatNamespace obfuscation mode** - Complete structure hiding for maximum privacy
- **PreserveStructure obfuscation mode** - Keep folder paths, hash filenames only
- All 4 obfuscation modes now available: `flatNamespace`, `deterministic`, `random`, `preserveStructure`

### Changed

- Minimum SDK version raised to 3.3.0 (required for inline-class feature)
- Minimum Flutter version raised to 3.19.0
- FlatNamespace is now the recommended default for new projects

### Fixed

- Documentation updated to match actual API signatures

## [0.1.0] - 2024-01-09

### Added

- Initial release of fula_client Flutter SDK
- Client-side encryption with AES-256-GCM
- Metadata privacy with configurable obfuscation modes
- Secure file sharing with capability-based tokens
- Key rotation support
- Flat namespace API for file system-like access
- Android support via FFI
- Web support via WASM
- Multipart upload support for large files

### Security

- HPKE (Hybrid Public Key Encryption) for key exchange
- BLAKE3 for fast, secure hashing
- X25519 for elliptic curve Diffie-Hellman

## [Unreleased]

### Planned

- iOS support
- Desktop support (Windows, macOS, Linux)
- Offline-first sync capabilities
- Background upload/download
