# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
