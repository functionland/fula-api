# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
