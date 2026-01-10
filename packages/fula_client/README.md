# fula_client

A Flutter SDK for [Fula](https://fx.land) decentralized storage with client-side encryption, metadata privacy, and secure file sharing.

## Features

- **Client-side encryption** - AES-256-GCM encryption, data never leaves your device unencrypted
- **Metadata privacy** - File names and sizes are obfuscated from the server
- **Secure sharing** - Share files with capability-based access tokens
- **Key rotation** - Rotate encryption keys without re-uploading data
- **Cross-platform** - Works on Android (FFI) and Web (WASM)

## Installation

```yaml
dependencies:
  fula_client: ^0.1.0
```

Or run:

```bash
flutter pub add fula_client
```

## Quick Start

```dart
import 'package:fula_client/fula_client.dart';
import 'dart:convert';
import 'dart:typed_data';

Future<void> main() async {
  // Create encrypted client
  final config = FulaConfig(
    endpoint: 'http://localhost:9000',
    accessToken: 'your-jwt-token',
  );

  // FlatNamespace is RECOMMENDED for maximum privacy
  final encConfig = EncryptionConfig(
    enableMetadataPrivacy: true,
    obfuscationMode: ObfuscationMode.flatNamespace,
  );

  final client = await createEncryptedClient(config, encConfig);

  // Upload encrypted file
  final data = utf8.encode('Secret document content');
  await putFlat(
    client,
    'my-bucket',
    '/documents/secret.txt',
    Uint8List.fromList(data),
    'text/plain',
  );

  // Download and decrypt
  final decrypted = await getFlat(client, 'my-bucket', '/documents/secret.txt');
  print('Content: ${utf8.decode(decrypted)}');

  // List files (shows original names, not obfuscated)
  final files = await listDecrypted(client, 'my-bucket', ListOptions());
  for (final file in files) {
    print('${file.originalKey} - ${file.size} bytes');
  }
}
```

## Platform Setup

### Android

Add to `android/app/build.gradle`:

```gradle
android {
    defaultConfig {
        ndk {
            abiFilters 'arm64-v8a', 'armeabi-v7a', 'x86_64'
        }
    }
}
```

### Web

Ensure your web server serves WASM files with the correct MIME type:
```
application/wasm
```

## API Overview

### Client Creation

- `createClient(config)` - Create basic client
- `createEncryptedClient(config, encConfig)` - Create client with encryption

### Bucket Operations

- `createBucket(client, name)` - Create a bucket
- `listBuckets(client)` - List all buckets
- `deleteBucket(client, name)` - Delete a bucket

### Object Operations

- `putObject(client, bucket, key, data)` - Upload object
- `getObject(client, bucket, key)` - Download object
- `deleteObject(client, bucket, key)` - Delete object
- `listObjects(client, bucket, options)` - List objects

### Encrypted Operations

- `putEncrypted(client, bucket, key, data)` - Upload with encryption
- `getDecrypted(client, bucket, key)` - Download and decrypt
- `listDecrypted(client, bucket, options)` - List with decrypted metadata

### Flat Namespace (File System API)

- `putFlat(client, bucket, path, data, contentType)` - Upload by path
- `getFlat(client, bucket, path)` - Download by path
- `deleteFlat(client, bucket, path)` - Delete by path
- `listDirectory(client, bucket, path)` - List directory contents

### Secure Sharing

- `createShareToken(client, key, mode, expiry)` - Create share token
- `acceptShare(tokenJson)` - Accept a share
- `getWithShare(client, bucket, key, share)` - Access shared file

### Key Management

- `exportSecretKey(client)` - Export encryption key for backup
- `createRotationManager(client)` - Create key rotation manager
- `rotateBucket(client, bucket, manager)` - Rotate all keys in bucket

## Obfuscation Modes

The SDK supports 4 obfuscation modes for metadata privacy:

| Mode | Server Sees | Privacy Level | Use Case |
|------|-------------|---------------|----------|
| `flatNamespace` | `QmX7a8f3e2d1c9b4...` | **Highest** | Default, recommended |
| `deterministic` | `e/a7c3f9b2e8d14a6f` | Medium | Server deduplication |
| `random` | `e/random-uuid-here` | High | Max privacy, no dedup |
| `preserveStructure` | `/photos/vacation/e_a7c3` | Low | Folder organization |

```dart
// FlatNamespace (RECOMMENDED) - complete structure hiding
final encConfig = EncryptionConfig(
  obfuscationMode: ObfuscationMode.flatNamespace,
);

// Deterministic - same file = same hash (allows deduplication)
final encConfig = EncryptionConfig(
  obfuscationMode: ObfuscationMode.deterministic,
);

// Random - new UUID for each upload (maximum privacy)
final encConfig = EncryptionConfig(
  obfuscationMode: ObfuscationMode.random,
);

// PreserveStructure - keep folder paths, hash filenames
final encConfig = EncryptionConfig(
  obfuscationMode: ObfuscationMode.preserveStructure,
);
```

## Documentation

- [Full API Documentation](https://functionland.github.io/fula-api/)
- [Flutter Integration Guide](https://github.com/functionland/fula-api/blob/main/docs/flutter-integration.md)
- [Security Model](https://github.com/functionland/fula-api/blob/main/docs/THREAT_MODEL.md)

## JavaScript / Web

For JavaScript/TypeScript web applications, use the npm package:

```bash
npm install @functionland/fula-client
```

## License

MIT License - see [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome! Please see our [Contributing Guide](https://github.com/functionland/fula-api/blob/main/CONTRIBUTING.md).

## Support

- [GitHub Issues](https://github.com/functionland/fula-api/issues)
- [Documentation](https://functionland.github.io/fula-api/)
