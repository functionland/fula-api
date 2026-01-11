/// Fula Client SDK
///
/// A Flutter/Dart SDK for Fula decentralized storage with client-side encryption,
/// metadata privacy, and secure file sharing.
///
/// ## Quick Start
///
/// ```dart
/// import 'package:fula_client/fula_client.dart';
///
/// // Initialize the FRB runtime
/// await RustLib.init();
///
/// // Create encrypted client
/// final config = FulaConfig(
///   endpoint: 'http://localhost:9000',
///   accessToken: 'your-token',
///   timeoutSeconds: 30,
///   maxRetries: 3,
/// );
///
/// final encConfig = EncryptionConfig(
///   enableMetadataPrivacy: true,
///   obfuscationMode: ObfuscationMode.flatNamespace, // Recommended
/// );
///
/// final client = await createEncryptedClient(config: config, encryption: encConfig);
///
/// // Upload encrypted file
/// await putFlat(client: client, bucket: 'my-bucket', path: '/photos/vacation.jpg',
///               data: bytes, contentType: 'image/jpeg');
///
/// // Download and decrypt
/// final data = await getFlat(client: client, bucket: 'my-bucket', path: '/photos/vacation.jpg');
/// ```
///
/// ## Obfuscation Modes
///
/// - **flatNamespace** (Recommended): Complete structure hiding. Server sees random hashes.
/// - **deterministic**: Same input = same hash. Allows server deduplication.
/// - **random**: Random UUID per upload. Maximum privacy, no dedup.
/// - **preserveStructure**: Keep folder paths, hash only filenames.
library fula_client;

// Re-export generated bindings
export 'src/frb_generated.dart' show RustLib;
export 'src/api/types.dart';
export 'src/api/client.dart';
export 'src/api/encrypted.dart';
export 'src/api/forest.dart';
export 'src/api/sharing.dart';
export 'src/api/rotation.dart';
export 'src/api/chunked.dart';
export 'src/api/multipart.dart';
