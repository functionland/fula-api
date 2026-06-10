// Web platform registration stub for fula_client.
//
// Flutter's generated web plugin registrant imports
// `package:fula_client/fula_client_web.dart` (the `web:` block in
// pubspec.yaml names this file, and plugin `fileName`s resolve under
// `lib/`), so this file must exist here or `flutter build web` fails
// before any app code compiles.
//
// It is intentionally a no-op: WASM loading is owned by
// flutter_rust_bridge. `RustLib.init()` injects `pkg/fula_flutter.js`
// (wasm-bindgen `--target no-modules` output) and instantiates
// `pkg/fula_flutter_bg.wasm` from the host app's web/ folder per the
// loader config in `lib/src/frb_generated.dart` (stem `fula_flutter`,
// webPrefix `pkg/`, wasmBindgenName `wasm_bindgen`).
import 'package:flutter_web_plugins/flutter_web_plugins.dart';

/// Web plugin entry point for fula_client. No platform channels to
/// register — see file header.
class FulaClientWeb {
  static void registerWith(Registrar registrar) {
    // No-op: flutter_rust_bridge owns WASM loading via RustLib.init().
  }
}
