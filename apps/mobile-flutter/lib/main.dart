import 'dart:async';

import 'package:leasegate_vault_ui/app/keylease_app.dart';
import 'package:leasegate_vault_ui/core/platform/app_capabilities.dart';
import 'package:leasegate_vault_ui/core/state/app_controller.dart';
import 'package:leasegate_vault_ui/core/state/connection_settings.dart';
import 'package:material_ui/material_ui.dart';
import 'package:path_provider/path_provider.dart';

import 'platform/android_security_adapter.dart';
import 'platform/android_biometric_vault.dart';
import 'platform/app_preferences_store.dart';
import 'platform/ffi_bridge.dart';
import 'platform/ffi_keylease_client.dart';
import 'platform/ffi_local_runtime_adapter.dart';

/// The Android composition root.
///
/// The whole widget tree comes from `package:leasegate_vault_ui`; this file
/// only decides which platform implementations to give it — the Kotlin
/// clipboard channel, app-private preferences, and the in-process vault.
Future<AppController> buildAndroidController() async {
  final support = await getApplicationSupportDirectory();

  final vault = await VaultIsolate.spawn();
  final storage = FfiVaultStorage(vault: vault, supportDirectory: support.path);
  await storage.initialize();

  final security = AndroidSecurityAdapter();
  final controller = AppController(
    adapter: security,
    runtime: FfiLocalRuntimeAdapter(storage),
    preferences: AppPreferencesStore(directory: support.path),
    clientFactory: (_) => FfiKeyLeaseClient(
      vault,
      onUnlocked: storage.recordUnlocked,
    ),
    capabilities: AppCapabilities.androidPhone,
    biometric: const AndroidBiometricVault(),
    // There is no socket and no token file: the vault is opened in process.
    defaultSettings: const ConnectionSettings.unset(),
  );

  // Locking must also drop the in-process session keys, not just the UI's view
  // of them, so the background trigger reaches the Rust side too.
  security.lockRequests.listen((_) {
    unawaited(vault.lock());
  });

  return controller;
}

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(
    KeyLeaseApp(
      controller: await buildAndroidController(),
      ownsController: true,
    ),
  );
}
