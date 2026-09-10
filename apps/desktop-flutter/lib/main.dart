import 'package:leasegate_vault_ui/app/keylease_app.dart';
import 'package:leasegate_vault_ui/core/platform/local_runtime_adapter.dart';
import 'package:leasegate_vault_ui/core/platform/security_adapter.dart';
import 'package:leasegate_vault_ui/core/state/app_controller.dart';
import 'package:material_ui/material_ui.dart';

import 'app/settings_window_app.dart';
import 'core/platform/desktop_connection_defaults.dart';
import 'core/platform/file_preferences_store.dart';
import 'core/rpc/keylease_rpc.dart';

export 'package:leasegate_vault_ui/app/keylease_app.dart' show KeyLeaseApp;

export 'core/rpc/keylease_rpc.dart'
    show KeyLeaseErrorCode, KeyLeaseException, KeyLeaseRpc;

/// The desktop composition root.
///
/// Everything host-specific is chosen here — the native method channels, the
/// preferences file, the managed socket paths and the socket transport — so the
/// widget tree in `package:leasegate_vault_ui` stays shared with the Android
/// client, which supplies its own.
AppController buildDesktopController() => AppController(
  adapter: MethodChannelSecurityAdapter(),
  runtime: MethodChannelLocalRuntimeAdapter(),
  preferences: FilePreferencesStore(),
  defaultSettings: desktopConnectionDefaults(),
  clientFactory: socketClientFactory,
);

void main() => runApp(
  KeyLeaseApp(controller: buildDesktopController(), ownsController: true),
);

/// Entrypoint used by the dedicated macOS Settings Flutter engine.
@pragma('vm:entry-point')
void settingsMain() => runApp(const KeyLeaseSettingsWindowApp());
