import 'package:material_ui/material_ui.dart';

import 'app/keylease_app.dart';
import 'app/settings_window_app.dart';

export 'app/keylease_app.dart' show KeyLeaseApp;
export 'core/rpc/keylease_rpc.dart'
    show KeyLeaseException, KeyLeaseErrorCode, KeyLeaseRpc;

void main() => runApp(const KeyLeaseApp());

/// Entrypoint used by the dedicated macOS Settings Flutter engine.
@pragma('vm:entry-point')
void settingsMain() => runApp(const KeyLeaseSettingsWindowApp());
