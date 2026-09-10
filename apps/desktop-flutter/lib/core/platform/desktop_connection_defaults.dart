import 'dart:io';

import 'package:leasegate_vault_ui/core/state/connection_settings.dart';

/// Where a desktop install keeps its managed socket and client token.
///
/// This is the half of the old `ConnectionSettings.defaults()` that needs
/// `dart:io`. It lives beside the other desktop-only platform code so the
/// state layer stays portable.
ConnectionSettings desktopConnectionDefaults() {
  final home =
      Platform.environment['HOME'] ??
      Platform.environment['USERPROFILE'] ??
      Directory.systemTemp.path;
  return ConnectionSettings(
    socketPath: '$home/.keylease/run/keylease.sock',
    agentId: 'agent_desktop',
    tokenPath: '$home/.keylease/desktop.token',
  );
}
