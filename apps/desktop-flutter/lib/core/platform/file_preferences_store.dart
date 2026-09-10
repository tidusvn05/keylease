import 'dart:convert';
import 'dart:io';

import 'package:leasegate_vault_ui/core/platform/preferences_store.dart';

/// The desktop preferences file.
///
/// Kept out of [PreferencesStore]'s own library because it is the only part
/// that needs `dart:io`: it resolves a path from `$HOME` and shells out to
/// `chmod`, neither of which means anything inside an Android app sandbox.
class FilePreferencesStore implements PreferencesStore {
  FilePreferencesStore({String? path}) : _path = path ?? _defaultPath();

  final String _path;

  static String _defaultPath() {
    final home =
        Platform.environment['HOME'] ??
        Platform.environment['USERPROFILE'] ??
        Directory.systemTemp.path;
    if (Platform.isMacOS) {
      return '$home/.keylease/ui.json';
    }
    if (Platform.isWindows) {
      final appData = Platform.environment['APPDATA'] ?? home;
      return '$appData\\KeyLease\\desktop-ui.json';
    }
    final xdg = Platform.environment['XDG_CONFIG_HOME'] ?? '$home/.config';
    return '$xdg/keylease/desktop-ui.json';
  }

  @override
  Future<Map<String, dynamic>> load() async {
    try {
      final file = File(_path);
      if (!file.existsSync()) return const {};
      final decoded = jsonDecode(await file.readAsString());
      return decoded is Map ? Map<String, dynamic>.from(decoded) : const {};
    } catch (_) {
      // Corrupt or unreadable preferences must never block start-up.
      return const {};
    }
  }

  @override
  Future<void> save(Map<String, dynamic> values) async {
    try {
      final file = File(_path);
      await file.parent.create(recursive: true);
      await file.writeAsString(jsonEncode(values), flush: true);
      if (!Platform.isWindows) {
        await Process.run('chmod', ['0600', _path]);
      }
    } catch (_) {
      // Preferences are a convenience; failing to persist them is not fatal.
    }
  }
}
