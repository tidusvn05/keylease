import 'dart:convert';
import 'dart:io';

/// Non-secret UI preferences: where the local service lives, which client id
/// to present, the path of the registered token file, and pane geometry.
///
/// The client token itself is never stored here; only its path, which the user
/// picked through the native security-scoped panel.
abstract class PreferencesStore {
  Future<Map<String, dynamic>> load();

  Future<void> save(Map<String, dynamic> values);
}

class InMemoryPreferencesStore implements PreferencesStore {
  InMemoryPreferencesStore([Map<String, dynamic>? initial])
    : _values = {...?initial};

  Map<String, dynamic> _values;

  @override
  Future<Map<String, dynamic>> load() async => {..._values};

  @override
  Future<void> save(Map<String, dynamic> values) async {
    _values = {...values};
  }
}

class FilePreferencesStore implements PreferencesStore {
  FilePreferencesStore({String? path}) : _path = path ?? _defaultPath();

  final String _path;

  static String _defaultPath() {
    final home =
        Platform.environment['HOME'] ??
        Platform.environment['USERPROFILE'] ??
        Directory.systemTemp.path;
    if (Platform.isMacOS) {
      return '$home/Library/Application Support/KeyLease/desktop-ui.json';
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
