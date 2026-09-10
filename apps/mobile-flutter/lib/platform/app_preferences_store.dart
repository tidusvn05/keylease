import 'dart:convert';
import 'dart:io';

import 'package:leasegate_vault_ui/core/platform/preferences_store.dart';

/// Non-secret UI preferences, in Android app-private storage.
///
/// A port of the desktop file store minus its `chmod 0600`: the app's own
/// directory is already `0700` and owned by this uid alone, so shelling out to
/// change the mode would add nothing.
///
/// The directory is supplied rather than resolved here because `path_provider`
/// is a plugin, and keeping the plugin at the composition root keeps this class
/// testable with a temp directory.
class AppPreferencesStore implements PreferencesStore {
  AppPreferencesStore({required String directory})
    : _path = '$directory/ui.json';

  final String _path;

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
    } catch (_) {
      // Preferences are a convenience; failing to persist them is not fatal.
    }
  }
}
