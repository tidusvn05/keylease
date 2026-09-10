/// Non-secret UI preferences such as pane geometry. Runtime paths are managed
/// internally under `~/.keylease` and never exposed as preferences.
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
