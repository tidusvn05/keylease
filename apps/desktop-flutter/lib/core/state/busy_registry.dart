import 'package:flutter/foundation.dart';

/// Tracks in-flight operations by key so a busy indicator only disables the
/// action it belongs to, never the whole window.
mixin BusyRegistry on ChangeNotifier {
  final Set<String> _pending = <String>{};

  bool isBusy(String key) => _pending.contains(key);

  bool get isAnythingBusy => _pending.isNotEmpty;

  @protected
  Future<T?> track<T>(
    String key,
    Future<T> Function() operation, {
    void Function(Object error)? onError,
  }) async {
    if (!_pending.add(key)) return null;
    notifyListeners();
    try {
      return await operation();
    } catch (error) {
      if (onError == null) rethrow;
      onError(error);
      return null;
    } finally {
      _pending.remove(key);
      notifyListeners();
    }
  }
}
