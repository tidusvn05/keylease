import 'dart:async';

import 'package:flutter/widgets.dart';

import '../models/models.dart';
import '../rpc/keylease_rpc.dart';
import 'busy_registry.dart';
import 'entry_draft.dart';
import 'user_message.dart';

/// What the entry list is showing right now.
enum VaultListState { loading, content, empty, searchEmpty }

/// Vault list/detail state: groups, the debounced search, the selection and
/// the on-demand secret reveals.
class VaultController extends ChangeNotifier with BusyRegistry {
  VaultController({
    required this.clientOf,
    this.searchDebounce = const Duration(milliseconds: 220),
    this.revealTimeout = const Duration(seconds: 15),
  });

  static const searchBusyKey = 'vault.search';

  final KeyLeaseClient Function() clientOf;

  /// How long typing settles before a search is sent. Mutable so tests and a
  /// future preference can shorten it without rebuilding the controller.
  Duration searchDebounce;
  final Duration revealTimeout;

  List<VaultGroup> groups = const [];
  List<EntrySummary> entries = const [];
  String query = '';
  String? selectedGroupId;
  String? selectedEntryId;
  UserMessage? error;
  Object? lastFailure;
  bool _loaded = false;
  bool _searching = false;

  Timer? _debounce;
  Timer? _revealTimer;
  int _issued = 0;
  int _applied = 0;

  final Map<String, String> _revealed = <String, String>{};

  /// Owned here so the query and the caret survive a list -> detail route on
  /// narrow windows and a desktop/touch shell swap on resize.
  final TextEditingController searchController = TextEditingController();
  final FocusNode searchFocus = FocusNode(debugLabel: 'vault.search');

  /// Entries filtered by the selected group. Ordering is whatever the daemon
  /// returned; `ItemMetadata` carries no "recently used" or favourite signal,
  /// so the UI does not invent one.
  List<EntrySummary> get visibleEntries => selectedGroupId == null
      ? entries
      : entries
            .where((entry) => entry.groupId == selectedGroupId)
            .toList(growable: false);

  VaultListState get listState {
    if (!_loaded || _searching) return VaultListState.loading;
    if (visibleEntries.isNotEmpty) return VaultListState.content;
    return query.trim().isEmpty
        ? VaultListState.empty
        : VaultListState.searchEmpty;
  }

  EntrySummary? get selectedEntry {
    final visible = visibleEntries;
    if (visible.isEmpty) return null;
    for (final entry in visible) {
      if (entry.id == selectedEntryId) return entry;
    }
    return visible.first;
  }

  String? revealedValue(String entryId, String field) =>
      _revealed['$entryId/$field'];

  bool get hasRevealedSecrets => _revealed.isNotEmpty;

  void select(String entryId) {
    if (selectedEntryId == entryId) return;
    selectedEntryId = entryId;
    hideSecrets();
    notifyListeners();
  }

  /// Moves the selection by [delta] within the visible list, for arrow keys.
  void moveSelection(int delta) {
    final visible = visibleEntries;
    if (visible.isEmpty) return;
    final current = visible.indexWhere((entry) => entry.id == selectedEntryId);
    final next = (current < 0 ? 0 : current + delta).clamp(
      0,
      visible.length - 1,
    );
    select(visible[next].id);
  }

  void selectGroup(String? groupId) {
    selectedGroupId = groupId;
    hideSecrets();
    notifyListeners();
  }

  /// Debounced search. Every keystroke updates the field immediately; only the
  /// newest response is allowed to replace the list.
  void setQuery(String value) {
    if (query == value) return;
    query = value;
    _searching = true;
    notifyListeners();
    _debounce?.cancel();
    _debounce = Timer(searchDebounce, () => unawaited(_search()));
  }

  Future<void> load() async {
    _debounce?.cancel();
    await _search(withGroups: true);
  }

  Future<void> _search({bool withGroups = false}) async {
    final sequence = ++_issued;
    _searching = true;
    notifyListeners();
    try {
      final client = clientOf();
      final nextGroups = withGroups
          ? parseList(
              await client.authorized({'command': 'groups_list'}),
              VaultGroup.fromJson,
            )
          : null;
      final result = await client.authorized({
        'command': 'entries_search',
        'query': query,
      });
      // A slower earlier query must never overwrite a newer screen.
      if (sequence <= _applied) return;
      _applied = sequence;
      if (nextGroups != null) groups = nextGroups;
      entries = parseList(result, EntrySummary.fromJson);
      error = null;
      lastFailure = null;
      _loaded = true;
      _normalizeSelection();
    } catch (caught) {
      if (sequence <= _applied) return;
      _applied = sequence;
      lastFailure = caught;
      error = UserMessage.from(caught);
    } finally {
      if (sequence >= _issued) _searching = false;
      notifyListeners();
    }
  }

  void _normalizeSelection() {
    final visible = visibleEntries;
    if (visible.isEmpty) {
      selectedEntryId = null;
      return;
    }
    if (!visible.any((entry) => entry.id == selectedEntryId)) {
      selectedEntryId = visible.first.id;
      _revealed.clear();
    }
  }

  /// Fetches a protected field without putting it on screen.
  ///
  /// Copying uses this: a copy must not also un-mask the field, because the
  /// two are different disclosures and only one of them was asked for.
  Future<String?> fetchSecret(EntrySummary entry, String field) =>
      track<String?>('reveal.${entry.id}/$field', () async {
        final response = await clientOf().authorized({
          'command': 'entries_reveal',
          'id': entry.id,
          'field': field,
        });
        return response is Map ? response['value']?.toString() : null;
      }, onError: (caught) => error = UserMessage.from(caught));

  /// Fetches a protected field on demand and keeps it visible only briefly.
  Future<String?> reveal(EntrySummary entry, String field) async {
    final value = await fetchSecret(entry, field);
    if (value != null) {
      _revealed['${entry.id}/$field'] = value;
      _restartRevealTimer();
      notifyListeners();
    }
    return value;
  }

  void hideSecret(String entryId, String field) {
    _revealed.remove('$entryId/$field');
    if (_revealed.isEmpty) {
      _revealTimer?.cancel();
      _revealTimer = null;
    }
    notifyListeners();
  }

  /// Drops every revealed secret. Called on lock, sleep and screen lock.
  void hideSecrets() {
    _revealTimer?.cancel();
    _revealTimer = null;
    if (_revealed.isEmpty) return;
    _revealed.clear();
    notifyListeners();
  }

  void _restartRevealTimer() {
    _revealTimer?.cancel();
    _revealTimer = Timer(revealTimeout, hideSecrets);
  }

  /// Clears everything derived from an unlocked vault.
  void clear() {
    _debounce?.cancel();
    hideSecrets();
    groups = const [];
    entries = const [];
    query = '';
    searchController.clear();
    selectedEntryId = null;
    selectedGroupId = null;
    error = null;
    lastFailure = null;
    _loaded = false;
    _searching = false;
    notifyListeners();
  }

  Future<List<EntryRevision>> history(EntrySummary entry) async {
    final result = await clientOf().authorized({
      'command': 'entries_history',
      'id': entry.id,
    });
    return parseList(result, EntryRevision.fromJson);
  }

  Future<Map<String, dynamic>> totp(EntrySummary entry) async {
    final result = await clientOf().authorized({
      'command': 'entries_totp',
      'id': entry.id,
    });
    return Map<String, dynamic>.from(result as Map);
  }

  Future<String?> generatePassword({int length = 32}) async {
    final result = await clientOf().authorized({
      'command': 'generate_password',
      'length': length,
    });
    return result is Map ? result['password']?.toString() : null;
  }

  String _idempotencyKey() =>
      'desktop-${DateTime.now().microsecondsSinceEpoch}';

  /// Saves [draft]. On failure the draft is untouched so the editor can retry.
  Future<void> save(EntryDraft draft) async {
    final client = clientOf();
    if (draft.isNew) {
      await client.authorized({
        'command': 'entries_create',
        'input': draft.toCreateInput(),
        'idempotency_key': _idempotencyKey(),
        'dry_run': false,
      });
    } else {
      await client.authorized({
        'command': 'entries_update',
        'id': draft.entryId,
        'patch': draft.toPatch(),
        'if_revision': draft.revision,
        'idempotency_key': _idempotencyKey(),
        'dry_run': false,
      });
    }
    await _search();
  }

  Future<void> deleteEntry(EntrySummary entry) async {
    await clientOf().authorized({
      'command': 'entries_delete',
      'id': entry.id,
      'if_revision': entry.revision,
      'idempotency_key': _idempotencyKey(),
      'dry_run': false,
    });
    await _search();
  }

  Future<void> createGroup(String name) async {
    await clientOf().authorized({
      'command': 'groups_create',
      'name': name,
      'parent_id': selectedGroupId,
      'idempotency_key': _idempotencyKey(),
      'dry_run': false,
    });
    await load();
  }

  Future<void> renameGroup(VaultGroup group, String name) async {
    await clientOf().authorized({
      'command': 'groups_update',
      'id': group.id,
      'name': name,
      'if_revision': group.revision,
      'idempotency_key': _idempotencyKey(),
      'dry_run': false,
    });
    await load();
  }

  Future<void> deleteGroup(VaultGroup group) async {
    await clientOf().authorized({
      'command': 'groups_delete',
      'id': group.id,
      'if_revision': group.revision,
      'idempotency_key': _idempotencyKey(),
      'dry_run': false,
    });
    if (selectedGroupId == group.id) selectedGroupId = null;
    await load();
  }

  @override
  void dispose() {
    _debounce?.cancel();
    _revealTimer?.cancel();
    _revealed.clear();
    searchController.dispose();
    searchFocus.dispose();
    super.dispose();
  }
}
