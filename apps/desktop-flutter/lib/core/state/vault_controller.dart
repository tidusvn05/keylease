import 'dart:async';

import 'package:flutter/widgets.dart';

import '../models/models.dart';
import '../rpc/keylease_rpc.dart';
import 'agent_creation_draft.dart';
import 'busy_registry.dart';
import 'entry_draft.dart';
import 'user_message.dart';

/// What the entry list is showing right now.
enum VaultListState { loading, content, empty, searchEmpty }

enum EntryWorkspaceMode { detail, create, edit, passwordGenerator }

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
  List<TemplateDefinition> templates = const [];
  List<VaultProjectModel> projects = const [];
  MigrationStatusModel? migrationStatus;
  String query = '';
  String? selectedGroupId;
  bool favoritesOnly = false;
  String? selectedEntryId;
  EntryWorkspaceMode workspaceMode = EntryWorkspaceMode.detail;
  EntryDraft? activeDraft;
  EntryCreationMode creationMode = EntryCreationMode.manual;
  AgentCreationDraft? agentCreationDraft;
  UserMessage? error;
  Object? lastFailure;
  bool _loaded = false;
  bool _searching = false;

  Timer? _debounce;
  Timer? _revealTimer;
  int _issued = 0;
  int _applied = 0;

  final Map<String, String> _revealed = <String, String>{};
  final Map<String, EntryDetailView> _entryViews = <String, EntryDetailView>{};

  /// Owned here so the query and the caret survive a list -> detail route on
  /// narrow windows and a desktop/touch shell swap on resize.
  final TextEditingController searchController = TextEditingController();
  final FocusNode searchFocus = FocusNode(debugLabel: 'vault.search');

  List<VaultGroup> get orderedGroups {
    final result = [...groups];
    result.sort((a, b) {
      final order = (a.sortOrder ?? 0x7fffffff).compareTo(
        b.sortOrder ?? 0x7fffffff,
      );
      if (order != 0) return order;
      final name = a.name.toLowerCase().compareTo(b.name.toLowerCase());
      return name != 0 ? name : a.id.compareTo(b.id);
    });
    return result;
  }

  List<EntrySummary> get visibleEntries {
    if (favoritesOnly) {
      return entries.where((entry) => entry.favorite).toList(growable: false);
    }
    final root = selectedGroupId;
    if (root == null) return entries;
    final ids = <String>{root};
    var changed = true;
    while (changed) {
      changed = false;
      for (final group in groups) {
        if (group.parentId != null &&
            ids.contains(group.parentId) &&
            ids.add(group.id)) {
          changed = true;
        }
      }
    }
    return entries
        .where((entry) => ids.contains(entry.groupId))
        .toList(growable: false);
  }

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

  EntryDetailView? entryView(String entryId) => _entryViews[entryId];

  String kindLabel(String kind) {
    for (final template in templates) {
      if (template.kind == kind) return template.label;
    }
    return kind;
  }

  String? projectName(String? id) {
    if (id == null) return null;
    for (final project in projects) {
      if (project.id == id) return project.name;
    }
    return id;
  }

  bool get hasRevealedSecrets => _revealed.isNotEmpty;

  void select(String entryId) {
    if (selectedEntryId == entryId) return;
    selectedEntryId = entryId;
    hideSecrets();
    notifyListeners();
    unawaited(loadEntryView(entryId));
  }

  void beginCreate({String initialPassword = ''}) {
    activeDraft = EntryDraft.create(
      groupId:
          selectedGroupId ??
          (orderedGroups.isEmpty ? null : orderedGroups.first.id),
      initialPassword: initialPassword,
    );
    creationMode = EntryCreationMode.manual;
    agentCreationDraft = AgentCreationDraft(
      kind: activeDraft!.kind,
      groupId: activeDraft!.groupId,
    );
    workspaceMode = EntryWorkspaceMode.create;
    hideSecrets();
    notifyListeners();
  }

  void openPasswordGenerator() {
    activeDraft?.wipeSecrets();
    activeDraft = null;
    agentCreationDraft = null;
    creationMode = EntryCreationMode.manual;
    workspaceMode = EntryWorkspaceMode.passwordGenerator;
    hideSecrets();
    notifyListeners();
  }

  void beginEdit(EntrySummary entry) {
    agentCreationDraft = null;
    creationMode = EntryCreationMode.manual;
    activeDraft = EntryDraft.edit(entry);
    workspaceMode = EntryWorkspaceMode.edit;
    hideSecrets();
    notifyListeners();
  }

  void closeEditor() {
    activeDraft?.wipeSecrets();
    activeDraft = null;
    agentCreationDraft = null;
    creationMode = EntryCreationMode.manual;
    workspaceMode = EntryWorkspaceMode.detail;
    notifyListeners();
  }

  Future<void> useAgentCreation() async {
    final manual = activeDraft;
    if (manual == null || !manual.isNew) return;
    final draft = agentCreationDraft ??= AgentCreationDraft(
      kind: manual.kind,
      groupId: manual.groupId,
    );
    if (!draft.promptCopied &&
        draft.recipeId == 'describe' &&
        draft.context.isEmpty &&
        draft.sourcePath.isEmpty) {
      draft
        ..kind = manual.kind
        ..groupId = manual.groupId;
    }
    creationMode = EntryCreationMode.agentDriven;
    notifyListeners();
    draft.baselineEntryIds ??= await snapshotEntryIds();
    notifyListeners();
  }

  void useManualCreation() {
    if (activeDraft == null) return;
    creationMode = EntryCreationMode.manual;
    notifyListeners();
  }

  Future<Set<String>> snapshotEntryIds() async {
    final result = await clientOf().authorized({
      'command': 'entries_search',
      'query': '',
    });
    return parseList(
      result,
      EntrySummary.fromJson,
    ).map((entry) => entry.id).toSet();
  }

  Future<List<EntrySummary>> entriesCreatedSince(Set<String> baseline) async {
    final result = await clientOf().authorized({
      'command': 'entries_search',
      'query': '',
    });
    final all = parseList(result, EntrySummary.fromJson);
    final created = all
        .where((entry) => !baseline.contains(entry.id))
        .toList(growable: false);
    created.sort((left, right) {
      final time = (right.updatedAt ?? DateTime.fromMillisecondsSinceEpoch(0))
          .compareTo(left.updatedAt ?? DateTime.fromMillisecondsSinceEpoch(0));
      return time != 0 ? time : left.title.compareTo(right.title);
    });
    return created;
  }

  void openAgentCreatedEntry(EntrySummary entry) {
    activeDraft?.wipeSecrets();
    activeDraft = null;
    agentCreationDraft = null;
    creationMode = EntryCreationMode.manual;
    workspaceMode = EntryWorkspaceMode.detail;
    query = '';
    searchController.clear();
    selectedGroupId = null;
    favoritesOnly = false;
    entries = [
      entry,
      ...entries.where((candidate) => candidate.id != entry.id),
    ];
    selectedEntryId = entry.id;
    hideSecrets();
    notifyListeners();
    unawaited(loadEntryView(entry.id));
    unawaited(_search());
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
    favoritesOnly = false;
    workspaceMode = EntryWorkspaceMode.detail;
    hideSecrets();
    _normalizeSelection();
    notifyListeners();
  }

  void selectFavorites() {
    selectedGroupId = null;
    favoritesOnly = true;
    workspaceMode = EntryWorkspaceMode.detail;
    hideSecrets();
    _normalizeSelection();
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

  Future<void> loadMigrations() async {
    try {
      final result = await clientOf().authorized({
        'command': 'migrations_status',
      });
      if (result is Map) {
        migrationStatus = MigrationStatusModel.fromJson(
          Map<String, dynamic>.from(result),
        );
        notifyListeners();
      }
    } catch (_) {
      // Migration discovery must not make an otherwise readable vault
      // unavailable. The normal error surface remains reserved for its
      // explicit preview/apply operations.
    }
  }

  Future<void> applyMigration(MigrationPreviewModel preview) async {
    await clientOf().authorized({
      'command': 'migrations_apply',
      'migration_id': preview.id,
      'preview_digest': preview.digest,
    });
    _entryViews.clear();
    await _search();
    await loadMigrations();
  }

  Future<void> rollbackMigration(String migrationId) async {
    await clientOf().authorized({
      'command': 'migrations_rollback',
      'migration_id': migrationId,
    });
    _entryViews.clear();
    await _search();
    await loadMigrations();
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
      List<TemplateDefinition>? nextTemplates;
      List<VaultProjectModel>? nextProjects;
      if (withGroups) {
        // Template/project discovery was added after the first desktop
        // contract. Keep startup compatible with an older daemon while the
        // normal entry list remains available.
        try {
          nextTemplates = parseList(
            await client.authorized({'command': 'templates_list'}),
            TemplateDefinition.fromJson,
          );
          nextProjects = parseList(
            await client.authorized({'command': 'projects_list'}),
            VaultProjectModel.fromJson,
          );
        } catch (_) {
          nextTemplates = null;
          nextProjects = null;
        }
      }
      final result = await client.authorized({
        'command': 'entries_search',
        'query': query,
      });
      // A slower earlier query must never overwrite a newer screen.
      if (sequence <= _applied) return;
      _applied = sequence;
      if (nextGroups != null) groups = nextGroups;
      if (nextTemplates != null) templates = nextTemplates;
      if (nextProjects != null) projects = nextProjects;
      entries = parseList(result, EntrySummary.fromJson);
      error = null;
      lastFailure = null;
      _loaded = true;
      _normalizeSelection();
      final selected = selectedEntryId;
      if (selected != null) unawaited(loadEntryView(selected));
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

  Future<void> loadEntryView(String entryId) async {
    try {
      final result = await clientOf().authorized({
        'command': 'entries_view',
        'id': entryId,
      });
      if (result is Map) {
        _entryViews[entryId] = EntryDetailView.fromJson(
          Map<String, dynamic>.from(result),
        );
        error = null;
        notifyListeners();
      }
    } catch (caught) {
      // An older daemon has no field-oriented view. The legacy login detail
      // remains usable; surface other failures without clearing list data.
      lastFailure = caught;
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

  Future<String?> fetchField(EntrySummary entry, EntryFieldView field) =>
      track<String?>('reveal.${entry.id}/${field.id}', () async {
        final response = await clientOf().authorized({
          'command': 'entries_reveal_by_id',
          'id': entry.id,
          'field_id': field.id,
        });
        final raw = response is Map ? response['value'] : null;
        return field.withValue(raw).displayValue;
      }, onError: (caught) => error = UserMessage.from(caught));

  Future<String?> revealField(EntrySummary entry, EntryFieldView field) async {
    final value = await fetchField(entry, field);
    if (value != null) {
      _revealed['${entry.id}/${field.id}'] = value;
      _restartRevealTimer();
      notifyListeners();
    }
    return value;
  }

  Future<Map<String, String>> fetchFields(
    EntrySummary entry,
    List<EntryFieldView> fields,
  ) async =>
      await track<Map<String, String>>('reveal.${entry.id}/batch', () async {
        final response = await clientOf().authorized({
          'command': 'entries_reveal_many',
          'id': entry.id,
          'field_ids': fields.map((field) => field.id).toList(growable: false),
        });
        final raw = response is Map ? response['values'] : null;
        if (raw is! Map) return const {};
        return {
          for (final field in fields)
            if (raw.containsKey(field.id))
              field.id: field.withValue(raw[field.id]).displayValue,
        };
      }, onError: (caught) => error = UserMessage.from(caught)) ??
      const {};

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
    templates = const [];
    projects = const [];
    migrationStatus = null;
    _entryViews.clear();
    query = '';
    searchController.clear();
    selectedEntryId = null;
    selectedGroupId = null;
    favoritesOnly = false;
    activeDraft?.wipeSecrets();
    activeDraft = null;
    agentCreationDraft = null;
    creationMode = EntryCreationMode.manual;
    workspaceMode = EntryWorkspaceMode.detail;
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

  Future<String?> fetchContentBody(EntrySummary entry) async {
    final result = await clientOf().authorized({
      'command': 'content_get',
      'id': entry.id,
    });
    return result is Map ? result['body']?.toString() : null;
  }

  Future<String?> generatePassword({
    int length = 32,
    Map<String, dynamic>? recipe,
  }) async {
    final result = await clientOf().authorized({
      'command': 'generate_password',
      'length': length,
      if (recipe != null) 'recipe': recipe,
    });
    return result is Map ? result['password']?.toString() : null;
  }

  String _idempotencyKey() =>
      'desktop-${DateTime.now().microsecondsSinceEpoch}';

  /// Saves [draft]. On failure the draft is untouched so the editor can retry.
  Future<String?> save(EntryDraft draft) async {
    final client = clientOf();
    String? savedId = draft.entryId;
    if (draft.isNew) {
      if (draft.isAgentContent) {
        final created = await client.authorized({
          'command': 'content_create',
          'input': draft.toContentCreateInput(),
          'idempotency_key': _idempotencyKey(),
        });
        if (draft.agentAccess != 'none' && created is Map) {
          final summary = created['summary'];
          if (summary is Map) {
            savedId = summary['id']?.toString();
            await client.authorized({
              'command': 'content_set_access',
              'id': summary['id'],
              'access': draft.agentAccess,
              'if_revision': summary['revision'],
              'idempotency_key': _idempotencyKey(),
            });
          }
        } else if (created is Map && created['summary'] is Map) {
          savedId = (created['summary'] as Map)['id']?.toString();
        }
      } else {
        final created = await client.authorized({
          'command': 'entries_create',
          'input': draft.toCreateInput(),
          'idempotency_key': _idempotencyKey(),
          'dry_run': false,
        });
        if (created is Map) savedId = created['id']?.toString();
      }
    } else if (draft.isAgentContent) {
      await client.authorized({
        'command': 'content_update',
        'id': draft.entryId,
        'patch': draft.toContentPatch(),
        'if_revision': draft.revision,
        'idempotency_key': _idempotencyKey(),
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
    return savedId;
  }

  Future<void> toggleFavorite(EntrySummary entry) async {
    final favorite = !entry.favorite;
    if (const {
      'core.prompt',
      'core.runbook',
      'core.note',
    }.contains(entry.kind)) {
      await clientOf().authorized({
        'command': 'content_update',
        'id': entry.id,
        'patch': {
          'favorite': favorite,
          'add_tags': <String>[],
          'remove_tags': <String>[],
          'clear_project': false,
        },
        'if_revision': entry.revision,
        'idempotency_key': _idempotencyKey(),
      });
    } else {
      await clientOf().authorized({
        'command': 'entries_update',
        'id': entry.id,
        'patch': {'favorite': favorite},
        'if_revision': entry.revision,
        'idempotency_key': _idempotencyKey(),
        'dry_run': false,
      });
    }
    selectedEntryId = entry.id;
    await _search();
  }

  Future<void> reorderGroups(String? parentId, List<VaultGroup> ordered) async {
    await clientOf().authorized({
      'command': 'groups_reorder',
      'parent_id': parentId,
      'ordered_ids': ordered.map((group) => group.id).toList(growable: false),
      'expected_revisions': {
        for (final group in ordered) group.id: group.revision,
      },
      'idempotency_key': _idempotencyKey(),
      'dry_run': false,
    });
    await load();
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
