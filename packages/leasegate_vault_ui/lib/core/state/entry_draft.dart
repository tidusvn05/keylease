import 'dart:convert';

import '../models/models.dart';

/// The editable snapshot of an entry.
///
/// Drafts live outside the widget tree so a failed save, a rebuild or a
/// navigation change cannot lose typed data. Secret fields start empty on an
/// edit: an empty secret means "keep the stored value", never "clear it".
class EntryDraft {
  EntryDraft.create({
    this.groupId,
    this.kind = 'core.login',
    String initialPassword = '',
  }) : entryId = null,
       revision = 0,
       _originalGroupId = groupId,
       _originalTitle = '',
       _originalUsername = '',
       _originalUrl = '' {
    password = initialPassword;
  }

  EntryDraft.edit(EntrySummary entry, {String? projectSlug})
    : entryId = entry.id,
      revision = entry.revision,
      kind = entry.kind,
      groupId = entry.groupId,
      _originalGroupId = entry.groupId,
      _originalTitle = entry.title,
      _originalUsername = entry.username ?? '',
      _originalUrl = entry.primaryUrl ?? '' {
    title = entry.title;
    username = entry.username ?? '';
    url = entry.primaryUrl ?? '';
    favorite = entry.favorite;
    _originalFavorite = entry.favorite;
    this.projectSlug = projectSlug;
    _originalProjectSlug = projectSlug;
  }

  final String? entryId;
  final int revision;
  String kind;
  String? groupId;

  final String? _originalGroupId;
  final String _originalTitle;
  final String _originalUsername;
  final String _originalUrl;
  bool _originalFavorite = false;
  String? _originalProjectSlug;

  String title = '';
  String username = '';
  String url = '';
  String password = '';
  String notes = '';
  String totp = '';
  String customFields = '';
  String sections = '';
  List<String> removeFieldIds = const [];
  Map<String, String> sshKeyBindings = const {};
  List<String> sshBindingsToClear = const [];
  Map<String, String> structuredErrors = const {};
  String tags = '';
  String? projectSlug;
  String agentAccess = 'none';
  bool favorite = false;

  bool get isAgentContent =>
      const {'core.prompt', 'core.runbook', 'core.note'}.contains(kind);

  bool get isNew => entryId == null;

  bool get isDirty =>
      title != _originalTitle ||
      username != _originalUsername ||
      url != _originalUrl ||
      groupId != _originalGroupId ||
      password.isNotEmpty ||
      notes.isNotEmpty ||
      totp.isNotEmpty ||
      tags.isNotEmpty ||
      projectSlug != _originalProjectSlug ||
      agentAccess != 'none' ||
      favorite != _originalFavorite ||
      customFields.isNotEmpty ||
      sections.isNotEmpty ||
      removeFieldIds.isNotEmpty ||
      sshKeyBindings.isNotEmpty ||
      sshBindingsToClear.isNotEmpty;

  /// Field-level validation messages, keyed by field name.
  Map<String, String> validate() {
    final errors = <String, String>{};
    if (title.trim().isEmpty) {
      errors['title'] = 'Give this item a name.';
    }
    if (!isAgentContent && (groupId == null || groupId!.isEmpty)) {
      errors['group'] = 'Choose a group for this item.';
    }
    if (customFields.trim().isNotEmpty && _parseCustomFields() == null) {
      errors['custom_fields'] = 'Custom fields must be a JSON array.';
    }
    if (sections.trim().isNotEmpty && _parseSections() == null) {
      errors['sections'] = 'Sections must be a JSON array.';
    }
    errors.addAll(structuredErrors);
    return errors;
  }

  List<dynamic>? _parseCustomFields() {
    try {
      final decoded = jsonDecode(customFields);
      return decoded is List<dynamic> ? decoded : null;
    } on FormatException {
      return null;
    }
  }

  List<dynamic>? _parseSections() {
    if (sections.trim().isEmpty) return <dynamic>[];
    try {
      final decoded = jsonDecode(sections);
      return decoded is List<dynamic> ? decoded : null;
    } on FormatException {
      return null;
    }
  }

  Map<String, dynamic>? _totpPayload() =>
      totp.trim().isEmpty || totp.startsWith('otpauth://')
      ? null
      : {
          'secret_base32': totp.trim(),
          'issuer': null,
          'account': null,
          'algorithm': 'sha1',
          'digits': 6,
          'period': 30,
          'source_representation': 'base32',
        };

  String? get _totpUri => totp.startsWith('otpauth://') ? totp.trim() : null;

  /// `entries_create` input.
  Map<String, dynamic> toCreateInput() => {
    'group_id': groupId,
    'kind': kind,
    'title': title.trim(),
    'project_slug': projectSlug,
    'favorite': favorite,
    'username': username,
    'password': password.isEmpty ? null : password,
    'url': url.isEmpty ? null : url,
    'notes': notes.isEmpty ? null : notes,
    'custom_fields': _parseCustomFields() ?? <dynamic>[],
    'sections': _parseSections() ?? <dynamic>[],
    'totp': _totpPayload(),
    'totp_uri': _totpUri,
  };

  Map<String, dynamic> toContentCreateInput() => {
    'kind': kind,
    'title': title.trim(),
    'body': notes,
    'tags': tags
        .split(',')
        .map((tag) => tag.trim())
        .where((tag) => tag.isNotEmpty)
        .toSet()
        .toList(growable: false),
    'project_slug': projectSlug,
    'favorite': favorite,
  };

  Map<String, dynamic> toContentPatch() => {
    'title': title.trim(),
    if (notes.isNotEmpty) 'body': notes,
    if (tags.trim().isNotEmpty)
      'tags': tags
          .split(',')
          .map((tag) => tag.trim())
          .where((tag) => tag.isNotEmpty)
          .toSet()
          .toList(growable: false),
    'add_tags': <String>[],
    'remove_tags': <String>[],
    if (projectSlug != _originalProjectSlug && projectSlug != null)
      'project_slug': projectSlug,
    'clear_project': projectSlug != _originalProjectSlug && projectSlug == null,
    if (favorite != _originalFavorite) 'favorite': favorite,
  };

  /// `entries_update` patch. Empty secrets are omitted so they keep their
  /// stored value instead of being overwritten with a blank.
  Map<String, dynamic> toPatch() {
    final parsed = _parseCustomFields();
    return <String, dynamic>{
      'title': title.trim(),
      if (projectSlug != _originalProjectSlug && projectSlug != null)
        'project_slug': projectSlug,
      if (projectSlug != _originalProjectSlug && projectSlug == null)
        'clear_project': true,
      'username': username,
      'url': url.isEmpty ? null : url,
      if (groupId != _originalGroupId) 'group_id': groupId,
      if (favorite != _originalFavorite) 'favorite': favorite,
      if (password.isNotEmpty) 'password': password,
      if (notes.isNotEmpty) 'notes': notes,
      if (_totpPayload() != null) 'totp': _totpPayload(),
      if (_totpUri != null) 'totp_uri': _totpUri,
      if (parsed != null) 'field_updates': parsed,
      if (sections.trim().isNotEmpty) 'sections': _parseSections(),
      if (removeFieldIds.isNotEmpty) 'remove_field_ids': removeFieldIds,
    };
  }

  /// Removes the secret material a draft accumulated.
  void wipeSecrets() {
    password = '';
    notes = '';
    totp = '';
    customFields = '';
    sections = '';
    removeFieldIds = const [];
    sshKeyBindings = const {};
    sshBindingsToClear = const [];
    structuredErrors = const {};
  }
}
