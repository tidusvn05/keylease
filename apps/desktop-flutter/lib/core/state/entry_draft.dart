import 'dart:convert';

import '../models/models.dart';

/// The editable snapshot of an entry.
///
/// Drafts live outside the widget tree so a failed save, a rebuild or a
/// navigation change cannot lose typed data. Secret fields start empty on an
/// edit: an empty secret means "keep the stored value", never "clear it".
class EntryDraft {
  EntryDraft.create({this.groupId, this.kind = 'core.login'})
    : entryId = null,
      revision = 0,
      _originalGroupId = groupId,
      _originalTitle = '',
      _originalUsername = '',
      _originalUrl = '';

  EntryDraft.edit(EntrySummary entry)
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
  }

  final String? entryId;
  final int revision;
  String kind;
  String? groupId;

  final String? _originalGroupId;
  final String _originalTitle;
  final String _originalUsername;
  final String _originalUrl;

  String title = '';
  String username = '';
  String url = '';
  String password = '';
  String notes = '';
  String totp = '';
  String customFields = '';

  bool get isNew => entryId == null;

  bool get isDirty =>
      title != _originalTitle ||
      username != _originalUsername ||
      url != _originalUrl ||
      groupId != _originalGroupId ||
      password.isNotEmpty ||
      notes.isNotEmpty ||
      totp.isNotEmpty ||
      customFields.isNotEmpty;

  /// Field-level validation messages, keyed by field name.
  Map<String, String> validate() {
    final errors = <String, String>{};
    if (title.trim().isEmpty) {
      errors['title'] = 'Give this item a name.';
    }
    if (groupId == null || groupId!.isEmpty) {
      errors['group'] = 'Choose a group for this item.';
    }
    if (customFields.trim().isNotEmpty && _parseCustomFields() == null) {
      errors['custom_fields'] = 'Custom fields must be a JSON array.';
    }
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
    'username': username,
    'password': password.isEmpty ? null : password,
    'url': url.isEmpty ? null : url,
    'notes': notes.isEmpty ? null : notes,
    'custom_fields': _parseCustomFields() ?? <dynamic>[],
    'totp': _totpPayload(),
    'totp_uri': _totpUri,
  };

  /// `entries_update` patch. Empty secrets are omitted so they keep their
  /// stored value instead of being overwritten with a blank.
  Map<String, dynamic> toPatch() {
    final parsed = _parseCustomFields();
    return <String, dynamic>{
      'title': title.trim(),
      'username': username,
      'url': url.isEmpty ? null : url,
      if (groupId != _originalGroupId) 'group_id': groupId,
      if (password.isNotEmpty) 'password': password,
      if (notes.isNotEmpty) 'notes': notes,
      if (_totpPayload() != null) 'totp': _totpPayload(),
      if (_totpUri != null) 'totp_uri': _totpUri,
      if (parsed != null) 'custom_fields': parsed,
    };
  }

  /// Removes the secret material a draft accumulated.
  void wipeSecrets() {
    password = '';
    notes = '';
    totp = '';
    customFields = '';
  }
}
