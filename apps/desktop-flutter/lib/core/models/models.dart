/// Typed views over the local IPC payloads.
///
/// Every field here exists in the daemon contract; UI-only guesses never enter
/// these models.
library;

import 'package:flutter/foundation.dart';

T? _string<T>(Object? value) => value is T ? value : null;

DateTime? _time(Object? value) =>
    value is String ? DateTime.tryParse(value)?.toLocal() : null;

List<String> _strings(Object? value) => value is List
    ? value.map((item) => '$item').toList(growable: false)
    : const <String>[];

/// `status` result. See `KeyLeaseService::status`.
@immutable
class VaultStatus {
  const VaultStatus({
    required this.locked,
    this.requiresUserAction = false,
    this.vaultId,
    this.idleExpiresAt,
  });

  factory VaultStatus.fromJson(Map<String, dynamic> json) => VaultStatus(
    locked: json['locked'] != false,
    requiresUserAction: json['requires_user_action'] == true,
    vaultId: _string<String>(json['vault_id']),
    idleExpiresAt: _time(json['idle_expires_at']),
  );

  final bool locked;
  final bool requiresUserAction;
  final String? vaultId;
  final DateTime? idleExpiresAt;
}

/// `groups_list` element. See `VaultGroup`.
@immutable
class VaultGroup {
  const VaultGroup({
    required this.id,
    required this.name,
    required this.revision,
    this.parentId,
    this.sortOrder,
  });

  factory VaultGroup.fromJson(Map<String, dynamic> json) => VaultGroup(
    id: '${json['id']}',
    name: _string<String>(json['name']) ?? 'Group',
    revision: (json['revision'] as num?)?.toInt() ?? 0,
    parentId: _string<String>(json['parent_id']),
    sortOrder: (json['sort_order'] as num?)?.toInt(),
  );

  final String id;
  final String name;
  final int revision;
  final String? parentId;
  final int? sortOrder;
}

/// `entries_search` / `entries_get` element. See `ItemMetadata`.
@immutable
class EntrySummary {
  const EntrySummary({
    required this.id,
    required this.groupId,
    required this.kind,
    required this.title,
    required this.revision,
    this.username,
    this.urls = const [],
    this.hasPassword = false,
    this.hasNotes = false,
    this.hasTotp = false,
    this.favorite = false,
    this.updatedAt,
  });

  factory EntrySummary.fromJson(Map<String, dynamic> json) => EntrySummary(
    id: '${json['id']}',
    groupId: '${json['group_id']}',
    kind: _string<String>(json['kind']) ?? 'core.generic',
    title: _string<String>(json['title']) ?? 'Untitled',
    revision: (json['revision'] as num?)?.toInt() ?? 0,
    username: _string<String>(json['username']),
    urls: _strings(json['urls']),
    hasPassword: json['has_password'] == true,
    hasNotes: json['has_notes'] == true,
    hasTotp: json['has_totp'] == true,
    favorite: json['favorite'] == true,
    updatedAt: _time(json['updated_at']),
  );

  final String id;
  final String groupId;
  final String kind;
  final String title;
  final int revision;
  final String? username;
  final List<String> urls;
  final bool hasPassword;
  final bool hasNotes;
  final bool hasTotp;
  final bool favorite;
  final DateTime? updatedAt;

  String? get primaryUrl => urls.isEmpty ? null : urls.first;

  /// Monogram used by the list and detail marks.
  String get monogram {
    final trimmed = title.trim();
    if (trimmed.isEmpty) return '?';
    final words = trimmed.split(RegExp(r'\s+'));
    if (words.length > 1 && words[1].isNotEmpty) {
      return '${words[0][0]}${words[1][0]}'.toUpperCase();
    }
    return (trimmed.length > 1 ? trimmed.substring(0, 2) : trimmed)
        .toUpperCase();
  }

  String get subtitle => [
    if (username != null && username!.isNotEmpty) username!,
    ...urls,
  ].join(' · ');
}

/// A field from `entries_view`. Protected values are intentionally absent
/// until the user explicitly reveals or copies the field.
@immutable
class EntryFieldView {
  const EntryFieldView({
    required this.id,
    required this.key,
    required this.label,
    required this.valueType,
    required this.sensitivity,
    required this.protected,
    required this.hasValue,
    this.semanticRole,
    this.value,
    this.displayHint,
  });

  factory EntryFieldView.fromJson(Map<String, dynamic> json) => EntryFieldView(
    id: '${json['id']}',
    key: _string<String>(json['key']) ?? '',
    label:
        _string<String>(json['label']) ??
        _string<String>(json['key']) ??
        'Field',
    semanticRole: _string<String>(json['semantic_role']),
    valueType: _string<String>(json['value_type']) ?? 'text',
    sensitivity: _string<String>(json['sensitivity']) ?? 'private_metadata',
    protected: json['protected'] == true,
    hasValue: json['has_value'] == true,
    value: json['value'],
    displayHint: _string<String>(json['display_hint']),
  );

  final String id;
  final String key;
  final String label;
  final String? semanticRole;
  final String valueType;
  final String sensitivity;
  final bool protected;
  final bool hasValue;
  final Object? value;
  final String? displayHint;

  EntryFieldView withValue(Object? next) => EntryFieldView(
    id: id,
    key: key,
    label: label,
    semanticRole: semanticRole,
    valueType: valueType,
    sensitivity: sensitivity,
    protected: protected,
    hasValue: hasValue,
    value: next,
    displayHint: displayHint,
  );

  String get displayValue {
    if (value == null) return displayHint ?? (hasValue ? 'Stored' : '');
    final envelope = value;
    if (envelope is! Map) return '$envelope';
    final type = '${envelope['type']}';
    final content = envelope['value'];
    if (type == 'month_year' && content is Map) {
      final month = (content['month'] as num?)?.toInt();
      final year = (content['year'] as num?)?.toInt();
      if (month != null && year != null) {
        return '${month.toString().padLeft(2, '0')}/$year';
      }
    }
    if (type == 'address' && content is Map) {
      return content.values
          .where((part) => part != null && '$part'.trim().isNotEmpty)
          .map((part) => '$part')
          .join(', ');
    }
    if (content is Map || content is List) return '$content';
    return content?.toString() ?? '';
  }
}

/// Full, field-oriented entry projection used by the detail pane.
@immutable
class EntryDetailView {
  const EntryDetailView({
    required this.metadata,
    required this.templateVersion,
    required this.tags,
    required this.sections,
    required this.fields,
    this.projectId,
    this.hasNotes = false,
  });

  factory EntryDetailView.fromJson(Map<String, dynamic> json) =>
      EntryDetailView(
        metadata: EntrySummary.fromJson(
          Map<String, dynamic>.from(json['metadata'] as Map),
        ),
        templateVersion: (json['template_version'] as num?)?.toInt() ?? 1,
        projectId: _string<String>(json['project_id']),
        tags: _strings(json['tags']),
        sections: parseList(json['sections'], EntrySectionView.fromJson),
        fields: parseList(json['fields'], EntryFieldView.fromJson),
        hasNotes: json['has_notes'] == true,
      );

  final EntrySummary metadata;
  final int templateVersion;
  final String? projectId;
  final List<String> tags;
  final List<EntrySectionView> sections;
  final List<EntryFieldView> fields;
  final bool hasNotes;
}

@immutable
class EntrySectionView {
  const EntrySectionView({
    required this.id,
    required this.label,
    required this.fieldIds,
    this.semanticRole,
  });

  factory EntrySectionView.fromJson(Map<String, dynamic> json) =>
      EntrySectionView(
        id: '${json['id']}',
        label: _string<String>(json['label']) ?? 'Details',
        fieldIds: _strings(json['field_ids']),
        semanticRole: _string<String>(json['semantic_role']),
      );

  final String id;
  final String label;
  final List<String> fieldIds;
  final String? semanticRole;

  Map<String, dynamic> toJson() => {
    'id': id,
    'label': label,
    'field_ids': fieldIds,
    'semantic_role': semanticRole,
  };
}

@immutable
class TemplateDefinition {
  const TemplateDefinition({
    required this.kind,
    required this.label,
    required this.family,
    required this.markdownNotes,
    required this.fields,
  });

  factory TemplateDefinition.fromJson(Map<String, dynamic> json) =>
      TemplateDefinition(
        kind: '${json['kind']}',
        label: _string<String>(json['label']) ?? '${json['kind']}',
        family: _string<String>(json['family']) ?? 'other',
        markdownNotes: json['markdown_notes'] == true,
        fields: parseList(json['fields'], TemplateFieldDefinition.fromJson),
      );

  final String kind;
  final String label;
  final String family;
  final bool markdownNotes;
  final List<TemplateFieldDefinition> fields;
}

@immutable
class TemplateFieldDefinition {
  const TemplateFieldDefinition({
    required this.key,
    required this.label,
    required this.valueType,
    required this.semanticRole,
    required this.sensitivity,
    required this.protected,
    required this.section,
  });

  factory TemplateFieldDefinition.fromJson(Map<String, dynamic> json) =>
      TemplateFieldDefinition(
        key: '${json['key']}',
        label: '${json['label']}',
        valueType: _string<String>(json['value_type']) ?? 'text',
        semanticRole:
            _string<String>(json['semantic_role']) ?? '${json['key']}',
        sensitivity: _string<String>(json['sensitivity']) ?? 'private_metadata',
        protected: json['protected'] == true,
        section: _string<String>(json['section']) ?? 'Details',
      );

  final String key;
  final String label;
  final String valueType;
  final String semanticRole;
  final String sensitivity;
  final bool protected;
  final String section;
}

@immutable
class VaultProjectModel {
  const VaultProjectModel({
    required this.id,
    required this.slug,
    required this.name,
  });

  factory VaultProjectModel.fromJson(
    Map<String, dynamic> json,
  ) => VaultProjectModel(
    id: '${json['id']}',
    slug: _string<String>(json['slug']) ?? '',
    name: _string<String>(json['name']) ?? _string<String>(json['slug']) ?? '',
  );

  final String id;
  final String slug;
  final String name;
}

@immutable
class MigrationProposalModel {
  const MigrationProposalModel({
    required this.itemId,
    required this.title,
    required this.currentKind,
    required this.proposedKind,
    required this.confidence,
    required this.reasons,
    required this.expectedRevision,
  });

  factory MigrationProposalModel.fromJson(Map<String, dynamic> json) =>
      MigrationProposalModel(
        itemId: '${json['item_id']}',
        title: _string<String>(json['title']) ?? 'Untitled',
        currentKind: _string<String>(json['current_kind']) ?? 'core.generic',
        proposedKind: _string<String>(json['proposed_kind']) ?? 'core.generic',
        confidence: _string<String>(json['confidence']) ?? 'unknown',
        reasons: _strings(json['reasons']),
        expectedRevision: (json['expected_revision'] as num?)?.toInt() ?? 0,
      );

  final String itemId;
  final String title;
  final String currentKind;
  final String proposedKind;
  final String confidence;
  final List<String> reasons;
  final int expectedRevision;
}

@immutable
class MigrationPreviewModel {
  const MigrationPreviewModel({
    required this.id,
    required this.version,
    required this.title,
    required this.type,
    required this.digest,
    required this.proposals,
  });

  factory MigrationPreviewModel.fromJson(Map<String, dynamic> json) =>
      MigrationPreviewModel(
        id: '${json['migration_id']}',
        version: (json['version'] as num?)?.toInt() ?? 1,
        title: _string<String>(json['title']) ?? '${json['migration_id']}',
        type: _string<String>(json['migration_type']) ?? 'semantic',
        digest: _string<String>(json['preview_digest']) ?? '',
        proposals: parseList(
          json['proposals'],
          MigrationProposalModel.fromJson,
        ),
      );

  final String id;
  final int version;
  final String title;
  final String type;
  final String digest;
  final List<MigrationProposalModel> proposals;
}

@immutable
class MigrationStatusModel {
  const MigrationStatusModel({
    required this.frameworkVersion,
    required this.pending,
    required this.history,
  });

  factory MigrationStatusModel.fromJson(Map<String, dynamic> json) =>
      MigrationStatusModel(
        frameworkVersion: (json['framework_version'] as num?)?.toInt() ?? 1,
        pending: parseList(json['pending'], MigrationPreviewModel.fromJson),
        history: parseList(json['history'], MigrationHistoryModel.fromJson),
      );

  final int frameworkVersion;
  final List<MigrationPreviewModel> pending;
  final List<MigrationHistoryModel> history;
}

@immutable
class MigrationHistoryModel {
  const MigrationHistoryModel({
    required this.id,
    required this.version,
    required this.state,
    required this.itemCount,
    this.appliedAt,
    this.rolledBackAt,
  });

  factory MigrationHistoryModel.fromJson(Map<String, dynamic> json) =>
      MigrationHistoryModel(
        id: '${json['migration_id']}',
        version: (json['version'] as num?)?.toInt() ?? 1,
        state: _string<String>(json['state']) ?? 'unknown',
        itemCount: (json['item_count'] as num?)?.toInt() ?? 0,
        appliedAt: _time(json['applied_at']),
        rolledBackAt: _time(json['rolled_back_at']),
      );

  final String id;
  final int version;
  final String state;
  final int itemCount;
  final DateTime? appliedAt;
  final DateTime? rolledBackAt;
}

/// `connections_list` element. See `ConnectionRecord`.
@immutable
class ConnectionSummary {
  const ConnectionSummary({
    required this.id,
    required this.provider,
    required this.health,
    required this.authMethod,
    required this.trustMode,
    required this.executionLocation,
    required this.authorizedResources,
    this.healthReason,
    this.reauthorizationRequired = false,
    this.grantedPermissions = const [],
    this.lastCheckedAt,
    this.lastRefreshedAt,
  });

  factory ConnectionSummary.fromJson(Map<String, dynamic> json) =>
      ConnectionSummary(
        id: '${json['id']}',
        provider: _string<String>(json['provider']) ?? 'unknown',
        health: _string<String>(json['health']) ?? 'unknown',
        authMethod: _string<String>(json['auth_method']) ?? 'unknown',
        trustMode: _string<String>(json['trust_mode']) ?? 'unknown',
        executionLocation:
            _string<String>(json['execution_location']) ?? 'unknown',
        authorizedResources: _strings(json['authorized_resources']),
        healthReason: _string<String>(json['health_reason']),
        reauthorizationRequired: json['reauthorization_required'] == true,
        grantedPermissions: _strings(json['granted_permissions']),
        lastCheckedAt: _time(json['last_checked_at']),
        lastRefreshedAt: _time(json['last_refreshed_at']),
      );

  final String id;
  final String provider;
  final String health;
  final String authMethod;
  final String trustMode;
  final String executionLocation;
  final List<String> authorizedResources;
  final String? healthReason;
  final bool reauthorizationRequired;
  final List<String> grantedPermissions;
  final DateTime? lastCheckedAt;
  final DateTime? lastRefreshedAt;
}

/// `approvals_list` element. See `ApprovalRecord`.
@immutable
class ApprovalSummary {
  const ApprovalSummary({
    required this.id,
    required this.requestDigestHex,
    required this.policyVersion,
    required this.state,
    required this.expiresAt,
    this.agentId,
    this.action,
    this.resource,
    this.risk,
    this.createdAt,
    this.operation,
    this.target,
    this.changedFields = const [],
    this.blastRadius,
  });

  factory ApprovalSummary.fromJson(Map<String, dynamic> json) {
    final summary = json['semantic_summary'];
    final semantic = summary is Map ? Map<String, dynamic>.from(summary) : null;
    return ApprovalSummary(
      id: '${json['id']}',
      requestDigestHex: _string<String>(json['request_digest_hex']) ?? '',
      policyVersion: (json['policy_version'] as num?)?.toInt() ?? 0,
      state: _string<String>(json['state']) ?? 'pending',
      expiresAt:
          _time(json['expires_at']) ??
          DateTime.fromMillisecondsSinceEpoch(0, isUtc: true).toLocal(),
      agentId: _string<String>(json['agent_id']),
      action: _string<String>(json['action']),
      resource: _string<String>(json['resource']),
      risk: _string<String>(json['risk']),
      createdAt: _time(json['created_at']),
      operation: semantic == null
          ? null
          : _string<String>(semantic['operation']),
      target: semantic == null ? null : _string<String>(semantic['target']),
      changedFields: semantic == null
          ? const []
          : _strings(semantic['changed_fields']),
      blastRadius: semantic == null
          ? null
          : _string<String>(semantic['blast_radius']),
    );
  }

  final String id;
  final String requestDigestHex;
  final int policyVersion;
  final String state;
  final DateTime expiresAt;
  final String? agentId;
  final String? action;
  final String? resource;
  final String? risk;
  final DateTime? createdAt;
  final String? operation;
  final String? target;
  final List<String> changedFields;
  final String? blastRadius;

  bool get isPending => state == 'pending';

  bool decidableAt(DateTime now) => isPending && expiresAt.isAfter(now);

  /// The exact request this decision would bind to.
  bool sameRequestAs(ApprovalSummary other) =>
      id == other.id &&
      requestDigestHex == other.requestDigestHex &&
      policyVersion == other.policyVersion;
}

/// `audit_query` element. See `AuditEvent`.
@immutable
class ActivityEvent {
  const ActivityEvent({
    required this.action,
    required this.resource,
    required this.decision,
    required this.outcome,
    required this.agentId,
    this.timestamp,
    this.policyVersion,
    this.itemCount,
    this.cellCount,
    this.byteCount,
    this.changedFields = const [],
    this.connector,
  });

  factory ActivityEvent.fromJson(Map<String, dynamic> json) => ActivityEvent(
    action: _string<String>(json['action']) ?? 'unknown',
    resource: _string<String>(json['resource']) ?? '',
    decision: _string<String>(json['decision']) ?? 'unknown',
    outcome: _string<String>(json['outcome']) ?? 'unknown',
    agentId: _string<String>(json['agent_id']) ?? 'unknown client',
    timestamp: _time(json['timestamp']),
    policyVersion: (json['policy_version'] as num?)?.toInt(),
    itemCount: (json['item_count'] as num?)?.toInt(),
    cellCount: (json['cell_count'] as num?)?.toInt(),
    byteCount: (json['byte_count'] as num?)?.toInt(),
    changedFields: _strings(json['changed_fields']),
    connector: _string<String>(json['connector']),
  );

  final String action;
  final String resource;
  final String decision;
  final String outcome;
  final String agentId;
  final DateTime? timestamp;
  final int? policyVersion;
  final int? itemCount;
  final int? cellCount;
  final int? byteCount;
  final List<String> changedFields;
  final String? connector;

  bool get denied => decision != 'allow' || outcome != 'success';

  String get volume => [
    if (itemCount != null) '$itemCount items',
    if (cellCount != null) '$cellCount cells',
    if (byteCount != null) '$byteCount bytes',
  ].join(' · ');
}

/// `entries_history` element.
@immutable
class EntryRevision {
  const EntryRevision({required this.revision, this.updatedAt});

  factory EntryRevision.fromJson(Map<String, dynamic> json) => EntryRevision(
    revision: (json['revision'] as num?)?.toInt() ?? 0,
    updatedAt: _time(json['updated_at']),
  );

  final int revision;
  final DateTime? updatedAt;
}

List<T> parseList<T>(Object? value, T Function(Map<String, dynamic>) parse) =>
    value is List
    ? value
          .whereType<Map>()
          .map((item) => parse(Map<String, dynamic>.from(item)))
          .toList(growable: false)
    : const [];
