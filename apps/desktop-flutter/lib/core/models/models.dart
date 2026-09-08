/// Typed views over the local IPC payloads.
///
/// Every field here exists in the daemon contract. Fields the prototype
/// suggested but the contract does not carry (entry favourites, "recently
/// used" ordering, a human display name for a client, and a free-text approval
/// reason) are deliberately absent; see `docs/forui-migration-decisions.md`.
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
  });

  factory VaultGroup.fromJson(Map<String, dynamic> json) => VaultGroup(
    id: '${json['id']}',
    name: _string<String>(json['name']) ?? 'Group',
    revision: (json['revision'] as num?)?.toInt() ?? 0,
    parentId: _string<String>(json['parent_id']),
  );

  final String id;
  final String name;
  final int revision;
  final String? parentId;
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
