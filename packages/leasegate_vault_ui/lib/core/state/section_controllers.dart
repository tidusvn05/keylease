import 'package:flutter/foundation.dart';

import '../models/models.dart';
import '../rpc/keylease_client.dart';
import 'busy_registry.dart';
import 'user_message.dart';

/// Shared loading/error plumbing for the read-mostly sections.
abstract class SectionController<T> extends ChangeNotifier with BusyRegistry {
  SectionController(this.clientOf);

  final KeyLeaseClient Function() clientOf;

  List<T> items = const [];
  UserMessage? error;
  bool loaded = false;
  bool loading = false;

  KeyLeaseClient get client => clientOf();

  @protected
  Future<List<T>> fetch();

  Future<void> load() async {
    loading = true;
    notifyListeners();
    try {
      items = await fetch();
      error = null;
      loaded = true;
    } catch (caught) {
      error = UserMessage.from(caught);
    } finally {
      loading = false;
      notifyListeners();
    }
  }

  void clear() {
    items = const [];
    error = null;
    loaded = false;
    loading = false;
    notifyListeners();
  }
}

class ConnectionsController extends SectionController<ConnectionSummary> {
  ConnectionsController(super.client);

  @override
  Future<List<ConnectionSummary>> fetch() async => parseList(
    await client.authorized({'command': 'connections_list'}),
    ConnectionSummary.fromJson,
  );

  Future<void> manage(ConnectionSummary connection, String operation) async {
    await client.authorized({
      'command': 'connection_$operation',
      'id': connection.id,
    });
    await load();
  }

  Future<void> setResource(
    ConnectionSummary connection,
    String resource, {
    required bool enrolled,
  }) async {
    await client.authorized({
      'command': enrolled ? 'connection_enroll' : 'connection_unenroll',
      'id': connection.id,
      'resource': resource,
    });
    await load();
  }

  Future<void> add({
    required String provider,
    required String credential,
    required List<String> authorizedResources,
  }) async {
    await client.authorized({
      'command': 'connection_add',
      'provider': provider,
      'credential': credential,
      'authorized_resources': authorizedResources,
    });
    await load();
  }

  Future<Map<String, dynamic>> beginGoogleOauth({
    required String clientId,
    String? clientSecret,
  }) async {
    final result = await client.authorized({
      'command': 'connection_google_oauth_begin',
      'client_id': clientId,
      'client_secret': clientSecret == null || clientSecret.isEmpty
          ? null
          : clientSecret,
    });
    return Map<String, dynamic>.from(result as Map);
  }

  Future<void> completeGoogleOauth(String flowId) async {
    await client.authorized({
      'command': 'connection_google_oauth_complete',
      'flow_id': flowId,
    });
    await load();
  }
}

/// Raised when an approval decision no longer matches the pending request.
class StaleApprovalException implements Exception {
  const StaleApprovalException(this.message);

  final String message;

  @override
  String toString() => message;
}

class ApprovalsController extends SectionController<ApprovalSummary> {
  ApprovalsController(super.client);

  @override
  Future<List<ApprovalSummary>> fetch() async => parseList(
    await client.authorized({'command': 'approvals_list', 'limit': 100}),
    ApprovalSummary.fromJson,
  );

  /// Re-reads the pending list and refuses to decide on a request that has
  /// expired, been decided elsewhere, or whose digest changed.
  Future<void> decide(
    ApprovalSummary approval, {
    required bool approve,
    DateTime? now,
  }) async {
    final current = await fetch();
    items = current;
    notifyListeners();
    final match = current.where((item) => item.id == approval.id).firstOrNull;
    if (match == null || !match.sameRequestAs(approval)) {
      throw const StaleApprovalException(
        'This request is no longer pending. The list has been refreshed.',
      );
    }
    if (!match.decidableAt(now ?? DateTime.now())) {
      throw const StaleApprovalException(
        'This request expired before the decision was sent.',
      );
    }
    await client.authorized({
      'command': 'approval_decide',
      'id': approval.id,
      'approve': approve,
    });
    await load();
  }
}

class ActivityController extends SectionController<ActivityEvent> {
  ActivityController(super.client);

  bool deniedOnly = false;

  @override
  Future<List<ActivityEvent>> fetch() async => parseList(
    await client.authorized({'command': 'audit_query', 'limit': 200}),
    ActivityEvent.fromJson,
  );

  List<ActivityEvent> get filtered => deniedOnly
      ? items.where((event) => event.denied).toList(growable: false)
      : items;

  void setDeniedOnly({required bool value}) {
    if (deniedOnly == value) return;
    deniedOnly = value;
    notifyListeners();
  }
}

extension<T> on Iterable<T> {
  T? get firstOrNull {
    final iterator = this.iterator;
    return iterator.moveNext() ? iterator.current : null;
  }
}
