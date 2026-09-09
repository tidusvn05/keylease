import 'dart:async';

import 'package:flutter/services.dart';

class BackgroundApprovalRequired implements Exception {
  const BackgroundApprovalRequired();
}

enum LocalRuntimeState { needsOnboarding, ready, repairRequired }

class LocalRuntimeInspection {
  const LocalRuntimeInspection({
    required this.state,
    this.legacyAvailable = false,
    this.legacyDatabase,
    this.serviceVersion,
    this.tokenPath,
  });

  factory LocalRuntimeInspection.fromJson(Map<String, dynamic> json) {
    final raw = json['state'] as String? ?? 'needs_onboarding';
    return LocalRuntimeInspection(
      state: switch (raw) {
        'ready' => LocalRuntimeState.ready,
        'repair_required' => LocalRuntimeState.repairRequired,
        _ => LocalRuntimeState.needsOnboarding,
      },
      legacyAvailable: json['legacy_available'] == true,
      legacyDatabase: json['legacy_database'] as String?,
      serviceVersion: json['service_version'] as String?,
      tokenPath: json['token_path'] as String?,
    );
  }

  final LocalRuntimeState state;
  final bool legacyAvailable;
  final String? legacyDatabase;
  final String? serviceVersion;
  final String? tokenPath;
}

class LocalVaultProfile {
  const LocalVaultProfile({
    required this.id,
    required this.name,
    required this.active,
  });

  factory LocalVaultProfile.fromJson(
    Map<String, dynamic> json,
    String activeId,
  ) => LocalVaultProfile(
    id: '${json['id']}',
    name: '${json['name']}',
    active: '${json['id']}' == activeId,
  );

  final String id;
  final String name;
  final bool active;
}

abstract class LocalRuntimeAdapter {
  Stream<void> get vaultChanges;
  Future<LocalRuntimeInspection> inspect();
  Future<String?> chooseVaultSource();
  Future<Map<String, dynamic>> inspectSource(String path);
  Future<void> provision(Map<String, dynamic> request);
  Future<void> ensureService();
  Future<void> restartService();
  Future<void> openLoginItemsSettings();
  Future<void> openDataFolder();
  Future<List<LocalVaultProfile>> listVaults();
  Future<void> createVault(String name, Map<String, dynamic> request);
  Future<void> switchVault(String id);
  Future<void> publishVaultChange();
  Future<void> renameVault(String id, String name);
  Future<void> dispose();
}

class MethodChannelLocalRuntimeAdapter implements LocalRuntimeAdapter {
  MethodChannelLocalRuntimeAdapter([
    this.channel = const MethodChannel('com.keylease/runtime'),
  ]) {
    channel.setMethodCallHandler(_handleNativeCall);
  }

  final MethodChannel channel;
  final _vaultChanges = StreamController<void>.broadcast();

  @override
  Stream<void> get vaultChanges => _vaultChanges.stream;

  Future<Object?> _handleNativeCall(MethodCall call) async {
    if (call.method == 'vaultChanged') {
      _vaultChanges.add(null);
    }
    return null;
  }

  @override
  Future<LocalRuntimeInspection> inspect() async =>
      LocalRuntimeInspection.fromJson(
        Map<String, dynamic>.from(
          (await channel.invokeMethod<Object?>('inspect')) as Map,
        ),
      );

  @override
  Future<String?> chooseVaultSource() =>
      channel.invokeMethod<String>('chooseVaultSource');

  @override
  Future<Map<String, dynamic>> inspectSource(String path) async =>
      Map<String, dynamic>.from(
        (await channel.invokeMethod<Object?>('inspectSource', {'path': path}))
            as Map,
      );

  @override
  Future<void> provision(Map<String, dynamic> request) =>
      channel.invokeMethod<void>('provision', request);

  @override
  Future<void> ensureService() async {
    try {
      await channel.invokeMethod<void>('ensureService');
    } on PlatformException catch (error) {
      if (error.code == 'BACKGROUND_APPROVAL_REQUIRED') {
        throw const BackgroundApprovalRequired();
      }
      rethrow;
    }
  }

  @override
  Future<void> restartService() async {
    try {
      await channel.invokeMethod<void>('restartService');
    } on PlatformException catch (error) {
      if (error.code == 'BACKGROUND_APPROVAL_REQUIRED') {
        throw const BackgroundApprovalRequired();
      }
      rethrow;
    }
  }

  @override
  Future<void> openLoginItemsSettings() =>
      channel.invokeMethod<void>('openLoginItemsSettings');

  @override
  Future<void> openDataFolder() => channel.invokeMethod<void>('openDataFolder');

  @override
  Future<List<LocalVaultProfile>> listVaults() async {
    final raw = Map<String, dynamic>.from(
      (await channel.invokeMethod<Object?>('listVaults')) as Map,
    );
    final active = '${raw['active_id']}';
    return (raw['profiles'] as List? ?? const [])
        .map(
          (value) => LocalVaultProfile.fromJson(
            Map<String, dynamic>.from(value as Map),
            active,
          ),
        )
        .toList(growable: false);
  }

  @override
  Future<void> createVault(String name, Map<String, dynamic> request) => channel
      .invokeMethod<void>('createVault', {'name': name, 'request': request});

  @override
  Future<void> switchVault(String id) =>
      channel.invokeMethod<void>('switchVault', {'id': id});

  @override
  Future<void> publishVaultChange() =>
      channel.invokeMethod<void>('publishVaultChange');

  @override
  Future<void> renameVault(String id, String name) =>
      channel.invokeMethod<void>('renameVault', {'id': id, 'name': name});

  @override
  Future<void> dispose() async {
    channel.setMethodCallHandler(null);
    await _vaultChanges.close();
  }
}
