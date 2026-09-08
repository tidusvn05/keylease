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
    );
  }

  final LocalRuntimeState state;
  final bool legacyAvailable;
  final String? legacyDatabase;
  final String? serviceVersion;
}

abstract class LocalRuntimeAdapter {
  Future<LocalRuntimeInspection> inspect();
  Future<String?> chooseVaultSource();
  Future<Map<String, dynamic>> inspectSource(String path);
  Future<void> provision(Map<String, dynamic> request);
  Future<void> ensureService();
  Future<void> restartService();
  Future<void> openLoginItemsSettings();
  Future<void> openDataFolder();
}

class MethodChannelLocalRuntimeAdapter implements LocalRuntimeAdapter {
  const MethodChannelLocalRuntimeAdapter([
    this.channel = const MethodChannel('com.keylease/runtime'),
  ]);

  final MethodChannel channel;

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
}
