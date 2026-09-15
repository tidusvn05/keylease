import 'dart:io';

import 'package:flutter/services.dart';
import 'package:flutter/widgets.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:leasegate_mobile/platform/android_security_adapter.dart';
import 'package:leasegate_mobile/platform/app_preferences_store.dart';
import 'package:leasegate_mobile/platform/ffi_local_runtime_adapter.dart';
import 'package:leasegate_vault_ui/core/platform/local_runtime_adapter.dart';
import 'package:leasegate_vault_ui/core/platform/security_adapter.dart';

class _FakeStorage implements VaultStorage {
  _FakeStorage({this.exists = true});

  bool exists;
  final calls = <String>[];

  @override
  Future<bool> vaultExists() async => exists;

  @override
  Future<String?> serviceVersion() async => '0.1.0';

  @override
  Future<List<LocalVaultProfile>> listVaults() async => const [];

  @override
  Future<Map<String, dynamic>> provision(Map<String, dynamic> request) async {
    calls.add('provision:${request['provision']}');
    return {'ok': true};
  }

  @override
  Future<void> switchVault(String id) async => calls.add('switch:$id');

  @override
  Future<void> createVault(String name, Map<String, dynamic> request) async =>
      calls.add('create:$name');

  @override
  Future<void> renameVault(String id, String name) async =>
      calls.add('rename:$id');

  @override
  Future<String?> importBackupFile() async => '/tmp/backup';
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  group('AndroidSecurityAdapter', () {
    late List<MethodCall> calls;
    late AndroidSecurityAdapter adapter;

    setUp(() {
      calls = [];
      const channel = MethodChannel('com.keylease/security');
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, (call) async {
            calls.add(call);
            return true;
          });
      adapter = AndroidSecurityAdapter(idleTimeout: const Duration(days: 1));
    });

    tearDown(() async => adapter.dispose());

    test('copying a secret goes to the native clipboard with a clear delay', () async {
      // Deliberately not Clipboard.setData: a Dart timer dies with the engine,
      // so the clear-after guarantee has to live in Kotlin.
      await adapter.copySensitive(
        's3cret',
        clearAfter: const Duration(seconds: 30),
      );
      expect(calls.single.method, 'copySensitive');
      expect(calls.single.arguments['value'], 's3cret');
      expect(calls.single.arguments['clear_after_seconds'], 30);
    });

    test('backgrounding the app asks for a lock', () async {
      final locks = <LockTrigger>[];
      final subscription = adapter.lockRequests.listen(locks.add);
      addTearDown(subscription.cancel);

      // Drives the real observer rather than a test-only hook.
      TestWidgetsFlutterBinding.instance.handleAppLifecycleStateChanged(
        AppLifecycleState.paused,
      );
      await Future<void>.delayed(Duration.zero);
      expect(locks, isNotEmpty);
    });

    test('a transient inactive state does not lock', () async {
      // `inactive` fires for a system dialog or the app switcher preview.
      // Locking there would make the app unusable.
      final locks = <LockTrigger>[];
      final subscription = adapter.lockRequests.listen(locks.add);
      addTearDown(subscription.cancel);

      TestWidgetsFlutterBinding.instance.handleAppLifecycleStateChanged(
        AppLifecycleState.inactive,
      );
      await Future<void>.delayed(Duration.zero);
      expect(locks, isEmpty);
    });

    test(
      'capabilities with no Android implementation fail with a typed error',
      () {
        // The UI renders these as a message rather than crashing.
        expect(
          adapter.scanTotpQrCodeFromScreen,
          throwsA(isA<UnsupportedPlatformCapability>()),
        );
        expect(
          adapter.discoverSshPrivateKeys,
          throwsA(isA<UnsupportedPlatformCapability>()),
        );
        expect(
          adapter.selectClientToken,
          throwsA(isA<UnsupportedPlatformCapability>()),
        );
      },
    );

    test('the settings window falls back to the in-shell section', () async {
      expect(await adapter.openSettingsWindow(), isFalse);
    });

    test('there is no menu bar to listen to', () async {
      expect(await adapter.menuActions.isEmpty, isTrue);
    });
  });

  group('FfiLocalRuntimeAdapter', () {
    test('an existing vault reports ready with no token path', () async {
      final adapter = FfiLocalRuntimeAdapter(_FakeStorage(exists: true));
      final inspection = await adapter.inspect();
      expect(inspection.state, LocalRuntimeState.ready);
      expect(
        inspection.tokenPath,
        isNull,
        reason: 'the owner credential never leaves the Rust side',
      );
    });

    test('no vault yet means onboarding', () async {
      final adapter = FfiLocalRuntimeAdapter(_FakeStorage(exists: false));
      expect(
        (await adapter.inspect()).state,
        LocalRuntimeState.needsOnboarding,
      );
    });

    test('desktop-shaped onboarding requests map to the mobile lifecycle channel', () async {
      final storage = _FakeStorage(exists: false);
      final adapter = FfiLocalRuntimeAdapter(storage);

      await adapter.provision({'mode': 'create', 'password': 'long-password'});
      await adapter.inspectSource('/private/import.source');

      expect(storage.calls, [
        'provision:create',
        'provision:inspect_source',
      ]);
    });

    test('service lifecycle is inert because there is no daemon', () async {
      final storage = _FakeStorage();
      final adapter = FfiLocalRuntimeAdapter(storage);
      await adapter.ensureService();
      await adapter.restartService();
      await adapter.publishVaultChange();
      expect(storage.calls, isEmpty);
      expect(await adapter.vaultChanges.isEmpty, isTrue);
    });

    test('the data folder is not reachable from a file manager', () {
      final adapter = FfiLocalRuntimeAdapter(_FakeStorage());
      expect(
        adapter.openDataFolder,
        throwsA(isA<UnsupportedPlatformCapability>()),
      );
    });
  });

  group('AppPreferencesStore', () {
    test('round-trips values and survives a missing file', () async {
      final dir = await Directory.systemTemp.createTemp('prefs');
      addTearDown(() => dir.delete(recursive: true));
      final store = AppPreferencesStore(directory: dir.path);

      expect(await store.load(), isEmpty);
      await store.save({'list_width': 320.0});
      expect((await store.load())['list_width'], 320.0);
    });

    test('corrupt preferences do not block start-up', () async {
      final dir = await Directory.systemTemp.createTemp('prefs');
      addTearDown(() => dir.delete(recursive: true));
      await File('${dir.path}/ui.json').writeAsString('{not json');

      expect(await AppPreferencesStore(directory: dir.path).load(), isEmpty);
    });
  });
}
