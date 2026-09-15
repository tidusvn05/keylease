import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:leasegate_mobile/platform/android_biometric_vault.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  test('biometric enrollment and unlock use the dedicated native channel', () async {
    const channel = MethodChannel('test.biometric');
    final calls = <MethodCall>[];
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) async {
          calls.add(call);
          return switch (call.method) {
            'isAvailable' || 'hasCredential' || 'enable' => true,
            'unlock' => 'master-password',
            _ => null,
          };
        });
    const adapter = AndroidBiometricVault(channel);

    expect(await adapter.isAvailable(), isTrue);
    expect(await adapter.hasCredential('vault_1'), isTrue);
    await adapter.enable('vault_1', 'master-password');
    expect(await adapter.unlock('vault_1'), 'master-password');

    expect(calls.map((call) => call.method), [
      'isAvailable',
      'hasCredential',
      'enable',
      'unlock',
    ]);
    expect(calls[2].arguments, {
      'vault_id': 'vault_1',
      'password': 'master-password',
    });
  });
}
