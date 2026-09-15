import 'package:flutter/services.dart';
import 'package:leasegate_vault_ui/core/platform/security_adapter.dart';

class AndroidBiometricVault implements BiometricVaultAdapter {
  const AndroidBiometricVault([
    this.channel = const MethodChannel('com.keylease/biometric'),
  ]);

  final MethodChannel channel;

  @override
  Future<bool> isAvailable() async =>
      await channel.invokeMethod<bool>('isAvailable') ?? false;

  @override
  Future<bool> hasCredential(String vaultId) async =>
      await channel.invokeMethod<bool>('hasCredential', {'vault_id': vaultId}) ??
      false;

  @override
  Future<void> enable(String vaultId, String password) async {
    await channel.invokeMethod<bool>('enable', {
      'vault_id': vaultId,
      'password': password,
    });
  }

  @override
  Future<String?> unlock(String vaultId) =>
      channel.invokeMethod<String>('unlock', {'vault_id': vaultId});

  @override
  Future<void> disable(String vaultId) async {
    await channel.invokeMethod<bool>('disable', {'vault_id': vaultId});
  }
}
