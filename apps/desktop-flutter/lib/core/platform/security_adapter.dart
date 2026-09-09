import 'dart:async';
import 'dart:io';

import 'package:flutter/services.dart';

/// Why the host asked the app to lock.
enum LockTrigger { systemSleep, screenLock, unknown }

/// A native menu selection the app has to carry out.
///
/// macOS consumes a menu key equivalent before the Flutter view sees it, so
/// the shortcuts the template menu already owns (Command-F, Command-Comma)
/// have to arrive this way rather than as key events.
enum MenuAction { search, newItem, refresh, settings, lock }

class SshPrivateKeyCandidate {
  const SshPrivateKeyCandidate({required this.path, required this.name});

  factory SshPrivateKeyCandidate.fromJson(Map<dynamic, dynamic> json) =>
      SshPrivateKeyCandidate(path: '${json['path']}', name: '${json['name']}');

  final String path;
  final String name;
}

/// Native capabilities the UI must not re-implement in Dart.
///
/// The macOS implementation lives in `macos/Runner/MainFlutterWindow.swift`
/// and owns the conditional clipboard clear, the security-scoped file picker
/// and the OAuth browser hand-off. The UI never writes secrets to the
/// clipboard itself, so a platform without an adapter fails loudly instead of
/// silently downgrading the guarantee.
abstract class SecurityAdapter {
  /// Emits when the host wants the vault locked (sleep, screen lock).
  Stream<LockTrigger> get lockRequests;

  /// Emits when the user picks a KeyLease item from the native menu bar.
  Stream<MenuAction> get menuActions;

  /// Copies [value] and asks the host to clear it after [clearAfter] unless
  /// the pasteboard changed in the meantime.
  Future<void> copySensitive(String value, {Duration clearAfter});

  /// Clears a previously copied secret if the pasteboard is unchanged.
  Future<void> clearSensitiveClipboard();

  /// Opens the security-scoped picker for the registered client token.
  Future<String?> selectClientToken();

  /// Returns local private-key candidates without exposing file contents.
  Future<List<SshPrivateKeyCandidate>> discoverSshPrivateKeys();

  /// Lets the user choose a private key path for this device.
  Future<String?> selectSshPrivateKey();

  /// Lets the host select an image and returns an otpauth TOTP URI decoded
  /// from its QR code.
  Future<String?> scanTotpQrCode();

  /// Captures the visible displays locally and returns the first TOTP QR code.
  ///
  /// On macOS this requires Screen Recording permission. The captured pixels
  /// never leave the process and are not written to disk.
  Future<String?> scanTotpQrCodeFromScreen();

  /// Opens the operating system's Screen Recording privacy settings.
  Future<bool> openScreenRecordingSettings();

  /// Opens the Google authorization URL in the user's browser.
  Future<bool> openGoogleAuthorization(String url);

  /// Opens an ordinary HTTP(S) URL in the user's default browser.
  Future<bool> openExternalUrl(String url);

  /// Opens the platform settings window when the host provides one.
  ///
  /// Returns false on platforms that keep Settings inside the main shell.
  Future<bool> openSettingsWindow();

  Future<void> dispose();
}

/// Raised when a platform build has no native adapter for a capability.
class UnsupportedPlatformCapability implements Exception {
  const UnsupportedPlatformCapability(this.capability);

  final String capability;

  @override
  String toString() =>
      'This build has no native $capability support on ${Platform.operatingSystem}.';
}

class ScreenRecordingPermissionRequired implements Exception {
  const ScreenRecordingPermissionRequired();

  @override
  String toString() => 'Screen Recording permission is required.';
}

class TotpQrCodeNotFound implements Exception {
  const TotpQrCodeNotFound(this.source);

  final String source;

  @override
  String toString() => 'No TOTP QR code was found in the $source.';
}

class MethodChannelSecurityAdapter implements SecurityAdapter {
  MethodChannelSecurityAdapter([
    this.channel = const MethodChannel('com.keylease/security'),
  ]) {
    channel.setMethodCallHandler(_handle);
  }

  final MethodChannel channel;
  final _lockRequests = StreamController<LockTrigger>.broadcast();
  final _menuActions = StreamController<MenuAction>.broadcast();

  Future<dynamic> _handle(MethodCall call) async {
    switch (call.method) {
      case 'lockRequested':
        _lockRequests.add(switch (call.arguments) {
          'system_sleep' => LockTrigger.systemSleep,
          'screen_lock' => LockTrigger.screenLock,
          _ => LockTrigger.unknown,
        });
      case 'menuAction':
        final action = switch (call.arguments) {
          'search' => MenuAction.search,
          'new_item' => MenuAction.newItem,
          'refresh' => MenuAction.refresh,
          'settings' => MenuAction.settings,
          'lock' => MenuAction.lock,
          _ => null,
        };
        if (action != null) _menuActions.add(action);
    }
    return null;
  }

  @override
  Stream<LockTrigger> get lockRequests => _lockRequests.stream;

  @override
  Stream<MenuAction> get menuActions => _menuActions.stream;

  @override
  Future<void> copySensitive(
    String value, {
    Duration clearAfter = const Duration(seconds: 30),
  }) async {
    try {
      final copied = await channel.invokeMethod<bool>('copySensitive', {
        'value': value,
        'clear_after_seconds': clearAfter.inSeconds,
      });
      if (copied != true) {
        throw const UnsupportedPlatformCapability('clipboard');
      }
    } on MissingPluginException {
      throw const UnsupportedPlatformCapability('clipboard');
    }
  }

  @override
  Future<void> clearSensitiveClipboard() async {
    try {
      await channel.invokeMethod<bool>('clearSensitiveClipboard');
    } on MissingPluginException {
      // Nothing was written through the managed clipboard on this platform.
    }
  }

  @override
  Future<String?> selectClientToken() async {
    try {
      return await channel.invokeMethod<String>('selectClientToken');
    } on MissingPluginException {
      throw const UnsupportedPlatformCapability('file picker');
    }
  }

  @override
  Future<List<SshPrivateKeyCandidate>> discoverSshPrivateKeys() async {
    try {
      final result = await channel.invokeListMethod<dynamic>(
        'discoverSshPrivateKeys',
      );
      return [
        for (final candidate in result ?? const [])
          if (candidate is Map) SshPrivateKeyCandidate.fromJson(candidate),
      ];
    } on MissingPluginException {
      throw const UnsupportedPlatformCapability('SSH private key discovery');
    }
  }

  @override
  Future<String?> selectSshPrivateKey() async {
    try {
      return await channel.invokeMethod<String>('selectSshPrivateKey');
    } on MissingPluginException {
      throw const UnsupportedPlatformCapability('SSH private key picker');
    }
  }

  @override
  Future<String?> scanTotpQrCode() async {
    try {
      return await channel.invokeMethod<String>('scanTotpQrCode');
    } on PlatformException catch (error) {
      if (error.code == 'TOTP_QR_NOT_FOUND') {
        throw const TotpQrCodeNotFound('selected image');
      }
      rethrow;
    } on MissingPluginException {
      throw const UnsupportedPlatformCapability('QR code scanner');
    }
  }

  @override
  Future<String?> scanTotpQrCodeFromScreen() async {
    try {
      return await channel.invokeMethod<String>('scanTotpQrCodeFromScreen');
    } on PlatformException catch (error) {
      if (error.code == 'SCREEN_RECORDING_PERMISSION_REQUIRED') {
        throw const ScreenRecordingPermissionRequired();
      }
      if (error.code == 'TOTP_QR_NOT_FOUND') {
        throw const TotpQrCodeNotFound('screen');
      }
      rethrow;
    } on MissingPluginException {
      throw const UnsupportedPlatformCapability('screen QR code scanner');
    }
  }

  @override
  Future<bool> openScreenRecordingSettings() async {
    try {
      return await channel.invokeMethod<bool>('openScreenRecordingSettings') ??
          false;
    } on MissingPluginException {
      throw const UnsupportedPlatformCapability('Screen Recording settings');
    }
  }

  @override
  Future<bool> openGoogleAuthorization(String url) async {
    try {
      return await channel.invokeMethod<bool>('openGoogleAuthorization', url) ??
          false;
    } on MissingPluginException {
      throw const UnsupportedPlatformCapability('browser hand-off');
    }
  }

  @override
  Future<bool> openExternalUrl(String url) async {
    try {
      return await channel.invokeMethod<bool>('openExternalUrl', url) ?? false;
    } on MissingPluginException {
      throw const UnsupportedPlatformCapability('browser hand-off');
    }
  }

  @override
  Future<bool> openSettingsWindow() async {
    try {
      return await channel.invokeMethod<bool>('openSettingsWindow') ?? false;
    } on MissingPluginException {
      return false;
    }
  }

  @override
  Future<void> dispose() async {
    channel.setMethodCallHandler(null);
    await _lockRequests.close();
    await _menuActions.close();
  }
}
