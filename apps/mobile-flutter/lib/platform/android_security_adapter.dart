import 'dart:async';

import 'package:flutter/services.dart';
import 'package:flutter/widgets.dart';
import 'package:leasegate_vault_ui/core/platform/security_adapter.dart';

/// The Android implementation of [SecurityAdapter].
///
/// Split three ways by necessity rather than taste:
///
/// * The clipboard goes through a method channel, because its clear-after
///   timer has to outlive the Flutter engine. See `SecurityPlugin.kt`.
/// * Locking is pure Dart, driven by the app lifecycle and an idle timer.
/// * The rest either has a plugin-backed implementation or throws
///   [UnsupportedPlatformCapability], which the UI already renders as a real
///   message rather than a crash.
class AndroidSecurityAdapter implements SecurityAdapter {
  AndroidSecurityAdapter({
    MethodChannel channel = const MethodChannel('com.keylease/security'),
    this.idleTimeout = const Duration(minutes: 3),
    QrScanner? scanner,
    UrlOpener? urlOpener,
  }) : _channel = channel,
       _scanner = scanner,
       _urlOpener = urlOpener {
    _observer = _LifecycleObserver(
      onBackgrounded: () => _requestLock(LockTrigger.screenLock),
      onForegrounded: _restartIdleTimer,
    );
    WidgetsBinding.instance.addObserver(_observer);
    _restartIdleTimer();
  }

  /// How long the app may sit in the foreground untouched before locking.
  ///
  /// The desktop has no equivalent — it locks on sleep and screen lock — but a
  /// phone is put down mid-task and picked up by someone else.
  final Duration idleTimeout;

  final MethodChannel _channel;
  final QrScanner? _scanner;
  final UrlOpener? _urlOpener;

  final _lockRequests = StreamController<LockTrigger>.broadcast();
  late final _LifecycleObserver _observer;
  Timer? _idleTimer;

  @override
  Stream<LockTrigger> get lockRequests => _lockRequests.stream;

  /// Android has no menu bar, so this never emits.
  @override
  Stream<MenuAction> get menuActions => const Stream<MenuAction>.empty();

  /// Call on any user interaction to defer the idle lock.
  void noteActivity() => _restartIdleTimer();

  void _restartIdleTimer() {
    _idleTimer?.cancel();
    _idleTimer = Timer(idleTimeout, () => _requestLock(LockTrigger.unknown));
  }

  void _requestLock(LockTrigger trigger) {
    if (_lockRequests.isClosed) return;
    _lockRequests.add(trigger);
  }

  @override
  Future<void> copySensitive(
    String value, {
    Duration clearAfter = const Duration(seconds: 30),
  }) async {
    try {
      await _channel.invokeMethod<bool>('copySensitive', {
        'value': value,
        'clear_after_seconds': clearAfter.inSeconds,
      });
    } on MissingPluginException {
      // Never fall back to Clipboard.setData: that would copy the secret with
      // no clear-after guarantee at all, which is worse than refusing.
      throw const UnsupportedPlatformCapability('clipboard');
    }
  }

  @override
  Future<void> clearSensitiveClipboard() async {
    try {
      await _channel.invokeMethod<bool>('clearSensitiveClipboard');
    } on MissingPluginException {
      throw const UnsupportedPlatformCapability('clipboard');
    }
  }

  /// There is no client token on Android: the vault is opened in process.
  @override
  Future<String?> selectClientToken() async =>
      throw const UnsupportedPlatformCapability('client token picker');

  /// Scoped storage puts `~/.ssh` out of reach.
  @override
  Future<List<SshPrivateKeyCandidate>> discoverSshPrivateKeys() async =>
      throw const UnsupportedPlatformCapability('SSH key discovery');

  @override
  Future<String?> selectSshPrivateKey() async =>
      throw const UnsupportedPlatformCapability('SSH private key picker');

  @override
  Future<String?> scanTotpQrCode() async {
    final scanner = _scanner;
    if (scanner == null) {
      throw const UnsupportedPlatformCapability('QR code scanner');
    }
    return scanner.fromImage();
  }

  @override
  Future<String?> scanTotpQrCodeFromCamera() async {
    final scanner = _scanner;
    if (scanner == null) {
      throw const UnsupportedPlatformCapability('camera QR scanner');
    }
    return scanner.fromCamera();
  }

  /// MediaProjection needs a foreground service and a consent dialog per
  /// capture. The camera is the mobile answer; see [scanTotpQrCodeFromCamera].
  @override
  Future<String?> scanTotpQrCodeFromScreen() async =>
      throw const UnsupportedPlatformCapability('screen capture');

  @override
  Future<bool> openScreenRecordingSettings() async =>
      throw const UnsupportedPlatformCapability('screen recording settings');

  /// Cut from v1 along with connection creation; see the `mobile_owner` role.
  @override
  Future<bool> openGoogleAuthorization(String url) async =>
      throw const UnsupportedPlatformCapability('Google authorization');

  @override
  Future<bool> openExternalUrl(String url) async {
    final opener = _urlOpener;
    if (opener == null) {
      throw const UnsupportedPlatformCapability('external browser');
    }
    return opener.open(url);
  }

  /// Android keeps Settings inside the shell; the caller already falls back.
  @override
  Future<bool> openSettingsWindow() async => false;

  @override
  Future<void> dispose() async {
    _idleTimer?.cancel();
    WidgetsBinding.instance.removeObserver(_observer);
    await _lockRequests.close();
  }
}

/// Reads a TOTP QR code.
///
/// An interface rather than a direct plugin call so the adapter stays testable
/// without a camera, and so the plugin choice is not baked into it.
abstract class QrScanner {
  Future<String?> fromCamera();

  Future<String?> fromImage();
}

/// Opens a URL in the user's browser.
abstract class UrlOpener {
  Future<bool> open(String url);
}

class _LifecycleObserver with WidgetsBindingObserver {
  _LifecycleObserver({
    required this.onBackgrounded,
    required this.onForegrounded,
  });

  final VoidCallback onBackgrounded;
  final VoidCallback onForegrounded;

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    switch (state) {
      // `inactive` is deliberately excluded: it fires for a transient system
      // dialog or the app switcher preview, and locking there would make the
      // app unusable. FLAG_SECURE already blanks the recents thumbnail.
      case AppLifecycleState.paused:
      case AppLifecycleState.hidden:
      case AppLifecycleState.detached:
        onBackgrounded();
      case AppLifecycleState.resumed:
        onForegrounded();
      case AppLifecycleState.inactive:
        break;
    }
  }
}
