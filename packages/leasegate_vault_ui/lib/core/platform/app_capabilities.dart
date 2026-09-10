import 'package:flutter/foundation.dart';

/// What this build of the client offers.
///
/// Some of the desktop surface has no meaning on a phone, and a few parts have
/// no safe implementation there at all. Rather than fork the widget tree, the
/// features stay in one place and read these flags.
///
/// This is a value, not a compile-time switch, so both apps build the identical
/// tree and a test can exercise either shape by passing a different value. The
/// defaults are all `false` so that adding a capability cannot silently enable
/// it somewhere it does not belong; [AppCapabilities.desktop] opts everything
/// in explicitly.
@immutable
class AppCapabilities {
  const AppCapabilities({
    this.agentWorkflows = false,
    this.sshKeyBinding = false,
    this.developerTemplateEditing = false,
    this.screenQrScan = false,
    this.cameraQrScan = false,
    this.imageQrScan = false,
    this.googleOauth = false,
    this.connectionCreation = false,
    this.vaultMigrations = false,
    this.dataFolder = false,
    this.loginItems = false,
    this.windowTrafficLights = false,
  });

  /// The macOS desktop client: the full surface.
  static const desktop = AppCapabilities(
    agentWorkflows: true,
    sshKeyBinding: true,
    developerTemplateEditing: true,
    screenQrScan: true,
    imageQrScan: true,
    googleOauth: true,
    connectionCreation: true,
    vaultMigrations: true,
    dataFolder: true,
    loginItems: true,
    windowTrafficLights: true,
  );

  /// The Android client.
  ///
  /// The exclusions are not arbitrary. Agent workflows hand the user a CLI
  /// command to paste into a coding agent on the same machine. SSH key binding
  /// needs to read `~/.ssh`, which scoped storage forbids. Connection creation
  /// and migrations are refused by the `mobile_owner` policy rule regardless of
  /// what the UI offers, so showing them would only produce a denial.
  static const androidPhone = AppCapabilities(
    developerTemplateEditing: true,
    cameraQrScan: true,
    imageQrScan: true,
  );

  /// Whether the agent-driven creation flow is offered.
  final bool agentWorkflows;

  /// Whether SSH private keys on this host can be discovered and bound.
  final bool sshKeyBinding;

  /// Whether developer template entries can be edited rather than only read.
  final bool developerTemplateEditing;

  /// Whether a TOTP QR code can be captured from the screen.
  final bool screenQrScan;

  /// Whether a TOTP QR code can be scanned with the camera.
  final bool cameraQrScan;

  /// Whether a TOTP QR code can be read from a saved image.
  final bool imageQrScan;

  /// Whether the Google Workspace connection flow is offered.
  final bool googleOauth;

  /// Whether new connections can be created.
  final bool connectionCreation;

  /// Whether vault migrations can be applied or rolled back.
  final bool vaultMigrations;

  /// Whether the managed data folder can be revealed in a file manager.
  final bool dataFolder;

  /// Whether the host has a login-items setting to open.
  final bool loginItems;

  /// Whether the window has traffic-light buttons the title bar must clear.
  final bool windowTrafficLights;

  /// Whether any way of capturing a TOTP QR code is available.
  bool get anyQrScan => screenQrScan || cameraQrScan || imageQrScan;
}
