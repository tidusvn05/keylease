/// The mutually exclusive start-up and session states.
///
/// These are deliberately separate: collapsing "no client token yet",
/// "service not running" and "this client is not allowed" into `locked` was
/// the main defect of the previous UI.
enum AppPhase {
  /// The first status probe has not answered yet.
  checking,

  /// No managed vault exists yet. The user chooses create or import.
  onboarding,

  /// Provisioning is running in the bundled helper.
  provisioning,

  /// Managed files exist but the desktop credential needs repair.
  repairRequired,

  /// macOS requires the user to enable the background item.
  backgroundApprovalRequired,

  /// The local service could not be reached.
  serviceUnavailable,

  /// The service answered and the vault is locked.
  locked,

  /// The vault is unlocked but this client may not read it.
  permissionDenied,

  /// The vault is unlocked and this client may use it.
  ready,
}

/// Top-level navigation destinations, shared by every form factor.
enum AppSection { vault, connections, approvals, activity, settings }

extension AppSectionLabel on AppSection {
  String get label => switch (this) {
    AppSection.vault => 'Vault',
    AppSection.connections => 'Connections',
    AppSection.approvals => 'Approvals',
    AppSection.activity => 'Activity',
    AppSection.settings => 'Settings',
  };

  /// Sections that need an unlocked vault and an authorized client.
  bool get requiresReady => this != AppSection.settings;
}
