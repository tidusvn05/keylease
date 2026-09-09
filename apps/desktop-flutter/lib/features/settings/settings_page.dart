import 'dart:async';

import 'package:forui/forui.dart';
import 'package:material_ui/material_ui.dart';

import '../../app/app_scope.dart';
import '../../core/state/app_phase.dart';
import '../../core/state/app_controller.dart';
import '../activity/activity_page.dart';
import '../connections/connections_page.dart';
import '../migrations/migration_center.dart';
import '../../ui/components/section_label.dart';
import '../../ui/components/secret_field.dart';
import '../../ui/components/scroll_area.dart';
import '../../ui/components/keylease_dialog.dart';
import '../../ui/tokens/keylease_tokens.dart';
import '../vault/totp_dialog.dart';

/// User-facing controls only. Runtime paths are managed under `~/.keylease`.
class SettingsPage extends StatefulWidget {
  const SettingsPage({this.windowMode = false, super.key});

  final bool windowMode;

  @override
  State<SettingsPage> createState() => _SettingsPageState();
}

class _SettingsPageState extends State<SettingsPage> {
  final _repairPassword = TextEditingController();
  _SettingsDestination _destination = _SettingsDestination.general;

  @override
  void dispose() {
    _repairPassword.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final app = AppScope.of(context);
    final tokens = KeyLeaseTokens.of(context);
    return Row(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        SizedBox(
          width: 190,
          child: ColoredBox(
            color: context.theme.colors.muted.withValues(alpha: 0.35),
            child: KeyLeaseScrollArea(
              padding: EdgeInsets.fromLTRB(
                tokens.gutterSmall,
                widget.windowMode ? 14 : tokens.gutter,
                tokens.gutterSmall,
                tokens.gutter,
              ),
              children: [
                Padding(
                  padding: const EdgeInsets.fromLTRB(10, 4, 10, 12),
                  child: Text(
                    'Settings',
                    style: context.theme.typography.body.lg.copyWith(
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                ),
                for (final destination in _SettingsDestination.values) ...[
                  _SettingsNavigationItem(
                    key: ValueKey('settings-${destination.name}'),
                    icon: destination.icon,
                    label: destination.label,
                    selected: _destination == destination,
                    onPress: () => _select(app, destination),
                  ),
                  if (destination != _SettingsDestination.values.last)
                    const SizedBox(height: 4),
                ],
              ],
            ),
          ),
        ),
        ColoredBox(
          color: context.theme.colors.border,
          child: const SizedBox(width: 1),
        ),
        Expanded(child: _content(context, app, tokens)),
      ],
    );
  }

  void _select(AppController app, _SettingsDestination destination) {
    if (_destination == destination) return;
    setState(() => _destination = destination);
    if (!app.isReady) return;
    switch (destination) {
      case _SettingsDestination.connections:
        unawaited(app.connections.load());
      case _SettingsDestination.activity:
        unawaited(app.activity.load());
      default:
        break;
    }
  }

  Widget _content(
    BuildContext context,
    AppController app,
    KeyLeaseTokens tokens,
  ) => switch (_destination) {
    _SettingsDestination.general => _settingsScroll(tokens, [
      const SectionLabel('General'),
      _SettingsCard(
        icon: FLucideIcons.hardDrive,
        title: const Text('KeyLease data'),
        subtitle: const Text(
          'Vault, backups, and runtime files are kept privately in ~/.keylease.',
        ),
        trailing: FButton(
          variant: FButtonVariant.outline,
          size: FButtonSizeVariant.sm,
          mainAxisSize: MainAxisSize.min,
          onPress: app.openDataFolder,
          child: const Text('Open folder'),
        ),
      ),
      SizedBox(height: tokens.gutterSmall),
      if (app.isReady)
        _SettingsCard(
          icon: FLucideIcons.databaseBackup,
          title: const Text('Vault migrations'),
          subtitle: Text(
            (app.vault.migrationStatus?.pending.isNotEmpty ?? false)
                ? '${app.vault.migrationStatus!.pending.first.proposals.length} items need review.'
                : 'Review migration history and rollback checkpoints.',
          ),
          trailing: FButton(
            variant: FButtonVariant.outline,
            size: FButtonSizeVariant.sm,
            mainAxisSize: MainAxisSize.min,
            onPress: () => openMigrationCenter(context, app),
            child: const Text('Manage'),
          ),
        ),
      if (app.isReady) SizedBox(height: tokens.gutterSmall),
      _SettingsCard(
        icon: FLucideIcons.activity,
        title: const Text('Background service'),
        subtitle: Text(
          app.serviceVersion == null
              ? 'Runs automatically while you are signed in.'
              : 'Version ${app.serviceVersion} · runs automatically while you are signed in.',
        ),
        trailing: FButton(
          variant: FButtonVariant.outline,
          size: FButtonSizeVariant.sm,
          mainAxisSize: MainAxisSize.min,
          onPress: app.restartService,
          child: const Text('Restart'),
        ),
      ),
      if (app.phase == AppPhase.repairRequired) ...[
        SizedBox(height: tokens.gutter),
        const SectionLabel('Repair'),
        const Text(
          'Enter your vault password to recreate this Mac’s local desktop credential. Vault data is unchanged.',
        ),
        SizedBox(height: tokens.gutterSmall),
        FTextField(
          label: const Text('Master password'),
          obscureText: true,
          control: FTextFieldControl.managed(controller: _repairPassword),
        ),
        SizedBox(height: tokens.gutterSmall),
        FButton(
          onPress: () async {
            final password = _repairPassword.text;
            if (password.isEmpty) return;
            await app.provision({
              'mode': 'repair_desktop_client',
              'password': password,
            });
            _repairPassword.clear();
          },
          child: const Text('Repair connection'),
        ),
      ],
    ]),
    _SettingsDestination.vaults => _settingsScroll(tokens, [
      Row(
        children: [
          const Expanded(child: SectionLabel('Vaults')),
          FButton(
            variant: FButtonVariant.outline,
            onPress: () => _importVault(context, app),
            child: const Text('Import'),
          ),
          const SizedBox(width: 8),
          FButton(
            onPress: () => _createVault(context, app),
            child: const Text('New vault'),
          ),
        ],
      ),
      for (final profile in app.vaultProfiles)
        FItem(
          prefix: Icon(
            profile.active ? FLucideIcons.circleCheck : FLucideIcons.circle,
            size: 17,
          ),
          title: Text(profile.name),
          subtitle: Text(
            profile.active ? 'Active vault' : 'Locked until selected',
          ),
          suffix: Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              IconAction(
                label: 'Rename ${profile.name}',
                icon: FLucideIcons.squarePen,
                onPress: () =>
                    _renameVault(context, app, profile.id, profile.name),
              ),
              if (!profile.active) ...[
                const SizedBox(width: 8),
                FButton(
                  variant: FButtonVariant.outline,
                  onPress: () => _switchVault(context, app, profile.id),
                  child: const Text('Switch'),
                ),
              ],
            ],
          ),
        ),
    ]),
    _SettingsDestination.connections => const ConnectionsPage(),
    _SettingsDestination.security => _settingsScroll(tokens, [
      const SectionLabel('Security'),
      _SettingsCard(
        icon: FLucideIcons.clipboard,
        title: const Text('Clipboard'),
        subtitle: const Text(
          'Copied secrets are cleared after 30 seconds if nothing else has replaced them.',
        ),
      ),
      SizedBox(height: tokens.gutterSmall),
      _SettingsCard(
        icon: FLucideIcons.moon,
        title: const Text('Sleep and screen lock'),
        subtitle: const Text(
          'KeyLease locks the vault and hides revealed secrets when this Mac sleeps or locks.',
        ),
      ),
    ]),
    _SettingsDestination.activity => const ActivityPage(),
  };

  Widget _settingsScroll(KeyLeaseTokens tokens, List<Widget> children) =>
      KeyLeaseScrollArea(
        padding: EdgeInsets.all(tokens.gutter * 1.5),
        children: children,
      );

  Future<void> _switchVault(
    BuildContext context,
    AppController app,
    String id,
  ) async {
    try {
      await app.switchManagedVault(id);
    } catch (caught) {
      if (context.mounted) showFailure(context, caught);
    }
  }

  Future<void> _createVault(BuildContext context, AppController app) async {
    final name = TextEditingController();
    final password = TextEditingController();
    final submitted = await showKeyLeaseDialog<bool>(
      context: context,
      title: 'New vault',
      description: 'This vault has its own master password.',
      bodyBuilder: (context) => Column(
        children: [
          FTextField(
            label: const Text('Vault name'),
            autofocus: true,
            control: FTextFieldControl.managed(controller: name),
          ),
          const SizedBox(height: 10),
          FTextField(
            label: const Text('Master password'),
            obscureText: true,
            control: FTextFieldControl.managed(controller: password),
          ),
        ],
      ),
      actionsBuilder: (context) => [
        FButton(
          variant: FButtonVariant.outline,
          onPress: () => Navigator.of(context).pop(false),
          child: const Text('Cancel'),
        ),
        FButton(
          onPress: () => Navigator.of(context).pop(true),
          child: const Text('Create'),
        ),
      ],
    );
    final vaultName = name.text.trim();
    final secret = password.text;
    name.dispose();
    password.clear();
    password.dispose();
    if (submitted != true || vaultName.isEmpty || secret.isEmpty) return;
    try {
      await app.createManagedVault(vaultName, {
        'mode': 'create',
        'password': secret,
      });
    } catch (caught) {
      if (context.mounted) showFailure(context, caught);
    }
  }

  Future<void> _renameVault(
    BuildContext context,
    AppController app,
    String id,
    String currentName,
  ) async {
    final name = TextEditingController(text: currentName);
    final submitted = await showKeyLeaseDialog<bool>(
      context: context,
      title: 'Rename vault',
      bodyBuilder: (context) => FTextField(
        label: const Text('Vault name'),
        autofocus: true,
        control: FTextFieldControl.managed(controller: name),
      ),
      actionsBuilder: (context) => [
        FButton(
          variant: FButtonVariant.outline,
          onPress: () => Navigator.of(context).pop(false),
          child: const Text('Cancel'),
        ),
        FButton(
          onPress: () => Navigator.of(context).pop(true),
          child: const Text('Rename'),
        ),
      ],
    );
    final value = name.text.trim();
    name.dispose();
    if (submitted != true || value.isEmpty || value == currentName) return;
    try {
      await app.renameManagedVault(id, value);
    } catch (caught) {
      if (context.mounted) showFailure(context, caught);
    }
  }

  Future<void> _importVault(BuildContext context, AppController app) async {
    final path = await app.chooseVaultSource();
    if (path == null || !context.mounted) return;
    final source = await app.inspectSource(path);
    if (!context.mounted) return;
    final name = TextEditingController();
    final sourcePassword = TextEditingController();
    final password = TextEditingController();
    final submitted = await showKeyLeaseDialog<bool>(
      context: context,
      title: 'Import as a new vault',
      description:
          'The imported vault remains independent from your current vault.',
      bodyBuilder: (context) => Column(
        children: [
          FTextField(
            label: const Text('Vault name'),
            autofocus: true,
            control: FTextFieldControl.managed(controller: name),
          ),
          if (source['kind'] == 'kdbx') ...[
            const SizedBox(height: 10),
            FTextField(
              label: const Text('Source password'),
              obscureText: true,
              control: FTextFieldControl.managed(controller: sourcePassword),
            ),
          ],
          const SizedBox(height: 10),
          FTextField(
            label: Text(
              source['kind'] == 'keylease_database'
                  ? 'Vault password'
                  : 'New master password',
            ),
            obscureText: true,
            control: FTextFieldControl.managed(controller: password),
          ),
        ],
      ),
      actionsBuilder: (context) => [
        FButton(
          variant: FButtonVariant.outline,
          onPress: () => Navigator.of(context).pop(false),
          child: const Text('Cancel'),
        ),
        FButton(
          onPress: () => Navigator.of(context).pop(true),
          child: const Text('Import'),
        ),
      ],
    );
    final vaultName = name.text.trim();
    final sourceSecret = sourcePassword.text;
    final secret = password.text;
    name.dispose();
    sourcePassword.clear();
    sourcePassword.dispose();
    password.clear();
    password.dispose();
    if (submitted != true || vaultName.isEmpty || secret.isEmpty) return;
    final kind = '${source['kind']}';
    final request = <String, dynamic>{
      'mode': switch (kind) {
        'keylease_database' => 'adopt_keylease_database',
        'keylease_backup' => 'restore_keylease_backup',
        'kdbx' => 'import_kdbx',
        _ => 'import_onepux',
      },
      'source_path': path,
      'password': secret,
      if (kind == 'kdbx') 'source_password': sourceSecret,
      if (kind == 'onepux') 'acknowledge_plaintext': true,
    };
    try {
      await app.createManagedVault(vaultName, request);
    } catch (caught) {
      if (context.mounted) showFailure(context, caught);
    }
  }
}

class _SettingsNavigationItem extends StatefulWidget {
  const _SettingsNavigationItem({
    required this.icon,
    required this.label,
    required this.selected,
    required this.onPress,
    super.key,
  });

  final IconData icon;
  final String label;
  final bool selected;
  final VoidCallback onPress;

  @override
  State<_SettingsNavigationItem> createState() =>
      _SettingsNavigationItemState();
}

class _SettingsNavigationItemState extends State<_SettingsNavigationItem> {
  bool _hovered = false;

  @override
  Widget build(BuildContext context) {
    final theme = context.theme;
    final tokens = KeyLeaseTokens.of(context);
    final selected = widget.selected;
    return Semantics(
      button: true,
      selected: selected,
      label: widget.label,
      child: MouseRegion(
        cursor: SystemMouseCursors.click,
        onEnter: (_) => setState(() => _hovered = true),
        onExit: (_) => setState(() => _hovered = false),
        child: GestureDetector(
          behavior: HitTestBehavior.opaque,
          onTap: widget.onPress,
          child: AnimatedContainer(
            duration: const Duration(milliseconds: 120),
            height: 38,
            padding: const EdgeInsets.symmetric(horizontal: 11),
            decoration: BoxDecoration(
              color: selected
                  ? theme.colors.muted
                  : _hovered
                  ? theme.colors.muted.withValues(alpha: 0.55)
                  : null,
              border: Border.all(
                color: selected
                    ? tokens.accent.withValues(alpha: 0.28)
                    : const Color(0x00000000),
              ),
              borderRadius: BorderRadius.circular(8),
            ),
            child: Row(
              children: [
                Icon(
                  widget.icon,
                  size: 17,
                  color: selected ? tokens.accent : theme.colors.foreground,
                ),
                const SizedBox(width: 10),
                Expanded(
                  child: Text(
                    widget.label,
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                    style: theme.typography.body.sm.copyWith(
                      fontWeight: selected ? FontWeight.w600 : FontWeight.w500,
                    ),
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}

class _SettingsCard extends StatelessWidget {
  const _SettingsCard({
    required this.icon,
    required this.title,
    required this.subtitle,
    this.trailing,
  });

  final IconData icon;
  final Widget title;
  final Widget subtitle;
  final Widget? trailing;

  @override
  Widget build(BuildContext context) {
    final theme = context.theme;
    final tokens = KeyLeaseTokens.of(context);
    return Container(
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: theme.colors.muted.withValues(alpha: 0.22),
        border: Border.all(color: theme.colors.border),
        borderRadius: BorderRadius.circular(10),
      ),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.center,
        children: [
          Container(
            width: 34,
            height: 34,
            decoration: BoxDecoration(
              color: tokens.accent.withValues(alpha: 0.11),
              borderRadius: BorderRadius.circular(8),
            ),
            child: Icon(icon, size: 18, color: tokens.accent),
          ),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                DefaultTextStyle(
                  style: theme.typography.body.sm.copyWith(
                    color: theme.colors.foreground,
                    fontWeight: FontWeight.w600,
                  ),
                  child: title,
                ),
                const SizedBox(height: 4),
                DefaultTextStyle(
                  style: theme.typography.body.xs.copyWith(
                    color: theme.colors.mutedForeground,
                  ),
                  child: subtitle,
                ),
              ],
            ),
          ),
          if (trailing != null) ...[const SizedBox(width: 16), trailing!],
        ],
      ),
    );
  }
}

enum _SettingsDestination { general, vaults, connections, security, activity }

extension on _SettingsDestination {
  String get label => switch (this) {
    _SettingsDestination.general => 'General',
    _SettingsDestination.vaults => 'Vaults',
    _SettingsDestination.connections => 'Connections',
    _SettingsDestination.security => 'Security',
    _SettingsDestination.activity => 'Activity',
  };

  IconData get icon => switch (this) {
    _SettingsDestination.general => FLucideIcons.slidersHorizontal,
    _SettingsDestination.vaults => FLucideIcons.vault,
    _SettingsDestination.connections => FLucideIcons.link,
    _SettingsDestination.security => FLucideIcons.shieldCheck,
    _SettingsDestination.activity => FLucideIcons.clock,
  };
}
