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
  const SettingsPage({super.key});

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
    if (_destination == _SettingsDestination.connections) {
      return _SettingsSubpage(
        title: 'Connections',
        onBack: () =>
            setState(() => _destination = _SettingsDestination.general),
        child: const ConnectionsPage(),
      );
    }
    if (_destination == _SettingsDestination.activity) {
      return _SettingsSubpage(
        title: 'Activity',
        onBack: () =>
            setState(() => _destination = _SettingsDestination.general),
        child: const ActivityPage(),
      );
    }
    return KeyLeaseScrollArea(
      padding: EdgeInsets.all(tokens.gutter * 1.5),
      children: [
        const SectionLabel('Settings'),
        FItem(
          prefix: const Icon(FLucideIcons.vault, size: 18),
          title: const Text('Vaults'),
          subtitle: const Text('Current vault and local storage.'),
          suffix: Row(
            mainAxisSize: MainAxisSize.min,
            children: [
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
                    onPress: () async {
                      try {
                        await app.switchManagedVault(profile.id);
                      } catch (caught) {
                        if (context.mounted) showFailure(context, caught);
                      }
                    },
                    child: const Text('Switch'),
                  ),
                ],
              ],
            ),
          ),
        FItem(
          prefix: const Icon(FLucideIcons.link, size: 18),
          title: const Text('Connections'),
          subtitle: const Text('Services and connector credentials.'),
          suffix: const Icon(FLucideIcons.chevronRight, size: 16),
          onPress: () =>
              setState(() => _destination = _SettingsDestination.connections),
        ),
        FItem(
          prefix: const Icon(FLucideIcons.clock, size: 18),
          title: const Text('Activity'),
          subtitle: const Text('Audit and recent vault activity.'),
          suffix: const Icon(FLucideIcons.chevronRight, size: 16),
          onPress: () =>
              setState(() => _destination = _SettingsDestination.activity),
        ),
        SizedBox(height: tokens.gutter * 1.5),
        const SectionLabel('KeyLease on this Mac'),
        FItem(
          prefix: const Icon(FLucideIcons.hardDrive, size: 18),
          title: const Text('Managed vault'),
          subtitle: const Text(
            'Vault, local credential, backups, and runtime files are kept privately in ~/.keylease.',
          ),
          suffix: FButton(
            variant: FButtonVariant.outline,
            onPress: app.openDataFolder,
            child: const Text('Open folder'),
          ),
        ),
        if (app.isReady)
          FItem(
            prefix: const Icon(FLucideIcons.databaseBackup, size: 18),
            title: const Text('Vault migrations'),
            subtitle: Text(
              (app.vault.migrationStatus?.pending.isNotEmpty ?? false)
                  ? '${app.vault.migrationStatus!.pending.first.proposals.length} items need review.'
                  : 'Review migration history and rollback checkpoints.',
            ),
            suffix: FButton(
              variant: FButtonVariant.outline,
              onPress: () => openMigrationCenter(context, app),
              child: const Text('Manage'),
            ),
          ),
        FItem(
          prefix: const Icon(FLucideIcons.activity, size: 18),
          title: const Text('Background service'),
          subtitle: Text(
            app.serviceVersion == null
                ? 'Runs automatically while you are signed in.'
                : 'Version ${app.serviceVersion} · runs automatically while you are signed in.',
          ),
          suffix: FButton(
            variant: FButtonVariant.outline,
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
        SizedBox(height: tokens.gutter * 1.5),
        const SectionLabel('Security'),
        FItem(
          prefix: const Icon(FLucideIcons.clipboard, size: 18),
          title: const Text('Clipboard'),
          subtitle: const Text(
            'Copied secrets are cleared after 30 seconds if nothing else has replaced them.',
          ),
        ),
        FItem(
          prefix: const Icon(FLucideIcons.moon, size: 18),
          title: const Text('Sleep and screen lock'),
          subtitle: const Text(
            'KeyLease locks the vault and hides revealed secrets when this Mac sleeps or locks.',
          ),
        ),
      ],
    );
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

enum _SettingsDestination { general, connections, activity }

class _SettingsSubpage extends StatelessWidget {
  const _SettingsSubpage({
    required this.title,
    required this.onBack,
    required this.child,
  });

  final String title;
  final VoidCallback onBack;
  final Widget child;

  @override
  Widget build(BuildContext context) => Column(
    crossAxisAlignment: CrossAxisAlignment.stretch,
    children: [
      Padding(
        padding: const EdgeInsets.all(12),
        child: Row(
          children: [
            IconAction(
              label: 'Back to Settings',
              icon: FLucideIcons.arrowLeft,
              onPress: onBack,
            ),
            const SizedBox(width: 8),
            Text(
              title,
              style: context.theme.typography.body.lg.copyWith(
                fontWeight: FontWeight.w600,
              ),
            ),
          ],
        ),
      ),
      const Divider(height: 1),
      Expanded(child: child),
    ],
  );
}
