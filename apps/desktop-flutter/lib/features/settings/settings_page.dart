import 'package:forui/forui.dart';
import 'package:material_ui/material_ui.dart';

import '../../app/app_scope.dart';
import '../../core/state/app_phase.dart';
import '../../ui/components/section_label.dart';
import '../../ui/tokens/keylease_tokens.dart';

/// User-facing controls only. Runtime paths are managed under `~/.keylease`.
class SettingsPage extends StatefulWidget {
  const SettingsPage({super.key});

  @override
  State<SettingsPage> createState() => _SettingsPageState();
}

class _SettingsPageState extends State<SettingsPage> {
  final _repairPassword = TextEditingController();

  @override
  void dispose() {
    _repairPassword.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final app = AppScope.of(context);
    final tokens = KeyLeaseTokens.of(context);
    return ListView(
      padding: EdgeInsets.all(tokens.gutter * 1.5),
      children: [
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
}
