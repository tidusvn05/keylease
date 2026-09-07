import 'package:forui/forui.dart';
import 'package:material_ui/material_ui.dart';

import '../../app/app_scope.dart';
import '../../core/platform/security_adapter.dart';
import '../../core/state/app_controller.dart';
import '../../core/state/connection_settings.dart';
import '../../core/state/user_message.dart';
import '../../ui/components/message_banner.dart';
import '../../ui/components/section_label.dart';
import '../../ui/tokens/keylease_tokens.dart';

/// Settings edit a draft. Nothing is applied until Save, and Cancel restores
/// the values that are actually in force. No secret is ever stored here: the
/// token file stays on disk and is validated by the daemon on every call.
class SettingsPage extends StatefulWidget {
  const SettingsPage({super.key});

  @override
  State<SettingsPage> createState() => _SettingsPageState();
}

class _SettingsPageState extends State<SettingsPage> {
  final _socket = TextEditingController();
  final _agent = TextEditingController();
  final _token = TextEditingController();
  ConnectionSettings? _applied;
  UserMessage? _failure;
  bool _saving = false;

  @override
  void dispose() {
    _socket.dispose();
    _agent.dispose();
    _token.dispose();
    super.dispose();
  }

  void _syncFrom(ConnectionSettings settings) {
    if (_applied == settings) return;
    _applied = settings;
    _socket.text = settings.socketPath;
    _agent.text = settings.agentId;
    _token.text = settings.tokenPath;
  }

  ConnectionSettings get _draft => ConnectionSettings(
    socketPath: _socket.text.trim(),
    agentId: _agent.text.trim(),
    tokenPath: _token.text.trim(),
  );

  bool get _dirty => _applied != null && _draft != _applied;

  Future<void> _pickToken(AppController app) async {
    try {
      final path = await app.adapter.selectClientToken();
      if (path != null && path.isNotEmpty && mounted) {
        setState(() => _token.text = path);
      }
    } on UnsupportedPlatformCapability catch (caught) {
      if (mounted) setState(() => _failure = UserMessage.from(caught));
    }
  }

  Future<void> _save(AppController app) async {
    setState(() {
      _saving = true;
      _failure = null;
    });
    final next = _draft;
    await app.applySettings(next);
    if (!mounted) return;
    setState(() {
      _applied = next;
      _saving = false;
    });
  }

  @override
  Widget build(BuildContext context) {
    final app = AppScope.of(context);
    final tokens = KeyLeaseTokens.of(context);
    _syncFrom(app.settings);
    return ListView(
      padding: EdgeInsets.all(tokens.gutter * 1.5),
      children: [
        if (_failure != null) ...[
          MessageBanner(message: _failure!),
          SizedBox(height: tokens.gutter),
        ],
        const SectionLabel('Local service'),
        Text(
          'KeyLease talks to a service running on this machine over a private '
          'socket. Nothing here is a secret.',
          style: context.theme.typography.body.sm.copyWith(
            color: context.theme.colors.mutedForeground,
          ),
        ),
        SizedBox(height: tokens.gutter),
        FTextField(
          key: const ValueKey('settings-socket'),
          label: const Text('Unix socket'),
          control: FTextFieldControl.managed(
            controller: _socket,
            onChange: (_) => setState(() {}),
          ),
        ),
        SizedBox(height: tokens.gutterSmall),
        FTextField(
          key: const ValueKey('settings-agent'),
          label: const Text('Client ID'),
          control: FTextFieldControl.managed(
            controller: _agent,
            onChange: (_) => setState(() {}),
          ),
        ),
        SizedBox(height: tokens.gutterSmall),
        Row(
          crossAxisAlignment: CrossAxisAlignment.end,
          children: [
            Expanded(
              child: FTextField(
                key: const ValueKey('settings-token'),
                label: const Text('Client token file (mode 0600)'),
                description: const Text(
                  'Choose the file KeyLease issued for this app. The app reads '
                  'it only to authenticate each request.',
                ),
                control: FTextFieldControl.managed(
                  controller: _token,
                  onChange: (_) => setState(() {}),
                ),
              ),
            ),
            SizedBox(width: tokens.gutterSmall),
            Padding(
              padding: const EdgeInsets.only(bottom: 36),
              child: FButton(
                key: const ValueKey('settings-choose-token'),
                variant: FButtonVariant.outline,
                onPress: () => _pickToken(app),
                prefix: const Icon(FLucideIcons.folderOpen, size: 16),
                child: const Text('Choose…'),
              ),
            ),
          ],
        ),
        SizedBox(height: tokens.gutter * 1.5),
        const SectionLabel('Security'),
        FItem(
          prefix: const Icon(FLucideIcons.clipboard, size: 18),
          title: const Text('Clipboard'),
          subtitle: const Text(
            'Copied secrets are cleared after 30 seconds, and only if nothing '
            'else has written to the clipboard since.',
          ),
        ),
        FItem(
          prefix: const Icon(FLucideIcons.moon, size: 18),
          title: const Text('Sleep and screen lock'),
          subtitle: const Text(
            'KeyLease locks the vault and hides revealed secrets when the '
            'machine sleeps or the screen locks.',
          ),
        ),
        SizedBox(height: tokens.gutter * 1.5),
        Row(
          mainAxisAlignment: MainAxisAlignment.end,
          children: [
            FButton(
              key: const ValueKey('settings-cancel'),
              variant: FButtonVariant.outline,
              onPress: _dirty && !_saving
                  ? () => setState(() {
                      _applied = null;
                      _syncFrom(app.settings);
                    })
                  : null,
              child: const Text('Cancel'),
            ),
            SizedBox(width: tokens.gutterSmall),
            FButton(
              key: const ValueKey('settings-save'),
              onPress: _dirty && !_saving ? () => _save(app) : null,
              child: Text(_saving ? 'Connecting…' : 'Save and connect'),
            ),
          ],
        ),
      ],
    );
  }
}
