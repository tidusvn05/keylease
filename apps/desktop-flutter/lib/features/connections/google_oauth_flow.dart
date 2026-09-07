import 'package:forui/forui.dart';
import 'package:material_ui/material_ui.dart';

import '../../core/state/app_controller.dart';
import '../../ui/components/keylease_dialog.dart';
import '../vault/totp_dialog.dart';

/// The Google Workspace OAuth hand-off.
///
/// The browser hop stays in the native adapter, which only opens
/// `https://accounts.google.com`. The UI never handles the credential.
Future<void> connectGoogle(BuildContext context, AppController app) async {
  final clientId = TextEditingController();
  final clientSecret = TextEditingController();
  final proceed = await showKeyLeaseDialog<bool>(
    context: context,
    title: 'Connect Google Workspace',
    description:
        'Use a Desktop OAuth client. Google requests only '
        'drive.file and opens its Picker so you choose the exact files.',
    barrierDismissible: false,
    bodyBuilder: (context) => Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        FTextField(
          key: const ValueKey('google-client-id'),
          label: const Text('OAuth client ID'),
          autofocus: true,
          control: FTextFieldControl.managed(controller: clientId),
        ),
        const SizedBox(height: 10),
        FTextField(
          key: const ValueKey('google-client-secret'),
          label: const Text('Client secret (optional for desktop clients)'),
          obscureText: true,
          control: FTextFieldControl.managed(controller: clientSecret),
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
        child: const Text('Open Google'),
      ),
    ],
  );
  final id = clientId.text.trim();
  final secret = clientSecret.text;
  clientId.dispose();
  clientSecret
    ..clear()
    ..dispose();
  if (proceed != true || id.isEmpty || !context.mounted) return;

  Map<String, dynamic> flow;
  try {
    flow = await app.connections.beginGoogleOauth(
      clientId: id,
      clientSecret: secret.isEmpty ? null : secret,
    );
    final opened = await app.adapter.openGoogleAuthorization(
      '${flow['authorization_url']}',
    );
    if (!opened) throw Exception('Could not open Google authorization');
  } catch (caught) {
    if (context.mounted) showFailure(context, caught);
    return;
  }
  if (!context.mounted) return;

  final complete = await confirm(
    context: context,
    title: 'Finish in the Google Picker',
    message:
        'Choose the files in your browser, then come back here. '
        'This flow expires at ${flow['expires_at']}.',
    confirmLabel: 'Complete connection',
  );
  if (!complete || !context.mounted) return;
  try {
    await app.connections.completeGoogleOauth('${flow['flow_id']}');
  } catch (caught) {
    if (context.mounted) showFailure(context, caught);
  }
}
