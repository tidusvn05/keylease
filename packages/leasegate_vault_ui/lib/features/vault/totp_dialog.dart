import 'dart:async';

import 'package:forui/forui.dart';
import 'package:material_ui/material_ui.dart';

import '../../core/models/models.dart';
import '../../core/state/app_controller.dart';
import '../../core/state/user_message.dart';
import '../../ui/components/keylease_dialog.dart';
import '../../ui/components/message_banner.dart';

/// Shows a failure without losing the user's place.
void showFailure(BuildContext context, Object error) {
  final message = UserMessage.from(error);
  unawaited(
    showKeyLeaseDialog<void>(
      context: context,
      title: message.title,
      bodyBuilder: (context) => MessageBanner(message: message),
      actionsBuilder: (context) => [
        FButton(
          onPress: () => Navigator.of(context).pop(),
          child: const Text('Close'),
        ),
      ],
    ),
  );
}

/// Fetches a one-time code on demand and stops showing it when it expires.
Future<void> showTotpDialog(
  BuildContext context,
  AppController app,
  EntrySummary entry,
) async {
  Map<String, dynamic> response;
  try {
    response = await app.vault.totp(entry);
  } catch (caught) {
    if (context.mounted) showFailure(context, caught);
    return;
  }
  if (!context.mounted) return;
  final code = '${response['code']}';
  final expiresIn = (response['expires_in'] as num?)?.toInt() ?? 0;
  await showKeyLeaseDialog<void>(
    context: context,
    title: 'One-time password',
    description: 'This code is shown on request and is not stored by the app.',
    bodyBuilder: (context) => _TotpBody(code: code, expiresIn: expiresIn),
    actionsBuilder: (context) => [
      FButton(
        variant: FButtonVariant.outline,
        onPress: () async {
          final copied = await app.copySensitive(code);
          if (copied && context.mounted) Navigator.of(context).pop();
        },
        child: const Text('Copy code'),
      ),
      FButton(
        onPress: () => Navigator.of(context).pop(),
        child: const Text('Close'),
      ),
    ],
  );
}

class _TotpBody extends StatefulWidget {
  const _TotpBody({required this.code, required this.expiresIn});

  final String code;
  final int expiresIn;

  @override
  State<_TotpBody> createState() => _TotpBodyState();
}

class _TotpBodyState extends State<_TotpBody> {
  late int remaining = widget.expiresIn;
  Timer? timer;

  @override
  void initState() {
    super.initState();
    timer = Timer.periodic(const Duration(seconds: 1), (_) {
      if (!mounted) return;
      setState(() => remaining = remaining > 0 ? remaining - 1 : 0);
    });
  }

  @override
  void dispose() {
    timer?.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) => Column(
    crossAxisAlignment: CrossAxisAlignment.stretch,
    children: [
      SelectionArea(
        child: Text(
          remaining == 0 ? '••• •••' : widget.code,
          textAlign: TextAlign.center,
          style: context.theme.typography.display.xl2.copyWith(
            fontFamily: 'Menlo',
            letterSpacing: 4,
          ),
        ),
      ),
      const SizedBox(height: 14),
      FDeterminateProgress(
        semanticsLabel: 'Time left on this code',
        value: widget.expiresIn == 0 ? 0 : remaining / widget.expiresIn,
      ),
      const SizedBox(height: 8),
      Text(
        remaining == 0
            ? 'This code expired. Close and ask for a new one.'
            : 'Expires in ${remaining}s',
        textAlign: TextAlign.center,
        style: context.theme.typography.body.sm.copyWith(
          color: context.theme.colors.mutedForeground,
        ),
      ),
    ],
  );
}
