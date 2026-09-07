import 'package:forui/forui.dart';
import 'package:material_ui/material_ui.dart';

import '../../core/state/user_message.dart';
import '../tokens/keylease_tokens.dart';
import 'state_screen.dart';

/// An inline, dismissible failure notice.
///
/// Shows the user-language explanation; the daemon payload stays behind the
/// diagnostics disclosure.
class MessageBanner extends StatelessWidget {
  const MessageBanner({
    required this.message,
    this.onDismiss,
    this.onAction,
    super.key,
  });

  final UserMessage message;
  final VoidCallback? onDismiss;
  final VoidCallback? onAction;

  @override
  Widget build(BuildContext context) {
    final tokens = KeyLeaseTokens.of(context);
    return Padding(
      padding: EdgeInsets.fromLTRB(
        tokens.gutter,
        tokens.gutterSmall,
        tokens.gutter,
        0,
      ),
      child: Semantics(
        liveRegion: true,
        child: FAlert(
          variant: FAlertVariant.destructive,
          icon: const Icon(FLucideIcons.triangleAlert),
          title: Text(message.title),
          subtitle: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(message.detail),
              Row(
                children: [
                  if (message.actionLabel != null && onAction != null)
                    FButton(
                      variant: FButtonVariant.ghost,
                      onPress: onAction,
                      child: Text(message.actionLabel!),
                    ),
                  if (onDismiss != null)
                    FButton(
                      variant: FButtonVariant.ghost,
                      onPress: onDismiss,
                      child: const Text('Dismiss'),
                    ),
                ],
              ),
              if (message.diagnostics != null)
                DiagnosticsDisclosure(details: message.diagnostics!),
            ],
          ),
        ),
      ),
    );
  }
}
