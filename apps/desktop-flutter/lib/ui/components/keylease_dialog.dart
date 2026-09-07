import 'package:forui/forui.dart';
import 'package:material_ui/material_ui.dart';

import '../tokens/keylease_tokens.dart';

/// Forui 0.26 removed `FDialog`'s built-in layout, so KeyLease owns one.
///
/// Dialogs are reserved for decisions and editing. Reading entry metadata
/// happens in the detail pane, never in a dialog.
Future<T?> showKeyLeaseDialog<T>({
  required BuildContext context,
  required String title,
  required Widget Function(BuildContext context) bodyBuilder,
  required List<Widget> Function(BuildContext context) actionsBuilder,
  String? description,
  bool barrierDismissible = true,
  double maxWidth = 560,
}) => showFDialog<T>(
  context: context,
  barrierDismissible: barrierDismissible,
  builder: (context, style, animation) => FDialog(
    semanticsLabel: title,
    constraints: BoxConstraints(minWidth: 280, maxWidth: maxWidth),
    builder: (context, style) => KeyLeaseDialogBody(
      title: title,
      description: description,
      actions: actionsBuilder(context),
      child: bodyBuilder(context),
    ),
  ),
);

class KeyLeaseDialogBody extends StatelessWidget {
  const KeyLeaseDialogBody({
    required this.title,
    required this.actions,
    required this.child,
    this.description,
    super.key,
  });

  final String title;
  final String? description;
  final List<Widget> actions;
  final Widget child;

  @override
  Widget build(BuildContext context) {
    final tokens = KeyLeaseTokens.of(context);
    final theme = context.theme;
    return Padding(
      padding: EdgeInsets.all(tokens.gutter * 1.25),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Text(
            title,
            style: theme.typography.body.lg.copyWith(
              fontWeight: FontWeight.w600,
            ),
          ),
          if (description != null) ...[
            const SizedBox(height: 6),
            Text(
              description!,
              style: theme.typography.body.sm.copyWith(
                color: theme.colors.mutedForeground,
              ),
            ),
          ],
          SizedBox(height: tokens.gutter),
          Flexible(child: SingleChildScrollView(child: child)),
          SizedBox(height: tokens.gutter),
          Row(
            mainAxisAlignment: MainAxisAlignment.end,
            children: [
              for (var index = 0; index < actions.length; index++) ...[
                if (index > 0) SizedBox(width: tokens.gutterSmall),
                actions[index],
              ],
            ],
          ),
        ],
      ),
    );
  }
}

/// A confirmation the user must read before it can be sent.
Future<bool> confirm({
  required BuildContext context,
  required String title,
  required String message,
  required String confirmLabel,
  Widget? extra,
  bool destructive = false,
}) async =>
    await showKeyLeaseDialog<bool>(
      context: context,
      title: title,
      barrierDismissible: false,
      bodyBuilder: (context) => Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(message),
          if (extra != null) ...[const SizedBox(height: 12), extra],
        ],
      ),
      actionsBuilder: (context) => [
        FButton(
          variant: FButtonVariant.outline,
          onPress: () => Navigator.of(context).pop(false),
          child: const Text('Cancel'),
        ),
        FButton(
          variant: destructive
              ? FButtonVariant.destructive
              : FButtonVariant.primary,
          onPress: () => Navigator.of(context).pop(true),
          child: Text(confirmLabel),
        ),
      ],
    ) ??
    false;
