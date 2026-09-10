import 'package:forui/forui.dart';
import 'package:material_ui/material_ui.dart';

import '../tokens/keylease_tokens.dart';

/// How a modal is presented.
enum KeyLeasePresentation {
  /// A centred dialog above [KeyLeaseTokens.compactBreakpoint], a bottom sheet
  /// below it. Right for anything short.
  auto,

  /// Always a full-screen route on a narrow screen.
  ///
  /// For multi-field forms and multi-step flows, where a sheet leaves too
  /// little room once the keyboard is up.
  fullScreen,
}

/// Forui 0.26 removed `FDialog`'s built-in layout, so KeyLease owns one.
///
/// Dialogs are reserved for decisions and editing. Reading entry metadata
/// happens in the detail pane, never in a dialog.
///
/// Below [KeyLeaseTokens.compactBreakpoint] this presents as a bottom sheet or
/// a full-screen route instead of a centred dialog. That dispatch lives here
/// rather than at the call sites so every existing modal adapts at once, and so
/// the desktop path stays byte-for-byte what it was.
Future<T?> showKeyLeaseDialog<T>({
  required BuildContext context,
  required String title,
  required Widget Function(BuildContext context) bodyBuilder,
  required List<Widget> Function(BuildContext context) actionsBuilder,
  String? description,
  bool barrierDismissible = true,
  double maxWidth = 560,
  KeyLeasePresentation presentation = KeyLeasePresentation.auto,
}) {
  final tokens = KeyLeaseTokens.of(context);
  if (MediaQuery.sizeOf(context).width < tokens.compactBreakpoint) {
    return presentation == KeyLeasePresentation.fullScreen
        ? _showCompactRoute<T>(
            context: context,
            title: title,
            description: description,
            bodyBuilder: bodyBuilder,
            actionsBuilder: actionsBuilder,
          )
        : _showCompactSheet<T>(
            context: context,
            title: title,
            description: description,
            barrierDismissible: barrierDismissible,
            bodyBuilder: bodyBuilder,
            actionsBuilder: actionsBuilder,
          );
  }

  final theme = context.theme;
  final localizations = FLocalizations.of(context) ?? FDefaultLocalizations();

  // Forui's default dialog route animates a sigma-5 BackdropFilter across the
  // complete window. That is disproportionately expensive on desktop GPUs and
  // makes opening even a small confirmation dialog drop frames. A solid modal
  // scrim preserves hierarchy and contrast without re-rasterizing the scene
  // behind it on every animation frame.
  return showGeneralDialog<T>(
    context: context,
    barrierDismissible: barrierDismissible,
    barrierLabel: localizations.barrierLabel,
    barrierColor: theme.colors.barrier,
    transitionDuration: const Duration(milliseconds: 80),
    transitionBuilder: (context, animation, secondaryAnimation, child) =>
        FadeTransition(
          opacity: CurvedAnimation(parent: animation, curve: Curves.easeOut),
          child: child,
        ),
    pageBuilder: (context, animation, secondaryAnimation) => FDialog(
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
}

/// A modal as a bottom sheet, for a narrow screen.
///
/// `isScrollControlled` plus the view inset padding is what keeps the actions
/// above the software keyboard; a centred dialog overflows once the IME opens.
Future<T?> _showCompactSheet<T>({
  required BuildContext context,
  required String title,
  required String? description,
  required bool barrierDismissible,
  required Widget Function(BuildContext context) bodyBuilder,
  required List<Widget> Function(BuildContext context) actionsBuilder,
}) => showModalBottomSheet<T>(
  context: context,
  isScrollControlled: true,
  useSafeArea: true,
  isDismissible: barrierDismissible,
  enableDrag: barrierDismissible,
  backgroundColor: context.theme.colors.background,
  builder: (context) => Padding(
    padding: EdgeInsets.only(bottom: MediaQuery.viewInsetsOf(context).bottom),
    child: KeyLeaseDialogBody(
      title: title,
      description: description,
      actions: actionsBuilder(context),
      child: bodyBuilder(context),
    ),
  ),
);

/// A modal as a full-screen route, for multi-field forms on a narrow screen.
Future<T?> _showCompactRoute<T>({
  required BuildContext context,
  required String title,
  required String? description,
  required Widget Function(BuildContext context) bodyBuilder,
  required List<Widget> Function(BuildContext context) actionsBuilder,
}) => Navigator.of(context).push<T>(
  MaterialPageRoute<T>(
    fullscreenDialog: true,
    builder: (context) => FScaffold(
      childPad: false,
      child: SafeArea(
        child: Padding(
          padding: EdgeInsets.only(
            bottom: MediaQuery.viewInsetsOf(context).bottom,
          ),
          child: KeyLeaseDialogBody(
            title: title,
            description: description,
            actions: actionsBuilder(context),
            child: bodyBuilder(context),
          ),
        ),
      ),
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
          if (MediaQuery.sizeOf(context).width < tokens.compactBreakpoint)
            // Reversed so the primary action, which a Row puts last, sits at
            // the top of the stack where a thumb reaches it first.
            Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                for (final (index, action) in actions.reversed.indexed) ...[
                  if (index > 0) SizedBox(height: tokens.gutterSmall),
                  action,
                ],
              ],
            )
          else
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
