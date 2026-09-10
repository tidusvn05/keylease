import 'package:forui/forui.dart';
import 'package:material_ui/material_ui.dart';

import '../tokens/keylease_tokens.dart';
import 'keylease_mark.dart';

/// The full-surface message used for setup, offline, locked, denied and empty.
///
/// Every state gets its own headline, explanation and next step so they stay
/// distinguishable instead of collapsing into a single "locked" screen.
class StateScreen extends StatelessWidget {
  const StateScreen({
    required this.icon,
    required this.title,
    required this.message,
    this.actions = const [],
    this.footnote,
    this.details,
    this.child,
    super.key,
  });

  final IconData icon;
  final String title;
  final String message;
  final List<Widget> actions;
  final String? footnote;
  final String? details;
  final Widget? child;

  @override
  Widget build(BuildContext context) {
    final tokens = KeyLeaseTokens.of(context);
    final theme = context.theme;
    return Center(
      child: SingleChildScrollView(
        padding: EdgeInsets.all(tokens.gutter * 1.5),
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 420),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.center,
            children: [
              KeyLeaseBrandMark(size: 46, icon: icon),
              SizedBox(height: tokens.gutter),
              Text(
                title,
                textAlign: TextAlign.center,
                style: theme.typography.display.xl.copyWith(
                  fontWeight: FontWeight.w600,
                ),
              ),
              SizedBox(height: tokens.gutterSmall),
              Text(
                message,
                textAlign: TextAlign.center,
                style: theme.typography.body.sm.copyWith(
                  color: theme.colors.mutedForeground,
                ),
              ),
              if (child != null) ...[SizedBox(height: tokens.gutter), child!],
              if (actions.isNotEmpty) ...[
                SizedBox(height: tokens.gutter),
                Wrap(
                  spacing: tokens.gutterSmall,
                  runSpacing: tokens.gutterSmall,
                  alignment: WrapAlignment.center,
                  children: actions,
                ),
              ],
              if (footnote != null) ...[
                SizedBox(height: tokens.gutter),
                Text(
                  footnote!,
                  textAlign: TextAlign.center,
                  style: theme.typography.body.xs.copyWith(
                    color: theme.colors.mutedForeground,
                  ),
                ),
              ],
              if (details != null) ...[
                SizedBox(height: tokens.gutter),
                DiagnosticsDisclosure(details: details!),
              ],
            ],
          ),
        ),
      ),
    );
  }
}

/// Technical payloads stay behind a disclosure, never in the headline.
class DiagnosticsDisclosure extends StatefulWidget {
  const DiagnosticsDisclosure({required this.details, super.key});

  final String details;

  @override
  State<DiagnosticsDisclosure> createState() => _DiagnosticsDisclosureState();
}

class _DiagnosticsDisclosureState extends State<DiagnosticsDisclosure> {
  bool expanded = false;

  @override
  Widget build(BuildContext context) {
    final theme = context.theme;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        FButton(
          variant: FButtonVariant.ghost,
          onPress: () => setState(() => expanded = !expanded),
          child: Text(expanded ? 'Hide details' : 'Show technical details'),
        ),
        if (expanded)
          Container(
            width: double.infinity,
            margin: const EdgeInsets.only(top: 8),
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: theme.colors.muted,
              borderRadius: BorderRadius.circular(8),
            ),
            child: SelectionArea(
              child: Text(
                widget.details,
                style: theme.typography.body.xs.copyWith(fontFamily: 'Menlo'),
              ),
            ),
          ),
      ],
    );
  }
}
