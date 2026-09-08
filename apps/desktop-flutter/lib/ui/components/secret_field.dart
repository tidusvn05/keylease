import 'package:forui/forui.dart';
import 'package:material_ui/material_ui.dart';

import '../tokens/keylease_tokens.dart';

/// One labelled row inside a [FieldGroup].
class DetailField extends StatelessWidget {
  const DetailField({
    required this.label,
    required this.value,
    this.actions = const [],
    this.monospace = false,
    this.accent = false,
    this.placeholder,
    this.onPress,
    super.key,
  });

  final String label;
  final String? value;
  final List<Widget> actions;
  final bool monospace;
  final bool accent;
  final String? placeholder;
  final VoidCallback? onPress;

  @override
  Widget build(BuildContext context) {
    final tokens = KeyLeaseTokens.of(context);
    final theme = context.theme;
    final empty = value == null || value!.isEmpty;
    return Padding(
      padding: EdgeInsets.symmetric(
        horizontal: tokens.gutter * 0.95,
        vertical: tokens.gutterSmall * 1.5,
      ),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.center,
        children: [
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  label,
                  style: theme.typography.body.xs.copyWith(
                    color: theme.colors.mutedForeground,
                  ),
                ),
                const SizedBox(height: 5),
                _DetailValue(
                  key: ValueKey('detail-field-value-$label'),
                  value: empty ? (placeholder ?? 'Not set') : value!,
                  monospace: monospace,
                  color: empty
                      ? theme.colors.mutedForeground
                      : accent
                      ? tokens.accent
                      : theme.colors.foreground,
                  fontSize: tokens.bodySize,
                  onPress: empty ? null : onPress,
                ),
              ],
            ),
          ),
          if (actions.isNotEmpty) ...[
            SizedBox(width: tokens.gutterSmall),
            Row(mainAxisSize: MainAxisSize.min, children: actions),
          ],
        ],
      ),
    );
  }
}

class _DetailValue extends StatefulWidget {
  const _DetailValue({
    required this.value,
    required this.monospace,
    required this.color,
    required this.fontSize,
    this.onPress,
    super.key,
  });

  final String value;
  final bool monospace;
  final Color color;
  final double fontSize;
  final VoidCallback? onPress;

  @override
  State<_DetailValue> createState() => _DetailValueState();
}

class _DetailValueState extends State<_DetailValue> {
  bool _hovered = false;

  @override
  Widget build(BuildContext context) {
    final text = Text(
      widget.value,
      style: TextStyle(
        fontSize: widget.fontSize,
        fontFamily: widget.monospace ? 'Menlo' : null,
        fontFamilyFallback: widget.monospace
            ? const ['Courier New', 'monospace']
            : null,
        color: widget.color,
        decoration: widget.onPress != null && _hovered
            ? TextDecoration.underline
            : null,
        decorationColor: widget.color,
      ),
    );
    final onPress = widget.onPress;
    if (onPress == null) return SelectionArea(child: text);
    return Semantics(
      button: true,
      link: true,
      label: widget.value,
      child: MouseRegion(
        cursor: SystemMouseCursors.click,
        onEnter: (_) => setState(() => _hovered = true),
        onExit: (_) => setState(() => _hovered = false),
        child: GestureDetector(onTap: onPress, child: text),
      ),
    );
  }
}

/// A protected field: masked until the user explicitly reveals it.
///
/// The widget never holds the plaintext itself. [revealedValue] comes from the
/// controller, which fetched it on demand and drops it again on lock, sleep or
/// its own reveal timeout.
class SecretField extends StatelessWidget {
  const SecretField({
    required this.label,
    required this.revealedValue,
    required this.onReveal,
    required this.onHide,
    required this.onCopy,
    this.busy = false,
    this.maskLength = 12,
    super.key,
  });

  final String label;
  final String? revealedValue;
  final VoidCallback? onReveal;
  final VoidCallback? onHide;
  final VoidCallback? onCopy;
  final bool busy;
  final int maskLength;

  bool get revealed => revealedValue != null;

  @override
  Widget build(BuildContext context) => DetailField(
    label: label,
    value: revealed ? revealedValue : '•' * maskLength,
    monospace: true,
    actions: [
      IconAction(
        label: revealed ? 'Hide $label' : 'Reveal $label',
        icon: revealed ? FLucideIcons.eyeOff : FLucideIcons.eye,
        onPress: busy ? null : (revealed ? onHide : onReveal),
      ),
      const SizedBox(width: 6),
      IconAction(
        label: 'Copy $label',
        icon: FLucideIcons.copy,
        onPress: busy ? null : onCopy,
      ),
    ],
  );
}

/// A small icon button with a tooltip and a screen-reader label.
class IconAction extends StatelessWidget {
  const IconAction({
    required this.label,
    required this.icon,
    required this.onPress,
    this.variant = FButtonVariant.outline,
    super.key,
  });

  final String label;
  final IconData icon;
  final VoidCallback? onPress;
  final FButtonVariant variant;

  @override
  Widget build(BuildContext context) => FTooltip(
    tipBuilder: (context, controller) => Text(label),
    child: FButton.icon(
      key: ValueKey('action-$label'),
      variant: variant,
      onPress: onPress,
      semanticsLabel: label,
      child: Icon(icon, size: 17),
    ),
  );
}
