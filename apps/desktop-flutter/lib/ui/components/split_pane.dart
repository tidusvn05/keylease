import 'package:flutter/services.dart';
import 'package:forui/forui.dart';
import 'package:material_ui/material_ui.dart';

/// A two-pane split with a draggable, focusable separator.
///
/// Forui has no split view, so this is a KeyLease component: the leading pane
/// keeps a caller-owned width between [minWidth] and [maxWidth], the trailing
/// pane takes the rest, and the separator is reachable by keyboard as well as
/// by pointer.
class SplitPane extends StatelessWidget {
  const SplitPane({
    required this.width,
    required this.onWidthChanged,
    required this.leading,
    required this.trailing,
    required this.minWidth,
    required this.maxWidth,
    this.semanticsLabel = 'Resize pane',
    this.keyboardStep = 16,
    super.key,
  });

  final double width;
  final ValueChanged<double> onWidthChanged;
  final Widget leading;
  final Widget trailing;
  final double minWidth;
  final double maxWidth;
  final String semanticsLabel;
  final double keyboardStep;

  @override
  Widget build(BuildContext context) => LayoutBuilder(
    builder: (context, constraints) {
      final ceiling = constraints.maxWidth.isFinite
          ? maxWidth.clamp(minWidth, constraints.maxWidth)
          : maxWidth;
      final resolved = width.clamp(minWidth, ceiling).toDouble();
      void nudge(double delta) =>
          onWidthChanged((resolved + delta).clamp(minWidth, ceiling));
      return Row(
        children: [
          SizedBox(width: resolved, child: leading),
          _Separator(
            semanticsLabel: semanticsLabel,
            onDrag: (delta) => nudge(delta),
            onStep: (direction) => nudge(direction * keyboardStep),
          ),
          Expanded(child: trailing),
        ],
      );
    },
  );
}

class _Separator extends StatelessWidget {
  const _Separator({
    required this.semanticsLabel,
    required this.onDrag,
    required this.onStep,
  });

  final String semanticsLabel;
  final ValueChanged<double> onDrag;
  final ValueChanged<int> onStep;

  @override
  Widget build(BuildContext context) => Semantics(
    label: semanticsLabel,
    slider: true,
    child: FocusableActionDetector(
      shortcuts: const {
        SingleActivator(LogicalKeyboardKey.arrowLeft): _StepIntent(-1),
        SingleActivator(LogicalKeyboardKey.arrowRight): _StepIntent(1),
      },
      actions: {
        _StepIntent: CallbackAction<_StepIntent>(
          onInvoke: (intent) {
            onStep(intent.direction);
            return null;
          },
        ),
      },
      mouseCursor: SystemMouseCursors.resizeColumn,
      child: GestureDetector(
        behavior: HitTestBehavior.opaque,
        onHorizontalDragUpdate: (details) => onDrag(details.delta.dx),
        child: SizedBox(
          width: 7,
          child: Center(
            child: ColoredBox(
              color: context.theme.colors.border,
              child: const SizedBox(width: 1, height: double.infinity),
            ),
          ),
        ),
      ),
    ),
  );
}

class _StepIntent extends Intent {
  const _StepIntent(this.direction);

  final int direction;
}
