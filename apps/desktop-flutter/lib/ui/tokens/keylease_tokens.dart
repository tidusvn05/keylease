import 'package:flutter/widgets.dart';
import 'package:forui/forui.dart';

/// KeyLease design tokens.
///
/// Sizes come from the HTML prototype's baseline (sidebar 214, list 306,
/// compact 190/263, toolbar 61, row 65, controls 30–36, body 13–14,
/// metadata 11–12, item title 25). They are a density contract, not a
/// pixel-for-pixel port: the touch density scales the same tokens up.
/// Pane widths the desktop shell starts from, in logical pixels.
///
/// These live outside [KeyLeaseTokens] because [AppController] restores them
/// from preferences before there is a [BuildContext] to resolve a theme.
abstract final class KeyLeaseLayout {
  static const sidebarWidth = 214.0;
  static const listWidth = 306.0;
}

@immutable
class KeyLeaseTokens {
  const KeyLeaseTokens({
    required this.brightness,
    required this.touch,
    required this.accent,
    required this.onAccent,
    required this.success,
    required this.warning,
    required this.danger,
    required this.markSurface,
    required this.markForeground,
  });

  factory KeyLeaseTokens.of(BuildContext context) {
    final touch = !context.platformVariant.desktop;
    return FTheme.of(context).colors.brightness == Brightness.dark
        ? KeyLeaseTokens.dark(touch: touch)
        : KeyLeaseTokens.light(touch: touch);
  }

  factory KeyLeaseTokens.light({required bool touch}) => KeyLeaseTokens(
    brightness: Brightness.light,
    touch: touch,
    accent: const Color(0xff0b68d5),
    onAccent: const Color(0xffffffff),
    success: const Color(0xff1a7f47),
    warning: const Color(0xff9a6207),
    danger: const Color(0xffb3261e),
    markSurface: const Color(0x140b68d5),
    markForeground: const Color(0xff0b68d5),
  );

  factory KeyLeaseTokens.dark({required bool touch}) => KeyLeaseTokens(
    brightness: Brightness.dark,
    touch: touch,
    accent: const Color(0xff6aa9f5),
    onAccent: const Color(0xff08121f),
    success: const Color(0xff5ec98b),
    warning: const Color(0xffe0b062),
    danger: const Color(0xffef8079),
    markSurface: const Color(0x1f6aa9f5),
    markForeground: const Color(0xff9cc7fa),
  );

  final Brightness brightness;
  final bool touch;

  final Color accent;
  final Color onAccent;
  final Color success;
  final Color warning;
  final Color danger;
  final Color markSurface;
  final Color markForeground;

  double get _scale => touch ? 1.18 : 1;

  // Layout
  double get sidebarMinWidth => 180 * _scale;
  double get sidebarMaxWidth => 320 * _scale;
  double get listMinWidth => 240 * _scale;
  double get listMaxWidth => 460 * _scale;

  /// Below this the shell drops the detail pane and routes list → detail.
  double get splitBreakpoint => 660;

  /// Below this the shell uses compact navigation instead of a sidebar.
  double get compactBreakpoint => 560;

  /// Above this a tablet gets the full desktop sidebar rather than a rail.
  double get expandedBreakpoint => 900;

  // Spacing
  double get gutter => 16 * _scale;
  double get gutterSmall => 8 * _scale;
  double get markSize => 37 * _scale;
  double get largeMarkSize => 54 * _scale;
  double get markRadius => 9;

  // Typography
  double get bodySize => touch ? 15 : 13;
  double get titleSize => touch ? 22 : 25;

  Color statusColor(String health) => switch (health) {
    'connected' => success,
    'degraded' || 'expired' => warning,
    'revoked' || 'disconnected' => danger,
    _ => warning,
  };
}
