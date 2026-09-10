import 'package:forui/forui.dart';
import 'package:material_ui/material_ui.dart';

import '../ui/tokens/keylease_tokens.dart';

/// KeyLease themes.
///
/// Forui's neutral scheme is the base; the KeyLease accent replaces `primary`
/// and `error` follows the KeyLease danger token. Every brightness has both a
/// desktop and a touch density: nothing is hard-coded per screen, and the two
/// densities share the same brand.
abstract final class KeyLeaseTheme {
  static final _cache = <String, FThemeData>{};

  static FThemeData resolve({
    required Brightness brightness,
    required bool desktop,
  }) {
    final key = '$brightness/$desktop';
    return _cache[key] ??= _build(brightness: brightness, desktop: desktop);
  }

  static FThemeData _build({
    required Brightness brightness,
    required bool desktop,
  }) {
    final dark = brightness == Brightness.dark;
    final tokens = dark
        ? KeyLeaseTokens.dark(touch: !desktop)
        : KeyLeaseTokens.light(touch: !desktop);
    final base = FThemeData(
      debugLabel:
          'KeyLease ${dark ? 'Dark' : 'Light'} '
          '${desktop ? 'Desktop' : 'Touch'}',
      touch: !desktop,
      colors: (dark ? FColors.neutralDark : FColors.neutralLight).copyWith(
        primary: tokens.accent,
        primaryForeground: tokens.onAccent,
        error: tokens.danger,
      ),
    );
    if (!desktop) return base;

    // A desktop select is a short, direct interaction. Forui normally waits
    // for its 100ms closing animation before applying the selected value.
    // Besides feeling delayed, the scale transition makes a portal embedded
    // in a dialog unnecessarily expensive to composite. Keep touch motion
    // unchanged, but make desktop selects immediate.
    return base.copyWith(
      selectStyle: const FSelectStyleDelta.delta(
        contentStyle: FSelectContentStyleDelta.delta(
          motion: FPopoverMotion(
            entranceDuration: Duration.zero,
            exitDuration: Duration.zero,
            scaleTween: FImmutableTween(begin: 1.0, end: 1.0),
            fadeTween: FImmutableTween(begin: 1.0, end: 1.0),
          ),
        ),
      ),
    );
  }

  /// Maps the host platform to a Forui platform variant.
  static FPlatformVariant variantFor(TargetPlatform platform) =>
      switch (platform) {
        TargetPlatform.iOS => FPlatformVariant.iOS,
        TargetPlatform.android => FPlatformVariant.android,
        TargetPlatform.macOS => FPlatformVariant.macOS,
        TargetPlatform.windows => FPlatformVariant.windows,
        TargetPlatform.linux => FPlatformVariant.linux,
        TargetPlatform.fuchsia => FPlatformVariant.fuchsia,
      };

  static ThemeData material(FThemeData theme) =>
      theme.toApproximateMaterialTheme();
}
