import 'dart:math' as math;

import 'package:flutter_test/flutter_test.dart';
import 'package:leasegate_vault_ui/app/app_theme.dart';
import 'package:leasegate_vault_ui/ui/tokens/keylease_tokens.dart';
import 'package:material_ui/material_ui.dart';

void main() {
  test('desktop selects apply values without waiting for overlay motion', () {
    final theme = KeyLeaseTheme.resolve(
      brightness: Brightness.dark,
      desktop: true,
    );
    final motion = theme.selectStyle.contentStyle.motion;

    expect(motion.entranceDuration, Duration.zero);
    expect(motion.exitDuration, Duration.zero);
    expect(motion.scaleTween.transform(0), 1);
    expect(motion.fadeTween.transform(0), 1);
  });

  test('touch selects retain platform motion', () {
    final theme = KeyLeaseTheme.resolve(
      brightness: Brightness.dark,
      desktop: false,
    );

    expect(
      theme.selectStyle.contentStyle.motion.exitDuration,
      isNot(Duration.zero),
    );
  });
  group('brand palette', () {
    // brand/BRAND.md is the written specification and the shipped Android
    // assets already derive from it. Pinning the values here stops the Dart
    // palette drifting away from it again, which is how the desktop app and
    // the approval app ended up with three different accents.
    const gatewayBlue = Color(0xff2f72ff);
    const cloud = Color(0xfff5f8fc);
    const midnight = Color(0xff071426);

    test('the light accent is Gateway Blue', () {
      expect(KeyLeaseTokens.light(touch: false).accent, gatewayBlue);
    });

    test('the accent is usable as a fill on the brand background', () {
      // BRAND.md assigns Gateway Blue to "mark, actions, focus" — UI
      // components, where WCAG asks 3:1 rather than 4.5:1.
      final tokens = KeyLeaseTokens.light(touch: false);
      expect(_contrast(tokens.accent, cloud), greaterThanOrEqualTo(3.0));
    });

    test('accent text reaches 4.5:1 in both themes', () {
      // Gateway Blue itself only manages 3.97:1 on Cloud, so text and icons
      // use a slightly darker same-hue variant. This is the assertion that
      // stops someone "fixing" accentText back to the brand hex.
      expect(
        _contrast(KeyLeaseTokens.light(touch: false).accentText, cloud),
        greaterThanOrEqualTo(4.5),
      );
      expect(
        _contrast(KeyLeaseTokens.dark(touch: false).accentText, midnight),
        greaterThanOrEqualTo(4.5),
      );
    });

    test('semantic colours stay readable as text', () {
      final light = KeyLeaseTokens.light(touch: false);
      for (final entry in {
        'success': light.success,
        'warning': light.warning,
        'danger': light.danger,
      }.entries) {
        expect(
          _contrast(entry.value, cloud),
          greaterThanOrEqualTo(4.5),
          reason: '${entry.key} is used for text and must clear AA',
        );
      }
    });
  });
}

/// WCAG relative luminance.
double _luminance(Color color) {
  double channel(double raw) => raw <= 0.04045
      ? raw / 12.92
      : math.pow((raw + 0.055) / 1.055, 2.4).toDouble();
  return 0.2126 * channel(color.r) +
      0.7152 * channel(color.g) +
      0.0722 * channel(color.b);
}

double _contrast(Color a, Color b) {
  final la = _luminance(a);
  final lb = _luminance(b);
  final hi = math.max(la, lb);
  final lo = math.min(la, lb);
  return (hi + 0.05) / (lo + 0.05);
}
