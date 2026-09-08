import 'package:flutter_test/flutter_test.dart';
import 'package:forui/forui.dart';
import 'package:keylease_desktop/app/app_theme.dart';
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
}
