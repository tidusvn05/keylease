import 'package:flutter_test/flutter_test.dart';
import 'package:keylease_desktop/ui_spikes/forui_spike.dart';
import 'package:material_ui/material_ui.dart';

// The macos_ui comparison spike is archived under `spikes/macos_ui/` and is no
// longer part of the production dependency graph, so it is not exercised here.
void main() {
  Future<void> setDesktopSize(WidgetTester tester) async {
    tester.view.physicalSize = const Size(1280, 800);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
  }

  testWidgets('Forui spike supports selection, search and reveal', (
    tester,
  ) async {
    await setDesktopSize(tester);
    await tester.pumpWidget(const ForuiSpikeApp());
    await tester.pumpAndSettle();

    expect(find.text('GitHub'), findsWidgets);
    await tester.tap(find.byKey(const ValueKey('entry-linear')));
    await tester.pumpAndSettle();
    expect(find.text('linear.app'), findsOneWidget);

    await tester.enterText(find.byKey(const ValueKey('forui-search')), 'AWS');
    await tester.pumpAndSettle();
    expect(find.text('AWS Console'), findsWidgets);
    expect(find.text('Linear'), findsNothing);

    await tester.tap(find.byKey(const ValueKey('action-Reveal password')));
    await tester.pumpAndSettle();
    expect(find.text('Demo-only!47-sample'), findsOneWidget);
  });
}
