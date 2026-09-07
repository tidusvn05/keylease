import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:keylease_desktop/ui_spikes/forui_spike.dart';
import 'package:keylease_desktop/ui_spikes/macos_ui_spike.dart';

void main() {
  Future<void> setDesktopSize(WidgetTester tester) async {
    tester.view.physicalSize = const Size(1280, 800);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
  }

  testWidgets('macos_ui spike supports selection, search and reveal',
      (tester) async {
    await setDesktopSize(tester);
    await tester.pumpWidget(const MacosUiSpikeApp());
    await tester.pumpAndSettle();

    expect(find.text('GitHub'), findsWidgets);
    await tester.tap(find.byKey(const ValueKey('entry-linear')));
    await tester.pumpAndSettle();
    expect(find.text('linear.app'), findsOneWidget);

    await tester.enterText(
      find.byKey(const ValueKey('macos-search')),
      'AWS',
    );
    await tester.pumpAndSettle();
    expect(find.text('AWS Console'), findsWidgets);
    expect(find.text('Linear'), findsNothing);

    await tester.tap(find.byKey(const ValueKey('action-Reveal password')));
    await tester.pumpAndSettle();
    expect(find.text('Demo-only!47-sample'), findsOneWidget);
  });

  testWidgets('Forui spike supports selection, search and reveal',
      (tester) async {
    await setDesktopSize(tester);
    await tester.pumpWidget(const ForuiSpikeApp());
    await tester.pumpAndSettle();

    expect(find.text('GitHub'), findsWidgets);
    await tester.tap(find.byKey(const ValueKey('entry-linear')));
    await tester.pumpAndSettle();
    expect(find.text('linear.app'), findsOneWidget);

    await tester.enterText(
      find.byKey(const ValueKey('forui-search')),
      'AWS',
    );
    await tester.pumpAndSettle();
    expect(find.text('AWS Console'), findsWidgets);
    expect(find.text('Linear'), findsNothing);

    await tester.tap(find.byKey(const ValueKey('action-Reveal password')));
    await tester.pumpAndSettle();
    expect(find.text('Demo-only!47-sample'), findsOneWidget);
  });
}
