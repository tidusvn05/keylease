import 'package:flutter_test/flutter_test.dart';
import 'package:forui/forui.dart';
import 'package:leasegate_vault_ui/app/keylease_app.dart';
import 'package:leasegate_vault_ui/core/platform/app_capabilities.dart';
import 'package:leasegate_vault_ui/testing.dart';
import 'package:leasegate_vault_ui/ui/components/split_pane.dart';
import 'package:material_ui/material_ui.dart';

const _phone = Size(412, 915);
const _desktop = Size(1280, 800);

Future<void> pumpShell(
  WidgetTester tester, {
  Size size = _phone,
  TargetPlatform platform = TargetPlatform.android,
  AppCapabilities capabilities = AppCapabilities.androidPhone,
}) async {
  tester.view.physicalSize = size;
  tester.view.devicePixelRatio = 1;
  addTearDown(tester.view.reset);
  final app = buildController(capabilities: capabilities).app;
  await tester.pumpWidget(
    KeyLeaseApp(controller: app, platformOverride: platform),
  );
  await tester.pumpAndSettle();
}

/// Opens the delete confirmation from an entry, a real `showKeyLeaseDialog`
/// call site reachable on both form factors.
Future<void> openDeleteConfirmation(WidgetTester tester) async {
  await tester.tap(find.text('GitHub').first);
  await tester.pumpAndSettle();
  await tester.tap(find.bySemanticsLabel('Delete').first);
  await tester.pumpAndSettle();
}

void main() {
  group('modal presentation', () {
    testWidgets('a narrow screen gets a bottom sheet', (tester) async {
      // A centred dialog overflows once the IME opens at 412px.
      await pumpShell(tester);
      await openDeleteConfirmation(tester);
      expect(find.byType(BottomSheet), findsOneWidget);
      expect(find.byType(FDialog), findsNothing);
    });

    testWidgets('a wide screen keeps the centred dialog', (tester) async {
      await pumpShell(
        tester,
        size: _desktop,
        platform: TargetPlatform.macOS,
        capabilities: AppCapabilities.desktop,
      );
      await openDeleteConfirmation(tester);
      expect(find.byType(FDialog), findsOneWidget);
      expect(find.byType(BottomSheet), findsNothing);
    });
  });

  group('compact shell', () {
    testWidgets('a phone gets bottom navigation and no split pane', (
      tester,
    ) async {
      await pumpShell(tester);
      expect(find.byType(FBottomNavigationBar), findsOneWidget);
      expect(find.byType(SplitPane), findsNothing);
    });

    testWidgets('a desktop gets the split pane and no bottom bar', (
      tester,
    ) async {
      await pumpShell(
        tester,
        size: _desktop,
        platform: TargetPlatform.macOS,
        capabilities: AppCapabilities.desktop,
      );
      expect(find.byType(SplitPane), findsWidgets);
      expect(find.byType(FBottomNavigationBar), findsNothing);
    });

    testWidgets('the bottom bar clears the gesture inset', (tester) async {
      // Android 15 forces edge-to-edge; without a SafeArea the bar sits under
      // the gesture handle.
      tester.view.physicalSize = _phone;
      tester.view.devicePixelRatio = 1;
      tester.view.viewPadding = const FakeViewPadding(top: 132, bottom: 63);
      tester.view.padding = const FakeViewPadding(top: 132, bottom: 63);
      addTearDown(tester.view.reset);

      final app = buildController(capabilities: AppCapabilities.androidPhone)
          .app;
      await tester.pumpWidget(
        KeyLeaseApp(controller: app, platformOverride: TargetPlatform.android),
      );
      await tester.pumpAndSettle();

      final bar = tester.getRect(find.byType(FBottomNavigationBar));
      expect(
        bar.bottom,
        lessThanOrEqualTo(915 - 63 + 1),
        reason: 'the bar must sit above the gesture inset',
      );
    });
  });

  group('compact settings', () {
    testWidgets('the fixed rail is replaced by a pushable list', (
      tester,
    ) async {
      // The wide layout puts a 190px rail beside the content, which at 412px
      // would leave 222px for everything else.
      await pumpShell(tester);
      await tester.tap(find.text('Settings').last);
      await tester.pumpAndSettle();

      expect(
        find.byKey(const ValueKey('settings-general')),
        findsOneWidget,
        reason: 'every destination stays reachable',
      );
      final rail = find.byKey(const ValueKey('settings-security'));
      expect(rail, findsOneWidget);
      expect(
        tester.getSize(rail).width,
        greaterThan(222),
        reason: 'a destination should use the width, not sit in a 190px rail',
      );
    });
  });
}
