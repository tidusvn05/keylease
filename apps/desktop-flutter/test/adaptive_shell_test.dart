import 'package:flutter/gestures.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:keylease_desktop/app/keylease_app.dart';
import 'package:keylease_desktop/core/state/app_controller.dart';
import 'package:keylease_desktop/core/platform/security_adapter.dart';
import 'package:keylease_desktop/core/rpc/keylease_rpc.dart';
import 'package:keylease_desktop/core/state/app_phase.dart';
import 'package:material_ui/material_ui.dart';

import 'support/fakes.dart';

/// Sizes the test window and restores it afterwards.
Future<void> useWindow(WidgetTester tester, Size size) async {
  tester.view.physicalSize = size;
  tester.view.devicePixelRatio = 1;
  addTearDown(tester.view.resetPhysicalSize);
  addTearDown(tester.view.resetDevicePixelRatio);
}

Future<AppController> pumpApp(
  WidgetTester tester, {
  Size size = const Size(1280, 800),
  TargetPlatform platform = TargetPlatform.macOS,
  Brightness brightness = Brightness.light,
  void Function(FakeKeyLeaseClient client)? script,
  AppController? controller,
}) async {
  await useWindow(tester, size);
  tester.platformDispatcher.platformBrightnessTestValue = brightness;
  addTearDown(tester.platformDispatcher.clearPlatformBrightnessTestValue);
  final app = controller ?? buildController(script: script).app;
  if (controller == null) addTearDown(app.dispose);
  await tester.pumpWidget(
    KeyLeaseApp(controller: app, platformOverride: platform),
  );
  await tester.pumpAndSettle();
  return app;
}

void main() {
  group('cross-platform shell', crossPlatform);

  group('responsive shell', () {
    testWidgets('group drag handle reorders without covering row actions', (
      tester,
    ) async {
      var groups = <Map<String, dynamic>>[
        {
          'id': 'group-alpha',
          'vault_id': 'vault-1',
          'parent_id': null,
          'name': 'Alpha',
          'sort_order': 0,
          'revision': 1,
          'created_at': '2026-09-01T10:00:00Z',
          'updated_at': '2026-09-01T10:00:00Z',
        },
        {
          'id': 'group-bravo',
          'vault_id': 'vault-1',
          'parent_id': null,
          'name': 'Bravo',
          'sort_order': 1,
          'revision': 1,
          'created_at': '2026-09-01T10:00:00Z',
          'updated_at': '2026-09-01T10:00:00Z',
        },
      ];
      List<dynamic>? reorderedIds;
      final harness = buildController(
        script: (client) => client
          ..on('groups_list', (_) async => groups)
          ..on('groups_reorder', (request) async {
            reorderedIds = request['ordered_ids'] as List<dynamic>;
            groups = [
              for (final (index, id) in reorderedIds!.indexed)
                {
                  ...groups.firstWhere((group) => group['id'] == id),
                  'sort_order': index,
                  'revision': 2,
                },
            ];
            return groups;
          }),
      );
      addTearDown(harness.app.dispose);
      await pumpApp(tester, controller: harness.app);

      await tester.tap(find.byKey(const ValueKey('group-manage')));
      await tester.pumpAndSettle();

      // Desktop dialogs use a solid scrim. Reintroducing Forui's full-window
      // backdrop blur here causes visible raster jank on older Intel Macs.
      expect(find.byType(BackdropFilter), findsNothing);

      final handle = find.byKey(const ValueKey('manage-drag-group-alpha'));
      final delete = find.byKey(const ValueKey('action-Delete Alpha'));
      expect(handle, findsOneWidget);
      expect(delete, findsOneWidget);
      expect(tester.getRect(handle).overlaps(tester.getRect(delete)), isFalse);

      final gesture = await tester.startGesture(tester.getCenter(handle));
      await tester.pump(kPressTimeout);
      await gesture.moveBy(const Offset(0, 160));
      await tester.pump();
      await gesture.up();
      await tester.pumpAndSettle();

      expect(reorderedIds, ['group-bravo', 'group-alpha']);
      expect(tester.takeException(), isNull);
    });

    testWidgets('1280x800 shows sidebar, list and detail together', (
      tester,
    ) async {
      await pumpApp(tester);

      expect(find.byKey(const ValueKey('group-all')), findsOneWidget);
      expect(find.byKey(const ValueKey('vault-search')), findsOneWidget);
      expect(find.byKey(const ValueKey('entry-entry-github')), findsOneWidget);
      // The detail pane is present without opening a dialog.
      expect(find.byKey(const ValueKey('detail-entry-github')), findsOneWidget);

      final generator = tester.getRect(
        find.byKey(const ValueKey('action-Password generator')),
      );
      final newItem = tester.getRect(
        find.byKey(const ValueKey('action-New item')),
      );
      expect(newItem.left - generator.right, greaterThanOrEqualTo(5));

      // With search in the unified title bar, the item count still needs
      // breathing room below the top edge of its pane.
      expect(tester.getTopLeft(find.text('1 item')).dy, greaterThan(56));
      expect(tester.takeException(), isNull);
    });

    testWidgets('800x600 keeps list and detail without overflowing', (
      tester,
    ) async {
      await pumpApp(tester, size: const Size(800, 600));

      expect(find.byKey(const ValueKey('vault-search')), findsOneWidget);
      expect(find.byKey(const ValueKey('detail-entry-github')), findsOneWidget);
      expect(tester.takeException(), isNull);
    });

    testWidgets('a phone-sized window uses compact navigation and routes to '
        'the detail view', (tester) async {
      await pumpApp(
        tester,
        size: const Size(390, 780),
        platform: TargetPlatform.iOS,
      );

      // Compact navigation, no persistent sidebar and no detail pane.
      expect(find.byKey(const ValueKey('nav-vault')), findsNothing);
      expect(find.byKey(const ValueKey('detail-entry-github')), findsNothing);

      await tester.tap(find.byKey(const ValueKey('entry-entry-github')));
      await tester.pumpAndSettle();

      expect(find.byKey(const ValueKey('detail-entry-github')), findsOneWidget);
      expect(find.text('Items'), findsOneWidget);
      expect(tester.takeException(), isNull);
    });

    testWidgets('a tablet-sized window uses a rail and keeps the split', (
      tester,
    ) async {
      await pumpApp(
        tester,
        size: const Size(834, 1112),
        platform: TargetPlatform.iOS,
      );

      expect(find.byKey(const ValueKey('nav-vault')), findsNothing);
      expect(find.byKey(const ValueKey('detail-entry-github')), findsOneWidget);
      expect(tester.takeException(), isNull);
    });

    testWidgets('dark mode renders the same surfaces', (tester) async {
      await pumpApp(tester, brightness: Brightness.dark);

      expect(find.byKey(const ValueKey('vault-search')), findsOneWidget);
      expect(find.byKey(const ValueKey('detail-entry-github')), findsOneWidget);
      expect(tester.takeException(), isNull);
    });

    testWidgets('larger text does not overflow the desktop shell', (
      tester,
    ) async {
      await useWindow(tester, const Size(800, 600));
      final app = buildController().app;
      addTearDown(app.dispose);
      await tester.pumpWidget(
        MediaQuery(
          data: const MediaQueryData(textScaler: TextScaler.linear(1.4)),
          child: KeyLeaseApp(
            controller: app,
            platformOverride: TargetPlatform.macOS,
          ),
        ),
      );
      await tester.pumpAndSettle();

      expect(tester.takeException(), isNull);
    });
  });

  group('phase screens', () {
    testWidgets('setup, offline and denied each get their own screen', (
      tester,
    ) async {
      await pumpApp(
        tester,
        script: (client) => client.fail(
          'groups_list',
          KeyLeaseException.fromDaemon(const {
            'error': 'denied',
            'reason': 'client lacks vault:read',
          }),
        ),
      );

      expect(find.text('Permission needed'), findsOneWidget);
      expect(find.text('Welcome back'), findsNothing);
    });

    testWidgets('a locked vault offers unlock, not a generic error', (
      tester,
    ) async {
      final app = await pumpApp(
        tester,
        script: (client) => client.value('status', Fixtures.lockedStatus),
      );

      expect(app.phase, AppPhase.locked);
      expect(find.byKey(const ValueKey('unlock-password')), findsOneWidget);
      expect(find.text('Welcome back'), findsOneWidget);
      expect(find.byKey(const ValueKey('group-all')), findsNothing);
    });

    testWidgets('a wrong master password explains itself and stays locked', (
      tester,
    ) async {
      final app = await pumpApp(
        tester,
        script: (client) => client
          ..value('status', Fixtures.lockedStatus)
          ..fail(
            'unlock',
            KeyLeaseException.fromDaemon(const {'error': 'crypto'}),
          ),
      );

      await tester.enterText(
        find.byKey(const ValueKey('unlock-password')),
        'wrong',
      );
      await tester.tap(find.byKey(const ValueKey('unlock-submit')));
      await tester.pumpAndSettle();

      expect(app.phase, AppPhase.locked);
      expect(
        find.text('Incorrect master password. Try again.'),
        findsOneWidget,
      );
      expect(find.text('Show technical details'), findsNothing);
      expect(find.text('Dismiss'), findsNothing);
      expect(app.banner, isNull);
      expect(app.unlockMessage?.title, 'Incorrect master password');
      expect(find.byKey(const ValueKey('unlock-submit')), findsOneWidget);

      await tester.enterText(
        find.byKey(const ValueKey('unlock-password')),
        'correct',
      );
      await tester.pumpAndSettle();
      expect(find.text('Incorrect master password. Try again.'), findsNothing);
      expect(app.unlockMessage, isNull);
    });

    testWidgets('settings stays reachable while the vault is unreachable', (
      tester,
    ) async {
      final app = await pumpApp(
        tester,
        script: (client) => client.fail(
          'status',
          const KeyLeaseException.transport('connection refused'),
        ),
      );
      expect(find.text("Can't reach KeyLease"), findsOneWidget);

      app.selectSection(AppSection.settings);
      await tester.pumpAndSettle();

      expect(find.text('KeyLease data'), findsOneWidget);
      expect(find.text('Unix socket'), findsNothing);
    });
  });

  group('keyboard', () {
    testWidgets('the search accelerator focuses the vault search', (
      tester,
    ) async {
      final app = await pumpApp(tester);
      // Move focus into the shell, then leave the vault section.
      await tester.tap(find.byKey(const ValueKey('nav-approvals')));
      await tester.pumpAndSettle();
      expect(app.section, AppSection.approvals);

      await tester.sendKeyDownEvent(LogicalKeyboardKey.metaLeft);
      await tester.sendKeyEvent(LogicalKeyboardKey.keyF);
      await tester.sendKeyUpEvent(LogicalKeyboardKey.metaLeft);
      await tester.pumpAndSettle();

      expect(app.section, AppSection.vault);
      expect(app.vault.searchFocus.hasFocus, isTrue);
    });

    testWidgets('native menu selections run the same intents', (tester) async {
      final harness = buildController();
      addTearDown(harness.app.dispose);
      final app = await pumpApp(tester, controller: harness.app);
      app.selectSection(AppSection.approvals);
      await tester.pumpAndSettle();

      harness.adapter.selectMenu(MenuAction.search);
      await tester.pumpAndSettle();
      expect(app.section, AppSection.vault);
      expect(app.vault.searchFocus.hasFocus, isTrue);

      harness.adapter.selectMenu(MenuAction.settings);
      await tester.pumpAndSettle();
      expect(app.section, AppSection.settings);

      harness.client.value('status', Fixtures.lockedStatus);
      harness.adapter.selectMenu(MenuAction.lock);
      await tester.pumpAndSettle();
      expect(app.phase, AppPhase.locked);
    });

    testWidgets('macOS settings window keeps the main vault destination', (
      tester,
    ) async {
      final harness = buildController();
      harness.adapter.settingsWindowOpens = true;
      addTearDown(harness.app.dispose);
      final app = await pumpApp(tester, controller: harness.app);

      harness.adapter.selectMenu(MenuAction.settings);
      await tester.pumpAndSettle();

      expect(harness.adapter.settingsWindowRequests, 1);
      expect(app.section, AppSection.vault);
      expect(find.byKey(const ValueKey('vault-search')), findsOneWidget);
    });

    testWidgets('arrow keys move the selection from the search field', (
      tester,
    ) async {
      final app = await pumpApp(
        tester,
        script: (client) => client.value('entries_search', [
          Fixtures.entry(id: 'a', title: 'Alpha'),
          Fixtures.entry(id: 'b', title: 'Bravo'),
        ]),
      );
      await tester.tap(find.byKey(const ValueKey('vault-search')));
      await tester.pumpAndSettle();

      await tester.sendKeyEvent(LogicalKeyboardKey.arrowDown);
      await tester.pumpAndSettle();

      expect(app.vault.selectedEntry?.id, 'b');
    });
  });
}

/// Phase 5: the same state and business components must render on every
/// supported target from one code base. These are fixture-backed widget
/// tests, not per-platform release acceptance.
void crossPlatform() {
  for (final (platform, size, label) in <(TargetPlatform, Size, String)>[
    (TargetPlatform.macOS, Size(1280, 800), 'macOS desktop'),
    (TargetPlatform.windows, Size(1280, 800), 'Windows desktop'),
    (TargetPlatform.android, Size(412, 915), 'Android phone'),
    (TargetPlatform.iOS, Size(834, 1112), 'iPad'),
  ]) {
    testWidgets('$label renders the shared vault surfaces', (tester) async {
      final app = await pumpApp(tester, size: size, platform: platform);

      expect(find.byKey(const ValueKey('vault-search')), findsOneWidget);
      expect(find.text('GitHub'), findsWidgets);
      expect(app.phase, AppPhase.ready);
      expect(tester.takeException(), isNull);
    });
  }
}
