import 'package:flutter_test/flutter_test.dart';
import 'package:keylease_desktop/app/keylease_app.dart';
import 'package:keylease_desktop/core/rpc/keylease_rpc.dart';
import 'package:keylease_desktop/core/state/app_controller.dart';
import 'package:keylease_desktop/core/state/app_phase.dart';
import 'package:material_ui/material_ui.dart';

import 'support/fakes.dart';

Future<
  ({AppController app, FakeKeyLeaseClient client, FakeSecurityAdapter adapter})
>
pumpVault(
  WidgetTester tester, {
  Size size = const Size(1280, 800),
  void Function(FakeKeyLeaseClient client)? script,
}) async {
  tester.view.physicalSize = size;
  tester.view.devicePixelRatio = 1;
  addTearDown(tester.view.resetPhysicalSize);
  addTearDown(tester.view.resetDevicePixelRatio);
  final harness = buildController(script: script);
  addTearDown(harness.app.dispose);
  await tester.pumpWidget(
    KeyLeaseApp(
      controller: harness.app,
      platformOverride: TargetPlatform.macOS,
    ),
  );
  await tester.pumpAndSettle();
  return harness;
}

void main() {
  testWidgets('search, select and copy works with the pointer', (tester) async {
    final harness = await pumpVault(
      tester,
      script: (client) => client.on('entries_search', (request) async {
        final query = '${request['query']}'.toLowerCase();
        final all = [
          Fixtures.entry(id: 'github', title: 'GitHub'),
          Fixtures.entry(id: 'aws', title: 'AWS Console', username: 'admin'),
        ];
        return all
            .where((entry) => '${entry['title']}'.toLowerCase().contains(query))
            .toList();
      }),
    );
    harness.app.vault.searchDebounce = Duration.zero;

    await tester.enterText(find.byKey(const ValueKey('vault-search')), 'aws');
    await tester.pumpAndSettle();
    expect(find.text('AWS Console'), findsWidgets);
    expect(find.text('GitHub'), findsNothing);

    await tester.tap(find.byKey(const ValueKey('entry-aws')));
    await tester.pumpAndSettle();

    // The password is masked until the user asks for it.
    expect(find.text('Demo-only!47-sample'), findsNothing);
    await tester.tap(find.byKey(const ValueKey('action-Copy Password')));
    await tester.pumpAndSettle();

    expect(harness.adapter.copied, ['Demo-only!47-sample']);
    // Copying is not a reveal: the field stays masked.
    expect(find.text('Demo-only!47-sample'), findsNothing);
    expect(harness.app.vault.hasRevealedSecrets, isFalse);
  });

  testWidgets('reveal shows the secret only after an explicit request', (
    tester,
  ) async {
    final harness = await pumpVault(tester);

    expect(find.text('Demo-only!47-sample'), findsNothing);
    await tester.tap(find.byKey(const ValueKey('action-Reveal Password')));
    await tester.pumpAndSettle();
    expect(find.text('Demo-only!47-sample'), findsOneWidget);

    await tester.tap(find.byKey(const ValueKey('action-Hide Password')));
    await tester.pumpAndSettle();
    expect(find.text('Demo-only!47-sample'), findsNothing);
    expect(harness.app.vault.hasRevealedSecrets, isFalse);
    // Let Forui's tooltip dismissal timer drain before the tree is disposed.
    await tester.pump(const Duration(milliseconds: 400));
  });

  testWidgets('a rejected save keeps the editor open with the typed values', (
    tester,
  ) async {
    await pumpVault(
      tester,
      script: (client) => client.fail(
        'entries_update',
        KeyLeaseException.fromDaemon(const {
          'error': 'revision_conflict',
          'expected': 3,
          'actual': 4,
          'retryable': true,
        }),
      ),
    );

    await tester.tap(find.byKey(const ValueKey('action-Edit')));
    await tester.pumpAndSettle();

    await tester.enterText(
      find.byKey(const ValueKey('entry-title')),
      'GitHub renamed',
    );
    await tester.tap(find.byKey(const ValueKey('entry-save')));
    await tester.pumpAndSettle();

    // The dialog stays open, explains the conflict, and keeps the draft.
    expect(find.text('This item changed elsewhere'), findsOneWidget);
    expect(find.text('GitHub renamed'), findsWidgets);
    expect(find.byKey(const ValueKey('entry-save')), findsOneWidget);
  });

  testWidgets('settings apply on save and revert on cancel', (tester) async {
    final harness = await pumpVault(tester);
    harness.app.selectSection(AppSection.settings);
    await tester.pumpAndSettle();

    await tester.enterText(
      find.byKey(const ValueKey('settings-agent')),
      'agent_other',
    );
    await tester.pumpAndSettle();
    // Nothing is applied until Save.
    expect(harness.app.settings.agentId, 'agent_test');

    await tester.tap(find.byKey(const ValueKey('settings-cancel')));
    await tester.pumpAndSettle();
    expect(harness.app.settings.agentId, 'agent_test');

    await tester.enterText(
      find.byKey(const ValueKey('settings-agent')),
      'agent_other',
    );
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const ValueKey('settings-save')));
    await tester.pumpAndSettle();

    expect(harness.app.settings.agentId, 'agent_other');
  });
}
