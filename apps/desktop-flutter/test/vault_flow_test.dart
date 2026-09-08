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

  testWidgets('Prompt is scoped to the selected entry', (tester) async {
    final harness = await pumpVault(tester);

    await tester.tap(find.byKey(const ValueKey('entry-prompt-entry-github')));
    await tester.pump();

    expect(harness.adapter.copied, hasLength(1));
    final prompt = harness.adapter.copied.single;
    expect(prompt, startsWith('Use KeyLease entry'));
    expect(prompt, contains('entry-github'));
    expect(prompt, contains('GitHub'));
    expect(prompt, isNot(contains('Demo-only!47-sample')));
    expect(prompt, isNot(contains('client-token-fixture')));
    expect(prompt, isNot(contains('~/.keylease')));
    expect(prompt, isNot(contains('desktop.token')));
    expect(find.text('Entry prompt copied'), findsOneWidget);
    await tester.pump(const Duration(milliseconds: 400));
  });

  testWidgets('CLI copies a command scoped to the selected entry', (
    tester,
  ) async {
    final harness = await pumpVault(tester);

    await tester.tap(find.byKey(const ValueKey('entry-cli-entry-github')));
    await tester.pump();

    expect(harness.adapter.copied, ['keylease entries get entry-github']);
    expect(find.text('CLI command copied'), findsOneWidget);
    await tester.pump(const Duration(milliseconds: 400));
  });

  testWidgets('website value opens in the default browser', (tester) async {
    final harness = await pumpVault(tester);

    await tester.tap(find.byKey(const ValueKey('detail-field-value-Website')));
    await tester.pump();

    expect(harness.adapter.openedUrls, ['https://github.com']);
  });

  testWidgets('OTP action is hidden for entries without a typed OTP', (
    tester,
  ) async {
    await pumpVault(tester);

    expect(find.text('Two-factor authentication'), findsNothing);
    expect(find.text('Available on request'), findsNothing);
    expect(find.byKey(const ValueKey('action-Show code')), findsNothing);
  });

  testWidgets('notes load for the selected entry and can be copied', (
    tester,
  ) async {
    final harness = await pumpVault(
      tester,
      script: (client) => client.value('entries_search', [
        Fixtures.entry(
          kind: 'core.secure_note',
          username: '',
          urls: const [],
          hasPassword: false,
          hasNotes: true,
        ),
      ]),
    );

    expect(harness.app.vault.selectedEntry?.hasNotes, isTrue);
    expect(find.text('Login details'), findsNothing);
    expect(find.text('NOTES'), findsOneWidget);
    expect(find.textContaining('Recovery instructions'), findsOneWidget);
    expect(
      harness.client.calls.any(
        (call) =>
            call['command'] == 'entries_reveal' && call['field'] == 'notes',
      ),
      isTrue,
    );

    await tester.tap(find.byKey(const ValueKey('action-Copy notes')));
    await tester.pump();
    expect(harness.adapter.copied, [
      'Recovery instructions\n\nContact the account owner.',
    ]);
    await tester.pump(const Duration(milliseconds: 400));
  });

  testWidgets('metadata stays collapsed until requested', (tester) async {
    await pumpVault(tester);

    expect(find.text('Metadata'), findsOneWidget);
    expect(find.text('Revision'), findsNothing);
    await tester.tap(
      find.byKey(const ValueKey('metadata-toggle-entry-github')),
    );
    await tester.pumpAndSettle();
    expect(find.text('Revision'), findsOneWidget);
  });

  testWidgets('OTP entry loads and displays its code inline', (tester) async {
    final harness = await pumpVault(
      tester,
      script: (client) => client
        ..value('entries_search', [Fixtures.entry(hasTotp: true)])
        ..value('entries_totp', {'code': '123456', 'expires_in': 20}),
    );

    expect(find.text('Available on request'), findsNothing);
    expect(find.text('One-time password'), findsOneWidget);
    expect(find.textContaining('123456'), findsOneWidget);
    expect(
      harness.client.calls.where((call) => call['command'] == 'entries_totp'),
      hasLength(1),
    );
    await tester.tap(
      find.byKey(const ValueKey('action-Copy one-time password')),
    );
    await tester.pump();
    expect(harness.adapter.copied, ['123456']);
    // Let Forui's tap and tooltip timers drain before disposal.
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

  testWidgets('settings hide internal connection details', (tester) async {
    final harness = await pumpVault(tester);
    harness.app.selectSection(AppSection.settings);
    await tester.pumpAndSettle();

    expect(find.text('Managed vault'), findsOneWidget);
    expect(find.text('Background service'), findsOneWidget);
    expect(find.text('Unix socket'), findsNothing);
    expect(find.text('Client ID'), findsNothing);
    expect(find.textContaining('token'), findsNothing);
  });
}
