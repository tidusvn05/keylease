import 'package:flutter_test/flutter_test.dart';
import 'package:keylease_desktop/app/keylease_app.dart';
import 'package:keylease_desktop/core/platform/security_adapter.dart';
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

  testWidgets('changing template rebuilds the form from its schema', (
    tester,
  ) async {
    await pumpVault(
      tester,
      script: (client) => client.value('templates_list', [
        {
          'kind': 'core.login',
          'label': 'Login',
          'family': 'access',
          'markdown_notes': true,
          'fields': [
            {
              'key': 'username',
              'label': 'Username',
              'value_type': 'text',
              'semantic_role': 'username',
              'section': 'Login',
            },
            {
              'key': 'password',
              'label': 'Password',
              'value_type': 'concealed',
              'semantic_role': 'password',
              'protected': true,
              'section': 'Login',
            },
          ],
        },
        {
          'kind': 'core.note',
          'label': 'Note',
          'family': 'agent_content',
          'markdown_notes': true,
          'fields': <Map<String, dynamic>>[],
        },
        {
          'kind': 'core.credit_card',
          'label': 'Credit Card',
          'family': 'financial',
          'markdown_notes': true,
          'fields': [
            {
              'key': 'card_number',
              'label': 'Card number',
              'value_type': 'concealed',
              'semantic_role': 'card_number',
              'protected': true,
              'section': 'Card',
            },
            {
              'key': 'expiry',
              'label': 'Expiry',
              'value_type': 'month_year',
              'semantic_role': 'expiry',
              'section': 'Card',
            },
          ],
        },
      ]),
    );

    await tester.tap(find.byKey(const ValueKey('action-New item')));
    await tester.pumpAndSettle();
    expect(find.byKey(const ValueKey('entry-username')), findsOneWidget);
    expect(find.byKey(const ValueKey('entry-password')), findsOneWidget);

    await tester.tap(find.byKey(const ValueKey('entry-kind')));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Note').last);
    await tester.pumpAndSettle();

    expect(find.byKey(const ValueKey('entry-username')), findsNothing);
    expect(find.byKey(const ValueKey('entry-password')), findsNothing);
    expect(find.text('Markdown body'), findsOneWidget);
    expect(find.byKey(const ValueKey('entry-notes')), findsOneWidget);
    expect(find.byKey(const ValueKey('entry-tags')), findsOneWidget);
    expect(find.byKey(const ValueKey('entry-project')), findsOneWidget);
    expect(find.byKey(const ValueKey('entry-group')), findsNothing);

    await tester.tap(find.byKey(const ValueKey('entry-kind')));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Credit Card').last);
    await tester.pumpAndSettle();

    expect(
      find.byKey(const ValueKey('entry-template-card_number')),
      findsOneWidget,
    );
    expect(find.byKey(const ValueKey('entry-template-expiry')), findsOneWidget);
    expect(find.byKey(const ValueKey('entry-tags')), findsNothing);
    expect(find.byKey(const ValueKey('entry-group')), findsOneWidget);
  });

  testWidgets('settings hide internal connection details', (tester) async {
    final harness = await pumpVault(tester);
    harness.app.selectSection(AppSection.settings);
    await tester.pumpAndSettle();

    expect(find.text('KeyLease data'), findsOneWidget);
    expect(find.text('Background service'), findsOneWidget);
    expect(find.text('Unix socket'), findsNothing);
    expect(find.text('Client ID'), findsNothing);
    expect(find.textContaining('token'), findsNothing);

    final general = tester.getRect(
      find.byKey(const ValueKey('settings-general')),
    );
    final vaults = tester.getRect(
      find.byKey(const ValueKey('settings-vaults')),
    );
    expect(vaults.top - general.bottom, greaterThanOrEqualTo(3));

    await tester.tap(find.byKey(const ValueKey('settings-security')));
    await tester.pumpAndSettle();
    expect(find.text('Clipboard'), findsOneWidget);
    expect(find.text('Sleep and screen lock'), findsOneWidget);
  });

  testWidgets('standalone generator copies and creates a prefilled Login', (
    tester,
  ) async {
    final harness = await pumpVault(tester);

    await tester.tap(find.byKey(const ValueKey('tool-password-generator')));
    await tester.pumpAndSettle();

    expect(find.text('Password generator'), findsWidgets);
    expect(find.byKey(const ValueKey('password-copied')), findsOneWidget);
    expect(harness.adapter.copied, ['generated-32-characters-long!!']);
    await tester.pump(const Duration(seconds: 1));
    expect(find.byKey(const ValueKey('password-copied')), findsNothing);

    await tester.tap(find.byKey(const ValueKey('password-use')));
    await tester.pumpAndSettle();

    expect(find.text('New item'), findsOneWidget);
    expect(harness.app.vault.activeDraft?.kind, 'core.login');
    expect(
      harness.app.vault.activeDraft?.password,
      'generated-32-characters-long!!',
    );
  });

  testWidgets('password field generates immediately and shows copied briefly', (
    tester,
  ) async {
    final harness = await pumpVault(tester);

    await tester.tap(find.byKey(const ValueKey('action-New item')));
    await tester.pumpAndSettle();
    expect(
      find.byKey(const ValueKey('entry-password-settings')),
      findsOneWidget,
    );

    await tester.tap(find.byKey(const ValueKey('entry-password-generate')));
    await tester.pump();
    await tester.pump();

    expect(harness.adapter.copied, ['generated-32-characters-long!!']);
    expect(
      find.bySemanticsLabel('Password generated and copied'),
      findsOneWidget,
    );
    expect(find.text('Password generator settings'), findsNothing);

    await tester.pump(const Duration(seconds: 1));
    expect(find.bySemanticsLabel('Generate and copy password'), findsOneWidget);

    await tester.tap(find.byKey(const ValueKey('entry-password-settings')));
    await tester.pumpAndSettle();
    expect(find.text('Password generator settings'), findsOneWidget);
    expect(
      find.byKey(const ValueKey('password-settings-save')),
      findsOneWidget,
    );
  });

  testWidgets('Login editor scans a TOTP QR image into the item', (
    tester,
  ) async {
    final harness = await pumpVault(tester);
    const uri =
        'otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Example';
    harness.adapter.qrCodeToReturn = uri;

    await tester.tap(find.byKey(const ValueKey('action-New item')));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const ValueKey('entry-totp-scan')));
    await tester.pumpAndSettle();

    expect(harness.app.vault.activeDraft?.totp, uri);
    final editable = tester.widget<EditableText>(
      find.descendant(
        of: find.byKey(const ValueKey('entry-totp')),
        matching: find.byType(EditableText),
      ),
    );
    expect(editable.controller.text, uri);
  });

  testWidgets('Login editor scans a TOTP QR code from the screen', (
    tester,
  ) async {
    final harness = await pumpVault(tester);
    const uri =
        'otpauth://totp/Screen:alice?secret=JBSWY3DPEHPK3PXP&issuer=Screen';
    harness.adapter.screenQrCodeToReturn = uri;

    await tester.tap(find.byKey(const ValueKey('action-New item')));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const ValueKey('entry-totp-scan-screen')));
    await tester.pumpAndSettle();

    expect(harness.adapter.screenQrScanRequests, 1);
    expect(harness.app.vault.activeDraft?.totp, uri);
  });

  testWidgets('Screen scan permission error links to System Settings', (
    tester,
  ) async {
    final harness = await pumpVault(tester);
    harness.adapter.screenQrScanError =
        const ScreenRecordingPermissionRequired();

    await tester.tap(find.byKey(const ValueKey('action-New item')));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const ValueKey('entry-totp-scan-screen')));
    await tester.pumpAndSettle();

    expect(find.text('Screen Recording permission needed'), findsOneWidget);
    await tester.tap(find.text('Open System Settings'));
    await tester.pumpAndSettle();
    expect(harness.adapter.screenRecordingSettingsRequests, 1);
  });
}
