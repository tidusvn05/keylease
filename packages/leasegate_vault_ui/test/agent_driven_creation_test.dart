import 'package:flutter_test/flutter_test.dart';
import 'package:leasegate_vault_ui/app/keylease_app.dart';
import 'package:leasegate_vault_ui/core/state/agent_creation_draft.dart';
import 'package:leasegate_vault_ui/core/state/app_controller.dart';
import 'package:material_ui/material_ui.dart';

import 'package:leasegate_vault_ui/testing.dart';

const _templates = <Map<String, dynamic>>[
  {
    'kind': 'core.login',
    'label': 'Login',
    'family': 'common',
    'markdown_notes': true,
    'fields': <Map<String, dynamic>>[],
  },
  {
    'kind': 'core.environment',
    'label': 'Environment',
    'family': 'developer',
    'markdown_notes': true,
    'fields': <Map<String, dynamic>>[],
  },
  {
    'kind': 'core.ssh_server',
    'label': 'SSH Server',
    'family': 'developer',
    'markdown_notes': true,
    'fields': <Map<String, dynamic>>[],
  },
  {
    'kind': 'core.prompt',
    'label': 'Prompt',
    'family': 'agent_content',
    'markdown_notes': true,
    'fields': <Map<String, dynamic>>[],
  },
];

Future<
  ({AppController app, FakeKeyLeaseClient client, FakeSecurityAdapter adapter})
>
_pump(
  WidgetTester tester, {
  void Function(FakeKeyLeaseClient client)? script,
}) async {
  tester.view.physicalSize = const Size(1280, 800);
  tester.view.devicePixelRatio = 1;
  addTearDown(tester.view.resetPhysicalSize);
  addTearDown(tester.view.resetDevicePixelRatio);
  final harness = buildController(
    script: (client) {
      client.value('templates_list', _templates);
      client.value('agent_handoff_create', {
        'protocol_version': 1,
        'handoff_id': 'handoff-test',
        'command': 'keylease agent new-item handoff-test',
        'expires_at': DateTime.now()
            .add(const Duration(hours: 2))
            .toUtc()
            .toIso8601String(),
      });
      script?.call(client);
    },
  );
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
  test('handoff receipt produces only a short CLI navigation message', () {
    final handoff = AgentCreationHandoff.fromJson({
      'handoff_id': 'handoff-test',
      'command': 'keylease agent new-item handoff-test',
      'expires_at': DateTime.now()
          .add(const Duration(hours: 2))
          .toUtc()
          .toIso8601String(),
    });

    expect(handoff.clipboardText, contains(handoff.command));
    expect(handoff.clipboardText.length, lessThan(200));
    expect(handoff.clipboardText, isNot(contains('vault-1')));
    expect(handoff.clipboardText, isNot(contains('desktop.token')));
  });

  testWidgets('New Item switches modes without losing the manual draft', (
    tester,
  ) async {
    final harness = await _pump(tester);

    await tester.tap(find.byKey(const ValueKey('action-New item')));
    await tester.pumpAndSettle();
    await tester.enterText(
      find.byKey(const ValueKey('entry-title')),
      'Keep this title',
    );

    await tester.tap(find.byKey(const ValueKey('entry-creation-mode')));
    await tester.pumpAndSettle();

    expect(find.text('Fill manually'), findsOneWidget);
    expect(find.byKey(const ValueKey('agent-driven-guidance')), findsOneWidget);
    expect(find.byKey(const ValueKey('agent-handoff-preview')), findsOneWidget);
    expect(find.byKey(const ValueKey('entry-save')), findsNothing);

    await tester.tap(find.byKey(const ValueKey('entry-creation-mode')));
    await tester.pumpAndSettle();

    expect(find.text('Use Agent'), findsOneWidget);
    expect(find.byKey(const ValueKey('entry-save')), findsOneWidget);
    expect(find.text('Keep this title'), findsOneWidget);
    expect(harness.app.vault.activeDraft?.title, 'Keep this title');
  });

  testWidgets('copies a scoped handoff and refreshes into the created item', (
    tester,
  ) async {
    var created = false;
    final harness = await _pump(
      tester,
      script: (client) => client.on(
        'entries_search',
        (_) async => [
          Fixtures.entry(),
          if (created)
            Fixtures.entry(
              id: 'agent-created',
              title: 'Agent-created Environment',
              kind: 'core.environment',
              username: '',
              urls: const [],
              hasPassword: false,
            ),
        ],
      ),
    );

    await tester.tap(find.byKey(const ValueKey('action-New item')));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const ValueKey('entry-creation-mode')));
    await tester.pumpAndSettle();
    await tester.enterText(
      find.byKey(const ValueKey('agent-context')),
      'Create the development login from the current task',
    );

    final copy = find.byKey(const ValueKey('agent-copy-command'));
    await tester.drag(find.byType(ListView).last, const Offset(0, -1400));
    await tester.pumpAndSettle();
    await tester.tap(copy);
    await tester.pumpAndSettle();

    expect(harness.adapter.copied, hasLength(1));
    final instruction = harness.adapter.copied.single;
    expect(instruction.length, lessThan(200));
    expect(instruction, contains('keylease agent new-item handoff-test'));
    expect(instruction, isNot(contains('vault-1')));
    expect(instruction, isNot(contains('group-work')));
    expect(instruction, isNot(contains('development login')));

    final handoffRequest = harness.client.calls.lastWhere(
      (request) => request['command'] == 'agent_handoff_create',
    );
    final input = Map<String, dynamic>.from(handoffRequest['input'] as Map);
    expect(input['expected_vault_id'], 'vault-1');
    expect(input['group_id'], 'group-work');
    expect(input['kind'], 'core.login');
    expect(
      input['context'],
      'Create the development login from the current task',
    );

    await tester.pump(const Duration(seconds: 4));
    final refresh = find.byKey(const ValueKey('agent-refresh-review'));
    await tester.drag(find.byType(ListView).last, const Offset(0, -500));
    await tester.pumpAndSettle();
    await tester.tap(refresh);
    await tester.pumpAndSettle();
    expect(find.text('The agent has not created an item yet'), findsOneWidget);

    created = true;
    await tester.tap(refresh);
    await tester.pumpAndSettle();

    expect(harness.app.vault.selectedEntryId, 'agent-created');
    expect(harness.app.vault.activeDraft, isNull);
    expect(find.text('Agent-created Environment'), findsWidgets);
    await tester.pump(const Duration(milliseconds: 400));
  });
}
