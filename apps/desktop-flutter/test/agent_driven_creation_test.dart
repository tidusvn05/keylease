import 'package:flutter_test/flutter_test.dart';
import 'package:keylease_desktop/app/keylease_app.dart';
import 'package:keylease_desktop/core/models/models.dart';
import 'package:keylease_desktop/core/state/agent_creation_draft.dart';
import 'package:keylease_desktop/core/state/app_controller.dart';
import 'package:material_ui/material_ui.dart';

import 'support/fakes.dart';

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
  test(
    'entry prompt validates then creates immediately in the expected vault',
    () {
      final draft =
          AgentCreationDraft(kind: 'core.ssh_server', groupId: 'group-work')
            ..recipeId = 'ssh_topology'
            ..context = 'One bastion and one application server';
      final prompt = AgentCreationPromptBuilder.build(
        draft: draft,
        vaultId: 'vault-1',
        vaultName: 'Primary Vault',
        templateLabel: 'SSH Server',
        groupName: 'Work',
        template: const TemplateDefinition(
          kind: 'core.ssh_server',
          label: 'SSH Server',
          family: 'developer',
          markdownNotes: true,
          fields: [],
        ),
      );

      expect(prompt, contains('Run `keylease status`'));
      expect(prompt, contains('vault ID is not `vault-1`'));
      expect(prompt, contains('entries create --input-json -'));
      expect(prompt, contains('--dry-run'));
      expect(prompt, contains('create it immediately'));
      expect(prompt.toLowerCase(), contains('create exactly one item'));
      expect(prompt, contains('ssh_connect_via'));
      expect(prompt, contains('Never save an `IdentityFile` path'));
      expect(prompt, isNot(contains('desktop.token')));
      expect(prompt, isNot(contains('client-token-file')));
      expect(prompt, isNot(contains('master password:')));
    },
  );

  test('content prompt creates Markdown and applies selected agent access', () {
    final draft = AgentCreationDraft(kind: 'core.prompt')
      ..recipeId = 'prompt'
      ..projectSlug = 'leasegate'
      ..tags = 'agent, reusable'
      ..agentAccess = 'read_write';
    final prompt = AgentCreationPromptBuilder.build(
      draft: draft,
      vaultId: 'vault-1',
      vaultName: 'Primary Vault',
      templateLabel: 'Prompt',
      groupName: null,
      template: null,
    );

    expect(prompt, contains('keylease content create --type prompt'));
    expect(prompt, contains('--project leasegate'));
    expect(prompt, contains('--tag "agent"'));
    expect(prompt, contains('content access <id> read-write'));
    expect(prompt, isNot(contains('entries create')));
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
    expect(find.byKey(const ValueKey('agent-prompt-preview')), findsOneWidget);
    expect(find.byKey(const ValueKey('entry-save')), findsNothing);

    await tester.tap(find.byKey(const ValueKey('entry-creation-mode')));
    await tester.pumpAndSettle();

    expect(find.text('Use Agent'), findsOneWidget);
    expect(find.byKey(const ValueKey('entry-save')), findsOneWidget);
    expect(find.text('Keep this title'), findsOneWidget);
    expect(harness.app.vault.activeDraft?.title, 'Keep this title');
  });

  testWidgets('copies a scoped prompt and refreshes into the created item', (
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

    final copy = find.byKey(const ValueKey('agent-copy-prompt'));
    await tester.drag(find.byType(ListView).last, const Offset(0, -1400));
    await tester.pumpAndSettle();
    await tester.tap(copy);
    await tester.pumpAndSettle();

    expect(harness.adapter.copied, hasLength(1));
    final prompt = harness.adapter.copied.single;
    expect(prompt, contains('Target vault: "Primary Vault" (`vault-1`)'));
    expect(prompt, contains('Destination group: "Work" (`group-work`)'));
    expect(prompt, contains('Do not create a second item'));

    created = true;
    await tester.pump(const Duration(seconds: 4));
    final refresh = find.byKey(const ValueKey('agent-refresh-review'));
    await tester.drag(find.byType(ListView).last, const Offset(0, -500));
    await tester.pumpAndSettle();
    await tester.tap(refresh);
    await tester.pumpAndSettle();

    expect(harness.app.vault.selectedEntryId, 'agent-created');
    expect(harness.app.vault.activeDraft, isNull);
    expect(find.text('Agent-created Environment'), findsWidgets);
    await tester.pump(const Duration(milliseconds: 400));
  });
}
