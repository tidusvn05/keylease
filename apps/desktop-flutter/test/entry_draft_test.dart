import 'package:flutter_test/flutter_test.dart';
import 'package:keylease_desktop/core/models/models.dart';
import 'package:keylease_desktop/core/rpc/keylease_rpc.dart';
import 'package:keylease_desktop/core/state/entry_draft.dart';

import 'support/fakes.dart';

void main() {
  group('entry draft', () {
    test('a new entry needs a title and a group', () {
      final draft = EntryDraft.create();
      expect(draft.validate().keys, containsAll(['title', 'group']));

      draft
        ..title = 'GitHub'
        ..groupId = 'group-work';
      expect(draft.validate(), isEmpty);
    });

    test('malformed custom fields fail validation instead of being sent', () {
      final draft = EntryDraft.create(groupId: 'group-work')
        ..title = 'GitHub'
        ..customFields = '{not json}';

      expect(draft.validate()['custom_fields'], isNotNull);
    });

    test('an empty secret keeps the stored value instead of clearing it', () {
      final draft = EntryDraft.edit(EntrySummary.fromJson(Fixtures.entry()))
        ..title = 'GitHub renamed';

      final patch = draft.toPatch();
      expect(patch.containsKey('password'), isFalse);
      expect(patch.containsKey('notes'), isFalse);
      expect(patch.containsKey('totp'), isFalse);
      expect(patch['title'], 'GitHub renamed');
    });

    test('a supplied secret is sent', () {
      final draft = EntryDraft.edit(EntrySummary.fromJson(Fixtures.entry()))
        ..password = 'new-secret';

      expect(draft.toPatch()['password'], 'new-secret');
    });

    test('structured templates send sections and explicit field removals', () {
      final draft = EntryDraft.edit(EntrySummary.fromJson(Fixtures.entry()))
        ..customFields = '[]'
        ..sections = '[{"id":"environment_variables","label":"Variables","field_ids":[],"semantic_role":"environment_variables"}]'
        ..removeFieldIds = const ['field_old'];

      final patch = draft.toPatch();
      expect(patch['field_updates'], isEmpty);
      expect(patch['sections'], hasLength(1));
      expect(patch['remove_field_ids'], ['field_old']);
    });

    test('an otpauth URI and a base32 secret take different fields', () {
      final uri = EntryDraft.create(groupId: 'g')
        ..title = 'x'
        ..totp = 'otpauth://totp/Example?secret=ABCD';
      expect(uri.toCreateInput()['totp_uri'], isNotNull);
      expect(uri.toCreateInput()['totp'], isNull);

      final base32 = EntryDraft.create(groupId: 'g')
        ..title = 'x'
        ..totp = 'ABCDEFGH';
      expect(base32.toCreateInput()['totp_uri'], isNull);
      expect(base32.toCreateInput()['totp']?['secret_base32'], 'ABCDEFGH');
    });

    test('dirty tracking notices typed values, including secrets', () {
      final draft = EntryDraft.edit(EntrySummary.fromJson(Fixtures.entry()));
      expect(draft.isDirty, isFalse);

      draft.password = 'x';
      expect(draft.isDirty, isTrue);

      draft.wipeSecrets();
      expect(draft.isDirty, isFalse);
    });

    test('an update sends the revision it was based on', () async {
      final harness = buildController();
      addTearDown(harness.app.dispose);
      await harness.app.start();

      final entry = harness.app.vault.entries.single;
      await harness.app.vault.save(EntryDraft.edit(entry)..title = 'Renamed');

      final update = harness.client.calls.lastWhere(
        (call) => call['command'] == 'entries_update',
      );
      expect(update['if_revision'], entry.revision);
      expect(update['dry_run'], false);
    });

    test('a rejected save leaves the draft intact for a retry', () async {
      final harness = buildController(
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
      addTearDown(harness.app.dispose);
      await harness.app.start();

      final draft = EntryDraft.edit(harness.app.vault.entries.single)
        ..title = 'Renamed'
        ..password = 'kept-secret';

      await expectLater(harness.app.vault.save(draft), throwsA(anything));

      expect(draft.title, 'Renamed');
      expect(draft.password, 'kept-secret');
    });

    test(
      'SSH private key bindings are local, persisted, and removable',
      () async {
        final harness = buildController();
        addTearDown(harness.app.dispose);
        await harness.app.start();

        await harness.app.setSshKeyBinding(
          'entry-server',
          'ssh_endpoint_main',
          '/Users/test/.ssh/id_ed25519',
        );
        expect(
          harness.app.sshKeyBinding('entry-server', 'ssh_endpoint_main'),
          '/Users/test/.ssh/id_ed25519',
        );

        await harness.app.setSshKeyBinding(
          'entry-server',
          'ssh_endpoint_main',
          null,
        );
        expect(
          harness.app.sshKeyBinding('entry-server', 'ssh_endpoint_main'),
          isNull,
        );
      },
    );
  });
}
