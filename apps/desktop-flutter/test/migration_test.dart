import 'package:flutter_test/flutter_test.dart';

import 'support/fakes.dart';

void main() {
  test('migration discovery preserves the preview digest on apply', () async {
    final harness = buildController(
      script: (client) {
        client
          ..value('migrations_status', {
            'framework_version': 1,
            'pending': [
              {
                'migration_id': 'kdbx-reclassify-v1',
                'version': 1,
                'title': 'Reclassify legacy Strongbox/KDBX items',
                'migration_type': 'semantic',
                'preview_digest': 'preview-digest',
                'proposals': [
                  {
                    'item_id': 'item-card',
                    'title': 'VISA',
                    'current_kind': 'core.login',
                    'proposed_kind': 'core.credit_card',
                    'confidence': 'high',
                    'reasons': ['card number field', 'expiry field'],
                    'expected_revision': 1,
                  },
                ],
              },
            ],
            'history': <Map<String, dynamic>>[],
          })
          ..value('migrations_apply', {
            'migration_id': 'kdbx-reclassify-v1',
            'state': 'applied',
            'item_count': 1,
            'checkpoint_available': true,
          });
      },
    );
    addTearDown(harness.app.dispose);
    await harness.app.start();

    final preview = harness.app.vault.migrationStatus!.pending.single;
    expect(preview.proposals.single.proposedKind, 'core.credit_card');
    await harness.app.vault.applyMigration(preview);

    final request = harness.client.calls.lastWhere(
      (call) => call['command'] == 'migrations_apply',
    );
    expect(request['migration_id'], 'kdbx-reclassify-v1');
    expect(request['preview_digest'], 'preview-digest');
  });
}
