import 'package:flutter_test/flutter_test.dart';
import 'package:keylease_desktop/core/platform/local_runtime_adapter.dart';
import 'package:keylease_desktop/core/rpc/keylease_rpc.dart';
import 'package:keylease_desktop/core/state/app_phase.dart';
import 'package:keylease_desktop/core/state/vault_controller.dart';

import 'support/fakes.dart';

void main() {
  group('app phase routing', () {
    test('a missing managed vault starts onboarding, not locked', () async {
      final harness = buildController(
        runtimeInspection: const LocalRuntimeInspection(
          state: LocalRuntimeState.needsOnboarding,
        ),
      );
      addTearDown(harness.app.dispose);

      await harness.app.start();

      expect(harness.app.phase, AppPhase.onboarding);
      expect(harness.client.calls, isEmpty);
    });

    test('an unreachable service is offline, not locked', () async {
      final harness = buildController(
        script: (client) => client.fail(
          'status',
          const KeyLeaseException.transport('connection refused'),
        ),
      );
      addTearDown(harness.app.dispose);

      await harness.app.start();

      expect(harness.app.phase, AppPhase.serviceUnavailable);
      expect(harness.app.phaseMessage?.title, "Can't reach KeyLease");
    });

    test('a locked vault is locked', () async {
      final harness = buildController(
        script: (client) => client.value('status', Fixtures.lockedStatus),
      );
      addTearDown(harness.app.dispose);

      await harness.app.start();

      expect(harness.app.phase, AppPhase.locked);
    });

    test('an unlocked vault this client may not read is denied', () async {
      final harness = buildController(
        script: (client) => client.fail(
          'groups_list',
          KeyLeaseException.fromDaemon({
            'error': 'denied',
            'reason': 'client lacks vault:read',
          }),
        ),
      );
      addTearDown(harness.app.dispose);

      await harness.app.start();

      expect(harness.app.phase, AppPhase.permissionDenied);
      expect(harness.app.phaseMessage?.detail, contains('vault:read'));
    });

    test('an unlocked, permitted vault is ready and loads the vault', () async {
      final harness = buildController();
      addTearDown(harness.app.dispose);

      await harness.app.start();

      expect(harness.app.phase, AppPhase.ready);
      expect(harness.app.vault.entries, hasLength(1));
      expect(harness.app.vault.listState, VaultListState.content);
    });

    test('an empty vault is empty, not an error', () async {
      final harness = buildController(
        script: (client) =>
            client.value('entries_search', <Map<String, dynamic>>[]),
      );
      addTearDown(harness.app.dispose);

      await harness.app.start();

      expect(harness.app.phase, AppPhase.ready);
      expect(harness.app.vault.listState, VaultListState.empty);
    });

    test('a search with no results is distinct from an empty vault', () async {
      final harness = buildController(
        script: (client) => client.on('entries_search', (request) async {
          final query = '${request['query']}';
          return query.isEmpty ? [Fixtures.entry()] : <Map<String, dynamic>>[];
        }),
      );
      addTearDown(harness.app.dispose);
      await harness.app.start();

      harness.app.vault.setQuery('nothing matches this');
      await Future<void>.delayed(const Duration(milliseconds: 400));

      expect(harness.app.vault.listState, VaultListState.searchEmpty);
    });
  });
}
