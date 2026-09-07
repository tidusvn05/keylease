import 'package:flutter_test/flutter_test.dart';
import 'package:keylease_desktop/core/platform/security_adapter.dart';
import 'package:keylease_desktop/core/state/app_phase.dart';

import 'support/fakes.dart';

void main() {
  group('secret handling', () {
    test('a revealed secret is fetched on demand, not with the list', () async {
      final harness = buildController();
      addTearDown(harness.app.dispose);
      await harness.app.start();
      final vault = harness.app.vault;
      final entry = vault.entries.single;

      expect(vault.revealedValue(entry.id, 'password'), isNull);
      expect(
        harness.client.calls.any((c) => c['command'] == 'entries_reveal'),
        isFalse,
      );

      await vault.reveal(entry, 'password');
      expect(vault.revealedValue(entry.id, 'password'), isNotNull);
    });

    test('selecting another entry drops the revealed secret', () async {
      final harness = buildController(
        script: (client) => client.value('entries_search', [
          Fixtures.entry(id: 'a', title: 'Alpha'),
          Fixtures.entry(id: 'b', title: 'Bravo'),
        ]),
      );
      addTearDown(harness.app.dispose);
      await harness.app.start();
      final vault = harness.app.vault;

      await vault.reveal(vault.entries.first, 'password');
      expect(vault.hasRevealedSecrets, isTrue);

      vault.select('b');
      expect(vault.hasRevealedSecrets, isFalse);
    });

    test(
      'copying goes through the native adapter, never the plain clipboard',
      () async {
        final harness = buildController();
        addTearDown(harness.app.dispose);
        await harness.app.start();

        final copied = await harness.app.copySensitive('s3cret');

        expect(copied, isTrue);
        expect(harness.adapter.copied, ['s3cret']);
      },
    );

    test(
      'a platform without a managed clipboard refuses instead of leaking',
      () async {
        final harness = buildController();
        addTearDown(harness.app.dispose);
        await harness.app.start();
        harness.adapter.clipboardSupported = false;

        final copied = await harness.app.copySensitive('s3cret');

        expect(copied, isFalse);
        expect(harness.adapter.copied, isEmpty);
        expect(harness.app.banner?.title, 'Not available in this build');
      },
    );
  });

  group('lock transitions', () {
    test('lock clears the clipboard, the session data and the phase', () async {
      final harness = buildController();
      addTearDown(harness.app.dispose);
      await harness.app.start();
      await harness.app.vault.reveal(
        harness.app.vault.entries.single,
        'password',
      );

      harness.client.value('status', Fixtures.lockedStatus);
      await harness.app.lock();

      expect(harness.adapter.clipboardClears, greaterThanOrEqualTo(1));
      expect(harness.app.vault.hasRevealedSecrets, isFalse);
      expect(harness.app.vault.entries, isEmpty);
      expect(harness.app.phase, AppPhase.locked);
    });

    test('sleep and screen lock hide secrets and lock the vault', () async {
      final harness = buildController();
      addTearDown(harness.app.dispose);
      await harness.app.start();
      await harness.app.vault.reveal(
        harness.app.vault.entries.single,
        'password',
      );
      expect(harness.app.vault.hasRevealedSecrets, isTrue);

      harness.client.value('status', Fixtures.lockedStatus);
      harness.adapter.requestLock(LockTrigger.screenLock);
      await Future<void>.delayed(const Duration(milliseconds: 50));

      expect(harness.app.vault.hasRevealedSecrets, isFalse);
      expect(harness.app.phase, AppPhase.locked);
    });

    test('unlocking moves back to ready and reloads', () async {
      final harness = buildController(
        script: (client) => client.value('status', Fixtures.lockedStatus),
      );
      addTearDown(harness.app.dispose);
      await harness.app.start();
      expect(harness.app.phase, AppPhase.locked);

      harness.client.value('status', Fixtures.unlockedStatus);
      final unlocked = await harness.app.unlock('correct horse');

      expect(unlocked, isTrue);
      expect(harness.app.phase, AppPhase.ready);
      expect(harness.app.vault.entries, hasLength(1));
    });
  });
}
