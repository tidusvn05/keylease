import 'package:flutter_test/flutter_test.dart';
import 'package:keylease_desktop/core/state/vault_controller.dart';

import 'support/fakes.dart';

void main() {
  test('typing does not fire one RPC per keystroke', () async {
    final harness = buildController();
    addTearDown(harness.app.dispose);
    await harness.app.start();
    harness.client.calls.clear();

    for (final query in ['g', 'gi', 'git', 'gith']) {
      harness.app.vault.setQuery(query);
      await Future<void>.delayed(const Duration(milliseconds: 20));
    }
    await Future<void>.delayed(const Duration(milliseconds: 400));

    final searches = harness.client.calls
        .where((call) => call['command'] == 'entries_search')
        .toList();
    expect(searches, hasLength(1));
    expect(searches.single['query'], 'gith');
  });

  test('a slow earlier response never overwrites a newer query', () async {
    final harness = buildController(
      script: (client) => client.on('entries_search', (request) async {
        final query = '${request['query']}';
        // The first query answers last.
        await Future<void>.delayed(
          query == 'slow'
              ? const Duration(milliseconds: 300)
              : const Duration(milliseconds: 10),
        );
        return [Fixtures.entry(id: 'entry-$query', title: 'Result for $query')];
      }),
    );
    addTearDown(harness.app.dispose);
    await harness.app.start();
    final vault = harness.app.vault..searchDebounce = Duration.zero;

    vault.setQuery('slow');
    await Future<void>.delayed(const Duration(milliseconds: 30));
    vault.setQuery('fast');
    await Future<void>.delayed(const Duration(milliseconds: 500));

    expect(vault.entries.single.title, 'Result for fast');
    expect(vault.listState, VaultListState.content);
  });

  test('arrow keys move the selection within the visible list', () async {
    final harness = buildController(
      script: (client) => client.value('entries_search', [
        Fixtures.entry(id: 'a', title: 'Alpha'),
        Fixtures.entry(id: 'b', title: 'Bravo'),
        Fixtures.entry(id: 'c', title: 'Charlie'),
      ]),
    );
    addTearDown(harness.app.dispose);
    await harness.app.start();
    final vault = harness.app.vault;

    expect(vault.selectedEntry?.id, 'a');
    vault.moveSelection(1);
    expect(vault.selectedEntry?.id, 'b');
    vault.moveSelection(1);
    vault.moveSelection(1);
    expect(vault.selectedEntry?.id, 'c', reason: 'clamped at the end');
    vault.moveSelection(-2);
    expect(vault.selectedEntry?.id, 'a');
  });

  test('favorites and parent groups filter from contract data', () async {
    final harness = buildController(
      script: (client) {
        client.value('groups_list', [
          {...Fixtures.groups.first, 'sort_order': 1},
          {
            ...Fixtures.groups.first,
            'id': 'group-child',
            'name': 'Child',
            'parent_id': 'group-work',
            'sort_order': 0,
          },
        ]);
        client.value('entries_search', [
          Fixtures.entry(id: 'root'),
          Fixtures.entry(id: 'favorite', favorite: true),
          {...Fixtures.entry(id: 'child'), 'group_id': 'group-child'},
        ]);
      },
    );
    addTearDown(harness.app.dispose);
    await harness.app.start();

    harness.app.vault.selectGroup('group-work');
    expect(harness.app.vault.visibleEntries, hasLength(3));
    harness.app.vault.selectFavorites();
    expect(harness.app.vault.visibleEntries.single.id, 'favorite');
  });

  test(
    'a failed search reports itself and keeps the previous results',
    () async {
      var fail = false;
      final harness = buildController(
        script: (client) => client.on('entries_search', (_) async {
          if (fail) {
            throw StateError('daemon blew up');
          }
          return [Fixtures.entry()];
        }),
      );
      addTearDown(harness.app.dispose);
      await harness.app.start();
      final vault = harness.app.vault..searchDebounce = Duration.zero;

      fail = true;
      vault.setQuery('boom');
      await Future<void>.delayed(const Duration(milliseconds: 100));

      expect(vault.error, isNotNull);
      expect(vault.entries, hasLength(1), reason: 'the old screen is kept');
    },
  );
}
