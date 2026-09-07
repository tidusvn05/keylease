import 'package:flutter/services.dart';
import 'package:forui/forui.dart';
import 'package:material_ui/material_ui.dart';

import '../../app/shortcuts.dart';

import '../../core/models/models.dart';
import '../../core/state/vault_controller.dart';
import '../../ui/components/entry_row.dart';
import '../../ui/components/message_banner.dart';
import '../../ui/components/state_screen.dart';
import '../../ui/tokens/keylease_tokens.dart';

/// Search + result list. Loading is shown inside the list area only, so the
/// search field stays usable while a query is in flight.
class EntryList extends StatelessWidget {
  const EntryList({
    required this.controller,
    required this.onActivate,
    required this.onCreate,
    this.openOnSelect = false,
    super.key,
  });

  final VaultController controller;
  final ValueChanged<String> onActivate;
  final VoidCallback onCreate;

  /// Narrow layouts route straight from the list to the detail view.
  final bool openOnSelect;

  @override
  Widget build(BuildContext context) {
    final tokens = KeyLeaseTokens.of(context);
    final theme = context.theme;
    final entries = controller.visibleEntries;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Padding(
          padding: EdgeInsets.fromLTRB(
            tokens.gutter,
            tokens.gutter,
            tokens.gutter,
            tokens.gutterSmall,
          ),
          // Arrow keys move the list selection while the caret stays in the
          // field. This Shortcuts sits below DefaultTextEditingShortcuts, so
          // it wins for these two activators only.
          child: Shortcuts(
            shortcuts: const {
              SingleActivator(LogicalKeyboardKey.arrowDown):
                  MoveSelectionIntent(1),
              SingleActivator(LogicalKeyboardKey.arrowUp): MoveSelectionIntent(
                -1,
              ),
            },
            child: Actions(
              actions: {
                MoveSelectionIntent: CallbackAction<MoveSelectionIntent>(
                  onInvoke: (intent) {
                    controller.moveSelection(intent.delta);
                    return null;
                  },
                ),
              },
              child: FTextField(
                key: const ValueKey('vault-search'),
                focusNode: controller.searchFocus,
                control: FTextFieldControl.managed(
                  controller: controller.searchController,
                  onChange: (value) => controller.setQuery(value.text),
                ),
                hint: 'Search title, username or URL',
                prefixBuilder: (context, style, variants) => const Padding(
                  padding: EdgeInsets.only(left: 11, right: 6),
                  child: Icon(FLucideIcons.search, size: 17),
                ),
                onSubmit: (_) {
                  final selected = controller.selectedEntry;
                  if (selected != null) onActivate(selected.id);
                },
                clearable: (value) => value.text.isNotEmpty,
              ),
            ),
          ),
        ),
        Padding(
          padding: EdgeInsets.fromLTRB(
            tokens.gutter,
            0,
            tokens.gutter,
            tokens.gutterSmall,
          ),
          child: Row(
            children: [
              Expanded(
                child: Text(
                  switch (controller.listState) {
                    VaultListState.loading => 'Searching…',
                    _ =>
                      '${entries.length} '
                          '${entries.length == 1 ? 'item' : 'items'}',
                  },
                  style: theme.typography.body.xs.copyWith(
                    color: theme.colors.mutedForeground,
                  ),
                ),
              ),
              if (controller.listState == VaultListState.loading)
                const SizedBox(
                  width: 14,
                  height: 14,
                  child: FCircularProgress(),
                ),
            ],
          ),
        ),
        if (controller.error != null)
          MessageBanner(message: controller.error!, onAction: controller.load),
        Expanded(child: _body(context, entries)),
      ],
    );
  }

  Widget _body(BuildContext context, List<EntrySummary> entries) =>
      switch (controller.listState) {
        VaultListState.loading when entries.isEmpty => const Center(
          child: FCircularProgress(),
        ),
        VaultListState.empty => StateScreen(
          icon: FLucideIcons.keyRound,
          title: 'No items yet',
          message: 'Add your first item to start using this vault.',
          actions: [FButton(onPress: onCreate, child: const Text('New item'))],
        ),
        VaultListState.searchEmpty => StateScreen(
          icon: FLucideIcons.search,
          title: 'No matches',
          message:
              'Nothing matches "${controller.query}". Try a shorter '
              'search, or clear it to see everything.',
          actions: [
            FButton(
              variant: FButtonVariant.outline,
              onPress: () {
                controller.searchController.clear();
                controller.setQuery('');
              },
              child: const Text('Clear search'),
            ),
            FButton(onPress: onCreate, child: const Text('New item')),
          ],
        ),
        _ => ListView.builder(
          padding: const EdgeInsets.only(bottom: 12),
          itemCount: controller.visibleEntries.length,
          itemBuilder: (context, index) {
            final entry = controller.visibleEntries[index];
            return EntryRow(
              entry: entry,
              selected: controller.selectedEntry?.id == entry.id,
              onSelect: () {
                controller.select(entry.id);
                if (openOnSelect) onActivate(entry.id);
              },
            );
          },
        ),
      };
}
