import 'package:flutter/services.dart';
import 'package:forui/forui.dart';
import 'package:material_ui/material_ui.dart';

import '../../app/shortcuts.dart';
import '../../app/app_scope.dart';

import '../../core/models/models.dart';
import '../../core/state/vault_controller.dart';
import '../../ui/components/entry_row.dart';
import '../../ui/components/message_banner.dart';
import '../../ui/components/scroll_area.dart';
import '../../ui/components/secret_field.dart';
import '../../ui/components/state_screen.dart';
import '../../ui/tokens/keylease_tokens.dart';
import 'entry_editor.dart';

/// Search + result list. Loading is shown inside the list area only, so the
/// search field stays usable while a query is in flight.
class EntryList extends StatelessWidget {
  const EntryList({
    required this.controller,
    required this.onActivate,
    required this.onCreate,
    required this.onGeneratePassword,
    required this.onRefresh,
    required this.refreshing,
    this.openOnSelect = false,
    this.showSearch = true,
    super.key,
  });

  final VaultController controller;
  final ValueChanged<String> onActivate;
  final VoidCallback onCreate;
  final VoidCallback onGeneratePassword;
  final VoidCallback onRefresh;
  final bool refreshing;

  /// Narrow layouts route straight from the list to the detail view.
  final bool openOnSelect;
  final bool showSearch;

  @override
  Widget build(BuildContext context) {
    final tokens = KeyLeaseTokens.of(context);
    final theme = context.theme;
    final entries = controller.visibleEntries;
    final showInlineActions =
        showSearch &&
        MediaQuery.sizeOf(context).width >= tokens.expandedBreakpoint;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        if (showSearch)
          Padding(
            padding: EdgeInsets.fromLTRB(
              tokens.gutter,
              tokens.gutter,
              tokens.gutter,
              tokens.gutterSmall,
            ),
            child: VaultSearchField(
              controller: controller,
              onActivate: onActivate,
            ),
          ),
        Padding(
          padding: EdgeInsets.fromLTRB(
            tokens.gutter,
            showSearch ? 0 : tokens.gutterSmall,
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
              if (showInlineActions) ...[
                const SizedBox(width: 6),
                IconAction(
                  label: 'Refresh',
                  icon: FLucideIcons.refreshCw,
                  onPress: refreshing ? null : onRefresh,
                ),
                const SizedBox(width: 4),
                IconAction(
                  label: 'Password generator',
                  icon: FLucideIcons.sparkles,
                  onPress: onGeneratePassword,
                ),
                const SizedBox(width: 4),
                IconAction(
                  label: 'New item',
                  icon: FLucideIcons.plus,
                  onPress: onCreate,
                ),
              ],
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
        _ => KeyLeaseScrollArea.builder(
          padding: const EdgeInsets.only(bottom: 12),
          itemCount: controller.visibleEntries.length,
          itemBuilder: (context, index) {
            final entry = controller.visibleEntries[index];
            return EntryRow(
              entry: entry,
              selected: controller.selectedEntry?.id == entry.id,
              onSelect: () async {
                final app = AppScope.of(context);
                if (!await confirmCloseEntryEditor(context, app)) return;
                controller.select(entry.id);
                if (openOnSelect) onActivate(entry.id);
              },
            );
          },
        ),
      };
}

/// Search field shared by the compact list and the unified desktop toolbar.
class VaultSearchField extends StatelessWidget {
  const VaultSearchField({
    required this.controller,
    required this.onActivate,
    super.key,
  });

  final VaultController controller;
  final ValueChanged<String> onActivate;

  @override
  Widget build(BuildContext context) => Shortcuts(
    shortcuts: const {
      SingleActivator(LogicalKeyboardKey.arrowDown): MoveSelectionIntent(1),
      SingleActivator(LogicalKeyboardKey.arrowUp): MoveSelectionIntent(-1),
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
        hint: 'Search',
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
  );
}
