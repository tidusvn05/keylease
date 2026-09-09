import 'package:material_ui/material_ui.dart';

import '../../app/app_scope.dart';
import '../../core/state/app_controller.dart';
import '../../core/state/vault_controller.dart';
import '../../ui/components/split_pane.dart';
import '../../ui/tokens/keylease_tokens.dart';
import 'entry_detail.dart';
import 'entry_editor.dart';
import 'entry_list.dart';
import 'password_generator.dart';

/// Vault list/detail.
///
/// Wide windows keep both panes with a resizable separator. Narrow windows
/// route list → detail and keep the same selection and search state, because
/// both live in the controller rather than in either screen.
class VaultPage extends StatelessWidget {
  const VaultPage({
    required this.splitView,
    this.desktopToolbar = false,
    super.key,
  });

  final bool splitView;
  final bool desktopToolbar;

  @override
  Widget build(BuildContext context) {
    final app = AppScope.of(context);
    final tokens = KeyLeaseTokens.of(context);
    return Observe(
      listenable: app.vault,
      builder: (context, vault) {
        final list = EntryList(
          controller: vault,
          openOnSelect: !splitView,
          onCreate: () => openEntryEditor(context, app),
          onGeneratePassword: () => openPasswordGenerator(context, app),
          onRefresh: app.refresh,
          refreshing: app.isBusy(AppController.refreshKey),
          onActivate: (id) => _openDetail(context, app),
          showSearch: !desktopToolbar,
        );
        if (!splitView) return list;
        return SplitPane(
          width: app.listWidth,
          minWidth: tokens.listMinWidth,
          maxWidth: tokens.listMaxWidth,
          semanticsLabel: 'Resize the item list',
          onWidthChanged: (value) => app.setPaneWidths(list: value),
          leading: list,
          trailing: switch (vault.workspaceMode) {
            EntryWorkspaceMode.detail => EntryDetail(
              app: app,
              entry: vault.selectedEntry,
            ),
            EntryWorkspaceMode.passwordGenerator => PasswordGeneratorPane(
              app: app,
            ),
            _ => EntryEditorPane(app: app),
          },
        );
      },
    );
  }

  void _openDetail(BuildContext context, AppController app) {
    Navigator.of(context).push(
      MaterialPageRoute<void>(
        builder: (context) => Observe(
          listenable: app.vault,
          builder: (context, vault) => AppScope(
            controller: app,
            child: ColoredBox(
              color: Theme.of(context).colorScheme.surface,
              child: SafeArea(
                child: EntryDetail(
                  app: app,
                  entry: vault.selectedEntry,
                  onBack: () => Navigator.of(context).pop(),
                ),
              ),
            ),
          ),
        ),
      ),
    );
  }
}
