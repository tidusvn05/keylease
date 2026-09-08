import 'package:material_ui/material_ui.dart';

import '../../app/app_scope.dart';
import '../../core/state/app_controller.dart';
import '../../ui/components/split_pane.dart';
import '../../ui/tokens/keylease_tokens.dart';
import 'entry_detail.dart';
import 'entry_editor.dart';
import 'entry_list.dart';

/// Vault list/detail.
///
/// Wide windows keep both panes with a resizable separator. Narrow windows
/// route list → detail and keep the same selection and search state, because
/// both live in the controller rather than in either screen.
class VaultPage extends StatelessWidget {
  const VaultPage({required this.splitView, super.key});

  final bool splitView;

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
          onRefresh: app.refresh,
          refreshing: app.isBusy(AppController.refreshKey),
          onActivate: (id) => _openDetail(context, app),
        );
        if (!splitView) return list;
        return SplitPane(
          width: app.listWidth,
          minWidth: tokens.listMinWidth,
          maxWidth: tokens.listMaxWidth,
          semanticsLabel: 'Resize the item list',
          onWidthChanged: (value) => app.setPaneWidths(list: value),
          leading: list,
          trailing: EntryDetail(app: app, entry: vault.selectedEntry),
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
