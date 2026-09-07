import 'package:forui/forui.dart';
import 'package:material_ui/material_ui.dart';

import '../../core/models/models.dart';
import '../../core/state/app_controller.dart';
import '../../core/state/vault_controller.dart';
import '../../ui/components/keylease_dialog.dart';
import '../../ui/components/keylease_mark.dart';
import '../../ui/components/secret_field.dart';
import '../../ui/components/section_label.dart';
import '../../ui/components/state_screen.dart';
import '../../ui/tokens/keylease_tokens.dart';
import 'entry_editor.dart';
import 'totp_dialog.dart';

/// The always-present detail pane. Reading entry metadata never opens a
/// dialog; only decisions and editing do.
class EntryDetail extends StatelessWidget {
  const EntryDetail({
    required this.app,
    required this.entry,
    this.onBack,
    super.key,
  });

  final AppController app;
  final EntrySummary? entry;
  final VoidCallback? onBack;

  VaultController get vault => app.vault;

  Future<void> _copy(
    BuildContext context,
    EntrySummary item,
    String field,
    String label,
  ) async {
    // Copy must not un-mask the field: only fetch, never store for display.
    final value =
        vault.revealedValue(item.id, field) ??
        await vault.fetchSecret(item, field);
    if (value == null || value.isEmpty) return;
    if (!context.mounted) return;
    final copied = await app.copySensitive(value);
    if (copied && context.mounted) {
      showFToast(
        context: context,
        title: Text('$label copied'),
        description: const Text('The clipboard clears in 30 seconds.'),
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    final item = entry;
    if (item == null) {
      return const StateScreen(
        icon: FLucideIcons.mousePointerClick,
        title: 'Nothing selected',
        message: 'Choose an item on the left to see its details.',
      );
    }
    final tokens = KeyLeaseTokens.of(context);
    final theme = context.theme;
    final password = vault.revealedValue(item.id, 'password');
    final username = vault.revealedValue(item.id, 'username');
    return ListView(
      key: ValueKey('detail-${item.id}'),
      padding: EdgeInsets.fromLTRB(
        tokens.gutter * 1.6,
        tokens.gutter * 1.3,
        tokens.gutter * 1.6,
        tokens.gutter * 2,
      ),
      children: [
        if (onBack != null)
          Align(
            alignment: Alignment.centerLeft,
            child: FButton(
              variant: FButtonVariant.ghost,
              onPress: onBack,
              prefix: const Icon(FLucideIcons.arrowLeft, size: 16),
              child: const Text('Items'),
            ),
          ),
        Row(
          children: [
            KeyLeaseMark(text: item.monogram, large: true),
            SizedBox(width: tokens.gutter),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    item.title,
                    style: TextStyle(
                      fontSize: tokens.titleSize,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                  const SizedBox(height: 5),
                  Text(
                    item.primaryUrl ?? kindLabel(item.kind),
                    style: theme.typography.body.sm.copyWith(
                      color: theme.colors.mutedForeground,
                    ),
                  ),
                ],
              ),
            ),
            IconAction(
              label: 'Edit',
              icon: FLucideIcons.squarePen,
              onPress: () => openEntryEditor(context, app, existing: item),
            ),
            const SizedBox(width: 6),
            IconAction(
              label: 'Delete',
              icon: FLucideIcons.trash2,
              onPress: () => _delete(context, item),
            ),
          ],
        ),
        SizedBox(height: tokens.gutter * 1.8),
        const SectionLabel('Login details'),
        FieldGroup(
          children: [
            DetailField(
              label: 'Username',
              value: username ?? item.username,
              placeholder: 'Not set',
              actions: [
                IconAction(
                  label: 'Copy username',
                  icon: FLucideIcons.copy,
                  onPress: () => _copy(context, item, 'username', 'Username'),
                ),
              ],
            ),
            SecretField(
              label: 'Password',
              revealedValue: password,
              busy: vault.isBusy('reveal.${item.id}/password'),
              onReveal: () => vault.reveal(item, 'password'),
              onHide: () => vault.hideSecret(item.id, 'password'),
              onCopy: () => _copy(context, item, 'password', 'Password'),
            ),
            if (item.primaryUrl != null)
              DetailField(
                label: 'Website',
                value: item.primaryUrl,
                accent: true,
              ),
          ],
        ),
        SizedBox(height: tokens.gutter * 1.5),
        const SectionLabel('Two-factor authentication'),
        FieldGroup(
          children: [
            DetailField(
              label: 'One-time password',
              value: 'Available on request',
              actions: [
                IconAction(
                  label: 'Show code',
                  icon: FLucideIcons.timer,
                  onPress: () => showTotpDialog(context, app, item),
                ),
              ],
            ),
          ],
        ),
        SizedBox(height: tokens.gutter * 1.5),
        const SectionLabel('Item details'),
        FieldGroup(
          children: [
            DetailField(label: 'Template', value: kindLabel(item.kind)),
            DetailField(label: 'Group', value: _groupName(item.groupId)),
            DetailField(
              label: 'Last updated',
              value: item.updatedAt?.toString() ?? 'Unknown',
            ),
            DetailField(
              label: 'Revision',
              value: '${item.revision}',
              actions: [
                IconAction(
                  label: 'View history',
                  icon: FLucideIcons.history,
                  onPress: () => _history(context, item),
                ),
              ],
            ),
          ],
        ),
      ],
    );
  }

  String _groupName(String id) {
    for (final group in vault.groups) {
      if (group.id == id) return group.name;
    }
    return id;
  }

  Future<void> _delete(BuildContext context, EntrySummary item) async {
    final confirmed = await confirm(
      context: context,
      title: 'Move to recycle bin?',
      message:
          '"${item.title}" moves to the recycle bin. '
          'Anything already copied is unaffected.',
      confirmLabel: 'Delete',
      destructive: true,
    );
    if (!confirmed || !context.mounted) return;
    try {
      await vault.deleteEntry(item);
    } catch (caught) {
      if (context.mounted) showFailure(context, caught);
    }
  }

  Future<void> _history(BuildContext context, EntrySummary item) async {
    List<EntryRevision> revisions;
    try {
      revisions = await vault.history(item);
    } catch (caught) {
      if (context.mounted) showFailure(context, caught);
      return;
    }
    if (!context.mounted) return;
    await showKeyLeaseDialog<void>(
      context: context,
      title: 'History · ${item.title}',
      bodyBuilder: (context) => revisions.isEmpty
          ? const Text('No earlier revisions.')
          : Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                for (final revision in revisions)
                  DetailField(
                    label: 'Revision ${revision.revision}',
                    value: revision.updatedAt?.toString() ?? 'Unknown time',
                  ),
              ],
            ),
      actionsBuilder: (context) => [
        FButton(
          onPress: () => Navigator.of(context).pop(),
          child: const Text('Close'),
        ),
      ],
    );
  }
}

String kindLabel(String kind) => switch (kind) {
  'core.login' => 'Login',
  'core.api_credential' => 'API credential',
  'core.secure_note' => 'Secure note',
  'core.generic' => 'Generic item',
  _ => kind,
};
