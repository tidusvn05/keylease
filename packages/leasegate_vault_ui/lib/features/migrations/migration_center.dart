import 'package:forui/forui.dart';
import 'package:material_ui/material_ui.dart';

import '../../core/models/models.dart';
import '../../core/state/app_controller.dart';
import '../../ui/components/keylease_dialog.dart';
import '../../ui/tokens/keylease_tokens.dart';
import '../vault/totp_dialog.dart';

Future<void> openMigrationCenter(
  BuildContext context,
  AppController app,
) async {
  await app.vault.loadMigrations();
  if (!context.mounted) return;
  final status = app.vault.migrationStatus;
  if (status == null) return;
  final preview = status.pending.isEmpty ? null : status.pending.first;
  MigrationHistoryModel? applied;
  for (final entry in status.history) {
    if (entry.state == 'applied') {
      applied = entry;
      break;
    }
  }
  final action = await showKeyLeaseDialog<String>(
    context: context,
    title: 'Migration Center',
    description: preview == null
        ? 'Migration history and rollback checkpoints'
        : '${preview.title} · ${preview.proposals.length} high-confidence items',
    bodyBuilder: (context) => preview == null
        ? _MigrationHistory(history: status.history)
        : _MigrationPreview(preview: preview),
    actionsBuilder: (context) => [
      FButton(
        variant: FButtonVariant.outline,
        onPress: () => Navigator.of(context).pop('close'),
        child: Text(preview == null ? 'Close' : 'Later'),
      ),
      if (preview != null)
        FButton(
          onPress: () => Navigator.of(context).pop('apply'),
          child: Text('Migrate ${preview.proposals.length} items'),
        ),
      if (preview == null && applied != null)
        FButton(
          variant: FButtonVariant.destructive,
          onPress: () => Navigator.of(context).pop('rollback'),
          child: const Text('Rollback latest'),
        ),
    ],
    presentation: KeyLeasePresentation.fullScreen,
  );
  if (action == null || action == 'close' || !context.mounted) return;
  try {
    if (action == 'apply' && preview != null) {
      await app.vault.applyMigration(preview);
    } else if (action == 'rollback' && applied != null) {
      await app.vault.rollbackMigration(applied.id);
    } else {
      return;
    }
    if (context.mounted) {
      showFToast(
        context: context,
        title: Text(
          action == 'rollback'
              ? 'Migration rolled back'
              : 'Migration completed',
        ),
        description: Text(
          action == 'rollback'
              ? 'The previous templates were restored as a new revision.'
              : '${preview!.proposals.length} items updated. An encrypted rollback checkpoint is available.',
        ),
      );
    }
  } catch (caught) {
    if (context.mounted) showFailure(context, caught);
  }
}

class _MigrationHistory extends StatelessWidget {
  const _MigrationHistory({required this.history});

  final List<MigrationHistoryModel> history;

  @override
  Widget build(BuildContext context) {
    if (history.isEmpty) {
      return const Text('No vault migrations have been applied.');
    }
    final tokens = KeyLeaseTokens.of(context);
    return Column(
      children: [
        for (final entry in history)
          Padding(
            padding: EdgeInsets.only(bottom: tokens.gutterSmall),
            child: FItem(
              title: Text(entry.id),
              subtitle: Text(
                '${entry.itemCount} items · version ${entry.version}',
              ),
              details: Text(entry.state),
            ),
          ),
      ],
    );
  }
}

class _MigrationPreview extends StatelessWidget {
  const _MigrationPreview({required this.preview});

  final MigrationPreviewModel preview;

  @override
  Widget build(BuildContext context) {
    final tokens = KeyLeaseTokens.of(context);
    final theme = context.theme;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        DecoratedBox(
          decoration: BoxDecoration(
            color: tokens.warning.withValues(alpha: 0.08),
            border: Border.all(color: tokens.warning.withValues(alpha: 0.4)),
            borderRadius: BorderRadius.circular(9),
          ),
          child: Padding(
            padding: EdgeInsets.all(tokens.gutterSmall),
            child: const Text(
              'Only template, semantic roles, and protection metadata change. Secret values, groups, tags, IDs, and agent access are preserved.',
            ),
          ),
        ),
        SizedBox(height: tokens.gutter),
        for (final proposal in preview.proposals)
          Padding(
            padding: EdgeInsets.only(bottom: tokens.gutterSmall),
            child: FItem(
              prefix: const Icon(FLucideIcons.fileCheck2, size: 18),
              title: Text(proposal.title),
              subtitle: Text(proposal.reasons.join(' · ')),
              details: Text(
                '${_kind(proposal.currentKind)} → ${_kind(proposal.proposedKind)}',
                style: theme.typography.body.xs.copyWith(
                  color: theme.colors.mutedForeground,
                ),
              ),
            ),
          ),
      ],
    );
  }

  String _kind(String value) => value
      .replaceFirst('core.', '')
      .split('_')
      .map(
        (part) => part.isEmpty
            ? part
            : '${part[0].toUpperCase()}${part.substring(1)}',
      )
      .join(' ');
}
