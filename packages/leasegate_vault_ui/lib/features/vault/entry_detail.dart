import 'dart:async';

import 'package:forui/forui.dart';
import 'package:material_ui/material_ui.dart';

import '../../core/models/models.dart';
import '../../core/state/app_controller.dart';
import '../../core/state/user_message.dart';
import '../../core/state/vault_controller.dart';
import '../../ui/components/keylease_dialog.dart';
import '../../ui/components/keylease_mark.dart';
import '../../ui/components/secret_field.dart';
import '../../ui/components/section_label.dart';
import '../../ui/components/scroll_area.dart';
import '../../ui/components/state_screen.dart';
import '../../ui/tokens/keylease_tokens.dart';
import 'entry_editor.dart';
import 'developer_template_detail.dart';
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

  Future<void> _copyField(
    BuildContext context,
    EntrySummary item,
    EntryFieldView field,
  ) async {
    final value = field.protected
        ? vault.revealedValue(item.id, field.id) ??
              await vault.fetchField(item, field)
        : field.displayValue;
    if (value == null || value.isEmpty) return;
    if (!context.mounted) return;
    final copied = await app.copySensitive(value);
    if (copied && context.mounted) {
      showFToast(
        context: context,
        title: Text('${field.label} copied'),
        description: const Text('The clipboard clears in 30 seconds.'),
      );
    }
  }

  Future<void> _copyAgentPrompt(BuildContext context, EntrySummary item) async {
    final copied = await app.copyAgentPrompt(item);
    if (!copied || !context.mounted) return;
    showFToast(
      context: context,
      title: const Text('Entry prompt copied'),
      description: const Text('Paste it into Codex or another local agent.'),
    );
  }

  Future<void> _copyCliCommand(BuildContext context, EntrySummary item) async {
    final copied = await app.copyCliCommand(item);
    if (!copied || !context.mounted) return;
    showFToast(
      context: context,
      title: const Text('CLI command copied'),
      description: const Text('Paste it into Terminal.'),
    );
  }

  Future<void> _openWebsite(BuildContext context, String value) async {
    final trimmed = value.trim();
    final candidate = trimmed.contains('://') ? trimmed : 'https://$trimmed';
    final uri = Uri.tryParse(candidate);
    if (uri == null ||
        !const {'http', 'https'}.contains(uri.scheme.toLowerCase()) ||
        uri.host.isEmpty) {
      if (context.mounted) {
        showFToast(
          context: context,
          title: const Text('Invalid website'),
          description: const Text('Edit this item and enter a valid web URL.'),
        );
      }
      return;
    }
    try {
      final opened = await app.adapter.openExternalUrl(uri.toString());
      if (!opened) throw Exception('The browser did not open the website.');
    } catch (caught) {
      if (context.mounted) showFailure(context, caught);
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
    final detail = vault.entryView(item.id);
    final password = vault.revealedValue(item.id, 'password');
    final username = vault.revealedValue(item.id, 'username');
    final hasUsername = (username ?? item.username)?.isNotEmpty == true;
    final hasLoginDetails =
        hasUsername || item.hasPassword || item.primaryUrl != null;
    Widget identity() => Row(
      children: [
        KeyLeaseMark(text: item.monogram, large: true),
        SizedBox(width: tokens.gutter),
        Expanded(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                item.title,
                maxLines: 2,
                overflow: TextOverflow.ellipsis,
                style: TextStyle(
                  fontSize: tokens.titleSize,
                  fontWeight: FontWeight.w600,
                ),
              ),
              const SizedBox(height: 5),
              Text(
                item.primaryUrl ?? vault.kindLabel(item.kind),
                maxLines: 1,
                overflow: TextOverflow.ellipsis,
                style: theme.typography.body.sm.copyWith(
                  color: theme.colors.mutedForeground,
                ),
              ),
            ],
          ),
        ),
      ],
    );
    Widget actions() => DecoratedBox(
      decoration: BoxDecoration(
        color: theme.colors.muted.withValues(alpha: 0.22),
        border: Border.all(color: theme.colors.border),
        borderRadius: BorderRadius.circular(10),
      ),
      child: Padding(
        padding: const EdgeInsets.all(3),
        child: Wrap(
          spacing: 2,
          runSpacing: 2,
          alignment: WrapAlignment.end,
          children: [
            IconAction(
              label: item.favorite
                  ? 'Remove from favorites'
                  : 'Add to favorites',
              icon: item.favorite ? FLucideIcons.starOff : FLucideIcons.star,
              variant: item.favorite
                  ? FButtonVariant.secondary
                  : FButtonVariant.ghost,
              onPress: () async {
                try {
                  await vault.toggleFavorite(item);
                } catch (caught) {
                  if (context.mounted) showFailure(context, caught);
                }
              },
            ),
            // Both hand the user something to paste into a coding agent on
            // this machine, so they only make sense where one can run.
            if (app.capabilities.agentWorkflows) ...[
              IconAction(
                key: ValueKey('entry-prompt-${item.id}'),
                label: 'Copy prompt for agent',
                icon: FLucideIcons.clipboardCopy,
                variant: FButtonVariant.ghost,
                onPress: () => _copyAgentPrompt(context, item),
              ),
              IconAction(
                key: ValueKey('entry-cli-${item.id}'),
                label: 'Copy CLI command',
                icon: FLucideIcons.terminal,
                variant: FButtonVariant.ghost,
                onPress: () => _copyCliCommand(context, item),
              ),
            ],
            IconAction(
              label: 'Edit',
              icon: FLucideIcons.squarePen,
              variant: FButtonVariant.ghost,
              onPress: () => openEntryEditor(context, app, existing: item),
            ),
            IconAction(
              label: 'Delete',
              icon: FLucideIcons.trash2,
              variant: FButtonVariant.ghost,
              iconColor: tokens.danger,
              onPress: () => _delete(context, item),
            ),
          ],
        ),
      ),
    );
    return KeyLeaseScrollArea(
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
        LayoutBuilder(
          builder: (context, constraints) {
            final stack =
                constraints.maxWidth < 480 ||
                MediaQuery.textScalerOf(context).scale(1) > 1.15;
            if (!stack) {
              return Row(
                children: [
                  Expanded(child: identity()),
                  SizedBox(width: tokens.gutter),
                  actions(),
                ],
              );
            }
            return Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                identity(),
                SizedBox(height: tokens.gutterSmall),
                Align(alignment: Alignment.centerRight, child: actions()),
              ],
            );
          },
        ),
        if (hasLoginDetails) ...[
          SizedBox(height: tokens.gutter * 1.8),
          const SectionLabel('Login details'),
          FieldGroup(
            children: [
              if (hasUsername)
                DetailField(
                  label: 'Username',
                  value: username ?? item.username,
                  actions: [
                    IconAction(
                      label: 'Copy username',
                      icon: FLucideIcons.copy,
                      onPress: () =>
                          _copy(context, item, 'username', 'Username'),
                    ),
                  ],
                ),
              if (item.hasPassword)
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
                  onPress: () => _openWebsite(context, item.primaryUrl!),
                  actions: [
                    IconAction(
                      label: 'Open website',
                      icon: FLucideIcons.externalLink,
                      onPress: () => _openWebsite(context, item.primaryUrl!),
                    ),
                  ],
                ),
            ],
          ),
        ],
        if (detail != null &&
            const {'core.environment', 'core.ssh_server'}.contains(item.kind))
          DeveloperTemplateDetail(app: app, item: item, detail: detail),
        if (detail != null &&
            !const {
              'core.environment',
              'core.ssh_server',
            }.contains(item.kind) &&
            _additionalFields(detail).isNotEmpty) ...[
          SizedBox(height: tokens.gutter * 1.5),
          const SectionLabel('Details'),
          FieldGroup(
            children: [
              for (final field in _additionalFields(detail))
                if (field.protected)
                  SecretField(
                    label: field.label,
                    revealedValue: vault.revealedValue(item.id, field.id),
                    busy: vault.isBusy('reveal.${item.id}/${field.id}'),
                    maskedValue: field.displayHint,
                    onReveal: () => vault.revealField(item, field),
                    onHide: () => vault.hideSecret(item.id, field.id),
                    onCopy: () => _copyField(context, item, field),
                  )
                else
                  DetailField(
                    label: field.label,
                    value: field.displayValue,
                    actions: [
                      IconAction(
                        label: 'Copy ${field.label}',
                        icon: FLucideIcons.copy,
                        onPress: () => _copyField(context, item, field),
                      ),
                    ],
                  ),
            ],
          ),
        ],
        if (item.hasTotp) ...[
          SizedBox(height: tokens.gutter * 1.5),
          const SectionLabel('Two-factor authentication'),
          _InlineTotpField(app: app, entry: item),
        ],
        if (item.hasNotes) ...[
          SizedBox(height: tokens.gutter * 1.5),
          _InlineNotesSection(app: app, entry: item),
        ],
        SizedBox(height: tokens.gutter * 1.5),
        _MetadataSection(
          item: item,
          detail: detail,
          templateLabel: vault.kindLabel(item.kind),
          projectName: vault.projectName(detail?.projectId),
          groupName: _groupName(item.groupId),
          onHistory: () => _history(context, item),
        ),
      ],
    );
  }

  List<EntryFieldView> _additionalFields(EntryDetailView detail) {
    const legacyRoles = {'username', 'password', 'website', 'url', 'otp'};
    const legacyKeys = {
      'username',
      'password',
      'url',
      'website',
      'otp',
      'totp',
    };
    return detail.fields
        .where(
          (field) =>
              field.hasValue &&
              !legacyRoles.contains(field.semanticRole) &&
              !legacyKeys.contains(field.key.toLowerCase()),
        )
        .toList(growable: false);
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
      await app.removeSshBindingsForItem(item.id);
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

class _InlineNotesSection extends StatefulWidget {
  const _InlineNotesSection({required this.app, required this.entry});

  final AppController app;
  final EntrySummary entry;

  @override
  State<_InlineNotesSection> createState() => _InlineNotesSectionState();
}

class _InlineNotesSectionState extends State<_InlineNotesSection> {
  String? _notes;
  String? _error;
  bool _loading = false;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (mounted) unawaited(_load());
    });
  }

  @override
  void didUpdateWidget(covariant _InlineNotesSection oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.entry.id != widget.entry.id) {
      _notes = null;
      _error = null;
      WidgetsBinding.instance.addPostFrameCallback((_) {
        if (mounted) unawaited(_load());
      });
    }
  }

  Future<void> _load() async {
    if (_loading) return;
    setState(() {
      _loading = true;
      _error = null;
    });
    final notes = await widget.app.vault.fetchSecret(widget.entry, 'notes');
    if (!mounted) return;
    setState(() {
      _loading = false;
      _notes = notes;
      if (notes == null) _error = 'Could not load notes';
    });
  }

  Future<void> _copy(BuildContext context) async {
    final notes = _notes;
    if (notes == null || notes.isEmpty) return;
    final copied = await widget.app.copySensitive(notes);
    if (copied && context.mounted) {
      showFToast(
        context: context,
        title: const Text('Notes copied'),
        description: const Text('The clipboard clears in 30 seconds.'),
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    final tokens = KeyLeaseTokens.of(context);
    final theme = context.theme;
    final notes = _notes;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        SectionLabel(
          'Notes',
          action: notes == null
              ? null
              : IconAction(
                  label: 'Copy notes',
                  icon: FLucideIcons.copy,
                  onPress: () => _copy(context),
                ),
        ),
        DecoratedBox(
          decoration: BoxDecoration(
            border: Border.all(color: theme.colors.border),
            borderRadius: BorderRadius.circular(9),
          ),
          child: Padding(
            padding: EdgeInsets.all(tokens.gutter),
            child: _loading
                ? const Align(
                    alignment: Alignment.centerLeft,
                    child: FCircularProgress(),
                  )
                : _error != null
                ? Row(
                    children: [
                      Expanded(
                        child: Text(
                          _error!,
                          style: TextStyle(color: theme.colors.destructive),
                        ),
                      ),
                      FButton(
                        size: FButtonSizeVariant.xs,
                        variant: FButtonVariant.outline,
                        onPress: _load,
                        child: const Text('Retry'),
                      ),
                    ],
                  )
                : SelectionArea(
                    child: Text(
                      notes ?? '',
                      key: ValueKey('entry-notes-${widget.entry.id}'),
                      style: TextStyle(
                        fontSize: tokens.bodySize,
                        color: theme.colors.foreground,
                        height: 1.45,
                      ),
                    ),
                  ),
          ),
        ),
      ],
    );
  }
}

class _MetadataSection extends StatefulWidget {
  const _MetadataSection({
    required this.item,
    required this.detail,
    required this.templateLabel,
    required this.projectName,
    required this.groupName,
    required this.onHistory,
  });

  final EntrySummary item;
  final EntryDetailView? detail;
  final String templateLabel;
  final String? projectName;
  final String groupName;
  final VoidCallback onHistory;

  @override
  State<_MetadataSection> createState() => _MetadataSectionState();
}

class _MetadataSectionState extends State<_MetadataSection> {
  bool _expanded = false;

  @override
  void didUpdateWidget(covariant _MetadataSection oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.item.id != widget.item.id) _expanded = false;
  }

  @override
  Widget build(BuildContext context) => Column(
    crossAxisAlignment: CrossAxisAlignment.stretch,
    children: [
      FButton(
        key: ValueKey('metadata-toggle-${widget.item.id}'),
        variant: FButtonVariant.ghost,
        size: FButtonSizeVariant.sm,
        mainAxisSize: MainAxisSize.max,
        onPress: () => setState(() => _expanded = !_expanded),
        child: Row(
          children: [
            Icon(
              _expanded ? FLucideIcons.chevronDown : FLucideIcons.chevronRight,
              size: 16,
            ),
            const SizedBox(width: 7),
            const Text('Metadata'),
          ],
        ),
      ),
      if (_expanded) ...[
        const SizedBox(height: 8),
        FieldGroup(
          children: [
            DetailField(label: 'Template', value: widget.templateLabel),
            DetailField(label: 'Group', value: widget.groupName),
            if (widget.projectName != null)
              DetailField(label: 'Project', value: widget.projectName),
            if (widget.detail?.tags.isNotEmpty == true)
              DetailField(label: 'Tags', value: widget.detail!.tags.join(', ')),
            DetailField(
              label: 'Last updated',
              value: widget.item.updatedAt?.toString() ?? 'Unknown',
            ),
            DetailField(
              label: 'Revision',
              value: '${widget.item.revision}',
              actions: [
                IconAction(
                  label: 'View history',
                  icon: FLucideIcons.history,
                  onPress: widget.onHistory,
                ),
              ],
            ),
          ],
        ),
      ],
    ],
  );
}

class _InlineTotpField extends StatefulWidget {
  const _InlineTotpField({required this.app, required this.entry});

  final AppController app;
  final EntrySummary entry;

  @override
  State<_InlineTotpField> createState() => _InlineTotpFieldState();
}

class _InlineTotpFieldState extends State<_InlineTotpField> {
  String? _code;
  String? _error;
  int _remaining = 0;
  bool _loading = false;
  Timer? _timer;

  @override
  void initState() {
    super.initState();
    unawaited(_load());
  }

  @override
  void didUpdateWidget(covariant _InlineTotpField oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.entry.id != widget.entry.id) {
      _timer?.cancel();
      _code = null;
      _error = null;
      unawaited(_load());
    }
  }

  Future<void> _load() async {
    if (_loading) return;
    setState(() {
      _loading = true;
      _error = null;
    });
    try {
      final response = await widget.app.vault.totp(widget.entry);
      if (!mounted) return;
      _timer?.cancel();
      setState(() {
        _code = '${response['code']}';
        _remaining = (response['expires_in'] as num?)?.toInt() ?? 0;
        _loading = false;
      });
      if (_remaining > 0) {
        _timer = Timer.periodic(const Duration(seconds: 1), (_) {
          if (!mounted) return;
          if (_remaining <= 1) {
            _timer?.cancel();
            setState(() => _remaining = 0);
            unawaited(_load());
          } else {
            setState(() => _remaining--);
          }
        });
      }
    } catch (caught) {
      if (!mounted) return;
      setState(() {
        _loading = false;
        _code = null;
        _error = UserMessage.from(caught).detail;
      });
    }
  }

  @override
  void dispose() {
    _timer?.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final code = _code;
    return FieldGroup(
      children: [
        DetailField(
          label: 'One-time password',
          value: _loading
              ? 'Loading code…'
              : code == null
              ? (_error ?? 'Could not load code')
              : '$code · ${_remaining}s',
          actions: [
            if (code != null)
              IconAction(
                label: 'Copy one-time password',
                icon: FLucideIcons.copy,
                onPress: () => widget.app.copySensitive(code),
              ),
            if (_error != null)
              IconAction(
                label: 'Retry one-time password',
                icon: FLucideIcons.refreshCw,
                onPress: _load,
              ),
          ],
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
