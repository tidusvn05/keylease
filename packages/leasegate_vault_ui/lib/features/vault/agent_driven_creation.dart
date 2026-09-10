import 'dart:async';

import 'package:forui/forui.dart';
import 'package:material_ui/material_ui.dart';

import '../../core/models/models.dart';
import '../../core/state/agent_creation_draft.dart';
import '../../core/state/app_controller.dart';
import '../../core/state/user_message.dart';
import '../../ui/components/message_banner.dart';
import '../../ui/components/searchable_select.dart';
import '../../ui/components/section_label.dart';
import 'template_guidance.dart';

class AgentDrivenCreationPane extends StatefulWidget {
  const AgentDrivenCreationPane({
    required this.app,
    required this.draft,
    required this.onReview,
    super.key,
  });

  final AppController app;
  final AgentCreationDraft draft;
  final ValueChanged<String> onReview;

  @override
  State<AgentDrivenCreationPane> createState() =>
      _AgentDrivenCreationPaneState();
}

class _AgentDrivenCreationPaneState extends State<AgentDrivenCreationPane> {
  late final _context = TextEditingController(text: widget.draft.context);
  late final _sourcePath = TextEditingController(text: widget.draft.sourcePath);
  late final _tags = TextEditingController(text: widget.draft.tags);
  UserMessage? _message;
  List<EntrySummary> _candidates = const [];
  bool _copying = false;
  bool _refreshing = false;

  AgentCreationDraft get draft => widget.draft;

  @override
  void dispose() {
    _context.dispose();
    _sourcePath.dispose();
    _tags.dispose();
    super.dispose();
  }

  String _groupBreadcrumb(VaultGroup group) {
    final groups = widget.app.vault.groups;
    final names = <String>[group.name];
    final visited = <String>{group.id};
    var parentId = group.parentId;
    while (parentId != null && visited.add(parentId)) {
      VaultGroup? parent;
      for (final candidate in groups) {
        if (candidate.id == parentId) {
          parent = candidate;
          break;
        }
      }
      if (parent == null) break;
      names.insert(0, parent.name);
      parentId = parent.parentId;
    }
    return names.join(' / ');
  }

  void _sync() {
    draft
      ..context = _context.text
      ..sourcePath = _sourcePath.text
      ..tags = _tags.text
      ..invalidateHandoff();
    if (mounted) {
      setState(() {
        _message = null;
        _candidates = const [];
      });
    }
  }

  void _selectRecipe(AgentCreationRecipe recipe) {
    setState(() {
      draft.applyRecipe(recipe);
      _sourcePath.text = draft.sourcePath;
      _message = null;
      _candidates = const [];
    });
  }

  void _changeTemplate(String? kind) {
    if (kind == null || kind == draft.kind) return;
    setState(() {
      draft
        ..kind = kind
        ..invalidateHandoff();
      _message = null;
      _candidates = const [];
    });
  }

  String? _validationError() {
    if ((widget.app.status?.vaultId ?? '').isEmpty) {
      return 'The active vault identity is not available. Refresh KeyLease and try again.';
    }
    if (!draft.isAgentContent && (draft.groupId ?? '').isEmpty) {
      return 'Choose the group where the agent should create this item.';
    }
    if (draft.recipeId == 'dotenv' && _sourcePath.text.trim().isEmpty) {
      return 'Enter the path to the .env file the agent may read.';
    }
    return null;
  }

  Future<void> _copyAgentInstruction() async {
    draft
      ..context = _context.text
      ..sourcePath = _sourcePath.text
      ..tags = _tags.text;
    final validation = _validationError();
    if (validation != null) {
      setState(() {
        _message = UserMessage(title: 'Complete the setup', detail: validation);
      });
      return;
    }
    setState(() {
      _copying = true;
      _message = null;
    });
    try {
      draft.baselineEntryIds ??= await widget.app.vault.snapshotEntryIds();
      var handoff = draft.handoff;
      if (handoff == null || handoff.expired) {
        handoff = await widget.app.vault.createAgentHandoff(
          draft: draft,
          expectedVaultId: widget.app.status!.vaultId!,
        );
        draft.handoff = handoff;
      }
      final copied = await widget.app.copySensitive(
        handoff.clipboardText,
        clearAfter: const Duration(seconds: 120),
      );
      if (!mounted) return;
      if (copied) {
        setState(() => draft.handoffCopied = true);
        showFToast(
          context: context,
          title: const Text('Agent command copied'),
          description: const Text(
            'Paste the short instruction into your agent. The CLI will provide the complete workflow.',
          ),
        );
      }
    } catch (caught) {
      if (mounted) setState(() => _message = UserMessage.from(caught));
    } finally {
      if (mounted) setState(() => _copying = false);
    }
  }

  Future<void> _refreshAndReview() async {
    final baseline = draft.baselineEntryIds;
    if (baseline == null) return;
    setState(() {
      _refreshing = true;
      _message = null;
      _candidates = const [];
    });
    try {
      final candidates = await widget.app.vault.entriesCreatedSince(baseline);
      if (!mounted) return;
      if (candidates.length == 1) {
        _open(candidates.single);
      } else if (candidates.isEmpty) {
        setState(() {
          _message = const UserMessage(
            title: 'The agent has not created an item yet',
            detail:
                'If the agent asked for a title or fields, reply in that chat first. Refresh only after it says “Created in KeyLease” and returns an item ID.',
          );
        });
      } else {
        setState(() {
          _candidates = candidates;
          _message = const UserMessage(
            title: 'Choose the item to review',
            detail: 'More than one item changed while the agent was working.',
          );
        });
      }
    } catch (caught) {
      if (mounted) setState(() => _message = UserMessage.from(caught));
    } finally {
      if (mounted) setState(() => _refreshing = false);
    }
  }

  void _open(EntrySummary entry) {
    widget.app.vault.openAgentCreatedEntry(entry);
    widget.onReview(entry.id);
  }

  @override
  Widget build(BuildContext context) {
    final theme = context.theme;
    final templates = widget.app.vault.templates;
    final handoff = draft.handoff;
    final launchText = handoff == null || handoff.expired
        ? 'KeyLease will prepare a temporary CLI handoff when you copy.'
        : handoff.clipboardText;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        const GuidanceCard(
          key: ValueKey('agent-driven-guidance'),
          title: 'Create this item with a local agent',
          summary:
              'Choose a starting point, then copy one short command into Codex or another agent with terminal access.',
          useWhen:
              'The KeyLease CLI supplies the complete, version-matched workflow. The handoff expires after two hours and never needs your master password.',
        ),
        const SizedBox(height: 20),
        const _StepTitle(number: 1, title: 'Choose a starting point'),
        const SizedBox(height: 10),
        LayoutBuilder(
          builder: (context, constraints) {
            final cardWidth = constraints.maxWidth < 620
                ? constraints.maxWidth
                : (constraints.maxWidth - 12) / 2;
            return Wrap(
              spacing: 12,
              runSpacing: 12,
              children: [
                for (final recipe in agentCreationRecipes)
                  SizedBox(
                    width: cardWidth,
                    child: _RecipeCard(
                      recipe: recipe,
                      selected: recipe.id == draft.recipeId,
                      onPressed: () => _selectRecipe(recipe),
                    ),
                  ),
              ],
            );
          },
        ),
        const SizedBox(height: 24),
        const _StepTitle(number: 2, title: 'Set the target and source'),
        const SizedBox(height: 10),
        SearchableSelect<String>(
          key: const ValueKey('agent-entry-kind'),
          label: const Text('Template'),
          options: [
            for (final template in templates)
              SearchSelectOption(
                value: template.kind,
                label: template.label,
                subtitle: guidanceForTemplate(
                  template.kind,
                  label: template.label,
                ).summary,
                searchTerms: [template.kind, template.family],
              ),
          ],
          value: draft.kind,
          onChange: _changeTemplate,
        ),
        const SizedBox(height: 10),
        if (draft.isAgentContent) ...[
          SearchableSelect<String>(
            key: const ValueKey('agent-entry-project'),
            label: const Text('Project (optional)'),
            clearable: true,
            options: [
              for (final project in widget.app.vault.projects)
                SearchSelectOption(
                  value: project.slug,
                  label: project.name,
                  subtitle: project.slug,
                ),
            ],
            value: draft.projectSlug,
            onChange: (value) => setState(() {
              draft
                ..projectSlug = value
                ..invalidateHandoff();
            }),
          ),
          const SizedBox(height: 10),
          FTextField(
            key: const ValueKey('agent-entry-tags'),
            label: const Text('Tags (comma separated)'),
            control: FTextFieldControl.managed(
              controller: _tags,
              onChange: (_) => _sync(),
            ),
          ),
          const SizedBox(height: 10),
          FSelect<String>(
            key: const ValueKey('agent-entry-access'),
            label: const Text('Agent access after creation'),
            items: const {
              'Read and write': 'read_write',
              'Read only': 'read',
              'Owner only': 'none',
            },
            control: FSelectControl.lifted(
              value: draft.agentAccess,
              onChange: (value) => setState(() {
                draft
                  ..agentAccess = value ?? 'read_write'
                  ..invalidateHandoff();
              }),
            ),
          ),
        ] else
          SearchableSelect<String>(
            key: const ValueKey('agent-entry-group'),
            label: const Text('Group'),
            hint: 'Choose a destination group',
            options: [
              for (final group in widget.app.vault.orderedGroups)
                SearchSelectOption(
                  value: group.id,
                  label: _groupBreadcrumb(group),
                  searchTerms: [group.name, group.id],
                ),
            ],
            value: draft.groupId,
            onChange: (value) => setState(() {
              draft
                ..groupId = value
                ..invalidateHandoff();
            }),
          ),
        const SizedBox(height: 10),
        FTextField(
          key: const ValueKey('agent-source-path'),
          label: const Text('Source path (optional)'),
          description: const Text(
            'A file or directory the agent may read. Do not enter a secret value here.',
          ),
          control: FTextFieldControl.managed(
            controller: _sourcePath,
            onChange: (_) => _sync(),
          ),
        ),
        const SizedBox(height: 10),
        FTextField.multiline(
          key: const ValueKey('agent-context'),
          label: const Text('What should the agent create? (optional)'),
          description: const Text(
            'Describe the goal, host alias, environment, or expected content. Do not paste secret values.',
          ),
          minLines: 3,
          maxLines: 7,
          control: FTextFieldControl.managed(
            controller: _context,
            onChange: (_) => _sync(),
          ),
        ),
        const SizedBox(height: 24),
        const _StepTitle(number: 3, title: 'Copy the CLI handoff'),
        const SizedBox(height: 10),
        DecoratedBox(
          decoration: BoxDecoration(
            color: theme.colors.muted.withValues(alpha: 0.3),
            border: Border.all(color: theme.colors.border),
            borderRadius: BorderRadius.circular(8),
          ),
          child: Padding(
            padding: const EdgeInsets.all(12),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                SelectableText(
                  launchText,
                  key: const ValueKey('agent-handoff-preview'),
                  style: const TextStyle(
                    fontFamily: 'monospace',
                    fontSize: 12,
                    height: 1.4,
                  ),
                ),
                if (handoff != null && !handoff.expired) ...[
                  const SizedBox(height: 8),
                  Text(
                    'Available until ${MaterialLocalizations.of(context).formatTimeOfDay(TimeOfDay.fromDateTime(handoff.expiresAt))}',
                    style: theme.typography.body.sm.copyWith(
                      color: theme.colors.mutedForeground,
                    ),
                  ),
                ],
              ],
            ),
          ),
        ),
        const SizedBox(height: 10),
        Align(
          alignment: Alignment.centerRight,
          child: FButton(
            key: const ValueKey('agent-copy-command'),
            onPress: _copying ? null : _copyAgentInstruction,
            child: Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                Icon(
                  _copying ? FLucideIcons.loaderCircle : FLucideIcons.copy,
                  size: 16,
                ),
                const SizedBox(width: 7),
                Text(_copying ? 'Preparing…' : 'Copy agent command'),
              ],
            ),
          ),
        ),
        const SizedBox(height: 24),
        const _StepTitle(number: 4, title: 'Refresh and review'),
        const SizedBox(height: 8),
        Text(
          'Continue the agent conversation until it says “Created in KeyLease” and returns an item ID. Then refresh here to review and edit the result.',
          style: theme.typography.body.sm.copyWith(
            color: theme.colors.mutedForeground,
          ),
        ),
        const SizedBox(height: 10),
        Align(
          alignment: Alignment.centerLeft,
          child: FButton(
            key: const ValueKey('agent-refresh-review'),
            variant: FButtonVariant.outline,
            onPress: !draft.handoffCopied || _refreshing
                ? null
                : _refreshAndReview,
            child: Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                Icon(FLucideIcons.refreshCw, size: 16),
                const SizedBox(width: 7),
                Text(_refreshing ? 'Refreshing…' : 'Refresh & review'),
              ],
            ),
          ),
        ),
        if (_message != null) ...[
          const SizedBox(height: 12),
          MessageBanner(
            message: _message!,
            onDismiss: () => setState(() => _message = null),
          ),
        ],
        if (_candidates.isNotEmpty) ...[
          const SizedBox(height: 12),
          const SectionLabel('New items'),
          const SizedBox(height: 8),
          for (final candidate in _candidates)
            Padding(
              padding: const EdgeInsets.only(bottom: 8),
              child: FButton(
                variant: FButtonVariant.outline,
                onPress: () => _open(candidate),
                child: Align(
                  alignment: Alignment.centerLeft,
                  child: Text(
                    '${candidate.title} · ${widget.app.vault.kindLabel(candidate.kind)}',
                  ),
                ),
              ),
            ),
        ],
        const SizedBox(height: 96),
      ],
    );
  }
}

class _StepTitle extends StatelessWidget {
  const _StepTitle({required this.number, required this.title});

  final int number;
  final String title;

  @override
  Widget build(BuildContext context) => Row(
    children: [
      DecoratedBox(
        decoration: BoxDecoration(
          color: context.theme.colors.primary,
          shape: BoxShape.circle,
        ),
        child: SizedBox.square(
          dimension: 24,
          child: Center(
            child: Text(
              '$number',
              style: TextStyle(
                color: context.theme.colors.primaryForeground,
                fontWeight: FontWeight.w700,
                fontSize: 12,
              ),
            ),
          ),
        ),
      ),
      const SizedBox(width: 8),
      Expanded(child: SectionLabel(title)),
    ],
  );
}

class _RecipeCard extends StatelessWidget {
  const _RecipeCard({
    required this.recipe,
    required this.selected,
    required this.onPressed,
  });

  final AgentCreationRecipe recipe;
  final bool selected;
  final VoidCallback onPressed;

  @override
  Widget build(BuildContext context) {
    final theme = context.theme;
    return Semantics(
      button: true,
      selected: selected,
      label: recipe.title,
      child: Material(
        color: selected
            ? theme.colors.primary.withValues(alpha: 0.1)
            : theme.colors.muted.withValues(alpha: 0.22),
        shape: RoundedRectangleBorder(
          side: BorderSide(
            color: selected ? theme.colors.primary : theme.colors.border,
          ),
          borderRadius: BorderRadius.circular(9),
        ),
        child: InkWell(
          key: ValueKey('agent-recipe-${recipe.id}'),
          borderRadius: BorderRadius.circular(9),
          onTap: onPressed,
          child: Padding(
            padding: const EdgeInsets.all(12),
            child: Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Icon(
                  selected ? FLucideIcons.check : FLucideIcons.sparkles,
                  size: 17,
                  color: selected
                      ? theme.colors.primary
                      : theme.colors.mutedForeground,
                ),
                const SizedBox(width: 9),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        recipe.title,
                        style: theme.typography.body.sm.copyWith(
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                      const SizedBox(height: 3),
                      Text(
                        recipe.description,
                        style: theme.typography.body.sm.copyWith(
                          color: theme.colors.mutedForeground,
                        ),
                      ),
                    ],
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}
