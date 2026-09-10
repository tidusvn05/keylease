import 'package:forui/forui.dart';
import 'package:material_ui/material_ui.dart';

import '../core/models/models.dart';
import '../core/state/app_controller.dart';
import '../core/state/app_phase.dart';
import '../core/state/user_message.dart';
import '../core/state/vault_controller.dart';
import '../features/approvals/approvals_page.dart';
import '../features/migrations/migration_center.dart';
import '../features/onboarding/phase_screens.dart';
import '../features/settings/settings_page.dart';
import '../features/vault/entry_editor.dart';
import '../features/vault/entry_list.dart';
import '../features/vault/password_generator.dart';
import '../features/vault/totp_dialog.dart';
import '../features/vault/vault_page.dart';
import '../ui/components/keylease_dialog.dart';
import '../ui/components/keylease_mark.dart';
import '../ui/components/message_banner.dart';
import '../ui/components/secret_field.dart';
import '../ui/components/scroll_area.dart';
import '../ui/components/split_pane.dart';
import '../ui/tokens/keylease_tokens.dart';
import 'app_scope.dart';

/// Chooses the shell for the current window, then hands every form factor the
/// same feature state.
///
/// Desktop keeps a persistent sidebar and a resizable list/detail split.
/// Tablet keeps a rail and the split when there is room. Phone uses compact
/// navigation and routes list → detail.
class AdaptiveShell extends StatelessWidget {
  const AdaptiveShell({super.key});

  @override
  Widget build(BuildContext context) {
    final app = AppScope.of(context);
    final tokens = KeyLeaseTokens.of(context);
    return LayoutBuilder(
      builder: (context, constraints) {
        final width = constraints.maxWidth;
        final splitView = width >= tokens.splitBreakpoint;
        final desktopToolbar = width >= tokens.expandedBreakpoint;
        final body = _ShellBody(
          app: app,
          splitView: splitView,
          desktopToolbar: desktopToolbar,
        );

        // Locked and recovery states are focused tasks, not vault
        // destinations. Keeping the navigation visible suggests that its
        // items are usable and leaves the unlock form visually off-centre.
        if (!app.isReady && app.section != AppSection.settings) {
          return FScaffold(childPad: false, child: body);
        }
        if (width >= tokens.expandedBreakpoint) {
          return _DesktopShell(app: app, body: body);
        }
        if (width >= tokens.compactBreakpoint) {
          return _RailShell(app: app, body: body);
        }
        return _CompactShell(app: app, body: body);
      },
    );
  }
}

/// Section content plus the app-wide banner, shared by every shell.
class _ShellBody extends StatelessWidget {
  const _ShellBody({
    required this.app,
    required this.splitView,
    required this.desktopToolbar,
  });

  final AppController app;
  final bool splitView;
  final bool desktopToolbar;

  @override
  Widget build(BuildContext context) {
    final section = app.section;
    final gated = section.requiresReady && !app.isReady;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        if (app.isReady &&
            (app.vault.migrationStatus?.pending.isNotEmpty ?? false))
          MessageBanner(
            message: UserMessage(
              title: 'Vault migration available',
              detail:
                  '${app.vault.migrationStatus!.pending.first.proposals.length} legacy items can be safely reclassified.',
              actionLabel: 'Review migration',
            ),
            onAction: () => openMigrationCenter(context, app),
          ),
        if (app.banner != null)
          MessageBanner(
            message: app.banner!,
            onDismiss: app.dismissBanner,
            onAction: app.refresh,
          ),
        Expanded(
          child: gated
              ? PhaseScreen(phase: app.phase)
              : switch (section) {
                  AppSection.vault => VaultPage(
                    splitView: splitView,
                    desktopToolbar: desktopToolbar,
                  ),
                  AppSection.approvals => const ApprovalsPage(),
                  AppSection.settings => const SettingsPage(),
                },
        ),
      ],
    );
  }
}

class _Header extends StatelessWidget {
  const _Header({required this.app});

  final AppController app;

  @override
  Widget build(BuildContext context) => FHeader(
    title: app.section == AppSection.vault
        ? const SizedBox.shrink()
        : Text(app.section.label),
    suffixes: [
      if (app.section == AppSection.vault && app.isReady)
        FHeaderAction(
          semanticsLabel: 'Password generator',
          icon: const Icon(FLucideIcons.sparkles),
          onPress: () => openPasswordGenerator(context, app),
        ),
      if (app.section == AppSection.vault && app.isReady)
        FHeaderAction(
          semanticsLabel: 'New item',
          icon: const Icon(FLucideIcons.plus),
          onPress: () => openEntryEditor(context, app),
        ),
      FHeaderAction(
        semanticsLabel: 'Refresh',
        icon: const Icon(FLucideIcons.refreshCw),
        onPress: app.isBusy(AppController.refreshKey) ? null : app.refresh,
      ),
      if (app.isReady)
        FHeaderAction(
          semanticsLabel: 'Lock vault',
          icon: const Icon(FLucideIcons.lock),
          onPress: app.isBusy(AppController.lockKey) ? null : app.lock,
        ),
    ],
  );
}

class _DesktopShell extends StatelessWidget {
  const _DesktopShell({required this.app, required this.body});

  final AppController app;
  final Widget body;

  @override
  Widget build(BuildContext context) {
    final tokens = KeyLeaseTokens.of(context);
    return Column(
      children: [
        _DesktopTitleBar(app: app),
        Expanded(
          child: SplitPane(
            width: app.sidebarWidth,
            minWidth: tokens.sidebarMinWidth,
            maxWidth: tokens.sidebarMaxWidth,
            semanticsLabel: 'Resize the sidebar',
            onWidthChanged: (value) => app.setPaneWidths(sidebar: value),
            leading: _Sidebar(app: app),
            trailing: FScaffold(childPad: false, child: body),
          ),
        ),
      ],
    );
  }
}

class _DesktopTitleBar extends StatelessWidget {
  const _DesktopTitleBar({required this.app});

  final AppController app;

  @override
  Widget build(BuildContext context) {
    final theme = context.theme;
    final vault = app.vault;
    final activeVault = app.vaultProfiles
        .where((profile) => profile.active)
        .firstOrNull;
    return Container(
      height: 52,
      decoration: BoxDecoration(
        color: theme.colors.muted.withValues(alpha: 0.24),
        border: Border(bottom: BorderSide(color: theme.colors.border)),
      ),
      child: Row(
        children: [
          SizedBox(
            width: app.sidebarWidth,
            child: Padding(
              // Clears the macOS traffic lights. `_DesktopShell` starts at
              // 900px, which an Android tablet or an unfolded foldable also
              // reaches, so this cannot be unconditional.
              padding: EdgeInsets.only(
                left: app.capabilities.windowTrafficLights ? 78 : 12,
                right: 10,
              ),
              child: Row(
                children: [
                  const KeyLeaseBrandMark(size: 24),
                  const SizedBox(width: 8),
                  Expanded(
                    child: Text(
                      activeVault?.name ?? 'KeyLease',
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                      style: theme.typography.body.sm.copyWith(
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                  ),
                ],
              ),
            ),
          ),
          ColoredBox(
            color: theme.colors.border,
            child: const SizedBox(width: 1),
          ),
          SizedBox(
            width: app.listWidth + 6,
            child: Padding(
              padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 7),
              child: app.section == AppSection.vault
                  ? VaultSearchField(controller: vault, onActivate: (_) {})
                  : Align(
                      alignment: Alignment.centerLeft,
                      child: Text(
                        app.section.label,
                        style: theme.typography.body.md.copyWith(
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                    ),
            ),
          ),
          ColoredBox(
            color: theme.colors.border,
            child: const SizedBox(width: 1),
          ),
          Expanded(
            child: Padding(
              padding: const EdgeInsets.symmetric(horizontal: 8),
              child: Row(
                mainAxisAlignment: MainAxisAlignment.end,
                children: [
                  if (app.section == AppSection.vault) ...[
                    IconAction(
                      label: 'Password generator',
                      icon: FLucideIcons.sparkles,
                      onPress: () => openPasswordGenerator(context, app),
                    ),
                    const SizedBox(width: 6),
                    IconAction(
                      label: 'New item',
                      icon: FLucideIcons.plus,
                      onPress: () => openEntryEditor(context, app),
                    ),
                    const SizedBox(width: 6),
                  ],
                  IconAction(
                    label: 'Refresh',
                    icon: FLucideIcons.refreshCw,
                    onPress: app.isBusy(AppController.refreshKey)
                        ? null
                        : app.refresh,
                  ),
                  const SizedBox(width: 6),
                  IconAction(
                    label: 'Lock vault',
                    icon: FLucideIcons.lock,
                    onPress: app.isBusy(AppController.lockKey)
                        ? null
                        : app.lock,
                  ),
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }
}

class _RailShell extends StatelessWidget {
  const _RailShell({required this.app, required this.body});

  final AppController app;
  final Widget body;

  @override
  Widget build(BuildContext context) => FScaffold(
    childPad: false,
    header: _Header(app: app),
    child: Row(
      children: [
        _Rail(app: app),
        ColoredBox(
          color: context.theme.colors.border,
          child: const SizedBox(width: 1, height: double.infinity),
        ),
        Expanded(child: body),
      ],
    ),
  );
}

class _CompactShell extends StatelessWidget {
  const _CompactShell({required this.app, required this.body});

  final AppController app;
  final Widget body;

  @override
  Widget build(BuildContext context) => PopScope(
    // Android's back gesture should walk back through the sections before it
    // leaves the app, the way every other Android app behaves. Vault is the
    // root, so back from there does exit.
    canPop: app.section == AppSection.vault,
    onPopInvokedWithResult: (didPop, _) {
      if (didPop) return;
      app.selectSection(AppSection.vault);
    },
    child: _buildShell(context),
  );

  Widget _buildShell(BuildContext context) => FScaffold(
    childPad: false,
    header: SafeArea(bottom: false, child: _Header(app: app)),
    // Android 15 forces edge-to-edge for targetSdk 35+, so the bottom bar sits
    // under the gesture handle unless it is inset explicitly.
    footer: SafeArea(
      top: false,
      child: FBottomNavigationBar(
        index: AppSection.values.indexOf(app.section),
        onChange: (index) {
          final section = AppSection.values[index];
          if (section == AppSection.settings) {
            app.openSettings();
          } else {
            app.selectSection(section);
          }
        },
        children: const [
          FBottomNavigationBarItem(
            icon: Icon(FLucideIcons.keyRound),
            label: Text('Vault'),
          ),
          FBottomNavigationBarItem(
            icon: Icon(FLucideIcons.shieldCheck),
            label: Text('Approvals'),
          ),
          FBottomNavigationBarItem(
            icon: Icon(FLucideIcons.settings),
            label: Text('Settings'),
          ),
        ],
      ),
    ),
    child: SafeArea(top: false, bottom: false, child: body),
  );
}

class _Rail extends StatelessWidget {
  const _Rail({required this.app});

  final AppController app;

  static const _icons = {
    AppSection.vault: FLucideIcons.keyRound,
    AppSection.approvals: FLucideIcons.shieldCheck,
    AppSection.settings: FLucideIcons.settings,
  };

  @override
  Widget build(BuildContext context) => SizedBox(
    width: 68,
    child: Column(
      children: [
        const SizedBox(height: 12),
        const KeyLeaseBrandMark(size: 32),
        const SizedBox(height: 12),
        for (final section in AppSection.values)
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
            child: IconAction(
              label: section.label,
              icon: _icons[section]!,
              variant: app.section == section
                  ? FButtonVariant.secondary
                  : FButtonVariant.ghost,
              onPress: () {
                if (section == AppSection.settings) {
                  app.openSettings();
                } else {
                  app.selectSection(section);
                }
              },
            ),
          ),
      ],
    ),
  );
}

class _Sidebar extends StatelessWidget {
  const _Sidebar({required this.app});

  final AppController app;

  @override
  Widget build(BuildContext context) {
    return Observe(
      listenable: app.vault,
      builder: (context, vault) => FSidebar.raw(
        style: const FSidebarStyleDelta.delta(
          contentPadding: EdgeInsetsGeometryDelta.value(EdgeInsets.zero),
        ),
        footer: _ConnectionFooter(app: app),
        child: KeyLeaseScrollArea(
          padding: const EdgeInsets.symmetric(vertical: 8),
          children: [
            if (app.isReady)
              FSidebarGroup(
                label: const Text('Groups'),
                action: const Icon(FLucideIcons.folderPlus, size: 15),
                onActionPress: () => _createGroup(context),
                children: [
                  FSidebarItem(
                    key: const ValueKey('group-all'),
                    icon: const Icon(FLucideIcons.layoutGrid),
                    label: const Text('All items'),
                    selected:
                        app.section == AppSection.vault &&
                        vault.selectedGroupId == null &&
                        !vault.favoritesOnly,
                    onPress: () async {
                      if (!await confirmCloseEntryEditor(context, app)) return;
                      app.selectSection(AppSection.vault);
                      vault.selectGroup(null);
                    },
                  ),
                  FSidebarItem(
                    key: const ValueKey('group-favorites'),
                    icon: const Icon(FLucideIcons.star),
                    label: const Text('Favorites'),
                    selected:
                        app.section == AppSection.vault && vault.favoritesOnly,
                    onPress: () async {
                      if (!await confirmCloseEntryEditor(context, app)) return;
                      app.selectSection(AppSection.vault);
                      vault.selectFavorites();
                    },
                  ),
                  for (final group in vault.orderedGroups.where(
                    (group) => group.parentId == null,
                  )) ...[
                    FSidebarItem(
                      key: ValueKey('group-${group.id}'),
                      icon: const Icon(FLucideIcons.folder),
                      label: Text(group.name),
                      selected:
                          app.section == AppSection.vault &&
                          vault.selectedGroupId == group.id,
                      onPress: () async {
                        if (!await confirmCloseEntryEditor(context, app)) {
                          return;
                        }
                        app.selectSection(AppSection.vault);
                        vault.selectGroup(group.id);
                      },
                    ),
                    for (final child in vault.orderedGroups.where(
                      (candidate) => candidate.parentId == group.id,
                    ))
                      FSidebarItem(
                        key: ValueKey('group-${child.id}'),
                        icon: const Icon(
                          FLucideIcons.cornerDownRight,
                          size: 15,
                        ),
                        label: Padding(
                          padding: const EdgeInsets.only(left: 8),
                          child: Text(child.name),
                        ),
                        selected:
                            app.section == AppSection.vault &&
                            vault.selectedGroupId == child.id,
                        onPress: () async {
                          if (!await confirmCloseEntryEditor(context, app)) {
                            return;
                          }
                          app.selectSection(AppSection.vault);
                          vault.selectGroup(child.id);
                        },
                      ),
                  ],
                  if (vault.groups.isNotEmpty)
                    FSidebarItem(
                      key: const ValueKey('group-manage'),
                      icon: const Icon(FLucideIcons.settings2),
                      label: const Text('Manage groups'),
                      onPress: () => _manageGroups(context),
                    ),
                ],
              ),
            FSidebarGroup(
              label: const Text('Tools'),
              children: [
                if (app.isReady)
                  FSidebarItem(
                    key: const ValueKey('tool-password-generator'),
                    icon: const Icon(FLucideIcons.sparkles),
                    label: const Text('Password generator'),
                    selected:
                        app.section == AppSection.vault &&
                        vault.workspaceMode ==
                            EntryWorkspaceMode.passwordGenerator,
                    onPress: () async {
                      if (!await confirmCloseEntryEditor(context, app)) return;
                      if (!context.mounted) return;
                      app.selectSection(AppSection.vault);
                      await openPasswordGenerator(context, app);
                    },
                  ),
              ],
            ),
            FSidebarGroup(
              children: [
                for (final section in const [
                  AppSection.approvals,
                  AppSection.settings,
                ])
                  FSidebarItem(
                    key: ValueKey('nav-${section.name}'),
                    icon: Icon(_Rail._icons[section]),
                    label: Text(section.label),
                    selected: app.section == section,
                    onPress: () async {
                      if (!await confirmCloseEntryEditor(context, app)) return;
                      if (section == AppSection.settings) {
                        await app.openSettings();
                      } else {
                        app.selectSection(section);
                      }
                    },
                  ),
              ],
            ),
          ],
        ),
      ),
    );
  }

  Future<void> _createGroup(BuildContext context) async {
    final name = TextEditingController();
    final submitted = await showKeyLeaseDialog<bool>(
      context: context,
      title: 'New group',
      bodyBuilder: (context) => FTextField(
        key: const ValueKey('group-name'),
        label: const Text('Name'),
        autofocus: true,
        control: FTextFieldControl.managed(controller: name),
      ),
      actionsBuilder: (context) => [
        FButton(
          variant: FButtonVariant.outline,
          onPress: () => Navigator.of(context).pop(false),
          child: const Text('Cancel'),
        ),
        FButton(
          onPress: () => Navigator.of(context).pop(true),
          child: const Text('Create'),
        ),
      ],
    );
    final value = name.text.trim();
    name.dispose();
    if (submitted != true || value.isEmpty || !context.mounted) return;
    try {
      await app.vault.createGroup(value);
    } catch (caught) {
      if (context.mounted) showFailure(context, caught);
    }
  }

  Future<void> _manageGroups(BuildContext context) => showKeyLeaseDialog<void>(
    context: context,
    title: 'Manage groups',
    description: 'Drag groups or use the arrow buttons to choose their order.',
    bodyBuilder: (context) => _GroupManager(app: app),
    actionsBuilder: (context) => [
      FButton(
        onPress: () => Navigator.of(context).pop(),
        child: const Text('Done'),
      ),
    ],
    presentation: KeyLeasePresentation.fullScreen,
  );
}

class _GroupManager extends StatelessWidget {
  const _GroupManager({required this.app});

  final AppController app;

  @override
  Widget build(BuildContext context) => Observe(
    listenable: app.vault,
    builder: (context, vault) {
      final roots = vault.orderedGroups
          .where((group) => group.parentId == null)
          .toList(growable: false);
      return Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          _ReorderableGroupLevel(app: app, groups: roots),
          for (final root in roots)
            if (vault.orderedGroups.any(
              (group) => group.parentId == root.id,
            )) ...[
              Padding(
                padding: const EdgeInsets.fromLTRB(12, 12, 0, 4),
                child: Text('${root.name} subgroups'),
              ),
              _ReorderableGroupLevel(
                app: app,
                groups: vault.orderedGroups
                    .where((group) => group.parentId == root.id)
                    .toList(growable: false),
                indent: 12,
              ),
            ],
        ],
      );
    },
  );
}

class _ReorderableGroupLevel extends StatelessWidget {
  const _ReorderableGroupLevel({
    required this.app,
    required this.groups,
    this.indent = 0,
  });

  final AppController app;
  final List<VaultGroup> groups;
  final double indent;

  Future<void> _move(BuildContext context, int from, int to) async {
    if (from == to || to < 0 || to >= groups.length) return;
    final ordered = [...groups];
    ordered.insert(to, ordered.removeAt(from));
    try {
      await app.vault.reorderGroups(groups.first.parentId, ordered);
    } catch (caught) {
      if (context.mounted) showFailure(context, caught);
    }
  }

  @override
  Widget build(BuildContext context) => Padding(
    padding: EdgeInsets.only(left: indent),
    child: ReorderableListView.builder(
      shrinkWrap: true,
      physics: const NeverScrollableScrollPhysics(),
      // Flutter's default desktop handle is overlaid at the trailing edge.
      // That position collides with this row's delete action, making both
      // controls unreliable. Each row owns an explicit leading handle below.
      buildDefaultDragHandles: false,
      itemCount: groups.length,
      onReorderItem: (from, to) => _move(context, from, to),
      itemBuilder: (context, index) => _GroupRow(
        key: ValueKey('manage-${groups[index].id}'),
        app: app,
        group: groups[index],
        reorderIndex: index,
        onMoveUp: index == 0 ? null : () => _move(context, index, index - 1),
        onMoveDown: index == groups.length - 1
            ? null
            : () => _move(context, index, index + 1),
      ),
    ),
  );
}

class _GroupRow extends StatelessWidget {
  const _GroupRow({
    required this.app,
    required this.group,
    required this.reorderIndex,
    this.onMoveUp,
    this.onMoveDown,
    super.key,
  });

  final AppController app;
  final VaultGroup group;
  final int reorderIndex;
  final VoidCallback? onMoveUp;
  final VoidCallback? onMoveDown;

  @override
  Widget build(BuildContext context) => FItem(
    prefix: ReorderableDragStartListener(
      key: ValueKey('manage-drag-${group.id}'),
      index: reorderIndex,
      child: MouseRegion(
        cursor: SystemMouseCursors.grab,
        child: Semantics(
          button: true,
          label: 'Drag ${group.name} to reorder',
          child: const SizedBox.square(
            dimension: 32,
            child: Center(child: Icon(FLucideIcons.gripVertical, size: 18)),
          ),
        ),
      ),
    ),
    title: Text(group.name),
    suffix: Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        IconAction(
          label: 'Move ${group.name} up',
          icon: FLucideIcons.arrowUp,
          onPress: onMoveUp,
        ),
        const SizedBox(width: 6),
        IconAction(
          label: 'Move ${group.name} down',
          icon: FLucideIcons.arrowDown,
          onPress: onMoveDown,
        ),
        const SizedBox(width: 6),
        IconAction(
          label: 'Rename ${group.name}',
          icon: FLucideIcons.squarePen,
          onPress: () => _rename(context),
        ),
        const SizedBox(width: 6),
        IconAction(
          label: 'Delete ${group.name}',
          icon: FLucideIcons.trash2,
          onPress: () => _delete(context),
        ),
      ],
    ),
  );

  Future<void> _rename(BuildContext context) async {
    final name = TextEditingController(text: group.name);
    final submitted = await showKeyLeaseDialog<bool>(
      context: context,
      title: 'Rename group',
      bodyBuilder: (context) => FTextField(
        label: const Text('Name'),
        autofocus: true,
        control: FTextFieldControl.managed(controller: name),
      ),
      actionsBuilder: (context) => [
        FButton(
          variant: FButtonVariant.outline,
          onPress: () => Navigator.of(context).pop(false),
          child: const Text('Cancel'),
        ),
        FButton(
          onPress: () => Navigator.of(context).pop(true),
          child: const Text('Rename'),
        ),
      ],
    );
    final value = name.text.trim();
    name.dispose();
    if (submitted != true || value.isEmpty || !context.mounted) return;
    try {
      await app.vault.renameGroup(group, value);
    } catch (caught) {
      if (context.mounted) showFailure(context, caught);
    }
  }

  Future<void> _delete(BuildContext context) async {
    final confirmed = await confirm(
      context: context,
      title: 'Delete this group?',
      message:
          'Only an empty group can be deleted. "${group.name}" is '
          'removed from the vault.',
      confirmLabel: 'Delete',
      destructive: true,
    );
    if (!confirmed || !context.mounted) return;
    try {
      await app.vault.deleteGroup(group);
    } catch (caught) {
      if (context.mounted) showFailure(context, caught);
    }
  }
}

class _ConnectionFooter extends StatelessWidget {
  const _ConnectionFooter({required this.app});

  final AppController app;

  @override
  Widget build(BuildContext context) {
    final tokens = KeyLeaseTokens.of(context);
    final (label, color) = switch (app.phase) {
      AppPhase.checking => ('Checking the local service', tokens.warning),
      AppPhase.onboarding => ('Setup needed', tokens.warning),
      AppPhase.provisioning => ('Preparing vault', tokens.warning),
      AppPhase.repairRequired => ('Repair needed', tokens.danger),
      AppPhase.backgroundApprovalRequired => (
        'Background access needed',
        tokens.warning,
      ),
      AppPhase.serviceUnavailable => ('Service unavailable', tokens.danger),
      AppPhase.locked => ('Connected · Vault locked', tokens.warning),
      AppPhase.permissionDenied => ('Connected · Not permitted', tokens.danger),
      AppPhase.ready => ('Connected · Vault unlocked', tokens.success),
    };
    return Padding(
      padding: const EdgeInsets.all(7),
      child: Row(
        children: [
          Container(
            width: 8,
            height: 8,
            decoration: BoxDecoration(color: color, shape: BoxShape.circle),
          ),
          const SizedBox(width: 8),
          Expanded(
            child: Text(
              label,
              maxLines: 2,
              style: context.theme.typography.body.xs.copyWith(color: color),
            ),
          ),
        ],
      ),
    );
  }
}
