import 'package:forui/forui.dart';
import 'package:material_ui/material_ui.dart';

import '../../app/app_scope.dart';
import '../../core/models/models.dart';
import '../../core/state/section_controllers.dart';
import '../../ui/components/connection_health.dart';
import '../../ui/components/keylease_dialog.dart';
import '../../ui/components/message_banner.dart';
import '../../ui/components/scroll_area.dart';
import '../../ui/components/secret_field.dart';
import '../../ui/components/section_label.dart';
import '../../ui/components/state_screen.dart';
import '../../ui/tokens/keylease_tokens.dart';
import '../vault/totp_dialog.dart';
import 'google_oauth_flow.dart';

/// Connections: who the vault can act for, whether it still works, and how to
/// fix it when it does not.
class ConnectionsPage extends StatelessWidget {
  const ConnectionsPage({super.key});

  @override
  Widget build(BuildContext context) {
    final app = AppScope.of(context);
    final tokens = KeyLeaseTokens.of(context);
    return Observe(
      listenable: app.connections,
      builder: (context, controller) {
        if (controller.loading && !controller.loaded) {
          return const Center(child: FCircularProgress());
        }
        return Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            if (controller.error != null)
              MessageBanner(
                message: controller.error!,
                onAction: controller.load,
              ),
            Padding(
              padding: EdgeInsets.all(tokens.gutter),
              child: Wrap(
                spacing: tokens.gutterSmall,
                runSpacing: tokens.gutterSmall,
                alignment: WrapAlignment.end,
                children: [
                  FButton(
                    variant: FButtonVariant.outline,
                    onPress: () => _addTokenConnection(context, controller),
                    prefix: const Icon(FLucideIcons.link, size: 16),
                    child: const Text('Add token connection'),
                  ),
                  FButton(
                    onPress: () => connectGoogle(context, app),
                    prefix: const Icon(FLucideIcons.hardDrive, size: 16),
                    child: const Text('Connect Google'),
                  ),
                ],
              ),
            ),
            Expanded(
              child: controller.items.isEmpty
                  ? const StateScreen(
                      icon: FLucideIcons.link,
                      title: 'No connections yet',
                      message:
                          'Connect an account so KeyLease can act on the '
                          'exact resources you allow.',
                    )
                  : KeyLeaseScrollArea.builder(
                      padding: EdgeInsets.fromLTRB(
                        tokens.gutter,
                        0,
                        tokens.gutter,
                        tokens.gutter,
                      ),
                      itemCount: controller.items.length,
                      itemBuilder: (context, index) => _ConnectionCard(
                        controller: controller,
                        connection: controller.items[index],
                      ),
                    ),
            ),
          ],
        );
      },
    );
  }
}

class _ConnectionCard extends StatelessWidget {
  const _ConnectionCard({required this.controller, required this.connection});

  final ConnectionsController controller;
  final ConnectionSummary connection;

  Future<void> _run(BuildContext context, String operation) async {
    if (operation == 'revoke') {
      final confirmed = await confirm(
        context: context,
        title: 'Revoke this connection?',
        message:
            'KeyLease asks the provider to revoke the credential. '
            'This cannot be undone.',
        confirmLabel: 'Revoke',
        destructive: true,
      );
      if (!confirmed || !context.mounted) return;
    }
    try {
      await controller.manage(connection, operation);
    } catch (caught) {
      if (context.mounted) showFailure(context, caught);
    }
  }

  @override
  Widget build(BuildContext context) {
    final tokens = KeyLeaseTokens.of(context);
    final theme = context.theme;
    final remedy = ConnectionHealthBadge.remedy(connection);
    return Container(
      margin: EdgeInsets.only(bottom: tokens.gutterSmall),
      padding: EdgeInsets.all(tokens.gutter),
      decoration: BoxDecoration(
        border: Border.all(color: theme.colors.border),
        borderRadius: BorderRadius.circular(10),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      connection.provider,
                      style: theme.typography.body.md.copyWith(
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                    const SizedBox(height: 4),
                    ConnectionHealthBadge(connection: connection),
                  ],
                ),
              ),
              Wrap(
                spacing: 6,
                children: [
                  IconAction(
                    label: 'Test ${connection.provider}',
                    icon: FLucideIcons.activity,
                    onPress: () => _run(context, 'test'),
                  ),
                  IconAction(
                    label: 'Refresh ${connection.provider}',
                    icon: FLucideIcons.refreshCw,
                    onPress: () => _run(context, 'refresh'),
                  ),
                  IconAction(
                    label: 'Disconnect ${connection.provider}',
                    icon: FLucideIcons.unlink,
                    onPress: () => _run(context, 'disconnect'),
                  ),
                  IconAction(
                    label: 'Revoke ${connection.provider}',
                    icon: FLucideIcons.shieldOff,
                    onPress: () => _run(context, 'revoke'),
                  ),
                ],
              ),
            ],
          ),
          if (remedy != null) ...[
            SizedBox(height: tokens.gutterSmall),
            Text(
              connection.healthReason == null
                  ? remedy
                  : '$remedy (${connection.healthReason})',
              style: theme.typography.body.sm.copyWith(
                color: tokens.statusColor(connection.health),
              ),
            ),
          ],
          SizedBox(height: tokens.gutterSmall),
          Text(
            '${connection.trustMode} · ${connection.executionLocation} · '
            '${connection.authMethod}',
            style: theme.typography.body.xs.copyWith(
              color: theme.colors.mutedForeground,
            ),
          ),
          if (connection.lastCheckedAt != null)
            Text(
              'Last checked ${connection.lastCheckedAt}',
              style: theme.typography.body.xs.copyWith(
                color: theme.colors.mutedForeground,
              ),
            ),
          SizedBox(height: tokens.gutter),
          const SectionLabel('Resources this connection may touch'),
          if (connection.authorizedResources.isEmpty)
            Text(
              'No resources enrolled yet.',
              style: theme.typography.body.sm.copyWith(
                color: theme.colors.mutedForeground,
              ),
            )
          else
            Wrap(
              spacing: 6,
              runSpacing: 6,
              children: [
                for (final resource in connection.authorizedResources)
                  _ResourceChip(
                    resource: resource,
                    onRemove: () async {
                      try {
                        await controller.setResource(
                          connection,
                          resource,
                          enrolled: false,
                        );
                      } catch (caught) {
                        if (context.mounted) showFailure(context, caught);
                      }
                    },
                  ),
              ],
            ),
          SizedBox(height: tokens.gutterSmall),
          Align(
            alignment: Alignment.centerLeft,
            child: FButton(
              variant: FButtonVariant.outline,
              onPress: () => _enroll(context),
              prefix: const Icon(FLucideIcons.plus, size: 16),
              child: const Text('Enroll a resource'),
            ),
          ),
        ],
      ),
    );
  }

  Future<void> _enroll(BuildContext context) async {
    final resource = TextEditingController();
    final value = await showKeyLeaseDialog<String>(
      context: context,
      title: 'Enroll an exact resource',
      description: 'KeyLease only touches resources you list here.',
      bodyBuilder: (context) => FTextField(
        key: const ValueKey('enroll-resource'),
        label: const Text('Canonical resource ID'),
        autofocus: true,
        control: FTextFieldControl.managed(controller: resource),
      ),
      actionsBuilder: (context) => [
        FButton(
          variant: FButtonVariant.outline,
          onPress: () => Navigator.of(context).pop(),
          child: const Text('Cancel'),
        ),
        FButton(
          onPress: () => Navigator.of(context).pop(resource.text.trim()),
          child: const Text('Enroll'),
        ),
      ],
    );
    resource.dispose();
    if (value == null || value.isEmpty || !context.mounted) return;
    try {
      await controller.setResource(connection, value, enrolled: true);
    } catch (caught) {
      if (context.mounted) showFailure(context, caught);
    }
  }
}

class _ResourceChip extends StatelessWidget {
  const _ResourceChip({required this.resource, required this.onRemove});

  final String resource;
  final VoidCallback onRemove;

  @override
  Widget build(BuildContext context) => Container(
    padding: const EdgeInsets.fromLTRB(10, 5, 4, 5),
    decoration: BoxDecoration(
      color: context.theme.colors.muted,
      borderRadius: BorderRadius.circular(6),
    ),
    child: Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        Text(resource, style: context.theme.typography.body.xs),
        const SizedBox(width: 4),
        FButton.icon(
          variant: FButtonVariant.ghost,
          semanticsLabel: 'Remove $resource',
          onPress: onRemove,
          child: const Icon(FLucideIcons.x, size: 13),
        ),
      ],
    ),
  );
}

Future<void> _addTokenConnection(
  BuildContext context,
  ConnectionsController controller,
) async {
  var provider = 'github';
  final credential = TextEditingController();
  final resources = TextEditingController();
  final submitted = await showKeyLeaseDialog<bool>(
    context: context,
    title: 'Add a token connection',
    barrierDismissible: false,
    bodyBuilder: (context) => StatefulBuilder(
      builder: (context, setState) => Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          FSelect<String>(
            label: const Text('Provider'),
            items: const {
              'GitHub': 'github',
              'Linear': 'linear',
              'Notion': 'notion',
              'Fake (testing)': 'fake',
            },
            control: FSelectControl.lifted(
              value: provider,
              onChange: (value) => setState(() => provider = value ?? provider),
            ),
          ),
          const SizedBox(height: 10),
          FTextField(
            label: const Text('Token or OAuth credential JSON'),
            obscureText: true,
            control: FTextFieldControl.managed(controller: credential),
          ),
          const SizedBox(height: 10),
          FTextField.multiline(
            label: const Text('Exact canonical resources (one per line)'),
            minLines: 2,
            maxLines: 5,
            control: FTextFieldControl.managed(controller: resources),
          ),
        ],
      ),
    ),
    actionsBuilder: (context) => [
      FButton(
        variant: FButtonVariant.outline,
        onPress: () => Navigator.of(context).pop(false),
        child: const Text('Cancel'),
      ),
      FButton(
        onPress: () => Navigator.of(context).pop(true),
        child: const Text('Add'),
      ),
    ],
    presentation: KeyLeasePresentation.fullScreen,
  );
  final secret = credential.text;
  final list = resources.text
      .split('\n')
      .map((value) => value.trim())
      .where((value) => value.isNotEmpty)
      .toList(growable: false);
  credential
    ..clear()
    ..dispose();
  resources.dispose();
  if (submitted != true || secret.isEmpty || !context.mounted) return;
  try {
    await controller.add(
      provider: provider,
      credential: secret,
      authorizedResources: list,
    );
  } catch (caught) {
    if (context.mounted) showFailure(context, caught);
  }
}
