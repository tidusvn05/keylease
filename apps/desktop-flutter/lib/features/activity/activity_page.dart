import 'package:forui/forui.dart';
import 'package:material_ui/material_ui.dart';

import '../../app/app_scope.dart';
import '../../core/models/models.dart';
import '../../ui/components/message_banner.dart';
import '../../ui/components/state_screen.dart';
import '../../ui/tokens/keylease_tokens.dart';

String friendlyTime(DateTime? when) {
  if (when == null) return 'Unknown time';
  final delta = DateTime.now().difference(when);
  if (delta.inSeconds < 60) return 'Just now';
  if (delta.inMinutes < 60) return '${delta.inMinutes} min ago';
  if (delta.inHours < 24) return '${delta.inHours} hr ago';
  if (delta.inDays < 7) return '${delta.inDays} days ago';
  return '${when.year}-${when.month.toString().padLeft(2, '0')}-'
      '${when.day.toString().padLeft(2, '0')}';
}

/// Activity: what was accessed, by which client, and what the policy decided.
class ActivityPage extends StatelessWidget {
  const ActivityPage({super.key});

  @override
  Widget build(BuildContext context) {
    final app = AppScope.of(context);
    final tokens = KeyLeaseTokens.of(context);
    return Observe(
      listenable: app.activity,
      builder: (context, controller) {
        if (controller.loading && !controller.loaded) {
          return const Center(child: FCircularProgress());
        }
        final events = controller.filtered;
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
              child: Row(
                children: [
                  FButton(
                    key: const ValueKey('activity-all'),
                    variant: controller.deniedOnly
                        ? FButtonVariant.outline
                        : FButtonVariant.secondary,
                    onPress: () => controller.setDeniedOnly(value: false),
                    child: const Text('All events'),
                  ),
                  SizedBox(width: tokens.gutterSmall),
                  FButton(
                    key: const ValueKey('activity-denied'),
                    variant: controller.deniedOnly
                        ? FButtonVariant.secondary
                        : FButtonVariant.outline,
                    onPress: () => controller.setDeniedOnly(value: true),
                    child: const Text('Denied or failed'),
                  ),
                ],
              ),
            ),
            Expanded(
              child: events.isEmpty
                  ? StateScreen(
                      icon: FLucideIcons.clock,
                      title: controller.deniedOnly
                          ? 'Nothing was refused'
                          : 'No activity yet',
                      message: controller.deniedOnly
                          ? 'No request was denied or failed in this window.'
                          : 'Actions taken through KeyLease show up here.',
                    )
                  : ListView.builder(
                      padding: EdgeInsets.fromLTRB(
                        tokens.gutter,
                        0,
                        tokens.gutter,
                        tokens.gutter,
                      ),
                      itemCount: events.length,
                      itemBuilder: (context, index) =>
                          _EventRow(event: events[index]),
                    ),
            ),
          ],
        );
      },
    );
  }
}

class _EventRow extends StatelessWidget {
  const _EventRow({required this.event});

  final ActivityEvent event;

  @override
  Widget build(BuildContext context) {
    final tokens = KeyLeaseTokens.of(context);
    final theme = context.theme;
    return Padding(
      padding: EdgeInsets.only(bottom: tokens.gutterSmall),
      child: FItem(
        prefix: Icon(
          event.denied ? FLucideIcons.shieldAlert : FLucideIcons.circleCheck,
          color: event.denied ? tokens.warning : tokens.success,
          size: 18,
        ),
        title: Text(event.action),
        subtitle: Text(
          '${event.resource}\n${event.agentId} · ${friendlyTime(event.timestamp)}'
          '${event.volume.isEmpty ? '' : ' · ${event.volume}'}',
        ),
        details: Text(
          event.denied ? 'Denied' : 'Allowed',
          style: theme.typography.body.xs.copyWith(
            color: event.denied ? tokens.warning : theme.colors.mutedForeground,
          ),
        ),
      ),
    );
  }
}
