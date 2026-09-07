import 'package:forui/forui.dart';
import 'package:material_ui/material_ui.dart';

import '../../app/app_scope.dart';
import '../../core/models/models.dart';
import '../../core/state/section_controllers.dart';
import '../../ui/components/keylease_dialog.dart';
import '../../ui/components/message_banner.dart';
import '../../ui/components/request_summary.dart';
import '../../ui/components/state_screen.dart';
import '../../ui/tokens/keylease_tokens.dart';
import '../vault/totp_dialog.dart';

/// Pending approvals. A decision is always bound to the exact request digest
/// the user just read, and a stale or expired request is refused before the
/// call is sent.
class ApprovalsPage extends StatelessWidget {
  const ApprovalsPage({super.key});

  @override
  Widget build(BuildContext context) {
    final app = AppScope.of(context);
    final tokens = KeyLeaseTokens.of(context);
    return Observe(
      listenable: app.approvals,
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
            Expanded(
              child: controller.items.isEmpty
                  ? const StateScreen(
                      icon: FLucideIcons.shieldCheck,
                      title: 'Nothing waiting for you',
                      message: 'Requests that need your decision appear here.',
                    )
                  : ListView.builder(
                      padding: EdgeInsets.all(tokens.gutter),
                      itemCount: controller.items.length,
                      itemBuilder: (context, index) => _ApprovalCard(
                        controller: controller,
                        approval: controller.items[index],
                      ),
                    ),
            ),
          ],
        );
      },
    );
  }
}

class _ApprovalCard extends StatelessWidget {
  const _ApprovalCard({required this.controller, required this.approval});

  final ApprovalsController controller;
  final ApprovalSummary approval;

  Future<void> _decide(BuildContext context, {required bool approve}) async {
    final confirmed = await confirm(
      context: context,
      title: approve ? 'Approve this exact request?' : 'Deny this request?',
      message: approve
          ? 'Your approval applies only to the request below. Anything else, '
                'even from the same client, still needs a new decision.'
          : 'Denying stops this request. The client can ask again.',
      confirmLabel: approve ? 'Approve' : 'Deny',
      destructive: !approve,
      extra: SelectionArea(
        child: Text(
          approval.requestDigestHex,
          style: context.theme.typography.body.xs.copyWith(fontFamily: 'Menlo'),
        ),
      ),
    );
    if (!confirmed || !context.mounted) return;
    try {
      await controller.decide(approval, approve: approve);
    } on StaleApprovalException catch (caught) {
      if (context.mounted) {
        await showKeyLeaseDialog<void>(
          context: context,
          title: 'That request moved on',
          bodyBuilder: (context) => Text(caught.message),
          actionsBuilder: (context) => [
            FButton(
              onPress: () => Navigator.of(context).pop(),
              child: const Text('Close'),
            ),
          ],
        );
      }
    } catch (caught) {
      if (context.mounted) showFailure(context, caught);
    }
  }

  @override
  Widget build(BuildContext context) {
    final tokens = KeyLeaseTokens.of(context);
    final decidable = approval.decidableAt(DateTime.now());
    return Container(
      margin: EdgeInsets.only(bottom: tokens.gutterSmall),
      padding: EdgeInsets.all(tokens.gutter),
      decoration: BoxDecoration(
        border: Border.all(color: context.theme.colors.border),
        borderRadius: BorderRadius.circular(10),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          RequestSummary(approval: approval),
          SizedBox(height: tokens.gutter),
          Row(
            mainAxisAlignment: MainAxisAlignment.end,
            children: [
              FButton(
                key: ValueKey('deny-${approval.id}'),
                variant: FButtonVariant.outline,
                onPress: decidable
                    ? () => _decide(context, approve: false)
                    : null,
                child: const Text('Deny'),
              ),
              SizedBox(width: tokens.gutterSmall),
              FButton(
                key: ValueKey('approve-${approval.id}'),
                onPress: decidable
                    ? () => _decide(context, approve: true)
                    : null,
                child: const Text('Approve'),
              ),
            ],
          ),
        ],
      ),
    );
  }
}
