import 'package:forui/forui.dart';
import 'package:material_ui/material_ui.dart';

import '../../core/models/models.dart';
import '../tokens/keylease_tokens.dart';
import 'section_label.dart';

String _relative(DateTime when, {DateTime? now}) {
  final delta = when.difference(now ?? DateTime.now());
  final seconds = delta.inSeconds;
  final past = seconds < 0;
  final magnitude = seconds.abs();
  final text = switch (magnitude) {
    < 60 => '$magnitude sec',
    < 3600 => '${magnitude ~/ 60} min',
    < 86400 => '${magnitude ~/ 3600} hr',
    _ => '${magnitude ~/ 86400} days',
  };
  return past ? '$text ago' : 'in $text';
}

/// Presents an approval request in the user's language.
///
/// Every field shown exists on `ApprovalRecord`. The prototype's free-text
/// "reason" does not, so the risk tier and the semantic summary's blast radius
/// carry that job instead of an invented field.
class RequestSummary extends StatelessWidget {
  const RequestSummary({
    required this.approval,
    this.now,
    this.dense = false,
    super.key,
  });

  final ApprovalSummary approval;
  final DateTime? now;
  final bool dense;

  @override
  Widget build(BuildContext context) {
    final tokens = KeyLeaseTokens.of(context);
    final theme = context.theme;
    final reference = now ?? DateTime.now();
    final expired = !approval.expiresAt.isAfter(reference);
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          children: [
            Expanded(
              child: Text(
                approval.operation ?? approval.action ?? 'Access request',
                style: theme.typography.body.md.copyWith(
                  fontWeight: FontWeight.w600,
                ),
              ),
            ),
            if (approval.risk != null)
              Padding(
                padding: const EdgeInsets.only(left: 8),
                child: FBadge(
                  variant: approval.risk == 'high'
                      ? FBadgeVariant.destructive
                      : FBadgeVariant.secondary,
                  child: Text('${approval.risk} risk'),
                ),
              ),
            if (!approval.isPending || expired)
              Padding(
                padding: const EdgeInsets.only(left: 8),
                child: FBadge(
                  variant: FBadgeVariant.outline,
                  child: Text(expired ? 'Expired' : approval.state),
                ),
              ),
          ],
        ),
        const SizedBox(height: 6),
        _Line(
          label: 'What it wants to do',
          value: approval.action ?? 'unknown action',
        ),
        _Line(
          label: 'Where',
          value: approval.target ?? approval.resource ?? 'unknown resource',
        ),
        _Line(
          label: 'Requested by',
          value: approval.agentId ?? 'unknown client',
        ),
        if (approval.changedFields.isNotEmpty)
          _Line(
            label: 'Fields it would change',
            value: approval.changedFields.join(', '),
          ),
        if (approval.blastRadius != null)
          _Line(label: 'Scope', value: approval.blastRadius!),
        _Line(
          label: expired ? 'Expired' : 'Expires',
          value:
              '${_relative(approval.expiresAt, now: reference)} '
              '· policy v${approval.policyVersion}',
        ),
        if (!dense) ...[
          SizedBox(height: tokens.gutterSmall),
          const SectionLabel('Exact request'),
          SelectionArea(
            child: Text(
              approval.requestDigestHex,
              style: theme.typography.body.xs.copyWith(
                fontFamily: 'Menlo',
                color: theme.colors.mutedForeground,
              ),
            ),
          ),
        ],
      ],
    );
  }
}

class _Line extends StatelessWidget {
  const _Line({required this.label, required this.value});

  final String label;
  final String value;

  @override
  Widget build(BuildContext context) {
    final theme = context.theme;
    return Padding(
      padding: const EdgeInsets.only(top: 4),
      child: RichText(
        text: TextSpan(
          style: theme.typography.body.sm.copyWith(
            color: theme.colors.foreground,
          ),
          children: [
            TextSpan(
              text: '$label: ',
              style: TextStyle(color: theme.colors.mutedForeground),
            ),
            TextSpan(text: value),
          ],
        ),
      ),
    );
  }
}
