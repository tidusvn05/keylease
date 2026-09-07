import 'package:flutter_test/flutter_test.dart';
import 'package:keylease_desktop/core/models/models.dart';
import 'package:keylease_desktop/core/state/section_controllers.dart';

import 'support/fakes.dart';

void main() {
  group('approval decisions', () {
    test(
      'a pending, unexpired request is decided against its exact digest',
      () async {
        final harness = buildController(
          script: (client) => client
            ..value('approvals_list', [Fixtures.approval()])
            ..value('approval_decide', {'state': 'approved'}),
        );
        addTearDown(harness.app.dispose);
        await harness.app.start();
        harness.app.approvals.items = [
          ApprovalSummary.fromJson(Fixtures.approval()),
        ];

        await harness.app.approvals.decide(
          harness.app.approvals.items.single,
          approve: true,
        );

        final decision = harness.client.calls.lastWhere(
          (call) => call['command'] == 'approval_decide',
        );
        expect(decision['id'], 'approval-1');
        expect(decision['approve'], true);
      },
    );

    test(
      'a request whose digest changed is refused before it is sent',
      () async {
        final stale = ApprovalSummary.fromJson(Fixtures.approval());
        final harness = buildController(
          script: (client) => client
            ..value('approvals_list', [Fixtures.approval(digest: 'deadbeef')])
            ..value('approval_decide', {'state': 'approved'}),
        );
        addTearDown(harness.app.dispose);
        await harness.app.start();

        await expectLater(
          harness.app.approvals.decide(stale, approve: true),
          throwsA(isA<StaleApprovalException>()),
        );
        expect(
          harness.client.calls.any((c) => c['command'] == 'approval_decide'),
          isFalse,
        );
      },
    );

    test('a request that was already decided elsewhere is refused', () async {
      final stale = ApprovalSummary.fromJson(Fixtures.approval());
      final harness = buildController(
        script: (client) => client
          ..value('approvals_list', <Map<String, dynamic>>[])
          ..value('approval_decide', {'state': 'approved'}),
      );
      addTearDown(harness.app.dispose);
      await harness.app.start();

      await expectLater(
        harness.app.approvals.decide(stale, approve: false),
        throwsA(isA<StaleApprovalException>()),
      );
    });

    test('an expired request is refused', () async {
      final expired = Fixtures.approval(
        expiresIn: const Duration(seconds: -30),
      );
      final harness = buildController(
        script: (client) => client
          ..value('approvals_list', [expired])
          ..value('approval_decide', {'state': 'approved'}),
      );
      addTearDown(harness.app.dispose);
      await harness.app.start();

      await expectLater(
        harness.app.approvals.decide(
          ApprovalSummary.fromJson(expired),
          approve: true,
        ),
        throwsA(isA<StaleApprovalException>()),
      );
      expect(
        harness.client.calls.any((c) => c['command'] == 'approval_decide'),
        isFalse,
      );
    });

    test('the summary only uses fields the contract carries', () {
      final approval = ApprovalSummary.fromJson(Fixtures.approval());

      expect(approval.operation, 'Read a spreadsheet');
      expect(approval.blastRadius, 'One file');
      expect(approval.risk, 'medium');
      expect(approval.policyVersion, 7);
      expect(approval.requestDigestHex, 'a1b2c3d4e5f6');
    });
  });

  group('activity', () {
    test('the denied filter keeps only refused or failed events', () async {
      final harness = buildController(
        script: (client) => client.value('audit_query', [
          Fixtures.auditEvent,
          {...Fixtures.auditEvent, 'decision': 'deny', 'outcome': 'denied'},
        ]),
      );
      addTearDown(harness.app.dispose);
      await harness.app.start();
      await harness.app.activity.load();

      expect(harness.app.activity.filtered, hasLength(2));
      harness.app.activity.setDeniedOnly(value: true);
      expect(harness.app.activity.filtered, hasLength(1));
      expect(harness.app.activity.filtered.single.denied, isTrue);
    });
  });
}
