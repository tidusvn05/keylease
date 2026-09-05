import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:keylease_desktop/main.dart';

void main() {
  testWidgets('desktop exposes all Phase 1 navigation surfaces',
      (tester) async {
    await tester.pumpWidget(const KeyLeaseApp());
    await tester.pump(const Duration(milliseconds: 100));

    expect(find.text('Vault'), findsOneWidget);
    expect(find.text('Connections'), findsOneWidget);
    expect(find.text('Approvals'), findsOneWidget);
    expect(find.text('Audit'), findsOneWidget);
    expect(find.text('Vault locked'), findsOneWidget);
  });

  test('client token must be a private regular file', () async {
    final directory =
        await Directory.systemTemp.createTemp('keylease-ui-test-');
    addTearDown(() => directory.delete(recursive: true));
    final token = File('${directory.path}/client.token');
    await token.writeAsString('kl_client_fixture');
    await Process.run('chmod', ['0600', token.path]);

    final auth =
        await KeyLeaseRpc('/tmp/unused.sock', 'agent_ui', token.path).auth();
    expect(auth['agent_id'], 'agent_ui');
    expect(auth['token'], 'kl_client_fixture');

    await Process.run('chmod', ['0644', token.path]);
    expect(
      () => KeyLeaseRpc('/tmp/unused.sock', 'agent_ui', token.path).auth(),
      throwsA(isA<KeyLeaseException>()),
    );

    final link = Link('${directory.path}/client-link.token');
    await link.create(token.path);
    expect(
      () => KeyLeaseRpc('/tmp/unused.sock', 'agent_ui', link.path).auth(),
      throwsA(isA<KeyLeaseException>()),
    );
  });
}
