import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:keylease_desktop/main.dart';

/// The client-token contract is a security boundary, not a UI concern: the
/// checks here are unchanged from the original single-file client.
void main() {
  test('client token must be a private regular file', () async {
    final directory = await Directory.systemTemp.createTemp(
      'keylease-ui-test-',
    );
    addTearDown(() => directory.delete(recursive: true));
    final token = File('${directory.path}/client.token');
    await token.writeAsString('kl_client_fixture');
    await Process.run('chmod', ['0600', token.path]);

    final auth = await KeyLeaseRpc(
      '/tmp/unused.sock',
      'agent_ui',
      token.path,
    ).auth();
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

  test(
    'an unreachable socket is a transport failure, not a daemon error',
    () async {
      final directory = await Directory.systemTemp.createTemp(
        'keylease-ui-test-',
      );
      addTearDown(() => directory.delete(recursive: true));
      final token = File('${directory.path}/client.token');
      await token.writeAsString('kl_client_fixture');
      await Process.run('chmod', ['0600', token.path]);

      final rpc = KeyLeaseRpc(
        '${directory.path}/absent.sock',
        'agent_ui',
        token.path,
      );

      await expectLater(
        rpc.call({'command': 'status'}),
        throwsA(
          isA<KeyLeaseException>().having(
            (error) => error.code,
            'code',
            KeyLeaseErrorCode.transport,
          ),
        ),
      );
    },
  );

  test('a daemon error keeps its typed code and payload', () {
    final error = KeyLeaseException.fromDaemon(const {
      'error': 'denied',
      'reason': 'client lacks vault:read',
    });

    expect(error.code, KeyLeaseErrorCode.denied);
    expect(error.details?['reason'], 'client lacks vault:read');
    expect(error.diagnostics, contains('vault:read'));
  });
}
