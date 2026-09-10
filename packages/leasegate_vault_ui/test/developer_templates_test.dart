import 'package:flutter_test/flutter_test.dart';
import 'package:leasegate_vault_ui/features/vault/developer_templates.dart';

void main() {
  group('.env parser and renderer', () {
    test('parses common dotenv forms and reports normalized layout', () {
      final result = parseDotEnv('''
# service settings
export PORT=8080
TOKEN="line one\\nline two"
HASH=value#literal
EMPTY=
''');

      expect(result.issues, isEmpty);
      expect(result.ignoredComments, 1);
      expect(result.normalizedExports, 1);
      expect(result.variables.map((variable) => variable.key), [
        'PORT',
        'TOKEN',
        'HASH',
        'EMPTY',
      ]);
      expect(result.variables[1].value, 'line one\nline two');
      expect(result.variables[2].value, 'value#literal');
      expect(result.variables[3].value, '');
    });

    test('rejects duplicate and invalid variable names with line numbers', () {
      final result = parseDotEnv('GOOD=1\nBAD-NAME=2\nGOOD=3');
      expect(result.issues.map((issue) => issue.line), [2, 3]);
    });

    test('canonical output preserves order and round-trips values', () {
      final rendered = renderDotEnv(const [
        MapEntry('FIRST', 'plain'),
        MapEntry('SECOND', 'has spaces'),
        MapEntry('THIRD', "quote' and\nline"),
      ]);
      final reparsed = parseDotEnv(rendered);
      expect(reparsed.issues, isEmpty);
      expect(reparsed.variables.map((variable) => variable.key), [
        'FIRST',
        'SECOND',
        'THIRD',
      ]);
      expect(reparsed.variables.map((variable) => variable.value), [
        'plain',
        'has spaces',
        "quote' and\nline",
      ]);
      expect(rendered.endsWith('\n'), isTrue);
    });
  });

  group('SSH config renderer', () {
    const endpoints = [
      SshEndpointConfig(
        sectionId: 'jump-a',
        name: 'Jump A',
        alias: 'jump-a',
        host: 'jump.example.com',
        port: 22,
        username: 'deploy',
        authMode: 'ssh_agent',
      ),
      SshEndpointConfig(
        sectionId: 'jump-b',
        name: 'Jump B',
        alias: 'jump-b',
        host: '10.0.0.2',
        port: 22,
        username: 'deploy',
        authMode: 'ssh_agent',
        connectVia: 'jump-a',
      ),
      SshEndpointConfig(
        sectionId: 'target',
        name: 'Target',
        alias: 'target',
        host: '10.0.1.5',
        port: 2222,
        username: 'root',
        authMode: 'private_key',
        connectVia: 'jump-b',
      ),
    ];

    test('renders multi-hop ProxyJump and all forwarding types', () {
      final config = renderSshConfig(
        endpoints: endpoints,
        privateKeyPaths: const {'target': '/Users/me/.ssh/id_ed25519'},
        forwards: const [
          SshForwardConfig(
            endpointId: 'target',
            type: 'local',
            bindAddress: '127.0.0.1',
            bindPort: 5432,
            destinationHost: 'db.internal',
            destinationPort: 5432,
          ),
          SshForwardConfig(
            endpointId: 'target',
            type: 'dynamic',
            bindAddress: '127.0.0.1',
            bindPort: 1080,
            destinationHost: '',
            destinationPort: 0,
          ),
        ],
      );

      expect(config, contains('ProxyJump jump-a,jump-b'));
      expect(config, contains('IdentityFile /Users/me/.ssh/id_ed25519'));
      expect(config, contains('LocalForward 127.0.0.1:5432 db.internal:5432'));
      expect(config, contains('DynamicForward 127.0.0.1:1080'));
      expect(config, isNot(contains('password')));
    });

    test('requires a per-device key binding for private-key auth', () {
      expect(
        () => renderSshConfig(
          endpoints: endpoints,
          forwards: const [],
          privateKeyPaths: const {},
        ),
        throwsFormatException,
      );
    });

    test('automatically binds the only discovered private key', () async {
      final selected = <String, String>{};
      final paths = await resolveSshPrivateKeyPaths(
        endpoints: endpoints,
        currentPaths: const {},
        discover: () async => ['/Users/me/.ssh/id_ed25519'],
        select: (_) async => throw StateError('picker should not open'),
        onSelected: (endpoint, path) async {
          selected[endpoint.sectionId] = path;
        },
      );

      expect(paths, const {'target': '/Users/me/.ssh/id_ed25519'});
      expect(selected, paths);
    });

    test(
      'asks for a key when discovery is ambiguous and handles cancel',
      () async {
        var pickerCalls = 0;
        final paths = await resolveSshPrivateKeyPaths(
          endpoints: endpoints,
          currentPaths: const {},
          discover: () async => [
            '/Users/me/.ssh/id_ed25519',
            '/Users/me/.ssh/work',
          ],
          select: (_) async {
            pickerCalls++;
            return null;
          },
          onSelected: (_, _) async {},
        );

        expect(paths, isNull);
        expect(pickerCalls, 1);
      },
    );
  });
}
