import 'dart:convert';
import 'dart:math';

import 'package:cryptography/cryptography.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:http/http.dart' as http;
import 'package:local_auth/local_auth.dart';

void main() => runApp(const LeaseGateControlApp());

class LeaseGateControlApp extends StatelessWidget {
  const LeaseGateControlApp({super.key});

  @override
  Widget build(BuildContext context) => MaterialApp(
        title: 'LeaseGate Control',
        debugShowCheckedModeBanner: false,
        theme: ThemeData(
          colorScheme: ColorScheme.fromSeed(
            seedColor: const Color(0xff315c4a),
            brightness: Brightness.light,
          ),
          useMaterial3: true,
        ),
        home: const ControlHome(),
      );
}

class ControlHome extends StatefulWidget {
  const ControlHome({super.key});

  @override
  State<ControlHome> createState() => _ControlHomeState();
}

class _ControlHomeState extends State<ControlHome> {
  static const secureStorage = FlutterSecureStorage();
  final token = TextEditingController();
  final cloud = TextEditingController(
    text: const String.fromEnvironment('KEYLEASE_CLOUD_URL'),
  );
  final organization = TextEditingController(
    text: const String.fromEnvironment('KEYLEASE_ORGANIZATION_ID'),
  );
  final project = TextEditingController(
    text: const String.fromEnvironment('KEYLEASE_PROJECT_ID'),
  );
  final approver = TextEditingController(
    text: const String.fromEnvironment('KEYLEASE_APPROVER_ID'),
  );
  final agent = TextEditingController(
    text: const String.fromEnvironment('KEYLEASE_AGENT_ID'),
  );
  final simulateConnection = TextEditingController();
  final simulateAction = TextEditingController(text: 'github.issue.create');
  final simulateResource = TextEditingController();
  final simulateArguments = TextEditingController(text: '{"title":"Example"}');
  final auditAction = TextEditingController();
  final notionClientId = TextEditingController();
  final oauthRedirect = TextEditingController();
  final oidcIdToken = TextEditingController();
  final setupAccount = TextEditingController(text: 'acct_selfhosted_primary');
  final setupOrganization = TextEditingController(text: 'My organization');
  final setupProject = TextEditingController(text: 'default');
  final setupOwner = TextEditingController(text: 'Owner');

  List<Map<String, dynamic>> approvals = const [];
  List<Map<String, dynamic>> edges = const [];
  List<Map<String, dynamic>> connections = const [];
  List<Map<String, dynamic>> permissions = const [];
  List<Map<String, dynamic>> proposals = const [];
  List<Map<String, dynamic>> auditEvents = const [];
  List<Map<String, dynamic>> credentialLeases = const [];
  List<Map<String, dynamic>> connectionPostures = const [];
  List<Map<String, dynamic>> rotations = const [];
  List<Map<String, dynamic>> securityAlerts = const [];
  Map<String, dynamic>? simulation;
  Map<String, dynamic>? systemStatus;
  int? policyVersion;
  bool busy = false;
  bool connected = false;
  bool deviceBound = false;
  String? error;
  String? notice;

  Map<String, String> get headers => {
        'authorization': 'Bearer ${token.text}',
        'content-type': 'application/json',
      };

  String get projectPrefix =>
      '/v1/organizations/${Uri.encodeComponent(organization.text)}/projects/${Uri.encodeComponent(project.text)}';

  Uri endpoint(String path) {
    final base = cloud.text.trim().replaceFirst(RegExp(r'/+$'), '');
    return Uri.parse('$base$path');
  }

  bool validateConfiguration() {
    if (token.text.length < 32 ||
        !cloud.text.startsWith('https://') ||
        organization.text.isEmpty ||
        project.text.isEmpty ||
        approver.text.isEmpty) {
      setState(() => error =
          'Enter an HTTPS Cloud URL, organization/project IDs, approver ID, and operator credential.');
      return false;
    }
    return true;
  }

  Future<Map<String, dynamic>> getJson(String path) async {
    final response = await http.get(endpoint(path), headers: headers);
    if (response.statusCode != 200) {
      throw FormatException('Cloud returned ${response.statusCode}.');
    }
    return jsonDecode(response.body) as Map<String, dynamic>;
  }

  Future<Map<String, dynamic>> postJson(
    String path,
    Map<String, dynamic> body,
  ) async {
    final response = await http.post(
      endpoint(path),
      headers: headers,
      body: jsonEncode(body),
    );
    if (response.statusCode != 200) {
      throw FormatException('Cloud returned ${response.statusCode}.');
    }
    return jsonDecode(response.body) as Map<String, dynamic>;
  }

  Future<void> refresh() async {
    if (!validateConfiguration()) return;
    setState(() {
      busy = true;
      error = null;
    });
    try {
      if (deviceBound) {
        final results = await Future.wait([
          getJson('/v1/mobile${projectPrefix.substring(3)}/approvals?limit=100'),
          getJson('/v1/mobile${projectPrefix.substring(3)}/security-alerts?limit=100'),
        ]);
        setState(() {
          approvals = _maps(results[0]['approvals']);
          securityAlerts = _maps(results[1]['alerts']);
          connected = true;
        });
        return;
      }
      final requests = <Future<Map<String, dynamic>>>[
        getJson('$projectPrefix/approvals?limit=100'),
        getJson('$projectPrefix/edges'),
        getJson('$projectPrefix/connections'),
        getJson('$projectPrefix/policy/proposals?limit=100'),
        getJson(
          '$projectPrefix/audit?limit=100${auditAction.text.trim().isEmpty ? '' : '&action=${Uri.encodeQueryComponent(auditAction.text.trim())}'}',
        ),
        getJson('$projectPrefix/credential-leases?limit=100'),
        getJson('$projectPrefix/connection-posture'),
        getJson('$projectPrefix/credential-rotations'),
        getJson('/v1/system/status'),
      ];
      if (agent.text.isNotEmpty) {
        requests.add(getJson(
          '$projectPrefix/agents/${Uri.encodeComponent(agent.text)}/permissions',
        ));
      }
      final results = await Future.wait(requests);
      setState(() {
        approvals = _maps(results[0]['approvals']);
        edges = _maps(results[1]['edges']);
        connections = _maps(results[2]['connections']);
        proposals = _maps(results[3]['proposals']);
        auditEvents = _maps(results[4]['events']);
        credentialLeases = _maps(results[5]['leases']);
        connectionPostures = _maps(results[6]['postures']);
        rotations = _maps(results[7]['rotations']);
        systemStatus = results[8];
        if (results.length > 9) {
          permissions = _maps(results[9]['permissions']);
          policyVersion = results[9]['policy_version'] as int?;
        }
        connected = true;
      });
    } catch (_) {
      setState(() => error =
          'Unable to load the control plane. Check identity, tenant IDs, and network.');
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  Future<void> bootstrapSelfHostedOwner() async {
    if (token.text.length < 32 || !cloud.text.startsWith('https://')) {
      setState(() => error =
          'Enter the HTTPS Control Plane URL and bootstrap credential first.');
      return;
    }
    if ([setupAccount, setupOrganization, setupProject, setupOwner]
        .any((controller) => controller.text.trim().isEmpty)) {
      setState(() => error = 'Complete all setup fields.');
      return;
    }
    setState(() {
      busy = true;
      error = null;
      notice = null;
    });
    try {
      final result = await postJson('/v1/bootstrap', {
        'account_id': setupAccount.text.trim(),
        'organization_name': setupOrganization.text.trim(),
        'project_name': setupProject.text.trim(),
        'oidc_issuer': 'urn:leasegate:direct-operator',
        'oidc_subject': 'owner',
        'human_name': setupOwner.text.trim(),
      });
      final createdOrganization =
          Map<String, dynamic>.from(result['organization'] as Map);
      final createdProject = Map<String, dynamic>.from(result['project'] as Map);
      final membership = Map<String, dynamic>.from(result['membership'] as Map);
      setState(() {
        organization.text = '${createdOrganization['id']}';
        project.text = '${createdProject['id']}';
        approver.text = '${membership['human_id']}';
        notice =
            'Owner workspace created. Save these routing IDs in the VPS configuration, then complete local Gateway enrollment with the host CLI.';
      });
    } catch (_) {
      if (mounted) {
        setState(() => error =
            'Bootstrap failed. This deployment may already have an owner workspace.');
      }
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  Future<void> decideApproval(
    Map<String, dynamic> approval,
    bool approve,
  ) async {
    await _operation(() async {
      final approvalId = Uri.encodeComponent('${approval['approval_id']}');
      await postJson(
        '${deviceBound ? '/v1/mobile' : '/v1'}/organizations/${Uri.encodeComponent(organization.text)}/approvals/$approvalId/decision',
        {
          'schema_version': 1,
          'decision': approve ? 'approved' : 'denied',
          'approver_id': approver.text,
          'expected_request_digest_hex': approval['request_digest_hex'],
          'expected_policy_version': approval['policy_version'],
        },
      );
      await refresh();
    }, 'Approval decision was rejected; refresh before retrying.');
  }

  Future<void> simulate() async {
    await _operation(() async {
      final arguments = jsonDecode(simulateArguments.text);
      if (arguments is! Map<String, dynamic>) {
        throw const FormatException('Arguments must be a JSON object.');
      }
      final result = await postJson('$projectPrefix/policy/simulate', {
        'schema_version': 1,
        'request': {
          'schema_version': 1,
          'request_id': 'req_simulation',
          'subject': {
            'agent_id': agent.text,
            'workload_id': null,
            'human_principal': null,
            'on_behalf_of': null,
            'client_session_id': 'policy-simulator',
          },
          'task_id': 'task_policy_simulation',
          'connection_id': simulateConnection.text,
          'resource': simulateResource.text,
          'action': simulateAction.text,
          'arguments': arguments,
          'idempotency_key': 'simulation-no-side-effects',
        },
      });
      setState(() => simulation =
          Map<String, dynamic>.from(result['simulation'] as Map));
    }, 'Simulation failed. Check the typed action, connection, and JSON arguments.');
  }

  Future<void> reviewProposal(
    Map<String, dynamic> proposal,
    bool approve,
  ) async {
    await _operation(() async {
      final id = Uri.encodeComponent('${proposal['proposal_id']}');
      await postJson('$projectPrefix/policy/proposals/$id/review', {
        'schema_version': 1,
        'reviewer_id': approver.text,
        'decision': approve ? 'approve' : 'reject',
        'expected_proposal_digest_sha256':
            proposal['proposal_digest_sha256'],
        'expected_base_policy_version': proposal['base_policy_version'],
        'note': approve ? 'Approved in LeaseGate Control' : 'Rejected in LeaseGate Control',
      });
      await refresh();
    }, 'Proposal review failed because its state or base policy changed.');
  }

  Future<void> activateProposal(Map<String, dynamic> proposal) async {
    await _operation(() async {
      final id = Uri.encodeComponent('${proposal['proposal_id']}');
      await postJson('$projectPrefix/policy/proposals/$id/activate', {
        'schema_version': 1,
        'expected_proposal_digest_sha256':
            proposal['proposal_digest_sha256'],
        'validity_seconds': 86400,
        'offline': {'allow_r0_r1': true, 'max_seconds': 300},
        'minimum_edge_version': '0.1.0',
      });
      await refresh();
    }, 'Proposal activation failed. It may be stale or no longer approved.');
  }

  Future<void> beginNotionOnboarding() async {
    await _operation(() async {
      if (notionClientId.text.isEmpty || !oauthRedirect.text.startsWith('https://')) {
        throw const FormatException('Client ID and HTTPS callback are required.');
      }
      final random = Random.secure();
      final state = base64Url
          .encode(List<int>.generate(32, (_) => random.nextInt(256)))
          .replaceAll('=', '');
      final result = await postJson('$projectPrefix/connections/onboarding', {
        'schema_version': 1,
        'provider': 'notion',
        'connector_version': '1-beta',
        'display_name': 'Notion workspace',
        'client_id': notionClientId.text,
        'redirect_uri': oauthRedirect.text,
        'state': state,
        'code_challenge': null,
        'requested_scopes': <String>[],
      });
      if (!mounted) return;
      await showDialog<void>(
        context: context,
        builder: (context) => AlertDialog(
          title: const Text('Continue in Notion'),
          content: SizedBox(
            width: 640,
            child: SelectableText('${result['authorization_url']}'),
          ),
          actions: [
            FilledButton(
              onPressed: () => Navigator.pop(context),
              child: const Text('Done'),
            ),
          ],
        ),
      );
      await refresh();
    }, 'Unable to begin Notion onboarding.');
  }

  Future<void> revokeCredentialLease(Map<String, dynamic> lease) async {
    await _operation(() async {
      final leaseId = Uri.encodeComponent('${lease['lease_id']}');
      await postJson('$projectPrefix/credential-leases/$leaseId/revoke', {
        'schema_version': 1,
        'reason': 'Operator revoked from LeaseGate Control',
      });
      await refresh();
    }, 'Credential revocation failed or the lease is already terminal.');
  }

  Future<void> createRotation(Map<String, dynamic> connection) async {
    await _operation(() async {
      await postJson('$projectPrefix/credential-rotations', {
        'schema_version': 1,
        'connection_id': connection['connection_id'],
        'requested_by': approver.text,
        'reason': 'Operator requested credential rotation',
        'expected_connection_updated_at': connection['updated_at'],
      });
      await refresh();
    }, 'Rotation could not be created; refresh the connection revision first.');
  }

  Future<void> advanceRotation(Map<String, dynamic> rotation) async {
    final current = '${rotation['state']}';
    final next = switch (current) {
      'pending' => 'rotating',
      'rotating' => 'verifying',
      'verifying' => 'activated',
      'failed' => 'rolled_back',
      _ => null,
    };
    if (next == null) return;
    await _operation(() async {
      final id = Uri.encodeComponent('${rotation['rotation_id']}');
      await postJson('$projectPrefix/credential-rotations/$id/transition', {
        'schema_version': 1,
        'expected_state': current,
        'next_state': next,
        'failure_code': null,
      });
      await refresh();
    }, 'Rotation state changed concurrently or the transition is invalid.');
  }

  Future<void> enrollAndAuthenticateDevice() async {
    if (!validateConfiguration()) return;
    setState(() { busy = true; error = null; });
    try {
      final algorithm = Ed25519();
      var deviceId = await secureStorage.read(key: 'leasegate_device_id');
      var privateKey = await secureStorage.read(key: 'leasegate_device_private');
      var publicKey = await secureStorage.read(key: 'leasegate_device_public');
      if (deviceId == null || privateKey == null || publicKey == null) {
        final pair = await algorithm.newKeyPair();
        final data = await pair.extract();
        final random = Random.secure();
        deviceId = 'device_${List<int>.generate(16, (_) => random.nextInt(256)).map((value) => value.toRadixString(16).padLeft(2, '0')).join()}';
        privateKey = base64UrlEncode(data.bytes).replaceAll('=', '');
        publicKey = base64UrlEncode(data.publicKey.bytes).replaceAll('=', '');
        await postJson('/v1/organizations/${Uri.encodeComponent(organization.text)}/operator-devices', {
          'device_id': deviceId,
          'human_id': approver.text,
          'platform': _platformName(),
          'display_name': 'LeaseGate approval device',
          'verifying_key_base64': publicKey,
          'push_token': null,
        });
        await secureStorage.write(key: 'leasegate_device_id', value: deviceId);
        await secureStorage.write(key: 'leasegate_device_private', value: privateKey);
        await secureStorage.write(key: 'leasegate_device_public', value: publicKey);
      }
      if (!kIsWeb) {
        final authenticated = await LocalAuthentication().authenticate(
          localizedReason: 'Authenticate to access LeaseGate approvals',
        );
        if (!authenticated) throw const FormatException('Biometric authentication failed.');
      }
      final challengeResponse = await postJson(
        '/v1/organizations/${Uri.encodeComponent(organization.text)}/operator-devices/${Uri.encodeComponent(deviceId)}/challenge',
        const {},
      );
      final challenge = Map<String, dynamic>.from(challengeResponse['challenge'] as Map);
      final payload = base64Url.decode(base64Url.normalize('${challengeResponse['signing_payload_base64']}'));
      final keyPair = SimpleKeyPairData(
        base64Url.decode(base64Url.normalize(privateKey)),
        publicKey: SimplePublicKey(
          base64Url.decode(base64Url.normalize(publicKey)),
          type: KeyPairType.ed25519,
        ),
        type: KeyPairType.ed25519,
      );
      final signature = await algorithm.sign(payload, keyPair: keyPair);
      final verified = await postJson(
        '/v1/organizations/${Uri.encodeComponent(organization.text)}/operator-devices/challenges/${Uri.encodeComponent('${challenge['challenge_id']}')}/verify',
        {
          'signature_base64': base64UrlEncode(signature.bytes).replaceAll('=', ''),
          'id_token': oidcIdToken.text.trim().isEmpty ? null : oidcIdToken.text.trim(),
        },
      );
      token.text = '${verified['access_token']}';
      setState(() { deviceBound = true; connected = false; });
      await refresh();
    } catch (_) {
      if (mounted) setState(() => error = 'Device enrollment or biometric authentication failed.');
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  String _platformName() {
    if (kIsWeb) return 'web';
    return switch (defaultTargetPlatform) {
      TargetPlatform.iOS => 'ios',
      TargetPlatform.android => 'android',
      _ => 'web',
    };
  }

  Future<void> acknowledgeAlert(Map<String, dynamic> alert) async {
    await _operation(() async {
      final alertId = Uri.encodeComponent('${alert['alert_id']}');
      await postJson('/v1/mobile${projectPrefix.substring(3)}/security-alerts/$alertId/acknowledge', const {});
      await refresh();
    }, 'The alert could not be acknowledged with this device role.');
  }

  Future<void> _operation(
    Future<void> Function() operation,
    String failure,
  ) async {
    if (!validateConfiguration()) return;
    setState(() {
      busy = true;
      error = null;
    });
    try {
      await operation();
    } catch (_) {
      if (mounted) setState(() => error = failure);
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  @override
  void dispose() {
    for (final controller in [
      token,
      cloud,
      organization,
      project,
      approver,
      agent,
      simulateConnection,
      simulateAction,
      simulateResource,
      simulateArguments,
      auditAction,
      notionClientId,
      oauthRedirect,
      oidcIdToken,
      setupAccount,
      setupOrganization,
      setupProject,
      setupOwner,
    ]) {
      controller.dispose();
    }
    super.dispose();
  }

  @override
  Widget build(BuildContext context) => DefaultTabController(
        length: 7,
        child: Scaffold(
          appBar: AppBar(
            title: const Text('LeaseGate Control'),
            actions: [
              IconButton(
                tooltip: 'Refresh',
                onPressed: busy ? null : refresh,
                icon: const Icon(Icons.refresh),
              ),
            ],
            bottom: const TabBar(
              isScrollable: true,
              tabs: [
                Tab(icon: Icon(Icons.shield_outlined), text: 'Access'),
                Tab(icon: Icon(Icons.science_outlined), text: 'Simulator'),
                Tab(icon: Icon(Icons.rule_folder_outlined), text: 'Proposals'),
                Tab(icon: Icon(Icons.cable_outlined), text: 'Connections'),
                Tab(icon: Icon(Icons.key_outlined), text: 'Credentials'),
                Tab(icon: Icon(Icons.fact_check_outlined), text: 'Audit'),
                Tab(icon: Icon(Icons.monitor_heart_outlined), text: 'Operations'),
              ],
            ),
          ),
          body: SafeArea(
            child: Column(
              children: [
                if (error != null)
                  MaterialBanner(
                    content: Text(error!),
                    actions: [
                      TextButton(
                        onPressed: () => setState(() => error = null),
                        child: const Text('Dismiss'),
                      ),
                    ],
                  ),
                if (notice != null)
                  MaterialBanner(
                    content: SelectableText(notice!),
                    actions: [
                      TextButton(
                        onPressed: () => setState(() => notice = null),
                        child: const Text('Dismiss'),
                      ),
                    ],
                  ),
                if (busy) const LinearProgressIndicator(),
                Expanded(
                  child: !connected
                      ? SingleChildScrollView(child: _configurationCard())
                      : TabBarView(
                          children: [
                            _accessView(),
                            _simulatorView(),
                            _proposalView(),
                            _connectionsView(),
                            _credentialsView(),
                            _auditView(),
                            _operationsView(),
                          ],
                        ),
                ),
              ],
            ),
          ),
        ),
      );

  Widget _page(List<Widget> children) => Center(
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 1100),
          child: ListView(
            padding: const EdgeInsets.all(16),
            children: children,
          ),
        ),
      );

  Widget _configurationCard() => Padding(
        padding: const EdgeInsets.fromLTRB(16, 16, 16, 0),
        child: Card(
          child: ExpansionTile(
            initiallyExpanded: true,
            title: const Text('Direct operator mode'),
            subtitle: const Text(
              'Credential stays in tab memory and is never persisted.',
            ),
            childrenPadding: const EdgeInsets.all(16),
            children: [
              if (organization.text.isEmpty || project.text.isEmpty) ...[
                _heading(
                  'First-run setup',
                  'Creates the first owner workspace. Credentials remain in tab memory.',
                ),
                Wrap(
                  spacing: 12,
                  runSpacing: 12,
                  children: [
                    _field(setupAccount, 'Account ID'),
                    _field(setupOrganization, 'Organization name'),
                    _field(setupProject, 'Project name'),
                    _field(setupOwner, 'Owner name'),
                  ],
                ),
                const SizedBox(height: 12),
                Align(
                  alignment: Alignment.centerRight,
                  child: FilledButton.tonalIcon(
                    onPressed: busy ? null : bootstrapSelfHostedOwner,
                    icon: const Icon(Icons.rocket_launch_outlined),
                    label: const Text('Create owner workspace'),
                  ),
                ),
                const Divider(height: 32),
              ],
              Wrap(
                spacing: 12,
                runSpacing: 12,
                children: [
                  _field(cloud, 'Cloud URL (HTTPS)'),
                  _field(organization, 'Organization ID'),
                  _field(project, 'Project ID'),
                  _field(approver, 'Approver human ID'),
                  _field(agent, 'Agent ID for permission view'),
                  SizedBox(
                    width: 320,
                    child: TextField(
                      controller: oidcIdToken,
                      obscureText: true,
                      enableSuggestions: false,
                      autocorrect: false,
                      decoration: const InputDecoration(
                        labelText: 'OIDC ID token (when SSO is enabled)',
                      ),
                    ),
                  ),
                  SizedBox(
                    width: 320,
                    child: TextField(
                      controller: token,
                      obscureText: true,
                      enableSuggestions: false,
                      autocorrect: false,
                      decoration:
                          const InputDecoration(labelText: 'Operator credential'),
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 12),
              Align(
                alignment: Alignment.centerRight,
                child: FilledButton.icon(
                  onPressed: busy ? null : refresh,
                  icon: const Icon(Icons.lock_open),
                  label: const Text('Connect'),
                ),
              ),
              const SizedBox(height: 8),
              Align(
                alignment: Alignment.centerRight,
                child: FilledButton.tonalIcon(
                  onPressed: busy ? null : enrollAndAuthenticateDevice,
                  icon: const Icon(Icons.fingerprint),
                  label: const Text('Enroll and use device-bound session'),
                ),
              ),
            ],
          ),
        ),
      );

  Widget _field(TextEditingController controller, String label,
          {double width = 320}) =>
      SizedBox(
        width: width,
        child: TextField(
          controller: controller,
          decoration: InputDecoration(labelText: label),
        ),
      );

  Widget _accessView() => _page([
        _heading('Effective permissions',
            'Policy v${policyVersion ?? 'none'} · ${permissions.length} entries'),
        if (agent.text.isEmpty)
          const Card(
            child: ListTile(
              title: Text('Enter an agent ID in connection settings'),
            ),
          )
        else if (permissions.isEmpty)
          const Card(child: ListTile(title: Text('Default deny: no effective permissions')))
        else
          SingleChildScrollView(
            scrollDirection: Axis.horizontal,
            child: DataTable(
              columns: const [
                DataColumn(label: Text('Effect')),
                DataColumn(label: Text('Connection')),
                DataColumn(label: Text('Resource')),
                DataColumn(label: Text('Action')),
                DataColumn(label: Text('Rule')),
                DataColumn(label: Text('Limits')),
              ],
              rows: permissions.map((permission) {
                final budget = permission['budget'] is Map
                    ? Map<String, dynamic>.from(permission['budget'] as Map)
                    : <String, dynamic>{};
                return DataRow(cells: [
                  DataCell(_effectChip('${permission['effect']}')),
                  DataCell(Text('${permission['connection_id'] ?? 'any'}')),
                  DataCell(Text('${permission['resource_prefix']}')),
                  DataCell(Text('${permission['action']}')),
                  DataCell(Text('${permission['rule_id']}')),
                  DataCell(Text(
                    'uses ${permission['max_uses']} · requests ${budget['max_task_requests'] ?? '∞'}',
                  )),
                ]);
              }).toList(),
            ),
          ),
      ]);

  Widget _simulatorView() => _page([
        _heading('Policy simulator', 'No lease, budget reservation, or provider call is created.'),
        Card(
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: Column(
              children: [
                Wrap(
                  spacing: 12,
                  runSpacing: 12,
                  children: [
                    _field(simulateConnection, 'Connection ID'),
                    _field(simulateAction, 'Typed action'),
                    _field(simulateResource, 'Canonical resource'),
                  ],
                ),
                const SizedBox(height: 12),
                TextField(
                  controller: simulateArguments,
                  minLines: 3,
                  maxLines: 8,
                  decoration: const InputDecoration(
                    labelText: 'Arguments JSON',
                    border: OutlineInputBorder(),
                  ),
                ),
                const SizedBox(height: 12),
                Align(
                  alignment: Alignment.centerRight,
                  child: FilledButton.icon(
                    onPressed: busy ? null : simulate,
                    icon: const Icon(Icons.play_arrow),
                    label: const Text('Simulate'),
                  ),
                ),
              ],
            ),
          ),
        ),
        if (simulation != null) _simulationResult(simulation!),
      ]);

  Widget _simulationResult(Map<String, dynamic> value) {
    final decision = value['decision'] is Map
        ? Map<String, dynamic>.from(value['decision'] as Map)
        : <String, dynamic>{};
    final trace = _maps(value['trace']);
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text('Decision: ${decision['decision']}',
                style: Theme.of(context).textTheme.titleLarge),
            Text('Matched rule: ${decision['matched_rule'] ?? 'none'}'),
            Text('Warnings: ${_strings(value['warnings']).join(', ')}'),
            const Divider(),
            ...trace.map((entry) => ListTile(
                  dense: true,
                  leading: Icon(entry['outcome'] == 'matched'
                      ? Icons.check_circle_outline
                      : Icons.remove_circle_outline),
                  title: Text('${entry['rule_id']} · ${entry['effect']}'),
                  subtitle: Text(_strings(entry['reasons']).join(', ')),
                )),
          ],
        ),
      ),
    );
  }

  Widget _proposalView() => _page([
        _heading('Policy proposals', 'Agents draft; humans review and activate.'),
        if (proposals.isEmpty)
          const Card(child: ListTile(title: Text('No policy proposals'))),
        ...proposals.map((proposal) => Card(
              child: Padding(
                padding: const EdgeInsets.all(16),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text('${proposal['title']}',
                        style: Theme.of(context).textTheme.titleMedium),
                    Text('${proposal['reason']}'),
                    Text(
                      '${proposal['status']} · base v${proposal['base_policy_version']} · ${_list(proposal['rules']).length} rules',
                    ),
                    SelectableText('Digest ${proposal['proposal_digest_sha256']}'),
                    const SizedBox(height: 8),
                    Wrap(spacing: 8, children: [
                      if (proposal['status'] == 'pending') ...[
                        OutlinedButton(
                          onPressed: busy
                              ? null
                              : () => reviewProposal(proposal, false),
                          child: const Text('Reject'),
                        ),
                        FilledButton(
                          onPressed: busy
                              ? null
                              : () => reviewProposal(proposal, true),
                          child: const Text('Approve draft'),
                        ),
                      ],
                      if (proposal['status'] == 'approved')
                        FilledButton.icon(
                          onPressed:
                              busy ? null : () => activateProposal(proposal),
                          icon: const Icon(Icons.verified_user_outlined),
                          label: const Text('Activate signed policy'),
                        ),
                    ]),
                  ],
                ),
              ),
            )),
      ]);

  Widget _connectionsView() => _page([
        _heading('Connections', 'OAuth credentials stay encrypted at Edge.'),
        Card(
          child: ExpansionTile(
            title: const Text('Add Notion public connection'),
            subtitle: const Text('One-click authorization metadata; token exchange occurs at Edge.'),
            childrenPadding: const EdgeInsets.all(16),
            children: [
              Wrap(spacing: 12, runSpacing: 12, children: [
                _field(notionClientId, 'Notion OAuth client ID'),
                _field(oauthRedirect, 'HTTPS callback URL'),
              ]),
              const SizedBox(height: 12),
              Align(
                alignment: Alignment.centerRight,
                child: FilledButton(
                  onPressed: busy ? null : beginNotionOnboarding,
                  child: const Text('Add to Notion'),
                ),
              ),
            ],
          ),
        ),
        if (connections.isEmpty)
          const Card(child: ListTile(title: Text('No registered connections'))),
        ...connections.map((connection) => Card(
              child: ListTile(
                leading: Icon(connection['health'] == 'connected'
                    ? Icons.link
                    : Icons.link_off),
                title: Text('${connection['display_name']}'),
                subtitle: Text(
                  '${connection['provider']} ${connection['connector_version']} · ${connection['health']}\n'
                  '${_strings(connection['authorized_resources']).length} resources · '
                  '${_strings(connection['granted_permissions']).length} permissions',
                ),
                isThreeLine: true,
                trailing: connection['reauthorization_required'] == true
                    ? const Chip(label: Text('Action required'))
                    : OutlinedButton(
                        onPressed: busy ? null : () => createRotation(connection),
                        child: const Text('Rotate'),
                      ),
              ),
            )),
      ]);

  Widget _credentialsView() => _page([
        _heading(
          'Dynamic credentials',
          'self_hosted · local_gateway — credential material never enters the Control Plane.',
        ),
        Text('Active and recent leases',
            style: Theme.of(context).textTheme.titleMedium),
        const SizedBox(height: 8),
        if (credentialLeases.isEmpty)
          const Card(child: ListTile(title: Text('No credential lease metadata'))),
        ...credentialLeases.map((lease) {
          final active = lease['state'] == 'active';
          final sender = lease['sender_constraint'] is Map
              ? Map<String, dynamic>.from(lease['sender_constraint'] as Map)
              : <String, dynamic>{};
          return Card(
            child: ListTile(
              leading: Icon(active ? Icons.key : Icons.key_off_outlined),
              title: Text('${lease['kind']} · ${lease['target']}'),
              subtitle: Text(
                '${lease['state']} · ${lease['agent_id']}\n'
                'Expires ${lease['expires_at']} · binding ${sender['kind'] ?? 'none'}',
              ),
              isThreeLine: true,
              trailing: active
                  ? FilledButton.tonal(
                      onPressed: busy ? null : () => revokeCredentialLease(lease),
                      child: const Text('Revoke'),
                    )
                  : null,
            ),
          );
        }),
        const SizedBox(height: 20),
        Text('Connection posture',
            style: Theme.of(context).textTheme.titleMedium),
        const SizedBox(height: 8),
        if (connectionPostures.isEmpty)
          const Card(child: ListTile(title: Text('No posture report from Gateway'))),
        ...connectionPostures.map((posture) => Card(
              child: ListTile(
                leading: Icon(posture['status'] == 'healthy'
                    ? Icons.verified_user_outlined
                    : Icons.warning_amber_outlined),
                title: Text('${posture['connection_id']} · ${posture['status']}'),
                subtitle: Text(
                  'Checked ${posture['checked_at']}\n${_strings(posture['reason_codes']).join(', ')}',
                ),
                isThreeLine: true,
              ),
            )),
        const SizedBox(height: 20),
        Text('Rotation workflow',
            style: Theme.of(context).textTheme.titleMedium),
        const SizedBox(height: 8),
        if (rotations.isEmpty)
          const Card(child: ListTile(title: Text('No credential rotations'))),
        ...rotations.map((rotation) {
          final state = '${rotation['state']}';
          final actionable =
              ['pending', 'rotating', 'verifying', 'failed'].contains(state);
          return Card(
            child: ListTile(
              leading: const Icon(Icons.autorenew),
              title: Text('${rotation['connection_id']} · $state'),
              subtitle:
                  Text('${rotation['reason']}\nUpdated ${rotation['updated_at']}'),
              isThreeLine: true,
              trailing: actionable
                  ? FilledButton.tonal(
                      onPressed: busy ? null : () => advanceRotation(rotation),
                      child: const Text('Advance'),
                    )
                  : null,
            ),
          );
        }),
      ]);

  Widget _auditView() => _page([
        _heading('Audit explorer', 'Bounded, tenant-scoped, redacted events only.'),
        Row(children: [
          Expanded(child: _field(auditAction, 'Filter exact action', width: double.infinity)),
          const SizedBox(width: 8),
          FilledButton(
            onPressed: busy ? null : refresh,
            child: const Text('Apply'),
          ),
        ]),
        const SizedBox(height: 12),
        if (auditEvents.isEmpty)
          const Card(child: ListTile(title: Text('No matching audit events'))),
        ...auditEvents.map((event) => Card(
              child: ListTile(
                leading: Icon(event['outcome'] == 'success'
                    ? Icons.check_circle_outline
                    : Icons.error_outline),
                title: Text('${event['action']} · ${event['decision']}'),
                subtitle: Text(
                  '${event['resource']}\n${event['agent_id']} · ${event['timestamp']}',
                ),
                isThreeLine: true,
                trailing: Text('${event['outcome']}'),
              ),
            )),
      ]);

  Widget _operationsView() => _page([
        _heading('Single-VPS host', _hostStatusSummary()),
        _hostStatusCard(),
        const SizedBox(height: 20),
        _heading('Pending approvals', '${approvals.length} waiting'),
        if (approvals.isEmpty)
          const Card(child: ListTile(title: Text('No pending approvals'))),
        ...approvals.map(_approvalCard),
        const SizedBox(height: 20),
        _heading('Edge health', '${edges.length} enrolled'),
        if (edges.isEmpty)
          const Card(child: ListTile(title: Text('No enrolled Edge'))),
        ...edges.map(_edgeCard),
        const SizedBox(height: 20),
        _heading('Security alerts', '${securityAlerts.where((alert) => alert['acknowledged_at'] == null).length} open'),
        if (securityAlerts.isEmpty)
          const Card(child: ListTile(title: Text('No security alerts'))),
        ...securityAlerts.map((alert) => Card(
              child: ListTile(
                leading: Icon(alert['severity'] == 'critical' ? Icons.gpp_bad : Icons.warning_amber),
                title: Text('${alert['code']}'),
                subtitle: Text('${alert['aggregate_id']} · ${alert['created_at']}'),
                trailing: alert['acknowledged_at'] == null
                    ? FilledButton.tonal(
                        onPressed: busy ? null : () => acknowledgeAlert(alert),
                        child: const Text('Acknowledge'),
                      )
                    : const Chip(label: Text('Acknowledged')),
              ),
            )),
      ]);

  String _hostStatusSummary() {
    final status = systemStatus;
    if (status == null || status['available'] != true) {
      return 'Host snapshot is not available yet';
    }
    return status['healthy'] == true ? 'Healthy' : 'Operator attention required';
  }

  Widget _hostStatusCard() {
    final status = systemStatus;
    if (status == null || status['available'] != true) {
      return const Card(
        child: ListTile(
          leading: Icon(Icons.hourglass_empty),
          title: Text('Waiting for the host monitor'),
          subtitle: Text('Run leasegate monitor on the VPS to publish a redacted snapshot.'),
        ),
      );
    }
    final services = status['services'] is Map
        ? Map<String, dynamic>.from(status['services'] as Map)
        : <String, dynamic>{};
    final backup = status['backup'] is Map
        ? Map<String, dynamic>.from(status['backup'] as Map)
        : <String, dynamic>{};
    final disk = status['disk'] is Map
        ? Map<String, dynamic>.from(status['disk'] as Map)
        : <String, dynamic>{};
    final tls = status['tls'] is Map
        ? Map<String, dynamic>.from(status['tls'] as Map)
        : <String, dynamic>{};
    final issues = _strings(status['issues']);
    return Card(
      child: ListTile(
        leading: Icon(
          status['healthy'] == true ? Icons.check_circle_outline : Icons.warning_amber,
        ),
        title: Text('Release ${status['release_id'] ?? 'unknown'} · ${services['running'] ?? 0}/${services['expected'] ?? 6} services'),
        subtitle: Text(
          'Disk ${disk['used_percent'] ?? '?'}% · backup age ${backup['age_seconds'] ?? -1}s · TLS ${tls['expiry_seconds'] ?? -1}s\n'
          '${issues.isEmpty ? 'No reported issue' : 'Issues: ${issues.join(', ')}'} · ${status['generated_at'] ?? 'unknown time'}',
        ),
        isThreeLine: true,
      ),
    );
  }

  Widget _heading(String title, String subtitle) => Padding(
        padding: const EdgeInsets.only(bottom: 8),
        child: ListTile(
          contentPadding: EdgeInsets.zero,
          title: Text(title, style: Theme.of(context).textTheme.headlineSmall),
          subtitle: Text(subtitle),
        ),
      );

  Widget _effectChip(String effect) => Chip(
        label: Text(effect),
        avatar: Icon(
          effect == 'allow'
              ? Icons.check
              : effect == 'require_approval'
                  ? Icons.approval_outlined
                  : Icons.block,
          size: 16,
        ),
      );

  Widget _approvalCard(Map<String, dynamic> approval) {
    final summary = approval['summary'] is Map
        ? Map<String, dynamic>.from(approval['summary'] as Map)
        : <String, dynamic>{};
    final fields = _strings(summary['changed_fields']).join(', ');
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text('${summary['operation'] ?? approval['action']}',
                style: const TextStyle(fontWeight: FontWeight.w700)),
            SelectableText('${summary['target'] ?? approval['resource']}'),
            Text('Risk ${approval['risk']} · policy v${approval['policy_version']}'),
            if (fields.isNotEmpty) Text('Changed: $fields'),
            if (summary['blast_radius'] != null)
              Text('Blast radius: ${summary['blast_radius']}'),
            Text('Expires: ${approval['expires_at']}'),
            const SizedBox(height: 12),
            Wrap(spacing: 8, children: [
              OutlinedButton(
                onPressed: busy ? null : () => decideApproval(approval, false),
                child: const Text('Deny'),
              ),
              FilledButton(
                onPressed: busy ? null : () => decideApproval(approval, true),
                child: const Text('Approve exact request'),
              ),
            ]),
          ],
        ),
      ),
    );
  }

  Widget _edgeCard(Map<String, dynamic> edge) => Card(
        child: ListTile(
          leading: Icon(edge['health'] == 'healthy'
              ? Icons.cloud_done
              : Icons.cloud_off),
          title: Text('${edge['name'] ?? edge['id']}'),
          subtitle: Text(
            '${edge['health']} · v${edge['software_version']}\nLast seen: ${edge['last_seen_at'] ?? 'never'}',
          ),
          isThreeLine: true,
        ),
      );
}

List<Object?> _list(Object? value) => value is List ? value : const [];

List<Map<String, dynamic>> _maps(Object? value) => value is List
    ? value
        .whereType<Map>()
        .map((item) => Map<String, dynamic>.from(item))
        .toList()
    : const [];

List<String> _strings(Object? value) =>
    value is List ? value.map((item) => '$item').toList() : const [];
