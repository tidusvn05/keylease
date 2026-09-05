import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;

void main() => runApp(const LeaseGateApprovalApp());

class LeaseGateApprovalApp extends StatelessWidget {
  const LeaseGateApprovalApp({super.key});

  @override
  Widget build(BuildContext context) => MaterialApp(
        title: 'LeaseGate Approval',
        debugShowCheckedModeBanner: false,
        theme: ThemeData(
          colorScheme: ColorScheme.fromSeed(
            seedColor: const Color(0xff315c4a),
            brightness: Brightness.light,
          ),
          useMaterial3: true,
        ),
        home: const ApprovalHome(),
      );
}

class ApprovalHome extends StatefulWidget {
  const ApprovalHome({super.key});

  @override
  State<ApprovalHome> createState() => _ApprovalHomeState();
}

class _ApprovalHomeState extends State<ApprovalHome> {
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
  List<Map<String, dynamic>> approvals = const [];
  List<Map<String, dynamic>> edges = const [];
  bool busy = false;
  String? error;

  Map<String, String> get headers => {
        'authorization': 'Bearer ${token.text}',
        'content-type': 'application/json',
      };

  Uri endpoint(String path) {
    final base = cloud.text.trim().replaceFirst(RegExp(r'/+$'), '');
    return Uri.parse('$base$path');
  }

  Future<void> refresh() async {
    if (token.text.length < 32 ||
        !cloud.text.startsWith('https://') ||
        organization.text.isEmpty ||
        project.text.isEmpty ||
        approver.text.isEmpty) {
      setState(() => error = 'Enter HTTPS Cloud URL, organization/project IDs, and operator credential.');
      return;
    }
    setState(() {
      busy = true;
      error = null;
    });
    try {
      final prefix = '/v1/organizations/${Uri.encodeComponent(organization.text)}/projects/${Uri.encodeComponent(project.text)}';
      final results = await Future.wait([
        http.get(endpoint('$prefix/approvals?limit=100'), headers: headers),
        http.get(endpoint('$prefix/edges'), headers: headers),
      ]);
      if (results.any((response) => response.statusCode != 200)) {
        throw const FormatException('Cloud denied the request.');
      }
      final approvalBody = jsonDecode(results[0].body) as Map<String, dynamic>;
      final edgeBody = jsonDecode(results[1].body) as Map<String, dynamic>;
      setState(() {
        approvals = _maps(approvalBody['approvals']);
        edges = _maps(edgeBody['edges']);
      });
    } catch (_) {
      setState(() => error = 'Unable to load approval/Edge state. Check identity and network.');
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  Future<void> decide(Map<String, dynamic> approval, bool approve) async {
    setState(() {
      busy = true;
      error = null;
    });
    try {
      final approvalId = Uri.encodeComponent('${approval['approval_id']}');
      final uri = endpoint(
        '/v1/organizations/${Uri.encodeComponent(organization.text)}/approvals/$approvalId/decision',
      );
      final response = await http.post(
        uri,
        headers: headers,
        body: jsonEncode({
          'schema_version': 1,
          'decision': approve ? 'approved' : 'denied',
          // In the beta proxy profile this value is supplied by the identity
          // proxy. It is configurable here only for direct operator mode.
          'approver_id': approver.text,
          'expected_request_digest_hex': approval['request_digest_hex'],
          'expected_policy_version': approval['policy_version'],
        }),
      );
      if (response.statusCode != 200) {
        throw const FormatException('Decision rejected.');
      }
      await refresh();
    } catch (_) {
      setState(() => error = 'Decision was not accepted; refresh before retrying.');
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  @override
  void dispose() {
    token.dispose();
    cloud.dispose();
    organization.dispose();
    project.dispose();
    approver.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) => Scaffold(
        appBar: AppBar(
          title: const Text('LeaseGate Control'),
          actions: [
            IconButton(onPressed: busy ? null : refresh, icon: const Icon(Icons.refresh)),
          ],
        ),
        body: SafeArea(
          child: Center(
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 920),
              child: ListView(
                padding: const EdgeInsets.all(16),
                children: [
                  _connectionCard(),
                  if (error != null) ...[
                    const SizedBox(height: 12),
                    MaterialBanner(
                      content: Text(error!),
                      actions: [TextButton(onPressed: () => setState(() => error = null), child: const Text('Dismiss'))],
                    ),
                  ],
                  const SizedBox(height: 20),
                  Text('Pending approvals', style: Theme.of(context).textTheme.headlineSmall),
                  const SizedBox(height: 8),
                  if (approvals.isEmpty) const Card(child: ListTile(title: Text('No pending approvals'))),
                  ...approvals.map(_approvalCard),
                  const SizedBox(height: 20),
                  Text('Edge health', style: Theme.of(context).textTheme.headlineSmall),
                  const SizedBox(height: 8),
                  if (edges.isEmpty) const Card(child: ListTile(title: Text('No enrolled Edge'))),
                  ...edges.map(_edgeCard),
                ],
              ),
            ),
          ),
        ),
      );

  Widget _connectionCard() => Card(
        child: Padding(
          padding: const EdgeInsets.all(16),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              const Text('Direct operator mode', style: TextStyle(fontWeight: FontWeight.w700)),
              const SizedBox(height: 4),
              const Text('Credential stays in this tab memory and is never persisted by the app.'),
              const SizedBox(height: 12),
              TextField(controller: cloud, decoration: const InputDecoration(labelText: 'Cloud URL (HTTPS)')),
              TextField(controller: organization, decoration: const InputDecoration(labelText: 'Organization ID')),
              TextField(controller: project, decoration: const InputDecoration(labelText: 'Project ID')),
              TextField(controller: approver, decoration: const InputDecoration(labelText: 'Approver human ID')),
              TextField(
                controller: token,
                obscureText: true,
                enableSuggestions: false,
                autocorrect: false,
                decoration: const InputDecoration(labelText: 'Operator credential'),
              ),
              const SizedBox(height: 12),
              FilledButton.icon(
                onPressed: busy ? null : refresh,
                icon: busy
                    ? const SizedBox.square(dimension: 18, child: CircularProgressIndicator(strokeWidth: 2))
                    : const Icon(Icons.lock_open),
                label: const Text('Connect'),
              ),
            ],
          ),
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
            Text('${summary['operation'] ?? approval['action']}', style: const TextStyle(fontWeight: FontWeight.w700)),
            const SizedBox(height: 6),
            SelectableText('${summary['target'] ?? approval['resource']}'),
            Text('Risk ${approval['risk']} · policy v${approval['policy_version']}'),
            if (fields.isNotEmpty) Text('Changed: $fields'),
            if (summary['blast_radius'] != null) Text('Blast radius: ${summary['blast_radius']}'),
            Text('Expires: ${approval['expires_at']}'),
            const SizedBox(height: 12),
            Wrap(
              spacing: 8,
              children: [
                OutlinedButton(onPressed: busy ? null : () => decide(approval, false), child: const Text('Deny')),
                FilledButton(onPressed: busy ? null : () => decide(approval, true), child: const Text('Approve exact request')),
              ],
            ),
          ],
        ),
      ),
    );
  }

  Widget _edgeCard(Map<String, dynamic> edge) => Card(
        child: ListTile(
          leading: Icon(edge['health'] == 'healthy' ? Icons.cloud_done : Icons.cloud_off),
          title: Text('${edge['name'] ?? edge['id']}'),
          subtitle: Text('${edge['health']} · v${edge['software_version']}\nLast seen: ${edge['last_seen_at'] ?? 'never'}'),
          isThreeLine: true,
        ),
      );
}

List<Map<String, dynamic>> _maps(Object? value) => value is List
    ? value.whereType<Map>().map((item) => Map<String, dynamic>.from(item)).toList()
    : const [];

List<String> _strings(Object? value) => value is List ? value.map((item) => '$item').toList() : const [];
