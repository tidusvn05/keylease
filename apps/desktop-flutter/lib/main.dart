import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

void main() => runApp(const KeyLeaseApp());

class KeyLeaseApp extends StatelessWidget {
  const KeyLeaseApp({super.key});

  @override
  Widget build(BuildContext context) => MaterialApp(
        title: 'KeyLease',
        debugShowCheckedModeBanner: false,
        theme: ThemeData(
          colorSchemeSeed: const Color(0xff5965d8),
          brightness: Brightness.light,
          useMaterial3: true,
        ),
        darkTheme: ThemeData(
          colorSchemeSeed: const Color(0xff8e9aff),
          brightness: Brightness.dark,
          useMaterial3: true,
        ),
        home: const VaultScreen(),
      );
}

class VaultScreen extends StatefulWidget {
  const VaultScreen({super.key});

  @override
  State<VaultScreen> createState() => _VaultScreenState();
}

class _VaultScreenState extends State<VaultScreen> {
  static const securityChannel = MethodChannel('com.keylease/security');
  final search = TextEditingController();
  final socket = TextEditingController(
    text: '/tmp/keylease-${Platform.environment['USER'] ?? 'user'}.sock',
  );
  final agent = TextEditingController(text: 'agent_desktop');
  final tokenFile = TextEditingController();

  List<Map<String, dynamic>> entries = const [];
  List<Map<String, dynamic>> groups = const [];
  List<Map<String, dynamic>> connections = const [];
  List<Map<String, dynamic>> approvals = const [];
  List<Map<String, dynamic>> audits = const [];
  Map<String, dynamic>? status;
  String? error;
  bool busy = false;
  int selectedIndex = 0;
  String? selectedGroupId;

  KeyLeaseRpc get rpc => KeyLeaseRpc(socket.text, agent.text, tokenFile.text);
  bool get unlocked => status?['locked'] == false;

  @override
  void initState() {
    super.initState();
    securityChannel.setMethodCallHandler((call) async {
      if (call.method == 'lockRequested' && unlocked && !busy) {
        await lockVault();
      }
    });
    unawaited(refresh());
  }

  @override
  void dispose() {
    securityChannel.setMethodCallHandler(null);
    search.dispose();
    socket.dispose();
    agent.dispose();
    tokenFile.dispose();
    super.dispose();
  }

  List<Map<String, dynamic>> _maps(dynamic value) => (value as List<dynamic>)
      .map((item) => Map<String, dynamic>.from(item as Map))
      .toList(growable: false);

  Future<void> refresh() => run(() async {
        status = Map<String, dynamic>.from(
          await rpc.call({'command': 'status'}) as Map,
        );
        if (!unlocked || tokenFile.text.isEmpty) {
          entries = const [];
          groups = const [];
          connections = const [];
          approvals = const [];
          audits = const [];
          return;
        }
        final auth = await rpc.auth();
        switch (selectedIndex) {
          case 0:
            groups = _maps(await rpc.call({
              'command': 'groups_list',
              'auth': auth,
            }));
            entries = _maps(await rpc.call({
              'command': 'entries_search',
              'auth': auth,
              'query': search.text,
            }));
          case 1:
            connections = _maps(await rpc.call({
              'command': 'connections_list',
              'auth': auth,
            }));
          case 2:
            approvals = _maps(await rpc.call({
              'command': 'approvals_list',
              'auth': auth,
              'limit': 100,
            }));
          case 3:
            audits = _maps(await rpc.call({
              'command': 'audit_query',
              'auth': auth,
              'limit': 200,
            }));
        }
      });

  Future<void> run(Future<void> Function() operation) async {
    if (mounted) {
      setState(() {
        busy = true;
        error = null;
      });
    }
    try {
      await operation();
    } catch (caught) {
      error = '$caught';
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  @override
  Widget build(BuildContext context) => Scaffold(
        appBar: AppBar(
          title: const Text('KeyLease'),
          actions: [
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 8),
              child: Chip(
                avatar: Icon(
                  unlocked ? Icons.lock_open : Icons.lock,
                  size: 18,
                ),
                label: Text(unlocked ? 'Unlocked' : 'Locked'),
              ),
            ),
            IconButton(
              onPressed: busy ? null : (unlocked ? lockVault : unlockVault),
              icon: Icon(unlocked ? Icons.lock_outline : Icons.lock_open),
              tooltip: unlocked ? 'Lock vault' : 'Unlock vault',
            ),
            IconButton(
              onPressed: busy ? null : refresh,
              icon: const Icon(Icons.refresh),
              tooltip: 'Refresh',
            ),
            IconButton(
              onPressed: () => showDialog<void>(
                context: context,
                builder: (_) => settings(),
              ),
              icon: const Icon(Icons.settings_outlined),
              tooltip: 'Local service settings',
            ),
          ],
        ),
        floatingActionButton:
            selectedIndex == 0 && unlocked && groups.isNotEmpty
                ? FloatingActionButton.extended(
                    onPressed: busy ? null : createEntry,
                    icon: const Icon(Icons.add),
                    label: const Text('New entry'),
                  )
                : null,
        body: Row(
          children: [
            NavigationRail(
              labelType: NavigationRailLabelType.all,
              destinations: const [
                NavigationRailDestination(
                  icon: Icon(Icons.vpn_key_outlined),
                  selectedIcon: Icon(Icons.vpn_key),
                  label: Text('Vault'),
                ),
                NavigationRailDestination(
                  icon: Icon(Icons.link_outlined),
                  selectedIcon: Icon(Icons.link),
                  label: Text('Connections'),
                ),
                NavigationRailDestination(
                  icon: Icon(Icons.approval_outlined),
                  selectedIcon: Icon(Icons.approval),
                  label: Text('Approvals'),
                ),
                NavigationRailDestination(
                  icon: Icon(Icons.receipt_long_outlined),
                  selectedIcon: Icon(Icons.receipt_long),
                  label: Text('Audit'),
                ),
              ],
              selectedIndex: selectedIndex,
              onDestinationSelected: (index) {
                setState(() => selectedIndex = index);
                unawaited(refresh());
              },
            ),
            const VerticalDivider(width: 1),
            Expanded(
              child: Column(
                children: [
                  if (busy) const LinearProgressIndicator(),
                  if (!unlocked) const _LockedNotice(),
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
                  Expanded(child: _content()),
                ],
              ),
            ),
          ],
        ),
      );

  Widget _content() {
    if (!unlocked) {
      return const Center(
          child: Text('Start an interactive KeyLease session.'));
    }
    if (tokenFile.text.isEmpty) {
      return const Center(
        child: Text(
            'Select a mode-0600 registered client-token file in Settings.'),
      );
    }
    return switch (selectedIndex) {
      0 => vaultView(),
      1 => connectionsView(),
      2 => approvalsView(),
      _ => auditView(),
    };
  }

  Widget vaultView() => Column(
        children: [
          Padding(
            padding: const EdgeInsets.all(16),
            child: SearchBar(
              controller: search,
              hintText: 'Search title, username or URL',
              leading: const Icon(Icons.search),
              onSubmitted: (_) => refresh(),
            ),
          ),
          Expanded(
            child: Row(
              children: [
                SizedBox(
                  width: 210,
                  child: Column(
                    children: [
                      ListTile(
                        selected: selectedGroupId == null,
                        leading: const Icon(Icons.folder_copy_outlined),
                        title: const Text('All entries'),
                        onTap: () => setState(() => selectedGroupId = null),
                      ),
                      Expanded(
                        child: ListView(
                          children: groups
                              .map(
                                (group) => ListTile(
                                  dense: true,
                                  selected: selectedGroupId == group['id'],
                                  leading: const Icon(Icons.folder_outlined),
                                  title: Text(
                                      group['name']?.toString() ?? 'Group'),
                                  trailing: PopupMenuButton<String>(
                                    onSelected: (choice) => choice == 'rename'
                                        ? renameGroup(group)
                                        : deleteGroup(group),
                                    itemBuilder: (_) => const [
                                      PopupMenuItem(
                                        value: 'rename',
                                        child: Text('Rename'),
                                      ),
                                      PopupMenuItem(
                                        value: 'delete',
                                        child: Text('Delete'),
                                      ),
                                    ],
                                  ),
                                  onTap: () => setState(
                                    () => selectedGroupId =
                                        group['id']?.toString(),
                                  ),
                                ),
                              )
                              .toList(),
                        ),
                      ),
                      Padding(
                        padding: const EdgeInsets.all(8),
                        child: OutlinedButton.icon(
                          onPressed: busy ? null : createGroup,
                          icon: const Icon(Icons.create_new_folder_outlined),
                          label: const Text('New group'),
                        ),
                      ),
                    ],
                  ),
                ),
                const VerticalDivider(width: 1),
                Expanded(child: entryList()),
              ],
            ),
          ),
        ],
      );

  Widget entryList() {
    final visible = selectedGroupId == null
        ? entries
        : entries
            .where((entry) => entry['group_id'] == selectedGroupId)
            .toList(growable: false);
    return visible.isEmpty
        ? const Center(child: Text('No matching entries'))
        : ListView.separated(
            itemCount: visible.length,
            separatorBuilder: (_, __) => const Divider(height: 1),
            itemBuilder: (_, index) {
              final item = visible[index];
              final urls = (item['urls'] as List<dynamic>? ?? const [])
                  .map((value) => value.toString());
              return ListTile(
                leading: const CircleAvatar(child: Icon(Icons.key)),
                title: Text(item['title']?.toString() ?? 'Untitled'),
                subtitle: Text(
                  [item['username'], ...urls]
                      .whereType<String>()
                      .where((value) => value.isNotEmpty)
                      .join(' · '),
                ),
                trailing: PopupMenuButton<String>(
                  onSelected: (choice) => entryAction(item, choice),
                  itemBuilder: (_) => const [
                    PopupMenuItem(
                        value: 'copy_username', child: Text('Copy username')),
                    PopupMenuItem(
                        value: 'reveal_password',
                        child: Text('Reveal password')),
                    PopupMenuItem(
                        value: 'copy_password', child: Text('Copy password')),
                    PopupMenuItem(value: 'totp', child: Text('Show TOTP')),
                    PopupMenuItem(
                        value: 'history', child: Text('View history')),
                    PopupMenuItem(value: 'edit', child: Text('Edit')),
                    PopupMenuItem(value: 'delete', child: Text('Delete')),
                  ],
                ),
                onTap: () => showEntry(item),
              );
            },
          );
  }

  Widget connectionsView() => Column(
        children: [
          Padding(
            padding: const EdgeInsets.all(12),
            child: Row(
              mainAxisAlignment: MainAxisAlignment.end,
              children: [
                FilledButton.icon(
                  onPressed: busy ? null : connectGoogle,
                  icon: const Icon(Icons.add_to_drive),
                  label: const Text('Connect Google'),
                ),
                const SizedBox(width: 8),
                OutlinedButton.icon(
                  onPressed: busy ? null : addConnection,
                  icon: const Icon(Icons.add_link),
                  label: const Text('Add token connection'),
                ),
              ],
            ),
          ),
          Expanded(
            child: _ListOrEmpty(
              empty: 'No connections',
              children: connections.map((connection) {
                final resources =
                    (connection['authorized_resources'] as List<dynamic>? ??
                        const []);
                return Card(
                  margin:
                      const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
                  child: Padding(
                    padding: const EdgeInsets.all(16),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Row(
                          children: [
                            const Icon(Icons.link),
                            const SizedBox(width: 12),
                            Expanded(
                              child: Text(
                                connection['provider']?.toString() ??
                                    'Unknown provider',
                                style: Theme.of(context).textTheme.titleMedium,
                              ),
                            ),
                            Chip(
                                label: Text(connection['health']?.toString() ??
                                    'unknown')),
                            PopupMenuButton<String>(
                              onSelected: (choice) =>
                                  manageConnection(connection, choice),
                              itemBuilder: (_) => const [
                                PopupMenuItem(
                                    value: 'test', child: Text('Test')),
                                PopupMenuItem(
                                    value: 'refresh', child: Text('Refresh')),
                                PopupMenuItem(
                                    value: 'enroll',
                                    child: Text('Enroll resource')),
                                PopupMenuItem(
                                    value: 'disconnect',
                                    child: Text('Disconnect')),
                                PopupMenuItem(
                                    value: 'revoke', child: Text('Revoke')),
                              ],
                            ),
                          ],
                        ),
                        const SizedBox(height: 8),
                        Text(
                          '${connection['trust_mode']} · ${connection['execution_location']} · ${connection['auth_method']}',
                        ),
                        const SizedBox(height: 8),
                        Wrap(
                          spacing: 6,
                          runSpacing: 6,
                          children: resources
                              .map((resource) => InputChip(
                                    label: Text(resource.toString()),
                                    onDeleted: busy
                                        ? null
                                        : () => connectionResource(
                                              connection,
                                              resource.toString(),
                                              false,
                                            ),
                                  ))
                              .toList(),
                        ),
                      ],
                    ),
                  ),
                );
              }).toList(),
            ),
          ),
        ],
      );

  Future<void> addConnection() async {
    var provider = 'github';
    final credential = TextEditingController();
    final resources = TextEditingController();
    final input = await showDialog<Map<String, dynamic>>(
      context: context,
      builder: (context) => StatefulBuilder(
        builder: (context, setDialogState) => AlertDialog(
          title: const Text('Add connection'),
          content: SizedBox(
            width: 560,
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                DropdownButtonFormField<String>(
                  initialValue: provider,
                  decoration: const InputDecoration(labelText: 'Provider'),
                  items: const [
                    DropdownMenuItem(value: 'github', child: Text('GitHub')),
                    DropdownMenuItem(value: 'linear', child: Text('Linear')),
                    DropdownMenuItem(value: 'notion', child: Text('Notion')),
                    DropdownMenuItem(value: 'fake', child: Text('Fake')),
                  ],
                  onChanged: (value) =>
                      setDialogState(() => provider = value ?? provider),
                ),
                TextField(
                  controller: credential,
                  obscureText: true,
                  onChanged: (_) => setDialogState(() {}),
                  decoration: const InputDecoration(
                    labelText: 'Token or OAuth credential JSON',
                  ),
                ),
                TextField(
                  controller: resources,
                  minLines: 2,
                  maxLines: 5,
                  decoration: const InputDecoration(
                    labelText: 'Exact canonical resources (one per line)',
                  ),
                ),
              ],
            ),
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(context),
              child: const Text('Cancel'),
            ),
            FilledButton(
              onPressed: credential.text.isEmpty
                  ? null
                  : () => Navigator.pop(context, {
                        'provider': provider,
                        'credential': credential.text,
                        'authorized_resources': resources.text
                            .split('\n')
                            .map((value) => value.trim())
                            .where((value) => value.isNotEmpty)
                            .toList(),
                      }),
              child: const Text('Add'),
            ),
          ],
        ),
      ),
    );
    credential.clear();
    credential.dispose();
    resources.dispose();
    if (input == null) return;
    await run(() async {
      final auth = await rpc.auth();
      await rpc.call({
        'command': 'connection_add',
        'auth': auth,
        ...input,
      });
      connections = _maps(await rpc.call({
        'command': 'connections_list',
        'auth': auth,
      }));
    });
  }

  Future<void> connectGoogle() async {
    final clientId = TextEditingController();
    final clientSecret = TextEditingController();
    final configuration = await showDialog<Map<String, String>>(
      context: context,
      builder: (context) => StatefulBuilder(
        builder: (context, setDialogState) => AlertDialog(
          title: const Text('Google Workspace OAuth'),
          content: SizedBox(
            width: 560,
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                const Text(
                  'Use a Desktop OAuth client. Google will request only drive.file and open its Picker so you choose the exact files and folders.',
                ),
                TextField(
                  controller: clientId,
                  autofocus: true,
                  onChanged: (_) => setDialogState(() {}),
                  decoration:
                      const InputDecoration(labelText: 'OAuth client ID'),
                ),
                TextField(
                  controller: clientSecret,
                  obscureText: true,
                  decoration: const InputDecoration(
                    labelText: 'Client secret (optional for desktop clients)',
                  ),
                ),
              ],
            ),
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(context),
              child: const Text('Cancel'),
            ),
            FilledButton(
              onPressed: clientId.text.trim().isEmpty
                  ? null
                  : () => Navigator.pop(context, {
                        'client_id': clientId.text.trim(),
                        'client_secret': clientSecret.text,
                      }),
              child: const Text('Open Google'),
            ),
          ],
        ),
      ),
    );
    clientSecret.clear();
    clientId.dispose();
    clientSecret.dispose();
    if (configuration == null) return;
    Map<String, dynamic>? start;
    await run(() async {
      final auth = await rpc.auth();
      start = Map<String, dynamic>.from(
        await rpc.call({
          'command': 'connection_google_oauth_begin',
          'auth': auth,
          'client_id': configuration['client_id'],
          'client_secret': configuration['client_secret']!.isEmpty
              ? null
              : configuration['client_secret'],
        }) as Map,
      );
      final opened = await securityChannel.invokeMethod<bool>(
        'openGoogleAuthorization',
        start!['authorization_url'],
      );
      if (opened != true) {
        throw const KeyLeaseException('Could not open Google authorization');
      }
    });
    if (!mounted || start == null) return;
    final complete = await showDialog<bool>(
      context: context,
      barrierDismissible: false,
      builder: (context) => AlertDialog(
        title: const Text('Finish in Google Picker'),
        content: Text(
          'Choose the files in the browser, then return here. This flow expires at ${start!['expires_at']}.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(context, true),
            child: const Text('Complete connection'),
          ),
        ],
      ),
    );
    if (complete != true) return;
    await run(() async {
      final auth = await rpc.auth();
      await rpc.call({
        'command': 'connection_google_oauth_complete',
        'auth': auth,
        'flow_id': start!['flow_id'],
      });
      connections = _maps(await rpc.call({
        'command': 'connections_list',
        'auth': auth,
      }));
    });
  }

  Future<void> manageConnection(
    Map<String, dynamic> connection,
    String operation,
  ) async {
    if (operation == 'enroll') {
      final resource = TextEditingController();
      final value = await showDialog<String>(
        context: context,
        builder: (context) => AlertDialog(
          title: const Text('Enroll exact resource'),
          content: TextField(
            controller: resource,
            autofocus: true,
            decoration: const InputDecoration(
              labelText: 'Canonical resource ID',
            ),
            onSubmitted: (value) => Navigator.pop(context, value.trim()),
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(context),
              child: const Text('Cancel'),
            ),
            FilledButton(
              onPressed: () => Navigator.pop(context, resource.text.trim()),
              child: const Text('Enroll'),
            ),
          ],
        ),
      );
      resource.dispose();
      if (value != null && value.isNotEmpty) {
        await connectionResource(connection, value, true);
      }
      return;
    }
    if (operation == 'revoke') {
      final confirmed = await showDialog<bool>(
        context: context,
        builder: (context) => AlertDialog(
          title: const Text('Revoke connection?'),
          content: const Text(
            'This asks the provider to revoke the credential and cannot be undone.',
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(context, false),
              child: const Text('Cancel'),
            ),
            FilledButton(
              onPressed: () => Navigator.pop(context, true),
              child: const Text('Revoke'),
            ),
          ],
        ),
      );
      if (confirmed != true) return;
    }
    await run(() async {
      final auth = await rpc.auth();
      await rpc.call({
        'command': 'connection_$operation',
        'auth': auth,
        'id': connection['id'],
      });
      connections = _maps(await rpc.call({
        'command': 'connections_list',
        'auth': auth,
      }));
    });
  }

  Future<void> connectionResource(
    Map<String, dynamic> connection,
    String resource,
    bool enroll,
  ) =>
      run(() async {
        final auth = await rpc.auth();
        await rpc.call({
          'command': enroll ? 'connection_enroll' : 'connection_unenroll',
          'auth': auth,
          'id': connection['id'],
          'resource': resource,
        });
        connections = _maps(await rpc.call({
          'command': 'connections_list',
          'auth': auth,
        }));
      });

  Widget approvalsView() => _ListOrEmpty(
        empty: 'No pending approvals',
        children: approvals.map((approval) {
          final digest = approval['request_digest_hex']?.toString() ?? '';
          return Card(
            margin: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
            child: ListTile(
              leading: const Icon(Icons.policy_outlined),
              title: Text(approval['action']?.toString() ?? 'Approval request'),
              subtitle: Text(
                '${approval['resource'] ?? approval['id']}\n'
                '${approval['agent_id'] ?? 'unknown client'} · policy v${approval['policy_version']} · expires ${approval['expires_at']}\n'
                'Request ${digest.length > 20 ? '${digest.substring(0, 20)}…' : digest}',
              ),
              isThreeLine: true,
              trailing: Wrap(
                spacing: 8,
                children: [
                  OutlinedButton(
                    onPressed:
                        busy ? null : () => decideApproval(approval, false),
                    child: const Text('Deny'),
                  ),
                  FilledButton(
                    onPressed:
                        busy ? null : () => decideApproval(approval, true),
                    child: const Text('Approve'),
                  ),
                ],
              ),
            ),
          );
        }).toList(),
      );

  Widget auditView() => _ListOrEmpty(
        empty: 'No audit events',
        children: audits.map((event) {
          final counts = [
            if (event['item_count'] != null) '${event['item_count']} items',
            if (event['cell_count'] != null) '${event['cell_count']} cells',
            if (event['byte_count'] != null) '${event['byte_count']} bytes',
          ].join(' · ');
          return ListTile(
            leading: Icon(
              event['outcome'] == 'success' ? Icons.check_circle : Icons.info,
            ),
            title: Text(event['action']?.toString() ?? 'Unknown action'),
            subtitle: Text(
              '${event['timestamp']}\n${event['resource']}'
              '${counts.isEmpty ? '' : '\n$counts'}',
            ),
            isThreeLine: true,
            trailing: Chip(
              label: Text('${event['decision']} / ${event['outcome']}'),
            ),
          );
        }).toList(),
      );

  Future<void> decideApproval(
    Map<String, dynamic> approval,
    bool approve,
  ) async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: Text(approve ? 'Approve exact request?' : 'Deny request?'),
        content: Text(
          'This decision applies only to request digest\n'
          '${approval['request_digest_hex']}',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(context, true),
            child: Text(approve ? 'Approve' : 'Deny'),
          ),
        ],
      ),
    );
    if (confirmed != true) return;
    await run(() async {
      final auth = await rpc.auth();
      await rpc.call({
        'command': 'approval_decide',
        'auth': auth,
        'id': approval['id'],
        'approve': approve,
      });
      approvals = _maps(await rpc.call({
        'command': 'approvals_list',
        'auth': auth,
        'limit': 100,
      }));
    });
  }

  Future<void> unlockVault() async {
    final password = TextEditingController();
    final submitted = await showDialog<String>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Unlock KeyLease'),
        content: TextField(
          controller: password,
          autofocus: true,
          obscureText: true,
          decoration: const InputDecoration(labelText: 'Master password'),
          onSubmitted: (value) => Navigator.pop(context, value),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(context, password.text),
            child: const Text('Unlock'),
          ),
        ],
      ),
    );
    password.clear();
    password.dispose();
    if (submitted == null || submitted.isEmpty) return;
    await run(() async {
      final auth = await rpc.auth();
      await rpc.call({
        'command': 'unlock',
        'auth': auth,
        'password': submitted,
        'session_ttl_seconds': 900,
      });
      status = Map<String, dynamic>.from(
        await rpc.call({'command': 'status'}) as Map,
      );
    });
    if (unlocked) await refresh();
  }

  Future<void> lockVault() => run(() async {
        if (Platform.isMacOS) {
          await securityChannel.invokeMethod<bool>('clearSensitiveClipboard');
        }
        final auth = await rpc.auth();
        await rpc.call({'command': 'lock', 'auth': auth});
        status = Map<String, dynamic>.from(
          await rpc.call({'command': 'status'}) as Map,
        );
        entries = const [];
        groups = const [];
        connections = const [];
        approvals = const [];
        audits = const [];
      });

  Future<void> selectTokenFile() async {
    final path =
        await securityChannel.invokeMethod<String>('selectClientToken');
    if (path != null && path.isNotEmpty) {
      setState(() => tokenFile.text = path);
    }
  }

  Future<void> showEntry(Map<String, dynamic> item) => showDialog<void>(
        context: context,
        builder: (context) => AlertDialog(
          title: Text(item['title']?.toString() ?? 'Entry'),
          content: SelectableText(
            'Kind: ${item['kind']}\n'
            'Group: ${item['group_id']}\n'
            'Username: ${item['username'] ?? ''}\n'
            'URLs: ${(item['urls'] as List<dynamic>? ?? const []).join(', ')}\n'
            'Revision: ${item['revision']}\n'
            'Updated: ${item['updated_at']}',
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(context),
              child: const Text('Close'),
            ),
          ],
        ),
      );

  Future<void> entryAction(
    Map<String, dynamic> item,
    String action,
  ) async {
    switch (action) {
      case 'copy_username':
        await copyEntryField(item, 'username');
      case 'reveal_password':
        await revealPassword(item);
      case 'copy_password':
        await copyEntryField(item, 'password');
      case 'totp':
        await showTotp(item);
      case 'history':
        await showHistory(item);
      case 'edit':
        await editEntry(item);
      case 'delete':
        await deleteEntry(item);
    }
  }

  Future<String?> revealEntryField(
    Map<String, dynamic> item,
    String field,
  ) async {
    String? value;
    await run(() async {
      final auth = await rpc.auth();
      final response = Map<String, dynamic>.from(
        await rpc.call({
          'command': 'entries_reveal',
          'auth': auth,
          'id': item['id'],
          'field': field,
        }) as Map,
      );
      value = response['value']?.toString();
    });
    return value;
  }

  Future<void> copySensitive(String value, String label) async {
    try {
      final copied = await securityChannel.invokeMethod<bool>('copySensitive', {
        'value': value,
        'clear_after_seconds': 30,
      });
      if (copied != true) throw const KeyLeaseException('Clipboard rejected');
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('$label copied; clipboard clears in 30s')),
        );
      }
    } catch (caught) {
      if (mounted) setState(() => error = '$caught');
    }
  }

  Future<void> copyEntryField(
    Map<String, dynamic> item,
    String field,
  ) async {
    final value = await revealEntryField(item, field);
    if (value != null && value.isNotEmpty) {
      await copySensitive(value, field == 'username' ? 'Username' : 'Password');
    }
  }

  Future<void> revealPassword(Map<String, dynamic> item) async {
    final value = await revealEntryField(item, 'password');
    if (!mounted || value == null) return;
    await showDialog<void>(
      context: context,
      builder: (context) => _SecretDialog(
        title: 'Password · ${item['title'] ?? ''}',
        value: value,
        onCopy: () => copySensitive(value, 'Password'),
      ),
    );
  }

  Future<void> showTotp(Map<String, dynamic> item) async {
    Map<String, dynamic>? response;
    await run(() async {
      final auth = await rpc.auth();
      response = Map<String, dynamic>.from(
        await rpc.call({
          'command': 'entries_totp',
          'auth': auth,
          'id': item['id'],
        }) as Map,
      );
    });
    if (!mounted || response == null) return;
    await showDialog<void>(
      context: context,
      builder: (_) => _TotpDialog(
        code: response!['code'].toString(),
        expiresIn: response!['expires_in'] as int,
        onCopy: () => copySensitive(response!['code'].toString(), 'TOTP'),
      ),
    );
  }

  Future<void> showHistory(Map<String, dynamic> item) async {
    List<Map<String, dynamic>> history = const [];
    await run(() async {
      final auth = await rpc.auth();
      history = _maps(await rpc.call({
        'command': 'entries_history',
        'auth': auth,
        'id': item['id'],
      }));
    });
    if (!mounted) return;
    await showDialog<void>(
      context: context,
      builder: (context) => AlertDialog(
        title: Text('History · ${item['title'] ?? ''}'),
        content: SizedBox(
          width: 520,
          child: history.isEmpty
              ? const Text('No earlier revisions')
              : ListView(
                  shrinkWrap: true,
                  children: history
                      .map(
                        (revision) => ListTile(
                          title: Text('Revision ${revision['revision']}'),
                          subtitle: Text('${revision['updated_at']}'),
                        ),
                      )
                      .toList(),
                ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('Close'),
          ),
        ],
      ),
    );
  }

  Future<String?> generateEntryPassword() async {
    try {
      final auth = await rpc.auth();
      final response = Map<String, dynamic>.from(
        await rpc.call({
          'command': 'generate_password',
          'auth': auth,
          'length': 32,
        }) as Map,
      );
      return response['password']?.toString();
    } catch (caught) {
      if (mounted) setState(() => error = '$caught');
      return null;
    }
  }

  Future<void> createEntry() async {
    final input = await entryDialog();
    if (input == null) return;
    await run(() async {
      final auth = await rpc.auth();
      await rpc.call({
        'command': 'entries_create',
        'auth': auth,
        'input': input,
        'idempotency_key': 'desktop-${DateTime.now().microsecondsSinceEpoch}',
        'dry_run': false,
      });
      entries = _maps(await rpc.call({
        'command': 'entries_search',
        'auth': auth,
        'query': search.text,
      }));
    });
  }

  Future<void> createGroup() async {
    final controller = TextEditingController();
    final name = await showDialog<String>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('New group'),
        content: TextField(
          controller: controller,
          autofocus: true,
          decoration: const InputDecoration(labelText: 'Name'),
          onSubmitted: (value) {
            if (value.trim().isNotEmpty) Navigator.pop(context, value.trim());
          },
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () {
              if (controller.text.trim().isNotEmpty) {
                Navigator.pop(context, controller.text.trim());
              }
            },
            child: const Text('Create'),
          ),
        ],
      ),
    );
    controller.dispose();
    if (name == null) return;
    await run(() async {
      final auth = await rpc.auth();
      await rpc.call({
        'command': 'groups_create',
        'auth': auth,
        'name': name,
        'parent_id': selectedGroupId,
        'idempotency_key': 'desktop-${DateTime.now().microsecondsSinceEpoch}',
        'dry_run': false,
      });
      groups = _maps(await rpc.call({
        'command': 'groups_list',
        'auth': auth,
      }));
    });
  }

  Future<void> renameGroup(Map<String, dynamic> group) async {
    final controller =
        TextEditingController(text: group['name']?.toString() ?? '');
    final name = await showDialog<String>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Rename group'),
        content: TextField(
          controller: controller,
          autofocus: true,
          decoration: const InputDecoration(labelText: 'Name'),
          onSubmitted: (value) => Navigator.pop(context, value.trim()),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(context, controller.text.trim()),
            child: const Text('Rename'),
          ),
        ],
      ),
    );
    controller.dispose();
    if (name == null || name.isEmpty) return;
    await run(() async {
      final auth = await rpc.auth();
      await rpc.call({
        'command': 'groups_update',
        'auth': auth,
        'id': group['id'],
        'name': name,
        'if_revision': group['revision'],
        'idempotency_key': 'desktop-${DateTime.now().microsecondsSinceEpoch}',
        'dry_run': false,
      });
      groups = _maps(await rpc.call({
        'command': 'groups_list',
        'auth': auth,
      }));
    });
  }

  Future<void> deleteGroup(Map<String, dynamic> group) async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Delete empty group?'),
        content: Text(group['name']?.toString() ?? 'Group'),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(context, true),
            child: const Text('Delete'),
          ),
        ],
      ),
    );
    if (confirmed != true) return;
    await run(() async {
      final auth = await rpc.auth();
      await rpc.call({
        'command': 'groups_delete',
        'auth': auth,
        'id': group['id'],
        'if_revision': group['revision'],
        'idempotency_key': 'desktop-${DateTime.now().microsecondsSinceEpoch}',
        'dry_run': false,
      });
      if (selectedGroupId == group['id']) selectedGroupId = null;
      groups = _maps(await rpc.call({
        'command': 'groups_list',
        'auth': auth,
      }));
    });
  }

  Future<void> editEntry(Map<String, dynamic> item) async {
    final input = await entryDialog(existing: item);
    if (input == null) return;
    final password = input.remove('password');
    final notes = input.remove('notes');
    final totp = input.remove('totp');
    final totpUri = input.remove('totp_uri');
    final customFields = input.remove('custom_fields');
    final patch = <String, dynamic>{
      'title': input['title'],
      'username': input['username'],
      'url': input['url'],
      if (input['group_id'] != item['group_id']) 'group_id': input['group_id'],
      if (password is String && password.isNotEmpty) 'password': password,
      if (notes is String && notes.isNotEmpty) 'notes': notes,
      if (totp is Map<String, dynamic>) 'totp': totp,
      if (totpUri is String && totpUri.isNotEmpty) 'totp_uri': totpUri,
      if (customFields is List<dynamic>) 'custom_fields': customFields,
    };
    await run(() async {
      final auth = await rpc.auth();
      await rpc.call({
        'command': 'entries_update',
        'auth': auth,
        'id': item['id'],
        'patch': patch,
        'if_revision': item['revision'],
        'idempotency_key': 'desktop-${DateTime.now().microsecondsSinceEpoch}',
        'dry_run': false,
      });
      entries = _maps(await rpc.call({
        'command': 'entries_search',
        'auth': auth,
        'query': search.text,
      }));
    });
  }

  Future<Map<String, dynamic>?> entryDialog(
      {Map<String, dynamic>? existing}) async {
    var kind = existing?['kind']?.toString() ?? 'core.login';
    final title = TextEditingController(text: existing?['title']?.toString());
    final username =
        TextEditingController(text: existing?['username']?.toString());
    final password = TextEditingController();
    final existingUrls = existing?['urls'] as List<dynamic>? ?? const [];
    final url = TextEditingController(
      text: existingUrls.isEmpty ? null : existingUrls.first.toString(),
    );
    final notes = TextEditingController();
    final totpUri = TextEditingController();
    final customFields = TextEditingController();
    String? groupId = existing?['group_id']?.toString() ??
        (groups.isEmpty ? null : groups.first['id']?.toString());
    String? validationError;
    final result = await showDialog<Map<String, dynamic>>(
      context: context,
      builder: (context) => StatefulBuilder(
        builder: (context, setDialogState) => AlertDialog(
          title: Text(existing == null ? 'New item' : 'Edit entry'),
          content: SizedBox(
            width: 520,
            child: SingleChildScrollView(
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  DropdownButtonFormField<String>(
                    initialValue: kind,
                    decoration: const InputDecoration(labelText: 'Template'),
                    items: const [
                      DropdownMenuItem(
                          value: 'core.login', child: Text('Login')),
                      DropdownMenuItem(
                          value: 'core.api_credential',
                          child: Text('API Credential')),
                      DropdownMenuItem(
                          value: 'core.secure_note',
                          child: Text('Secure Note')),
                      DropdownMenuItem(
                          value: 'core.generic', child: Text('Generic item')),
                    ],
                    onChanged: existing == null
                        ? (value) => setDialogState(() => kind = value ?? kind)
                        : null,
                  ),
                  DropdownButtonFormField<String>(
                    initialValue: groupId,
                    decoration: const InputDecoration(labelText: 'Group'),
                    items: groups
                        .map(
                          (group) => DropdownMenuItem(
                            value: group['id']?.toString(),
                            child: Text(group['name']?.toString() ?? 'Group'),
                          ),
                        )
                        .toList(),
                    onChanged: (value) => setDialogState(() => groupId = value),
                  ),
                  TextField(
                    controller: title,
                    autofocus: true,
                    decoration: const InputDecoration(labelText: 'Title'),
                    onChanged: (_) => setDialogState(() {}),
                  ),
                  TextField(
                    controller: username,
                    decoration: const InputDecoration(labelText: 'Username'),
                  ),
                  TextField(
                    controller: password,
                    obscureText: true,
                    decoration: InputDecoration(
                      labelText: existing == null
                          ? 'Password'
                          : 'New password (leave blank to keep current)',
                      suffixIcon: IconButton(
                        icon: const Icon(Icons.auto_awesome),
                        tooltip: 'Generate 32-character password',
                        onPressed: () async {
                          final generated = await generateEntryPassword();
                          if (context.mounted && generated != null) {
                            password.text = generated;
                            setDialogState(() {});
                          }
                        },
                      ),
                    ),
                  ),
                  TextField(
                    controller: url,
                    decoration: const InputDecoration(labelText: 'URL'),
                  ),
                  TextField(
                    controller: notes,
                    minLines: 2,
                    maxLines: 5,
                    decoration: InputDecoration(
                      labelText: existing == null
                          ? 'Notes'
                          : 'New notes (blank keeps current)',
                    ),
                  ),
                  TextField(
                    controller: totpUri,
                    obscureText: true,
                    decoration: InputDecoration(
                      labelText: existing == null
                          ? 'TOTP Base32 secret or otpauth URI'
                          : 'New TOTP Base32 secret or URI (blank keeps current)',
                    ),
                  ),
                  TextField(
                    controller: customFields,
                    minLines: 2,
                    maxLines: 7,
                    decoration: InputDecoration(
                      labelText: existing == null
                          ? 'Custom fields JSON array (optional)'
                          : 'Replacement custom fields JSON (blank keeps current)',
                      helperText:
                          'Typed fields retain protected and sensitivity flags.',
                    ),
                  ),
                  if (validationError != null)
                    Padding(
                      padding: const EdgeInsets.only(top: 8),
                      child: Text(
                        validationError!,
                        style: TextStyle(
                            color: Theme.of(context).colorScheme.error),
                      ),
                    ),
                ],
              ),
            ),
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(context),
              child: const Text('Cancel'),
            ),
            FilledButton(
              onPressed: title.text.trim().isEmpty || groupId == null
                  ? null
                  : () {
                      List<dynamic>? parsedCustomFields;
                      if (customFields.text.trim().isNotEmpty) {
                        try {
                          final decoded = jsonDecode(customFields.text);
                          if (decoded is! List<dynamic>) {
                            throw const FormatException();
                          }
                          parsedCustomFields = decoded;
                        } on FormatException {
                          setDialogState(() => validationError =
                              'Custom fields must be a JSON array.');
                          return;
                        }
                      }
                      Navigator.pop(context, {
                        'group_id': groupId,
                        'kind': kind,
                        'title': title.text.trim(),
                        'username': username.text,
                        'password':
                            password.text.isEmpty ? null : password.text,
                        'url': url.text.isEmpty ? null : url.text,
                        'notes': notes.text.isEmpty ? null : notes.text,
                        if (existing == null || parsedCustomFields != null)
                          'custom_fields': parsedCustomFields ?? <dynamic>[],
                        'totp': totpUri.text.isEmpty ||
                                totpUri.text.startsWith('otpauth://')
                            ? null
                            : {
                                'secret_base32': totpUri.text.trim(),
                                'issuer': null,
                                'account': null,
                                'algorithm': 'sha1',
                                'digits': 6,
                                'period': 30,
                                'source_representation': 'base32',
                              },
                        'totp_uri': totpUri.text.startsWith('otpauth://')
                            ? totpUri.text.trim()
                            : null,
                      });
                    },
              child: const Text('Save'),
            ),
          ],
        ),
      ),
    );
    title.dispose();
    username.dispose();
    password.clear();
    password.dispose();
    url.dispose();
    notes.clear();
    notes.dispose();
    totpUri.clear();
    totpUri.dispose();
    customFields.clear();
    customFields.dispose();
    return result;
  }

  Future<void> deleteEntry(Map<String, dynamic> item) async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Move entry to recycle bin?'),
        content: Text(item['title']?.toString() ?? 'Entry'),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(context, true),
            child: const Text('Delete'),
          ),
        ],
      ),
    );
    if (confirmed != true) return;
    await run(() async {
      final auth = await rpc.auth();
      await rpc.call({
        'command': 'entries_delete',
        'auth': auth,
        'id': item['id'],
        'if_revision': item['revision'],
        'idempotency_key': 'desktop-${DateTime.now().microsecondsSinceEpoch}',
        'dry_run': false,
      });
      entries = _maps(await rpc.call({
        'command': 'entries_search',
        'auth': auth,
        'query': search.text,
      }));
    });
  }

  Widget settings() => AlertDialog(
        title: const Text('Local service'),
        content: SizedBox(
          width: 480,
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              TextField(
                controller: socket,
                decoration: const InputDecoration(labelText: 'Unix socket'),
              ),
              TextField(
                controller: agent,
                decoration: const InputDecoration(labelText: 'Client ID'),
              ),
              Row(
                children: [
                  Expanded(
                    child: TextField(
                      controller: tokenFile,
                      decoration: const InputDecoration(
                        labelText: 'Client token file (mode 0600)',
                      ),
                    ),
                  ),
                  IconButton(
                    onPressed: selectTokenFile,
                    icon: const Icon(Icons.folder_open),
                    tooltip: 'Choose token file',
                  ),
                ],
              ),
            ],
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () {
              Navigator.pop(context);
              unawaited(refresh());
            },
            child: const Text('Connect'),
          ),
        ],
      );
}

class _SecretDialog extends StatefulWidget {
  const _SecretDialog({
    required this.title,
    required this.value,
    required this.onCopy,
  });

  final String title;
  final String value;
  final Future<void> Function() onCopy;

  @override
  State<_SecretDialog> createState() => _SecretDialogState();
}

class _SecretDialogState extends State<_SecretDialog> {
  bool visible = false;

  @override
  Widget build(BuildContext context) => AlertDialog(
        title: Text(widget.title),
        content: SelectableText(
          visible ? widget.value : '•' * widget.value.characters.length,
          style: Theme.of(context).textTheme.headlineSmall,
        ),
        actions: [
          TextButton.icon(
            onPressed: () => setState(() => visible = !visible),
            icon: Icon(visible ? Icons.visibility_off : Icons.visibility),
            label: Text(visible ? 'Hide' : 'Reveal'),
          ),
          TextButton.icon(
            onPressed: widget.onCopy,
            icon: const Icon(Icons.copy),
            label: const Text('Copy'),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('Close'),
          ),
        ],
      );
}

class _TotpDialog extends StatefulWidget {
  const _TotpDialog({
    required this.code,
    required this.expiresIn,
    required this.onCopy,
  });

  final String code;
  final int expiresIn;
  final Future<void> Function() onCopy;

  @override
  State<_TotpDialog> createState() => _TotpDialogState();
}

class _TotpDialogState extends State<_TotpDialog> {
  late int remaining = widget.expiresIn;
  Timer? timer;

  @override
  void initState() {
    super.initState();
    timer = Timer.periodic(const Duration(seconds: 1), (_) {
      if (mounted) {
        setState(() => remaining = remaining > 0 ? remaining - 1 : 0);
      }
    });
  }

  @override
  void dispose() {
    timer?.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) => AlertDialog(
        title: const Text('One-time password'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            SelectableText(
              widget.code,
              style: Theme.of(context).textTheme.displaySmall,
            ),
            const SizedBox(height: 12),
            LinearProgressIndicator(
              value: widget.expiresIn == 0 ? 0 : remaining / widget.expiresIn,
            ),
            const SizedBox(height: 8),
            Text(remaining == 0 ? 'Expired' : 'Expires in ${remaining}s'),
          ],
        ),
        actions: [
          TextButton.icon(
            onPressed: remaining == 0 ? null : widget.onCopy,
            icon: const Icon(Icons.copy),
            label: const Text('Copy TOTP'),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('Close'),
          ),
        ],
      );
}

class _LockedNotice extends StatelessWidget {
  const _LockedNotice();

  @override
  Widget build(BuildContext context) => const ListTile(
        leading: Icon(Icons.lock),
        title: Text('Vault locked'),
        subtitle: Text(
          'Use Unlock in the toolbar with a registered private client token.',
        ),
      );
}

class _ListOrEmpty extends StatelessWidget {
  const _ListOrEmpty({required this.empty, required this.children});

  final String empty;
  final List<Widget> children;

  @override
  Widget build(BuildContext context) => children.isEmpty
      ? Center(child: Text(empty))
      : ListView(children: children);
}

class KeyLeaseRpc {
  KeyLeaseRpc(this.socketPath, this.agentId, this.tokenPath);

  static const maxMessageBytes = 4 * 1024 * 1024;
  final String socketPath;
  final String agentId;
  final String tokenPath;

  Future<Map<String, dynamic>> auth() async {
    if (agentId.trim().isEmpty || tokenPath.trim().isEmpty) {
      throw const KeyLeaseException('Client ID and token file are required');
    }
    final type = await FileSystemEntity.type(tokenPath, followLinks: false);
    if (type != FileSystemEntityType.file) {
      throw const KeyLeaseException('Client token must be a regular file');
    }
    final stat = await File(tokenPath).stat();
    if (stat.size <= 0 || stat.size > 4096) {
      throw const KeyLeaseException('Client token file has an invalid size');
    }
    if (!Platform.isWindows && stat.mode & 0x3f != 0) {
      throw const KeyLeaseException('Client token file must have mode 0600');
    }
    final token = (await File(tokenPath).readAsString()).trim();
    if (token.isEmpty) throw const KeyLeaseException('Client token is empty');
    return {
      'agent_id': agentId.trim(),
      'token': token,
      'session_id': 'desktop',
    };
  }

  Future<dynamic> call(Map<String, dynamic> request) async {
    final encoded = utf8.encode('${jsonEncode(request)}\n');
    if (encoded.length > maxMessageBytes) {
      throw const KeyLeaseException('Request exceeds the local IPC size limit');
    }
    final connection = await Socket.connect(
      InternetAddress(socketPath, type: InternetAddressType.unix),
      0,
    ).timeout(const Duration(seconds: 10));
    try {
      connection.add(encoded);
      await connection.flush();
      final responseBytes = <int>[];
      var complete = false;
      await for (final chunk
          in connection.timeout(const Duration(seconds: 30))) {
        for (final byte in chunk) {
          if (byte == 10) {
            complete = true;
            break;
          }
          responseBytes.add(byte);
          if (responseBytes.length > maxMessageBytes) {
            throw const KeyLeaseException(
              'Response exceeds the local IPC size limit',
            );
          }
        }
        if (complete) break;
      }
      if (!complete) {
        throw const KeyLeaseException('Incomplete local IPC response');
      }
      final response = jsonDecode(utf8.decode(responseBytes));
      if (response is! Map<String, dynamic>) {
        throw const KeyLeaseException('Invalid local IPC response');
      }
      if (response['ok'] == false) throw KeyLeaseException(response['error']);
      return response['result'];
    } finally {
      connection.destroy();
    }
  }
}

class KeyLeaseException implements Exception {
  const KeyLeaseException(this.payload);

  final dynamic payload;

  @override
  String toString() => 'KeyLease: ${jsonEncode(payload)}';
}
