import 'package:forui/forui.dart';
import 'package:material_ui/material_ui.dart';

import '../../core/models/models.dart';
import '../../core/state/app_controller.dart';
import '../../ui/components/secret_field.dart';
import '../../ui/components/section_label.dart';
import 'developer_templates.dart';
import 'totp_dialog.dart';

class DeveloperTemplateDetail extends StatelessWidget {
  const DeveloperTemplateDetail({
    required this.app,
    required this.item,
    required this.detail,
    super.key,
  });

  final AppController app;
  final EntrySummary item;
  final EntryDetailView detail;

  @override
  Widget build(BuildContext context) => switch (item.kind) {
    'core.environment' => _EnvironmentDetail(
      app: app,
      item: item,
      detail: detail,
    ),
    'core.ssh_server' => _SshDetail(app: app, item: item, detail: detail),
    _ => const SizedBox.shrink(),
  };
}

Future<void> _copyField(
  BuildContext context,
  AppController app,
  EntrySummary item,
  EntryFieldView field,
) async {
  try {
    final value = field.protected
        ? await app.vault.fetchField(item, field)
        : field.displayValue;
    if (value == null || !context.mounted) return;
    final copied = await app.copySensitive(value);
    if (copied && context.mounted) {
      showFToast(
        context: context,
        title: Text('${field.label} copied'),
        description: const Text('The clipboard clears in 30 seconds.'),
      );
    }
  } catch (caught) {
    if (context.mounted) showFailure(context, caught);
  }
}

class _EnvironmentDetail extends StatefulWidget {
  const _EnvironmentDetail({
    required this.app,
    required this.item,
    required this.detail,
  });
  final AppController app;
  final EntrySummary item;
  final EntryDetailView detail;

  @override
  State<_EnvironmentDetail> createState() => _EnvironmentDetailState();
}

class _EnvironmentDetailState extends State<_EnvironmentDetail> {
  final _search = TextEditingController();

  @override
  void dispose() {
    _search.dispose();
    super.dispose();
  }

  List<EntryFieldView> get _variables {
    final section = widget.detail.sections
        .where((section) => section.semanticRole == 'environment_variables')
        .firstOrNull;
    if (section == null) return const [];
    final query = _search.text.trim().toLowerCase();
    return [
      for (final id in section.fieldIds)
        if (widget.detail.fields.where((field) => field.id == id).firstOrNull
            case final field?)
          if (query.isEmpty || field.label.toLowerCase().contains(query)) field,
    ];
  }

  Future<void> _copyDotEnv() async {
    final section = widget.detail.sections
        .where((entry) => entry.semanticRole == 'environment_variables')
        .firstOrNull;
    if (section == null || section.fieldIds.isEmpty) return;
    final fields = [
      for (final id in section.fieldIds)
        if (widget.detail.fields.where((field) => field.id == id).firstOrNull
            case final field?)
          field,
    ];
    try {
      final values = await widget.app.vault.fetchFields(widget.item, fields);
      final content = renderDotEnv(
        fields.map((field) => MapEntry(field.label, values[field.id] ?? '')),
      );
      if (!mounted) return;
      final copied = await widget.app.copySensitive(content);
      if (copied && mounted) {
        showFToast(
          context: context,
          title: const Text('.env copied'),
          description: Text(
            '${fields.length} variables · clipboard clears in 30 seconds.',
          ),
        );
      }
    } catch (caught) {
      if (mounted) showFailure(context, caught);
    }
  }

  @override
  Widget build(BuildContext context) {
    final metadataSection = widget.detail.sections
        .where((section) => section.semanticRole == 'environment_metadata')
        .firstOrNull;
    final metadata = metadataSection == null
        ? const <String, EntryFieldView>{}
        : fieldsByRole(metadataSection, widget.detail);
    String value(String role) => metadata[role]?.displayValue ?? '';
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        const SizedBox(height: 24),
        const SectionLabel('Environment'),
        FieldGroup(
          children: [
            DetailField(
              label: 'Project / repository',
              value: value('environment_project'),
            ),
            DetailField(
              label: 'Environment',
              value: value('environment_scope'),
            ),
            DetailField(label: 'Source', value: value('environment_source')),
          ],
        ),
        const SizedBox(height: 18),
        Row(
          children: [
            const Expanded(child: SectionLabel('Variables')),
            FButton(
              key: ValueKey('copy-dotenv-${widget.item.id}'),
              size: FButtonSizeVariant.xs,
              variant: FButtonVariant.outline,
              onPress: _copyDotEnv,
              prefix: const Icon(FLucideIcons.copy, size: 14),
              child: const Text('Copy .env'),
            ),
          ],
        ),
        const SizedBox(height: 8),
        FTextField(
          key: ValueKey('environment-search-${widget.item.id}'),
          hint: 'Find a variable',
          prefixBuilder: (_, _, _) => const Padding(
            padding: EdgeInsets.only(left: 10),
            child: Icon(FLucideIcons.search, size: 15),
          ),
          control: FTextFieldControl.managed(
            controller: _search,
            onChange: (_) => setState(() {}),
          ),
        ),
        const SizedBox(height: 8),
        FieldGroup(
          children: [
            for (final field in _variables)
              if (field.protected)
                SecretField(
                  label: field.label,
                  revealedValue: widget.app.vault.revealedValue(
                    widget.item.id,
                    field.id,
                  ),
                  busy: widget.app.vault.isBusy(
                    'reveal.${widget.item.id}/${field.id}',
                  ),
                  maskedValue: field.displayHint,
                  onReveal: () =>
                      widget.app.vault.revealField(widget.item, field),
                  onHide: () =>
                      widget.app.vault.hideSecret(widget.item.id, field.id),
                  onCopy: () =>
                      _copyField(context, widget.app, widget.item, field),
                )
              else
                DetailField(
                  label: field.label,
                  value: field.displayValue,
                  actions: [
                    IconAction(
                      label: 'Copy ${field.label}',
                      icon: FLucideIcons.copy,
                      onPress: () =>
                          _copyField(context, widget.app, widget.item, field),
                    ),
                  ],
                ),
          ],
        ),
      ],
    );
  }
}

class _SshDetail extends StatelessWidget {
  const _SshDetail({
    required this.app,
    required this.item,
    required this.detail,
  });
  final AppController app;
  final EntrySummary item;
  final EntryDetailView detail;

  List<SshEndpointConfig> get _endpoints => [
    for (final section in detail.sections.where(
      (entry) => entry.semanticRole == 'ssh_endpoint',
    ))
      if (fieldsByRole(section, detail) case final fields)
        SshEndpointConfig(
          sectionId: section.id,
          name: fields['ssh_display_name']?.displayValue ?? section.label,
          alias: fields['ssh_alias']?.displayValue ?? '',
          host: fields['ssh_host']?.displayValue ?? '',
          port: int.tryParse(fields['ssh_port']?.displayValue ?? '') ?? 22,
          username: fields['ssh_username']?.displayValue ?? '',
          authMode: fields['ssh_auth_mode']?.displayValue ?? 'ssh_agent',
          connectVia: fields['ssh_connect_via']?.displayValue,
        ),
  ];

  List<SshForwardConfig> get _forwards => [
    for (final section in detail.sections.where(
      (entry) => entry.semanticRole == 'ssh_forward',
    ))
      if (fieldsByRole(section, detail) case final fields)
        SshForwardConfig(
          endpointId: fields['ssh_forward_endpoint']?.displayValue ?? '',
          type: fields['ssh_forward_type']?.displayValue ?? 'local',
          bindAddress: fields['ssh_bind_address']?.displayValue ?? '127.0.0.1',
          bindPort:
              int.tryParse(fields['ssh_bind_port']?.displayValue ?? '') ?? 0,
          destinationHost: fields['ssh_destination_host']?.displayValue ?? '',
          destinationPort:
              int.tryParse(
                fields['ssh_destination_port']?.displayValue ?? '',
              ) ??
              0,
        ),
  ];

  Future<void> _copyConfig(BuildContext context) async {
    try {
      final content = renderSshConfig(
        endpoints: _endpoints,
        forwards: _forwards,
        privateKeyPaths: {
          for (final endpoint in _endpoints)
            if (app.sshKeyBinding(item.id, endpoint.sectionId) case final path?)
              endpoint.sectionId: path,
        },
      );
      final copied = await app.copySensitive(content);
      if (copied && context.mounted) {
        showFToast(
          context: context,
          title: const Text('SSH config copied'),
          description: const Text(
            'No passwords are included. Clipboard clears in 30 seconds.',
          ),
        );
      }
    } catch (caught) {
      if (context.mounted) showFailure(context, caught);
    }
  }

  Future<void> _copyCommand(BuildContext context, String alias) async {
    final copied = await app.copySensitive('ssh $alias');
    if (copied && context.mounted) {
      showFToast(
        context: context,
        title: const Text('SSH command copied'),
        description: const Text(
          'Install or merge the generated SSH config before using it.',
        ),
      );
    }
  }

  Future<void> _selectKey(BuildContext context, String endpointId) async {
    try {
      final path = await app.adapter.selectSshPrivateKey();
      if (path != null) await app.setSshKeyBinding(item.id, endpointId, path);
    } catch (caught) {
      if (context.mounted) showFailure(context, caught);
    }
  }

  @override
  Widget build(BuildContext context) {
    final endpoints = _endpoints;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        const SizedBox(height: 24),
        Row(
          children: [
            const Expanded(child: SectionLabel('SSH servers')),
            FButton(
              key: ValueKey('copy-ssh-config-${item.id}'),
              size: FButtonSizeVariant.xs,
              variant: FButtonVariant.outline,
              onPress: () => _copyConfig(context),
              prefix: const Icon(FLucideIcons.copy, size: 14),
              child: const Text('Copy SSH config'),
            ),
          ],
        ),
        for (final endpoint in endpoints)
          if (detail.sections
                  .where((section) => section.id == endpoint.sectionId)
                  .firstOrNull
              case final section?)
            _SshEndpointDetail(
              app: app,
              item: item,
              detail: detail,
              section: section,
              endpoint: endpoint,
              jumpName: endpoints
                  .where(
                    (candidate) => candidate.sectionId == endpoint.connectVia,
                  )
                  .firstOrNull
                  ?.name,
              keyPath: app.sshKeyBinding(item.id, endpoint.sectionId),
              onSelectKey: () => _selectKey(context, endpoint.sectionId),
              onCopyCommand: () => _copyCommand(context, endpoint.alias),
            ),
        if (_forwards.isNotEmpty) ...[
          const SizedBox(height: 18),
          const SectionLabel('SSH tunnels'),
          FieldGroup(
            children: [
              for (final forward in _forwards)
                DetailField(
                  label:
                      '${forward.type.toUpperCase()} · ${endpoints.where((endpoint) => endpoint.sectionId == forward.endpointId).firstOrNull?.name ?? forward.endpointId}',
                  value: forward.type == 'dynamic'
                      ? '${forward.bindAddress}:${forward.bindPort}'
                      : '${forward.bindAddress}:${forward.bindPort} → ${forward.destinationHost}:${forward.destinationPort}',
                ),
            ],
          ),
        ],
      ],
    );
  }
}

class _SshEndpointDetail extends StatelessWidget {
  const _SshEndpointDetail({
    required this.app,
    required this.item,
    required this.detail,
    required this.section,
    required this.endpoint,
    required this.keyPath,
    required this.onSelectKey,
    required this.onCopyCommand,
    this.jumpName,
  });
  final AppController app;
  final EntrySummary item;
  final EntryDetailView detail;
  final EntrySectionView section;
  final SshEndpointConfig endpoint;
  final String? jumpName;
  final String? keyPath;
  final VoidCallback onSelectKey;
  final VoidCallback onCopyCommand;

  @override
  Widget build(BuildContext context) {
    final fields = fieldsByRole(section, detail);
    final secretRoles = [
      'ssh_password',
      'ssh_private_key_passphrase',
      'ssh_sudo_password',
    ];
    return Padding(
      padding: const EdgeInsets.only(top: 10),
      child: FieldGroup(
        children: [
          DetailField(
            label: endpoint.name,
            value:
                '${endpoint.username.isEmpty ? '' : '${endpoint.username}@'}${endpoint.host}:${endpoint.port}',
            actions: [
              IconAction(
                label: 'Copy SSH command',
                icon: FLucideIcons.terminal,
                onPress: onCopyCommand,
              ),
            ],
          ),
          DetailField(label: 'Alias', value: endpoint.alias),
          DetailField(
            label: 'Authentication',
            value: endpoint.authMode.replaceAll('_', ' '),
          ),
          if (jumpName != null)
            DetailField(label: 'Connect via', value: jumpName),
          if (endpoint.authMode == 'private_key')
            DetailField(
              label: 'Private key on this device',
              value: keyPath ?? 'Not selected on this device',
              actions: [
                IconAction(
                  label: 'Select private key',
                  icon: FLucideIcons.folderOpen,
                  onPress: onSelectKey,
                ),
              ],
            ),
          for (final role in secretRoles)
            if (fields[role] case final field?)
              if (field.hasValue)
                SecretField(
                  label: field.label,
                  revealedValue: app.vault.revealedValue(item.id, field.id),
                  busy: app.vault.isBusy('reveal.${item.id}/${field.id}'),
                  maskedValue: field.displayHint,
                  onReveal: () => app.vault.revealField(item, field),
                  onHide: () => app.vault.hideSecret(item.id, field.id),
                  onCopy: () => _copyField(context, app, item, field),
                ),
        ],
      ),
    );
  }
}
