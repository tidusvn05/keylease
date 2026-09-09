import 'dart:async';
import 'dart:convert';

import 'package:forui/forui.dart';
import 'package:material_ui/material_ui.dart';

import '../../core/models/models.dart';
import '../../core/platform/security_adapter.dart';
import '../../core/state/app_controller.dart';
import '../../core/state/entry_draft.dart';
import '../../ui/components/keylease_dialog.dart';
import '../../ui/components/searchable_select.dart';
import '../../ui/components/section_label.dart';
import 'developer_templates.dart';

class DeveloperTemplateEditor extends StatelessWidget {
  const DeveloperTemplateEditor({
    required this.app,
    required this.draft,
    required this.detail,
    super.key,
  });

  final AppController app;
  final EntryDraft draft;
  final EntryDetailView? detail;

  @override
  Widget build(BuildContext context) => switch (draft.kind) {
    'core.environment' => EnvironmentTemplateEditor(
      draft: draft,
      detail: detail,
    ),
    'core.ssh_server' => SshServerTemplateEditor(
      app: app,
      draft: draft,
      detail: detail,
    ),
    _ => const SizedBox.shrink(),
  };
}

class EnvironmentTemplateEditor extends StatefulWidget {
  const EnvironmentTemplateEditor({
    required this.draft,
    this.detail,
    super.key,
  });

  final EntryDraft draft;
  final EntryDetailView? detail;

  @override
  State<EnvironmentTemplateEditor> createState() =>
      _EnvironmentTemplateEditorState();
}

class _EnvironmentTemplateEditorState extends State<EnvironmentTemplateEditor> {
  final _project = TextEditingController();
  final _paste = TextEditingController();
  final _variables = <EnvVariableDraft>[];
  final _removed = <String>[];
  final _metadataIds = <String, String>{};
  var _scope = 'development';
  var _source = 'dotenv';
  var _pasteMode = false;
  var _hydrated = false;
  EnvParseResult? _parseResult;

  @override
  void initState() {
    super.initState();
    _hydrate();
    if (widget.draft.isNew) {
      WidgetsBinding.instance.addPostFrameCallback((_) => _sync());
    }
  }

  @override
  void didUpdateWidget(covariant EnvironmentTemplateEditor oldWidget) {
    super.didUpdateWidget(oldWidget);
    _hydrate();
  }

  void _hydrate() {
    if (_hydrated || widget.draft.isNew || widget.detail == null) return;
    final detail = widget.detail!;
    final metadata = detail.sections
        .where((section) => section.semanticRole == 'environment_metadata')
        .firstOrNull;
    final variableSection = detail.sections
        .where((section) => section.semanticRole == 'environment_variables')
        .firstOrNull;
    if (metadata == null || variableSection == null) return;
    final fields = fieldsByRole(metadata, detail);
    String value(String role, String fallback) {
      final field = fields[role];
      if (field == null) return fallback;
      _metadataIds[role] = field.id;
      return entryFieldText(field) ?? fallback;
    }

    _project.text = value('environment_project', '');
    _scope = value('environment_scope', 'development');
    _source = value('environment_source', 'dotenv');
    for (final id in variableSection.fieldIds) {
      final field = detail.fields
          .where((candidate) => candidate.id == id)
          .firstOrNull;
      if (field == null || field.semanticRole != 'environment_variable') {
        continue;
      }
      _variables.add(
        EnvVariableDraft(
          id: field.id,
          key: field.label,
          value: entryFieldText(field) ?? '',
          secret: field.protected,
          existing: true,
          hasStoredValue: field.hasValue,
          dirty: false,
        ),
      );
    }
    _hydrated = true;
  }

  @override
  void dispose() {
    _project.dispose();
    _paste
      ..clear()
      ..dispose();
    super.dispose();
  }

  void _changed() {
    if (!_hydrated && !widget.draft.isNew) return;
    _sync();
  }

  String _metadataId(String role) =>
      _metadataIds.putIfAbsent(role, () => structuredId('field_environment'));

  void _sync() {
    final errors = <String, String>{};
    if (_project.text.trim().isEmpty) {
      errors['environment_project'] = 'Enter a project or repository.';
    }
    final keys = <String>{};
    for (final variable in _variables) {
      if (!RegExp(r'^[A-Za-z_][A-Za-z0-9_]*$').hasMatch(variable.key)) {
        errors['environment_variables'] =
            'Variable names must use shell identifier syntax.';
      } else if (!keys.add(variable.key)) {
        errors['environment_variables'] = 'Variable names must be unique.';
      }
      if (variable.existing &&
          variable.dirty &&
          variable.hasStoredValue &&
          variable.value.isEmpty) {
        errors['environment_variables'] = 'Re-enter a stored secret before renaming it or changing its protection.';
      }
    }
    final projectId = _metadataId('environment_project');
    final scopeId = _metadataId('environment_scope');
    final sourceId = _metadataId('environment_source');
    final updates = <Map<String, dynamic>>[
      structuredTextField(
        id: projectId,
        key: 'environment.project',
        label: 'Project / repository',
        role: 'environment_project',
        value: _project.text.trim(),
      ),
      structuredTextField(
        id: scopeId,
        key: 'environment.scope',
        label: 'Environment',
        role: 'environment_scope',
        value: _scope,
      ),
      structuredTextField(
        id: sourceId,
        key: 'environment.source',
        label: 'Source',
        role: 'environment_source',
        value: _source,
      ),
      for (final variable in _variables)
        if (!variable.existing || variable.dirty) variable.toField(),
    ];
    final sections = [
      EntrySectionView(
        id: 'environment_metadata',
        label: 'Environment',
        fieldIds: [projectId, scopeId, sourceId],
        semanticRole: 'environment_metadata',
      ),
      EntrySectionView(
        id: 'environment_variables',
        label: 'Variables',
        fieldIds: _variables
            .map((variable) => variable.id)
            .toList(growable: false),
        semanticRole: 'environment_variables',
      ),
    ];
    widget.draft
      ..customFields = jsonEncode(updates)
      ..sections = encodeStructuredSections(sections)
      ..removeFieldIds = List.unmodifiable(_removed)
      ..structuredErrors = errors;
  }

  void _addVariable() {
    setState(() {
      _variables.add(
        EnvVariableDraft(
          id: structuredId('field_env', _variables.length),
          key: 'NEW_VARIABLE',
          value: '',
        ),
      );
    });
    _sync();
  }

  void _removeVariable(EnvVariableDraft variable) {
    setState(() {
      _variables.remove(variable);
      if (variable.existing) _removed.add(variable.id);
    });
    _sync();
  }

  void _move(EnvVariableDraft variable, int offset) {
    final from = _variables.indexOf(variable);
    final to = from + offset;
    if (to < 0 || to >= _variables.length) return;
    setState(() {
      _variables.removeAt(from);
      _variables.insert(to, variable);
    });
    _sync();
  }

  void _parsePaste() => setState(() => _parseResult = parseDotEnv(_paste.text));

  Future<void> _applyPaste({required bool replace}) async {
    final parsed = parseDotEnv(_paste.text);
    setState(() => _parseResult = parsed);
    if (!parsed.valid) return;
    if (replace && _variables.isNotEmpty) {
      final accepted = await confirm(
        context: context,
        title: 'Replace all variables?',
        message:
            '${_variables.length} existing variables will be removed or replaced.',
        confirmLabel: 'Replace all',
        destructive: true,
      );
      if (!accepted || !mounted) return;
    }
    setState(() {
      if (replace) {
        _removed.addAll(
          _variables.where((item) => item.existing).map((item) => item.id),
        );
        _variables.clear();
      }
      for (final incoming in parsed.variables) {
        final existing = _variables
            .where((item) => item.key == incoming.key)
            .firstOrNull;
        if (existing == null) {
          _variables.add(incoming);
        } else {
          existing
            ..value = incoming.value
            ..dirty = true;
        }
      }
      _paste.clear();
      _pasteMode = false;
    });
    _sync();
  }

  @override
  Widget build(BuildContext context) => Column(
    crossAxisAlignment: CrossAxisAlignment.stretch,
    children: [
      const SizedBox(height: 18),
      const SectionLabel('Environment'),
      const SizedBox(height: 8),
      FTextField(
        key: const ValueKey('environment-project'),
        label: const Text('Project / repository'),
        error: widget.draft.structuredErrors['environment_project'] == null
            ? null
            : Text(widget.draft.structuredErrors['environment_project']!),
        control: FTextFieldControl.managed(
          controller: _project,
          onChange: (_) => _changed(),
        ),
      ),
      const SizedBox(height: 10),
      FSelect<String>(
        label: const Text('Environment'),
        items: const {
          'Local': 'local',
          'Development': 'development',
          'Test': 'test',
          'Staging': 'staging',
          'Production': 'production',
          'Other': 'other',
        },
        control: FSelectControl.lifted(
          value: _scope,
          onChange: (value) {
            setState(() => _scope = value ?? 'development');
            _sync();
          },
        ),
      ),
      const SizedBox(height: 10),
      FSelect<String>(
        label: const Text('Source'),
        items: const {
          '.env': 'dotenv',
          'GitHub Actions': 'github_actions',
          'GitLab CI/CD': 'gitlab_ci',
          'Docker / Compose': 'docker',
          'Kubernetes': 'kubernetes',
          'Other': 'other',
        },
        control: FSelectControl.lifted(
          value: _source,
          onChange: (value) {
            setState(() => _source = value ?? 'dotenv');
            _sync();
          },
        ),
      ),
      const SizedBox(height: 18),
      Row(
        children: [
          const Expanded(child: SectionLabel('Variables')),
          FButton(
            size: FButtonSizeVariant.xs,
            variant: _pasteMode
                ? FButtonVariant.outline
                : FButtonVariant.primary,
            onPress: () => setState(() => _pasteMode = false),
            child: const Text('Fields'),
          ),
          const SizedBox(width: 6),
          FButton(
            size: FButtonSizeVariant.xs,
            variant: _pasteMode
                ? FButtonVariant.primary
                : FButtonVariant.outline,
            onPress: () => setState(() => _pasteMode = true),
            child: const Text('Paste .env'),
          ),
        ],
      ),
      const SizedBox(height: 8),
      if (_pasteMode) ...[
        FTextField.multiline(
          key: const ValueKey('environment-paste'),
          label: const Text('.env content'),
          minLines: 7,
          maxLines: 16,
          control: FTextFieldControl.managed(
            controller: _paste,
            onChange: (_) => _parsePaste(),
          ),
        ),
        if (_parseResult case final result?) ...[
          const SizedBox(height: 6),
          Text(
            result.valid
                ? '${result.variables.length} variables · ${result.ignoredComments} comments and ${result.ignoredBlankLines} blank lines will be normalized.'
                : result.issues
                      .map((issue) => 'Line ${issue.line}: ${issue.message}')
                      .join('\n'),
          ),
        ],
        const SizedBox(height: 8),
        Row(
          mainAxisAlignment: MainAxisAlignment.end,
          children: [
            FButton(
              variant: FButtonVariant.outline,
              onPress: () => _applyPaste(replace: true),
              child: const Text('Replace all'),
            ),
            const SizedBox(width: 8),
            FButton(
              onPress: () => _applyPaste(replace: false),
              child: const Text('Merge'),
            ),
          ],
        ),
      ] else ...[
        if (widget.draft.structuredErrors['environment_variables']
            case final error?)
          Text(
            error,
            style: TextStyle(color: context.theme.colors.destructive),
          ),
        for (final (index, variable) in _variables.indexed)
          _EnvironmentVariableRow(
            key: ValueKey(variable.id),
            variable: variable,
            canMoveUp: index > 0,
            canMoveDown: index < _variables.length - 1,
            onChanged: _sync,
            onRemove: () => _removeVariable(variable),
            onMoveUp: () => _move(variable, -1),
            onMoveDown: () => _move(variable, 1),
          ),
        const SizedBox(height: 8),
        FButton(
          variant: FButtonVariant.outline,
          onPress: _addVariable,
          child: const Text('Add variable'),
        ),
      ],
    ],
  );
}

class _EnvironmentVariableRow extends StatefulWidget {
  const _EnvironmentVariableRow({
    required this.variable,
    required this.canMoveUp,
    required this.canMoveDown,
    required this.onChanged,
    required this.onRemove,
    required this.onMoveUp,
    required this.onMoveDown,
    super.key,
  });

  final EnvVariableDraft variable;
  final bool canMoveUp;
  final bool canMoveDown;
  final VoidCallback onChanged;
  final VoidCallback onRemove;
  final VoidCallback onMoveUp;
  final VoidCallback onMoveDown;

  @override
  State<_EnvironmentVariableRow> createState() =>
      _EnvironmentVariableRowState();
}

class _EnvironmentVariableRowState extends State<_EnvironmentVariableRow> {
  late final _key = TextEditingController(text: widget.variable.key);
  late final _value = TextEditingController(text: widget.variable.value);

  @override
  void dispose() {
    _key.dispose();
    _value
      ..clear()
      ..dispose();
    super.dispose();
  }

  void _sync() {
    widget.variable
      ..key = _key.text.trim()
      ..value = _value.text
      ..dirty = true;
    widget.onChanged();
  }

  @override
  Widget build(BuildContext context) => Padding(
    padding: const EdgeInsets.only(bottom: 10),
    child: Row(
      crossAxisAlignment: CrossAxisAlignment.end,
      children: [
        Expanded(
          flex: 2,
          child: FTextField(
            label: const Text('Name'),
            control: FTextFieldControl.managed(
              controller: _key,
              onChange: (_) => _sync(),
            ),
          ),
        ),
        const SizedBox(width: 8),
        Expanded(
          flex: 3,
          child: FTextField(
            label: Text(
              widget.variable.hasStoredValue && _value.text.isEmpty
                  ? 'Value (stored; blank keeps it)'
                  : 'Value',
            ),
            obscureText: widget.variable.secret,
            control: FTextFieldControl.managed(
              controller: _value,
              onChange: (_) => _sync(),
            ),
          ),
        ),
        const SizedBox(width: 8),
        FCheckbox(
          label: const Text('Secret'),
          value: widget.variable.secret,
          onChange: (value) {
            setState(() {
              widget.variable
                ..secret = value
                ..dirty = true;
            });
            widget.onChanged();
          },
        ),
        IconButton(
          onPressed: widget.canMoveUp ? widget.onMoveUp : null,
          icon: const Icon(FLucideIcons.arrowUp, size: 16),
        ),
        IconButton(
          onPressed: widget.canMoveDown ? widget.onMoveDown : null,
          icon: const Icon(FLucideIcons.arrowDown, size: 16),
        ),
        IconButton(
          onPressed: widget.onRemove,
          icon: const Icon(FLucideIcons.trash2, size: 16),
        ),
      ],
    ),
  );
}

class SshServerTemplateEditor extends StatefulWidget {
  const SshServerTemplateEditor({
    required this.app,
    required this.draft,
    this.detail,
    super.key,
  });

  final AppController app;
  final EntryDraft draft;
  final EntryDetailView? detail;

  @override
  State<SshServerTemplateEditor> createState() =>
      _SshServerTemplateEditorState();
}

class _SshEndpointDraft {
  _SshEndpointDraft({required this.id, this.existing = false});

  final String id;
  final bool existing;
  final fields = <String, String>{};
  final fieldIds = <String, String>{};
  final storedRoles = <String>{};
  String name = '';
  String alias = '';
  String host = '';
  String port = '22';
  String username = '';
  String connectVia = '';
  String authMode = 'ssh_agent';
  String password = '';
  String passphrase = '';
  String sudoMode = 'none';
  String sudoPassword = '';
  String fingerprint = '';
}

class _SshForwardDraft {
  _SshForwardDraft({required this.id, this.existing = false});
  final String id;
  final bool existing;
  final fieldIds = <String, String>{};
  String endpointId = '';
  String type = 'local';
  String bindAddress = '127.0.0.1';
  String bindPort = '';
  String destinationHost = '';
  String destinationPort = '';
}

class _SshServerTemplateEditorState extends State<SshServerTemplateEditor> {
  final _endpoints = <_SshEndpointDraft>[];
  final _forwards = <_SshForwardDraft>[];
  final _removed = <String>[];
  var _hydrated = false;
  var _discovering = false;
  List<SshPrivateKeyCandidate> _keys = const [];

  @override
  void initState() {
    super.initState();
    _hydrate();
    if (widget.draft.isNew) {
      _endpoints.add(_SshEndpointDraft(id: structuredId('ssh_endpoint')));
      WidgetsBinding.instance.addPostFrameCallback((_) => _sync());
    }
    unawaited(_discoverKeys());
  }

  @override
  void didUpdateWidget(covariant SshServerTemplateEditor oldWidget) {
    super.didUpdateWidget(oldWidget);
    _hydrate();
  }

  Future<void> _discoverKeys() async {
    if (_discovering) return;
    setState(() => _discovering = true);
    try {
      final keys = await widget.app.adapter.discoverSshPrivateKeys();
      if (mounted) setState(() => _keys = keys);
    } catch (_) {
      // Manual selection remains available on platforms without discovery.
    } finally {
      if (mounted) setState(() => _discovering = false);
    }
  }

  void _hydrate() {
    if (_hydrated || widget.draft.isNew || widget.detail == null) return;
    final detail = widget.detail!;
    for (final section in detail.sections.where(
      (item) => item.semanticRole == 'ssh_endpoint',
    )) {
      final endpoint = _SshEndpointDraft(id: section.id, existing: true);
      final fields = fieldsByRole(section, detail);
      String value(String role, [String fallback = '']) {
        final field = fields[role];
        if (field == null) return fallback;
        endpoint.fieldIds[role] = field.id;
        if (field.hasValue) endpoint.storedRoles.add(role);
        return entryFieldText(field) ?? fallback;
      }

      endpoint
        ..name = value('ssh_display_name')
        ..alias = value('ssh_alias')
        ..host = value('ssh_host')
        ..port = value('ssh_port', '22')
        ..username = value('ssh_username')
        ..connectVia = value('ssh_connect_via')
        ..authMode = value('ssh_auth_mode', 'ssh_agent')
        ..sudoMode = value('ssh_sudo_mode', 'none')
        ..fingerprint = value('ssh_host_fingerprint');
      value('ssh_password');
      value('ssh_private_key_passphrase');
      value('ssh_sudo_password');
      _endpoints.add(endpoint);
    }
    for (final section in detail.sections.where(
      (item) => item.semanticRole == 'ssh_forward',
    )) {
      final forward = _SshForwardDraft(id: section.id, existing: true);
      final fields = fieldsByRole(section, detail);
      String value(String role, [String fallback = '']) {
        final field = fields[role];
        if (field != null) forward.fieldIds[role] = field.id;
        return field == null ? fallback : entryFieldText(field) ?? fallback;
      }

      forward
        ..endpointId = value('ssh_forward_endpoint')
        ..type = value('ssh_forward_type', 'local')
        ..bindAddress = value('ssh_bind_address', '127.0.0.1')
        ..bindPort = value('ssh_bind_port')
        ..destinationHost = value('ssh_destination_host')
        ..destinationPort = value('ssh_destination_port');
      _forwards.add(forward);
    }
    _hydrated = true;
  }

  String _fieldId(Map<String, String> ids, String role) =>
      ids.putIfAbsent(role, () => structuredId('field_ssh'));

  Map<String, dynamic> _field(
    String sectionId,
    Map<String, String> ids,
    String role,
    String value, {
    bool secret = false,
  }) => structuredTextField(
    id: _fieldId(ids, role),
    key: 'ssh.$sectionId.${role.substring(4)}',
    label: role.substring(4).replaceAll('_', ' '),
    role: role,
    value: value,
    secret: secret,
  );

  void _sync() {
    final errors = <String, String>{};
    final removals = <String>{..._removed};
    final aliases = <String>{};
    final endpointIds = _endpoints.map((endpoint) => endpoint.id).toSet();
    for (final endpoint in _endpoints) {
      if (endpoint.name.trim().isEmpty || endpoint.host.trim().isEmpty) {
        errors['ssh_endpoints'] = 'Every server needs a name and host.';
      }
      if (!RegExp(r'^[A-Za-z0-9._-]+$').hasMatch(endpoint.alias) ||
          !aliases.add(endpoint.alias)) {
        errors['ssh_endpoints'] = 'SSH aliases must be unique and contain only letters, digits, dot, underscore, or hyphen.';
      }
      final port = int.tryParse(endpoint.port);
      if (port == null || port < 1 || port > 65535) {
        errors['ssh_endpoints'] = 'SSH ports must be in 1..65535.';
      }
      if (endpoint.connectVia.isNotEmpty &&
          !endpointIds.contains(endpoint.connectVia)) {
        errors['ssh_endpoints'] = 'A selected jump host no longer exists.';
      }
      if (endpoint.authMode == 'password' &&
          endpoint.password.isEmpty &&
          !endpoint.storedRoles.contains('ssh_password')) {
        errors['ssh_endpoints'] =
            'Password authentication requires a password.';
      }
      if (endpoint.sudoMode == 'same_as_ssh_password' &&
          endpoint.authMode != 'password') {
        errors['ssh_endpoints'] = 'Sudo can reuse the SSH password only with password authentication.';
      }
      if (endpoint.sudoMode == 'separate_password' &&
          endpoint.sudoPassword.isEmpty &&
          !endpoint.storedRoles.contains('ssh_sudo_password')) {
        errors['ssh_endpoints'] =
            'Separate sudo mode requires a sudo password.';
      }
    }
    for (final endpoint in _endpoints) {
      final seen = <String>{};
      var cursor = endpoint;
      while (cursor.connectVia.isNotEmpty) {
        if (!seen.add(cursor.id)) {
          errors['ssh_endpoints'] = 'Jump host chains cannot contain a cycle.';
          break;
        }
        final next = _endpoints
            .where((item) => item.id == cursor.connectVia)
            .firstOrNull;
        if (next == null) break;
        cursor = next;
      }
    }
    final fields = <Map<String, dynamic>>[];
    final sections = <EntrySectionView>[];
    for (final endpoint in _endpoints) {
      final endpointFields = <Map<String, dynamic>>[
        _field(
          endpoint.id,
          endpoint.fieldIds,
          'ssh_display_name',
          endpoint.name,
        ),
        _field(endpoint.id, endpoint.fieldIds, 'ssh_alias', endpoint.alias),
        _field(endpoint.id, endpoint.fieldIds, 'ssh_host', endpoint.host),
        _field(endpoint.id, endpoint.fieldIds, 'ssh_port', endpoint.port),
        _field(
          endpoint.id,
          endpoint.fieldIds,
          'ssh_username',
          endpoint.username,
        ),
        _field(
          endpoint.id,
          endpoint.fieldIds,
          'ssh_connect_via',
          endpoint.connectVia,
        ),
        _field(
          endpoint.id,
          endpoint.fieldIds,
          'ssh_auth_mode',
          endpoint.authMode,
        ),
        _field(
          endpoint.id,
          endpoint.fieldIds,
          'ssh_sudo_mode',
          endpoint.sudoMode,
        ),
        _field(
          endpoint.id,
          endpoint.fieldIds,
          'ssh_host_fingerprint',
          endpoint.fingerprint,
        ),
        if (endpoint.password.isNotEmpty ||
            (!endpoint.existing && endpoint.authMode == 'password'))
          _field(
            endpoint.id,
            endpoint.fieldIds,
            'ssh_password',
            endpoint.password,
            secret: true,
          ),
        if (endpoint.passphrase.isNotEmpty)
          _field(
            endpoint.id,
            endpoint.fieldIds,
            'ssh_private_key_passphrase',
            endpoint.passphrase,
            secret: true,
          ),
        if (endpoint.sudoPassword.isNotEmpty ||
            (!endpoint.existing && endpoint.sudoMode == 'separate_password'))
          _field(
            endpoint.id,
            endpoint.fieldIds,
            'ssh_sudo_password',
            endpoint.sudoPassword,
            secret: true,
          ),
      ];
      if (endpoint.existing && endpoint.authMode != 'password') {
        final id = endpoint.fieldIds['ssh_password'];
        if (id != null) removals.add(id);
      }
      if (endpoint.existing && endpoint.authMode != 'private_key') {
        final id = endpoint.fieldIds['ssh_private_key_passphrase'];
        if (id != null) removals.add(id);
      }
      if (endpoint.existing && endpoint.sudoMode != 'separate_password') {
        final id = endpoint.fieldIds['ssh_sudo_password'];
        if (id != null) removals.add(id);
      }
      fields.addAll(endpointFields);
      const requiredRoles = [
        'ssh_display_name',
        'ssh_alias',
        'ssh_host',
        'ssh_port',
        'ssh_username',
        'ssh_connect_via',
        'ssh_auth_mode',
        'ssh_sudo_mode',
        'ssh_host_fingerprint',
      ];
      final activeRoles = <String>[
        ...requiredRoles,
        if (endpoint.authMode == 'password' &&
            endpoint.fieldIds.containsKey('ssh_password'))
          'ssh_password',
        if (endpoint.authMode == 'private_key' &&
            endpoint.fieldIds.containsKey('ssh_private_key_passphrase'))
          'ssh_private_key_passphrase',
        if (endpoint.sudoMode == 'separate_password' &&
            endpoint.fieldIds.containsKey('ssh_sudo_password'))
          'ssh_sudo_password',
      ];
      sections.add(
        EntrySectionView(
          id: endpoint.id,
          label: endpoint.name.trim().isEmpty
              ? 'SSH server'
              : endpoint.name.trim(),
          fieldIds: activeRoles
              .map((role) => endpoint.fieldIds[role]!)
              .toList(growable: false),
          semanticRole: 'ssh_endpoint',
        ),
      );
    }
    for (final forward in _forwards) {
      final forwardFields = [
        _field(
          forward.id,
          forward.fieldIds,
          'ssh_forward_endpoint',
          forward.endpointId,
        ),
        _field(forward.id, forward.fieldIds, 'ssh_forward_type', forward.type),
        _field(
          forward.id,
          forward.fieldIds,
          'ssh_bind_address',
          forward.bindAddress,
        ),
        _field(forward.id, forward.fieldIds, 'ssh_bind_port', forward.bindPort),
        _field(
          forward.id,
          forward.fieldIds,
          'ssh_destination_host',
          forward.destinationHost,
        ),
        _field(
          forward.id,
          forward.fieldIds,
          'ssh_destination_port',
          forward.destinationPort,
        ),
      ];
      fields.addAll(forwardFields);
      final bindPort = int.tryParse(forward.bindPort);
      final destinationPort = int.tryParse(forward.destinationPort);
      if (!endpointIds.contains(forward.endpointId) ||
          bindPort == null ||
          bindPort < 1 ||
          bindPort > 65535 ||
          (forward.type != 'dynamic' &&
              (forward.destinationHost.isEmpty ||
                  destinationPort == null ||
                  destinationPort < 1 ||
                  destinationPort > 65535))) {
        errors['ssh_forwards'] =
            'Every tunnel needs a valid server, bind port, and destination.';
      }
      sections.add(
        EntrySectionView(
          id: forward.id,
          label: '${forward.type} tunnel',
          fieldIds: forward.fieldIds.values.toList(growable: false),
          semanticRole: 'ssh_forward',
        ),
      );
    }
    widget.draft
      ..customFields = jsonEncode(fields)
      ..sections = encodeStructuredSections(sections)
      ..removeFieldIds = List.unmodifiable(removals)
      ..structuredErrors = errors;
  }

  void _addEndpoint() {
    setState(
      () => _endpoints.add(
        _SshEndpointDraft(id: structuredId('ssh_endpoint', _endpoints.length)),
      ),
    );
    _sync();
  }

  void _removeEndpoint(_SshEndpointDraft endpoint) {
    setState(() {
      _endpoints.remove(endpoint);
      widget.draft.sshBindingsToClear = {
        ...widget.draft.sshBindingsToClear,
        endpoint.id,
      }.toList(growable: false);
      if (endpoint.existing) _removed.addAll(endpoint.fieldIds.values);
      final removedForwards = _forwards
          .where((forward) => forward.endpointId == endpoint.id)
          .toList();
      for (final forward in removedForwards) {
        if (forward.existing) _removed.addAll(forward.fieldIds.values);
      }
      _forwards.removeWhere((forward) => forward.endpointId == endpoint.id);
      for (final item in _endpoints.where(
        (item) => item.connectVia == endpoint.id,
      )) {
        item.connectVia = '';
      }
    });
    _sync();
  }

  void _moveEndpoint(_SshEndpointDraft endpoint, int offset) {
    final from = _endpoints.indexOf(endpoint);
    final to = from + offset;
    if (to < 0 || to >= _endpoints.length) return;
    setState(() {
      _endpoints.removeAt(from);
      _endpoints.insert(to, endpoint);
    });
    _sync();
  }

  void _addForward() {
    setState(() {
      _forwards.add(
        _SshForwardDraft(id: structuredId('ssh_forward', _forwards.length))
          ..endpointId = _endpoints.firstOrNull?.id ?? '',
      );
    });
    _sync();
  }

  void _removeForward(_SshForwardDraft forward) {
    setState(() {
      _forwards.remove(forward);
      if (forward.existing) _removed.addAll(forward.fieldIds.values);
    });
    _sync();
  }

  Future<void> _chooseKey(_SshEndpointDraft endpoint) async {
    final path = await widget.app.adapter.selectSshPrivateKey();
    if (path == null || !mounted) return;
    setState(() {
      widget.draft.sshKeyBindings = {
        ...widget.draft.sshKeyBindings,
        endpoint.id: path,
      };
    });
  }

  String? _binding(_SshEndpointDraft endpoint) =>
      widget.draft.sshKeyBindings[endpoint.id] ??
      (widget.draft.entryId == null
          ? null
          : widget.app.sshKeyBinding(widget.draft.entryId!, endpoint.id));

  @override
  Widget build(BuildContext context) => Column(
    crossAxisAlignment: CrossAxisAlignment.stretch,
    children: [
      const SizedBox(height: 18),
      Row(
        children: [
          const Expanded(child: SectionLabel('SSH servers')),
          FButton(
            size: FButtonSizeVariant.xs,
            variant: FButtonVariant.outline,
            onPress: _addEndpoint,
            child: const Text('Add server'),
          ),
        ],
      ),
      if (widget.draft.structuredErrors['ssh_endpoints'] case final error?)
        Padding(
          padding: const EdgeInsets.only(top: 8),
          child: Text(
            error,
            style: TextStyle(color: context.theme.colors.destructive),
          ),
        ),
      for (final (index, endpoint) in _endpoints.indexed)
        _SshEndpointCard(
          key: ValueKey(endpoint.id),
          endpoint: endpoint,
          endpoints: _endpoints,
          keyCandidates: _keys,
          discovering: _discovering,
          binding: _binding(endpoint),
          onBinding: (path) => setState(() {
            widget.draft
              ..sshKeyBindings = {
                ...widget.draft.sshKeyBindings,
                endpoint.id: path,
              }
              ..sshBindingsToClear = widget.draft.sshBindingsToClear
                  .where((id) => id != endpoint.id)
                  .toList(growable: false);
          }),
          onKeepBinding: () => setState(() {
            widget.draft.sshBindingsToClear = widget.draft.sshBindingsToClear
                .where((id) => id != endpoint.id)
                .toList(growable: false);
          }),
          onClearBinding: () => setState(() {
            final bindings = {...widget.draft.sshKeyBindings}
              ..remove(endpoint.id);
            widget.draft
              ..sshKeyBindings = bindings
              ..sshBindingsToClear = {
                ...widget.draft.sshBindingsToClear,
                endpoint.id,
              }.toList(growable: false);
          }),
          onChooseKey: () => _chooseKey(endpoint),
          onChanged: _sync,
          onRemove: _endpoints.length > 1
              ? () => _removeEndpoint(endpoint)
              : null,
          onMoveUp: index > 0 ? () => _moveEndpoint(endpoint, -1) : null,
          onMoveDown: index < _endpoints.length - 1
              ? () => _moveEndpoint(endpoint, 1)
              : null,
        ),
      const SizedBox(height: 18),
      Row(
        children: [
          const Expanded(child: SectionLabel('SSH tunnels')),
          FButton(
            size: FButtonSizeVariant.xs,
            variant: FButtonVariant.outline,
            onPress: _endpoints.isEmpty ? null : _addForward,
            child: const Text('Add tunnel'),
          ),
        ],
      ),
      if (widget.draft.structuredErrors['ssh_forwards'] case final error?)
        Padding(
          padding: const EdgeInsets.only(top: 8),
          child: Text(
            error,
            style: TextStyle(color: context.theme.colors.destructive),
          ),
        ),
      for (final forward in _forwards)
        _SshForwardCard(
          key: ValueKey(forward.id),
          forward: forward,
          endpoints: _endpoints,
          onChanged: _sync,
          onRemove: () => _removeForward(forward),
        ),
    ],
  );
}

class _SshEndpointCard extends StatefulWidget {
  const _SshEndpointCard({
    required this.endpoint,
    required this.endpoints,
    required this.keyCandidates,
    required this.discovering,
    required this.binding,
    required this.onBinding,
    required this.onKeepBinding,
    required this.onClearBinding,
    required this.onChooseKey,
    required this.onChanged,
    this.onRemove,
    this.onMoveUp,
    this.onMoveDown,
    super.key,
  });

  final _SshEndpointDraft endpoint;
  final List<_SshEndpointDraft> endpoints;
  final List<SshPrivateKeyCandidate> keyCandidates;
  final bool discovering;
  final String? binding;
  final ValueChanged<String> onBinding;
  final VoidCallback onKeepBinding;
  final VoidCallback onClearBinding;
  final VoidCallback onChooseKey;
  final VoidCallback onChanged;
  final VoidCallback? onRemove;
  final VoidCallback? onMoveUp;
  final VoidCallback? onMoveDown;

  @override
  State<_SshEndpointCard> createState() => _SshEndpointCardState();
}

class _SshEndpointCardState extends State<_SshEndpointCard> {
  late final _keyPath = TextEditingController(text: widget.binding ?? '');
  late final Map<String, TextEditingController> _controllers = {
    'name': TextEditingController(text: widget.endpoint.name),
    'alias': TextEditingController(text: widget.endpoint.alias),
    'host': TextEditingController(text: widget.endpoint.host),
    'port': TextEditingController(text: widget.endpoint.port),
    'username': TextEditingController(text: widget.endpoint.username),
    'password': TextEditingController(),
    'passphrase': TextEditingController(),
    'sudoPassword': TextEditingController(),
    'fingerprint': TextEditingController(text: widget.endpoint.fingerprint),
  };

  @override
  void didUpdateWidget(covariant _SshEndpointCard oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (widget.binding != oldWidget.binding &&
        _keyPath.text != (widget.binding ?? '')) {
      _keyPath.text = widget.binding ?? '';
    }
  }

  @override
  void dispose() {
    for (final controller in _controllers.values) {
      controller
        ..clear()
        ..dispose();
    }
    _keyPath.dispose();
    super.dispose();
  }

  void _sync() {
    widget.endpoint
      ..name = _controllers['name']!.text
      ..alias = _controllers['alias']!.text.trim()
      ..host = _controllers['host']!.text.trim()
      ..port = _controllers['port']!.text.trim()
      ..username = _controllers['username']!.text.trim()
      ..password = _controllers['password']!.text
      ..passphrase = _controllers['passphrase']!.text
      ..sudoPassword = _controllers['sudoPassword']!.text
      ..fingerprint = _controllers['fingerprint']!.text.trim();
    widget.onChanged();
  }

  FTextField _text(
    String name,
    String label, {
    bool secret = false,
    String? description,
  }) => FTextField(
    label: Text(label),
    description: description == null ? null : Text(description),
    obscureText: secret,
    control: FTextFieldControl.managed(
      controller: _controllers[name]!,
      onChange: (_) => _sync(),
    ),
  );

  @override
  Widget build(BuildContext context) {
    final endpoint = widget.endpoint;
    return FCard(
      child: Padding(
        padding: const EdgeInsets.all(12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Row(
              children: [
                Expanded(
                  child: Text(
                    endpoint.name.isEmpty ? 'SSH server' : endpoint.name,
                  ),
                ),
                IconButton(
                  onPressed: widget.onMoveUp,
                  icon: const Icon(FLucideIcons.arrowUp, size: 16),
                ),
                IconButton(
                  onPressed: widget.onMoveDown,
                  icon: const Icon(FLucideIcons.arrowDown, size: 16),
                ),
                IconButton(
                  onPressed: widget.onRemove,
                  icon: const Icon(FLucideIcons.trash2, size: 16),
                ),
              ],
            ),
            const SizedBox(height: 8),
            _text('name', 'Display name'),
            const SizedBox(height: 8),
            _text('alias', 'SSH alias'),
            const SizedBox(height: 8),
            Row(
              children: [
                Expanded(flex: 3, child: _text('host', 'Host / IP')),
                const SizedBox(width: 8),
                Expanded(child: _text('port', 'Port')),
              ],
            ),
            const SizedBox(height: 8),
            _text('username', 'Username'),
            const SizedBox(height: 8),
            SearchableSelect<String>(
              label: const Text('Connect via'),
              clearable: true,
              hint: 'Direct connection',
              options: [
                for (final candidate in widget.endpoints.where(
                  (item) => item.id != endpoint.id,
                ))
                  SearchSelectOption(
                    value: candidate.id,
                    label: candidate.name.isEmpty
                        ? candidate.alias
                        : candidate.name,
                    searchTerms: [candidate.alias, candidate.host],
                  ),
              ],
              value: endpoint.connectVia.isEmpty ? null : endpoint.connectVia,
              onChange: (value) {
                setState(() => endpoint.connectVia = value ?? '');
                widget.onChanged();
              },
            ),
            const SizedBox(height: 8),
            FSelect<String>(
              label: const Text('Authentication'),
              items: const {
                'SSH agent / system default': 'ssh_agent',
                'Private key': 'private_key',
                'Password': 'password',
              },
              control: FSelectControl.lifted(
                value: endpoint.authMode,
                onChange: (value) {
                  final next = value ?? 'ssh_agent';
                  if (endpoint.authMode == 'private_key' &&
                      next != 'private_key') {
                    widget.onClearBinding();
                  } else if (next == 'private_key') {
                    widget.onKeepBinding();
                  }
                  setState(() => endpoint.authMode = next);
                  widget.onChanged();
                },
              ),
            ),
            if (endpoint.authMode == 'password') ...[
              const SizedBox(height: 8),
              _text(
                'password',
                'SSH password',
                secret: true,
                description: endpoint.storedRoles.contains('ssh_password')
                    ? 'Stored; blank keeps current password.'
                    : null,
              ),
            ],
            if (endpoint.authMode == 'private_key') ...[
              const SizedBox(height: 8),
              FTextField(
                label: const Text('Private key path on this device'),
                description: const Text(
                  'Saved locally only; never synced into the vault.',
                ),
                control: FTextFieldControl.managed(
                  controller: _keyPath,
                  onChange: (value) => widget.onBinding(value.text.trim()),
                ),
              ),
              const SizedBox(height: 8),
              SearchableSelect<String>(
                label: const Text('Private key on this device'),
                hint: widget.discovering
                    ? 'Scanning ~/.ssh…'
                    : 'Select a private key',
                options: [
                  for (final key in widget.keyCandidates)
                    SearchSelectOption(
                      value: key.path,
                      label: key.name,
                      subtitle: key.path,
                    ),
                ],
                value: widget.binding,
                onChange: (value) {
                  if (value != null) widget.onBinding(value);
                },
              ),
              const SizedBox(height: 6),
              Align(
                alignment: Alignment.centerRight,
                child: FButton(
                  size: FButtonSizeVariant.xs,
                  variant: FButtonVariant.outline,
                  onPress: widget.onChooseKey,
                  child: const Text('Choose file…'),
                ),
              ),
              const SizedBox(height: 8),
              _text(
                'passphrase',
                'Key passphrase (optional)',
                secret: true,
                description:
                    endpoint.storedRoles.contains('ssh_private_key_passphrase')
                    ? 'Stored; blank keeps current passphrase.'
                    : null,
              ),
            ],
            const SizedBox(height: 8),
            FSelect<String>(
              label: const Text('Sudo'),
              items: const {
                'None': 'none',
                'Passwordless': 'passwordless',
                'Same as SSH password': 'same_as_ssh_password',
                'Separate password': 'separate_password',
              },
              control: FSelectControl.lifted(
                value: endpoint.sudoMode,
                onChange: (value) {
                  setState(() => endpoint.sudoMode = value ?? 'none');
                  widget.onChanged();
                },
              ),
            ),
            if (endpoint.sudoMode == 'separate_password') ...[
              const SizedBox(height: 8),
              _text(
                'sudoPassword',
                'Sudo password',
                secret: true,
                description: endpoint.storedRoles.contains('ssh_sudo_password')
                    ? 'Stored; blank keeps current password.'
                    : null,
              ),
            ],
            const SizedBox(height: 8),
            _text('fingerprint', 'Host key fingerprint (optional)'),
          ],
        ),
      ),
    );
  }
}

class _SshForwardCard extends StatefulWidget {
  const _SshForwardCard({
    required this.forward,
    required this.endpoints,
    required this.onChanged,
    required this.onRemove,
    super.key,
  });
  final _SshForwardDraft forward;
  final List<_SshEndpointDraft> endpoints;
  final VoidCallback onChanged;
  final VoidCallback onRemove;

  @override
  State<_SshForwardCard> createState() => _SshForwardCardState();
}

class _SshForwardCardState extends State<_SshForwardCard> {
  late final _bindAddress = TextEditingController(
    text: widget.forward.bindAddress,
  );
  late final _bindPort = TextEditingController(text: widget.forward.bindPort);
  late final _destinationHost = TextEditingController(
    text: widget.forward.destinationHost,
  );
  late final _destinationPort = TextEditingController(
    text: widget.forward.destinationPort,
  );

  @override
  void dispose() {
    _bindAddress.dispose();
    _bindPort.dispose();
    _destinationHost.dispose();
    _destinationPort.dispose();
    super.dispose();
  }

  void _sync() {
    widget.forward
      ..bindAddress = _bindAddress.text.trim()
      ..bindPort = _bindPort.text.trim()
      ..destinationHost = _destinationHost.text.trim()
      ..destinationPort = _destinationPort.text.trim();
    widget.onChanged();
  }

  FTextField _text(TextEditingController controller, String label) =>
      FTextField(
        label: Text(label),
        control: FTextFieldControl.managed(
          controller: controller,
          onChange: (_) => _sync(),
        ),
      );

  @override
  Widget build(BuildContext context) => FCard(
    child: Padding(
      padding: const EdgeInsets.all(12),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Row(
            children: [
              const Expanded(child: Text('SSH tunnel')),
              IconButton(
                onPressed: widget.onRemove,
                icon: const Icon(FLucideIcons.trash2, size: 16),
              ),
            ],
          ),
          SearchableSelect<String>(
            label: const Text('Server'),
            options: [
              for (final endpoint in widget.endpoints)
                SearchSelectOption(
                  value: endpoint.id,
                  label: endpoint.name.isEmpty ? endpoint.alias : endpoint.name,
                ),
            ],
            value: widget.forward.endpointId,
            onChange: (value) {
              setState(() => widget.forward.endpointId = value ?? '');
              widget.onChanged();
            },
          ),
          const SizedBox(height: 8),
          FSelect<String>(
            label: const Text('Type'),
            items: const {
              'Local': 'local',
              'Remote': 'remote',
              'Dynamic SOCKS': 'dynamic',
            },
            control: FSelectControl.lifted(
              value: widget.forward.type,
              onChange: (value) {
                setState(() => widget.forward.type = value ?? 'local');
                widget.onChanged();
              },
            ),
          ),
          const SizedBox(height: 8),
          Row(
            children: [
              Expanded(flex: 2, child: _text(_bindAddress, 'Bind address')),
              const SizedBox(width: 8),
              Expanded(child: _text(_bindPort, 'Bind port')),
            ],
          ),
          if (widget.forward.type != 'dynamic') ...[
            const SizedBox(height: 8),
            Row(
              children: [
                Expanded(
                  flex: 2,
                  child: _text(_destinationHost, 'Destination host'),
                ),
                const SizedBox(width: 8),
                Expanded(child: _text(_destinationPort, 'Destination port')),
              ],
            ),
          ],
          if (const {
            '0.0.0.0',
            '::',
            '*',
          }.contains(_bindAddress.text.trim())) ...[
            const SizedBox(height: 6),
            Text(
              'Warning: this bind address may expose the tunnel publicly.',
              style: TextStyle(color: context.theme.colors.destructive),
            ),
          ],
        ],
      ),
    ),
  );
}
