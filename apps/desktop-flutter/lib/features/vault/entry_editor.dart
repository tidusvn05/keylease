import 'dart:async';
import 'dart:convert';

import 'package:forui/forui.dart';
import 'package:material_ui/material_ui.dart';

import '../../core/models/models.dart';
import '../../core/platform/security_adapter.dart';
import '../../core/state/app_controller.dart';
import '../../core/state/entry_draft.dart';
import '../../core/state/user_message.dart';
import '../../ui/components/keylease_dialog.dart';
import '../../ui/components/message_banner.dart';
import '../../ui/components/secret_field.dart';
import '../../ui/components/scroll_area.dart';
import '../../ui/components/searchable_select.dart';
import '../../ui/components/section_label.dart';
import '../../ui/tokens/keylease_tokens.dart';
import 'password_generator.dart';
import 'developer_template_editor.dart';
import 'template_guidance.dart';

/// Opens the draft-based editor.
///
/// The draft outlives a failed save: a rejected request leaves every typed
/// value in place so the user can fix one field and retry.
Future<void> openEntryEditor(
  BuildContext context,
  AppController app, {
  EntrySummary? existing,
}) async {
  if (existing == null) {
    app.vault.beginCreate();
  } else {
    app.vault.beginEdit(existing);
  }
  final split =
      MediaQuery.sizeOf(context).width >=
      KeyLeaseTokens.of(context).splitBreakpoint;
  if (split || !context.mounted) return;
  await Navigator.of(context).push(
    MaterialPageRoute<void>(
      builder: (context) => EntryEditorPane(
        app: app,
        onClosed: () => Navigator.of(context).pop(),
      ),
    ),
  );
  if (app.vault.activeDraft != null) app.vault.closeEditor();
}

Future<bool> confirmCloseEntryEditor(
  BuildContext context,
  AppController app,
) async {
  final draft = app.vault.activeDraft;
  if (draft == null) return true;
  if (draft.isDirty) {
    final discard = await confirm(
      context: context,
      title: 'Discard changes?',
      message: 'This item has unsaved changes. Discarding cannot be undone.',
      confirmLabel: 'Discard',
      destructive: true,
    );
    if (!discard) return false;
  }
  app.vault.closeEditor();
  return true;
}

/// Persistent right-hand workspace for both new and edited items.
class EntryEditorPane extends StatefulWidget {
  const EntryEditorPane({required this.app, this.onClosed, super.key});

  final AppController app;
  final VoidCallback? onClosed;

  @override
  State<EntryEditorPane> createState() => _EntryEditorPaneState();
}

class _EntryEditorPaneState extends State<EntryEditorPane> {
  final _editor = _EditorController();

  @override
  void dispose() {
    _editor.dispose();
    super.dispose();
  }

  void _close() {
    widget.app.vault.closeEditor();
    widget.onClosed?.call();
  }

  @override
  Widget build(BuildContext context) {
    final draft = widget.app.vault.activeDraft;
    if (draft == null) return const SizedBox.shrink();
    final tokens = KeyLeaseTokens.of(context);
    return SafeArea(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Padding(
            padding: EdgeInsets.all(tokens.gutter),
            child: Row(
              children: [
                if (widget.onClosed != null) ...[
                  IconAction(
                    label: 'Back',
                    icon: FLucideIcons.arrowLeft,
                    onPress: _editor.cancel,
                  ),
                  const SizedBox(width: 8),
                ],
                Expanded(
                  child: Text(
                    draft.isNew ? 'New item' : 'Edit item',
                    style: context.theme.typography.body.lg.copyWith(
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                ),
                _EditorActions(editor: _editor),
              ],
            ),
          ),
          const Divider(height: 1),
          Expanded(
            child: KeyLeaseScrollArea(
              padding: EdgeInsets.all(tokens.gutter * 1.25),
              children: [
                _EntryForm(
                  key: ValueKey('${draft.entryId}-${draft.hashCode}'),
                  app: widget.app,
                  draft: draft,
                  editor: _editor,
                  onFinished: _close,
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}

/// Bridges the form's state to the dialog's pinned action row.
class _EditorController extends ChangeNotifier {
  bool saving = false;
  Future<void> Function()? save;
  Future<void> Function()? cancel;

  void bind({
    required Future<void> Function() save,
    required Future<void> Function() cancel,
  }) {
    this.save = save;
    this.cancel = cancel;
    WidgetsBinding.instance.addPostFrameCallback((_) => notifyListeners());
  }

  void setSaving({required bool value}) {
    saving = value;
    notifyListeners();
  }
}

class _EditorActions extends StatelessWidget {
  const _EditorActions({required this.editor});

  final _EditorController editor;

  @override
  Widget build(BuildContext context) => ListenableBuilder(
    listenable: editor,
    builder: (context, _) => Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        FButton(
          variant: FButtonVariant.outline,
          onPress: editor.saving ? null : editor.cancel,
          child: const Text('Cancel'),
        ),
        const SizedBox(width: 8),
        FButton(
          key: const ValueKey('entry-save'),
          onPress: editor.saving ? null : editor.save,
          child: Text(editor.saving ? 'Saving…' : 'Save'),
        ),
      ],
    ),
  );
}

class _EntryForm extends StatefulWidget {
  const _EntryForm({
    required this.app,
    required this.draft,
    required this.editor,
    required this.onFinished,
    super.key,
  });

  final AppController app;
  final EntryDraft draft;
  final _EditorController editor;
  final VoidCallback onFinished;

  @override
  State<_EntryForm> createState() => _EntryFormState();
}

class _EntryFormState extends State<_EntryForm> {
  late final _title = TextEditingController(text: widget.draft.title);
  late final _username = TextEditingController(text: widget.draft.username);
  late final _url = TextEditingController(text: widget.draft.url);
  late final _password = TextEditingController(text: widget.draft.password);
  final _notes = TextEditingController();
  final _totp = TextEditingController();
  final _custom = TextEditingController();
  final _tags = TextEditingController();
  final Map<String, TextEditingController> _templateFields = {};
  final Map<String, String> _templateFieldOriginals = {};
  final Map<String, String> _templateFieldIds = {};

  Map<String, String> errors = const {};
  UserMessage? failure;
  VoidCallback? _failureAction;
  bool _passwordRevealed = false;
  bool _passwordCopied = false;
  bool _totpScanning = false;
  Timer? _passwordCopiedTimer;

  EntryDraft get draft => widget.draft;

  bool get _isDeveloperTemplate =>
      const {'core.environment', 'core.ssh_server'}.contains(draft.kind);

  String _groupBreadcrumb(VaultGroup group, List<VaultGroup> groups) {
    final names = <String>[group.name];
    final visited = <String>{group.id};
    var parentId = group.parentId;
    while (parentId != null && visited.add(parentId)) {
      final parent = groups
          .where((candidate) => candidate.id == parentId)
          .firstOrNull;
      if (parent == null) break;
      names.insert(0, parent.name);
      parentId = parent.parentId;
    }
    return names.join(' / ');
  }

  String _templateSection(TemplateDefinition template) {
    const essentials = {
      'core.prompt',
      'core.runbook',
      'core.environment',
      'core.ssh_server',
      'core.login',
      'core.api_credential',
      'core.database',
      'core.ssh_key',
    };
    if (essentials.contains(template.kind)) return 'Developer essentials';
    return switch (template.family) {
      'developer' => 'Developer',
      'common' => 'Common',
      'agent_knowledge' => 'Agent knowledge',
      'personal' => 'Personal',
      _ => 'Other',
    };
  }

  @override
  void initState() {
    super.initState();
    widget.editor.bind(save: _save, cancel: _cancel);
    for (final controller in [
      _title,
      _username,
      _url,
      _password,
      _notes,
      _totp,
      _custom,
      _tags,
    ]) {
      controller.addListener(_sync);
    }
    _hydrateTemplateFields();
  }

  @override
  void didUpdateWidget(covariant _EntryForm oldWidget) {
    super.didUpdateWidget(oldWidget);
    // Entry details can arrive after the editor has opened. Hydrate any fields
    // that have not been touched yet without overwriting the user's input.
    _hydrateTemplateFields();
  }

  @override
  void dispose() {
    _passwordCopiedTimer?.cancel();
    for (final controller in [
      _title,
      _username,
      _url,
      _password,
      _notes,
      _totp,
      _custom,
      _tags,
      ..._templateFields.values,
    ]) {
      controller.removeListener(_sync);
    }
    _title.dispose();
    _username.dispose();
    _url.dispose();
    _password
      ..clear()
      ..dispose();
    _notes
      ..clear()
      ..dispose();
    _totp
      ..clear()
      ..dispose();
    _custom
      ..clear()
      ..dispose();
    _tags.dispose();
    for (final controller in _templateFields.values) {
      controller
        ..clear()
        ..dispose();
    }
    super.dispose();
  }

  void _sync() {
    draft
      ..title = _title.text
      ..username = _username.text
      ..url = _url.text
      ..password = _password.text
      ..notes = _notes.text
      ..totp = _totp.text
      ..tags = _tags.text;
    if (!_isDeveloperTemplate) {
      draft.customFields = _templateFieldPayload() ?? _custom.text;
    }
  }

  TemplateDefinition? get _template {
    for (final template in widget.app.vault.templates) {
      if (template.kind == draft.kind) return template;
    }
    return _fallbackTemplate(draft.kind);
  }

  TemplateDefinition? _fallbackTemplate(String kind) {
    TemplateFieldDefinition field(
      String key,
      String label,
      String valueType,
      String role, {
      bool protected = false,
      String section = 'Details',
    }) => TemplateFieldDefinition(
      key: key,
      label: label,
      valueType: valueType,
      semanticRole: role,
      sensitivity: protected ? 'highly_sensitive' : 'private_metadata',
      protected: protected,
      section: section,
    );
    final fields = switch (kind) {
      'core.login' => [
        field('username', 'Username', 'text', 'username', section: 'Login'),
        field(
          'password',
          'Password',
          'concealed',
          'password',
          protected: true,
          section: 'Login',
        ),
        field('website', 'Website', 'url', 'website', section: 'Login'),
        field(
          'otp',
          'One-time password',
          'totp',
          'otp',
          protected: true,
          section: 'Login',
        ),
      ],
      'core.password' => [
        field('password', 'Password', 'concealed', 'password', protected: true),
        field('website', 'Website', 'url', 'website'),
      ],
      'core.api_credential' => [
        field('provider', 'Provider', 'text', 'provider'),
        field(
          'credential',
          'Credential',
          'concealed',
          'credential',
          protected: true,
        ),
        field('hostname', 'Host', 'url', 'host'),
      ],
      'core.secure_note' ||
      'core.generic' ||
      'core.prompt' ||
      'core.runbook' ||
      'core.note' => <TemplateFieldDefinition>[],
      _ => null,
    };
    if (fields == null) return null;
    return TemplateDefinition(
      kind: kind,
      label: kind.substring(5),
      family: 'other',
      markdownNotes: true,
      fields: fields,
    );
  }

  bool _isUsername(TemplateFieldDefinition field) =>
      field.key == 'username' || field.semanticRole == 'username';

  bool _isPassword(TemplateFieldDefinition field) =>
      field.key == 'password' || field.semanticRole == 'password';

  bool _isOtp(TemplateFieldDefinition field) =>
      field.key == 'otp' ||
      field.semanticRole == 'otp' ||
      field.valueType == 'totp';

  bool _isPrimaryUrl(TemplateFieldDefinition field) =>
      field.semanticRole == 'website' ||
      field.semanticRole == 'url' ||
      field.key == 'website' ||
      field.key == 'url';

  bool _isStandardField(TemplateFieldDefinition field) =>
      _isUsername(field) ||
      _isPassword(field) ||
      _isOtp(field) ||
      _isPrimaryUrl(field);

  List<TemplateFieldDefinition> get _customTemplateFields =>
      (_template?.fields ?? const [])
          .where((field) => !_isStandardField(field))
          .toList(growable: false);

  TextEditingController _controllerFor(TemplateFieldDefinition field) {
    if (_isUsername(field)) return _username;
    if (_isPassword(field)) return _password;
    if (_isOtp(field)) return _totp;
    if (_isPrimaryUrl(field)) return _url;
    return _fieldController(field.key);
  }

  void _hydrateTemplateFields() {
    final entryId = draft.entryId;
    if (entryId == null) return;
    final detail = widget.app.vault.entryView(entryId);
    if (detail == null) return;
    for (final definition in _customTemplateFields) {
      if (_templateFieldIds.containsKey(definition.key)) continue;
      final field = detail.fields.cast<EntryFieldView?>().firstWhere(
        (candidate) =>
            candidate?.key == definition.key ||
            (definition.semanticRole.isNotEmpty &&
                candidate?.semanticRole == definition.semanticRole),
        orElse: () => null,
      );
      if (field == null) continue;
      _templateFieldIds[definition.key] = field.id;
      final original = field.protected ? '' : field.displayValue;
      _templateFieldOriginals[definition.key] = original;
      _fieldController(definition.key).text = original;
    }
  }

  TextEditingController _fieldController(String key) => _templateFields
      .putIfAbsent(key, () => TextEditingController()..addListener(_sync));

  String? _templateFieldPayload() {
    if (_customTemplateFields.isEmpty) return null;
    final fields = <Map<String, dynamic>>[];
    for (final definition in _customTemplateFields) {
      final text = _fieldController(definition.key).text.trim();
      final original = _templateFieldOriginals[definition.key] ?? '';
      if (text.isEmpty && (draft.isNew || original.isEmpty)) continue;
      if (!draft.isNew && text == original) {
        continue;
      }
      fields.add({
        'id':
            _templateFieldIds[definition.key] ??
            'field_${draft.kind.substring(5)}_${definition.key}',
        'key': definition.key,
        'label': definition.label,
        'value': _typedValue(definition.valueType, text),
        'sensitivity': definition.sensitivity,
        'protected': definition.protected,
        'semantic_role': definition.semanticRole,
      });
    }
    return jsonEncode(fields);
  }

  Map<String, dynamic> _typedValue(String type, String text) {
    if (type == 'month_year') {
      final match = RegExp(r'^(\d{1,2})\s*[/\-]\s*(\d{4})$').firstMatch(text);
      if (match != null) {
        return {
          'type': type,
          'value': {
            'month': int.parse(match.group(1)!),
            'year': int.parse(match.group(2)!),
          },
        };
      }
    }
    if (type == 'address') {
      return {
        'type': type,
        'value': {
          'street': text,
          'city': '',
          'state': '',
          'postal_code': '',
          'country': '',
        },
      };
    }
    if (type == 'number') {
      return {'type': type, 'value': num.tryParse(text) ?? 0};
    }
    if (type == 'boolean') {
      return {'type': type, 'value': text.toLowerCase() == 'true'};
    }
    const supported = {
      'text',
      'concealed',
      'url',
      'email',
      'phone',
      'date',
      'certificate',
      'attachment_ref',
      'reference',
    };
    return {'type': supported.contains(type) ? type : 'text', 'value': text};
  }

  Map<String, String> _validateTemplateFields() {
    final result = <String, String>{};
    for (final field
        in _template?.fields ?? const <TemplateFieldDefinition>[]) {
      final value = _controllerFor(field).text.trim();
      if (value.isEmpty) continue;
      if (field.valueType == 'month_year') {
        final match = RegExp(r'^(\d{1,2})\s*[/\-]\s*(\d{4})$')
            .firstMatch(value);
        final month = match == null ? null : int.tryParse(match.group(1)!);
        if (month == null || month < 1 || month > 12) {
          result['template_${field.key}'] = 'Use MM/YYYY.';
        }
      }
      if (field.valueType == 'number' && num.tryParse(value) == null) {
        result['template_${field.key}'] = 'Enter a number.';
      }
    }
    return result;
  }

  Future<void> _save() async {
    _sync();
    final validation = {...draft.validate(), ..._validateTemplateFields()};
    if (validation.isNotEmpty) {
      setState(() => errors = validation);
      return;
    }
    setState(() {
      errors = const {};
      failure = null;
    });
    widget.editor.setSaving(value: true);
    try {
      final savedId = await widget.app.vault.save(draft);
      Object? bindingFailure;
      if (savedId != null) {
        try {
          for (final endpointId in draft.sshBindingsToClear) {
            await widget.app.setSshKeyBinding(savedId, endpointId, null);
          }
          for (final binding in draft.sshKeyBindings.entries) {
            await widget.app.setSshKeyBinding(
              savedId,
              binding.key,
              binding.value,
            );
          }
        } catch (caught) {
          bindingFailure = caught;
        }
      }
      if (mounted) {
        if (bindingFailure != null) {
          showFToast(
            context: context,
            title: const Text('Item saved, private key not bound'),
            description: const Text(
              'Select the private key again from the saved item on this device.',
            ),
          );
        }
        widget.onFinished();
      }
    } catch (caught) {
      // The draft is untouched: the user keeps every typed value.
      if (mounted) setState(() => failure = UserMessage.from(caught));
    } finally {
      widget.editor.setSaving(value: false);
    }
  }

  Future<void> _cancel() async {
    _sync();
    if (draft.isDirty) {
      final discard = await confirm(
        context: context,
        title: 'Discard changes?',
        message: 'This item has unsaved changes. Discarding cannot be undone.',
        confirmLabel: 'Discard',
        destructive: true,
      );
      if (!discard) return;
    }
    if (mounted) widget.onFinished();
  }

  Future<void> _generate() async {
    try {
      final settings = widget.app.passwordGeneratorSettings;
      final generated = await widget.app.vault.generatePassword(
        length: settings.requestLength,
        recipe: settings.recipe,
      );
      if (generated == null || !mounted) return;
      _password.text = generated;
      final copied = await widget.app.copySensitive(generated);
      if (!mounted) return;
      _passwordCopiedTimer?.cancel();
      setState(() => _passwordCopied = copied);
      if (copied) {
        _passwordCopiedTimer = Timer(const Duration(seconds: 1), () {
          if (mounted) setState(() => _passwordCopied = false);
        });
      }
    } catch (caught) {
      if (mounted) setState(() => failure = UserMessage.from(caught));
    }
  }

  Future<void> _openGeneratorSettings() async {
    await showPasswordGeneratorSettings(context, widget.app);
  }

  Future<void> _scanTotp({required bool fromScreen}) async {
    if (_totpScanning) return;
    setState(() {
      _totpScanning = true;
      failure = null;
      _failureAction = null;
    });
    try {
      final uri = fromScreen
          ? await widget.app.adapter.scanTotpQrCodeFromScreen()
          : await widget.app.adapter.scanTotpQrCode();
      if (uri != null && mounted) {
        _totp.text = uri;
        setState(() => _totpScanning = false);
      }
    } catch (caught) {
      if (!mounted) return;
      setState(() {
        _totpScanning = false;
        failure = UserMessage.from(caught);
        if (caught is ScreenRecordingPermissionRequired) {
          _failureAction = () => unawaited(_openScreenRecordingSettings());
        }
      });
    } finally {
      if (mounted && _totpScanning) {
        setState(() => _totpScanning = false);
      }
    }
  }

  Future<void> _openScreenRecordingSettings() async {
    try {
      await widget.app.adapter.openScreenRecordingSettings();
    } catch (caught) {
      if (mounted) {
        setState(() {
          failure = UserMessage.from(caught);
          _failureAction = null;
        });
      }
    }
  }

  void _changeTemplate(String? value) {
    final next = value ?? draft.kind;
    if (next == draft.kind) return;
    _username.clear();
    _password.clear();
    _url.clear();
    _totp.clear();
    _custom.clear();
    draft
      ..customFields = ''
      ..sections = ''
      ..removeFieldIds = const []
      ..structuredErrors = const {}
      ..sshKeyBindings = const {}
      ..sshBindingsToClear = const [];
    for (final controller in _templateFields.values) {
      controller.clear();
    }
    _templateFieldOriginals.clear();
    _templateFieldIds.clear();
    setState(() {
      draft.kind = next;
      errors = const {};
    });
    _sync();
  }

  List<Widget> _dynamicTemplateFields() {
    final result = <Widget>[];
    String? section;
    for (final field
        in _template?.fields ?? const <TemplateFieldDefinition>[]) {
      if (field.section != section) {
        section = field.section;
        result.add(const SizedBox(height: 18));
        result.add(SectionLabel(section));
      }
      result.add(const SizedBox(height: 8));
      final controller = _controllerFor(field);
      final storedProtected =
          !draft.isNew &&
          field.protected &&
          (widget.app.vault
                  .entryView(draft.entryId!)
                  ?.fields
                  .any(
                    (candidate) =>
                        candidate.hasValue &&
                        (candidate.key == field.key ||
                            candidate.semanticRole == field.semanticRole),
                  ) ??
              false);
      final label = storedProtected
          ? '${field.label} (blank keeps current)'
          : field.label;
      if (field.valueType == 'boolean') {
        result.add(
          FCheckbox(
            key: ValueKey('entry-template-${field.key}'),
            label: Text(label),
            value: controller.text.toLowerCase() == 'true',
            onChange: (value) => setState(() => controller.text = '$value'),
          ),
        );
        continue;
      }
      final description = switch (field.valueType) {
        'month_year' => 'MM/YYYY',
        'date' => 'YYYY-MM-DD',
        'totp' => 'Base32 secret or otpauth:// URI. Scan the screen or choose an image.',
        'address' => 'Street and address details',
        _ => null,
      };
      result.add(
        FTextField(
          key: ValueKey(
            _isUsername(field)
                ? 'entry-username'
                : _isPassword(field)
                ? 'entry-password'
                : _isOtp(field)
                ? 'entry-totp'
                : _isPrimaryUrl(field)
                ? 'entry-url'
                : 'entry-template-${field.key}',
          ),
          label: Text(label),
          description: description == null ? null : Text(description),
          error: errors['template_${field.key}'] == null
              ? null
              : Text(errors['template_${field.key}']!),
          obscureText:
              field.protected && (!_isPassword(field) || !_passwordRevealed),
          keyboardType: field.valueType == 'number'
              ? TextInputType.number
              : field.valueType == 'email'
              ? TextInputType.emailAddress
              : field.valueType == 'url'
              ? TextInputType.url
              : null,
          control: FTextFieldControl.managed(controller: controller),
          suffixBuilder: _isPassword(field)
              ? (context, style, variants) => Padding(
                  padding: const EdgeInsets.only(right: 6),
                  child: Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      FButton.icon(
                        key: const ValueKey('entry-password-reveal'),
                        variant: FButtonVariant.ghost,
                        semanticsLabel: _passwordRevealed
                            ? 'Hide password'
                            : 'Reveal password',
                        onPress: () => setState(
                          () => _passwordRevealed = !_passwordRevealed,
                        ),
                        child: Icon(
                          _passwordRevealed
                              ? FLucideIcons.eyeOff
                              : FLucideIcons.eye,
                          size: 16,
                        ),
                      ),
                      FButton.icon(
                        key: const ValueKey('entry-password-generate'),
                        variant: FButtonVariant.ghost,
                        semanticsLabel: _passwordCopied
                            ? 'Password generated and copied'
                            : 'Generate and copy password',
                        onPress: _generate,
                        child: Icon(
                          _passwordCopied
                              ? FLucideIcons.check
                              : FLucideIcons.sparkles,
                          size: 16,
                        ),
                      ),
                      FButton.icon(
                        key: const ValueKey('entry-password-settings'),
                        variant: FButtonVariant.ghost,
                        semanticsLabel: 'Password generator settings',
                        onPress: _openGeneratorSettings,
                        child: const Icon(FLucideIcons.settings2, size: 14),
                      ),
                    ],
                  ),
                )
              : _isOtp(field)
              ? (context, style, variants) => Padding(
                  padding: const EdgeInsets.only(right: 6),
                  child: Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      FButton.icon(
                        key: const ValueKey('entry-totp-scan-screen'),
                        variant: FButtonVariant.ghost,
                        semanticsLabel: 'Scan TOTP QR code from screen',
                        onPress: _totpScanning
                            ? null
                            : () => _scanTotp(fromScreen: true),
                        child: Icon(
                          _totpScanning
                              ? FLucideIcons.loaderCircle
                              : FLucideIcons.scanQrCode,
                          size: 16,
                        ),
                      ),
                      const SizedBox(width: 2),
                      FButton.icon(
                        key: const ValueKey('entry-totp-scan'),
                        variant: FButtonVariant.ghost,
                        semanticsLabel: 'Choose TOTP QR code image',
                        onPress: _totpScanning
                            ? null
                            : () => _scanTotp(fromScreen: false),
                        child: const Icon(FLucideIcons.image, size: 15),
                      ),
                    ],
                  ),
                )
              : null,
        ),
      );
    }
    return result;
  }

  @override
  Widget build(BuildContext context) {
    final vault = widget.app.vault;
    final groups = vault.groups;
    final templates = vault.templates;
    final guidance = guidanceForTemplate(draft.kind, label: _template?.label);
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        if (failure != null) ...[
          MessageBanner(
            message: failure!,
            onAction: _failureAction,
            onDismiss: () => setState(() {
              failure = null;
              _failureAction = null;
            }),
          ),
          const SizedBox(height: 12),
        ],
        if (draft.isNew)
          SearchableSelect<String>(
            key: const ValueKey('entry-kind'),
            label: const Text('Template'),
            options: templates.isEmpty
                ? const [
                    SearchSelectOption(value: 'core.login', label: 'Login'),
                    SearchSelectOption(
                      value: 'core.api_credential',
                      label: 'API credential',
                    ),
                    SearchSelectOption(
                      value: 'core.secure_note',
                      label: 'Secure note',
                    ),
                    SearchSelectOption(
                      value: 'core.generic',
                      label: 'Generic item',
                    ),
                  ]
                : [
                    for (final template in templates)
                      SearchSelectOption(
                        value: template.kind,
                        label: template.kind == 'core.server'
                            ? 'Server (generic)'
                            : template.label,
                        section: _templateSection(template),
                        subtitle: guidanceForTemplate(
                          template.kind,
                          label: template.label,
                        ).summary,
                        searchTerms: [template.kind, template.family],
                      ),
                  ],
            value: draft.kind,
            onChange: _changeTemplate,
          ),
        if (draft.isNew) ...[
          const SizedBox(height: 8),
          GuidanceCard(
            key: const ValueKey('entry-template-guidance'),
            title: 'About this template',
            summary: guidance.summary,
            useWhen: guidance.useWhen,
          ),
        ],
        const SizedBox(height: 10),
        if (!draft.isAgentContent)
          SearchableSelect<String>(
            key: const ValueKey('entry-group'),
            label: const Text('Group'),
            hint: 'Choose a group',
            forceErrorText: errors['group'],
            options: [
              for (final group in groups)
                SearchSelectOption(
                  value: group.id,
                  label: _groupBreadcrumb(group, groups),
                  searchTerms: [group.name, group.id],
                ),
            ],
            value: draft.groupId,
            onChange: (value) => setState(() => draft.groupId = value),
          ),
        const SizedBox(height: 10),
        FTextField(
          key: const ValueKey('entry-title'),
          label: const Text('Title'),
          autofocus: true,
          error: errors['title'] == null ? null : Text(errors['title']!),
          control: FTextFieldControl.managed(controller: _title),
        ),
        const SizedBox(height: 10),
        FCheckbox(
          label: const Text('Favorite'),
          value: draft.favorite,
          onChange: (value) => setState(() => draft.favorite = value),
        ),
        ..._dynamicTemplateFields(),
        if (_isDeveloperTemplate)
          DeveloperTemplateEditor(
            app: widget.app,
            draft: draft,
            detail: draft.entryId == null
                ? null
                : vault.entryView(draft.entryId!),
          ),
        if (_template?.markdownNotes == true || draft.isAgentContent) ...[
          const SizedBox(height: 18),
          SectionLabel(draft.isAgentContent ? 'Agent content' : 'Notes'),
          const SizedBox(height: 8),
          FTextField.multiline(
            key: const ValueKey('entry-notes'),
            label: Text(
              draft.isAgentContent
                  ? 'Markdown body'
                  : draft.kind == 'core.secure_note'
                  ? 'Secure note (Markdown)'
                  : draft.isNew
                  ? 'Notes (Markdown)'
                  : 'New notes (blank keeps current)',
            ),
            minLines: draft.isAgentContent || draft.kind == 'core.secure_note'
                ? 8
                : 3,
            maxLines: 16,
            control: FTextFieldControl.managed(controller: _notes),
          ),
        ],
        if (draft.isAgentContent) ...[
          const SizedBox(height: 10),
          FTextField(
            key: const ValueKey('entry-tags'),
            label: const Text('Tags'),
            description: const Text('Comma-separated'),
            control: FTextFieldControl.managed(controller: _tags),
          ),
          const SizedBox(height: 10),
          SearchableSelect<String>(
            key: const ValueKey('entry-project'),
            label: const Text('Project (optional)'),
            options: [
              const SearchSelectOption(value: '', label: 'No project'),
              for (final project in vault.projects)
                SearchSelectOption(
                  value: project.slug,
                  label: project.name,
                  subtitle: project.slug,
                  searchTerms: [project.slug],
                ),
            ],
            value: draft.projectSlug ?? '',
            onChange: (value) => setState(
              () => draft.projectSlug = value == null || value.isEmpty
                  ? null
                  : value,
            ),
          ),
          if (draft.isNew) ...[
            const SizedBox(height: 10),
            FSelect<String>(
              key: const ValueKey('entry-agent-access'),
              label: const Text('Agent access'),
              items: const {
                'None': 'none',
                'Read': 'read',
                'Read and write': 'read_write',
              },
              control: FSelectControl.lifted(
                value: draft.agentAccess,
                onChange: (value) =>
                    setState(() => draft.agentAccess = value ?? 'none'),
              ),
            ),
          ],
        ],
        if (_template == null && !draft.isAgentContent) ...[
          const SizedBox(height: 10),
          FTextField.multiline(
            key: const ValueKey('entry-custom-fields'),
            label: const Text('Custom fields (JSON array, optional)'),
            description: const Text(
              'Typed fields keep their protected and sensitivity '
              'flags.',
            ),
            error: errors['custom_fields'] == null
                ? null
                : Text(errors['custom_fields']!),
            minLines: 2,
            maxLines: 6,
            control: FTextFieldControl.managed(controller: _custom),
          ),
        ],
      ],
    );
  }
}
