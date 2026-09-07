import 'package:forui/forui.dart';
import 'package:material_ui/material_ui.dart';

import '../../core/models/models.dart';
import '../../core/state/app_controller.dart';
import '../../core/state/entry_draft.dart';
import '../../core/state/user_message.dart';
import '../../ui/components/keylease_dialog.dart';
import '../../ui/components/message_banner.dart';

/// Opens the draft-based editor.
///
/// The draft outlives a failed save: a rejected request leaves every typed
/// value in place so the user can fix one field and retry.
Future<void> openEntryEditor(
  BuildContext context,
  AppController app, {
  EntrySummary? existing,
}) async {
  final vault = app.vault;
  final draft = existing == null
      ? EntryDraft.create(
          groupId:
              vault.selectedGroupId ??
              (vault.groups.isEmpty ? null : vault.groups.first.id),
        )
      : EntryDraft.edit(existing);
  final editor = _EditorController();
  await showKeyLeaseDialog<void>(
    context: context,
    title: existing == null ? 'New item' : 'Edit item',
    barrierDismissible: false,
    bodyBuilder: (context) =>
        _EntryForm(app: app, draft: draft, editor: editor),
    // The action row lives outside the scrollable body so Save stays reachable
    // on a short window without scrolling to the bottom of the form.
    actionsBuilder: (context) => [_EditorActions(editor: editor)],
  );
  editor.dispose();
  draft.wipeSecrets();
}

/// Bridges the form's state to the dialog's pinned action row.
class _EditorController extends ChangeNotifier {
  bool saving = false;
  Future<void> Function()? save;
  Future<void> Function()? cancel;

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
  });

  final AppController app;
  final EntryDraft draft;
  final _EditorController editor;

  @override
  State<_EntryForm> createState() => _EntryFormState();
}

class _EntryFormState extends State<_EntryForm> {
  late final _title = TextEditingController(text: widget.draft.title);
  late final _username = TextEditingController(text: widget.draft.username);
  late final _url = TextEditingController(text: widget.draft.url);
  final _password = TextEditingController();
  final _notes = TextEditingController();
  final _totp = TextEditingController();
  final _custom = TextEditingController();

  Map<String, String> errors = const {};
  UserMessage? failure;

  EntryDraft get draft => widget.draft;

  @override
  void initState() {
    super.initState();
    widget.editor
      ..save = _save
      ..cancel = _cancel;
  }

  @override
  void dispose() {
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
      ..customFields = _custom.text;
  }

  Future<void> _save() async {
    _sync();
    final validation = draft.validate();
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
      await widget.app.vault.save(draft);
      if (mounted) Navigator.of(context).pop();
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
    if (mounted) Navigator.of(context).pop();
  }

  Future<void> _generate() async {
    try {
      final generated = await widget.app.vault.generatePassword();
      if (generated != null && mounted) {
        _password.text = generated;
        setState(() {});
      }
    } catch (caught) {
      if (mounted) setState(() => failure = UserMessage.from(caught));
    }
  }

  @override
  Widget build(BuildContext context) {
    final groups = widget.app.vault.groups;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        if (failure != null) ...[
          MessageBanner(message: failure!),
          const SizedBox(height: 12),
        ],
        if (draft.isNew)
          FSelect<String>(
            key: const ValueKey('entry-kind'),
            label: const Text('Template'),
            items: const {
              'Login': 'core.login',
              'API credential': 'core.api_credential',
              'Secure note': 'core.secure_note',
              'Generic item': 'core.generic',
            },
            control: FSelectControl.lifted(
              value: draft.kind,
              onChange: (value) =>
                  setState(() => draft.kind = value ?? draft.kind),
            ),
          ),
        const SizedBox(height: 10),
        FSelect<String>(
          key: const ValueKey('entry-group'),
          label: const Text('Group'),
          hint: 'Choose a group',
          forceErrorText: errors['group'],
          items: {for (final group in groups) group.name: group.id},
          control: FSelectControl.lifted(
            value: draft.groupId,
            onChange: (value) => setState(() => draft.groupId = value),
          ),
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
        FTextField(
          key: const ValueKey('entry-username'),
          label: const Text('Username'),
          control: FTextFieldControl.managed(controller: _username),
        ),
        const SizedBox(height: 10),
        FTextField(
          key: const ValueKey('entry-password'),
          label: Text(
            draft.isNew
                ? 'Password'
                : 'New password (leave blank to keep the current one)',
          ),
          obscureText: true,
          control: FTextFieldControl.managed(controller: _password),
          suffixBuilder: (context, style, variants) => Padding(
            padding: const EdgeInsets.only(right: 6),
            child: FButton.icon(
              variant: FButtonVariant.ghost,
              semanticsLabel: 'Generate a 32-character password',
              onPress: _generate,
              child: const Icon(FLucideIcons.sparkles, size: 16),
            ),
          ),
        ),
        const SizedBox(height: 10),
        FTextField(
          key: const ValueKey('entry-url'),
          label: const Text('Website'),
          control: FTextFieldControl.managed(controller: _url),
        ),
        const SizedBox(height: 10),
        FTextField.multiline(
          key: const ValueKey('entry-notes'),
          label: Text(
            draft.isNew ? 'Notes' : 'New notes (blank keeps current)',
          ),
          minLines: 2,
          maxLines: 5,
          control: FTextFieldControl.managed(controller: _notes),
        ),
        const SizedBox(height: 10),
        FTextField(
          key: const ValueKey('entry-totp'),
          label: Text(
            draft.isNew
                ? 'TOTP secret or otpauth:// URI'
                : 'New TOTP secret or URI (blank keeps current)',
          ),
          obscureText: true,
          control: FTextFieldControl.managed(controller: _totp),
        ),
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
    );
  }
}
