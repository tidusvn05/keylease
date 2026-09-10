import 'dart:async';
import 'dart:math' as math;

import 'package:forui/forui.dart';
import 'package:material_ui/material_ui.dart';

import '../../core/state/app_controller.dart';
import '../../core/state/password_generator_settings.dart';
import '../../core/state/user_message.dart';
import '../../core/state/vault_controller.dart';
import '../../ui/components/keylease_dialog.dart';
import '../../ui/components/message_banner.dart';
import '../../ui/components/scroll_area.dart';
import '../../ui/components/secret_field.dart';
import '../../ui/tokens/keylease_tokens.dart';
import 'entry_editor.dart';

Future<void> openPasswordGenerator(
  BuildContext context,
  AppController app,
) async {
  app.vault.openPasswordGenerator();
  final split =
      MediaQuery.sizeOf(context).width >=
      KeyLeaseTokens.of(context).splitBreakpoint;
  if (split || !context.mounted) return;
  await Navigator.of(context).push(
    MaterialPageRoute<void>(
      builder: (context) => PasswordGeneratorPane(
        app: app,
        onClosed: () => Navigator.of(context).pop(),
      ),
    ),
  );
  if (app.vault.workspaceMode == EntryWorkspaceMode.passwordGenerator) {
    app.vault.closeEditor();
  }
}

Future<bool> showPasswordGeneratorSettings(
  BuildContext context,
  AppController app,
) async =>
    await showKeyLeaseDialog<bool>(
      context: context,
      title: 'Password generator settings',
      description: 'Saved settings are reused everywhere in KeyLease.',
      maxWidth: 560,
      bodyBuilder: (context) => _PasswordSettingsForm(app: app),
      actionsBuilder: (_) => const [],
    ) ??
    false;

class PasswordGeneratorPane extends StatelessWidget {
  const PasswordGeneratorPane({required this.app, this.onClosed, super.key});

  final AppController app;
  final VoidCallback? onClosed;

  @override
  Widget build(BuildContext context) {
    final tokens = KeyLeaseTokens.of(context);
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Padding(
          padding: EdgeInsets.all(tokens.gutter),
          child: Row(
            children: [
              if (onClosed != null) ...[
                IconAction(
                  label: 'Back',
                  icon: FLucideIcons.arrowLeft,
                  onPress: onClosed,
                ),
                const SizedBox(width: 8),
              ],
              Expanded(
                child: Text(
                  'Password generator',
                  style: context.theme.typography.body.lg.copyWith(
                    fontWeight: FontWeight.w600,
                  ),
                ),
              ),
            ],
          ),
        ),
        const Divider(height: 1),
        Expanded(
          child: KeyLeaseScrollArea(
            padding: EdgeInsets.all(tokens.gutter * 1.25),
            children: [
              PasswordGenerator(
                app: app,
                useLabel: 'Create Login',
                onUse: (password) {
                  app.vault.beginCreate(initialPassword: password);
                  if (onClosed != null) {
                    Navigator.of(context).pushReplacement(
                      MaterialPageRoute<void>(
                        builder: (context) => EntryEditorPane(
                          app: app,
                          onClosed: () => Navigator.of(context).pop(),
                        ),
                      ),
                    );
                  }
                },
              ),
            ],
          ),
        ),
      ],
    );
  }
}

class PasswordGenerator extends StatefulWidget {
  const PasswordGenerator({
    required this.app,
    required this.onUse,
    required this.useLabel,
    super.key,
  });

  final AppController app;
  final ValueChanged<String> onUse;
  final String useLabel;

  @override
  State<PasswordGenerator> createState() => _PasswordGeneratorState();
}

class _PasswordGeneratorState extends State<PasswordGenerator> {
  final _password = TextEditingController();
  PasswordGeneratorSettings? _generatedWith;
  bool _revealed = false;
  bool _generating = false;
  bool _copied = false;
  Timer? _copiedTimer;
  UserMessage? _failure;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) => unawaited(_generate()));
  }

  @override
  void dispose() {
    _copiedTimer?.cancel();
    _password
      ..clear()
      ..dispose();
    super.dispose();
  }

  int _entropyBits(PasswordGeneratorSettings settings) =>
      switch (settings.pattern) {
        PasswordPattern.random =>
          _randomPoolSize(settings) == 0
              ? 0
              : (settings.length *
                        math.log(_randomPoolSize(settings)) /
                        math.ln2)
                    .round(),
        PasswordPattern.words =>
          settings.wordCount * 12 + (settings.wordNumber ? 7 : 0),
        PasswordPattern.pin =>
          (settings.pinLength * math.log(10) / math.ln2).round(),
      };

  int _randomPoolSize(PasswordGeneratorSettings settings) =>
      (settings.uppercase ? 24 : 0) +
      (settings.lowercase ? 25 : 0) +
      (settings.numbers ? 8 : 0) +
      (settings.symbols ? 14 : 0);

  String _strength(int bits) => switch (bits) {
    < 40 => 'Weak',
    < 60 => 'Fair',
    < 80 => 'Strong',
    _ => 'Very strong',
  };

  void _showCopied() {
    _copiedTimer?.cancel();
    setState(() => _copied = true);
    _copiedTimer = Timer(const Duration(seconds: 1), () {
      if (mounted) setState(() => _copied = false);
    });
  }

  Future<void> _generate() async {
    if (_generating) return;
    final settings = widget.app.passwordGeneratorSettings;
    setState(() {
      _generating = true;
      _failure = null;
      _copied = false;
    });
    try {
      final value = await widget.app.vault.generatePassword(
        length: settings.requestLength,
        recipe: settings.recipe,
      );
      if (value == null || !mounted) return;
      _password.text = value;
      _generatedWith = settings;
      if (await widget.app.copySensitive(value) && mounted) _showCopied();
    } catch (caught) {
      if (mounted) setState(() => _failure = UserMessage.from(caught));
    } finally {
      if (mounted) setState(() => _generating = false);
    }
  }

  Future<void> _copy() async {
    if (_password.text.isEmpty) return;
    if (await widget.app.copySensitive(_password.text) && mounted) {
      _showCopied();
    }
  }

  Future<void> _settings() async {
    final saved = await showPasswordGeneratorSettings(context, widget.app);
    if (saved && mounted) setState(() {});
  }

  @override
  Widget build(BuildContext context) {
    final theme = context.theme;
    final generatedWith =
        _generatedWith ?? widget.app.passwordGeneratorSettings;
    final bits = _entropyBits(generatedWith);
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        if (_failure != null) ...[
          MessageBanner(message: _failure!),
          const SizedBox(height: 12),
        ],
        FTextField(
          key: const ValueKey('generated-password'),
          label: const Text('Generated password'),
          obscureText: !_revealed,
          readOnly: true,
          control: FTextFieldControl.managed(controller: _password),
          suffixBuilder: (context, style, variants) => Padding(
            padding: const EdgeInsets.only(right: 10),
            child: _copied
                ? const Row(
                    key: ValueKey('password-copied'),
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Icon(FLucideIcons.check, size: 14),
                      SizedBox(width: 4),
                      Text('Copied'),
                    ],
                  )
                : const SizedBox.shrink(),
          ),
        ),
        const SizedBox(height: 8),
        Row(
          children: [
            Text(
              '${_strength(bits)} · approximately $bits bits',
              style: theme.typography.body.xs.copyWith(
                color: theme.colors.mutedForeground,
              ),
            ),
            const Spacer(),
            IconAction(
              label: _revealed ? 'Hide password' : 'Reveal password',
              icon: _revealed ? FLucideIcons.eyeOff : FLucideIcons.eye,
              onPress: () => setState(() => _revealed = !_revealed),
            ),
            IconAction(
              label: 'Copy password',
              icon: FLucideIcons.copy,
              onPress: _password.text.isEmpty ? null : _copy,
            ),
            IconAction(
              key: const ValueKey('password-generate'),
              label: 'Generate new password',
              icon: FLucideIcons.sparkles,
              onPress: _generating ? null : _generate,
            ),
            IconAction(
              key: const ValueKey('password-settings'),
              label: 'Password generator settings',
              icon: FLucideIcons.settings2,
              onPress: _settings,
            ),
          ],
        ),
        const SizedBox(height: 18),
        FButton(
          key: const ValueKey('password-use'),
          onPress: _password.text.isEmpty
              ? null
              : () => widget.onUse(_password.text),
          prefix: const Icon(FLucideIcons.plus, size: 16),
          child: Text(widget.useLabel),
        ),
      ],
    );
  }
}

class _PasswordSettingsForm extends StatefulWidget {
  const _PasswordSettingsForm({required this.app});

  final AppController app;

  @override
  State<_PasswordSettingsForm> createState() => _PasswordSettingsFormState();
}

class _PasswordSettingsFormState extends State<_PasswordSettingsForm> {
  late PasswordGeneratorSettings value = widget.app.passwordGeneratorSettings;
  String? error;
  bool saving = false;

  void change(PasswordGeneratorSettings next) => setState(() {
    value = next;
    error = null;
  });

  Future<void> save() async {
    if (value.pattern == PasswordPattern.random &&
        !value.uppercase &&
        !value.lowercase &&
        !value.numbers &&
        !value.symbols) {
      setState(() => error = 'Select at least one character type.');
      return;
    }
    setState(() => saving = true);
    await widget.app.updatePasswordGeneratorSettings(value);
    if (mounted) Navigator.of(context).pop(true);
  }

  @override
  Widget build(BuildContext context) => Column(
    crossAxisAlignment: CrossAxisAlignment.stretch,
    children: [
      FSelect<PasswordPattern>(
        key: const ValueKey('password-pattern'),
        label: const Text('Pattern'),
        items: const {
          'Random characters': PasswordPattern.random,
          'Memorable words': PasswordPattern.words,
          'PIN': PasswordPattern.pin,
        },
        control: FSelectControl.lifted(
          value: value.pattern,
          onChange: (next) {
            if (next != null) change(value.copyWith(pattern: next));
          },
        ),
      ),
      const SizedBox(height: 10),
      ...switch (value.pattern) {
        PasswordPattern.random => randomSettings(),
        PasswordPattern.words => wordSettings(),
        PasswordPattern.pin => pinSettings(),
      },
      if (error != null) ...[
        const SizedBox(height: 8),
        Text(error!, style: TextStyle(color: context.theme.colors.destructive)),
      ],
      const SizedBox(height: 18),
      Row(
        mainAxisAlignment: MainAxisAlignment.end,
        children: [
          FButton(
            variant: FButtonVariant.outline,
            onPress: saving ? null : () => Navigator.of(context).pop(false),
            child: const Text('Cancel'),
          ),
          const SizedBox(width: 8),
          FButton(
            key: const ValueKey('password-settings-save'),
            onPress: saving ? null : save,
            child: Text(saving ? 'Saving…' : 'Save settings'),
          ),
        ],
      ),
    ],
  );

  List<Widget> randomSettings() => [
    FSelect<int>(
      key: const ValueKey('password-length'),
      label: const Text('Length'),
      items: const {'16': 16, '20': 20, '24': 24, '32': 32, '40': 40, '64': 64},
      control: FSelectControl.lifted(
        value: value.length,
        onChange: (next) {
          if (next != null) change(value.copyWith(length: next));
        },
      ),
    ),
    const SizedBox(height: 10),
    FCheckbox(
      label: const Text('Uppercase letters'),
      value: value.uppercase,
      onChange: (next) => change(value.copyWith(uppercase: next)),
    ),
    FCheckbox(
      label: const Text('Lowercase letters'),
      value: value.lowercase,
      onChange: (next) => change(value.copyWith(lowercase: next)),
    ),
    FCheckbox(
      label: const Text('Numbers'),
      value: value.numbers,
      onChange: (next) => change(value.copyWith(numbers: next)),
    ),
    FCheckbox(
      label: const Text('Symbols'),
      value: value.symbols,
      onChange: (next) => change(value.copyWith(symbols: next)),
    ),
    FCheckbox(
      label: const Text('Avoid ambiguous characters (0, O, 1, l)'),
      value: value.avoidAmbiguous,
      onChange: (next) => change(value.copyWith(avoidAmbiguous: next)),
    ),
  ];

  List<Widget> wordSettings() => [
    FSelect<int>(
      key: const ValueKey('password-word-count'),
      label: const Text('Words'),
      items: const {'3': 3, '4': 4, '5': 5, '6': 6, '7': 7, '8': 8},
      control: FSelectControl.lifted(
        value: value.wordCount,
        onChange: (next) {
          if (next != null) change(value.copyWith(wordCount: next));
        },
      ),
    ),
    const SizedBox(height: 10),
    FSelect<String>(
      key: const ValueKey('password-separator'),
      label: const Text('Separator'),
      items: const {
        'Hyphen (-)': '-',
        'Space': ' ',
        'Period (.)': '.',
        'Underscore (_)': '_',
      },
      control: FSelectControl.lifted(
        value: value.separator,
        onChange: (next) {
          if (next != null) change(value.copyWith(separator: next));
        },
      ),
    ),
    const SizedBox(height: 10),
    FCheckbox(
      label: const Text('Capitalize words'),
      value: value.capitalize,
      onChange: (next) => change(value.copyWith(capitalize: next)),
    ),
    FCheckbox(
      label: const Text('Include a number'),
      value: value.wordNumber,
      onChange: (next) => change(value.copyWith(wordNumber: next)),
    ),
  ];

  List<Widget> pinSettings() => [
    FSelect<int>(
      key: const ValueKey('password-pin-length'),
      label: const Text('Digits'),
      items: const {'4': 4, '6': 6, '8': 8, '10': 10, '12': 12},
      control: FSelectControl.lifted(
        value: value.pinLength,
        onChange: (next) {
          if (next != null) change(value.copyWith(pinLength: next));
        },
      ),
    ),
  ];
}
