import 'package:forui/forui.dart';
import 'package:material_ui/material_ui.dart';

import '../../app/app_scope.dart';
import '../../core/state/app_controller.dart';
import '../../core/state/app_phase.dart';
import '../../ui/components/state_screen.dart';
import '../../ui/tokens/keylease_tokens.dart';

/// The screen for the current [AppPhase].
///
/// Each phase has its own headline, explanation and next step. Checking,
/// setup, offline, locked and permission-denied are never merged.
class PhaseScreen extends StatelessWidget {
  const PhaseScreen({required this.phase, super.key});

  final AppPhase phase;

  @override
  Widget build(BuildContext context) {
    final app = AppScope.of(context);
    final details = app.phaseMessage?.diagnostics;
    return switch (phase) {
      AppPhase.checking => const StateScreen(
        icon: FLucideIcons.loaderCircle,
        title: 'Checking KeyLease',
        message: 'Looking for the local service on this machine…',
        child: FCircularProgress(),
      ),
      AppPhase.onboarding => const OnboardingScreen(),
      AppPhase.provisioning => const StateScreen(
        icon: FLucideIcons.loaderCircle,
        title: 'Preparing your vault',
        message: 'KeyLease is securely setting everything up on this Mac…',
        child: FCircularProgress(),
      ),
      AppPhase.repairRequired => StateScreen(
        icon: FLucideIcons.wrench,
        title: 'Repair KeyLease',
        message: 'Your vault is here, but the desktop connection needs repair.',
        actions: [
          FButton(
            onPress: () => app.selectSection(AppSection.settings),
            child: const Text('Open Settings'),
          ),
        ],
        details: details,
      ),
      AppPhase.backgroundApprovalRequired => StateScreen(
        icon: FLucideIcons.circleAlert,
        title: 'Allow KeyLease in the background',
        message: 'macOS needs your approval so the vault is ready when you open the app.',
        actions: [
          FButton(
            onPress: app.openLoginItemsSettings,
            child: const Text('Open Login Items'),
          ),
          FButton(
            variant: FButtonVariant.outline,
            onPress: app.start,
            child: const Text('Try again'),
          ),
        ],
      ),
      AppPhase.serviceUnavailable => StateScreen(
        icon: FLucideIcons.monitorX,
        title: "Can't reach KeyLease",
        message:
            'Your vault has not been opened. Make sure the local '
            'background service is allowed, then try again.',
        actions: [
          FButton(
            variant: FButtonVariant.outline,
            onPress: () => app.selectSection(AppSection.settings),
            child: const Text('Open settings'),
          ),
          FButton(
            key: const ValueKey('phase-retry'),
            onPress: app.refresh,
            prefix: const Icon(FLucideIcons.refreshCw, size: 16),
            child: const Text('Try again'),
          ),
        ],
        details: details,
      ),
      AppPhase.permissionDenied => StateScreen(
        icon: FLucideIcons.shieldOff,
        title: 'Permission needed',
        message:
            'This Mac’s local desktop access needs to be repaired before '
            'KeyLease can read vault items.',
        actions: [
          FButton(
            onPress: () => app.selectSection(AppSection.settings),
            child: const Text('Repair in Settings'),
          ),
        ],
        footnote: 'Your vault and its existing permissions are unchanged.',
        details: details,
      ),
      AppPhase.locked => const UnlockScreen(),
      AppPhase.ready => const SizedBox.shrink(),
    };
  }
}

class OnboardingScreen extends StatefulWidget {
  const OnboardingScreen({super.key});

  @override
  State<OnboardingScreen> createState() => _OnboardingScreenState();
}

class _OnboardingScreenState extends State<OnboardingScreen> {
  final _password = TextEditingController();
  final _confirm = TextEditingController();
  final _sourcePassword = TextEditingController();
  String? _sourcePath;
  String? _sourceKind;
  String? _error;
  bool _differentPassword = false;
  bool _acknowledgePlaintext = false;

  @override
  void dispose() {
    _password.dispose();
    _confirm.dispose();
    _sourcePassword.dispose();
    super.dispose();
  }

  Future<void> _choose(AppController app) async {
    try {
      final path = await app.chooseVaultSource();
      if (path == null) {
        return;
      }
      final inspected = await app.inspectSource(path);
      if (mounted) {
        setState(() {
          _sourcePath = path;
          _sourceKind = inspected['kind'] as String?;
          _error = null;
        });
      }
    } catch (caught) {
      if (mounted) {
        setState(() => _error = 'This file is not a supported vault.');
      }
    }
  }

  Future<void> _submit(AppController app) async {
    final kind = _sourceKind;
    final targetPassword = kind == 'kdbx' && !_differentPassword
        ? _sourcePassword.text
        : _password.text;
    if (targetPassword.isEmpty ||
        (kind != 'kdbx' || _differentPassword) &&
            targetPassword != _confirm.text) {
      setState(() => _error = 'Enter matching passwords to continue.');
      return;
    }
    if (kind == 'onepux' && !_acknowledgePlaintext) {
      setState(
        () =>
            _error = 'Confirm that this export may contain plaintext secrets.',
      );
      return;
    }
    final request = <String, dynamic>{'password': targetPassword};
    if (kind == null) {
      request['mode'] = 'create';
    } else {
      request.addAll({'source_path': _sourcePath});
      switch (kind) {
        case 'keylease_database':
          request['mode'] = 'adopt_keylease_database';
        case 'keylease_backup':
          request['mode'] = 'restore_keylease_backup';
        case 'kdbx':
          request['mode'] = 'import_kdbx';
          request['source_password'] = _sourcePassword.text;
        case 'onepux':
          request['mode'] = 'import_onepux';
          request['acknowledge_plaintext'] = true;
      }
    }
    await app.provision(request);
    _password.clear();
    _confirm.clear();
    _sourcePassword.clear();
  }

  @override
  Widget build(BuildContext context) {
    final app = AppScope.of(context);
    final tokens = KeyLeaseTokens.of(context);
    final importing = _sourcePath != null;
    final needsSourcePassword = _sourceKind == 'kdbx';
    final needsTargetPassword = !needsSourcePassword || _differentPassword;
    return StateScreen(
      icon: FLucideIcons.keyRound,
      title: importing ? 'Bring your vault to KeyLease' : 'Welcome to KeyLease',
      message: importing
          ? 'Your original file stays unchanged. KeyLease creates a managed copy on this Mac.'
          : 'Create a new encrypted vault, or use one you already have.',
      footnote: 'KeyLease stores its managed files privately in ~/.keylease.',
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          if (_error != null) ...[
            Text(
              _error!,
              style: TextStyle(color: context.theme.colors.destructive),
            ),
            SizedBox(height: tokens.gutterSmall),
          ],
          if (!importing) ...[
            FButton(
              onPress: () => setState(() => _sourcePath = null),
              child: const Text('Create a new vault'),
            ),
            SizedBox(height: tokens.gutterSmall),
            FButton(
              variant: FButtonVariant.outline,
              onPress: () => _choose(app),
              child: const Text('Use an existing vault'),
            ),
            if (app.legacyDatabase != null) ...[
              SizedBox(height: tokens.gutterSmall),
              FButton(
                variant: FButtonVariant.ghost,
                onPress: () async {
                  final path = app.legacyDatabase!;
                  final inspected = await app.inspectSource(path);
                  if (mounted) {
                    setState(() {
                      _sourcePath = path;
                      _sourceKind = inspected['kind'] as String?;
                    });
                  }
                },
                child: const Text(
                  'Continue with the vault from an earlier KeyLease setup',
                ),
              ),
            ],
          ] else ...[
            Text(_sourcePath!, maxLines: 2, overflow: TextOverflow.ellipsis),
            SizedBox(height: tokens.gutterSmall),
            FButton(
              variant: FButtonVariant.outline,
              onPress: () => setState(() {
                _sourcePath = null;
                _sourceKind = null;
              }),
              child: const Text('Choose another file'),
            ),
          ],
          SizedBox(height: tokens.gutter),
          if (needsSourcePassword) ...[
            FTextField(
              label: const Text('Existing vault password'),
              obscureText: true,
              control: FTextFieldControl.managed(controller: _sourcePassword),
            ),
            SizedBox(height: tokens.gutterSmall),
            FCheckbox(
              label: const Text('Use a different password in KeyLease'),
              value: _differentPassword,
              onChange: (value) => setState(() => _differentPassword = value),
            ),
          ],
          if (needsTargetPassword) ...[
            FTextField(
              label: Text(importing ? 'KeyLease password' : 'Master password'),
              obscureText: true,
              control: FTextFieldControl.managed(controller: _password),
            ),
            SizedBox(height: tokens.gutterSmall),
            FTextField(
              label: const Text('Confirm password'),
              obscureText: true,
              control: FTextFieldControl.managed(controller: _confirm),
            ),
          ],
          if (_sourceKind == 'onepux')
            FCheckbox(
              label: const Text(
                'I understand this export may contain plaintext secrets',
              ),
              value: _acknowledgePlaintext,
              onChange: (value) =>
                  setState(() => _acknowledgePlaintext = value),
            ),
          SizedBox(height: tokens.gutter),
          FButton(
            onPress: () => _submit(app),
            child: Text(importing ? 'Import and continue' : 'Create vault'),
          ),
        ],
      ),
    );
  }
}

/// The unlock form. The password never leaves this widget except as the
/// argument of the `unlock` call, and the field is cleared straight after.
class UnlockScreen extends StatefulWidget {
  const UnlockScreen({super.key});

  @override
  State<UnlockScreen> createState() => _UnlockScreenState();
}

class _UnlockScreenState extends State<UnlockScreen> {
  final _password = TextEditingController();
  final _focus = FocusNode(debugLabel: 'unlock.password');

  @override
  void dispose() {
    _password
      ..clear()
      ..dispose();
    _focus.dispose();
    super.dispose();
  }

  Future<void> _submit(AppController app) async {
    final value = _password.text;
    if (value.isEmpty) return;
    _password.clear();
    await app.unlock(value);
  }

  @override
  Widget build(BuildContext context) {
    final app = AppScope.of(context);
    final tokens = KeyLeaseTokens.of(context);
    final busy = app.isBusy(AppController.unlockKey);
    return StateScreen(
      icon: FLucideIcons.lock,
      title: 'Welcome back',
      message: 'Unlock your vault to access your items.',
      footnote: app.status?.idleExpiresAt == null
          ? 'The vault locks itself when this machine sleeps or the screen '
                'locks.'
          : null,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          FTextField(
            key: const ValueKey('unlock-password'),
            label: const Text('Master password'),
            obscureText: true,
            autofocus: true,
            focusNode: _focus,
            enabled: !busy,
            onSubmit: (_) => _submit(app),
            control: FTextFieldControl.managed(controller: _password),
          ),
          SizedBox(height: tokens.gutterSmall),
          FButton(
            key: const ValueKey('unlock-submit'),
            onPress: busy ? null : () => _submit(app),
            prefix: const Icon(FLucideIcons.lockOpen, size: 16),
            child: Text(busy ? 'Unlocking…' : 'Unlock vault'),
          ),
        ],
      ),
    );
  }
}
