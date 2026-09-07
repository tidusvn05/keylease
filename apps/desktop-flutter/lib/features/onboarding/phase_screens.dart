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
      AppPhase.setupRequired => StateScreen(
        icon: FLucideIcons.keyRound,
        title: 'Make yourself at home',
        message:
            app.phaseMessage?.detail ??
            'Connect this app to your local KeyLease service, then unlock '
                'your vault.',
        actions: [
          FButton(
            key: const ValueKey('phase-open-settings'),
            onPress: () => app.selectSection(AppSection.settings),
            child: const Text('Open settings'),
          ),
        ],
        footnote:
            'KeyLease reads the client file you choose. It never '
            'stores your master password.',
        details: details,
      ),
      AppPhase.serviceUnavailable => StateScreen(
        icon: FLucideIcons.monitorX,
        title: "Can't reach KeyLease",
        message:
            'Your vault has not been opened. Make sure the local '
            'service is running, then try connecting again.',
        actions: [
          FButton(
            variant: FButtonVariant.outline,
            onPress: () => app.selectSection(AppSection.settings),
            child: const Text('Connection settings'),
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
            'This desktop client is not allowed to read vault items. '
            'Choose an authorized client file, or ask your administrator '
            'to review its access.',
        actions: [
          FButton(
            onPress: () => app.selectSection(AppSection.settings),
            child: const Text('Review connection settings'),
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
