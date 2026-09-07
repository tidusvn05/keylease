import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:forui/forui.dart';
import 'package:material_ui/material_ui.dart';

import '../core/platform/preferences_store.dart';
import '../core/platform/security_adapter.dart';
import '../core/state/app_controller.dart';
import '../core/state/app_phase.dart';
import '../features/vault/entry_editor.dart';
import 'adaptive_shell.dart';
import 'app_scope.dart';
import 'app_theme.dart';
import 'shortcuts.dart';

/// The KeyLease client.
///
/// One widget tree for macOS, Windows, Android and iOS. The shell adapts to
/// the window; the state, the RPC contract and the security semantics do not.
class KeyLeaseApp extends StatefulWidget {
  const KeyLeaseApp({this.controller, this.platformOverride, super.key});

  /// Injected in tests. In production the app builds its own controller over
  /// the real method channel and preferences file.
  final AppController? controller;

  /// Forces a platform variant, for tests and for the touch/desktop preview.
  final TargetPlatform? platformOverride;

  @override
  State<KeyLeaseApp> createState() => _KeyLeaseAppState();
}

class _KeyLeaseAppState extends State<KeyLeaseApp> {
  late final AppController controller =
      widget.controller ??
      AppController(
        adapter: MethodChannelSecurityAdapter(),
        preferences: FilePreferencesStore(),
      );
  late final bool _ownsController = widget.controller == null;

  @override
  void initState() {
    super.initState();
    _menuSubscription = controller.adapter.menuActions.listen(_onMenuAction);
    unawaited(controller.start());
  }

  /// The native menu is the only path for shortcuts AppKit already owns, so
  /// menu selections run the same intents as the in-app accelerators.
  void _onMenuAction(MenuAction action) {
    switch (action) {
      case MenuAction.search:
        _focusSearch();
      case MenuAction.newItem:
        _newItem();
      case MenuAction.settings:
        controller.selectSection(AppSection.settings);
      case MenuAction.lock:
        _lock();
      case MenuAction.refresh:
        unawaited(controller.refresh());
    }
  }

  void _focusSearch() {
    controller.selectSection(AppSection.vault);
    controller.vault.searchFocus.requestFocus();
  }

  void _newItem() {
    final context = _navigatorKey.currentContext;
    if (!controller.isReady || context == null) return;
    controller.selectSection(AppSection.vault);
    unawaited(openEntryEditor(context, controller));
  }

  void _lock() {
    if (controller.isReady) unawaited(controller.lock());
  }

  @override
  void dispose() {
    unawaited(_menuSubscription?.cancel());
    if (_ownsController) controller.dispose();
    super.dispose();
  }

  final _navigatorKey = GlobalKey<NavigatorState>();
  StreamSubscription<MenuAction>? _menuSubscription;

  /// App-wide accelerators.
  ///
  /// These live above the navigator: a shortcut installed under `home` would
  /// never be consulted, because key events are dispatched from the focused
  /// node upwards and the route's focus scope sits above it.
  Map<Type, Action<Intent>> _actions() => {
    SearchIntent: CallbackAction<SearchIntent>(
      onInvoke: (_) {
        controller.selectSection(AppSection.vault);
        controller.vault.searchFocus.requestFocus();
        return null;
      },
    ),
    NewItemIntent: CallbackAction<NewItemIntent>(
      onInvoke: (_) {
        final context = _navigatorKey.currentContext;
        if (!controller.isReady || context == null) return null;
        controller.selectSection(AppSection.vault);
        unawaited(openEntryEditor(context, controller));
        return null;
      },
    ),
    SettingsIntent: CallbackAction<SettingsIntent>(
      onInvoke: (_) {
        controller.selectSection(AppSection.settings);
        return null;
      },
    ),
    LockIntent: CallbackAction<LockIntent>(
      onInvoke: (_) {
        if (controller.isReady) unawaited(controller.lock());
        return null;
      },
    ),
  };

  @override
  Widget build(BuildContext context) {
    final platform = widget.platformOverride ?? defaultTargetPlatform;
    final variant = KeyLeaseTheme.variantFor(platform);
    final desktop = variant.desktop;
    final light = KeyLeaseTheme.resolve(
      brightness: Brightness.light,
      desktop: desktop,
    );
    final dark = KeyLeaseTheme.resolve(
      brightness: Brightness.dark,
      desktop: desktop,
    );
    return AppScope(
      controller: controller,
      child: MaterialApp(
        title: 'KeyLease',
        debugShowCheckedModeBanner: false,
        navigatorKey: _navigatorKey,
        localizationsDelegates: FLocalizations.localizationsDelegates,
        supportedLocales: FLocalizations.supportedLocales,
        theme: KeyLeaseTheme.material(light),
        darkTheme: KeyLeaseTheme.material(dark),
        shortcuts: {
          ...WidgetsApp.defaultShortcuts,
          ...appShortcuts(platform: platform),
        },
        actions: {...WidgetsApp.defaultActions, ..._actions()},
        builder: (context, child) {
          final brightness =
              MediaQuery.maybePlatformBrightnessOf(context) ??
              PlatformDispatcher.instance.platformBrightness;
          return FTheme(
            data: brightness == Brightness.dark ? dark : light,
            platform: variant,
            child: FToaster(child: FTooltipGroup(child: child!)),
          );
        },
        home: Builder(
          builder: (context) => Observe(
            listenable: controller,
            builder: (context, app) => ColoredBox(
              color: context.theme.colors.background,
              child: const AdaptiveShell(),
            ),
          ),
        ),
      ),
    );
  }
}
