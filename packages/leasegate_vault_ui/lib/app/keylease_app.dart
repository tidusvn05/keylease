import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:forui/forui.dart';
import 'package:material_ui/material_ui.dart';

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
  const KeyLeaseApp({
    required this.controller,
    this.ownsController = false,
    this.platformOverride,
    super.key,
  });

  /// The session this widget presents.
  ///
  /// Always injected, because the platform adapters it needs differ per host
  /// and this widget is shared between them. The composition root — `main.dart`
  /// on desktop — decides which ones to build.
  final AppController controller;

  /// Whether disposing this widget should dispose [controller].
  ///
  /// True for the app that created it, false for a test that reuses one.
  final bool ownsController;

  /// Forces a platform variant, for tests and for the touch/desktop preview.
  final TargetPlatform? platformOverride;

  @override
  State<KeyLeaseApp> createState() => _KeyLeaseAppState();
}

class _KeyLeaseAppState extends State<KeyLeaseApp> {
  AppController get controller => widget.controller;

  @override
  void initState() {
    super.initState();
    _menuSubscription = controller.adapter.menuActions.listen(_onMenuAction);
    controller.addListener(_onControllerChanged);
    unawaited(controller.start());
  }

  void _onControllerChanged() {
    if (!controller.consumeCreateFirstItemRequest()) return;
    WidgetsBinding.instance.addPostFrameCallback((_) => _newItem());
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
        unawaited(controller.openSettings());
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
    controller.removeListener(_onControllerChanged);
    if (widget.ownsController) controller.dispose();
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
        unawaited(controller.openSettings());
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
