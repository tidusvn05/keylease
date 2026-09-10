import 'dart:async';
import 'dart:ui';

import 'package:forui/forui.dart';
import 'package:material_ui/material_ui.dart';

import 'package:leasegate_vault_ui/app/app_scope.dart';
import 'package:leasegate_vault_ui/app/app_theme.dart';
import 'package:leasegate_vault_ui/core/platform/local_runtime_adapter.dart';
import 'package:leasegate_vault_ui/core/platform/security_adapter.dart';
import 'package:leasegate_vault_ui/core/state/app_controller.dart';
import 'package:leasegate_vault_ui/features/settings/settings_page.dart';

import '../core/platform/desktop_connection_defaults.dart';
import '../core/platform/file_preferences_store.dart';
import '../core/rpc/keylease_rpc.dart';

/// Root for the dedicated macOS Settings window.
///
/// It intentionally owns a lightweight controller connected to the same local
/// daemon. No secret state is copied from the main Flutter engine.
class KeyLeaseSettingsWindowApp extends StatefulWidget {
  const KeyLeaseSettingsWindowApp({super.key});

  @override
  State<KeyLeaseSettingsWindowApp> createState() =>
      _KeyLeaseSettingsWindowAppState();
}

class _KeyLeaseSettingsWindowAppState extends State<KeyLeaseSettingsWindowApp> {
  late final AppController controller = AppController(
    adapter: MethodChannelSecurityAdapter(),
    runtime: MethodChannelLocalRuntimeAdapter(),
    preferences: FilePreferencesStore(),
    defaultSettings: desktopConnectionDefaults(),
    clientFactory: socketClientFactory,
  );

  @override
  void initState() {
    super.initState();
    unawaited(controller.start());
  }

  @override
  void dispose() {
    controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final light = KeyLeaseTheme.resolve(
      brightness: Brightness.light,
      desktop: true,
    );
    final dark = KeyLeaseTheme.resolve(
      brightness: Brightness.dark,
      desktop: true,
    );
    return AppScope(
      controller: controller,
      child: MaterialApp(
        title: 'KeyLease Settings',
        debugShowCheckedModeBanner: false,
        localizationsDelegates: FLocalizations.localizationsDelegates,
        supportedLocales: FLocalizations.supportedLocales,
        theme: KeyLeaseTheme.material(light),
        darkTheme: KeyLeaseTheme.material(dark),
        builder: (context, child) {
          final brightness =
              MediaQuery.maybePlatformBrightnessOf(context) ??
              PlatformDispatcher.instance.platformBrightness;
          return FTheme(
            data: brightness == Brightness.dark ? dark : light,
            platform: FPlatformVariant.macOS,
            child: FToaster(child: child!),
          );
        },
        home: Observe(
          listenable: controller,
          builder: (context, app) => AppScope(
            controller: app,
            child: ColoredBox(
              color: context.theme.colors.background,
              child: const SettingsPage(windowMode: true),
            ),
          ),
        ),
      ),
    );
  }
}
