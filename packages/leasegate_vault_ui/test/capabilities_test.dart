import 'package:flutter/widgets.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:leasegate_vault_ui/app/keylease_app.dart';
import 'package:leasegate_vault_ui/core/platform/app_capabilities.dart';

import 'package:leasegate_vault_ui/testing.dart';

/// Pumps the shell with a given capability set at a given size.
Future<void> pumpWith(
  WidgetTester tester,
  AppCapabilities capabilities, {
  Size size = const Size(1280, 800),
  TargetPlatform platform = TargetPlatform.macOS,
}) async {
  tester.view.physicalSize = size;
  tester.view.devicePixelRatio = 1;
  addTearDown(tester.view.reset);
  final app = buildController(capabilities: capabilities).app;
  await tester.pumpWidget(
    KeyLeaseApp(controller: app, platformOverride: platform),
  );
  await tester.pumpAndSettle();
}

void main() {
  // These gates are the mechanism the Android client uses to drop desktop-only
  // surface without forking the widget tree. Without a test they would rot
  // silently: the desktop build never exercises the `false` branch.
  group('capability gating', () {
    testWidgets('the desktop build offers the agent actions', (tester) async {
      await pumpWith(tester, AppCapabilities.desktop);
      await tester.tap(find.text('GitHub').first);
      await tester.pumpAndSettle();
      expect(
        find.byKey(const ValueKey('entry-prompt-entry-github')),
        findsOneWidget,
      );
      expect(
        find.byKey(const ValueKey('entry-cli-entry-github')),
        findsOneWidget,
      );
    });

    testWidgets('a phone build hides the agent actions', (tester) async {
      await pumpWith(
        tester,
        AppCapabilities.androidPhone,
        size: const Size(412, 915),
        platform: TargetPlatform.android,
      );
      await tester.tap(find.text('GitHub').first);
      await tester.pumpAndSettle();
      expect(
        find.byKey(const ValueKey('entry-prompt-entry-github')),
        findsNothing,
        reason: 'the agent prompt is pasted into a CLI on the same machine',
      );
      expect(
        find.byKey(const ValueKey('entry-cli-entry-github')),
        findsNothing,
      );
    });

    testWidgets('the phone build offers no screen-capture QR scan', (
      tester,
    ) async {
      await pumpWith(
        tester,
        AppCapabilities.androidPhone,
        size: const Size(412, 915),
        platform: TargetPlatform.android,
      );
      expect(
        find.byKey(const ValueKey('entry-totp-scan-screen')),
        findsNothing,
      );
    });

    test('the phone capability set drops what a phone cannot do', () {
      const phone = AppCapabilities.androidPhone;
      // Each of these is refused elsewhere too — by scoped storage, or by the
      // mobile_owner policy rule — so offering them would only produce errors.
      expect(phone.agentWorkflows, isFalse);
      expect(phone.sshKeyBinding, isFalse);
      expect(phone.screenQrScan, isFalse);
      expect(phone.connectionCreation, isFalse);
      expect(phone.vaultMigrations, isFalse);
      expect(phone.dataFolder, isFalse);
      expect(phone.loginItems, isFalse);
      expect(phone.windowTrafficLights, isFalse);

      // And keeps what it can.
      expect(phone.cameraQrScan, isTrue);
      expect(phone.imageQrScan, isTrue);
      expect(phone.developerTemplateEditing, isTrue);
      expect(phone.anyQrScan, isTrue);
    });

    test('an unspecified capability defaults to off', () {
      // Adding a flag must not silently enable it on a client that has not
      // opted in.
      const bare = AppCapabilities();
      expect(bare.agentWorkflows, isFalse);
      expect(bare.anyQrScan, isFalse);
    });
  });
}
