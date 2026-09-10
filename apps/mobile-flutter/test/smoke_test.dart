import 'package:flutter_test/flutter_test.dart';
import 'package:leasegate_vault_ui/core/platform/app_capabilities.dart';

void main() {
  // The composition root itself needs a device: it loads libkeylease_mobile.so
  // and app-private storage. What can be asserted here is the capability set it
  // hands the shared package, which is what keeps desktop-only surface off the
  // phone. The FFI boundary is covered on the host by
  // crates/keylease-mobile/tests/ffi.rs and tests/provisioning.rs.
  test('the phone capability set excludes what a phone cannot do', () {
    const phone = AppCapabilities.androidPhone;
    expect(phone.agentWorkflows, isFalse);
    expect(phone.sshKeyBinding, isFalse);
    expect(phone.connectionCreation, isFalse);
    expect(phone.vaultMigrations, isFalse);
    expect(phone.cameraQrScan, isTrue);
  });
}
