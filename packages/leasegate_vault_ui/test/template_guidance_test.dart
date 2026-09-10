import 'package:flutter_test/flutter_test.dart';
import 'package:leasegate_vault_ui/features/vault/template_guidance.dart';

void main() {
  test('every built-in template has explicit guidance', () {
    const builtInKinds = {
      'core.prompt',
      'core.runbook',
      'core.environment',
      'core.ssh_server',
      'core.login',
      'core.api_credential',
      'core.database',
      'core.ssh_key',
      'core.secure_note',
      'core.note',
      'core.password',
      'core.email_account',
      'core.server',
      'core.software_license',
      'core.wireless_router',
      'core.credit_card',
      'core.document',
      'core.identity',
      'core.bank_account',
      'core.crypto_wallet',
      'core.driver_license',
      'core.medical_record',
      'core.membership',
      'core.outdoor_license',
      'core.passport',
      'core.reward_program',
      'core.social_security_number',
      'core.generic',
    };

    expect(templateGuidance.keys.toSet(), builtInKinds);
    for (final guidance in templateGuidance.values) {
      expect(guidance.summary, isNotEmpty);
      expect(guidance.useWhen, startsWith('Use'));
    }
  });

  test('unknown custom templates receive useful fallback guidance', () {
    final guidance = guidanceForTemplate(
      'custom.service',
      label: 'Internal service',
    );

    expect(guidance.summary, contains('Internal service'));
    expect(guidance.useWhen, isNotEmpty);
  });
}
