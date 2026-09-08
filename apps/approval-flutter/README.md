# Leasegate Approval

Mobile-first Phase 3-6 operator UI for approval and Edge health plus the
permission matrix, deterministic simulator, policy proposals, connection
onboarding and bounded audit explorer. Build-time values are public
configuration only; never bake an operator credential into the bundle.

```sh
flutter pub get
flutter build web --release \
  --dart-define=KEYLEASE_CLOUD_URL=https://leasegate.example.com \
  --dart-define=KEYLEASE_ORGANIZATION_ID=org_... \
  --dart-define=KEYLEASE_PROJECT_ID=project_... \
  --dart-define=KEYLEASE_APPROVER_ID=human_... \
  --dart-define=KEYLEASE_AGENT_ID=agent_...
```

The beta direct-operator profile asks for a credential per browser tab and
keeps it only in memory. Native iOS/Android builds can enroll an Ed25519 device
key, keep it in platform secure storage, gate challenge signing with biometrics
and use a five-minute role-bound session for approval and security alerts.
When organization OIDC is enabled, the deployment login flow must provide the
validated ID token during device authentication.

```sh
# Configure a private release keystore in CI/local Gradle settings first;
# the repository deliberately does not fall back to the Android debug key.
flutter build apk --release
# Run the iOS build and signing step on macOS with Xcode:
flutter build ios --release
```
