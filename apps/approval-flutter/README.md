# LeaseGate approval web

Mobile-first Phase 3/4 operator UI for approval and Edge health plus the
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
keeps it only in memory. Put an OIDC identity proxy in front before exposing a
team installation to the Internet; direct mode is intended for a single-owner
self-hosted VPS.
