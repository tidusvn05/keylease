# LeaseGate approval web

Mobile-first Phase 3 approval and Edge-health UI. Build-time values are public
configuration only; never bake an operator credential into the bundle.

```sh
flutter pub get
flutter build web --release \
  --dart-define=KEYLEASE_CLOUD_URL=https://leasegate.example.com \
  --dart-define=KEYLEASE_ORGANIZATION_ID=org_... \
  --dart-define=KEYLEASE_PROJECT_ID=project_...
```

The beta direct-operator profile asks for a credential per browser tab and
keeps it only in memory. Put an OIDC identity proxy in front before exposing a
team installation to the Internet; direct mode is intended for a single-owner
self-hosted VPS.
