/// The shared Leasegate vault client.
///
/// Everything above the transport lives here: the typed views over the IPC
/// payloads, the session and feature state, the design tokens and the whole
/// feature UI. What stays in each app is its composition root and the platform
/// code that differs — the socket client and preferences file on desktop, the
/// FFI client and app-private storage on Android.
///
/// Deep imports are deliberately still legal; this barrel is a convenience for
/// composition roots, not an encapsulation boundary.
library;

export 'app/app_scope.dart' show AppScope, Observe;
export 'app/app_theme.dart' show KeyLeaseTheme;
export 'app/keylease_app.dart' show KeyLeaseApp;
export 'core/models/models.dart';
export 'core/platform/app_capabilities.dart';
export 'core/platform/local_runtime_adapter.dart';
export 'core/platform/preferences_store.dart'
    show PreferencesStore, InMemoryPreferencesStore;
export 'core/platform/security_adapter.dart';
export 'core/rpc/keylease_client.dart'
    show KeyLeaseClient, KeyLeaseErrorCode, KeyLeaseException;
export 'core/state/app_controller.dart' show AppController, ClientFactory;
export 'core/state/app_phase.dart' show AppPhase, AppSection;
export 'core/state/connection_settings.dart' show ConnectionSettings;
export 'ui/tokens/keylease_tokens.dart' show KeyLeaseLayout, KeyLeaseTokens;
